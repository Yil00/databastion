//! The connection (ADR-0060 decisions 1, 3 and 4).
//!
//! 1. TCP to the declared loopback address and port; the peer-uid rule
//!    before anything is sent ([`crate::peer`]).
//! 2. `op_connect` offering protocol 16 only and `Srp256` only, with `A`,
//!    naming the database (`attach`) **in clear**: wire encryption has not
//!    started yet, and the server needs the name to apply a per-database
//!    `AuthServer` or `WireCrypt` (with an empty name, a server enabling
//!    `Srp256` or `WireCrypt` for that database only refuses the login or
//!    offers no key; measured on 4.0.7 and 5.0.4).
//!    The answer must be `op_cond_accept` of protocol 16, generic,
//!    `ptype_batch_send`, plugin `Srp256`, not yet authenticated; anything
//!    else ends the connection before anything derived from the password
//!    is computed.
//! 3. `op_cont_auth` with `M`; the server's `op_response` carries the wire
//!    keys.
//! 4. `op_crypt` naming `ChaCha64`, else `ChaCha` (never Arc4); the
//!    encrypted answer must be exactly a success `op_response` before the
//!    client sends any encrypted byte (key confirmation).
//! 5. `op_attach` with the DPB of decision 3.
//!
//! Then statements: a read-only read-committed transaction, one statement
//! at a time (allocate, prepare with describe, execute with the
//! server-side timeout, bounded fetches, free), the client's own deadline
//! as a backstop with `op_cancel` and at most 5 s for its answer.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use databastion_core::FailureCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use crate::crypt::Cipher;
use crate::error::{Detail, FbError, Stage};
use crate::sql::{self, Col, Column, Value};
use crate::srp;
use crate::wire::{self, CryptPlugin, Keys, Phase, Server};
use crate::xdr::{Reader, Writer, XdrError};

/// The byte streams a connection runs over (TCP, or a duplex in tests).
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Largest message (one server item plus its row) kept while it arrives.
const MAX_MESSAGE: usize = 1 << 20;
/// One read from the socket.
const READ_CHUNK: usize = 64 * 1024;
/// Rows asked for by one `op_fetch` (decision 1: at most 64).
const FETCH_ROWS: u32 = 64;
/// How long the answer to `op_cancel` is waited for (decision 4).
const CANCEL_WAIT: Duration = Duration::from_secs(5);
/// The client's margin over the server-side statement timeout.
const CLIENT_MARGIN: Duration = Duration::from_secs(1);

/// The transport of one attachment, with its ciphers.
pub(crate) struct Conn {
    io: Box<dyn Io>,
    /// Received (decrypted) bytes not yet parsed; reserved once, so that
    /// no reallocation leaves an unzeroized copy.
    rx: Zeroizing<Vec<u8>>,
    rx_cipher: Option<Cipher>,
    tx_cipher: Option<Cipher>,
}

impl Conn {
    pub(crate) fn new(io: Box<dyn Io>) -> Self {
        Self {
            io,
            rx: Zeroizing::new(Vec::with_capacity(MAX_MESSAGE + READ_CHUNK)),
            rx_cipher: None,
            tx_cipher: None,
        }
    }

    async fn send(&mut self, msg: &Writer, deadline: Instant, stage: Stage) -> Result<(), FbError> {
        let mut buf = Zeroizing::new(msg.as_slice().to_vec());
        if let Some(c) = self.tx_cipher.as_mut() {
            c.apply(&mut buf).map_err(|_| {
                FbError::new(FailureCode::TargetUnreachable, stage)
                    .with_detail(Detail::KeystreamEnd)
            })?;
        }
        let write = async {
            self.io.write_all(&buf).await?;
            self.io.flush().await
        };
        match tokio::time::timeout_at(deadline, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(FbError::io(&e, stage)),
            Err(_) => Err(FbError::new(FailureCode::Timeout, stage)),
        }
    }

    /// Parses the next message with `parse`, reading more bytes until it
    /// is complete (bounded by [`MAX_MESSAGE`]).
    async fn recv<T>(
        &mut self,
        deadline: Instant,
        stage: Stage,
        mut parse: impl FnMut(&mut Reader<'_>) -> Result<T, XdrError>,
    ) -> Result<T, FbError> {
        loop {
            let mut r = Reader::new(&self.rx);
            match parse(&mut r) {
                Ok(v) => {
                    let used = r.pos();
                    self.consume(used);
                    return Ok(v);
                }
                Err(XdrError::Bound) => return Err(FbError::protocol(stage)),
                Err(XdrError::Incomplete) => {}
            }
            if self.rx.len() >= MAX_MESSAGE {
                return Err(FbError::protocol(stage));
            }
            let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
            let n = match tokio::time::timeout_at(deadline, self.io.read(&mut chunk)).await {
                Ok(Ok(0)) => {
                    return Err(FbError::new(FailureCode::TargetUnreachable, stage));
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(FbError::io(&e, stage)),
                Err(_) => return Err(FbError::new(FailureCode::Timeout, stage)),
            };
            if let Some(c) = self.rx_cipher.as_mut() {
                c.apply(&mut chunk[..n]).map_err(|_| {
                    FbError::new(FailureCode::TargetUnreachable, stage)
                        .with_detail(Detail::KeystreamEnd)
                })?;
            }
            self.rx.extend_from_slice(&chunk[..n]);
        }
    }

    /// Drops the first `n` buffered bytes, zeroizing what is left behind.
    fn consume(&mut self, n: usize) {
        let len = self.rx.len();
        let n = n.min(len);
        self.rx.copy_within(n.., 0);
        self.rx[len - n..].zeroize();
        self.rx.truncate(len - n);
    }

    /// Writes `op_disconnect` and shuts the stream down (best effort).
    async fn shutdown(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        let _ = self.send(&wire::disconnect(), deadline, Stage::Check).await;
        let _ = tokio::time::timeout_at(deadline, self.io.shutdown()).await;
    }
}

/// What the connection needs from the target's configuration.
#[derive(Clone)]
pub(crate) struct Endpoint {
    pub(crate) addr: SocketAddr,
    pub(crate) login: String,
    pub(crate) peer_uid: u32,
}

impl Endpoint {
    /// The endpoint of a validated `firebird` target: the loopback IP
    /// literal (refused at load otherwise), the port, the upper-cased
    /// account, the resolved peer uid.
    pub(crate) fn of(target: &databastion_core::config::TargetConfig) -> Result<Self, FbError> {
        let host = target.host.as_deref().unwrap_or_default();
        let settings = target
            .firebird_settings()
            .ok_or(FbError::new(FailureCode::Internal, Stage::Connect))?;
        let ip: IpAddr = host
            .parse()
            .ok()
            .filter(|ip: &IpAddr| {
                databastion_core::config::firebird::host_is_loopback_literal(host)
                    && ip.is_loopback()
            })
            .ok_or(
                FbError::new(FailureCode::InvalidParams, Stage::Connect)
                    .with_detail(Detail::NotLoopback),
            )?;
        let port = target
            .effective_port()
            .unwrap_or(databastion_core::config::firebird::DEFAULT_PORT);
        let peer_uid = settings
            .peer_uid()
            .ok_or(FbError::new(FailureCode::Internal, Stage::Connect))?;
        Ok(Self {
            addr: SocketAddr::new(ip, port),
            login: target.account.to_ascii_uppercase(),
            peer_uid,
        })
    }
}

/// An attached session.
pub(crate) struct Session {
    conn: Conn,
    /// The agent's end of the TCP connection (the forwarder rule).
    pub(crate) local: Option<SocketAddr>,
    /// The negotiated wire encryption.
    pub(crate) plugin: CryptPlugin,
    tx: Option<u16>,
    statement_timeout: Duration,
    /// After a failure that may have left the connection out of step
    /// (a client deadline, a protocol violation), nothing more is sent.
    broken: bool,
    /// The outcome of the last `op_cancel` (the client deadline's
    /// backstop): what the server answered and how long it took.
    pub(crate) last_cancel: Option<CancelOutcome>,
    /// The account of the last statement's fetch, for its execution
    /// credit (ADR-0060 R22 item 1).
    pub(crate) last_fetch: FetchAccount,
    /// A cancel was sent and the pending request was answered by rows or
    /// its end rather than by `isc_cancelled` (R22 item 3, a stale
    /// cancel): the next request may meet it.
    stale_cancel: bool,
    /// The agent's own attachment (decision 6): the ledger of the
    /// endpoint, the declared `attach`, the attachment id once
    /// `CURRENT_CONNECTION` was read, and the credits of executions run
    /// before it (moved to the ledger then).
    own: Own,
}

/// A session's place in the ledger of its endpoint ([`crate::own`]).
#[derive(Default)]
struct Own {
    ledger: Option<std::sync::Arc<crate::own::Ledger>>,
    attach: String,
    id: Option<u64>,
    early: Vec<(String, Option<String>, FetchAccount)>,
    closed: bool,
    /// The table of the built statement being run (its credit names it).
    table: Option<String>,
}

/// How the fetch of one execution ended (ADR-0060 R22 item 1, R35).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum FetchEnd {
    /// No fetch ran (prepared or executed only, or not yet ended).
    #[default]
    NotRun,
    /// The server's end-of-result answer was read.
    End,
    /// Stopped before the end: the byte budget, the row-limit cut, or the
    /// client deadline with the answer to every request sent read.
    Early,
    /// The attachment was dropped while an answer was still unread.
    Lost,
    /// The server's statement timeout (`isc_cancelled` and the timeout
    /// code).
    Failed,
    /// The connector's `op_cancel` was answered by `isc_cancelled` (R35).
    Cancelled,
    /// Any other server error.
    Error,
}

/// What one execution requested and counted (ADR-0060 R22 item 1): the
/// bounds of its record's `records fetched` follow from it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FetchAccount {
    /// Rows received from the server (C).
    pub(crate) counted: u64,
    /// The sum of the row counts of the `op_fetch` messages written (Q).
    pub(crate) requested: u64,
    /// The row count of the last `op_fetch` (L).
    pub(crate) last: u32,
    /// The largest row count of one `op_fetch` (M, at most 64).
    pub(crate) largest: u32,
    /// How the fetch ended.
    pub(crate) end: FetchEnd,
    /// The stale cancel's `isc_cancelled` answered the `DSQL_drop` that
    /// followed (R22 item 3: a follow-up of the same credit).
    pub(crate) stale_cancel_follow_up: bool,
    /// The session was ended cleanly after a stale cancel whose
    /// `DSQL_drop` succeeded (R22 item 3, review L7).
    pub(crate) session_retired: bool,
}

/// What the server answered to the client's `op_cancel` (decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CancelOutcome {
    /// The first GDS code of the answer to the cancelled operation
    /// (`isc_cancelled` expected), `None` for a success answer.
    pub(crate) gds: Option<u32>,
    /// From `op_cancel` sent to that answer read.
    pub(crate) after: Duration,
}

/// Opens TCP to the endpoint, applies the peer rule, then runs the
/// handshake and attaches `attach`.
pub(crate) async fn connect(
    endpoint: &Endpoint,
    password: &[u8],
    attach: &str,
    deadline: Instant,
    statement_timeout: Duration,
) -> Result<Session, FbError> {
    let stream = match tokio::time::timeout_at(
        deadline,
        tokio::net::TcpStream::connect(endpoint.addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(FbError::io(&e, Stage::Connect)),
        Err(_) => return Err(FbError::new(FailureCode::Timeout, Stage::Connect)),
    };
    let _ = stream.set_nodelay(true);
    let local = stream
        .local_addr()
        .map_err(|e| FbError::io(&e, Stage::Connect))?;
    // Decision 3, security review L1: before op_connect is sent.
    crate::peer::check(endpoint.addr, local, endpoint.peer_uid)
        .await
        .map_err(|d| FbError::new(FailureCode::TargetUnreachable, Stage::Connect).with_detail(d))?;
    let mut s = handshake(
        Box::new(stream),
        &endpoint.login,
        password,
        attach,
        deadline,
        statement_timeout,
    )
    .await?;
    s.local = Some(local);
    s.own.ledger = Some(crate::own::ledger_for(endpoint.addr));
    Ok(s)
}

/// The exact `op_response` that confirms the wire key (decision 1): no
/// object, no blob, no data, the success status vector.
const KEY_CONFIRMATION: [u8; 32] = [
    0, 0, 0, 9, // op_response
    0, 0, 0, 0, // object
    0, 0, 0, 0, 0, 0, 0, 0, // blob id
    0, 0, 0, 0, // data: empty
    0, 0, 0, 1, 0, 0, 0, 0, // isc_arg_gds, 0
    0, 0, 0, 0, // isc_arg_end
];

/// The handshake and the attachment over `io` (decisions 1 and 3).
pub(crate) async fn handshake(
    io: Box<dyn Io>,
    login: &str,
    password: &[u8],
    attach: &str,
    deadline: Instant,
    statement_timeout: Duration,
) -> Result<Session, FbError> {
    let mut conn = Conn::new(io);
    let client =
        srp::Client::new().map_err(|_| FbError::new(FailureCode::Internal, Stage::Connect))?;
    conn.send(
        &wire::connect(attach, login, &client.public_hex()),
        deadline,
        Stage::Connect,
    )
    .await?;
    let accept = match conn
        .recv(deadline, Stage::Connect, |r| wire::parse(r, Phase::Connect))
        .await?
    {
        Server::Accept(a) => a,
        Server::Reject => {
            return Err(FbError::new(FailureCode::Unsupported, Stage::Connect)
                .with_detail(Detail::ProtocolVersion));
        }
        Server::Response(r) if r.status.failed() => {
            return Err(FbError::server(&r.status.codes, Stage::Connect));
        }
        Server::CryptKeyCallback => {
            return Err(FbError::protocol(Stage::Connect).with_detail(Detail::CryptKeyCallback));
        }
        _ => return Err(FbError::protocol(Stage::Connect)),
    };
    if !accept.is_protocol_16() {
        return Err(FbError::new(FailureCode::Unsupported, Stage::Connect)
            .with_detail(Detail::ProtocolVersion));
    }
    // SRP must complete: authenticated before `M` is a refusal, and so is
    // any plugin other than Srp256 or an accept without auth data.
    if accept.authenticated != 0 {
        return Err(FbError::new(FailureCode::AuthenticationFailed, Stage::Auth)
            .with_detail(Detail::AuthenticatedEarly));
    }
    if !accept.conditional || accept.plugin != wire::SRP256 {
        return Err(FbError::new(FailureCode::AuthenticationFailed, Stage::Auth)
            .with_detail(Detail::AuthPlugin));
    }
    let mut keys = Keys::default();
    keys.add(&accept.keys)
        .map_err(|_| FbError::protocol(Stage::Auth))?;
    let server = srp::ServerData::parse(&accept.data).map_err(|_| {
        FbError::new(FailureCode::AuthenticationFailed, Stage::Auth).with_detail(Detail::SrpData)
    })?;
    let proof = client.proof(login, password, &server).map_err(|_| {
        FbError::new(FailureCode::AuthenticationFailed, Stage::Auth).with_detail(Detail::SrpData)
    })?;
    conn.send(&wire::cont_auth(&proof.hex), deadline, Stage::Auth)
        .await?;
    match conn
        .recv(deadline, Stage::Auth, |r| wire::parse(r, Phase::Auth))
        .await?
    {
        Server::Response(r) if !r.status.failed() => {
            keys.add(&r.data)
                .map_err(|_| FbError::protocol(Stage::Auth))?;
        }
        Server::Response(r) => return Err(FbError::server(&r.status.codes, Stage::Auth)),
        Server::CryptKeyCallback => {
            return Err(FbError::protocol(Stage::Auth).with_detail(Detail::CryptKeyCallback));
        }
        // Srp256 completes in one round: another round is refused.
        _ => return Err(FbError::protocol(Stage::Auth)),
    }
    // Wire encryption (decision 1): ChaCha64, else ChaCha, never Arc4.
    let (plugin, specific) = keys.choose().ok_or(
        FbError::new(FailureCode::TargetUnreachable, Stage::Tls).with_detail(Detail::NoChacha),
    )?;
    let (Some(rx), Some(tx)) = (
        Cipher::new(plugin, &proof.key, specific),
        Cipher::new(plugin, &proof.key, specific),
    ) else {
        return Err(FbError::protocol(Stage::Tls));
    };
    drop(proof);
    if !conn.rx.is_empty() {
        // Nothing may arrive unasked before op_crypt.
        return Err(FbError::protocol(Stage::Tls));
    }
    conn.send(&wire::crypt(plugin.name()), deadline, Stage::Tls)
        .await?;
    conn.rx_cipher = Some(rx);
    let confirmed = conn
        .recv(deadline, Stage::Tls, |r| {
            r.raw(KEY_CONFIRMATION.len()).map(|b| b == KEY_CONFIRMATION)
        })
        .await
        .map_err(|e| {
            if e.code == FailureCode::Timeout {
                e
            } else {
                FbError::new(FailureCode::TargetUnreachable, Stage::Tls)
                    .with_detail(Detail::KeyConfirmation)
            }
        })?;
    if !confirmed {
        return Err(FbError::new(FailureCode::TargetUnreachable, Stage::Tls)
            .with_detail(Detail::KeyConfirmation));
    }
    conn.tx_cipher = Some(tx);
    let mut session = Session {
        conn,
        local: None,
        plugin,
        tx: None,
        statement_timeout,
        broken: false,
        last_cancel: None,
        last_fetch: FetchAccount::default(),
        stale_cancel: false,
        own: Own {
            attach: attach.to_owned(),
            ..Own::default()
        },
    };
    session
        .request(&wire::attach(attach, login), deadline, Stage::SessionSetup)
        .await?;
    Ok(session)
}

/// The rows of one statement, and whether the row bound cut them.
#[derive(Debug, Default)]
pub(crate) struct Rows {
    pub(crate) rows: Vec<Vec<Value>>,
    pub(crate) cut: bool,
}

impl Session {
    /// The negotiated plugin's name.
    pub(crate) fn plugin_name(&self) -> &'static str {
        self.plugin.name()
    }

    /// Sends `msg` and reads its `op_response`; a failed status vector is
    /// the server's error (`fatal` per [`FbError::server`]).
    async fn request(
        &mut self,
        msg: &Writer,
        deadline: Instant,
        stage: Stage,
    ) -> Result<wire::Response, FbError> {
        if self.broken {
            return Err(FbError::new(FailureCode::TargetUnreachable, stage));
        }
        let out = self.request_inner(msg, deadline, stage).await;
        if let Err(e) = &out
            && e.fatal
        {
            self.broken = true;
        }
        out
    }

    async fn request_inner(
        &mut self,
        msg: &Writer,
        deadline: Instant,
        stage: Stage,
    ) -> Result<wire::Response, FbError> {
        self.conn.send(msg, deadline, stage).await?;
        match self
            .conn
            .recv(deadline, stage, |r| wire::parse(r, Phase::Session))
            .await?
        {
            Server::Response(r) if r.status.failed() => {
                Err(FbError::server(&r.status.codes, stage))
            }
            Server::Response(r) => Ok(r),
            _ => Err(FbError::protocol(stage)),
        }
    }

    /// Starts the read-only read-committed transaction of decision 4, if
    /// none is open.
    pub(crate) async fn begin(&mut self, deadline: Instant) -> Result<(), FbError> {
        if self.tx.is_none() {
            let r = self
                .request(&wire::transaction(), deadline, Stage::SessionSetup)
                .await?;
            self.tx = Some(r.object);
        }
        Ok(())
    }

    /// Commits the open transaction, if any.
    pub(crate) async fn commit(&mut self, deadline: Instant) -> Result<(), FbError> {
        if let Some(tx) = self.tx.take() {
            self.request(&wire::release(wire::op::COMMIT, tx), deadline, Stage::Check)
                .await?;
        }
        Ok(())
    }

    /// Runs one statement of the closed set and returns at most `max_rows`
    /// rows; its columns must be exactly `shape` (fail closed: the
    /// attachment is then unusable).
    pub(crate) async fn query(
        &mut self,
        text: &'static str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
    ) -> Result<Rows, FbError> {
        if !sql::checked(text) {
            return Err(FbError::new(FailureCode::Internal, Stage::Check));
        }
        self.own.table = None;
        self.query_text(text, shape, max_rows, deadline).await
    }

    /// Test support: any text (the integration measurements).
    #[cfg(test)]
    pub(crate) async fn query_for_tests(
        &mut self,
        text: &str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
    ) -> Result<Rows, FbError> {
        self.query_text(text, shape, max_rows, deadline).await
    }

    /// Test support: any text, each row to `on_row`.
    #[cfg(test)]
    pub(crate) async fn fetch_for_tests(
        &mut self,
        text: &str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
        on_row: &mut (dyn FnMut(Vec<Value>) -> Flow + Send),
    ) -> Result<Fetched, FbError> {
        self.statement(text, shape, max_rows, deadline, on_row)
            .await
    }

    /// Whether nothing more can be sent on this attachment.
    pub(crate) fn is_broken(&self) -> bool {
        self.broken
    }

    /// A statement whose text the caller has checked: its rows collected.
    async fn query_text(
        &mut self,
        text: &str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
    ) -> Result<Rows, FbError> {
        let mut rows = Vec::new();
        let fetched = self
            .statement(text, shape, max_rows, deadline, &mut |row| {
                rows.push(row);
                Flow::Continue
            })
            .await?;
        Ok(Rows {
            rows,
            cut: fetched.cut,
        })
    }

    /// Runs a statement built from catalog names (Discovery, decision 5):
    /// each row is handed to `on_row` as it arrives, which may stop the
    /// fetch ([`Flow::Stop`]: no further `op_fetch`, the rows of the round
    /// in flight read and dropped, then the cursor closed).
    pub(crate) async fn sample(
        &mut self,
        stmt: &sql::Built,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
        on_row: &mut (dyn FnMut(Vec<Value>) -> Flow + Send),
    ) -> Result<Fetched, FbError> {
        self.own.table = Some(stmt.table().to_owned());
        self.statement(stmt.text(), shape, max_rows, deadline, on_row)
            .await
    }

    /// A built statement's rows collected (the CAS guard's aggregate).
    pub(crate) async fn query_built(
        &mut self,
        stmt: &sql::Built,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
    ) -> Result<Rows, FbError> {
        self.own.table = Some(stmt.table().to_owned());
        self.query_text(stmt.text(), shape, max_rows, deadline)
            .await
    }

    async fn statement(
        &mut self,
        text: &str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
        on_row: &mut (dyn FnMut(Vec<Value>) -> Flow + Send),
    ) -> Result<Fetched, FbError> {
        self.last_fetch = FetchAccount::default();
        self.stale_cancel = false;
        self.begin(deadline).await?;
        let tx = self.tx.unwrap_or(0);
        let stmt = self
            .request(&wire::allocate(), deadline, Stage::Check)
            .await?
            .object;
        let result = self
            .run((tx, stmt), text, shape, max_rows, deadline, on_row)
            .await;
        if result.is_err() && self.last_fetch.end == FetchEnd::NotRun {
            self.last_fetch.end = FetchEnd::Error;
        }
        if !self.broken {
            // `DSQL_drop` closes the cursor and releases the handle; after
            // a statement cancelled at the deadline, within the cancel's
            // own bound (decision 4: 5 s).
            let cleanup = deadline.max(Instant::now() + CANCEL_WAIT);
            let free = self.free_after(stmt, cleanup).await;
            if let (Ok(_), Err(e)) = (&result, free) {
                self.record_credit(text);
                return Err(e);
            }
        }
        self.record_credit(text);
        result
    }

    /// One execution's credit (decision 6, R22 item 1): to the ledger once
    /// the attachment id is known, held until then.
    fn record_credit(&mut self, text: &str) {
        let account = self.last_fetch;
        let table = self.own.table.take();
        match (&self.own.ledger, self.own.id) {
            (Some(l), Some(id)) => l.credit(&self.own.attach, id, text, table.as_deref(), account),
            (Some(_), None) if self.own.early.len() < 64 => {
                self.own.early.push((text.to_owned(), table, account));
            }
            _ => {}
        }
    }

    /// The attachment id read from `CURRENT_CONNECTION` and the server pid
    /// (decision 6, R1 rule 1): the session's attachment enters the
    /// ledger, with the credits of the executions before it.
    pub(crate) fn register_own(&mut self, id: u64, pid: u32) {
        let (Some(l), Some(local)) = (self.own.ledger.clone(), self.local) else {
            return;
        };
        if self.own.id.is_some() {
            return;
        }
        l.register(&self.own.attach, id, local.port(), pid);
        self.own.id = Some(id);
        for (text, table, account) in std::mem::take(&mut self.own.early) {
            l.credit(&self.own.attach, id, &text, table.as_deref(), account);
        }
    }

    /// The attachment id the session registered in the ledger (its
    /// `CURRENT_CONNECTION`), `None` before or without one.
    pub(crate) fn own_id(&self) -> Option<u64> {
        self.own.id
    }

    /// `DSQL_drop` of a statement handle (R22 item 3). After a stale
    /// cancel, the drop may meet it: an `isc_cancelled` answer is its
    /// expected follow-up (the drop is sent once more, and the attachment
    /// stays usable); a successful drop may leave the cancel pending on
    /// the server, so the session ends cleanly (rolled back and detached,
    /// review L7) and the caller reconnects; any other answer, or none,
    /// drops the attachment (`lost`).
    async fn free_after(&mut self, stmt: u16, until: Instant) -> Result<(), FbError> {
        let stale = std::mem::take(&mut self.stale_cancel);
        let free = self
            .request(&wire::free(stmt, wire::DSQL_DROP), until, Stage::Check)
            .await;
        if !stale {
            return free.map(|_| ());
        }
        match free {
            Err(e) if e.gds == Some(crate::error::gds::CANCELLED) && !self.broken => {
                self.last_fetch.stale_cancel_follow_up = true;
                self.request(&wire::free(stmt, wire::DSQL_DROP), until, Stage::Check)
                    .await
                    .map(|_| ())
                    .inspect_err(|_| {
                        self.broken = true;
                        self.last_fetch.end = FetchEnd::Lost;
                    })
            }
            Ok(_) => {
                self.end_cleanly().await;
                self.last_fetch.session_retired = true;
                Ok(())
            }
            Err(e) => {
                self.broken = true;
                self.last_fetch.end = FetchEnd::Lost;
                Err(e)
            }
        }
    }

    /// Rolls back and detaches, then marks the session unusable: no later
    /// request of this attachment can meet a cancel still pending on the
    /// server (R22 item 3, review L7).
    async fn end_cleanly(&mut self) {
        let deadline = Instant::now() + CANCEL_WAIT;
        if let Some(tx) = self.tx.take() {
            let _ = self
                .request(
                    &wire::release(wire::op::ROLLBACK, tx),
                    deadline,
                    Stage::Check,
                )
                .await;
        }
        if !self.broken {
            let _ = self
                .request(&wire::release(wire::op::DETACH, 0), deadline, Stage::Check)
                .await;
        }
        self.broken = true;
    }

    /// Runs a statement that returns no rows (the session-management
    /// statement of decision 3).
    pub(crate) async fn exec(
        &mut self,
        text: &'static str,
        deadline: Instant,
    ) -> Result<(), FbError> {
        if !sql::checked(text) {
            return Err(FbError::new(FailureCode::Internal, Stage::Check));
        }
        self.own.table = None;
        self.begin(deadline).await?;
        let tx = self.tx.unwrap_or(0);
        let stmt = self
            .request(&wire::allocate(), deadline, Stage::Check)
            .await?
            .object;
        let result = async {
            let prepared = self
                .request(
                    &wire::prepare(tx, stmt, text, sql::DESCRIBE_ITEMS, sql::DESCRIBE_BUFFER),
                    deadline,
                    Stage::Check,
                )
                .await?;
            let d = sql::parse_describe(&prepared.data).map_err(|_| self.fail(Stage::Check))?;
            if !d.columns.is_empty() || d.parameters != 0 {
                return Err(self.fail(Stage::Check));
            }
            self.execute(stmt, tx, deadline, None).await
        }
        .await;
        if !self.broken {
            let _ = self
                .request(&wire::free(stmt, wire::DSQL_DROP), deadline, Stage::Check)
                .await;
        }
        self.last_fetch = FetchAccount {
            end: if result.is_ok() {
                FetchEnd::NotRun
            } else {
                FetchEnd::Error
            },
            ..FetchAccount::default()
        };
        self.record_credit(text);
        result
    }

    fn fail(&mut self, stage: Stage) -> FbError {
        self.broken = true;
        FbError::protocol(stage)
    }

    async fn run(
        &mut self,
        (tx, stmt): (u16, u16),
        text: &str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
        on_row: &mut (dyn FnMut(Vec<Value>) -> Flow + Send),
    ) -> Result<Fetched, FbError> {
        let prepared = self
            .request(
                &wire::prepare(tx, stmt, text, sql::DESCRIBE_ITEMS, sql::DESCRIBE_BUFFER),
                deadline,
                Stage::Check,
            )
            .await?;
        let d = sql::parse_describe(&prepared.data).map_err(|_| self.fail(Stage::Check))?;
        if d.stmt_type != sql::STMT_SELECT
            || d.parameters != 0
            || !sql::matches_shape(&d.columns, shape)
        {
            return Err(self.fail(Stage::Check));
        }
        self.execute(stmt, tx, deadline, Some(&d.columns)).await?;
        self.fetch_all(stmt, &d.columns, max_rows, deadline, on_row)
            .await
    }

    /// `op_execute` with the server-side timeout; the client's deadline
    /// sends `op_cancel` (decision 4).
    async fn execute(
        &mut self,
        stmt: u16,
        tx: u16,
        deadline: Instant,
        columns: Option<&[Column]>,
    ) -> Result<(), FbError> {
        let timeout_ms = u32::try_from(self.statement_timeout.as_millis()).unwrap_or(u32::MAX);
        let msg = wire::execute(stmt, tx, timeout_ms);
        self.conn
            .send(&msg, deadline, Stage::Check)
            .await
            .inspect_err(|_| {
                self.broken = true;
            })?;
        let until = self.statement_deadline(deadline);
        match self.next(until, columns).await {
            Ok(Next::Response(r)) if r.status.failed() => {
                let e = FbError::server(&r.status.codes, Stage::Check);
                self.broken |= e.fatal;
                Err(e)
            }
            Ok(Next::Response(_)) => Ok(()),
            Ok(Next::Row(_) | Next::End { .. }) => Err(self.fail(Stage::Check)),
            Err(e) => Err(self.after_client_failure(e, columns).await),
        }
    }

    fn statement_deadline(&self, deadline: Instant) -> Instant {
        (Instant::now() + self.statement_timeout + CLIENT_MARGIN).min(deadline)
    }

    async fn fetch_all(
        &mut self,
        stmt: u16,
        columns: &[Column],
        max_rows: usize,
        deadline: Instant,
        on_row: &mut (dyn FnMut(Vec<Value>) -> Flow + Send),
    ) -> Result<Fetched, FbError> {
        let blr = sql::output_blr(columns);
        let mut out = Fetched::default();
        let mut first = true;
        loop {
            // R22 item 3: the client deadline is checked before each
            // `op_fetch`. Past it, nothing more is requested and the
            // caller closes the cursor (`DSQL_drop`): no request is
            // pending, so no `op_cancel` is sent. The fetch ends early.
            if Instant::now() >= deadline {
                self.last_fetch.end = FetchEnd::Early;
                return Err(FbError::new(FailureCode::Timeout, Stage::Check));
            }
            let want = u32::try_from((max_rows + 1).saturating_sub(out.rows))
                .unwrap_or(FETCH_ROWS)
                .clamp(1, FETCH_ROWS);
            let msg = wire::fetch(stmt, if first { &blr } else { &[] }, want);
            first = false;
            self.conn
                .send(&msg, deadline, Stage::Check)
                .await
                .inspect_err(|_| {
                    self.broken = true;
                    self.last_fetch.end = FetchEnd::Lost;
                })?;
            let account = &mut self.last_fetch;
            account.requested += u64::from(want);
            account.last = want;
            account.largest = account.largest.max(want);
            let until = self.statement_deadline(deadline);
            let mut received = 0u32;
            loop {
                match self.next(until, Some(columns)).await {
                    Ok(Next::Row(row)) => {
                        received += 1;
                        self.last_fetch.counted += 1;
                        if received > want {
                            self.last_fetch.end = FetchEnd::Lost;
                            return Err(self.fail(Stage::Check));
                        }
                        if out.stopped {
                            // Read and dropped (zeroized with the row).
                        } else if out.rows < max_rows {
                            out.rows += 1;
                            if on_row(row) == Flow::Stop {
                                out.stopped = true;
                            }
                        } else {
                            out.cut = true;
                        }
                    }
                    Ok(Next::End { more }) => {
                        if !more {
                            self.last_fetch.end = FetchEnd::End;
                            return Ok(out);
                        }
                        if out.cut || out.stopped {
                            self.last_fetch.end = FetchEnd::Early;
                            return Ok(out);
                        }
                        break;
                    }
                    Ok(Next::Response(r)) if r.status.failed() => {
                        self.last_fetch.end = server_end(&r.status.codes);
                        let e = FbError::server(&r.status.codes, Stage::Check);
                        self.broken |= e.fatal;
                        return Err(e);
                    }
                    Ok(Next::Response(_)) => {
                        self.last_fetch.end = FetchEnd::Lost;
                        return Err(self.fail(Stage::Check));
                    }
                    Err(e) => return Err(self.after_client_failure(e, Some(columns)).await),
                }
            }
        }
    }

    /// After a client-side failure while a request is pending: on the
    /// client deadline, `op_cancel`, then at most [`CANCEL_WAIT`] until the
    /// pending request's answer is complete (rows still in flight read and
    /// dropped) or the cancelled answer arrives (R22 item 3). An
    /// `isc_cancelled` answer ends the fetch `cancelled` (R35); an answer
    /// by rows or the end of the result leaves a stale cancel, which the
    /// following `DSQL_drop` may meet ([`Self::free_after`]). Otherwise, or
    /// without an answer, the attachment is unusable (`lost`).
    async fn after_client_failure(&mut self, e: FbError, columns: Option<&[Column]>) -> FbError {
        if e.code != FailureCode::Timeout || self.broken {
            self.broken = true;
            self.last_fetch.end = FetchEnd::Lost;
            return e;
        }
        let sent = Instant::now();
        let wait = sent + CANCEL_WAIT;
        if self
            .conn
            .send(&wire::cancel(), wait, Stage::Check)
            .await
            .is_err()
        {
            self.broken = true;
            self.last_fetch.end = FetchEnd::Lost;
            return e;
        }
        loop {
            match self.next(wait, columns).await {
                Ok(Next::Response(r)) => {
                    let outcome = CancelOutcome {
                        gds: r.status.codes.first().copied(),
                        after: sent.elapsed(),
                    };
                    tracing::debug!(
                        gds = outcome.gds,
                        after_ms = u64::try_from(outcome.after.as_millis()).unwrap_or(u64::MAX),
                        "statement cancelled at the client deadline"
                    );
                    self.last_cancel = Some(outcome);
                    // Cancelled only when `isc_cancelled` is the sole code
                    // (R35; review of part 1, L4): with the timeout code
                    // too it is the server's own timeout.
                    if r.status.codes == [crate::error::gds::CANCELLED] {
                        self.last_fetch.end = FetchEnd::Cancelled;
                    } else if r.status.failed() {
                        self.last_fetch.end = server_end(&r.status.codes);
                    } else {
                        // `op_execute` answered before the cancel arrived.
                        self.stale_cancel = true;
                        self.last_fetch.end = FetchEnd::Early;
                    }
                    return e;
                }
                Ok(Next::Row(_)) => {
                    self.last_fetch.counted += 1;
                }
                Ok(Next::End { .. }) => {
                    // The pending fetch was answered in full: the cancel
                    // is stale (R22 item 3).
                    self.stale_cancel = true;
                    self.last_fetch.end = FetchEnd::Early;
                    return e;
                }
                Err(_) => {
                    self.broken = true;
                    self.last_fetch.end = FetchEnd::Lost;
                    return e;
                }
            }
        }
    }

    /// The next message of a running statement.
    async fn next(&mut self, until: Instant, columns: Option<&[Column]>) -> Result<Next, FbError> {
        self.conn
            .recv(until, Stage::Check, |r| {
                match wire::parse(r, Phase::Session)? {
                    Server::Response(resp) => Ok(Next::Response(resp)),
                    Server::FetchResponse { status, count } => match (status, count, columns) {
                        (0, 1, Some(cols)) => Ok(Next::Row(sql::parse_row(r, cols)?)),
                        (0, 0, _) => Ok(Next::End { more: true }),
                        (100, 0, _) => Ok(Next::End { more: false }),
                        _ => Err(XdrError::Bound),
                    },
                    _ => Err(XdrError::Bound),
                }
            })
            .await
    }

    /// Detaches and disconnects (best effort, bounded).
    pub(crate) async fn close(mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        if !self.broken {
            if let Some(tx) = self.tx.take() {
                let _ = self
                    .request(
                        &wire::release(wire::op::ROLLBACK, tx),
                        deadline,
                        Stage::Check,
                    )
                    .await;
            }
            let _ = self
                .request(&wire::release(wire::op::DETACH, 0), deadline, Stage::Check)
                .await;
        }
        self.conn.shutdown().await;
        self.end_own();
    }

    /// The attachment's end in the ledger: clean when nothing failed.
    fn end_own(&mut self) {
        if std::mem::replace(&mut self.own.closed, true) {
            return;
        }
        if let (Some(l), Some(id)) = (&self.own.ledger, self.own.id) {
            l.close(&self.own.attach, id, self.broken, self.statement_timeout);
        }
    }
}

impl Drop for Session {
    /// A session dropped without `close` (an error path): its attachment
    /// lives on in the ledger for the statement timeout plus 5 s (R22).
    fn drop(&mut self) {
        if !self.own.closed {
            self.broken = true;
            self.end_own();
        }
    }
}

/// How a server error ends a fetch (R22 item 1): `isc_cancelled` with the
/// statement-timeout code is the server's own timeout, anything else an
/// error (a cancel the connector did not send included, R35).
fn server_end(codes: &[u32]) -> FetchEnd {
    use crate::error::gds;
    if codes.len() == 2 && codes.contains(&gds::CANCELLED) && codes.contains(&gds::REQ_STMT_TIMEOUT)
    {
        FetchEnd::Failed
    } else {
        FetchEnd::Error
    }
}

/// What a row callback asks of the fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Stop,
}

/// How a fetch ended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fetched {
    /// Rows handed to the callback.
    pub(crate) rows: usize,
    /// More rows than `max_rows` were sent.
    pub(crate) cut: bool,
    /// The callback stopped the fetch.
    pub(crate) stopped: bool,
}

/// A message of a running statement.
enum Next {
    Response(wire::Response),
    Row(Vec<Value>),
    End { more: bool },
}
