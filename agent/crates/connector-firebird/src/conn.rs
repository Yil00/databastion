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
        self.begin(deadline).await?;
        let tx = self.tx.unwrap_or(0);
        let stmt = self
            .request(&wire::allocate(), deadline, Stage::Check)
            .await?
            .object;
        let result = self.run(tx, stmt, text, shape, max_rows, deadline).await;
        if !self.broken {
            // `DSQL_drop` closes the cursor and releases the handle.
            let free = self
                .request(&wire::free(stmt, wire::DSQL_DROP), deadline, Stage::Check)
                .await;
            if let (Ok(_), Err(e)) = (&result, free) {
                return Err(e);
            }
        }
        result
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
        result
    }

    fn fail(&mut self, stage: Stage) -> FbError {
        self.broken = true;
        FbError::protocol(stage)
    }

    async fn run(
        &mut self,
        tx: u16,
        stmt: u16,
        text: &'static str,
        shape: &[Col],
        max_rows: usize,
        deadline: Instant,
    ) -> Result<Rows, FbError> {
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
        self.fetch_all(stmt, &d.columns, max_rows, deadline).await
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
    ) -> Result<Rows, FbError> {
        let blr = sql::output_blr(columns);
        let mut out = Rows::default();
        let mut first = true;
        loop {
            let want = u32::try_from((max_rows + 1).saturating_sub(out.rows.len()))
                .unwrap_or(FETCH_ROWS)
                .clamp(1, FETCH_ROWS);
            let msg = wire::fetch(stmt, if first { &blr } else { &[] }, want);
            first = false;
            self.conn
                .send(&msg, deadline, Stage::Check)
                .await
                .inspect_err(|_| {
                    self.broken = true;
                })?;
            let until = self.statement_deadline(deadline);
            let mut received = 0u32;
            loop {
                match self.next(until, Some(columns)).await {
                    Ok(Next::Row(row)) => {
                        received += 1;
                        if received > want {
                            return Err(self.fail(Stage::Check));
                        }
                        if out.rows.len() < max_rows {
                            out.rows.push(row);
                        } else {
                            out.cut = true;
                        }
                    }
                    Ok(Next::End { more }) => {
                        if !more || out.cut {
                            return Ok(out);
                        }
                        break;
                    }
                    Ok(Next::Response(r)) if r.status.failed() => {
                        let e = FbError::server(&r.status.codes, Stage::Check);
                        self.broken |= e.fatal;
                        return Err(e);
                    }
                    Ok(Next::Response(_)) => return Err(self.fail(Stage::Check)),
                    Err(e) => return Err(self.after_client_failure(e, Some(columns)).await),
                }
            }
        }
    }

    /// After a client-side failure while a statement runs: on the client
    /// deadline, `op_cancel`, then at most [`CANCEL_WAIT`] for the
    /// statement's answer (rows still in flight are read and dropped);
    /// otherwise, or without an answer, the attachment is unusable.
    async fn after_client_failure(&mut self, e: FbError, columns: Option<&[Column]>) -> FbError {
        if e.code != FailureCode::Timeout || self.broken {
            self.broken = true;
            return e;
        }
        let wait = Instant::now() + CANCEL_WAIT;
        if self
            .conn
            .send(&wire::cancel(), wait, Stage::Check)
            .await
            .is_err()
        {
            self.broken = true;
            return e;
        }
        loop {
            match self.next(wait, columns).await {
                Ok(Next::Response(_)) => return e,
                Ok(Next::Row(_) | Next::End { .. }) => {}
                Err(_) => {
                    self.broken = true;
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
    }
}

/// A message of a running statement.
enum Next {
    Response(wire::Response),
    Row(Vec<Value>),
    End { more: bool },
}
