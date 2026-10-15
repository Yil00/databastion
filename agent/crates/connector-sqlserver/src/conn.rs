//! Sessions (ADR-0051 decisions 1, 2 and 5): TCP to the declared host and
//! port only (I5), TLS in `strict` or `mandatory` mode (`auto` chooses,
//! [`TlsChoice`]), `LOGIN7` with SQL authentication, the constant session
//! settings read back, then one statement per `SQLBatch`.
//!
//! Every statement has a client-side deadline (no server-side timeout
//! exists for the login); at the deadline, when a bound is reached, or when
//! the caller stops, the client sends `ATTENTION` and reads until the
//! `DONE` with `DONE_ATTN` within 5 s, otherwise the session is poisoned
//! and closed. Reads go through cancel-safe `read` calls into
//! [`tds::Reassembly`], so a deadline never desynchronizes the framing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_core::FailureCode;
use databastion_core::config::TargetConfig;
use databastion_core::config::sqlserver::SqlserverTlsMode;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::error::{Detail, SsError, Stage};
use crate::tds::{self, ptype};
use crate::tls::{self, PreloginWrap};
use crate::token::{Decoder, Event, Limits, TokenError, Value, done};

/// TCP connect, TLS handshake and login timeout.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the `ATTENTION` acknowledgement is waited for (decision 5).
pub(crate) const ATTENTION_WAIT: Duration = Duration::from_secs(5);
/// A session idle longer than this is replaced (decision 2).
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60);
/// After a failed strict attempt, `auto` connects in `mandatory` for this
/// long before trying strict again (refinement item 3, in memory only).
pub(crate) const STRICT_RETRY: Duration = Duration::from_secs(3600);
/// Bound of the login response (decision 1).
const LOGIN_MESSAGE: usize = 64 * 1024;
/// Bound of the `PRELOGIN` response.
const PRELOGIN_MESSAGE: usize = 4096;

/// The constant session settings (decision 5), one batch.
pub(crate) const SESSION_SETTINGS: &str = "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; \
SET LOCK_TIMEOUT 2000; SET IMPLICIT_TRANSACTIONS OFF; SET XACT_ABORT ON; \
SET DEADLOCK_PRIORITY LOW; SET NOCOUNT OFF; SET QUOTED_IDENTIFIER ON; SET ANSI_NULLS ON; \
SET ROWCOUNT 0; SET TEXTSIZE 8000; SET LANGUAGE us_english; SET DATEFORMAT ymd";

/// The settings read back (decision 5): `@@OPTIONS`, `@@LOCK_TIMEOUT`,
/// `@@SPID` and the session's isolation level.
pub(crate) const SESSION_READBACK: &str = "SELECT CONVERT(int, @@OPTIONS), \
CONVERT(int, @@LOCK_TIMEOUT), CONVERT(int, @@SPID), CONVERT(int, (SELECT \
transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID))";

/// `@@OPTIONS` bits checked.
mod opt {
    pub(super) const IMPLICIT_TRANSACTIONS: i64 = 2;
    pub(super) const ANSI_NULLS: i64 = 32;
    pub(super) const QUOTED_IDENTIFIER: i64 = 256;
    pub(super) const NOCOUNT: i64 = 512;
    pub(super) const XACT_ABORT: i64 = 16384;
}

/// The byte stream of a session.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The TLS mode actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Strict,
    Mandatory,
}

/// `auto`'s memory per target (refinement item 3, decision 2): strict
/// seen (no fallback from then on, in memory), and the time until which
/// `mandatory` is used directly after a failed strict attempt. Nothing is
/// persisted: every agent start tries strict first.
#[derive(Default)]
pub(crate) struct TlsChoice {
    inner: Mutex<HashMap<String, Remembered>>,
}

#[derive(Clone, Copy)]
enum Remembered {
    StrictSeen,
    MandatoryUntil(Instant),
}

fn choice_key(target: &TargetConfig) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        target.id,
        target.host.as_deref().unwrap_or_default(),
        target.effective_port().unwrap_or_default()
    )
}

impl TlsChoice {
    fn get(&self, key: &str) -> Option<Remembered> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .copied()
    }

    fn set(&self, key: String, v: Remembered) {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bounded by the declared targets in practice; capped anyway.
        if map.len() >= 4096 && !map.contains_key(&key) {
            map.clear();
        }
        map.insert(key, v);
    }
}

/// What a statement may return.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Shape {
    /// Exactly this many columns (`COLMETADATA` with any other count ends
    /// the statement).
    pub(crate) columns: usize,
    /// At most this many rows: one more ends the statement (L1).
    pub(crate) max_rows: usize,
    /// Bound on the response bytes.
    pub(crate) max_bytes: usize,
    /// PLP cap (0: no `max` column).
    pub(crate) plp_cap: usize,
}

impl Shape {
    pub(crate) const fn rows(columns: usize, max_rows: usize) -> Self {
        Self {
            columns,
            max_rows,
            max_bytes: 8 * 1024 * 1024,
            plp_cap: 0,
        }
    }
}

/// What the caller says after each value or row end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Stop,
}

/// A value or the end of a row.
pub(crate) enum Cell {
    Value(usize, Value),
    RowEnd,
}

/// How a statement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    Complete,
    /// The caller stopped it (budget): `ATTENTION` acknowledged, the
    /// session is still usable.
    Stopped,
}

/// The server, as `LOGINACK` and `SERVERPROPERTY` describe it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServerInfo {
    pub(crate) tds_version: u32,
    pub(crate) loginack_major: u8,
}

/// An authenticated session.
pub(crate) struct Session {
    io: Box<dyn Io>,
    reasm: tds::Reassembly,
    buf: Vec<u8>,
    pos: usize,
    dec: Decoder,
    packet_size: usize,
    /// Response bytes of the current statement and their bound.
    msg_bytes: usize,
    msg_cap: usize,
    poisoned: bool,
    last_used: Instant,
    pub(crate) mode: Mode,
    pub(crate) info: ServerInfo,
    pub(crate) spid: Option<i64>,
    /// Statement timeout of this session.
    pub(crate) statement_timeout: Duration,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Opens a session to `target`, choosing the TLS mode (decision 2).
pub(crate) async fn connect(
    target: &TargetConfig,
    tls: &tls::TlsConfigs,
    choice: &TlsChoice,
    statement_timeout: Duration,
) -> Result<Session, SsError> {
    let settings = target.sqlserver_settings();
    let password = target
        .secret
        .read()
        .map_err(|_| SsError::new(FailureCode::AuthenticationFailed, Stage::Secret))?;
    let key = choice_key(target);
    let open = |mode| open(target, tls, mode, &password, statement_timeout);
    match settings.tls {
        SqlserverTlsMode::Strict => open(Mode::Strict).await.map_err(|e| {
            if e.stage == Stage::Tls && e.detail.is_none() {
                e.with_detail(Detail::StrictUnavailable)
            } else {
                e
            }
        }),
        SqlserverTlsMode::Mandatory => open(Mode::Mandatory).await,
        SqlserverTlsMode::Auto => match choice.get(&key) {
            Some(Remembered::StrictSeen) => open(Mode::Strict).await,
            Some(Remembered::MandatoryUntil(t)) if Instant::now() < t => {
                open(Mode::Mandatory).await
            }
            _ => match open(Mode::Strict).await {
                Ok(s) => {
                    choice.set(key, Remembered::StrictSeen);
                    Ok(s)
                }
                // The strict handshake failed before any TDS byte: one
                // fallback, fully verified, and strict again in an hour.
                Err(e) if e.stage == Stage::Tls => {
                    choice.set(
                        key,
                        Remembered::MandatoryUntil(Instant::now() + STRICT_RETRY),
                    );
                    tracing::info!(
                        target_id = %target.id,
                        "strict encryption (TDS 8.0) not available: mandatory encryption used"
                    );
                    open(Mode::Mandatory).await
                }
                Err(e) => Err(e),
            },
        },
    }
}

async fn tcp(target: &TargetConfig) -> Result<tokio::net::TcpStream, SsError> {
    let host = target
        .host
        .as_deref()
        .ok_or(SsError::new(FailureCode::Internal, Stage::Connect))?;
    let port = target.effective_port().unwrap_or(1433);
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| SsError::new(FailureCode::Timeout, Stage::Connect))?
    .map_err(|e| SsError::io(&e, Stage::Connect))?;
    stream
        .set_nodelay(true)
        .map_err(|e| SsError::io(&e, Stage::Connect))?;
    Ok(stream)
}

fn server_name(target: &TargetConfig) -> Result<ServerName<'static>, SsError> {
    let host = target.host.clone().unwrap_or_default();
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    ServerName::try_from(host).map_err(|_| SsError::new(FailureCode::Internal, Stage::Tls))
}

fn tls_error(tls: &tls::TlsConfigs) -> SsError {
    let e = SsError::new(FailureCode::TargetUnreachable, Stage::Tls);
    if tls
        .fallback_seen
        .swap(false, std::sync::atomic::Ordering::Relaxed)
    {
        e.with_detail(Detail::FallbackCertificate)
    } else {
        e
    }
}

async fn open(
    target: &TargetConfig,
    tls: &tls::TlsConfigs,
    mode: Mode,
    password: &str,
    statement_timeout: Duration,
) -> Result<Session, SsError> {
    let name = server_name(target)?;
    let stream = tcp(target).await?;
    let mut session = match mode {
        Mode::Strict => {
            let tls_stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                tokio_rustls::TlsConnector::from(std::sync::Arc::clone(&tls.strict))
                    .connect(name, stream),
            )
            .await
            .map_err(|_| SsError::new(FailureCode::Timeout, Stage::Tls))?
            .map_err(|_| tls_error(tls))?;
            let mut s = Session::new(Box::new(tls_stream), mode, statement_timeout);
            // PRELOGIN inside TLS; its answer is read and not relied on.
            s.prelogin().await?;
            s
        }
        Mode::Mandatory => {
            let mut s = Session::new(Box::new(stream), mode, statement_timeout);
            let enc = s.prelogin().await?;
            if !matches!(enc, Some(tds::encrypt::ON | tds::encrypt::REQ)) {
                return Err(SsError::new(FailureCode::Unsupported, Stage::Tls)
                    .with_detail(Detail::EncryptionRefused));
            }
            let raw = std::mem::replace(
                &mut s.io,
                Box::new(tokio::io::join(tokio::io::empty(), tokio::io::sink())),
            );
            let wrapped = PreloginWrap::new(raw);
            let mut tls_stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                tokio_rustls::TlsConnector::from(std::sync::Arc::clone(&tls.mandatory))
                    .connect(name, wrapped),
            )
            .await
            .map_err(|_| SsError::new(FailureCode::Timeout, Stage::Tls))?
            .map_err(|_| tls_error(tls))?;
            tls_stream.get_mut().0.pass_through();
            s.io = Box::new(tls_stream);
            s
        }
    };
    session.login(&target.account, password).await?;
    session.setup().await?;
    Ok(session)
}

impl Session {
    pub(crate) fn new(io: Box<dyn Io>, mode: Mode, statement_timeout: Duration) -> Self {
        Self {
            io,
            reasm: tds::Reassembly::default(),
            buf: Vec::new(),
            pos: 0,
            dec: Decoder::default(),
            packet_size: tds::DEFAULT_PACKET,
            msg_bytes: 0,
            msg_cap: PRELOGIN_MESSAGE,
            poisoned: false,
            last_used: Instant::now(),
            mode,
            info: ServerInfo::default(),
            spid: None,
            statement_timeout,
        }
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.last_used.elapsed() >= STALE_AFTER
    }

    /// Closes the connection (the server ends whatever ran on it).
    pub(crate) async fn close(mut self) {
        let _ = ::tokio::time::timeout(Duration::from_secs(1), self.io.shutdown()).await;
    }

    async fn send(&mut self, ptype: u8, payload: &[u8], stage: Stage) -> Result<(), SsError> {
        let mut framed = tds::frame(ptype, payload, self.packet_size);
        let deadline = Instant::now() + CONNECT_TIMEOUT.max(self.statement_timeout);
        let r = ::tokio::time::timeout_at(deadline.into(), async {
            self.io.write_all(&framed).await?;
            self.io.flush().await
        })
        .await;
        framed.zeroize();
        match r {
            Ok(Ok(())) => {
                self.last_used = Instant::now();
                Ok(())
            }
            Ok(Err(e)) => {
                self.poisoned = true;
                Err(SsError::io(&e, stage))
            }
            Err(_) => {
                self.poisoned = true;
                Err(SsError::new(FailureCode::Timeout, stage))
            }
        }
    }

    /// Reads more bytes (one cancel-safe `read`) into the payload buffer.
    async fn fill(&mut self, deadline: Instant, stage: Stage) -> Result<(), SsError> {
        let mut tmp = [0u8; 16 * 1024];
        let n = match ::tokio::time::timeout_at(deadline.into(), self.io.read(&mut tmp)).await {
            Err(_) => return Err(SsError::new(FailureCode::Timeout, stage)),
            Ok(Err(e)) => {
                self.poisoned = true;
                return Err(SsError::io(&e, stage));
            }
            Ok(Ok(0)) => {
                self.poisoned = true;
                return Err(SsError::new(FailureCode::TargetUnreachable, stage));
            }
            Ok(Ok(n)) => n,
        };
        let chunk = tmp.get(..n).unwrap_or_default();
        self.reasm.push(chunk);
        tmp.zeroize();
        self.msg_bytes = self.msg_bytes.saturating_add(n);
        // During the login the packet size is not confirmed yet.
        let max_packet = if self.info.tds_version == 0 {
            tds::MAX_PACKET
        } else {
            self.packet_size
        };
        if self
            .reasm
            .take(&mut self.buf, max_packet, &[ptype::TABULAR_RESULT])
            .is_err()
        {
            self.poisoned = true;
            return Err(SsError::protocol(stage));
        }
        Ok(())
    }

    /// The next event of the current message; `None` at its end.
    async fn next_event(
        &mut self,
        deadline: Instant,
        stage: Stage,
    ) -> Result<Option<Event>, SsError> {
        loop {
            let rest = self.buf.get(self.pos..).unwrap_or_default();
            match self.dec.next(rest) {
                Err(e) => {
                    self.poisoned = true;
                    tracing::debug!(error = ?e, stage = stage.as_str(), "response refused");
                    return Err(match e {
                        TokenError::Limit => SsError::new(FailureCode::ResourceLimit, stage),
                        _ => SsError::protocol(stage),
                    });
                }
                Ok(Some((ev, n))) => {
                    self.pos += n;
                    if self.pos > 64 * 1024 && self.pos * 2 > self.buf.len() {
                        self.buf.get_mut(..self.pos).map(Zeroize::zeroize);
                        self.buf.drain(..self.pos);
                        self.pos = 0;
                    }
                    if let Some(ev) = ev {
                        return Ok(Some(ev));
                    }
                }
                Ok(None) => {
                    let left = self.buf.len() - self.pos;
                    if self.reasm.eom {
                        if left == 0 && self.dec.at_token() {
                            self.reasm.next_message();
                            self.buf.zeroize();
                            self.buf.clear();
                            self.pos = 0;
                            // Packets of a following message already read.
                            if self.reasm.pending() > 0
                                && self
                                    .reasm
                                    .take(&mut self.buf, self.packet_size, &[ptype::TABULAR_RESULT])
                                    .is_err()
                            {
                                self.poisoned = true;
                                return Err(SsError::protocol(stage));
                            }
                            return Ok(None);
                        }
                        self.poisoned = true;
                        return Err(SsError::protocol(stage));
                    }
                    if left > crate::token::MAX_PENDING
                        || self.reasm.pending() > crate::token::MAX_PENDING
                    {
                        self.poisoned = true;
                        return Err(SsError::new(FailureCode::ResourceLimit, stage));
                    }
                    if self.msg_bytes > self.msg_cap {
                        // A bound of the statement: stopped by the caller.
                        return Err(SsError::new(FailureCode::ResourceLimit, stage));
                    }
                    self.fill(deadline, stage).await?;
                }
            }
        }
    }

    /// `PRELOGIN`: the `ENCRYPTION` value of the response.
    async fn prelogin(&mut self) -> Result<Option<u8>, SsError> {
        let payload = tds::prelogin();
        self.send(ptype::PRELOGIN, &payload, Stage::Tls).await?;
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        self.msg_bytes = 0;
        self.msg_cap = PRELOGIN_MESSAGE;
        // The response is one message of option bytes, not tokens.
        while !self.reasm.eom {
            self.fill(deadline, Stage::Tls).await?;
            if self.msg_bytes > PRELOGIN_MESSAGE {
                self.poisoned = true;
                return Err(SsError::protocol(Stage::Tls));
            }
        }
        let enc = tds::prelogin_encryption(&self.buf);
        self.buf.clear();
        self.pos = 0;
        self.reasm.next_message();
        Ok(enc)
    }

    async fn login(&mut self, user: &str, password: &str) -> Result<(), SsError> {
        let msg = tds::login7(user, password)
            .map_err(|_| SsError::new(FailureCode::AuthenticationFailed, Stage::Auth))?;
        self.send(ptype::LOGIN7, &msg, Stage::Auth).await?;
        drop(msg);
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        self.msg_bytes = 0;
        self.msg_cap = LOGIN_MESSAGE;
        let mut ack = None;
        let mut error = None;
        while let Some(ev) = self.next_event(deadline, Stage::Auth).await? {
            match ev {
                Event::LoginAck {
                    tds_version, major, ..
                } => ack = Some((tds_version, major)),
                Event::Error { number, class, .. } if class >= 11 => {
                    error.get_or_insert(SsError::server(number, class, Stage::Auth));
                }
                Event::PacketSize(n) => self.set_packet_size(n, Stage::Auth)?,
                Event::Routing => {
                    self.poisoned = true;
                    return Err(SsError::new(FailureCode::Unsupported, Stage::Auth)
                        .with_detail(Detail::Routing));
                }
                Event::Transaction => {
                    self.poisoned = true;
                    return Err(SsError::new(FailureCode::Unsupported, Stage::Auth)
                        .with_detail(Detail::Transaction));
                }
                Event::ColMetadata(_) | Event::RowStart | Event::Value(..) | Event::RowEnd => {
                    self.poisoned = true;
                    return Err(SsError::protocol(Stage::Auth));
                }
                _ => {}
            }
        }
        if let Some(e) = error {
            self.poisoned = true;
            return Err(e);
        }
        match ack {
            Some((v, major)) if v >= tds::TDS_74 => {
                self.info = ServerInfo {
                    tds_version: v,
                    loginack_major: major,
                };
                Ok(())
            }
            _ => {
                self.poisoned = true;
                Err(SsError::new(FailureCode::Unsupported, Stage::Auth)
                    .with_detail(Detail::UnsupportedServer))
            }
        }
    }

    fn set_packet_size(&mut self, n: usize, stage: Stage) -> Result<(), SsError> {
        if !(tds::MIN_PACKET..=tds::MAX_PACKET).contains(&n) {
            self.poisoned = true;
            return Err(SsError::protocol(stage));
        }
        self.packet_size = n;
        Ok(())
    }

    /// The constant session settings, read back and checked.
    async fn setup(&mut self) -> Result<(), SsError> {
        self.run(
            SESSION_SETTINGS,
            Stage::SessionSetup,
            Shape::rows(0, 0),
            |_| Flow::Continue,
        )
        .await?;
        let rows = self
            .rows(SESSION_READBACK, Stage::SessionSetup, Shape::rows(4, 1))
            .await?;
        let row = rows.first().ok_or(SsError::protocol(Stage::SessionSetup))?;
        let int = |i: usize| row.get(i).and_then(Value::as_int);
        let options = int(0).unwrap_or(0);
        let ok = options & opt::IMPLICIT_TRANSACTIONS == 0
            && options & opt::XACT_ABORT != 0
            && options & opt::QUOTED_IDENTIFIER != 0
            && options & opt::ANSI_NULLS != 0
            && options & opt::NOCOUNT == 0
            && int(1) == Some(2000)
            // 1: READ UNCOMMITTED.
            && int(3) == Some(1);
        if !ok {
            self.poisoned = true;
            return Err(SsError::new(FailureCode::Internal, Stage::SessionSetup));
        }
        self.spid = int(2);
        Ok(())
    }

    /// Runs a statement and returns its rows (at most `shape.max_rows`).
    pub(crate) async fn rows(
        &mut self,
        sql: &str,
        stage: Stage,
        shape: Shape,
    ) -> Result<Vec<Vec<Value>>, SsError> {
        let mut rows = Vec::new();
        let mut row = Vec::with_capacity(shape.columns);
        self.run(sql, stage, shape, |cell| {
            match cell {
                Cell::Value(_, v) => row.push(v),
                Cell::RowEnd => rows.push(std::mem::take(&mut row)),
            }
            Flow::Continue
        })
        .await?;
        Ok(rows)
    }

    /// Runs one statement of the closed set as a `SQLBatch`, handing each
    /// value to `on_cell`. Exactly one result of `shape.columns` columns
    /// (none for `columns: 0`), at most `shape.max_rows` rows.
    pub(crate) async fn run(
        &mut self,
        sql: &str,
        stage: Stage,
        shape: Shape,
        on_cell: impl FnMut(Cell) -> Flow,
    ) -> Result<Ended, SsError> {
        // The deny-list of refinement item 7 (M4), at run time too.
        if !crate::sql::checked(sql) {
            tracing::error!(stage = stage.as_str(), "statement refused by the deny-list");
            return Err(SsError::new(FailureCode::Internal, stage));
        }
        let payload =
            tds::sql_batch(sql).map_err(|_| SsError::new(FailureCode::Internal, stage))?;
        self.request(ptype::SQL_BATCH, &payload, stage, shape, on_cell)
            .await
    }

    /// Runs `sp_executesql` with a constant text and typed parameters.
    #[allow(dead_code)]
    pub(crate) async fn rpc(
        &mut self,
        text: &str,
        params: &[tds::Param],
        stage: Stage,
        shape: Shape,
        on_cell: impl FnMut(Cell) -> Flow,
    ) -> Result<Ended, SsError> {
        let payload = tds::rpc_executesql(text, params)
            .map_err(|_| SsError::new(FailureCode::Internal, stage))?;
        self.request(ptype::RPC, &payload, stage, shape, on_cell)
            .await
    }

    async fn request(
        &mut self,
        ptype: u8,
        payload: &[u8],
        stage: Stage,
        shape: Shape,
        mut on_cell: impl FnMut(Cell) -> Flow,
    ) -> Result<Ended, SsError> {
        if self.poisoned {
            return Err(SsError::new(FailureCode::Internal, stage));
        }
        self.dec.limits = Limits {
            max_columns: shape.columns.max(1),
            plp_cap: shape.plp_cap,
        };
        self.dec.discard = false;
        self.msg_bytes = 0;
        self.msg_cap = shape.max_bytes;
        self.send(ptype, payload, stage).await?;
        let deadline = Instant::now() + self.statement_timeout;
        let mut results = 0usize;
        let mut rows = 0usize;
        let mut error: Option<SsError> = None;
        let mut stop: Option<Result<Ended, SsError>> = None;
        loop {
            let ev = match self.next_event(deadline, stage).await {
                Ok(Some(ev)) => ev,
                Ok(None) => break,
                Err(e) if !self.poisoned => {
                    // Deadline or message bound: cancel.
                    stop = Some(Err(e));
                    break;
                }
                Err(e) => return Err(e),
            };
            match ev {
                Event::ColMetadata(n) => {
                    results += 1;
                    if results > 1 || n != shape.columns {
                        stop = Some(Err(SsError::protocol(stage)));
                        break;
                    }
                }
                Event::RowStart => {
                    rows += 1;
                    if rows > shape.max_rows {
                        stop = Some(Err(SsError::new(FailureCode::ResourceLimit, stage)));
                        break;
                    }
                }
                Event::Value(c, v) => {
                    if on_cell(Cell::Value(c, v)) == Flow::Stop {
                        stop = Some(Ok(Ended::Stopped));
                        break;
                    }
                }
                Event::RowEnd => {
                    if on_cell(Cell::RowEnd) == Flow::Stop {
                        stop = Some(Ok(Ended::Stopped));
                        break;
                    }
                }
                Event::Error { number, class, .. } if class >= 11 => {
                    if class >= 20 {
                        self.poisoned = true;
                    }
                    error.get_or_insert(SsError::server(number, class, stage));
                }
                Event::PacketSize(n) => self.set_packet_size(n, stage)?,
                Event::Routing => {
                    self.poisoned = true;
                    return Err(
                        SsError::new(FailureCode::Unsupported, stage).with_detail(Detail::Routing)
                    );
                }
                Event::Transaction => {
                    self.poisoned = true;
                    return Err(SsError::new(FailureCode::Unsupported, stage)
                        .with_detail(Detail::Transaction));
                }
                _ => {}
            }
        }
        if let Some(outcome) = stop {
            self.cancel(stage).await;
            return outcome;
        }
        self.last_used = Instant::now();
        match error {
            Some(e) => Err(e),
            None if results == 0 && shape.columns > 0 => Err(SsError::protocol(stage)),
            None => Ok(Ended::Complete),
        }
    }

    /// Sends `ATTENTION` and reads until its acknowledgement (`DONE` with
    /// `DONE_ATTN`) within [`ATTENTION_WAIT`]; otherwise poisons the
    /// session (closed by its owner, the server then ends the batch).
    pub(crate) async fn cancel(&mut self, stage: Stage) {
        if self.poisoned {
            return;
        }
        let attention = tds::attention();
        if let Err(e) = ::tokio::time::timeout(ATTENTION_WAIT, async {
            self.io.write_all(&attention).await?;
            self.io.flush().await
        })
        .await
        .unwrap_or(Err(std::io::ErrorKind::TimedOut.into()))
        {
            tracing::debug!(error = %e.kind(), "attention not sent");
            self.poisoned = true;
            return;
        }
        self.dec.discard = true;
        self.msg_cap = usize::MAX;
        let deadline = Instant::now() + ATTENTION_WAIT;
        loop {
            match self.next_event(deadline, stage).await {
                Ok(Some(Event::Done { status, .. })) if status & done::ATTN != 0 => break,
                Ok(_) => {}
                Err(_) => {
                    self.poisoned = true;
                    break;
                }
            }
        }
        self.dec.discard = false;
        // The rest of the acknowledging message, if any.
        if !self.poisoned && !(self.reasm.eom && self.pos >= self.buf.len()) {
            while let Ok(Some(_)) = self.next_event(deadline, stage).await {}
        } else if !self.poisoned {
            self.reasm.next_message();
            self.buf.clear();
            self.pos = 0;
        }
        tracing::debug!(poisoned = self.poisoned, "statement cancelled");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::token::{tests::build, tok};

    /// A session over an in-memory pipe whose other end replays scripted
    /// server messages (the TLS layer is tested apart).
    pub(crate) fn scripted(
        responses: Vec<Vec<u8>>,
    ) -> (Session, ::tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let (client, server) = ::tokio::io::duplex(1 << 20);
        let handle = ::tokio::spawn(crate::fake::serve(server, responses));
        let mut s = Session::new(Box::new(client), Mode::Mandatory, Duration::from_secs(2));
        s.info.tds_version = tds::TDS_74;
        (s, handle)
    }

    fn message(tokens: &[Vec<u8>]) -> Vec<u8> {
        tokens.concat()
    }

    #[::tokio::test]
    async fn rows_and_error_numbers() {
        let mut ok = build::colmeta_int(&["a"]);
        ok.extend(build::row_int(&[Some(7)]));
        ok.extend(build::done(tok::DONE, done::COUNT, 1));
        let err = message(&[
            build::error(229, 14, "The SELECT permission was denied on 'SECRET'"),
            build::done(tok::DONE, done::ERROR, 0),
        ]);
        let (mut s, _h) = scripted(vec![ok, err]);
        let rows = s
            .rows("SELECT 7", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap();
        assert_eq!(rows, vec![vec![Value::Int(7)]]);
        let e = s
            .rows("SELECT x", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap_err();
        assert_eq!(e.number, Some(229));
        assert_eq!(e.code, FailureCode::PermissionDenied);
        assert!(!s.is_poisoned());
    }

    #[::tokio::test]
    async fn extra_rows_end_the_statement_with_attention() {
        let mut many = build::colmeta_int(&["a"]);
        for i in 0..3 {
            many.extend(build::row_int(&[Some(i)]));
        }
        many.extend(build::done(tok::DONE, done::COUNT, 3));
        let ack = build::done(tok::DONE, done::ATTN, 0);
        let mut next = build::colmeta_int(&["a"]);
        next.extend(build::row_int(&[Some(1)]));
        next.extend(build::done(tok::DONE, 0, 1));
        let (mut s, h) = scripted(vec![many, ack, next]);
        let e = s
            .rows("SELECT a", Stage::Check, Shape::rows(1, 2))
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::ResourceLimit);
        assert!(!s.is_poisoned(), "attention acknowledged");
        // The session is still in step.
        let rows = s
            .rows("SELECT 1", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        drop(s);
        let sent = h.await.unwrap();
        assert!(sent.iter().any(|m| m.first() == Some(&ptype::ATTENTION)));
    }

    #[::tokio::test]
    async fn routing_and_transactions_end_the_session() {
        let routing = message(&[build::envchange(20, &[0, 0]), build::done(tok::DONE, 0, 0)]);
        let (mut s, _h) = scripted(vec![routing]);
        let e = s
            .rows("SELECT 1", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap_err();
        assert_eq!(e.detail, Some(Detail::Routing));
        assert!(s.is_poisoned());
        let tx = message(&[
            build::envchange(8, &[8, 1, 2, 3, 4, 5, 6, 7, 8, 0]),
            build::done(tok::DONE, 0, 0),
        ]);
        let (mut s, _h) = scripted(vec![tx]);
        let e = s
            .rows("SELECT 1", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap_err();
        assert_eq!(e.detail, Some(Detail::Transaction));
    }

    #[::tokio::test]
    async fn deadline_sends_attention() {
        // The server answers nothing to the statement, then acknowledges.
        let (mut s, h) = scripted(vec![
            crate::fake::SILENT.to_vec(),
            build::done(tok::DONE, done::ATTN, 0),
        ]);
        s.statement_timeout = Duration::from_millis(200);
        let e = s
            .rows("SELECT 1", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::Timeout);
        assert!(!s.is_poisoned());
        drop(s);
        let sent = h.await.unwrap();
        assert_eq!(sent.last().and_then(|m| m.first()), Some(&ptype::ATTENTION));
    }

    #[::tokio::test]
    async fn login_failure_and_lockout() {
        let fail = message(&[
            build::error(
                18486,
                14,
                "Login failed for user 'x' because the account is locked",
            ),
            build::done(tok::DONE, done::ERROR, 0),
        ]);
        let (mut s, _h) = scripted(vec![fail]);
        s.info.tds_version = 0;
        let e = s.login("databastion", "pw").await.unwrap_err();
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
        assert_eq!(e.detail, Some(Detail::LoginLockedOut));
        let mut ok = build::envchange(4, &{
            let mut v = build::b_varchar("8000");
            v.extend(build::b_varchar("4096"));
            v
        });
        ok.extend(build::loginack(16, 0, 4305));
        ok.extend(build::done(tok::DONE, 0, 0));
        let (mut s, _h) = scripted(vec![ok]);
        s.info.tds_version = 0;
        s.login("databastion", "pw").await.unwrap();
        assert_eq!(s.packet_size, 8000);
        assert_eq!(s.info.loginack_major, 16);
    }
}
