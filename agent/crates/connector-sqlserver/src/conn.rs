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

use std::collections::{HashMap, HashSet};
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

/// Bound of the TLS / TCP shutdown of a close.
const CLOSE_SHUTDOWN: Duration = Duration::from_secs(1);
/// What a clean close may take at most (its settle, then its shutdown): a
/// caller bounding a session's work by a deadline stops that work this
/// long before it, so that the close itself is not cancelled (#264 review
/// L1).
pub(crate) const CLOSE_ROOM: Duration = crate::audit::own::CLEAN_CLOSE_SETTLE
    .saturating_add(CLOSE_SHUTDOWN)
    .saturating_add(Duration::from_millis(100));

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
/// `@@SPID` and the session's isolation level; and the session's own
/// identity for the Audit own-session rule (decision 6, H1): the server's
/// UTC time, the time since its `login_time` (both in µs; `login_time` is
/// local time, so the difference is taken on the server's local clock),
/// and the client address the server sees. A session sees its own
/// `sys.dm_exec_sessions` row without `VIEW SERVER STATE` (measured).
pub(crate) const SESSION_READBACK: &str = "SELECT CONVERT(int, @@OPTIONS), \
CONVERT(int, @@LOCK_TIMEOUT), CONVERT(int, @@SPID), CONVERT(int, (SELECT \
transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID)), \
CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', SYSUTCDATETIME())), CONVERT(bigint, (SELECT \
DATEDIFF_BIG(microsecond, login_time, SYSDATETIME()) FROM sys.dm_exec_sessions WHERE session_id = \
@@SPID)), CONVERT(nvarchar(48), CONNECTIONPROPERTY('client_net_address'))";

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

/// `auto`'s memory per target (decision 2, refinement item 3): "strict
/// seen" (no fallback from then on), kept in memory **and persisted** in
/// the agent's `state_dir` with the declared host and port (security
/// review M1); and the time until which `mandatory` is used directly after
/// a failed strict attempt, in memory only, so every agent start tries
/// strict first.
#[derive(Default)]
pub(crate) struct TlsChoice {
    inner: Mutex<HashMap<String, Remembered>>,
    /// Targets whose mark was already cleared by this process (review L2:
    /// once per process and target, not at every connection attempt;
    /// reset when `auto` records a new strict session).
    cleared: Mutex<HashSet<String>>,
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

/// Directory of the persisted "strict seen" marks, under `state_dir`.
pub(crate) const STRICT_SEEN_DIR: &str = "sqlserver-strict-seen";

/// The persisted mark's content: the declared host and port; a mark for
/// another host or port (the target was changed) is not "seen".
fn strict_seen_mark(target: &TargetConfig) -> Vec<u8> {
    format!(
        "{}\n{}\n",
        target.host.as_deref().unwrap_or_default(),
        target.effective_port().unwrap_or_default()
    )
    .into_bytes()
}

/// Whether the target's persisted mark says "strict seen" (fail safe:
/// absent, unreadable or for another endpoint is "not seen").
pub(crate) fn persisted_strict_seen(target: &TargetConfig) -> bool {
    target.state_dir().is_some_and(|dir| {
        databastion_core::local_state::load(&dir.join(STRICT_SEEN_DIR), &target.id)
            .is_some_and(|m| m == strict_seen_mark(target))
    })
}

fn persist_strict_seen(target: &TargetConfig) {
    let Some(dir) = target.state_dir() else {
        return;
    };
    if let Err(e) = databastion_core::local_state::store(
        &dir.join(STRICT_SEEN_DIR),
        &target.id,
        &strict_seen_mark(target),
    ) {
        tracing::warn!(target_id = %target.id, error = %e.kind(), "strict-seen mark not persisted");
    }
}

/// Clears the target's "strict seen" mark, in memory and on disk, when its
/// `tls` setting is not `auto` (decision 2: the mark is cleared by
/// changing the target's host, port or `tls` setting; re-review R4). A
/// later return to `auto` tries strict first again, with the one
/// fallback.
fn clear_strict_seen(target: &TargetConfig, choice: &TlsChoice, key: &str) {
    if !choice.first_clear(key) {
        return;
    }
    choice.remove(key);
    let Some(dir) = target.state_dir() else {
        return;
    };
    match databastion_core::local_state::remove(&dir.join(STRICT_SEEN_DIR), &target.id) {
        Ok(true) => tracing::info!(
            target_id = %target.id,
            "tls is not auto: strict-seen mark cleared"
        ),
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(target_id = %target.id, error = %e.kind(), "strict-seen mark not cleared");
        }
    }
}

/// Records a completed strict session of an `auto` target: in memory, on
/// disk, and so that a later non-`auto` setting clears the new mark again.
fn remember_strict_seen(target: &TargetConfig, choice: &TlsChoice, key: String) {
    choice
        .cleared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&key);
    choice.set(key, Remembered::StrictSeen);
    persist_strict_seen(target);
}

impl TlsChoice {
    /// Whether this is the first clear of `key` in this process (then
    /// recorded).
    fn first_clear(&self, key: &str) -> bool {
        let mut cleared = self
            .cleared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cleared.contains(key) {
            return false;
        }
        // Bounded by the declared targets in practice; capped anyway.
        if cleared.len() >= 4096 {
            cleared.clear();
        }
        cleared.insert(key.to_owned());
        true
    }

    fn remove(&self, key: &str) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

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
    /// The session's registration as one of the agent's own (decision 6).
    pub(crate) own: Option<crate::audit::own::Handle>,
    /// A request is in flight (a drop then loses the session).
    in_flight: bool,
    /// Tests only: the session may send texts off the allow-list.
    #[cfg(test)]
    pub(crate) any_text: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.buf.zeroize();
        if let Some(h) = self.own.as_mut() {
            // Not closed through `close()`: lost (decision 6).
            h.end(true, self.statement_timeout + crate::audit::own::LOST_GRACE);
        }
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
    let key = choice_key(target);
    if settings.tls != SqlserverTlsMode::Auto {
        clear_strict_seen(target, choice, &key);
    }
    let password = target
        .secret
        .read()
        .map_err(|_| SsError::new(FailureCode::AuthenticationFailed, Stage::Secret))?;
    let open = |mode| open(target, tls, mode, &password, statement_timeout);
    match settings.tls {
        SqlserverTlsMode::Strict => open(Mode::Strict).await.map_err(|e| {
            if e.detail == Some(Detail::HandshakeFailed) {
                e.with_detail(Detail::StrictUnavailable)
            } else {
                e
            }
        }),
        SqlserverTlsMode::Mandatory => open(Mode::Mandatory).await,
        SqlserverTlsMode::Auto => match choice
            .get(&key)
            .or_else(|| persisted_strict_seen(target).then_some(Remembered::StrictSeen))
        {
            Some(Remembered::StrictSeen) => {
                choice.set(key, Remembered::StrictSeen);
                open(Mode::Strict).await
            }
            Some(Remembered::MandatoryUntil(t)) if Instant::now() < t => {
                open(Mode::Mandatory).await
            }
            _ => match open(Mode::Strict).await {
                Ok(s) => {
                    remember_strict_seen(target, choice, key);
                    Ok(s)
                }
                // The strict handshake failed before any TDS byte (I/O,
                // alert, protocol; never a certificate error, never after
                // a completed handshake): one fallback, fully verified,
                // and strict again in an hour (security review M1).
                Err(e) if e.detail == Some(Detail::HandshakeFailed) => {
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

/// Classifies a TLS handshake failure: the fallback certificate, another
/// certificate error, or a handshake failure (I/O, alert, protocol).
fn tls_error(tls: &tls::TlsConfigs, err: &std::io::Error) -> SsError {
    let e = SsError::new(FailureCode::TargetUnreachable, Stage::Tls);
    if tls
        .fallback_seen
        .swap(false, std::sync::atomic::Ordering::Relaxed)
    {
        return e.with_detail(Detail::FallbackCertificate);
    }
    if is_certificate_error(err) {
        e.with_detail(Detail::CertificateRejected)
    } else {
        e.with_detail(Detail::HandshakeFailed)
    }
}

/// Whether a handshake I/O error carries a rustls certificate error.
pub(crate) fn is_certificate_error(err: &std::io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|r| {
            matches!(
                r,
                rustls::Error::InvalidCertificate(_)
                    | rustls::Error::NoCertificatesPresented
                    | rustls::Error::InvalidCertRevocationList(_)
            )
        })
}

fn handshake_timeout() -> SsError {
    SsError::new(FailureCode::Timeout, Stage::Tls).with_detail(Detail::HandshakeFailed)
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
            .map_err(|_| handshake_timeout())?
            .map_err(|e| tls_error(tls, &e))?;
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
            .map_err(|_| handshake_timeout())?
            .map_err(|e| tls_error(tls, &e))?;
            tls_stream.get_mut().0.pass_through();
            s.io = Box::new(tls_stream);
            s.reset_stream();
            s
        }
    };
    session.login(&target.account, password).await?;
    let identity = session.setup().await?;
    session.own = Some(crate::audit::own::opened(
        &target.id,
        identity.spid,
        identity.server_us,
        identity.since_login_us,
        identity.addr,
        identity.at,
    ));
    Ok(session)
}

/// What the read-back tells of the session itself (decision 6).
struct Identity {
    spid: i64,
    server_us: i64,
    since_login_us: i64,
    addr: Option<std::net::IpAddr>,
    /// The agent's instant before the read-back was sent.
    at: Instant,
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
            own: None,
            in_flight: false,
            #[cfg(test)]
            any_text: false,
        }
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.last_used.elapsed() >= STALE_AFTER
    }

    /// Closes the connection (the server ends whatever ran on it). A
    /// session with nothing in flight and not poisoned ends cleanly (no
    /// grace, decision 6, re-review N4); otherwise it is lost. A clean
    /// close first waits, idle, until
    /// [`crate::audit::own::CLEAN_CLOSE_SETTLE`] after the last answer
    /// (`last_used`: the end of the last response read, or of the
    /// `ATTENTION` acknowledgement of a cancelled statement), so that no
    /// record of a statement it sent is stamped after its end.
    ///
    /// The future must run to its end for the close to be clean: dropped
    /// during the settle or the shutdown (a caller's deadline), the
    /// session is dropped, hence recorded as lost with the lost
    /// connection's grace (fail closed, #264 review L1). A caller with a
    /// deadline leaves [`CLOSE_ROOM`] for it (`check::check`).
    pub(crate) async fn close(mut self) {
        let lost = self.poisoned || self.in_flight;
        let grace = self.statement_timeout + crate::audit::own::LOST_GRACE;
        let wait = self.settle_wait();
        if !wait.is_zero() {
            ::tokio::time::sleep(wait).await;
        }
        let _ = ::tokio::time::timeout(CLOSE_SHUTDOWN, self.io.shutdown()).await;
        if let Some(h) = self.own.as_mut() {
            h.end(lost, grace);
        }
    }

    /// How long a close waits before it shuts the connection down: until
    /// [`crate::audit::own::CLEAN_CLOSE_SETTLE`] after the last answer for
    /// a clean close of one of the agent's own sessions; nothing for a
    /// lost one (poisoned or in flight: it keeps its grace instead) or for
    /// a session idle for longer than that already.
    fn settle_wait(&self) -> Duration {
        if self.poisoned || self.in_flight || self.own.is_none() {
            return Duration::ZERO;
        }
        crate::audit::own::CLEAN_CLOSE_SETTLE.saturating_sub(self.last_used.elapsed())
    }

    /// Grants an Audit credit for `text` on this session (decision 6, L5):
    /// called right before a sampling statement, a CAS ticket count or an
    /// Audit poll is sent.
    pub(crate) fn credit(&self, text: &str) {
        if let Some(h) = &self.own {
            h.credit(text, self.statement_timeout, None);
        }
    }

    /// Grants the credit of an Audit poll (decision 6).
    pub(crate) fn credit_poll(&self, text: &str, kind: crate::audit::own::PollKind) {
        if let Some(h) = &self.own {
            h.credit(text, self.statement_timeout, Some(kind));
        }
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
        // Nothing may follow the response (security review H1): in
        // `mandatory` mode it travels in clear, and bytes after its `EOM`
        // would otherwise be parsed later as if they came through TLS.
        if self.reasm.pending() > 0 {
            self.poisoned = true;
            return Err(SsError::protocol(Stage::Tls));
        }
        let enc = tds::prelogin_encryption(&self.buf);
        self.reset_stream();
        Ok(enc)
    }

    /// Drops every buffered byte and decoder state: called whenever the
    /// I/O changes (the TLS upgrade), so nothing read before it is
    /// parsed after it (security review H1).
    fn reset_stream(&mut self) {
        self.buf.zeroize();
        self.buf.clear();
        self.pos = 0;
        self.reasm = tds::Reassembly::default();
        self.dec = Decoder::default();
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
    async fn setup(&mut self) -> Result<Identity, SsError> {
        self.run(
            SESSION_SETTINGS,
            Stage::SessionSetup,
            Shape::rows(0, 0),
            |_| Flow::Continue,
        )
        .await?;
        let at = Instant::now();
        let rows = self
            .rows(SESSION_READBACK, Stage::SessionSetup, Shape::rows(7, 1))
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
        let (Some(spid), Some(server_us), Some(since_login_us)) = (int(2), int(4), int(5)) else {
            self.poisoned = true;
            return Err(SsError::protocol(Stage::SessionSetup));
        };
        // Only an IP literal counts (decision 6).
        let addr = row
            .get(6)
            .and_then(Value::as_text)
            .and_then(|a| a.parse::<std::net::IpAddr>().ok());
        Ok(Identity {
            spid,
            server_us,
            since_login_us,
            addr,
            at,
        })
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

    /// The run-time checks of a text before it is sent: the deny-list of
    /// refinement item 7 (M4), then the reviewed allow-list
    /// (`sql::STATEMENTS`, end-of-phase-9 review L1). Either refusal is an
    /// agent bug: nothing is sent, `internal` (fail closed). Only a test
    /// session (`any_text`, the integration tests' `sa` and foreign
    /// sessions, the unit tests' scripted servers) skips the allow-list.
    fn vet(&self, text: &str, stage: Stage) -> Result<(), SsError> {
        if !crate::sql::checked(text) {
            tracing::error!(stage = stage.as_str(), "statement refused by the deny-list");
            return Err(SsError::new(FailureCode::Internal, stage));
        }
        #[cfg(test)]
        let any = self.any_text;
        #[cfg(not(test))]
        let any = false;
        if !any && !crate::sql::allowed(text) {
            tracing::error!(
                stage = stage.as_str(),
                "statement refused: not on the allow-list"
            );
            return Err(SsError::new(FailureCode::Internal, stage));
        }
        Ok(())
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
        // The deny-list of refinement item 7 (M4) and the allow-list, at
        // run time too.
        self.vet(sql, stage)?;
        let payload =
            tds::sql_batch(sql).map_err(|_| SsError::new(FailureCode::Internal, stage))?;
        if let Some(h) = self.own.as_mut() {
            h.sent(sql);
        }
        self.request(ptype::SQL_BATCH, &payload, stage, shape, on_cell)
            .await
    }

    /// Runs `sp_executesql` with a constant text and typed parameters.
    pub(crate) async fn rpc(
        &mut self,
        text: &str,
        params: &[tds::Param],
        stage: Stage,
        shape: Shape,
        on_cell: impl FnMut(Cell) -> Flow,
    ) -> Result<Ended, SsError> {
        self.vet(text, stage)?;
        let payload = tds::rpc_executesql(text, params)
            .map_err(|_| SsError::new(FailureCode::Internal, stage))?;
        if let Some(h) = self.own.as_mut() {
            h.sent(text);
        }
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
        // A fresh decoder per request: no column metadata of an earlier
        // statement can describe this one's rows (review L3).
        self.dec = Decoder::new(Limits {
            max_columns: shape.columns.max(1),
            plp_cap: shape.plp_cap,
        });
        self.dec.discard = false;
        self.msg_bytes = 0;
        self.msg_cap = shape.max_bytes;
        self.in_flight = true;
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
                    // A row before this statement's COLMETADATA (L3).
                    if results == 0 {
                        stop = Some(Err(SsError::protocol(stage)));
                        break;
                    }
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
            self.in_flight = self.poisoned;
            // The acknowledgement is the statement's last answer: a clean
            // close settles from it, not from the send (#264 review L2).
            self.last_used = Instant::now();
            return outcome;
        }
        self.in_flight = false;
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
            // Any error here leaves the stream out of step: poisoned
            // (review L2).
            loop {
                match self.next_event(deadline, stage).await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        self.poisoned = true;
                        break;
                    }
                }
            }
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
        // Scripted servers answer any text (the allow-list has its own
        // test, `texts_off_the_allow_list_are_never_sent`).
        s.any_text = true;
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

    /// Review L3: the column metadata of a previous statement never
    /// describes the next statement's rows.
    #[::tokio::test]
    async fn rows_need_this_statements_metadata() {
        let mut ok = build::colmeta_int(&["a"]);
        ok.extend(build::row_int(&[Some(7)]));
        ok.extend(build::done(tok::DONE, done::COUNT, 1));
        let mut bare = build::row_int(&[Some(8)]);
        bare.extend(build::done(tok::DONE, done::COUNT, 1));
        let (mut s, _h) = scripted(vec![ok, bare]);
        s.rows("SELECT 7", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap();
        assert!(
            s.rows("SELECT 8", Stage::Check, Shape::rows(1, 1))
                .await
                .is_err()
        );
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

    /// Security review H1: bytes after the cleartext `PRELOGIN` response
    /// are refused, never kept for after the TLS upgrade.
    #[::tokio::test]
    async fn bytes_after_the_prelogin_response_are_refused() {
        let (client, mut server) = ::tokio::io::duplex(1 << 16);
        let mut s = Session::new(Box::new(client), Mode::Mandatory, Duration::from_secs(2));
        let srv = ::tokio::spawn(async move {
            use ::tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut req = [0u8; 512];
            let _ = server.read(&mut req).await.unwrap();
            // The response, then a forged LOGINACK in the same write.
            let mut bytes = tds::frame(ptype::TABULAR_RESULT, &tds::prelogin(), 4096);
            let mut forged = build::loginack(16, 0, 1);
            forged.extend(build::done(tok::DONE, 0, 0));
            bytes.extend(tds::frame(ptype::TABULAR_RESULT, &forged, 4096));
            server.write_all(&bytes).await.unwrap();
            server
        });
        let e = s.prelogin().await.unwrap_err();
        assert_eq!(e.stage, Stage::Tls);
        assert!(s.is_poisoned());
        drop(srv.await.unwrap());
        // Without trailing bytes the response is accepted and nothing is
        // left buffered.
        let (client, mut server) = ::tokio::io::duplex(1 << 16);
        let mut s = Session::new(Box::new(client), Mode::Mandatory, Duration::from_secs(2));
        let srv = ::tokio::spawn(async move {
            use ::tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut req = [0u8; 512];
            let _ = server.read(&mut req).await.unwrap();
            let bytes = tds::frame(ptype::TABULAR_RESULT, &tds::prelogin(), 4096);
            server.write_all(&bytes).await.unwrap();
            server
        });
        assert_eq!(s.prelogin().await.unwrap(), Some(tds::encrypt::REQ));
        assert_eq!(s.reasm.pending(), 0);
        assert!(s.buf.is_empty());
        drop(srv.await.unwrap());
    }

    /// Security review M1: only handshake failures fall back; a
    /// certificate error never does.
    #[test]
    fn certificate_errors_are_told_apart() {
        let cert = std::io::Error::other(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(is_certificate_error(&cert));
        let alert = std::io::Error::other(rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure,
        ));
        assert!(!is_certificate_error(&alert));
        assert!(!is_certificate_error(
            &std::io::ErrorKind::UnexpectedEof.into()
        ));
    }

    /// Decision 2 (M1): "strict seen" is persisted per target, private,
    /// bound to the declared host and port, and read fail-safe.
    #[test]
    fn strict_seen_is_persisted_for_the_declared_endpoint() {
        let dir =
            std::env::temp_dir().join(format!("databastion-sqlserver-seen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parse = |host: &str| {
            databastion_core::AgentConfig::parse(&format!(
                "{{console: {{url: \"https://c.example\"}}, state_dir: {}, targets: [{{id: t1, \
                 engine: sqlserver, host: {host}, account: a, secret: {{env: X}}}}]}}",
                dir.display()
            ))
            .unwrap()
            .targets[0]
                .clone()
        };
        let t = parse("db.example");
        assert!(!persisted_strict_seen(&t));
        persist_strict_seen(&t);
        assert!(persisted_strict_seen(&t));
        let mark = dir.join(STRICT_SEEN_DIR).join("t1");
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&mark).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Another host: not seen.
        assert!(!persisted_strict_seen(&parse("other.example")));
        // Unreadable (not private): not seen.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mark, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(!persisted_strict_seen(&t));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-review R4: a target whose `tls` is not `auto` has its mark
    /// cleared, on disk and in memory, at its next connection attempt;
    /// once per process (review L2) until `auto` records a new strict
    /// session.
    #[::tokio::test]
    async fn strict_seen_is_cleared_when_tls_is_not_auto() {
        let dir = std::env::temp_dir().join(format!(
            "databastion-sqlserver-clear-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // The secret is unset: every attempt fails before any connection,
        // after the mark is handled.
        let parse = |tls: &str| {
            databastion_core::AgentConfig::parse(&format!(
                "{{console: {{url: \"https://c.example\"}}, state_dir: {}, targets: [{{id: t1, \
                 engine: sqlserver, host: 127.0.0.1, port: 9, account: a, \
                 secret: {{env: DATABASTION_TEST_SQLSERVER_CLEAR}}, sqlserver: {{tls: {tls}}}}}]}}",
                dir.display()
            ))
            .unwrap()
            .targets[0]
                .clone()
        };
        let ca = crate::fake::other_ca_file();
        let configs = tls::configs(Some(&ca)).unwrap();
        let _ = std::fs::remove_file(&ca);
        let choice = TlsChoice::default();
        for mode in ["mandatory", "strict"] {
            let auto = parse("auto");
            remember_strict_seen(&auto, &choice, choice_key(&auto));
            assert!(persisted_strict_seen(&auto));
            let t = parse(mode);
            let _ = connect(&t, &configs, &choice, Duration::from_secs(1)).await;
            assert!(!persisted_strict_seen(&auto), "{mode}");
            assert!(!dir.join(STRICT_SEEN_DIR).join("t1").exists(), "{mode}");
            assert!(choice.get(&choice_key(&auto)).is_none(), "{mode}");
        }
        // Once per process: a mark that appears afterwards without a strict
        // session of this process is not looked for again.
        let auto = parse("auto");
        persist_strict_seen(&auto);
        let _ = connect(
            &parse("mandatory"),
            &configs,
            &choice,
            Duration::from_secs(1),
        )
        .await;
        assert!(persisted_strict_seen(&auto));
        // `auto` keeps it.
        let _ = connect(&auto, &configs, &choice, Duration::from_secs(1)).await;
        assert!(persisted_strict_seen(&auto));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// CI failure of PR #262 (SQL Server Audit, 2022): the Discovery
    /// `columns` read of the scan's last table was reported as another
    /// session's. Its 1-row sample answered at once and the session closed
    /// right after: SQL Server Audit's clock, a few ms ahead of the
    /// `SYSUTCDATETIME()` the end is computed on, stamped the `columns`
    /// records after the computed end, and only the last statement (the
    /// sample) has a tolerance after a clean end. A clean close now waits
    /// until `CLEAN_CLOSE_SETTLE` after the last answer: the records of
    /// every statement sent fall inside the lifetime, and nothing after the
    /// end is matched.
    #[::tokio::test]
    async fn a_clean_close_settles_after_the_last_answer() {
        use crate::audit::own;
        let target = "conn-test-clean-close-settle";
        own::reset(target);
        let columns = crate::sql::columns("retail", 1_013_578_649).unwrap();
        let sample = crate::sql::sample_statement(
            "retail",
            "crm",
            "export_x",
            &[("phone", crate::sql::Sampled::Text)],
            5,
            None,
        )
        .unwrap();
        let mut ok = build::colmeta_int(&["a"]);
        ok.extend(build::row_int(&[Some(7)]));
        ok.extend(build::done(tok::DONE, done::COUNT, 1));
        let server_us = 1_800_000_000_000_000;
        let lead = 2_500;

        // The failure, without the wait: the session ends at once after
        // its last answer, and the `columns` records stamped `lead` later
        // on the audit clock fall after the computed end.
        let mut h = own::opened(target, 64, server_us, 0, None, Instant::now());
        h.sent(&columns);
        h.sent(&sample);
        h.end(false, Duration::ZERO);
        let end = own::session_at(target, 64, server_us, "")
            .unwrap()
            .end_us
            .unwrap();
        assert!(own::session_at(target, 64, end + lead, &sample).is_some());
        assert!(
            own::session_at(target, 64, end + lead, &columns).is_none(),
            "the mechanism: an earlier statement after the end"
        );

        // Through `Session::close`: the end is at least the settle time
        // after the last answer.
        let (mut s, _srv) = scripted(vec![ok.clone(), ok]);
        let at = Instant::now();
        s.own = Some(own::opened(target, 65, server_us, 0, None, at));
        s.rows(&columns, Stage::Columns, Shape::rows(1, 1))
            .await
            .unwrap();
        s.rows(&sample, Stage::Sample, Shape::rows(1, 1))
            .await
            .unwrap();
        let answered = server_us + i64::try_from(at.elapsed().as_micros()).unwrap();
        s.close().await;
        let end = own::session_at(target, 65, server_us, "")
            .unwrap()
            .end_us
            .unwrap();
        let settle = i64::try_from(own::CLEAN_CLOSE_SETTLE.as_micros()).unwrap();
        // `answered` is read a few µs after the answer the wait counts from.
        assert!(end + 1_000 >= answered + settle, "{end} {answered}");
        assert!(
            own::session_at(target, 65, answered + lead, &columns).is_some(),
            "the earlier statement's records, stamped ahead, are the session's"
        );
        // Nothing is widened: after the end, only the last text keeps its
        // tolerance.
        assert!(own::session_at(target, 65, end + 1, &columns).is_none());
        assert!(own::session_at(target, 65, end + 1, &sample).is_some());
        assert!(own::session_at(target, 65, end + own::CLOCK_TOLERANCE_US + 1, &sample).is_none());
    }

    /// #264 review L3: a lost close (poisoned, or a request in flight)
    /// does not wait and keeps its grace; a session idle for longer than
    /// the settle closes at once, cleanly; a session that is not one of
    /// the agent's own never waits.
    #[::tokio::test]
    async fn lost_and_idle_closes_do_not_wait() {
        use crate::audit::own;
        let target = "conn-test-close-no-wait";
        own::reset(target);
        let server_us = 1_800_000_000_000_000;
        let grace = i64::try_from((Duration::from_secs(30) + own::LOST_GRACE).as_micros()).unwrap();
        for (spid, poisoned, in_flight) in [(70, true, false), (71, false, true)] {
            let (mut s, _srv) = scripted(vec![]);
            let at = Instant::now();
            s.own = Some(own::opened(target, spid, server_us, 0, None, at));
            s.statement_timeout = Duration::from_secs(30);
            s.poisoned = poisoned;
            s.in_flight = in_flight;
            s.last_used = Instant::now();
            assert!(s.settle_wait().is_zero(), "spid {spid}");
            let t0 = Instant::now();
            s.close().await;
            assert!(
                t0.elapsed() < own::CLEAN_CLOSE_SETTLE,
                "spid {spid}: a lost close waited"
            );
            let end = own::session_at(target, spid, server_us, "")
                .unwrap()
                .end_us
                .unwrap();
            assert!(end >= server_us + grace, "spid {spid}: the grace is kept");
        }
        // Idle for longer than the settle: clean, at once.
        let (mut s, _srv) = scripted(vec![]);
        let at = Instant::now();
        s.own = Some(own::opened(target, 72, server_us, 0, None, at));
        s.last_used = Instant::now()
            .checked_sub(own::CLEAN_CLOSE_SETTLE * 3)
            .unwrap();
        assert!(s.settle_wait().is_zero());
        let t0 = Instant::now();
        s.close().await;
        assert!(
            t0.elapsed() < own::CLEAN_CLOSE_SETTLE,
            "an idle session waited"
        );
        let end = own::session_at(target, 72, server_us, "")
            .unwrap()
            .end_us
            .unwrap();
        assert!(end < server_us + grace, "a clean end: no grace");
        // Just answered: the wait is the rest of the settle.
        let (mut s, _srv) = scripted(vec![]);
        s.own = Some(own::opened(target, 73, server_us, 0, None, Instant::now()));
        s.last_used = Instant::now();
        let w = s.settle_wait();
        assert!(!w.is_zero() && w <= own::CLEAN_CLOSE_SETTLE);
        // Not an own session: no wait.
        s.own = None;
        assert!(s.settle_wait().is_zero());
    }

    /// #264 review L2: after a statement stopped early and cancelled, the
    /// settle counts from the `ATTENTION` acknowledgement (the last
    /// answer), not from the send.
    #[::tokio::test]
    async fn a_cancelled_statement_settles_from_its_acknowledgement() {
        // The statement times out (no answer for 200 ms), then the
        // `ATTENTION` is acknowledged: the last answer is that
        // acknowledgement, 200 ms or more after the send.
        let (mut s, _h) = scripted(vec![
            crate::fake::SILENT.to_vec(),
            build::done(tok::DONE, done::ATTN, 0),
        ]);
        s.statement_timeout = Duration::from_millis(200);
        let sent = Instant::now();
        let e = s
            .rows("SELECT 1", Stage::Check, Shape::rows(1, 1))
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::Timeout);
        assert!(
            !s.is_poisoned() && !s.in_flight,
            "acknowledged: a clean close"
        );
        assert!(
            s.last_used.duration_since(sent) >= Duration::from_millis(200),
            "the settle counts from the acknowledgement"
        );
    }

    /// End-of-phase-9 review L1: a text off the allow-list is refused
    /// before anything is sent (`internal`), the session staying usable;
    /// an allow-listed text is sent.
    #[::tokio::test]
    async fn texts_off_the_allow_list_are_never_sent() {
        let mut ok = build::colmeta_int(&["a"]);
        ok.extend(build::row_int(&[Some(7)]));
        ok.extend(build::done(tok::DONE, done::COUNT, 1));
        let (mut s, h) = scripted(vec![ok]);
        s.any_text = false;
        for text in [
            "SELECT 7",
            "SELECT name FROM sys.databases",
            // A near copy of an allow-listed constant.
            &format!("{} ", crate::sql::VERSION),
        ] {
            let e = s
                .rows(text, Stage::Check, Shape::rows(1, 1))
                .await
                .unwrap_err();
            assert_eq!(e.code, FailureCode::Internal, "{text}");
            assert!(!s.is_poisoned(), "{text}");
        }
        let e = s
            .rpc(
                "SELECT 7",
                &[],
                Stage::Introspection,
                Shape::rows(1, 1),
                |_| Flow::Continue,
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::Internal);
        // Not a column count: only the parsing of the answer matters here.
        let _ = s
            .rows(crate::sql::VERSION, Stage::Check, Shape::rows(1, 1))
            .await;
        drop(s);
        let sent = h.await.unwrap();
        assert_eq!(sent.len(), 1, "only the allow-listed text was sent");
    }
}
