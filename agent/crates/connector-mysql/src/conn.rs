//! Sessions, read-only transactions and server-side cancellation (P2-C
//! gates).
//!
//! - Credentials come from `agent.yaml` references only, are read on the
//!   agent host (I3), held in zeroized memory and never logged; the
//!   authentication exchanges follow the transport policy of `auth`.
//! - At connection (one statement each, read back and verified): pinned
//!   `sql_mode` (with `NO_BACKSLASH_ESCAPES`, never `ANSI_QUOTES`), utf8mb4,
//!   autocommit, `wait_timeout` / `net_read_timeout` / `net_write_timeout`,
//!   `lock_wait_timeout` / `innodb_lock_wait_timeout`, the statement timeout
//!   (`max_execution_time` on MySQL, `max_statement_time` on MariaDB, from
//!   the clamped job parameter, never `0`), MariaDB
//!   `idle_(readonly_)transaction_timeout`, and `SET SESSION TRANSACTION
//!   ISOLATION LEVEL READ COMMITTED, READ ONLY`.
//! - Every unit of work is a [`ReadTx`]: the statement timeout re-asserted,
//!   then `START TRANSACTION READ ONLY`, whose OK packet must carry the
//!   server's "in read-only transaction" status. A transaction is committed
//!   before any `.await` outside the database (in particular before
//!   `FindingSink::submit`): the connector never holds a transaction or an
//!   unread result across a submit.
//! - Every statement runs under a [`CancelOnDrop`] guard: if its future is
//!   dropped (job cancelled, `max_duration_s` reached, agent shutdown,
//!   `check()` timeout), `KILL QUERY <connection id>` is sent from a
//!   separate connection, so no statement outlives its job. The statement
//!   timeout remains the last bound.
//! - Server messages are never read as text (`proto`, `error`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_core::FailureCode;
use databastion_core::config::{MysqlTlsMode, TargetConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::auth::{self, Channel, Refusal};
use crate::error::{MyError, Stage};
use crate::net::{Endpoint, Transport};
use crate::proto::{self, PacketIo, ProtoError, Reader, cap, status};
use crate::sql;
use crate::tls;

/// Whole connection setup (TCP, TLS, authentication, session settings).
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on a `KILL QUERY` (connection included).
const KILL_TIMEOUT: Duration = Duration::from_secs(10);
/// A session idle for longer is replaced before its next statement (the
/// server closes it after `wait_timeout`).
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(45);
/// Most rows / bytes collected by [`Session::query`] (catalog reads).
const MAX_QUERY_ROWS: usize = 200_000;
const MAX_QUERY_BYTES: usize = 64 * 1024 * 1024;
/// Oldest supported servers.
const MIN_MYSQL: (u32, u32, u32) = (8, 0, 0);
const MIN_MARIADB: (u32, u32, u32) = (10, 6, 0);

/// Server family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Mysql,
    Mariadb,
}

impl Flavor {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Mysql => "mysql",
            Self::Mariadb => "mariadb",
        }
    }
}

/// Parses a handshake version (`8.4.11`, `11.4.13-MariaDB-ubu2404`,
/// `5.5.5-10.6.20-MariaDB`).
/// Whether `VERSION()`, read after TLS, names the flavor and release
/// series (major, minor) the unauthenticated handshake announced.
fn same_series(flavor: Flavor, version: (u32, u32, u32), version_text: &str) -> bool {
    parse_version(version_text)
        .is_some_and(|(f, v)| (f, v.0, v.1) == (flavor, version.0, version.1))
}

pub(crate) fn parse_version(v: &str) -> Option<(Flavor, (u32, u32, u32))> {
    let mariadb = v.contains("MariaDB");
    let v = if mariadb {
        v.strip_prefix("5.5.5-").unwrap_or(v)
    } else {
        v
    };
    let mut parts = v.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((
        if mariadb {
            Flavor::Mariadb
        } else {
            Flavor::Mysql
        },
        (major, minor, patch),
    ))
}

/// Statement timeout of a session, from the clamped job parameter; at
/// least 100 ms, never `0` (unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    statement_ms: u32,
}

impl Timeouts {
    pub(crate) fn new(statement: Duration) -> Self {
        let ms = u32::try_from(statement.as_millis()).unwrap_or(u32::MAX);
        Self {
            statement_ms: ms.max(100),
        }
    }

    pub(crate) fn statement_ms(self) -> u32 {
        self.statement_ms
    }
}

/// Sends `KILL QUERY` for the session's running statement when dropped
/// while armed.
struct CancelOnDrop {
    target: Option<Arc<TargetConfig>>,
    connection_id: u32,
}

impl CancelOnDrop {
    fn disarm(mut self) {
        self.target = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some(target) = self.target.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let id = self.connection_id;
        runtime.spawn(async move {
            let kill = async {
                let mut s =
                    Session::open(target, Timeouts::new(Duration::from_secs(5)), true, true)
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                stage = e.stage.as_str(),
                                errno = e.errno,
                                "cannot connect to kill a statement"
                            );
                        })?;
                let r = s.exec_unguarded(&sql::kill_query(id)).await;
                s.close().await;
                r.map_err(|e| {
                    let e = MyError::from_proto(e, Stage::Kill);
                    // ER_NO_SUCH_THREAD: the session already ended.
                    if e.errno != Some(1094) {
                        tracing::warn!(errno = e.errno, "KILL QUERY failed");
                    }
                })
            };
            match tokio::time::timeout(KILL_TIMEOUT, kill).await {
                Ok(Ok(_)) => tracing::debug!("statement killed on the server"),
                Ok(Err(())) => {}
                Err(_) => tracing::warn!("KILL QUERY timed out"),
            }
        });
    }
}

/// What a row consumer wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    /// Stop reading (byte budget): the statement is killed and the session
    /// poisoned (the caller reconnects).
    Stop,
}

/// How a streamed statement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Streamed {
    Complete,
    Stopped,
}

/// Rows of a catalog query (text values; `None` = NULL).
pub(crate) type Rows = Vec<Vec<Option<String>>>;

/// A connection to a target.
pub(crate) struct Session {
    io: PacketIo<Transport>,
    target: Arc<TargetConfig>,
    flavor: Flavor,
    version: (u32, u32, u32),
    connection_id: u32,
    timeouts: Timeouts,
    /// A statement was stopped before its end (unread result, kill in
    /// flight): no further statement is sent on this session.
    poisoned: bool,
    last_used: Instant,
    /// `false` for the sessions that send `KILL QUERY` themselves.
    kill_on_drop: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("flavor", &self.flavor)
            .field("connection_id", &self.connection_id)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

/// Why authentication failed.
#[derive(Debug)]
pub(crate) enum AuthFail {
    Proto(ProtoError),
    Refused(Refusal),
}

impl From<ProtoError> for AuthFail {
    fn from(e: ProtoError) -> Self {
        Self::Proto(e)
    }
}

impl Session {
    /// Connects to `target` with the agent's read-only session settings.
    pub(crate) async fn connect(
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<Self, MyError> {
        Self::open(Arc::new(target.clone()), timeouts, true, false).await
    }

    /// Connects without the read-only session default (test fixtures).
    #[cfg(test)]
    pub(crate) async fn connect_admin(
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<Self, MyError> {
        Self::open(Arc::new(target.clone()), timeouts, false, false).await
    }

    /// Connects without the cancel-on-drop guard (control of the kill
    /// probe).
    #[cfg(test)]
    pub(crate) async fn connect_unguarded(
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<Self, MyError> {
        Self::open(Arc::new(target.clone()), timeouts, true, true).await
    }

    /// `killer`: a session opened to send `KILL QUERY` (its own statements
    /// are not guarded).
    async fn open(
        target: Arc<TargetConfig>,
        timeouts: Timeouts,
        read_only: bool,
        killer: bool,
    ) -> Result<Self, MyError> {
        let id = target.id.clone();
        match tokio::time::timeout(
            SETUP_TIMEOUT,
            Self::open_inner(target, timeouts, read_only, killer),
        )
        .await
        {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => {
                tracing::debug!(
                    target_id = %id,
                    stage = e.stage.as_str(),
                    errno = e.errno,
                    sqlstate = e.sqlstate(),
                    "connection failed"
                );
                Err(e)
            }
            Err(_) => Err(MyError::new(FailureCode::Timeout, Stage::Connect)),
        }
    }

    async fn open_inner(
        target: Arc<TargetConfig>,
        timeouts: Timeouts,
        read_only: bool,
        killer: bool,
    ) -> Result<Self, MyError> {
        let settings = target.mysql_settings();
        let endpoint = match (&target.host, &target.socket) {
            (Some(host), _) => Endpoint::Tcp {
                host: host.clone(),
                port: target.port.unwrap_or(3306),
            },
            (None, Some(path)) => Endpoint::Unix { path: path.clone() },
            _ => return Err(MyError::new(FailureCode::TargetUnreachable, Stage::Connect)),
        };
        let tls = match settings.tls {
            MysqlTlsMode::VerifyFull => {
                if matches!(endpoint, Endpoint::Unix { .. }) {
                    return Err(MyError::new(FailureCode::TargetUnreachable, Stage::Tls));
                }
                Some(tls::verify_full(settings.ca_file.as_deref()).map_err(|e| {
                    tracing::warn!(target_id = %target.id, error = %e, "TLS setup failed");
                    MyError::new(FailureCode::TargetUnreachable, Stage::Tls)
                })?)
            }
            MysqlTlsMode::Disable => {
                // Config validation allows it for a socket or a loopback
                // literal only; checked again here (fail closed).
                if endpoint.plain_channel() == Channel::NetworkPlain {
                    return Err(MyError::new(FailureCode::TargetUnreachable, Stage::Tls));
                }
                None
            }
            MysqlTlsMode::DisableInsecure => {
                tracing::warn!(
                    target_id = %target.id,
                    "TLS disabled on a network connection (tls: disable_insecure): samples and \
                     statements travel in clear, and read-only is not guaranteed (an attacker \
                     on the path can relay the authentication and send its own statements); \
                     only the caching_sha2_password fast path is accepted, and its scramble \
                     (SHA-256, no salt stretching) can be brute-forced offline by anyone who \
                     sees it, which an attacker on the path can force with an auth switch"
                );
                None
            }
        };
        let secret = target.secret.read().map_err(|e| {
            tracing::warn!(target_id = %target.id, error = %e, "cannot read the target secret");
            MyError::new(FailureCode::AuthenticationFailed, Stage::Secret)
        })?;
        let transport = endpoint.open().await.map_err(|e| {
            tracing::warn!(target_id = %target.id, kind = %e.kind(), "cannot connect to the target");
            MyError::new(FailureCode::TargetUnreachable, Stage::Connect)
        })?;
        let mut io = PacketIo::new(transport);
        let handshake = io
            .read_small()
            .await
            .and_then(|p| proto::parse_handshake(&p))
            .map_err(|e| MyError::from_proto(e, Stage::Connect))?;
        if handshake.capabilities & cap::REQUIRED != cap::REQUIRED {
            return Err(MyError::new(FailureCode::Unsupported, Stage::Connect));
        }
        let (flavor, version) = parse_version(&handshake.server_version)
            .ok_or(MyError::new(FailureCode::Unsupported, Stage::Connect))?;
        let minimum = match flavor {
            Flavor::Mysql => MIN_MYSQL,
            Flavor::Mariadb => MIN_MARIADB,
        };
        if version < minimum {
            tracing::warn!(
                target_id = %target.id,
                flavor = flavor.as_str(),
                "server version not supported (MySQL 8.0+ or MariaDB 10.6+)"
            );
            return Err(MyError::new(FailureCode::Unsupported, Stage::Connect));
        }
        let mut caps = cap::WANTED & handshake.capabilities;
        let channel = if let Some(config) = tls {
            if handshake.capabilities & cap::SSL == 0 {
                tracing::warn!(
                    target_id = %target.id,
                    "the server does not offer TLS (tls: verify_full): not connecting"
                );
                return Err(MyError::new(FailureCode::TargetUnreachable, Stage::Tls));
            }
            caps |= cap::SSL;
            io.write(&proto::ssl_request(caps))
                .await
                .map_err(|e| MyError::from_proto(e, Stage::Tls))?;
            let host = target.host.clone().unwrap_or_default();
            let plain = std::mem::replace(&mut io.stream, Transport::Closed);
            io.stream = plain.upgrade(config, &host).await.map_err(|e| {
                tracing::warn!(
                    target_id = %target.id,
                    kind = %e.kind(),
                    "TLS handshake failed (certificate or host name not verified)"
                );
                MyError::new(FailureCode::TargetUnreachable, Stage::Tls)
            })?;
            Channel::Tls
        } else {
            endpoint.plain_channel()
        };
        let authenticated = login(
            &mut io,
            &handshake,
            caps,
            &target.account,
            secret.as_bytes(),
            channel,
        )
        .await;
        drop(secret);
        match authenticated {
            Ok(()) => {}
            Err(AuthFail::Refused(r)) => {
                tracing::warn!(
                    target_id = %target.id,
                    reason = r.as_str(),
                    "authentication exchange refused"
                );
                return Err(MyError::new(FailureCode::AuthenticationFailed, Stage::Auth));
            }
            Err(AuthFail::Proto(e)) => return Err(MyError::from_proto(e, Stage::Auth)),
        }
        let mut session = Self {
            io,
            target,
            flavor,
            version,
            connection_id: handshake.connection_id,
            timeouts,
            poisoned: false,
            last_used: Instant::now(),
            kill_on_drop: !killer,
        };
        session.setup(read_only).await?;
        Ok(session)
    }

    /// Session settings, read back and verified.
    async fn setup(&mut self, read_only: bool) -> Result<(), MyError> {
        let ms = self.timeouts.statement_ms();
        self.exec(Stage::SessionSetup, &sql::session_setup(self.flavor, ms))
            .await?;
        if read_only {
            self.exec(Stage::SessionSetup, sql::SESSION_READ_ONLY)
                .await?;
        }
        let var = self.tx_read_only_var();
        let rows = self
            .query(Stage::SessionSetup, &sql::session_check(self.flavor, var))
            .await?;
        let row = rows
            .first()
            .ok_or(MyError::new(FailureCode::Internal, Stage::SessionSetup))?;
        let text = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
        let timeout_ok = match self.flavor {
            Flavor::Mysql => text(1) == ms.to_string(),
            Flavor::Mariadb => text(1)
                .parse::<f64>()
                .is_ok_and(|s| ((s * 1000.0).round() - f64::from(ms)).abs() < 1.0),
        };
        let mode = text(3);
        let checks = [
            (
                text(0) == self.connection_id.to_string(),
                // A proxy (ProxySQL, MaxScale) in front of the server: the
                // handshake id is not the server session, so `KILL QUERY`
                // could not target it.
                "the server connection id differs from the handshake (proxy?): statements \
                 could not be killed",
            ),
            (
                // Read after TLS: the handshake that announced the flavor
                // and the version was not authenticated, and the version
                // picks the built-in function list of the Audit analysis
                // (ADR-0045 decision 8; security review of #188, L1).
                same_series(self.flavor, self.version, &text(6)),
                "the server flavor or release series differs from the handshake",
            ),
            (timeout_ok, "statement timeout not applied"),
            (
                !read_only || text(2) == "1",
                "read-only session default not applied",
            ),
            (
                mode.split(',').any(|m| m == "NO_BACKSLASH_ESCAPES")
                    && !mode
                        .split(',')
                        .any(|m| m == "ANSI_QUOTES" || m == "IGNORE_SPACE" || m == "ANSI"),
                "sql_mode not applied",
            ),
            (text(4) == "utf8mb4", "utf8mb4 results not applied"),
            (
                text(5) == sql::WAIT_TIMEOUT_S.to_string(),
                "idle timeout not applied",
            ),
        ];
        if let Some((_, reason)) = checks.iter().find(|(ok, _)| !ok) {
            tracing::warn!(
                target_id = %self.target.id,
                flavor = self.flavor.as_str(),
                reason,
                "session settings not applied as requested: not using this session"
            );
            return Err(MyError::new(FailureCode::Internal, Stage::SessionSetup));
        }
        Ok(())
    }

    /// Name of the session's read-only default variable.
    fn tx_read_only_var(&self) -> &'static str {
        match self.flavor {
            Flavor::Mariadb if self.version < (11, 1, 0) => "tx_read_only",
            _ => "transaction_read_only",
        }
    }

    pub(crate) fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// Server version from the handshake (MariaDB: without the `5.5.5-`
    /// prefix).
    pub(crate) fn version(&self) -> (u32, u32, u32) {
        self.version
    }

    /// See [`Session::poisoned`](Session).
    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Idle for long enough that the server may have closed it.
    pub(crate) fn is_stale(&self) -> bool {
        self.last_used.elapsed() >= STALE_AFTER
    }

    fn guard(&self) -> CancelOnDrop {
        CancelOnDrop {
            target: self.kill_on_drop.then(|| Arc::clone(&self.target)),
            connection_id: self.connection_id,
        }
    }

    /// Ends the session politely (`COM_QUIT`), best effort.
    pub(crate) async fn close(mut self) {
        if !self.poisoned {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.io.command(proto::COM_QUIT, &[]),
            )
            .await;
        }
    }

    /// A statement without a result set; returns the OK status flags.
    async fn exec_unguarded(&mut self, statement: &str) -> Result<u16, ProtoError> {
        if self.poisoned {
            return Err(ProtoError::Malformed);
        }
        self.io
            .command(proto::COM_QUERY, statement.as_bytes())
            .await?;
        let first = self.io.read_small().await?;
        let out = match first.first() {
            Some(0x00) => proto::parse_ok(&first),
            Some(0xFF) => Err(ProtoError::Server(proto::parse_err(&first)?)),
            // A result set (or a LOCAL INFILE request) where none was
            // expected: not read further.
            _ => {
                self.poisoned = true;
                Err(ProtoError::Malformed)
            }
        };
        self.last_used = Instant::now();
        out
    }

    /// A statement without a result set, under the cancel guard.
    pub(crate) async fn exec(&mut self, stage: Stage, statement: &str) -> Result<u16, MyError> {
        let guard = self.guard();
        let r = self.exec_unguarded(statement).await;
        guard.disarm();
        r.map_err(|e| self.fail(e, stage))
    }

    /// Reduces an error; a protocol error poisons the session.
    fn fail(&mut self, e: ProtoError, stage: Stage) -> MyError {
        let e = MyError::from_proto(e, stage);
        if e.fatal {
            self.poisoned = true;
        }
        e
    }

    /// Runs a statement and collects its rows (catalog reads), bounded to
    /// [`MAX_QUERY_ROWS`] rows and [`MAX_QUERY_BYTES`]. A row with a value
    /// that is not UTF-8 is dropped (the utf8mb4 results character set
    /// makes it unexpected).
    pub(crate) async fn query(&mut self, stage: Stage, statement: &str) -> Result<Rows, MyError> {
        self.query_counted(stage, statement)
            .await
            .map(|(rows, _)| rows)
    }

    /// Like [`query`](Self::query), with the number of rows skipped
    /// because a value was not UTF-8: a caller that must see every row
    /// (grant reads in `check()`) treats a skipped row as not understood.
    pub(crate) async fn query_counted(
        &mut self,
        stage: Stage,
        statement: &str,
    ) -> Result<(Rows, usize), MyError> {
        let mut rows: Rows = Vec::new();
        let mut bytes = 0usize;
        let mut dropped = 0usize;
        let streamed = self
            .query_stream(stage, statement, |row| {
                if rows.len() >= MAX_QUERY_ROWS || bytes >= MAX_QUERY_BYTES {
                    return Flow::Stop;
                }
                let mut out = Vec::with_capacity(row.len());
                for v in row {
                    match v {
                        None => out.push(None),
                        Some(b) => {
                            bytes += b.len();
                            match std::str::from_utf8(b) {
                                Ok(s) => out.push(Some(s.to_owned())),
                                Err(_) => {
                                    dropped += 1;
                                    return Flow::Continue;
                                }
                            }
                        }
                    }
                }
                rows.push(out);
                Flow::Continue
            })
            .await?;
        if dropped > 0 {
            tracing::warn!(
                stage = stage.as_str(),
                count = dropped,
                "rows that are not UTF-8 skipped"
            );
        }
        if streamed == Streamed::Stopped {
            return Err(MyError::new(FailureCode::ResourceLimit, stage));
        }
        Ok((rows, dropped))
    }

    /// Runs a statement and hands each row to `on_row`. The cancel guard
    /// covers the whole read (the statement runs while rows are read). When
    /// `on_row` returns [`Flow::Stop`], the guard stays armed: `KILL QUERY`
    /// is sent, the remaining rows are not read, and the session is
    /// poisoned (the caller drops it and reconnects).
    pub(crate) async fn query_stream<F>(
        &mut self,
        stage: Stage,
        statement: &str,
        on_row: F,
    ) -> Result<Streamed, MyError>
    where
        F: FnMut(&[Option<&[u8]>]) -> Flow,
    {
        if self.poisoned {
            return Err(MyError::new(FailureCode::Internal, stage));
        }
        let guard = self.guard();
        let r = self.read_result(statement, on_row).await;
        self.last_used = Instant::now();
        match r {
            Ok(Streamed::Complete) => {
                guard.disarm();
                Ok(Streamed::Complete)
            }
            Ok(Streamed::Stopped) => {
                self.poisoned = true;
                drop(guard);
                Ok(Streamed::Stopped)
            }
            Err(e) => {
                // A server error ends the result set (the statement is
                // over); a protocol error leaves it unread.
                let fatal = !matches!(e, ProtoError::Server(_));
                if fatal {
                    self.poisoned = true;
                    drop(guard);
                } else {
                    guard.disarm();
                }
                Err(self.fail(e, stage))
            }
        }
    }

    async fn read_result<F>(&mut self, statement: &str, on_row: F) -> Result<Streamed, ProtoError>
    where
        F: FnMut(&[Option<&[u8]>]) -> Flow,
    {
        read_result(&mut self.io, statement, on_row).await
    }

    /// Opens a read-only transaction: re-asserts the statement timeout,
    /// then `START TRANSACTION READ ONLY`, whose OK status must show a
    /// read-only transaction.
    pub(crate) async fn begin(&mut self) -> Result<ReadTx<'_>, MyError> {
        if self.poisoned {
            return Err(MyError::new(FailureCode::Internal, Stage::Begin));
        }
        let ms = self.timeouts.statement_ms();
        self.exec(Stage::Begin, &sql::set_statement_timeout(self.flavor, ms))
            .await?;
        let flags = self.exec(Stage::Begin, sql::BEGIN).await?;
        let tx = ReadTx {
            session: self,
            open: true,
        };
        if flags & status::IN_TRANS == 0 || flags & status::IN_TRANS_READONLY == 0 {
            // Refuse to read in a transaction the server does not report as
            // read-only.
            tx.rollback().await;
            return Err(MyError::new(FailureCode::Internal, Stage::Begin));
        }
        Ok(tx)
    }
}

/// Sends the handshake response and runs the authentication exchange
/// (after the TLS upgrade, if any).
pub(crate) async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut PacketIo<S>,
    handshake: &proto::Handshake,
    caps: u32,
    account: &str,
    password: &[u8],
    channel: Channel,
) -> Result<(), AuthFail> {
    let plugin = auth::initial_plugin(&handshake.plugin, channel);
    let first =
        auth::answer(plugin, &handshake.nonce, password, channel).map_err(AuthFail::Refused)?;
    io.write(&proto::handshake_response(caps, account, &first, plugin))
        .await?;
    authenticate(io, plugin, password, channel).await
}

/// Runs a text-protocol statement and hands each row to `on_row`.
pub(crate) async fn read_result<S, F>(
    io: &mut PacketIo<S>,
    statement: &str,
    mut on_row: F,
) -> Result<Streamed, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&[Option<&[u8]>]) -> Flow,
{
    io.command(proto::COM_QUERY, statement.as_bytes()).await?;
    let first = io.read_small().await?;
    let columns = match first.first() {
        Some(0x00) => return Ok(Streamed::Complete),
        Some(0xFF) => return Err(ProtoError::Server(proto::parse_err(&first)?)),
        // LOCAL INFILE request: never answered (the capability is not set;
        // a server sending it anyway is refused, no file is read).
        Some(0xFB) => return Err(ProtoError::Malformed),
        _ => {
            let mut r = Reader::new(&first);
            let n = r.lenenc()?;
            if r.remaining() != 0 || n == 0 || n > u64::from(sql::MAX_COLUMNS) + 16 {
                return Err(ProtoError::Malformed);
            }
            usize::try_from(n).map_err(|_| ProtoError::Malformed)?
        }
    };
    for _ in 0..columns {
        let def = io.read_small().await?;
        proto::column_type(&def)?;
    }
    let eof = io.read_small().await?;
    if !proto::is_eof(&eof) {
        return Err(ProtoError::Malformed);
    }
    loop {
        let packet = io.read().await?;
        match packet.first() {
            Some(0xFF) => return Err(ProtoError::Server(proto::parse_err(&packet)?)),
            _ if proto::is_eof(&packet) => {
                proto::eof_status(&packet)?;
                return Ok(Streamed::Complete);
            }
            _ => {
                let row = proto::parse_row(&packet, columns)?;
                if on_row(&row) == Flow::Stop {
                    return Ok(Streamed::Stopped);
                }
            }
        }
    }
}

/// Runs the authentication exchange after the handshake response.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut PacketIo<S>,
    plugin: &[u8],
    password: &[u8],
    channel: Channel,
) -> Result<(), AuthFail> {
    let mut plugin = plugin.to_vec();
    for _ in 0..8 {
        let packet = io.read_small().await?;
        match packet.first() {
            Some(0x00) => return Ok(()),
            Some(0xFF) => return Err(ProtoError::Server(proto::parse_err(&packet)?).into()),
            Some(0xFE) => {
                // Auth switch request: plugin name, then its nonce.
                if packet.len() == 1 {
                    return Err(AuthFail::Refused(Refusal::Plugin(
                        auth::KnownPlugin::OldPassword,
                    )));
                }
                let mut r = Reader::new(&packet[1..]);
                let name = r
                    .nul_bytes()
                    .map_err(|_| AuthFail::Refused(Refusal::Protocol))?;
                let data = r.rest();
                let nonce = data.strip_suffix(&[0]).unwrap_or(data);
                let answer =
                    auth::answer(name, nonce, password, channel).map_err(AuthFail::Refused)?;
                plugin = name.to_vec();
                io.write(&answer).await?;
            }
            Some(0x01) if plugin == auth::CACHING_SHA2 => match packet.get(1..) {
                Some([auth::FAST_AUTH_OK]) => {}
                Some([auth::PERFORM_FULL_AUTH]) => {
                    if !channel.may_send_password() {
                        return Err(AuthFail::Refused(Refusal::FullAuthWithoutTls));
                    }
                    // Capacity reserved first: the buffer never moves.
                    let mut clear = Zeroizing::new(Vec::with_capacity(password.len() + 1));
                    clear.extend_from_slice(password);
                    clear.push(0);
                    io.write(&clear).await?;
                }
                // Anything else (an unsolicited public key…).
                _ => return Err(AuthFail::Refused(Refusal::Protocol)),
            },
            _ => return Err(AuthFail::Refused(Refusal::Protocol)),
        }
    }
    Err(AuthFail::Refused(Refusal::Protocol))
}

/// A read-only transaction. Must end with [`ReadTx::commit`] or
/// [`ReadTx::rollback`] before the caller awaits anything else than this
/// session (never across `FindingSink::submit`). If its future is dropped,
/// the session is dropped with it and the server rolls the transaction back
/// when the connection closes.
pub(crate) struct ReadTx<'s> {
    session: &'s mut Session,
    open: bool,
}

impl ReadTx<'_> {
    pub(crate) fn flavor(&self) -> Flavor {
        self.session.flavor
    }

    pub(crate) fn timeouts(&self) -> Timeouts {
        self.session.timeouts
    }

    pub(crate) async fn query(&mut self, stage: Stage, statement: &str) -> Result<Rows, MyError> {
        self.session.query(stage, statement).await
    }

    pub(crate) async fn query_stream<F>(
        &mut self,
        stage: Stage,
        statement: &str,
        on_row: F,
    ) -> Result<Streamed, MyError>
    where
        F: FnMut(&[Option<&[u8]>]) -> Flow,
    {
        self.session.query_stream(stage, statement, on_row).await
    }

    /// Commits (a read-only transaction: ends it). On a poisoned session
    /// nothing is sent: closing the connection ends the transaction.
    pub(crate) async fn commit(mut self) -> Result<(), MyError> {
        self.open = false;
        if self.session.poisoned {
            return Ok(());
        }
        self.session
            .exec(Stage::Commit, sql::COMMIT)
            .await
            .map(|_| ())
    }

    /// Rolls back, ignoring errors (the session may be broken).
    pub(crate) async fn rollback(mut self) {
        self.open = false;
        if self.session.poisoned {
            return;
        }
        let _ = self.session.exec(Stage::Commit, sql::ROLLBACK).await;
    }
}

impl Drop for ReadTx<'_> {
    fn drop(&mut self) {
        if self.open {
            // Only reachable when the enclosing future is dropped, in which
            // case the session (and its connection) is dropped too.
            tracing::debug!("read-only transaction dropped without commit");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_timeout_is_never_zero() {
        assert_eq!(Timeouts::new(Duration::ZERO).statement_ms(), 100);
        assert_eq!(Timeouts::new(Duration::from_millis(5)).statement_ms(), 100);
        assert_eq!(
            Timeouts::new(Duration::from_secs(30)).statement_ms(),
            30_000
        );
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("8.4.11"), Some((Flavor::Mysql, (8, 4, 11))));
        assert_eq!(
            parse_version("11.4.13-MariaDB-ubu2404"),
            Some((Flavor::Mariadb, (11, 4, 13)))
        );
        assert_eq!(
            parse_version("5.5.5-10.6.20-MariaDB-log"),
            Some((Flavor::Mariadb, (10, 6, 20)))
        );
        assert_eq!(
            parse_version("8.0.36-28"),
            Some((Flavor::Mysql, (8, 0, 36)))
        );
        assert_eq!(parse_version("garbage"), None);
        // Security review of #188, L1: the series read after TLS must be
        // the handshake's.
        assert!(same_series(Flavor::Mysql, (8, 4, 11), "8.4.11"));
        assert!(same_series(Flavor::Mysql, (8, 4, 11), "8.4.12-12"));
        assert!(same_series(
            Flavor::Mariadb,
            (11, 4, 13),
            "11.4.13-MariaDB-ubu2404"
        ));
        assert!(!same_series(Flavor::Mysql, (8, 4, 11), "9.7.2"));
        assert!(!same_series(Flavor::Mysql, (8, 0, 46), "8.4.11"));
        assert!(!same_series(Flavor::Mysql, (11, 4, 13), "11.4.13-MariaDB"));
        assert!(!same_series(Flavor::Mariadb, (11, 4, 13), "11.8.9-MariaDB"));
        assert!(!same_series(Flavor::Mysql, (8, 4, 11), ""));
        assert!(parse_version("5.7.44").unwrap().1 < MIN_MYSQL);
    }
}
