//! Connections, read-only transactions and server-side cancellation
//! (ADR-0012 obligations 3, 4 and 7; P2-B cancellation gate).
//!
//! - Credentials come from `agent.yaml` references only, are read on the
//!   agent host (I3), held in zeroized memory and never logged.
//! - At connection: `search_path = ''`, read-only default transactions,
//!   session timeouts, `application_name = databastion-agent`.
//! - Every unit of work is a [`ReadTx`]: `BEGIN TRANSACTION READ ONLY`, then
//!   `SET LOCAL` of `statement_timeout` (from the clamped job parameter,
//!   never `0`), `lock_timeout` and `idle_in_transaction_session_timeout`.
//!   A transaction is committed before any `.await` outside the database
//!   (in particular before `FindingSink::submit`): the connector never holds
//!   a transaction or a cursor open across a submit.
//! - Every statement runs under a [`CancelOnDrop`] guard: if its future is
//!   dropped (job cancelled, `max_duration_s` reached, agent shutdown,
//!   `check()` timeout), a cancel request is sent to the server, so no
//!   statement outlives its job. The statement timeout remains the last
//!   bound.
//! - Server messages (notices, errors) are never read as text: notices
//!   are discarded, errors reduced to a SQLSTATE (`error`).

use std::future::Future;
use std::time::Duration;

use databastion_core::FailureCode;
use databastion_core::config::{PgTlsMode, TargetConfig};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{CancelToken, Client, Row, RowStream};

use crate::error::{PgError, Stage};
use crate::net::{AuthGuard, Endpoint, REFUSED_AUTH};
use crate::sql;
use crate::tls::RustlsConnector;

/// `application_name` of every connector session.
pub(crate) const APPLICATION_NAME: &str = "databastion-agent";
/// Whole connection setup (TCP, TLS, authentication, session settings).
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on sending a cancel request.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);
/// `lock_timeout` of every transaction (ADR-0012 default).
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// `idle_in_transaction_session_timeout` of every transaction: the
/// connector never idles inside a transaction, so a short bound.
pub(crate) const IDLE_IN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeouts applied to a transaction. The statement timeout comes from the
/// clamped job parameter (`ScanJob::statement_timeout`), at least 100 ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    statement_ms: u32,
    idle_ms: u128,
}

impl Timeouts {
    /// `statement` below 100 ms (or `0`) is raised to 100 ms: a timeout is
    /// never `0` (unlimited).
    pub(crate) fn new(statement: Duration) -> Self {
        let ms = u32::try_from(statement.as_millis()).unwrap_or(u32::MAX);
        Self {
            statement_ms: ms.max(100),
            idle_ms: IDLE_IN_TRANSACTION_TIMEOUT.as_millis(),
        }
    }

    /// Shorter idle-in-transaction timeout (tests).
    #[cfg(test)]
    pub(crate) fn with_idle(mut self, idle: Duration) -> Self {
        self.idle_ms = idle.as_millis();
        self
    }

    #[cfg(test)]
    pub(crate) fn statement_ms(self) -> u32 {
        self.statement_ms
    }

    /// Parameters of `SESSION_SETUP` / `SET_LOCAL_TIMEOUTS`, in
    /// milliseconds (the default unit of these settings).
    fn params(self) -> [String; 3] {
        [
            self.statement_ms.to_string(),
            LOCK_TIMEOUT.as_millis().to_string(),
            self.idle_ms.to_string(),
        ]
    }
}

/// Sends a cancel request for the connection's running statement when
/// dropped while armed.
struct CancelOnDrop {
    token: Option<CancelToken>,
    endpoint: Endpoint,
}

impl CancelOnDrop {
    fn disarm(mut self) {
        self.token = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let endpoint = self.endpoint.clone();
        runtime.spawn(async move {
            let cancel = async {
                let stream = endpoint.open().await.map_err(|e| {
                    tracing::warn!(kind = %e.kind(), "cannot connect to send a cancel request");
                })?;
                token
                    .cancel_query_raw(stream, endpoint.tls_connect())
                    .await
                    .map_err(|e| {
                        // The error text is not logged (obligation 7).
                        tracing::warn!(
                            sqlstate = e.code().map(|c| c.code()),
                            "cancel request failed"
                        );
                    })
            };
            match tokio::time::timeout(CANCEL_TIMEOUT, cancel).await {
                Ok(Ok(())) => tracing::debug!("statement cancelled on the server"),
                Ok(Err(())) => {}
                Err(_) => tracing::warn!("cancel request timed out"),
            }
        });
    }
}

/// A connection to one database of a target.
pub(crate) struct Session {
    client: Client,
    endpoint: Endpoint,
    server_version_num: u32,
    /// A cancel request may still be in flight (a sample stopped at its
    /// byte budget): no further statement is sent on this session.
    poisoned: std::sync::atomic::AtomicBool,
}

impl Session {
    /// Connects to `database` on `target` and applies the session settings.
    pub(crate) async fn connect(
        target: &TargetConfig,
        database: &str,
        timeouts: Timeouts,
    ) -> Result<Self, PgError> {
        match tokio::time::timeout(
            SETUP_TIMEOUT,
            Self::connect_inner(target, database, timeouts),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err(PgError::new(FailureCode::Timeout, Stage::Connect)),
        }
    }

    async fn connect_inner(
        target: &TargetConfig,
        database: &str,
        timeouts: Timeouts,
    ) -> Result<Self, PgError> {
        let settings = target.postgres_settings();
        let tls = match settings.tls {
            PgTlsMode::Disable => RustlsConnector::disabled(),
            PgTlsMode::DisableInsecure => {
                tracing::warn!(
                    target_id = %target.id,
                    "TLS disabled on a network connection (tls: disable_insecure): samples and \
                     statements travel in clear"
                );
                RustlsConnector::disabled()
            }
            PgTlsMode::VerifyFull => RustlsConnector::verify_full(settings.ca_file.as_deref())
                .map_err(|e| {
                    tracing::warn!(target_id = %target.id, error = %e, "TLS setup failed");
                    PgError::new(FailureCode::TargetUnreachable, Stage::Tls)
                })?,
        };
        let plaintext = settings.tls != PgTlsMode::VerifyFull;
        let endpoint = match (&target.host, &target.socket) {
            (Some(host), _) => Endpoint::tcp(host, target.port.unwrap_or(5432), tls),
            (None, Some(socket)) if plaintext => Endpoint::unix(socket),
            _ => return Err(PgError::new(FailureCode::TargetUnreachable, Stage::Connect)),
        };
        let secret = target.secret.read().map_err(|e| {
            // `SecretError` never carries the value.
            tracing::warn!(target_id = %target.id, error = %e, "cannot read the target secret");
            PgError::new(FailureCode::AuthenticationFailed, Stage::Secret)
        })?;
        let mut config = tokio_postgres::Config::new();
        config
            .user(target.account.as_str())
            .password(secret.as_bytes())
            .dbname(database)
            .application_name(APPLICATION_NAME)
            .ssl_mode(if plaintext {
                tokio_postgres::config::SslMode::Disable
            } else {
                tokio_postgres::config::SslMode::Require
            });
        drop(secret);
        let stream = endpoint.open().await.map_err(|e| {
            tracing::warn!(target_id = %target.id, kind = %e.kind(), "cannot connect to the target");
            PgError::new(FailureCode::TargetUnreachable, Stage::Connect)
        })?;
        let connected = config
            .connect_raw(AuthGuard::new(stream, plaintext), endpoint.tls_connect())
            .await;
        // `config` holds a copy of the password: dropped right away.
        drop(config);
        let (client, mut connection) = connected.map_err(|e| {
            if refused_auth(&e) {
                tracing::warn!(
                    target_id = %target.id,
                    "the server asked for a cleartext or MD5 password on a connection without \
                     TLS: refused (use SCRAM, or TLS)"
                );
                PgError::new(FailureCode::AuthenticationFailed, Stage::Connect)
            } else {
                PgError::from_driver(&e, Stage::Connect)
            }
        })?;
        tokio::spawn(async move {
            // Drives the connection. Notices and notifications are
            // discarded unread (their text is server data, obligation 7);
            // the task ends when the client is dropped or the connection
            // fails.
            while let Some(Ok(_)) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {}
        });
        let mut session = Self {
            client,
            endpoint,
            server_version_num: 0,
            poisoned: std::sync::atomic::AtomicBool::new(false),
        };
        let [st, lock, idle] = timeouts.params();
        let row = session
            .guarded(session.client.query_typed(
                sql::SESSION_SETUP,
                &[(&st, Type::TEXT), (&lock, Type::TEXT), (&idle, Type::TEXT)],
            ))
            .await
            .map_err(|e| PgError::from_driver(&e, Stage::SessionSetup))?
            .into_iter()
            .next()
            .ok_or(PgError::new(FailureCode::Internal, Stage::SessionSetup))?;
        let version: String = row
            .try_get(5)
            .map_err(|e| PgError::from_driver(&e, Stage::SessionSetup))?;
        session.server_version_num = version.parse().unwrap_or(0);
        Ok(session)
    }

    /// `server_version_num` (e.g. `170011`).
    pub(crate) fn server_version_num(&self) -> u32 {
        self.server_version_num
    }

    /// Runs `fut` (a statement of this session) under a cancel-on-drop
    /// guard.
    async fn guarded<T>(&self, fut: impl Future<Output = T>) -> T {
        let guard = self.cancel_guard();
        let out = fut.await;
        guard.disarm();
        out
    }

    fn cancel_guard(&self) -> CancelOnDrop {
        CancelOnDrop {
            token: Some(self.client.cancel_token()),
            endpoint: self.endpoint.clone(),
        }
    }

    /// Whether a cancel request may be in flight: the caller opens a new
    /// session instead of sending another statement.
    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Opens a read-only transaction with `SET LOCAL` timeouts.
    pub(crate) async fn begin(&self, timeouts: Timeouts) -> Result<ReadTx<'_>, PgError> {
        if self.is_poisoned() {
            return Err(PgError::new(FailureCode::Internal, Stage::Begin));
        }
        self.guarded(self.client.execute_typed(sql::BEGIN, &[]))
            .await
            .map_err(|e| PgError::from_driver(&e, Stage::Begin))?;
        let tx = ReadTx {
            session: self,
            open: true,
        };
        let [st, lock, idle] = timeouts.params();
        let rows = tx
            .query(
                Stage::Begin,
                sql::SET_LOCAL_TIMEOUTS,
                &[(&st, Type::TEXT), (&lock, Type::TEXT), (&idle, Type::TEXT)],
            )
            .await;
        let read_only = match rows {
            Ok(rows) => rows
                .first()
                .and_then(|r| r.try_get::<_, String>(3).ok())
                .is_some_and(|v| v == "on"),
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        };
        if !read_only {
            // Cannot happen after `BEGIN TRANSACTION READ ONLY`; refuse to
            // go on rather than read in a writable transaction.
            tx.rollback().await;
            return Err(PgError::new(FailureCode::Internal, Stage::Begin));
        }
        Ok(tx)
    }
}

/// A read-only transaction. Must end with [`ReadTx::commit`] or
/// [`ReadTx::rollback`] before the caller awaits anything else than this
/// session (never across `FindingSink::submit`). If its future is dropped,
/// the session is dropped with it and the server aborts the transaction
/// when the connection closes.
pub(crate) struct ReadTx<'s> {
    session: &'s Session,
    open: bool,
}

impl ReadTx<'_> {
    /// See [`Session::is_poisoned`].
    pub(crate) fn is_poisoned(&self) -> bool {
        self.session.is_poisoned()
    }

    /// Runs one statement and collects its rows.
    pub(crate) async fn query(
        &self,
        stage: Stage,
        statement: &str,
        params: &[(&(dyn ToSql + Sync), Type)],
    ) -> Result<Vec<Row>, PgError> {
        self.session
            .guarded(self.session.client.query_typed(statement, params))
            .await
            .map_err(|e| PgError::from_driver(&e, stage))
    }

    /// Runs one statement and hands its row stream to `consume`. The cancel
    /// guard covers the whole consumption (the statement runs while rows
    /// are read). When `consume` stops early ([`Streamed::Stopped`]), the
    /// guard stays armed: a cancel request is sent, the remaining rows are
    /// not drained, and the session is poisoned (no further statement:
    /// the caller reconnects).
    pub(crate) async fn query_stream<T, F, Fut>(
        &self,
        stage: Stage,
        statement: &str,
        params: &[(&(dyn ToSql + Sync), Type)],
        consume: F,
    ) -> Result<T, PgError>
    where
        F: FnOnce(RowStream) -> Fut,
        Fut: Future<Output = Result<Streamed<T>, tokio_postgres::Error>>,
    {
        let guard = self.session.cancel_guard();
        let result = async {
            let stream = self
                .session
                .client
                .query_typed_raw(statement, params.iter().map(|(v, t)| (*v, t.clone())))
                .await?;
            consume(stream).await
        }
        .await;
        match result {
            Ok(Streamed::Complete(v)) => {
                guard.disarm();
                Ok(v)
            }
            Ok(Streamed::Stopped(v)) => {
                self.session
                    .poisoned
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                drop(guard);
                Ok(v)
            }
            Err(e) => {
                guard.disarm();
                Err(PgError::from_driver(&e, stage))
            }
        }
    }

    /// Commits (a read-only transaction: ends it).
    pub(crate) async fn commit(mut self) -> Result<(), PgError> {
        self.open = false;
        if self.session.is_poisoned() {
            // Nothing more is sent; closing the connection ends the
            // transaction.
            return Ok(());
        }
        self.session
            .guarded(self.session.client.execute_typed(sql::COMMIT, &[]))
            .await
            .map(|_| ())
            .map_err(|e| PgError::from_driver(&e, Stage::Commit))
    }

    /// Rolls back, ignoring errors (the session may be broken).
    pub(crate) async fn rollback(mut self) {
        self.open = false;
        if self.session.is_poisoned() {
            return;
        }
        let _ = self
            .session
            .guarded(self.session.client.execute_typed(sql::ROLLBACK, &[]))
            .await;
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

/// How [`ReadTx::query_stream`]'s consumer ended.
pub(crate) enum Streamed<T> {
    /// Every row was read.
    Complete(T),
    /// Stopped early (byte budget): the statement is cancelled.
    Stopped(T),
}

/// Whether a connection error is the [`AuthGuard`] refusal.
fn refused_auth(e: &tokio_postgres::Error) -> bool {
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if s.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == REFUSED_AUTH)
        {
            return true;
        }
        source = s.source();
    }
    false
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
        let [st, lock, idle] = Timeouts::new(Duration::from_secs(30)).params();
        assert_eq!(
            (st.as_str(), lock.as_str(), idle.as_str()),
            ("30000", "2000", "10000")
        );
    }
}
