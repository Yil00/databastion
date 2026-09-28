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
use std::path::Path;
use std::time::Duration;

use databastion_core::FailureCode;
use databastion_core::config::{PgTlsMode, TargetConfig};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{CancelToken, Client, Row, RowStream};

use crate::error::{PgError, Stage};
use crate::sql;
use crate::tls::RustlsConnector;

/// `application_name` of every connector session.
pub(crate) const APPLICATION_NAME: &str = "databastion-agent";
/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
}

impl Timeouts {
    /// `statement` below 100 ms (or `0`) is raised to 100 ms: a timeout is
    /// never `0` (unlimited).
    pub(crate) fn new(statement: Duration) -> Self {
        let ms = u32::try_from(statement.as_millis()).unwrap_or(u32::MAX);
        Self {
            statement_ms: ms.max(100),
        }
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
            IDLE_IN_TRANSACTION_TIMEOUT.as_millis().to_string(),
        ]
    }
}

/// Sends a cancel request for the connection's running statement when
/// dropped while armed.
struct CancelOnDrop {
    token: Option<CancelToken>,
    tls: RustlsConnector,
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
        let tls = self.tls.clone();
        runtime.spawn(async move {
            match tokio::time::timeout(CANCEL_TIMEOUT, token.cancel_query(tls)).await {
                Ok(Ok(())) => tracing::debug!("statement cancelled on the server"),
                // The error text is not logged (obligation 7).
                Ok(Err(e)) => tracing::warn!(
                    sqlstate = e.code().map(|c| c.code()),
                    "cancel request failed"
                ),
                Err(_) => tracing::warn!("cancel request timed out"),
            }
        });
    }
}

/// A connection to one database of a target.
pub(crate) struct Session {
    client: Client,
    tls: RustlsConnector,
    server_version_num: u32,
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
            PgTlsMode::Disable => {
                if !is_local(target) {
                    tracing::warn!(
                        target_id = %target.id,
                        "TLS is disabled for a target that is neither a Unix socket nor a \
                         loopback address"
                    );
                }
                RustlsConnector::disabled()
            }
            PgTlsMode::VerifyFull => RustlsConnector::verify_full(settings.ca_file.as_deref())
                .map_err(|e| {
                    tracing::warn!(target_id = %target.id, error = %e, "TLS setup failed");
                    PgError::new(FailureCode::TargetUnreachable, Stage::Tls)
                })?,
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
            .connect_timeout(CONNECT_TIMEOUT)
            .keepalives(true)
            .ssl_mode(match settings.tls {
                PgTlsMode::Disable => tokio_postgres::config::SslMode::Disable,
                PgTlsMode::VerifyFull => tokio_postgres::config::SslMode::Require,
            });
        drop(secret);
        match (&target.host, &target.socket) {
            (Some(host), _) => {
                config.host(host).port(target.port.unwrap_or(5432));
            }
            (None, Some(socket)) => {
                let (dir, port) = socket_dir_and_port(socket);
                config.host_path(dir).port(port);
            }
            (None, None) => {
                return Err(PgError::new(FailureCode::TargetUnreachable, Stage::Connect));
            }
        }
        let (client, mut connection) = config
            .connect(tls.clone())
            .await
            .map_err(|e| PgError::from_driver(&e, Stage::Connect))?;
        // `config` holds a copy of the password: dropped right away.
        drop(config);
        tokio::spawn(async move {
            // Drives the connection. Notices and notifications are
            // discarded unread (their text is server data, obligation 7);
            // the task ends when the client is dropped or the connection
            // fails.
            while let Some(Ok(_)) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {}
        });
        let mut session = Self {
            client,
            tls,
            server_version_num: 0,
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
        let guard = CancelOnDrop {
            token: Some(self.client.cancel_token()),
            tls: self.tls.clone(),
        };
        let out = fut.await;
        guard.disarm();
        out
    }

    /// Opens a read-only transaction with `SET LOCAL` timeouts.
    pub(crate) async fn begin(&self, timeouts: Timeouts) -> Result<ReadTx<'_>, PgError> {
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

    /// Runs one statement and hands its row stream to `consume`, which
    /// must return once it has read what it needs. The cancel guard covers
    /// the whole consumption (the statement runs while rows are read).
    pub(crate) async fn query_stream<T, F, Fut>(
        &self,
        stage: Stage,
        statement: &str,
        params: &[(&(dyn ToSql + Sync), Type)],
        consume: F,
    ) -> Result<T, PgError>
    where
        F: FnOnce(RowStream) -> Fut,
        Fut: Future<Output = Result<T, tokio_postgres::Error>>,
    {
        self.session
            .guarded(async {
                let stream = self
                    .session
                    .client
                    .query_typed_raw(statement, params.iter().map(|(v, t)| (*v, t.clone())))
                    .await?;
                consume(stream).await
            })
            .await
            .map_err(|e| PgError::from_driver(&e, stage))
    }

    /// Commits (a read-only transaction: ends it).
    pub(crate) async fn commit(mut self) -> Result<(), PgError> {
        self.open = false;
        self.session
            .guarded(self.session.client.execute_typed(sql::COMMIT, &[]))
            .await
            .map(|_| ())
            .map_err(|e| PgError::from_driver(&e, Stage::Commit))
    }

    /// Rolls back, ignoring errors (the session may be broken).
    pub(crate) async fn rollback(mut self) {
        self.open = false;
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

/// Whether the target is a Unix socket or a loopback IP literal.
fn is_local(target: &TargetConfig) -> bool {
    target.socket.is_some()
        || target
            .host
            .as_deref()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
}

/// `agent.yaml` `socket` is either the socket file
/// (`/run/postgresql/.s.PGSQL.5432`) or its directory (port 5432).
fn socket_dir_and_port(socket: &Path) -> (&Path, u16) {
    let port = socket
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix(".s.PGSQL."))
        .and_then(|p| p.parse::<u16>().ok());
    match (port, socket.parent()) {
        (Some(port), Some(dir)) => (dir, port),
        _ => (socket, 5432),
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
        let [st, lock, idle] = Timeouts::new(Duration::from_secs(30)).params();
        assert_eq!(
            (st.as_str(), lock.as_str(), idle.as_str()),
            ("30000", "2000", "10000")
        );
    }

    #[test]
    fn socket_paths() {
        assert_eq!(
            socket_dir_and_port(Path::new("/run/postgresql/.s.PGSQL.5433")),
            (Path::new("/run/postgresql"), 5433)
        );
        assert_eq!(
            socket_dir_and_port(Path::new("/run/postgresql")),
            (Path::new("/run/postgresql"), 5432)
        );
    }
}
