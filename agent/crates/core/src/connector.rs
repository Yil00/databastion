//! The [`Connector`] trait (ADR-0002).

use async_trait::async_trait;
use databastion_classifiers::masking::EventSource;

use crate::config::TargetConfig;
use crate::engine::{Engine, FailureCode, TargetHealth};
pub use crate::job::{AuditConfig, ScanJob};
use crate::sink::{EventSink, FindingSink, SinkClosed};

/// The [`FailureCode`] of a failure at the TLS stage of a connection, the
/// same on every engine (P9-A lot 1 contract review L2): `timeout` and
/// `cancelled` are kept; every other cause is `target_unreachable`: the
/// target cannot be reached over a verified channel. That covers a failed
/// or refused handshake, a certificate or name not verified, a server that
/// refuses or does not offer TLS (PostgreSQL `SSLRequest`, MySQL
/// `CLIENT_SSL`, OpenLDAP StartTLS, SQL Server `PRELOGIN` encryption), an
/// anomaly around the negotiation (a malformed SQL Server `PRELOGIN`, an
/// unexpected StartTLS response, bytes received after it: a StartTLS
/// injection indicator, not an agent bug) and a local TLS setup error (a
/// CA or client certificate file that cannot be used, a host that is not a
/// TLS server name, TLS asked on a Unix socket). The `stage_tls` label of
/// the `check.stage_failed` note tells a TLS problem apart; the cause is in
/// the agent's log (and the engine code, when the server sent one).
#[must_use]
pub fn tls_stage_failure(code: FailureCode) -> FailureCode {
    match code {
        FailureCode::Timeout | FailureCode::Cancelled => code,
        _ => FailureCode::TargetUnreachable,
    }
}

/// SQLite reader processes that died (a signal, an exit, an IPC violation)
/// or were killed at their deadline (ADR-0059 decision 4): heartbeat metric
/// `sqlite_reader_failures_total`.
static SQLITE_READER_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Counts one SQLite reader failure (see [`SQLITE_READER_FAILURES`]).
pub fn count_sqlite_reader_failure() {
    SQLITE_READER_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Total of [`count_sqlite_reader_failure`].
pub(crate) fn sqlite_reader_failures() -> u64 {
    SQLITE_READER_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Errors returned by connectors.
///
/// Messages must never contain a sampled value or a credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectorError {
    /// The operation is not implemented yet for this engine.
    #[error("{engine}: {operation} is not implemented yet")]
    NotImplemented {
        /// Engine of the connector.
        engine: Engine,
        /// Name of the operation (`discover`, `audit_stream`…).
        operation: &'static str,
    },
    /// The core stopped consuming results.
    #[error(transparent)]
    SinkClosed(#[from] SinkClosed),
    /// The scan was cancelled during a Discovery pause
    /// ([`crate::pacing::Pacer`]).
    #[error("scan cancelled")]
    Cancelled,
    /// The target failed the operation. Reported to the console as `code`
    /// only; `engine_code` is the engine's error code (e.g. a SQLSTATE),
    /// never its message, detail or context text (ADR-0012 obligation 7).
    #[error("{engine}: target error {code} (engine code {engine_code:?})")]
    Target {
        /// Engine of the connector.
        engine: Engine,
        /// Closed failure cause.
        code: FailureCode,
        /// Engine error code: `[A-Za-z0-9_]{1,16}` only (contract
        /// `EngineCode`), e.g. a SQLSTATE.
        engine_code: Option<String>,
    },
}

/// Common interface of every engine connector.
///
/// Connectors only read (I4), with bounded queries, and never talk to the
/// console: results go through [`FindingSink`] / [`EventSink`], which only
/// accept masked types.
///
/// `async-trait` is used instead of native `async fn` in traits because the
/// agent holds heterogeneous connectors as `Box<dyn Connector>` (one per
/// configured target), and native async trait methods are not dyn-compatible.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Engine handled by this connector.
    fn engine(&self) -> Engine;

    /// Reachability and audit level actually available on `target` (one
    /// connector serves every declared target of its engine). A degraded
    /// audit level (e.g. PostgreSQL without pgaudit) is reported as such.
    async fn check(&self, target: &TargetConfig) -> TargetHealth;

    /// Runs a Discovery scan on `job.target()` and pushes masked findings
    /// into `sink`.
    ///
    /// Every bound comes from `job`, already checked against the contract
    /// and clamped to `agent.yaml` (I4): sample at most `job.sample_rows()`
    /// rows per object, set `job.statement_timeout_ms()` on every statement
    /// (never `0`), and skip objects out of `job.includes_*`. Classify each
    /// column with `job.classify(raw_column_name, &values)`, normalize names
    /// with `databastion_classifiers::names` (`normalize_field_path` for
    /// document keys), and submit `ColumnFinding::into_finding(location)`.
    /// Run each object's sampling and each catalog read through
    /// `job.paced(…)` (Discovery duty cycle, `crate::pacing`; `job.turn()`
    /// first when the unit's setup must follow the pause), stop on its
    /// `Cancelled` error (`?`), and on `Paced::OutOfTime` stop sampling and
    /// report the objects left with `job.skip_out_of_time`. Rotate object
    /// lists with `job.rotate`.
    /// The core stops the scan after `job.max_duration()`, or when the
    /// agent is suspended or revoked, by dropping this future.
    ///
    /// Dropping the future does not by itself stop a statement already
    /// running on the server: connectors cancel it server-side on drop
    /// (PostgreSQL: a cancel request through the client's cancel token;
    /// MySQL: `KILL QUERY` on a separate connection, P2-C) and rely on the
    /// statement timeout as the last bound.
    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError>;

    /// Streams masked access events of `cfg.target()` into `sink` until
    /// the core drops this future (audit disabled or reconfigured, agent
    /// shutdown). Poll the source at `cfg.poll_interval()` at most, bound
    /// every query with `cfg.statement_timeout()`, keep the read position
    /// in `cfg.cursor(…)`, and advance it only after the events read before
    /// it were submitted (the core back-pressures `submit()` while `/events`
    /// is parked). Returning is treated as a failure: the core restarts the
    /// stream after a backoff.
    async fn audit_stream(&self, cfg: &AuditConfig, sink: &EventSink)
    -> Result<(), ConnectorError>;

    /// Whether [`audit_stream`](Self::audit_stream) is implemented: an
    /// `audit.configure` job for another connector ends `unsupported`.
    fn supports_audit(&self) -> bool {
        false
    }

    /// Native audit source of the level last reported by
    /// [`check`](Self::check) for `target` (heartbeat `audit_source`).
    /// `None` when there is none or it is unknown.
    fn audit_source(&self, _target: &TargetConfig) -> Option<EventSource> {
        None
    }

    /// The server version the last [`check`](Self::check) of `target`
    /// read (heartbeat `TargetStatus.server_version`), as the server
    /// reported it; the core sends it only when it matches the contract
    /// pattern. `None` when unknown (the default).
    fn server_version(&self, _target: &TargetConfig) -> Option<String> {
        None
    }

    /// How `target` compares names that differ only by case (ADR-0055):
    /// the last value a [`check`](Self::check) read on the same server
    /// run, kept when a later check fails, times out or cannot reach the
    /// server (decision 2). `None` (the default) when the connector reports
    /// none or read nothing yet: for a `mysql`, `mariadb` or `sqlserver`
    /// target the core then sends `unknown` for both parts. Database names
    /// in it are normalized like the connector's locations (ADR-0009).
    fn name_case(&self, _target: &TargetConfig) -> Option<crate::name_case::NameCaseReport> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::AuditLevel;

    /// One mapping of TLS-stage failures on every engine (P9-A lot 1
    /// contract review L2).
    #[test]
    fn tls_stage_failures_have_one_mapping() {
        use FailureCode as F;
        for code in [F::Timeout, F::Cancelled] {
            assert_eq!(tls_stage_failure(code), code);
        }
        for code in [
            F::TargetUnreachable,
            F::AuthenticationFailed,
            F::PermissionDenied,
            F::Expired,
            F::UnknownTarget,
            F::Unsupported,
            F::InvalidParams,
            F::ResourceLimit,
            F::Internal,
        ] {
            assert_eq!(tls_stage_failure(code), F::TargetUnreachable, "{code}");
        }
    }

    struct Dummy;

    #[async_trait]
    impl Connector for Dummy {
        fn engine(&self) -> Engine {
            Engine::Postgres
        }

        async fn check(&self, _: &TargetConfig) -> TargetHealth {
            TargetHealth::not_implemented(self.engine())
        }

        async fn discover(&self, _: &ScanJob, _: &FindingSink) -> Result<(), ConnectorError> {
            Err(ConnectorError::NotImplemented {
                engine: self.engine(),
                operation: "discover",
            })
        }

        async fn audit_stream(&self, _: &AuditConfig, _: &EventSink) -> Result<(), ConnectorError> {
            Err(ConnectorError::NotImplemented {
                engine: self.engine(),
                operation: "audit_stream",
            })
        }
    }

    #[tokio::test]
    async fn connector_is_dyn_compatible() {
        let connectors: Vec<Box<dyn Connector>> = vec![Box::new(Dummy)];
        for connector in &connectors {
            let target: TargetConfig = serde_yaml_ng::from_str(
                "{id: pg, engine: postgres, host: db, account: a, secret: {env: PW}}",
            )
            .unwrap();
            assert_eq!(connector.check(&target).await.audit_level, AuditLevel::None);
        }
    }

    #[test]
    fn not_implemented_error_names_engine_and_operation() {
        let err = ConnectorError::NotImplemented {
            engine: Engine::Openldap,
            operation: "discover",
        };
        assert_eq!(err.to_string(), "openldap: discover is not implemented yet");
    }
}
