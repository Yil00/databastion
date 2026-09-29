//! The [`Connector`] trait (ADR-0002).

use async_trait::async_trait;
use databastion_classifiers::masking::EventSource;

use crate::config::TargetConfig;
use crate::engine::{Engine, FailureCode, TargetHealth};
pub use crate::job::{AuditConfig, ScanJob};
use crate::sink::{EventSink, FindingSink, SinkClosed};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::AuditLevel;

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
