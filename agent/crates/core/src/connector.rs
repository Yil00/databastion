//! The [`Connector`] trait (ADR-0002).

use async_trait::async_trait;

use crate::engine::{Engine, TargetHealth};
use crate::sink::{EventSink, FindingSink, SinkClosed};

/// Parameters of a `discovery.scan` job.
///
/// Placeholder: the core will map the generated
/// `databastion_protocol::DiscoveryScanParams` into it; connectors never see
/// the generated type. Protocol fields are not hand-written here (I6).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ScanJob {}

/// Audit configuration of a target (`audit.configure` job).
///
/// Placeholder: the core will map the generated
/// `databastion_protocol::AuditConfigureParams` into it; connectors never see
/// the generated type.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AuditConfig {}

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

    /// Reachability and audit level actually available on the target. A
    /// degraded audit level (e.g. PostgreSQL without pgaudit) is reported as
    /// such.
    async fn check(&self) -> TargetHealth;

    /// Runs a Discovery scan and pushes masked findings into `sink`.
    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError>;

    /// Streams normalized access events into `sink` until stopped.
    async fn audit_stream(&self, cfg: &AuditConfig, sink: &EventSink)
    -> Result<(), ConnectorError>;
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

        async fn check(&self) -> TargetHealth {
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
            assert_eq!(connector.check().await.audit_level, AuditLevel::None);
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
