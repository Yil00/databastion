//! MySQL / MariaDB connector for the DataBastion agent.
//!
//! Audit source (docs/08-engine-capabilities.md): MariaDB server_audit / Percona audit_log (Full) or performance_schema (Partial, MySQL Community).
//!
//! Skeleton status (P0-D): every operation returns a "not implemented"
//! result; nothing connects to a database yet.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// MySQL / MariaDB connector (stub).
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MysqlConnector {}

impl MysqlConnector {
    /// Creates the (stub) connector.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    fn not_implemented(&self, operation: &'static str) -> ConnectorError {
        ConnectorError::NotImplemented {
            engine: self.engine(),
            operation,
        }
    }
}

#[async_trait]
impl Connector for MysqlConnector {
    fn engine(&self) -> Engine {
        Engine::Mysql
    }

    async fn check(&self) -> TargetHealth {
        TargetHealth::not_implemented(self.engine())
    }

    async fn discover(&self, _job: &ScanJob, _sink: &FindingSink) -> Result<(), ConnectorError> {
        Err(self.not_implemented("discover"))
    }

    async fn audit_stream(
        &self,
        _cfg: &AuditConfig,
        _sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        Err(self.not_implemented("audit_stream"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_core::AuditLevel;

    #[tokio::test]
    async fn stub_reports_honest_health() {
        let connector = MysqlConnector::new();
        assert_eq!(connector.engine(), Engine::Mysql);
        let health = connector.check().await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
    }

    #[tokio::test]
    async fn stub_operations_return_not_implemented() {
        let connector = MysqlConnector::new();
        let (findings, _findings_rx) = FindingSink::channel(1);
        let (events, _events_rx) = EventSink::channel(1);
        let discover = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            discover,
            Err(ConnectorError::NotImplemented {
                engine: Engine::Mysql,
                operation: "discover"
            })
        ));
        let audit = connector
            .audit_stream(&AuditConfig::default(), &events)
            .await;
        assert!(matches!(
            audit,
            Err(ConnectorError::NotImplemented {
                engine: Engine::Mysql,
                operation: "audit_stream"
            })
        ));
    }
}
