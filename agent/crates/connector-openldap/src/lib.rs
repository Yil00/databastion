//! OpenLDAP connector for the DataBastion agent.
//!
//! Audit source (docs/08-engine-capabilities.md): slapo-accesslog overlay (Full).
//!
//! Skeleton status (P0-D): every operation returns a "not implemented"
//! result; nothing connects to a database yet.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
    config::TargetConfig,
};

/// OpenLDAP connector (stub).
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct OpenldapConnector {}

impl OpenldapConnector {
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
impl Connector for OpenldapConnector {
    fn engine(&self) -> Engine {
        Engine::Openldap
    }

    async fn check(&self, _target: &TargetConfig) -> TargetHealth {
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
        let connector = OpenldapConnector::new();
        assert_eq!(connector.engine(), Engine::Openldap);
        let config = databastion_core::AgentConfig::parse(
            "{console: {url: \"https://c.example\"}, state_dir: /s, targets: \
             [{id: t, engine: openldap, host: h, account: a, secret: {env: PW}}]}",
        )
        .unwrap();
        let health = connector.check(&config.targets[0]).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
    }

    #[tokio::test]
    async fn stub_operations_return_not_implemented() {
        let connector = OpenldapConnector::new();
        let (findings, _findings_rx) = FindingSink::channel(1);
        let (events, _events_rx) = EventSink::channel(1);
        let discover = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            discover,
            Err(ConnectorError::NotImplemented {
                engine: Engine::Openldap,
                operation: "discover"
            })
        ));
        let audit = connector
            .audit_stream(&AuditConfig::default(), &events)
            .await;
        assert!(matches!(
            audit,
            Err(ConnectorError::NotImplemented {
                engine: Engine::Openldap,
                operation: "audit_stream"
            })
        ));
    }
}
