//! PostgreSQL connector for the DataBastion agent (P2-B).
//!
//! - Discovery ([`discover`](Connector::discover)): catalog introspection and
//!   bounded sampling within the scope of ADR-0012 (obligations 1 to 4 and
//!   7), classification through `ScanJob::classify`, names through the
//!   ADR-0009 normalizer; only masked findings reach the sink (I2).
//! - [`check`](Connector::check): reachability, honest audit level (docs/08:
//!   readable pgaudit log = Full, `pg_stat_statements` = Limited), over-privilege and
//!   coverage of the role (ADR-0012 obligation 6).
//! - Audit ([`audit_stream`](Connector::audit_stream), P4-A): access events
//!   from the pgaudit log (`jsonlog` / `csvlog`, cursor persisted) or, as a
//!   degraded Limited level, from `pg_stat_statements` deltas; statement
//!   text is only analyzed locally (`classifiers::query`), never sent.
//!
//! The connector only reads (I4): read-only transactions, `SET LOCAL`
//! timeouts, statements cancelled on the server when their future is
//! dropped. It connects only to the declared target (I5), with credentials
//! from `agent.yaml` references (I3), over rustls TLS.

#![forbid(unsafe_code)]

mod audit;
mod catalog;
mod check;
mod conn;
mod discover;
mod error;
mod net;
mod policy;
mod sql;
mod tls;
mod wire;

#[cfg(test)]
mod it;

use async_trait::async_trait;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// PostgreSQL connector. One instance serves every declared PostgreSQL
/// target.
#[derive(Default)]
#[non_exhaustive]
pub struct PostgresConnector {
    check_state: check::CheckState,
}

impl std::fmt::Debug for PostgresConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresConnector").finish_non_exhaustive()
    }
}

impl PostgresConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for PostgresConnector {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        check::check(&self.check_state, target).await
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        discover::discover(job, sink).await
    }

    async fn audit_stream(
        &self,
        cfg: &AuditConfig,
        sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        audit::audit_stream(cfg, sink).await
    }

    fn supports_audit(&self) -> bool {
        true
    }

    fn audit_source(
        &self,
        target: &TargetConfig,
    ) -> Option<databastion_classifiers::masking::EventSource> {
        self.check_state.audit_source(&target.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_core::{AuditLevel, FailureCode};

    fn target(yaml: &str) -> TargetConfig {
        let config = databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
        ))
        .unwrap();
        config.targets[0].clone()
    }

    #[tokio::test]
    async fn unreadable_secret_is_reported_without_connecting() {
        let connector = PostgresConnector::new();
        let t = target(
            "{id: t, engine: postgres, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_PG_SECRET}, postgres: {tls: disable}}",
        );
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let connector = PostgresConnector::new();
        let (findings, _rx) = FindingSink::channel(1);
        let r = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            r,
            Err(ConnectorError::Target {
                engine: Engine::Postgres,
                code: FailureCode::Internal,
                ..
            })
        ));
        let (events, _rx) = EventSink::channel(1);
        assert!(matches!(
            connector
                .audit_stream(&AuditConfig::default(), &events)
                .await,
            Err(ConnectorError::Target {
                code: FailureCode::Internal,
                ..
            })
        ));
    }
}
