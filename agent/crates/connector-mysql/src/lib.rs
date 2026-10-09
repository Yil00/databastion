//! MySQL / MariaDB connector for the DataBastion agent (P2-C).
//!
//! - Discovery ([`discover`](Connector::discover)): `information_schema`
//!   introspection and bounded sampling of local base tables (never views,
//!   remote-access engines such as `FEDERATED`, nor virtual generated
//!   columns), classification through `ScanJob::classify`, names through
//!   the ADR-0009 normalizer; only masked findings reach the sink (I2).
//! - [`check`](Connector::check): reachability, honest audit level (docs/08:
//!   a readable audit log or `performance_schema` history = Partial, never
//!   Full: neither logs row counts per statement), over-privilege and
//!   coverage.
//! - Audit ([`audit_stream`](Connector::audit_stream), P4-B): access
//!   events from the MariaDB `server_audit` log or the Percona / MySQL
//!   Enterprise `audit_log` JSON file (`mysql.audit_log`, cursor
//!   persisted), or, as a degraded level, from `performance_schema`
//!   statement history; statement text is only analyzed locally
//!   (`classifiers::query`, MySQL dialect), never sent.
//!
//! The connector only reads (I4): read-only transactions and session
//! default, statement timeouts on every query (`max_execution_time` /
//! `max_statement_time`, never `0`), statements killed on the server
//! (`KILL QUERY`) when their future is dropped. It connects only to the
//! declared target (I5), with credentials from `agent.yaml` references
//! (I3), over rustls TLS, through its own implementation of the client
//! protocol (`proto`, `auth`): no local-file capability, no cleartext
//! password plugin, no RSA key retrieval.

#![forbid(unsafe_code)]

mod audit;
mod auth;
mod catalog;
mod check;
mod conn;
mod discover;
mod error;
mod grants;
mod net;
mod proto;
mod sql;
mod tls;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod it;
#[cfg(test)]
mod proptests;

use async_trait::async_trait;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// MySQL / MariaDB connector. One instance serves every declared MySQL and
/// MariaDB target.
#[derive(Default)]
#[non_exhaustive]
pub struct MysqlConnector {
    check_state: check::CheckState,
}

impl std::fmt::Debug for MysqlConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MysqlConnector").finish_non_exhaustive()
    }
}

impl MysqlConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for MysqlConnector {
    fn engine(&self) -> Engine {
        Engine::Mysql
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        check::check(&self.check_state, target).await
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        discover::discover(job, sink, &self.check_state).await
    }

    async fn audit_stream(
        &self,
        cfg: &AuditConfig,
        sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        audit::audit_stream(cfg, sink, &self.check_state).await
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
        let connector = MysqlConnector::new();
        let t = target(
            "{id: t, engine: mysql, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_MY_SECRET}, mysql: {tls: disable}}",
        );
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let connector = MysqlConnector::new();
        assert_eq!(connector.engine(), Engine::Mysql);
        let (findings, _rx) = FindingSink::channel(1);
        let r = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            r,
            Err(ConnectorError::Target {
                engine: Engine::Mysql,
                code: FailureCode::Internal,
                ..
            })
        ));
        let (events, _rx) = EventSink::channel(1);
        assert!(connector.supports_audit());
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
