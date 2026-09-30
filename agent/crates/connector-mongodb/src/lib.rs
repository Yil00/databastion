//! MongoDB connector for the DataBastion agent (P5-A, ADR-0026).
//!
//! - Discovery ([`discover`](Connector::discover)): the databases and
//!   collections the account holds privileges on (never `admin`, `local`,
//!   `config`, `system.*` collections nor views), one bounded read per
//!   collection (`$sample` on large collections, natural order otherwise),
//!   documents walked into normalized field paths (arrays as `[]`,
//!   dynamic keys as `*`, ADR-0009), classification through
//!   `ScanJob::classify`; only masked findings reach the sink (I2).
//! - [`check`](Connector::check): reachability, the audit level proven
//!   from what the agent can read (ADR-0027: Partial at best, Limited on
//!   Community), over-privilege from the account's resolved privileges,
//!   views not covered.
//! - Audit ([`audit_stream`](Connector::audit_stream), P5-B, P5-C): access
//!   events from the Enterprise / Percona `auditLog` JSON file or the
//!   structured JSON server log (`mongodb.audit_log`, cursor persisted),
//!   or from the profiler; command documents are never kept (closed-shape
//!   facts only; on the profiler they are computed by the server), and
//!   `mongodump` / `mongoexport` runs are flagged from their application
//!   name.
//!
//! The connector only reads (I4): a closed set of commands built in code,
//! `maxTimeMS` on every read (never `0`), no `getMore`, cursors killed at
//! once, no server session or transaction. It connects only to the
//! declared host or socket (I5; no replica-set discovery, no DNS SRV), with
//! credentials from `agent.yaml` references (I3), over rustls TLS, through
//! its own client for a subset of the wire protocol (`wire`, `bson`,
//! `scram`): SCRAM-SHA-256 only, with mutual authentication.

#![forbid(unsafe_code)]

mod audit;
mod bson;
mod catalog;
mod check;
mod conn;
mod discover;
mod error;
mod net;
mod paths;
mod privileges;
mod scram;
mod tls;
mod wire;

/// Fuzz target entry points (`agent/fuzz`); `fuzzing` feature only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod i2;
#[cfg(test)]
mod it;
#[cfg(test)]
mod proptests;

use async_trait::async_trait;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// MongoDB connector. One instance serves every declared MongoDB target.
#[derive(Default)]
#[non_exhaustive]
pub struct MongodbConnector {
    check_state: check::CheckState,
}

impl std::fmt::Debug for MongodbConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongodbConnector").finish_non_exhaustive()
    }
}

impl MongodbConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for MongodbConnector {
    fn engine(&self) -> Engine {
        Engine::Mongodb
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
        let connector = MongodbConnector::new();
        let t = target(
            "{id: t, engine: mongodb, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_MONGO_SECRET}, mongodb: {tls: disable}}",
        );
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(
            health.notes[0].code(),
            databastion_core::NoteCode::CheckStageFailed
        );
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let connector = MongodbConnector::new();
        assert_eq!(connector.engine(), Engine::Mongodb);
        assert!(connector.supports_audit());
        let (findings, _rx) = FindingSink::channel(1);
        let r = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            r,
            Err(ConnectorError::Target {
                engine: Engine::Mongodb,
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
                engine: Engine::Mongodb,
                code: FailureCode::Internal,
                ..
            })
        ));
    }
}
