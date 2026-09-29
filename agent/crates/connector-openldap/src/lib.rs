//! OpenLDAP connector for the DataBastion agent (phase 6, ADR-0029).
//!
//! - Discovery ([`discover`](Connector::discover)): per naming context, the
//!   containers (`organizationalUnit`, `organization`, `dcObject`,
//!   `domain`, `country`, `locality`), then a bounded one-level search in
//!   each, requesting only text attributes of the server schema (custom
//!   ones included) and never `userPassword`, `authPassword` or another
//!   credential attribute. Values are classified through
//!   `ScanJob::classify`; only masked findings reach the sink (I2).
//!   Locations: naming context, container, structural object class,
//!   attribute (normalized; entry DNs never leave the agent).
//! - [`check`](Connector::check): reachability, the audit level proven
//!   from `cn=accesslog` per naming context (Full / Partial / Limited /
//!   None), and what a read-only account can tell of its privileges
//!   (`cn=config`, password attributes, the log without Audit; write
//!   access is never tested and noted as not evaluated).
//! - Audit ([`audit_stream`](Connector::audit_stream)): `cn=accesslog`
//!   read incrementally by `entryCSN`, filters and DNs reduced to closed
//!   facts in memory, bulk searches (`shape.bulk_search`) and large or
//!   paged exports (`volume.large_result`) flagged.
//!
//! The connector only reads (I4): its own LDAPv3 client can encode no
//! write operation; every search has a size and a time limit and an
//! attribute list built in code. It connects only to the declared host or
//! `ldapi://` socket (I5; referrals never followed), with credentials from
//! `agent.yaml` references (I3), over rustls TLS (LDAPS or StartTLS).

#![forbid(unsafe_code)]
// Server input is sliced in this crate: slicing a string must be proven on
// ASCII or on a boundary found by the code (security review H1).
#![cfg_attr(not(test), deny(clippy::string_slice, clippy::indexing_slicing))]

mod audit;
mod ber;
mod catalog;
mod check;
mod conn;
mod discover;
mod dn;
mod error;
mod net;
mod proto;
mod schema;
mod time;
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

/// OpenLDAP connector. One instance serves every declared OpenLDAP target.
#[derive(Default)]
#[non_exhaustive]
pub struct OpenldapConnector {
    check_state: check::CheckState,
}

impl std::fmt::Debug for OpenldapConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenldapConnector").finish_non_exhaustive()
    }
}

impl OpenldapConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for OpenldapConnector {
    fn engine(&self) -> Engine {
        Engine::Openldap
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
        let connector = OpenldapConnector::new();
        let t = target(
            "{id: t, engine: openldap, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_LDAP_SECRET}, openldap: {tls: disable}}",
        );
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(
            health.notes[0].code(),
            databastion_core::NoteCode::CheckStageFailed
        );
        assert_eq!(connector.audit_source(&t), None);
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let connector = OpenldapConnector::new();
        assert_eq!(connector.engine(), Engine::Openldap);
        assert!(connector.supports_audit());
        let (findings, _rx) = FindingSink::channel(1);
        let r = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            r,
            Err(ConnectorError::Target {
                engine: Engine::Openldap,
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
                engine: Engine::Openldap,
                code: FailureCode::Internal,
                ..
            })
        ));
    }
}
