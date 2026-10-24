//! Microsoft SQL Server connector for the DataBastion agent (phase 9,
//! ADR-0051 and its accepted refinement of 2026-10-14). Lot 1: the TDS
//! client, `check()` and Discovery; lot 2: Audit from SQL Server Audit
//! ([`audit`], Partial at best); lot 3: Audit from an Extended Events
//! session (`audit::xe`, Partial at best, the only source on SQL Server
//! 2019).
//!
//! - Own bounded TDS client (decision 1): `PRELOGIN`, TLS (TDS 8.0 strict,
//!   or the handshake wrapped in `PRELOGIN` packets), `LOGIN7` with SQL
//!   authentication only, one statement per `SQLBatch`, `RPC` to
//!   `sp_executesql` only, `ATTENTION`. A closed token set and a closed
//!   row type set; server message text dropped while parsing.
//! - TLS on every transport (decision 2): `strict`, `mandatory`, or `auto`
//!   (strict first, one fallback to `mandatory`, strict retried hourly and
//!   at every start), certificates verified with the pinned CA as the only
//!   root or the system store; SQL Server's fallback certificate refused.
//! - [`check`](Connector::check): version and edition (2019, 2022, 2025;
//!   Standard, Enterprise, Developer, Express; Azure refused), the
//!   permission evaluation against the refusal list in every accessible
//!   database, the `password_hash` probe, logon triggers, the RLS tiers,
//!   the column coverage notes and the CAS guard.
//! - Discovery ([`discover`](Connector::discover)): three-part catalog
//!   reads, bounded sampling, values converted to `nvarchar` on the server
//!   with built-ins only, classified through `ScanJob::classify_guarded`;
//!   only masked findings reach the sink (I2).
//!
//! The connector only reads (I4) with a closed statement set
//! ([`sql::STATEMENTS`]), connects only to the declared host and port
//! (I5: no SQL Server Browser, no routing), with credentials from
//! `agent.yaml` references (I3).

#![forbid(unsafe_code)]

mod audit;
mod check;
mod conn;
mod discover;
mod error;
mod name_case;
mod sql;
mod tds;
mod tls;
mod token;

/// Fuzz target entry points (`agent/fuzz`); `fuzzing` feature only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;
#[cfg(all(test, not(feature = "fuzzing")))]
#[path = "fuzz.rs"]
#[allow(unreachable_pub, dead_code)]
mod fuzz_entry;
#[cfg(all(test, feature = "fuzzing"))]
use fuzz as fuzz_entry;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod it;
#[cfg(test)]
mod proptests;

use async_trait::async_trait;
use databastion_classifiers::masking::EventSource;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// The statement allow-list, for the agent's architecture test.
#[doc(hidden)]
#[must_use]
pub fn statement_allow_list() -> &'static [(&'static str, &'static str)] {
    sql::STATEMENTS
}

/// The statement deny-list, for the agent's architecture test.
#[doc(hidden)]
#[must_use]
pub fn statement_deny_list() -> &'static [&'static str] {
    sql::DENIED
}

/// A statement text without the content of its quoted identifiers and
/// literals, lower-cased (what the deny-list is checked on).
#[doc(hidden)]
#[must_use]
pub fn statement_skeleton(text: &str) -> String {
    sql::unquoted(text)
}

/// Whether the session would send `text` (the run-time deny-list check).
#[doc(hidden)]
#[must_use]
pub fn statement_checked(text: &str) -> bool {
    sql::checked(text)
}

/// Microsoft SQL Server connector. One instance serves every declared SQL
/// Server target.
#[derive(Default)]
#[non_exhaustive]
pub struct SqlserverConnector {
    state: check::CheckState,
}

impl std::fmt::Debug for SqlserverConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlserverConnector").finish_non_exhaustive()
    }
}

impl SqlserverConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for SqlserverConnector {
    fn engine(&self) -> Engine {
        Engine::Sqlserver
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        check::check(&self.state, target).await
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        discover::discover(job, sink, &self.state).await
    }

    async fn audit_stream(
        &self,
        cfg: &AuditConfig,
        sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        audit::audit_stream(cfg, sink, &self.state).await
    }

    fn supports_audit(&self) -> bool {
        true
    }

    fn audit_source(&self, target: &TargetConfig) -> Option<EventSource> {
        self.state.audit.chosen(&target.id).map(|s| match s {
            audit::Source::Audit => EventSource::SqlserverAudit,
            audit::Source::Xevents => EventSource::SqlserverXevents,
        })
    }

    fn server_version(&self, target: &TargetConfig) -> Option<String> {
        self.state.version(&target.id)
    }

    fn name_case(
        &self,
        target: &TargetConfig,
    ) -> Option<databastion_core::name_case::NameCaseReport> {
        self.state.name_case(&target.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_core::{AuditLevel, FailureCode};

    fn parse(
        yaml: &str,
    ) -> Result<databastion_core::AgentConfig, databastion_core::config::ConfigError> {
        databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
        ))
    }

    #[tokio::test]
    async fn unreadable_secret_is_reported_without_connecting() {
        let c = SqlserverConnector::new();
        let t = parse(
            "{id: t, engine: sqlserver, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_SQLSERVER_SECRET}}",
        )
        .unwrap()
        .targets[0]
            .clone();
        let h = c.check(&t).await;
        assert!(!h.reachable);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
        assert!(c.server_version(&t).is_none());
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let c = SqlserverConnector::new();
        assert_eq!(c.engine(), Engine::Sqlserver);
        assert!(c.supports_audit());
        let (findings, _rx) = FindingSink::channel(1);
        assert!(c.discover(&ScanJob::default(), &findings).await.is_err());
    }

    #[test]
    fn configuration_rules() {
        assert!(
            parse("{id: t, engine: sqlserver, host: s.example, account: a, secret: {env: X}}")
                .is_ok()
        );
        assert!(
            parse("{id: t, engine: sqlserver, socket: /run/x.sock, account: a, secret: {env: X}}")
                .is_err()
        );
        assert!(parse("{id: t, engine: sqlserver, host: s.example, account: a, secret: {env: X}, sqlserver: {tls: disable}}").is_err());
        assert!(parse("{id: t, engine: sqlserver, host: s.example, account: a, secret: {env: X}, sqlserver: {tls: strict, ca_file: /ca.pem, databases: [retail], rls_visibility: view_definition, extended_grants: true, max_tables: 100}}").is_ok());
        assert!(parse("{id: t, engine: sqlserver, host: s.example, account: a, secret: {env: X}, sqlserver: {max_tables: 0}}").is_err());
        assert!(parse("{id: t, engine: postgres, host: p.example, account: a, secret: {env: X}, sqlserver: {}}").is_err());
        let t = parse("{id: t, engine: sqlserver, host: s.example, account: a, secret: {env: X}}")
            .unwrap()
            .targets[0]
            .clone();
        assert_eq!(t.effective_port(), Some(1433));
    }
}
