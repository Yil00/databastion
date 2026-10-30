//! Firebird connector for the DataBastion agent (phase 10, ADR-0060 and
//! its accepted refinement of 2026-10-25). Lot 1 (decision 10): the wire
//! client, SRP-256, ChaCha wire encryption, the loopback, peer-uid and
//! forwarder rules, and `check()` reachability and privileges. Discovery
//! (lot 2) and Audit from the system audit trace log (lot 3) follow.
//!
//! - Own bounded client for the Firebird remote protocol 16 (decision 1):
//!   no driver crate, no `fbclient`; a closed operation set, every length
//!   checked before allocation, status-vector strings dropped at parse.
//! - `Srp256` only, constant-time modular exponentiation ([`srp`]);
//!   `ChaCha64` or `ChaCha` wire encryption required, Arc4 and no
//!   encryption refused, with key confirmation before the first encrypted
//!   byte is sent.
//! - **Loopback only** (decision 3): the declared host is `127.0.0.1` or
//!   `::1`; the server side of each connection must be owned by
//!   `firebird.peer_uid` (`/proc/net/tcp{,6}`, before anything is sent),
//!   and the server must see the agent's own socket (no forwarder) unless
//!   the operator declared a tunnel (`firebird.tunnel: true`).
//! - [`check`](Connector::check): the version (4.0, 5.0), the wire
//!   encryption and the read-only transaction as the server reports them,
//!   and the account against the refusal list (`SYSDBA`, `RDB$ADMIN`, the
//!   owner, the security-database administrator, the system privileges
//!   through the role graph, readable verifier relations) and the
//!   over-privilege list.
//!
//! The connector only reads (I4) with a closed statement set
//! ([`sql::STATEMENTS`]) in read-only transactions with server-side
//! timeouts, connects only to the declared loopback address and port (I5:
//! no event connections, no services API), with the password from
//! `agent.yaml` references, never sent (I3: SRP).

#![forbid(unsafe_code)]

mod catalog;
mod check;
mod conn;
mod crypt;
mod discover;
mod error;
#[cfg_attr(not(test), allow(dead_code))]
mod own;
mod peer;
mod privileges;
#[cfg(test)]
mod review_regressions;
mod sql;
#[cfg_attr(not(test), allow(dead_code))]
mod stream;
#[cfg(test)]
mod stream_tests;
// The Audit stream (lot 3) uses the parsers; until it is wired, only the
// tests and the fuzz targets do.
mod srp;
#[cfg_attr(not(test), allow(dead_code))]
mod trace_conf;
#[cfg(test)]
mod trace_conf_tests;
#[cfg_attr(not(test), allow(dead_code))]
mod trace_events;
#[cfg(test)]
mod trace_events_tests;
#[cfg_attr(not(test), allow(dead_code))]
mod trace_log;
#[cfg(test)]
mod trace_log_tests;
mod wire;
mod xdr;

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
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// The statement allow-list, for the agent's architecture test: `(name,
/// text)`, the one-bit probes included.
#[doc(hidden)]
#[must_use]
pub fn statement_allow_list() -> Vec<(&'static str, &'static str)> {
    sql::STATEMENTS
        .iter()
        .map(|s| (s.name, s.text))
        .chain(sql::PROBES.iter().copied())
        .collect()
}

/// Whether a statement text holds a word of the deny-list outside quotes,
/// for the agent's architecture test.
#[doc(hidden)]
#[must_use]
pub fn statement_has_denied_word(text: &str) -> bool {
    sql::has_denied_word(text)
}

/// Whether the session would send `text` (the run-time check of the
/// closed set).
#[doc(hidden)]
#[must_use]
pub fn statement_checked(text: &str) -> bool {
    sql::checked(text)
}

/// Firebird connector. One instance serves every declared Firebird target.
#[derive(Default)]
#[non_exhaustive]
pub struct FirebirdConnector {
    state: check::CheckState,
}

impl std::fmt::Debug for FirebirdConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirebirdConnector").finish_non_exhaustive()
    }
}

impl FirebirdConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl FirebirdConnector {
    /// `permission_denied` unless the last `check()` of the target cleared
    /// it ([`check::CheckState::blocks`] defaults to blocked).
    fn refused(&self, target: Option<&TargetConfig>) -> Option<ConnectorError> {
        target
            .is_none_or(|t| self.state.blocks(&t.id))
            .then_some(ConnectorError::Target {
                engine: Engine::Firebird,
                code: databastion_core::FailureCode::PermissionDenied,
                engine_code: None,
            })
    }
}

#[async_trait]
impl Connector for FirebirdConnector {
    fn engine(&self) -> Engine {
        Engine::Firebird
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        check::check(&self.state, target).await
    }

    /// Discovery (ADR-0060 decision 5, lot 2 of decision 10). The check's
    /// verdict is consulted first (review N11): a target never checked, or
    /// whose account is refused or not evaluated, is refused; the scan
    /// evaluates the refusal list again at each database.
    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        if let Some(e) = self.refused(job.target()) {
            return Err(e);
        }
        discover::discover(job, sink, &self.state).await
    }

    /// Audit comes with lot 3 (ADR-0060 decision 10), behind the same
    /// verdict as Discovery.
    async fn audit_stream(
        &self,
        cfg: &AuditConfig,
        _sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        if let Some(e) = self.refused(cfg.target()) {
            return Err(e);
        }
        Err(ConnectorError::NotImplemented {
            engine: Engine::Firebird,
            operation: "audit_stream",
        })
    }

    fn server_version(&self, target: &TargetConfig) -> Option<String> {
        self.state.version(&target.id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use databastion_core::{AuditLevel, FailureCode, NoteCode};

    fn parse(
        yaml: &str,
    ) -> Result<databastion_core::AgentConfig, databastion_core::config::ConfigError> {
        databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
        ))
    }

    #[tokio::test]
    async fn an_unreadable_secret_is_reported_without_connecting() {
        let c = FirebirdConnector::new();
        let t = parse(
            "{id: t, engine: firebird, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_FIREBIRD_SECRET}, \
             firebird: {peer_uid: 84, databases: [{name: app, attach: app}]}}",
        )
        .unwrap()
        .targets[0]
            .clone();
        let h = c.check(&t).await;
        assert!(!h.reachable);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(h.notes[0].code(), NoteCode::CheckStageFailed);
        assert!(c.server_version(&t).is_none());
        assert!(c.state.blocks("t"));
    }

    fn denied(r: Result<(), ConnectorError>) -> bool {
        matches!(
            r,
            Err(ConnectorError::Target {
                code: FailureCode::PermissionDenied,
                ..
            })
        )
    }

    /// Review N11: the verdict defaults to blocked, and Discovery and
    /// Audit consult it before anything else.
    #[tokio::test]
    async fn discovery_and_audit_consult_the_check_first() {
        let c = FirebirdConnector::new();
        assert_eq!(c.engine(), Engine::Firebird);
        assert!(!c.supports_audit());
        assert!(c.state.blocks("never-checked"));
        let (findings, _rx) = FindingSink::channel(1);
        let (events, _erx) = EventSink::channel(1);
        assert!(denied(c.discover(&ScanJob::default(), &findings).await));
        assert!(denied(
            c.audit_stream(&AuditConfig::default(), &events).await
        ));
        let t = parse(
            "{id: t, engine: firebird, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_FIREBIRD_SECRET}, \
             firebird: {peer_uid: 84, databases: [{name: app, attach: app}]}}",
        )
        .unwrap()
        .targets[0]
            .clone();
        let key = std::sync::Arc::new(
            databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap(),
        );
        let job = ScanJob::new(
            databastion_core::ScanParams::contract_defaults(),
            &t,
            &databastion_core::config::Limits::default(),
            key,
        );
        // Never checked: refused.
        assert!(denied(c.discover(&job, &findings).await));
        // A failed check leaves it blocked.
        let _ = c.check(&t).await;
        assert!(denied(c.discover(&job, &findings).await));
        // Cleared by a check: Discovery runs (here it cannot read the
        // secret).
        c.state.set_blocked("t", false);
        assert!(matches!(
            c.discover(&job, &findings).await,
            Err(ConnectorError::Target {
                code: FailureCode::AuthenticationFailed,
                ..
            })
        ));
        c.state.set_blocked("t", true);
        assert!(denied(c.discover(&job, &findings).await));
    }

    #[test]
    fn the_allow_list_is_closed() {
        for (name, text) in statement_allow_list() {
            assert!(statement_checked(text), "{name}");
            assert!(!statement_has_denied_word(text), "{name}");
        }
    }
}
