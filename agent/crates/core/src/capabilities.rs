//! Capability negotiation (ADR-0022).
//!
//! Every schema of the protocol is closed: a console built before an
//! optional request field was added answers `400` to a body carrying it (for
//! a heartbeat, the whole heartbeat is lost). The console therefore lists
//! the optional request fields it accepts in `HeartbeatResponse.accepts`,
//! and the agent sends such a field only when the latest heartbeat response
//! listed it: before the first response, when the list is absent, and after
//! a heartbeat rejected with `400` (e.g. a console rolled back), nothing is
//! accepted.
//!
//! Engines added after protocol 0.1.0 are negotiated the same way (ADR-0039
//! decision 8): `Engine`, `Connector` and `AuditSource` are closed enums
//! without a fallback value, so a console built before `cas` rejects any
//! body naming it. Until the console lists `engine.cas`, the agent sends no
//! `cas` connector, target, detected target, finding or event
//! ([`engine_token`], [`ConsoleCapabilities::accepts_engine`]).

use std::collections::BTreeSet;
use std::sync::RwLock;

use databastion_protocol::{
    AuditSource, CapabilityList, Connector, ConnectorList, Engine, HeartbeatRequest, TargetId,
};

/// Contract `CapabilityList.maxItems`: tokens past it are ignored (the
/// generated type does not enforce `maxItems`).
pub(crate) const MAX_CAPABILITIES: usize = 64;

/// Tokens of the optional request fields the agent may send (contract
/// `Capability`).
pub(crate) mod token {
    /// `TargetStatus.notes`.
    pub(crate) const TARGET_STATUS_NOTES: &str = "target_status.notes";
    /// `AccessEvent.bytes`.
    pub(crate) const ACCESS_EVENT_BYTES: &str = "access_event.bytes";
    /// `JobProgress.objects_sampled` and `skipped_*`.
    pub(crate) const JOB_PROGRESS_COVERAGE: &str = "job_progress.coverage";
    /// The `cas` values of `Engine` and `Connector`, and `cas_audit_log` of
    /// `AuditSource` (ADR-0041 decision 12).
    pub(crate) const ENGINE_CAS: &str = "engine.cas";
}

/// The token gating an `Engine` value (ADR-0039 decision 8): `None` for the
/// engines of protocol 0.1.0, always sendable. Exhaustive on purpose: a new
/// contract engine does not compile until it is given its token.
pub(crate) fn engine_token(engine: Engine) -> Option<&'static str> {
    match engine {
        Engine::Postgres | Engine::Mysql | Engine::Mariadb | Engine::Mongodb | Engine::Openldap => {
            None
        }
        Engine::Cas => Some(token::ENGINE_CAS),
    }
}

/// The token gating a `Connector` value (see [`engine_token`]).
pub(crate) fn connector_token(connector: Connector) -> Option<&'static str> {
    match connector {
        Connector::Postgres | Connector::Mysql | Connector::Mongodb | Connector::Openldap => None,
        Connector::Cas => Some(token::ENGINE_CAS),
    }
}

/// The token gating an `AuditSource` value: the token of its engine (see
/// [`engine_token`]).
pub(crate) fn audit_source_token(source: AuditSource) -> Option<&'static str> {
    match source {
        AuditSource::Pgaudit
        | AuditSource::PgStatStatements
        | AuditSource::PgStatActivity
        | AuditSource::MariadbServerAudit
        | AuditSource::MysqlAuditLog
        | AuditSource::PerformanceSchema
        | AuditSource::MongodbAuditLog
        | AuditSource::MongodbProfiler
        | AuditSource::MongodbLog
        | AuditSource::OpenldapAccesslog => None,
        AuditSource::CasAuditLog => Some(token::ENGINE_CAS),
    }
}

/// What the console accepts, from its latest heartbeat response.
#[derive(Debug, Default)]
pub(crate) struct ConsoleCapabilities {
    accepted: RwLock<BTreeSet<String>>,
}

impl ConsoleCapabilities {
    /// Replaces the set with the `accepts` of a heartbeat response (absent:
    /// nothing is accepted). Only the first [`MAX_CAPABILITIES`] tokens are
    /// kept, so a hostile or buggy console cannot grow the set.
    /// Returns whether the set changed.
    pub(crate) fn record(&self, accepts: Option<&CapabilityList>) -> bool {
        let set: BTreeSet<String> = accepts
            .map(|list| {
                list.iter()
                    .take(MAX_CAPABILITIES)
                    .map(|c| c.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let mut accepted = self
            .accepted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = *accepted != set;
        *accepted = set;
        changed
    }

    /// Forgets every capability (heartbeat rejected with `400`).
    pub(crate) fn clear(&self) {
        self.record(None);
    }

    /// Whether the console accepts `token`, or nothing needs accepting
    /// (`None`: a value of protocol 0.1.0).
    pub(crate) fn accepts_gate(&self, token: Option<&str>) -> bool {
        token.is_none_or(|t| self.console_accepts(t))
    }

    /// Whether an `Engine` value may be sent (ADR-0039 decision 8).
    pub(crate) fn accepts_engine(&self, engine: Engine) -> bool {
        self.accepts_gate(engine_token(engine))
    }

    /// Whether a `Connector` value may be sent.
    pub(crate) fn accepts_connector(&self, connector: Connector) -> bool {
        self.accepts_gate(connector_token(connector))
    }

    /// Whether an `AuditSource` value may be sent.
    pub(crate) fn accepts_audit_source(&self, source: AuditSource) -> bool {
        self.accepts_gate(audit_source_token(source))
    }

    /// Whether the latest heartbeat response listed `token`.
    pub(crate) fn console_accepts(&self, token: &str) -> bool {
        self.accepted
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(token)
    }
}

/// Removes from a heartbeat every value of an engine the console has not
/// accepted (ADR-0039 decision 8, ADR-0041 decision 12): such connectors,
/// targets and detected targets are left out, and the `audit_source` of a
/// kept target is dropped if its own token is not accepted. Returns the ids
/// of the targets left out (the caller logs that the console is too old).
pub(crate) fn withhold_unaccepted_engines(
    heartbeat: &mut HeartbeatRequest,
    caps: &ConsoleCapabilities,
) -> Vec<TargetId> {
    heartbeat
        .connectors
        .0
        .retain(|c| caps.accepts_connector(*c));
    let mut withheld = Vec::new();
    heartbeat.targets.retain(|t| {
        let keep = caps.accepts_engine(t.engine);
        if !keep {
            withheld.push(t.target_id.clone());
        }
        keep
    });
    for t in &mut heartbeat.targets {
        if t.audit_source
            .is_some_and(|s| !caps.accepts_audit_source(s))
        {
            t.audit_source = None;
        }
    }
    heartbeat
        .detected_targets
        .retain(|d| caps.accepts_engine(d.engine));
    withheld
}

/// The connectors sent in `/enroll`: those of protocol 0.1.0 only, since
/// enrollment precedes every heartbeat response, so no engine token can be
/// known yet. The others are reported by the first heartbeat whose
/// predecessor's response listed their token.
pub(crate) fn enroll_connectors(mut connectors: ConnectorList) -> ConnectorList {
    connectors.0.retain(|c| connector_token(*c).is_none());
    connectors
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn list(tokens: &[&str]) -> CapabilityList {
        serde_json::from_value(serde_json::json!(tokens)).unwrap()
    }

    #[test]
    fn nothing_is_accepted_before_the_first_response() {
        let caps = ConsoleCapabilities::default();
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(!caps.console_accepts(token::ACCESS_EVENT_BYTES));
        assert!(!caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
    }

    #[test]
    fn the_latest_response_wins() {
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list(&[
            token::ACCESS_EVENT_BYTES,
            token::TARGET_STATUS_NOTES,
            "future.feature",
        ])));
        assert!(caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(caps.console_accepts(token::ACCESS_EVENT_BYTES));
        assert!(!caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
        caps.record(Some(&list(&[token::JOB_PROGRESS_COVERAGE])));
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
    }

    #[test]
    fn an_absent_list_or_a_rejected_heartbeat_accepts_nothing() {
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list(&[token::TARGET_STATUS_NOTES])));
        caps.record(None);
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        caps.record(Some(&list(&[token::TARGET_STATUS_NOTES])));
        caps.clear();
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
    }

    #[test]
    fn tokens_past_the_contract_bound_are_ignored() {
        let mut tokens: Vec<String> = (0..MAX_CAPABILITIES)
            .map(|i| format!("filler.f{i}"))
            .collect();
        tokens.push(token::TARGET_STATUS_NOTES.to_owned());
        let list: CapabilityList = serde_json::from_value(serde_json::json!(tokens)).unwrap();
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list));
        assert!(caps.console_accepts("filler.f0"));
        assert!(caps.console_accepts(&format!("filler.f{}", MAX_CAPABILITIES - 1)));
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
    }

    #[test]
    fn engines_of_protocol_0_1_0_need_no_token() {
        let caps = ConsoleCapabilities::default();
        for e in [
            Engine::Postgres,
            Engine::Mysql,
            Engine::Mariadb,
            Engine::Mongodb,
            Engine::Openldap,
        ] {
            assert_eq!(engine_token(e), None);
            assert!(caps.accepts_engine(e));
        }
        for c in [
            Connector::Postgres,
            Connector::Mysql,
            Connector::Mongodb,
            Connector::Openldap,
        ] {
            assert!(caps.accepts_connector(c));
        }
        assert!(caps.accepts_audit_source(AuditSource::OpenldapAccesslog));
    }

    #[test]
    fn cas_is_sent_only_while_the_console_lists_engine_cas() {
        let caps = ConsoleCapabilities::default();
        assert!(!caps.accepts_engine(Engine::Cas));
        assert!(!caps.accepts_connector(Connector::Cas));
        assert!(!caps.accepts_audit_source(AuditSource::CasAuditLog));
        assert!(caps.record(Some(&list(&[token::ENGINE_CAS]))));
        assert!(caps.accepts_engine(Engine::Cas));
        assert!(caps.accepts_connector(Connector::Cas));
        assert!(caps.accepts_audit_source(AuditSource::CasAuditLog));
        assert!(!caps.record(Some(&list(&[token::ENGINE_CAS]))), "unchanged");
        caps.clear();
        assert!(!caps.accepts_engine(Engine::Cas));
        // A similar token is not the engine's.
        caps.record(Some(&list(&["engine.cas_v2", "engines.cas"])));
        assert!(!caps.accepts_engine(Engine::Cas));
    }

    #[test]
    fn engine_tokens_are_contract_capabilities_named_after_the_value() {
        let gated = [(
            engine_token(Engine::Cas),
            connector_token(Connector::Cas),
            audit_source_token(AuditSource::CasAuditLog),
            "cas",
        )];
        for (engine, connector, source, value) in gated {
            let token = engine.unwrap();
            assert_eq!(token, format!("engine.{value}"));
            assert_eq!(connector, Some(token));
            assert_eq!(source, Some(token));
            assert!(databastion_protocol::Capability::try_from(token).is_ok());
        }
    }

    /// The contract fixture of a heartbeat reporting `cas` targets.
    fn cas_heartbeat() -> HeartbeatRequest {
        serde_json::from_str(include_str!(
            "../../../../shared/protocol/fixtures/valid/HeartbeatRequest.cas.json"
        ))
        .unwrap()
    }

    #[test]
    fn a_heartbeat_reports_no_cas_value_until_the_console_lists_engine_cas() {
        let caps = ConsoleCapabilities::default();
        let mut hb = cas_heartbeat();
        hb.detected_targets.push(
            serde_json::from_value(serde_json::json!({"engine": "cas", "port": 8443})).unwrap(),
        );
        hb.detected_targets.push(
            serde_json::from_value(serde_json::json!({"engine": "postgres", "port": 5432}))
                .unwrap(),
        );
        let withheld = withhold_unaccepted_engines(&mut hb, &caps);
        assert_eq!(
            withheld.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            ["cas-prod", "cas-staging"]
        );
        let json = serde_json::to_string(&hb).unwrap();
        assert!(!json.contains("\"cas\""), "{json}");
        assert!(!json.contains("cas_audit_log"), "{json}");
        assert_eq!(hb.connectors.0.len(), 4);
        assert_eq!(hb.targets.len(), 1);
        assert_eq!(hb.detected_targets.len(), 1);
        // What is left is what a console built before `cas` accepts: the
        // generated types of that console are the 0.1.0 enums.
        for t in &hb.targets {
            assert!(engine_token(t.engine).is_none());
        }

        // Listed: everything is reported.
        caps.record(Some(&list(&[token::ENGINE_CAS])));
        let mut hb = cas_heartbeat();
        let before = serde_json::to_value(&hb).unwrap();
        assert!(withhold_unaccepted_engines(&mut hb, &caps).is_empty());
        assert_eq!(serde_json::to_value(&hb).unwrap(), before);
    }

    #[test]
    fn enrollment_lists_only_the_connectors_of_protocol_0_1_0() {
        let all: ConnectorList = serde_json::from_value(serde_json::json!([
            "postgres", "mysql", "mongodb", "openldap", "cas"
        ]))
        .unwrap();
        let sent = enroll_connectors(all);
        assert_eq!(
            serde_json::to_value(&sent).unwrap(),
            serde_json::json!(["postgres", "mysql", "mongodb", "openldap"])
        );
    }

    #[test]
    fn malformed_tokens_never_reach_the_agent() {
        // The generated `Capability` enforces the contract pattern: a
        // response with a malformed token fails to decode as a whole.
        assert!(
            serde_json::from_value::<CapabilityList>(serde_json::json!(["Target Notes"])).is_err()
        );
    }
}
