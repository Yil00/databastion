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
//! ([`engine_token`], [`ConsoleCapabilities::accepts_engine`]). The same
//! holds for `sqlserver` (`engine.sqlserver`, ADR-0051 decision 8) and for
//! `redis` / `valkey` (`engine.redis`, `engine.valkey`, ADR-0052 decision
//! 12); the `redis` connector and the `redis_*` audit sources serve both
//! engines, so they wait for **both** tokens.
//!
//! In the other direction (ADR-0022 decision 3), the agent lists in
//! `HeartbeatRequest.accepts` the console -> agent fields and value forms
//! introduced after protocol 0.1.0 that this build decodes
//! ([`AGENT_ACCEPTS`]): the console sends one only when the agent's latest
//! heartbeat listed it.

use std::collections::BTreeSet;
use std::sync::RwLock;
use std::time::Instant;

use databastion_protocol::{
    AuditSource, CapabilityList, Connector, ConnectorList, DetectedTargetProcess, Engine,
    HeartbeatRequest, TargetId, TargetStatus,
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
    /// `AccessEvent.objects_overflowed` (ADR-0053).
    pub(crate) const ACCESS_EVENT_OBJECTS_OVERFLOWED: &str = "access_event.objects_overflowed";
    /// `JobProgress.objects_sampled` and `skipped_*`.
    pub(crate) const JOB_PROGRESS_COVERAGE: &str = "job_progress.coverage";
    /// The `cas` values of `Engine` and `Connector`, and `cas_audit_log` of
    /// `AuditSource` (ADR-0041 decision 12).
    pub(crate) const ENGINE_CAS: &str = "engine.cas";
    /// The `sqlserver` values of `Engine` and `Connector`, and the
    /// `sqlserver_*` values of `AuditSource` (ADR-0051 decision 8).
    pub(crate) const ENGINE_SQLSERVER: &str = "engine.sqlserver";
    /// The `TargetNoteLabel` values of the Microsoft SQL Server revision
    /// (ADR-0051 decision 4, ADR-0022 decision 4).
    pub(crate) const NOTE_LABELS_2026_10: &str = "target_status.note_labels.2026_10";
    /// The `TargetNoteLabel` values of the second Microsoft SQL Server
    /// revision (ADR-0051 refinement of 2026-10-14, items 5 to 7; ADR-0022
    /// decision 4): database-scoped event-session permissions, the other
    /// permissions the connector judges by name, and the `check()` reads
    /// named with `privilege.not_evaluated`.
    pub(crate) const NOTE_LABELS_2026_10_B: &str = "target_status.note_labels.2026_10_b";
    /// The `TargetNoteLabel` value of the third Microsoft SQL Server
    /// revision (ADR-0051 refinement option (a'); ADR-0022 decision 4):
    /// `on_failure_probe`.
    pub(crate) const NOTE_LABELS_2026_10_C: &str = "target_status.note_labels.2026_10_c";
    /// The `redis` value of `Engine` (ADR-0052 decision 12).
    pub(crate) const ENGINE_REDIS: &str = "engine.redis";
    /// The `valkey` value of `Engine` (ADR-0052 decision 12).
    pub(crate) const ENGINE_VALKEY: &str = "engine.valkey";
}

/// Tokens of the console -> agent fields and value forms this build
/// accepts (contract `HeartbeatRequest.accepts`, ADR-0022 decision 3).
pub(crate) mod agent_token {
    /// A `KeyPattern` as `SensitiveObject.object` in `audit.configure` jobs
    /// for Redis / Valkey targets (agents built before decode it as an
    /// `Identifier` and would lose the whole job).
    pub(crate) const SENSITIVE_OBJECT_KEY_PATTERN: &str = "sensitive_object.key_pattern";
}

/// What this build lists in `HeartbeatRequest.accepts`.
pub(crate) const AGENT_ACCEPTS: &[&str] = &[agent_token::SENSITIVE_OBJECT_KEY_PATTERN];

/// [`AGENT_ACCEPTS`] as the contract list (every token is a well-formed
/// `Capability`; checked by a test).
pub(crate) fn agent_accepts() -> Option<CapabilityList> {
    let list: Vec<databastion_protocol::Capability> = AGENT_ACCEPTS
        .iter()
        .filter_map(|t| t.parse().ok())
        .collect();
    (!list.is_empty()).then_some(CapabilityList(list))
}

/// No token: a value of protocol 0.1.0.
const UNGATED: &[&str] = &[];
/// `engine.cas`.
const CAS: &[&str] = &[token::ENGINE_CAS];
/// `engine.sqlserver`.
const SQLSERVER: &[&str] = &[token::ENGINE_SQLSERVER];
/// The values shared by Redis and Valkey (the `redis` connector, the
/// `redis_*` audit sources): both tokens (ADR-0052 decision 12).
const REDIS_AND_VALKEY: &[&str] = &[token::ENGINE_REDIS, token::ENGINE_VALKEY];

/// The tokens gating an `Engine` value (ADR-0039 decision 8): none for the
/// engines of protocol 0.1.0, always sendable; otherwise the value is sent
/// only once the console lists every one. Exhaustive on purpose: a new
/// contract engine does not compile until it is given its token.
pub(crate) fn engine_token(engine: Engine) -> &'static [&'static str] {
    match engine {
        Engine::Postgres | Engine::Mysql | Engine::Mariadb | Engine::Mongodb | Engine::Openldap => {
            UNGATED
        }
        Engine::Cas => CAS,
        Engine::Sqlserver => SQLSERVER,
        Engine::Redis => &[token::ENGINE_REDIS],
        Engine::Valkey => &[token::ENGINE_VALKEY],
    }
}

/// The tokens gating a `DetectedTarget.process` value: those of the
/// engines the process can belong to, as the console checks them (contract
/// "Engine-token gate"). A detected target is sent only when both its
/// engine's and its process's tokens are listed (P9-C L1: a Valkey server
/// running as `redis-server` is a `valkey` target with a `redis` process,
/// which a console listing only `engine.valkey` refuses, with the whole
/// heartbeat).
pub(crate) fn process_token(process: DetectedTargetProcess) -> &'static [&'static str] {
    match process {
        DetectedTargetProcess::Postgres
        | DetectedTargetProcess::Mysqld
        | DetectedTargetProcess::Mariadbd
        | DetectedTargetProcess::Mongod
        | DetectedTargetProcess::Slapd => UNGATED,
        DetectedTargetProcess::Sqlservr => SQLSERVER,
        DetectedTargetProcess::RedisServer => &[token::ENGINE_REDIS],
        DetectedTargetProcess::ValkeyServer => &[token::ENGINE_VALKEY],
    }
}

/// The tokens gating a `Connector` value (see [`engine_token`]).
pub(crate) fn connector_token(connector: Connector) -> &'static [&'static str] {
    match connector {
        Connector::Postgres | Connector::Mysql | Connector::Mongodb | Connector::Openldap => {
            UNGATED
        }
        Connector::Cas => CAS,
        Connector::Sqlserver => SQLSERVER,
        Connector::Redis => REDIS_AND_VALKEY,
    }
}

/// The tokens gating an `AuditSource` value: those of its engine, or of
/// both engines for the sources Redis and Valkey share (see
/// [`engine_token`]).
pub(crate) fn audit_source_token(source: AuditSource) -> &'static [&'static str] {
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
        | AuditSource::OpenldapAccesslog => UNGATED,
        AuditSource::CasAuditLog => CAS,
        AuditSource::SqlserverAudit
        | AuditSource::SqlserverXevents
        | AuditSource::SqlserverQueryStats => SQLSERVER,
        AuditSource::RedisSlowlog
        | AuditSource::RedisCommandlog
        | AuditSource::RedisAclLog
        | AuditSource::RedisSync => REDIS_AND_VALKEY,
    }
}

/// How long gated fields may wait for a heartbeat answer while the
/// capability set is not known (see [`ConsoleCapabilities::settled`]): two
/// of the longest heartbeat intervals the agent accepts, so one heartbeat
/// lost on the way does not strip them. Counted from the latest heartbeat
/// attempt that failed with a transport error, until a result endpoint
/// answers: during an outage the hold does not run out.
pub(crate) const UNKNOWN_HOLD: std::time::Duration =
    std::time::Duration::from_secs(2 * crate::backoff::HEARTBEAT_MAX_S.unsigned_abs());

/// The longest the set may stay not known before gated fields are stripped
/// anyway, whatever the heartbeats do (heartbeats failing while `/events`
/// works must not hold events until the spool evicts them).
pub(crate) const UNKNOWN_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

/// What the console accepts, from its latest heartbeat response.
///
/// The set is **not known** from the start of the agent until the first
/// heartbeat response, and again from a [`clear`](Self::clear) (a `400` on
/// a gated field or on a heartbeat) until the next response. Gated
/// `AccessEvent` fields are spooled in full and stripped at send time
/// (ADR-0053 decision 2): batches carrying them wait while the set is not
/// known (see [`settled`](Self::settled)), so that events spooled before a
/// response keep fields the console then lists.
#[derive(Debug)]
pub(crate) struct ConsoleCapabilities {
    accepted: RwLock<Accepted>,
}

#[derive(Debug)]
struct Accepted {
    tokens: BTreeSet<String>,
    /// Since when the set has not been known; `None` once a heartbeat
    /// response recorded it (or after a clear that did not hold).
    unknown_since: Option<Instant>,
    /// Start of the current hold: `unknown_since`, moved to every heartbeat
    /// attempt the console did not answer since.
    hold_from: Option<Instant>,
    /// When a clear last started a hold (security review M1): a clear
    /// within [`UNKNOWN_HOLD`] of it does not hold again.
    last_hold: Option<Instant>,
    /// A result endpoint (`/events`, `/findings`) answered since the set
    /// became unknown: the console is reachable, so unanswered heartbeats
    /// no longer restart the hold (re-review N1).
    results_answered: bool,
}

/// The capability set read once (security review I-2): the tokens and
/// whether gated fields may be decided now.
#[derive(Debug, Default)]
pub(crate) struct Snapshot {
    tokens: BTreeSet<String>,
    settled: bool,
}

impl Snapshot {
    /// Whether the set listed `token`.
    pub(crate) fn accepts(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }

    /// See [`ConsoleCapabilities::settled`].
    pub(crate) fn settled(&self) -> bool {
        self.settled
    }

    /// A snapshot of a known set listing `tokens` (tests).
    #[cfg(test)]
    pub(crate) fn listing(tokens: &[&str]) -> Self {
        Self {
            tokens: tokens.iter().map(|t| (*t).to_owned()).collect(),
            settled: true,
        }
    }
}

impl Default for ConsoleCapabilities {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            accepted: RwLock::new(Accepted {
                tokens: BTreeSet::new(),
                unknown_since: Some(now),
                hold_from: Some(now),
                last_hold: None,
                results_answered: false,
            }),
        }
    }
}

impl ConsoleCapabilities {
    /// Replaces the set with the `accepts` of a heartbeat response (absent:
    /// nothing is accepted); the set is then known. Only the first
    /// [`MAX_CAPABILITIES`] tokens are kept, so a hostile or buggy console
    /// cannot grow the set. Returns whether the set changed, or became
    /// known.
    pub(crate) fn record(&self, accepts: Option<&CapabilityList>) -> bool {
        let set: BTreeSet<String> = accepts
            .map(|list| {
                list.iter()
                    .take(MAX_CAPABILITIES)
                    .map(|c| c.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let mut accepted = self.write();
        let changed = accepted.tokens != set || accepted.unknown_since.is_some();
        accepted.tokens = set;
        accepted.unknown_since = None;
        accepted.hold_from = None;
        changed
    }

    /// Forgets every capability (a `400` on a heartbeat or on a gated
    /// field): nothing is accepted, and the set is not known until the next
    /// heartbeat response. At most one clear per [`UNKNOWN_HOLD`] starts a
    /// hold (security review M1): an older replica refusing a field after
    /// every heartbeat that lists it would otherwise let one gated batch
    /// through per heartbeat. A clear within that window leaves the set
    /// known and empty, so batches are stripped at once.
    pub(crate) fn clear(&self) {
        self.clear_at(Instant::now());
    }

    pub(crate) fn clear_at(&self, now: Instant) {
        let mut accepted = self.write();
        accepted.tokens.clear();
        if accepted.unknown_since.is_some() {
            return;
        }
        if accepted
            .last_hold
            .is_some_and(|t| now.saturating_duration_since(t) < UNKNOWN_HOLD)
        {
            return;
        }
        accepted.unknown_since = Some(now);
        accepted.hold_from = Some(now);
        accepted.last_hold = Some(now);
        accepted.results_answered = false;
    }

    /// A heartbeat attempt that failed with a transport error: while the
    /// set is not known, and no result endpoint has answered since, the
    /// hold restarts from it (security review L1), so batches spooled
    /// during an outage keep their fields until the console answers.
    pub(crate) fn unanswered(&self) {
        self.unanswered_at(Instant::now());
    }

    pub(crate) fn unanswered_at(&self, now: Instant) {
        let mut accepted = self.write();
        if accepted.unknown_since.is_some() && !accepted.results_answered {
            accepted.hold_from = Some(now);
        }
    }

    /// A result endpoint answered (an ack or a contract error): the console
    /// is reachable, so the current hold is no longer extended by
    /// unanswered heartbeats.
    pub(crate) fn result_answered(&self) {
        let mut accepted = self.write();
        if accepted.unknown_since.is_some() && !accepted.results_answered {
            accepted.results_answered = true;
        }
    }

    /// Whether gated fields may be decided at `now`: the set is known, or
    /// the console has not answered for [`UNKNOWN_HOLD`] since the latest
    /// unanswered heartbeat attempt (or since the set became unknown), or
    /// the set has not been known for [`UNKNOWN_MAX`] (a console whose
    /// heartbeats keep failing must not hold events forever; they are then
    /// sent without the unlisted fields).
    #[cfg(test)]
    pub(crate) fn settled(&self, now: Instant) -> bool {
        Self::settled_in(&self.read(), now)
    }

    fn settled_in(a: &Accepted, now: Instant) -> bool {
        let since = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t));
        match (since(a.unknown_since), since(a.hold_from)) {
            (None, _) => true,
            (Some(total), hold) => total >= UNKNOWN_MAX || hold.is_none_or(|h| h >= UNKNOWN_HOLD),
        }
    }

    /// The set and [`settled`](Self::settled), read once.
    pub(crate) fn snapshot(&self, now: Instant) -> Snapshot {
        let a = self.read();
        Snapshot {
            tokens: a.tokens.clone(),
            settled: Self::settled_in(&a, now),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Accepted> {
        self.accepted
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Accepted> {
        self.accepted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the console accepts every one of `tokens` (none: a value of
    /// protocol 0.1.0).
    pub(crate) fn accepts_gate(&self, tokens: &[&str]) -> bool {
        tokens.iter().all(|t| self.console_accepts(t))
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
        self.read().tokens.contains(token)
    }
}

/// Whether a target status carries a gated field (ADR-0022):
/// `notes` (`target_status.notes`; the note-label revisions are values
/// inside it) and `name_case` (`target_status.name_case`, ADR-0055). A new
/// gated `TargetStatus` field must be added here and in
/// [`strip_gated_target_status`].
pub(crate) fn target_status_carries_gated(t: &TargetStatus) -> bool {
    !t.notes.is_empty() || t.name_case.is_some()
}

/// Removes every gated field of a target status (see
/// [`target_status_carries_gated`]).
pub(crate) fn strip_gated_target_status(t: &mut TargetStatus) {
    t.notes.clear();
    t.name_case = None;
}

/// Strips the gated fields of every target status of a heartbeat, for its
/// resend after a `400` reporting an unknown field (ADR-0022 decision 9).
/// Returns whether anything was stripped: `false` means the heartbeat
/// carried no gated field, so the refusal is not about one and the
/// heartbeat is not resent.
pub(crate) fn strip_gated_heartbeat(heartbeat: &mut HeartbeatRequest) -> bool {
    let mut stripped = false;
    for t in &mut heartbeat.targets {
        if target_status_carries_gated(t) {
            strip_gated_target_status(t);
            stripped = true;
        }
    }
    stripped
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
    heartbeat.detected_targets.retain(|d| {
        caps.accepts_engine(d.engine)
            && d.process
                .is_none_or(|p| caps.accepts_gate(process_token(p)))
    });
    withheld
}

/// The connectors sent in `/enroll`: those of protocol 0.1.0 only, since
/// enrollment precedes every heartbeat response, so no engine token can be
/// known yet. The others are reported by the first heartbeat whose
/// predecessor's response listed their token.
pub(crate) fn enroll_connectors(mut connectors: ConnectorList) -> ConnectorList {
    connectors.0.retain(|c| connector_token(*c).is_empty());
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
    fn the_agent_lists_every_token_it_decodes() {
        let sent = agent_accepts().unwrap();
        let tokens: Vec<&str> = sent.iter().map(|c| c.as_str()).collect();
        assert_eq!(tokens, AGENT_ACCEPTS);
        assert_eq!(tokens, ["sensitive_object.key_pattern"]);
        // A contract `CapabilityList` once serialized.
        let json = serde_json::to_value(&sent).unwrap();
        let back: CapabilityList = serde_json::from_value(json).unwrap();
        assert_eq!(back.len(), AGENT_ACCEPTS.len());
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

    /// ADR-0053 decision 2: the set is not known before the first
    /// response and after a clear, until the next response or the hold.
    #[test]
    fn the_set_is_settled_by_a_response_or_after_the_hold() {
        use std::time::Duration;
        let caps = ConsoleCapabilities::default();
        let now = Instant::now();
        assert!(!caps.settled(now));
        assert!(!caps.snapshot(now).settled());
        assert!(caps.settled(now + UNKNOWN_HOLD + Duration::from_secs(1)));
        // An empty answer is an answer: the set became known.
        assert!(caps.record(None), "known now");
        assert!(caps.settled(now));
        assert!(!caps.record(None), "unchanged");
        caps.record(Some(&list(&[token::ACCESS_EVENT_OBJECTS_OVERFLOWED])));
        assert!(
            caps.snapshot(now)
                .accepts(token::ACCESS_EVENT_OBJECTS_OVERFLOWED)
        );
        let t0 = Instant::now();
        caps.clear_at(t0);
        assert!(!caps.settled(t0));
        assert!(!caps.console_accepts(token::ACCESS_EVENT_OBJECTS_OVERFLOWED));
        // A second clear does not restart the hold.
        caps.clear_at(t0 + Duration::from_secs(60));
        assert!(caps.settled(t0 + UNKNOWN_HOLD));
        assert!(caps.record(Some(&list(&[token::ACCESS_EVENT_OBJECTS_OVERFLOWED]))));
        assert!(caps.settled(t0));
        assert_eq!(UNKNOWN_HOLD, Duration::from_secs(600));
    }

    /// Security review M1: within [`UNKNOWN_HOLD`] of the clear that last
    /// started a hold, a clear leaves the set known and empty (no hold);
    /// once the window has passed, a clear holds again.
    #[test]
    fn a_clear_holds_at_most_once_per_window() {
        use std::time::Duration;
        let caps = ConsoleCapabilities::default();
        let t0 = Instant::now();
        let listed = || list(&[token::ACCESS_EVENT_OBJECTS_OVERFLOWED]);
        caps.record(Some(&listed()));
        caps.clear_at(t0);
        assert!(!caps.settled(t0));
        for minute in 1..10 {
            let t = t0 + Duration::from_secs(60 * minute);
            caps.record(Some(&listed()));
            caps.clear_at(t);
            assert!(caps.settled(t), "minute {minute}: no second hold");
            assert!(!caps.console_accepts(token::ACCESS_EVENT_OBJECTS_OVERFLOWED));
        }
        let later = t0 + UNKNOWN_HOLD;
        caps.record(Some(&listed()));
        caps.clear_at(later);
        assert!(!caps.settled(later), "a new window: holds again");
    }

    /// Re-review N1: once a result endpoint has answered, unanswered
    /// heartbeats no longer restart the hold; a new hold starts afresh.
    #[test]
    fn a_result_answer_stops_extending_the_hold() {
        use std::time::Duration;
        let caps = ConsoleCapabilities::default();
        let t0 = Instant::now();
        caps.unanswered_at(t0 + Duration::from_secs(300));
        assert!(!caps.settled(t0 + Duration::from_secs(800)));
        caps.result_answered();
        caps.unanswered_at(t0 + Duration::from_secs(600));
        assert!(caps.settled(t0 + Duration::from_secs(900)), "not extended");
        // A later hold (after an answer and a clear) is extended again.
        caps.record(None);
        let t1 = t0 + Duration::from_secs(2000);
        caps.clear_at(t1);
        caps.unanswered_at(t1 + Duration::from_secs(300));
        assert!(!caps.settled(t1 + Duration::from_secs(800)));
    }

    /// Security review L1: unanswered heartbeat attempts restart the hold,
    /// up to [`UNKNOWN_MAX`]; they do nothing while the set is known.
    #[test]
    fn unanswered_heartbeats_restart_the_hold_up_to_the_cap() {
        use std::time::Duration;
        let caps = ConsoleCapabilities::default();
        let t0 = Instant::now();
        let mut t = t0;
        while t < t0 + UNKNOWN_MAX - UNKNOWN_HOLD {
            t += Duration::from_secs(300);
            caps.unanswered_at(t);
            assert!(!caps.settled(t + Duration::from_secs(299)));
        }
        caps.unanswered_at(t0 + UNKNOWN_MAX);
        assert!(caps.settled(t0 + UNKNOWN_MAX), "the cap");
        assert_eq!(UNKNOWN_MAX, Duration::from_secs(3600));
        caps.record(None);
        caps.unanswered_at(t0 + UNKNOWN_MAX);
        assert!(caps.settled(t0), "known: an outage does not unsettle it");
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
            assert!(engine_token(e).is_empty());
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
        for (engine, value) in [
            (Engine::Cas, "cas"),
            (Engine::Sqlserver, "sqlserver"),
            (Engine::Redis, "redis"),
            (Engine::Valkey, "valkey"),
        ] {
            assert_eq!(engine_token(engine), [format!("engine.{value}").as_str()]);
            assert_eq!(engine.to_string(), value);
            assert!(databastion_protocol::Capability::try_from(engine_token(engine)[0]).is_ok());
        }
        assert_eq!(connector_token(Connector::Cas), engine_token(Engine::Cas));
        assert_eq!(
            audit_source_token(AuditSource::CasAuditLog),
            engine_token(Engine::Cas)
        );
        assert_eq!(
            connector_token(Connector::Sqlserver),
            engine_token(Engine::Sqlserver)
        );
        for s in [
            AuditSource::SqlserverAudit,
            AuditSource::SqlserverXevents,
            AuditSource::SqlserverQueryStats,
        ] {
            assert_eq!(audit_source_token(s), engine_token(Engine::Sqlserver));
        }
        // One connector and four sources serve Redis and Valkey: both tokens.
        let both = [token::ENGINE_REDIS, token::ENGINE_VALKEY];
        assert_eq!(connector_token(Connector::Redis), both);
        for s in [
            AuditSource::RedisSlowlog,
            AuditSource::RedisCommandlog,
            AuditSource::RedisAclLog,
            AuditSource::RedisSync,
        ] {
            assert_eq!(audit_source_token(s), both);
        }
    }

    #[test]
    fn sqlserver_redis_and_valkey_values_wait_for_their_tokens() {
        let caps = ConsoleCapabilities::default();
        for e in [Engine::Sqlserver, Engine::Redis, Engine::Valkey] {
            assert!(!caps.accepts_engine(e));
        }
        assert!(!caps.accepts_connector(Connector::Sqlserver));
        assert!(!caps.accepts_connector(Connector::Redis));
        assert!(!caps.accepts_audit_source(AuditSource::SqlserverXevents));
        assert!(!caps.accepts_audit_source(AuditSource::RedisSlowlog));

        caps.record(Some(&list(&[token::ENGINE_SQLSERVER])));
        assert!(caps.accepts_engine(Engine::Sqlserver));
        assert!(caps.accepts_connector(Connector::Sqlserver));
        assert!(caps.accepts_audit_source(AuditSource::SqlserverAudit));
        assert!(!caps.accepts_engine(Engine::Redis));

        // One of the two tokens: that engine's targets, but not the shared
        // connector nor the shared sources.
        caps.record(Some(&list(&[token::ENGINE_REDIS])));
        assert!(caps.accepts_engine(Engine::Redis));
        assert!(!caps.accepts_engine(Engine::Valkey));
        assert!(!caps.accepts_connector(Connector::Redis));
        assert!(!caps.accepts_audit_source(AuditSource::RedisAclLog));
        caps.record(Some(&list(&[token::ENGINE_VALKEY])));
        assert!(caps.accepts_engine(Engine::Valkey));
        assert!(!caps.accepts_connector(Connector::Redis));
        assert!(!caps.accepts_audit_source(AuditSource::RedisSync));

        caps.record(Some(&list(&[token::ENGINE_REDIS, token::ENGINE_VALKEY])));
        assert!(caps.accepts_connector(Connector::Redis));
        assert!(caps.accepts_audit_source(AuditSource::RedisCommandlog));
        assert!(!caps.accepts_engine(Engine::Sqlserver));
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
            assert!(engine_token(t.engine).is_empty());
        }

        // Listed: everything is reported.
        caps.record(Some(&list(&[token::ENGINE_CAS])));
        let mut hb = cas_heartbeat();
        let before = serde_json::to_value(&hb).unwrap();
        assert!(withhold_unaccepted_engines(&mut hb, &caps).is_empty());
        assert_eq!(serde_json::to_value(&hb).unwrap(), before);
    }

    #[test]
    fn detected_targets_wait_for_their_process_token_too() {
        // A Valkey server started as `redis-server`: a `valkey` detected
        // target with a `redis-server` process (P9-C L1).
        let mut hb: HeartbeatRequest = serde_json::from_value(serde_json::json!({
            "agent_version": "0.7.0",
            "connectors": ["redis"],
            "targets": [],
            "detected_targets": [
                {"engine": "valkey", "process": "redis-server"},
                {"engine": "valkey", "process": "valkey-server"},
                {"engine": "redis", "port": 6379},
                {"engine": "postgres", "process": "postgres"}
            ],
            "ts": "2026-10-14T00:00:00Z",
            "uptime_s": 1,
            "spool": {"bytes": 0, "max_bytes": 1, "batches": 0}
        }))
        .unwrap();
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list(&[token::ENGINE_VALKEY])));
        let mut only_valkey = hb.clone();
        withhold_unaccepted_engines(&mut only_valkey, &caps);
        let json = serde_json::to_string(&only_valkey.detected_targets).unwrap();
        assert!(!json.contains("redis-server"), "{json}");
        assert!(json.contains("valkey-server"), "{json}");
        assert!(!json.contains(r#""engine":"redis""#), "{json}");
        assert!(json.contains("postgres"), "{json}");
        // The shared connector needs both tokens.
        assert!(only_valkey.connectors.0.is_empty());

        caps.record(Some(&list(&[token::ENGINE_VALKEY, token::ENGINE_REDIS])));
        withhold_unaccepted_engines(&mut hb, &caps);
        assert_eq!(hb.detected_targets.len(), 4);
        assert_eq!(hb.connectors.0, vec![Connector::Redis]);
        assert_eq!(
            process_token(DetectedTargetProcess::RedisServer),
            [token::ENGINE_REDIS]
        );
        assert!(process_token(DetectedTargetProcess::Slapd).is_empty());
    }

    #[test]
    fn enrollment_lists_only_the_connectors_of_protocol_0_1_0() {
        let all: ConnectorList = serde_json::from_value(serde_json::json!([
            "postgres",
            "mysql",
            "mongodb",
            "openldap",
            "cas",
            "sqlserver",
            "redis"
        ]))
        .unwrap();
        let sent = enroll_connectors(all);
        assert_eq!(
            serde_json::to_value(&sent).unwrap(),
            serde_json::json!(["postgres", "mysql", "mongodb", "openldap"])
        );
    }

    /// ADR-0055: `name_case` is a gated `TargetStatus` field, like
    /// `notes`: a heartbeat carrying either is stripped of both for its
    /// resend; one carrying neither is not resent.
    #[test]
    fn gated_target_status_fields_are_stripped_for_a_resend() {
        for fixture in [
            include_str!(
                "../../../../shared/protocol/fixtures/valid/HeartbeatRequest.name-case-sqlserver.json"
            ),
            include_str!(
                "../../../../shared/protocol/fixtures/valid/HeartbeatRequest.name-case-mysql-mariadb.json"
            ),
        ] {
            let mut hb: HeartbeatRequest = serde_json::from_str(fixture).unwrap();
            // Security review L2: `except` sorted by name, one entry per name.
            for t in &hb.targets {
                let names: Vec<&[u8]> = t
                    .name_case
                    .iter()
                    .flat_map(|n| &n.except)
                    .map(|e| e.database.as_str().as_bytes())
                    .collect();
                assert!(names.windows(2).all(|w| w[0] < w[1]), "{names:?}");
            }
            assert!(hb.targets.iter().all(target_status_carries_gated));
            assert!(strip_gated_heartbeat(&mut hb));
            assert!(!hb.targets.iter().any(target_status_carries_gated));
            let text = serde_json::to_string(&hb).unwrap();
            assert!(!text.contains("name_case") && !text.contains("notes"));
            // The rest of each status is kept.
            assert_eq!(hb.targets.len(), 3);
            assert!(!strip_gated_heartbeat(&mut hb), "nothing left to strip");
        }

        let mut notes_only: HeartbeatRequest = serde_json::from_str(include_str!(
            "../../../../shared/protocol/fixtures/valid/HeartbeatRequest.target-notes.json"
        ))
        .unwrap();
        assert!(notes_only.targets.iter().any(target_status_carries_gated));
        assert!(strip_gated_heartbeat(&mut notes_only));
        assert!(notes_only.targets.iter().all(|t| t.notes.is_empty()));
    }

    /// Security review I-2 (ADR-0055 contract): a target status with every
    /// optional field set keeps, once stripped, exactly the fields of
    /// protocol 0.1.0. The destructuring below has no `..`: a field added
    /// to `TargetStatus` does not compile until it is classified here (and,
    /// if gated, in [`target_status_carries_gated`] and
    /// [`strip_gated_target_status`]).
    #[test]
    fn stripping_a_target_status_leaves_only_the_0_1_0_fields() {
        let mut t: TargetStatus = serde_json::from_value(serde_json::json!({
            "target_id": "mssql-prod",
            "engine": "sqlserver",
            "edition": "enterprise",
            "server_version": "16.0.4305.5",
            "reachable": true,
            "audit_level": "partial",
            "audit_source": "sqlserver_audit",
            "last_error": "timeout",
            "notes": [{"code": "check.timed_out"}],
            "name_case": {
                "databases": "insensitive",
                "objects": "insensitive",
                "except": [{"database": "crm_cs", "objects": "sensitive"}]
            },
            "metrics": {"checks_total": 1}
        }))
        .unwrap();
        let TargetStatus {
            audit_level: _,
            audit_source,
            edition,
            engine: _,
            last_error,
            metrics,
            name_case,
            notes,
            reachable: _,
            server_version,
            target_id: _,
        } = &t;
        assert!(audit_source.is_some() && edition.is_some() && last_error.is_some());
        assert!(metrics.is_some() && server_version.is_some());
        assert!(name_case.is_some() && !notes.is_empty());
        assert!(target_status_carries_gated(&t));
        strip_gated_target_status(&mut t);
        assert!(!target_status_carries_gated(&t));
        let value = serde_json::to_value(&t).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "audit_level",
                "audit_source",
                "edition",
                "engine",
                "last_error",
                "metrics",
                "reachable",
                "server_version",
                "target_id",
            ]
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
