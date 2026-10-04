//! `check()`: reachability, honest audit level, over-privilege and
//! coverage (ADR-0012 obligation 6).
//!
//! Audit level, per docs/08, ADR-0012 obligation 6 and ADR-0015 decision 4,
//! reporting only what can be proven without `pg_read_all_settings`:
//! - **Full**: the audit log configured in `agent.yaml`
//!   (`postgres.audit_log`) is readable by the agent, pgaudit is loaded
//!   with the `read` class in `pgaudit.log` for a monitored database, and
//!   its records carry row counts: `pgaudit.log_rows` is proven on
//!   ([`pgaudit_rows_on`]). `pg_stat_statements` is not a volume source for
//!   Full: the Full stream reads the pgaudit log only (ADR-0037).
//! - **Partial**: the log is readable and pgaudit logs reads without row
//!   counts (`pgaudit.log_rows` off, or not defined before pgaudit 1.6),
//!   or only object audit is set (`pgaudit.role`, reads of the objects
//!   granted to that role). The stream still reads the pgaudit log; volume
//!   signals are absent. Reads without row counts are reported with the
//!   closed note `audit.log_without_row_counts`.
//! - **Limited**: `pg_stat_statements` is installed in a monitored database
//!   and loaded (its `pg_stat_statements_info` view, a member of the
//!   extension, answers), and the role sees other users' statements
//!   (member of `pg_read_all_stats`, or superuser).
//! - **None** otherwise.
//!
//! The source reported with the level (heartbeat `audit_source`) is
//! `pgaudit` for Full / Partial and `pg_stat_statements` for Limited: the
//! same choice as the Audit stream.
//!
//! Over-privilege (warned, not refused): superuser, `BYPASSRLS`,
//! replication, `CREATEROLE` / `CREATEDB`, membership of any role but
//! `pg_read_all_stats` (and `pg_read_all_data` / `pg_read_all_settings`
//! with the extended-variant flag, then an expected warning), write-type
//! privileges on user relations, `UPDATE` on sequences, ownership of
//! objects. Coverage: schemas without `USAGE`, relations without
//! `SELECT`, relations skipped for row-level security, and an enabled
//! `login` event trigger (PostgreSQL 17+).
//!
//! The detailed report (privileges, coverage) is recomputed at most every
//! [`REPORT_INTERVAL`] per database and logged when it changes; the
//! reachability and the audit level are checked on every call.
//!
//! Every explanation is also reported as a closed note
//! (`TargetHealth::notes`, `shared/protocol/target-notes.json`): a code, a
//! count and closed labels, never a name or any other text from the
//! server. Notes of several databases are merged per code: counts of
//! per-database facts (relations, schemas, owned objects) are added up,
//! cluster-wide facts (role attributes and memberships) are kept once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::EventSource;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditLevel, CountMerge, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};

use crate::catalog;
use crate::conn::{Session, Timeouts};
use crate::discover::normalize;
use crate::error::{PgError, Stage};
use crate::sql;

/// Statement timeout of `check()` queries.
const CHECK_STATEMENT_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Period of the detailed report.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);
/// Most names listed per category in a log line.
const MAX_LOGGED_NAMES: usize = 20;

/// Audit prerequisites of one database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AuditProbe {
    pub(crate) pss_installed: bool,
    pub(crate) pss_loaded: bool,
    pub(crate) stats_visible: bool,
    pub(crate) pgaudit_installed: bool,
    /// The pgaudit library is loaded (its own `pgaudit.log_catalog`
    /// setting is listed by `pg_settings`) and `pgaudit.log` is readable
    /// without `pg_read_all_settings`: `Some(true)`; not loaded:
    /// `Some(false)`; not readable: `None`.
    pub(crate) pgaudit_loaded: Option<bool>,
    /// `pgaudit.*` settings are set while the library is not loaded
    /// (placeholders): noted, and no pgaudit level.
    pub(crate) pgaudit_placeholders: bool,
    /// `pgaudit.log` enables the `read` class in this database.
    pub(crate) pgaudit_reads: bool,
    /// `pgaudit.log_rows` is on.
    pub(crate) pgaudit_rows: bool,
    /// `pgaudit.role` is set (object audit).
    pub(crate) pgaudit_object_audit: bool,
    /// `pgaudit.log_level` (severity of the pgaudit records).
    pub(crate) pgaudit_log_level: Option<String>,
    /// `pgaudit.log_catalog` (pgaudit loaded only).
    pub(crate) pgaudit_log_catalog: Option<bool>,
    /// Schema of the `pg_stat_statements` extension (its info view).
    pub(crate) pss_schema: Option<String>,
}

/// Whether a `pgaudit.log` value enables the `read` class: `read` or `all`
/// listed, and `-read` not listed.
pub(crate) fn pgaudit_logs_reads(setting: &str) -> bool {
    let items: Vec<String> = setting
        .split(',')
        .map(|i| i.trim().to_ascii_lowercase())
        .collect();
    items.iter().any(|i| i == "read" || i == "all") && !items.iter().any(|i| i == "-read")
}

/// Whether `pgaudit.log_rows` gives row counts: the library is loaded, it
/// defines the setting (listed by `pg_settings` as a boolean; pgaudit
/// before 1.6, built for PostgreSQL 13, does not), and its value is `on`.
/// A value alone may be a placeholder that `current_setting()` still
/// returns, while the records carry no row count.
pub(crate) fn pgaudit_rows_on(library: bool, defined: bool, value: Option<&str>) -> bool {
    library && defined && value.is_some_and(|v| v.eq_ignore_ascii_case("on"))
}

impl AuditProbe {
    /// pgaudit is loaded and logs reads in this database, but its records carry no row count.
    pub(crate) fn reads_without_row_counts(&self) -> bool {
        self.pgaudit_loaded == Some(true) && self.pgaudit_reads && !self.pgaudit_rows
    }

    /// Level proven in this database; `log_readable`: the configured audit
    /// log can be read by the agent.
    ///
    /// Full needs the row counts of the source it is read from (ADR-0037,
    /// refining ADR-0015 decision 4): `pgaudit.log_rows`, since the stream
    /// at Full reads the pgaudit log only and never polls
    /// `pg_stat_statements`.
    pub(crate) fn level(&self, log_readable: bool) -> AuditLevel {
        let limited = self.pss_installed && self.pss_loaded && self.stats_visible;
        let pgaudit = self.pgaudit_loaded == Some(true);
        if log_readable && pgaudit && self.pgaudit_reads && self.pgaudit_rows {
            AuditLevel::Full
        } else if log_readable && pgaudit && (self.pgaudit_reads || self.pgaudit_object_audit) {
            AuditLevel::Partial
        } else if limited {
            AuditLevel::Limited
        } else {
            AuditLevel::None
        }
    }
}

/// Privileges and coverage of the role in one database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Closed labels (role attributes, predefined roles, counts).
    pub(crate) over_privileged: Vec<String>,
    /// Expected with the extended-variant flag.
    pub(crate) expected: Vec<String>,
    /// The same privileges as closed notes.
    pub(crate) privilege_notes: Vec<TargetNote>,
    pub(crate) schemas_not_covered: Vec<String>,
    pub(crate) coverage: catalog::Coverage,
    pub(crate) login_event_trigger: bool,
}

/// Role attributes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RoleAttributes {
    pub(crate) superuser: bool,
    pub(crate) bypassrls: bool,
    pub(crate) replication: bool,
    pub(crate) createrole: bool,
    pub(crate) createdb: bool,
}

/// Evaluates over-privilege (obligation 6). Returns the over-privileged
/// and expected labels (logs), and the same as closed notes.
pub(crate) fn evaluate_privileges(
    attrs: RoleAttributes,
    memberships: &[(String, bool)],
    write_relations: i64,
    owned_objects: i64,
    extended: bool,
) -> (Vec<String>, Vec<String>, Vec<TargetNote>) {
    let mut over = Vec::new();
    let mut expected = Vec::new();
    let mut attributes = Vec::new();
    for (flag, label) in [
        (attrs.superuser, "superuser"),
        (attrs.bypassrls, "bypassrls"),
        (attrs.replication, "replication"),
        (attrs.createrole, "createrole"),
        (attrs.createdb, "createdb"),
    ] {
        if flag {
            over.push(label.to_owned());
            attributes.push(NoteLabel::parse(label));
        }
    }
    let mut predefined_over = Vec::new();
    let mut predefined_expected = Vec::new();
    let mut other_roles = 0usize;
    for (name, predefined) in memberships {
        match (name.as_str(), predefined) {
            ("pg_read_all_stats", true) => {}
            ("pg_read_all_data" | "pg_read_all_settings", true) if extended => {
                expected.push(format!("member of {name}"));
                predefined_expected.push(NoteLabel::parse(name));
            }
            // Predefined role names are PostgreSQL constants; one this
            // build does not know is the label `other`.
            (_, true) if name.starts_with("pg_") && name.len() <= 64 => {
                over.push(format!("member of {name}"));
                predefined_over.push(NoteLabel::parse(name));
            }
            _ => other_roles += 1,
        }
    }
    let mut notes = Vec::new();
    if !attributes.is_empty() {
        notes.push(TargetNote::new(NoteCode::PrivilegeRoleAttributes).with_labels(attributes));
    }
    if !predefined_over.is_empty() {
        notes
            .push(TargetNote::new(NoteCode::PrivilegePredefinedRoles).with_labels(predefined_over));
    }
    if !predefined_expected.is_empty() {
        notes.push(
            TargetNote::new(NoteCode::PrivilegeExtendedVariant).with_labels(predefined_expected),
        );
    }
    if other_roles > 0 {
        over.push(format!("member of {other_roles} non-predefined role(s)"));
        notes.push(TargetNote::new(NoteCode::PrivilegeOtherRoles).with_count(other_roles as u64));
    }
    if write_relations > 0 {
        over.push(format!("write privilege on {write_relations} relation(s)"));
        notes.push(
            TargetNote::new(NoteCode::PrivilegeWriteOnRelations)
                .with_count(write_relations.unsigned_abs()),
        );
    }
    if owned_objects > 0 {
        over.push(format!("owner of {owned_objects} object(s)"));
        notes.push(
            TargetNote::new(NoteCode::PrivilegeOwnerOfObjects)
                .with_count(owned_objects.unsigned_abs()),
        );
    }
    (over, expected, notes)
}

/// Notes of one database's report, merged into `notes`: per-database
/// counts are added up, cluster-wide facts kept once.
fn report_notes(r: &Report, notes: &mut Notes) {
    for n in &r.privilege_notes {
        let how = match n.code() {
            NoteCode::PrivilegeWriteOnRelations | NoteCode::PrivilegeOwnerOfObjects => {
                CountMerge::Sum
            }
            _ => CountMerge::Max,
        };
        notes.merge(n.clone(), how);
    }
    let c = &r.coverage;
    for (code, n) in [
        (
            NoteCode::CoverageSchemasWithoutUsage,
            r.schemas_not_covered.len(),
        ),
        (
            NoteCode::CoverageRelationsWithoutSelect,
            c.not_readable.len(),
        ),
        (
            NoteCode::CoverageRelationsRlsSkipped,
            c.rls_policy.len() + c.rls_ancestor.len(),
        ),
    ] {
        if n > 0 {
            notes.merge(TargetNote::new(code).with_count(n as u64), CountMerge::Sum);
        }
    }
    if r.login_event_trigger {
        notes.add(TargetNote::new(NoteCode::SecurityLoginEventTrigger));
    }
}

/// The note of an unreachable target: the stage that failed.
fn stage_note(stage: Stage) -> TargetNote {
    TargetNote::new(NoteCode::CheckStageFailed).with_labels([NoteLabel::stage(stage.as_str())])
}

struct Cached {
    at: Instant,
    report: Report,
}

/// Per target and database: last detailed report; per target: source of
/// the last reported level, and when the Audit stream last parsed a
/// pgaudit record.
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<(String, String), Cached>>,
    sources: Mutex<HashMap<String, EventSource>>,
    records: Mutex<HashMap<String, Instant>>,
    /// Per target: records dropped for their severity, and when the
    /// count started (reported for 24 h, then reset).
    severity_mismatches: Mutex<HashMap<String, (u64, Instant)>>,
    /// Per target: records dropped as oversized or damaged (an `AUDIT`
    /// record with an error context), and when the count started.
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
    /// Per target: the agent's own reads, shared by every Audit stream of
    /// the target (see `databastion_core::audit::own::OwnUsage`).
    own_usage: Mutex<HashMap<String, databastion_core::audit::own::SharedOwnUsage>>,
    /// Per target: the table-less statements registered by its streams
    /// (see `audit::events::PgOwn`).
    own_statements: Mutex<HashMap<String, crate::audit::events::SharedOwnStatements>>,
}

/// Full needs a pgaudit record parsed within this period.
pub(crate) const RECORD_FRESHNESS: Duration = Duration::from_secs(24 * 3600);

/// Adds `n` to a per-target count reported for [`RECORD_FRESHNESS`] from
/// its first addition, then restarted.
fn add_windowed(map: &Mutex<HashMap<String, (u64, Instant)>>, target_id: &str, n: u64) {
    let mut map = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = map
        .entry(target_id.to_owned())
        .or_insert((0, Instant::now()));
    if entry.1.elapsed() >= RECORD_FRESHNESS {
        *entry = (0, Instant::now());
    }
    entry.0 = entry.0.saturating_add(n);
}

/// The count of [`add_windowed`], `0` once its window has passed.
fn windowed(map: &Mutex<HashMap<String, (u64, Instant)>>, target_id: &str) -> u64 {
    map.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(target_id)
        .filter(|(_, since)| since.elapsed() < RECORD_FRESHNESS)
        .map_or(0, |(n, _)| *n)
}

impl CheckState {
    /// The Audit stream of `target_id` parsed a pgaudit record.
    pub(crate) fn note_record(&self, target_id: &str) {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), Instant::now());
    }

    /// The agent's own-read counters of `target_id`, created once and kept
    /// for the life of the connector.
    pub(crate) fn own_usage(
        &self,
        target_id: &str,
    ) -> databastion_core::audit::own::SharedOwnUsage {
        std::sync::Arc::clone(
            self.own_usage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// The table-less statements registered for `target_id`, kept for the
    /// life of the connector.
    pub(crate) fn own_statements(
        &self,
        target_id: &str,
    ) -> crate::audit::events::SharedOwnStatements {
        std::sync::Arc::clone(
            self.own_statements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// Records of `target_id` dropped for a severity other than
    /// `pgaudit.log_level`.
    pub(crate) fn note_severity_mismatch(&self, target_id: &str, n: u64) {
        add_windowed(&self.severity_mismatches, target_id, n);
    }

    fn severity_mismatches(&self, target_id: &str) -> u64 {
        windowed(&self.severity_mismatches, target_id)
    }

    /// Records of `target_id` dropped as oversized or damaged.
    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        add_windowed(&self.dropped, target_id, n);
    }

    fn dropped(&self, target_id: &str) -> u64 {
        windowed(&self.dropped, target_id)
    }

    /// Whether a pgaudit record of `target_id` was parsed recently.
    pub(crate) fn recent_record(&self, target_id: &str) -> bool {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .is_some_and(|t| t.elapsed() < RECORD_FRESHNESS)
    }

    /// Source of the level last reported for `target_id`.
    pub(crate) fn audit_source(&self, target_id: &str) -> Option<EventSource> {
        self.sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .copied()
    }

    fn set_source(&self, target_id: &str, level: AuditLevel) {
        let source = match level {
            AuditLevel::Full | AuditLevel::Partial => Some(EventSource::Pgaudit),
            AuditLevel::Limited => Some(EventSource::PgStatStatements),
            AuditLevel::None => None,
        };
        let mut map = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match source {
            Some(s) => {
                map.insert(target_id.to_owned(), s);
            }
            None => {
                map.remove(target_id);
            }
        }
    }

    fn due(&self, key: &(String, String)) -> bool {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .is_none_or(|c| c.at.elapsed() >= REPORT_INTERVAL)
    }

    /// Stores a report; `true` if it differs from the previous one.
    fn store(&self, key: (String, String), report: Report) -> bool {
        let mut map = self
            .reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = map.get(&key).is_none_or(|c| c.report != report);
        map.insert(
            key,
            Cached {
                at: Instant::now(),
                report,
            },
        );
        changed
    }

    fn cached(&self, key: &(String, String)) -> Option<Report> {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .map(|c| c.report.clone())
    }
}

fn unreachable(e: &PgError) -> TargetHealth {
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "{} failed (SQLSTATE {})",
            e.stage.as_str(),
            e.sqlstate().unwrap_or("none")
        )),
        notes: vec![stage_note(e.stage)],
    }
}

/// `check()` of a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let health = match tokio::time::timeout(CHECK_TIMEOUT, check_inner(state, target)).await {
        Ok(h) => h,
        Err(_) => TargetHealth {
            reachable: false,
            audit_level: AuditLevel::None,
            failure: Some(FailureCode::Timeout),
            detail: Some("check timed out".to_owned()),
            notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
        },
    };
    state.set_source(&target.id, health.audit_level);
    health
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let settings = target.postgres_settings();
    let timeouts = Timeouts::new(CHECK_STATEMENT_TIMEOUT);
    let mut level = AuditLevel::None;
    // `notes`: the local log detail; `codes`: the same as closed notes.
    let mut notes: Vec<String> = Vec::new();
    let mut codes = Notes::default();
    if settings.tls == databastion_core::config::PgTlsMode::DisableInsecure {
        notes.push(
            "INSECURE: TLS disabled on a network connection (tls: disable_insecure): traffic \
             in clear, read-only not guaranteed"
                .to_owned(),
        );
        codes.add(TargetNote::new(NoteCode::SecurityTlsDisabled));
    }
    let log_readable = crate::audit::log_readable(target).await;
    if settings.audit_log.is_some() && !log_readable {
        notes.push("the configured audit log is not readable by the agent".to_owned());
        codes.add(TargetNote::new(NoteCode::AuditLogNotReadable));
    }
    // ADR-0037 decision 4: a monitored database whose pgaudit logs reads without row counts, or
    // whose pgaudit settings could not be read, caps the target at Partial, whatever the other
    // databases reach.
    let mut rows_gap = false;
    for database in &settings.databases {
        let session = match Session::connect(target, database, timeouts).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    target_id = %target.id,
                    database = normalize(database).as_str(),
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    code = %e.code,
                    "target check failed"
                );
                return unreachable(&e);
            }
        };
        let probe = match audit_probe(&session, timeouts).await {
            Ok(p) => p,
            Err(e) => return unreachable(&e),
        };
        // CAS store guard (ADR-0041 decision 6): at every heartbeat, so a
        // ticket table recreated with a table grant is reported at once.
        match cas_guard_readable(&session, timeouts, target.cas_stores()).await {
            Ok(0) => {}
            Ok(n) => {
                notes.push(format!(
                    "database {}: the agent's role can read credential columns of {n} CAS \
                     ticket registry or audit trail relation(s) (grant SELECT on the metadata \
                     columns only)",
                    normalize(database).as_str()
                ));
                codes.merge(
                    TargetNote::new(NoteCode::PrivilegeTicketCredentialsReadable).with_count(n),
                    databastion_core::CountMerge::Sum,
                );
            }
            Err(e) => {
                tracing::warn!(
                    target_id = %target.id,
                    database = normalize(database).as_str(),
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    "CAS store guard privilege check failed"
                );
                // Not evaluated: never read as least privilege.
                codes.add(
                    TargetNote::new(NoteCode::CheckStageFailed)
                        .with_labels([databastion_core::NoteLabel::stage("check")]),
                );
            }
        }
        level = level.max(probe.level(log_readable));
        if probe.reads_without_row_counts() {
            rows_gap = true;
            notes.push(format!(
                "database {}: pgaudit logs reads without row counts, so the target cannot \
                 reach Full",
                normalize(database).as_str()
            ));
        } else if probe.pgaudit_loaded.is_none() {
            // Fail closed: settings that could not be read prove no row counts either.
            rows_gap = true;
            notes.push(format!(
                "database {}: pgaudit settings could not be read, so the target cannot reach \
                 Full",
                normalize(database).as_str()
            ));
        }
        let (text, probe_codes) = probe_notes(
            &probe,
            settings.audit_log.is_some(),
            settings.audit_log.is_some() && log_readable,
        );
        notes.extend(text);
        codes.extend(probe_codes);
        let key = (target.id.clone(), database.clone());
        if state.due(&key) {
            match report(&session, timeouts, settings.extended_grants).await {
                Ok(r) => {
                    if state.store(key.clone(), r.clone()) {
                        log_report(target, database, &r);
                    }
                }
                Err(e) => tracing::warn!(
                    target_id = %target.id,
                    database = normalize(database).as_str(),
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    "privilege report failed"
                ),
            }
        }
        if let Some(r) = state.cached(&key) {
            notes.extend(summary(&r));
            report_notes(&r, &mut codes);
        }
    }
    level = capped_without_row_counts(level, rows_gap);
    if level == AuditLevel::Full && !state.recent_record(&target.id) {
        // ADR-0015 decision 4: Full once the log is actually read.
        level = AuditLevel::Partial;
        notes.push(
            "Full once the Audit stream has read a pgaudit record (none in the last 24 h)"
                .to_owned(),
        );
        codes.add(TargetNote::new(NoteCode::AuditFullPendingFirstRecord));
    }
    let mismatched = state.severity_mismatches(&target.id);
    if mismatched > 0 {
        notes.push(format!(
            "{mismatched} pgaudit record(s) dropped in the last 24 h: severity differs from \
             pgaudit.log_level"
        ));
        codes.add(TargetNote::new(NoteCode::AuditRecordsDroppedSeverity).with_count(mismatched));
    }
    let dropped = state.dropped(&target.id);
    if dropped > 0 {
        notes.push(format!(
            "{dropped} pgaudit log record(s) dropped in the last 24 h (oversized or damaged)"
        ));
        codes.add(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(dropped));
    }
    notes.sort();
    notes.dedup();
    TargetHealth {
        reachable: true,
        audit_level: level,
        failure: None,
        detail: Some(format!(
            "audit level {level:?}{}{}",
            if notes.is_empty() { "" } else { "; " },
            notes.join("; ")
        )),
        notes: codes.into_vec(),
    }
}

/// Explanations of one database's audit prerequisites (log detail and
/// closed notes). `log_configured`: `postgres.audit_log` is set.
/// `log_read`: the configured pgaudit log is readable, i.e. it is the source the stream reads at
/// Partial or Full; the row-count note only describes that source.
fn probe_notes(
    probe: &AuditProbe,
    log_configured: bool,
    log_read: bool,
) -> (Vec<String>, Vec<TargetNote>) {
    let mut text = Vec::new();
    let mut codes = Vec::new();
    if (probe.pgaudit_installed || probe.pgaudit_loaded == Some(true)) && !log_configured {
        text.push(
            "pgaudit present; Full needs its log file in agent.yaml (postgres.audit_log)"
                .to_owned(),
        );
        codes.push(TargetNote::new(NoteCode::AuditPgauditLogNotConfigured));
    }
    if probe.pgaudit_placeholders {
        text.push(
            "pgaudit settings are set but the pgaudit library is not loaded \
             (shared_preload_libraries)"
                .to_owned(),
        );
        codes.push(TargetNote::new(NoteCode::AuditPgauditNotLoaded));
    }
    if probe.pgaudit_loaded == Some(true) && !probe.pgaudit_reads {
        text.push("pgaudit.log does not include the read class".to_owned());
        codes.push(TargetNote::new(NoteCode::AuditPgauditReadClassMissing));
    }
    if probe.reads_without_row_counts() {
        // ADR-0037: the local detail names the setting; the closed note is the
        // registered `audit.log_without_row_counts` (`postgres` since ROADMAP
        // v0.1.x item (n)). Settings that could not be read get neither: they
        // prove nothing about row counts (check() caps the level and says so
        // locally).
        text.push(
            "pgaudit.log_rows is off or not defined (pgaudit before 1.6): the pgaudit records \
             carry no row count, so Full is not reached and volume signals are absent"
                .to_owned(),
        );
        // Not when `pg_stat_statements` is the source (log not configured or unreadable): its
        // rows are counted.
        if log_read {
            codes.push(TargetNote::new(NoteCode::AuditLogWithoutRowCounts));
        }
    }
    (text, codes)
}

/// ADR-0037 decision 4: Full only when every monitored database logging reads through pgaudit
/// also logs their row counts.
fn capped_without_row_counts(level: AuditLevel, rows_gap: bool) -> AuditLevel {
    if level == AuditLevel::Full && rows_gap {
        AuditLevel::Partial
    } else {
        level
    }
}

fn summary(r: &Report) -> Vec<String> {
    let mut out = Vec::new();
    if !r.over_privileged.is_empty() {
        out.push(format!("over-privileged: {}", r.over_privileged.join(", ")));
    }
    if !r.expected.is_empty() {
        out.push(format!("extended variant: {}", r.expected.join(", ")));
    }
    let c = &r.coverage;
    if !r.schemas_not_covered.is_empty() || c.not_covered() > 0 {
        out.push(format!(
            "not covered: {} schema(s) without USAGE, {} relation(s) without SELECT, {} \
             relation(s) skipped for row-level security",
            r.schemas_not_covered.len(),
            c.not_readable.len(),
            c.rls_policy.len() + c.rls_ancestor.len()
        ));
    }
    if r.login_event_trigger {
        out.push("an enabled login event trigger runs user code at connection".to_owned());
    }
    out
}

fn log_report(target: &TargetConfig, database: &str, r: &Report) {
    let db = normalize(database);
    if r.over_privileged.is_empty() {
        tracing::info!(target_id = %target.id, database = db.as_str(), "role privileges match ADR-0012");
    } else {
        tracing::warn!(
            target_id = %target.id,
            database = db.as_str(),
            over_privileged = r.over_privileged.join(", "),
            "the agent role is over-privileged (ADR-0012)"
        );
    }
    if !r.expected.is_empty() {
        tracing::warn!(
            target_id = %target.id,
            database = db.as_str(),
            memberships = r.expected.join(", "),
            "extended grant variant: catalog tables with credentials are readable by the agent \
             role (the connector never reads them)"
        );
    }
    let names = |v: &mut dyn Iterator<Item = String>| -> String {
        v.take(MAX_LOGGED_NAMES).collect::<Vec<_>>().join(", ")
    };
    if !r.schemas_not_covered.is_empty() {
        tracing::warn!(
            target_id = %target.id,
            database = db.as_str(),
            count = r.schemas_not_covered.len(),
            schemas = names(&mut r.schemas_not_covered.iter().map(|s| normalize(s).as_str().to_owned())),
            "schemas without USAGE are not covered by Discovery"
        );
    }
    let c = &r.coverage;
    for (reason, list) in [
        ("no SELECT privilege", &c.not_readable),
        (
            "row-level security policy with user code or another relation",
            &c.rls_policy,
        ),
        ("row-level security on an ancestor", &c.rls_ancestor),
    ] {
        if !list.is_empty() {
            tracing::warn!(
                target_id = %target.id,
                database = db.as_str(),
                count = list.len(),
                reason,
                objects = names(&mut list.iter().map(|(s, n)| {
                    format!("{}.{}", normalize(s).as_str(), normalize(n).as_str())
                })),
                "relations not covered by Discovery"
            );
        }
    }
    if r.login_event_trigger {
        tracing::warn!(
            target_id = %target.id,
            database = db.as_str(),
            "an enabled login event trigger runs user code when the agent connects"
        );
    }
}

/// Audit prerequisites of a target, from the same probe and rule as
/// `check()`: the level provable now (before the freshness rule), and the
/// severity pgaudit writes its records at.
pub(crate) struct Prerequisites {
    pub(crate) level: AuditLevel,
    pub(crate) severity: String,
    /// Client address the server sees for the agent (`local` on a Unix
    /// socket), `None` when unknown.
    pub(crate) own_addr: Option<databastion_classifiers::masking::ClientAddr>,
    /// Per database: the extension schema of `pg_stat_statements` and
    /// `pgaudit.log_catalog` (what tells catalogs apart in the events).
    pub(crate) catalogs: crate::audit::events::Catalogs,
}

#[cfg(test)]
pub(crate) async fn prerequisites(
    target: &TargetConfig,
    timeouts: Timeouts,
) -> Result<Prerequisites, PgError> {
    prerequisites_with(target, timeouts, None).await
}

/// [`prerequisites`], probing the database of `held` (the held
/// `pg_stat_statements` session and its database) on that session rather
/// than on a new connection (phase 7, ADR-0025 decision 11).
pub(crate) async fn prerequisites_with(
    target: &TargetConfig,
    timeouts: Timeouts,
    held: Option<(&str, &Session)>,
) -> Result<Prerequisites, PgError> {
    let log_readable = crate::audit::log_readable(target).await;
    let mut level = AuditLevel::None;
    let mut log_level: Option<String> = None;
    let mut own_addr = None;
    let mut catalogs = crate::audit::events::Catalogs::default();
    for database in &target.postgres_settings().databases {
        let opened: Session;
        let session = match held {
            Some((db, s)) if db == database.as_str() => s,
            _ => {
                opened = Session::connect(target, database, timeouts).await?;
                &opened
            }
        };
        if own_addr.is_none() {
            own_addr = match probe(session, timeouts, sql::OWN_CLIENT_ADDR).await {
                Ok(rows) => {
                    let addr: Option<String> = rows
                        .first()
                        .map(|r| col::<Option<String>>(r, 0))
                        .transpose()?
                        .flatten();
                    match addr {
                        Some(a) => databastion_classifiers::masking::ClientAddr::parse(&a),
                        None => Some(databastion_classifiers::masking::ClientAddr::Local),
                    }
                }
                Err(e) if e.fatal => return Err(e),
                Err(_) => None,
            };
        }
        let probe = audit_probe(session, timeouts).await?;
        level = level.max(probe.level(log_readable));
        catalogs.insert(
            database,
            crate::audit::events::DbCatalog {
                pss_schema: probe.pss_schema.clone(),
                pgaudit_log_catalog: probe.pgaudit_log_catalog,
            },
        );
        if log_level.is_none() {
            log_level = probe.pgaudit_log_level.clone();
        }
    }
    Ok(Prerequisites {
        level,
        severity: crate::audit::records::expected_severity(log_level.as_deref()),
        own_addr,
        catalogs,
    })
}

/// Runs one statement in its own read-only transaction (a failing probe
/// does not abort the others).
/// How many CAS ticket registry or audit trail relations of the session's
/// database have a credential column the role can `SELECT` (directly,
/// through a role or `PUBLIC`, a table grant or `pg_read_all_data`;
/// ADR-0041 decision 6). Recognized by name (built-in and `cas_stores`)
/// and by column shape, whatever the column grants.
pub(crate) async fn cas_guard_readable(
    session: &Session,
    timeouts: Timeouts,
    stores: Option<&databastion_core::cas_guard::CasStores>,
) -> Result<u64, PgError> {
    use databastion_core::cas_guard;
    let keys = cas_guard::known_name_keys(stores);
    let tx = session.begin(timeouts).await?;
    let rows = match tx
        .query(
            Stage::Check,
            sql::CAS_GUARD_COLUMNS,
            &[(&keys, tokio_postgres::types::Type::TEXT_ARRAY)],
        )
        .await
    {
        Ok(rows) => {
            tx.commit().await?;
            rows
        }
        Err(e) => {
            tx.rollback().await;
            return Err(e);
        }
    };
    // Per relation: its name and its (column, readable) list.
    type Columns = Vec<(String, bool)>;
    let mut relations: Vec<(u32, String, Columns)> = Vec::new();
    for row in &rows {
        let oid: u32 = col(row, 0)?;
        let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Check);
        let (Some(name), Some(column)) = (
            crate::wire::catalog_text(row, 1).map_err(get)?,
            crate::wire::catalog_text(row, 2).map_err(get)?,
        ) else {
            continue;
        };
        let readable: bool = col(row, 3)?;
        match relations.last_mut() {
            Some((o, _, cols)) if *o == oid => cols.push((column, readable)),
            _ => relations.push((oid, name, vec![(column, readable)])),
        }
    }
    let mut count = 0u64;
    for (_, name, columns) in &relations {
        let kind = cas_guard::recognize(
            stores,
            [name.as_str()],
            columns.iter().map(|(c, _)| c.as_str()),
        );
        let Some(kind) = kind else { continue };
        if columns
            .iter()
            .any(|(c, readable)| *readable && cas_guard::is_credential_column(kind, c))
        {
            count += 1;
        }
    }
    Ok(count)
}

async fn probe(
    session: &Session,
    timeouts: Timeouts,
    statement: &str,
) -> Result<Vec<tokio_postgres::Row>, PgError> {
    let tx = session.begin(timeouts).await?;
    match tx.query(Stage::Check, statement, &[]).await {
        Ok(rows) => {
            tx.commit().await?;
            Ok(rows)
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

fn col<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    i: usize,
) -> Result<T, PgError> {
    row.try_get(i)
        .map_err(|e| PgError::from_driver(&e, Stage::Check))
}

pub(crate) async fn audit_probe(
    session: &Session,
    timeouts: Timeouts,
) -> Result<AuditProbe, PgError> {
    let rows = probe(session, timeouts, sql::AUDIT_PREREQUISITES).await?;
    let row = rows
        .first()
        .ok_or(PgError::new(FailureCode::Internal, Stage::Check))?;
    let mut p = AuditProbe {
        pss_installed: col(row, 0)?,
        pgaudit_installed: col(row, 1)?,
        stats_visible: col(row, 3)?,
        ..AuditProbe::default()
    };
    let info_schema: Option<String> = col(row, 2)?;
    p.pss_schema.clone_from(&info_schema);
    let superuser = probe(session, timeouts, sql::ROLE_ATTRIBUTES)
        .await?
        .first()
        .map(|r| col::<bool>(r, 0))
        .transpose()?
        .unwrap_or(false);
    p.stats_visible |= superuser;
    if let Some(statement) = info_schema.as_deref().and_then(sql::pss_probe) {
        p.pss_loaded = match probe(session, timeouts, &statement).await {
            Ok(_) => true,
            Err(e) if e.fatal => return Err(e),
            Err(_) => false,
        };
    }
    // `pgaudit.*` are readable without `pg_read_all_settings` (verified in
    // P2-B); `NULL` when pgaudit is not loaded.
    match probe(session, timeouts, sql::PGAUDIT_SETTINGS).await {
        Ok(rows) => {
            let setting = |i: usize| -> Result<Option<String>, PgError> {
                Ok(rows
                    .first()
                    .map(|r| col::<Option<String>>(r, i))
                    .transpose()?
                    .flatten())
            };
            let log = setting(0)?;
            // A `pgaudit.log` value alone may be a placeholder (the
            // library not loaded): the level needs the library's own
            // setting in `pg_settings` (`sql::PGAUDIT_SETTINGS`).
            let library = rows
                .first()
                .map(|r| col::<Option<bool>>(r, 4))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            p.pgaudit_loaded = Some(library && log.is_some());
            p.pgaudit_placeholders = !library && log.is_some();
            p.pgaudit_reads = log.as_deref().is_some_and(pgaudit_logs_reads);
            let rows_defined = rows
                .first()
                .map(|r| col::<Option<bool>>(r, 6))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            p.pgaudit_rows = pgaudit_rows_on(library, rows_defined, setting(1)?.as_deref());
            p.pgaudit_object_audit = setting(2)?.is_some_and(|v| !v.trim().is_empty());
            p.pgaudit_log_level = setting(3)?;
            if p.pgaudit_loaded == Some(true) {
                p.pgaudit_log_catalog = setting(5)?.map(|v| v.eq_ignore_ascii_case("on"));
            }
        }
        Err(e) if e.fatal => return Err(e),
        Err(_) => p.pgaudit_loaded = None,
    }
    Ok(p)
}

async fn report(session: &Session, timeouts: Timeouts, extended: bool) -> Result<Report, PgError> {
    let attrs = probe(session, timeouts, sql::ROLE_ATTRIBUTES)
        .await?
        .first()
        .map(|r| -> Result<RoleAttributes, PgError> {
            Ok(RoleAttributes {
                superuser: col(r, 0)?,
                bypassrls: col(r, 1)?,
                replication: col(r, 2)?,
                createrole: col(r, 3)?,
                createdb: col(r, 4)?,
            })
        })
        .transpose()?
        .unwrap_or_default();
    let mut memberships = Vec::new();
    for r in probe(session, timeouts, sql::MEMBERSHIPS).await? {
        let name = crate::wire::catalog_text(&r, 0)
            .map_err(|e| PgError::from_driver(&e, Stage::Check))?
            // Not UTF-8: counted as a non-predefined role.
            .unwrap_or_default();
        memberships.push((name, col::<bool>(&r, 1)?));
    }
    let count = |rows: Vec<tokio_postgres::Row>| -> Result<i64, PgError> {
        rows.first()
            .map(|r| col::<i64>(r, 0))
            .transpose()
            .map(Option::unwrap_or_default)
    };
    let pg17 = session.server_version_num() >= 170_000;
    let writes = count(probe(session, timeouts, &sql::write_privileges(pg17)).await?)?;
    let owned = count(probe(session, timeouts, sql::OWNERSHIP).await?)?;
    let login_event_trigger =
        pg17 && count(probe(session, timeouts, sql::LOGIN_EVENT_TRIGGERS).await?)? > 0;
    let mut schemas_not_covered = Vec::new();
    for r in probe(session, timeouts, sql::SCHEMAS_WITHOUT_USAGE).await? {
        schemas_not_covered.push(
            crate::wire::catalog_text(&r, 0)
                .map_err(|e| PgError::from_driver(&e, Stage::Check))?
                .unwrap_or_else(|| "*".to_owned()),
        );
    }
    let relations = {
        let tx = session.begin(timeouts).await?;
        match catalog::introspect(&tx).await {
            Ok(r) => {
                tx.commit().await?;
                r
            }
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        }
    };
    let (_, coverage) = catalog::plan(&relations, |_, _| true);
    let (over_privileged, expected, privilege_notes) =
        evaluate_privileges(attrs, &memberships, writes, owned, extended);
    Ok(Report {
        over_privileged,
        expected,
        privilege_notes,
        schemas_not_covered,
        coverage,
        login_event_trigger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> (String, bool) {
        (name.to_owned(), true)
    }

    #[test]
    fn minimal_variant_is_not_over_privileged() {
        let (over, expected, notes) = evaluate_privileges(
            RoleAttributes::default(),
            &[m("pg_read_all_stats")],
            0,
            0,
            false,
        );
        assert!(over.is_empty() && expected.is_empty(), "{over:?}");
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn over_privileges_are_reported() {
        let attrs = RoleAttributes {
            superuser: true,
            bypassrls: true,
            ..RoleAttributes::default()
        };
        let (over, _, notes) = evaluate_privileges(
            attrs,
            &[
                m("pg_monitor"),
                m("pg_read_all_data"),
                m("pg_write_all_data"),
                m("pg_read_server_files"),
                m("pg_future_role"),
                ("app_owner".to_owned(), false),
            ],
            3,
            1,
            false,
        );
        let json = notes_json(&notes);
        assert_eq!(
            json,
            serde_json::json!([
                {"code": "privilege.role_attributes", "labels": ["superuser", "bypassrls"]},
                {"code": "privilege.predefined_roles", "labels": [
                    "other", "pg_monitor", "pg_read_all_data", "pg_read_server_files",
                    "pg_write_all_data"
                ]},
                {"code": "privilege.other_roles", "count": 1},
                {"code": "privilege.write_on_relations", "count": 3},
                {"code": "privilege.owner_of_objects", "count": 1}
            ])
        );
        assert!(!json.to_string().contains("app_owner"));
        assert!(!json.to_string().contains("future"));
        for label in [
            "superuser",
            "bypassrls",
            "member of pg_monitor",
            "member of pg_read_all_data",
            "member of pg_write_all_data",
            "member of pg_read_server_files",
            "member of 1 non-predefined role(s)",
            "write privilege on 3 relation(s)",
            "owner of 1 object(s)",
        ] {
            assert!(over.iter().any(|o| o == label), "{label}: {over:?}");
        }
        // A non-predefined role name is never echoed.
        assert!(!over.iter().any(|o| o.contains("app_owner")));
    }

    #[test]
    fn extended_variant_is_an_expected_warning() {
        let memberships = [
            m("pg_read_all_data"),
            m("pg_read_all_settings"),
            m("pg_read_all_stats"),
        ];
        let (over, expected, notes) =
            evaluate_privileges(RoleAttributes::default(), &memberships, 0, 0, true);
        assert!(over.is_empty(), "{over:?}");
        assert_eq!(expected.len(), 2);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.extended_variant",
                                "labels": ["pg_read_all_data", "pg_read_all_settings"]}])
        );
        let (over, expected, notes) =
            evaluate_privileges(RoleAttributes::default(), &memberships, 0, 0, false);
        assert_eq!(over.len(), 2);
        assert!(expected.is_empty());
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].code(), NoteCode::PrivilegePredefinedRoles);
    }

    /// A note as the console receives it: `code`, `count`, `labels` only.
    fn note_json(n: &TargetNote) -> serde_json::Value {
        let mut v = serde_json::json!({"code": n.code().as_str()});
        if let Some(c) = n.count() {
            v["count"] = c.into();
        }
        if !n.labels().is_empty() {
            v["labels"] = n.labels().iter().map(|l| l.as_str()).collect();
        }
        v
    }

    fn notes_json(notes: &[TargetNote]) -> serde_json::Value {
        notes.iter().map(note_json).collect()
    }

    /// Codes registered for `postgres` in `shared/protocol/target-notes.json`.
    fn registered_for_postgres() -> std::collections::BTreeSet<String> {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../shared/protocol/target-notes.json"
        ))
        .unwrap();
        v.as_object()
            .unwrap()
            .iter()
            .filter(|(_, e)| {
                e["engines"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|x| x == "postgres")
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    fn codes(notes: &[TargetNote]) -> Vec<&'static str> {
        notes.iter().map(|n| n.code().as_str()).collect()
    }

    fn assert_registered(notes: &[TargetNote]) {
        let registered = registered_for_postgres();
        for n in notes {
            assert!(
                registered.contains(n.code().as_str()),
                "{} is not registered for postgres",
                n.code().as_str()
            );
        }
    }

    fn report(over: &[TargetNote], schemas: usize, not_readable: usize, rls: usize) -> Report {
        Report {
            privilege_notes: over.to_vec(),
            schemas_not_covered: vec!["s".to_owned(); schemas],
            coverage: catalog::Coverage {
                not_readable: vec![("s".to_owned(), "secret_table".to_owned()); not_readable],
                rls_policy: vec![("s".to_owned(), "t".to_owned()); rls],
                ..catalog::Coverage::default()
            },
            login_event_trigger: true,
            ..Report::default()
        }
    }

    #[test]
    fn notes_of_several_databases_are_merged_per_code() {
        let (_, _, privileges) = evaluate_privileges(
            RoleAttributes {
                createdb: true,
                ..RoleAttributes::default()
            },
            &[("app".to_owned(), false), ("etl".to_owned(), false)],
            4,
            0,
            false,
        );
        let mut notes = Notes::default();
        report_notes(&report(&privileges, 1, 2, 3), &mut notes);
        report_notes(&report(&privileges, 2, 0, 1), &mut notes);
        let notes = notes.into_vec();
        assert_registered(&notes);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "privilege.role_attributes", "labels": ["createdb"]},
                // Cluster-wide: the same two roles seen from both databases.
                {"code": "privilege.other_roles", "count": 2},
                // Per database: added up.
                {"code": "privilege.write_on_relations", "count": 8},
                {"code": "coverage.schemas_without_usage", "count": 3},
                {"code": "coverage.relations_without_select", "count": 2},
                {"code": "coverage.relations_rls_skipped", "count": 4},
                {"code": "security.login_event_trigger"}
            ])
        );
        // Names of schemas and relations never reach a note.
        let text = notes_json(&notes).to_string();
        assert!(
            !text.contains("secret_table") && !text.contains("\"s\""),
            "{text}"
        );
    }

    #[test]
    fn audit_prerequisites_are_noted() {
        let loaded = AuditProbe {
            pgaudit_installed: true,
            pgaudit_loaded: Some(true),
            pgaudit_reads: false,
            ..AuditProbe::default()
        };
        let (text, notes) = probe_notes(&loaded, false, false);
        assert_eq!(text.len(), notes.len());
        assert_registered(&notes);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "audit.pgaudit_log_not_configured"},
                {"code": "audit.pgaudit_read_class_missing"}
            ])
        );
        let placeholders = AuditProbe {
            pgaudit_placeholders: true,
            pgaudit_loaded: Some(false),
            ..AuditProbe::default()
        };
        let (_, notes) = probe_notes(&placeholders, true, true);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "audit.pgaudit_not_loaded"}])
        );
        let (_, notes) = probe_notes(&AuditProbe::default(), false, false);
        assert!(notes.is_empty());
    }

    #[test]
    fn check_failures_are_noted_with_their_stage_only() {
        let mut e = PgError::new(FailureCode::TargetUnreachable, Stage::Connect);
        e.sqlstate = Some("28P01".to_owned());
        let health = unreachable(&e);
        assert_registered(&health.notes);
        assert_eq!(
            notes_json(&health.notes),
            serde_json::json!([{"code": "check.stage_failed", "labels": ["stage_connect"]}])
        );
        // Every stage of this connector has its contract label.
        for stage in [
            Stage::Secret,
            Stage::Tls,
            Stage::Connect,
            Stage::SessionSetup,
            Stage::Begin,
            Stage::Commit,
            Stage::Introspection,
            Stage::Columns,
            Stage::Sample,
            Stage::Check,
            Stage::Audit,
        ] {
            assert!(!NoteLabel::stage(stage.as_str()).is_other(), "{stage:?}");
        }
    }

    #[test]
    fn dropped_records_are_counted_per_target() {
        let state = CheckState::default();
        assert_eq!(state.dropped("t"), 0);
        state.note_dropped("t", 2);
        state.note_dropped("t", 3);
        assert_eq!(state.dropped("t"), 5);
        assert_eq!(state.dropped("u"), 0);
        state.note_severity_mismatch("t", 1);
        assert_eq!(state.severity_mismatches("t"), 1);
    }

    #[test]
    fn own_usage_is_one_per_target() {
        let state = CheckState::default();
        assert!(std::sync::Arc::ptr_eq(
            &state.own_usage("t"),
            &state.own_usage("t")
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &state.own_usage("t"),
            &state.own_usage("u")
        ));
    }

    #[test]
    fn full_needs_a_recent_record() {
        let state = CheckState::default();
        assert!(!state.recent_record("t"));
        state.note_record("t");
        assert!(state.recent_record("t"));
        assert!(!state.recent_record("u"));
    }

    #[test]
    fn pgaudit_log_setting_is_read() {
        assert!(pgaudit_logs_reads("read, write"));
        assert!(pgaudit_logs_reads("ALL"));
        assert!(!pgaudit_logs_reads("all, -read"));
        assert!(!pgaudit_logs_reads("write,ddl"));
        assert!(!pgaudit_logs_reads("none"));
        assert!(!pgaudit_logs_reads("readx"));
    }

    #[test]
    fn pgaudit_log_rows_is_proven_not_assumed() {
        assert!(pgaudit_rows_on(true, true, Some("on")));
        assert!(pgaudit_rows_on(true, true, Some("ON")));
        assert!(!pgaudit_rows_on(true, true, Some("off")));
        assert!(!pgaudit_rows_on(true, true, None));
        // A placeholder: set, but not defined by the loaded pgaudit (1.5,
        // PostgreSQL 13), or the library not loaded at all.
        assert!(!pgaudit_rows_on(true, false, Some("on")));
        assert!(!pgaudit_rows_on(false, false, Some("on")));
        assert!(!pgaudit_rows_on(false, true, Some("on")));
    }

    #[test]
    fn audit_level_is_proven_not_assumed() {
        let full_prereqs = AuditProbe {
            pss_installed: true,
            pss_loaded: true,
            stats_visible: true,
            pgaudit_installed: true,
            pgaudit_loaded: Some(true),
            pgaudit_placeholders: false,
            pgaudit_reads: true,
            pgaudit_rows: false,
            pgaudit_object_audit: false,
            pgaudit_log_level: None,
            pgaudit_log_catalog: None,
            pss_schema: None,
        };
        // pgaudit reads and pg_stat_statements, no pgaudit.log_rows: Partial
        // (ADR-0037). The Full stream reads the pgaudit log only, so
        // pg_stat_statements is no volume source for it.
        assert_eq!(full_prereqs.level(true), AuditLevel::Partial);
        assert_eq!(full_prereqs.level(false), AuditLevel::Limited);
        // pgaudit.log_rows on: Full, with or without pg_stat_statements; the
        // log must be readable (ADR-0015 decision 4).
        let with_rows = AuditProbe {
            pgaudit_rows: true,
            ..full_prereqs.clone()
        };
        assert_eq!(with_rows.level(true), AuditLevel::Full);
        assert_eq!(with_rows.level(false), AuditLevel::Limited);
        let rows_only = AuditProbe {
            pss_loaded: false,
            ..with_rows.clone()
        };
        assert_eq!(rows_only.level(true), AuditLevel::Full);
        assert_eq!(rows_only.level(false), AuditLevel::None);
        // No volume source at all: Partial.
        let no_volume = AuditProbe {
            pss_loaded: false,
            ..full_prereqs.clone()
        };
        assert_eq!(no_volume.level(true), AuditLevel::Partial);
        // log_rows without the read class gives no Full.
        assert_eq!(
            AuditProbe {
                pgaudit_reads: false,
                ..with_rows.clone()
            }
            .level(true),
            AuditLevel::Limited
        );
        // pgaudit not logging reads: object audit only is Partial, else Limited.
        let no_reads = AuditProbe {
            pgaudit_reads: false,
            ..full_prereqs.clone()
        };
        assert_eq!(no_reads.level(true), AuditLevel::Limited);
        assert_eq!(
            AuditProbe {
                pgaudit_object_audit: true,
                ..no_reads.clone()
            }
            .level(true),
            AuditLevel::Partial
        );
        // pgaudit not loaded, or not provably loaded.
        for loaded in [Some(false), None] {
            assert_eq!(
                AuditProbe {
                    pgaudit_loaded: loaded,
                    ..full_prereqs.clone()
                }
                .level(true),
                AuditLevel::Limited
            );
        }
        let full_prereqs = AuditProbe {
            pgaudit_reads: false,
            ..full_prereqs
        };
        for p in [
            AuditProbe {
                pss_loaded: false,
                ..full_prereqs.clone()
            },
            AuditProbe {
                stats_visible: false,
                ..full_prereqs.clone()
            },
            AuditProbe {
                pss_installed: false,
                ..full_prereqs.clone()
            },
        ] {
            assert_eq!(p.level(false), AuditLevel::None);
        }
    }

    /// The whole reads x rows x `pg_stat_statements` matrix, pgaudit loaded
    /// and its log readable, no object audit (ADR-0037): Full only with
    /// both the read class and `pgaudit.log_rows`.
    #[test]
    fn full_requires_pgaudit_log_rows() {
        for reads in [false, true] {
            for rows in [false, true] {
                for pss in [false, true] {
                    let p = AuditProbe {
                        pss_installed: pss,
                        pss_loaded: pss,
                        stats_visible: pss,
                        pgaudit_installed: true,
                        pgaudit_loaded: Some(true),
                        pgaudit_reads: reads,
                        pgaudit_rows: rows,
                        ..AuditProbe::default()
                    };
                    let expected = match (reads, rows, pss) {
                        (true, true, _) => AuditLevel::Full,
                        (true, false, _) => AuditLevel::Partial,
                        (false, _, true) => AuditLevel::Limited,
                        (false, _, false) => AuditLevel::None,
                    };
                    assert_eq!(
                        p.level(true),
                        expected,
                        "reads {reads} rows {rows} pss {pss}"
                    );
                    // Without a readable log, pgaudit gives nothing.
                    let unreadable = if pss {
                        AuditLevel::Limited
                    } else {
                        AuditLevel::None
                    };
                    assert_eq!(
                        p.level(false),
                        unreadable,
                        "reads {reads} rows {rows} pss {pss}"
                    );
                    // At Partial and Full the stream reads the pgaudit log.
                    if reads {
                        assert_eq!(
                            crate::audit::source_for(p.level(true)),
                            crate::audit::Source::Pgaudit
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn one_database_without_row_counts_caps_the_target() {
        use AuditLevel::*;
        for level in [None, Limited, Partial, Full] {
            assert_eq!(capped_without_row_counts(level, false), level);
        }
        assert_eq!(capped_without_row_counts(Full, true), Partial);
        for level in [None, Limited, Partial] {
            assert_eq!(capped_without_row_counts(level, true), level);
        }
    }

    #[test]
    fn missing_log_rows_is_explained_and_noted() {
        let p = AuditProbe {
            pgaudit_installed: true,
            pgaudit_loaded: Some(true),
            pgaudit_reads: true,
            ..AuditProbe::default()
        };
        let (text, notes) = probe_notes(&p, true, true);
        assert_eq!(codes(&notes), ["audit.log_without_row_counts"]);
        assert_registered(&notes);
        assert_eq!(text.len(), 1);
        assert!(text[0].contains("pgaudit.log_rows"), "{text:?}");
        // The pgaudit log configured but unreadable: `pg_stat_statements` is the source and
        // counts rows, so the detail stays local and no note is sent.
        let (text, notes) = probe_notes(&p, true, false);
        assert!(
            text.iter().any(|t| t.contains("pgaudit.log_rows")),
            "{text:?}"
        );
        assert!(
            !codes(&notes).contains(&"audit.log_without_row_counts"),
            "{notes:?}"
        );
        // No log configured: the same.
        let (_, notes) = probe_notes(&p, false, false);
        assert!(
            !codes(&notes).contains(&"audit.log_without_row_counts"),
            "{notes:?}"
        );
        // Row counts on: neither the detail nor the note.
        let (text, notes) = probe_notes(
            &AuditProbe {
                pgaudit_rows: true,
                ..p.clone()
            },
            true,
            true,
        );
        assert!(text.is_empty(), "{text:?}");
        assert!(notes.is_empty(), "{notes:?}");
        // pgaudit not logging reads, not loaded, or its settings not readable
        // (`pgaudit_loaded: None`, capped by check() with a local detail only):
        // no row-count note.
        for probe in [
            AuditProbe {
                pgaudit_reads: false,
                ..p.clone()
            },
            AuditProbe {
                pgaudit_loaded: Some(false),
                ..p.clone()
            },
            AuditProbe {
                pgaudit_loaded: None,
                ..p.clone()
            },
        ] {
            let (_, notes) = probe_notes(&probe, true, true);
            assert!(
                !notes
                    .iter()
                    .any(|n| n.code() == NoteCode::AuditLogWithoutRowCounts),
                "{probe:?}: {notes:?}"
            );
        }
    }

    /// Two databases without row counts give one note (check() merges the
    /// per-database notes).
    #[test]
    fn row_count_note_is_deduplicated_across_databases() {
        let p = AuditProbe {
            pgaudit_installed: true,
            pgaudit_loaded: Some(true),
            pgaudit_reads: true,
            ..AuditProbe::default()
        };
        let mut merged = Notes::default();
        for _ in 0..2 {
            let (_, notes) = probe_notes(&p, true, true);
            merged.extend(notes);
        }
        assert_eq!(codes(merged.as_slice()), ["audit.log_without_row_counts"]);
    }
}
