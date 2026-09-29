//! `check()`: reachability, honest audit level, over-privilege and
//! coverage (ADR-0012 obligation 6).
//!
//! Audit level, per docs/08, ADR-0012 obligation 6 and ADR-0015 decision 4,
//! reporting only what can be proven without `pg_read_all_settings`:
//! - **Full**: the audit log configured in `agent.yaml`
//!   (`postgres.audit_log`) is readable by the agent, pgaudit is loaded
//!   with the `read` class in `pgaudit.log` for a monitored database, and
//!   volumes are visible: `pgaudit.log_rows` is on, or `pg_stat_statements`
//!   is usable (Limited prerequisites below).
//! - **Partial**: the log is readable and pgaudit logs reads (without a
//!   volume source), or only object audit is set (`pgaudit.role`, reads
//!   of the objects granted to that role).
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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::EventSource;
use databastion_core::config::TargetConfig;
use databastion_core::{AuditLevel, FailureCode, TargetHealth};

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

impl AuditProbe {
    /// Level proven in this database; `log_readable`: the configured audit
    /// log can be read by the agent.
    pub(crate) fn level(&self, log_readable: bool) -> AuditLevel {
        let limited = self.pss_installed && self.pss_loaded && self.stats_visible;
        let pgaudit = self.pgaudit_loaded == Some(true);
        if log_readable && pgaudit && self.pgaudit_reads && (self.pgaudit_rows || limited) {
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

/// Evaluates over-privilege (obligation 6). Returns (over-privileged,
/// expected) labels.
pub(crate) fn evaluate_privileges(
    attrs: RoleAttributes,
    memberships: &[(String, bool)],
    write_relations: i64,
    owned_objects: i64,
    extended: bool,
) -> (Vec<String>, Vec<String>) {
    let mut over = Vec::new();
    let mut expected = Vec::new();
    for (flag, label) in [
        (attrs.superuser, "superuser"),
        (attrs.bypassrls, "bypassrls"),
        (attrs.replication, "replication"),
        (attrs.createrole, "createrole"),
        (attrs.createdb, "createdb"),
    ] {
        if flag {
            over.push(label.to_owned());
        }
    }
    let mut other_roles = 0usize;
    for (name, predefined) in memberships {
        match (name.as_str(), predefined) {
            ("pg_read_all_stats", true) => {}
            ("pg_read_all_data" | "pg_read_all_settings", true) if extended => {
                expected.push(format!("member of {name}"));
            }
            // Predefined role names are PostgreSQL constants.
            (_, true) if name.starts_with("pg_") && name.len() <= 64 => {
                over.push(format!("member of {name}"));
            }
            _ => other_roles += 1,
        }
    }
    if other_roles > 0 {
        over.push(format!("member of {other_roles} non-predefined role(s)"));
    }
    if write_relations > 0 {
        over.push(format!("write privilege on {write_relations} relation(s)"));
    }
    if owned_objects > 0 {
        over.push(format!("owner of {owned_objects} object(s)"));
    }
    (over, expected)
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
    /// Per target: the agent's own reads, shared by every Audit stream of
    /// the target (see `audit::events::OwnUsage`).
    own_usage: Mutex<HashMap<String, crate::audit::events::SharedOwnUsage>>,
}

/// Full needs a pgaudit record parsed within this period.
pub(crate) const RECORD_FRESHNESS: Duration = Duration::from_secs(24 * 3600);

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
    pub(crate) fn own_usage(&self, target_id: &str) -> crate::audit::events::SharedOwnUsage {
        std::sync::Arc::clone(
            self.own_usage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// Records of `target_id` dropped for a severity other than
    /// `pgaudit.log_level`.
    pub(crate) fn note_severity_mismatch(&self, target_id: &str, n: u64) {
        let mut map = self
            .severity_mismatches
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

    fn severity_mismatches(&self, target_id: &str) -> u64 {
        self.severity_mismatches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .filter(|(_, since)| since.elapsed() < RECORD_FRESHNESS)
            .map_or(0, |(n, _)| *n)
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
        },
    };
    state.set_source(&target.id, health.audit_level);
    health
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let settings = target.postgres_settings();
    let timeouts = Timeouts::new(CHECK_STATEMENT_TIMEOUT);
    let mut level = AuditLevel::None;
    let mut notes: Vec<String> = Vec::new();
    if settings.tls == databastion_core::config::PgTlsMode::DisableInsecure {
        notes.push(
            "INSECURE: TLS disabled on a network connection (tls: disable_insecure): traffic \
             in clear, read-only not guaranteed"
                .to_owned(),
        );
    }
    let log_readable = crate::audit::log_readable(target).await;
    if settings.audit_log.is_some() && !log_readable {
        notes.push("the configured audit log is not readable by the agent".to_owned());
    }
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
        level = level.max(probe.level(log_readable));
        if (probe.pgaudit_installed || probe.pgaudit_loaded == Some(true))
            && settings.audit_log.is_none()
        {
            notes.push(
                "pgaudit present; Full needs its log file in agent.yaml (postgres.audit_log)"
                    .to_owned(),
            );
        }
        if probe.pgaudit_placeholders {
            notes.push(
                "pgaudit settings are set but the pgaudit library is not loaded \
                 (shared_preload_libraries)"
                    .to_owned(),
            );
        }
        if probe.pgaudit_loaded == Some(true) && !probe.pgaudit_reads {
            notes.push("pgaudit.log does not include the read class".to_owned());
        }
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
        }
    }
    if level == AuditLevel::Full && !state.recent_record(&target.id) {
        // ADR-0015 decision 4: Full once the log is actually read.
        level = AuditLevel::Partial;
        notes.push(
            "Full once the Audit stream has read a pgaudit record (none in the last 24 h)"
                .to_owned(),
        );
    }
    let mismatched = state.severity_mismatches(&target.id);
    if mismatched > 0 {
        notes.push(format!(
            "{mismatched} pgaudit record(s) dropped in the last 24 h: severity differs from \
             pgaudit.log_level"
        ));
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
}

pub(crate) async fn prerequisites(
    target: &TargetConfig,
    timeouts: Timeouts,
) -> Result<Prerequisites, PgError> {
    let log_readable = crate::audit::log_readable(target).await;
    let mut level = AuditLevel::None;
    let mut log_level: Option<String> = None;
    let mut own_addr = None;
    for database in &target.postgres_settings().databases {
        let session = Session::connect(target, database, timeouts).await?;
        if own_addr.is_none() {
            own_addr = match probe(&session, timeouts, sql::OWN_CLIENT_ADDR).await {
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
        let probe = audit_probe(&session, timeouts).await?;
        level = level.max(probe.level(log_readable));
        if log_level.is_none() {
            log_level = probe.pgaudit_log_level.clone();
        }
    }
    Ok(Prerequisites {
        level,
        severity: crate::audit::records::expected_severity(log_level.as_deref()),
        own_addr,
    })
}

/// Runs one statement in its own read-only transaction (a failing probe
/// does not abort the others).
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
            p.pgaudit_rows = setting(1)?.is_some_and(|v| v.eq_ignore_ascii_case("on"));
            p.pgaudit_object_audit = setting(2)?.is_some_and(|v| !v.trim().is_empty());
            p.pgaudit_log_level = setting(3)?;
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
    let (over_privileged, expected) =
        evaluate_privileges(attrs, &memberships, writes, owned, extended);
    Ok(Report {
        over_privileged,
        expected,
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
        let (over, expected) = evaluate_privileges(
            RoleAttributes::default(),
            &[m("pg_read_all_stats")],
            0,
            0,
            false,
        );
        assert!(over.is_empty() && expected.is_empty(), "{over:?}");
    }

    #[test]
    fn over_privileges_are_reported() {
        let attrs = RoleAttributes {
            superuser: true,
            bypassrls: true,
            ..RoleAttributes::default()
        };
        let (over, _) = evaluate_privileges(
            attrs,
            &[
                m("pg_monitor"),
                m("pg_read_all_data"),
                m("pg_write_all_data"),
                m("pg_read_server_files"),
                ("app_owner".to_owned(), false),
            ],
            3,
            1,
            false,
        );
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
        let (over, expected) =
            evaluate_privileges(RoleAttributes::default(), &memberships, 0, 0, true);
        assert!(over.is_empty(), "{over:?}");
        assert_eq!(expected.len(), 2);
        let (over, expected) =
            evaluate_privileges(RoleAttributes::default(), &memberships, 0, 0, false);
        assert_eq!(over.len(), 2);
        assert!(expected.is_empty());
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
        };
        // Full needs the audit log to be readable (ADR-0015 decision 4).
        assert_eq!(full_prereqs.level(true), AuditLevel::Full);
        assert_eq!(full_prereqs.level(false), AuditLevel::Limited);
        // Volumes from pgaudit.log_rows alone.
        let rows_only = AuditProbe {
            pss_loaded: false,
            pgaudit_rows: true,
            ..full_prereqs.clone()
        };
        assert_eq!(rows_only.level(true), AuditLevel::Full);
        // No volume source: Partial.
        let no_volume = AuditProbe {
            pss_loaded: false,
            ..full_prereqs.clone()
        };
        assert_eq!(no_volume.level(true), AuditLevel::Partial);
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
}
