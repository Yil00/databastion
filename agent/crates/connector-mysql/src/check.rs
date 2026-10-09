//! `check()`: reachability, honest audit level, over-privilege and
//! coverage.
//!
//! Audit level (docs/08), reporting only what the account can prove, with
//! the same rule as the Audit stream's source choice ([`choose`]):
//! - **Partial**, audit log source: `mysql.audit_log` is readable by the
//!   agent, the matching audit plugin is active and logs statements
//!   (MariaDB `server_audit` with file output; Percona `audit_log` with
//!   the JSON format, or the `audit_log_filter` component with the JSON
//!   format), and the Audit stream parsed a record of it in the last 24 h
//!   (Limited until then). Not Full: neither log carries a row count, so
//!   volumes are unknown.
//! - **Partial**, `performance_schema` source: `performance_schema` is on,
//!   the `events_statements_history_long` consumer and the consumers it
//!   depends on (`global_instrumentation`, `thread_instrumentation`,
//!   `events_statements_current`) are enabled, and the account can read
//!   the table (statements of every session, `ROWS_SENT`; a ring buffer).
//! - **Limited**: only the per-thread `events_statements_history` or
//!   `events_statements_current` consumers are active and readable (recent
//!   statements only, easily missed).
//! - **None** otherwise.
//!
//! Over-privilege (warned, not refused): any global privilege (`*.*`,
//! including `SELECT`, which reads `mysql.user` password hashes, `PROCESS`,
//! `SUPER`, `FILE`…), any grant `WITH GRANT OPTION`, any database / table /
//! column privilege other than `SELECT`, `SELECT` on the `mysql` or `sys`
//! database, `SELECT` on `performance_schema` while no Audit stream runs
//! for the target (ADR-0018: the statement text of every session, only
//! granted for Audit). The same rules apply to the privileges held through
//! roles (P4-D): every role applicable to the account (granted directly,
//! through another role, as MySQL mandatory role or MariaDB default role),
//! enabled or not, since the account can enable any of them itself. Their
//! privileges come from `SHOW GRANTS` (see [`role_privileges`]); a role
//! that cannot be evaluated is reported as such (on MariaDB, every role
//! but the default role: MariaDB shows no other role's grants to a
//! least-privilege account). `init_connect` (SQL run at
//! every login) is reported. Coverage: views and tables of engines that are
//! not sampled.
//!
//! The detailed report is recomputed at most every [`REPORT_INTERVAL`] per
//! target and logged when it changes; the reachability and the audit level
//! are checked on every call.
//!
//! Every explanation is also reported as a closed note
//! (`TargetHealth::notes`, `shared/protocol/target-notes.json`): a code, a
//! count and closed labels (privilege names mapped to the contract enum,
//! anything else `other`), never a name or any other text from the server.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::EventSource;
use databastion_core::audit::own::SharedOwnUsage;
use databastion_core::config::{MysqlLogFormat, MysqlTlsMode, TargetConfig, TargetEngine};
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};

use crate::audit::pfs::PsTable;
use crate::catalog::{self, Coverage, EngineSkip};
use crate::conn::{Flavor, Flow, Rows, Session, Timeouts};
use crate::discover::normalize;
use crate::error::{MyError, Stage};
use crate::grants::{self as grant_lines, Line, Scope};
use crate::sql;

/// Statement timeout of `check()` queries.
const CHECK_STATEMENT_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Period of the detailed report.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);
/// Most names listed in a log line.
const MAX_LOGGED_NAMES: usize = 20;
/// Most roles named in the MySQL `SHOW GRANTS … USING` statements; with
/// more, the roles are reported as not evaluated.
const MAX_EVALUATED_ROLES: usize = 16;

/// Audit prerequisites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AuditProbe {
    pub(crate) ps_enabled: bool,
    /// `performance_schema.setup_consumers` is readable (a grant on
    /// `performance_schema`, Audit only).
    pub(crate) consumers_readable: bool,
    /// `global_instrumentation` and `thread_instrumentation` enabled.
    pub(crate) instrumentation: bool,
    pub(crate) current_enabled: bool,
    pub(crate) history_enabled: bool,
    pub(crate) history_long_enabled: bool,
    pub(crate) current_readable: bool,
    pub(crate) history_readable: bool,
    pub(crate) history_long_readable: bool,
    /// MariaDB `server_audit`: active, logging on, file output, and
    /// statements or tables among the logged events.
    pub(crate) server_audit: Option<ServerAudit>,
    /// Percona `audit_log` plugin active: its format, and whether its
    /// policy logs statements.
    pub(crate) audit_log: Option<(String, bool)>,
    /// `audit_log_filter` component present: its format.
    pub(crate) audit_log_filter: Option<String>,
    pub(crate) general_log: bool,
}

/// MariaDB `server_audit` settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ServerAudit {
    pub(crate) logging: bool,
    pub(crate) file: bool,
    pub(crate) statements: bool,
}

/// What the agent knows of the configured audit log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileState {
    pub(crate) format: MysqlLogFormat,
    pub(crate) readable: bool,
    /// The Audit stream parsed a record of it in the last 24 h.
    pub(crate) recent: bool,
}

/// Audit source of a level (the stream reads the same one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    File(MysqlLogFormat),
    Ps(PsTable),
    None,
}

impl Source {
    pub(crate) fn event_source(self) -> Option<EventSource> {
        match self {
            Self::File(MysqlLogFormat::ServerAudit) => Some(EventSource::MariadbServerAudit),
            Self::File(MysqlLogFormat::Json) => Some(EventSource::MysqlAuditLog),
            Self::Ps(_) => Some(EventSource::PerformanceSchema),
            Self::None => None,
        }
    }
}

impl AuditProbe {
    /// Whether the audit plugin writing `format` is active and logs
    /// statements.
    pub(crate) fn file_plugin(&self, format: MysqlLogFormat) -> bool {
        let json = |f: &str| f.eq_ignore_ascii_case("json");
        match format {
            MysqlLogFormat::ServerAudit => self
                .server_audit
                .is_some_and(|a| a.logging && a.file && a.statements),
            MysqlLogFormat::Json => {
                self.audit_log.as_ref().is_some_and(|(f, q)| json(f) && *q)
                    || self.audit_log_filter.as_deref().is_some_and(json)
            }
        }
    }

    /// The `performance_schema` table the account can poll, and its level.
    pub(crate) fn ps(&self) -> Option<(AuditLevel, PsTable)> {
        let base = self.ps_enabled && self.instrumentation && self.current_enabled;
        if base && self.history_long_enabled && self.history_long_readable {
            Some((AuditLevel::Partial, PsTable::HistoryLong))
        } else if base && self.history_enabled && self.history_readable {
            Some((AuditLevel::Limited, PsTable::History))
        } else if base && self.current_readable {
            Some((AuditLevel::Limited, PsTable::Current))
        } else {
            None
        }
    }

    /// Level without an audit log file (`performance_schema` only).
    #[cfg(test)]
    pub(crate) fn level(&self) -> AuditLevel {
        choose(self, None).0
    }

    /// Explanations of the audit prerequisites, for the log detail.
    #[cfg(test)]
    fn notes(&self, file: Option<FileState>) -> Vec<String> {
        self.explain(file).0
    }

    /// Explanations of the audit prerequisites: the log detail, and the
    /// same as closed notes.
    fn explain(&self, file: Option<FileState>) -> (Vec<String>, Vec<TargetNote>) {
        let mut out = Vec::new();
        let mut codes = Vec::new();
        if let Some(a) = self.server_audit {
            out.push(format!(
                "server_audit active (logging {}, {} output{})",
                if a.logging { "ON" } else { "OFF" },
                if a.file { "file" } else { "non-file" },
                if a.statements {
                    ""
                } else {
                    ", no QUERY or TABLE events"
                }
            ));
            if file.is_none() {
                codes.push(
                    TargetNote::new(NoteCode::AuditServerAuditNotRead).with_labels([
                        NoteLabel::parse(if a.logging {
                            "logging_on"
                        } else {
                            "logging_off"
                        }),
                        NoteLabel::parse(if a.file {
                            "file_output"
                        } else {
                            "non_file_output"
                        }),
                    ]),
                );
            }
        }
        if let Some((format, queries)) = &self.audit_log {
            out.push(format!(
                "audit_log plugin active (format {}{})",
                label(&format.to_ascii_uppercase()),
                if *queries {
                    ""
                } else {
                    ", policy logs no queries"
                }
            ));
            if file.is_none() {
                codes.push(TargetNote::new(NoteCode::AuditAuditLogPluginNotRead));
            }
        }
        if let Some(format) = &self.audit_log_filter {
            out.push(format!(
                "audit_log_filter active (format {})",
                label(&format.to_ascii_uppercase())
            ));
            if file.is_none() {
                codes.push(TargetNote::new(NoteCode::AuditAuditLogFilterNotRead));
            }
        }
        let plugin = self.server_audit.is_some()
            || self.audit_log.is_some()
            || self.audit_log_filter.is_some();
        match file {
            None if plugin => out.push(
                "an audit plugin is active; reading its log needs mysql.audit_log in agent.yaml"
                    .to_owned(),
            ),
            None => {}
            Some(f) if !f.readable => {
                out.push("the configured audit log is not readable by the agent".to_owned());
                codes.push(TargetNote::new(NoteCode::AuditLogNotReadable));
            }
            Some(f) if !self.file_plugin(f.format) => {
                out.push(format!(
                    "the configured audit log ({}) has no matching active audit plugin logging \
                     statements in a supported format",
                    match f.format {
                        MysqlLogFormat::ServerAudit => "server_audit",
                        MysqlLogFormat::Json => "json",
                    }
                ));
                codes.push(TargetNote::new(NoteCode::AuditLogPluginMismatch));
            }
            Some(f) => {
                if !f.recent {
                    out.push(
                        "Partial once the Audit stream has read a record of the audit log \
                         (none in the last 24 h)"
                            .to_owned(),
                    );
                    codes.push(TargetNote::new(NoteCode::AuditPartialPendingFirstRecord));
                }
                out.push("the audit log carries no row counts (volumes unknown)".to_owned());
                codes.push(TargetNote::new(NoteCode::AuditLogWithoutRowCounts));
            }
        }
        if self.ps_enabled && !self.consumers_readable {
            out.push("performance_schema not readable by the account (no Audit grant)".to_owned());
            codes.push(TargetNote::new(NoteCode::AuditPerformanceSchemaNotReadable));
        } else if self.ps_enabled && !(self.instrumentation && self.current_enabled) {
            out.push(
                "performance_schema statement consumers inactive (global_instrumentation, \
                 thread_instrumentation and events_statements_current are needed)"
                    .to_owned(),
            );
            codes.push(TargetNote::new(NoteCode::AuditStatementConsumersDisabled));
        } else if self.ps_enabled && !self.history_long_enabled {
            out.push(
                "performance_schema events_statements_history_long consumer disabled".to_owned(),
            );
            codes.push(TargetNote::new(NoteCode::AuditHistoryLongConsumerDisabled));
        }
        if self.history_long_enabled && self.consumers_readable && !self.history_long_readable {
            out.push("performance_schema statement history not readable by the account".to_owned());
            codes.push(TargetNote::new(NoteCode::AuditHistoryNotReadable));
        }
        if self.general_log {
            out.push("general log enabled (not used as an audit source)".to_owned());
            codes.push(TargetNote::new(NoteCode::AuditGeneralLogEnabled));
        }
        (out, codes)
    }
}

/// The level and source of a target, from the probe and the configured
/// audit log: the log when it is readable and its plugin active (Partial
/// once a record was read recently, Limited before), else
/// `performance_schema`, else none. `check()` and the Audit stream use
/// this same rule.
pub(crate) fn choose(probe: &AuditProbe, file: Option<FileState>) -> (AuditLevel, Source) {
    if let Some(f) = file
        && f.readable
        && probe.file_plugin(f.format)
    {
        let level = if f.recent {
            AuditLevel::Partial
        } else {
            AuditLevel::Limited
        };
        return (level, Source::File(f.format));
    }
    match probe.ps() {
        Some((level, table)) => (level, Source::Ps(table)),
        None => (AuditLevel::None, Source::None),
    }
}

/// Privileges of the account (privilege names upper-case).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Grants {
    pub(crate) global: Vec<(String, bool)>,
    /// (database, privilege, grantable) at database, table and column
    /// level.
    pub(crate) scoped: Vec<(String, String, bool)>,
    /// Roles applicable to the account.
    pub(crate) roles: u64,
    /// Of them, the roles whose privileges could not be read or understood
    /// (their privileges are unknown).
    pub(crate) roles_unevaluated: u64,
    /// A grant with `WITH GRANT OPTION` / `WITH ADMIN OPTION` that is not
    /// in the lists above (a role, or `USAGE`).
    pub(crate) other_grantable: bool,
    /// The `SELECT` grants of the `SHOW GRANTS` lines read (roles and
    /// `PUBLIC`), with their tables and columns (CAS store guard).
    pub(crate) selects: Vec<grant_lines::SelectGrant>,
    /// A privilege line whose `SELECT` grants were not understood (CAS
    /// store guard: not evaluated, PR #141 review M1).
    pub(crate) selects_unknown: bool,
}

/// A privilege name as a closed label: `[A-Z ]{1,40}` (server constants,
/// including dynamic privileges such as `SYSTEM_VARIABLES_ADMIN`), else
/// `OTHER`.
fn label(privilege: &str) -> String {
    if !privilege.is_empty()
        && privilege.len() <= 40
        && privilege
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b == b' ')
    {
        privilege.to_owned()
    } else {
        "OTHER".to_owned()
    }
}

/// Whether a database name from a grant covers the database `name`.
///
/// Database-level grants are stored as `LIKE` patterns: `_` and `%` are
/// wildcards unless escaped with `\` (`performance\_schema`, `%`, `mysq_`
/// and `m%` all cover a system database). The comparison is a `LIKE`
/// match, case-insensitive, with `\` escapes; it over-reports on purpose
/// for a name that is literal on the server (a table-level grant, or a
/// database grant with `partial_revokes` ON), never under-reports.
pub(crate) fn db_matches(pattern: &str, name: &str) -> bool {
    #[derive(Clone, Copy)]
    enum P {
        Char(char),
        One,
        Any,
    }
    let mut p = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        p.push(match c {
            '\\' => match chars.next() {
                Some(e) => P::Char(e),
                None => P::Char('\\'),
            },
            '_' => P::One,
            '%' => P::Any,
            c => P::Char(c),
        });
    }
    let n: Vec<char> = name.chars().collect();
    // `m[i][j]`: the first `i` pattern items match the first `j` chars.
    let mut m = vec![vec![false; n.len() + 1]; p.len() + 1];
    m[0][0] = true;
    for i in 1..=p.len() {
        for j in 0..=n.len() {
            m[i][j] = match p[i - 1] {
                P::Any => m[i - 1][j] || (j > 0 && m[i][j - 1]),
                P::One => j > 0 && m[i - 1][j - 1],
                P::Char(c) => j > 0 && m[i - 1][j - 1] && c.eq_ignore_ascii_case(&n[j - 1]),
            };
        }
    }
    m[p.len()][n.len()]
}

/// Evaluates over-privilege. Returns (over-privileged, expected) closed
/// labels for the logs, and the same as closed notes; with the
/// extended-variant flag, a global `SELECT` is expected.
/// `audit`: an Audit stream runs for the target, so `SELECT` on
/// `performance_schema` is the documented Audit grant (ADR-0018), unless
/// `file_source`: the audit log is the source, and the grant is unused.
pub(crate) fn evaluate_privileges(
    g: &Grants,
    extended: bool,
    audit: bool,
    file_source: bool,
) -> (Vec<String>, Vec<String>, Vec<TargetNote>) {
    let mut over = Vec::new();
    let mut expected = Vec::new();
    let mut notes = Vec::new();
    let mut global: BTreeSet<String> = BTreeSet::new();
    let mut grantable = g.other_grantable;
    for (p, gr) in &g.global {
        grantable |= *gr;
        let p = p.to_ascii_uppercase();
        if p != "USAGE" {
            global.insert(label(&p));
        }
    }
    if global.remove("SELECT") {
        let label = "global SELECT (system tables readable, including mysql.user password hashes)"
            .to_owned();
        if extended {
            expected.push(label);
            notes.push(
                TargetNote::new(NoteCode::PrivilegeExtendedVariant)
                    .with_labels([NoteLabel::privilege("SELECT")]),
            );
        } else {
            over.push(label);
            notes.push(TargetNote::new(NoteCode::PrivilegeGlobalSelect));
        }
    }
    if !global.is_empty() {
        // `count`: the distinct privileges, all of them, when the labels
        // are cut to the 16 most severe.
        notes.push(
            TargetNote::new(NoteCode::PrivilegeGlobalPrivileges)
                .with_count(global.len() as u64)
                .with_labels(global.iter().map(|p| NoteLabel::privilege(p))),
        );
        over.push(format!(
            "global privileges: {}",
            global.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let mut beyond_select: BTreeSet<String> = BTreeSet::new();
    let mut system_select = false;
    let mut ps_select = false;
    for (db, p, gr) in &g.scoped {
        grantable |= *gr;
        let p = p.to_ascii_uppercase();
        if p == "SELECT" {
            if db_matches(db, "mysql") || db_matches(db, "sys") {
                system_select = true;
            }
            if db_matches(db, "performance_schema") {
                ps_select = true;
            }
        } else {
            beyond_select.insert(label(&p));
        }
    }
    if system_select {
        over.push("SELECT on the mysql or sys system database".to_owned());
        notes.push(TargetNote::new(NoteCode::PrivilegeSystemDatabaseSelect));
    }
    if ps_select && !audit {
        over.push(
            "SELECT on performance_schema without Audit enabled (statement text of every \
             session readable)"
                .to_owned(),
        );
        notes.push(TargetNote::new(
            NoteCode::PrivilegePerformanceSchemaWithoutAudit,
        ));
    } else if ps_select && file_source {
        over.push(
            "SELECT on performance_schema unused (the audit log is the source; statement text \
             of every session readable, clear-text passwords on MariaDB)"
                .to_owned(),
        );
        notes.push(TargetNote::new(NoteCode::PrivilegePerformanceSchemaUnused));
    }
    if !beyond_select.is_empty() {
        notes.push(
            TargetNote::new(NoteCode::PrivilegeBeyondSelect)
                .with_count(beyond_select.len() as u64)
                .with_labels(beyond_select.iter().map(|p| NoteLabel::privilege(p))),
        );
        over.push(format!(
            "privileges beyond SELECT on databases / tables / columns: {}",
            beyond_select.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if grantable {
        over.push("WITH GRANT OPTION".to_owned());
        notes.push(TargetNote::new(NoteCode::PrivilegeGrantOption));
    }
    if g.roles_unevaluated > 0 {
        over.push(format!(
            "granted {} role(s), {} of them not evaluated (their privileges are unknown)",
            g.roles, g.roles_unevaluated
        ));
        notes.push(
            TargetNote::new(NoteCode::PrivilegeRolesNotEvaluated).with_count(g.roles_unevaluated),
        );
    }
    (over, expected, notes)
}

/// Privileges and coverage of the account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) over_privileged: Vec<String>,
    /// Expected with the extended-variant flag.
    pub(crate) expected: Vec<String>,
    /// The same privileges as closed notes.
    pub(crate) privilege_notes: Vec<TargetNote>,
    /// The account name cannot be matched in the privilege tables.
    pub(crate) privileges_unknown: bool,
    pub(crate) init_connect: bool,
    pub(crate) coverage: Coverage,
}

struct Cached {
    at: Instant,
    report: Report,
}

/// Per target: last detailed report, source of the last reported level,
/// when the Audit stream last parsed an audit log record, the Audit
/// streams running, and the agent's own reads (shared by every stream of
/// the target).
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<String, Cached>>,
    sources: Mutex<HashMap<String, EventSource>>,
    records: Mutex<HashMap<String, Instant>>,
    streams: Mutex<HashMap<String, usize>>,
    own_usage: Mutex<HashMap<String, SharedOwnUsage>>,
    /// Per target: credits for the extra sampling statements of Discovery
    /// (`audit::credits`).
    sample_credits: Mutex<HashMap<String, crate::audit::credits::SharedCredits>>,
    /// Per target: audit log records dropped (not parsable, oversized or
    /// damaged), and when the count started (reported for 24 h).
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
}

/// An audit log record parsed within this period makes the log source
/// Partial.
pub(crate) const RECORD_FRESHNESS: Duration = Duration::from_secs(24 * 3600);

/// Marks an Audit stream as running for a target while alive.
pub(crate) struct StreamGuard<'a> {
    state: &'a CheckState,
    target_id: String,
}

impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        let mut map = self
            .state
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = map.get_mut(&self.target_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.target_id);
            }
        }
        self.state.invalidate(&self.target_id);
    }
}

impl CheckState {
    /// The Audit stream of `target_id` starts: `SELECT` on
    /// `performance_schema` is the Audit grant while the guard lives.
    pub(crate) fn stream_started(&self, target_id: &str) -> StreamGuard<'_> {
        *self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(target_id.to_owned())
            .or_default() += 1;
        self.invalidate(target_id);
        StreamGuard {
            state: self,
            target_id: target_id.to_owned(),
        }
    }

    pub(crate) fn stream_running(&self, target_id: &str) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(target_id)
    }

    /// Forgets the detailed report (recomputed at the next check).
    fn invalidate(&self, target_id: &str) {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(target_id);
    }

    /// The Audit stream of `target_id` parsed an audit log record.
    pub(crate) fn note_record(&self, target_id: &str) {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), Instant::now());
    }

    /// Audit log records of `target_id` dropped by the stream.
    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        let mut map = self
            .dropped
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

    fn dropped(&self, target_id: &str) -> u64 {
        self.dropped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .filter(|(_, since)| since.elapsed() < RECORD_FRESHNESS)
            .map_or(0, |(n, _)| *n)
    }

    /// Whether an audit log record of `target_id` was parsed recently.
    pub(crate) fn recent_record(&self, target_id: &str) -> bool {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .is_some_and(|t| t.elapsed() < RECORD_FRESHNESS)
    }

    /// The agent's own-read counters of `target_id`, created once and kept
    /// for the life of the connector.
    pub(crate) fn sample_credits(&self, target_id: &str) -> crate::audit::credits::SharedCredits {
        std::sync::Arc::clone(
            self.sample_credits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    pub(crate) fn own_usage(&self, target_id: &str) -> SharedOwnUsage {
        std::sync::Arc::clone(
            self.own_usage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// Source of the level last reported for `target_id`.
    pub(crate) fn audit_source(&self, target_id: &str) -> Option<EventSource> {
        self.sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .copied()
    }

    fn set_source(&self, target_id: &str, source: Option<EventSource>) {
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

    fn due(&self, key: &str) -> bool {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .is_none_or(|c| c.at.elapsed() >= REPORT_INTERVAL)
    }

    /// Stores a report; `true` if it differs from the previous one.
    fn store(&self, key: String, report: Report) -> bool {
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

    fn cached(&self, key: &str) -> Option<Report> {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .map(|c| c.report.clone())
    }
}

fn unreachable(e: &MyError) -> TargetHealth {
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "{} failed (error {})",
            e.stage.as_str(),
            e.engine_code().unwrap_or_else(|| "none".to_owned())
        )),
        notes: vec![
            TargetNote::new(NoteCode::CheckStageFailed)
                .with_labels([NoteLabel::stage(e.stage.as_str())]),
        ],
    }
}

/// `check()` of a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TIMEOUT, check_inner(state, target)).await {
        Ok((h, source)) => {
            state.set_source(&target.id, source.event_source());
            h
        }
        Err(_) => {
            state.set_source(&target.id, None);
            TargetHealth {
                reachable: false,
                audit_level: AuditLevel::None,
                failure: Some(FailureCode::Timeout),
                detail: Some("check timed out".to_owned()),
                notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
            }
        }
    }
}

/// Whether the configured audit log of `target` can be read now (file I/O
/// on a blocking thread), and whether a record was read recently.
pub(crate) async fn file_state(state: &CheckState, target: &TargetConfig) -> Option<FileState> {
    let log = target.mysql_settings().audit_log?;
    let path = log.path.clone();
    let readable =
        tokio::task::spawn_blocking(move || databastion_core::audit::tail::readable(&path))
            .await
            .unwrap_or(false);
    Some(FileState {
        format: log.format,
        readable,
        recent: state.recent_record(&target.id),
    })
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> (TargetHealth, Source) {
    let timeouts = Timeouts::new(CHECK_STATEMENT_TIMEOUT);
    // `notes`: the local log detail; `codes`: the same as closed notes.
    let mut notes: Vec<String> = Vec::new();
    let mut codes = Notes::default();
    if target.mysql_settings().tls == MysqlTlsMode::DisableInsecure {
        notes.push(
            "INSECURE: TLS disabled on a network connection (tls: disable_insecure): traffic \
             in clear, read-only not guaranteed, password scramble exposed to offline \
             brute force"
                .to_owned(),
        );
        codes.add(TargetNote::new(NoteCode::SecurityTlsDisabled));
    }
    let mut session = match Session::connect(target, timeouts).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target_id = %target.id,
                stage = e.stage.as_str(),
                errno = e.errno,
                sqlstate = e.sqlstate(),
                code = %e.code,
                "target check failed"
            );
            return (unreachable(&e), Source::None);
        }
    };
    match (target.engine, session.flavor()) {
        (TargetEngine::Mysql, Flavor::Mariadb) => {
            notes.push("the server is MariaDB (target declared as mysql)".to_owned());
            codes.add(TargetNote::new(NoteCode::CheckServerIsMariadb));
        }
        (TargetEngine::Mariadb, Flavor::Mysql) => {
            notes.push("the server is MySQL (target declared as mariadb)".to_owned());
            codes.add(TargetNote::new(NoteCode::CheckServerIsMysql));
        }
        _ => {}
    }
    let probe = match audit_probe(&mut session).await {
        Ok(p) => p,
        Err(e) => return (unreachable(&e), Source::None),
    };
    let file = file_state(state, target).await;
    let (level, source) = choose(&probe, file);
    let (text, probe_codes) = probe.explain(file);
    notes.extend(text);
    codes.extend(probe_codes);
    notes.push(match source {
        Source::File(MysqlLogFormat::ServerAudit) => "audit source: server_audit log".to_owned(),
        Source::File(MysqlLogFormat::Json) => "audit source: audit_log JSON file".to_owned(),
        Source::Ps(t) => format!("audit source: performance_schema.{}", t.name()),
        Source::None => "no audit source".to_owned(),
    });
    let dropped = state.dropped(&target.id);
    if dropped > 0 {
        notes.push(format!(
            "{dropped} audit log record(s) dropped in the last 24 h (not parsable, oversized or \
             damaged)"
        ));
        codes.add(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(dropped));
    }
    // CAS store guard (ADR-0041 decision 6): at every heartbeat, so a
    // ticket table recreated with a table grant is reported at once.
    if !session.is_poisoned() {
        match cas_guard_readable(&mut session, target.cas_stores()).await {
            Ok(r) => {
                if !r.complete {
                    notes.push(
                        "CAS store guard privileges not fully evaluated (a role or PUBLIC not \
                         evaluated, a grant line not understood, or too many candidate columns)"
                            .to_owned(),
                    );
                    codes.add(TargetNote::new(NoteCode::PrivilegeNotEvaluated));
                }
                let n = r.readable;
                if n > 0 {
                    notes.push(format!(
                        "the account can read credential columns of {n} CAS ticket registry \
                         or audit trail table(s) (grant SELECT on the metadata columns only)"
                    ));
                    codes.add(
                        TargetNote::new(NoteCode::PrivilegeTicketCredentialsReadable).with_count(n),
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target_id = %target.id,
                    stage = e.stage.as_str(),
                    errno = e.errno,
                    sqlstate = e.sqlstate(),
                    "CAS store guard privilege check failed"
                );
                codes.add(TargetNote::new(NoteCode::PrivilegeNotEvaluated));
            }
        }
    }
    if state.due(&target.id) && !session.is_poisoned() {
        match report(
            &mut session,
            target.mysql_settings().extended_grants,
            state.stream_running(&target.id),
            matches!(source, Source::File(_)),
        )
        .await
        {
            Ok(r) => {
                if state.store(target.id.clone(), r.clone()) {
                    log_report(target, &r);
                }
            }
            Err(e) => tracing::warn!(
                target_id = %target.id,
                stage = e.stage.as_str(),
                errno = e.errno,
                sqlstate = e.sqlstate(),
                "privilege report failed"
            ),
        }
    }
    if let Some(r) = state.cached(&target.id) {
        notes.extend(summary(&r));
        codes.extend(report_notes(&r));
    }
    session.close().await;
    notes.sort();
    notes.dedup();
    (
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
        },
        source,
    )
}

/// The report's explanations as closed notes: privileges, `init_connect`
/// and coverage (counts only, never a name).
fn report_notes(r: &Report) -> Vec<TargetNote> {
    let mut out = r.privilege_notes.clone();
    if r.privileges_unknown {
        out.push(TargetNote::new(NoteCode::PrivilegeNotEvaluated));
    }
    if r.init_connect {
        out.push(TargetNote::new(NoteCode::SecurityInitConnect));
    }
    let c = &r.coverage;
    let remote = c
        .engines
        .iter()
        .filter(|(_, _, k)| *k == EngineSkip::Remote)
        .count();
    for (code, n) in [
        (NoteCode::CoverageViewsNotSampled, c.views.len()),
        (NoteCode::CoverageRemoteEngineTables, remote),
        (
            NoteCode::CoverageOtherEngineTables,
            c.engines.len() - remote,
        ),
    ] {
        if n > 0 {
            out.push(TargetNote::new(code).with_count(n as u64));
        }
    }
    out
}

fn summary(r: &Report) -> Vec<String> {
    let mut out = Vec::new();
    if !r.over_privileged.is_empty() {
        out.push(format!("over-privileged: {}", r.over_privileged.join(", ")));
    }
    if !r.expected.is_empty() {
        out.push(format!("extended variant: {}", r.expected.join(", ")));
    }
    if r.privileges_unknown {
        out.push(
            "privileges not evaluated (account name not matched, or a privilege list incomplete)"
                .to_owned(),
        );
    }
    if r.init_connect {
        out.push("init_connect is set: SQL runs at every agent login".to_owned());
    }
    let c = &r.coverage;
    let remote = c
        .engines
        .iter()
        .filter(|(_, _, k)| *k == EngineSkip::Remote)
        .count();
    if c.not_covered() > 0 {
        out.push(format!(
            "not covered: {} view(s) not sampled, {} table(s) with a remote-access engine, {} \
             table(s) with another engine not sampled",
            c.views.len(),
            remote,
            c.engines.len() - remote
        ));
    }
    out
}

fn log_report(target: &TargetConfig, r: &Report) {
    if r.over_privileged.is_empty() && !r.privileges_unknown {
        tracing::info!(target_id = %target.id, "account privileges: SELECT-only, no global privilege");
    } else if !r.over_privileged.is_empty() {
        tracing::warn!(
            target_id = %target.id,
            over_privileged = r.over_privileged.join(", "),
            "the agent account is over-privileged"
        );
    }
    if !r.expected.is_empty() {
        tracing::warn!(
            target_id = %target.id,
            grants = r.expected.join(", "),
            "extended grant variant: system tables with password hashes are readable by the \
             agent account (the connector never reads them)"
        );
    }
    if r.init_connect {
        tracing::warn!(
            target_id = %target.id,
            "init_connect is set: SQL runs at every login of the agent account (user code)"
        );
    }
    let names = |v: &mut dyn Iterator<Item = String>| -> String {
        v.take(MAX_LOGGED_NAMES).collect::<Vec<_>>().join(", ")
    };
    let c = &r.coverage;
    if !c.views.is_empty() {
        tracing::info!(
            target_id = %target.id,
            count = c.views.len(),
            objects = names(&mut c.views.iter().map(|(s, n)| {
                format!("{}.{}", normalize(s).as_str(), normalize(n).as_str())
            })),
            "views are not sampled"
        );
    }
    if !c.engines.is_empty() {
        tracing::warn!(
            target_id = %target.id,
            count = c.engines.len(),
            objects = names(&mut c.engines.iter().map(|(s, n, k)| {
                format!("{}.{} ({})", normalize(s).as_str(), normalize(n).as_str(), k.as_str())
            })),
            "tables not covered by Discovery"
        );
    }
}

/// Runs one catalog statement outside a transaction (autocommit, session
/// read-only default).
async fn probe(session: &mut Session, statement: &str) -> Result<Rows, MyError> {
    session.query(Stage::Check, statement).await
}

/// Like [`probe`], but a permission / unknown-object error is `None` (the
/// account cannot read it), any other error is returned.
async fn optional(session: &mut Session, statement: &str) -> Result<Option<Rows>, MyError> {
    match probe(session, statement).await {
        Ok(r) => Ok(Some(r)),
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

/// Like [`optional`], for reads that must see every row: `Some(None)`
/// when a row was skipped (a value not UTF-8), so the caller treats the
/// result as not understood.
async fn optional_complete(
    session: &mut Session,
    statement: &str,
) -> Result<Option<Option<Rows>>, MyError> {
    match session.query_counted(Stage::Check, statement).await {
        Ok((rows, 0)) => Ok(Some(Some(rows))),
        Ok(_) => Ok(Some(None)),
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

fn cell(rows: &Rows, row: usize, col: usize) -> Option<&str> {
    rows.get(row)?.get(col)?.as_deref()
}

fn truthy(v: Option<&str>) -> bool {
    matches!(v, Some("1" | "ON" | "on" | "YES" | "yes"))
}

pub(crate) async fn audit_probe(session: &mut Session) -> Result<AuditProbe, MyError> {
    let mut p = AuditProbe::default();
    if let Some(rows) = optional(session, sql::PS_ENABLED).await? {
        p.ps_enabled = truthy(cell(&rows, 0, 0));
        p.general_log = truthy(cell(&rows, 0, 1));
    }
    if p.ps_enabled {
        if let Some(rows) = optional(session, sql::PS_CONSUMERS).await? {
            p.consumers_readable = true;
            let (mut global, mut thread) = (false, false);
            for row in &rows {
                let enabled = truthy(row.get(1).and_then(|v| v.as_deref()));
                match row.first().and_then(|v| v.as_deref()) {
                    Some("events_statements_history_long") => p.history_long_enabled = enabled,
                    Some("events_statements_history") => p.history_enabled = enabled,
                    Some("events_statements_current") => p.current_enabled = enabled,
                    Some("global_instrumentation") => global = enabled,
                    Some("thread_instrumentation") => thread = enabled,
                    _ => {}
                }
            }
            p.instrumentation = global && thread;
        }
        p.history_long_readable = optional(session, sql::PS_HISTORY_LONG).await?.is_some();
        p.history_readable = optional(session, sql::PS_HISTORY).await?.is_some();
        p.current_readable = optional(session, sql::PS_CURRENT).await?.is_some();
    }
    if let Some(rows) = optional(session, sql::AUDIT_PLUGINS).await? {
        for row in &rows {
            let active = row.get(1).and_then(|v| v.as_deref()) == Some("ACTIVE");
            match row.first().and_then(|v| v.as_deref()) {
                Some("SERVER_AUDIT") if active => p.server_audit = Some(ServerAudit::default()),
                Some("audit_log") if active => p.audit_log = Some((String::new(), false)),
                _ => {}
            }
        }
    }
    if p.server_audit.is_some()
        && let Some(rows) = optional(session, sql::SERVER_AUDIT_SETTINGS).await?
    {
        let events = cell(&rows, 0, 2).unwrap_or("").to_ascii_uppercase();
        p.server_audit = Some(ServerAudit {
            logging: truthy(cell(&rows, 0, 0)),
            file: cell(&rows, 0, 1).is_some_and(|v| v.eq_ignore_ascii_case("file")),
            // Empty: every event.
            statements: events.trim().is_empty()
                || events.split(',').any(|e| {
                    let e = e.trim();
                    e.starts_with("QUERY") || e == "TABLE"
                }),
        });
    }
    if p.audit_log.is_some()
        && let Some(rows) = optional(session, sql::AUDIT_LOG_SETTINGS).await?
    {
        let policy = cell(&rows, 0, 1).unwrap_or("").to_ascii_uppercase();
        p.audit_log = Some((
            cell(&rows, 0, 0).unwrap_or("").to_owned(),
            matches!(policy.as_str(), "ALL" | "QUERIES"),
        ));
    }
    // The audit_log_filter component is not a plugin: its variable exists
    // only when it is installed.
    if let Some(rows) = optional(session, sql::AUDIT_LOG_FILTER_FORMAT).await?
        && let Some(format) = cell(&rows, 0, 0)
    {
        p.audit_log_filter = Some(format.to_owned());
    }
    Ok(p)
}

/// Adds the privileges held through roles to `grants` (P4-D).
///
/// `information_schema` shows the privileges of the account itself only;
/// without a grant on the `mysql` database, the account can read those of
/// its roles through `SHOW GRANTS` only:
/// - MySQL: `SHOW GRANTS FOR CURRENT_USER() USING <roles>` with the roles
///   granted to the account itself and the mandatory roles; the server
///   expands the roles those grant. The role list is split over several
///   statements, each short enough never to be cut in the audit logs
///   (`sql::MAX_OWN_STATEMENT`), and the privileges they show are added
///   up (see [`merge_role_statements`]).
/// - MariaDB: `SHOW GRANTS FOR CURRENT_ROLE`, the only role whose grants
///   MariaDB shows without `SELECT` on `mysql`: the default role enabled at
///   login. Every other applicable role is reported as not evaluated.
///
/// Read-only statements, bounded like every `check()` statement: at most
/// [`MAX_EVALUATED_ROLES`] roles (MySQL), rows and bytes capped by
/// `Session::query`, cancelled with `KILL QUERY` when the `check()` bound
/// drops them (MySQL's `max_execution_time` does not apply to `SHOW`).
/// Role names are written into the statement only after an allow-list
/// check (`sql::show_grants_using`). A role whose grants cannot be read (a
/// refused name, a server error, a line the parser does not understand) is
/// counted in `roles_unevaluated`; on MySQL, where the statements cover
/// every role together, all of them are when any statement fails.
///
/// Fail closed (end-of-phase-4 review L2): when `APPLICABLE_ROLES` cannot
/// be read (no such table before MySQL 8.0.19, or any non-fatal error),
/// the roles are counted from the role grant lines of the account's own
/// `SHOW GRANTS` (and MySQL's `mandatory_roles`), all of them as not
/// evaluated. `Ok(false)` when that cannot be read either: the privileges
/// are then reported as not evaluated (`privilege.not_evaluated`).
///
/// MariaDB 10.11 and later: the privileges granted to `PUBLIC` too (see
/// [`public_privileges`]).
async fn role_privileges(session: &mut Session, grants: &mut Grants) -> Result<bool, MyError> {
    let evaluated = granted_role_privileges(session, grants).await?;
    public_privileges(session, grants).await?;
    Ok(evaluated)
}

/// The roles of [`role_privileges`], `PUBLIC` aside.
async fn granted_role_privileges(
    session: &mut Session,
    grants: &mut Grants,
) -> Result<bool, MyError> {
    let listed = match session.flavor() {
        Flavor::Mysql => mysql_role_privileges(session, grants).await?,
        Flavor::Mariadb => mariadb_role_privileges(session, grants).await?,
    };
    if listed {
        return Ok(true);
    }
    let Some(Some(rows)) = optional_complete(session, sql::SHOW_GRANTS_OWN).await? else {
        return Ok(false);
    };
    let mandatory = match session.flavor() {
        // Every supported MySQL (8.0 GA and later) has `mandatory_roles`:
        // a read error leaves the roles unknown (fail closed).
        // A NULL or a value that is not UTF-8 fails closed too.
        Flavor::Mysql => match optional_complete(session, sql::MANDATORY_ROLES).await? {
            Some(Some(r)) => match cell(&r, 0, 0) {
                Some(v) => Some(v.to_owned()),
                None => return Ok(false),
            },
            _ => return Ok(false),
        },
        Flavor::Mariadb => None,
    };
    Ok(roles_from_grant_lines(&rows, mandatory.as_deref(), grants))
}

/// `ER_NONEXISTING_GRANT`: `SHOW GRANTS FOR PUBLIC` when nothing was ever
/// granted to `PUBLIC`.
const ER_NONEXISTING_GRANT: u16 = 1141;
/// First MariaDB version with grants to `PUBLIC`.
const MARIADB_PUBLIC: (u32, u32, u32) = (10, 11, 0);

/// MariaDB 10.11 and later (ADR-0025 residual, phase 7): the privileges
/// granted to `PUBLIC` apply to every account, and `APPLICABLE_ROLES` does
/// not list `PUBLIC`. They are read with `SHOW GRANTS FOR PUBLIC` (no
/// privilege needed) and evaluated like a role's. Fail closed: when that
/// statement fails (other than "no such grant", i.e. nothing granted to
/// `PUBLIC`), skips a row or has a line the parser does not understand,
/// `PUBLIC` is counted as a role not evaluated
/// (`privilege.roles_not_evaluated`).
async fn public_privileges(session: &mut Session, grants: &mut Grants) -> Result<(), MyError> {
    if session.flavor() != Flavor::Mariadb || session.version() < MARIADB_PUBLIC {
        return Ok(());
    }
    let evaluated = match session
        .query_counted(Stage::Check, sql::SHOW_GRANTS_PUBLIC)
        .await
    {
        Ok((rows, 0)) => merge_public_lines(&rows, grants),
        Ok(_) => false,
        Err(e) if e.errno == Some(ER_NONEXISTING_GRANT) => true,
        Err(e) if !e.fatal => false,
        Err(e) => return Err(e),
    };
    if !evaluated {
        grants.roles = grants.roles.saturating_add(1);
        grants.roles_unevaluated = grants.roles_unevaluated.saturating_add(1);
    }
    Ok(())
}

/// Adds the privileges of the `SHOW GRANTS FOR PUBLIC` rows to `grants`;
/// `false` when a line is not understood or grants a role to `PUBLIC`
/// (that role's privileges are unknown).
fn merge_public_lines(rows: &Rows, grants: &mut Grants) -> bool {
    let grants_role = rows.iter().any(|row| {
        matches!(
            row.first()
                .and_then(|v| v.as_deref())
                .and_then(grant_lines::parse_line),
            Some(Line::Roles { .. })
        )
    });
    merge_grant_lines(rows, grants) && !grants_role
}

/// Counts the roles of the account's own `SHOW GRANTS` role lines, and of
/// `mandatory_roles` (a comma-separated list), all as not evaluated;
/// `false` when a line is not understood (it may grant a role).
fn roles_from_grant_lines(rows: &Rows, mandatory: Option<&str>, grants: &mut Grants) -> bool {
    let mut roles = 0u64;
    for row in rows {
        match row
            .first()
            .and_then(|v| v.as_deref())
            .and_then(grant_lines::parse_line)
        {
            None => return false,
            Some(Line::Roles { grantable, count }) => {
                grants.other_grantable |= grantable;
                roles = roles.saturating_add(count);
            }
            Some(Line::Ignored | Line::Privileges { .. }) => {}
        }
    }
    if let Some(m) = mandatory.map(str::trim).filter(|m| !m.is_empty()) {
        roles = roles.saturating_add(m.split(',').filter(|r| !r.trim().is_empty()).count() as u64);
    }
    grants.roles = grants.roles.saturating_add(roles);
    grants.roles_unevaluated = grants.roles_unevaluated.saturating_add(roles);
    true
}

/// `Ok(false)`: `APPLICABLE_ROLES` could not be read (see
/// [`role_privileges`]).
async fn mysql_role_privileges(
    session: &mut Session,
    grants: &mut Grants,
) -> Result<bool, MyError> {
    // No such table before MySQL 8.0.19, or an error: the roles are not
    // known from here.
    let Some(read) = optional_complete(session, sql::APPLICABLE_ROLES_MYSQL).await? else {
        return Ok(false);
    };
    // A row skipped or a list cut: some roles are unknown.
    let complete = read.as_ref().is_some_and(|r| r.len() <= sql::MAX_ROLE_ROWS);
    let rows = read.unwrap_or_default();
    let mut all: BTreeSet<(String, String)> = BTreeSet::new();
    let mut using: BTreeSet<(String, String)> = BTreeSet::new();
    for row in &rows {
        let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
        let role = (v(0), v(1));
        grants.other_grantable |= v(2) == "YES";
        if v(3) == "YES" || v(4) == "1" {
            using.insert(role.clone());
        }
        all.insert(role);
    }
    grants.roles = all.len() as u64;
    if !complete {
        // At least one role more than listed.
        grants.roles += 1;
        grants.roles_unevaluated = grants.roles;
        return Ok(true);
    }
    if all.is_empty() {
        return Ok(true);
    }
    let using: Vec<(String, String)> = using.into_iter().collect();
    let mut evaluated = false;
    if using.len() <= MAX_EVALUATED_ROLES
        && let Some(statements) = sql::show_grants_using(&using)
    {
        let mut results = Vec::with_capacity(statements.len());
        for statement in &statements {
            match optional_complete(session, statement).await? {
                Some(Some(rows)) => results.push(rows),
                // An error, or rows skipped: every role is unevaluated.
                _ => {
                    results.clear();
                    break;
                }
            }
        }
        evaluated = results.len() == statements.len() && merge_role_statements(&results, grants);
    }
    if !evaluated {
        grants.roles_unevaluated = grants.roles;
    }
    Ok(true)
}

/// Adds the privileges shown by the `SHOW GRANTS … USING` statements of
/// one role list (`sql::show_grants_using`, split over several statements)
/// to `grants`: their union. `false` when a line of any of them is not
/// understood (every role is then counted as not evaluated, and what was
/// added only over-reports).
///
/// Why the union of the split lists is the privileges of the whole list
/// (MySQL 8.0+): the privileges of an account with active roles are the
/// union of the account's and every role's, and partial revokes
/// (`partial_revokes = ON`) combine the same way: a restriction (`REVOKE
/// SELECT ON db.* FROM r1` under a global `SELECT`) holds only where no
/// other source (the account, another role) grants the privilege there,
/// so a `REVOKE` line shown with one part of the list may be lifted by a
/// role of another part, never the reverse. The parser ignores `REVOKE`
/// lines (`grants`: ignoring a revoke over-reports, never under-reports),
/// so no restriction of one statement can hide a grant of another: the
/// grant lines of every statement are added, as a single statement's
/// would be. A `SHOW GRANTS` line holds only grants of the account and of
/// the roles named in its statement (and those they grant), all of which
/// the account holds through the whole list too, so no statement shows a
/// privilege the whole list would not. Measured on MySQL 8.4 with
/// `partial_revokes = ON`: `USING r1` (`SELECT ON *.*`, `REVOKE SELECT ON
/// mysql.*`) shows the revoke, `USING r1, r2` (`r2`: `SELECT ON mysql.*`)
/// shows neither the revoke nor the `mysql` line, which the global grant
/// covers. Split, that `mysql` line is shown too: a privilege the account
/// holds, so a note it may add (`privilege.system_database_select`) is
/// true.
fn merge_role_statements(results: &[Rows], grants: &mut Grants) -> bool {
    let mut understood = true;
    for rows in results {
        understood &= merge_grant_lines(rows, grants);
    }
    understood
}

/// `Ok(false)`: `APPLICABLE_ROLES` could not be read (see
/// [`role_privileges`]).
async fn mariadb_role_privileges(
    session: &mut Session,
    grants: &mut Grants,
) -> Result<bool, MyError> {
    let Some(read) = optional_complete(session, sql::APPLICABLE_ROLES_MARIADB).await? else {
        return Ok(false);
    };
    // A row skipped or a list cut: some roles are unknown.
    let complete = read.as_ref().is_some_and(|r| r.len() <= sql::MAX_ROLE_ROWS);
    let rows = read.unwrap_or_default();
    let mut roles: BTreeSet<String> = BTreeSet::new();
    for row in &rows {
        let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
        grants.other_grantable |= v(1) == "YES";
        roles.insert(v(0));
    }
    grants.roles = roles.len() as u64;
    if !complete {
        grants.roles += 1;
        grants.roles_unevaluated = grants.roles;
        return Ok(true);
    }
    if roles.is_empty() {
        return Ok(true);
    }
    // Only the session's current role (the default role) is readable; the
    // other applicable roles, including those it grants, are counted as not
    // evaluated (never assumed harmless).
    let current = optional(session, sql::CURRENT_ROLE)
        .await?
        .and_then(|r| cell(&r, 0, 0).map(str::to_owned));
    let mut evaluated = false;
    if current.as_ref().is_some_and(|c| roles.contains(c))
        && let Some(Some(rows)) = optional_complete(session, sql::SHOW_GRANTS_CURRENT_ROLE).await?
    {
        evaluated = merge_grant_lines(&rows, grants);
    }
    grants.roles_unevaluated = grants.roles - u64::from(evaluated);
    Ok(true)
}

/// Adds the privileges of `SHOW GRANTS` rows to `grants`; `false` when a
/// line is not understood (its privileges are then unknown).
fn merge_grant_lines(rows: &Rows, grants: &mut Grants) -> bool {
    let mut understood = true;
    for row in rows {
        let line = row.first().and_then(|v| v.as_deref());
        match line.and_then(grant_lines::parse_line) {
            None => understood = false,
            Some(Line::Ignored) => {}
            Some(Line::Roles { grantable, .. }) => grants.other_grantable |= grantable,
            Some(Line::Privileges {
                privileges,
                scope,
                grantable,
            }) => {
                match line.and_then(grant_lines::select_grants) {
                    Some(selects) => grants.selects.extend(selects),
                    None => grants.selects_unknown = true,
                }
                for p in privileges {
                    match &scope {
                        Scope::Global => grants.global.push((p, grantable)),
                        Scope::Proxy => grants.global.push(("PROXY".to_owned(), grantable)),
                        Scope::Database(_) if p == "USAGE" => grants.other_grantable |= grantable,
                        Scope::Database(db) => grants.scoped.push((db.clone(), p, grantable)),
                    }
                }
            }
        }
    }
    understood
}

/// How many CAS ticket registry or audit trail tables have a credential
/// column the account can read (ADR-0041 decision 6): visible with
/// `SELECT` in `information_schema.COLUMNS` (direct grants, enabled roles,
/// `PUBLIC`), or covered by a `SELECT` grant of a role or of `PUBLIC` read
/// through `SHOW GRANTS` (roles the account can enable included, as in
/// ADR-0025): a table grant without a column list or with a credential
/// column, a grant on its database or on `*.*`. Tables recognized by name
/// (built-in and `cas_stores`) and by column shape.
///
/// Fail closed (PR #141 review M1, L2): the check is not complete when the
/// column list is cut at its limit (tables matched by name come first),
/// when the roles or `PUBLIC` could not all be evaluated (as in
/// [`role_privileges`]), or when a privilege line's `SELECT` grants were
/// not understood; the caller reports it as not evaluated.
pub(crate) async fn cas_guard_readable(
    session: &mut Session,
    stores: Option<&databastion_core::cas_guard::CasStores>,
) -> Result<databastion_core::cas_guard::ReadableCheck, MyError> {
    use databastion_core::cas_guard::{self, StoreKind};
    // Several statements, each short enough never to be cut in the audit
    // logs (`sql::CAS_GUARD_MAX_STATEMENT`): tables matched by name first,
    // then by shape; at most `CAS_GUARD_MAX_ROWS` rows in all.
    let guard = sql::cas_guard_statements_of(stores)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Check))?;
    let mut complete = true;
    // The name keys present in the catalog: the table list is streamed and
    // each name key computed here, as the column statements compute it in
    // SQL; only the known keys are kept. A name that is not UTF-8 cannot
    // be keyed: not complete (fail closed, as a skipped row below). More
    // than `CAS_GUARD_MAX_TABLES` tables: the list is cut, not complete
    // (security review of #181, L1).
    let mut present: BTreeSet<&str> = BTreeSet::new();
    let mut unkeyed = 0usize;
    let mut listed = 0usize;
    session
        .query_stream(Stage::Check, guard.tables, |row| {
            // The statement's `LIMIT` sends at most one row more (not
            // stopped: a stopped stream poisons the session).
            listed += 1;
            if listed > sql::CAS_GUARD_MAX_TABLES {
                return Flow::Continue;
            }
            match row.get(1).copied().flatten().map(std::str::from_utf8) {
                Some(Ok(name)) => {
                    let key = cas_guard::name_key(name);
                    // `by_key` is in key order.
                    if let Ok(i) = guard.by_key.binary_search_by(|(k, _)| k.as_str().cmp(&key)) {
                        present.insert(guard.by_key[i].0.as_str());
                    }
                }
                _ => unkeyed += 1,
            }
            Flow::Continue
        })
        .await?;
    complete &= unkeyed == 0 && listed <= sql::CAS_GUARD_MAX_TABLES;
    let statements = guard
        .by_key
        .iter()
        .filter(|(k, _)| present.contains(k.as_str()))
        .map(|(_, s)| s)
        .chain([&guard.shape]);
    let mut taken = 0usize;
    // Per table: (column, readable).
    type Columns = Vec<(String, bool)>;
    let mut tables: Vec<((String, String), Columns)> = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for statement in statements {
        if taken > sql::CAS_GUARD_MAX_ROWS {
            break;
        }
        let (rows, skipped) = session.query_counted(Stage::Check, statement).await?;
        complete &= skipped == 0;
        // Tables of the earlier statements (a table matched by name and by
        // shape) are not listed twice.
        let earlier = seen.clone();
        for row in &rows {
            let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
            let key = (v(0), v(1));
            if earlier.contains(&key) {
                continue;
            }
            taken += 1;
            if taken > sql::CAS_GUARD_MAX_ROWS {
                complete = false;
                break;
            }
            let readable = v(3)
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("select"));
            seen.insert(key.clone());
            match tables.last_mut() {
                Some((k, cols)) if *k == key => cols.push((v(2), readable)),
                _ => tables.push((key, vec![(v(2), readable)])),
            }
        }
    }
    let mut guarded: Vec<(&(String, String), StoreKind)> = Vec::new();
    let mut readable: BTreeSet<(String, String)> = BTreeSet::new();
    for (key, columns) in &tables {
        let Some(kind) = cas_guard::recognize(
            stores,
            [key.1.as_str()],
            columns.iter().map(|(c, _)| c.as_str()),
        ) else {
            continue;
        };
        if kind == StoreKind::ServiceRegistry {
            continue;
        }
        guarded.push((key, kind));
        if columns
            .iter()
            .any(|(c, r)| *r && cas_guard::is_credential_column(kind, c))
        {
            readable.insert(key.clone());
        }
    }
    // Roles and `PUBLIC` (`SHOW GRANTS`), enabled or not.
    let mut grants = Grants::default();
    let evaluated = role_privileges(session, &mut grants).await?;
    complete &= evaluated && grants.roles_unevaluated == 0 && !grants.selects_unknown;
    let db_of = |g: &grant_lines::SelectGrant, schema: &str| {
        g.db.as_deref()
            .is_none_or(|d| d.is_empty() || db_matches(d, schema))
    };
    for g in &grants.selects {
        match &g.table {
            Some(table) => {
                let kind = cas_guard::recognize_name(stores, [table.as_str()]).or_else(|| {
                    guarded
                        .iter()
                        .find(|((s, t), _)| t == table && db_of(g, s))
                        .map(|(_, k)| *k)
                });
                let Some(kind) = kind.filter(|k| *k != StoreKind::ServiceRegistry) else {
                    continue;
                };
                let credential = g.columns.as_ref().is_none_or(|cols| {
                    cols.iter()
                        .any(|c| cas_guard::is_credential_column(kind, c))
                });
                if credential {
                    readable.insert((g.db.clone().unwrap_or_default(), table.clone()));
                }
            }
            None => {
                for ((s, t), _) in &guarded {
                    if db_of(g, s) {
                        readable.insert((s.clone(), t.clone()));
                    }
                }
            }
        }
    }
    Ok(cas_guard::ReadableCheck {
        readable: readable.len() as u64,
        complete,
    })
}

async fn report(
    session: &mut Session,
    extended: bool,
    audit: bool,
    file_source: bool,
) -> Result<Report, MyError> {
    let current = probe(session, sql::CURRENT_USER).await?;
    let current = cell(&current, 0, 0).unwrap_or_default().to_owned();
    // The grantee expression cannot match names with quotes or
    // backslashes (escaped in the GRANTEE column).
    let matchable = !current.contains('\'') && !current.contains('\\') && current.contains('@');
    let mut grants = Grants::default();
    let mut privileges_unknown = !matchable;
    if matchable {
        let (global, skipped) = session
            .query_counted(Stage::Check, sql::USER_PRIVILEGES)
            .await?;
        // Every account has at least `USAGE`: no row means no match. A row
        // skipped (not UTF-8) or a list cut at its `LIMIT` leaves the
        // privileges unknown (fail closed).
        privileges_unknown = global.is_empty() || skipped > 0 || global.len() >= 1000;
        for row in &global {
            let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
            grants.global.push((v(0), v(1) == "YES"));
        }
        for (statement, limit) in [
            (sql::SCHEMA_PRIVILEGES, 10_000),
            (sql::TABLE_PRIVILEGES, 100_000),
            (sql::COLUMN_PRIVILEGES, 100_000),
        ] {
            let (rows, skipped) = session.query_counted(Stage::Check, statement).await?;
            privileges_unknown |= skipped > 0 || rows.len() >= limit;
            for row in &rows {
                let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
                grants.scoped.push((v(0), v(1), v(2) == "YES"));
            }
        }
    }
    privileges_unknown |= !role_privileges(session, &mut grants).await?;
    let init_connect = optional(session, sql::INIT_CONNECT)
        .await?
        .is_some_and(|r| truthy(cell(&r, 0, 0)));
    let tables = {
        let mut tx = session.begin().await?;
        match catalog::introspect(&mut tx).await {
            Ok(t) => {
                tx.commit().await?;
                t
            }
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        }
    };
    let (_, coverage) = catalog::plan(&tables, |_, _| true);
    let (over_privileged, expected, privilege_notes) =
        evaluate_privileges(&grants, extended, audit, file_source);
    Ok(Report {
        over_privileged,
        expected,
        privilege_notes,
        privileges_unknown,
        init_connect,
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(p: &str) -> (String, bool) {
        (p.to_owned(), false)
    }

    fn s(db: &str, p: &str) -> (String, String, bool) {
        (db.to_owned(), p.to_owned(), false)
    }

    #[test]
    fn select_only_account_is_not_over_privileged() {
        let grants = Grants {
            global: vec![g("USAGE")],
            scoped: vec![s("hr", "SELECT"), s("performance_schema", "SELECT")],
            ..Grants::default()
        };
        // performance_schema is the Audit grant while Audit runs...
        assert_eq!(
            evaluate_privileges(&grants, false, true, false),
            (vec![], vec![], vec![])
        );
        // ...and over-privilege otherwise (ADR-0018).
        let (over, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_eq!(over.len(), 1, "{over:?}");
        assert!(over[0].starts_with("SELECT on performance_schema without Audit"));
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.performance_schema_without_audit"}])
        );
        // With an audit log as the source, the grant is unused.
        let (over, _, notes) = evaluate_privileges(&grants, false, true, true);
        assert_eq!(over.len(), 1, "{over:?}");
        assert!(over[0].starts_with("SELECT on performance_schema unused"));
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.performance_schema_unused"}])
        );
        let hr_only = Grants {
            global: vec![g("USAGE")],
            scoped: vec![s("hr", "SELECT")],
            ..Grants::default()
        };
        assert_eq!(
            evaluate_privileges(&hr_only, false, false, false),
            (vec![], vec![], vec![])
        );
    }

    #[test]
    fn documented_dev_grants_are_reported() {
        // docs/05 today: SELECT, PROCESS, SHOW VIEW ON *.*.
        let grants = Grants {
            global: vec![g("SELECT"), g("PROCESS"), g("SHOW VIEW")],
            scoped: vec![s("performance_schema", "SELECT")],
            ..Grants::default()
        };
        let (over, expected, notes) = evaluate_privileges(&grants, false, true, false);
        assert_eq!(over.len(), 2, "{over:?}");
        assert!(expected.is_empty());
        assert!(over[0].starts_with("global SELECT"));
        assert_eq!(over[1], "global privileges: PROCESS, SHOW VIEW");
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "privilege.global_select"},
                {"code": "privilege.global_privileges", "count": 2, "labels": ["process", "show_view"]}
            ])
        );
        // Extended variant: global SELECT expected, PROCESS / SHOW VIEW not.
        let (over, expected, notes) = evaluate_privileges(&grants, true, true, false);
        assert_eq!(over, ["global privileges: PROCESS, SHOW VIEW"]);
        assert!(expected[0].starts_with("global SELECT"));
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "privilege.extended_variant", "labels": ["select"]},
                {"code": "privilege.global_privileges", "count": 2, "labels": ["process", "show_view"]}
            ])
        );
    }

    #[test]
    fn long_privilege_lists_keep_the_most_severe_labels_and_the_full_count() {
        let names = [
            "ALTER",
            "CREATE",
            "CREATE VIEW",
            "DELETE",
            "DROP",
            "EVENT",
            "EXECUTE",
            "INDEX",
            "INSERT",
            "LOCK TABLES",
            "REFERENCES",
            "SHOW VIEW",
            "SHOW DATABASES",
            "TRIGGER",
            "UPDATE",
            "CREATE ROUTINE",
            "ALTER ROUTINE",
            "FLUSH_TABLES",
            "SUPER",
            "FILE",
        ];
        let grants = Grants {
            global: names.iter().map(|n| g(n)).collect(),
            scoped: vec![],
            ..Grants::default()
        };
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_registered(&notes);
        let n = notes
            .iter()
            .find(|n| n.code() == NoteCode::PrivilegeGlobalPrivileges)
            .unwrap();
        assert_eq!(n.count(), Some(names.len() as u64));
        let labels: Vec<String> = n.labels().iter().map(|l| l.as_str()).collect();
        assert_eq!(labels.len(), 16);
        for must in ["super", "file", "execute"] {
            assert!(labels.iter().any(|l| l == must), "{must} cut: {labels:?}");
        }
    }

    #[test]
    fn over_privileges_are_reported() {
        let grants = Grants {
            global: vec![g("SUPER"), g("FILE"), ("USAGE".to_owned(), true)],
            scoped: vec![
                s("hr", "INSERT"),
                s("hr", "EXECUTE"),
                s("mysql", "SELECT"),
                s("hr", "weird-SECRET"),
            ],
            roles: 3,
            roles_unevaluated: 2,
            other_grantable: false,
            selects: Vec::new(),
            selects_unknown: false,
        };
        let (over, _, notes) = evaluate_privileges(&grants, true, true, false);
        assert_registered(&notes);
        let json = notes_json(&notes);
        assert_eq!(
            json,
            serde_json::json!([
                {"code": "privilege.global_privileges", "count": 2, "labels": ["file", "super"]},
                {"code": "privilege.system_database_select"},
                {"code": "privilege.beyond_select", "count": 3, "labels": ["other", "execute", "insert"]},
                {"code": "privilege.grant_option"},
                {"code": "privilege.roles_not_evaluated", "count": 2}
            ])
        );
        assert!(!json.to_string().contains("SECRET") && !json.to_string().contains("weird"));
        for label in [
            "global privileges: FILE, SUPER",
            "SELECT on the mysql or sys system database",
            "privileges beyond SELECT on databases / tables / columns: EXECUTE, INSERT, OTHER",
            "WITH GRANT OPTION",
            "granted 3 role(s), 2 of them not evaluated (their privileges are unknown)",
        ] {
            assert!(over.iter().any(|o| o == label), "{label}: {over:?}");
        }
        assert!(!over.iter().any(|o| o.contains("SECRET")));
    }

    fn rows(lines: &[&str]) -> Rows {
        lines.iter().map(|l| vec![Some((*l).to_owned())]).collect()
    }

    /// PR #141 review M1: a privilege line whose `SELECT` grants are not
    /// understood leaves the CAS store guard check not evaluated; `PROXY`
    /// lines grant no `SELECT` (the property tests check that every line
    /// `parse_line` reads as privileges has its `SELECT` grants read).
    #[test]
    fn select_grants_are_read_from_every_privilege_line() {
        let mut grants = Grants::default();
        assert!(merge_grant_lines(
            &rows(&[
                "GRANT PROXY ON ''@'' TO `u`@`%` WITH GRANT OPTION",
                "GRANT SELECT (`a`) ON `hr`.`t` TO `u`@`%`",
                "GRANT EXECUTE ON PROCEDURE `hr`.`p` TO `u`@`%`",
            ]),
            &mut grants
        ));
        assert!(!grants.selects_unknown);
        assert_eq!(grants.selects.len(), 1);
    }

    /// End-of-phase-4 review L2: without `APPLICABLE_ROLES`, the role
    /// lines of `SHOW GRANTS` (and MySQL's mandatory roles) are counted as
    /// not evaluated; a line not understood leaves the privileges unknown.
    #[test]
    fn roles_fall_back_to_show_grants_lines() {
        let mut grants = Grants::default();
        assert!(roles_from_grant_lines(
            &rows(&[
                "GRANT USAGE ON *.* TO `databastion`@`%`",
                "GRANT SELECT ON `hr`.* TO `databastion`@`%`",
                "GRANT `app_read`@`%`,`app_write`@`%` TO `databastion`@`%`",
                "GRANT `admin_role`@`%` TO `databastion`@`%` WITH ADMIN OPTION",
            ]),
            Some("`audit_all`@`%`, `ro`@`%`"),
            &mut grants
        ));
        assert_eq!((grants.roles, grants.roles_unevaluated), (5, 5));
        assert!(grants.other_grantable);
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert!(
            notes_json(&notes).as_array().unwrap().contains(
                &serde_json::json!({"code": "privilege.roles_not_evaluated", "count": 5})
            )
        );
        // No role line, no mandatory role: no role.
        let mut grants = Grants::default();
        assert!(roles_from_grant_lines(
            &rows(&["GRANT SELECT ON `hr`.* TO `databastion`@`%`"]),
            Some(""),
            &mut grants
        ));
        assert_eq!((grants.roles, grants.roles_unevaluated), (0, 0));
        // MariaDB lines.
        let mut grants = Grants::default();
        assert!(roles_from_grant_lines(
            &rows(&[
                "GRANT `app_read` TO `databastion`@`%`",
                "SET DEFAULT ROLE `app_read` FOR `databastion`@`%`",
            ]),
            None,
            &mut grants
        ));
        assert_eq!(grants.roles_unevaluated, 1);
        // A line not understood: not evaluated.
        let mut grants = Grants::default();
        assert!(!roles_from_grant_lines(
            &rows(&["GRANT SOMETHING ODD"]),
            None,
            &mut grants
        ));
    }

    /// MariaDB 10.11+ (ADR-0025 residual, phase 7): the privileges granted
    /// to `PUBLIC` are evaluated like a role's; a role granted to `PUBLIC`
    /// or a line not understood leaves them not evaluated.
    #[test]
    fn public_privileges_are_evaluated_like_a_role() {
        let mut grants = Grants {
            global: vec![g("USAGE")],
            scoped: vec![s("hr", "SELECT")],
            ..Grants::default()
        };
        assert!(merge_public_lines(
            &rows(&[
                "GRANT USAGE ON *.* TO PUBLIC",
                "GRANT SELECT ON `hr`.* TO PUBLIC",
                "GRANT INSERT ON `hr`.* TO PUBLIC",
                "GRANT SELECT ON `m%`.* TO PUBLIC",
            ]),
            &mut grants
        ));
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "privilege.system_database_select"},
                {"code": "privilege.beyond_select", "count": 1, "labels": ["insert"]}
            ])
        );
        // Only SELECT on an application database: nothing to report.
        let mut grants = Grants::default();
        assert!(merge_public_lines(
            &rows(&["GRANT SELECT ON `hr`.* TO PUBLIC"]),
            &mut grants
        ));
        assert!(
            evaluate_privileges(&grants, false, false, false)
                .2
                .is_empty()
        );
        // Fail closed.
        for line in ["GRANT `app_write` TO PUBLIC", "GRANT SOMETHING ODD"] {
            let mut grants = Grants::default();
            assert!(!merge_public_lines(&rows(&[line]), &mut grants), "{line}");
        }
    }

    #[test]
    fn role_privileges_are_evaluated_like_direct_ones() {
        // MySQL `SHOW GRANTS FOR CURRENT_USER() USING …`: the account's own
        // grants, its role grants, and the privileges of the roles.
        let mut grants = Grants {
            global: vec![g("USAGE")],
            scoped: vec![s("hr", "SELECT")],
            roles: 2,
            ..Grants::default()
        };
        assert!(merge_grant_lines(
            &rows(&[
                "GRANT USAGE ON *.* TO `databastion`@`%`",
                "GRANT SELECT ON `hr`.* TO `databastion`@`%`",
                "GRANT INSERT, UPDATE ON `hr`.* TO `databastion`@`%`",
                "GRANT SELECT ON `mysql`.`user` TO `databastion`@`%`",
                "GRANT PROCESS ON *.* TO `databastion`@`%`",
                "GRANT `app_read`@`%`,`app_write`@`%` TO `databastion`@`%`",
                "REVOKE INSERT ON `hr`.`t` FROM `databastion`@`%`",
            ]),
            &mut grants
        ));
        let (over, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_registered(&notes);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "privilege.global_privileges", "count": 1, "labels": ["process"]},
                {"code": "privilege.system_database_select"},
                {"code": "privilege.beyond_select", "count": 2, "labels": ["insert", "update"]}
            ])
        );
        // Every role evaluated: no "not evaluated" note.
        assert!(!over.iter().any(|o| o.contains("role")), "{over:?}");

        // A role granting SELECT on the application database only (the
        // ADR-0018 minimal variant through a role) is not over-privilege.
        let mut grants = Grants {
            roles: 1,
            ..Grants::default()
        };
        assert!(merge_grant_lines(
            &rows(&[
                "GRANT USAGE ON *.* TO `app_read`",
                "GRANT SELECT ON `support`.* TO `app_read`",
                "GRANT SELECT (`id`) ON `support`.`t` TO `app_read`",
            ]),
            &mut grants
        ));
        assert_eq!(
            evaluate_privileges(&grants, false, false, false),
            (vec![], vec![], vec![])
        );
    }

    #[test]
    fn grant_and_admin_options_through_roles_are_reported() {
        for lines in [
            &["GRANT SELECT ON `hr`.* TO `r` WITH GRANT OPTION"][..],
            &["GRANT USAGE ON `hr`.* TO `r` WITH GRANT OPTION"],
            &["GRANT `nested` TO `r` WITH ADMIN OPTION"],
            &["GRANT PROXY ON ``@`` TO `r` WITH GRANT OPTION"],
        ] {
            let mut grants = Grants {
                roles: 1,
                ..Grants::default()
            };
            assert!(merge_grant_lines(&rows(lines), &mut grants));
            let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
            assert_registered(&notes);
            assert!(
                notes
                    .iter()
                    .any(|n| n.code() == NoteCode::PrivilegeGrantOption),
                "{lines:?}: {notes:?}"
            );
        }
        // Admin option from `APPLICABLE_ROLES.IS_GRANTABLE`.
        let grants = Grants {
            roles: 1,
            other_grantable: true,
            ..Grants::default()
        };
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.grant_option"}])
        );
    }

    #[test]
    fn roles_that_cannot_be_evaluated_are_reported() {
        // A line the parser does not understand: the output is not trusted
        // to be complete.
        let mut grants = Grants {
            roles: 1,
            ..Grants::default()
        };
        assert!(!merge_grant_lines(
            &rows(&[
                "GRANT SELECT ON `hr`.* TO `r`",
                "GRANT SELECT ON `a`.`b`.`c` TO `r`",
            ]),
            &mut grants
        ));
        assert!(!merge_grant_lines(&vec![vec![None]], &mut grants));
        grants.roles_unevaluated = 1;
        let (over, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.roles_not_evaluated", "count": 1}])
        );
        assert_eq!(
            over,
            ["granted 1 role(s), 1 of them not evaluated (their privileges are unknown)"]
        );
        // Nothing from the server text reaches the notes.
        let mut grants = Grants::default();
        assert!(merge_grant_lines(
            &rows(&["GRANT SECRET_marker ON `hr_secret`.* TO `r`"]),
            &mut grants
        ));
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        let json = notes_json(&notes).to_string();
        assert!(
            !json.contains("secret") && !json.contains("SECRET"),
            "{json}"
        );
    }

    #[test]
    fn database_patterns_cover_the_system_databases() {
        for (pattern, name) in [
            ("mysql", "mysql"),
            ("MySQL", "mysql"),
            ("performance\\_schema", "performance_schema"),
            ("performance_schema", "performance_schema"),
            ("%", "mysql"),
            ("%", "sys"),
            ("mysq_", "mysql"),
            ("m%", "mysql"),
            ("%_schema", "performance_schema"),
            ("s_s", "sys"),
            ("\\%", "%"),
        ] {
            assert!(db_matches(pattern, name), "{pattern} {name}");
        }
        for (pattern, name) in [
            ("hr", "mysql"),
            ("mysql\\_", "mysql"),
            ("my\\%", "mysql"),
            ("\\_ys", "sys"),
            ("mysq", "mysql"),
            ("mysql_", "mysql"),
            ("", "sys"),
            ("h%", "sys"),
        ] {
            assert!(!db_matches(pattern, name), "{pattern} {name}");
        }
    }

    #[test]
    fn select_through_a_database_pattern_is_reported() {
        for (db, codes) in [
            (
                "%",
                &[
                    "privilege.system_database_select",
                    "privilege.performance_schema_without_audit",
                ][..],
            ),
            ("m%", &["privilege.system_database_select"]),
            ("mysq_", &["privilege.system_database_select"]),
            (
                "performance\\_schema",
                &["privilege.performance_schema_without_audit"],
            ),
            ("hr\\_%", &[]),
        ] {
            let grants = Grants {
                scoped: vec![s(db, "SELECT")],
                ..Grants::default()
            };
            let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
            assert_registered(&notes);
            let got: Vec<&str> = notes.iter().map(|n| n.code().as_str()).collect();
            assert_eq!(got, codes, "{db}");
        }
        // The same through a role's `SHOW GRANTS` line.
        let mut grants = Grants {
            roles: 1,
            ..Grants::default()
        };
        assert!(merge_grant_lines(
            &rows(&["GRANT SELECT ON `performance\\_schema`.* TO `r`"]),
            &mut grants
        ));
        let (_, _, notes) = evaluate_privileges(&grants, false, false, false);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([{"code": "privilege.performance_schema_without_audit"}])
        );
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

    /// Every note is registered for both `mysql` and `mariadb`, or for the
    /// engine it is specific to (`check.server_is_*`, the MySQL-only
    /// `audit_log` plugin and `audit_log_filter` component).
    fn assert_registered(notes: &[TargetNote]) {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../shared/protocol/target-notes.json"
        ))
        .unwrap();
        for n in notes {
            let code = n.code().as_str();
            let engines: Vec<&str> = v[code]["engines"]
                .as_array()
                .unwrap_or_else(|| panic!("{code} is not registered"))
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            let expected: &[&str] = match n.code() {
                NoteCode::CheckServerIsMariadb
                | NoteCode::AuditAuditLogPluginNotRead
                | NoteCode::AuditAuditLogFilterNotRead => &["mysql"],
                NoteCode::CheckServerIsMysql => &["mariadb"],
                _ => &["mysql", "mariadb"],
            };
            for e in expected {
                assert!(engines.contains(e), "{code} is not registered for {e}");
            }
        }
    }

    #[test]
    fn audit_notes_follow_the_log_detail() {
        let sa = |logging, file| AuditProbe {
            server_audit: Some(ServerAudit {
                logging,
                file,
                statements: true,
            }),
            audit_log: Some(("JSON".to_owned(), true)),
            audit_log_filter: Some("JSON".to_owned()),
            general_log: true,
            ..ps_probe()
        };
        // No audit log configured: each active plugin is noted with its state.
        let (text, notes) = sa(false, true).explain(None);
        assert_registered(&notes);
        assert_eq!(
            notes_json(&notes),
            serde_json::json!([
                {"code": "audit.server_audit_not_read", "labels": ["logging_off", "file_output"]},
                {"code": "audit.audit_log_plugin_not_read"},
                {"code": "audit.audit_log_filter_not_read"},
                {"code": "audit.general_log_enabled"}
            ])
        );
        assert!(text.len() > notes.len());
        let file = |readable, recent, format| {
            Some(FileState {
                format,
                readable,
                recent,
            })
        };
        let cases = [
            (
                file(false, false, MysqlLogFormat::ServerAudit),
                vec!["audit.log_not_readable"],
            ),
            (
                file(true, true, MysqlLogFormat::ServerAudit),
                vec!["audit.log_plugin_mismatch"],
            ),
            (
                file(true, false, MysqlLogFormat::Json),
                vec![
                    "audit.partial_pending_first_record",
                    "audit.log_without_row_counts",
                ],
            ),
            (
                file(true, true, MysqlLogFormat::Json),
                vec!["audit.log_without_row_counts"],
            ),
        ];
        for (f, expected) in cases {
            let (_, notes) = sa(false, true).explain(f);
            assert_registered(&notes);
            let codes: Vec<&str> = notes
                .iter()
                .map(|n| n.code().as_str())
                .filter(|c| *c != "audit.general_log_enabled")
                .collect();
            assert_eq!(codes, expected, "{f:?}");
        }
        // performance_schema states.
        for (probe, code) in [
            (
                AuditProbe {
                    consumers_readable: false,
                    ..ps_probe()
                },
                "audit.performance_schema_not_readable",
            ),
            (
                AuditProbe {
                    current_enabled: false,
                    ..ps_probe()
                },
                "audit.statement_consumers_disabled",
            ),
            (
                AuditProbe {
                    history_long_enabled: false,
                    ..ps_probe()
                },
                "audit.history_long_consumer_disabled",
            ),
            (
                AuditProbe {
                    history_long_readable: false,
                    ..ps_probe()
                },
                "audit.history_not_readable",
            ),
        ] {
            let (_, notes) = probe.explain(None);
            assert_registered(&notes);
            assert_eq!(notes_json(&notes), serde_json::json!([{"code": code}]));
        }
        assert!(ps_probe().explain(None).1.is_empty());
    }

    #[test]
    fn report_notes_are_counts_and_codes_only() {
        let r = Report {
            privileges_unknown: true,
            init_connect: true,
            coverage: Coverage {
                views: vec![("hr".to_owned(), "v_secret_view".to_owned()); 2],
                engines: vec![
                    ("hr".to_owned(), "fed".to_owned(), EngineSkip::Remote),
                    ("hr".to_owned(), "m".to_owned(), EngineSkip::Merge),
                    ("hr".to_owned(), "x".to_owned(), EngineSkip::Other),
                ],
                ..Coverage::default()
            },
            ..Report::default()
        };
        let notes = report_notes(&r);
        assert_registered(&notes);
        let json = notes_json(&notes);
        assert_eq!(
            json,
            serde_json::json!([
                {"code": "privilege.not_evaluated"},
                {"code": "security.init_connect"},
                {"code": "coverage.views_not_sampled", "count": 2},
                {"code": "coverage.remote_engine_tables", "count": 1},
                {"code": "coverage.other_engine_tables", "count": 2}
            ])
        );
        assert!(!json.to_string().contains("secret"));
        assert!(report_notes(&Report::default()).is_empty());
    }

    #[test]
    fn check_failures_are_noted_with_their_stage_only() {
        let mut e = MyError::new(FailureCode::TargetUnreachable, Stage::Auth);
        e.errno = Some(1045);
        let health = unreachable(&e);
        assert_registered(&health.notes);
        assert_eq!(
            notes_json(&health.notes),
            serde_json::json!([{"code": "check.stage_failed", "labels": ["stage_auth"]}])
        );
        for stage in [
            Stage::Secret,
            Stage::Tls,
            Stage::Connect,
            Stage::Auth,
            Stage::SessionSetup,
            Stage::Begin,
            Stage::Commit,
            Stage::Introspection,
            Stage::Columns,
            Stage::Sample,
            Stage::Check,
            Stage::Kill,
            Stage::Audit,
        ] {
            assert!(!NoteLabel::stage(stage.as_str()).is_other(), "{stage:?}");
        }
    }

    fn ps_probe() -> AuditProbe {
        AuditProbe {
            ps_enabled: true,
            consumers_readable: true,
            instrumentation: true,
            current_enabled: true,
            history_enabled: true,
            history_long_enabled: true,
            current_readable: true,
            history_readable: true,
            history_long_readable: true,
            server_audit: None,
            audit_log: None,
            audit_log_filter: None,
            general_log: false,
        }
    }

    #[test]
    fn audit_level_is_proven_not_assumed() {
        let full = ps_probe();
        assert_eq!(full.level(), AuditLevel::Partial);
        assert_eq!(choose(&full, None).1, Source::Ps(PsTable::HistoryLong));
        let limited = AuditProbe {
            history_long_enabled: false,
            ..full.clone()
        };
        assert_eq!(limited.level(), AuditLevel::Limited);
        assert_eq!(choose(&limited, None).1, Source::Ps(PsTable::History));
        // history_long depends on events_statements_current and the
        // instrumentation consumers (the MariaDB default has it off).
        for broken in [
            AuditProbe {
                current_enabled: false,
                ..full.clone()
            },
            AuditProbe {
                instrumentation: false,
                ..full.clone()
            },
        ] {
            assert_eq!(broken.level(), AuditLevel::None);
            assert!(
                broken
                    .notes(None)
                    .iter()
                    .any(|n| n.contains("consumers inactive")),
                "{:?}",
                broken.notes(None)
            );
        }
        let unreadable = AuditProbe {
            history_long_readable: false,
            history_readable: false,
            current_readable: false,
            ..full.clone()
        };
        assert_eq!(unreadable.level(), AuditLevel::None);
        let off = AuditProbe {
            ps_enabled: false,
            ..full
        };
        assert_eq!(off.level(), AuditLevel::None);
        let no_grant = AuditProbe {
            ps_enabled: true,
            ..AuditProbe::default()
        };
        assert_eq!(no_grant.level(), AuditLevel::None);
        assert!(no_grant.notes(None)[0].contains("not readable by the account"));
    }

    #[test]
    fn audit_log_source_needs_a_readable_file_an_active_plugin_and_a_record() {
        let sa = |logging, statements| AuditProbe {
            server_audit: Some(ServerAudit {
                logging,
                file: true,
                statements,
            }),
            ..AuditProbe::default()
        };
        let file = |readable, recent| {
            Some(FileState {
                format: MysqlLogFormat::ServerAudit,
                readable,
                recent,
            })
        };
        assert_eq!(
            choose(&sa(true, true), file(true, true)),
            (
                AuditLevel::Partial,
                Source::File(MysqlLogFormat::ServerAudit)
            )
        );
        // No record read yet: one level down.
        assert_eq!(
            choose(&sa(true, true), file(true, false)),
            (
                AuditLevel::Limited,
                Source::File(MysqlLogFormat::ServerAudit)
            )
        );
        for (probe, f) in [
            (sa(true, true), file(false, true)),
            (sa(false, true), file(true, true)),
            (sa(true, false), file(true, true)),
            (sa(true, true), None),
        ] {
            assert_eq!(choose(&probe, f), (AuditLevel::None, Source::None));
        }
        // performance_schema is the fallback.
        let both = AuditProbe {
            server_audit: Some(ServerAudit::default()),
            ..ps_probe()
        };
        assert_eq!(
            choose(&both, file(true, true)),
            (AuditLevel::Partial, Source::Ps(PsTable::HistoryLong))
        );
        assert!(
            both.notes(file(true, true))
                .iter()
                .any(|n| n.contains("no matching active audit plugin"))
        );
        // JSON: the audit_log plugin with the JSON format and a policy
        // logging queries, or the audit_log_filter component in JSON.
        let json = Some(FileState {
            format: MysqlLogFormat::Json,
            readable: true,
            recent: true,
        });
        let legacy = |format: &str, queries| AuditProbe {
            audit_log: Some((format.to_owned(), queries)),
            ..AuditProbe::default()
        };
        assert_eq!(choose(&legacy("JSON", true), json).0, AuditLevel::Partial);
        assert_eq!(choose(&legacy("NEW", true), json).0, AuditLevel::None);
        assert_eq!(choose(&legacy("JSON", false), json).0, AuditLevel::None);
        let filter = AuditProbe {
            audit_log_filter: Some("JSON".to_owned()),
            ..AuditProbe::default()
        };
        assert_eq!(choose(&filter, json).1, Source::File(MysqlLogFormat::Json));
        assert!(
            filter
                .notes(json)
                .iter()
                .any(|n| n.contains("no row counts")),
            "{:?}",
            filter.notes(json)
        );
    }
}
