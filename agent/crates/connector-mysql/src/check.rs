//! `check()`: reachability, honest audit level, over-privilege and
//! coverage.
//!
//! Audit level (docs/08), reporting only what the account can prove:
//! - **Partial**: `performance_schema` is on, the
//!   `events_statements_history_long` consumer is enabled and the account
//!   can read that table (statements of every session, `ROWS_SENT`).
//! - **Limited**: only the per-thread `events_statements_current` /
//!   `events_statements_history` consumers are enabled and readable (recent
//!   statements only, easily missed).
//! - **Full** needs the agent to read an audit log (MariaDB
//!   `server_audit`, Percona / Enterprise `audit_log`) from the file
//!   system. Its path is not configured before P4-A, so Full is never
//!   reported yet: an active audit plugin is only mentioned in the detail.
//! - **None** otherwise.
//!
//! Over-privilege (warned, not refused): any global privilege (`*.*`,
//! including `SELECT`, which reads `mysql.user` password hashes, `PROCESS`,
//! `SUPER`, `FILE`…), any grant `WITH GRANT OPTION`, any database / table /
//! column privilege other than `SELECT`, `SELECT` on the `mysql` or `sys`
//! database, and roles (whose privileges are not listed). `init_connect`
//! (SQL run at every login) is reported. Coverage: views and tables of
//! engines that are not sampled.
//!
//! The detailed report is recomputed at most every [`REPORT_INTERVAL`] per
//! target and logged when it changes; the reachability and the audit level
//! are checked on every call.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_core::config::{MysqlTlsMode, TargetConfig, TargetEngine};
use databastion_core::{AuditLevel, FailureCode, TargetHealth};

use crate::catalog::{self, Coverage, EngineSkip};
use crate::conn::{Flavor, Rows, Session, Timeouts};
use crate::discover::normalize;
use crate::error::{MyError, Stage};
use crate::sql;

/// Statement timeout of `check()` queries.
const CHECK_STATEMENT_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Period of the detailed report.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);
/// Most names listed in a log line.
const MAX_LOGGED_NAMES: usize = 20;

/// Audit prerequisites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AuditProbe {
    pub(crate) ps_enabled: bool,
    pub(crate) history_long_enabled: bool,
    pub(crate) history_long_readable: bool,
    pub(crate) current_enabled: bool,
    pub(crate) current_readable: bool,
    /// MariaDB `server_audit`: active, logging on, file output.
    pub(crate) server_audit: Option<(bool, bool)>,
    /// Percona / MySQL Enterprise `audit_log` (or `audit_log_filter`)
    /// active.
    pub(crate) audit_log_plugin: bool,
    pub(crate) general_log: bool,
}

impl AuditProbe {
    pub(crate) fn level(&self) -> AuditLevel {
        if self.ps_enabled && self.history_long_enabled && self.history_long_readable {
            AuditLevel::Partial
        } else if self.ps_enabled && self.current_enabled && self.current_readable {
            AuditLevel::Limited
        } else {
            AuditLevel::None
        }
    }

    fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some((logging, file)) = self.server_audit {
            out.push(format!(
                "server_audit active (logging {}, {} output); Full needs the agent to read its \
                 log file (not configured before P4-A)",
                if logging { "ON" } else { "OFF" },
                if file { "file" } else { "non-file" }
            ));
        }
        if self.audit_log_plugin {
            out.push(
                "audit_log plugin active; Full needs the agent to read its log file (not \
                 configured before P4-A)"
                    .to_owned(),
            );
        }
        if self.ps_enabled && !self.history_long_enabled {
            out.push(
                "performance_schema events_statements_history_long consumer disabled".to_owned(),
            );
        }
        if self.history_long_enabled && !self.history_long_readable {
            out.push("performance_schema statement history not readable by the account".to_owned());
        }
        if self.general_log {
            out.push("general log enabled (not used as an audit source)".to_owned());
        }
        out
    }
}

/// Privileges of the account (privilege names upper-case).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Grants {
    pub(crate) global: Vec<(String, bool)>,
    /// (database, privilege, grantable) at database, table and column
    /// level.
    pub(crate) scoped: Vec<(String, String, bool)>,
    pub(crate) roles: i64,
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

/// Evaluates over-privilege. Returns closed labels.
pub(crate) fn evaluate_privileges(g: &Grants) -> Vec<String> {
    let mut over = Vec::new();
    let mut global: BTreeSet<String> = BTreeSet::new();
    let mut grantable = false;
    for (p, gr) in &g.global {
        grantable |= *gr;
        let p = p.to_ascii_uppercase();
        if p != "USAGE" {
            global.insert(label(&p));
        }
    }
    if global.contains("SELECT") {
        over.push(
            "global SELECT (system tables readable, including mysql.user password hashes)"
                .to_owned(),
        );
        global.remove("SELECT");
    }
    if !global.is_empty() {
        over.push(format!(
            "global privileges: {}",
            global.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let mut beyond_select: BTreeSet<String> = BTreeSet::new();
    let mut system_select = false;
    for (db, p, gr) in &g.scoped {
        grantable |= *gr;
        let p = p.to_ascii_uppercase();
        if p == "SELECT" {
            if db.eq_ignore_ascii_case("mysql") || db.eq_ignore_ascii_case("sys") {
                system_select = true;
            }
        } else {
            beyond_select.insert(label(&p));
        }
    }
    if system_select {
        over.push("SELECT on the mysql or sys system database".to_owned());
    }
    if !beyond_select.is_empty() {
        over.push(format!(
            "privileges beyond SELECT on databases / tables / columns: {}",
            beyond_select.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if grantable {
        over.push("WITH GRANT OPTION".to_owned());
    }
    if g.roles > 0 {
        over.push(format!(
            "granted {} role(s) (their privileges are not evaluated)",
            g.roles
        ));
    }
    over
}

/// Privileges and coverage of the account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) over_privileged: Vec<String>,
    /// The account name cannot be matched in the privilege tables.
    pub(crate) privileges_unknown: bool,
    pub(crate) init_connect: bool,
    pub(crate) coverage: Coverage,
}

struct Cached {
    at: Instant,
    report: Report,
}

/// Per target: last detailed report.
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<String, Cached>>,
}

impl CheckState {
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
    }
}

/// `check()` of a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TIMEOUT, check_inner(state, target)).await {
        Ok(h) => h,
        Err(_) => TargetHealth {
            reachable: false,
            audit_level: AuditLevel::None,
            failure: Some(FailureCode::Timeout),
            detail: Some("check timed out".to_owned()),
        },
    }
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let timeouts = Timeouts::new(CHECK_STATEMENT_TIMEOUT);
    let mut notes: Vec<String> = Vec::new();
    if target.mysql_settings().tls == MysqlTlsMode::DisableInsecure {
        notes.push(
            "INSECURE: TLS disabled on a network connection (tls: disable_insecure): traffic \
             in clear, read-only not guaranteed"
                .to_owned(),
        );
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
            return unreachable(&e);
        }
    };
    match (target.engine, session.flavor()) {
        (TargetEngine::Mysql, Flavor::Mariadb) => {
            notes.push("the server is MariaDB (target declared as mysql)".to_owned());
        }
        (TargetEngine::Mariadb, Flavor::Mysql) => {
            notes.push("the server is MySQL (target declared as mariadb)".to_owned());
        }
        _ => {}
    }
    let probe = match audit_probe(&mut session).await {
        Ok(p) => p,
        Err(e) => return unreachable(&e),
    };
    let level = probe.level();
    notes.extend(probe.notes());
    if state.due(&target.id) && !session.is_poisoned() {
        match report(&mut session).await {
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
    }
    session.close().await;
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
    if r.privileges_unknown {
        out.push("privileges not evaluated (account name not matched)".to_owned());
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
            for row in &rows {
                let enabled = truthy(row.get(1).and_then(|v| v.as_deref()));
                match row.first().and_then(|v| v.as_deref()) {
                    Some("events_statements_history_long") => p.history_long_enabled = enabled,
                    Some("events_statements_history" | "events_statements_current") => {
                        p.current_enabled |= enabled;
                    }
                    _ => {}
                }
            }
        }
        p.history_long_readable = optional(session, sql::PS_HISTORY_LONG).await?.is_some();
        p.current_readable = optional(session, sql::PS_CURRENT).await?.is_some();
    }
    if let Some(rows) = optional(session, sql::AUDIT_PLUGINS).await? {
        for row in &rows {
            let active = row.get(1).and_then(|v| v.as_deref()) == Some("ACTIVE");
            match row.first().and_then(|v| v.as_deref()) {
                Some("SERVER_AUDIT") if active => p.server_audit = Some((false, false)),
                Some("audit_log" | "audit_log_filter") if active => p.audit_log_plugin = true,
                _ => {}
            }
        }
    }
    if p.server_audit.is_some() {
        if let Some(rows) = optional(session, sql::SERVER_AUDIT_SETTINGS).await? {
            p.server_audit = Some((
                truthy(cell(&rows, 0, 0)),
                cell(&rows, 0, 1).is_some_and(|v| v.eq_ignore_ascii_case("file")),
            ));
        }
    }
    Ok(p)
}

async fn report(session: &mut Session) -> Result<Report, MyError> {
    let current = probe(session, sql::CURRENT_USER).await?;
    let current = cell(&current, 0, 0).unwrap_or_default().to_owned();
    // The grantee expression cannot match names with quotes or
    // backslashes (escaped in the GRANTEE column).
    let matchable = !current.contains('\'') && !current.contains('\\') && current.contains('@');
    let mut grants = Grants::default();
    let mut privileges_unknown = !matchable;
    if matchable {
        let global = probe(session, sql::USER_PRIVILEGES).await?;
        // Every account has at least `USAGE`: no row means no match.
        privileges_unknown = global.is_empty();
        for row in &global {
            let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
            grants.global.push((v(0), v(1) == "YES"));
        }
        for statement in [
            sql::SCHEMA_PRIVILEGES,
            sql::TABLE_PRIVILEGES,
            sql::COLUMN_PRIVILEGES,
        ] {
            for row in &probe(session, statement).await? {
                let v = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
                grants.scoped.push((v(0), v(1), v(2) == "YES"));
            }
        }
    }
    grants.roles = optional(session, sql::ROLES)
        .await?
        .and_then(|r| cell(&r, 0, 0).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
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
    Ok(Report {
        over_privileged: evaluate_privileges(&grants),
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
            roles: 0,
        };
        assert!(evaluate_privileges(&grants).is_empty());
    }

    #[test]
    fn documented_dev_grants_are_reported() {
        // docs/05 today: SELECT, PROCESS, SHOW VIEW ON *.*.
        let grants = Grants {
            global: vec![g("SELECT"), g("PROCESS"), g("SHOW VIEW")],
            scoped: vec![s("performance_schema", "SELECT")],
            roles: 0,
        };
        let over = evaluate_privileges(&grants);
        assert_eq!(over.len(), 2, "{over:?}");
        assert!(over[0].starts_with("global SELECT"));
        assert_eq!(over[1], "global privileges: PROCESS, SHOW VIEW");
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
            roles: 2,
        };
        let over = evaluate_privileges(&grants);
        for label in [
            "global privileges: FILE, SUPER",
            "SELECT on the mysql or sys system database",
            "privileges beyond SELECT on databases / tables / columns: EXECUTE, INSERT, OTHER",
            "WITH GRANT OPTION",
            "granted 2 role(s) (their privileges are not evaluated)",
        ] {
            assert!(over.iter().any(|o| o == label), "{label}: {over:?}");
        }
        assert!(!over.iter().any(|o| o.contains("SECRET")));
    }

    #[test]
    fn audit_level_is_proven_not_assumed() {
        let full = AuditProbe {
            ps_enabled: true,
            history_long_enabled: true,
            history_long_readable: true,
            current_enabled: true,
            current_readable: true,
            server_audit: Some((true, true)),
            audit_log_plugin: false,
            general_log: false,
        };
        // Full needs the audit log file, which cannot be checked yet.
        assert_eq!(full.level(), AuditLevel::Partial);
        assert!(full.notes()[0].contains("server_audit active"));
        let limited = AuditProbe {
            history_long_enabled: false,
            ..full.clone()
        };
        assert_eq!(limited.level(), AuditLevel::Limited);
        let unreadable = AuditProbe {
            history_long_readable: false,
            current_readable: false,
            ..full.clone()
        };
        assert_eq!(unreadable.level(), AuditLevel::None);
        let off = AuditProbe {
            ps_enabled: false,
            ..full
        };
        assert_eq!(off.level(), AuditLevel::None);
    }
}
