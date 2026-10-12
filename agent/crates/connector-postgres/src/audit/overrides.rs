//! ADR-0012 refinement of 2026-10-12 (ADR-0037, refinement of 2026-10-12,
//! items 6, 9 and 14): the per-role, per-database and per-function
//! overrides of `log_min_messages` and `log_min_error_statement`, and the
//! `SET` / `ALTER SYSTEM` grants on them, that would hide a role's failed
//! statements (or their text) while the target reports Full.
//!
//! - `check()` (and the Audit stream's 5-minute probe) reads them with
//!   `sql::ROLE_LOG_OVERRIDES`, `sql::FUNCTION_LOG_OVERRIDES` and, on
//!   PostgreSQL 15+, `sql::PARAMETER_GRANTS`, in each monitored database,
//!   only while the database's level would be Full and no
//!   `pg_stat_statements` stream of the target runs ([`Probe::NotSent`]
//!   otherwise). The server filters the two keys: no other `setconfig` or
//!   `proconfig` entry reaches the agent.
//! - A database is proven ([`DbProof::proven`]) when every override and
//!   function `SET` clause of the two keys is `error` or lower, no role but
//!   the agent's and superusers holds a grant on them, and every statement
//!   was read in full. Otherwise the target is capped from Full to Partial,
//!   with a local detail ([`DbProof::detail`]) that names the database, the
//!   setting, and the roles or functions (normalized, at most 10, then a
//!   count), never a level or any other value.
//! - Item 4: the Audit stream's `FATAL` lines without a statement give no
//!   event only where the database is proven for the line's role
//!   ([`LogOverrides::fatal_quiet`]): not for a role with an override of
//!   `log_min_error_statement` above `error` or a `SET` grant on it, not for
//!   any role of a database with a database-wide override, a function `SET`
//!   clause or a `PUBLIC` or `ALTER SYSTEM` grant on it, a read that failed,
//!   was cut or was not sent, and not while the stream has seen an `ALTER
//!   ROLE`, `ALTER DATABASE`, function DDL, parameter grant or `ALTER
//!   SYSTEM` since the last two probes ([`LogOverrides::mark_stale`]).
//!
//! Role names stay in this module's memory to match the lines' users:
//! never sent; `Debug` prints counts only.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::check::logs_errors;
use crate::discover::normalize;

/// The setting whose override hides a `FATAL` line's statement (item 4).
pub(crate) const STATEMENT_KEY: &str = "log_min_error_statement";
/// The setting whose override hides `ERROR` lines.
pub(crate) const MESSAGES_KEY: &str = "log_min_messages";
/// Most names listed per category in the local detail.
const MAX_DETAIL_NAMES: usize = 10;
/// A proof older than this is not used by the stream (three of the
/// longest heartbeat intervals, as the collision probe).
pub(crate) const PROOF_MAX_AGE: Duration = Duration::from_secs(900);

/// One row of `sql::ROLE_LOG_OVERRIDES`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RoleRow {
    /// A database-wide entry (`setrole = 0`).
    pub(crate) every_role: bool,
    /// The role (`None` for a database-wide entry, or a name that is not
    /// UTF-8).
    pub(crate) role: Option<String>,
    pub(crate) setting: Option<String>,
    pub(crate) level: Option<String>,
}

/// One row of `sql::FUNCTION_LOG_OVERRIDES`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FunctionRow {
    pub(crate) schema: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) setting: Option<String>,
    pub(crate) level: Option<String>,
}

/// One row of `sql::PARAMETER_GRANTS`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GrantRow {
    pub(crate) public: bool,
    pub(crate) role: Option<String>,
    pub(crate) setting: Option<String>,
    pub(crate) privilege: Option<String>,
}

/// What one of the three statements gave.
pub(crate) enum Read<T> {
    Rows(Vec<T>),
    /// Refused or failed (not proven), with the SQLSTATE when known.
    Failed(Option<String>),
}

/// The proof of one database.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct DbProof {
    /// Local detail items (empty: proven).
    gaps: Vec<String>,
    /// Roles whose `FATAL` lines may carry no statement (item 4).
    hiding_roles: BTreeSet<String>,
    /// Every role's may.
    every_role: bool,
}

impl std::fmt::Debug for DbProof {
    // Role names never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbProof")
            .field("gaps", &self.gaps.len())
            .field("hiding_roles", &self.hiding_roles.len())
            .field("every_role", &self.every_role)
            .finish()
    }
}

/// The fixed name of a setting a row carries (`None`: not one of the two
/// keys, which the server's filter excludes: fail closed, never printed).
fn key_of(setting: Option<&str>) -> Option<&'static str> {
    match setting {
        Some(MESSAGES_KEY) => Some(MESSAGES_KEY),
        Some(STATEMENT_KEY) => Some(STATEMENT_KEY),
        _ => None,
    }
}

/// `names` normalized, at most [`MAX_DETAIL_NAMES`], then a count.
fn listed_names(names: &BTreeSet<String>) -> String {
    let mut out: Vec<String> = names
        .iter()
        .take(MAX_DETAIL_NAMES)
        .map(|n| normalize(n).as_str().to_owned())
        .collect();
    if names.len() > MAX_DETAIL_NAMES {
        out.push(format!("{} more", names.len() - MAX_DETAIL_NAMES));
    }
    out.join(", ")
}

impl DbProof {
    /// A database whose proof could not be made (`reason`, a fixed text).
    pub(crate) fn not_proven(reason: &str) -> Self {
        Self {
            gaps: vec![format!("not proven: {reason}")],
            hiding_roles: BTreeSet::new(),
            every_role: true,
        }
    }

    /// Whether the database is proven (the target may stay at Full).
    pub(crate) fn proven(&self) -> bool {
        self.gaps.is_empty()
    }

    /// The local detail of a database not proven (normalized names, no
    /// value).
    pub(crate) fn detail(&self, database: &str) -> Option<String> {
        (!self.proven()).then(|| {
            format!(
                "database {}: {}; failed or cancelled statements of these roles may leave no \
                 ERROR line or no statement text, so the target cannot reach Full (reset the \
                 overrides, revoke the grants, or grant SELECT on pg_db_role_setting to the \
                 agent's role)",
                normalize(database).as_str(),
                self.gaps.join("; ")
            )
        })
    }

    /// From the three statements' results (`grants`: `None` on PostgreSQL
    /// 14, where the catalog does not exist and only superusers can set the
    /// two settings). A cut result (more than `max` rows), a row whose
    /// setting is not one of the two keys, a failed or refused statement:
    /// not proven.
    pub(crate) fn evaluate(
        roles: Read<RoleRow>,
        functions: Read<FunctionRow>,
        grants: Option<Read<GrantRow>>,
        max: usize,
    ) -> Self {
        let mut p = Self::default();
        let unread = |p: &mut Self, what: &str, read: &Option<String>| {
            p.every_role = true;
            p.gaps.push(match read {
                Some(code) => format!("{what} not read (SQLSTATE {code}): not proven"),
                None => format!("{what} not read: not proven"),
            });
        };
        // Per setting: every role (database-wide), and the roles.
        let mut every: BTreeSet<&'static str> = BTreeSet::new();
        let mut by_role: HashMap<&'static str, BTreeSet<String>> = HashMap::new();
        match roles {
            Read::Failed(code) => unread(&mut p, "role and database settings", &code),
            Read::Rows(rows) => {
                if rows.len() > max {
                    unread(&mut p, "role and database settings (cut)", &None);
                }
                for r in rows.iter().take(max) {
                    let Some(key) = key_of(r.setting.as_deref()) else {
                        unread(&mut p, "role and database settings (unexpected row)", &None);
                        continue;
                    };
                    if logs_errors(r.level.as_deref()) {
                        continue;
                    }
                    match (&r.role, r.every_role) {
                        (_, true) => {
                            // Database-wide (the agent's session sees it
                            // too, ADR-0037 item 6).
                            every.insert(key);
                            if key == STATEMENT_KEY {
                                p.every_role = true;
                            }
                        }
                        (Some(role), false) => {
                            by_role.entry(key).or_default().insert(role.clone());
                            if key == STATEMENT_KEY {
                                p.hiding_roles.insert(role.clone());
                            }
                        }
                        (None, false) => {
                            // A role name that is not UTF-8: not matched
                            // by name, so every role.
                            by_role
                                .entry(key)
                                .or_default()
                                .insert("<name not UTF-8>".to_owned());
                            if key == STATEMENT_KEY {
                                p.every_role = true;
                            }
                        }
                    }
                }
            }
        }
        for key in [MESSAGES_KEY, STATEMENT_KEY] {
            if every.contains(key) {
                p.gaps.push(format!(
                    "{key} above error for every role (database setting)"
                ));
            }
            if let Some(roles) = by_role.get(key) {
                p.gaps.push(format!(
                    "{key} above error for role(s) {}",
                    listed_names(roles)
                ));
            }
        }
        match functions {
            Read::Failed(code) => unread(&mut p, "function SET clauses", &code),
            Read::Rows(rows) => {
                if rows.len() > max {
                    unread(&mut p, "function SET clauses (cut)", &None);
                }
                let mut found: HashMap<&'static str, BTreeSet<String>> = HashMap::new();
                for r in rows.iter().take(max) {
                    let Some(key) = key_of(r.setting.as_deref()) else {
                        unread(&mut p, "function SET clauses (unexpected row)", &None);
                        continue;
                    };
                    if logs_errors(r.level.as_deref()) {
                        continue;
                    }
                    // A caller's statement inside the function: any role.
                    if key == STATEMENT_KEY {
                        p.every_role = true;
                    }
                    let name = match (&r.schema, &r.name) {
                        (Some(s), Some(n)) => {
                            format!("{}.{}", normalize(s).as_str(), normalize(n).as_str())
                        }
                        _ => "<a name not UTF-8>".to_owned(),
                    };
                    found.entry(key).or_default().insert(name);
                }
                for key in [MESSAGES_KEY, STATEMENT_KEY] {
                    if let Some(f) = found.get(key) {
                        // Already normalized.
                        let mut names: Vec<&str> = f
                            .iter()
                            .take(MAX_DETAIL_NAMES)
                            .map(String::as_str)
                            .collect();
                        let more = f.len().saturating_sub(MAX_DETAIL_NAMES).to_string();
                        if f.len() > MAX_DETAIL_NAMES {
                            names.push(&more);
                        }
                        p.gaps.push(format!(
                            "{key} above error in the SET clause of function(s) {}",
                            names.join(", ")
                        ));
                    }
                }
            }
        }
        match grants {
            None => {}
            Some(Read::Failed(code)) => unread(&mut p, "parameter grants", &code),
            Some(Read::Rows(rows)) => {
                if rows.len() > max {
                    unread(&mut p, "parameter grants (cut)", &None);
                }
                let mut found: HashMap<(&'static str, &'static str), BTreeSet<String>> =
                    HashMap::new();
                let mut public: BTreeSet<(&'static str, &'static str)> = BTreeSet::new();
                for r in rows.iter().take(max) {
                    let Some(key) = key_of(r.setting.as_deref()) else {
                        unread(&mut p, "parameter grants (unexpected row)", &None);
                        continue;
                    };
                    let privilege = match r.privilege.as_deref() {
                        Some("SET") => "SET",
                        Some("ALTER SYSTEM") => "ALTER SYSTEM",
                        _ => "a privilege",
                    };
                    match (&r.role, r.public) {
                        (Some(role), false) => {
                            found
                                .entry((key, privilege))
                                .or_default()
                                .insert(role.clone());
                            if key == STATEMENT_KEY {
                                if privilege == "SET" {
                                    p.hiding_roles.insert(role.clone());
                                } else {
                                    // The server-wide value: every role.
                                    p.every_role = true;
                                }
                            }
                        }
                        _ => {
                            public.insert((key, privilege));
                            if key == STATEMENT_KEY {
                                p.every_role = true;
                            }
                        }
                    }
                }
                for key in [MESSAGES_KEY, STATEMENT_KEY] {
                    for privilege in ["SET", "ALTER SYSTEM", "a privilege"] {
                        if public.contains(&(key, privilege)) {
                            p.gaps
                                .push(format!("{privilege} on {key} granted to every role"));
                        }
                        if let Some(roles) = found.get(&(key, privilege)) {
                            p.gaps.push(format!(
                                "{privilege} on {key} granted to role(s) {}",
                                listed_names(roles)
                            ));
                        }
                    }
                }
            }
        }
        p
    }
}

/// The last probe of a database.
#[derive(Debug, Clone)]
pub(crate) enum Probe {
    /// The database's level is below Full: the statements are not sent,
    /// and item 9 keeps the session's own proof (ADR-0037 item 6).
    NotApplicable,
    /// Read (proven or not).
    Done(DbProof),
}

#[derive(Debug, Default)]
struct DbEntry {
    probe: Option<(Instant, Probe)>,
    stale_since: Option<Instant>,
    fresh_after_mark: u8,
}

/// Most databases remembered per target.
const MAX_DATABASES: usize = 1024;

/// The proofs of one target's databases, shared by `check()` and the
/// Audit stream's probe (which store them) and the stream's event builder
/// (which reads them and marks them stale).
#[derive(Debug, Default)]
pub(crate) struct LogOverrides {
    dbs: HashMap<String, DbEntry>,
}

/// [`LogOverrides`] shared by `check()` and the streams of one target.
pub(crate) type SharedLogOverrides = Arc<Mutex<LogOverrides>>;

impl LogOverrides {
    /// Stores the probe of `database` that started at `started`; a probe
    /// that started after the last stale mark counts toward clearing it
    /// (two such probes clear it: one may race the statement's commit).
    pub(crate) fn store(&mut self, database: &str, started: Instant, probe: Probe) {
        if !self.dbs.contains_key(database) && self.dbs.len() >= MAX_DATABASES {
            return;
        }
        let e = self.dbs.entry(database.to_owned()).or_default();
        if e.probe.as_ref().is_some_and(|(at, _)| *at > started) {
            return;
        }
        e.probe = Some((started, probe));
        if e.stale_since.is_some_and(|s| started > s) {
            e.fresh_after_mark = e.fresh_after_mark.saturating_add(1);
            if e.fresh_after_mark >= 2 {
                e.stale_since = None;
                e.fresh_after_mark = 0;
            }
        }
    }

    /// The stream saw, at `now`, a statement that can change the overrides
    /// of `database` (`None`: of every database: `ALTER ROLE`, `ALTER
    /// DATABASE`, a parameter grant, `ALTER SYSTEM`).
    pub(crate) fn mark_stale(&mut self, database: Option<&str>, now: Instant) {
        let mark = |e: &mut DbEntry| {
            e.stale_since = Some(e.stale_since.map_or(now, |s| s.max(now)));
            e.fresh_after_mark = 0;
        };
        match database {
            Some(db) => {
                if !self.dbs.contains_key(db) && self.dbs.len() >= MAX_DATABASES {
                    return;
                }
                mark(self.dbs.entry(db.to_owned()).or_default());
            }
            None => self.dbs.values_mut().for_each(mark),
        }
    }

    /// ADR-0037 item 9 as refined by item 4: whether a `FATAL` line without
    /// a statement from `user` in `database` (whose session proof holds)
    /// ends an idle session. Not when the database was not probed yet, its
    /// probe is stale or older than [`PROOF_MAX_AGE`], or the proof does not
    /// hold for that role.
    pub(crate) fn fatal_quiet(&self, database: &str, user: &str, now: Instant) -> bool {
        let Some(e) = self.dbs.get(database) else {
            return false;
        };
        let Some((started, probe)) = &e.probe else {
            return false;
        };
        if e.stale_since.is_some() || now.saturating_duration_since(*started) > PROOF_MAX_AGE {
            return false;
        }
        match probe {
            Probe::NotApplicable => true,
            Probe::Done(p) => !p.every_role && !p.hiding_roles.contains(user),
        }
    }
}

/// Locks a [`SharedLogOverrides`] (a poisoned lock is still used: plain
/// data).
pub(crate) fn lock(shared: &SharedLogOverrides) -> std::sync::MutexGuard<'_, LogOverrides> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The target's [`SharedLogOverrides`] as held by the stream's catalog
/// facts (`events::Catalogs`). Without one (`None`), no database is proven
/// for item 9 (fail closed); unit tests that build their catalog facts by
/// hand get a proof that found nothing, so that they test the rest of the
/// rules.
#[derive(Clone, Default)]
pub(crate) struct LogOverridesHandle(Option<SharedLogOverrides>);

impl std::fmt::Debug for LogOverridesHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogOverridesHandle")
    }
}

impl PartialEq for LogOverridesHandle {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for LogOverridesHandle {}

impl LogOverridesHandle {
    pub(crate) fn new(shared: SharedLogOverrides) -> Self {
        Self(Some(shared))
    }

    /// [`LogOverrides::fatal_quiet`] now.
    pub(crate) fn fatal_quiet(&self, database: &str, user: &str) -> bool {
        match &self.0 {
            Some(shared) => lock(shared).fatal_quiet(database, user, Instant::now()),
            #[cfg(test)]
            None => true,
            #[cfg(not(test))]
            None => false,
        }
    }

    /// [`LogOverrides::mark_stale`] now.
    pub(crate) fn mark_stale(&self, database: Option<&str>) {
        if let Some(shared) = &self.0 {
            lock(shared).mark_stale(database, Instant::now());
        }
    }
}

/// Whether a pgaudit record's command (and text) can change the overrides
/// the proof reads (item 4): `Some(None)` for every database (`ALTER
/// ROLE`, `ALTER USER`, `ALTER GROUP` share the `ALTER ROLE` tag; `ALTER
/// DATABASE`; a `GRANT` or `REVOKE` on a parameter; `ALTER SYSTEM`),
/// `Some(Some(()))` for the record's own database (`CREATE` or `ALTER` of
/// a function, procedure or routine: a `SET` clause), `None` otherwise.
pub(crate) fn changes_overrides(command: &str, text: &str) -> Option<Option<()>> {
    let c = command.trim().to_ascii_uppercase();
    match c.as_str() {
        "ALTER ROLE" | "ALTER DATABASE" | "ALTER SYSTEM" => Some(None),
        "GRANT" | "REVOKE" if text.to_ascii_lowercase().contains("parameter") => Some(None),
        "CREATE FUNCTION" | "ALTER FUNCTION" | "CREATE PROCEDURE" | "ALTER PROCEDURE"
        | "ALTER ROUTINE" => Some(Some(())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(every: bool, r: Option<&str>, setting: &str, level: &str) -> RoleRow {
        RoleRow {
            every_role: every,
            role: r.map(str::to_owned),
            setting: Some(setting.to_owned()),
            level: Some(level.to_owned()),
        }
    }

    fn func(name: &str, setting: &str, level: &str) -> FunctionRow {
        FunctionRow {
            schema: Some("app".to_owned()),
            name: Some(name.to_owned()),
            setting: Some(setting.to_owned()),
            level: Some(level.to_owned()),
        }
    }

    fn grant(r: Option<&str>, setting: &str, privilege: &str) -> GrantRow {
        GrantRow {
            public: r.is_none(),
            role: r.map(str::to_owned),
            setting: Some(setting.to_owned()),
            privilege: Some(privilege.to_owned()),
        }
    }

    fn eval(
        roles: Vec<RoleRow>,
        functions: Vec<FunctionRow>,
        grants: Option<Vec<GrantRow>>,
    ) -> DbProof {
        DbProof::evaluate(
            Read::Rows(roles),
            Read::Rows(functions),
            grants.map(Read::Rows),
            1000,
        )
    }

    #[test]
    fn levels_up_to_error_are_proven() {
        for level in [
            "debug5", "debug4", "debug3", "debug2", "debug1", "debug", "info", "notice", "warning",
            "error", "ERROR",
        ] {
            let p = eval(
                vec![
                    role(false, Some("app"), MESSAGES_KEY, level),
                    role(true, None, STATEMENT_KEY, level),
                ],
                vec![func("f", STATEMENT_KEY, level)],
                Some(vec![]),
            );
            assert!(p.proven(), "{level}");
            assert!(p.detail("shop").is_none());
        }
        for level in ["log", "fatal", "panic", "", "unknown", "error2"] {
            let p = eval(
                vec![role(false, Some("app"), MESSAGES_KEY, level)],
                vec![],
                None,
            );
            assert!(!p.proven(), "{level}");
        }
    }

    #[test]
    fn overrides_cap_and_are_detailed_without_values() {
        let p = eval(
            vec![
                role(false, Some("other"), MESSAGES_KEY, "fatal"),
                role(false, Some("app"), STATEMENT_KEY, "panic"),
                role(true, None, MESSAGES_KEY, "log"),
            ],
            vec![func("hide", MESSAGES_KEY, "fatal")],
            None,
        );
        assert!(!p.proven());
        let d = p.detail("shop").unwrap();
        assert!(d.contains("database shop"), "{d}");
        assert!(
            d.contains("log_min_messages above error for every role"),
            "{d}"
        );
        assert!(
            d.contains("log_min_messages above error for role(s) other"),
            "{d}"
        );
        assert!(
            d.contains("log_min_error_statement above error for role(s) app"),
            "{d}"
        );
        assert!(d.contains("SET clause of function(s) app.hide"), "{d}");
        for value in ["fatal", "panic", " log "] {
            assert!(!d.contains(value), "{value} in {d}");
        }
        // Item 4: only `app` hides its statements (a database-wide
        // `log_min_messages` writes no FATAL line at all).
        assert_eq!(p.hiding_roles.iter().collect::<Vec<_>>(), ["app"]);
        assert!(!p.every_role);
        assert!(!format!("{p:?}").contains("app"));
    }

    #[test]
    fn grants_cap_and_name_the_grantees() {
        let p = eval(
            vec![],
            vec![],
            Some(vec![
                grant(Some("other"), MESSAGES_KEY, "SET"),
                grant(Some("app"), STATEMENT_KEY, "SET"),
                grant(Some("ops"), STATEMENT_KEY, "ALTER SYSTEM"),
            ]),
        );
        let d = p.detail("shop").unwrap();
        assert!(
            d.contains("SET on log_min_messages granted to role(s) other"),
            "{d}"
        );
        assert!(
            d.contains("ALTER SYSTEM on log_min_error_statement granted to role(s) ops"),
            "{d}"
        );
        assert!(p.hiding_roles.contains("app"));
        assert!(p.every_role, "ALTER SYSTEM changes every role's value");
        let p = eval(
            vec![],
            vec![],
            Some(vec![grant(None, STATEMENT_KEY, "SET")]),
        );
        assert!(p.every_role);
        assert!(
            p.detail("shop")
                .unwrap()
                .contains("SET on log_min_error_statement granted to every role")
        );
    }

    #[test]
    fn unread_cut_or_unexpected_rows_are_not_proven() {
        let p = DbProof::evaluate(
            Read::Failed(Some("42501".to_owned())),
            Read::Rows(vec![]),
            None,
            1000,
        );
        assert!(!p.proven());
        assert!(p.every_role);
        assert!(p.detail("shop").unwrap().contains("SQLSTATE 42501"));
        let rows: Vec<RoleRow> = (0..1001)
            .map(|_| role(false, Some("a"), MESSAGES_KEY, "error"))
            .collect();
        let p = DbProof::evaluate(Read::Rows(rows), Read::Rows(vec![]), None, 1000);
        assert!(!p.proven());
        assert!(p.every_role);
        let p = eval(
            vec![role(false, Some("a"), "app.secret", "x")],
            vec![],
            None,
        );
        assert!(!p.proven());
        assert!(!p.detail("shop").unwrap().contains("app.secret"));
        let p = DbProof::evaluate(
            Read::Rows(vec![]),
            Read::Rows(vec![]),
            Some(Read::Failed(None)),
            1000,
        );
        assert!(!p.proven());
        // A role name that is not UTF-8: every role.
        let p = eval(
            vec![role(false, None, STATEMENT_KEY, "panic")],
            vec![],
            None,
        );
        assert!(p.every_role);
    }

    #[test]
    fn many_names_are_counted() {
        let rows: Vec<RoleRow> = (0..13)
            .map(|i| role(false, Some(&format!("r{i:02}")), MESSAGES_KEY, "fatal"))
            .collect();
        let d = eval(rows, vec![], None).detail("shop").unwrap();
        assert!(d.contains("r09, 3 more"), "{d}");
        assert!(!d.contains("r10"), "{d}");
    }

    #[test]
    fn item_4_per_role_and_stale_marks() {
        let mut s = LogOverrides::default();
        let t0 = Instant::now();
        // Not probed: not quiet.
        assert!(!s.fatal_quiet("shop", "app", t0));
        let p = eval(
            vec![role(false, Some("hider"), STATEMENT_KEY, "panic")],
            vec![],
            None,
        );
        s.store("shop", t0, Probe::Done(p));
        assert!(s.fatal_quiet("shop", "app", t0));
        assert!(!s.fatal_quiet("shop", "hider", t0));
        // Too old.
        assert!(!s.fatal_quiet("shop", "app", t0 + PROOF_MAX_AGE + Duration::from_secs(1)));
        // Below Full: the session proof decides.
        s.store("other", t0, Probe::NotApplicable);
        assert!(s.fatal_quiet("other", "hider", t0));
        // An `ALTER ROLE` record: every database stale until two probes
        // that started after it.
        let mark = t0 + Duration::from_secs(1);
        s.mark_stale(None, mark);
        assert!(!s.fatal_quiet("shop", "app", mark));
        assert!(!s.fatal_quiet("other", "app", mark));
        s.store(
            "shop",
            mark + Duration::from_secs(1),
            Probe::Done(DbProof::default()),
        );
        assert!(!s.fatal_quiet("shop", "app", mark));
        s.store(
            "shop",
            mark + Duration::from_secs(2),
            Probe::Done(DbProof::default()),
        );
        assert!(s.fatal_quiet("shop", "app", mark + Duration::from_secs(2)));
        assert!(s.fatal_quiet("shop", "hider", mark + Duration::from_secs(2)));
        // A probe that started before the mark does not clear it.
        s.mark_stale(Some("shop"), mark + Duration::from_secs(10));
        s.store(
            "shop",
            mark + Duration::from_secs(5),
            Probe::Done(DbProof::default()),
        );
        assert!(!s.fatal_quiet("shop", "app", mark + Duration::from_secs(10)));
        // A failed read: every role.
        let mut s = LogOverrides::default();
        s.store(
            "shop",
            t0,
            Probe::Done(DbProof::not_proven("a pg_stat_statements stream runs")),
        );
        assert!(!s.fatal_quiet("shop", "app", t0));
    }

    /// The keys the statements filter on are the two this module knows.
    #[test]
    fn the_statements_filter_the_two_keys() {
        for s in [
            crate::sql::ROLE_LOG_OVERRIDES,
            crate::sql::FUNCTION_LOG_OVERRIDES,
            crate::sql::PARAMETER_GRANTS,
        ] {
            assert!(
                s.contains(&format!(
                    "'{{{MESSAGES_KEY},{STATEMENT_KEY}}}'::pg_catalog.text[]"
                )),
                "{s}"
            );
            assert!(s.ends_with(&format!("LIMIT {}", crate::sql::LOG_OVERRIDES_MAX_ROWS + 1)));
        }
    }

    #[test]
    fn statements_that_change_the_overrides() {
        assert_eq!(
            changes_overrides("ALTER ROLE", "ALTER USER a SET x = 1"),
            Some(None)
        );
        assert_eq!(changes_overrides("ALTER DATABASE", ""), Some(None));
        assert_eq!(changes_overrides("ALTER SYSTEM", ""), Some(None));
        assert_eq!(
            changes_overrides("GRANT", "GRANT SET ON PARAMETER log_min_messages TO a"),
            Some(None)
        );
        assert_eq!(changes_overrides("GRANT", "GRANT SELECT ON t TO a"), None);
        assert_eq!(changes_overrides("CREATE FUNCTION", ""), Some(Some(())));
        assert_eq!(changes_overrides("ALTER PROCEDURE", ""), Some(Some(())));
        assert_eq!(changes_overrides("CREATE TABLE", ""), None);
        assert_eq!(changes_overrides("SELECT", ""), None);
    }
}
