//! ADR-0049 decision 8: user code next to catalogs only. In a statement
//! whose relations are all catalogs, a call of a function, an operator or
//! a cast that is not built in for that database adds `*` to the read,
//! always reported and never the agent's own.
//!
//! "Built in" is decided against the lists of the server's major version
//! ([`super::builtins`]) and the per-database collision probe
//! (`sql::USER_CODE_PROBE`, run by `check()` at every heartbeat):
//!
//! - **functions and operators**: the names of user overloads (outside
//!   `pg_catalog` and `information_schema`) of built-in names that a value
//!   or literal of a catalog-only statement can reach (CVE-2018-1058 and
//!   its variants: built-in, polymorphic or pseudo argument types, domains
//!   over them, composite types (`ROW(…)`), implicit-cast targets, and
//!   types an untyped literal can resolve to). Such a name is not built in
//!   in that database when unqualified;
//! - **types**: user type and domain names that collide with a built-in
//!   type name (relation row types and their arrays excluded);
//! - **casts**: a user-function cast between two built-in types. Explicit:
//!   its target type name is not built in. Implicit or assignment: every
//!   catalog-only statement of that database is `*` (they run with no cast
//!   and no unqualified name in the text);
//! - **bound parameters** (refinement, proposed): a client types a `$n`
//!   itself, so with a parameter in the text the names of user overloads
//!   whose code is not C or internal are not built in whatever their
//!   argument types.
//!
//! A probe that failed, was cut (more than [`PROBE_MAX_NAMES`] rows), is
//! older than [`PROBE_MAX_AGE`], is stale (a routine, type, cast or
//! extension DDL of that database seen by the stream after it started) or
//! has not run yet: every unqualified call, operator and cast of a
//! catalog-only statement is `*` (fail closed).
//!
//! The probe's names stay in this module's memory: never logged, never
//! sent (I2); `Debug` prints counts only.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use databastion_classifiers::query::{PgCode, RelationName};

use super::builtins::{self, Builtins, KeywordCategory};

/// Most rows of the probe; one more is read to tell a cut.
pub(crate) const PROBE_MAX_NAMES: usize = 20_000;

/// A probe older than this is not used (heartbeats are at most 300 s
/// apart: three missed heartbeats).
pub(crate) const PROBE_MAX_AGE: Duration = Duration::from_secs(900);

/// What the collision probe found in one database.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ProbeNames {
    /// Function names with a reachable user overload.
    pub(crate) functions: HashSet<String>,
    /// Operator symbols with a reachable user overload.
    pub(crate) operators: HashSet<String>,
    /// User type and domain names that collide with a built-in type name.
    pub(crate) types: HashSet<String>,
    /// Built-in type names targeted by an explicit user-function cast
    /// between two built-in types.
    pub(crate) explicit_cast_targets: HashSet<String>,
    /// An implicit or assignment user-function cast between two built-in
    /// types exists.
    pub(crate) implicit_cast: bool,
    /// Function names with a user overload whose code is neither C nor
    /// internal (any argument types: a bound parameter reaches them).
    pub(crate) param_functions: HashSet<String>,
    /// Operator symbols with such a user overload.
    pub(crate) param_operators: HashSet<String>,
}

impl std::fmt::Debug for ProbeNames {
    // Names never printed (I2).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeNames")
            .field("functions", &self.functions.len())
            .field("operators", &self.operators.len())
            .field("types", &self.types.len())
            .field("explicit_cast_targets", &self.explicit_cast_targets.len())
            .field("implicit_cast", &self.implicit_cast)
            .field("param_functions", &self.param_functions.len())
            .field("param_operators", &self.param_operators.len())
            .finish()
    }
}

impl ProbeNames {
    /// From the probe's rows (kind, name), at most [`PROBE_MAX_NAMES`]:
    /// `None` when there are more (cut) or a kind is unknown.
    pub(crate) fn from_rows<I>(rows: I) -> Option<Self>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut out = Self::default();
        for (n, (kind, name)) in rows.into_iter().enumerate() {
            if n >= PROBE_MAX_NAMES {
                return None;
            }
            match kind.as_str() {
                "f" => {
                    out.functions.insert(name);
                }
                "o" => {
                    out.operators.insert(name);
                }
                "t" => {
                    out.types.insert(name);
                }
                "e" => {
                    out.explicit_cast_targets.insert(name);
                }
                "i" => out.implicit_cast = true,
                "F" => {
                    out.param_functions.insert(name);
                }
                "O" => {
                    out.param_operators.insert(name);
                }
                _ => return None,
            }
        }
        Some(out)
    }
}

/// The last probe of a database.
#[derive(Debug)]
enum Outcome {
    Done(Box<ProbeNames>),
    /// Failed or cut.
    Failed,
}

#[derive(Debug, Default)]
struct DbEntry {
    /// When the last probe started, the server version it saw, and its
    /// outcome.
    probe: Option<(Instant, u32, Outcome)>,
    /// When the stream last saw a routine, type, cast or extension DDL in
    /// this database.
    stale_since: Option<Instant>,
}

/// Most databases remembered per target (a pgaudit log names every
/// database of the server; only the declared ones are probed).
const MAX_DATABASES: usize = 1024;

/// The probes of one target's databases, shared by `check()` (which
/// stores them) and the Audit streams (which decide and mark them stale).
#[derive(Debug, Default)]
pub(crate) struct UserCode {
    dbs: HashMap<String, DbEntry>,
}

/// [`UserCode`] shared by `check()` and the streams of one target.
pub(crate) type SharedUserCode = Arc<Mutex<UserCode>>;

/// How the code of a catalog-only statement is judged in one database.
#[derive(Debug)]
pub(crate) enum View<'a> {
    /// No usable probe: every unqualified call, operator and cast is `*`
    /// (decided on the lists of the last version seen, if any).
    Unknown(Option<&'static Builtins>),
    /// An implicit or assignment user-function cast between built-in
    /// types: every catalog-only statement is `*`.
    Everything,
    /// A usable probe, and the lists of the server's version (`None`:
    /// older than the oldest list, nothing unqualified is built in).
    Known(&'a ProbeNames, Option<&'static Builtins>),
}

impl UserCode {
    /// Stores the probe of `database` that started at `started` on a
    /// server of `server_version_num` (`None`: failed or cut). A probe
    /// that started after the last stale mark clears it.
    pub(crate) fn store(
        &mut self,
        database: &str,
        started: Instant,
        server_version_num: u32,
        names: Option<ProbeNames>,
    ) {
        if !self.dbs.contains_key(database) && self.dbs.len() >= MAX_DATABASES {
            return;
        }
        let e = self.dbs.entry(database.to_owned()).or_default();
        if e.probe.as_ref().is_some_and(|(at, ..)| *at > started) {
            // An older probe finishing late.
            return;
        }
        let outcome = names.map_or(Outcome::Failed, |n| Outcome::Done(Box::new(n)));
        e.probe = Some((started, server_version_num, outcome));
        if e.stale_since.is_some_and(|s| started > s) {
            e.stale_since = None;
        }
    }

    /// The stream saw, at `now`, a routine, type, cast or extension DDL in
    /// `database` (already executed): its probe is stale until one starts
    /// after `now`.
    pub(crate) fn mark_stale(&mut self, database: &str, now: Instant) {
        if !self.dbs.contains_key(database) && self.dbs.len() >= MAX_DATABASES {
            return;
        }
        let e = self.dbs.entry(database.to_owned()).or_default();
        e.stale_since = Some(e.stale_since.map_or(now, |s| s.max(now)));
    }

    /// The view of `database` at `now`.
    pub(crate) fn view(&self, database: &str, now: Instant) -> View<'_> {
        let Some(e) = self.dbs.get(database) else {
            return View::Unknown(None);
        };
        let Some((started, version, outcome)) = &e.probe else {
            return View::Unknown(None);
        };
        let lists = builtins::for_server(*version);
        let stale = e.stale_since.is_some_and(|s| s >= *started);
        let old = now.saturating_duration_since(*started) > PROBE_MAX_AGE;
        match outcome {
            Outcome::Done(names) if !stale && !old => {
                if names.implicit_cast {
                    View::Everything
                } else {
                    View::Known(names, lists)
                }
            }
            Outcome::Done(names) if names.implicit_cast => View::Everything,
            _ => View::Unknown(lists),
        }
    }
}

/// The analysis of a text for decision 8, kept with its analysis (the
/// verdict depends on the probe at event time).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum CodeUse {
    /// The statement names a relation that is not a catalog, names none,
    /// or is not a query: decision 8 does not apply.
    #[default]
    NotApplicable,
    /// Every relation it names is a catalog (or a core-list entry read in
    /// the no-text shape).
    CatalogOnly {
        /// The code the text uses; `None`: the text could not be scanned.
        code: Option<Arc<PgCode>>,
        /// The text may be cut: code may follow the cut.
        cut: bool,
    },
}

/// Whether a catalog-only statement reads past its relations through user
/// code: `*`. `excluded`: the functions of decisions 1 and 7, decided by
/// those decisions (ADR-0049 re-review N4).
pub(crate) fn user_code(
    code: Option<&PgCode>,
    cut: bool,
    view: &View<'_>,
    excluded: &dyn Fn(&RelationName) -> bool,
) -> bool {
    if cut {
        return true;
    }
    let Some(code) = code else {
        return true;
    };
    if code.overflow {
        return true;
    }
    match view {
        View::Everything => true,
        View::Unknown(lists) => unknown(code, *lists, excluded),
        View::Known(names, lists) => known(code, names, *lists, excluded),
    }
}

/// `name(`: a call, or a grammar form of the keyword lists (`COALESCE (`,
/// `VALUES (`, `numeric (`, `x LIKE (…)`).
fn grammar_form(c: &databastion_classifiers::query::PgCodeName, lists: &Builtins) -> bool {
    if c.quoted || c.name.schema.is_some() {
        return false;
    }
    let n = c.name.name.as_str();
    match lists.keyword(n) {
        // Column-name and reserved keywords are never a bare function
        // name: the grammar's own forms, unless the form calls the
        // function of that name (`SUBSTRING (`, `OVERLAY (`, `POSITION (`
        // … are on the function list and decided as calls). `XMLTABLE` and
        // `JSON_TABLE` declare column types the scan does not read.
        Some(KeywordCategory::ColumnName | KeywordCategory::Reserved) => {
            !lists.function(n) && !matches!(n, "xmltable" | "json_table")
        }
        // `x LIKE (…)`, `a JOIN (…)`: infix syntax.
        Some(KeywordCategory::TypeFunctionName) => c.after_operand,
        _ => false,
    }
}

/// An unqualified type spelling the grammar maps to `pg_catalog`
/// (`integer`, `double precision`): its targets.
fn keyword_type(
    t: &databastion_classifiers::query::PgCodeName,
    lists: Option<&Builtins>,
) -> Option<&'static [&'static str]> {
    if t.quoted || t.name.schema.is_some() {
        return None;
    }
    lists?.keyword_type(&t.name.name)
}

/// [`View::Unknown`]: every unqualified call, operator and cast is `*`;
/// qualified `pg_catalog` (and `information_schema`) names on the lists
/// are kept (on every major version's lists when the version is not
/// known).
fn unknown(
    code: &PgCode,
    lists: Option<&Builtins>,
    excluded: &dyn Fn(&RelationName) -> bool,
) -> bool {
    let on_lists = |f: &dyn Fn(&Builtins) -> bool| match lists {
        Some(l) => f(l),
        None => builtins::all_majors(f),
    };
    for c in &code.calls {
        if excluded(&c.name) || on_lists(&|l| grammar_form(c, l)) {
            continue;
        }
        let n = c.name.name.as_str();
        let built_in = match c.name.schema.as_deref() {
            Some("pg_catalog") => on_lists(&|l| l.function(n)),
            Some("information_schema") => on_lists(&|l| l.information_schema_function(n)),
            _ => false,
        };
        if !built_in {
            return true;
        }
    }
    for o in &code.operators {
        let built_in =
            o.schema.as_deref() == Some("pg_catalog") && on_lists(&|l| l.operator(&o.symbol));
        if !built_in {
            return true;
        }
    }
    for t in &code.types {
        let n = t.name.name.as_str();
        let built_in = match t.name.schema.as_deref() {
            Some("pg_catalog") => on_lists(&|l| l.type_name(n)),
            Some("information_schema") => on_lists(&|l| l.information_schema_type(n)),
            _ => false,
        };
        if !built_in {
            return true;
        }
    }
    false
}

/// [`View::Known`].
fn known(
    code: &PgCode,
    names: &ProbeNames,
    lists: Option<&Builtins>,
    excluded: &dyn Fn(&RelationName) -> bool,
) -> bool {
    let Some(lists) = lists else {
        // No list for this version: only qualified names of decisions 1
        // and 7 pass.
        return !code.operators.is_empty()
            || !code.types.is_empty()
            || code.calls.iter().any(|c| !excluded(&c.name));
    };
    for c in &code.calls {
        if excluded(&c.name) || grammar_form(c, lists) {
            continue;
        }
        let n = c.name.name.as_str();
        let built_in = match c.name.schema.as_deref() {
            Some("pg_catalog") => lists.function(n),
            Some("information_schema") => lists.information_schema_function(n),
            Some(_) => false,
            None => {
                lists.function(n)
                    && !names.functions.contains(n)
                    && !(code.params && names.param_functions.contains(n))
            }
        };
        if !built_in {
            return true;
        }
    }
    for o in &code.operators {
        let s = o.symbol.as_str();
        let built_in = match o.schema.as_deref() {
            Some("pg_catalog") => lists.operator(s),
            Some(_) => false,
            None => {
                lists.operator(s)
                    && !names.operators.contains(s)
                    && !(code.params && names.param_operators.contains(s))
            }
        };
        if !built_in {
            return true;
        }
    }
    for t in &code.types {
        let n = t.name.name.as_str();
        if let Some(targets) = keyword_type(t, Some(lists)) {
            if targets
                .iter()
                .any(|x| names.explicit_cast_targets.contains(*x))
            {
                return true;
            }
            continue;
        }
        let built_in = match t.name.schema.as_deref() {
            Some("pg_catalog") => lists.type_name(n) && !names.explicit_cast_targets.contains(n),
            Some("information_schema") => lists.information_schema_type(n),
            Some(_) => false,
            None => {
                lists.type_name(n)
                    && !names.types.contains(n)
                    && !names.explicit_cast_targets.contains(n)
            }
        };
        if !built_in {
            return true;
        }
    }
    false
}

/// A pgaudit command tag of a statement that makes the probe stale
/// (`CREATE FUNCTION`, `ALTER EXTENSION`, `DROP OWNED`…).
pub(crate) fn routine_ddl_command(command: &str) -> bool {
    let mut w = command.split_ascii_whitespace();
    let (Some(verb), Some(object)) = (w.next(), w.next()) else {
        return false;
    };
    let verb = verb.to_ascii_uppercase();
    let object = object.to_ascii_uppercase();
    matches!(verb.as_str(), "CREATE" | "ALTER" | "DROP")
        && (matches!(
            object.as_str(),
            "FUNCTION"
                | "PROCEDURE"
                | "ROUTINE"
                | "AGGREGATE"
                | "OPERATOR"
                | "TYPE"
                | "DOMAIN"
                | "CAST"
                | "EXTENSION"
        ) || (verb == "DROP" && matches!(object.as_str(), "OWNED" | "SCHEMA")))
}

/// The target's [`SharedUserCode`] as held by the stream's catalog facts
/// (`events::Catalogs`). Without one (`None`), every database is
/// [`View::Unknown`] (fail closed); unit tests that build their catalog
/// facts by hand get a probe that found nothing on PostgreSQL 16, so that
/// they test the rest of the rules.
#[derive(Clone, Default)]
pub(crate) struct UserCodeHandle(Option<SharedUserCode>);

impl std::fmt::Debug for UserCodeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserCodeHandle")
    }
}

impl PartialEq for UserCodeHandle {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for UserCodeHandle {}

impl UserCodeHandle {
    pub(crate) fn new(shared: SharedUserCode) -> Self {
        Self(Some(shared))
    }

    /// [`user_code`] in `database` now.
    pub(crate) fn decide(
        &self,
        database: &str,
        code: Option<&PgCode>,
        cut: bool,
        excluded: &dyn Fn(&RelationName) -> bool,
    ) -> bool {
        match &self.0 {
            Some(shared) => {
                let guard = lock(shared);
                let view = guard.view(database, Instant::now());
                user_code(code, cut, &view, excluded)
            }
            #[cfg(test)]
            None => {
                let names = ProbeNames::default();
                let view = View::Known(&names, builtins::for_server(160_000));
                user_code(code, cut, &view, excluded)
            }
            #[cfg(not(test))]
            None => user_code(code, cut, &View::Unknown(None), excluded),
        }
    }

    /// The stream saw a routine, type, cast or extension DDL in
    /// `database`.
    pub(crate) fn mark_stale(&self, database: &str) {
        if let Some(shared) = &self.0 {
            lock(shared).mark_stale(database, Instant::now());
        }
    }
}

/// Locks a [`SharedUserCode`] (a poisoned lock is still used: the state
/// is plain data).
pub(crate) fn lock(shared: &SharedUserCode) -> std::sync::MutexGuard<'_, UserCode> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_classifiers::query::pg_scan;

    fn names(rows: &[(&str, &str)]) -> ProbeNames {
        ProbeNames::from_rows(rows.iter().map(|(k, n)| ((*k).to_owned(), (*n).to_owned()))).unwrap()
    }

    fn none(_: &RelationName) -> bool {
        false
    }

    /// The verdict on `text` with a probe of `rows` on PostgreSQL 16.
    fn star(text: &str, rows: &[(&str, &str)]) -> bool {
        let mut u = UserCode::default();
        u.store("shop", Instant::now(), 160_013, Some(names(rows)));
        let code = pg_scan(text).unwrap().code();
        user_code(Some(&code), false, &u.view("shop", Instant::now()), &none)
    }

    #[test]
    fn built_ins_pass_and_user_code_does_not() {
        for q in [
            "SELECT relname FROM pg_class",
            "SELECT length(relname), lower(relname) FROM pg_class WHERE relkind = 'r'",
            "SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class",
            "SELECT coalesce(relname, 'x'), CAST(relpages AS bigint) FROM pg_class \
             WHERE relname IN ('a') AND relname LIKE 'p%'",
            "SELECT substring(relname from 1 for 2), relname::text, date '2020-01-01', \
             x::double precision, information_schema._pg_expandarray(i.indkey) \
             FROM pg_index i, pg_class",
            "SELECT 1 FROM pg_class c LEFT JOIN (pg_namespace n CROSS JOIN pg_am a) ON true",
            "SELECT a OPERATOR(pg_catalog.~) 'x' FROM pg_class",
        ] {
            assert!(!star(q, &[]), "{q}");
        }
        for q in [
            "SELECT my_f() FROM pg_class LIMIT 1",
            "SELECT crm.f() FROM pg_class LIMIT 1",
            "SELECT pg_catalog.my_ext_function() FROM pg_class",
            "SELECT \"coalesce\"(relname) FROM pg_class",
            "SELECT 1 FROM pg_class WHERE relname OPERATOR(public.+++) 'x'",
            "SELECT 1 FROM pg_class WHERE relname #+# 'x'",
            "SELECT relpages::public.dpos FROM pg_class",
            "SELECT relpages::dpos FROM pg_class",
            "SELECT mytype 'x' FROM pg_class",
            "SELECT 1 FROM xmltable('/a' PASSING x COLUMNS a public.t PATH 'a'), pg_class",
        ] {
            assert!(star(q, &[]), "{q}");
        }
    }

    #[test]
    fn collisions_are_per_database() {
        let colliding = [("f", "length")];
        assert!(star("SELECT length(42) FROM pg_class LIMIT 1", &colliding));
        assert!(!star(
            "SELECT pg_catalog.length('x') FROM pg_class LIMIT 1",
            &colliding
        ));
        assert!(!star("SELECT length(42) FROM pg_class LIMIT 1", &[]));
        // Another database of the same target: no collision there.
        let mut u = UserCode::default();
        let now = Instant::now();
        u.store("a", now, 160_013, Some(names(&colliding)));
        u.store("b", now, 160_013, Some(names(&[])));
        let code = pg_scan("SELECT length(42) FROM pg_class").unwrap().code();
        assert!(user_code(Some(&code), false, &u.view("a", now), &none));
        assert!(!user_code(Some(&code), false, &u.view("b", now), &none));
        // Operators, types, explicit casts.
        assert!(star("SELECT 1 + 1 FROM pg_class", &[("o", "+")]));
        assert!(star("SELECT 1 FROM pg_class WHERE 1 IN (1)", &[("o", "=")]));
        assert!(!star(
            "SELECT 1 OPERATOR(pg_catalog.+) 1 FROM pg_class",
            &[("o", "+")]
        ));
        assert!(star("SELECT 'x'::text FROM pg_class", &[("t", "text")]));
        assert!(!star(
            "SELECT 'x'::pg_catalog.text FROM pg_class",
            &[("t", "text")]
        ));
        assert!(star("SELECT 42::text FROM pg_class", &[("e", "text")]));
        assert!(star(
            "SELECT 42::pg_catalog.text FROM pg_class",
            &[("e", "text")]
        ));
        assert!(star(
            "SELECT 4.2::double precision FROM pg_class",
            &[("e", "float8")]
        ));
        assert!(!star(
            "SELECT 4.2::double precision FROM pg_class",
            &[("e", "text")]
        ));
        // An implicit or assignment cast: everything.
        assert!(star("SELECT relname FROM pg_class", &[("i", "text")]));
        assert!(star(
            "SELECT pg_catalog.length(42) FROM pg_class LIMIT 1",
            &[("i", "text")]
        ));
    }

    #[test]
    fn parameters_reach_any_user_overload() {
        let rows = [("F", "lower"), ("O", "=")];
        assert!(!star("SELECT lower('x') FROM pg_class", &rows));
        assert!(star("SELECT lower($1) FROM pg_class", &rows));
        assert!(!star("SELECT 1 FROM pg_class WHERE relname = 'x'", &rows));
        assert!(star("SELECT 1 FROM pg_class WHERE relname = $1", &rows));
    }

    #[test]
    fn decisions_1_and_7_are_left_to_them() {
        let mut u = UserCode::default();
        u.store("shop", Instant::now(), 160_013, Some(ProbeNames::default()));
        let view = u.view("shop", Instant::now());
        let code = pg_scan("SELECT s.calls FROM public.pg_stat_statements(false) s, pg_class")
            .unwrap()
            .code();
        assert!(user_code(Some(&code), false, &view, &none));
        let pss = |r: &RelationName| r.name == "pg_stat_statements";
        assert!(!user_code(Some(&code), false, &view, &pss));
    }

    #[test]
    fn unknown_failed_cut_stale_and_old_probes_fail_closed() {
        let unqualified = pg_scan("SELECT length(relname) FROM pg_class")
            .unwrap()
            .code();
        let qualified = pg_scan("SELECT pg_catalog.length(relname) FROM pg_catalog.pg_class")
            .unwrap()
            .code();
        let operator = pg_scan("SELECT 1 FROM pg_class WHERE relkind = 'r'")
            .unwrap()
            .code();
        let plain = pg_scan("SELECT relname FROM pg_class").unwrap().code();
        let t0 = Instant::now();
        let mut u = UserCode::default();
        // Not run yet.
        let v = u.view("shop", t0);
        assert!(matches!(v, View::Unknown(None)));
        assert!(user_code(Some(&unqualified), false, &v, &none));
        assert!(user_code(Some(&operator), false, &v, &none));
        assert!(!user_code(Some(&plain), false, &v, &none));
        // Failed (or cut).
        u.store("shop", t0, 160_013, None);
        let v = u.view("shop", t0);
        assert!(matches!(v, View::Unknown(Some(_))));
        assert!(user_code(Some(&unqualified), false, &v, &none));
        assert!(!user_code(Some(&qualified), false, &v, &none));
        // Cut: more rows than the bound.
        assert!(
            ProbeNames::from_rows((0..=PROBE_MAX_NAMES).map(|k| ("f".to_owned(), k.to_string())))
                .is_none()
        );
        assert!(
            ProbeNames::from_rows((0..PROBE_MAX_NAMES).map(|k| ("f".to_owned(), k.to_string())))
                .is_some()
        );
        // Done, then stale after a DDL, fresh again after a later probe.
        let t1 = t0 + Duration::from_secs(1);
        u.store("shop", t1, 160_013, Some(ProbeNames::default()));
        assert!(!user_code(
            Some(&unqualified),
            false,
            &u.view("shop", t1),
            &none
        ));
        let t2 = t1 + Duration::from_secs(1);
        u.mark_stale("shop", t2);
        assert!(user_code(
            Some(&unqualified),
            false,
            &u.view("shop", t2),
            &none
        ));
        // A probe that started before the mark does not clear it.
        u.store(
            "shop",
            t2 - Duration::from_millis(1),
            160_013,
            Some(ProbeNames::default()),
        );
        assert!(user_code(
            Some(&unqualified),
            false,
            &u.view("shop", t2),
            &none
        ));
        let t3 = t2 + Duration::from_secs(1);
        u.store("shop", t3, 160_013, Some(ProbeNames::default()));
        assert!(!user_code(
            Some(&unqualified),
            false,
            &u.view("shop", t3),
            &none
        ));
        // Too old.
        let late = t3 + PROBE_MAX_AGE + Duration::from_secs(1);
        assert!(user_code(
            Some(&unqualified),
            false,
            &u.view("shop", late),
            &none
        ));
        // A cut text or an unscanned one.
        assert!(user_code(Some(&plain), true, &u.view("shop", t3), &none));
        assert!(user_code(None, false, &u.view("shop", t3), &none));
        // A stale implicit cast stays "everything".
        let t4 = t3 + Duration::from_secs(1);
        u.store("shop", t4, 160_013, Some(names(&[("i", "text")])));
        u.mark_stale("shop", t4 + Duration::from_secs(1));
        assert!(matches!(
            u.view("shop", t4 + Duration::from_secs(1)),
            View::Everything
        ));
    }

    #[test]
    fn versions_without_lists() {
        let mut u = UserCode::default();
        let now = Instant::now();
        u.store("shop", now, 130_020, Some(ProbeNames::default()));
        let v = u.view("shop", now);
        let code = pg_scan("SELECT pg_catalog.length(relname) FROM pg_class")
            .unwrap()
            .code();
        assert!(user_code(Some(&code), false, &v, &none));
        let code = pg_scan("SELECT relname FROM pg_class").unwrap().code();
        assert!(!user_code(Some(&code), false, &v, &none));
    }

    #[test]
    fn routine_ddl_command_tags() {
        for c in [
            "CREATE FUNCTION",
            "ALTER FUNCTION",
            "DROP FUNCTION",
            "CREATE OPERATOR CLASS",
            "CREATE TYPE",
            "ALTER DOMAIN",
            "CREATE CAST",
            "DROP EXTENSION",
            "ALTER ROUTINE",
            "DROP OWNED",
            "DROP SCHEMA",
        ] {
            assert!(routine_ddl_command(c), "{c}");
        }
        for c in ["CREATE TABLE", "SELECT", "DROP TABLE", "ALTER ROLE", ""] {
            assert!(!routine_ddl_command(c), "{c}");
        }
    }

    #[test]
    fn probe_names_are_never_printed() {
        let n = names(&[("f", "secret_name"), ("t", "other_name")]);
        let s = format!("{n:?}");
        assert!(
            !s.contains("secret_name") && !s.contains("other_name"),
            "{s}"
        );
        let mut u = UserCode::default();
        u.store("shop", Instant::now(), 160_013, Some(n));
        assert!(!format!("{u:?}").contains("secret_name"));
    }
}
