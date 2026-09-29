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
//!   `WHERE`, `GROUP BY` / aggregate-only list, derived table, or with a
//!   limit of at least [`LARGE_LIMIT`] rows.
//! - `volume.large_result`: at least [`LARGE_ROWS`] rows returned or
//!   affected (one statement, or one counter delta).
//!
//! Relations of the catalogs (`pg_catalog`, `information_schema`,
//! `pg_toast`, unqualified `pg_*`) are not reported as objects. Statements
//! of the agent's own role are skipped.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::SystemTime;

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::query::{
    AnalyzeOptions, CopyEndpoint, QueryAnalysis, RelationName, StatementKind, analyze,
};

use super::records::AuditRecord;
use crate::discover::normalize;

/// A limit of at least this many rows reads a whole relation.
pub(crate) const LARGE_LIMIT: u64 = 10_000;
/// Rows from which `volume.large_result` is set.
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
    o.large_limit = LARGE_LIMIT;
    o
}

fn is_catalog(r: &RelationName) -> bool {
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

/// Signals of a statement from its analysis (not the session pattern).
fn statement_signals(a: &QueryAnalysis, rows: Option<u64>) -> Vec<Signal> {
    let mut out = Vec::new();
    if let Some(c) = a.copy() {
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
    if a.kind().is_read()
        && !a.relations().iter().all(is_catalog)
        && a.shape().is_some_and(|s| s.whole_relation(LARGE_LIMIT))
    {
        out.push(Signal::FullTableRead);
    }
    if rows.is_some_and(|r| r >= LARGE_ROWS) {
        out.push(Signal::LargeResult);
    }
    out
}

/// Whether a statement copies whole relations to the client.
fn copies_to_client(a: &QueryAnalysis) -> bool {
    a.copy()
        .is_some_and(|c| c.to && c.whole_relation && c.endpoint == CopyEndpoint::Client)
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

    /// Whether the session already reached the pattern.
    pub(crate) fn flagged(&self, session: &str) -> bool {
        self.sessions
            .get(session)
            .is_some_and(|s| s.len() >= DUMP_MIN_RELATIONS)
    }
}

/// Builds events from pgaudit records.
pub(crate) struct PgauditEvents {
    own_account: String,
    dumps: DumpTracker,
}

/// Per class of a statement: objects and rows.
#[derive(Default)]
struct ClassPart {
    objects: Vec<RelationName>,
    rows: Option<u64>,
    copy_record: bool,
}

impl PgauditEvents {
    pub(crate) fn new(own_account: &str) -> Self {
        Self {
            own_account: own_account.to_owned(),
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
            if r.user == self.own_account {
                continue;
            }
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
        let analysis = analyze(&first.audit.statement, analyze_opts(false));
        let mut parts: HashMap<EventAction, ClassPart> = HashMap::new();
        let mut seen_subs: HashSet<(u64, String, String)> = HashSet::new();
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
            let part = parts.entry(action).or_default();
            if !r.audit.object_name.is_empty() && is_relation_type(&r.audit.object_type) {
                if let Some(rel) = split_object_name(&r.audit.object_name) {
                    if !is_catalog(&rel) && !part.objects.contains(&rel) {
                        part.objects.push(rel);
                    }
                }
            }
            // A utility COPY record has no object and logs 0 rows: unknown.
            let utility_copy = r.audit.command == "COPY" && r.audit.object_name.is_empty();
            part.copy_record |= utility_copy;
            if let (Some(rows), false) = (r.audit.rows, utility_copy) {
                part.rows = Some(part.rows.map_or(rows, |p| p.max(rows)));
            }
        }
        if parts.is_empty() {
            return;
        }
        // Objects the log does not name (COPY of a relation, SESSION
        // records without log_relation): from the statement's identifiers.
        let text_relations: Vec<RelationName> = analysis
            .relations()
            .iter()
            .filter(|r| !is_catalog(r))
            .cloned()
            .collect();
        let to_client = copies_to_client(&analysis);
        let dump_pattern = to_client && self.dumps.copied(&first.session, &text_relations);
        let dump = is_dump_application(&first.application)
            || dump_pattern
            || (to_client && self.dumps.flagged(&first.session));
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
            let mut objects = part.objects;
            if objects.is_empty() && matches!(action, EventAction::Read | EventAction::Write) {
                objects = text_relations.clone();
            }
            if objects.is_empty() && matches!(action, EventAction::Read | EventAction::Write) {
                // A catalog-only statement, or objects that cannot be told.
                continue;
            }
            let mut e = MaskedEvent::new(EventSource::Pgaudit, action, principal.clone(), ts)
                .with_rows(part.rows);
            for o in objects.iter().take(16) {
                e = e.with_object(object(&first.database, o));
            }
            if action == EventAction::Read {
                for s in statement_signals(&analysis, part.rows) {
                    e = e.with_signal(s);
                }
                if dump {
                    e = e.with_signal(Signal::PgDump);
                }
            } else if part.rows.is_some_and(|r| r >= LARGE_ROWS) {
                e = e.with_signal(Signal::LargeResult);
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
pub(crate) fn pss_events(
    deltas: &[StatementDelta<'_>],
    from: SystemTime,
    to: SystemTime,
) -> Vec<MaskedEvent> {
    // The pg_dump pattern per role within the poll.
    let mut copied: HashMap<&str, HashSet<RelationName>> = HashMap::new();
    for d in deltas {
        if copies_to_client(d.analysis) {
            let set = copied.entry(d.user).or_default();
            for r in d.analysis.relations().iter().filter(|r| !is_catalog(r)) {
                set.insert(r.clone());
            }
        }
    }
    let mut out = Vec::new();
    for d in deltas {
        let a = d.analysis;
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
        let objects: Vec<&RelationName> = a.relations().iter().filter(|r| !is_catalog(r)).collect();
        if objects.is_empty() && matches!(action, EventAction::Read | EventAction::Write) {
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
        for o in objects {
            e = e.with_object(object(d.database, o));
        }
        if action == EventAction::Read {
            for s in statement_signals(a, rows) {
                e = e.with_signal(s);
            }
            if copies_to_client(a)
                && copied
                    .get(d.user)
                    .is_some_and(|s| s.len() >= DUMP_MIN_RELATIONS)
            {
                e = e.with_signal(Signal::PgDump);
            }
        } else if d.rows >= LARGE_ROWS {
            e = e.with_signal(Signal::LargeResult);
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
            "timestamp": "2026-09-28 21:45:31.320 UTC", "user": "backup", "dbname": "shop",
            "remote_host": "192.0.2.14", "session_id": session, "application_name": app,
            "message": format!("AUDIT: SESSION,{stmt},{sub},{class},{command},{},{object},\"{text}\",<not logged>{rows}",
                if object.is_empty() { "" } else { "TABLE" }),
        });
        parse_record(Format::Jsonlog, line.to_string().as_bytes()).unwrap()
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
        let mut b = PgauditEvents::new("databastion");
        let recs = vec![
            rec(
                "s1",
                1,
                1,
                "READ",
                "SELECT",
                "",
                "SELECT pg_catalog.set_config('search_path', '', false);",
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
        let mut b = PgauditEvents::new("databastion");
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
        let mut b = PgauditEvents::new("databastion");
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
        let mut b = PgauditEvents::new("databastion");
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
    fn own_statements_and_misc_classes_are_skipped() {
        let mut b = PgauditEvents::new("backup");
        let recs = vec![rec(
            "s5",
            1,
            1,
            "READ",
            "SELECT",
            "crm.t",
            "select * from crm.t",
            Some(1),
            "x",
        )];
        assert!(b.convert(recs, SystemTime::now()).is_empty());
        let mut b = PgauditEvents::new("databastion");
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
    fn value_like_names_are_masked() {
        let mut b = PgauditEvents::new("databastion");
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
        let events = pss_events(&deltas, t0, t1);
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
