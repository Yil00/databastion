//! From audit records and `performance_schema` rows to masked access
//! events (ADR-0007): who, which objects (normalized names), which action,
//! how many rows (`performance_schema` only), and the signals computed
//! here from the raw text, which never leaves the agent.
//!
//! Signal heuristics (vocabulary: `classifiers::masking::Signal`):
//! - `signature.mysqldump`: a whole-table read (the `shape.full_table_read`
//!   rule below) by a client whose `program_name` is `mysqldump` /
//!   `mariadb-dump` / `mysqlpump` / `mydumper` (`performance_schema`, or
//!   the connect record of `audit_log_filter`), or carrying `SQL_NO_CACHE`
//!   (`SELECT /*!40001 SQL_NO_CACHE */ … FROM t`, what these tools send),
//!   or in a session that took a consistent snapshot (`START TRANSACTION
//!   WITH CONSISTENT SNAPSHOT`), a global read lock (`FLUSH TABLES WITH
//!   READ LOCK`) or `LOCK TABLES`, or of a table the session ran `SHOW
//!   CREATE TABLE` on. The utility statements are only visible when the
//!   source logs them (`audit_log`, `performance_schema`; not
//!   `server_audit` with `QUERY_DML`).
//! - `signature.into_outfile`: `SELECT … INTO OUTFILE` / `INTO DUMPFILE`,
//!   also when the server refused it (an attempt).
//! - `shape.full_table_read`: a read without top-level `WHERE`,
//!   aggregation, derived table, and without a limit or with a limit above
//!   [`LARGE_LIMIT`] rows.
//! - `volume.large_result`: more than [`LARGE_ROWS`] rows returned or
//!   affected by one statement (`performance_schema` only: the audit log
//!   files carry no row count).
//!
//! The table-access records of a statement and its statement record are
//! grouped per connection (and query id, or text), not by adjacency:
//! concurrent sessions interleave them in the log (see [`Pending`]).
//!
//! Objects come from the table-access records when the source has them
//! (`server_audit` `TABLE` events, `audit_log_filter` `table_access`),
//! otherwise from the statement text (reads and writes only: DDL and DCL
//! events take no name from text); an unqualified name is in the
//! statement's current database. `information_schema`,
//! `performance_schema`, `sys`, `DUAL` and MariaDB's internal statistics
//! tables (`mysql.*_stats`) are not application data and are skipped; the
//! `mysql` schema is kept for reads and writes (reading `mysql.user` is an
//! access worth reporting). A read or write whose objects cannot be told
//! (text that does not lex, `CALL`) is reported against `*`. Statements
//! that failed are skipped, except `INTO OUTFILE` attempts; a statement the
//! server could not parse (error 1064 / 1149) never yields an event.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::{
    EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::{
    AnalyzeOptions, QueryAnalysis, RelationName, StatementInfo, StatementKind, analyze_raw,
};
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::audit::tail::RecordPos;

use super::records::{FileRecord, Op, TableOp};
use crate::discover::normalize;

/// A limit above this many rows reads a whole table.
pub(crate) const LARGE_LIMIT: u64 = 10_000;
/// Rows above which `volume.large_result` is set. Both thresholds sit just
/// above the agent's own maximum sample (`limits.max_sample_rows` is at
/// most 10 000), so its Discovery statements never carry these signals.
pub(crate) const LARGE_ROWS: u64 = 10_000;
/// Sessions followed for the dump patterns (oldest forgotten first).
const MAX_SESSIONS: usize = 4096;
/// Tables remembered per session (`SHOW CREATE TABLE`).
const MAX_SESSION_RELATIONS: usize = 256;
/// Longest table or database name remembered from `SHOW CREATE TABLE`.
const MAX_SHOWN_NAME_CHARS: usize = 64;
/// Server errors of a statement it could not parse: the text is not SQL.
const PARSE_ERRORS: [u32; 2] = [1064, 1149];
/// Server errors raised before a statement reads anything: unknown
/// database / table / column (1049, 1051, 1054, 1109, 1146), ambiguous or
/// duplicate names (1052, 1066), access denied (1044, 1142, 1143, 1227,
/// 1370), unknown routine (1305). A failed statement with another error
/// may have sent rows before it failed, and is reported.
const PRE_EXECUTION_ERRORS: [u32; 13] = [
    1044, 1049, 1051, 1052, 1054, 1066, 1109, 1142, 1143, 1146, 1227, 1305, 1370,
];

fn analyze_opts(truncated: bool) -> AnalyzeOptions {
    let mut o = AnalyzeOptions::mysql().truncated(truncated);
    o.large_limit = LARGE_LIMIT + 1;
    o
}

/// Schemas that hold no application data.
pub(crate) fn is_system_schema(db: &str) -> bool {
    ["information_schema", "performance_schema", "sys"]
        .iter()
        .any(|s| s.eq_ignore_ascii_case(db))
}

/// MariaDB's engine-independent statistics, read by the server itself for
/// many statements, and InnoDB's persistent statistics.
fn is_internal_table(db: &str, table: &str) -> bool {
    db.eq_ignore_ascii_case("mysql")
        && [
            "table_stats",
            "column_stats",
            "index_stats",
            "innodb_table_stats",
            "innodb_index_stats",
        ]
        .iter()
        .any(|t| t.eq_ignore_ascii_case(table))
}

/// A relation named by a statement (unqualified: in `database`) that holds
/// no application data: a system schema, an internal statistics table, or
/// `DUAL`.
fn is_system_relation(r: &RelationName, database: &str) -> bool {
    let db = r.schema.as_deref().unwrap_or(database);
    is_system_schema(db)
        || is_internal_table(db, &r.name)
        || (r.schema.is_none() && r.name.eq_ignore_ascii_case("dual"))
}

/// Connection errors that are not authentication failures: bad handshake
/// (1043), aborted or failed network reads and writes (1152 to 1161).
fn is_network_error(status: u32) -> bool {
    status == 1043 || (1152..=1161).contains(&status)
}

/// Client programs that export whole databases.
pub(crate) fn is_dump_program(program: &str) -> bool {
    let p = program.trim().to_ascii_lowercase();
    let base = p.rsplit('/').next().unwrap_or(&p);
    matches!(
        base.strip_suffix(".exe").unwrap_or(base),
        "mysqldump" | "mariadb-dump" | "mariadbdump" | "mysqlpump" | "mydumper"
    )
}

/// What the agent remembers of one client session.
#[derive(Default)]
struct SessionState {
    /// Consistent snapshot, global read lock or `LOCK TABLES` taken.
    snapshot: bool,
    /// Tables `SHOW CREATE TABLE` ran on.
    shown: HashSet<RelationName>,
    /// `program_name` from the connect record.
    program: Option<String>,
}

/// Sessions followed for the dump patterns, bounded: at most
/// [`MAX_SESSIONS`] states, oldest evicted first. The eviction queue holds
/// (key, generation) pairs; a removed or re-created session leaves a stale
/// pair behind, skipped at eviction and dropped by a compaction once the
/// queue reaches twice the bound.
#[derive(Default)]
pub(crate) struct Sessions {
    map: HashMap<String, (SessionState, u64)>,
    order: VecDeque<(String, u64)>,
    generation: u64,
}

impl Sessions {
    fn live(&self, key: &str, generation: u64) -> bool {
        self.map.get(key).is_some_and(|(_, g)| *g == generation)
    }

    fn compact(&mut self) {
        if self.order.len() >= 2 * MAX_SESSIONS {
            let map = &self.map;
            self.order
                .retain(|(k, g)| map.get(k).is_some_and(|(_, live)| live == g));
        }
    }

    fn entry(&mut self, key: &str) -> &mut SessionState {
        if !self.map.contains_key(key) {
            if self.map.len() >= MAX_SESSIONS {
                while let Some((old, g)) = self.order.pop_front() {
                    if self.live(&old, g) {
                        self.map.remove(&old);
                        break;
                    }
                }
            }
            self.generation += 1;
            self.order.push_back((key.to_owned(), self.generation));
            self.compact();
        }
        let generation = self.generation;
        &mut self
            .map
            .entry(key.to_owned())
            .or_insert_with(|| (SessionState::default(), generation))
            .0
    }

    fn get(&self, key: &str) -> Option<&SessionState> {
        self.map.get(key).map(|(s, _)| s)
    }

    fn remove(&mut self, key: &str) {
        self.map.remove(key);
        self.compact();
    }

    #[cfg(test)]
    fn sizes(&self) -> (usize, usize) {
        (self.map.len(), self.order.len())
    }
}

/// Connections with a statement pending at most.
const MAX_PENDING_CONNECTIONS: usize = 1024;
/// Statements flushed before their statement record that are remembered.
const MAX_EARLY_REPORTED: usize = 16 * MAX_PENDING_CONNECTIONS;
/// Table-access records kept per pending statement (distinct tables; an
/// event names 16 objects at most), and tables remembered per statement
/// flushed early.
const MAX_PENDING_RECORDS: usize = 64;
/// Bytes held by all pending statements at most: their records' names
/// (user, host, database, table: at most 1 KiB each, `records`) and
/// statement text (only the JSON `table_access` records carry one, kept
/// once per statement; one record is at most
/// `databastion_core::audit::tail::MAX_RECORD_BYTES`, 1 MiB), plus a fixed
/// overhead per record.
const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
/// Fixed overhead counted per pending record.
const RECORD_OVERHEAD: usize = 256;
/// A pending statement whose statement record has not come after this
/// long is reported from its table-access records alone.
const PENDING_TIMEOUT: Duration = Duration::from_secs(300);
/// A statement flushed early is forgotten after this long: its late
/// records are then handled as a new statement (security review of #93,
/// L4: the memory of `reported` does not outlive the statements it is for,
/// and a connection id reused after a server restart is not mistaken for
/// the old one for long).
const REPORTED_TTL: Duration = Duration::from_secs(2 * 300);

/// Bytes a pending record holds (see [`MAX_PENDING_BYTES`]).
fn record_bytes(r: &FileRecord) -> usize {
    RECORD_OVERHEAD
        + r.user.len()
        + r.host.len()
        + r.database.len()
        + r.table.as_ref().map_or(0, |(d, t)| d.len() + t.len())
        + r.text.as_ref().map_or(0, |t| t.len())
}

/// Since when a statement starting with `r` is pending, on the monotonic
/// clock: when it was read (`mono`), or for a record re-read after a
/// restart (`FileRecord::replayed`), when it was logged (`ts`, at most
/// [`PENDING_TIMEOUT`] back). An agent restarting more often than the
/// timeout still flushes a held statement early, so its cursor is not kept
/// pinned to it and the log re-read at every restart does not grow
/// (security review of #93, R4). Without a log time: when it was read.
fn pending_since(r: &FileRecord, now: SystemTime, mono: Instant) -> Instant {
    if !r.replayed {
        return mono;
    }
    let age =
        r.ts.and_then(|ts| now.duration_since(ts).ok())
            .unwrap_or_default()
            .min(PENDING_TIMEOUT);
    mono.checked_sub(age).unwrap_or(mono)
}

/// Table-access records of one statement waiting for its statement
/// record.
struct PendingStatement {
    records: Vec<FileRecord>,
    seq: u64,
    since: Instant,
    bytes: usize,
}

/// Statements whose table-access records were read and whose statement
/// record was not yet, **per connection**: the server writes a statement's
/// `TABLE` records when it opens the tables and its `QUERY` record when it
/// ends, and concurrent sessions interleave theirs (`READ a`, `READ b`,
/// `QUERY a`, `QUERY b`). A connection runs one statement at a time, so a
/// pending statement ends at its statement record, at a record of another
/// statement of the same connection, at the connection's disconnect (or a
/// new connect with its id), after [`PENDING_TIMEOUT`], when the state is
/// full, and when the stream ends ([`EventBuilder::finish`]); it is kept
/// across polls, so a statement split by a poll bound or a log rotation is
/// still one event.
///
/// Bounded: at most [`MAX_PENDING_CONNECTIONS`] statements of
/// [`MAX_PENDING_RECORDS`] records, [`MAX_PENDING_BYTES`] in all (the
/// oldest statement is flushed first, in insertion order: `order`). A
/// statement flushed before its statement record (timeout, full state) is
/// remembered by its query id and the tables already reported for it
/// (`reported`, at most [`MAX_EARLY_REPORTED`], each with at most
/// [`MAX_PENDING_RECORDS`] tables kept as 8-byte keyed hashes: 8 MiB at
/// most; forgotten after [`REPORTED_TTL`], oldest first), so its late
/// records do not count it twice: a late table record of a table already
/// reported is ignored, one of another table starts a continuation of the
/// statement that is reported like any pending statement (a `CALL` that
/// reads a harmless table, waits past the timeout, then reads another one
/// is never hidden), and a late statement record without a continuation
/// yields an event only when its text shows a signal (a whole-table read
/// by a dump program that ran longer than the timeout). Without query ids
/// (`audit_log_filter`) nothing is remembered.
#[derive(Default)]
struct Pending {
    map: HashMap<u64, PendingStatement>,
    /// Sequence → connection of the pending statements (oldest first).
    order: BTreeMap<u64, u64>,
    /// Connection → statement flushed early.
    reported: HashMap<u64, Reported>,
    /// Sequence → connection of `reported` (oldest first).
    reported_order: BTreeMap<u64, u64>,
    /// Keys of the table hashes (random per process: names are
    /// client-controlled).
    hasher: std::collections::hash_map::RandomState,
    seq: u64,
    bytes: usize,
    /// Statements flushed early because the state was full.
    evicted: u64,
}

/// A statement flushed before its statement record.
struct Reported {
    query_id: u64,
    seq: u64,
    since: Instant,
    /// Keyed hashes of the tables (and operation) already reported for it
    /// (at most [`MAX_PENDING_RECORDS`]).
    tables: Vec<u64>,
}

impl Pending {
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn table_key(&self, r: &FileRecord) -> u64 {
        use std::hash::BuildHasher as _;
        self.hasher.hash_one((&r.table, r.op))
    }

    fn first(&self, connection: u64) -> Option<&FileRecord> {
        self.map.get(&connection).and_then(|p| p.records.first())
    }

    fn take(&mut self, connection: u64) -> Option<Vec<FileRecord>> {
        let p = self.map.remove(&connection)?;
        self.order.remove(&p.seq);
        self.bytes = self.bytes.saturating_sub(p.bytes);
        Some(p.records)
    }

    /// Forgets the early-flushed statement of a connection.
    fn forget(&mut self, connection: u64) {
        if let Some(rep) = self.reported.remove(&connection) {
            self.reported_order.remove(&rep.seq);
        }
    }

    /// The early-flushed statement `r` belongs to, if any.
    fn reported_of(&self, r: &FileRecord) -> Option<&Reported> {
        let q = r.query_id?;
        self.reported
            .get(&r.connection)
            .filter(|rep| rep.query_id == q)
    }

    /// Whether `r` belongs to a statement already flushed early.
    fn reported(&self, r: &FileRecord) -> bool {
        self.reported_of(r).is_some()
    }

    /// Whether `r` is a table record of an early-flushed statement whose
    /// table was already reported.
    fn table_reported(&self, r: &FileRecord) -> bool {
        let key = self.table_key(r);
        self.reported_of(r)
            .is_some_and(|rep| rep.tables.contains(&key))
    }

    /// Takes a statement out before its statement record, remembering it
    /// with its tables (merged with those of an earlier part of it).
    fn take_early(&mut self, connection: u64, mono: Instant) -> Option<Vec<FileRecord>> {
        let records = self.take(connection)?;
        if let Some(q) = records.first().and_then(|r| r.query_id) {
            let mut tables = match self.reported.get(&connection) {
                Some(old) if old.query_id == q => old.tables.clone(),
                _ => Vec::new(),
            };
            self.forget(connection);
            for r in &records {
                let key = self.table_key(r);
                if !tables.contains(&key) && tables.len() < MAX_PENDING_RECORDS {
                    tables.push(key);
                }
            }
            while self.reported.len() >= MAX_EARLY_REPORTED {
                match self.reported_order.first_key_value().map(|(_, c)| *c) {
                    Some(old) => self.forget(old),
                    None => break,
                }
            }
            let seq = self.next_seq();
            self.reported_order.insert(seq, connection);
            self.reported.insert(
                connection,
                Reported {
                    query_id: q,
                    seq,
                    since: mono,
                    tables,
                },
            );
        }
        Some(records)
    }

    fn evict_oldest(&mut self, mono: Instant) -> Option<Vec<FileRecord>> {
        let oldest = self.order.first_key_value().map(|(_, c)| *c)?;
        self.evicted = self.evicted.saturating_add(1);
        self.take_early(oldest, mono)
    }

    /// Adds a table-access record (of the connection's pending statement,
    /// if any: the caller flushed another statement first). Returns the
    /// statements flushed to make room.
    fn add(&mut self, mut r: FileRecord, mono: Instant, now: SystemTime) -> Vec<Vec<FileRecord>> {
        let since = pending_since(&r, now, mono);
        let c = r.connection;
        // Another statement than the early-flushed one: the connection
        // moved on (a continuation of it keeps it).
        if !self.reported(&r) {
            self.forget(c);
        }
        let mut flushed = Vec::new();
        if let Some(p) = self.map.get_mut(&c) {
            // Records of one statement carry the same text, if any (the
            // grouping compares it): the first one keeps it.
            r.text = None;
            let known = p.records.iter().any(|g| g.op == r.op && g.table == r.table);
            if !known && p.records.len() < MAX_PENDING_RECORDS {
                let n = record_bytes(&r);
                p.bytes += n;
                self.bytes = self.bytes.saturating_add(n);
                p.records.push(r);
            }
        } else {
            while self.map.len() >= MAX_PENDING_CONNECTIONS {
                match self.evict_oldest(mono) {
                    Some(p) => flushed.push(p),
                    None => break,
                }
            }
            let bytes = record_bytes(&r);
            let seq = self.next_seq();
            self.bytes = self.bytes.saturating_add(bytes);
            self.order.insert(seq, c);
            self.map.insert(
                c,
                PendingStatement {
                    records: vec![r],
                    seq,
                    since,
                    bytes,
                },
            );
        }
        while self.bytes > MAX_PENDING_BYTES {
            match self.evict_oldest(mono) {
                Some(p) => flushed.push(p),
                None => break,
            }
        }
        flushed
    }

    /// Statements pending for [`PENDING_TIMEOUT`] or more, oldest first;
    /// early-flushed statements older than [`REPORTED_TTL`] are forgotten.
    fn expired(&mut self, mono: Instant) -> Vec<Vec<FileRecord>> {
        while let Some((_, c)) = self.reported_order.first_key_value().map(|(s, c)| (*s, *c)) {
            let old = self
                .reported
                .get(&c)
                .is_none_or(|rep| mono.saturating_duration_since(rep.since) >= REPORTED_TTL);
            if !old {
                break;
            }
            self.forget(c);
        }
        let mut out = Vec::new();
        while let Some(c) = self.order.first_key_value().map(|(_, c)| *c) {
            let due = self
                .map
                .get(&c)
                .is_none_or(|p| mono.saturating_duration_since(p.since) >= PENDING_TIMEOUT);
            if !due {
                break;
            }
            match self.take_early(c, mono) {
                Some(p) => out.push(p),
                None => {
                    // Not pending (cannot happen): drop the stale entry.
                    self.order.pop_first();
                }
            }
        }
        out
    }

    /// (connection, position of its first record) of every pending
    /// statement whose records have positions.
    fn held(&self) -> Vec<(u64, RecordPos)> {
        self.order
            .values()
            .filter_map(|c| {
                let pos = self.map.get(c)?.records.first()?.pos?;
                Some((*c, pos))
            })
            .collect()
    }

    /// Every pending statement, oldest first; the state is emptied.
    fn drain(&mut self) -> Vec<Vec<FileRecord>> {
        let conns: Vec<u64> = self.order.values().copied().collect();
        let out = conns.into_iter().filter_map(|c| self.take(c)).collect();
        self.reported.clear();
        self.reported_order.clear();
        self.order.clear();
        out
    }

    #[cfg(test)]
    fn sizes(&self) -> (usize, usize, usize, usize) {
        (
            self.map.len(),
            self.map
                .values()
                .map(|p| p.records.len())
                .max()
                .unwrap_or(0),
            self.bytes,
            self.reported.len(),
        )
    }
}

/// One statement to turn into an event.
pub(crate) struct Access<'a> {
    /// Session key (`c<connection id>`, `t<thread id>`).
    pub(crate) session: String,
    /// Login user (empty when unknown).
    pub(crate) user: &'a str,
    pub(crate) principal: EventPrincipal,
    pub(crate) client: ClientSeen,
    /// `program_name` of the client, when the source shows it.
    pub(crate) application: Option<&'a str>,
    /// Current database of the statement.
    pub(crate) database: &'a str,
    /// Statement text as raw bytes (never decoded lossily for analysis).
    pub(crate) text: Option<&'a [u8]>,
    /// The text is only good for its statement kind (see
    /// `records::FileRecord::opaque`).
    pub(crate) opaque: bool,
    pub(crate) truncated: bool,
    /// Table-access records of the statement.
    pub(crate) tables: Vec<(&'a str, &'a str, TableOp)>,
    pub(crate) rows: Option<u64>,
    pub(crate) status: u32,
    pub(crate) ts: SystemTime,
    pub(crate) source: EventSource,
}

fn object(database: &str, name: &str) -> EventObject {
    let db = if database.is_empty() {
        NormalizedName::wildcard()
    } else {
        normalize(database)
    };
    EventObject::new(db, None, normalize(name))
}

/// An object the source does not name: the database, and `*`.
fn unknown_object(database: &str) -> EventObject {
    let db = if database.is_empty() {
        NormalizedName::wildcard()
    } else {
        normalize(database)
    };
    EventObject::new(db, None, NormalizedName::wildcard())
}

/// Updates the session's dump state from its utility statements.
fn note_utility(s: &mut SessionState, parts: &[StatementInfo]) {
    for p in parts {
        let lead: Vec<&str> = p.lead.iter().map(String::as_str).collect();
        match lead.as_slice() {
            ["flush", rest @ ..] if rest.contains(&"lock") && rest.contains(&"read") => {
                s.snapshot = true;
            }
            ["start", "transaction", rest @ ..] if rest.contains(&"consistent") => {
                s.snapshot = true;
            }
            ["lock", "tables" | "table", ..] => s.snapshot = true,
            ["show", "create", "table", ..] => {
                for r in &p.relations {
                    let short = r.name.chars().count() <= MAX_SHOWN_NAME_CHARS
                        && r.schema
                            .as_deref()
                            .is_none_or(|s| s.chars().count() <= MAX_SHOWN_NAME_CHARS);
                    if short && s.shown.len() < MAX_SESSION_RELATIONS {
                        s.shown.insert(r.clone());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Builds events for one target and source.
pub(crate) struct EventBuilder {
    own: OwnAccount,
    sessions: Sessions,
    /// Table-access records waiting for their statement record.
    pending: Pending,
    /// Failed statements skipped (no rows were read).
    pub(crate) failed: u64,
    /// Records dropped because their conversion panicked (PR #83
    /// re-review M-A).
    pub(crate) panicked: u64,
}

impl EventBuilder {
    pub(crate) fn new(own: OwnAccount) -> Self {
        Self {
            own,
            sessions: Sessions::default(),
            pending: Pending::default(),
            panicked: 0,
            failed: 0,
        }
    }

    /// The agent's address as the server sees it, refreshed at each
    /// re-probe of the source.
    pub(crate) fn set_own_addr(
        &mut self,
        addr: Option<databastion_classifiers::masking::ClientAddr>,
    ) {
        self.own.set_addr(addr);
    }

    /// The event of one statement, if any (see the module documentation).
    pub(crate) fn statement(&mut self, a: Access<'_>, now: SystemTime) -> Option<MaskedEvent> {
        let opaque = a.opaque || a.text.is_some_and(|t| std::str::from_utf8(t).is_err());
        let analysis: Option<QueryAnalysis> = a.text.map(|t| {
            // performance_schema texts come transcoded to utf8mb4 by the
            // server: the multibyte trail-byte guard is for raw client
            // bytes (audit log files) only.
            let transcoded = a.source == EventSource::PerformanceSchema;
            analyze_raw(
                t,
                analyze_opts(a.truncated)
                    .opaque(a.opaque)
                    .transcoded(transcoded),
            )
        });
        let parts: &[StatementInfo] = analysis.as_ref().map_or(&[], QueryAnalysis::parts);
        let parsed = !parts.is_empty();
        if let Some(app) = a.application {
            let s = self.sessions.entry(&a.session);
            if s.program.is_none() {
                s.program = Some(app.to_owned());
            }
        }
        if a.status == 0 {
            note_utility(self.sessions.entry(&a.session), parts);
        }
        let outfile = parts.iter().any(|p| p.outfile);
        // A failed statement is skipped only when it failed before reading
        // anything (and sent no row); an INTO OUTFILE attempt is kept. A
        // statement with table read records read something whatever its
        // error says (`SIGNAL … SET MYSQL_ERRNO = 1146` in a function after
        // rows were sent): never skipped.
        let read_records = a.tables.iter().any(|t| t.2 == TableOp::Read);
        if a.status != 0 && a.rows.unwrap_or(0) == 0 && !read_records {
            let pre = PRE_EXECUTION_ERRORS.contains(&a.status) && !outfile;
            if PARSE_ERRORS.contains(&a.status) || pre {
                self.failed += 1;
                return None;
            }
        }
        let lead0 = parts
            .first()
            .and_then(|p| p.lead.first())
            .map(String::as_str);
        let table_action = if a.tables.iter().any(|t| t.2 == TableOp::Read) {
            Some(EventAction::Read)
        } else if a.tables.iter().any(|t| t.2 == TableOp::Write) {
            Some(EventAction::Write)
        } else if a.tables.iter().any(|t| t.2 == TableOp::Ddl) {
            Some(EventAction::Ddl)
        } else {
            None
        };
        let kind = analysis
            .as_ref()
            .map_or(StatementKind::Other, QueryAnalysis::kind);
        let call = lead0 == Some("call");
        let action = match kind {
            StatementKind::Select
            | StatementKind::Table
            | StatementKind::Values
            | StatementKind::Handler => EventAction::Read,
            StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge => EventAction::Write,
            StatementKind::Ddl => EventAction::Ddl,
            StatementKind::Dcl => EventAction::Dcl,
            _ if call => EventAction::Read,
            _ => match (table_action, opaque) {
                (Some(t), _) => t,
                // A text that cannot be read: reported against `*`.
                (None, true) => EventAction::Read,
                (None, false) => return None,
            },
        };
        let rw = matches!(action, EventAction::Read | EventAction::Write);
        let mut objects: Vec<(String, String)> = Vec::new();
        let mut unknown = false;
        if a.tables.is_empty() && rw {
            // Names from the text for reads and writes only: DDL and DCL
            // text can hold program bodies (MySQL JavaScript routines in
            // `$$ … $$`) that the SQL lexer does not delimit, and their
            // events need no object.
            let mut named_any = false;
            for p in parts {
                for r in &p.relations {
                    named_any = true;
                    if is_system_relation(r, a.database) {
                        continue;
                    }
                    let db = r.schema.as_deref().unwrap_or(a.database);
                    let o = (db.to_owned(), r.name.clone());
                    if !objects.contains(&o) {
                        objects.push(o);
                    }
                }
            }
            if !named_any && (!parsed || call) {
                unknown = true;
            }
        } else {
            for (db, table, _) in &a.tables {
                let system = is_system_schema(db)
                    || is_internal_table(db, table)
                    || (!rw && db.eq_ignore_ascii_case("mysql"));
                let o = ((*db).to_owned(), (*table).to_owned());
                if !system && !objects.contains(&o) {
                    objects.push(o);
                }
            }
        }
        if rw && objects.is_empty() && !unknown {
            // Only system tables, or no table at all (`SELECT 1`).
            return None;
        }
        let ts = a.ts.min(now);
        let mut e = MaskedEvent::new(a.source, action, a.principal.clone(), ts).with_rows(a.rows);
        for (db, name) in objects.iter().take(16) {
            e = e.with_object(object(db, name));
        }
        if unknown {
            e = e.with_object(unknown_object(a.database));
        }
        if action == EventAction::Read {
            let session = self.sessions.get(&a.session);
            let dumper = a
                .application
                .or_else(|| session.and_then(|s| s.program.as_deref()))
                .is_some_and(is_dump_program);
            for p in parts {
                let user_relations: Vec<&RelationName> = p
                    .relations
                    .iter()
                    .filter(|r| !is_system_relation(r, a.database))
                    .collect();
                if p.outfile {
                    e = e.with_signal(Signal::IntoOutfile);
                }
                let whole = p.kind.is_read()
                    && !user_relations.is_empty()
                    && p.shape.is_some_and(|s| s.whole_relation(LARGE_LIMIT + 1));
                if whole {
                    e = e.with_signal(Signal::FullTableRead);
                    let no_cache = p.lead.iter().skip(1).any(|w| w == "sql_no_cache");
                    let pattern = session.is_some_and(|s| {
                        s.snapshot || user_relations.iter().any(|r| s.shown.contains(*r))
                    });
                    if no_cache || dumper || pattern {
                        e = e.with_signal(Signal::Mysqldump);
                    }
                }
            }
        }
        if a.rows.is_some_and(|r| r > LARGE_ROWS) {
            e = e.with_signal(Signal::LargeResult);
        }
        if self
            .own
            .routine(a.user, a.application, a.client, &e, Instant::now())
        {
            return None;
        }
        Some(e)
    }

    /// Converts audit log records (in file order): the table-access
    /// records and the statement record of one statement are merged, per
    /// connection (see [`Pending`]). Table-access records whose statement
    /// record has not been read yet stay pending across calls (a later
    /// poll, a rotated file); [`Self::finish`] flushes them when the
    /// stream ends.
    pub(crate) fn convert_file(
        &mut self,
        records: Vec<FileRecord>,
        source: EventSource,
        now: SystemTime,
    ) -> Vec<MaskedEvent> {
        self.convert_file_at(records, source, now, Instant::now())
    }

    /// [`Self::convert_file`] at the monotonic time `mono` (tests).
    fn convert_file_at(
        &mut self,
        records: Vec<FileRecord>,
        source: EventSource,
        now: SystemTime,
        mono: Instant,
    ) -> Vec<MaskedEvent> {
        let mut out = Vec::new();
        for r in records {
            match r.op {
                Op::Connect | Op::FailedConnect | Op::Disconnect => {
                    // The connection's statement ends with it (a new
                    // session reusing the id starts afresh).
                    if let Some(p) = self.pending.take(r.connection) {
                        self.flush_isolated(p, source, now, &mut out);
                    }
                    self.pending.forget(r.connection);
                    match databastion_core::isolate(|| self.connection(&r, source, now)) {
                        Some(Some(e)) => out.push(e),
                        Some(None) => {}
                        None => self.panicked = self.panicked.saturating_add(1),
                    }
                }
                Op::Table(_) => self.table_record(r, source, now, mono, &mut out),
                Op::Query => self.query_record(r, source, now, &mut out),
            }
        }
        for p in self.pending.expired(mono) {
            self.flush_isolated(p, source, now, &mut out);
        }
        out
    }

    /// Flushes every pending statement (the stream ends: the source
    /// changes, the log became unreadable).
    pub(crate) fn finish(&mut self, source: EventSource, now: SystemTime) -> Vec<MaskedEvent> {
        let mut out = Vec::new();
        for p in self.pending.drain() {
            self.flush_isolated(p, source, now, &mut out);
        }
        out
    }

    /// Where the pending statements start in the log: the stream commits
    /// its cursor back to the oldest of them (`Tailer::commit_from`), so a
    /// restart replays them (security review of #93, M1).
    pub(crate) fn held(&self) -> Vec<(u64, RecordPos)> {
        self.pending.held()
    }

    /// Statements flushed before their statement record because the
    /// pending state was full (see [`Pending`]).
    pub(crate) fn pending_evicted(&self) -> u64 {
        self.pending.evicted
    }

    /// A table-access record: added to its connection's pending
    /// statement, or starting one.
    fn table_record(
        &mut self,
        r: FileRecord,
        source: EventSource,
        now: SystemTime,
        mono: Instant,
        out: &mut Vec<MaskedEvent>,
    ) {
        if self.pending.table_reported(&r) {
            // Its statement and this table were already reported (timeout,
            // eviction). Another table of it is a continuation: pending,
            // reported like any statement (never dropped).
            return;
        }
        let c = r.connection;
        if self
            .pending
            .first(c)
            .is_some_and(|g| !same_statement(g, &r))
        {
            // A connection runs one statement at a time: a record of
            // another statement ends the pending one (a statement whose
            // source logs no statement record).
            if let Some(p) = self.pending.take(c) {
                self.flush_isolated(p, source, now, out);
            }
        }
        for p in self.pending.add(r, mono, now) {
            self.flush_isolated(p, source, now, out);
        }
    }

    /// A statement record: flushed with its connection's pending
    /// table-access records.
    fn query_record(
        &mut self,
        r: FileRecord,
        source: EventSource,
        now: SystemTime,
        out: &mut Vec<MaskedEvent>,
    ) {
        let c = r.connection;
        match self.pending.take(c) {
            Some(mut group) if group.first().is_some_and(|g| same_statement(g, &r)) => {
                // Its pending records (a continuation of an early-flushed
                // statement included: its new tables are reported).
                self.pending.forget(c);
                group.push(r);
                self.flush_isolated(group, source, now, out);
                return;
            }
            Some(group) => self.flush_isolated(group, source, now, out),
            None => {}
        }
        if self.pending.reported(&r) {
            // Its table-access records were reported without it (the
            // statement outlived the pending timeout, or was evicted): its
            // own event is only kept when the text shows a signal the
            // table records could not, so the statement is counted once
            // unless it matters.
            self.pending.forget(c);
            let mut late = Vec::new();
            self.flush_isolated(vec![r], source, now, &mut late);
            out.extend(late.into_iter().filter(|e| !e.signals().is_empty()));
            return;
        }
        self.pending.forget(c);
        self.flush_isolated(vec![r], source, now, out);
    }

    /// [`Self::flush`] of one statement in isolation: a statement whose
    /// conversion panics is dropped alone, its records counted in
    /// `panicked` (PR #83 re-review M-A).
    fn flush_isolated(
        &mut self,
        group: Vec<FileRecord>,
        source: EventSource,
        now: SystemTime,
        out: &mut Vec<MaskedEvent>,
    ) {
        let n = group.len() as u64;
        match databastion_core::isolate(|| {
            let mut events = Vec::new();
            self.flush(group, source, now, &mut events);
            events
        }) {
            Some(events) => out.extend(events),
            None => self.panicked = self.panicked.saturating_add(n),
        }
    }

    fn connection(
        &mut self,
        r: &FileRecord,
        source: EventSource,
        now: SystemTime,
    ) -> Option<MaskedEvent> {
        let key = format!("c{}", r.connection);
        let client = databastion_classifiers::masking::ClientAddr::parse(&r.host);
        let ts = r.ts.unwrap_or(now).min(now);
        match r.op {
            Op::Disconnect => {
                self.sessions.remove(&key);
                None
            }
            // A client that dropped the connection during the handshake
            // (a port probe, a health check): not an authentication
            // failure.
            Op::FailedConnect if is_network_error(r.status) => None,
            Op::FailedConnect => Some(MaskedEvent::new(
                source,
                EventAction::AuthFailure,
                EventPrincipal::failed_account(&r.user).with_client(client),
                ts,
            )),
            _ => {
                self.sessions.remove(&key);
                let mut principal = EventPrincipal::account(&r.user).with_client(client);
                if let Some(p) = &r.program {
                    self.sessions.entry(&key).program = Some(p.clone());
                    principal = principal.with_application(p);
                }
                let e = MaskedEvent::new(source, EventAction::Connect, principal, ts);
                let routine = self.own.routine(
                    &r.user,
                    r.program.as_deref(),
                    ClientSeen::Logged(client),
                    &e,
                    Instant::now(),
                );
                (!routine).then_some(e)
            }
        }
    }

    fn flush(
        &mut self,
        group: Vec<FileRecord>,
        source: EventSource,
        now: SystemTime,
        out: &mut Vec<MaskedEvent>,
    ) {
        let Some(first) = group.first() else {
            return;
        };
        let query = group.iter().find(|r| r.op == Op::Query);
        let text_record = query.or_else(|| group.iter().find(|r| r.text.is_some()));
        let key = format!("c{}", first.connection);
        let program = self.sessions.get(&key).and_then(|s| s.program.clone());
        let client = databastion_classifiers::masking::ClientAddr::parse(&first.host);
        let mut principal = EventPrincipal::account(&first.user).with_client(client);
        if let Some(p) = &program {
            principal = principal.with_application(p);
        }
        let tables: Vec<(&str, &str, TableOp)> = group
            .iter()
            .filter_map(|r| match (r.op, &r.table) {
                (Op::Table(op), Some((db, t))) => Some((db.as_str(), t.as_str(), op)),
                _ => None,
            })
            .collect();
        let access = Access {
            session: key.clone(),
            user: &first.user,
            principal,
            client: ClientSeen::Logged(client),
            application: program.as_deref(),
            database: query.map_or(first.database.as_str(), |q| q.database.as_str()),
            text: text_record.and_then(|r| r.text.as_deref().map(Vec::as_slice)),
            opaque: text_record.is_some_and(|r| r.opaque),
            truncated: text_record.is_some_and(|r| r.truncated),
            tables,
            rows: None,
            status: query.map_or(0, |q| q.status),
            ts: first.ts.unwrap_or(now),
            source,
        };
        if let Some(e) = self.statement(access, now) {
            out.push(e);
        }
    }
}

/// Whether `r` belongs to the statement of `g`, the first record of a
/// pending statement (same connection, and the same query id, or without
/// query ids the same text).
fn same_statement(g: &FileRecord, r: &FileRecord) -> bool {
    g.connection == r.connection
        && g.op != Op::Query
        && match (g.query_id, r.query_id) {
            (Some(a), Some(b)) => a == b,
            (None, None) => match (&g.text, &r.text) {
                (Some(a), Some(b)) => a.as_slice() == b.as_slice(),
                _ => false,
            },
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use databastion_classifiers::masking::ClientAddr;
    use databastion_core::audit::own::SharedOwnUsage;

    use super::*;
    use crate::audit::records::{parse_json, parse_server_audit};

    fn own() -> OwnAccount {
        OwnAccount::new(
            "databastion",
            Some("databastion-agent"),
            ClientAddr::parse("172.18.0.1"),
            1000,
            SharedOwnUsage::default(),
        )
    }

    fn show(e: &MaskedEvent) -> String {
        format!(
            "{} {:?} {:?} {:?}",
            e.action().as_str(),
            e.objects()
                .iter()
                .map(|o| format!("{}.{}", o.database().as_str(), o.object().as_str()))
                .collect::<Vec<_>>(),
            e.rows(),
            e.signals().iter().map(|s| s.as_str()).collect::<Vec<_>>()
        )
    }

    fn sa(lines: &[&str]) -> Vec<FileRecord> {
        lines
            .iter()
            .map(|l| parse_server_audit(l.as_bytes(), 0, 1024).unwrap())
            .collect()
    }

    fn file(b: &mut EventBuilder, recs: Vec<FileRecord>) -> Vec<String> {
        b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now())
            .iter()
            .map(show)
            .collect()
    }

    #[test]
    fn mariadb_dump_is_a_signature() {
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                "20260929 09:42:04,h,root,localhost,51,0,CONNECT,,,0",
                r"20260929 09:42:04,h,root,localhost,51,155,QUERY,support,'SELECT engine, table_type FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = DATABASE() AND table_name = \'tickets\'',0",
                "20260929 09:42:04,h,root,localhost,51,174,READ,support,tickets,",
                "20260929 09:42:04,h,root,localhost,51,174,READ,mysql,table_stats,",
                r"20260929 09:42:04,h,root,localhost,51,174,QUERY,support,'SELECT /*!40001 SQL_NO_CACHE */ `id`, `requester_email` FROM `tickets`',0",
                "20260929 09:42:04,h,root,localhost,51,177,QUERY,support,'select @@collation_database',0",
                "20260929 09:42:04,h,root,localhost,51,0,DISCONNECT,support,,0",
            ]),
        );
        assert_eq!(
            out,
            [
                "connect [] None []",
                "read [\"support.tickets\"] None [\"shape.full_table_read\", \"signature.mysqldump\"]"
            ],
            "{out:#?}"
        );
    }

    #[test]
    fn outfile_attempts_and_failures() {
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                "20260929 09:41:34,h,app,10.0.0.5,37,109,READ,support,tickets,",
                r"20260929 09:41:34,h,app,10.0.0.5,37,109,QUERY,mysql,'select * from support.tickets where 1=0 into outfile \'/tmp/x\'',1086",
                r"20260929 09:41:34,h,app,10.0.0.5,37,110,QUERY,support,'select * from nope where a = \'x\'',1146",
                r"20260929 09:41:34,h,app,10.0.0.5,37,111,QUERY,support,'selec * from tickets',1064",
            ]),
        );
        assert_eq!(
            out,
            ["read [\"support.tickets\"] None [\"signature.into_outfile\"]"],
            "{out:#?}"
        );
        assert_eq!(b.failed, 2);
    }

    #[test]
    fn objects_from_table_events_or_text() {
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                // Filtered read, objects from the TABLE events.
                "20260929 09:41:34,h,app,10.0.0.5,37,1,READ,support,tickets,",
                "20260929 09:41:34,h,app,10.0.0.5,37,1,READ,support,escalations,",
                r"20260929 09:41:34,h,app,10.0.0.5,37,1,QUERY,support,'select t.id from tickets t join escalations e on e.ticket_id = t.id where t.id = 3',0",
                // Only information_schema: skipped.
                "20260929 09:41:34,h,app,10.0.0.5,37,2,QUERY,support,'select count(*) from information_schema.tables',0",
                // No table: skipped.
                "20260929 09:41:34,h,app,10.0.0.5,37,3,QUERY,support,'select 1',0",
                // Write, from TABLE events only (QUERY record filtered out).
                "20260929 09:41:34,h,app,10.0.0.5,37,4,WRITE,support,tickets,",
                // DDL on the mysql schema (a GRANT): no mysql object.
                "20260929 09:41:34,h,app,10.0.0.5,37,5,WRITE,mysql,global_priv,",
                r"20260929 09:41:34,h,app,10.0.0.5,37,5,QUERY,mysql,'GRANT SELECT ON support.* TO \'u\'@\'%\' IDENTIFIED BY *****',0",
                // Reading mysql.user is reported.
                "20260929 09:41:34,h,app,10.0.0.5,37,6,READ,mysql,user,",
                "20260929 09:41:34,h,app,10.0.0.5,37,6,QUERY,support,'select authentication_string from mysql.user',0",
                // A procedure: objects unknown.
                "20260929 09:41:34,h,app,10.0.0.5,37,7,QUERY,support,'call report()',0",
                // Truncated or unlexable text without TABLE events: `*`.
                "20260929 09:41:34,h,app,10.0.0.5,37,8,QUERY,support,'select \\'open',0",
            ]),
        );
        assert_eq!(
            out,
            [
                "read [\"support.escalations\", \"support.tickets\"] None []",
                "write [\"support.tickets\"] None []",
                "dcl [] None []",
                "read [\"mysql.user\"] None [\"shape.full_table_read\"]",
                "read [\"support.*\"] None []",
                "read [\"support.*\"] None []",
            ],
            "{out:#?}"
        );
    }

    #[test]
    fn auth_failures_are_fingerprinted_and_connects_reported() {
        let mut b = EventBuilder::new(own());
        let ev = b.convert_file(
            sa(&[
                "20260929 09:40:35,h,Secr3t-typed-as-user,10.0.0.9,12,0,FAILED_CONNECT,,,1045",
                // A bare TCP connect (health check): not an auth failure.
                "20260929 09:40:35,h,,127.0.0.1,15,0,FAILED_CONNECT,,,1158",
                "20260929 09:40:35,h,app,10.0.0.9,13,0,CONNECT,shop,,0",
                // The agent's own connection, from its address.
                "20260929 09:40:35,h,databastion,172.18.0.1,14,0,CONNECT,,,0",
            ]),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].action(), EventAction::AuthFailure);
        assert!(!ev[0].principal().send_name());
        assert_eq!(ev[1].action(), EventAction::Connect);
        assert_eq!(ev[1].principal().client(), ClientAddr::parse("10.0.0.9"));
    }

    #[test]
    fn own_writes_ddl_and_dcl_are_always_reported() {
        let line = |q: u64, text: &str| {
            format!("20260929 09:40:35,h,databastion,172.18.0.1,20,{q},QUERY,support,'{text}',0")
        };
        let mut b = EventBuilder::new(own());
        for (q, text) in [
            (
                1,
                "UPDATE `support`.`tickets` SET `status` = 1 WHERE `id` = 2",
            ),
            (2, "DROP TABLE `support`.`tickets`"),
            (3, "GRANT SELECT ON `support`.* TO `x`@`%`"),
        ] {
            let ev = file(&mut b, sa(&[&line(q, text)]));
            assert_eq!(ev.len(), 1, "{text}");
        }
    }

    #[test]
    fn own_account_is_left_out_only_when_routine() {
        let sample = r"20260929 09:40:35,h,databastion,172.18.0.1,20,{q},QUERY,support,'SELECT LEFT(`requester_email`, 4096) FROM `support`.`tickets` LIMIT 1000',0";
        let line = |q: u64| sample.replace("{q}", &q.to_string());
        let mut b = EventBuilder::new(own());
        // Within the budget (unknown rows are charged the whole budget):
        // the first sampling read is routine, the second is reported.
        assert!(file(&mut b, sa(&[&line(1)])).is_empty());
        assert_eq!(file(&mut b, sa(&[&line(2)])).len(), 1);
        // Same account from another address, or a whole-table read: reported.
        let mut b = EventBuilder::new(own());
        let other = line(1).replace("172.18.0.1", "10.9.9.9");
        assert_eq!(file(&mut b, sa(&[&other])).len(), 1);
        let dump = r"20260929 09:40:35,h,databastion,172.18.0.1,20,3,QUERY,support,'select * from tickets',0";
        assert_eq!(file(&mut b, sa(&[dump])).len(), 1);
        // The agent's address is a host name: nothing is left out.
        let mut b = EventBuilder::new(own());
        let named = line(1).replace("172.18.0.1", "localhost");
        assert_eq!(file(&mut b, sa(&[&named])).len(), 1);
    }

    #[test]
    fn filter_json_groups_and_program_name() {
        let recs = [
            r#"{"timestamp":"2026-09-29 10:06:12","class":"connection","event":"connect","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"connection_data":{"status":0,"db":"","connection_attributes":{"program_name":"mysqldump"}}}"#,
            r#"{"timestamp":"2026-09-29 10:06:12","class":"general","event":"status","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"general_data":{"command":"Query","query":"show create table `t`","status":0}}"#,
            r#"{"timestamp":"2026-09-29 10:06:12","class":"table_access","event":"read","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"table_access_data":{"db":"hr","table":"t","query":"SELECT * FROM `t`"}}"#,
            r#"{"timestamp":"2026-09-29 10:06:12","class":"general","event":"status","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"general_data":{"command":"Query","query":"SELECT * FROM `t`","status":0}}"#,
            r#"{"timestamp":"2026-09-29 10:06:12","class":"table_access","event":"read","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"table_access_data":{"db":"hr","table":"t","query":"SELECT * FROM `t`"}}"#,
            r#"{"timestamp":"2026-09-29 10:06:12","class":"general","event":"status","connection_id":22,"login":{"user":"root","ip":"10.1.2.3"},"general_data":{"command":"Query","query":"SELECT * FROM `t`","status":0}}"#,
        ];
        let recs: Vec<FileRecord> = recs
            .iter()
            .map(|r| parse_json(r.as_bytes()).unwrap())
            .collect();
        let mut b = EventBuilder::new(own());
        let ev = b.convert_file(recs, EventSource::MysqlAuditLog, SystemTime::now());
        let all: Vec<String> = ev.iter().map(show).collect();
        assert_eq!(all.len(), 3, "{all:#?}");
        assert_eq!(ev[0].principal().application(), Some("mysqldump"));
        for e in &ev[1..] {
            assert_eq!(e.principal().application(), Some("mysqldump"));
            assert!(e.signals().contains(&Signal::Mysqldump), "{}", show(e));
        }
    }

    #[test]
    fn session_patterns_without_the_program_name() {
        let q = |id: u64, text: &str| {
            format!(
                "20260929 09:40:35,h,backup,10.0.0.7,30,{id},QUERY,hr,'{}',0",
                text.replace('\'', "\\'")
            )
        };
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                &q(1, "select * from employees"),
                &q(2, "SHOW CREATE TABLE `settings`"),
                &q(3, "select * from `settings`"),
                &q(4, "START TRANSACTION /*!40100 WITH CONSISTENT SNAPSHOT */"),
                &q(5, "select id, email from bonus"),
                &q(6, "select * from bonus where id = 1"),
            ]),
        );
        assert_eq!(
            out,
            [
                "read [\"hr.employees\"] None [\"shape.full_table_read\"]",
                "read [\"hr.settings\"] None [\"shape.full_table_read\", \"signature.mysqldump\"]",
                "read [\"hr.bonus\"] None [\"shape.full_table_read\", \"signature.mysqldump\"]",
                "read [\"hr.bonus\"] None []",
            ],
            "{out:#?}"
        );
    }

    #[test]
    fn value_like_names_are_masked_and_times_clamped() {
        let mut b = EventBuilder::new(own());
        let future = SystemTime::now() + Duration::from_secs(3600);
        let ev = b.statement(
            Access {
                session: "t1".into(),
                user: "app",
                principal: EventPrincipal::account("app"),
                client: ClientSeen::Logged(None),
                application: None,
                database: "support",
                text: Some(b"select a from `escalations_jean.richard@example.com` where x = 1"),
                opaque: false,
                truncated: false,
                tables: Vec::new(),
                rows: Some(20_000),
                status: 0,
                ts: future,
                source: EventSource::PerformanceSchema,
            },
            SystemTime::now(),
        );
        let e = ev.unwrap();
        assert!(!show(&e).contains("jean"), "{}", show(&e));
        assert!(e.signals().contains(&Signal::LargeResult));
        assert!(e.ts() <= SystemTime::now());
    }

    #[test]
    fn ddl_and_dcl_take_no_name_from_text() {
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                r#"20260929 09:41:34,h,app,10.0.0.5,37,1,QUERY,support,'CREATE FUNCTION f() RETURNS TEXT LANGUAGE JAVASCRIPT AS $$ let s = "a\' from jane_doe x"; return s $$',0"#,
                r"20260929 09:41:34,h,app,10.0.0.5,37,2,QUERY,support,'create table t2 as select * from tickets',0",
            ]),
        );
        assert_eq!(out, ["ddl [] None []", "ddl [] None []"], "{out:#?}");
    }

    #[test]
    fn sessions_stay_bounded_across_connect_disconnect_cycles() {
        let mut b = EventBuilder::new(own());
        for c in 0..100_000u64 {
            let recs = sa(&[
                &format!("20260929 09:40:35,h,app,10.0.0.9,{c},0,CONNECT,shop,,0"),
                &format!("20260929 09:40:35,h,app,10.0.0.9,{c},0,DISCONNECT,shop,,0"),
            ]);
            b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now());
            let (map, order) = b.sessions.sizes();
            assert!(
                map <= MAX_SESSIONS && order <= 2 * MAX_SESSIONS,
                "{map} {order}"
            );
        }
        // Sessions that never disconnect are evicted oldest first.
        let mut s = Sessions::default();
        for c in 0..3 * MAX_SESSIONS {
            s.entry(&format!("t{c}")).snapshot = true;
            s.remove(&format!("t{}", c / 2));
            let (map, order) = s.sizes();
            assert!(
                map <= MAX_SESSIONS && order <= 2 * MAX_SESSIONS,
                "{map} {order}"
            );
        }
    }

    #[test]
    fn failed_statements_are_skipped_only_before_execution() {
        let q = |id: u64, text: &str, status: u32| {
            format!(
                "20260929 09:40:35,h,app,10.0.0.7,30,{id},QUERY,hr,'{}',{status}",
                text.replace('\'', "\\'")
            )
        };
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                // Unknown table, access denied, syntax: nothing was read.
                &q(1, "select * from nope", 1146),
                &q(2, "select * from employees", 1142),
                &q(3, "selec * from employees", 1064),
                // Killed or timed out while sending rows: reported.
                &q(4, "select email from employees where id > 0", 3024),
                &q(5, "select email from employees where id > 0", 1317),
                // A failed statement records no session state.
                &q(6, "SHOW CREATE TABLE `employees`", 1146),
                &q(7, "select * from employees", 0),
            ]),
        );
        assert_eq!(
            out,
            [
                "read [\"hr.employees\"] None []",
                "read [\"hr.employees\"] None []",
                "read [\"hr.employees\"] None [\"shape.full_table_read\"]",
            ],
            "{out:#?}"
        );
        assert_eq!(b.failed, 4);
        // performance_schema: rows were sent before the error, even an
        // access error: reported.
        let ev = b.statement(
            Access {
                session: "t9".into(),
                user: "app",
                principal: EventPrincipal::account("app"),
                client: ClientSeen::Logged(None),
                application: None,
                database: "hr",
                text: Some(b"select email from employees where id > 0"),
                opaque: false,
                truncated: false,
                tables: Vec::new(),
                rows: Some(99),
                status: 1142,
                ts: SystemTime::now(),
                source: EventSource::PerformanceSchema,
            },
            SystemTime::now(),
        );
        assert_eq!(ev.unwrap().rows(), Some(99));
    }

    #[test]
    fn failed_statements_with_read_records_are_reported() {
        // A function SIGNALs 1146 after rows were sent: the TABLE records
        // show what was read.
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa(&[
                "20260929 09:41:34,h,app,10.0.0.5,37,1,READ,hr,employees,",
                "20260929 09:41:34,h,app,10.0.0.5,37,1,QUERY,hr,'select email, leak() from employees',1146",
                // A genuine unknown table: no TABLE record, skipped.
                "20260929 09:41:34,h,app,10.0.0.5,37,2,QUERY,hr,'select * from nope',1146",
            ]),
        );
        assert_eq!(
            out,
            ["read [\"hr.employees\"] None [\"shape.full_table_read\"]"],
            "{out:#?}"
        );
        assert_eq!(b.failed, 1);
    }

    #[test]
    fn transcoded_texts_keep_non_ascii_names() {
        let mut b = EventBuilder::new(own());
        let text = "SELECT * FROM `hr` . `\u{5ba2}\u{6237}`";
        let access = |source| Access {
            session: "t1".into(),
            user: "app",
            principal: EventPrincipal::account("app"),
            client: ClientSeen::Logged(None),
            application: None,
            database: "hr",
            text: Some(text.as_bytes()),
            opaque: false,
            truncated: false,
            tables: Vec::new(),
            rows: Some(3),
            status: 0,
            ts: SystemTime::now(),
            source,
        };
        let ps = b
            .statement(access(EventSource::PerformanceSchema), SystemTime::now())
            .unwrap();
        assert!(
            ps.signals().contains(&Signal::FullTableRead),
            "{}",
            show(&ps)
        );
        assert!(!show(&ps).contains("hr.*"), "{}", show(&ps));
        // The same bytes from an audit log file: kind only, against `*`.
        let file_ev = b
            .statement(access(EventSource::MariadbServerAudit), SystemTime::now())
            .unwrap();
        assert!(show(&file_ev).contains("hr.*"), "{}", show(&file_ev));
        assert!(file_ev.signals().is_empty());
    }

    #[test]
    fn unreadable_texts_are_reported_against_a_wildcard() {
        let mut b = EventBuilder::new(own());
        // gbk trail byte 0x5c after 0xbf: the text keeps its kind only.
        let mut line = b"20260929 09:40:35,h,app,10.0.0.7,30,1,QUERY,hr,'select \\'\xbf\\\\\\' , 1 from t where x = \\' from payroll.S3cr3t \\'',0".to_vec();
        let recs = vec![parse_server_audit(&line, 0, 1024).unwrap()];
        let out = file(&mut b, recs);
        assert_eq!(out, ["read [\"hr.*\"] None []"], "{out:#?}");
        // An escape the format does not define: kept, against `*`.
        line = br"20260929 09:40:35,h,app,10.0.0.7,30,2,QUERY,hr,'SET @x = \q',0".to_vec();
        let r = parse_server_audit(&line, 0, 1024).unwrap();
        assert!(r.opaque);
        assert_eq!(file(&mut b, vec![r]), ["read [\"hr.*\"] None []"]);
    }

    fn rd(c: u64, q: u64, table: &str) -> String {
        format!("20260929 09:41:34,h,app,10.0.0.5,{c},{q},READ,shop,{table},")
    }

    fn qy(c: u64, q: u64, text: &str) -> String {
        format!("20260929 09:41:34,h,app,10.0.0.5,{c},{q},QUERY,shop,'{text}',0")
    }

    fn at(b: &mut EventBuilder, lines: &[String], mono: Instant) -> Vec<String> {
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        b.convert_file_at(
            sa(&refs),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
            mono,
        )
        .iter()
        .map(show)
        .collect()
    }

    #[test]
    fn interleaved_sessions_give_one_event_per_statement() {
        // What the load harness saw: concurrent sessions interleave the
        // TABLE and QUERY records of their statements.
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        let out = at(
            &mut b,
            &[
                rd(1, 10, "a"),
                rd(2, 11, "b"),
                rd(3, 12, "c"),
                rd(1, 10, "a2"),
                qy(2, 11, "select v from b where id = 1"),
                qy(1, 10, "select v from a join a2 using (id) where id = 1"),
                rd(2, 13, "b"),
                qy(3, 12, "select v from c where id = 1"),
                qy(2, 13, "select v from b where id = 2"),
                // Split by a poll bound or a rotation: the rest comes in
                // the next batch.
                rd(1, 14, "a"),
                rd(3, 15, "c"),
            ],
            t0,
        );
        assert_eq!(
            out,
            [
                "read [\"shop.b\"] None []",
                "read [\"shop.a\", \"shop.a2\"] None []",
                "read [\"shop.c\"] None []",
                "read [\"shop.b\"] None []",
            ],
            "{out:#?}"
        );
        let out = at(
            &mut b,
            &[
                qy(3, 15, "select v from c where id = 3"),
                qy(1, 14, "select v from a where id = 3"),
            ],
            t0,
        );
        assert_eq!(
            out,
            ["read [\"shop.c\"] None []", "read [\"shop.a\"] None []"],
            "{out:#?}"
        );
        assert_eq!(b.pending.sizes().0, 0);
    }

    #[test]
    fn pending_statements_end_with_their_connection_or_stream() {
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        // A statement whose source logs no QUERY record ends at the
        // connection's next statement, or at its disconnect.
        let out = at(
            &mut b,
            &[
                "20260929 09:41:34,h,app,10.0.0.5,1,20,WRITE,shop,a,".to_owned(),
                rd(2, 21, "b"),
                qy(1, 22, "select v from a where id = 1"),
                "20260929 09:41:34,h,app,10.0.0.5,2,0,DISCONNECT,shop,,0".to_owned(),
                rd(3, 23, "c"),
            ],
            t0,
        );
        assert_eq!(
            out,
            [
                "write [\"shop.a\"] None []",
                "read [\"shop.a\"] None []",
                "read [\"shop.b\"] None []",
            ],
            "{out:#?}"
        );
        // The stream ends: what is pending is reported.
        let out: Vec<String> = b
            .finish(EventSource::MariadbServerAudit, SystemTime::now())
            .iter()
            .map(show)
            .collect();
        assert_eq!(out, ["read [\"shop.c\"] None []"], "{out:#?}");
        assert_eq!(b.pending.sizes(), (0, 0, 0, 0));
    }

    /// Security review of #93, R4: a statement re-read after a restart is
    /// pending since its log time, not since it was read again, so an agent
    /// restarting more often than the timeout still flushes it on time and
    /// its cursor moves on.
    #[test]
    fn replayed_statements_are_pending_since_their_log_time() {
        let logged = |line: &str| {
            let mut r = parse_server_audit(line.as_bytes(), 0, 1024).unwrap();
            r.replayed = true;
            r
        };
        let ts = logged(&rd(1, 30, "a")).ts.unwrap();
        // Past the timeout 4 minutes ago: flushed at once.
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now() + PENDING_TIMEOUT;
        let out = b.convert_file_at(
            vec![logged(&rd(1, 30, "a"))],
            EventSource::MariadbServerAudit,
            ts + PENDING_TIMEOUT + Duration::from_secs(240),
            t0,
        );
        assert_eq!(
            out.iter().map(show).collect::<Vec<_>>(),
            ["read [\"shop.a\"] None []"]
        );
        assert!(b.held().is_empty());
        // Logged 100 s ago: flushed 200 s later, not after a full timeout.
        let run = |b: &mut EventBuilder, recs: Vec<FileRecord>, mono: Instant| {
            b.convert_file_at(
                recs,
                EventSource::MariadbServerAudit,
                ts + Duration::from_secs(100),
                mono,
            )
            .len()
        };
        let mut b = EventBuilder::new(own());
        assert_eq!(run(&mut b, vec![logged(&rd(1, 30, "a"))], t0), 0);
        let due = t0 + PENDING_TIMEOUT - Duration::from_secs(100);
        assert_eq!(run(&mut b, vec![], due - Duration::from_secs(1)), 0);
        assert_eq!(run(&mut b, vec![], due), 1);
        // A record read live (not replayed) keeps its reading time.
        let mut b = EventBuilder::new(own());
        let live = parse_server_audit(rd(1, 30, "a").as_bytes(), 0, 1024).unwrap();
        assert_eq!(run(&mut b, vec![live], t0), 0);
        assert_eq!(run(&mut b, vec![], due), 0);
        assert_eq!(run(&mut b, vec![], t0 + PENDING_TIMEOUT), 1);
    }

    #[test]
    fn timed_out_statements_are_not_counted_twice() {
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        assert!(at(&mut b, &[rd(1, 30, "a"), rd(2, 31, "big")], t0).is_empty());
        // Nothing yet just before the timeout.
        let early = t0 + PENDING_TIMEOUT - Duration::from_secs(1);
        assert!(at(&mut b, &[], early).is_empty());
        // At the timeout: reported from the table records.
        let out = at(&mut b, &[], t0 + PENDING_TIMEOUT);
        assert_eq!(
            out,
            ["read [\"shop.a\"] None []", "read [\"shop.big\"] None []"],
            "{out:#?}"
        );
        // The late QUERY records: no second event without a signal, one
        // with the signal the table records could not show.
        let late = t0 + PENDING_TIMEOUT * 2;
        let out = at(
            &mut b,
            &[
                rd(1, 30, "a"),
                qy(1, 30, "select v from a where id = 1"),
                qy(2, 31, "SELECT /*!40001 SQL_NO_CACHE */ * FROM big"),
            ],
            late,
        );
        assert_eq!(
            out,
            ["read [\"shop.big\"] None [\"shape.full_table_read\", \"signature.mysqldump\"]"],
            "{out:#?}"
        );
        // The connections moved on: their next statements are reported.
        let out = at(
            &mut b,
            &[rd(1, 32, "a"), qy(1, 32, "select v from a where id = 2")],
            late,
        );
        assert_eq!(out, ["read [\"shop.a\"] None []"], "{out:#?}");
        assert_eq!(b.pending.sizes(), (0, 0, 0, 0));
    }

    /// Security review of #93 (M2): after an early flush, a table the
    /// statement reads later is reported, never dropped.
    #[test]
    fn late_tables_of_an_early_flushed_statement_are_reported() {
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        assert!(at(&mut b, &[rd(1, 40, "harmless")], t0).is_empty());
        let t1 = t0 + PENDING_TIMEOUT;
        let out = at(&mut b, &[], t1);
        assert_eq!(out, ["read [\"shop.harmless\"] None []"], "{out:#?}");
        // The procedure goes on: the same table again (ignored), then
        // another one, then its statement record.
        let out = at(
            &mut b,
            &[
                rd(1, 40, "harmless"),
                rd(1, 40, "salaries"),
                qy(1, 40, "call report()"),
            ],
            t1,
        );
        assert_eq!(out, ["read [\"shop.salaries\"] None []"], "{out:#?}");
        // A continuation that times out too is reported, and remembered
        // with every table so far.
        assert!(at(&mut b, &[rd(2, 41, "a")], t1).is_empty());
        let t2 = t1 + PENDING_TIMEOUT;
        assert_eq!(at(&mut b, &[], t2), ["read [\"shop.a\"] None []"]);
        assert!(at(&mut b, &[rd(2, 41, "b")], t2).is_empty());
        let t3 = t2 + PENDING_TIMEOUT;
        assert_eq!(at(&mut b, &[], t3), ["read [\"shop.b\"] None []"]);
        let out = at(
            &mut b,
            &[
                rd(2, 41, "a"),
                rd(2, 41, "b"),
                qy(2, 41, "select v from a join b using (id) where id = 1"),
            ],
            t3,
        );
        assert!(out.is_empty(), "{out:#?}");
        assert_eq!(b.pending.sizes(), (0, 0, 0, 0));
    }

    #[test]
    fn early_flushed_statements_are_forgotten_after_their_ttl() {
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        assert!(at(&mut b, &[rd(1, 50, "a")], t0).is_empty());
        assert_eq!(at(&mut b, &[], t0 + PENDING_TIMEOUT).len(), 1);
        assert_eq!(b.pending.sizes().3, 1);
        let late = t0 + PENDING_TIMEOUT + REPORTED_TTL;
        assert!(at(&mut b, &[], late).is_empty());
        assert_eq!(b.pending.sizes().3, 0);
        // A record after that is a statement of its own.
        assert_eq!(
            at(&mut b, &[qy(1, 50, "select v from a where id = 1")], late),
            ["read [\"shop.a\"] None []"]
        );
    }

    #[test]
    fn pending_state_stays_bounded_and_counts_exactly() {
        let mut b = EventBuilder::new(own());
        let t0 = Instant::now();
        let n = 3 * MAX_PENDING_CONNECTIONS as u64;
        // Many sessions open a statement each before any ends.
        let mut reported = 0usize;
        for c in 0..n {
            reported += at(&mut b, &[rd(c + 1, c + 1, "a")], t0).len();
            let (conns, _, _, done) = b.pending.sizes();
            assert!(conns <= MAX_PENDING_CONNECTIONS, "{conns}");
            assert!(done <= MAX_EARLY_REPORTED, "{done}");
        }
        assert_eq!(b.pending_evicted(), n - MAX_PENDING_CONNECTIONS as u64);
        // Then every statement ends: each is counted once in all.
        for c in 0..n {
            reported += at(
                &mut b,
                &[qy(c + 1, c + 1, "select v from a where id = 1")],
                t0,
            )
            .len();
        }
        assert_eq!(reported as u64, n);
        // One statement touching many tables keeps a bounded record list.
        let lines: Vec<String> = (0..4 * MAX_PENDING_RECORDS)
            .map(|i| rd(1, 999_999, &format!("t{i}")))
            .collect();
        assert!(at(&mut b, &lines, t0).is_empty());
        assert_eq!(b.pending.sizes().1, MAX_PENDING_RECORDS);
        // JSON table_access records carry the text: bounded in bytes.
        let text = "x".repeat(900 * 1024);
        let mut b = EventBuilder::new(own());
        for c in 0..64u64 {
            let rec = format!(
                r#"{{"timestamp":"2026-09-29 10:06:12","class":"table_access","event":"read","connection_id":{c},"login":{{"user":"app","ip":"10.1.2.3"}},"table_access_data":{{"db":"hr","table":"t","query":"select {text} from t"}}}}"#
            );
            let recs = vec![parse_json(rec.as_bytes()).unwrap()];
            b.convert_file_at(recs, EventSource::MysqlAuditLog, SystemTime::now(), t0);
            assert!(b.pending.sizes().2 <= MAX_PENDING_BYTES);
        }
    }

    #[test]
    fn dump_programs() {
        for p in [
            "mysqldump",
            "/usr/bin/mariadb-dump",
            "MYSQLDUMP.EXE",
            "mydumper",
        ] {
            assert!(is_dump_program(p), "{p}");
        }
        assert!(!is_dump_program("mysql"));
        assert!(!is_dump_program("databastion-agent"));
    }
}
