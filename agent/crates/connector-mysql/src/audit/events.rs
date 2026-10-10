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
//! `performance_schema`, `sys`, `DUAL` and the internal statistics tables
//! (`mysql.*_stats`) are skipped from the objects of reads only: a write
//! names them (`UPDATE performance_schema.setup_consumers …` turns the
//! `performance_schema` source off), and so does a table record that
//! writes a system schema table, whatever the statement's action. The
//! `mysql` schema is kept for reads and writes (reading `mysql.user` is an
//! access worth reporting). Server configuration changes (`SET GLOBAL` /
//! `PERSIST`, `INSTALL` / `UNINSTALL`, `TRUNCATE`) are DDL events. A
//! text that only kept its kind (opaque, ambiguous readings, not
//! lexable) is reported against `*` with the most reportable kind of its
//! readings; code that runs out of sight (`CALL`, `EXECUTE`, `PREPARE`, a
//! schema-qualified function call, an unqualified call of a name that is
//! not built in on the server's series: `crate::builtins`, ADR-0045 part
//! (b)) adds `*`. A text with several
//! statements takes the action of its most reportable one. A statement
//! that writes or changes something, runs code out of sight or cannot be
//! read is never left out as the agent's own (I4), unless table records
//! that all read decide for an unreadable text. Changes that touch a
//! system schema, configuration DDL (audit log administration functions
//! included), code out of sight and unreadable texts are marked always
//! reported (never dropped by `min_rows`). Read signals are computed per
//! read statement, whatever the event's action. A read or write whose objects cannot be told
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
    most_reportable,
};
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::audit::tail::RecordPos;

use super::records::{FileRecord, Op, TableOp};
use crate::builtins::BuiltinList;
use crate::conn::Flavor;
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

/// Analysis options of a text, with the names built in on every listed
/// server (an event builder uses its server's list instead).
fn analyze_opts(truncated: bool) -> AnalyzeOptions {
    let mut o = AnalyzeOptions::mysql()
        .truncated(truncated)
        .builtins(crate::builtins::any_server());
    o.large_limit = LARGE_LIMIT + 1;
    o
}

/// The server's own schemas: dictionary views (`information_schema`),
/// instrumentation (`performance_schema`) and its helper views (`sys`).
/// They hold no application rows, but they are not harmless:
/// `performance_schema` holds other sessions' statement texts (literals
/// included on `SQL_TEXT`, clear-text passwords on MariaDB) and its setup
/// tables drive the `performance_schema` Audit source. Reads of them are
/// not reported; writes are (see [`EventBuilder::statement`]).
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
/// `DUAL`. Skipped from the objects of reads only.
fn is_system_relation(r: &RelationName, database: &str) -> bool {
    let db = r.schema.as_deref().unwrap_or(database);
    is_system_schema(db)
        || is_internal_table(db, &r.name)
        || (r.schema.is_none() && r.name.eq_ignore_ascii_case("dual"))
}

/// Where a statement-text table holds statement text (ADR-0045 decision
/// 1): on both flavors, or on MySQL only (`events_statements_summary_by_digest`
/// holds digests only on MariaDB). A table that one flavor does not have
/// is still listed for both: the flavor comes from the server's version
/// string, which a proxy can rewrite (security review of #186, L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextOn {
    Both,
    Mysql,
}

/// The system tables that hold other sessions' statement texts with their
/// literal values, or the values of locked index records (ADR-0045
/// decision 1, with the maintainer's answer to its open question 1):
/// (schema, table, flavor), with their names as the servers list them.
/// The same on MySQL 8.0.46, 8.4.11 and 9.7.2 and on MariaDB 10.11.19,
/// 11.4.13 and 11.8.9 (the engine matrix), checked by the drift test
/// (`it::stmt_text_it`). Tables holding digests only (`DIGEST_TEXT`, and
/// `events_statements_summary_by_digest` on MariaDB, which has no
/// `QUERY_SAMPLE_TEXT`), the other summaries, the `setup_*` tables and the
/// dictionary views are not listed.
pub(crate) const STATEMENT_TEXT_TABLES: &[(&str, &str, TextOn)] = &[
    // `SQL_TEXT` (literals; MariaDB: clear-text passwords).
    (
        "performance_schema",
        "events_statements_current",
        TextOn::Both,
    ),
    (
        "performance_schema",
        "events_statements_history",
        TextOn::Both,
    ),
    (
        "performance_schema",
        "events_statements_history_long",
        TextOn::Both,
    ),
    // `QUERY_SAMPLE_TEXT` (MySQL 8.0.3+).
    (
        "performance_schema",
        "events_statements_summary_by_digest",
        TextOn::Mysql,
    ),
    // `SQL_TEXT` of prepared statements (MariaDB 10.5+).
    (
        "performance_schema",
        "prepared_statements_instances",
        TextOn::Both,
    ),
    // `PROCESSLIST_INFO`.
    ("performance_schema", "threads", TextOn::Both),
    // `INFO` (MySQL 8.0.22+).
    ("performance_schema", "processlist", TextOn::Both),
    // `LOCK_DATA`: values of locked index records (MySQL 8.0+).
    ("performance_schema", "data_locks", TextOn::Both),
    // `VARIABLE_VALUE`: other sessions' user variables, which can hold
    // values read from tables (`SET @x = (SELECT …)`).
    (
        "performance_schema",
        "user_variables_by_thread",
        TextOn::Both,
    ),
    // `INFO` (and `INFO_BINARY` on MariaDB).
    ("information_schema", "PROCESSLIST", TextOn::Both),
    // `WORD`: words of the rows of the table set in the global
    // `innodb_ft_aux_table` (its full-text index).
    ("information_schema", "INNODB_FT_INDEX_TABLE", TextOn::Both),
    ("information_schema", "INNODB_FT_INDEX_CACHE", TextOn::Both),
    // `trx_query`.
    ("information_schema", "INNODB_TRX", TextOn::Both),
    // `lock_data` (MariaDB; MySQL 8.0 removed the table).
    ("information_schema", "INNODB_LOCKS", TextOn::Both),
    // `STATEMENT_TEXT` (the `query_cache_info` plugin, when loaded).
    ("information_schema", "QUERY_CACHE_INFO", TextOn::Both),
    // `current_statement`, `last_statement` (MariaDB: `sys` since 10.6).
    ("sys", "processlist", TextOn::Both),
    ("sys", "x$processlist", TextOn::Both),
    ("sys", "session", TextOn::Both),
    ("sys", "x$session", TextOn::Both),
    // `waiting_query`, `blocking_query`.
    ("sys", "innodb_lock_waits", TextOn::Both),
    ("sys", "x$innodb_lock_waits", TextOn::Both),
    ("sys", "schema_table_lock_waits", TextOn::Both),
    ("sys", "x$schema_table_lock_waits", TextOn::Both),
];

/// The statement-text table `db`.`table` is, as listed (compared
/// ASCII-case-insensitively), for the server's flavor (`None`, unknown:
/// every listed table, fail closed).
pub(crate) fn statement_text_table(
    flavor: Option<Flavor>,
    db: &str,
    table: &str,
) -> Option<(&'static str, &'static str)> {
    STATEMENT_TEXT_TABLES
        .iter()
        .find(|(d, t, on)| {
            let here = match (on, flavor) {
                (TextOn::Both, _) | (_, None) => true,
                (TextOn::Mysql, Some(f)) => f == Flavor::Mysql,
            };
            here && d.eq_ignore_ascii_case(db) && t.eq_ignore_ascii_case(table)
        })
        .map(|(d, t, _)| (*d, *t))
}

/// A `USE` with another statement in one text, in either order (security
/// review of #186, M1): unqualified names after it resolve in the database
/// it sets, and the database a source logs for the whole text may be the
/// one before or after it, so the objects cannot be told (`USE
/// performance_schema; SELECT SQL_TEXT FROM events_statements_history_long`).
/// Fails closed like a hidden read. (MariaDB 11.4 `server_audit` and the
/// Percona 8.4 `audit_log_filter` log each statement of a multi-statement
/// packet as its own record, with the database current at it on
/// `server_audit`; this is for sources or clients that do not.)
fn use_then(x: &QueryAnalysis) -> bool {
    x.statements() > 1
        && x.parts()
            .iter()
            .any(|p| p.lead.first().map(String::as_str) == Some("use"))
}

/// Whether an object resolved in an unknown database (`db` empty: an
/// unqualified name on a source that logs no current database, the
/// `audit_log_filter` JSON general records) may be a statement-text table:
/// its name is a listed table's name in any schema (`USE
/// performance_schema` in an earlier record, or a connect database, then
/// `SELECT … FROM events_statements_history_long`). It keeps the name the
/// source shows (`processlist` is in three schemas), and is marked like a
/// listed table: always reported, never the agent's own.
fn unresolved_text_table(flavor: Option<Flavor>, db: &str, table: &str) -> bool {
    db.is_empty()
        && STATEMENT_TEXT_TABLES.iter().any(|(d, t, _)| {
            t.eq_ignore_ascii_case(table) && statement_text_table(flavor, d, t).is_some()
        })
}

/// `SHOW [FULL] PROCESSLIST`: a read of `information_schema.PROCESSLIST`
/// (ADR-0045 decision 2), whatever the server reads it from.
fn is_show_processlist(p: &StatementInfo) -> bool {
    let lead: Vec<&str> = p.lead.iter().map(String::as_str).collect();
    matches!(
        lead.as_slice(),
        ["show", "processlist", ..] | ["show", "full", "processlist", ..]
    )
}

/// A statement that shows other sessions' statement texts without naming
/// a table (ADR-0045 open question 3, as answered): `SHOW ENGINE INNODB
/// STATUS` (its transaction and deadlock sections; any `SHOW ENGINE` but
/// `PERFORMANCE_SCHEMA STATUS` and `… MUTEX`, fail closed), and the plan
/// of another connection's statement (`SHOW EXPLAIN` / `SHOW ANALYZE …
/// FOR`, `EXPLAIN … FOR CONNECTION`: its text, verified on MariaDB 11.4,
/// and its literals in MySQL 8.4's `FORMAT=TREE`), and the statements of
/// the binary and relay logs (`SHOW BINLOG EVENTS`, `SHOW RELAYLOG EVENTS`:
/// security review of #186, M3). A read of `*`, always reported, never the
/// agent's own.
fn shows_session_text(p: &StatementInfo) -> bool {
    let lead: Vec<&str> = p.lead.iter().map(String::as_str).collect();
    let engine = match lead.as_slice() {
        ["show", "engine", "performance_schema", "status", ..]
        | ["show", "engine", _, "mutex", ..] => false,
        ["show", "engine", ..]
        | ["show", "innodb", "status", ..]
        | ["show", "binlog" | "relaylog", "events", ..] => true,
        _ => false,
    };
    engine || p.explain_connection
}

/// The tables behind the audit log administration functions (MySQL
/// Enterprise Audit and the Percona `audit_log_filter` component):
/// `mysql.audit_log_filter` and `mysql.audit_log_user`. Writing them
/// changes what the audit log records.
fn is_audit_table(db: &str, table: &str) -> bool {
    db.eq_ignore_ascii_case("mysql")
        && ["audit_log_filter", "audit_log_user"]
            .iter()
            .any(|t| t.eq_ignore_ascii_case(table))
}

/// The closed allow-list of statements of no known kind that produce no
/// event: they can neither read nor change data, and hold no subquery nor
/// `LOAD_FILE` call. Session `SET` without a table, a schema-qualified
/// function call or `LOAD_FILE` (`SET NAMES`,
/// `SET CHARACTER SET`, `SET TRANSACTION`, `SET autocommit = 1`…), `USE`,
/// `BEGIN` (not `BEGIN NOT ATOMIC`), `START TRANSACTION`, `COMMIT`,
/// `ROLLBACK`, `SAVEPOINT`, `RELEASE`, `SHOW`, `EXPLAIN` / `DESCRIBE` /
/// `DESC` without `ANALYZE` (and with its statement within the prefix
/// bound), `LOCK` / `UNLOCK TABLES`, `FLUSH`, `ANALYZE`
/// / `OPTIMIZE` / `CHECK` / `CHECKSUM` / `REPAIR TABLE`, `KILL`,
/// `DEALLOCATE PREPARE`.
pub(crate) fn is_quiet(p: &StatementInfo) -> bool {
    if p.subquery
        || p.compound
        || p.analyze_wrapped
        || p.audit_function
        || p.file_read
        || p.unknown_call
        || p.explain_unbounded
    {
        return false;
    }
    let lead: Vec<&str> = p.lead.iter().map(String::as_str).collect();
    let table_word = |w: Option<&&str>| matches!(w.copied(), Some("table" | "tables"));
    match lead.as_slice() {
        // Built-in calls are fine (`SET sql_mode = CONCAT(@@sql_mode, …)`,
        // sent by Connector/J on every pooled connection); a
        // schema-qualified (stored) function is not, nor an unknown call,
        // an audit function or `LOAD_FILE` (excluded above).
        ["set", ..] => !p.routine_call && p.relations.is_empty(),
        ["begin"] | ["begin", "work"] => true,
        ["start", "transaction", ..]
        | [
            "commit" | "rollback" | "savepoint" | "release" | "use" | "kill" | "flush",
            ..,
        ]
        | ["show" | "explain" | "describe" | "desc", ..]
        | ["lock" | "unlock", "table" | "tables", ..]
        | ["deallocate", "prepare", ..] => true,
        [
            "analyze" | "optimize" | "check" | "checksum" | "repair",
            rest @ ..,
        ] => {
            table_word(rest.first())
                || (matches!(rest.first().copied(), Some("no_write_to_binlog" | "local"))
                    && table_word(rest.get(1)))
        }
        _ => false,
    }
}

/// A statement kind that changes something: rows, schema or privileges.
fn is_change_kind(k: StatementKind) -> bool {
    is_write_kind(k) || matches!(k, StatementKind::Ddl | StatementKind::Dcl)
}

/// A statement kind that writes rows.
fn is_write_kind(k: StatementKind) -> bool {
    matches!(
        k,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
    )
}

/// `DUAL`, unqualified: no table at all.
fn is_dual(r: &RelationName) -> bool {
    r.schema.is_none() && r.name.eq_ignore_ascii_case("dual")
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

/// The connector's own `performance_schema` statements, as bytes (see
/// [`EventBuilder::own_ps_read`]).
static OWN_PS_READS: std::sync::LazyLock<Vec<(Vec<u8>, Vec<&'static str>)>> =
    std::sync::LazyLock::new(|| {
        crate::sql::own_performance_schema_reads()
            .into_iter()
            .map(|(t, tables)| (t.into_bytes(), tables))
            .collect()
    });

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
    /// A second whole text of the same statement (`performance_schema`:
    /// the digest next to an uncut `SQL_TEXT`), analyzed too: the event
    /// takes the objects and signals of both (security review of 09e93da,
    /// R1). The agent's exact-text matches use `text` only.
    pub(crate) alt_text: Option<&'a [u8]>,
    /// `text` is a `performance_schema` digest (`alt_text` always is):
    /// read with `AnalyzeOptions::digest`.
    pub(crate) digest: bool,
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
    /// Exact texts of the statements the connector itself sends that read
    /// no relation but `information_schema.TABLES` names and
    /// `information_schema.COLUMNS` (the CAS store guard's table list and
    /// column queries, ADR-0041 decision 6, each short enough never to be
    /// cut at the default log limits): recognized by their whole text and
    /// left out without a charge (see [`Self::own_statement`]).
    own_statements: Vec<Vec<u8>>,
    /// Credits for the extra sampling statements of Discovery (see
    /// [`Self::own_batch`]).
    credits: Option<super::credits::SharedCredits>,
    /// The server's flavor, which decides a few statement-text tables
    /// ([`statement_text_table`]; `None`: every listed table).
    flavor: Option<Flavor>,
    /// The server's built-in function names (ADR-0045 decision 8; until
    /// set, the names built in on every listed server).
    builtins: &'static BuiltinList,
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
            own_statements: Vec::new(),
            credits: None,
            flavor: None,
            builtins: crate::builtins::any_server(),
            sessions: Sessions::default(),
            pending: Pending::default(),
            panicked: 0,
            failed: 0,
        }
    }

    /// The connector's own statements of this target (exact texts, as
    /// sent): see [`Self::own_statement`].
    #[must_use]
    pub(crate) fn with_own_statements(mut self, texts: Vec<Vec<u8>>) -> Self {
        self.own_statements = texts;
        self
    }

    /// The server's flavor (see [`statement_text_table`]).
    #[must_use]
    pub(crate) fn with_flavor(mut self, flavor: Flavor) -> Self {
        self.flavor = Some(flavor);
        self
    }

    /// The server's built-in function names (`crate::builtins::for_server`).
    #[must_use]
    pub(crate) fn with_builtins(mut self, builtins: &'static BuiltinList) -> Self {
        self.builtins = builtins;
        self
    }

    /// The target's Discovery sampling credits (`audit::credits`).
    #[must_use]
    pub(crate) fn with_sample_credits(mut self, credits: super::credits::SharedCredits) -> Self {
        self.credits = Some(credits);
        self
    }

    /// An extra sampling statement of a Discovery scan (security review
    /// of 914c9d2, N3): its exact, uncut text holds a live credit, its
    /// table records (if any) only read the credit's table, and the
    /// identity is the agent's. The credit is consumed; the statement is
    /// left out without a charge (the table's first batch was charged).
    fn own_batch(&self, a: &Access<'_>, now: SystemTime) -> bool {
        let (Some(credits), Some(text)) = (&self.credits, a.text) else {
            return false;
        };
        if a.truncated || a.opaque || a.tables.iter().any(|t| t.2 != TableOp::Read) {
            return false;
        }
        let mono = Instant::now();
        let mut c = credits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((schema, table)) = c.peek(text, mono) else {
            return false;
        };
        if !a
            .tables
            .iter()
            .all(|(db, t, _)| db.eq_ignore_ascii_case(&schema) && t.eq_ignore_ascii_case(&table))
        {
            return false;
        }
        let e = MaskedEvent::new(
            a.source,
            EventAction::Read,
            a.principal.clone(),
            a.ts.min(now),
        )
        .with_object(object(&schema, &table));
        if !self
            .own
            .routine_unbudgeted(a.user, a.application, a.client, &e)
        {
            return false;
        }
        c.take(text, mono)
    }

    /// Whether a statement record is one of the connector's own statements
    /// (text only; the caller checks the account, the application, the
    /// address and the tables): its decoded text (`server_audit` escapes
    /// undone by `records::parse_server_audit`, the JSON string of the
    /// `audit_log` file, `performance_schema`'s `SQL_TEXT`) is **equal** to
    /// one of them, and the record is **not** marked truncated. A cut text
    /// proves nothing about what followed the cut: it is never matched
    /// (security review of f9bab99, H1). A `DIGEST_TEXT` never matches
    /// (its literals are replaced), nor does an opaque text.
    fn own_statement(&self, text: &[u8], truncated: bool, opaque: bool) -> bool {
        !truncated && !opaque && self.own_statements.iter().any(|g| text == g.as_slice())
    }

    /// The text and table conditions of an own guard statement (the
    /// identity conditions are `OwnAccount::routine_unbudgeted`'s).
    fn own_guard(&self, a: &Access<'_>) -> bool {
        a.text
            .is_some_and(|t| self.own_statement(t, a.truncated, a.opaque))
            && a.tables.iter().all(|(db, table, op)| {
                *op == TableOp::Read
                    && db.eq_ignore_ascii_case("information_schema")
                    && statement_text_table(None, db, table).is_none()
            })
    }

    /// One of the connector's own `performance_schema` statements
    /// (ADR-0045 decision 4; the identity conditions are
    /// `OwnAccount::routine_unbudgeted`'s): its whole text is **equal** to
    /// one of the constant texts of `sql::own_performance_schema_reads`,
    /// the record is not marked cut (nor opaque), and its table records
    /// (if any) read only the tables that text names. Never matched by
    /// prefix, digest or shape: a `DIGEST_TEXT` never equals these texts.
    fn own_ps_read(a: &Access<'_>) -> bool {
        let Some(text) = a.text else {
            return false;
        };
        if a.truncated || a.opaque {
            return false;
        }
        OWN_PS_READS.iter().any(|(t, tables)| {
            text == t.as_slice()
                && a.tables.iter().all(|(db, table, op)| {
                    *op == TableOp::Read
                        && db.eq_ignore_ascii_case("performance_schema")
                        && tables.iter().any(|x| x.eq_ignore_ascii_case(table))
                })
        })
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
        // The connector's own guard statements, by their exact whole text:
        // they read `information_schema.TABLES` / `.COLUMNS` only. Left out without a
        // charge when the account, application and address are the agent's,
        // every table record (if any) is in `information_schema` (not
        // `performance_schema` nor `sys`: security review of f9bab99, M1),
        // and no signal applies. Anything else takes the usual path.
        if self.own_guard(&a) {
            let e = MaskedEvent::new(
                a.source,
                EventAction::Read,
                a.principal.clone(),
                a.ts.min(now),
            )
            .with_object(unknown_object(a.database));
            if self
                .own
                .routine_unbudgeted(a.user, a.application, a.client, &e)
            {
                return None;
            }
        }
        if self.own_batch(&a, now) {
            return None;
        }
        // The connector's own `performance_schema` probes and polls, by
        // their exact whole text (ADR-0045 decision 4): left out without
        // a charge when the identity is the agent's and no signal applies.
        if Self::own_ps_read(&a) {
            let e = MaskedEvent::new(
                a.source,
                EventAction::Read,
                a.principal.clone(),
                a.ts.min(now),
            )
            .with_object(object("performance_schema", "*"));
            if self
                .own
                .routine_unbudgeted(a.user, a.application, a.client, &e)
            {
                return None;
            }
        }
        let opaque = a.opaque || a.text.is_some_and(|t| std::str::from_utf8(t).is_err());
        // performance_schema texts come transcoded to utf8mb4 by the
        // server: the multibyte trail-byte guard is for raw client bytes
        // (audit log files) only.
        let transcoded = a.source == EventSource::PerformanceSchema;
        let analysis: Option<QueryAnalysis> = a.text.map(|t| {
            analyze_raw(
                t,
                analyze_opts(a.truncated)
                    .opaque(a.opaque)
                    .transcoded(transcoded)
                    .builtins(self.builtins)
                    .digest(a.digest),
            )
        });
        // A second whole text of the statement (the digest next to an
        // uncut `SQL_TEXT`): its statements are analyzed with the first
        // one's, so the event takes the objects and signals of both
        // (security review of 09e93da, R1).
        let alt_analysis: Option<QueryAnalysis> = a.alt_text.map(|t| {
            analyze_raw(
                t,
                analyze_opts(false)
                    .transcoded(transcoded)
                    .builtins(self.builtins)
                    .digest(true),
            )
        });
        let joined: Vec<StatementInfo>;
        let parts: &[StatementInfo] = match &alt_analysis {
            None => analysis.as_ref().map_or(&[], QueryAnalysis::parts),
            Some(alt) => {
                joined = analysis
                    .as_ref()
                    .map_or(&[][..], QueryAnalysis::parts)
                    .iter()
                    .chain(alt.parts())
                    .cloned()
                    .collect();
                &joined
            }
        };
        let parsed = !parts.is_empty();
        // A text that only kept its kind (opaque, ambiguous under the
        // possible `sql_mode` / version-comment readings, or not lexable):
        // what it touched cannot be told (fail closed). A second text that
        // does not lex makes the statement unparsed too.
        let unparsed = opaque
            || a.text.is_some() && !analysis.as_ref().is_some_and(QueryAnalysis::lexed)
            || alt_analysis.as_ref().is_some_and(|x| !x.lexed());
        // A text cut by the source (`server_audit_query_log_limit`,
        // `performance_schema_max_sql_text_length`, a full digest): what
        // followed the cut cannot be told (whitespace, comment or token
        // padding before a `UNION`, a subquery, a second statement, a
        // `LOAD_FILE` call). Fail closed whatever its table records: never
        // quiet, never the agent's own, a read or write of what the records
        // or the visible part name and of `*`, always reported (security
        // review of #181, H1; of #184, M1: table records do not name the
        // server file a `LOAD_FILE` past the cut read). The agent keeps
        // its own statements under the default limits
        // (`sql::MAX_OWN_STATEMENT`).
        let cut_blind = a.truncated;
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
        let table_action = if a.tables.iter().any(|t| t.2 == TableOp::Read) {
            Some(EventAction::Read)
        } else if a.tables.iter().any(|t| t.2 == TableOp::Write) {
            Some(EventAction::Write)
        } else if a.tables.iter().any(|t| t.2 == TableOp::Ddl) {
            Some(EventAction::Ddl)
        } else {
            None
        };
        // The most reportable statement of a multi-statement text
        // (`SET @a = 1; UPDATE performance_schema.setup_consumers …`).
        let kind = if parsed {
            parts
                .iter()
                .fold(StatementKind::Other, |k, p| most_reportable(k, p.kind))
        } else {
            analysis
                .iter()
                .chain(&alt_analysis)
                .fold(StatementKind::Other, |k, x| most_reportable(k, x.kind()))
        };
        // A `LOAD_FILE` call (#168 review L2) or a server-side `LOAD DATA
        // INFILE` / `LOAD XML INFILE` (#184 review L2), a call of a name
        // holding a non-ASCII character (#184 review M2: never a built-in
        // function), each in a lexed statement or found by a raw scan of a
        // text that did not lex, and an `EXPLAIN` whose statement is past
        // the prefix bound (#168 review L3): what they read (a server
        // file, a statement that may run) is named by no audit source, so
        // the event adds `*` whatever its table records. So does an
        // unqualified call of a name that is not a built-in function of the
        // server's series (ADR-0045 decisions 8 to 10): a stored function
        // of the default database or a loadable function, whose reads no
        // statement text names; the routine's name is never an object.
        // A statement that shows other sessions' statement texts without
        // naming a table (`SHOW ENGINE INNODB STATUS`, `SHOW EXPLAIN FOR`,
        // `EXPLAIN FOR CONNECTION`; ADR-0045 open question 3) is handled
        // the same way: a read of `*`, always reported, never the agent's
        // own.
        //
        // The analysis keeps at most 16 relations per statement and 64
        // statements per text: a statement at the relation bound, or a
        // text with more statements than were analyzed, may name a table
        // that was not kept (a statement-text table after 16 others). It
        // fails closed the same way (ADR-0045 decisions 3 and 4).
        let hidden = parts.iter().any(|p| {
            p.file_read
                || p.non_ascii_call
                || p.unknown_call
                || p.explain_unbounded
                || p.relations_full
                || shows_session_text(p)
        }) || analysis
            .iter()
            .chain(&alt_analysis)
            .any(|x| x.lexed() && (x.statements() > x.parts().len() || use_then(x)))
            || analysis
                .iter()
                .chain(&alt_analysis)
                .any(|x| x.file_read() || x.non_ascii_call() || x.unknown_call());
        // Code that runs out of sight: a procedure, a prepared statement,
        // a stored function (schema-qualified, or an unqualified call of a
        // name that is not built in on the server, above: ADR-0045 part
        // (b)), `LOAD_FILE` and an unbounded `EXPLAIN` (above).
        // A `"…"` name (`ANSI_QUOTES`) hides the objects the same way.
        let call = hidden
            || parts.iter().any(|p| {
                p.routine_call
                    || p.dquoted_name
                    || p.compound
                    || matches!(
                        p.lead.first().map(String::as_str),
                        Some("call" | "execute" | "prepare")
                    )
            });
        // The statement changed something, or may have, whatever its
        // reported action (a `CALL` whose table records write, a write
        // after a read in a multi-statement text, code that runs out of
        // sight, a text that cannot be read): the agent only reads (I4)
        // and never sends these, so such a statement with its identity is
        // never left out as its own.
        //
        // An unreadable text with table records that all read (a name
        // ending in a non-ASCII character before a backtick trips the
        // multibyte rule) is decided by its records: they name what it
        // read.
        // A raw scan of an unreadable text that finds an audit log
        // administration function or `LOAD_FILE` makes it blind whatever
        // its records (fail closed).
        let audit_function = analysis
            .iter()
            .chain(&alt_analysis)
            .any(QueryAnalysis::audit_function);
        let blind = unparsed
            && (a.tables.is_empty()
                || a.tables.iter().any(|t| t.2 != TableOp::Read)
                || audit_function
                || hidden);
        // Backstop for `"…"` names the positions above miss: a read or a
        // write holding any `"…"` token adds `*` and is never the agent's
        // own (the agent never sends `"`), but is not marked always
        // reported (double-quoted string literals are common).
        let dquoted = parts.iter().any(|p| {
            p.dquoted
                && (is_write_kind(p.kind)
                    || matches!(
                        p.kind,
                        StatementKind::Select
                            | StatementKind::Table
                            | StatementKind::Values
                            | StatementKind::Handler
                    ))
        });
        // Fail closed for statements of no known kind: one produces no
        // event only when it is on a closed allow-list of statements that
        // can neither read nor change data ([`is_quiet`]). Any other
        // (`DO`, `SET @x = (SELECT …)`, `XA`, a utility statement with a
        // subquery…) is a read, of the tables it names or of `*`, and
        // never the agent's own (its own statements are all on the list
        // or recognized reads).
        let loud_other = parts
            .iter()
            .any(|p| p.kind == StatementKind::Other && !is_quiet(p));
        // `ANALYZE` / `EXPLAIN ANALYZE` run their statement; the agent
        // never sends them.
        let analyze_wrapped = parts.iter().any(|p| p.analyze_wrapped);
        // `SHOW [FULL] PROCESSLIST`: a read of
        // `information_schema.PROCESSLIST` (ADR-0045 decision 2).
        let processlist = parts.iter().any(is_show_processlist);
        let changes = is_change_kind(kind)
            || parts.iter().any(|p| is_change_kind(p.kind))
            || call
            || dquoted
            || loud_other
            || analyze_wrapped
            || blind
            || cut_blind
            || a.tables
                .iter()
                .any(|(db, table, op)| *op != TableOp::Read && !is_internal_table(db, table));
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
            _ if call || processlist => EventAction::Read,
            _ => match (table_action, unparsed) {
                (Some(t), _) => t,
                // A text that cannot be read: reported against `*`.
                (None, true) => EventAction::Read,
                (None, false) if loud_other || cut_blind => EventAction::Read,
                (None, false) => return None,
            },
        };
        let rw = matches!(action, EventAction::Read | EventAction::Write);
        let write = action == EventAction::Write;
        let mut objects: Vec<(String, String)> = Vec::new();
        let mut unknown = false;
        if a.tables.is_empty() && rw {
            // Names from the text for reads and writes only: DDL and DCL
            // text can hold program bodies (MySQL JavaScript routines in
            // `$$ … $$`) that the SQL lexer does not delimit, and their
            // events need no object.
            let mut named_any = false;
            for p in parts {
                // A write names its system tables (`UPDATE
                // performance_schema.setup_consumers …` turns the
                // `performance_schema` source off): only reads skip them.
                let keep_system = write || is_write_kind(p.kind);
                for r in &p.relations {
                    named_any = true;
                    let db = r.schema.as_deref().unwrap_or(a.database);
                    // A statement-text table keeps its name, as listed
                    // (ADR-0045 decision 1).
                    let text_table = statement_text_table(self.flavor, db, &r.name);
                    if is_dual(r)
                        || (!keep_system
                            && text_table.is_none()
                            && is_system_relation(r, a.database))
                    {
                        continue;
                    }
                    let o = text_table.map_or_else(
                        || (db.to_owned(), r.name.clone()),
                        |(d, t)| (d.to_owned(), t.to_owned()),
                    );
                    if !objects.contains(&o) {
                        objects.push(o);
                    }
                }
            }
            // Unknown objects: a text that cannot be read, code that runs
            // out of sight, a write that names no table (or only `DUAL`), a
            // text cut with no table record.
            if (!named_any && !parsed)
                || call
                || cut_blind
                || ((write || loud_other) && objects.is_empty())
            {
                unknown = true;
            }
        } else {
            for (db, table, op) in &a.tables {
                // System tables are skipped from reads only: a write
                // statement names every table it touched, and a table
                // record that writes or changes a system schema table
                // names it whatever the statement's action (a `CALL`).
                let text_table = statement_text_table(self.flavor, db, table);
                let system = (is_system_schema(db)
                    && !write
                    && *op == TableOp::Read
                    && text_table.is_none())
                    || (is_internal_table(db, table) && !write)
                    || (!rw && db.eq_ignore_ascii_case("mysql"));
                let o = text_table.map_or_else(
                    || ((*db).to_owned(), (*table).to_owned()),
                    |(d, t)| (d.to_owned(), t.to_owned()),
                );
                if !system && !objects.contains(&o) {
                    objects.push(o);
                }
            }
            // The table records do not name the server file `LOAD_FILE`
            // read, nor what a cut text hid past the cut.
            unknown = (hidden || cut_blind) && rw;
        }
        if processlist && rw {
            let o = ("information_schema".to_owned(), "PROCESSLIST".to_owned());
            if !objects.contains(&o) {
                objects.push(o);
            }
        }
        // Reads of statement-text tables (ADR-0045 decisions 1 to 4):
        // named first (an event names 16 objects at most), always
        // reported, and never the agent's own (its exact texts are left
        // out above).
        let text_tables = objects.iter().any(|(db, t)| {
            statement_text_table(self.flavor, db, t).is_some()
                || unresolved_text_table(self.flavor, db, t)
        });
        if text_tables {
            let flavor = self.flavor;
            objects.sort_by_key(|(db, t)| {
                statement_text_table(flavor, db, t).is_none()
                    && !unresolved_text_table(flavor, db, t)
            });
        }
        if rw && objects.is_empty() && !unknown && !dquoted {
            // A read of system tables only, or no table at all (`SELECT
            // 1`). A write keeps its system tables above.
            return None;
        }
        let ts = a.ts.min(now);
        let mut e = MaskedEvent::new(a.source, action, a.principal.clone(), ts).with_rows(a.rows);
        // An event names 16 objects at most: `*` keeps its place.
        let star = unknown || (dquoted && rw);
        for (db, name) in objects.iter().take(if star { 15 } else { 16 }) {
            e = e.with_object(object(db, name));
        }
        if star {
            e = e.with_object(unknown_object(a.database));
        }
        // Never filtered by `min_rows` (ADR-0022 settings, agent side):
        // changes that touch a system schema (they can turn the
        // `performance_schema` source off or erase it), server
        // configuration changes (`SET GLOBAL`, `INSTALL` / `UNINSTALL`),
        // and changes whose text cannot be read.
        let system = |db: &str| is_system_schema(db);
        let touches_system = a.tables.iter().any(|(db, table, op)| {
            (system(db) || is_audit_table(db, table))
                && (*op != TableOp::Read || action != EventAction::Read)
        }) || (action != EventAction::Read
            && (objects
                .iter()
                .any(|(db, table)| system(db) || is_audit_table(db, table))
                || parts.iter().any(|p| {
                    p.relations.iter().any(|r| {
                        let db = r.schema.as_deref().unwrap_or(a.database);
                        system(db) || is_audit_table(db, &r.name)
                    })
                })));
        let configuration = audit_function
            || parts.iter().any(|p| {
                p.audit_function
                    || p.kind == StatementKind::Ddl
                        && matches!(
                            p.lead.first().map(String::as_str),
                            Some("set" | "install" | "uninstall")
                        )
            });
        // Also reads of `*`: code that runs out of sight or a text that
        // cannot be read never matches `sensitive_objects` and has no
        // useful row count, so `min_rows` would drop it.
        if touches_system || configuration || call || blind || cut_blind || text_tables {
            e = e.with_always_report();
        }
        // Read signals per read statement, whatever the event's action (a
        // multi-statement text whose most reportable statement is a
        // write keeps the signals of its reads; the contract allows any
        // registered signal on any action).
        {
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
        if !changes
            && !text_tables
            && self
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
        let unlogged = source == EventSource::MariadbServerAudit && text_record.is_none();
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
            alt_text: None,
            digest: false,
            // `server_audit` table-access records with no statement record
            // (security review of #188, M2): a statement the event set does
            // not log (`SET @x = f()`, DDL under `QUERY_DML`), a lost
            // record, or one that outlived the pending timeout. What the
            // text would have shown (a function call, a server file) is
            // unknown: handled as a cut text, a read or write of the tables
            // and of `*`, always reported, never the agent's own.
            truncated: text_record.is_some_and(|r| r.truncated) || unlogged,
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

    /// The CAS store guard statements `check()` sends: for the built-in
    /// names, and for 64 names of 128 characters in each `cas_stores` list
    /// (the most allowed).
    fn guard_sets() -> Vec<Vec<String>> {
        let names = |p: char| -> Vec<String> {
            (0..64)
                .map(|i| format!("{i:02}{}", p.to_string().repeat(126)))
                .collect()
        };
        let full = databastion_core::cas_guard::CasStores {
            ticket_registry: names('t'),
            service_registry: names('s'),
            audit_trail: names('a'),
        };
        vec![
            crate::sql::cas_guard_statement_texts(None).unwrap(),
            crate::sql::cas_guard_statement_texts(Some(&full)).unwrap(),
        ]
    }

    fn guard_builder(texts: &[String]) -> EventBuilder {
        EventBuilder::new(own())
            .with_own_statements(texts.iter().map(|t| t.clone().into_bytes()).collect())
    }

    /// A `server_audit` QUERY line for `text` as `user` from `host`, cut as
    /// the plugin cuts it at `limit` escaped bytes (`None`: not cut).
    fn sa_query(user: &str, host: &str, q: u64, text: &str, limit: Option<usize>) -> String {
        let mut esc = String::new();
        for c in text.chars() {
            match c {
                '\'' => esc.push_str("\\'"),
                '\\' => esc.push_str("\\\\"),
                '\n' => esc.push_str("\\n"),
                '\r' => esc.push_str("\\r"),
                '\t' => esc.push_str("\\t"),
                c => esc.push(c),
            }
        }
        if let Some(l) = limit {
            esc.truncate(l.min(esc.len()));
            // Never end inside an escape.
            if esc.ends_with('\\') && !esc.ends_with("\\\\") {
                esc.pop();
            }
        }
        format!("20260929 09:40:35,h,{user},{host},30,{q},QUERY,shop,'{esc}',0")
    }

    fn sa_at(lines: &[String], limit: usize) -> Vec<FileRecord> {
        lines
            .iter()
            .map(|l| parse_server_audit(l.as_bytes(), 0, limit).unwrap())
            .collect()
    }

    fn pfs_access<'a>(
        text: &'a [u8],
        truncated: bool,
        tables: Vec<(&'a str, &'a str, TableOp)>,
    ) -> Access<'a> {
        Access {
            session: "t9".to_owned(),
            user: "databastion",
            principal: EventPrincipal::account("databastion"),
            client: ClientSeen::NotVisible,
            application: Some("databastion-agent"),
            database: "",
            text: Some(text),
            opaque: false,
            alt_text: None,
            digest: false,
            truncated,
            tables,
            rows: None,
            status: 0,
            ts: SystemTime::now(),
            source: EventSource::PerformanceSchema,
        }
    }

    /// E2E regression (mariadb-e2e I2): every guard statement stays under
    /// the default 1024-byte log limits, is never cut, and is left out at
    /// every heartbeat on each source.
    #[test]
    fn the_cas_guard_statement_is_left_out_whole_or_truncated() {
        for set in guard_sets() {
            for g in &set {
                assert!(
                    crate::sql::server_audit_escaped_len(g) <= 900,
                    "{}",
                    g.len()
                );
                let mut b = guard_builder(&set);
                for q in 1..=3 {
                    let recs = sa_at(
                        &[sa_query("databastion", "172.18.0.1", q, g, Some(1024))],
                        1024,
                    );
                    assert!(!recs[0].truncated);
                    assert_eq!(
                        recs[0].text.as_deref().map(Vec::as_slice),
                        Some(g.as_bytes())
                    );
                    assert_eq!(file(&mut b, recs), Vec::<String>::new());
                }
                // The `audit_log` JSON file.
                let mut b = guard_builder(&set);
                for c in 1..=3u64 {
                    let rec = format!(
                        r#"{{"timestamp":"2026-09-29 10:06:12","class":"general","event":"status","connection_id":{c},"login":{{"user":"databastion","ip":"172.18.0.1"}},"general_data":{{"command":"Query","query":{},"status":0}}}}"#,
                        serde_json::to_string(g).unwrap()
                    );
                    let recs = vec![parse_json(rec.as_bytes()).unwrap()];
                    let ev = b.convert_file(recs, EventSource::MysqlAuditLog, SystemTime::now());
                    assert!(
                        ev.is_empty(),
                        "{:?}",
                        ev.iter().map(show).collect::<Vec<_>>()
                    );
                }
                // performance_schema `SQL_TEXT`, not cut.
                let mut b = guard_builder(&set);
                for _ in 0..3 {
                    let access = pfs_access(g.as_bytes(), false, Vec::new());
                    assert!(b.own_guard(&access));
                    assert!(b.statement(access, SystemTime::now()).is_none());
                }
            }
        }
    }

    /// The narrow-match checks of [`the_cas_guard_match_is_narrow`] for one
    /// guard text `g` of `set`.
    fn narrow_for(set: &[String], g: &str) {
        // Three heartbeats: an unknown read of the agent's account is
        // charged the whole budget, so the first may still be left out by
        // the row budget; the next ones are reported.
        let heartbeats = |text: &str, limit: usize| {
            let mut b = guard_builder(set);
            let mut out = Vec::new();
            for q in 1..=3u64 {
                let cut = (limit < text.len()).then_some(limit);
                out.extend(file(
                    &mut b,
                    sa_at(
                        &[sa_query("databastion", "172.18.0.1", q, text, cut)],
                        limit,
                    ),
                ));
            }
            out
        };
        // The guard text followed by another read, cut at the limit inside
        // a literal (server_audit with QUERY events only: no table record).
        // (The padding puts the cut inside the literal, whatever the
        // guard text's length.)
        let pad = 1100 - crate::sql::server_audit_escaped_len(g);
        let forged = format!(
            "{g} UNION ALL SELECT name, email, phone, '{}' FROM shop.customers",
            "x".repeat(pad)
        );
        let out = heartbeats(&forged, 1024);
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(
            out.iter().all(|e| e.starts_with("read [\"shop.*\"]")),
            "{out:?}"
        );
        // The same on performance_schema (`SQL_TEXT` cut, no table record).
        let mut b = guard_builder(set);
        for _ in 0..3 {
            let access = pfs_access(&forged.as_bytes()[..1020], true, Vec::new());
            assert!(!b.own_guard(&access));
            let e = b.statement(access, SystemTime::now()).unwrap();
            assert!(e.always_report());
        }
        // The exact guard text cut by a lowered limit, anywhere: no longer
        // matched (a truncated record never is, below), and a cut text with
        // no table record is a read of `*`, always reported, at every
        // heartbeat (security review of #181, H1; documented: keep the
        // limits at 1024).
        let mut cuts = vec![crate::sql::server_audit_escaped_len(g) / 2];
        if let Some(regex_at) = g.find("[^ABC") {
            cuts.push(crate::sql::server_audit_escaped_len(&g[..regex_at]) + 10);
        }
        for low in cuts {
            let out = heartbeats(g, low);
            assert_eq!(out.len(), 3, "{out:?}");
            assert!(out.iter().all(|e| e.contains(".*\"")), "{out:?}");
        }
        // The exact guard text with a table record outside
        // `information_schema` never takes the uncharged path.
        let b = guard_builder(set);
        for db in ["performance_schema", "sys", "shop"] {
            let access = pfs_access(g.as_bytes(), false, vec![(db, "t", TableOp::Read)]);
            assert!(!b.own_guard(&access), "{db}");
        }
        assert!(b.own_guard(&pfs_access(
            g.as_bytes(),
            false,
            vec![("information_schema", "COLUMNS", TableOp::Read)]
        )));
        // A truncated record whose text equals the guard is not matched
        // either, nor an opaque one.
        assert!(!b.own_guard(&pfs_access(g.as_bytes(), true, Vec::new())));
        let mut opaque = pfs_access(g.as_bytes(), false, Vec::new());
        opaque.opaque = true;
        assert!(!b.own_guard(&opaque));
    }

    /// Only the whole, uncut guard text with no table record outside
    /// `information_schema` takes the uncharged path (security review of
    /// f9bab99, H1, M1, L1).
    #[test]
    fn the_cas_guard_match_is_narrow() {
        let set = guard_sets().remove(0);
        // A column statement of one name key, the shape statement and the
        // table list.
        let (list, shape) = (&set[set.len() - 1], &set[set.len() - 2]);
        assert_eq!(list, crate::sql::CAS_GUARD_TABLES);
        for g in [&set[0], shape, list] {
            narrow_for(&set, g);
        }
        let g = &set[0];
        // Exact text from another account or address: not the uncharged
        // path (whatever the usual path then decides).
        let mut b = guard_builder(&set);
        let line = sa_query("app", "172.18.0.1", 1, g, None);
        let _ = file(&mut b, sa_at(&[line], 1024));
        let mut other = pfs_access(g.as_bytes(), false, Vec::new());
        other.user = "app";
        let e = MaskedEvent::new(
            other.source,
            EventAction::Read,
            other.principal.clone(),
            other.ts,
        );
        assert!(
            !b.own
                .routine_unbudgeted(other.user, other.application, other.client, &e)
        );
    }

    /// Padding that pushes a read past the cut of a source with no table
    /// record: whitespace, a line comment, repeated tokens. `hr.customers`
    /// is never visible.
    fn padded_reads(head: &str) -> Vec<String> {
        let tail = " UNION ALL SELECT name, email, phone FROM hr.customers";
        vec![
            format!("{head} WHERE 1 = 1{}{tail}", " ".repeat(1200)),
            format!("{head} WHERE 1 = 1 -- {}\n{tail}", "x".repeat(1200)),
            format!(
                "{head} WHERE 1 = 1{}{tail}",
                " AND TABLE_NAME = TABLE_NAME".repeat(200)
            ),
        ]
    }

    /// Every padded read, from the agent's account (after the exact guard
    /// table list) and from another one.
    fn padded_cases(set: &[String]) -> Vec<String> {
        let mut texts = padded_reads("SELECT * FROM information_schema.TABLES");
        // The exact table list as the visible head.
        let list = crate::sql::CAS_GUARD_TABLES;
        assert!(set.iter().any(|t| t == list));
        texts.extend(padded_reads(&format!("{list}\n")));
        texts.push(format!(
            "SELECT 1 {} UNION SELECT * FROM hr.customers",
            " ".repeat(1200)
        ));
        texts
    }

    fn assert_cut_read(e: &MaskedEvent, db: &str) {
        assert_eq!(e.action(), EventAction::Read, "{}", show(e));
        assert!(e.always_report(), "{}", show(e));
        assert!(
            e.objects()
                .iter()
                .any(|o| o.database().as_str() == db && o.object().as_str() == "*"),
            "{}",
            show(e)
        );
    }

    /// Security review of #181, H1: a text cut by the source with no table
    /// record is never quiet nor the agent's own: a read of `*`, always
    /// reported, from any account, on a QUERY-only `server_audit` log.
    #[test]
    fn cut_texts_are_reads_of_star_on_server_audit() {
        let set = guard_sets().remove(0);
        for text in padded_cases(&set) {
            for (user, host) in [("databastion", "172.18.0.1"), ("app", "10.0.0.5")] {
                let mut b = guard_builder(&set);
                for q in 1..=3u64 {
                    // The guard table list, exact, then the padded text.
                    let list = sa_query(user, host, 2 * q, crate::sql::CAS_GUARD_TABLES, None);
                    let line = sa_query(user, host, 2 * q + 1, &text, Some(1024));
                    let recs = sa_at(&[list, line], 1024);
                    assert!(recs[1].truncated, "{text}");
                    let ev =
                        b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now());
                    let cut: Vec<_> = ev.iter().filter(|e| e.always_report()).collect();
                    assert_eq!(
                        cut.len(),
                        1,
                        "{user}: {:?}",
                        ev.iter().map(show).collect::<Vec<_>>()
                    );
                    assert_cut_read(cut[0], "shop");
                    if user == "databastion" {
                        // The exact table list itself stays left out.
                        assert_eq!(ev.len(), 1, "{:?}", ev.iter().map(show).collect::<Vec<_>>());
                    }
                }
            }
        }
        // A cut quiet statement (`SHOW`, `SET`) is a read of `*` too.
        for text in [
            format!(
                "SHOW TABLES WHERE 1 = 1{} OR 1 IN (SELECT 1 FROM hr.customers)",
                " ".repeat(1200)
            ),
            format!(
                "SET @x = 1{}, @y = (SELECT email FROM hr.customers LIMIT 1)",
                " ".repeat(1200)
            ),
        ] {
            let mut b = guard_builder(&set);
            let recs = sa_at(&[sa_query("app", "10.0.0.5", 1, &text, Some(1024))], 1024);
            let ev = b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now());
            assert_eq!(ev.len(), 1, "{text}");
            assert_cut_read(&ev[0], "shop");
        }
        // Not cut: the same texts with their tables named are reported as
        // usual (no `*`).
        let mut b = guard_builder(&set);
        let short = "SELECT 1 UNION SELECT * FROM hr.customers";
        let recs = sa_at(&[sa_query("app", "10.0.0.5", 1, short, None)], 1024);
        assert_eq!(file(&mut b, recs), ["read [\"hr.customers\"] None []"]);
    }

    /// The same on `performance_schema`, with the cut rule of the poller
    /// (`pfs::text_cut`): `SQL_TEXT` cut at 1024 bytes (the server ends it
    /// with `...`), and a `DIGEST_TEXT` cut at its token storage (token
    /// padding renders past the limit, without `...`: measured on MySQL
    /// 8.4 and MariaDB 11.4).
    #[test]
    fn cut_texts_are_reads_of_star_on_performance_schema() {
        let set = guard_sets().remove(0);
        let mut texts: Vec<(Vec<u8>, bool)> = Vec::new();
        for t in padded_cases(&set) {
            let mut cut = t.as_bytes()[..1021].to_vec();
            cut.extend_from_slice(b"...");
            texts.push((cut, false));
        }
        // Digest texts: whitespace and comments are not kept, tokens are.
        let digest = format!(
            "SELECT * FROM `information_schema` . `TABLES` WHERE ? = ?{}",
            " AND `TABLE_NAME` = `TABLE_NAME`".repeat(100)
        );
        texts.push((digest.as_bytes()[..1023].to_vec(), true));
        texts.push((digest.into_bytes(), true));
        let full = "SELECT * FROM `information_schema` . `TABLES` WHERE ? = ? AND `TABLE_NAME` ...";
        texts.push((full.as_bytes().to_vec(), true));
        for (text, _) in &texts {
            assert!(super::super::pfs::text_cut(text, 1024));
            for user in ["databastion", "app"] {
                let mut b = guard_builder(&set);
                for _ in 0..3 {
                    let mut a = pfs_access(text, true, Vec::new());
                    a.user = user;
                    if user != "databastion" {
                        a.principal = EventPrincipal::account(user);
                        a.application = None;
                    }
                    assert!(!b.own_guard(&a));
                    let e = b.statement(a, SystemTime::now()).unwrap();
                    assert_cut_read(&e, "*");
                }
            }
        }
        // A text past the poller's size bound is dropped and still cut: a
        // read of `*`.
        let mut b = guard_builder(&set);
        let mut a = pfs_access(b"", true, Vec::new());
        a.text = None;
        assert_cut_read(&b.statement(a, SystemTime::now()).unwrap(), "*");
        // Not cut: the agent's guard statements (at most 900 bytes) and
        // their digests.
        for g in &set {
            assert!(!super::super::pfs::text_cut(g.as_bytes(), 1024));
        }
    }

    /// The sampling statements of a 40-column table (two batches at least).
    fn wide_batches() -> Vec<String> {
        let cols: Vec<String> = (0..40).map(|i| format!("customer_field_{i:02}")).collect();
        let sel: Vec<(&str, crate::sql::Sampled)> = cols
            .iter()
            .map(|c| (c.as_str(), crate::sql::Sampled::Text))
            .collect();
        let all = crate::sql::sample_statements(
            crate::conn::Flavor::Mariadb,
            30_000,
            "shop",
            "customers",
            &sel,
            200,
            1024,
        )
        .unwrap();
        assert!(all.len() >= 2);
        all.into_iter().map(|(_, s)| s).collect()
    }

    /// Security review of 914c9d2, N3: one scan of a wide table is charged
    /// once to the agent's own budget (its extra batches hold credits), on
    /// a QUERY-only `server_audit` log, with or without table records, and
    /// on performance_schema; an extra batch text without a credit (outside
    /// a scan, or replayed) is charged and reported.
    #[test]
    fn extra_sampling_batches_are_charged_once_per_scan() {
        let batches = wide_batches();
        let lines = |q0: u64, tables: bool| -> Vec<String> {
            let mut out = Vec::new();
            for (i, b) in batches.iter().enumerate() {
                let q = q0 + i as u64;
                if tables {
                    out.push(format!(
                        "20260929 09:40:35,h,databastion,172.18.0.1,30,{q},READ,shop,customers,"
                    ));
                }
                out.push(sa_query("databastion", "172.18.0.1", q, b, None));
            }
            out
        };
        for tables in [false, true] {
            let credits = super::super::credits::SharedCredits::default();
            let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
            let grant = || {
                let mut c = credits.lock().unwrap();
                for t in &batches[1..] {
                    c.grant(
                        t,
                        "shop",
                        "customers",
                        Duration::from_secs(30),
                        Instant::now(),
                    );
                }
            };
            // One scan: no event.
            grant();
            assert_eq!(
                file(&mut b, sa_at(&lines(10, tables), 1024)),
                Vec::<String>::new()
            );
            assert_eq!(credits.lock().unwrap().len(), 0);
            // The extra batches again without credits: charged, reported.
            let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
            let out = file(&mut b, sa_at(&lines(20, tables), 1024));
            assert_eq!(out.len(), batches.len() - 1, "{out:?}");
            assert!(
                out.iter()
                    .all(|e| e.starts_with("read [\"shop.customers\"]"))
            );
            // A credit is for its own table and the agent's identity only.
            grant();
            let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
            let other = sa_query("app", "10.0.0.5", 40, &batches[1], None);
            assert_eq!(file(&mut b, sa_at(&[other], 1024)).len(), 1);
            assert_eq!(credits.lock().unwrap().len(), batches.len() - 1);
            let wrong_table = vec![
                "20260929 09:40:35,h,databastion,172.18.0.1,30,41,READ,shop,orders,".to_owned(),
                sa_query("databastion", "172.18.0.1", 41, &batches[1], None),
            ];
            let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
            let _ = file(&mut b, sa_at(&wrong_table, 1024));
            assert_eq!(credits.lock().unwrap().len(), batches.len() - 1);
            credits
                .lock()
                .unwrap()
                .take(batches[1].as_bytes(), Instant::now());
            for t in &batches[2..] {
                credits.lock().unwrap().take(t.as_bytes(), Instant::now());
            }
        }
        // performance_schema (`SQL_TEXT` of the agent's account).
        let credits = super::super::credits::SharedCredits::default();
        let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
        for t in &batches[1..] {
            credits.lock().unwrap().grant(
                t,
                "shop",
                "customers",
                Duration::from_secs(30),
                Instant::now(),
            );
        }
        for t in &batches {
            let mut a = pfs_access(t.as_bytes(), false, Vec::new());
            a.rows = Some(1000);
            assert!(b.statement(a, SystemTime::now()).is_none());
        }
        // Replayed: no credit left, over the budget.
        let mut a = pfs_access(batches[1].as_bytes(), false, Vec::new());
        a.rows = Some(1000);
        assert!(b.statement(a, SystemTime::now()).is_some());
    }

    /// Security review of 09e93da, R1 (defence in depth): with a whole
    /// `SQL_TEXT` and a whole digest, the event takes the objects and
    /// signals of both, so that preferring one text never drops a table
    /// the other names; the agent's exact-text matches still use
    /// `SQL_TEXT` only.
    #[test]
    fn both_whole_texts_are_analyzed() {
        let sql = b"SELECT TABLE_NAME FROM information_schema.TABLES WHERE 1 = 1";
        let digest = b"SELECT `TABLE_NAME` FROM `information_schema` . `TABLES` WHERE ? = ? \
                       UNION ALL SELECT * FROM `hr` . `customers` INTO OUTFILE ?";
        let mut b = EventBuilder::new(own());
        let mut a = pfs_access(sql, false, Vec::new());
        a.user = "app";
        a.principal = EventPrincipal::account("app");
        a.application = None;
        a.alt_text = Some(digest);
        let e = b.statement(a, SystemTime::now()).unwrap();
        assert_eq!(
            show(&e),
            "read [\"hr.customers\"] None [\"signature.into_outfile\"]"
        );
        // Without the second text: no event (system tables only).
        let mut a = pfs_access(sql, false, Vec::new());
        a.user = "app";
        a.principal = EventPrincipal::account("app");
        a.application = None;
        assert!(b.statement(a, SystemTime::now()).is_none());
        // The exact guard text with its digest: still the agent's own.
        let set = guard_sets().remove(0);
        let b = guard_builder(&set);
        let mut a = pfs_access(set[0].as_bytes(), false, Vec::new());
        a.alt_text = Some(b"SELECT `TABLE_SCHEMA` FROM `information_schema` . `COLUMNS`");
        assert!(b.own_guard(&a));
        // A sampling batch with its digest: its credit still applies.
        let batches = wide_batches();
        let credits = super::super::credits::SharedCredits::default();
        let mut b = EventBuilder::new(own()).with_sample_credits(credits.clone());
        credits.lock().unwrap().grant(
            &batches[1],
            "shop",
            "customers",
            Duration::from_secs(30),
            Instant::now(),
        );
        for t in &batches[..2] {
            let mut a = pfs_access(t.as_bytes(), false, Vec::new());
            a.rows = Some(1000);
            a.alt_text =
                Some(b"SELECT LEFT ( `customer_field_00` , ? ) FROM `shop` . `customers` LIMIT ?");
            assert!(b.statement(a, SystemTime::now()).is_none());
        }
        assert_eq!(credits.lock().unwrap().len(), 0);
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
                // Write, from TABLE events only (QUERY record filtered out):
                // the statement is unknown, `*` too (security review of
                // #188, M2).
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
                "write [\"support.*\", \"support.tickets\"] None []",
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
                alt_text: None,
                digest: false,
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
                alt_text: None,
                digest: false,
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
        // `leak()` is not a built-in function: `*` too (ADR-0045 part (b)).
        assert_eq!(
            out,
            ["read [\"hr.*\", \"hr.employees\"] None [\"shape.full_table_read\"]"],
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
            alt_text: None,
            digest: false,
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
                "write [\"shop.*\", \"shop.a\"] None []",
                "read [\"shop.a\"] None []",
                "read [\"shop.*\", \"shop.b\"] None []",
            ],
            "{out:#?}"
        );
        // The stream ends: what is pending is reported.
        let out: Vec<String> = b
            .finish(EventSource::MariadbServerAudit, SystemTime::now())
            .iter()
            .map(show)
            .collect();
        assert_eq!(out, ["read [\"shop.*\", \"shop.c\"] None []"], "{out:#?}");
        assert_eq!(b.pending.sizes(), (0, 0, 0, 0));
    }

    /// Security review of #188, M2: `server_audit` table-access records
    /// with no statement record (`SET @x = f()` under `QUERY_DML`) are a
    /// read of the tables and of `*`, always reported, also with the
    /// agent's identity.
    #[test]
    fn unlogged_statements_are_reads_of_star() {
        for user in ["app", "databastion"] {
            let lines = [
                format!("20260929 09:41:34,h,{user},172.18.0.1,7,50,READ,shop,customers,"),
                format!("20260929 09:41:34,h,{user},172.18.0.1,7,0,DISCONNECT,shop,,0"),
            ];
            let mut b = EventBuilder::new(own());
            let ev = b.convert_file(
                sa_at(&lines, 1024),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                ev.iter().map(show).collect::<Vec<_>>(),
                ["read [\"shop.*\", \"shop.customers\"] None []"],
                "{user}"
            );
            assert!(ev.iter().all(MaskedEvent::always_report), "{user}");
        }
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
            ["read [\"shop.*\", \"shop.a\"] None []"]
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
            [
                "read [\"shop.*\", \"shop.a\"] None []",
                "read [\"shop.*\", \"shop.big\"] None []"
            ],
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
        assert_eq!(
            out,
            ["read [\"shop.*\", \"shop.harmless\"] None []"],
            "{out:#?}"
        );
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
        assert_eq!(
            at(&mut b, &[], t2),
            ["read [\"shop.*\", \"shop.a\"] None []"]
        );
        assert!(at(&mut b, &[rd(2, 41, "b")], t2).is_empty());
        let t3 = t2 + PENDING_TIMEOUT;
        assert_eq!(
            at(&mut b, &[], t3),
            ["read [\"shop.*\", \"shop.b\"] None []"]
        );
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

    /// A `server_audit` QUERY line of `user` from `host`.
    fn sa_line(user: &str, host: &str, q: u64, text: &str) -> String {
        sa_query(user, host, q, text, None)
    }

    /// A Percona `audit_log` JSON statement record.
    fn json_query(user: &str, ip: &str, c: u64, text: &str) -> FileRecord {
        let rec = format!(
            r#"{{"timestamp":"2026-09-29 10:06:12","class":"general","event":"status","connection_id":{c},"login":{{"user":"{user}","ip":"{ip}"}},"general_data":{{"command":"Query","query":{},"status":0}}}}"#,
            serde_json::to_string(text).unwrap()
        );
        parse_json(rec.as_bytes()).unwrap()
    }

    const DISABLE_CONSUMER: &str = "UPDATE performance_schema.setup_consumers SET ENABLED = 'NO' WHERE NAME = 'events_statements_history_long'";
    const DISABLE_DIGEST: &str =
        "UPDATE `performance_schema` . `setup_consumers` SET `ENABLED` = ? WHERE `NAME` = ?";

    /// Writes to system schema tables turn the `performance_schema` source
    /// off: reported with the table named, from any account, the agent's
    /// included, on every source.
    #[test]
    fn writes_to_system_schemas_are_reported_with_their_tables() {
        let consumers = "write [\"performance_schema.setup_consumers\"] None []";
        for user in ["app", "databastion"] {
            // server_audit, QUERY record only (text path) and with its
            // WRITE table record (table path).
            let mut b = EventBuilder::new(own());
            let out = file(
                &mut b,
                sa_at(
                    &[
                        sa_line(user, "172.18.0.1", 1, DISABLE_CONSUMER),
                        sa_line(
                            user,
                            "172.18.0.1",
                            2,
                            "update performance_schema.setup_instruments set enabled = 'NO'",
                        ),
                        format!(
                            "20260929 09:40:35,h,{user},172.18.0.1,30,3,WRITE,performance_schema,setup_consumers,"
                        ),
                        sa_line(user, "172.18.0.1", 3, DISABLE_CONSUMER),
                        // MariaDB `SET STATEMENT … FOR`: the write it wraps.
                        sa_line(
                            user,
                            "172.18.0.1",
                            4,
                            &format!("SET STATEMENT max_statement_time = 1 FOR {DISABLE_CONSUMER}"),
                        ),
                        // Copying other sessions' statement texts.
                        sa_line(
                            user,
                            "172.18.0.1",
                            5,
                            "insert into shop.t select sql_text from performance_schema.events_statements_history_long",
                        ),
                    ],
                    1024,
                ),
            );
            assert_eq!(
                out,
                [
                    consumers,
                    "write [\"performance_schema.setup_instruments\"] None []",
                    consumers,
                    consumers,
                    "write [\"performance_schema.events_statements_history_long\", \"shop.t\"] None []",
                ],
                "{user}: {out:#?}"
            );
            // The Percona `audit_log` JSON file.
            let mut b = EventBuilder::new(own());
            let ev = b.convert_file(
                vec![json_query(user, "172.18.0.1", 7, DISABLE_CONSUMER)],
                EventSource::MysqlAuditLog,
                SystemTime::now(),
            );
            assert_eq!(
                ev.iter().map(show).collect::<Vec<_>>(),
                [consumers],
                "{user}"
            );
            // performance_schema (`DIGEST_TEXT`), with an affected row
            // count far below the own-account budget.
            let mut b = EventBuilder::new(own());
            let mut access = pfs_access(DISABLE_DIGEST.as_bytes(), false, Vec::new());
            access.user = user;
            access.principal = EventPrincipal::account(user);
            access.rows = Some(1);
            let e = b.statement(access, SystemTime::now()).expect(user);
            assert_eq!(
                show(&e),
                "write [\"performance_schema.setup_consumers\"] Some(1) []"
            );
        }
    }

    /// Reads of the other system schema tables (dictionary views,
    /// `setup_*`, digest summaries, internal statistics, `DUAL`) stay
    /// unreported, from the text or from table records (ADR-0045 decision
    /// 1: only the statement-text tables are named).
    #[test]
    fn dictionary_reads_stay_quiet() {
        let mut b = EventBuilder::new(own()).with_flavor(Flavor::Mariadb);
        let out = file(
            &mut b,
            sa_at(
                &[
                    sa_line("app", "10.0.0.5", 1, "select * from information_schema.COLUMNS"),
                    sa_line("app", "10.0.0.5", 2, "select * from sys.statement_analysis"),
                    "20260929 09:40:35,h,app,10.0.0.5,30,3,READ,performance_schema,setup_consumers,"
                        .to_owned(),
                    sa_line(
                        "app",
                        "10.0.0.5",
                        3,
                        "select * from performance_schema.setup_consumers",
                    ),
                    sa_line("app", "10.0.0.5", 4, "select 1 from dual"),
                    sa_line(
                        "app",
                        "10.0.0.5",
                        5,
                        "select digest_text from performance_schema.events_statements_summary_by_digest",
                    ),
                    sa_line("app", "10.0.0.5", 6, "select * from information_schema.TABLES t join information_schema.TRIGGERS g"),
                    sa_line("app", "10.0.0.5", 7, "select * from mysql.innodb_table_stats"),
                    sa_line("app", "10.0.0.5", 8, "SHOW ENGINE INNODB MUTEX"),
                    sa_line("app", "10.0.0.5", 9, "SHOW ENGINE PERFORMANCE_SCHEMA STATUS"),
                    sa_line("app", "10.0.0.5", 10, "SHOW ENGINES"),
                    sa_line("app", "10.0.0.5", 11, "SHOW STATUS"),
                    sa_line("app", "10.0.0.5", 12, "EXPLAIN SELECT * FROM sys.statement_analysis"),
                ],
                1024,
            ),
        );
        assert_eq!(out, Vec::<String>::new());
        let access = pfs_access(
            b"SELECT * FROM `performance_schema` . `setup_consumers`",
            false,
            Vec::new(),
        );
        assert!(b.statement(access, SystemTime::now()).is_none());
    }

    /// Changes to the audit configuration: DDL events (no object: DDL
    /// takes no name from text, ADR-0023 decision 7), from any account;
    /// session `SET`s stay unreported.
    #[test]
    fn audit_configuration_changes_are_reported() {
        for user in ["app", "databastion"] {
            let texts = [
                "TRUNCATE performance_schema.events_statements_history_long",
                "TRUNCATE TABLE performance_schema.events_statements_history_long",
                "SET GLOBAL server_audit_logging = OFF",
                "set global server_audit_events = ''",
                "SET @@global.server_audit_logging = 0",
                "SET autocommit = 1, GLOBAL server_audit_logging = OFF",
                "SET PERSIST audit_log_disable = ON",
                "SET GLOBAL audit_log_flush = ON",
                "SET GLOBAL performance_schema_max_sql_text_length = 0",
                "UNINSTALL PLUGIN server_audit",
                "UNINSTALL SONAME 'server_audit'",
                "UNINSTALL COMPONENT 'file://component_audit_log_filter'",
                "INSTALL PLUGIN server_audit SONAME 'server_audit'",
            ];
            let lines: Vec<String> = texts
                .iter()
                .enumerate()
                .map(|(i, t)| sa_line(user, "172.18.0.1", i as u64 + 1, t))
                .collect();
            let mut b = EventBuilder::new(own());
            let out = file(&mut b, sa_at(&lines, 1024));
            assert_eq!(out, vec!["ddl [] None []"; texts.len()], "{user}");
            // The same from performance_schema digests and the JSON file.
            for t in [
                "TRUNCATE TABLE `performance_schema` . `events_statements_history_long`",
                "SET GLOBAL `server_audit_logging` = ?",
                "UNINSTALL PLUGIN `server_audit`",
            ] {
                let mut access = pfs_access(t.as_bytes(), false, Vec::new());
                access.user = user;
                let e = b.statement(access, SystemTime::now()).expect(t);
                assert_eq!(e.action(), EventAction::Ddl, "{t}");
                let ev = b.convert_file(
                    vec![json_query(user, "172.18.0.1", 9, t)],
                    EventSource::MysqlAuditLog,
                    SystemTime::now(),
                );
                assert_eq!(ev.len(), 1, "{t}");
            }
        }
        // Session settings (the agent's own, any account's): no event.
        let mut b = EventBuilder::new(own());
        for t in [
            crate::sql::session_setup(crate::conn::Flavor::Mariadb, 1000),
            crate::sql::session_setup(crate::conn::Flavor::Mysql, 1000),
            crate::sql::SESSION_READ_ONLY.to_owned(),
            "SET @x = @@global.server_audit_logging".to_owned(),
            "SET NAMES utf8mb4".to_owned(),
        ] {
            let out = file(&mut b, sa_at(&[sa_line("app", "10.0.0.5", 1, &t)], 1024));
            assert!(out.is_empty(), "{t}: {out:?}");
            let access = pfs_access(t.as_bytes(), false, Vec::new());
            assert!(b.statement(access, SystemTime::now()).is_none(), "{t}");
        }
    }

    /// A statement whose table records change something is never left out
    /// as the agent's own, whatever its action (a `CALL` of a procedure
    /// that writes); the agent's MariaDB `SET STATEMENT … FOR SELECT`
    /// samples stay its own reads.
    #[test]
    fn own_statements_that_change_something_are_reported() {
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa_at(
                &[
                    "20260929 09:40:35,h,databastion,172.18.0.1,30,1,WRITE,performance_schema,setup_consumers,"
                        .to_owned(),
                    sa_line("databastion", "172.18.0.1", 1, "call shop.p()"),
                ],
                1024,
            ),
        );
        assert_eq!(
            out,
            ["read [\"performance_schema.setup_consumers\"] None []"]
        );
        // The agent's own MariaDB sample on performance_schema: a read of
        // the sampled table, within the row budget.
        let sample = crate::sql::sample_statement(
            crate::conn::Flavor::Mariadb,
            1000,
            "support",
            "tickets",
            &[("c", crate::sql::Sampled::Text)],
            10,
        )
        .unwrap();
        let mut access = pfs_access(sample.as_bytes(), false, Vec::new());
        access.rows = Some(10);
        assert!(b.statement(access, SystemTime::now()).is_none());
        // The same text from another address: reported as a read.
        let mut access = pfs_access(sample.as_bytes(), false, Vec::new());
        access.rows = Some(10);
        access.client = ClientSeen::Logged(ClientAddr::parse("10.9.9.9"));
        let e = b.statement(access, SystemTime::now()).unwrap();
        assert_eq!(show(&e), "read [\"support.tickets\"] Some(10) []");
        // The CAS guard text with a write table record in
        // `information_schema` never takes the uncharged path.
        let set = guard_sets().remove(0);
        let b = guard_builder(&set);
        assert!(!b.own_guard(&pfs_access(
            set[0].as_bytes(),
            false,
            vec![("information_schema", "COLUMNS", TableOp::Write)]
        )));
    }

    /// The events of `text` sent by `user` from the agent's address, on
    /// each source: `server_audit` (QUERY record only), the `audit_log`
    /// JSON file and `performance_schema`; a fresh builder each time.
    fn on_every_source(user: &str, text: &str) -> Vec<(EventSource, Option<MaskedEvent>)> {
        let one = |ev: Vec<MaskedEvent>| {
            assert!(ev.len() <= 1, "{text}");
            ev.into_iter().next()
        };
        let mut out = Vec::new();
        let mut b = EventBuilder::new(own());
        let recs = sa_at(&[sa_line(user, "172.18.0.1", 1, text)], 4096);
        out.push((
            EventSource::MariadbServerAudit,
            one(b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now())),
        ));
        let mut b = EventBuilder::new(own());
        out.push((
            EventSource::MysqlAuditLog,
            one(b.convert_file(
                vec![json_query(user, "172.18.0.1", 1, text)],
                EventSource::MysqlAuditLog,
                SystemTime::now(),
            )),
        ));
        let mut b = EventBuilder::new(own());
        let mut access = pfs_access(text.as_bytes(), false, Vec::new());
        access.user = user;
        access.principal = EventPrincipal::account(user);
        access.rows = Some(1);
        out.push((
            EventSource::PerformanceSchema,
            b.statement(access, SystemTime::now()),
        ));
        out
    }

    /// `show` without the rows (they differ per source) and with the
    /// always-reported mark.
    fn shown(e: &MaskedEvent) -> String {
        format!(
            "{} {:?}{}",
            e.action().as_str(),
            e.objects()
                .iter()
                .map(|o| format!("{}.{}", o.database().as_str(), o.object().as_str()))
                .collect::<Vec<_>>(),
            if e.always_report() { " always" } else { "" }
        )
    }

    /// Checks `text` from `app` and from the agent's account on every
    /// source: `want(source)` is the expected [`shown`] event.
    fn expect_everywhere(text: &str, want: impl Fn(EventSource) -> String) {
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(user, text) {
                let got = ev.as_ref().map(shown);
                assert_eq!(
                    got.as_deref(),
                    Some(want(source).as_str()),
                    "{user} {source:?}: {text}"
                );
            }
        }
    }

    /// The database of an unknown object: the session's (`shop` in the
    /// `server_audit` lines), none in the other records of these tests.
    fn star(source: EventSource) -> &'static str {
        if source == EventSource::MariadbServerAudit {
            "shop.*"
        } else {
            "*.*"
        }
    }

    /// Security review of #168, H1: texts whose readings differ (version
    /// comments) or that do not lex keep their most reportable kind and
    /// are reported (fail closed), never dropped.
    #[test]
    fn ambiguous_and_unlexable_texts_are_reported() {
        for text in [
            "SET /*M! GLOBAL */ server_audit_excl_users = 'mallory'",
            "/*!80000 SET GLOBAL audit_log_exclude_accounts = 'mallory@%' */",
            "SET /**/ GLOBAL server_audit_excl_users = 'x\u{e9}\\'",
            "SET STATEMENT sql_mode='' FOR SET GLOBAL server_audit_excl_users = CONCAT('mallory', LEFT('\u{e9}\\',0))",
        ] {
            expect_everywhere(text, |_| "ddl [] always".to_owned());
        }
        expect_everywhere(
            "SET STATEMENT max_statement_time=1 /*M! FOR UPDATE performance_schema.setup_consumers SET enabled='NO' */",
            |s| format!("write [{:?}] always", star(s)),
        );
        for text in [
            "/*M! SELECT * FROM hr.customers */",
            "/*!80000 SELECT * FROM hr.customers */",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
    }

    /// Review of #168, M3, M1, L2: nested `SET STATEMENT`, code that runs
    /// out of sight, `LOAD DATA`, `RENAME TABLE`, multi-statement texts.
    #[test]
    fn hidden_changes_are_reported() {
        let consumers = "write [\"performance_schema.setup_consumers\"] always";
        for text in [
            "SET STATEMENT a=1 FOR SET STATEMENT b=1 FOR UPDATE performance_schema.setup_consumers SET enabled='NO'",
            "SET STATEMENT a=1 FOR SET STATEMENT b=1 FOR SET STATEMENT c=1 FOR UPDATE performance_schema.setup_consumers SET enabled='NO'",
            "SET @a=1; UPDATE performance_schema.setup_consumers SET enabled='NO'",
        ] {
            expect_everywhere(text, |_| consumers.to_owned());
        }
        // A server-side `LOAD DATA` / `LOAD XML` also reads a server file
        // no source names (#184 review L2): the table and `*`.
        for (text, table) in [
            (
                "LOAD DATA INFILE '/tmp/x' INTO TABLE performance_schema.setup_consumers",
                "performance_schema.setup_consumers",
            ),
            (
                "LOAD DATA INFILE '/var/lib/mysql/hr/customers.ibd' INTO TABLE shop.t",
                "shop.t",
            ),
            ("LOAD XML INFILE '/etc/passwd' INTO TABLE `hr`.`t`", "hr.t"),
        ] {
            expect_everywhere(text, |s| {
                let mut o = [star(s), table];
                o.sort_unstable();
                format!("write [{:?}, {:?}] always", o[0], o[1])
            });
        }
        // Deeper than 8 levels: DDL (fail closed).
        let deep = format!(
            "{}UPDATE performance_schema.setup_consumers SET enabled='NO'",
            "SET STATEMENT a=1 FOR ".repeat(9)
        );
        expect_everywhere(&deep, |_| "ddl [] always".to_owned());
        expect_everywhere(
            "SET autocommit=1; SET GLOBAL server_audit_logging=OFF",
            |_| "ddl [] always".to_owned(),
        );
        expect_everywhere(
            "LOAD DATA LOCAL INFILE '/tmp/x' REPLACE INTO TABLE `hr`.`t` (a, b)",
            |_| "write [\"hr.t\"]".to_owned(),
        );
        expect_everywhere("INSERT hr.t (a) VALUES (1)", |_| {
            "write [\"hr.t\"]".to_owned()
        });
        expect_everywhere("RENAME TABLE hr.a TO hr.b", |_| "ddl []".to_owned());
        for text in [
            "EXECUTE s",
            "EXECUTE IMMEDIATE @q",
            "PREPARE s FROM @q",
            "SELECT hr.f(1)",
            "DO `hr`.`f`()",
            "SET @x = hr.f()",
            "CALL hr.p()",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
        // A named read that also calls a stored function: both.
        expect_everywhere(
            "SELECT email, hr.f(id) FROM hr.customers WHERE id = 1",
            // Objects are sorted: `*` first.
            |s| match star(s) {
                "*.*" => "read [\"*.*\", \"hr.customers\"] always".to_owned(),
                st => format!("read [\"hr.customers\", {st:?}] always"),
            },
        );
        // An ordinary small write is not marked: `min_rows` applies.
        expect_everywhere("UPDATE hr.t SET a = 1 WHERE id = 2", |_| {
            "write [\"hr.t\"]".to_owned()
        });
    }

    /// Review of #168, L1: with the agent's identity, a `CALL`, an
    /// `EXECUTE`, a stored function call and a text that cannot be read
    /// are never its own, even within its row budget; its plain reads
    /// still are.
    #[test]
    fn the_agents_hidden_code_is_never_its_own() {
        for text in [
            "CALL hr.p()",
            "EXECUTE s",
            "SELECT hr.f(1) FROM hr.t LIMIT 1",
            "/*M! SELECT a FROM hr.t LIMIT 1 */",
            "SELECT a FROM hr.t WHERE b = 'x\u{e9}\\' LIMIT 1",
        ] {
            for (source, ev) in on_every_source("databastion", text) {
                assert!(ev.is_some(), "{source:?}: {text}");
            }
        }
        for (source, ev) in on_every_source("databastion", "SELECT a FROM hr.t LIMIT 1") {
            assert!(ev.is_none(), "{source:?}");
        }
    }

    /// Re-review of #168, N1: a multi-statement text whose most
    /// reportable statement is a write keeps the signals of its reads.
    #[test]
    fn read_signals_survive_a_write_in_the_same_text() {
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(
                user,
                "SELECT * FROM hr.customers INTO OUTFILE '/tmp/x'; UPDATE shop.t SET a = a WHERE 0",
            ) {
                let e = ev.unwrap_or_else(|| panic!("{user} {source:?}"));
                assert_eq!(e.action(), EventAction::Write, "{source:?}");
                assert!(e.signals().contains(&Signal::IntoOutfile), "{source:?}");
                assert!(e.signals().contains(&Signal::FullTableRead), "{source:?}");
            }
            for (source, ev) in on_every_source(
                user,
                "SELECT SQL_NO_CACHE * FROM hr.customers; INSERT INTO shop.t VALUES (1)",
            ) {
                let e = ev.unwrap_or_else(|| panic!("{user} {source:?}"));
                assert_eq!(e.action(), EventAction::Write, "{source:?}");
                assert_eq!(
                    e.signals(),
                    [Signal::FullTableRead, Signal::Mysqldump],
                    "{source:?}"
                );
            }
        }
    }

    /// Re-review of #168, N2: audit log administration functions are
    /// configuration DDL, always reported, qualified or not.
    #[test]
    fn audit_functions_are_reported() {
        for text in [
            "SELECT audit_log_filter_set_user('%', 'log_none')",
            "SELECT audit_log_filter_set_filter('log_none', '{\"filter\": {\"log\": false}}')",
            "SELECT audit_log_filter_remove_user('%')",
            "SELECT audit_log_filter_remove_filter('log_all')",
            "SELECT audit_log_filter_flush()",
            "SELECT audit_log_read()",
            "SELECT audit_log_read_bookmark()",
            "SELECT audit_log_rotate()",
            "SELECT audit_log_encryption_password_set('x')",
            "SELECT mysql.audit_log_filter_set_user('%', 'log_none')",
            "DO audit_log_filter_remove_user('%')",
            "SET @x = audit_log_filter_remove_user('%')",
        ] {
            expect_everywhere(text, |_| "ddl [] always".to_owned());
        }
    }

    /// `performance_schema` rows of `text` from `user`: its `SQL_TEXT`
    /// with its digest as the second text, then the digest alone (another
    /// account's short digest), each with a fresh builder.
    fn on_pfs_digest(user: &str, text: &str, digest: &str) -> Vec<Option<MaskedEvent>> {
        let mut out = Vec::new();
        for (t, alt) in [(text, Some(digest)), (digest, None)] {
            let mut b = EventBuilder::new(own());
            let mut access = pfs_access(t.as_bytes(), false, Vec::new());
            access.user = user;
            access.principal = EventPrincipal::account(user);
            access.alt_text = alt.map(str::as_bytes);
            access.rows = Some(1);
            out.push(b.statement(access, SystemTime::now()));
        }
        out
    }

    /// #168 review L2: `LOAD_FILE` reads a file on the database server
    /// (with `FILE` and a permissive `secure_file_priv`) that no audit
    /// source names: code that runs out of sight, reported against `*`,
    /// always, never the agent's own, on every source and from every
    /// account. Before, a table-less call produced no event.
    #[test]
    fn load_file_calls_are_reported() {
        for text in [
            "SELECT LOAD_FILE('/etc/passwd')",
            "select load_file ( '/var/lib/mysql/hr/customers.ibd' )",
            "SET @x = LOAD_FILE('/etc/passwd')",
            "SET @x := `LOAD_FILE`('/etc/passwd'), @y = 1",
            "SET SESSION sql_mode = '', @x = LOAD_FILE('/etc/passwd')",
            "DO LOAD_FILE('/etc/passwd')",
            "SELECT /*!LOAD_FILE*/('/etc/passwd')",
            "SELECT \"load_file\"('/etc/passwd')",
            "SELECT 1 FROM DUAL WHERE LOAD_FILE('/etc/passwd') IS NOT NULL",
            "SELECT 1 FROM information_schema.TABLES WHERE LOAD_FILE('/etc/passwd') LIKE 'r%' LIMIT 1",
            "SHOW DATABASES WHERE LOAD_FILE('/etc/passwd') LIKE 'r%'",
            "EXPLAIN SELECT LOAD_FILE('/etc/passwd')",
            // Readings that differ, and a text that does not lex (raw
            // scan; on `performance_schema` the backslash readings differ).
            "SELECT 1 /*M! , LOAD_FILE('/etc/passwd') */",
            "SELECT LOAD_FILE('/etc/x\u{e9}\\')",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
        // A named read with a file read: both.
        expect_everywhere(
            "SELECT email, LOAD_FILE('/etc/passwd') FROM hr.customers WHERE id = 1",
            |s| match star(s) {
                "*.*" => "read [\"*.*\", \"hr.customers\"] always".to_owned(),
                st => format!("read [\"hr.customers\", {st:?}] always"),
            },
        );
        // A write of the file's content: the table and `*`.
        expect_everywhere(
            "INSERT INTO shop.t (b) VALUES (LOAD_FILE('/etc/passwd'))",
            |s| format!("write [{:?}, \"shop.t\"] always", star(s)),
        );
        // Not a call: unchanged (a plain read, the agent's own within its
        // budget; a quiet session `SET`).
        let literal = "SELECT a FROM hr.t WHERE b = 'LOAD_FILE(x)' LIMIT 1";
        for (source, ev) in on_every_source("app", literal) {
            let got = ev.as_ref().map(shown);
            assert_eq!(got.as_deref(), Some("read [\"hr.t\"]"), "{source:?}");
        }
        for (source, ev) in on_every_source("databastion", literal) {
            assert!(ev.is_none(), "{source:?}");
        }
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(user, "SET @x = 'LOAD_FILE(x)'") {
                assert!(ev.is_none(), "{user} {source:?}");
            }
        }
        // `performance_schema`: `SQL_TEXT` with its digest, and the digest
        // alone, from another account and from the agent's.
        for user in ["app", "databastion"] {
            for (text, digest) in [
                ("SELECT LOAD_FILE('/etc/passwd')", "SELECT `LOAD_FILE` (?)"),
                ("SELECT LOAD_FILE('/etc/passwd')", "SELECT LOAD_FILE (?)"),
                (
                    "SET @x = LOAD_FILE('/etc/passwd')",
                    "SET @? = `LOAD_FILE` (?)",
                ),
                ("DO load_file('/etc/passwd')", "DO `load_file` (?)"),
            ] {
                for ev in on_pfs_digest(user, text, digest) {
                    let e = ev.unwrap_or_else(|| panic!("{user}: {text} / {digest}"));
                    assert_eq!(shown(&e), "read [\"*.*\"] always", "{user}: {digest}");
                }
            }
        }
        // `server_audit` with table records that all read, from the
        // agent's identity: the records name the table, the file read adds
        // `*`, and it is never its own (a plain read would be).
        let text = "SELECT a, LOAD_FILE('/etc/passwd') FROM hr.t LIMIT 1";
        let lines = [
            "20260929 09:40:35,h,databastion,172.18.0.1,30,1,READ,hr,t,".to_owned(),
            sa_line("databastion", "172.18.0.1", 1, text),
        ];
        let mut b = EventBuilder::new(own());
        let out = b.convert_file(
            sa_at(&lines, 4096),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert_eq!(
            out.iter().map(shown).collect::<Vec<_>>(),
            ["read [\"hr.t\", \"shop.*\"] always"]
        );
        // The same records with an unreadable text: the raw scan makes it
        // blind whatever its records.
        let text = "SELECT a, LOAD_FILE('/etc/x\u{e9}\\') FROM hr.t LIMIT 1";
        let lines = [
            "20260929 09:40:35,h,databastion,172.18.0.1,30,1,READ,hr,t,".to_owned(),
            sa_line("databastion", "172.18.0.1", 1, text),
        ];
        let mut b = EventBuilder::new(own());
        let out = b.convert_file(
            sa_at(&lines, 4096),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].always_report());
        let plain = "SELECT a FROM hr.t LIMIT 1";
        let lines = [
            "20260929 09:40:35,h,databastion,172.18.0.1,30,1,READ,hr,t,".to_owned(),
            sa_line("databastion", "172.18.0.1", 1, plain),
        ];
        let mut b = EventBuilder::new(own());
        assert!(
            b.convert_file(
                sa_at(&lines, 4096),
                EventSource::MariadbServerAudit,
                SystemTime::now()
            )
            .is_empty()
        );
    }

    /// One `server_audit` statement of `user` with its table records
    /// (`op`, `db`, `table`), logged under the 1024-byte default limit.
    fn sa_with_records(user: &str, records: &[(&str, &str, &str)], text: &str) -> Vec<String> {
        let host = if user == "databastion" {
            "172.18.0.1"
        } else {
            "10.0.0.5"
        };
        let mut lines: Vec<String> = records
            .iter()
            .map(|(op, db, t)| format!("20260929 09:40:35,h,{user},{host},30,1,{op},{db},{t},"))
            .collect();
        lines.push(sa_query(user, host, 1, text, Some(1024)));
        lines
    }

    /// Security review of #184, M1: a text cut by the source is never the
    /// agent's own and adds `*`, always reported, even with table records:
    /// the records do not name what followed the cut (a `LOAD_FILE` call
    /// padded past the limit). `server_audit` TABLE + QUERY records.
    #[test]
    fn cut_texts_with_table_records_are_reads_of_star() {
        let pad = " ".repeat(1100);
        let cases = [
            (
                format!(
                    "SELECT a,{pad}, LOAD_FILE('/var/lib/mysql/hr/customers.ibd') FROM hr.t LIMIT 1"
                ),
                vec![("READ", "hr", "t")],
                "read [\"hr.t\", \"shop.*\"] always",
            ),
            (
                format!(
                    "SELECT a FROM hr.t WHERE id = 1{pad} UNION SELECT LOAD_FILE('/etc/passwd')"
                ),
                vec![("READ", "hr", "t")],
                "read [\"hr.t\", \"shop.*\"] always",
            ),
            (
                format!(
                    "UPDATE hr.t SET a = 1 WHERE id = 2{pad} OR LOAD_FILE('/etc/passwd') IS NULL"
                ),
                vec![("WRITE", "hr", "t")],
                "write [\"hr.t\", \"shop.*\"] always",
            ),
        ];
        for (text, records, want) in &cases {
            for user in ["databastion", "app"] {
                let lines = sa_with_records(user, records, text);
                let recs = sa_at(&lines, 1024);
                assert!(recs.last().unwrap().truncated, "{text}");
                let mut b = EventBuilder::new(own());
                let out = b.convert_file(recs, EventSource::MariadbServerAudit, SystemTime::now());
                assert_eq!(
                    out.iter().map(shown).collect::<Vec<_>>(),
                    [*want],
                    "{user}: {text}"
                );
            }
        }
        // Not cut: the agent's plain read with its records stays its own,
        // another account's is a plain read.
        let text = "SELECT a FROM hr.t LIMIT 1";
        for (user, want) in [
            ("databastion", Vec::<String>::new()),
            ("app", vec!["read [\"hr.t\"]".to_owned()]),
        ] {
            let lines = sa_with_records(user, &[("READ", "hr", "t")], text);
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(&lines, 1024),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(out.iter().map(shown).collect::<Vec<_>>(), want, "{user}");
        }
    }

    /// Security review of #184, M2: a call of a name holding a non-ASCII
    /// character is never a built-in function (`LOAD_FÍLE` and the like
    /// are stored function lookups on MySQL 8.4 and MariaDB 11.4): `*`,
    /// always reported, never the agent's own, with or without table
    /// records. A table name before a column list is not a call.
    #[test]
    fn non_ascii_calls_are_reported() {
        for text in [
            "SELECT LOAD_F\u{cd}LE('/etc/passwd')",
            "SELECT \u{ff2c}OAD_FILE('/etc/passwd')",
            "SET @x = `LOAD_F\u{130}LE`('/etc/passwd')",
            "DO caf\u{e9}(1)",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
        for user in ["databastion", "app"] {
            let lines = sa_with_records(
                user,
                &[("READ", "hr", "t")],
                "SELECT a, LOAD_FIL\u{c9}('/etc/passwd') FROM hr.t LIMIT 1",
            );
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(&lines, 1024),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                out.iter().map(shown).collect::<Vec<_>>(),
                ["read [\"hr.t\", \"shop.*\"] always"],
                "{user}"
            );
        }
        expect_everywhere("INSERT INTO hr.`client\u{e8}le` (nom) VALUES ('x')", |_| {
            "write [\"hr.client\u{e8}le\"]".to_owned()
        });
    }

    /// ADR-0045 part (b): an unqualified call of a name that is not built
    /// in (a stored function reading `hr.customers`, a loadable function)
    /// is a read of `*`, always reported and never the agent's own, on
    /// every source, plainly, backquoted, double-quoted (`ANSI_QUOTES`),
    /// or a keyword function with whitespace before `(`; the routine's
    /// name is never an object.
    #[test]
    fn unknown_calls_are_reads_of_star() {
        for text in [
            "SELECT get_customer_email(1)",
            "DO get_customer_email(1)",
            "SET @x = get_customer_email(1)",
            "SELECT `get_customer_email`(1)",
            "SELECT \"get_customer_email\"(1)",
            "SELECT `now`()",
            "SELECT now ()",
            "SELECT count (*)",
            "SELECT \"count\"(*)",
            "SELECT 1f()",
            "SELECT /*!50000 get_customer_email(1) */",
            "SELECT 1 WHERE f() > 0",
            "SET STATEMENT max_statement_time = 1 FOR SELECT f()",
            // A loadable function: not built in (open question 7).
            "SELECT version_tokens_show()",
            // `SHOW … WHERE` with an unknown call runs it.
            "SHOW TABLES WHERE f()",
            // Followed by `AS` (security review of #188, H1).
            "SELECT get_customer_email(1) AS x",
            "SELECT CAST(get_customer_email(1) AS CHAR)",
            "SET @x = (SELECT get_customer_email(1) AS y)",
            "DO (SELECT get_customer_email(1) AS y)",
            "SELECT get_customer_email(1) AS \"x\"",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
            for user in ["app", "databastion"] {
                for (_, e) in on_every_source(user, text) {
                    let e = e.unwrap();
                    assert!(
                        e.objects()
                            .iter()
                            .all(|o| !o.object().as_str().contains("customer")),
                        "{text}"
                    );
                }
            }
        }
        // With tables: the tables and `*` (objects in name order).
        let with_table = |action: &str, s: EventSource| {
            let mut o = ["hr.t", star(s)];
            o.sort_unstable();
            format!("{action} {o:?} always")
        };
        expect_everywhere("SELECT a, f(b) FROM hr.t", |s| with_table("read", s));
        expect_everywhere("UPDATE hr.t SET a = f(a)", |s| with_table("write", s));
        expect_everywhere("SELECT f(1) AS a FROM hr.t", |s| with_table("read", s));
        // With table records: they decide the tables, `*` is added.
        for user in ["databastion", "app"] {
            let lines = sa_with_records(
                user,
                &[("READ", "hr", "t")],
                "SELECT a, get_customer_email(a) FROM hr.t LIMIT 1",
            );
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(&lines, 1024),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                out.iter().map(shown).collect::<Vec<_>>(),
                ["read [\"hr.t\", \"shop.*\"] always"],
                "{user}"
            );
        }
        // A digest: `` `f` ( `` is a call, `COUNT (` a keyword.
        for (digest, want) in [
            (
                "SELECT `get_customer_email` ( ? )",
                Some("read [\"*.*\"] always"),
            ),
            ("SELECT `count` ( * )", Some("read [\"*.*\"] always")),
            ("SELECT COUNT ( * ) , NOW ( ) , `concat` ( ? )", None),
        ] {
            let mut b = EventBuilder::new(own());
            let mut access = pfs_access(digest.as_bytes(), false, Vec::new());
            access.digest = true;
            access.user = "app";
            access.principal = EventPrincipal::account("app");
            let got = b.statement(access, SystemTime::now());
            assert_eq!(got.as_ref().map(shown).as_deref(), want, "{digest}");
            // The digest next to a whole `SQL_TEXT`: analyzed too.
            let mut b = EventBuilder::new(own());
            let mut access = pfs_access(b"SELECT 1", false, Vec::new());
            access.alt_text = Some(digest.as_bytes());
            access.user = "app";
            access.principal = EventPrincipal::account("app");
            let got = b.statement(access, SystemTime::now());
            assert_eq!(got.as_ref().map(shown).as_deref(), want, "{digest}");
        }
    }

    /// The side accounts of the load harness's MariaDB Audit run
    /// (`e2e/load/side-clients.sh`, ADR-0045): the monitoring-like reader
    /// names `threads` and `PROCESSLIST` only (the digest summary holds no
    /// statement text on MariaDB), always reported; the table-less built-in
    /// mix gives no event on any MariaDB list.
    #[test]
    fn load_harness_side_statements() {
        let monitor = [
            (
                "SELECT SCHEMA_NAME, DIGEST, COUNT_STAR, SUM_TIMER_WAIT FROM \
                 performance_schema.events_statements_summary_by_digest ORDER BY SUM_TIMER_WAIT \
                 DESC LIMIT 50",
                None,
            ),
            (
                "SELECT THREAD_ID, PROCESSLIST_ID, PROCESSLIST_USER, PROCESSLIST_COMMAND, \
                 PROCESSLIST_STATE FROM performance_schema.threads",
                Some("performance_schema.threads"),
            ),
            (
                "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE FROM information_schema.PROCESSLIST",
                Some("information_schema.PROCESSLIST"),
            ),
        ];
        let builtins = [
            "SELECT NOW()",
            "SELECT LAST_INSERT_ID()",
            "SELECT DATABASE()",
            "SELECT @@session.auto_increment_increment AS auto_increment_increment, \
             @@character_set_client AS character_set_client, @@max_allowed_packet AS \
             max_allowed_packet, @@sql_mode AS sql_mode",
            "SELECT CONNECTION_ID(), VERSION(), USER(), CURRENT_USER()",
            "SET NAMES utf8mb4",
            "SELECT UTC_TIMESTAMP(), UNIX_TIMESTAMP(), CONCAT('a', 'b'), IFNULL(NULL, 1), \
             COALESCE(NULL, 2)",
            "SELECT 1",
        ];
        let lists = crate::builtins::lists()
            .iter()
            .filter(|l| l.flavor == Flavor::Mariadb);
        let mut checked = 0;
        for list in lists {
            for (text, want) in monitor {
                let mut b = EventBuilder::new(own())
                    .with_flavor(Flavor::Mariadb)
                    .with_builtins(list);
                let out = b.convert_file(
                    sa_at(&[sa_line("load_monitor", "10.0.0.7", 1, text)], 1024),
                    EventSource::MariadbServerAudit,
                    SystemTime::now(),
                );
                let names: Vec<String> = out
                    .iter()
                    .flat_map(|e| {
                        e.objects()
                            .iter()
                            .map(|o| format!("{}.{}", o.database().as_str(), o.object().as_str()))
                    })
                    .collect();
                assert_eq!(names, want.into_iter().collect::<Vec<_>>(), "{text}");
                assert!(out.iter().all(MaskedEvent::always_report), "{text}");
                checked += 1;
            }
            for text in builtins {
                let mut b = EventBuilder::new(own())
                    .with_flavor(Flavor::Mariadb)
                    .with_builtins(list);
                let out = file(
                    &mut b,
                    sa_at(&[sa_line("load_builtins", "10.0.0.7", 1, text)], 1024),
                );
                assert!(out.is_empty(), "{:?}: {text}: {out:?}", list.series);
                checked += 1;
            }
        }
        assert_eq!(checked, 3 * 11);
    }

    /// ADR-0045 part (b): every listed built-in, called table-less (plain;
    /// backquoted when native; spaced unless `sql_functions`), gives no
    /// event, on the list of its series; so do a driver's session probes.
    #[test]
    fn listed_built_ins_called_table_less_give_no_event() {
        // `LOAD_FILE` keeps its own rule (a read of `*`). Keywords that
        // are not calls (`SELECT in()`: a syntax error on the servers) give
        // no event either.
        let not_calls = |n: &str| n == "load_file";
        let mut checked = 0;
        for list in crate::builtins::lists() {
            let mut texts: Vec<String> = Vec::new();
            for (name, form) in list.names() {
                if not_calls(name) {
                    continue;
                }
                texts.push(format!("SELECT {name}()"));
                texts.push(format!("SELECT {}()", name.to_ascii_uppercase()));
                if form == crate::builtins::Form::Native {
                    texts.push(format!("SELECT `{name}`()"));
                }
                if form != crate::builtins::Form::KeywordAdjacent {
                    texts.push(format!("SELECT {name} ()"));
                }
            }
            texts.extend(
                [
                    "SELECT NOW()",
                    "SELECT LAST_INSERT_ID()",
                    "SELECT DATABASE()",
                    "SELECT @@session.auto_increment_increment AS auto_increment_increment, \
                     @@character_set_client AS character_set_client, @@max_allowed_packet",
                    "SELECT CONNECTION_ID()",
                    "SELECT VERSION()",
                    "SELECT USER(), CURRENT_USER()",
                    "SET NAMES utf8mb4 COLLATE utf8mb4_general_ci",
                    "SET sql_mode = CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')",
                    "SET @@session.time_zone = '+00:00'",
                    "SELECT UTC_TIMESTAMP(), UNIX_TIMESTAMP()",
                    "SELECT 1 FROM DUAL WHERE IFNULL(NULL, 1) = 1",
                ]
                .map(str::to_owned),
            );
            for text in texts {
                for user in ["app", "databastion"] {
                    let mut b = EventBuilder::new(own()).with_builtins(list);
                    let mut access = pfs_access(text.as_bytes(), false, Vec::new());
                    access.user = user;
                    access.principal = EventPrincipal::account(user);
                    access.rows = Some(1);
                    let got = b.statement(access, SystemTime::now());
                    assert!(
                        got.is_none(),
                        "{:?} {:?} {user}: {text} -> {:?}",
                        list.flavor,
                        list.series,
                        got.as_ref().map(shown)
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 6 * 2 * 1000, "{checked}");
    }

    /// Security review of 914c9d2 (Low): the `SHOW GRANTS … USING`
    /// statements of a long role list are split within the own-statement
    /// bound, so that at the default 1024-byte limits none is cut and the
    /// agent's heartbeat checks produce no event; the one statement of
    /// before was cut, and a read of `*` by the agent's account.
    #[test]
    fn split_role_statements_are_never_cut() {
        let roles: Vec<(String, String)> = (0..16)
            .map(|i| {
                (
                    format!("databastion_it_many_{i:02}"),
                    "many-roles.databastion-it.example.test".to_owned(),
                )
            })
            .collect();
        let statements = crate::sql::show_grants_using(&roles).unwrap();
        assert!(statements.len() > 1);
        let joined = format!(
            "SHOW GRANTS FOR CURRENT_USER() USING {}",
            statements
                .iter()
                .map(|s| s.trim_start_matches("SHOW GRANTS FOR CURRENT_USER() USING "))
                .collect::<Vec<_>>()
                .join(", ")
        );
        // `server_audit` (QUERY only) and `performance_schema` (`SQL_TEXT`
        // without a whole digest), as the agent's account, at 1024.
        let events = |text: &str| {
            let mut out = Vec::new();
            let mut b = EventBuilder::new(own());
            let line = sa_query("databastion", "172.18.0.1", 1, text, Some(1024));
            out.extend(b.convert_file(
                sa_at(&[line], 1024),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            ));
            let mut b = EventBuilder::new(own());
            let cut = crate::audit::pfs::text_cut(text.as_bytes(), 1024);
            let seen = if cut {
                &text.as_bytes()[..1021]
            } else {
                text.as_bytes()
            };
            out.extend(b.statement(pfs_access(seen, cut, Vec::new()), SystemTime::now()));
            out.iter().map(shown).collect::<Vec<_>>()
        };
        for s in &statements {
            assert!(events(s).is_empty(), "{s}");
        }
        assert_eq!(
            events(&joined),
            ["read [\"shop.*\"] always", "read [\"*.*\"] always"]
        );
    }

    /// #168 review L3: an `EXPLAIN` / `DESCRIBE` whose statement keyword
    /// is past the 32-token prefix bound is never quiet: reported against
    /// `*` (and what it names), always, never the agent's own.
    #[test]
    fn explain_prefixes_past_the_bound_are_reported() {
        let junk = "FORMAT = TREE ".repeat(11);
        for lead in ["EXPLAIN", "DESCRIBE", "DESC"] {
            for tail in ["ANALYZE DELETE FROM shop.t", "", "SELECT 1"] {
                let text = format!("{lead} {junk}{tail}");
                expect_everywhere(&text, |s| {
                    if tail.contains("shop.t") {
                        match star(s) {
                            "*.*" => "read [\"*.*\", \"shop.t\"] always".to_owned(),
                            _ => "read [\"shop.*\", \"shop.t\"] always".to_owned(),
                        }
                    } else {
                        format!("read [{:?}] always", star(s))
                    }
                });
            }
        }
        // Within the bound: quiet, as before.
        for text in [
            "EXPLAIN SELECT * FROM hr.customers",
            "DESCRIBE hr.customers",
            &format!("EXPLAIN {}SELECT 1", "FORMAT = TREE ".repeat(10)),
        ] {
            for user in ["app", "databastion"] {
                for (source, ev) in on_every_source(user, text) {
                    assert!(ev.is_none(), "{user} {source:?}: {text}");
                }
            }
        }
    }

    /// Re-review of #168, N3: a qualified call after `ON` in a read is a
    /// call: reported against `*`, never the agent's own.
    #[test]
    fn calls_after_on_in_a_read_are_calls() {
        expect_everywhere(
            "SELECT a FROM hr.t JOIN hr.u ON hr.disable_consumers() LIMIT 1",
            |s| match star(s) {
                "*.*" => "read [\"*.*\", \"hr.t\", \"hr.u\"] always".to_owned(),
                st => format!("read [\"hr.t\", \"hr.u\", {st:?}] always"),
            },
        );
    }

    /// Re-review of #168, N5: a text that trips the multibyte rule (a name
    /// ending in a non-ASCII character, before its closing backtick) is decided by
    /// its table records when they all read; without records it is
    /// reported.
    #[test]
    fn unreadable_own_samples_with_read_records_stay_own() {
        let text = "SELECT LEFT(`c`, 4096) FROM `hr`.`caf\u{e9}` LIMIT 10";
        assert!(!analyze_raw(text.as_bytes(), analyze_opts(false)).lexed());
        let records = |q: u64| {
            vec![
                format!("20260929 09:40:35,h,databastion,172.18.0.1,30,{q},READ,hr,caf\u{e9},"),
                sa_line("databastion", "172.18.0.1", q, text),
            ]
        };
        let mut b = EventBuilder::new(own());
        // Within the budget (unknown rows: the whole budget): left out,
        // then reported, as any own read of a table.
        assert_eq!(file(&mut b, sa_at(&records(1), 4096)), Vec::<String>::new());
        assert_eq!(file(&mut b, sa_at(&records(2), 4096)).len(), 1);
        // Without table records: never the agent's own.
        let mut b = EventBuilder::new(own());
        let out = b.convert_file(
            sa_at(&[sa_line("databastion", "172.18.0.1", 1, text)], 4096),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert_eq!(
            out.iter().map(shown).collect::<Vec<_>>(),
            ["read [\"shop.*\"] always"]
        );
    }

    /// Re-review of d162baa, P1: double-quoted names (`ANSI_QUOTES`, set
    /// by any session without an event) hide the objects: reported against
    /// `*`, always reported, never the agent's own.
    #[test]
    fn double_quoted_names_are_reported() {
        let star = |s: EventSource, action: &str| format!("{action} [{:?}] always", star(s));
        for text in [
            "SELECT * FROM \"hr\".\"customers\"",
            "SELECT * FROM \"customers\"",
            "SELECT a FROM hr.t JOIN \"customers\" c ON c.id = t.id",
            "SELECT \"hr\".\"f\"(1)",
        ] {
            expect_everywhere(text, |s| match text {
                t if t.contains("JOIN") => match super::tests::star(s) {
                    "*.*" => "read [\"*.*\", \"hr.t\"] always".to_owned(),
                    st => format!("read [\"hr.t\", {st:?}] always"),
                },
                _ => star(s, "read"),
            });
        }
        expect_everywhere("SELECT * FROM hr.a, \"b\"", |s| {
            match super::tests::star(s) {
                "*.*" => "read [\"*.*\", \"hr.a\"] always".to_owned(),
                st => format!("read [\"hr.a\", {st:?}] always"),
            }
        });
        expect_everywhere(
            "UPDATE \"performance_schema\".\"setup_consumers\" SET \"ENABLED\" = 'NO'",
            |s| star(s, "write"),
        );
        expect_everywhere("DELETE FROM \"hr\".\"customers\"", |s| star(s, "write"));
        for text in [
            "SELECT \"audit_log_filter_remove_user\"('%')",
            "SELECT \"AUDIT_LOG_ROTATE\" ()",
        ] {
            expect_everywhere(text, |_| "ddl [] always".to_owned());
        }
        // Double-quoted strings in value positions: the backstop adds `*`
        // without the always-reported mark (from any account: the agent
        // never sends `"`).
        let with_star = |s: EventSource, action: &str, table: &str| match self::star(s) {
            "*.*" => format!("{action} [\"*.*\", {table:?}]"),
            st => format!("{action} [{table:?}, {st:?}]"),
        };
        expect_everywhere("SELECT a FROM hr.t WHERE a = \"x\"", |s| {
            with_star(s, "read", "hr.t")
        });
        expect_everywhere("INSERT INTO hr.t VALUES (\"x\", \"y\")", |s| {
            with_star(s, "write", "hr.t")
        });
        expect_everywhere("UPDATE hr.t SET a = \"x\", b = \"y\" WHERE id = 1", |s| {
            with_star(s, "write", "hr.t")
        });
        expect_everywhere("SELECT \"x\", CONCAT(\"a\", \"b\")", |s| {
            format!("read [{:?}]", self::star(s))
        });
        // INTO OUTFILE "…" keeps its signal.
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(user, "SELECT a FROM hr.t INTO OUTFILE \"/x\"") {
                let e = ev.unwrap_or_else(|| panic!("{user} {source:?}"));
                assert!(e.signals().contains(&Signal::IntoOutfile), "{source:?}");
                assert!(!e.always_report(), "{source:?}");
            }
        }
        // Session settings with double quotes: no event.
        for (source, ev) in on_every_source("app", "SET NAMES \"utf8mb4\"") {
            assert!(ev.is_none(), "{source:?}");
        }
    }

    /// Re-review of 86e2d31, R1: double-quoted names in positions the
    /// precise rule now covers, and the backstop for the others, on the
    /// file sources without table records, and from the agent's account
    /// with a READ record of a decoy table.
    #[test]
    fn double_quoted_name_bypasses_are_closed() {
        let precise = [
            "SELECT * FROM (\"customers\")",
            "SELECT * FROM ((\"customers\"))",
            "SELECT * FROM (SELECT 1) x, \"customers\"",
            "SELECT * FROM hr.a AS x, \"customers\"",
            "HANDLER \"customers\" OPEN",
            "HANDLER \"customers\" READ FIRST",
            "SELECT * FROM hr.a STRAIGHT_JOIN \"customers\"",
            "SELECT * FROM hr.a USE INDEX (i), \"customers\"",
        ];
        for text in precise {
            let parts = analyze_raw(text.as_bytes(), analyze_opts(false));
            assert!(
                parts.parts().iter().any(|p| p.dquoted_name),
                "precise: {text}"
            );
        }
        for text in precise {
            for user in ["app", "databastion"] {
                let mut b = EventBuilder::new(own());
                let out = b.convert_file(
                    sa_at(&[sa_line(user, "172.18.0.1", 1, text)], 4096),
                    EventSource::MariadbServerAudit,
                    SystemTime::now(),
                );
                assert_eq!(out.len(), 1, "{user} server_audit: {text}");
                assert!(out[0].always_report(), "{user}: {text}");
                assert!(show(&out[0]).contains("shop.*"), "{user}: {text}");
                let mut b = EventBuilder::new(own());
                let out = b.convert_file(
                    vec![json_query(user, "172.18.0.1", 1, text)],
                    EventSource::MysqlAuditLog,
                    SystemTime::now(),
                );
                assert_eq!(out.len(), 1, "{user} json: {text}");
                assert!(out[0].always_report(), "{user}: {text}");
            }
            // The agent's account with a READ record of a decoy table:
            // reported, `*` added.
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(
                    &[
                        "20260929 09:40:35,h,databastion,172.18.0.1,30,1,READ,hr,a,".to_owned(),
                        sa_line("databastion", "172.18.0.1", 1, text),
                    ],
                    4096,
                ),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(out.len(), 1, "own with record: {text}");
            assert!(show(&out[0]).contains("shop.*"), "{text}");
        }
        // Backstop only: a double-quoted token the precise rule does not
        // place (`FROM a JOIN b ON x, "t"` style), still `*`, never own.
        let text = "SELECT * FROM hr.a JOIN hr.b ON hr.a.id = hr.b.id, \"customers\"";
        let a = analyze_raw(text.as_bytes(), analyze_opts(false));
        assert!(a.parts().iter().all(|p| !p.dquoted_name && p.dquoted));
        for user in ["app", "databastion"] {
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(
                    &[
                        format!("20260929 09:40:35,h,{user},172.18.0.1,30,1,READ,hr,a,"),
                        sa_line(user, "172.18.0.1", 1, text),
                    ],
                    4096,
                ),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                out.iter().map(shown).collect::<Vec<_>>(),
                ["read [\"hr.a\", \"shop.*\"]"],
                "{user}"
            );
        }
    }

    /// Re-review of d162baa, P2: an audit function after an unreadable
    /// literal is found by a raw scan: DDL, always reported, never the
    /// agent's own, also with table records that all read.
    #[test]
    fn audit_functions_after_unreadable_literals_are_reported() {
        let text = "SELECT a FROM hr.t WHERE x = 'x\u{e9}\\' AND audit_log_filter_remove_user /* c */ ('%') IS NOT NULL";
        assert!(!analyze_raw(text.as_bytes(), analyze_opts(false)).lexed());
        for user in ["app", "databastion"] {
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                sa_at(
                    &[
                        format!("20260929 09:40:35,h,{user},172.18.0.1,30,1,READ,hr,t,"),
                        sa_line(user, "172.18.0.1", 1, text),
                    ],
                    4096,
                ),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                out.iter().map(shown).collect::<Vec<_>>(),
                ["ddl [\"hr.t\"] always"],
                "{user}"
            );
            let mut b = EventBuilder::new(own());
            let out = b.convert_file(
                vec![json_query(user, "172.18.0.1", 1, text)],
                EventSource::MysqlAuditLog,
                SystemTime::now(),
            );
            assert_eq!(
                out.iter().map(shown).collect::<Vec<_>>(),
                ["ddl [] always"],
                "{user}"
            );
        }
    }

    /// Writes to the tables behind the audit functions are always
    /// reported.
    #[test]
    fn writes_to_audit_filter_tables_are_always_reported() {
        expect_everywhere(
            "UPDATE mysql.audit_log_user SET FILTERNAME = 'log_none' WHERE USER = '%'",
            |_| "write [\"mysql.audit_log_user\"] always".to_owned(),
        );
        expect_everywhere(
            "INSERT INTO mysql.audit_log_filter (NAME, FILTER) VALUES ('n', '{}')",
            |_| "write [\"mysql.audit_log_filter\"] always".to_owned(),
        );
        expect_everywhere("UPDATE mysql.user SET a = 1 WHERE b = 2", |_| {
            "write [\"mysql.user\"]".to_owned()
        });
    }

    /// Re-review of 07b04d6, H1: reads inside a session `SET` or `DO`
    /// (then `SELECT @x`) are reads of their tables, from any account,
    /// never the agent's own; utility statements and the agent's session
    /// settings are unchanged.
    #[test]
    fn reads_inside_session_sets_are_reported() {
        for text in [
            "SET @x = (SELECT GROUP_CONCAT(email) FROM hr.customers)",
            "SET @x := (SELECT GROUP_CONCAT(email) FROM hr.customers)",
            "SET @a = 1, @x = (SELECT email FROM hr.customers WHERE id = 1)",
            "DO (SELECT COUNT(*) FROM hr.customers)",
            "SET @x = CONCAT('a', (SELECT GROUP_CONCAT(email) FROM hr.customers))",
            "SET STATEMENT max_statement_time = 1 FOR SET @x = (SELECT email FROM hr.customers LIMIT 1)",
        ] {
            expect_everywhere(text, |_| "read [\"hr.customers\"]".to_owned());
        }
        // A subquery inside a function call of a read names its table.
        for (source, ev) in on_every_source(
            "app",
            "SELECT CONCAT((SELECT GROUP_CONCAT(email) FROM hr.customers))",
        ) {
            assert_eq!(
                ev.as_ref().map(shown).as_deref(),
                Some("read [\"hr.customers\"]"),
                "{source:?}"
            );
        }
        // Already a read (and the agent's own within its budget).
        for (source, ev) in on_every_source("app", "SELECT email INTO @x FROM hr.customers LIMIT 1")
        {
            assert_eq!(
                ev.as_ref().map(shown).as_deref(),
                Some("read [\"hr.customers\"]"),
                "{source:?}"
            );
        }
        // A subquery without a user table: a read of `*` (fail closed);
        // of a statement-text table: a read of it, always (ADR-0045).
        for text in [
            "SET @x = (SELECT 1)",
            "SET @x = (SELECT COUNT(*) FROM performance_schema.setup_consumers)",
        ] {
            for (source, ev) in on_every_source("app", text) {
                assert_eq!(
                    ev.as_ref().map(shown).as_deref(),
                    Some(format!("read [{:?}]", star(source)).as_str()),
                    "{source:?}: {text}"
                );
            }
        }
        expect_everywhere(
            "SET @x = (SELECT COUNT(*) FROM performance_schema.threads)",
            |_| "read [\"performance_schema.threads\"] always".to_owned(),
        );
        // No table, or an allow-listed utility statement: no event.
        for text in [
            "SELECT @x",
            "SHOW CREATE TABLE hr.customers",
            "SHOW COLUMNS FROM hr.customers",
            "LOCK TABLES hr.customers READ",
            "EXPLAIN SELECT * FROM hr.customers",
            "FLUSH TABLES hr.customers",
        ] {
            for (source, ev) in on_every_source("app", text) {
                assert!(ev.is_none(), "{source:?}: {text}");
            }
        }
        // `EXPLAIN ANALYZE` runs its statement.
        for (source, ev) in on_every_source("app", "EXPLAIN ANALYZE SELECT a FROM hr.t WHERE b = 1")
        {
            assert!(ev.is_some(), "{source:?}");
        }
        // The agent's session settings and its MariaDB sample statements.
        for text in [
            crate::sql::session_setup(crate::conn::Flavor::Mariadb, 1000),
            crate::sql::session_setup(crate::conn::Flavor::Mysql, 1000),
            crate::sql::SESSION_READ_ONLY.to_owned(),
            crate::sql::sample_statement(
                crate::conn::Flavor::Mariadb,
                1000,
                "support",
                "tickets",
                &[("c", crate::sql::Sampled::Text)],
                10,
            )
            .unwrap(),
        ] {
            for (source, ev) in on_every_source("databastion", &text) {
                assert!(ev.is_none(), "{source:?}: {text}");
            }
        }
    }

    /// Re-review of a2684a2: `ANALYZE` / `EXPLAIN ANALYZE` run their
    /// statement, `BEGIN NOT ATOMIC` runs a block, and statements of no
    /// known kind fail closed outside a closed allow-list.
    #[test]
    fn wrapped_and_unknown_statements_fail_closed() {
        let consumers = "write [\"performance_schema.setup_consumers\"] always";
        let actors = "write [\"performance_schema.setup_actors\"] always";
        for (text, want) in [
            (
                "ANALYZE UPDATE performance_schema.setup_consumers SET ENABLED='NO'",
                consumers,
            ),
            (
                "ANALYZE DELETE FROM performance_schema.setup_actors",
                actors,
            ),
            (
                "ANALYZE FORMAT=JSON DELETE FROM performance_schema.setup_actors",
                actors,
            ),
            (
                "EXPLAIN ANALYZE DELETE FROM performance_schema.setup_actors",
                actors,
            ),
            (
                "EXPLAIN FORMAT=TREE ANALYZE DELETE FROM performance_schema.setup_actors",
                actors,
            ),
            (
                "SET STATEMENT max_statement_time=1 FOR ANALYZE DELETE FROM performance_schema.setup_actors",
                actors,
            ),
            (
                "ANALYZE DELETE FROM hr.customers",
                "write [\"hr.customers\"]",
            ),
            (
                "ANALYZE SELECT * FROM hr.customers",
                "read [\"hr.customers\"]",
            ),
            (
                "DESCRIBE ANALYZE SELECT * FROM hr.customers",
                "read [\"hr.customers\"]",
            ),
            (
                "EXPLAIN ANALYZE UPDATE performance_schema.setup_consumers c, performance_schema.setup_instruments i SET c.ENABLED='NO'",
                "write [\"performance_schema.setup_consumers\", \"performance_schema.setup_instruments\"] always",
            ),
            (
                "EXPLAIN ANALYZE DELETE a FROM performance_schema.setup_actors a, performance_schema.setup_objects o",
                "write [\"performance_schema.setup_actors\", \"performance_schema.setup_objects\"] always",
            ),
        ] {
            expect_everywhere(text, |_| want.to_owned());
        }
        // `BEGIN NOT ATOMIC`: like a procedure (`*`, always reported),
        // with what its statements name.
        expect_everywhere(
            "BEGIN NOT ATOMIC SELECT * FROM hr.customers; END",
            |s| match star(s) {
                "*.*" => "read [\"*.*\", \"hr.customers\"] always".to_owned(),
                st => format!("read [\"hr.customers\", {st:?}] always"),
            },
        );
        expect_everywhere(
            "lbl: BEGIN NOT ATOMIC UPDATE performance_schema.setup_consumers SET ENABLED='NO'; END",
            |s| match star(s) {
                "*.*" => {
                    "write [\"*.*\", \"performance_schema.setup_consumers\"] always".to_owned()
                }
                st => format!("write [\"performance_schema.setup_consumers\", {st:?}] always"),
            },
        );
        // Not on the allow-list: a read of what they name, or of `*`.
        expect_everywhere(
            "SHOW TABLES WHERE (SELECT COUNT(*) FROM hr.customers) > 0",
            |_| "read [\"hr.customers\"]".to_owned(),
        );
        for text in ["DO 1", "XA START 'x'", "HELP 'select'", "END"] {
            expect_everywhere(text, |s| format!("read [{:?}]", star(s)));
        }
        // The allow-list: no event.
        for text in [
            "SET NAMES utf8mb4",
            "SET CHARACTER SET utf8mb4",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET autocommit = 1",
            "SET @x = 1",
            "SET @x = NOW()",
            "SET sql_mode = CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')",
            "FLUSH TABLES hr.customers FOR EXPORT",
            "USE hr",
            "BEGIN",
            "BEGIN WORK",
            "START TRANSACTION READ ONLY",
            "COMMIT",
            "ROLLBACK",
            "ROLLBACK TO SAVEPOINT s",
            "SAVEPOINT s",
            "RELEASE SAVEPOINT s",
            "SHOW TABLES",
            "SHOW GRANTS FOR CURRENT_USER()",
            "EXPLAIN SELECT * FROM hr.customers",
            "DESCRIBE hr.customers",
            "LOCK TABLES hr.customers READ",
            "UNLOCK TABLES",
            "FLUSH PRIVILEGES",
            "ANALYZE TABLE hr.customers",
            "ANALYZE NO_WRITE_TO_BINLOG TABLE hr.customers",
            "OPTIMIZE TABLE hr.customers",
            "CHECK TABLE hr.customers",
            "CHECKSUM TABLE hr.customers",
            "REPAIR TABLE hr.customers",
            "KILL 5",
            "KILL QUERY 5",
            "DEALLOCATE PREPARE s",
        ] {
            for user in ["app", "databastion"] {
                for (source, ev) in on_every_source(user, text) {
                    assert!(ev.is_none(), "{user} {source:?}: {text}");
                }
            }
        }
    }

    /// Re-review of c173fe8: `UPDATE` / `DELETE` / `REPLACE` modifiers,
    /// `EXPLAIN … ANALYZE` anywhere before the statement, `(TABLE …)` /
    /// `(VALUES …)` subqueries, and session `SET`s with function calls.
    #[test]
    fn modifiers_explain_forms_and_set_calls() {
        let consumers = "write [\"performance_schema.setup_consumers\"] always";
        for text in [
            "UPDATE LOW_PRIORITY performance_schema.setup_consumers SET ENABLED = 'NO'",
            "UPDATE IGNORE performance_schema.setup_consumers SET ENABLED = 'NO'",
            "DELETE LOW_PRIORITY QUICK IGNORE FROM performance_schema.setup_consumers",
            "REPLACE LOW_PRIORITY INTO performance_schema.setup_consumers VALUES ('x', 'NO')",
            "REPLACE DELAYED performance_schema.setup_consumers VALUES ('x', 'NO')",
        ] {
            expect_everywhere(text, |_| consumers.to_owned());
        }
        expect_everywhere(
            "UPDATE LOW_PRIORITY IGNORE performance_schema.setup_consumers, hr.a SET ENABLED = 'NO'",
            |_| "write [\"hr.a\", \"performance_schema.setup_consumers\"] always".to_owned(),
        );
        let actors = "write [\"performance_schema.setup_actors\"] always";
        for text in [
            "EXPLAIN ANALYZE FORMAT=JSON INTO @x DELETE FROM performance_schema.setup_actors",
            "EXPLAIN FORMAT=JSON INTO @x ANALYZE DELETE FROM performance_schema.setup_actors",
            // #184 review L3: a variable named like a statement keyword
            // is not the statement.
            "EXPLAIN FORMAT=JSON INTO @select ANALYZE DELETE FROM performance_schema.setup_actors",
            "EXPLAIN FORMAT=JSON INTO @table ANALYZE DELETE FROM performance_schema.setup_actors",
        ] {
            expect_everywhere(text, |_| actors.to_owned());
        }
        expect_everywhere(
            "EXPLAIN FORMAT=JSON INTO @select ANALYZE DELETE FROM hr.t",
            |_| "write [\"hr.t\"]".to_owned(),
        );
        for (source, ev) in on_every_source(
            "databastion",
            "EXPLAIN FORMAT=JSON INTO @select ANALYZE SELECT a FROM hr.t LIMIT 1",
        ) {
            assert!(ev.is_some(), "{source:?}");
        }
        // `ANALYZE` without a statement found: never quiet (`*`); the plan
        // of another connection shows its text (ADR-0045): always.
        expect_everywhere("EXPLAIN ANALYZE FOR CONNECTION 5", |s| {
            format!("read [{:?}] always", star(s))
        });
        for text in [
            "SHOW TABLES WHERE 'a' IN (TABLE hr.customers)",
            "SHOW TABLES WHERE ROW(1) IN (VALUES ROW(1)) AND 'a' IN (TABLE hr.customers)",
        ] {
            expect_everywhere(text, |_| "read [\"hr.customers\"]".to_owned());
        }
        // Session SETs: built-in calls are quiet; a stored or audit
        // function is not.
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(
                user,
                "SET sql_mode = CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')",
            ) {
                assert!(ev.is_none(), "{user} {source:?}");
            }
        }
        expect_everywhere("SET @x = hr.f()", |s| {
            format!("read [{:?}] always", star(s))
        });
        expect_everywhere("SET @x = audit_log_rotate()", |_| {
            "ddl [] always".to_owned()
        });
    }

    /// The canonical `db.table` of a statement-text table event object.
    fn text_object(db: &str, table: &str) -> String {
        format!("{db}.{table}")
    }

    /// A `server_audit` QUERY line in database `db` (no quote in `text`).
    fn sa_in(user: &str, host: &str, q: u64, db: &str, text: &str) -> String {
        assert!(!text.contains('\''));
        format!("20260929 09:40:35,h,{user},{host},30,{q},QUERY,{db},'{text}',0")
    }

    /// ADR-0045 decisions 1 and 3: every listed table, qualified,
    /// backquoted, in any case, in a `JOIN`, in a subquery of a `SET`, is
    /// a read naming it (as listed), always reported, from any account,
    /// the agent's included (decision 4), on every source.
    #[test]
    fn statement_text_tables_are_named_and_always_reported() {
        for (db, table, _) in STATEMENT_TEXT_TABLES {
            let named = text_object(db, table);
            let want = format!("read [{named:?}] always");
            for text in [
                format!("SELECT * FROM {db}.{table}"),
                format!("select * from `{db}`.`{table}` where 1 = 1 limit 5"),
                format!(
                    "SELECT COUNT(*) FROM {}.{}",
                    db.to_ascii_uppercase(),
                    table.to_ascii_uppercase()
                ),
                format!("SET @x = (SELECT COUNT(*) FROM {db}.{table})"),
                format!("DO (SELECT 1 FROM {db}.{table} LIMIT 1)"),
            ] {
                expect_everywhere(&text, |_| want.clone());
            }
            // In a `JOIN` with an application table: both.
            let mut both = [named.clone(), "hr.customers".to_owned()];
            both.sort();
            expect_everywhere(
                &format!("SELECT * FROM hr.customers c JOIN {db}.{table} p ON 1 = 1"),
                |_| format!("read {both:?} always"),
            );
            // Unqualified, in the statement's current database.
            for user in ["app", "databastion"] {
                let mut b = EventBuilder::new(own());
                let out = file(
                    &mut b,
                    sa_at(
                        &[sa_in(
                            user,
                            "172.18.0.1",
                            1,
                            db,
                            &format!("SELECT * FROM `{table}`"),
                        )],
                        1024,
                    ),
                );
                assert_eq!(out, [format!("read [{named:?}] None []")], "{user}");
                let mut b = EventBuilder::new(own());
                let text = format!("SELECT * FROM {table}");
                let mut access = pfs_access(text.as_bytes(), false, Vec::new());
                access.user = user;
                access.principal = EventPrincipal::account(user);
                access.database = db;
                let e = b.statement(access, SystemTime::now()).expect(user);
                assert!(e.always_report());
                assert_eq!(show(&e), format!("read [{named:?}] None []"), "{user}");
            }
        }
        // From table records only (`server_audit` `READ`), whatever the
        // text names.
        for user in ["app", "databastion"] {
            let mut b = EventBuilder::new(own());
            let ev = b.convert_file(
                sa_at(
                    &[
                        format!(
                            "20260929 09:40:35,h,{user},172.18.0.1,30,4,READ,PERFORMANCE_SCHEMA,EVENTS_STATEMENTS_HISTORY_LONG,"
                        ),
                        sa_line(user, "172.18.0.1", 4, "SELECT * FROM shop.v_statements"),
                    ],
                    1024,
                ),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                ev.iter().map(shown).collect::<Vec<_>>(),
                ["read [\"performance_schema.events_statements_history_long\"] always"],
                "{user}"
            );
        }
        // At most 16 relations per analyzed statement: a listed table
        // named after 16 others is not seen in the text, which fails
        // closed (`*`, always reported, never the agent's own).
        let many: Vec<String> = (0..20).map(|i| format!("hr.t{i:02}")).collect();
        let text = format!(
            "SELECT * FROM {}, information_schema.PROCESSLIST",
            many.join(", ")
        );
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(user, &text) {
                let e = ev.expect("event");
                assert!(e.always_report(), "{source:?}");
                assert_eq!(e.objects().len(), 16, "{source:?}");
                assert!(
                    e.objects().iter().any(|o| o.object().as_str() == "*"),
                    "{source:?}"
                );
            }
        }
        // With table records (at most 16 objects per event), the listed
        // table is named first, so it is kept.
        let mut lines: Vec<String> = (0..20)
            .map(|i| format!("20260929 09:40:35,h,app,10.0.0.5,30,5,READ,hr,t{i:02},"))
            .collect();
        lines.push(
            "20260929 09:40:35,h,app,10.0.0.5,30,5,READ,information_schema,PROCESSLIST,".to_owned(),
        );
        lines.push(sa_line("app", "10.0.0.5", 5, "SELECT * FROM shop.v_all"));
        let mut b = EventBuilder::new(own());
        let ev = b.convert_file(
            sa_at(&lines, 1024),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert_eq!(ev.len(), 1);
        assert!(ev[0].always_report());
        assert!(
            ev[0]
                .objects()
                .iter()
                .any(|o| o.object().as_str() == "PROCESSLIST")
        );
        // More statements than the analysis keeps (64): the last ones may
        // read a listed table; fail closed.
        let text = format!(
            "{}SELECT * FROM performance_schema.threads",
            "SELECT 1; ".repeat(64)
        );
        for user in ["app", "databastion"] {
            for (source, ev) in on_every_source(user, &text) {
                let e = ev.expect("event");
                assert!(e.always_report(), "{user} {source:?}");
            }
        }
        // A large monitoring read: no signal but `volume.large_result`.
        let mut b = EventBuilder::new(own());
        let mut access = pfs_access(
            b"SELECT * FROM performance_schema.events_statements_history_long",
            false,
            Vec::new(),
        );
        access.user = "app";
        access.principal = EventPrincipal::account("app");
        access.rows = Some(3);
        let e = b.statement(access, SystemTime::now()).unwrap();
        assert!(e.signals().is_empty(), "{}", show(&e));
    }

    /// `events_statements_summary_by_digest` holds statement texts with
    /// literals on MySQL (`QUERY_SAMPLE_TEXT`), digests only on MariaDB.
    #[test]
    fn statement_text_tables_follow_the_flavor() {
        let text = "SELECT * FROM performance_schema.events_statements_summary_by_digest";
        for (flavor, want) in [
            (
                Some(Flavor::Mysql),
                Some("read [\"performance_schema.events_statements_summary_by_digest\"] None []"),
            ),
            (Some(Flavor::Mariadb), None),
            (
                None,
                Some("read [\"performance_schema.events_statements_summary_by_digest\"] None []"),
            ),
        ] {
            let mut b = EventBuilder::new(own());
            if let Some(f) = flavor {
                b = b.with_flavor(f);
            }
            let out = file(&mut b, sa_at(&[sa_line("app", "10.0.0.5", 1, text)], 1024));
            assert_eq!(out.first().map(String::as_str), want, "{flavor:?}");
        }
        assert!(
            statement_text_table(Some(Flavor::Mariadb), "information_schema", "innodb_locks")
                .is_some()
        );
        assert!(
            statement_text_table(Some(Flavor::Mysql), "performance_schema", "DATA_LOCKS").is_some()
        );
        // Only `summary_by_digest` depends on the flavor; the version string
        // can lie (a proxy), so tables one flavor lacks are listed for both
        // (security review of #186, L2).
        for (db, t) in [
            ("performance_schema", "data_locks"),
            ("performance_schema", "processlist"),
            ("information_schema", "INNODB_LOCKS"),
            ("information_schema", "QUERY_CACHE_INFO"),
            ("information_schema", "INNODB_FT_INDEX_TABLE"),
            ("performance_schema", "user_variables_by_thread"),
        ] {
            for f in [Flavor::Mysql, Flavor::Mariadb] {
                assert!(statement_text_table(Some(f), db, t).is_some(), "{f:?} {t}");
            }
        }
        assert!(statement_text_table(None, "information_schema", "TABLES").is_none());
        assert!(statement_text_table(None, "hr", "threads").is_none());
    }

    /// ADR-0045 decision 2 and open question 3: `SHOW [FULL] PROCESSLIST`
    /// reads `information_schema.PROCESSLIST`; `SHOW ENGINE INNODB STATUS`
    /// and the plan of another connection are reads of `*`; all always
    /// reported, from any account.
    #[test]
    fn statements_showing_other_sessions_are_reported() {
        for text in [
            "SHOW PROCESSLIST",
            "SHOW FULL PROCESSLIST",
            "show /* x */ full processlist",
            "SET STATEMENT max_statement_time = 1 FOR SHOW FULL PROCESSLIST",
        ] {
            expect_everywhere(text, |_| {
                "read [\"information_schema.PROCESSLIST\"] always".to_owned()
            });
        }
        for text in [
            "SHOW ENGINE INNODB STATUS",
            "show engine innodb status",
            "SHOW ENGINE `InnoDB` STATUS",
            "SHOW EXPLAIN FOR 12",
            "SHOW EXPLAIN FORMAT=JSON FOR 12",
            "SHOW ANALYZE FOR 12",
            "EXPLAIN FOR CONNECTION 12",
            "EXPLAIN FORMAT=TREE FOR CONNECTION 12",
            "DESCRIBE FOR CONNECTION 12",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
        for text in [
            "SHOW ENGINE INNODB MUTEX",
            "SHOW ENGINE PERFORMANCE_SCHEMA STATUS",
            "SHOW ENGINES",
            "SHOW PROCEDURE STATUS",
            "EXPLAIN SELECT * FROM performance_schema.threads",
        ] {
            for user in ["app", "databastion"] {
                for (source, ev) in on_every_source(user, text) {
                    assert!(ev.is_none(), "{user} {source:?}: {text}");
                }
            }
        }
    }

    /// Security review of #186: a `USE` with another statement in one
    /// text, in either order (M1); the binary and relay log events (M3);
    /// an unqualified listed name in an unknown database (the JSON general
    /// records log none): always reported, never the agent's own.
    #[test]
    fn use_binlog_and_unknown_databases_fail_closed() {
        for text in [
            "USE performance_schema; SELECT SQL_TEXT FROM events_statements_history_long",
            "SELECT SQL_TEXT FROM events_statements_history_long; USE performance_schema",
            "USE hr; SELECT 1",
            "SELECT 1; USE performance_schema",
        ] {
            for user in ["app", "databastion"] {
                for (source, ev) in on_every_source(user, text) {
                    let e = ev.unwrap_or_else(|| panic!("{user} {source:?}: {text}"));
                    assert!(e.always_report(), "{user} {source:?}: {text}");
                    assert!(
                        e.objects().iter().any(|o| o.object().as_str() == "*"),
                        "{user} {source:?}: {text}"
                    );
                }
            }
        }
        // `USE` alone stays quiet.
        for (source, ev) in on_every_source("app", "USE performance_schema") {
            assert!(ev.is_none(), "{source:?}");
        }
        for text in [
            "SHOW BINLOG EVENTS",
            "SHOW BINLOG EVENTS IN 'binlog.000002' FROM 4 LIMIT 10",
            "show relaylog events",
            "SHOW RELAYLOG EVENTS FOR CHANNEL 'c'",
        ] {
            expect_everywhere(text, |s| format!("read [{:?}] always", star(s)));
        }
        for (source, ev) in on_every_source("app", "SHOW BINARY LOGS") {
            assert!(ev.is_none(), "{source:?}");
        }
        // An unqualified listed name with no database logged (the JSON
        // file and `performance_schema` records of these tests log none):
        // always reported, from any account; `server_audit` logs `shop`.
        for (table, want) in [
            ("events_statements_history_long", true),
            ("processlist", true),
            ("user_variables_by_thread", true),
            ("customers", false),
        ] {
            let text = format!("SELECT * FROM {table}");
            for user in ["app", "databastion"] {
                for (source, ev) in on_every_source(user, &text) {
                    if source == EventSource::MariadbServerAudit {
                        continue;
                    }
                    if want {
                        let e = ev.unwrap_or_else(|| panic!("{user} {source:?}: {text}"));
                        assert!(e.always_report(), "{user} {source:?}: {text}");
                    } else if let Some(e) = ev {
                        assert!(!e.always_report(), "{user} {source:?}: {text}");
                    }
                }
            }
        }
    }

    /// The events of `text` sent by `user` at the agent's address on each
    /// source, with the own-account counters `usage` (see
    /// [`on_every_source`]); `cut`: the record is marked cut (`server_audit`
    /// at a 16-byte limit, `performance_schema` flagged), `tables`: extra
    /// `server_audit` table records.
    fn own_sources(
        usage: &SharedOwnUsage,
        user: &str,
        text: &str,
        cut: bool,
        tables: &[(&str, &str)],
    ) -> Vec<(EventSource, Option<MaskedEvent>)> {
        let own = || {
            OwnAccount::new(
                "databastion",
                Some("databastion-agent"),
                ClientAddr::parse("172.18.0.1"),
                1000,
                usage.clone(),
            )
        };
        let mut out = Vec::new();
        let mut lines: Vec<String> = tables
            .iter()
            .map(|(db, t)| format!("20260929 09:40:35,h,{user},172.18.0.1,30,1,READ,{db},{t},"))
            .collect();
        lines.push(sa_line(user, "172.18.0.1", 1, text));
        let mut b = EventBuilder::new(own());
        let ev = b.convert_file(
            sa_at(&lines, if cut { 16 } else { 4096 }),
            EventSource::MariadbServerAudit,
            SystemTime::now(),
        );
        assert!(ev.len() <= 1, "{text}");
        out.push((EventSource::MariadbServerAudit, ev.into_iter().next()));
        if tables.is_empty() {
            let mut b = EventBuilder::new(own());
            let mut rec = json_query(user, "172.18.0.1", 1, text);
            rec.truncated = cut;
            let ev = b.convert_file(vec![rec], EventSource::MysqlAuditLog, SystemTime::now());
            out.push((EventSource::MysqlAuditLog, ev.into_iter().next()));
            let mut b = EventBuilder::new(own());
            let mut access = pfs_access(text.as_bytes(), cut, Vec::new());
            access.user = user;
            access.principal = EventPrincipal::account(user);
            access.rows = Some(1);
            out.push((
                EventSource::PerformanceSchema,
                b.statement(access, SystemTime::now()),
            ));
        }
        out
    }

    /// A changed own text: (text, cut, `server_audit` table records).
    type Case<'a> = (String, bool, Vec<(&'a str, &'a str)>);

    /// Whether `text` reads a listed table.
    fn reads_text_table(tables: &[&str]) -> bool {
        tables
            .iter()
            .any(|t| statement_text_table(None, "performance_schema", t).is_some())
    }

    /// ADR-0045 decision 4: the agent's own `performance_schema` probes
    /// and polls are left out, uncharged, only by their whole uncut text
    /// with table records of their own tables; the same text from another
    /// account, one byte changed, cut, or with another table record is
    /// reported, never charged; the `SET` of the poll variables is quiet.
    #[test]
    fn own_performance_schema_reads_are_matched_exactly() {
        let own_texts = crate::sql::own_performance_schema_reads();
        assert!(own_texts.len() >= 14);
        for (text, tables) in &own_texts {
            let listed = reads_text_table(tables);
            // The agent's own, exact: no event, no charge, with or
            // without its own table records.
            let usage = SharedOwnUsage::default();
            let records: Vec<(&str, &str)> =
                tables.iter().map(|t| ("performance_schema", *t)).collect();
            for recs in [&[][..], &records[..]] {
                for (source, ev) in own_sources(&usage, "databastion", text, false, recs) {
                    assert!(ev.is_none(), "{source:?}: {text}");
                }
            }
            assert!(
                usage.lock().unwrap().budgeted_objects().is_empty(),
                "{text}"
            );
            if !listed || text.starts_with("EXPLAIN ") {
                // `PS_CONSUMERS` (no listed table) and the readability
                // `EXPLAIN`s: quiet from any account.
                for (source, ev) in own_sources(&usage, "app", text, false, &[]) {
                    assert!(ev.is_none(), "{source:?}: {text}");
                }
                continue;
            }
            // Another account: reported, always.
            for (source, ev) in own_sources(&usage, "app", text, false, &[]) {
                assert!(ev.is_some_and(|e| e.always_report()), "{source:?}: {text}");
            }
            // One byte changed, a byte added, cut, another table record:
            // reported, never charged.
            let changed = [
                format!("{text} "),
                text.replacen("SELECT", "select", 1),
                text.replacen(" FROM ", "  FROM ", 1),
                format!("{text} -- x"),
            ];
            let mut cases: Vec<Case<'_>> = changed
                .iter()
                .map(|t| (t.clone(), false, Vec::new()))
                .collect();
            cases.push((text.clone(), true, Vec::new()));
            let mut extra = records.clone();
            extra.push(("performance_schema", "events_statements_history"));
            extra.push(("hr", "customers"));
            cases.push((text.clone(), false, extra.clone()));
            cases.push((
                text.clone(),
                false,
                vec![("information_schema", "PROCESSLIST")],
            ));
            for (t, cut, recs) in &cases {
                for (source, ev) in own_sources(&usage, "databastion", t, *cut, recs) {
                    // A changed text that no longer lexes may only be
                    // reported against `*`; it is reported in any case.
                    let e = ev.unwrap_or_else(|| panic!("{source:?} cut={cut} {recs:?}: {t}"));
                    assert!(e.always_report(), "{source:?}: {t}");
                }
            }
            assert!(
                usage.lock().unwrap().budgeted_objects().is_empty(),
                "charged: {text}"
            );
        }
        // The session variables of the poll texts: quiet, from any account.
        for user in ["databastion", "app"] {
            for (source, ev) in
                on_every_source(user, &crate::sql::ps_poll_variables(1_234_567_890_123))
            {
                assert!(ev.is_none(), "{user} {source:?}");
            }
        }
        // Another address: not the agent's identity.
        let mut b = EventBuilder::new(own());
        let out = file(
            &mut b,
            sa_at(
                &[sa_line(
                    "databastion",
                    "10.9.9.9",
                    1,
                    crate::sql::PS_OWN_THREAD,
                )],
                1024,
            ),
        );
        assert_eq!(out, ["read [\"performance_schema.threads\"] None []"]);
        // The CAS store guard's exact text with a statement-text table
        // record: reported.
        for set in guard_sets() {
            let mut b = guard_builder(&set);
            let ev = b.convert_file(
                sa_at(
                    &[
                        "20260929 09:40:35,h,databastion,172.18.0.1,30,1,READ,information_schema,PROCESSLIST,".to_owned(),
                        sa_query("databastion", "172.18.0.1", 1, &set[0], None),
                    ],
                    1024,
                ),
                EventSource::MariadbServerAudit,
                SystemTime::now(),
            );
            assert_eq!(
                ev.iter().map(shown).collect::<Vec<_>>(),
                ["read [\"information_schema.PROCESSLIST\"] always"]
            );
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
