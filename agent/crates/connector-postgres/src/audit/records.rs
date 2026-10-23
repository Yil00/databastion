//! Server log records: splitting (jsonlog, csvlog), and parsing of the
//! pgaudit `AUDIT:` records (ADR-0012 obligation 7) and of the server's
//! `ERROR` and `FATAL` lines of client backends (ADR-0037, refinement of
//! 2026-10-12: failed and cancelled statements, [`ErrorLine`]).
//!
//! - Records are split out of the byte stream by the core's tailer
//!   (`databastion_core::audit::tail`), with a bound: a longer record is
//!   skipped to its end and counted, never buffered.
//! - Only records whose message starts with `AUDIT: ` are parsed. From
//!   them, only the structured fields are kept (time, user, database,
//!   client address, application, session) plus the pgaudit fields; the
//!   statement text is kept in a zeroizing buffer for the local analysis
//!   (`classifiers::query`) and never logged. `detail`, `hint`,
//!   `context`, `internal_query` and the pgaudit parameter field are never
//!   read.
//! - From an `ERROR` or `FATAL` line, only the severity, the SQLSTATE, the
//!   identity fields (time, user, database, client address, application,
//!   session, virtual transaction) and the statement text are kept (I2,
//!   ADR-0037 refinement item 2): `message`, `detail`, `hint`, `context`
//!   and `internal_query`, which can quote values, are never copied. In
//!   jsonlog they are skipped as `serde::de::IgnoredAny`; in csvlog their
//!   columns are walked inside the tailer's zeroized buffer without being
//!   copied ([`csv_pick`]). Of `context`, only its presence is tested
//!   (F1).
//! - A record (or a pgaudit payload) whose CSV does not parse is dropped.

use std::fmt;
use std::time::{Duration, SystemTime};

use databastion_core::audit::tail::Framing;
use zeroize::Zeroizing;

/// Longest CSV field count accepted in a record.
const MAX_FIELDS: usize = 64;
/// Most columns of a csvlog record: the largest layout PostgreSQL writes
/// (26 since PostgreSQL 14, with `backend_type`, `leader_pid` and
/// `query_id`). A record with more is not one the server wrote (a hybrid
/// of a damaged record and the next: security review of #278, M1).
const MAX_CSV_COLUMNS: usize = 26;
/// Prefix of pgaudit messages.
const AUDIT_PREFIX: &str = "AUDIT: ";

/// Format of the server log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Jsonlog,
    Csvlog,
}

impl Format {
    /// How records are delimited in a log of this format.
    pub(crate) fn framing(self) -> Framing {
        match self {
            Self::Jsonlog => Framing::Lines,
            Self::Csvlog => Framing::Csv,
        }
    }
}

/// Parses one CSV record (RFC 4180 as written by PostgreSQL: `"` quoting
/// with `""` escapes, fields may hold newlines when quoted). Strict: a
/// quote inside an unquoted field, or text after a closing quote, fails.
pub(crate) fn parse_csv(record: &str) -> Option<Vec<Zeroizing<String>>> {
    let mut fields = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut chars = record.chars().peekable();
    let mut quoted = false;
    let mut at_start = true;
    let mut closed = false;
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            ',' => {
                fields.push(std::mem::replace(&mut field, Zeroizing::new(String::new())));
                if fields.len() > MAX_FIELDS {
                    return None;
                }
                at_start = true;
                closed = false;
            }
            '"' if at_start => {
                quoted = true;
                at_start = false;
            }
            _ if closed || c == '"' => return None,
            _ => {
                field.push(c);
                at_start = false;
            }
        }
    }
    if quoted {
        return None;
    }
    fields.push(field);
    Some(fields)
}

/// The pgaudit fields of an `AUDIT:` message.
pub(crate) struct PgAudit {
    /// `OBJECT` (object audit) rather than `SESSION`.
    pub(crate) object_audit: bool,
    pub(crate) statement_id: u64,
    pub(crate) substatement_id: u64,
    /// `READ`, `WRITE`, `FUNCTION`, `ROLE`, `DDL`, `MISC`, `MISC_SET`.
    pub(crate) class: String,
    /// Command tag (`SELECT`, `COPY`…).
    pub(crate) command: String,
    pub(crate) object_type: String,
    /// Qualified object name as logged (`schema.table`), may be empty.
    pub(crate) object_name: Zeroizing<String>,
    /// Statement text: local analysis only, never logged or sent.
    pub(crate) statement: Zeroizing<String>,
    /// `pgaudit.log_rows` field, when present.
    pub(crate) rows: Option<u64>,
}

impl fmt::Debug for PgAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgAudit")
            .field("object_audit", &self.object_audit)
            .field("statement_id", &self.statement_id)
            .field("substatement_id", &self.substatement_id)
            .field("class", &self.class)
            .field("command", &self.command)
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

/// A closed token of the pgaudit payload (class, command, object type):
/// upper-case letters, digits, `_` and spaces, at most 64 bytes.
fn closed_token(s: &str) -> Option<String> {
    (s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b' '))
    .then(|| s.to_owned())
}

/// Parses the payload after `AUDIT: `: `AUDIT_TYPE,STATEMENT_ID,
/// SUBSTATEMENT_ID,CLASS,COMMAND,OBJECT_TYPE,OBJECT_NAME,STATEMENT,
/// PARAMETER[,ROWS]`. The parameter field is discarded.
pub(crate) fn parse_pgaudit(message: &str) -> Option<PgAudit> {
    let payload = message.strip_prefix(AUDIT_PREFIX)?;
    let mut f = parse_csv(payload)?;
    if !(9..=10).contains(&f.len()) {
        return None;
    }
    let rows = if f.len() == 10 {
        Some(f[9].parse::<u64>().ok()?)
    } else {
        None
    };
    let object_audit = match f[0].as_str() {
        "OBJECT" => true,
        "SESSION" => false,
        _ => return None,
    };
    let statement = std::mem::take(&mut *f[7]);
    let object_name = std::mem::take(&mut *f[6]);
    Some(PgAudit {
        object_audit,
        statement_id: f[1].parse().ok()?,
        substatement_id: f[2].parse().ok()?,
        class: closed_token(&f[3])?,
        command: closed_token(&f[4])?,
        object_type: closed_token(&f[5])?,
        object_name: Zeroizing::new(object_name),
        statement: Zeroizing::new(statement),
        rows,
    })
}

/// A pgaudit record with the structured fields of its log line.
pub(crate) struct AuditRecord {
    pub(crate) ts: Option<SystemTime>,
    pub(crate) user: String,
    pub(crate) database: String,
    /// Client host as logged (IP literal, `[local]`, or a host name with
    /// `log_hostname`); only an IP or `[local]` is ever kept downstream.
    pub(crate) remote: Option<String>,
    pub(crate) application: String,
    pub(crate) session: String,
    /// Virtual transaction id (`backend/local`), empty when not logged.
    pub(crate) vxid: String,
    pub(crate) audit: PgAudit,
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("session", &self.session)
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

/// The jsonlog keys read. Everything else (`detail`, `hint`, `context`,
/// `statement`, `internal_query`…) is skipped unread by serde.
#[derive(serde::Deserialize)]
struct JsonLine {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    dbname: Option<String>,
    #[serde(default)]
    remote_host: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    vxid: Option<String>,
    #[serde(default)]
    application_name: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error_severity: Option<String>,
    /// Only its presence is checked (pgaudit hides the context); the
    /// text is never kept.
    #[serde(default)]
    context: Option<serde::de::IgnoredAny>,
}

/// Severity written in the server log for a `pgaudit.log_level` value
/// (`debug1`…`debug5` are all written `DEBUG`). Default: `LOG`.
pub(crate) fn expected_severity(log_level: Option<&str>) -> String {
    let level = log_level.unwrap_or("log").trim().to_ascii_uppercase();
    if level.starts_with("DEBUG") {
        "DEBUG".to_owned()
    } else if level.is_empty() {
        "LOG".to_owned()
    } else {
        level
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Parses one log record; `None` unless it is a well-formed pgaudit
/// record.
///
/// Forgery: any role can write `AUDIT: …` into the server log (`RAISE LOG`
/// in PL/pgSQL). pgaudit emits its records at `pgaudit.log_level` with the
/// error context hidden, so a record whose severity differs from
/// `severity` (see [`expected_severity`]) or that carries a context (a
/// `RAISE` always has one, `… at RAISE`) is dropped. What remains forgeable
/// needs native code that hides the context (C
/// extensions, untrusted PLs). `log_error_verbosity = terse` does not
/// remove it from jsonlog nor csvlog (verified on PostgreSQL 16.13: a
/// `RAISE` line still has its context with `terse`).
#[cfg(test)]
pub(crate) fn parse_record(format: Format, record: &[u8], severity: &str) -> Option<AuditRecord> {
    parse_record_checked(format, record, severity).ok()
}

/// Why a log record gives no pgaudit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Skip {
    /// Not an `AUDIT:` record, or malformed.
    NotAudit,
    /// Carries an error context: forged (`RAISE`).
    Context,
    /// Well-formed, no context, but another severity than
    /// `pgaudit.log_level`: likely genuine (the setting changed, or it
    /// differs per database or role). Counted and warned.
    Severity,
    /// An `ERROR` or `FATAL` line that cannot be read: counted as dropped.
    Damaged,
}

/// [`parse_record`] with the reason a record is dropped.
pub(crate) fn parse_record_checked(
    format: Format,
    record: &[u8],
    severity: &str,
) -> Result<AuditRecord, Skip> {
    let check = |sev: Option<&str>, has_context: bool| {
        if has_context {
            Err(Skip::Context)
        } else if sev != Some(severity) {
            Err(Skip::Severity)
        } else {
            Ok(())
        }
    };
    match format {
        Format::Jsonlog => {
            // Cheap pre-filter: other records are never deserialized.
            if !contains(record, b"\"message\":\"AUDIT: ") {
                return Err(Skip::NotAudit);
            }
            let line: JsonLine = serde_json::from_slice(record).map_err(|_| Skip::NotAudit)?;
            let message = Zeroizing::new(line.message.ok_or(Skip::NotAudit)?);
            let audit = parse_pgaudit(&message).ok_or(Skip::NotAudit)?;
            check(line.error_severity.as_deref(), line.context.is_some())?;
            Ok(AuditRecord {
                ts: line.timestamp.as_deref().and_then(parse_log_time),
                user: line.user.ok_or(Skip::NotAudit)?,
                database: line.dbname.ok_or(Skip::NotAudit)?,
                remote: line.remote_host,
                application: line.application_name.unwrap_or_default(),
                session: line.session_id.unwrap_or_default(),
                vxid: line.vxid.unwrap_or_default(),
                audit,
            })
        }
        Format::Csvlog => {
            if !contains(record, b",\"AUDIT: ") {
                return Err(Skip::NotAudit);
            }
            let text = std::str::from_utf8(record).map_err(|_| Skip::NotAudit)?;
            let f = parse_csv(text).ok_or(Skip::NotAudit)?;
            if f.len() < 23 || f.len() > MAX_CSV_COLUMNS {
                return Err(Skip::NotAudit);
            }
            let audit = parse_pgaudit(&f[13]).ok_or(Skip::NotAudit)?;
            // error_severity (11), context (18).
            check(Some(f[11].as_str()), !f[18].is_empty())?;
            // `connection_from` is `host:port` or `[local]`.
            let remote = csv_remote(f[4].as_str());
            Ok(AuditRecord {
                ts: parse_log_time(&f[0]),
                user: f[1].to_string(),
                database: f[2].to_string(),
                remote,
                application: f[22].to_string(),
                session: f[5].to_string(),
                vxid: f[9].to_string(),
                audit,
            })
        }
    }
}

/// A SQLSTATE: five characters of `[0-9A-Z]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SqlState([u8; 5]);

impl SqlState {
    /// `None` unless `s` is five characters of `[0-9A-Z]`.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let b: [u8; 5] = s.as_bytes().try_into().ok()?;
        b.iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
            .then_some(Self(b))
    }

    pub(crate) fn as_str(&self) -> &str {
        // Five ASCII bytes, checked by `parse`.
        std::str::from_utf8(&self.0).unwrap_or("XX000")
    }

    /// The class: the first two characters.
    pub(crate) fn class(&self) -> &str {
        self.as_str().get(..2).unwrap_or("XX")
    }
}

impl fmt::Debug for SqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An `ERROR` or `FATAL` line of a client backend (ADR-0037, refinement of
/// 2026-10-12, item 1): the fields that cannot quote a value, and the
/// statement text, kept for the local analysis only.
pub(crate) struct ErrorLine {
    pub(crate) ts: Option<SystemTime>,
    pub(crate) user: String,
    pub(crate) database: String,
    /// Client host as logged (see [`AuditRecord::remote`]).
    pub(crate) remote: Option<String>,
    pub(crate) application: String,
    pub(crate) session: String,
    /// Virtual transaction id (`backend/local`): ties a line to the
    /// pgaudit record of the same statement (item 4).
    pub(crate) vxid: String,
    /// `FATAL` rather than `ERROR`.
    pub(crate) fatal: bool,
    /// `None`: missing or malformed (an unknown code, fail closed).
    pub(crate) sqlstate: Option<SqlState>,
    /// The line has an error context (only its presence is read, F1).
    pub(crate) has_context: bool,
    /// Statement text (`statement` in jsonlog, `query` in csvlog): local
    /// analysis only, never logged or sent. `None` when not logged.
    pub(crate) statement: Option<Zeroizing<String>>,
}

impl fmt::Debug for ErrorLine {
    // No statement text, no identity (they can hold anything).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorLine")
            .field("fatal", &self.fatal)
            .field("sqlstate", &self.sqlstate)
            .field("has_context", &self.has_context)
            .field("statement", &self.statement.as_ref().map(|s| s.len()))
            .finish_non_exhaustive()
    }
}

/// One parsed log record.
#[derive(Debug)]
pub(crate) enum LogEntry {
    Audit(AuditRecord),
    Error(ErrorLine),
}

/// The jsonlog keys of an `ERROR` or `FATAL` line. `message`, `detail`,
/// `hint`, `context` and `internal_query` can quote values (I2): they are
/// declared only to be skipped as [`serde::de::IgnoredAny`], which reads
/// past a value without copying it; `context` is only tested for presence
/// (F1). Any other key is skipped the same way by serde.
#[derive(serde::Deserialize)]
struct JsonErrorLine {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    dbname: Option<String>,
    #[serde(default)]
    remote_host: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    vxid: Option<String>,
    #[serde(default)]
    application_name: Option<String>,
    #[serde(default)]
    backend_type: Option<String>,
    #[serde(default)]
    error_severity: Option<String>,
    #[serde(default)]
    state_code: Option<String>,
    /// Deserialized straight into a zeroizing buffer, so that it is wiped
    /// also when a later key fails the line.
    #[serde(default, deserialize_with = "zeroizing_string")]
    statement: Option<Zeroizing<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    message: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    #[allow(dead_code)]
    detail: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    #[allow(dead_code)]
    hint: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    context: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    #[allow(dead_code)]
    internal_query: Option<serde::de::IgnoredAny>,
}

/// Backend types (`backend_type`) of the server's own processes, whose
/// lines are not read: their errors are no client's statement
/// (autovacuum's "canceling autovacuum task"), or are re-raised by the
/// leader whose line is read (parallel workers). A closed list: `client
/// backend`, `walsender` (replication clients), `standalone backend`,
/// background workers of extensions (`pg_cron`…), a missing and any other
/// type are read (fails closed).
const SYSTEM_PROCESSES: [&str; 20] = [
    "autovacuum launcher",
    "autovacuum worker",
    "archiver",
    "background writer",
    "checkpointer",
    "io worker",
    "logger",
    "logical replication launcher",
    "logical replication worker",
    "logical replication apply worker",
    "logical replication parallel worker",
    "logical replication tablesync worker",
    "parallel worker",
    "postmaster",
    "slotsync worker",
    "startup",
    "walreceiver",
    "walsummarizer",
    "walwriter",
    "wal summarizer",
];

/// Whether a line's backend type is one of [`SYSTEM_PROCESSES`].
pub(crate) fn system_process(backend_type: &str) -> bool {
    SYSTEM_PROCESSES.contains(&backend_type)
}

/// Deserializes an optional string straight into a [`Zeroizing`] buffer
/// (one allocation of the exact size; `serde_json`'s own scratch buffer
/// for a string with escapes is outside this connector's reach).
fn zeroizing_string<'de, D>(d: D) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Inner;
    impl<'de> serde::de::Visitor<'de> for Inner {
        type Value = Zeroizing<String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let mut out = Zeroizing::new(String::with_capacity(v.len()));
            out.push_str(v);
            Ok(out)
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(v))
        }
    }
    struct Outer;
    impl<'de> serde::de::Visitor<'de> for Outer {
        type Value = Option<Zeroizing<String>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
            d.deserialize_str(Inner).map(Some)
        }
    }
    d.deserialize_option(Outer)
}

/// csvlog columns (PostgreSQL 13+).
mod col {
    pub(super) const TIME: usize = 0;
    pub(super) const USER: usize = 1;
    pub(super) const DATABASE: usize = 2;
    pub(super) const FROM: usize = 4;
    pub(super) const SESSION: usize = 5;
    pub(super) const VXID: usize = 9;
    pub(super) const SEVERITY: usize = 11;
    pub(super) const SQLSTATE: usize = 12;
    pub(super) const CONTEXT: usize = 18;
    pub(super) const QUERY: usize = 19;
    pub(super) const APPLICATION: usize = 22;
    pub(super) const BACKEND_TYPE: usize = 23;
}

/// The columns copied out of a csvlog `ERROR` / `FATAL` line, in this
/// order. `message` (13), `detail` (14), `hint` (15), `internal_query`
/// (16) and `context` (18) are not among them.
const CSV_PICKED: [usize; 11] = [
    col::TIME,
    col::USER,
    col::DATABASE,
    col::FROM,
    col::SESSION,
    col::VXID,
    col::SEVERITY,
    col::SQLSTATE,
    col::QUERY,
    col::APPLICATION,
    col::BACKEND_TYPE,
];

/// The picked columns of a CSV record, and whether each column is present
/// (quoted, or not empty).
pub(crate) struct CsvPick {
    /// One per picked column, in the order asked; empty when the record
    /// has fewer columns.
    pub(crate) picked: Vec<Zeroizing<String>>,
    /// Per column of the record: present.
    pub(crate) present: Vec<bool>,
}

/// [`parse_csv`] that copies only the columns in `pick` out of `record`,
/// walking every other column in place (the tailer's zeroized buffer):
/// their text is never copied (I2). Same strictness as [`parse_csv`].
///
/// `reserve`: a picked column (the statement text) whose buffer gets the
/// record's length as capacity before any character is pushed, so that it
/// never grows: a reallocation would leave the earlier, shorter copy in
/// freed memory, not zeroized.
pub(crate) fn csv_pick(record: &str, pick: &[usize], reserve: Option<usize>) -> Option<CsvPick> {
    let mut picked: Vec<Zeroizing<String>> = pick
        .iter()
        .map(|&c| {
            Zeroizing::new(if Some(c) == reserve {
                String::with_capacity(record.len())
            } else {
                String::new()
            })
        })
        .collect();
    let mut present = Vec::new();
    let mut index = 0usize;
    // Position in `picked` of the current column, when it is picked.
    let slot = |i: usize| pick.iter().position(|&p| p == i);
    let mut current = slot(0);
    let mut field_present = false;
    let mut chars = record.chars().peekable();
    let mut quoted = false;
    let mut at_start = true;
    let mut closed = false;
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    if let Some(k) = current {
                        picked[k].push('"');
                    }
                } else {
                    quoted = false;
                    closed = true;
                }
            } else if let Some(k) = current {
                picked[k].push(c);
            }
            continue;
        }
        match c {
            ',' => {
                present.push(field_present);
                index += 1;
                if index > MAX_FIELDS {
                    return None;
                }
                current = slot(index);
                field_present = false;
                at_start = true;
                closed = false;
            }
            '"' if at_start => {
                quoted = true;
                field_present = true;
                at_start = false;
            }
            _ if closed || c == '"' => return None,
            _ => {
                if let Some(k) = current {
                    picked[k].push(c);
                }
                field_present = true;
                at_start = false;
            }
        }
    }
    if quoted {
        return None;
    }
    present.push(field_present);
    Some(CsvPick { picked, present })
}

/// The client address of a csvlog `connection_from` (`host:port` or
/// `[local]`).
fn csv_remote(from: &str) -> Option<String> {
    if from.is_empty() {
        None
    } else if from == "[local]" {
        Some(from.to_owned())
    } else {
        Some(
            from.rsplit_once(':')
                .map_or(from, |(host, _port)| host)
                .to_owned(),
        )
    }
}

/// `Some(fatal)` for the severities of the lines read.
pub(crate) fn is_error_severity(sev: &str) -> Option<bool> {
    match sev {
        "ERROR" => Some(false),
        "FATAL" => Some(true),
        _ => None,
    }
}

/// Parses an `ERROR` or `FATAL` line of a client backend. `Ok(None)` for
/// a line of that severity from another process; `Err(NotAudit)` for any
/// other record; `Err(Damaged)` for a line of that severity that cannot be
/// read (counted as dropped: never a silent loss).
pub(crate) fn parse_error_line(format: Format, record: &[u8]) -> Result<Option<ErrorLine>, Skip> {
    match format {
        Format::Jsonlog => {
            // Cheap pre-filter: a `"` inside a jsonlog value is escaped, so
            // these bytes are the key and its value.
            if !contains(record, b"\"error_severity\":\"ERROR\"")
                && !contains(record, b"\"error_severity\":\"FATAL\"")
            {
                return Err(Skip::NotAudit);
            }
            let line: JsonErrorLine = serde_json::from_slice(record).map_err(|_| Skip::Damaged)?;
            let fatal = line
                .error_severity
                .as_deref()
                .and_then(is_error_severity)
                .ok_or(Skip::NotAudit)?;
            if line.backend_type.as_deref().is_some_and(system_process) {
                return Ok(None);
            }
            let statement = line.statement;
            Ok(Some(ErrorLine {
                ts: line.timestamp.as_deref().and_then(parse_log_time),
                user: line.user.unwrap_or_default(),
                database: line.dbname.unwrap_or_default(),
                remote: line.remote_host,
                application: line.application_name.unwrap_or_default(),
                session: line.session_id.unwrap_or_default(),
                vxid: line.vxid.unwrap_or_default(),
                fatal,
                sqlstate: line.state_code.as_deref().and_then(SqlState::parse),
                has_context: line.context.is_some(),
                statement,
            }))
        }
        Format::Csvlog => {
            if !contains(record, b",ERROR,") && !contains(record, b",FATAL,") {
                return Err(Skip::NotAudit);
            }
            let text = std::str::from_utf8(record).map_err(|_| Skip::NotAudit)?;
            let mut p = csv_pick(text, &CSV_PICKED, Some(col::QUERY)).ok_or(Skip::NotAudit)?;
            // More columns than PostgreSQL writes: not a line of the
            // server (security review of #278, M1); counted as dropped.
            if p.present.len() > MAX_CSV_COLUMNS {
                return Err(Skip::Damaged);
            }
            let field = |c: usize| -> &str {
                CSV_PICKED
                    .iter()
                    .position(|&x| x == c)
                    .map_or("", |k| p.picked[k].as_str())
            };
            let Some(fatal) = is_error_severity(field(col::SEVERITY)) else {
                return Err(Skip::NotAudit);
            };
            // A record without the backend type column (before
            // PostgreSQL 13) is read: an unknown type (fails closed).
            if system_process(field(col::BACKEND_TYPE)) {
                return Ok(None);
            }
            // Moved out of its reserved, zeroizing buffer: never copied.
            let query = CSV_PICKED
                .iter()
                .position(|&x| x == col::QUERY)
                .map(|k| std::mem::take(&mut *p.picked[k]))
                .map(Zeroizing::new)
                .unwrap_or_default();
            let field = |c: usize| -> &str {
                CSV_PICKED
                    .iter()
                    .position(|&x| x == c)
                    .map_or("", |k| p.picked[k].as_str())
            };
            Ok(Some(ErrorLine {
                ts: parse_log_time(field(col::TIME)),
                user: field(col::USER).to_owned(),
                database: field(col::DATABASE).to_owned(),
                remote: csv_remote(field(col::FROM)),
                application: field(col::APPLICATION).to_owned(),
                session: field(col::SESSION).to_owned(),
                vxid: field(col::VXID).to_owned(),
                fatal,
                sqlstate: SqlState::parse(field(col::SQLSTATE)),
                has_context: p.present.get(col::CONTEXT).copied().unwrap_or(false),
                statement: (!query.is_empty()).then_some(query),
            }))
        }
    }
}

/// Parses one log record: an `ERROR` / `FATAL` line of a client backend
/// ([`parse_error_line`]; pgaudit never logs at those severities, its
/// `log_level` cannot be set to them), else a pgaudit record
/// ([`parse_record_checked`]).
pub(crate) fn parse_entry(format: Format, record: &[u8], severity: &str) -> Result<LogEntry, Skip> {
    match parse_error_line(format, record) {
        Ok(Some(line)) => return Ok(LogEntry::Error(line)),
        Ok(None) => return Err(Skip::NotAudit),
        Err(Skip::NotAudit) => {}
        Err(other) => return Err(other),
    }
    parse_record_checked(format, record, severity).map(LogEntry::Audit)
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses a server log time `YYYY-MM-DD HH:MM:SS[.fff] TZ`. Only `UTC`,
/// `GMT` and numeric offsets (`+02`, `-0530`) are read; any other time
/// zone abbreviation is ambiguous and gives `None` (the caller then uses
/// the time the record was read; `log_timezone = UTC` is recommended).
pub(crate) fn parse_log_time(s: &str) -> Option<SystemTime> {
    let (date, rest) = s.split_once(' ')?;
    let (time, zone) = rest.split_once(' ').unwrap_or((rest, "UTC"));
    let mut d = date.splitn(3, '-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: u32 = d.next()?.parse().ok()?;
    let da: u32 = d.next()?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut t = hms.splitn(3, ':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let se: i64 = t.next()?.parse().ok()?;
    if h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let frac: String = frac.chars().take(9).collect();
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let nanos: u32 = format!("{frac:0<9}").parse().ok()?;
    let offset_s: i64 = match zone {
        "UTC" | "GMT" | "Z" => 0,
        z if z.starts_with('+') || z.starts_with('-') => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits = &z[1..];
            if !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let (hh, mm) = match digits.len() {
                2 => (digits.parse::<i64>().ok()?, 0),
                4 => (
                    digits[..2].parse::<i64>().ok()?,
                    digits[2..].parse::<i64>().ok()?,
                ),
                _ => return None,
            };
            sign * (hh * 3600 + mm * 60)
        }
        _ => return None,
    };
    let secs = days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + se - offset_s;
    let secs = u64::try_from(secs).ok()?;
    Some(
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(u64::from(nanos)),
    )
}

/// Tests: a pgaudit record of `session` with `text` (statement 1).
#[cfg(test)]
pub(crate) fn tests_audit_record(session: &str, text: &str, rows: Option<u64>) -> AuditRecord {
    let rows = rows.map_or(String::new(), |r| format!(",{r}"));
    let line = serde_json::json!({
        "timestamp": "2026-09-28 21:45:31.320 UTC", "user": "backup", "dbname": "shop",
        "error_severity": "LOG", "remote_host": "192.0.2.14", "session_id": session,
        "application_name": "psql", "backend_type": "client backend",
        "message": format!(
            "AUDIT: SESSION,1,1,READ,SELECT,,,\"{}\",<not logged>{rows}",
            text.replace('"', "\"\"")
        ),
    });
    parse_record(Format::Jsonlog, line.to_string().as_bytes(), "LOG").unwrap_or_else(|| {
        #[allow(clippy::panic)]
        {
            panic!("test record does not parse")
        }
    })
}

/// Tests: an `ERROR` line of `session` with `code` and `text`.
#[cfg(test)]
pub(crate) fn tests_error_line(
    session: &str,
    code: &str,
    text: Option<&str>,
    vxid: &str,
) -> ErrorLine {
    let mut v = serde_json::json!({
        "timestamp": "2026-09-28 21:45:32.000 UTC", "user": "backup", "dbname": "shop",
        "error_severity": "ERROR", "state_code": code, "remote_host": "192.0.2.14",
        "session_id": session, "vxid": vxid, "application_name": "psql",
        "backend_type": "client backend", "message": "m",
    });
    if let Some(t) = text {
        v["statement"] = serde_json::Value::from(t);
    }
    parse_error_line(Format::Jsonlog, v.to_string().as_bytes())
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            #[allow(clippy::panic)]
            {
                panic!("test line does not parse")
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_AUDIT: &str = r#"{"timestamp":"2026-09-28 21:45:31.320 UTC","user":"postgres","dbname":"shop","pid":1007,"remote_host":"127.0.0.1","remote_port":42682,"session_id":"6abadffb.3ef","line_num":5,"ps":"SELECT","session_start":"2026-09-28 21:45:31 UTC","vxid":"3/56","txid":0,"error_severity":"LOG","message":"AUDIT: OBJECT,2,1,READ,SELECT,TABLE,crm.customers,select count(*) from crm.customers where email like '%x%',<not logged>,1","application_name":"psql","backend_type":"client backend","query_id":4482980966766602260}"#;

    const CSV_MULTILINE: &str = "2026-09-28 21:45:31.455 UTC,\"postgres\",\"shop\",1015,\"127.0.0.1:42692\",6abadffb.3f7,8,\"PREPARE\",2026-09-28 21:45:31 UTC,3/71,0,LOG,00000,\"AUDIT: SESSION,5,1,READ,PREPARE,,,\"\"PREPARE dumpFunc(pg_catalog.oid) AS\nSELECT\nproretset, 'lit,eral'\nFROM pg_catalog.pg_proc p\"\",<not logged>,1\",,,,,,,,,\"pg_dump\",\"client backend\",,6233516217350320405\n";

    use databastion_core::audit::tail::{MAX_RECORD_BYTES, Splitter};

    fn split(format: Format, data: &[u8], max: usize) -> (Vec<Vec<u8>>, Splitter) {
        let mut s = Splitter::with_max(format.framing(), max);
        let mut out = Vec::new();
        s.feed(data, &mut out);
        (out.into_iter().map(|r| r.to_vec()).collect(), s)
    }

    #[test]
    fn jsonlog_audit_record_is_parsed() {
        let r = parse_record(Format::Jsonlog, JSON_AUDIT.as_bytes(), "LOG").unwrap();
        assert_eq!(r.user, "postgres");
        assert_eq!(r.database, "shop");
        assert_eq!(r.remote.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.application, "psql");
        assert_eq!(r.session, "6abadffb.3ef");
        assert!(r.audit.object_audit);
        assert_eq!(r.audit.statement_id, 2);
        assert_eq!(r.audit.class, "READ");
        assert_eq!(r.audit.command, "SELECT");
        assert_eq!(r.audit.object_type, "TABLE");
        assert_eq!(r.audit.object_name.as_str(), "crm.customers");
        assert_eq!(r.audit.rows, Some(1));
        assert!(r.audit.statement.contains("email like"));
        assert!(r.ts.is_some());
        // Debug never shows the statement.
        assert!(!format!("{r:?}").contains("email"));
    }

    #[test]
    fn csvlog_multiline_record_is_split_and_parsed() {
        let data = format!("{CSV_MULTILINE}{CSV_MULTILINE}partial,\"open");
        let (records, s) = split(Format::Csvlog, data.as_bytes(), MAX_RECORD_BYTES);
        assert_eq!(records.len(), 2);
        assert_eq!(s.pending(), "partial,\"open".len() as u64);
        let r = parse_record(Format::Csvlog, &records[0], "LOG").unwrap();
        assert_eq!(r.remote.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.application, "pg_dump");
        assert_eq!(r.audit.command, "PREPARE");
        assert!(r.audit.statement.contains("'lit,eral'"));
        assert!(r.audit.statement.contains('\n'));
    }

    /// Security review of #278, M1: a csvlog record with more columns than
    /// PostgreSQL writes (a hybrid of a damaged record and the next one) is
    /// never read, as a pgaudit record or as an `ERROR` line.
    #[test]
    fn csvlog_records_past_the_largest_layout_are_refused() {
        let ok = CSV_MULTILINE.trim_end();
        assert_eq!(parse_csv(ok).unwrap().len(), MAX_CSV_COLUMNS);
        assert!(parse_record(Format::Csvlog, ok.as_bytes(), "LOG").is_some());
        let wide = format!("2026-10-18 09:00:00.000 UTC,mallory,{ok}");
        assert_eq!(
            parse_record_checked(Format::Csvlog, wide.as_bytes(), "LOG").err(),
            Some(Skip::NotAudit)
        );
        let error = "2026-10-18 09:00:00.000 UTC,\"mallory\",\"shop\",1,\"127.0.0.1:1\",s,1,\"SELECT\",\
                     2026-10-18 09:00:00 UTC,3/1,0,ERROR,57014,\"canceling statement\",,,,,,\
                     \"SELECT * FROM crm.customers\",,,\"psql\",\"client backend\",,0";
        assert!(matches!(
            parse_error_line(Format::Csvlog, error.as_bytes()),
            Ok(Some(_))
        ));
        let wide = format!("x,{error}");
        assert_eq!(
            parse_error_line(Format::Csvlog, wide.as_bytes()).err(),
            Some(Skip::Damaged)
        );
    }

    #[test]
    fn forged_records_are_dropped() {
        // RAISE LOG 'AUDIT: …' from PL/pgSQL (as logged by PostgreSQL 16).
        let raise = r#"{"timestamp":"2026-09-28 21:45:31.320 UTC","user":"mallory","dbname":"shop","remote_host":"127.0.0.1","session_id":"s","error_severity":"LOG","message":"AUDIT: SESSION,1,1,READ,SELECT,TABLE,crm.fake,select 1,<not logged>,5","context":"PL/pgSQL function inline_code_block line 1 at RAISE","application_name":"psql"}"#;
        assert!(parse_record(Format::Jsonlog, raise.as_bytes(), "LOG").is_none());
        // Another severity than pgaudit.log_level (RAISE NOTICE, WARNING…).
        let notice = JSON_AUDIT.replace("\"LOG\"", "\"NOTICE\"");
        assert!(parse_record(Format::Jsonlog, notice.as_bytes(), "LOG").is_none());
        assert!(parse_record(Format::Jsonlog, notice.as_bytes(), "NOTICE").is_some());
        // csvlog: context column (18) set.
        let csv = CSV_MULTILINE.trim_end().replacen(
            ",,,,,,,,,\"pg_dump\"",
            ",,,,,\"PL/pgSQL function f() line 3 at RAISE\",,,,\"pg_dump\"",
            1,
        );
        assert_ne!(csv, CSV_MULTILINE.trim_end());
        assert!(parse_record(Format::Csvlog, csv.as_bytes(), "LOG").is_none());
        assert!(
            parse_record(
                Format::Csvlog,
                CSV_MULTILINE.trim_end().as_bytes(),
                "WARNING"
            )
            .is_none()
        );
        assert_eq!(
            parse_record_checked(Format::Jsonlog, raise.as_bytes(), "LOG").err(),
            Some(Skip::Context)
        );
        assert_eq!(
            parse_record_checked(Format::Jsonlog, notice.as_bytes(), "LOG").err(),
            Some(Skip::Severity)
        );
        assert_eq!(expected_severity(Some("debug3")), "DEBUG");
        assert_eq!(expected_severity(Some("notice")), "NOTICE");
        assert_eq!(expected_severity(None), "LOG");
    }

    #[test]
    fn non_audit_records_are_not_parsed() {
        let other = r#"{"timestamp":"2026-09-28 21:45:31.568 UTC","user":"postgres","message":"connection authorized: user=postgres","detail":"AUDIT: SESSION,1,1,READ,SELECT,,,x,<not logged>"}"#;
        assert!(parse_record(Format::Jsonlog, other.as_bytes(), "LOG").is_none());
        let error = r#"{"message":"duplicate key","statement":"insert into t values ('secret')","error_severity":"ERROR"}"#;
        assert!(parse_record(Format::Jsonlog, error.as_bytes(), "LOG").is_none());
        assert!(parse_record(Format::Csvlog, b"a,b,c", "LOG").is_none());
    }

    #[test]
    fn malformed_payloads_are_dropped() {
        for bad in [
            "AUDIT: SESSION,1,1,READ,SELECT,,,select 1",
            "AUDIT: SESSION,x,1,READ,SELECT,,,select 1,<not logged>",
            "AUDIT: OTHER,1,1,READ,SELECT,,,select 1,<not logged>",
            "AUDIT: SESSION,1,1,READ,SELECT,,,\"unterminated,<not logged>",
            "AUDIT: SESSION,1,1,READ,SELECT,,,\"a\"b,<not logged>",
            "AUDIT: SESSION,1,1,read;drop,SELECT,,,x,<not logged>",
            "AUDIT: SESSION,1,1,READ,SELECT,,,x,<not logged>,notanumber",
            "AUDIT: SESSION,1,1,READ,SELECT,,,x,<not logged>,1,extra",
        ] {
            assert!(parse_pgaudit(bad).is_none(), "{bad}");
        }
        let ok = parse_pgaudit("AUDIT: SESSION,1,2,READ,COPY,,,\"COPY t TO stdout;\",<not logged>")
            .unwrap();
        assert_eq!(ok.rows, None);
        assert_eq!(ok.statement.as_str(), "COPY t TO stdout;");
    }

    #[test]
    fn hostile_lines_do_not_panic() {
        for line in [
            &b"{\"message\":\"AUDIT: \\u0000\"}"[..],
            b"{\"message\":\"AUDIT: SESSION,1,1,READ,SELECT,,,x,<not logged>\"",
            b"\"message\":\"AUDIT: ",
            b"{\"message\":\"AUDIT: SESSION,18446744073709551616,1,READ,SELECT,,,x,<not logged>\"}",
            &[0xff, 0xfe, b'"', b','],
        ] {
            let _ = parse_record(Format::Jsonlog, line, "LOG");
            let _ = parse_record(Format::Csvlog, line, "LOG");
        }
        let deep = format!(
            "{{\"message\":\"AUDIT: \",\"x\":{}{}}}",
            "[".repeat(10_000),
            "]".repeat(10_000)
        );
        assert!(parse_record(Format::Jsonlog, deep.as_bytes(), "LOG").is_none());
    }

    #[test]
    fn log_times() {
        let t = parse_log_time("2026-09-28 21:45:31.320 UTC").unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_790_631_931);
        let plus = parse_log_time("2026-09-28 23:45:31 +02").unwrap();
        assert_eq!(
            plus.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            secs
        );
        assert!(parse_log_time("2026-09-28 21:45:31 CEST").is_none());
        assert!(parse_log_time("garbage").is_none());
        assert!(parse_log_time("2026-13-28 21:45:31 UTC").is_none());
    }
}
