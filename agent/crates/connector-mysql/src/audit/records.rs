//! Audit log records: the MariaDB `server_audit` file and the Percona /
//! MySQL Enterprise JSON files (`audit_log` with `audit_log_format =
//! JSON`, and `audit_log_filter` / Enterprise JSON).
//!
//! Only structured fields are kept: time, connection id, query id, the
//! kind of record, the login user, the client address, the current
//! database, the table of a table-access record, the status, the client's
//! `program_name` (connect records of `audit_log_filter`) and the
//! statement text. The text is kept in a zeroizing buffer, analyzed
//! locally by the query normalizer (`classifiers::query`), and never
//! logged nor sent. Everything else in a record is ignored. A record that
//! does not parse is dropped (counted by the caller).
//!
//! `server_audit` line: `YYYYMMDD HH:MM:SS,serverhost,user,host,connid,
//! queryid,OPERATION,database,object,retcode`, the time in the server's
//! local time zone; `object` is the table of a table event, or the
//! statement quoted with `'` and the escapes `\'`, `\\`, `\n`, `\r`,
//! `\t`, `\b` and `\f`. Any other escape keeps the record, with a text
//! that is only used for its statement kind (the event names `*`).
//!
//! Statement texts are kept as raw bytes: bytes that are not UTF-8 (a
//! client in a legacy character set) make the text opaque (kind only), and
//! JSON records that are not UTF-8 are parsed from a lossy decoding with
//! their text opaque, rather than dropped.

use std::fmt;
use std::time::{Duration, SystemTime};

use databastion_core::jtext;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// Longest user, host or database name kept, in bytes (longer: the record
/// is dropped).
const MAX_NAME_BYTES: usize = 1024;

/// What a record reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Connect,
    FailedConnect,
    Disconnect,
    /// A statement (its text).
    Query,
    /// A table accessed by the statement of the same query id.
    Table(TableOp),
}

/// Access to a table (a table-access record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TableOp {
    Read,
    Write,
    Ddl,
}

/// One audit log record (see the module documentation).
pub(crate) struct FileRecord {
    /// UTC time.
    pub(crate) ts: Option<SystemTime>,
    pub(crate) connection: u64,
    /// `server_audit` query id / `audit_log` record number: records of
    /// one statement share it. `None` in `audit_log_filter` (grouped by
    /// text).
    pub(crate) query_id: Option<u64>,
    pub(crate) op: Op,
    pub(crate) user: String,
    /// Client address as logged (an IP literal, or a host name).
    pub(crate) host: String,
    pub(crate) database: String,
    /// `(database, table)` of a table-access record.
    pub(crate) table: Option<(String, String)>,
    /// Statement text as raw bytes (analyzed by `query::analyze_raw`).
    pub(crate) text: Option<Zeroizing<Vec<u8>>>,
    /// The text is not in a form the lexer can trust (an unknown
    /// `server_audit` escape, JSON bytes that were not UTF-8): only its
    /// statement kind is used.
    pub(crate) opaque: bool,
    /// The text may have been cut by the server
    /// (`server_audit_query_log_limit`).
    pub(crate) truncated: bool,
    /// Server error number (0: success).
    pub(crate) status: u32,
    /// `program_name` connection attribute (connect records).
    pub(crate) program: Option<String>,
    /// Position in the log file (set by the stream after parsing).
    pub(crate) pos: Option<databastion_core::audit::tail::RecordPos>,
    /// Re-read after a restart from a cursor moved back to held records
    /// (set by the stream's replay filter): its statement has been pending
    /// since its log time `ts`, not since it was read again.
    pub(crate) replayed: bool,
}

impl fmt::Debug for FileRecord {
    // The statement text and names are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileRecord")
            .field("connection", &self.connection)
            .field("query_id", &self.query_id)
            .field("op", &self.op)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

fn bounded(s: &str) -> Option<String> {
    (s.len() <= MAX_NAME_BYTES && !s.contains('\0')).then(|| s.to_owned())
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(1970..=9999).contains(&y) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Seconds since the epoch of `y-m-d h:mi:s` read as UTC.
fn epoch_secs(y: &str, mo: &str, d: &str, h: &str, mi: &str, s: &str) -> Option<i64> {
    let num = |v: &str| -> Option<u32> {
        (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .then(|| v.parse().ok())
            .flatten()
    };
    let (h, mi, s) = (num(h)?, num(mi)?, num(s)?);
    if h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(i64::from(num(y)?), num(mo)?, num(d)?)?;
    Some(days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s))
}

fn to_time(secs: i64) -> Option<SystemTime> {
    let secs = u64::try_from(secs).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// `YYYYMMDD HH:MM:SS` in the server's local time, `utc_offset` seconds
/// ahead of UTC.
fn server_audit_time(raw: &str, utc_offset: i64) -> Option<SystemTime> {
    let b = raw.as_bytes();
    if b.len() != 17 || b[8] != b' ' || b[11] != b':' || b[14] != b':' {
        return None;
    }
    let local = epoch_secs(
        &raw[0..4],
        &raw[4..6],
        &raw[6..8],
        &raw[9..11],
        &raw[12..14],
        &raw[15..17],
    )?;
    to_time(local - utc_offset)
}

/// `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DD HH:MM:SS` (UTC), fractional
/// seconds ignored.
fn json_time(raw: &str) -> Option<SystemTime> {
    let b = raw.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') {
        return None;
    }
    let rest = &raw[19..];
    let rest = rest.strip_suffix('Z').unwrap_or(rest);
    if !(rest.is_empty()
        || (rest.starts_with('.') && rest[1..].bytes().all(|c| c.is_ascii_digit())))
    {
        return None;
    }
    to_time(epoch_secs(
        &raw[0..4],
        &raw[5..7],
        &raw[8..10],
        &raw[11..13],
        &raw[14..16],
        &raw[17..19],
    )?)
}

/// A `server_audit` quoted statement, unescaped.
struct QuotedText<'a> {
    text: Zeroizing<Vec<u8>>,
    /// An escape this format does not define was met: the text is kept
    /// raw, for its statement kind only.
    opaque: bool,
    /// Bytes between the quotes, as written (escaped).
    escaped_len: usize,
    rest: &'a [u8],
}

/// Unescapes a `server_audit` quoted statement starting at `b[0] == '\''`.
/// MariaDB escapes `'`, `\`, newline, carriage return, tab, backspace and
/// form feed. `None` when the quote is not closed.
fn server_audit_text(b: &[u8]) -> Option<QuotedText<'_>> {
    if b.first() != Some(&b'\'') {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut opaque = false;
    let mut i = 1;
    loop {
        match *b.get(i)? {
            b'\\' => {
                let next = *b.get(i + 1)?;
                match next {
                    b'\\' => out.push(b'\\'),
                    b'\'' => out.push(b'\''),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    other => {
                        opaque = true;
                        out.push(b'\\');
                        out.push(other);
                    }
                }
                i += 2;
            }
            b'\'' => break,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(QuotedText {
        text: out,
        opaque,
        escaped_len: i - 1,
        rest: b.get(i + 1..)?,
    })
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Parses one `server_audit` line. `utc_offset`: seconds the server's
/// local time is ahead of UTC; `query_limit`: `server_audit_query_log_limit`
/// (a text reaching it may be cut). The statement text is kept as raw
/// bytes (never decoded lossily for analysis); names are decoded lossily.
pub(crate) fn parse_server_audit(
    line: &[u8],
    utc_offset: i64,
    query_limit: usize,
) -> Option<FileRecord> {
    let comma = |b: &u8| *b == b',';
    let mut head = line.splitn(3, comma);
    let ts = server_audit_time(&lossy(head.next()?), utc_offset);
    let _serverhost = head.next()?;
    let rest = head.next()?;
    // `user,host,connid,queryid,OP,` — the user may hold commas: find the
    // first `,host,<digits>,<digits>,<OP>,` sequence.
    let fields: Vec<&[u8]> = rest.splitn(64, comma).collect();
    let digits = |f: &[u8]| !f.is_empty() && f.iter().all(u8::is_ascii_digit);
    let op_at = |f: &[u8]| std::str::from_utf8(f).ok().and_then(op_of);
    let k = (1..fields.len().saturating_sub(4)).find(|&k| {
        digits(fields[k + 1]) && digits(fields[k + 2]) && op_at(fields[k + 3]).is_some()
    })?;
    let user = bounded(&lossy(&fields[..k].join(&b',')))?;
    let host = bounded(&lossy(fields[k]))?;
    let connection: u64 = std::str::from_utf8(fields[k + 1]).ok()?.parse().ok()?;
    let query_id: u64 = std::str::from_utf8(fields[k + 2]).ok()?.parse().ok()?;
    let op = op_at(fields[k + 3])?;
    // Everything after `OP,`.
    let consumed: usize = fields[..=k + 3].iter().map(|f| f.len() + 1).sum();
    let tail = rest.get(consumed..)?;
    let mut record = FileRecord {
        ts,
        connection,
        query_id: (query_id != 0).then_some(query_id),
        op,
        user,
        host,
        database: String::new(),
        table: None,
        text: None,
        opaque: false,
        truncated: false,
        status: 0,
        program: None,
        pos: None,
        replayed: false,
    };
    let status_of =
        |b: &[u8]| -> Option<u32> { std::str::from_utf8(b).ok()?.trim_end().parse().ok() };
    match op {
        Op::Query => {
            // `database,'text',retcode`: the database ends at the first
            // `,'` (a database name with `,'` is not supported).
            let q = tail.windows(2).position(|w| w == b",'")?;
            record.database = bounded(&lossy(&tail[..q]))?;
            let quoted = server_audit_text(&tail[q + 1..])?;
            let status = quoted.rest.strip_prefix(b",")?;
            record.status = status_of(status)?;
            // The limit applies to the escaped text.
            record.truncated = quoted.escaped_len >= query_limit.saturating_sub(2);
            record.opaque = quoted.opaque;
            record.text = Some(quoted.text);
        }
        Op::Table(_) => {
            // `database,table,` (no return code).
            let body = tail.strip_suffix(b",").unwrap_or(tail);
            let c = body.iter().position(comma)?;
            let (db, table) = (&body[..c], &body[c + 1..]);
            record.database = bounded(&lossy(db))?;
            record.table = Some((bounded(&lossy(db))?, bounded(&lossy(table))?));
        }
        Op::Connect | Op::FailedConnect | Op::Disconnect => {
            // `database,,retcode`
            let c = tail.iter().position(comma)?;
            record.database = bounded(&lossy(&tail[..c]))?;
            let status = tail[c + 1..].rsplit(comma).next()?;
            let status = lossy(status);
            let status = status.trim_end();
            record.status = if status.is_empty() {
                0
            } else {
                status.parse().ok()?
            };
            if op == Op::Connect && record.status != 0 {
                record.op = Op::FailedConnect;
            }
        }
    }
    Some(record)
}

fn op_of(raw: &str) -> Option<Op> {
    Some(match raw {
        "CONNECT" => Op::Connect,
        "FAILED_CONNECT" => Op::FailedConnect,
        "DISCONNECT" => Op::Disconnect,
        "QUERY" => Op::Query,
        "READ" => Op::Table(TableOp::Read),
        "WRITE" => Op::Table(TableOp::Write),
        "CREATE" | "ALTER" | "DROP" | "RENAME" => Op::Table(TableOp::Ddl),
        _ => return None,
    })
}

/// A JSON field type that does not match what the record layout declares
/// (a string where a number is expected…): the record is dropped.
struct Mismatch;

/// A required string field.
fn req_str(raw: Option<&RawValue>) -> Result<Zeroizing<String>, Mismatch> {
    opt_str(raw)?.ok_or(Mismatch)
}

/// An optional string field (absent or `null`: `None`), unescaped whole
/// into a zeroizing buffer.
fn opt_str(raw: Option<&RawValue>) -> Result<Option<Zeroizing<String>>, Mismatch> {
    let Some(raw) = raw.filter(|r| !jtext::is_null(r)) else {
        return Ok(None);
    };
    match jtext::string(raw, usize::MAX) {
        Ok(Some(s)) => Ok(Some(s)),
        Ok(None) | Err(_) => Err(Mismatch),
    }
}

/// An optional unsigned integer field.
fn opt_u64(raw: Option<&RawValue>) -> Result<Option<u64>, Mismatch> {
    let Some(raw) = raw.filter(|r| !jtext::is_null(r)) else {
        return Ok(None);
    };
    jtext::unsigned(raw).map(Some).ok_or(Mismatch)
}

fn opt_u32(raw: Option<&RawValue>) -> Result<Option<u32>, Mismatch> {
    opt_u64(raw)?
        .map(|n| u32::try_from(n).map_err(|_| Mismatch))
        .transpose()
}

/// An optional object field: the raw values of `keys` in it.
fn opt_obj<'a, const N: usize>(
    raw: Option<&'a RawValue>,
    keys: &[&str; N],
) -> Result<Option<[Option<&'a RawValue>; N]>, Mismatch> {
    let Some(raw) = raw.filter(|r| !jtext::is_null(r)) else {
        return Ok(None);
    };
    match jtext::object(raw.get(), keys) {
        Ok(Some(fields)) => Ok(Some(fields)),
        Ok(None) | Err(_) => Err(Mismatch),
    }
}

/// The bytes of a zeroizing string, moved (not copied) into a zeroizing
/// byte buffer.
fn into_bytes(mut s: Zeroizing<String>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(std::mem::take(&mut *s).into_bytes())
}

/// Keys of a JSON record line: `audit_record` (Percona `audit_log`) or
/// the `audit_log_filter` / Enterprise layout.
const LINE_KEYS: [&str; 10] = [
    "audit_record",
    "timestamp",
    "class",
    "event",
    "connection_id",
    "account",
    "login",
    "general_data",
    "connection_data",
    "table_access_data",
];

/// Percona `audit_log` JSON record (`{"audit_record": {…}}`).
struct LegacyRecord<'a> {
    name: Zeroizing<String>,
    record: Option<Zeroizing<String>>,
    timestamp: Zeroizing<String>,
    /// A string or a number.
    connection_id: Option<&'a RawValue>,
    status: Option<u32>,
    sqltext: Option<Zeroizing<String>>,
    user: Option<Zeroizing<String>>,
    host: Option<Zeroizing<String>>,
    ip: Option<Zeroizing<String>>,
    db: Option<Zeroizing<String>>,
}

impl<'a> LegacyRecord<'a> {
    const KEYS: [&'static str; 10] = [
        "name",
        "record",
        "timestamp",
        "connection_id",
        "status",
        "sqltext",
        "user",
        "host",
        "ip",
        "db",
    ];

    fn read(raw: &'a RawValue) -> Result<Self, Mismatch> {
        let [
            name,
            record,
            timestamp,
            connection_id,
            status,
            sqltext,
            user,
            host,
            ip,
            db,
        ] = opt_obj(Some(raw), &Self::KEYS)?.ok_or(Mismatch)?;
        Ok(Self {
            name: req_str(name)?,
            record: opt_str(record)?,
            timestamp: req_str(timestamp)?,
            connection_id: connection_id.filter(|r| !jtext::is_null(r)),
            status: opt_u32(status)?,
            sqltext: opt_str(sqltext)?,
            user: opt_str(user)?,
            host: opt_str(host)?,
            ip: opt_str(ip)?,
            db: opt_str(db)?,
        })
    }
}

/// `audit_log_filter` / MySQL Enterprise JSON record.
struct FilterRecord {
    timestamp: Zeroizing<String>,
    class: Zeroizing<String>,
    event: Zeroizing<String>,
    connection_id: Option<u64>,
    /// `account.user`.
    account_user: Option<Zeroizing<String>>,
    login: Option<Login>,
    general_data: Option<GeneralData>,
    connection_data: Option<ConnectionData>,
    table_access_data: Option<TableAccess>,
}

struct Login {
    user: Option<Zeroizing<String>>,
    ip: Option<Zeroizing<String>>,
}

struct GeneralData {
    command: Option<Zeroizing<String>>,
    query: Option<Zeroizing<String>>,
    status: Option<u32>,
}

struct ConnectionData {
    status: Option<u32>,
    db: Option<Zeroizing<String>>,
    /// `connection_attributes.program_name`.
    program_name: Option<Zeroizing<String>>,
}

struct TableAccess {
    db: Option<Zeroizing<String>>,
    table: Option<Zeroizing<String>>,
    query: Option<Zeroizing<String>>,
}

impl FilterRecord {
    /// Every field the layout declares is type-checked, used or not (as
    /// the typed deserialization this replaces did).
    fn read(f: [Option<&RawValue>; LINE_KEYS.len()]) -> Result<Self, Mismatch> {
        let [
            _,
            timestamp,
            class,
            event,
            connection_id,
            account,
            login,
            general_data,
            connection_data,
            table_access_data,
        ] = f;
        let account_user = match opt_obj(account, &["user"])? {
            Some([user]) => opt_str(user)?,
            None => None,
        };
        let login = match opt_obj(login, &["user", "ip"])? {
            Some([user, ip]) => Some(Login {
                user: opt_str(user)?,
                ip: opt_str(ip)?,
            }),
            None => None,
        };
        let general_data = match opt_obj(general_data, &["command", "query", "status"])? {
            Some([command, query, status]) => Some(GeneralData {
                command: opt_str(command)?,
                query: opt_str(query)?,
                status: opt_u32(status)?,
            }),
            None => None,
        };
        let connection_data =
            match opt_obj(connection_data, &["status", "db", "connection_attributes"])? {
                Some([status, db, attributes]) => Some(ConnectionData {
                    status: opt_u32(status)?,
                    db: opt_str(db)?,
                    program_name: match opt_obj(attributes, &["program_name"])? {
                        Some([program]) => opt_str(program)?,
                        None => None,
                    },
                }),
                None => None,
            };
        let table_access_data = match opt_obj(table_access_data, &["db", "table", "query"])? {
            Some([db, table, query]) => Some(TableAccess {
                db: opt_str(db)?,
                table: opt_str(table)?,
                query: opt_str(query)?,
            }),
            None => None,
        };
        Ok(Self {
            timestamp: req_str(timestamp)?,
            class: req_str(class)?,
            event: req_str(event)?,
            connection_id: opt_u64(connection_id)?,
            account_user,
            login,
            general_data,
            connection_data,
            table_access_data,
        })
    }
}

/// Parses one JSON record of either layout.
///
/// No unzeroized copy of a string (ROADMAP phase 8 follow-up, review of
/// #168 M2): the record is read as `serde_json` raw values borrowed from
/// `record` (the caller's zeroizing buffer), and the kept strings,
/// statement text included, are unescaped by [`jtext`] into zeroizing
/// buffers allocated once. `serde_json` never unescapes a string into its
/// private scratch buffer, and no `serde_json::Value` (whose strings are
/// freed without being wiped) is built. Field types are checked as before
/// (a kept field of the wrong type drops the record, a repeated key keeps
/// its last value); values the layouts do not declare are only skipped
/// and, as `serde_json`'s skip path does, not checked for lone surrogate
/// escapes nor out-of-range numbers.
pub(crate) fn parse_json(record: &[u8]) -> Option<FileRecord> {
    // A client in a legacy character set writes bytes that are not UTF-8
    // into the statement: the structure is read from a lossy decoding and
    // the text is opaque (kind only), rather than the record dropped.
    // The lossy decoding is a full copy of the record, statement text
    // included: zeroized when dropped.
    let owned: Zeroizing<String>;
    let (json, utf8): (&str, bool) = match std::str::from_utf8(record) {
        Ok(s) => (s, true),
        Err(_) => {
            owned = Zeroizing::new(String::from_utf8_lossy(record).into_owned());
            (owned.as_str(), false)
        }
    };
    let fields = jtext::object(json, &LINE_KEYS).ok()??;
    let mut parsed = match fields[0] {
        Some(audit_record) => parse_legacy(LegacyRecord::read(audit_record).ok()?),
        None => parse_filter(FilterRecord::read(fields).ok()?),
    }?;
    parsed.opaque = !utf8;
    Some(parsed)
}

/// The login user of a legacy `Query` record: `user[priv_user] @ host
/// [ip]`.
fn legacy_user(raw: &str) -> Option<String> {
    let (left, _) = raw.rsplit_once(" @ ")?;
    let left = left.strip_suffix(']')?;
    let (user, _) = left.rsplit_once('[')?;
    bounded(user)
}

fn parse_legacy(r: LegacyRecord<'_>) -> Option<FileRecord> {
    // A string or a number, as a `serde_json::Value` was read before.
    let id = r.connection_id?;
    let connection = match id.get().as_bytes().first() {
        Some(b'"') => jtext::string(id, usize::MAX).ok()??.parse().ok()?,
        Some(b'-' | b'0'..=b'9') => jtext::unsigned(id)?,
        _ => return None,
    };
    let status = r.status.unwrap_or(0);
    let op = match r.name.as_str() {
        "Query" => Op::Query,
        "Connect" if status == 0 => Op::Connect,
        "Connect" => Op::FailedConnect,
        "Quit" => Op::Disconnect,
        _ => return None,
    };
    let user = match op {
        Op::Query => legacy_user(r.user.as_deref()?)?,
        _ => bounded(r.user.as_deref()?)?,
    };
    let host = match r.ip.as_deref().filter(|ip| !ip.is_empty()) {
        Some(ip) => bounded(ip)?,
        None => bounded(r.host.as_deref().map_or("", String::as_str))?,
    };
    // `record` is `<sequence>_<start time>`: unique per record.
    let query_id = r
        .record
        .as_deref()
        .and_then(|v| v.split('_').next())
        .and_then(|v| v.parse().ok());
    Some(FileRecord {
        ts: json_time(&r.timestamp),
        connection,
        query_id,
        op,
        user,
        host,
        database: bounded(r.db.as_deref().map_or("", String::as_str))?,
        table: None,
        text: match op {
            Op::Query => Some(into_bytes(r.sqltext?)),
            _ => None,
        },
        opaque: false,
        truncated: false,
        status,
        program: None,
        pos: None,
        replayed: false,
    })
}

fn parse_filter(r: FilterRecord) -> Option<FileRecord> {
    let connection = r.connection_id?;
    let login = r.login.as_ref();
    let user = login
        .and_then(|l| l.user.as_deref())
        .or(r.account_user.as_deref())?;
    let host = login
        .and_then(|l| l.ip.as_deref())
        .map_or("", String::as_str);
    let mut record = FileRecord {
        ts: json_time(&r.timestamp),
        connection,
        query_id: None,
        op: Op::Query,
        user: bounded(user)?,
        host: bounded(host)?,
        database: String::new(),
        table: None,
        text: None,
        opaque: false,
        truncated: false,
        status: 0,
        program: None,
        pos: None,
        replayed: false,
    };
    match (r.class.as_str(), r.event.as_str()) {
        ("connection", "connect" | "change_user") => {
            let c = r.connection_data?;
            record.status = c.status.unwrap_or(0);
            record.op = if record.status == 0 {
                Op::Connect
            } else {
                Op::FailedConnect
            };
            record.database = bounded(c.db.as_deref().map_or("", String::as_str))?;
            record.program = c.program_name.and_then(|p| bounded(&p));
        }
        ("connection", "disconnect") => record.op = Op::Disconnect,
        ("general", "status") => {
            let g = r.general_data?;
            if g.command.as_deref().map(String::as_str) != Some("Query") {
                return None;
            }
            record.status = g.status.unwrap_or(0);
            record.text = Some(into_bytes(g.query?));
        }
        ("table_access", event) => {
            let t = r.table_access_data?;
            record.op = Op::Table(match event {
                "read" => TableOp::Read,
                "insert" | "update" | "delete" => TableOp::Write,
                _ => return None,
            });
            let db = bounded(t.db.as_deref()?)?;
            record.table = Some((db.clone(), bounded(t.table.as_deref()?)?));
            record.database = db;
            record.text = t.query.map(into_bytes);
        }
        _ => return None,
    }
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Option<SystemTime> {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn server_audit_lines_are_parsed() {
        let q = br"20260929 09:42:04,7eba2b5d12b8,root,localhost,51,174,QUERY,support,'SELECT /*!40001 SQL_NO_CACHE */ `id` FROM `tickets` WHERE a = \'x\\\'y\' -- c\nfrom',0";
        let r = parse_server_audit(q, 7200, 1024).unwrap();
        assert_eq!(r.op, Op::Query);
        assert_eq!((r.connection, r.query_id), (51, Some(174)));
        assert_eq!((r.user.as_str(), r.host.as_str()), ("root", "localhost"));
        assert_eq!(r.database, "support");
        assert_eq!(
            r.text
                .as_deref()
                .map(|t| String::from_utf8_lossy(t).into_owned()),
            Some(
                "SELECT /*!40001 SQL_NO_CACHE */ `id` FROM `tickets` WHERE a = 'x\\'y' -- c\nfrom"
                    .to_owned()
            )
        );
        assert_eq!(r.status, 0);
        // 2026-09-29 09:42:04 at UTC+2 is 07:42:04 UTC.
        assert_eq!(r.ts, at(1_790_667_724));
        assert!(!r.truncated);
        let t = parse_server_audit(
            b"20260929 09:42:04,h,root,172.18.0.1,51,174,READ,support,tickets,",
            0,
            1024,
        )
        .unwrap();
        assert_eq!(t.op, Op::Table(TableOp::Read));
        assert_eq!(t.table, Some(("support".into(), "tickets".into())));
        let c = parse_server_audit(
            b"20260929 09:40:35,h,wrong,172.18.0.1,12,0,FAILED_CONNECT,,,1045",
            0,
            1024,
        )
        .unwrap();
        assert_eq!(
            (c.op, c.status, c.query_id),
            (Op::FailedConnect, 1045, None)
        );
        let d = parse_server_audit(
            b"20260929 09:40:35,h,root,localhost,11,0,DISCONNECT,support,,0",
            0,
            1024,
        )
        .unwrap();
        assert_eq!(d.op, Op::Disconnect);
        // A user name holding commas and digits.
        let u = parse_server_audit(
            b"20260929 09:40:35,h,a,1,2,b,10.0.0.1,7,9,QUERY,,'select 1',0",
            0,
            1024,
        )
        .unwrap();
        assert_eq!(u.user, "a,1,2,b");
        assert_eq!(u.connection, 7);
        // Failed statement.
        let f = parse_server_audit(
            br"20260929 09:41:34,h,root,localhost,37,109,QUERY,x,'select * from t into outfile \'/tmp/f\'',1086",
            0,
            1024,
        )
        .unwrap();
        assert_eq!(f.status, 1086);
    }

    #[test]
    fn server_audit_texts_fail_closed() {
        for bad in [
            &br"20260929 09:42:04,h,root,localhost,51,174,QUERY,db,'unterminated,0"[..],
            br"20260929 09:42:04,h,root,localhost,51,174,QUERY,db,'x',notanumber",
            br"20260929 09:42:04,h,root,localhost,x,174,QUERY,db,'x',0",
            br"garbage",
            b"",
        ] {
            assert!(parse_server_audit(bad, 0, 1024).is_none(), "{bad:?}");
        }
        // An escape the format does not define: the record is kept, its
        // text only good for the statement kind.
        let r = parse_server_audit(
            br"20260929 09:42:04,h,root,localhost,51,174,QUERY,db,'select \q from t',0",
            0,
            1024,
        )
        .unwrap();
        assert!(r.opaque && r.text.is_some());
        // The limit applies to the escaped text: 1022 escaped bytes (511
        // escaped quotes) reach a 1024-byte limit.
        let escaped = format!(
            "20260929 09:42:04,h,root,localhost,51,174,QUERY,db,'{}',0",
            r"\'".repeat(511)
        );
        let r = parse_server_audit(escaped.as_bytes(), 0, 1024).unwrap();
        assert!(r.truncated);
        assert_eq!(r.text.as_ref().map(|t| t.len()), Some(511));
        let short = parse_server_audit(
            br"20260929 09:42:04,h,root,localhost,51,174,QUERY,db,'select 1',0",
            0,
            1024,
        )
        .unwrap();
        assert!(!short.truncated);
        // A bad time keeps the record without a time.
        let r =
            parse_server_audit(b"2026 bad,h,root,localhost,51,174,READ,db,t,", 0, 1024).unwrap();
        assert!(r.ts.is_none());
    }

    #[test]
    fn server_audit_tab_backspace_and_form_feed_escapes() {
        // A real MariaDB 11.4.13 line (dev image).
        let line = br"20260929 11:24:12,a7eb24276602,root,localhost,1803,7166,QUERY,support,'select \'a\tb\bc\fd\', id from support.tickets where id = 1',0";
        let r = parse_server_audit(line, 0, 1024).unwrap();
        assert!(!r.opaque);
        assert_eq!(
            r.text.as_deref().map(Vec::as_slice),
            Some(&b"select 'a\tb\x08c\x0cd', id from support.tickets where id = 1"[..])
        );
    }

    #[test]
    fn non_utf8_texts_are_kept_opaque() {
        // A latin1 client: `é` written as 0xE9.
        let mut json = br#"{"audit_record":{"name":"Query","record":"5_x","timestamp":"2026-09-29T09:45:20Z","connection_id":"11","status":0,"sqltext":"select 'caf"#.to_vec();
        json.push(0xe9);
        json.extend_from_slice(
            br#"' from hr.t","user":"root[root] @  [127.0.0.1]","ip":"127.0.0.1","db":"hr"}}"#,
        );
        let r = parse_json(&json).unwrap();
        assert!(r.opaque);
        assert_eq!(r.op, Op::Query);
        let mut line = br"20260929 09:42:04,h,root,10.0.0.1,51,174,QUERY,db,'select \'caf".to_vec();
        line.push(0xe9);
        line.extend_from_slice(br"\' from t',0");
        let r = parse_server_audit(&line, 0, 1024).unwrap();
        // Kept raw: the analyzer sees bytes that are not UTF-8.
        assert!(
            r.text
                .as_deref()
                .is_some_and(|t| std::str::from_utf8(t).is_err())
        );
    }

    #[test]
    fn legacy_json_records_are_parsed() {
        let q = br#"{"audit_record":{"name":"Query","record":"7306164_2026-09-29T09:45:09","timestamp":"2026-09-29T09:45:20Z","command_class":"select","connection_id":"11","status":0,"sqltext":"select 'multi\nline' from hr.t","user":"root[root] @  [127.0.0.1]","host":"","os_user":"","ip":"127.0.0.1","db":"hr"}}"#;
        let r = parse_json(q).unwrap();
        assert_eq!(r.op, Op::Query);
        assert_eq!((r.connection, r.query_id), (11, Some(7_306_164)));
        assert_eq!(
            (r.user.as_str(), r.host.as_str(), r.database.as_str()),
            ("root", "127.0.0.1", "hr")
        );
        assert_eq!(
            r.text
                .as_deref()
                .map(|t| String::from_utf8_lossy(t).into_owned()),
            Some("select 'multi\nline' from hr.t".to_owned())
        );
        assert_eq!(r.ts, at(1_790_675_120));
        let c = br#"{"audit_record":{"name":"Connect","record":"1_x","timestamp":"2026-09-29T09:45:20Z","connection_id":"12","status":1045,"user":"wrong","priv_user":"","os_login":"","proxy_user":"","host":"","ip":"127.0.0.1","db":""}}"#;
        let c = parse_json(c).unwrap();
        assert_eq!((c.op, c.user.as_str()), (Op::FailedConnect, "wrong"));
        assert!(parse_json(br#"{"audit_record":{"name":"Audit","timestamp":"x"}}"#).is_none());
    }

    #[test]
    fn filter_json_records_are_parsed() {
        let connect = br#"{"timestamp": "2026-09-29 10:06:12", "id": 24, "class": "connection", "event": "connect", "connection_id": 22,
            "account": { "user": "root", "host": "" }, "login": { "user": "root", "os": "", "ip": "10.1.2.3", "proxy": "" },
            "connection_data": { "connection_type": "ssl", "status": 0, "db": "hr",
              "connection_attributes": { "_pid": "135", "program_name": "mysqldump" } } }"#;
        let c = parse_json(connect).unwrap();
        assert_eq!(
            (c.op, c.connection, c.host.as_str()),
            (Op::Connect, 22, "10.1.2.3")
        );
        assert_eq!(c.program.as_deref(), Some("mysqldump"));
        let table = br#"{"timestamp": "2026-09-29 10:06:12", "id": 47, "class": "table_access", "event": "read", "connection_id": 22,
            "account": { "user": "root", "host": "" }, "login": { "user": "root", "os": "", "ip": "10.1.2.3", "proxy": "" },
            "table_access_data": { "db": "hr", "table": "t", "query": "SELECT /*!40001 SQL_NO_CACHE */ * FROM `t`", "sql_command": "select" } }"#;
        let t = parse_json(table).unwrap();
        assert_eq!(t.op, Op::Table(TableOp::Read));
        assert_eq!(t.table, Some(("hr".into(), "t".into())));
        assert!(t.text.is_some());
        let status = br#"{"timestamp": "2026-09-29 10:06:12", "id": 48, "class": "general", "event": "status", "connection_id": 22,
            "account": { "user": "root", "host": "" }, "login": { "user": "root", "os": "", "ip": "10.1.2.3", "proxy": "" },
            "general_data": { "command": "Query", "sql_command": "select", "query": "SELECT 1", "status": 1146 } }"#;
        let s = parse_json(status).unwrap();
        assert_eq!((s.op, s.status), (Op::Query, 1146));
        assert_eq!(s.ts, at(1_790_676_372));
        assert!(parse_json(b"{\"class\": \"general\"}").is_none());
        assert!(parse_json(b"not json").is_none());
    }

    #[test]
    fn debug_hides_texts_and_names() {
        let r = parse_server_audit(
            br"20260929 09:42:04,h,jane.doe,localhost,51,174,QUERY,db,'select \'jane@example.com\'',0",
            0,
            1024,
        )
        .unwrap();
        let d = format!("{r:?}");
        assert!(!d.contains("jane"), "{d}");
    }

    /// The typed `serde_json` parser this module used before reading raw
    /// values (kept as the reference of the equivalence tests).
    mod typed {
        #![allow(clippy::all)]
        use super::super::{FileRecord, Op, TableOp, bounded, json_time, legacy_user};
        use zeroize::Zeroizing;

        /// Percona `audit_log` JSON record (`{"audit_record": {…}}`).
        #[derive(serde::Deserialize)]
        struct LegacyLine {
            audit_record: LegacyRecord,
        }

        #[derive(serde::Deserialize)]
        struct LegacyRecord {
            name: String,
            #[serde(default)]
            record: Option<String>,
            timestamp: String,
            #[serde(default)]
            connection_id: Option<serde_json::Value>,
            #[serde(default)]
            status: Option<u32>,
            #[serde(default)]
            sqltext: Option<String>,
            #[serde(default)]
            user: Option<String>,
            #[serde(default)]
            host: Option<String>,
            #[serde(default)]
            ip: Option<String>,
            #[serde(default)]
            db: Option<String>,
        }

        /// `audit_log_filter` / MySQL Enterprise JSON record.
        #[derive(serde::Deserialize)]
        struct FilterRecord {
            timestamp: String,
            class: String,
            event: String,
            #[serde(default)]
            connection_id: Option<u64>,
            #[serde(default)]
            account: Option<Account>,
            #[serde(default)]
            login: Option<Login>,
            #[serde(default)]
            general_data: Option<GeneralData>,
            #[serde(default)]
            connection_data: Option<ConnectionData>,
            #[serde(default)]
            table_access_data: Option<TableAccess>,
        }

        #[derive(serde::Deserialize)]
        struct Account {
            #[serde(default)]
            user: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct Login {
            #[serde(default)]
            user: Option<String>,
            #[serde(default)]
            ip: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct GeneralData {
            #[serde(default)]
            command: Option<String>,
            #[serde(default)]
            query: Option<String>,
            #[serde(default)]
            status: Option<u32>,
        }

        #[derive(serde::Deserialize)]
        struct ConnectionData {
            #[serde(default)]
            status: Option<u32>,
            #[serde(default)]
            db: Option<String>,
            #[serde(default)]
            connection_attributes: Option<ConnectionAttributes>,
        }

        #[derive(serde::Deserialize)]
        struct ConnectionAttributes {
            #[serde(default)]
            program_name: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct TableAccess {
            #[serde(default)]
            db: Option<String>,
            #[serde(default)]
            table: Option<String>,
            #[serde(default)]
            query: Option<String>,
        }

        /// Parses one JSON record of either layout.
        pub(super) fn parse_json(record: &[u8]) -> Option<FileRecord> {
            // A client in a legacy character set writes bytes that are not UTF-8
            // into the statement: the structure is read from a lossy decoding and
            // the text is opaque (kind only), rather than the record dropped.
            // The lossy decoding is a full copy of the record, statement text
            // included: zeroized when dropped.
            let owned: Zeroizing<String>;
            let (json, utf8): (&str, bool) = match std::str::from_utf8(record) {
                Ok(s) => (s, true),
                Err(_) => {
                    owned = Zeroizing::new(String::from_utf8_lossy(record).into_owned());
                    (owned.as_str(), false)
                }
            };
            let value: serde_json::Value = serde_json::from_str(json).ok()?;
            let mut parsed = if value.get("audit_record").is_some() {
                let line: LegacyLine = serde_json::from_value(value).ok()?;
                parse_legacy(line.audit_record)
            } else {
                let r: FilterRecord = serde_json::from_value(value).ok()?;
                parse_filter(r)
            }?;
            parsed.opaque = !utf8;
            Some(parsed)
        }

        fn parse_legacy(r: LegacyRecord) -> Option<FileRecord> {
            let connection = match r.connection_id? {
                serde_json::Value::String(s) => s.parse().ok()?,
                serde_json::Value::Number(n) => n.as_u64()?,
                _ => return None,
            };
            let status = r.status.unwrap_or(0);
            let op = match r.name.as_str() {
                "Query" => Op::Query,
                "Connect" if status == 0 => Op::Connect,
                "Connect" => Op::FailedConnect,
                "Quit" => Op::Disconnect,
                _ => return None,
            };
            let user = match op {
                Op::Query => legacy_user(r.user.as_deref()?)?,
                _ => bounded(r.user.as_deref()?)?,
            };
            let host = match r.ip.as_deref().filter(|ip| !ip.is_empty()) {
                Some(ip) => bounded(ip)?,
                None => bounded(r.host.as_deref().unwrap_or(""))?,
            };
            // `record` is `<sequence>_<start time>`: unique per record.
            let query_id = r
                .record
                .as_deref()
                .and_then(|v| v.split('_').next())
                .and_then(|v| v.parse().ok());
            Some(FileRecord {
                ts: json_time(&r.timestamp),
                connection,
                query_id,
                op,
                user,
                host,
                database: bounded(r.db.as_deref().unwrap_or(""))?,
                table: None,
                text: match op {
                    Op::Query => Some(Zeroizing::new(r.sqltext?.into_bytes())),
                    _ => None,
                },
                opaque: false,
                truncated: false,
                status,
                program: None,
                pos: None,
                replayed: false,
            })
        }

        fn parse_filter(r: FilterRecord) -> Option<FileRecord> {
            let connection = r.connection_id?;
            let login = r.login.as_ref();
            let user = login
                .and_then(|l| l.user.as_deref())
                .or_else(|| r.account.as_ref().and_then(|a| a.user.as_deref()))?;
            let host = login.and_then(|l| l.ip.as_deref()).unwrap_or("");
            let mut record = FileRecord {
                ts: json_time(&r.timestamp),
                connection,
                query_id: None,
                op: Op::Query,
                user: bounded(user)?,
                host: bounded(host)?,
                database: String::new(),
                table: None,
                text: None,
                opaque: false,
                truncated: false,
                status: 0,
                program: None,
                pos: None,
                replayed: false,
            };
            match (r.class.as_str(), r.event.as_str()) {
                ("connection", "connect" | "change_user") => {
                    let c = r.connection_data?;
                    record.status = c.status.unwrap_or(0);
                    record.op = if record.status == 0 {
                        Op::Connect
                    } else {
                        Op::FailedConnect
                    };
                    record.database = bounded(c.db.as_deref().unwrap_or(""))?;
                    record.program = c
                        .connection_attributes
                        .and_then(|a| a.program_name)
                        .and_then(|p| bounded(&p));
                }
                ("connection", "disconnect") => record.op = Op::Disconnect,
                ("general", "status") => {
                    let g = r.general_data?;
                    if g.command.as_deref() != Some("Query") {
                        return None;
                    }
                    record.status = g.status.unwrap_or(0);
                    record.text = Some(Zeroizing::new(g.query?.into_bytes()));
                }
                ("table_access", event) => {
                    let t = r.table_access_data?;
                    record.op = Op::Table(match event {
                        "read" => TableOp::Read,
                        "insert" | "update" | "delete" => TableOp::Write,
                        _ => return None,
                    });
                    let db = bounded(t.db.as_deref()?)?;
                    record.table = Some((db.clone(), bounded(t.table.as_deref()?)?));
                    record.database = db;
                    record.text = t.query.map(|q| Zeroizing::new(q.into_bytes()));
                }
                _ => return None,
            }
            Some(record)
        }
    }

    /// What a parsed record holds, for comparisons.
    fn summary(r: Option<&FileRecord>) -> Option<String> {
        r.map(|r| {
            format!(
                "{:?} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {} {} {:?}",
                r.ts,
                r.connection,
                r.query_id,
                r.op,
                r.user,
                r.host,
                r.database,
                r.table,
                r.text.as_deref(),
                r.opaque,
                r.truncated,
                r.status,
                r.program
            )
        })
    }

    /// A JSON string literal of `s`, each character written plain or as
    /// an escape according to `styles` (always a valid literal, never a
    /// lone surrogate).
    fn escaped(s: &str, styles: &[u8]) -> String {
        let mut out = String::from("\"");
        for (i, c) in s.chars().enumerate() {
            let style = styles.get(i % styles.len().max(1)).copied().unwrap_or(0) % 3;
            match c {
                '"' if style == 0 => out.push_str("\\\""),
                '\\' if style == 0 => out.push_str("\\\\"),
                '/' if style == 2 => out.push_str("\\/"),
                '\n' if style != 1 => out.push_str("\\n"),
                c if style == 1 || c == '"' || c == '\\' || c < ' ' => {
                    let mut buf = [0u16; 2];
                    for unit in c.encode_utf16(&mut buf) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// A value for a field: the right type (a string, escaped), or another
    /// JSON type, or absent.
    fn field(kind: u8, text: &str, styles: &[u8]) -> Option<String> {
        Some(match kind % 12 {
            0 => return None,
            1 => "null".to_owned(),
            2 => "17".to_owned(),
            3 => "-1".to_owned(),
            4 => "1.5".to_owned(),
            5 => "true".to_owned(),
            6 => format!("{{\"x\": {}}}", escaped(text, styles)),
            7 => "4294967296".to_owned(),
            8 => "-0".to_owned(),
            _ => escaped(text, styles),
        })
    }

    fn object(fields: &[(&str, Option<String>)], styles: &[u8]) -> String {
        let body: Vec<String> = fields
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!("{}: {v}", escaped(k, styles))))
            .collect();
        format!("{{{}}}", body.join(", "))
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 2048,
            failure_persistence: None,
            ..proptest::prelude::ProptestConfig::default()
        })]

        /// The raw-value parser reads every record as the typed
        /// `serde_json` parser did: same fields, same drops.
        #[test]
        fn raw_and_typed_json_parsers_agree(
            legacy in proptest::prelude::any::<bool>(),
            kinds in proptest::collection::vec(proptest::prelude::any::<u8>(), 24),
            styles in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..8),
            text in "(select|SELECT|insert|update|\\PC){0,6}[ -~\\n\\t\"\\\\/é😀]{0,24}",
            user in "[a-z\\[\\] @.0-9]{0,12}",
            event in proptest::sample::select(vec![
                "connect", "change_user", "disconnect", "status", "read", "insert", "update",
                "delete", "other",
            ]),
            class in proptest::sample::select(vec!["connection", "general", "table_access", "x"]),
            name in proptest::sample::select(vec!["Query", "Connect", "Quit", "Audit"]),
            dup in proptest::prelude::any::<bool>(),
        ) {
            let k = |i: usize| kinds[i];
            // Mostly well-typed fields.
            let f = |i: usize, t: &str| field(if k(i) % 3 == 0 { k(i) } else { 9 }, t, &styles);
            let num = |i: usize, n: &str| match k(i) % 4 {
                0 => field(k(i) / 4, n, &styles),
                _ => Some(n.to_owned()),
            };
            let json = if legacy {
                let mut fields = vec![
                    ("name", f(0, name)),
                    ("record", f(1, "7306164_2026-09-29T09:45:09")),
                    ("timestamp", f(2, "2026-09-29T09:45:20Z")),
                    ("connection_id", match k(3) % 3 { 0 => num(4, "11"), 1 => f(4, "11"), _ => field(k(4), "x", &styles) }),
                    ("status", num(5, if k(5) % 2 == 0 { "0" } else { "1045" })),
                    ("sqltext", f(6, &text)),
                    ("user", f(7, &format!("{user}[{user}] @  [127.0.0.1]"))),
                    ("host", f(8, "")),
                    ("ip", f(9, "127.0.0.1")),
                    ("db", f(10, "hr")),
                    ("command_class", field(k(11), "select", &styles)),
                ];
                if dup {
                    fields.push(("sqltext", f(12, "select 2")));
                }
                format!("{{\"audit_record\": {}, \"x\": [1, {{\"y\": null}}]}}", object(&fields, &styles))
            } else {
                let mut fields = vec![
                    ("timestamp", f(0, "2026-09-29 10:06:12")),
                    ("id", num(1, "24")),
                    ("class", f(2, class)),
                    ("event", f(3, event)),
                    ("connection_id", num(4, "22")),
                    ("account", Some(object(&[("user", f(5, &user)), ("host", f(6, ""))], &styles))),
                    ("login", match k(7) % 4 { 0 => field(k(7) / 4, "x", &styles), _ => Some(object(&[("user", f(8, &user)), ("ip", f(9, "10.1.2.3"))], &styles)) }),
                    ("connection_data", Some(object(&[
                        ("status", num(10, "0")),
                        ("db", f(11, "hr")),
                        ("connection_attributes", match k(12) % 4 { 0 => field(k(12) / 4, "x", &styles), _ => Some(object(&[("program_name", f(13, "mysqldump"))], &styles)) }),
                    ], &styles))),
                    ("general_data", match k(14) % 4 { 0 => field(k(14) / 4, "x", &styles), _ => Some(object(&[
                        ("command", f(15, "Query")),
                        ("query", f(16, &text)),
                        ("status", num(17, "1146")),
                    ], &styles)) }),
                    ("table_access_data", match k(18) % 4 { 0 => field(k(18) / 4, "x", &styles), _ => Some(object(&[
                        ("db", f(19, "hr")),
                        ("table", f(20, "t")),
                        ("query", f(21, &text)),
                    ], &styles)) }),
                ];
                if dup {
                    fields.push(("event", f(22, "read")));
                }
                object(&fields, &styles)
            };
            let ours = parse_json(json.as_bytes());
            let theirs = typed::parse_json(json.as_bytes());
            proptest::prop_assert_eq!(summary(ours.as_ref()), summary(theirs.as_ref()), "{}", json);
        }

        /// Any byte string: same outcome (lone surrogate escapes and
        /// out-of-range numbers aside, which the generator cannot write).
        #[test]
        fn raw_and_typed_json_parsers_agree_on_noise(
            data in proptest::collection::vec(proptest::sample::select(b"{}[]:,\"\\ux0123456789abcdefnulltrue-. audit_recordsqltextnameQuery".to_vec()), 0..96),
        ) {
            let ours = parse_json(&data);
            let theirs = typed::parse_json(&data);
            proptest::prop_assert_eq!(summary(ours.as_ref()), summary(theirs.as_ref()));
        }
    }

    #[test]
    fn statement_texts_with_escapes_are_unescaped() {
        let q = br#"{"audit_record":{"name":"Query","record":"1_x","timestamp":"2026-09-29T09:45:20Z","connection_id":"1\u0031","status":0,"sqltext":"select \"caf\u00e9\" from hr.t \/* \ud83d\ude00 *\/","user":"root[root] @  [127.0.0.1]","ip":"127.0.0.1","db":"hr"}}"#;
        let r = parse_json(q).unwrap();
        assert_eq!(r.connection, 11);
        assert_eq!(
            r.text
                .as_deref()
                .map(|t| std::str::from_utf8(t).unwrap().to_owned()),
            Some("select \"café\" from hr.t /* 😀 */".to_owned())
        );
        // A lone surrogate in the statement drops the record, as before.
        let bad = br#"{"audit_record":{"name":"Query","timestamp":"x","connection_id":1,"sqltext":"\ud800","user":"u[u] @  [h]"}}"#;
        assert!(parse_json(bad).is_none());
        assert!(typed::parse_json(bad).is_none());
    }

    #[test]
    fn times_are_validated() {
        assert!(json_time("2026-13-01 00:00:00").is_none());
        assert!(json_time("2026-09-29T09:45:20.123456Z").is_some());
        assert!(json_time("2026-09-29T09:45:20+02:00").is_none());
        assert!(server_audit_time("20260229 25:00:00", 0).is_none());
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11_017));
    }
}
