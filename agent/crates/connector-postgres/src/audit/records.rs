//! Server log records: splitting (jsonlog, csvlog), and parsing of the
//! pgaudit `AUDIT:` records only (ADR-0012 obligation 7).
//!
//! - Records are split out of the byte stream with a bound
//!   ([`MAX_RECORD_BYTES`]): a longer record is skipped to its end and
//!   counted, never buffered.
//! - Only records whose message starts with `AUDIT: ` are parsed. From
//!   them, only the structured fields are kept (time, user, database,
//!   client address, application, session) plus the pgaudit fields; the
//!   statement text is kept in a zeroizing buffer for the local analysis
//!   (`classifiers::query`) and never logged. `detail`, `hint`,
//!   `context`, `internal_query`, the error `statement` of other records
//!   and the pgaudit parameter field are never read.
//! - A record (or a pgaudit payload) whose CSV does not parse is dropped.

use std::fmt;
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

/// Longest log record kept, in bytes.
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Longest CSV field count accepted in a record.
const MAX_FIELDS: usize = 64;
/// Prefix of pgaudit messages.
const AUDIT_PREFIX: &str = "AUDIT: ";

/// Format of the server log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Jsonlog,
    Csvlog,
}

/// Splits a byte stream into records (a newline ends a record; in csvlog,
/// only outside a quoted field). Bounded: see [`MAX_RECORD_BYTES`].
pub(crate) struct Splitter {
    csv: bool,
    buf: Zeroizing<Vec<u8>>,
    in_quotes: bool,
    skipping: bool,
    /// Bytes consumed since the end of the last complete record.
    pending: u64,
    /// Records skipped for their size.
    pub(crate) oversized: u64,
    max: usize,
}

impl Splitter {
    pub(crate) fn new(format: Format) -> Self {
        Self::with_max(format, MAX_RECORD_BYTES)
    }

    pub(crate) fn with_max(format: Format, max: usize) -> Self {
        Self {
            csv: format == Format::Csvlog,
            buf: Zeroizing::new(Vec::new()),
            in_quotes: false,
            skipping: false,
            pending: 0,
            oversized: 0,
            max,
        }
    }

    /// Bytes of an incomplete record at the end of what was fed.
    pub(crate) fn pending(&self) -> u64 {
        self.pending
    }

    /// Forgets any incomplete record (file rotated or truncated).
    pub(crate) fn reset(&mut self) {
        self.buf.clear();
        self.in_quotes = false;
        self.skipping = false;
        self.pending = 0;
    }

    /// Feeds bytes; complete records are appended to `out`.
    pub(crate) fn feed(&mut self, data: &[u8], out: &mut Vec<Zeroizing<Vec<u8>>>) {
        for &b in data {
            self.pending += 1;
            if self.csv && b == b'"' {
                self.in_quotes = !self.in_quotes;
            }
            if b == b'\n' && !self.in_quotes {
                if self.skipping {
                    self.skipping = false;
                    self.oversized += 1;
                } else if !self.buf.is_empty() {
                    let mut record = Zeroizing::new(Vec::with_capacity(self.buf.len()));
                    record.extend_from_slice(&self.buf);
                    if record.last() == Some(&b'\r') {
                        record.pop();
                    }
                    out.push(record);
                }
                self.buf.clear();
                self.pending = 0;
                continue;
            }
            if self.skipping {
                continue;
            }
            if self.buf.len() >= self.max {
                self.skipping = true;
                self.buf.clear();
                continue;
            }
            self.buf.push(b);
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
/// needs a role that can hide the context (`log_error_verbosity = terse`
/// is superuser-only, but a server-wide `log_error_verbosity = terse`
/// removes every context and with it this protection) or native code (C
/// extensions, untrusted PLs).
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
                audit,
            })
        }
        Format::Csvlog => {
            if !contains(record, b",\"AUDIT: ") {
                return Err(Skip::NotAudit);
            }
            let text = std::str::from_utf8(record).map_err(|_| Skip::NotAudit)?;
            let f = parse_csv(text).ok_or(Skip::NotAudit)?;
            if f.len() < 23 {
                return Err(Skip::NotAudit);
            }
            let audit = parse_pgaudit(&f[13]).ok_or(Skip::NotAudit)?;
            // error_severity (11), context (18).
            check(Some(f[11].as_str()), !f[18].is_empty())?;
            // `connection_from` is `host:port` or `[local]`.
            let from = f[4].as_str();
            let remote = if from.is_empty() {
                None
            } else if from == "[local]" {
                Some(from.to_owned())
            } else {
                Some(
                    from.rsplit_once(':')
                        .map_or(from, |(host, _port)| host)
                        .to_owned(),
                )
            };
            Ok(AuditRecord {
                ts: parse_log_time(&f[0]),
                user: f[1].to_string(),
                database: f[2].to_string(),
                remote,
                application: f[22].to_string(),
                session: f[5].to_string(),
                audit,
            })
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_AUDIT: &str = r#"{"timestamp":"2026-09-28 21:45:31.320 UTC","user":"postgres","dbname":"shop","pid":1007,"remote_host":"127.0.0.1","remote_port":42682,"session_id":"6abadffb.3ef","line_num":5,"ps":"SELECT","session_start":"2026-09-28 21:45:31 UTC","vxid":"3/56","txid":0,"error_severity":"LOG","message":"AUDIT: OBJECT,2,1,READ,SELECT,TABLE,crm.customers,select count(*) from crm.customers where email like '%x%',<not logged>,1","application_name":"psql","backend_type":"client backend","query_id":4482980966766602260}"#;

    const CSV_MULTILINE: &str = "2026-09-28 21:45:31.455 UTC,\"postgres\",\"shop\",1015,\"127.0.0.1:42692\",6abadffb.3f7,8,\"PREPARE\",2026-09-28 21:45:31 UTC,3/71,0,LOG,00000,\"AUDIT: SESSION,5,1,READ,PREPARE,,,\"\"PREPARE dumpFunc(pg_catalog.oid) AS\nSELECT\nproretset, 'lit,eral'\nFROM pg_catalog.pg_proc p\"\",<not logged>,1\",,,,,,,,,\"pg_dump\",\"client backend\",,6233516217350320405\n";

    fn split(format: Format, data: &[u8], max: usize) -> (Vec<Vec<u8>>, Splitter) {
        let mut s = Splitter::with_max(format, max);
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
    fn huge_records_are_skipped_not_buffered() {
        let mut data = vec![b'x'; 5000];
        data.push(b'\n');
        data.extend_from_slice(JSON_AUDIT.as_bytes());
        data.push(b'\n');
        let (records, s) = split(Format::Jsonlog, &data, 4096);
        assert_eq!(records.len(), 1);
        assert_eq!(s.oversized, 1);
        assert_eq!(s.pending(), 0);
        // A huge unterminated record keeps at most `max` bytes.
        let mut s = Splitter::with_max(Format::Jsonlog, 16);
        let mut out = Vec::new();
        s.feed(&[b'y'; 100_000], &mut out);
        assert!(out.is_empty());
        assert!(s.buf.len() <= 16);
        assert_eq!(s.pending(), 100_000);
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
