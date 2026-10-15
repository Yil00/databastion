//! Extended Events records (ADR-0051 decision 6, "What is kept",
//! "Extended Events, one event per statement" and refinement item 4):
//! parsed from the poll's rows ([`XeRecord::from_row`], the event XML read
//! by the bounded reader of [`super::xml`]), put in context
//! ([`context`]), then mapped to access events ([`convert`]).
//!
//! - **One event per statement** (M5): only `sql_statement_completed` and
//!   `sp_statement_completed` produce access events. `rpc_completed` and
//!   `sql_batch_completed` are context only: their texts are never kept,
//!   and an `rpc_completed` of a user procedure (not `sp_executesql`,
//!   `sp_prepexec`, `sp_execute`, `sp_cursor*`…) adds the procedure as an
//!   object to the statement events of its request (open question 12).
//!   Requests are told apart by causality (`attach_activity_id`, with
//!   `TRACK_CAUSALITY = ON`), else by session and event order (the
//!   statements of a request come before its `rpc_completed`, with no
//!   other `*_completed` boundary of that session between them), within
//!   one poll.
//! - **Objects from the text** (the source has no object list): the
//!   tables, views and procedures the statement names
//!   (`classifiers::query::tsql`, `TsqlAnalysis::relations`), in the
//!   database of a three-part name or the event's `database_name`. When
//!   the text does not tell every object (not lexed, ambiguous, cut, an
//!   unknown call in a table position, dynamic SQL, a user function, a
//!   four-part name, remote access) the event names `*` and is always
//!   reported. DDL and DCL keep their kind, never text: `*`, always
//!   reported. A password-bearing statement (its text is never read past
//!   its class, the #82 rule; Extended Events records some as a comment,
//!   `-- CREATE LOGIN`, measured) is DCL, `*`, always reported.
//! - **Rows**: `row_count`, so `volume.large_result` and the agent's own
//!   row budget apply as on the other engines.
//! - **Failed logins**: `error_reported` with a login failure number
//!   (18456, 18452, 18470, 18486, 18487, 18488), the name tried taken from
//!   the session principal action and fingerprinted (never the message,
//!   which is dropped at parse); the server reports each failure twice
//!   (with and without its reason, measured on 2019), counted once.
//! - **Statistics builds** (refinement item 4): an `sp_statement_completed`
//!   whose whole text is the server's `StatMan` grammar, paired with a
//!   reported statement of the same request naming the same table in the
//!   same database, is left out, only on the allow-listed builds where
//!   users cannot call `StatMan` ([`STATMAN_BUILDS`]).
//! - **Oversized events** (above `sql::XE_EVENT_BYTES`): no XML; a
//!   statement event is a read of `*` by an unidentified principal, always
//!   reported.

use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::{
    EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::tsql::{self, TsqlAnalysis, TsqlKind};
use zeroize::Zeroizing;

use super::xml::{self, Kind, XeEvent};
use crate::audit::Positioned;
use crate::audit::records::LARGE_LIMIT;
use crate::discover::normalize;
use crate::token::Value;

/// Rows above this many are a large result (`volume.large_result`, as on
/// the other engines).
pub(crate) const LARGE_ROWS: u64 = 10_000;

/// Error numbers of a failed login.
const LOGIN_FAILURES: &[i64] = &[18_456, 18_452, 18_470, 18_486, 18_487, 18_488];

/// Server builds (`ProductVersion`) where `StatMan` was checked not
/// callable by users (refinement item 4: by a minimal login and a
/// `sysadmin`, as a batch and inside `sp_executesql`, error 195; measured
/// on 2026-10-15 on 2019, 2022 and 2025 Express): the statistics
/// exclusion is on there only.
pub(crate) const STATMAN_BUILDS: &[&str] = &["15.0.4500.2", "16.0.4305.5", "17.0.5015.4"];

/// RPCs of the driver protocol, not user procedures (open question 12).
fn system_rpc(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "sp_executesql"
            | "sp_prepexec"
            | "sp_execute"
            | "sp_prepare"
            | "sp_unprepare"
            | "sp_reset_connection"
    ) || n.starts_with("sp_cursor")
}

/// One poll row.
pub(crate) struct XeRecord {
    pub(crate) file: String,
    pub(crate) offset: i64,
    /// UTC, µs since 1970 (`timestamp_utc`).
    pub(crate) time_us: i64,
    /// The event's name (the `object_name` column).
    pub(crate) name: String,
    /// The event; `None` when its XML was above the poll's bound.
    pub(crate) event: Option<XeEvent>,
    /// A user procedure an `rpc_completed` of the same request called
    /// ([`context`]).
    pub(crate) procedure: Option<String>,
    /// Left out by [`context`] (a duplicate failed login, a statistics
    /// build).
    pub(crate) skip: bool,
    /// A statement event whose data could not be read (malformed, cut,
    /// or the reader panicked): reported as a read of `*`.
    pub(crate) unreadable: bool,
}

impl std::fmt::Debug for XeRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XeRecord")
            .field("name", &self.name)
            .field("offset", &self.offset)
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

impl Positioned for XeRecord {
    fn file(&self) -> &str {
        &self.file
    }
    fn offset(&self) -> i64 {
        self.offset
    }
}

/// Why a row is not a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The event of the joined slices: UTF-16 units decoded once (a lone
/// surrogate or an odd length is malformed), the length the server
/// reported, the XML read by the bounded reader and naming the row's event.
fn body(bytes: &[u8], size: Option<usize>, name: &str) -> Result<Option<XeEvent>, Malformed> {
    if size != Some(bytes.len()) || !bytes.len().is_multiple_of(2) {
        return Err(Malformed);
    }
    let units: Zeroizing<Vec<u16>> = Zeroizing::new(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect(),
    );
    let x = Zeroizing::new(String::from_utf16(&units).map_err(|_| Malformed)?);
    let e = xml::parse(&x).map_err(|_| Malformed)?;
    if e.name != name {
        return Err(Malformed);
    }
    Ok(Some(e))
}

impl XeRecord {
    /// A record from one poll row (`sql::XE_POLL_COLUMNS` columns: the
    /// name, the slices of the XML as UTF-16 bytes, the position, the time,
    /// the XML's size). The name, position and time are required (`Err`
    /// otherwise: the caller drops and counts the row). The slices are
    /// joined as bytes and decoded once, checked against the size, and the
    /// XML read under panic isolation; when any of that fails for a
    /// statement event, the record keeps no event data and is
    /// [`Self::unreadable`]: a read of `*` by an unidentified principal,
    /// always reported, as an oversized one (security review of lot 3, M1;
    /// the ADR-0032 / #90 precedent), never dropped. Another event that
    /// fails is `Err`.
    pub(crate) fn from_row(mut row: Vec<Value>) -> Result<Self, Malformed> {
        use crate::sql::XE_SLICES;
        if row.len() != crate::sql::XE_POLL_COLUMNS {
            return Err(Malformed);
        }
        let int = |row: &[Value], i: usize| row.get(i).and_then(Value::as_int);
        let offset = int(&row, XE_SLICES + 2).ok_or(Malformed)?;
        let time_us = int(&row, XE_SLICES + 3).ok_or(Malformed)?;
        let size = int(&row, XE_SLICES + 4).and_then(|n| usize::try_from(n).ok());
        let text = |row: &mut [Value], i: usize| match row.get_mut(i) {
            Some(Value::Text(t)) => std::mem::take(t),
            _ => String::new(),
        };
        let name = text(&mut row, 0).trim().to_owned();
        let file = text(&mut row, XE_SLICES + 1).trim_end().to_owned();
        if name.is_empty() || name.len() > 60 || file.is_empty() {
            return Err(Malformed);
        }
        let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut present = false;
        for v in row.iter_mut().take(XE_SLICES + 1).skip(1) {
            if let Value::Binary(b) = v {
                present = true;
                bytes.extend_from_slice(b);
                zeroize::Zeroize::zeroize(b);
            }
        }
        let body = if present {
            databastion_core::isolate(|| body(&bytes, size, &name)).unwrap_or(Err(Malformed))
        } else if size > Some(crate::sql::XE_EVENT_BYTES) {
            // Above the poll's bound: no XML, by design.
            Ok(None)
        } else {
            Err(Malformed)
        };
        let (event, unreadable) = match body {
            Ok(e) => (e, false),
            Err(Malformed) if Kind::of(&name).is_statement() => (None, true),
            Err(e) => return Err(e),
        };
        Ok(Self {
            file,
            offset,
            time_us,
            name,
            event,
            procedure: None,
            skip: false,
            unreadable,
        })
    }

    pub(crate) fn kind(&self) -> Kind {
        Kind::of(&self.name)
    }

    /// The acting login: the session's login (`session_server_principal_name`,
    /// the impersonator under `EXECUTE AS`), else the event's principal.
    pub(crate) fn login(&self) -> &str {
        let Some(e) = &self.event else { return "" };
        match (&e.session_principal, &e.server_principal) {
            (Some(s), _) if !s.is_empty() => s,
            (_, Some(p)) => p,
            _ => "",
        }
    }

    fn session(&self) -> Option<i64> {
        self.event.as_ref().and_then(|e| e.session_id)
    }

    fn activity(&self) -> Option<&str> {
        self.event
            .as_ref()
            .and_then(|e| e.activity.as_ref())
            .map(|(g, _)| g.as_str())
    }

    fn boundary(&self) -> bool {
        matches!(
            self.kind(),
            Kind::RpcCompleted | Kind::SqlBatchCompleted | Kind::SqlStatementCompleted
        )
    }
}

/// Whether two records belong to one request: the same activity when both
/// carry one; else the same session (event order decides, see
/// [`context`]).
fn same_request(a: &XeRecord, b: &XeRecord) -> bool {
    if a.session() != b.session() || a.session().is_none() {
        return false;
    }
    match (a.activity(), b.activity()) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

/// How far back or ahead a request is looked for, in records.
const CONTEXT_WINDOW: usize = 256;

/// The relations of a statement event, resolved to (database, schema,
/// table) lowercased, for the statistics pairing.
fn resolved(r: &XeRecord) -> Vec<(Zeroizing<String>, Zeroizing<String>, Zeroizing<String>)> {
    let Some(e) = &r.event else { return Vec::new() };
    let Some(text) = &e.statement else {
        return Vec::new();
    };
    let a = tsql::analyze_tsql(text, e.statement_cut);
    let db = Zeroizing::new(e.database.clone().unwrap_or_default());
    a.relations
        .iter()
        .map(|rel| {
            (
                Zeroizing::new(rel.database.as_deref().unwrap_or(&db).to_lowercase()),
                Zeroizing::new(rel.schema.as_deref().unwrap_or_default().to_lowercase()),
                Zeroizing::new(rel.name.to_lowercase()),
            )
        })
        .collect()
}

/// The context pass over one poll's records, in file order (see the
/// module documentation): procedure names of RPCs, duplicate failed
/// logins, statistics builds on the allow-listed builds (`statman`).
pub(crate) fn context(records: &mut [XeRecord], statman: bool) {
    // RPCs of user procedures: their statements, back to the previous
    // boundary of the session.
    for i in 0..records.len() {
        if records[i].kind() != Kind::RpcCompleted {
            continue;
        }
        let Some(proc_name) = records[i]
            .event
            .as_ref()
            .and_then(|e| e.object_name.clone())
            .filter(|n| !n.is_empty() && !system_rpc(n))
        else {
            continue;
        };
        let lo = i.saturating_sub(CONTEXT_WINDOW);
        for j in (lo..i).rev() {
            let (head, tail) = records.split_at_mut(i);
            let (Some(r), Some(rpc)) = (head.get_mut(j), tail.first()) else {
                break;
            };
            if r.session() != rpc.session() {
                continue;
            }
            if r.boundary() {
                break;
            }
            if r.kind() == Kind::SpStatementCompleted && same_request(r, rpc) {
                r.procedure = Some(proc_name.clone());
            }
        }
    }
    // A failed login is reported twice by the server (measured on 2019):
    // the second of the same session, name and request (or time) is left
    // out.
    for i in 1..records.len() {
        let lo = i.saturating_sub(8);
        let dup = (lo..i).any(|j| {
            let (a, b) = (&records[j], &records[i]);
            let fails = |r: &XeRecord| {
                r.kind() == Kind::ErrorReported
                    && r.event
                        .as_ref()
                        .and_then(|e| e.error_number)
                        .is_some_and(|n| LOGIN_FAILURES.contains(&n))
            };
            fails(a)
                && fails(b)
                && !a.skip
                && a.session() == b.session()
                && a.login() == b.login()
                && match (a.activity(), b.activity()) {
                    (Some(x), Some(y)) => x == y,
                    _ => a.time_us == b.time_us,
                }
        });
        if dup {
            records[i].skip = true;
        }
    }
    if !statman {
        return;
    }
    // Statistics builds, paired with a reported statement of the same
    // request naming the same table in the same database.
    for i in 0..records.len() {
        let r = &records[i];
        if r.kind() != Kind::SpStatementCompleted {
            continue;
        }
        let Some(e) = &r.event else { continue };
        if e.statement_cut {
            continue;
        }
        let Some((schema, table)) = e.statement.as_deref().and_then(|t| tsql::statman_table(t))
        else {
            continue;
        };
        let key = (
            Zeroizing::new(e.database.clone().unwrap_or_default().to_lowercase()),
            Zeroizing::new(schema.to_lowercase()),
            Zeroizing::new(table.to_lowercase()),
        );
        let hi = (i + 1 + CONTEXT_WINDOW).min(records.len());
        let lo = i.saturating_sub(CONTEXT_WINDOW);
        let paired = (lo..hi).filter(|j| *j != i).any(|j| {
            let o = &records[j];
            o.kind().is_statement()
                && same_request(o, r)
                && o.event
                    .as_ref()
                    .and_then(|e| e.statement.as_deref())
                    .is_some_and(|t| tsql::statman_table(t).is_none())
                && no_boundary_between(records, i, j)
                && resolved(o).contains(&key)
        });
        if paired {
            records[i].skip = true;
        }
    }
}

/// No `rpc_completed` / `sql_batch_completed` of the session between `a`
/// and `b` (a statement of another request otherwise).
fn no_boundary_between(records: &[XeRecord], a: usize, b: usize) -> bool {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let Some(session) = records.get(a).and_then(XeRecord::session) else {
        return false;
    };
    records.get(lo + 1..hi).unwrap_or_default().iter().all(|r| {
        r.session() != Some(session)
            || !matches!(r.kind(), Kind::RpcCompleted | Kind::SqlBatchCompleted)
    })
}

/// Export tools by application name (`signature.bcp`).
fn export_tool(app: &str) -> bool {
    let a = app.trim().to_ascii_lowercase();
    a == "bcp" || a.starts_with("sqlpackage") || a.contains("import and export wizard")
}

fn db_name(db: Option<&str>) -> NormalizedName {
    match db {
        Some(d) if !d.is_empty() => normalize(d),
        _ => NormalizedName::wildcard(),
    }
}

/// The access event of a record: `None` for context events, other events,
/// statements that touch no data (`SET`, `PRINT`, a `SELECT` without
/// `FROM`…), and left-out records. Returns the event and the text analysis
/// (for the own rule).
pub(crate) fn convert(r: &XeRecord) -> Option<(MaskedEvent, Option<TsqlAnalysis>)> {
    if r.skip {
        return None;
    }
    let ts = SystemTime::UNIX_EPOCH + Duration::from_micros(u64::try_from(r.time_us).unwrap_or(0));
    let kind = r.kind();
    let Some(e) = &r.event else {
        // Above the poll's bound: nothing but its name is known.
        if !kind.is_statement() {
            return None;
        }
        let ev = MaskedEvent::new(
            EventSource::SqlserverXevents,
            EventAction::Read,
            EventPrincipal::unidentified(),
            ts,
        )
        .with_object(EventObject::new(
            NormalizedName::wildcard(),
            None,
            NormalizedName::wildcard(),
        ))
        .with_always_report();
        return Some((ev, None));
    };
    let app = e.client_app.as_deref().unwrap_or_default();
    match kind {
        Kind::ErrorReported => {
            let n = e.error_number?;
            if !LOGIN_FAILURES.contains(&n) {
                return None;
            }
            let principal = EventPrincipal::failed_account(r.login()).with_application(app);
            return Some((
                MaskedEvent::new(
                    EventSource::SqlserverXevents,
                    EventAction::AuthFailure,
                    principal,
                    ts,
                ),
                None,
            ));
        }
        Kind::Login => {
            let principal = EventPrincipal::account(r.login()).with_application(app);
            return Some((
                MaskedEvent::new(
                    EventSource::SqlserverXevents,
                    EventAction::Connect,
                    principal,
                    ts,
                ),
                None,
            ));
        }
        Kind::SqlStatementCompleted | Kind::SpStatementCompleted => {}
        _ => return None,
    }
    // A statement with no principal (a system task): an unidentified
    // account, never an empty name.
    let principal = if r.login().is_empty() {
        EventPrincipal::unidentified()
    } else {
        EventPrincipal::account(r.login())
    }
    .with_application(app);
    let db = e.database.as_deref();
    let star = |ev: MaskedEvent| {
        ev.with_object(EventObject::new(
            db_name(db),
            None,
            NormalizedName::wildcard(),
        ))
        .with_always_report()
    };
    let new =
        |action| MaskedEvent::new(EventSource::SqlserverXevents, action, principal.clone(), ts);
    let text = e.statement.as_deref().map_or("", |s| s.as_str());
    if text.trim().is_empty() {
        // No statement text (collection off): what it read is unknown.
        return Some((star(new(EventAction::Read)), None));
    }
    let a = tsql::analyze_tsql(text, e.statement_cut);
    if a.comment_only {
        // The server's placeholder for a statement it does not record
        // (measured on 2019): `-- CREATE LOGIN`, `-- CREATE CREDENTIAL`,
        // `-- sp_addlogin` (password-bearing: DCL), `-- SELECT` (a read
        // calling ENCRYPTBYPASSPHRASE), `-- Encrypted text` (a statement of
        // an encrypted module: code that runs out of sight). The kind its
        // words name, never more; `*`, always reported.
        let action = if a.credential {
            EventAction::Dcl
        } else if a.kind == TsqlKind::Write {
            EventAction::Write
        } else if matches!(a.kind, TsqlKind::Ddl | TsqlKind::Dcl) {
            EventAction::Dcl
        } else {
            EventAction::Read
        };
        return Some((star(new(action)), Some(a)));
    }
    if a.credential {
        // A password-bearing statement: its class, never its text or
        // objects.
        return Some((star(new(EventAction::Dcl)), Some(a)));
    }
    let action = match a.kind {
        // A write into a table variable or a `#temp` table only reads.
        TsqlKind::Write if a.usable() && !a.writes_table => EventAction::Read,
        TsqlKind::Write | TsqlKind::Bulk => EventAction::Write,
        TsqlKind::Ddl => EventAction::Ddl,
        TsqlKind::Dcl => EventAction::Dcl,
        _ => EventAction::Read,
    };
    if matches!(a.kind, TsqlKind::Ddl | TsqlKind::Dcl) {
        return Some((star(new(action)), Some(a)));
    }
    let mut ev = new(action).with_rows(e.row_count);
    if !a.usable() {
        // Cut, unlexable or ambiguous (the ADR-0045 #181 rule), or a call
        // of a password-taking function: what it names cannot be used.
        return Some((star(ev), Some(a)));
    }
    let mut always = false;
    let mut wildcard = false;
    for rel in &a.relations {
        let rdb = rel.database.as_deref().or(db);
        ev = ev.with_object(EventObject::new(
            db_name(rdb),
            rel.schema.as_deref().map(normalize),
            normalize(&rel.name),
        ));
    }
    if let Some(p) = &r.procedure {
        ev = ev.with_object(EventObject::new(db_name(db), None, normalize(p)));
    }
    for n in &a.listed {
        ev = ev.with_object(EventObject::new(
            db_name(db),
            Some(normalize("sys")),
            normalize(n),
        ));
        always = true;
    }
    if !a.relations_complete {
        wildcard = true;
    }
    if a.remote_access {
        ev = ev.with_signal(Signal::RemoteDataAccess);
        wildcard = true;
    }
    if a.backup || a.kind == TsqlKind::Backup {
        ev = ev.with_signal(Signal::BackupDatabase);
        always = true;
        wildcard = true;
    }
    if a.kind == TsqlKind::Dbcc && a.listed.is_empty() {
        wildcard = true;
    }
    if a.dynamic_sql || a.user_function || a.four_part {
        wildcard = true;
    }
    let touches = !ev.objects().is_empty() || wildcard;
    if !touches {
        // `SET`, `PRINT`, `BEGIN TRAN`, a `SELECT` of constants: no data.
        return None;
    }
    if action == EventAction::Read && a.full_table_read(LARGE_LIMIT + 1) {
        ev = ev.with_signal(Signal::FullTableRead);
    }
    if e.row_count.is_some_and(|n| n > LARGE_ROWS) {
        ev = ev.with_signal(Signal::LargeResult);
    }
    if action == EventAction::Read && export_tool(app) {
        ev = ev.with_signal(Signal::Bcp);
    }
    if wildcard {
        ev = star(ev);
    } else if always {
        ev = ev.with_always_report();
    }
    Some((ev, Some(a)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use crate::audit::xe::xml::tests::event;

    pub(crate) fn rec(name: &str, data: &[(&str, &str)], actions: &[(&str, &str)]) -> XeRecord {
        let x = event(name, data, actions);
        XeRecord {
            file: "/x/s_0_1.xel".to_owned(),
            offset: 4096,
            time_us: 1_800_000_000_000_000,
            name: name.to_owned(),
            event: Some(xml::parse(&x).unwrap()),
            procedure: None,
            skip: false,
            unreadable: false,
        }
    }

    pub(crate) fn who(login: &str, session: &str) -> Vec<(&'static str, String)> {
        vec![
            ("session_id", session.to_owned()),
            ("server_principal_name", login.to_owned()),
            ("session_server_principal_name", login.to_owned()),
            ("database_name", "retail".to_owned()),
            ("client_app_name", "SQLCMD".to_owned()),
        ]
    }

    pub(crate) fn stmt(kind: &str, text: &str, rows: u64, session: &str) -> XeRecord {
        let rows = rows.to_string();
        let a = who("app", session);
        let actions: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let t = text.replace('&', "&amp;").replace('<', "&lt;");
        rec(kind, &[("row_count", &rows), ("statement", &t)], &actions)
    }

    fn names(ev: &MaskedEvent) -> Vec<String> {
        ev.objects()
            .iter()
            .map(|o| {
                format!(
                    "{}.{}.{}",
                    o.database().as_str(),
                    o.schema().map_or("-", |s| s.as_str()),
                    o.object().as_str()
                )
            })
            .collect()
    }

    fn one(r: &XeRecord) -> MaskedEvent {
        convert(r).unwrap().0
    }

    #[test]
    fn reads_name_their_tables_and_carry_rows() {
        let ev = one(&stmt(
            "sql_statement_completed",
            "SELECT TOP (2) id FROM retail.crm.customers c JOIN crm.customer_notes n ON n.cid = c.id",
            2,
            "51",
        ));
        assert_eq!(ev.action(), EventAction::Read);
        assert_eq!(ev.source(), EventSource::SqlserverXevents);
        assert_eq!(
            names(&ev),
            ["retail.crm.customer_notes", "retail.crm.customers"]
        );
        assert_eq!(ev.rows(), Some(2));
        assert!(ev.signals().is_empty() && !ev.always_report());
        // A dump-like read: whole table and large.
        let ev = one(&stmt(
            "sql_statement_completed",
            "select * from crm.customers",
            20_000,
            "51",
        ));
        assert!(ev.signals().contains(&Signal::FullTableRead));
        assert!(ev.signals().contains(&Signal::LargeResult));
        // An ORM's parameterized statement keeps its objects.
        let ev = one(&stmt(
            "sp_statement_completed",
            "SELECT TOP (1) id FROM retail.crm.customers WHERE id = @p",
            1,
            "51",
        ));
        assert_eq!(names(&ev), ["retail.crm.customers"]);
        // Writes.
        let ev = one(&stmt(
            "sql_statement_completed",
            "UPDATE crm.customers SET name = N'x' WHERE id = 1",
            1,
            "51",
        ));
        assert_eq!(ev.action(), EventAction::Write);
    }

    #[test]
    fn statements_without_data_are_not_events() {
        for t in [
            "SET NOCOUNT ON; ",
            "SELECT 1 AS x",
            "SELECT @@VERSION",
            "BEGIN TRAN",
            "PRINT 'x'",
        ] {
            assert!(
                convert(&stmt("sql_statement_completed", t, 0, "51")).is_none(),
                "{t}"
            );
        }
    }

    #[test]
    fn unknown_objects_name_star_and_are_always_reported() {
        for t in [
            "EXEC sp_executesql N'SELECT TOP (1) id FROM retail.crm.customers WHERE id = @p', N'@p int', @p = 5",
            "SELECT * FROM GetCustomers(1)",
            "SELECT dbo.f(a) FROM crm.customers",
            "SELECT * FROM srv.retail.crm.customers",
            "SELECT 'abc",
            "SELECT * FROM OPENROWSET('x', 'y', 'SELECT 1')",
        ] {
            let ev = one(&stmt("sql_statement_completed", t, 1, "51"));
            assert!(ev.always_report(), "{t}");
            assert!(names(&ev).contains(&"retail.-.*".to_owned()), "{t}");
        }
        // A cut text.
        let mut r = stmt(
            "sql_statement_completed",
            "SELECT a FROM crm.customers",
            1,
            "51",
        );
        r.event.as_mut().unwrap().statement_cut = true;
        assert!(one(&r).always_report());
        // Listed objects.
        let ev = one(&stmt(
            "sql_statement_completed",
            "SELECT t.text FROM sys.dm_exec_query_stats s CROSS APPLY sys.dm_exec_sql_text(s.sql_handle) t",
            3,
            "51",
        ));
        assert!(ev.always_report());
        assert!(names(&ev).contains(&"retail.sys.dm_exec_sql_text".to_owned()));
    }

    #[test]
    fn password_statements_keep_their_class_only() {
        for t in ["-- SELECT", "-- Encrypted text"] {
            let ev = one(&stmt("sp_statement_completed", t, 1, "51"));
            assert_eq!(ev.action(), EventAction::Read, "{t}");
            assert!(ev.always_report() && names(&ev) == ["retail.-.*"], "{t}");
        }
        for t in [
            "-- CREATE LOGIN",
            "-- CREATE CREDENTIAL",
            "-- sp_addlogin",
            "-- sp_addlinkedsrvlogin",
            "CREATE LOGIN jane WITH PASSWORD = 'Marker-123'",
            "EXEC sp_addlogin jane, Pa55wordMarker",
        ] {
            let (ev, _) = convert(&stmt("sql_statement_completed", t, 0, "51")).unwrap();
            assert_eq!(ev.action(), EventAction::Dcl, "{t}");
            assert!(ev.always_report() && names(&ev) == ["retail.-.*"], "{t}");
        }
        let ev = one(&stmt(
            "sql_statement_completed",
            "DROP TABLE crm.x",
            0,
            "51",
        ));
        assert_eq!(ev.action(), EventAction::Ddl);
        assert!(ev.always_report());
    }

    #[test]
    fn failed_logins_are_fingerprinted_once() {
        let fail = || {
            rec(
                "error_reported",
                &[
                    ("error_number", "18456"),
                    ("message", "Login failed for user 'jane'."),
                ],
                &[
                    ("session_id", "51"),
                    ("session_server_principal_name", "jane"),
                    (
                        "attach_activity_id",
                        "330EEB20-6C37-4B26-B0B6-4748924CE0EF-1",
                    ),
                ],
            )
        };
        let mut recs = vec![fail(), fail()];
        context(&mut recs, false);
        let evs: Vec<MaskedEvent> = recs.iter().filter_map(convert).map(|(e, _)| e).collect();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].action(), EventAction::AuthFailure);
        assert!(!evs[0].principal().send_name());
        assert_eq!(evs[0].principal().account_name(), "jane");
        // Another error: no event.
        let other = rec(
            "error_reported",
            &[("error_number", "208")],
            &[("session_id", "51")],
        );
        assert!(convert(&other).is_none());
    }

    #[test]
    fn rpc_procedures_and_context_events() {
        let a = who("app", "60");
        let actions: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut recs = vec![
            stmt(
                "sp_statement_completed",
                "SELECT a FROM crm.customers WHERE id = @id",
                1,
                "60",
            ),
            rec(
                "rpc_completed",
                &[
                    ("object_name", "get_customer"),
                    ("statement", "exec get_customer @id = 7"),
                    ("row_count", "1"),
                ],
                &actions,
            ),
        ];
        context(&mut recs, false);
        let ev = one(&recs[0]);
        assert_eq!(
            names(&ev),
            ["retail.-.get_customer", "retail.crm.customers"]
        );
        assert!(convert(&recs[1]).is_none(), "rpc_completed is context only");
        // sp_executesql is the driver protocol, not a procedure.
        let mut recs = vec![
            stmt(
                "sp_statement_completed",
                "SELECT a FROM crm.customers WHERE id = @id",
                1,
                "60",
            ),
            rec(
                "rpc_completed",
                &[("object_name", "sp_executesql")],
                &actions,
            ),
        ];
        context(&mut recs, false);
        assert_eq!(names(&one(&recs[0])), ["retail.crm.customers"]);
    }

    #[test]
    fn statistics_builds_need_a_pair_and_an_allowed_build() {
        let statman = "SELECT StatMan([SC0]) FROM (SELECT TOP 100 PERCENT [id] AS [SC0] FROM \
            [crm].[customers] WITH (READUNCOMMITTED)  ORDER BY [SC0] ) AS _MS_UPDSTATS_TBL  OPTION (MAXDOP 16)";
        let build = || {
            vec![
                stmt("sp_statement_completed", statman, 1, "51"),
                stmt(
                    "sql_statement_completed",
                    "SELECT TOP (2) id FROM crm.customers WHERE id > 3",
                    2,
                    "51",
                ),
            ]
        };
        let mut recs = build();
        context(&mut recs, true);
        assert!(recs[0].skip, "paired: left out");
        let mut recs = build();
        context(&mut recs, false);
        assert!(!recs[0].skip, "not an allow-listed build: counted");
        let ev = one(&recs[0]);
        assert_eq!(names(&ev), ["retail.crm.customers"]);
        // No pair (another table, another session): counted.
        let mut recs = vec![
            stmt("sp_statement_completed", statman, 1, "51"),
            stmt(
                "sql_statement_completed",
                "SELECT TOP (2) id FROM crm.cards",
                2,
                "51",
            ),
            stmt(
                "sql_statement_completed",
                "SELECT TOP (2) id FROM crm.customers",
                2,
                "52",
            ),
        ];
        context(&mut recs, true);
        assert!(!recs[0].skip);
        // A pair alone in another database: counted.
        let mut recs = vec![
            stmt("sp_statement_completed", statman, 1, "51"),
            stmt(
                "sql_statement_completed",
                "SELECT TOP (2) id FROM other.crm.customers",
                2,
                "51",
            ),
        ];
        context(&mut recs, true);
        assert!(!recs[0].skip);
    }

    #[test]
    fn oversized_events_are_reads_of_star() {
        let r = XeRecord {
            file: "/x/s_0_1.xel".to_owned(),
            offset: 4096,
            time_us: 1,
            name: "sql_statement_completed".to_owned(),
            event: None,
            procedure: None,
            skip: false,
            unreadable: false,
        };
        let ev = one(&r);
        assert!(ev.always_report() && !ev.principal().send_name());
        assert_eq!(names(&ev), ["*.-.*"]);
    }

    /// A poll row whose slices hold `units` as UTF-16LE bytes (8 000 bytes
    /// each, as `sql::XE_COLUMNS`) and whose size is `size`.
    pub(crate) fn row_of(name: &str, units: &[u16], size: usize) -> Vec<Value> {
        use crate::sql::XE_SLICES;
        let mut row = vec![Value::Null; crate::sql::XE_POLL_COLUMNS];
        row[0] = Value::Text(name.to_owned());
        let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
        for i in 0..XE_SLICES {
            let part = bytes
                .get(i * 8000..((i + 1) * 8000).min(bytes.len()))
                .unwrap_or_default();
            row[1 + i] = Value::Binary(part.to_vec());
        }
        row[XE_SLICES + 1] = Value::Text("/x/s_0_1.xel".to_owned());
        row[XE_SLICES + 2] = Value::Int(4096);
        row[XE_SLICES + 3] = Value::Int(1);
        row[XE_SLICES + 4] = Value::Int(i64::try_from(size).unwrap());
        row
    }

    #[test]
    fn rows_need_their_required_columns() {
        use crate::sql::XE_SLICES;
        assert!(XeRecord::from_row(vec![Value::Null; 3]).is_err());
        let mut row = vec![Value::Null; crate::sql::XE_POLL_COLUMNS];
        assert!(XeRecord::from_row(row.clone()).is_err());
        row[0] = Value::Text("sql_statement_completed".to_owned());
        row[XE_SLICES + 1] = Value::Text("/x/s_0_1.xel".to_owned());
        row[XE_SLICES + 2] = Value::Int(4096);
        row[XE_SLICES + 3] = Value::Int(1);
        row[XE_SLICES + 4] = Value::Int(300_000);
        let r = XeRecord::from_row(row.clone()).unwrap();
        assert!(
            r.event.is_none() && !r.unreadable,
            "above the bound: no XML"
        );
        let units = |x: &str| -> Vec<u16> { x.encode_utf16().collect() };
        // The XML must name the row's event.
        let x = units(&event("login", &[], &[]));
        assert!(
            XeRecord::from_row(row_of("sql_statement_completed", &x, x.len() * 2))
                .unwrap()
                .unreadable
        );
        // A statement whose surrogate pair straddles the 8 000-byte slice
        // boundary is joined exactly (M2).
        let head = "<event name=\"sql_statement_completed\"><data name=\"statement\"><value>";
        let pad = 4000 - head.encode_utf16().count() - 1;
        let stmt = format!("{}\u{1F600} tail", "y".repeat(pad));
        let x = units(&format!("{head}{stmt}</value></data></event>"));
        assert_eq!(x[3999], 0xD83D, "the pair is split by the slices");
        let r = XeRecord::from_row(row_of("sql_statement_completed", &x, x.len() * 2)).unwrap();
        assert_eq!(
            r.event
                .as_ref()
                .unwrap()
                .statement
                .as_deref()
                .map(String::as_str),
            Some(stmt.as_str())
        );
    }

    /// Security review of lot 3, M1: a statement event that cannot be read
    /// is a read of `*` by an unidentified principal, always reported;
    /// another event is dropped and counted.
    #[test]
    fn unreadable_statement_events_are_reported() {
        let units = |x: &str| -> Vec<u16> { x.encode_utf16().collect() };
        let bad_xml = [
            event(
                "sql_statement_completed",
                &[("statement", "SELECT &#0;")],
                &[],
            ),
            event(
                "sql_statement_completed",
                &[("statement", "SELECT &#xD800;")],
                &[],
            ),
            "<event name=\"sql_statement_completed\"><data".to_owned(),
        ];
        for x in &bad_xml {
            let u = units(x);
            let r = XeRecord::from_row(row_of("sql_statement_completed", &u, u.len() * 2)).unwrap();
            assert!(r.unreadable && r.event.is_none());
            let ev = one(&r);
            assert!(ev.always_report() && !ev.principal().send_name());
            assert_eq!(names(&ev), ["*.-.*"]);
        }
        // A lone surrogate in the bytes, an odd length, a size that does not
        // match the slices, and no slice at all under the bound.
        let mut lone = units(&event("sp_statement_completed", &[("statement", "x")], &[]));
        lone[60] = 0xDC00;
        let cases = [
            row_of("sp_statement_completed", &lone, lone.len() * 2),
            row_of("sp_statement_completed", &units("<event/>"), 5),
            row_of("sp_statement_completed", &units("<event/>"), 10),
        ];
        for row in cases {
            assert!(XeRecord::from_row(row).unwrap().unreadable);
        }
        let mut none = row_of("sql_statement_completed", &[], 100);
        for v in none.iter_mut().take(crate::sql::XE_SLICES + 1).skip(1) {
            *v = Value::Null;
        }
        assert!(XeRecord::from_row(none).unwrap().unreadable);
        // Not a statement event: dropped (counted by the caller).
        let u = units("<event name=\"login\"><data");
        assert!(XeRecord::from_row(row_of("login", &u, u.len() * 2)).is_err());
    }
}
