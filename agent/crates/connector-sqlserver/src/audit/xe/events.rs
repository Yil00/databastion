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

use std::time::{Duration, Instant, SystemTime};

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
    /// Its place among the records of its read (the deferral of a build,
    /// refinement of 2026-10-16, item 4).
    pub(crate) index: usize,
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
            index: 0,
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
/// Returns how many statistics statements it left out. `own` tells
/// whether a record is from one of the agent's own sessions within its
/// lifetime with both principals the agent's (case 2).
pub(crate) fn context(
    records: &mut [XeRecord],
    statman: bool,
    own: &dyn Fn(&XeRecord) -> bool,
) -> usize {
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
        return 0;
    }
    // Statistics builds (refinement item 4 and the refinement of
    // 2026-10-15, case 2).
    let mut builds: Vec<usize> = Vec::new();
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
        // Item 4: paired with a reported statement of the same request
        // naming the same table in the same database.
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
        // Case 2: a build on a measured system base table, in one of the
        // agent's own sessions (`own`: SPID, lifetime, both principals),
        // in the same causality activity as one of the agent's exact
        // catalog texts from its own session.
        let own_catalog = || {
            let Some((guid, _)) = e.activity.as_ref() else {
                return false;
            };
            schema.eq_ignore_ascii_case("sys")
                && SYS_BASE_TABLES
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(&table))
                && own(r)
                && (lo..hi).filter(|j| *j != i).any(|j| {
                    let o = &records[j];
                    o.kind().is_statement()
                        && o.event.as_ref().is_some_and(|oe| {
                            !oe.statement_cut
                                && oe.activity.as_ref().is_some_and(|(g, _)| g == guid)
                                && oe
                                    .statement
                                    .as_deref()
                                    .is_some_and(|t| crate::sql::catalog_text(t))
                        })
                        && own(o)
                })
        };
        if paired || own_catalog() {
            builds.push(i);
        }
    }
    let mut left_out = 0;
    for &i in &builds {
        records[i].skip = true;
        left_out += 1;
        // Case 1: the build's internal statements that follow it in its
        // causality activity (never by session order), at contiguous
        // sequence numbers, at most 3, each of the measured shape.
        let Some((guid, seq)) = records[i].event.as_ref().and_then(|e| e.activity.clone()) else {
            continue;
        };
        let build_nest = records[i].event.as_ref().and_then(|e| e.nest_level);
        // In file order, an internal statement can come before its build
        // (measured on 2022): looked for on both sides, by sequence.
        let lo = i.saturating_sub(CONTEXT_WINDOW);
        let hi = (i + 1 + CONTEXT_WINDOW).min(records.len());
        for next in seq + 1..=seq + MAX_BUILD_INTERNALS {
            let found = (lo..hi).find(|&j| {
                records[j]
                    .event
                    .as_ref()
                    .and_then(|e| e.activity.as_ref())
                    .is_some_and(|(g, s)| *g == guid && *s == next)
            });
            match found {
                Some(j) if build_internal(&records[j], build_nest) && !records[j].skip => {
                    records[j].skip = true;
                    left_out += 1;
                }
                // Not contiguous, or not of the shape: the run ends.
                _ => break,
            }
        }
    }
    left_out
}

/// A build that case 2 could leave out but that its read left unpaired
/// (refinement of 2026-10-16, item 4): an `sp_statement_completed`
/// statistics build, not left out, with causality, on a listed system base
/// table, from one of the agent's own sessions (`own`), on an allow-listed
/// build (`statman`). Never a record of another session.
pub(crate) fn unpaired_case_2(
    r: &XeRecord,
    statman: bool,
    own: &dyn Fn(&XeRecord) -> bool,
) -> bool {
    if !statman || r.skip || r.kind() != Kind::SpStatementCompleted {
        return false;
    }
    let Some(e) = &r.event else { return false };
    if e.statement_cut || e.activity.is_none() {
        return false;
    }
    let Some((schema, table)) = e.statement.as_deref().and_then(|t| tsql::statman_table(t)) else {
        return false;
    };
    schema.eq_ignore_ascii_case("sys")
        && SYS_BASE_TABLES
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&table))
        && own(r)
}

/// The longest a build is deferred (refinement of 2026-10-16, item 4).
pub(crate) const MAX_DEFERRAL: Duration = Duration::from_secs(60);
/// Builds remembered at most; beyond, no new deferral (reported).
const MAX_DEFERRED: usize = 4096;
/// A deferral is forgotten this long after its bound.
const DEFERRAL_KEEP: Duration = Duration::from_secs(600);

/// The deferrals of unpaired case 2 builds across the reads of one stream
/// (refinement of 2026-10-16, item 4), in memory only: a read that holds
/// one ends just before it, so that the next read, which starts at it,
/// can pair it. One deferral per build (by its causality activity and
/// sequence number), for at most its bound from when it was first seen;
/// after that, the build is handled as it stands (reported when still
/// unpaired).
#[derive(Debug, Default)]
pub(crate) struct Deferrals {
    until: std::collections::HashMap<(String, u64), Instant>,
}

impl Deferrals {
    /// The index (in its read, [`XeRecord::index`]) before which the read
    /// ends, if one of `records` (after [`context`]) is a build to defer.
    pub(crate) fn cut(
        &mut self,
        records: &[XeRecord],
        statman: bool,
        own: &dyn Fn(&XeRecord) -> bool,
        now: Instant,
        bound: Duration,
    ) -> Option<usize> {
        let bound = bound.min(MAX_DEFERRAL);
        self.until
            .retain(|_, until| now.saturating_duration_since(*until) <= DEFERRAL_KEEP);
        for r in records {
            if !unpaired_case_2(r, statman, own) {
                continue;
            }
            let Some(key) = r.event.as_ref().and_then(|e| e.activity.clone()) else {
                continue;
            };
            match self.until.get(&key) {
                Some(until) if now < *until => return Some(r.index),
                // Its deferral is over: handled as it stands.
                Some(_) => {}
                None if self.until.len() < MAX_DEFERRED && !bound.is_zero() => {
                    self.until.insert(key, now + bound);
                    return Some(r.index);
                }
                None => {}
            }
        }
        None
    }
}

/// Internal statements of one statistics build left out at most (case 1:
/// one to three measured).
const MAX_BUILD_INTERNALS: u64 = 3;

/// Measured system base tables whose statistics the agent's own catalog
/// reads make a fresh server build (2019 15.0.4500.2, 2022 16.0.4305.5 and
/// 2025 17.0.5015.4, each on a new data volume, measured on 2026-10-15; the
/// same tables on all three): the closed list of case 2, never
/// any `sys` table. `sysowners` and `sysxlgns` were measured too (builds on
/// their `password` and `type` columns) and are left off: they hold
/// credentials, so a build on them stays reported (decided by the
/// maintainer, ADR-0051 refinement of 2026-10-16, item 3). `sysguidrefs`
/// (in `master`, a build paired with the `audit_file` proof, measured on
/// 2022 and 2025) joined the list on 2026-10-16 (ADR-0051, addendum to the
/// refinement of 2026-10-16), under the same conditions as the others.
pub(crate) const SYS_BASE_TABLES: &[&str] = &[
    "sysschobjs",
    "sysrowsets",
    "syscolpars",
    "sysobjvalues",
    "sysidxstats",
    "sysclsobjs",
    "sysmultiobjrefs",
    "syssingleobjrefs",
    "sysprivs",
    "sysdbreg",
    "sysguidrefs",
];

/// The `object_type` map value of `ADHOC`.
const ADHOC: i64 = 20_801;

/// The measured shape of a statistics build's internal statement (case 1,
/// condition 4 as revised on 2026-10-16): `sp_statement_completed`, an
/// empty complete text, `object_type` ADHOC, both offsets 0, at the
/// build's `nest_level` minus one, the build's `nest_level` being 2 or
/// more (measured on 2019, 2022 and 2025).
pub(crate) fn build_internal(r: &XeRecord, build_nest: Option<i64>) -> bool {
    let Some(build_nest) = build_nest.filter(|n| *n >= 2) else {
        return false;
    };
    r.kind() == Kind::SpStatementCompleted
        && r.event.as_ref().is_some_and(|e| {
            !e.statement_cut
                && e.statement.as_deref().is_some_and(|t| t.is_empty())
                && e.object_type == Some(ADHOC)
                && e.object_type_name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case("adhoc"))
                && e.nest_level == Some(build_nest - 1)
                && e.offset == Some(0)
                && e.offset_end == Some(0)
        })
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
            index: 0,
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

    pub(super) fn names(ev: &MaskedEvent) -> Vec<String> {
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

    /// Re-review L6: an `INSERT` column list is not a function call; the
    /// event names the target and the sources and is not always reported.
    #[test]
    fn write_target_aliases_and_column_lists() {
        for (t, want) in [
            (
                "INSERT crm.copy (a, b) SELECT a, b FROM crm.src",
                vec!["retail.crm.copy", "retail.crm.src"],
            ),
            (
                "INSERT INTO crm.copy (a, b) SELECT a, b FROM crm.src",
                vec!["retail.crm.copy", "retail.crm.src"],
            ),
            ("INSERT crm.copy (a) VALUES (1)", vec!["retail.crm.copy"]),
            (
                "INSERT INTO retail.crm.copy(a) VALUES (1)",
                vec!["retail.crm.copy"],
            ),
        ] {
            let ev = one(&stmt("sql_statement_completed", t, 1, "51"));
            assert_eq!(ev.action(), EventAction::Write, "{t}");
            assert_eq!(names(&ev), want, "{t}");
            assert!(!ev.always_report(), "{t}");
        }
        // A user function in the inserted rows still names `*`.
        for t in [
            "INSERT crm.copy (a) SELECT crm.f(a) FROM crm.src",
            "INSERT crm.copy (a) VALUES (crm.f(1))",
        ] {
            let ev = one(&stmt("sql_statement_completed", t, 1, "51"));
            assert!(ev.always_report(), "{t}");
            assert!(names(&ev).contains(&"retail.-.*".to_owned()), "{t}");
        }
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
        context(&mut recs, false, &|_| false);
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
        context(&mut recs, false, &|_| false);
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
        context(&mut recs, false, &|_| false);
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
        context(&mut recs, true, &|_| false);
        assert!(recs[0].skip, "paired: left out");
        let mut recs = build();
        context(&mut recs, false, &|_| false);
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
        context(&mut recs, true, &|_| false);
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
        context(&mut recs, true, &|_| false);
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
            index: 0,
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

/// The refinement of 2026-10-15 (statistics builds, cases 1 and 2): each
/// condition on its excluded and its reported side, and the measured
/// fixtures of each matrix image.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod statistics_tests {
    use super::tests::{names, rec, who};
    use super::*;

    const BUILD: &str = "SELECT StatMan([SC0]) FROM (SELECT TOP 100 PERCENT [nsid] AS [SC0] FROM \
        [sys].[sysschobjs] WITH (READUNCOMMITTED)  ORDER BY [SC0] ) AS _MS_UPDSTATS_TBL  OPTION (MAXDOP 16)";
    const USER_BUILD: &str = "SELECT StatMan([SC0]) FROM (SELECT TOP 100 PERCENT [v] AS [SC0] FROM \
        [crm].[t] WITH (READUNCOMMITTED)  ORDER BY [SC0] ) AS _MS_UPDSTATS_TBL  OPTION (MAXDOP 16)";
    const GUID: &str = "B84042D7-4A61-4898-A945-0C2CF29E7FDA";

    /// An `sp_statement_completed` of `login` in activity (`guid`, `seq`).
    fn sp(
        login: &str,
        text: &str,
        guid: Option<&str>,
        seq: u64,
        shape: (i64, &str, i64, i64),
    ) -> XeRecord {
        let (nest, otype, off, end) = shape;
        let mut a: Vec<(&str, String)> = who(login, "56");
        if let Some(g) = guid {
            a.push(("attach_activity_id", format!("{g}-{seq}")));
        }
        let actions: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let nest = nest.to_string();
        let off = off.to_string();
        let end = end.to_string();
        let x = format!(
            "<event name=\"sp_statement_completed\"><data name=\"object_type\"><value>{}</value><text>{otype}</text></data>\
             <data name=\"nest_level\"><value>{nest}</value></data><data name=\"offset\"><value>{off}</value></data>\
             <data name=\"offset_end\"><value>{end}</value></data><data name=\"statement\"><value>{}</value></data>{}</event>",
            if otype == "ADHOC" { 20_801 } else { 8272 },
            text.replace('&', "&amp;").replace('<', "&lt;"),
            actions
                .iter()
                .map(|(k, v)| format!("<action name=\"{k}\"><value>{v}</value></action>"))
                .collect::<String>()
        );
        let mut r = rec("sp_statement_completed", &[], &[]);
        r.event = Some(xml::parse(&x).unwrap());
        r
    }

    const INTERNAL: (i64, &str, i64, i64) = (2, "ADHOC", 0, 0);
    const BUILD_SHAPE: (i64, &str, i64, i64) = (3, "ADHOC", 0, 342);

    /// A statement of `login` in activity (`guid`, `seq`).
    fn stmt_in(login: &str, text: &str, guid: Option<&str>, seq: u64) -> XeRecord {
        let mut a: Vec<(&str, String)> = who(login, "56");
        if let Some(g) = guid {
            a.push(("attach_activity_id", format!("{g}-{seq}")));
        }
        let actions: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let t = text.replace('&', "&amp;").replace('<', "&lt;");
        rec(
            "sql_statement_completed",
            &[("row_count", "1"), ("statement", &t)],
            &actions,
        )
    }

    fn own(r: &XeRecord) -> bool {
        r.login() == "databastion"
    }

    fn catalog() -> String {
        crate::sql::tables("retail", 16_384).unwrap()
    }

    fn reported(recs: &[XeRecord]) -> Vec<usize> {
        recs.iter()
            .enumerate()
            .filter(|(_, r)| convert(r).is_some())
            .map(|(i, _)| i)
            .collect()
    }

    /// Case 2: a build on a measured base table in the agent's own session,
    /// in the activity of one of its exact catalog texts.
    fn own_build(guid: Option<&str>) -> Vec<XeRecord> {
        vec![
            sp("databastion", BUILD, guid, 1, BUILD_SHAPE),
            sp("databastion", "", guid, 2, INTERNAL),
            stmt_in("databastion", &catalog(), guid, 3),
        ]
    }

    #[test]
    fn case_2_needs_every_condition() {
        // Excluded: the build and its internal statement; the catalog read
        // is the agent's own by its exact text (the stream's own rule).
        let mut recs = own_build(Some(GUID));
        assert_eq!(context(&mut recs, true, &own), 2);
        assert!(recs[0].skip && recs[1].skip && !recs[2].skip);
        // Reported: no causality, a build not allow-listed, not the
        // agent's session, no exact catalog text in the activity, another
        // activity, a table off the list, a credential table.
        let mut recs = own_build(None);
        context(&mut recs, true, &own);
        assert!(!recs[0].skip && !recs[1].skip, "no causality");
        let mut recs = own_build(Some(GUID));
        context(&mut recs, false, &own);
        assert!(!recs[0].skip, "not an allow-listed build");
        let mut recs = own_build(Some(GUID));
        context(&mut recs, true, &|_| false);
        assert!(!recs[0].skip, "not the agent's session");
        let mut recs = own_build(Some(GUID));
        recs[2] = stmt_in("databastion", "SELECT name FROM sys.objects", Some(GUID), 3);
        context(&mut recs, true, &own);
        assert!(!recs[0].skip, "no exact catalog text");
        // One of the agent's exact texts that is not a catalog read.
        for text in [
            crate::sql::VERSION.to_owned(),
            crate::conn::SESSION_SETTINGS.to_owned(),
            crate::sql::render(crate::sql::XE_EVENTS, &[("session", "N'databastion_xe'")]).unwrap(),
        ] {
            assert_eq!(
                crate::sql::own_text(&text),
                crate::sql::OwnText::Exact,
                "{text}"
            );
            let mut recs = own_build(Some(GUID));
            recs[2] = stmt_in("databastion", &text, Some(GUID), 3);
            context(&mut recs, true, &own);
            assert!(!recs[0].skip, "not a catalog read: {text}");
        }
        let mut recs = own_build(Some(GUID));
        recs[2] = stmt_in(
            "databastion",
            &catalog(),
            Some("AAAAAAAA-0000-0000-0000-000000000000"),
            3,
        );
        context(&mut recs, true, &own);
        assert!(!recs[0].skip, "the catalog text in another activity");
        for table in [
            "[sys].[sysowners]",
            "[sys].[sysxlgns]",
            "[sys].[sysfiles1]",
            "[dbo].[sysschobjs]",
        ] {
            let mut recs = own_build(Some(GUID));
            recs[0] = sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", table),
                Some(GUID),
                1,
                BUILD_SHAPE,
            );
            context(&mut recs, true, &own);
            assert!(!recs[0].skip, "{table}");
            assert_eq!(reported(&recs), [0, 1, 2], "{table}");
        }
    }

    #[test]
    fn case_1_needs_every_condition() {
        // A user's build, paired by item 4 with the user's read.
        let build = |shape: (i64, &str, i64, i64), guid: Option<&str>, seq_internal: u64| {
            vec![
                sp("app", "", guid, seq_internal, shape),
                sp("app", USER_BUILD, guid, 1, BUILD_SHAPE),
                stmt_in("app", "SELECT TOP (5) id FROM crm.t WHERE v = 3", guid, 9),
            ]
        };
        // Excluded (before the build in file order, as measured).
        let mut recs = build(INTERNAL, Some(GUID), 2);
        assert_eq!(context(&mut recs, true, &|_| false), 2);
        assert_eq!(reported(&recs), [2]);
        // Reported: no causality (no session-order fallback), another
        // activity, not contiguous, another shape, not allow-listed.
        let mut recs = build(INTERNAL, None, 2);
        context(&mut recs, true, &|_| false);
        assert_eq!(reported(&recs), [0, 2], "no causality");
        let mut recs = build(INTERNAL, Some(GUID), 3);
        context(&mut recs, true, &|_| false);
        assert_eq!(reported(&recs), [0, 2], "not contiguous");
        for shape in [
            (1, "ADHOC", 0, 0),
            (2, "PROC", 0, 0),
            (2, "ADHOC", 4, 0),
            (2, "ADHOC", 0, -1),
        ] {
            let mut recs = build(shape, Some(GUID), 2);
            context(&mut recs, true, &|_| false);
            assert_eq!(reported(&recs), [0, 2], "{shape:?}");
        }
        let mut recs = build(INTERNAL, Some(GUID), 2);
        recs[0] = sp("app", "SELECT 1 FROM crm.t", Some(GUID), 2, INTERNAL);
        context(&mut recs, true, &|_| false);
        assert!(!recs[0].skip, "a text: not an internal statement");
        let mut recs = build(INTERNAL, Some(GUID), 2);
        context(&mut recs, false, &|_| false);
        assert_eq!(reported(&recs), [0, 1, 2], "not an allow-listed build");
        // Another activity's internal statement with the next sequence.
        let mut recs = build(INTERNAL, Some(GUID), 2);
        recs[0] = sp(
            "app",
            "",
            Some("AAAAAAAA-0000-0000-0000-000000000000"),
            2,
            INTERNAL,
        );
        context(&mut recs, true, &|_| false);
        assert!(!recs[0].skip);
        // At most 3.
        let mut recs: Vec<XeRecord> = (2..=5)
            .map(|s| sp("app", "", Some(GUID), s, INTERNAL))
            .collect();
        recs.push(sp("app", USER_BUILD, Some(GUID), 1, BUILD_SHAPE));
        recs.push(stmt_in(
            "app",
            "SELECT TOP (5) id FROM crm.t WHERE v = 3",
            Some(GUID),
            9,
        ));
        assert_eq!(context(&mut recs, true, &|_| false), 4);
        assert!(recs[0].skip && recs[1].skip && recs[2].skip && !recs[3].skip);
    }

    /// Reads a fixture: one event per line, captured on the image.
    fn fixture(name: &str) -> Vec<XeRecord> {
        let text =
            std::fs::read_to_string(format!("{}/fixtures/xe/{name}", env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        text.lines()
            .filter(|l| l.trim_start().starts_with("<event"))
            .enumerate()
            .map(|(i, l)| {
                let e = xml::parse(l.trim()).unwrap();
                XeRecord {
                    file: "/x/s_0_1.xel".to_owned(),
                    offset: 4096,
                    time_us: i64::try_from(i).unwrap(),
                    name: e.name.clone(),
                    event: Some(e),
                    procedure: None,
                    skip: false,
                    unreadable: false,
                    index: 0,
                }
            })
            .collect()
    }

    /// The drift fixtures, one per matrix image (captured on 2026-10-16:
    /// the agent's own builds on a fresh server, and a client's first reads
    /// of two columns, in a batch, build at nest level 2, and inside
    /// `sp_executesql` called by a batch, deeper: 4 on 2022): every build
    /// is left out
    /// (item 4 or case 2), and every internal statement with it, at the
    /// build's nest level minus one (case 1 as revised on 2026-10-16).
    #[test]
    fn fixtures_of_the_matrix_images() {
        for file in [
            "statistics-15.0.4500.2.xml",
            "statistics-16.0.4305.5.xml",
            "statistics-17.0.5015.4.xml",
        ] {
            let mut recs = fixture(file);
            let is_build = |r: &XeRecord| {
                r.event
                    .as_ref()
                    .and_then(|e| e.statement.as_deref())
                    .is_some_and(|t| t.contains("StatMan"))
            };
            let builds = recs.iter().filter(|r| is_build(r)).count();
            let internals = recs
                .iter()
                .filter(|r| {
                    r.kind() == Kind::SpStatementCompleted
                        && r.event
                            .as_ref()
                            .and_then(|e| e.statement.as_deref())
                            .is_some_and(|t| t.is_empty())
                })
                .count();
            assert_eq!(context(&mut recs, true, &own), builds + internals, "{file}");
            let mut depths = std::collections::BTreeSet::new();
            for (i, r) in recs.iter().enumerate() {
                let e = r.event.as_ref().unwrap();
                let login = r.login();
                if is_build(r) {
                    assert!(r.skip, "{file} {i} {login}: a build is left out");
                    if login == "it_xstats" {
                        depths.extend(e.nest_level);
                    }
                } else if e.statement.as_deref().is_some_and(|t| t.is_empty()) {
                    let under = recs.iter().find(|b| {
                        b.event.as_ref().is_some_and(|be| {
                            matches!((&be.activity, &e.activity),
                                (Some((g, s)), Some((h, t))) if g == h && s + 1 == *t)
                        })
                    });
                    let nest = under
                        .and_then(|b| b.event.as_ref())
                        .and_then(|b| b.nest_level);
                    assert_eq!(e.nest_level.zip(nest).map(|(a, b)| a + 1 == b), Some(true));
                    assert!(
                        r.skip,
                        "{file} {i} {login}: an internal statement is left out"
                    );
                } else {
                    assert!(!r.skip, "{file} {i} {login}: a client's statement stays");
                }
            }
            assert!(
                depths.contains(&2) && depths.iter().any(|d| *d >= 3),
                "{file}: a client's builds in a batch and inside sp_executesql: {depths:?}"
            );
            assert!(
                recs.iter().any(|r| r.login() == "databastion" && r.skip),
                "{file}"
            );
        }
    }

    /// Case 1, condition 4 as revised on 2026-10-16: the build's nest
    /// level minus one, the build at nest level 2 or more.
    #[test]
    fn case_1_internal_at_the_build_nest_level_minus_one() {
        let at = |build: i64, internal: i64| {
            let mut recs = vec![
                sp("app", USER_BUILD, Some(GUID), 1, (build, "ADHOC", 0, 342)),
                sp("app", "", Some(GUID), 2, (internal, "ADHOC", 0, 0)),
                stmt_in(
                    "app",
                    "SELECT TOP (5) id FROM crm.t WHERE v = 3",
                    Some(GUID),
                    9,
                ),
            ];
            context(&mut recs, true, &|_| false);
            recs[1].skip
        };
        // A client's first read in a batch (build at 2), inside
        // `sp_executesql` or a procedure (3), deeper nesting.
        assert!(at(2, 1));
        assert!(at(3, 2));
        assert!(at(4, 3));
        // Any other depth is reported.
        for (build, internal) in [(2, 2), (3, 1), (3, 3), (1, 0), (2, 0), (0, -1)] {
            assert!(!at(build, internal), "build {build}, internal {internal}");
        }
    }

    /// Refinement of 2026-10-16, item 3: the credential-bearing base tables
    /// stay off the list, and their builds stay reported, even with every
    /// other condition of case 2 met.
    #[test]
    fn credential_tables_stay_off_the_list() {
        for table in ["sysowners", "sysxlgns"] {
            assert!(!SYS_BASE_TABLES.contains(&table), "{table}");
            let mut recs = own_build(Some(GUID));
            recs[0] = sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", &format!("[sys].[{table}]")),
                Some(GUID),
                1,
                BUILD_SHAPE,
            );
            context(&mut recs, true, &own);
            assert!(!recs[0].skip, "{table}");
            let ev = convert(&recs[0]).unwrap().0;
            assert_eq!(names(&ev), [format!("retail.sys.{table}")], "{table}");
        }
    }

    /// A build on `sys.sysguidrefs` (in `master`), of the shape measured on
    /// 2022 and 2025 after the `audit_file` proof.
    const GUIDREFS_BUILD: &str = "SELECT StatMan([SC0]) FROM (SELECT TOP 100 PERCENT [class] AS [SC0] FROM \
        [sys].[sysguidrefs] WITH (READUNCOMMITTED)  ORDER BY [SC0] ) AS _MS_UPDSTATS_TBL  OPTION (MAXDOP 16)";
    const GUIDREFS_SHAPE: (i64, &str, i64, i64) = (2, "ADHOC", 0, 344);

    /// The `audit_file` proof of decision 6 (one of case 2's catalog
    /// reads), as the agent renders it.
    fn audit_file() -> String {
        let name = crate::sql::quote_literal("databastion_audit").unwrap();
        crate::sql::render(crate::sql::AUDIT_FILE, &[("audit", &name)]).unwrap()
    }

    /// A build on `sysguidrefs` (`build_login`), its internal statement
    /// (at the build's nest level minus one), and a partner statement
    /// (`partner_login`, `partner`) in activity `guid`: build, internal,
    /// partner in file order, or the partner first when `partner_first`.
    fn guidrefs(
        build_login: &str,
        partner_login: &str,
        partner: &str,
        guid: Option<&str>,
        partner_first: bool,
    ) -> Vec<XeRecord> {
        let mut recs = vec![
            sp(build_login, GUIDREFS_BUILD, guid, 2, GUIDREFS_SHAPE),
            sp(build_login, "", guid, 3, (1, "ADHOC", 0, 0)),
        ];
        let p = stmt_in(partner_login, partner, guid, 1);
        if partner_first {
            recs.insert(0, p);
        } else {
            recs.push(p);
        }
        recs
    }

    fn statement(r: &XeRecord) -> Option<&str> {
        r.event
            .as_ref()
            .and_then(|e| e.statement.as_deref())
            .map(|s| s.as_str())
    }

    /// ADR-0051, addendum of 2026-10-16 to the refinement of that day:
    /// `sys.sysguidrefs` is on case 2's closed list, paired with the
    /// `audit_file` proof, every other condition of case 2 unchanged.
    #[test]
    fn sysguidrefs_build_paired_with_the_audit_file_proof() {
        assert!(SYS_BASE_TABLES.contains(&"sysguidrefs"));
        assert!(crate::sql::catalog_text(&audit_file()));
        // Left out with its internal statement, whichever comes first in
        // the file; the proof itself is not touched by case 2.
        for first in [false, true] {
            let mut recs = guidrefs(
                "databastion",
                "databastion",
                &audit_file(),
                Some(GUID),
                first,
            );
            assert_eq!(context(&mut recs, true, &own), 2, "partner first {first}");
            for r in &recs {
                let is_proof = statement(r) == Some(audit_file().as_str());
                assert_eq!(r.skip, !is_proof, "partner first {first}");
            }
        }
        // Another quoted audit name renders the same template.
        let name = crate::sql::quote_literal("Audit 'x'").unwrap();
        let other = crate::sql::render(crate::sql::AUDIT_FILE, &[("audit", &name)]).unwrap();
        assert!(crate::sql::catalog_text(&other));
        let mut recs = guidrefs("databastion", "databastion", &other, Some(GUID), false);
        assert_eq!(context(&mut recs, true, &own), 2);

        // Reported: no causality (no session-order fallback).
        let mut recs = guidrefs("databastion", "databastion", &audit_file(), None, false);
        assert_eq!(context(&mut recs, true, &own), 0);
        assert_eq!(reported(&recs), [0, 1, 2], "no causality");
        // Reported: a foreign session's build with the agent's proof in the
        // same activity, and the agent's build with the proof's text sent
        // by a foreign session.
        for (build, partner) in [("app", "databastion"), ("databastion", "app")] {
            let mut recs = guidrefs(build, partner, &audit_file(), Some(GUID), false);
            context(&mut recs, true, &own);
            assert!(
                !recs[0].skip && !recs[1].skip,
                "build {build}, partner {partner}"
            );
            let ev = convert(&recs[0]).unwrap().0;
            assert_eq!(names(&ev), ["retail.sys.sysguidrefs"], "build {build}");
        }
        let mut recs = guidrefs(
            "databastion",
            "databastion",
            &audit_file(),
            Some(GUID),
            false,
        );
        context(&mut recs, true, &|_| false);
        assert!(!recs[0].skip, "no own session at all");
        // Reported: a partner that is not one of the catalog reads: the
        // agent's own exact texts that are not (the version, the session
        // settings, the DMV proof, the SQL Server Audit poll), a near-copy
        // of the proof, and a client's read of the same view.
        for text in [
            crate::sql::VERSION.to_owned(),
            crate::conn::SESSION_SETTINGS.to_owned(),
            crate::sql::render(crate::sql::XE_EVENTS, &[("session", "N'databastion_xe'")]).unwrap(),
            crate::sql::AUDIT_POLL_START.to_owned(),
            audit_file().replace("TOP (2)", "TOP (3)"),
            "SELECT name FROM sys.server_file_audits".to_owned(),
        ] {
            assert!(!crate::sql::catalog_text(&text), "{text}");
            let mut recs = guidrefs("databastion", "databastion", &text, Some(GUID), false);
            context(&mut recs, true, &own);
            assert!(!recs[0].skip && !recs[1].skip, "not a catalog read: {text}");
        }
        // Reported: the proof in another activity.
        let mut recs = guidrefs(
            "databastion",
            "databastion",
            &audit_file(),
            Some(GUID),
            false,
        );
        recs[2] = stmt_in(
            "databastion",
            &audit_file(),
            Some("AAAAAAAA-0000-0000-0000-000000000000"),
            1,
        );
        context(&mut recs, true, &own);
        assert!(!recs[0].skip, "the proof in another activity");
        // Reported: a build that is not allow-listed.
        let mut recs = guidrefs(
            "databastion",
            "databastion",
            &audit_file(),
            Some(GUID),
            false,
        );
        assert_eq!(context(&mut recs, false, &own), 0);
        assert_eq!(reported(&recs), [0, 1, 2], "not an allow-listed build");
        assert!(!unpaired_case_2(&recs[0], false, &own));
        // Unpaired in its read, the agent's build is a deferral candidate
        // (item 4) like any listed table; a foreign session's is not.
        let mut recs = guidrefs(
            "databastion",
            "databastion",
            crate::sql::VERSION,
            Some(GUID),
            false,
        );
        context(&mut recs, true, &own);
        assert!(unpaired_case_2(&recs[0], true, &own));
        assert!(!unpaired_case_2(&recs[0], true, &|_| false));
        // Only `sys.sysguidrefs` by its exact name.
        for table in [
            "[sys].[sysguidrefs2]",
            "[sys].[sysguidref]",
            "[dbo].[sysguidrefs]",
        ] {
            let mut recs = guidrefs(
                "databastion",
                "databastion",
                &audit_file(),
                Some(GUID),
                false,
            );
            recs[0] = sp(
                "databastion",
                &GUIDREFS_BUILD.replace("[sys].[sysguidrefs]", table),
                Some(GUID),
                2,
                GUIDREFS_SHAPE,
            );
            context(&mut recs, true, &own);
            assert!(!recs[0].skip, "{table}");
        }
    }

    /// The `audit_file` proof's builds on a fresh server, one fixture per
    /// image with a SQL Server Audit source (captured on 2026-10-16 from a
    /// new data volume by the fresh-server integration test; 2019 has no
    /// such proof, so no build on `sysguidrefs`): builds on `sysguidrefs`
    /// at nest level 1 (several columns, no internal statement) and 2 (one
    /// column, an internal statement at 1), and on `sysobjvalues`, all in
    /// the proof's activity, all left out with their internal statements;
    /// the proof itself is not touched. Each is reported without
    /// causality, from a foreign session, or off the allow-listed builds.
    #[test]
    fn sysguidrefs_fixtures_of_the_audit_images() {
        for file in ["sysguidrefs-16.0.4305.5.xml", "sysguidrefs-17.0.5015.4.xml"] {
            let recs = fixture(file);
            let is_build = |r: &XeRecord| statement(r).is_some_and(|t| t.contains("StatMan"));
            let guidrefs = recs
                .iter()
                .filter(|r| statement(r).is_some_and(|t| t.contains("[sys].[sysguidrefs]")))
                .count();
            assert!(guidrefs >= 2, "{file}");
            let depths: std::collections::BTreeSet<i64> = recs
                .iter()
                .filter(|r| is_build(r))
                .filter_map(|r| r.event.as_ref().and_then(|e| e.nest_level))
                .collect();
            assert!(
                depths.contains(&1) && depths.contains(&2),
                "{file}: {depths:?}"
            );
            let proofs = recs
                .iter()
                .filter(|r| statement(r).is_some_and(crate::sql::catalog_text))
                .count();
            assert_eq!(proofs, 1, "{file}: the audit_file proof");
            let mut left = fixture(file);
            assert_eq!(context(&mut left, true, &own), recs.len() - 1, "{file}");
            for r in &left {
                assert_eq!(
                    r.skip,
                    !statement(r).is_some_and(crate::sql::catalog_text),
                    "{file}"
                );
            }
            // Reported: not an allow-listed build, a foreign session, no
            // causality.
            let mut off = fixture(file);
            assert_eq!(context(&mut off, false, &own), 0, "{file}");
            let mut foreign = fixture(file);
            assert_eq!(context(&mut foreign, true, &|_| false), 0, "{file}");
            let mut no_causality = fixture(file);
            for r in &mut no_causality {
                if let Some(e) = r.event.as_mut() {
                    e.activity = None;
                }
            }
            assert_eq!(context(&mut no_causality, true, &own), 0, "{file}");
            for r in off.iter().chain(&foreign).chain(&no_causality) {
                assert!(!r.skip, "{file}");
            }
        }
    }

    /// The credential-bearing tables stay reported next to a `sysguidrefs`
    /// build left out in the same activity (item 3, unchanged by the
    /// addendum).
    #[test]
    fn credential_tables_stay_reported_next_to_sysguidrefs() {
        for table in ["sysowners", "sysxlgns"] {
            let mut recs = guidrefs(
                "databastion",
                "databastion",
                &audit_file(),
                Some(GUID),
                false,
            );
            recs.push(sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", &format!("[sys].[{table}]")),
                Some(GUID),
                5,
                BUILD_SHAPE,
            ));
            context(&mut recs, true, &own);
            assert!(recs[0].skip && recs[1].skip && !recs[3].skip, "{table}");
            assert_eq!(reported(&recs), [2, 3], "{table}");
            let ev = convert(&recs[3]).unwrap().0;
            assert_eq!(names(&ev), [format!("retail.sys.{table}")], "{table}");
        }
    }

    /// One row of a simulated event file: its buffer offset and what it is.
    #[derive(Clone, Copy)]
    enum Row {
        /// A client's statement (its id).
        Client(i64),
        Build,
        Internal,
        /// The agent's catalog read of the build's activity (its pair).
        Catalog,
        /// A row the reader cannot read (dropped and counted).
        Malformed,
    }

    /// Reads a simulated file through deferrals: `schedule` gives, per
    /// read, the rows written so far and the rows asked. Returns the
    /// events handled (time, left out) and the malformed rows met.
    fn walk(rows: &[(i64, Row)], schedule: &[(usize, usize)]) -> (Vec<(i64, bool)>, usize) {
        use crate::audit::Cursor;
        use crate::audit::xe::xe_next;
        let make = |offset: i64, row: Row| {
            let mut r = match row {
                Row::Client(id) => {
                    let mut r = stmt_in("app", "SELECT TOP (1) id FROM crm.t", None, 0);
                    r.time_us = id;
                    r
                }
                Row::Build => {
                    let mut r = sp("databastion", BUILD, Some(GUID), 1, BUILD_SHAPE);
                    r.time_us = 101;
                    r
                }
                Row::Internal => {
                    let mut r = sp("databastion", "", Some(GUID), 2, INTERNAL);
                    r.time_us = 102;
                    r
                }
                Row::Catalog | Row::Malformed => {
                    let mut r = stmt_in("databastion", &catalog(), Some(GUID), 3);
                    r.time_us = 103;
                    r
                }
            };
            r.file = "f".to_owned();
            r.offset = offset;
            r
        };
        let mut deferrals = Deferrals::default();
        let mut cursor = Cursor::default();
        let mut handled = Vec::new();
        let mut malformed = 0;
        let t0 = Instant::now();
        for (read, &(written, asked)) in schedule.iter().enumerate() {
            // The server: after the buffer at the position, skip rows, then
            // at most `asked` rows; the reader drops the malformed ones.
            let start = rows
                .iter()
                .take(written)
                .position(|(o, _)| cursor.file.is_none() || *o > cursor.offset)
                .unwrap_or(written);
            let served: Vec<(i64, Row)> = rows
                .iter()
                .take(written)
                .skip(start + cursor.skip as usize)
                .take(asked)
                .copied()
                .collect();
            let returned = served.len();
            let mut recs = Vec::new();
            for (o, row) in served {
                if matches!(row, Row::Malformed) {
                    malformed += 1;
                    continue;
                }
                let mut r = make(o, row);
                r.index = recs.len();
                recs.push(r);
            }
            let positions: Vec<(String, i64)> =
                recs.iter().map(|r| (r.file.clone(), r.offset)).collect();
            context(&mut recs, true, &own);
            let now = t0 + Duration::from_secs(u64::try_from(read).unwrap());
            let cut = deferrals.cut(&recs, true, &own, now, Duration::from_secs(5));
            let (next, gap) = match cut {
                Some(i) => {
                    recs.retain(|r| r.index < i);
                    for r in &mut recs {
                        r.skip = false;
                    }
                    context(&mut recs, true, &own);
                    xe_next(&cursor, &positions[..i], true)
                }
                None => xe_next(&cursor, &positions, returned >= asked),
            };
            assert!(!gap);
            handled.extend(recs.iter().map(|r| (r.time_us, r.skip)));
            cursor = next;
        }
        (handled, malformed)
    }

    /// Refinement of 2026-10-16, item 4: a read whose own-session build on
    /// a listed table is not paired yet ends just before it; the next read
    /// starts at it and pairs it. Every event is handled once: none twice,
    /// none lost.
    #[test]
    fn a_deferred_build_is_paired_by_the_next_read_without_duplicate_or_drop() {
        use Row::{Build, Catalog, Client, Internal, Malformed};
        let want = |clients: &[i64]| {
            let mut v: Vec<(i64, bool)> = clients.iter().map(|c| (*c, false)).collect();
            v.extend([(101, true), (102, true), (103, false)]);
            v
        };
        // Buffer 4096: a client's read, the agent's build and its internal
        // statement; buffer 8192, written only after the first read: the
        // agent's catalog read of the same activity (the build's pair).
        let rows = [
            (4096, Client(0)),
            (4096, Build),
            (4096, Internal),
            (8192, Catalog),
        ];
        let (handled, _) = walk(&rows, &[(3, 500), (4, 500), (4, 500)]);
        assert_eq!(handled, want(&[0]), "no duplicate, no drop");

        // The cut buffer's first events were handled by an earlier full
        // read (`cursor.skip > 0`): the cut adds to the skip count.
        let rows = [
            (4096, Client(0)),
            (4096, Client(1)),
            (4096, Client(2)),
            (4096, Build),
            (4096, Internal),
            (8192, Catalog),
        ];
        let (handled, _) = walk(&rows, &[(5, 2), (5, 500), (6, 500), (6, 500)]);
        assert_eq!(handled, want(&[0, 1, 2]), "no duplicate, no drop");

        // A malformed row in the cut buffer, after the client's event: the
        // skip counts the events read, not the rows, so the next read
        // meets the malformed row again (dropped and counted twice), and
        // no event is lost or handled twice.
        let rows = [
            (4096, Client(0)),
            (4096, Malformed),
            (4096, Build),
            (4096, Internal),
            (8192, Catalog),
        ];
        let (handled, malformed) = walk(&rows, &[(4, 500), (5, 500), (5, 500)]);
        assert_eq!(handled, want(&[0]), "no drop");
        assert_eq!(malformed, 2, "the malformed row is met again (bounded)");

        // Before the client's event: the next read starts one row early,
        // so that event is handled twice (bounded: one per malformed row
        // before the cut in the cut buffer, each counted as dropped);
        // nothing is lost.
        let rows = [
            (4096, Malformed),
            (4096, Client(0)),
            (4096, Build),
            (4096, Internal),
            (8192, Catalog),
        ];
        let (handled, malformed) = walk(&rows, &[(4, 500), (5, 500), (5, 500)]);
        let mut twice = want(&[0]);
        twice.insert(1, (0, false));
        assert_eq!(handled, twice, "a bounded duplicate, no drop");
        assert_eq!(malformed, 1);
    }

    /// A build still unpaired after its bound is handled as it stands
    /// (reported); one deferral per build; never for another session's
    /// record; nothing on a build off the allow-list.
    #[test]
    fn deferrals_are_bounded_and_for_the_agents_builds_only() {
        let lone = || {
            let mut r = sp("databastion", BUILD, Some(GUID), 1, BUILD_SHAPE);
            r.index = 7;
            vec![r]
        };
        let t0 = Instant::now();
        let bound = Duration::from_secs(5);
        let mut d = Deferrals::default();
        let mut recs = lone();
        context(&mut recs, true, &own);
        assert_eq!(d.cut(&recs, true, &own, t0, bound), Some(7));
        assert_eq!(
            d.cut(&recs, true, &own, t0 + Duration::from_secs(4), bound),
            Some(7),
            "within its bound"
        );
        assert_eq!(
            d.cut(&recs, true, &own, t0 + Duration::from_secs(5), bound),
            None,
            "after its bound: reported"
        );
        assert_eq!(reported(&recs), [0]);
        assert_eq!(
            d.cut(&recs, true, &own, t0 + Duration::from_secs(6), bound),
            None,
            "one deferral per build"
        );
        // Capped at 60 s whatever the bound.
        let mut d = Deferrals::default();
        assert!(
            d.cut(&recs, true, &own, t0, Duration::from_secs(3600))
                .is_some()
        );
        assert!(
            d.cut(
                &recs,
                true,
                &own,
                t0 + Duration::from_secs(60),
                Duration::from_secs(3600)
            )
            .is_none()
        );
        // Another session's build, a client's build, no causality, a table
        // off the list, a credential table, not allow-listed: no deferral.
        let mut d = Deferrals::default();
        assert_eq!(
            d.cut(&recs, true, &|_| false, t0, bound),
            None,
            "a foreign session"
        );
        let mut user = lone();
        user[0] = sp("databastion", USER_BUILD, Some(GUID), 1, BUILD_SHAPE);
        assert_eq!(d.cut(&user, true, &own, t0, bound), None, "a user table");
        let mut nocause = lone();
        nocause[0] = sp("databastion", BUILD, None, 1, BUILD_SHAPE);
        assert_eq!(d.cut(&nocause, true, &own, t0, bound), None, "no causality");
        for table in ["[sys].[sysowners]", "[sys].[sysfiles1]"] {
            let mut off = lone();
            off[0] = sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", table),
                Some(GUID),
                1,
                BUILD_SHAPE,
            );
            assert_eq!(d.cut(&off, true, &own, t0, bound), None, "{table}");
        }
        assert_eq!(
            d.cut(&recs, false, &own, t0, bound),
            None,
            "not allow-listed"
        );
        // A paired build is not deferred.
        let mut paired = own_build(Some(GUID));
        context(&mut paired, true, &own);
        assert_eq!(d.cut(&paired, true, &own, t0, bound), None);
    }
}
