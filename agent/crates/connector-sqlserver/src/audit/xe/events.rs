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
//!   four-part name, remote access), or when it names more objects than
//!   an event holds ([`crate::audit::objects`]), the event names `*` and is
//!   always reported; a name that normalization masks (`*`) stays a name.
//!   DDL and DCL keep their kind, never text: `*`, always reported
//!   (`CREATE` / `ALTER` / `DROP` of a principal or credential is DCL, as
//!   the principal classes of SQL Server Audit). A
//!   password-bearing statement (its text is never read past its class,
//!   the #82 rule; Extended Events records some as a comment,
//!   `-- CREATE LOGIN`, `-- ALTER LOGIN`, measured) is DCL, `*`, always
//!   reported.
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
use databastion_classifiers::names::fold_case;
use databastion_classifiers::query::tsql::{self, TsqlAnalysis, TsqlKind};
use zeroize::Zeroizing;

use super::xml::{self, Kind, XeEvent};
use crate::audit::Positioned;
use crate::audit::objects::Objects;
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

    /// An `error_reported` of error 18456 (a failed login): read, it
    /// proves that the session's `error_reported` admits failed logins.
    pub(crate) fn is_failed_login_18456(&self) -> bool {
        self.kind() == Kind::ErrorReported
            && self.event.as_ref().and_then(|e| e.error_number) == Some(18_456)
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
                Zeroizing::new(fold_case(rel.database.as_deref().unwrap_or(&db))),
                Zeroizing::new(fold_case(rel.schema.as_deref().unwrap_or_default())),
                Zeroizing::new(fold_case(&rel.name)),
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
            Zeroizing::new(fold_case(e.database.as_deref().unwrap_or_default())),
            Zeroizing::new(fold_case(&schema)),
            Zeroizing::new(fold_case(&table)),
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

/// A build that item 4 or case 2 could leave out but that its read left
/// unpaired, deferred across reads (refinement of 2026-10-18, case 1
/// builds, extending item 4 of the refinement of 2026-10-16): an
/// `sp_statement_completed` statistics build, not left out, complete, with
/// causality (the deferral's key; a build without it is never deferred),
/// on an allow-listed build (`statman`), from any session. Whether it is
/// left out after the deferral is decided by [`context`] as in one read:
/// the pairing rules are unchanged.
pub(crate) fn unpaired_build(r: &XeRecord, statman: bool) -> bool {
    if !statman || r.skip || r.kind() != Kind::SpStatementCompleted {
        return false;
    }
    let Some(e) = &r.event else { return false };
    !e.statement_cut
        && e.activity.is_some()
        && e.statement
            .as_deref()
            .and_then(|t| tsql::statman_table(t))
            .is_some()
}

/// A build that case 2 could leave out but that its read left unpaired
/// (refinement of 2026-10-16, item 4): [`unpaired_build`] on a listed
/// system base table, from one of the agent's own sessions (`own`).
#[cfg(test)]
pub(crate) fn unpaired_case_2(
    r: &XeRecord,
    statman: bool,
    own: &dyn Fn(&XeRecord) -> bool,
) -> bool {
    if !unpaired_build(r, statman) {
        return false;
    }
    let Some((schema, table)) = r
        .event
        .as_ref()
        .and_then(|e| e.statement.as_deref())
        .and_then(|t| tsql::statman_table(t))
    else {
        return false;
    };
    schema.eq_ignore_ascii_case("sys")
        && SYS_BASE_TABLES
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&table))
        && own(r)
}

/// The longest a build is deferred (refinement of 2026-10-16, item 4, and
/// of 2026-10-18), and the longest the stream is held behind deferrals in
/// a row.
pub(crate) const MAX_DEFERRAL: Duration = Duration::from_secs(60);
/// Builds remembered at most, case 1 and case 2 together (one memory
/// bound); beyond, no new deferral (reported).
const MAX_DEFERRED: usize = 4096;
/// A deferral is forgotten this long after its bound.
const DEFERRAL_KEEP: Duration = Duration::from_secs(600);

/// The deferrals of unpaired statistics builds across the reads of one
/// stream (refinement of 2026-10-16, item 4, for case 2 builds, and of
/// 2026-10-18 for any session's build), in memory only: a read that holds
/// one ends just before it (or before one of its internal statements that
/// comes earlier in file order), so that the next read, which starts
/// there, can pair it. The position never moves past a deferred build, so
/// an agent restart reads it again (deferred once more at most, never
/// lost). Two kinds of cut:
///
/// - **A full read** (more rows follow it on the server): a build in the
///   second half of the read, or within [`CONTEXT_WINDOW`] of its end, may
///   be unpaired only because its pair is in rows not fetched yet. The read
///   ends before it and the next read follows at once (no poll wait); this
///   is not a deferral (it uses none of the build's), and it moves the
///   position by at least half the read. A build earlier in the read is
///   handled as it stands, and so is one at the start of the read (its
///   window is the whole read).
/// - **A read that reached the end of the file** (not full): the pair may
///   not be written yet. The read ends before the first unpaired build,
///   once per build (by its causality activity and sequence number), for
///   at most its bound from when it was first seen, and the stream waits a
///   poll interval; after that, the build is handled as it stands
///   (reported when still unpaired).
///
/// **The hold is bounded per position**: from the first deferral, until a
/// read reaches the end of the file without a cut, the stream is held; once
/// it has been held for [`MAX_DEFERRAL`], nothing is deferred until it has
/// caught up (full reads follow at once). So an event that can be read is
/// handled within [`MAX_DEFERRAL`] plus one bound and one poll interval,
/// plus the time the stream needs to catch up (when the agent reads faster
/// than the server writes), whatever builds a client writes.
#[derive(Debug, Default)]
pub(crate) struct Deferrals {
    until: std::collections::HashMap<(String, u64), Instant>,
    /// When the stream started being held (`None`: the last read that
    /// reached the end of the file was not cut).
    held_since: Option<Instant>,
}

/// Where a read ends ([`Deferrals::cut`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cut {
    /// The index (in its read, [`XeRecord::index`]) before which it ends.
    pub(crate) at: usize,
    /// A deferral: the stream waits a poll interval before the next read
    /// (else the next read follows at once).
    pub(crate) wait: bool,
}

impl Deferrals {
    /// Where the read ends, if one of `records` (after [`context`], in
    /// index order) is a build to read again; `full` is the number of rows
    /// of the read (its index space) when more rows follow it.
    pub(crate) fn cut(
        &mut self,
        records: &[XeRecord],
        statman: bool,
        now: Instant,
        bound: Duration,
        full: Option<usize>,
    ) -> Option<Cut> {
        if let Some(len) = full {
            // At least half the read is handled: the position always moves.
            let from = (len / 2).max(len.saturating_sub(CONTEXT_WINDOW)).max(1);
            return records
                .iter()
                .filter(|r| unpaired_build(r, statman))
                .map(|r| cut_index(records, r))
                .find(|at| *at >= from)
                .map(|at| Cut { at, wait: false });
        }
        let bound = bound.min(MAX_DEFERRAL);
        self.until
            .retain(|_, until| now.saturating_duration_since(*until) <= DEFERRAL_KEEP);
        let at = self.find(records, statman, now, bound);
        if at.is_some() {
            self.held_since.get_or_insert(now);
        } else {
            self.held_since = None;
        }
        at.map(|at| Cut { at, wait: true })
    }

    fn find(
        &mut self,
        records: &[XeRecord],
        statman: bool,
        now: Instant,
        bound: Duration,
    ) -> Option<usize> {
        if self
            .held_since
            .is_some_and(|h| now.saturating_duration_since(h) >= MAX_DEFERRAL)
        {
            return None;
        }
        for r in records {
            if !unpaired_build(r, statman) {
                continue;
            }
            let Some(key) = r.event.as_ref().and_then(|e| e.activity.clone()) else {
                continue;
            };
            match self.until.get(&key) {
                Some(until) if now < *until => return Some(cut_index(records, r)),
                // Its deferral is over: handled as it stands.
                Some(_) => {}
                None if self.until.len() < MAX_DEFERRED && !bound.is_zero() => {
                    self.until.insert(key, now + bound);
                    return Some(cut_index(records, r));
                }
                None => {}
            }
        }
        None
    }
}

/// Where a read ends to defer `build`: just before it, or before the
/// first of its internal statements (case 1's shape, in its activity at
/// the sequence numbers that may follow it) that comes earlier in file
/// order (measured on 2022), so that the next read holds them together.
fn cut_index(records: &[XeRecord], build: &XeRecord) -> usize {
    let at = build.index;
    let Some(e) = &build.event else { return at };
    let Some((guid, seq)) = &e.activity else {
        return at;
    };
    records
        .iter()
        .take_while(|r| r.index < at)
        .find(|r| {
            !r.skip
                && r.event
                    .as_ref()
                    .and_then(|x| x.activity.as_ref())
                    .is_some_and(|(g, s)| {
                        g == guid && *s > *seq && *s <= seq.saturating_add(MAX_BUILD_INTERNALS)
                    })
                && build_internal(r, e.nest_level)
        })
        .map_or(at, |r| r.index)
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
/// `sysaudacts` (in `master`, a build on `audit_spec_id` at `nest_level`
/// 2 paired with the `audit_specifications` proof, measured on 2022)
/// joined it on 2026-10-18 (ADR-0051 note of that day, accepted by the
/// maintainer), under the same conditions.
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
    "sysaudacts",
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
        // (measured on 2019, and `-- ALTER LOGIN` on 2022): `-- CREATE
        // LOGIN`, `-- ALTER LOGIN`, `-- CREATE CREDENTIAL`,
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
    // A statement that names more objects than an event holds names `*`
    // and is always reported instead of losing some (the core's bound,
    // `MaskedEvent::with_object`; end-of-phase-9 review, gates G1 and G7).
    // A name normalized to `*` (a masked name, protocol "The object `*`")
    // stays a name, under the filters, as the same name on SQL Server
    // Audit.
    let mut objects = Objects::default();
    for rel in &a.relations {
        let rdb = rel.database.as_deref().or(db);
        objects.push(EventObject::new(
            db_name(rdb),
            rel.schema.as_deref().map(normalize),
            normalize(&rel.name),
        ));
    }
    if let Some(p) = &r.procedure {
        objects.push(EventObject::new(db_name(db), None, normalize(p)));
    }
    for n in &a.listed {
        objects.push(EventObject::new(
            db_name(db),
            Some(normalize("sys")),
            normalize(n),
        ));
        always = true;
    }
    // Past the event's bound, the core names `*` and always reports the
    // event (`MaskedEvent::with_object`, end-of-phase-9 review G7).
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
    let touches = !objects.is_empty() || wildcard;
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
        // `*` first, so that it always fits.
        ev = objects.apply(star(ev));
    } else {
        ev = objects.apply(ev);
        if always {
            ev = ev.with_always_report();
        }
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

    /// End-of-phase-9 review, N1: a bracketed name with trailing spaces is
    /// the name without them, as SQL Server compares identifiers and as
    /// Discovery records it.
    #[test]
    fn trailing_spaces_of_bracketed_names_are_dropped() {
        let ev = one(&stmt(
            "sql_statement_completed",
            "SELECT * FROM [crm  ].[customers ]",
            1,
            "51",
        ));
        assert_eq!(names(&ev), ["retail.crm.customers"]);
    }

    /// End-of-phase-9 review, G7: past the bound, a table of another
    /// database widens the event's `*` to `(*, -, *)` (the core's rule).
    #[test]
    fn objects_past_the_bound_in_another_database_widen_star() {
        let tables: Vec<String> = (0..16u8)
            .map(|i| format!("crm.t{}", char::from(b'a' + i)))
            .collect();
        let ev = one(&stmt(
            "sql_statement_completed",
            &format!("SELECT * FROM {}, hr.dbo.salaries", tables.join(", ")),
            1,
            "51",
        ));
        assert!(ev.always_report() && ev.objects_overflowed());
        assert!(names(&ev).contains(&"*.-.*".to_owned()), "{:?}", names(&ev));
    }

    /// End-of-phase-9 review, gate G1 (the nightly fuzz run 39014225515):
    /// a statement with more objects than an event holds would lose some,
    /// so it names `*` and is always reported. A name that normalization
    /// masks (the fuzz input's bracketed name, a value, a long digit run)
    /// is a masked name, not an unknown object (protocol "The object
    /// `*`"): it stays under the filters, as on SQL Server Audit.
    #[test]
    fn objects_past_the_bound_are_always_reported_and_masked_names_stay_names() {
        for (t, name) in [
            (
                "SELECT * FROM crm.customers c CROSS APPLY [insert/\"[] d",
                "retail.-.*",
            ),
            ("SELECT * FROM crm.[jane@example.com]", "retail.crm.*"),
            ("SELECT * FROM crm.orders_12345678901", "retail.crm.*"),
        ] {
            let ev = one(&stmt("sql_statement_completed", t, 1, "51"));
            assert!(!ev.always_report(), "{t:?}");
            assert!(names(&ev).contains(&name.to_owned()), "{t:?}");
        }
        let kept = databastion_classifiers::masking::MAX_EVENT_OBJECTS - 1;
        let tables = |n: usize| -> String {
            (0..n)
                .map(|i| format!("crm.t{}", char::from(b'a' + u8::try_from(i).unwrap())))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let ev = one(&stmt(
            "sql_statement_completed",
            &format!("SELECT * FROM {}", tables(kept)),
            1,
            "51",
        ));
        assert!(!ev.always_report() && ev.objects().len() == kept);
        for n in [kept, 20] {
            // The last table named would be lost.
            let ev = one(&stmt(
                "sql_statement_completed",
                &format!("SELECT * FROM {}, crm.zcustomers", tables(n)),
                1,
                "51",
            ));
            assert!(ev.always_report(), "{n}");
            assert!(names(&ev).contains(&"retail.-.*".to_owned()), "{n}");
        }
        // With a procedure from the request's rpc_completed.
        let mut r = stmt(
            "sp_statement_completed",
            &format!("SELECT * FROM {}", tables(kept)),
            1,
            "51",
        );
        r.procedure = Some("get_x".to_owned());
        let ev = one(&r);
        assert!(ev.always_report() && names(&ev).contains(&"retail.-.*".to_owned()));
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
            "-- ALTER LOGIN",
            "-- CREATE CREDENTIAL",
            "-- sp_addlogin",
            "-- sp_addlinkedsrvlogin",
            "CREATE LOGIN jane WITH PASSWORD = 'Marker-123'",
            "EXEC sp_addlogin jane, Pa55wordMarker",
            // Principal changes with no password: DCL, as on SQL Server
            // Audit (`DR` on a principal class), not DDL.
            "DROP LOGIN e2e_dcl_probe;",
            "DROP USER jane",
            "ALTER ROLE r ADD MEMBER jane",
            "ALTER SERVER ROLE sysadmin ADD MEMBER jane",
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
    /// A client's activity (case 1 of 2026-10-18).
    const GUID2: &str = "0B5C2E61-9D3A-4F7E-8C21-6A4D2F1E9B03";

    /// An `sp_statement_completed` of `login` in activity (`guid`, `seq`).
    fn sp(
        login: &str,
        text: &str,
        guid: Option<&str>,
        seq: u64,
        shape: (i64, &str, i64, i64),
    ) -> XeRecord {
        sp_on(login, "56", text, guid, seq, shape)
    }

    /// [`sp`] on session `session`.
    fn sp_on(
        login: &str,
        session: &str,
        text: &str,
        guid: Option<&str>,
        seq: u64,
        shape: (i64, &str, i64, i64),
    ) -> XeRecord {
        let (nest, otype, off, end) = shape;
        let mut a: Vec<(&str, String)> = who(login, session);
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
    /// A client's build in a batch (nest level 2) and its internal
    /// statement (at 1).
    const CLIENT_BUILD_SHAPE: (i64, &str, i64, i64) = (2, "ADHOC", 0, 342);
    const CLIENT_INTERNAL: (i64, &str, i64, i64) = (1, "ADHOC", 0, 0);

    /// A statement of `login` in activity (`guid`, `seq`).
    fn stmt_in(login: &str, text: &str, guid: Option<&str>, seq: u64) -> XeRecord {
        stmt_on(login, "56", text, guid, seq)
    }

    /// [`stmt_in`] on session `session`.
    fn stmt_on(login: &str, session: &str, text: &str, guid: Option<&str>, seq: u64) -> XeRecord {
        let mut a: Vec<(&str, String)> = who(login, session);
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

    /// The e2e DCL batch on the Extended Events source (captured on 2022,
    /// 16.0.4305.5): `CREATE LOGIN … WITH PASSWORD`, `ALTER LOGIN … WITH
    /// PASSWORD` and `DROP LOGIN` by a login holding `ALTER ANY LOGIN`.
    /// The server records the first two as `-- CREATE LOGIN` and `-- ALTER
    /// LOGIN`; `DROP LOGIN` keeps its text. All three are DCL, `*`, always
    /// reported, like the three `CR` / `AL` / `DR` records of SQL Server
    /// Audit; no other event of the batch (the `sp_droplogin` internals)
    /// is DCL.
    #[test]
    fn password_dcl_batch_is_three_dcl_events() {
        let mut recs = fixture("password-dcl-16.0.4305.5.xml");
        assert_eq!(recs.len(), 24);
        context(&mut recs, true, &|_| false);
        let texts: Vec<&str> = recs
            .iter()
            .filter(|r| r.kind() == Kind::SqlStatementCompleted)
            .filter_map(|r| r.event.as_ref()?.statement.as_deref().map(|t| t.trim()))
            .filter(|t| t.to_ascii_lowercase().contains("login"))
            .collect();
        assert_eq!(
            texts,
            [
                "-- CREATE LOGIN",
                "-- ALTER LOGIN",
                "DROP LOGIN e2e_dcl_probe;"
            ],
            "the server's forms"
        );
        let evs: Vec<MaskedEvent> = recs
            .iter()
            .filter(|r| !r.skip)
            .filter_map(convert)
            .map(|(e, _)| e)
            .collect();
        let dcl: Vec<&MaskedEvent> = evs
            .iter()
            .filter(|e| e.action() == EventAction::Dcl)
            .collect();
        assert_eq!(dcl.len(), 3, "{evs:?}");
        for e in &dcl {
            assert!(e.always_report());
            assert_eq!(names(e), ["retail.-.*"]);
            assert_eq!(
                e.principal(),
                &EventPrincipal::account("e2e_admin").with_application("SQLCMD")
            );
        }
        // The one DDL: `create table #retval` inside `sp_droplogin` (a
        // statement of the server's procedure, reported as DDL as any).
        assert_eq!(
            evs.iter()
                .filter(|e| e.action() == EventAction::Ddl)
                .count(),
            1
        );
        // No password, nor anything of the statement text, in the events.
        let dump = format!("{evs:?}");
        assert!(!dump.contains("e2e_dcl_probe") && !dump.to_ascii_lowercase().contains("password"));
    }

    /// The principal changes of the security review of d4175ea (L2),
    /// captured on 2022 (16.0.4305.5), one batch each: the inner
    /// statements of `sp_addrolemember`, `sp_addsrvrolemember`,
    /// `sp_dropuser` and `sp_droplogin` are statement events of their own,
    /// and so is the `DROP LOGIN` of `IF 1=1 DROP LOGIN x`: each is DCL,
    /// with the batches' statements, `ALTER AUTHORIZATION` and the
    /// password placeholders. Nothing else is; the only DDL is the
    /// `#retval` table of `sp_droplogin`.
    #[test]
    fn principal_changes_and_their_procedures_are_dcl() {
        let mut recs = fixture("dcl-procedures-16.0.4305.5.xml");
        assert_eq!(recs.len(), 144);
        context(&mut recs, true, &|_| false);
        let text = |r: &XeRecord| {
            r.event
                .as_ref()
                .and_then(|e| e.statement.as_deref())
                .map(|t| t.trim().to_owned())
                .unwrap_or_default()
        };
        let mut dcl = Vec::new();
        for r in recs.iter().filter(|r| !r.skip) {
            if let Some((e, _)) = convert(r) {
                // The one DDL: `sp_droplogin`'s own `#retval` table.
                if e.action() == EventAction::Ddl {
                    assert!(text(r).starts_with("create table #retval"), "{}", text(r));
                }
                if e.action() == EventAction::Dcl {
                    assert!(e.always_report() && names(&e).iter().all(|n| n.ends_with(".-.*")));
                    dcl.push(text(r));
                }
            }
        }
        dcl.sort();
        let mut want = vec![
            "-- CREATE LOGIN",
            "-- CREATE LOGIN",
            "CREATE USER m_u1 FOR LOGIN m_l1;",
            "CREATE ROLE m_r1;",
            "alter role [m_r1] add member [m_u1]",
            "alter server role [bulkadmin] add member [m_l1]",
            "ALTER AUTHORIZATION ON ROLE::m_r1 TO dbo;",
            "ALTER AUTHORIZATION ON SCHEMA::crm TO dbo;",
            "drop user [m_u1]",
            "DROP ROLE m_r1;",
            "drop login [m_l1]",
            "DROP LOGIN m_l2;",
        ];
        want.sort_unstable();
        assert_eq!(dcl, want);
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

    /// The `audit_specifications` proof's build on a fresh 2022 server
    /// (captured on 2026-10-18 from a new data volume by the fresh-server
    /// integration test, the dev service's audit named): the build on
    /// `sysaudacts` at nest level 2 and its internal statement at 1, in the
    /// proof's activity, left out; the proof itself is not touched. Each is
    /// reported without causality, from a foreign session, or off the
    /// allow-listed builds (ADR-0051 note of 2026-10-18).
    #[test]
    fn sysaudacts_fixture_of_2022() {
        let file = "sysaudacts-16.0.4305.5.xml";
        let recs = fixture(file);
        assert_eq!(recs.len(), 3, "{file}");
        let builds: Vec<&XeRecord> = recs
            .iter()
            .filter(|r| statement(r).is_some_and(|t| t.contains("[sys].[sysaudacts]")))
            .collect();
        assert_eq!(builds.len(), 1, "{file}");
        assert_eq!(builds[0].event.as_ref().and_then(|e| e.nest_level), Some(2));
        let proof = recs
            .iter()
            .filter(|r| statement(r).is_some_and(crate::sql::catalog_text))
            .count();
        assert_eq!(proof, 1, "{file}: the audit_specifications proof");
        let mut left = fixture(file);
        assert_eq!(context(&mut left, true, &own), 2, "{file}");
        for r in &left {
            assert_eq!(
                r.skip,
                !statement(r).is_some_and(crate::sql::catalog_text),
                "{file}"
            );
        }
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

    /// A build on `sys.sysaudacts` (in `master`), of the shape measured on
    /// 2022 after the `audit_specifications` proof (`audit_spec_id`,
    /// `nest_level` 2, an internal statement at 1).
    const AUDACTS_BUILD: &str = "SELECT StatMan([SC0]) FROM (SELECT TOP 100 PERCENT [audit_spec_id] AS [SC0] \
        FROM [sys].[sysaudacts] WITH (READUNCOMMITTED)  ORDER BY [SC0] ) AS _MS_UPDSTATS_TBL  OPTION (MAXDOP 16)";

    /// The `audit_specifications` proof of decision 6 (one of case 2's
    /// catalog reads), as the agent renders it.
    fn audit_specifications() -> String {
        let guid = crate::sql::quote_guid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0").unwrap();
        crate::sql::render(crate::sql::AUDIT_SPECIFICATIONS, &[("guid", &guid)]).unwrap()
    }

    /// The `sysaudacts` build, its internal statement and a partner, as
    /// [`guidrefs`] builds them.
    fn audacts(
        build_login: &str,
        partner_login: &str,
        partner: &str,
        guid: Option<&str>,
        partner_first: bool,
    ) -> Vec<XeRecord> {
        let mut recs = guidrefs(build_login, partner_login, partner, guid, partner_first);
        let at = usize::from(partner_first);
        recs[at] = sp(build_login, AUDACTS_BUILD, guid, 2, GUIDREFS_SHAPE);
        recs
    }

    /// ADR-0051 note of 2026-10-18 (accepted by the maintainer):
    /// `sys.sysaudacts` is on case 2's closed list, paired with the
    /// `audit_specifications` proof, every other condition of case 2
    /// unchanged; the same both-sided cases as `sysguidrefs`.
    #[test]
    fn sysaudacts_build_paired_with_the_audit_specifications_proof() {
        assert!(SYS_BASE_TABLES.contains(&"sysaudacts"));
        let proof = audit_specifications();
        assert!(crate::sql::catalog_text(&proof));
        for first in [false, true] {
            let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), first);
            assert_eq!(context(&mut recs, true, &own), 2, "partner first {first}");
            for r in &recs {
                assert_eq!(
                    r.skip,
                    statement(r) != Some(proof.as_str()),
                    "partner first {first}"
                );
            }
        }
        // The `audit_file` proof is a catalog read too: paired with it.
        let mut recs = audacts(
            "databastion",
            "databastion",
            &audit_file(),
            Some(GUID),
            false,
        );
        assert_eq!(context(&mut recs, true, &own), 2);
        // Reported: no causality.
        let mut recs = audacts("databastion", "databastion", &proof, None, false);
        assert_eq!(context(&mut recs, true, &own), 0);
        assert_eq!(reported(&recs), [0, 1, 2], "no causality");
        // Reported: a foreign session's build, or the proof's text from a
        // foreign session.
        for (build, partner) in [("app", "databastion"), ("databastion", "app")] {
            let mut recs = audacts(build, partner, &proof, Some(GUID), false);
            context(&mut recs, true, &own);
            assert!(
                !recs[0].skip && !recs[1].skip,
                "build {build}, partner {partner}"
            );
            let ev = convert(&recs[0]).unwrap().0;
            assert_eq!(names(&ev), ["retail.sys.sysaudacts"], "build {build}");
        }
        let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), false);
        context(&mut recs, true, &|_| false);
        assert!(!recs[0].skip, "no own session at all");
        // Reported: a partner that is not a catalog read.
        for text in [
            crate::sql::VERSION.to_owned(),
            crate::sql::AUDIT_POLL_START.to_owned(),
            proof.replace("TOP (513)", "TOP (514)"),
            "SELECT audit_action_name FROM sys.server_audit_specification_details".to_owned(),
        ] {
            assert!(!crate::sql::catalog_text(&text), "{text}");
            let mut recs = audacts("databastion", "databastion", &text, Some(GUID), false);
            context(&mut recs, true, &own);
            assert!(!recs[0].skip && !recs[1].skip, "not a catalog read: {text}");
        }
        // Reported: the proof in another activity.
        let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), false);
        recs[2] = stmt_in(
            "databastion",
            &proof,
            Some("AAAAAAAA-0000-0000-0000-000000000000"),
            1,
        );
        context(&mut recs, true, &own);
        assert!(!recs[0].skip, "the proof in another activity");
        // Reported: off the allow-listed builds.
        let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), false);
        assert_eq!(context(&mut recs, false, &own), 0);
        assert!(!unpaired_case_2(&recs[0], false, &own));
        // Unpaired in its read: a deferral candidate (item 4) for the
        // agent's session only.
        let mut recs = audacts(
            "databastion",
            "databastion",
            crate::sql::VERSION,
            Some(GUID),
            false,
        );
        context(&mut recs, true, &own);
        assert!(unpaired_case_2(&recs[0], true, &own));
        assert!(!unpaired_case_2(&recs[0], true, &|_| false));
        // Only `sys.sysaudacts` by its exact name.
        for table in [
            "[sys].[sysaudacts2]",
            "[sys].[sysaudact]",
            "[dbo].[sysaudacts]",
        ] {
            let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), false);
            recs[0] = sp(
                "databastion",
                &AUDACTS_BUILD.replace("[sys].[sysaudacts]", table),
                Some(GUID),
                2,
                GUIDREFS_SHAPE,
            );
            context(&mut recs, true, &own);
            assert!(!recs[0].skip, "{table}");
        }
        // The credential-bearing tables stay reported next to it.
        for table in ["sysowners", "sysxlgns"] {
            let mut recs = audacts("databastion", "databastion", &proof, Some(GUID), false);
            recs.push(sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", &format!("[sys].[{table}]")),
                Some(GUID),
                5,
                BUILD_SHAPE,
            ));
            context(&mut recs, true, &own);
            assert!(recs[0].skip && recs[1].skip && !recs[3].skip, "{table}");
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
        /// A client's statistics build on `crm.t` (case 1 of 2026-10-18).
        ClientBuild,
        /// The client's internal statement of that build.
        ClientInternal,
        /// The client's statement that made it (its pair, item 4).
        ClientRead,
    }

    /// Reads a simulated file through deferrals: `schedule` gives, per
    /// read, the rows written so far and the rows asked. Returns the
    /// events handled (time, left out) and the malformed rows met.
    fn walk(rows: &[(i64, Row)], schedule: &[(usize, usize)]) -> (Vec<(i64, bool)>, usize) {
        let (handled, malformed, _) = walk_seen(rows, schedule, &[]);
        (handled, malformed)
    }

    /// [`walk`], with the latest time seen after each read
    /// (`crate::audit::advance_seen`, the stream's rule with the cut).
    /// An agent restart before each read of `restarts`: the deferrals
    /// (in memory) are lost, the position (persisted) is kept.
    fn walk_seen(
        rows: &[(i64, Row)],
        schedule: &[(usize, usize)],
        restarts: &[usize],
    ) -> (Vec<(i64, bool)>, usize, Vec<Option<i64>>) {
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
                Row::ClientBuild => {
                    let mut r = sp("app", USER_BUILD, Some(GUID2), 1, CLIENT_BUILD_SHAPE);
                    r.time_us = 201;
                    r
                }
                Row::ClientInternal => {
                    let mut r = sp("app", "", Some(GUID2), 2, CLIENT_INTERNAL);
                    r.time_us = 202;
                    r
                }
                Row::ClientRead => {
                    let mut r = stmt_in("app", "SELECT TOP (5) id FROM crm.t", Some(GUID2), 3);
                    r.time_us = 203;
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
        let mut seen = None;
        let mut seens = Vec::new();
        let t0 = Instant::now();
        for (read, &(written, asked)) in schedule.iter().enumerate() {
            if restarts.contains(&read) {
                deferrals = Deferrals::default();
            }
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
            let cut = deferrals
                .cut(&recs, true, now, Duration::from_secs(5), None)
                .map(|c| c.at);
            let times: Vec<(usize, i64)> = recs.iter().map(|r| (r.index, r.time_us)).collect();
            seen = crate::audit::advance_seen(seen, &times, cut);
            seens.push(seen);
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
        (handled, malformed, seens)
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
        let (handled, _, seen) = walk_seen(&rows, &[(3, 500), (4, 500), (4, 500)], &[]);
        assert_eq!(handled, want(&[0]), "no duplicate, no drop");
        // #255 review: the cut read sees only the client's event (0), not
        // the deferred build (101), read again by the next read.
        assert_eq!(seen, [Some(0), Some(103), Some(103)]);

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
    /// (reported); one deferral per build; any session's build with
    /// causality on an allow-listed build (refinement of 2026-10-18), never
    /// one without causality, off the allow-list, or already paired.
    #[test]
    fn deferrals_are_bounded_and_need_causality_and_an_allowed_build() {
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
        assert_eq!(d.cut(&recs, true, t0, bound, None).map(|c| c.at), Some(7));
        assert_eq!(
            d.cut(&recs, true, t0 + Duration::from_secs(4), bound, None)
                .map(|c| c.at),
            Some(7),
            "within its bound"
        );
        assert_eq!(
            d.cut(&recs, true, t0 + Duration::from_secs(5), bound, None)
                .map(|c| c.at),
            None,
            "after its bound: reported"
        );
        assert_eq!(reported(&recs), [0]);
        assert_eq!(
            d.cut(&recs, true, t0 + Duration::from_secs(6), bound, None)
                .map(|c| c.at),
            None,
            "one deferral per build"
        );
        // Capped at 60 s whatever the bound.
        let mut d = Deferrals::default();
        assert!(
            d.cut(&recs, true, t0, Duration::from_secs(3600), None)
                .map(|c| c.at)
                .is_some()
        );
        assert!(
            d.cut(
                &recs,
                true,
                t0 + Duration::from_secs(60),
                Duration::from_secs(3600),
                None
            )
            .map(|c| c.at)
            .is_none()
        );
        // Case 1 (2026-10-18): another session's build, a client's build on
        // a user table, a system table off case 2's list, a credential
        // table: deferred too (the pairing after it is unchanged).
        let mut user = lone();
        user[0] = sp("app", USER_BUILD, Some(GUID), 1, CLIENT_BUILD_SHAPE);
        user[0].index = 7;
        context(&mut user, true, &own);
        assert_eq!(
            Deferrals::default()
                .cut(&user, true, t0, bound, None)
                .map(|c| c.at),
            Some(7),
            "a client's build"
        );
        assert_eq!(
            Deferrals::default()
                .cut(&recs, true, t0, bound, None)
                .map(|c| c.at),
            Some(7),
            "the agent's build"
        );
        for table in ["[sys].[sysowners]", "[sys].[sysfiles1]"] {
            let mut off = lone();
            off[0] = sp(
                "databastion",
                &BUILD.replace("[sys].[sysschobjs]", table),
                Some(GUID),
                1,
                BUILD_SHAPE,
            );
            context(&mut off, true, &own);
            assert_eq!(
                Deferrals::default()
                    .cut(&off, true, t0, bound, None)
                    .map(|c| c.at),
                Some(0),
                "{table}"
            );
        }
        // No causality, not allow-listed, a cut text, already paired: no
        // deferral.
        let mut nocause = lone();
        nocause[0] = sp("app", USER_BUILD, None, 1, CLIENT_BUILD_SHAPE);
        context(&mut nocause, true, &own);
        assert_eq!(
            Deferrals::default()
                .cut(&nocause, true, t0, bound, None)
                .map(|c| c.at),
            None,
            "no causality"
        );
        assert_eq!(
            Deferrals::default()
                .cut(&recs, false, t0, bound, None)
                .map(|c| c.at),
            None,
            "not allow-listed"
        );
        let mut cut = lone();
        if let Some(e) = cut[0].event.as_mut() {
            e.statement_cut = true;
        }
        assert_eq!(
            Deferrals::default()
                .cut(&cut, true, t0, bound, None)
                .map(|c| c.at),
            None,
            "cut"
        );
        let mut paired = own_build(Some(GUID));
        context(&mut paired, true, &own);
        assert_eq!(
            Deferrals::default()
                .cut(&paired, true, t0, bound, None)
                .map(|c| c.at),
            None
        );
        let mut paired = vec![
            sp("app", USER_BUILD, Some(GUID2), 1, CLIENT_BUILD_SHAPE),
            stmt_in("app", "SELECT TOP (5) id FROM crm.t", Some(GUID2), 3),
        ];
        context(&mut paired, true, &own);
        assert!(paired[0].skip);
        assert_eq!(
            Deferrals::default()
                .cut(&paired, true, t0, bound, None)
                .map(|c| c.at),
            None
        );
    }

    /// Refinement of 2026-10-18 (case 1 builds): a client's build whose
    /// statement reaches the file in a later read is deferred, then paired
    /// by the next read with its internal statement; none twice, none lost,
    /// across an agent restart too (the position never moves past it).
    #[test]
    fn a_deferred_client_build_is_paired_by_the_next_read() {
        use Row::{ClientBuild, ClientInternal, ClientRead};
        let paired = [(201, true), (202, true), (203, false)];
        let rows = [
            (4096, ClientBuild),
            (4096, ClientInternal),
            (8192, ClientRead),
        ];
        let (handled, _) = walk(&rows, &[(2, 500), (3, 500), (3, 500)]);
        assert_eq!(handled, paired, "no duplicate, no drop");
        // Written at the third read only, after a restart at the second
        // read: deferred again after it, never skipped.
        let (handled, _, _) = walk_seen(&rows, &[(2, 500), (2, 500), (3, 500), (3, 500)], &[1]);
        assert_eq!(handled, paired, "across a restart");
        // The internal statement before its build in file order (measured
        // on 2022): the read ends before the internal statement, so the
        // next read holds both with the pair.
        let rows = [
            (4096, ClientInternal),
            (4096, ClientBuild),
            (8192, ClientRead),
        ];
        let (handled, _) = walk(&rows, &[(2, 500), (3, 500), (3, 500)]);
        assert_eq!(handled, [(202, true), (201, true), (203, false)]);
        // Never paired: deferred for its bound (5 s, one read a second),
        // then reported once with its internal statement as a read of `*`;
        // a restart defers it once more, never drops it.
        let rows = [(4096, ClientBuild), (4096, ClientInternal)];
        let schedule = [(2, 500); 12];
        let (handled, _, _) = walk_seen(&rows, &schedule, &[]);
        assert_eq!(handled, [(201, false), (202, false)], "reported once");
        let (handled, _, _) = walk_seen(&rows, &schedule, &[3]);
        assert_eq!(handled, [(201, false), (202, false)], "reported once");
    }

    /// Reads fixture `name` through deferrals, the `n`th read seeing the
    /// file's first `written[n]` events (one read a second, a 5 s bound):
    /// the events handled, in file order (time = line, left out).
    fn split_reads(name: &str, written: &[usize], bound: Duration) -> Vec<(i64, bool)> {
        let mut d = Deferrals::default();
        let mut pos = 0;
        let mut out = Vec::new();
        let t0 = Instant::now();
        for (read, &w) in written.iter().enumerate() {
            let mut recs: Vec<XeRecord> = fixture(name)
                .into_iter()
                .take(w)
                .skip(pos)
                .enumerate()
                .map(|(i, mut r)| {
                    r.index = i;
                    r
                })
                .collect();
            context(&mut recs, true, &own);
            let now = t0 + Duration::from_secs(u64::try_from(read).unwrap());
            if let Some(at) = d.cut(&recs, true, now, bound, None).map(|c| c.at) {
                recs.truncate(at);
                for r in &mut recs {
                    r.skip = false;
                    r.procedure = None;
                }
                context(&mut recs, true, &own);
                pos += at;
            } else {
                pos = pos.max(w);
            }
            out.extend(recs.iter().map(|r| (r.time_us, r.skip)));
        }
        out
    }

    /// The CI failure of `xe_statistics_builds_match_the_fixture` (left 3,
    /// right 2): a read boundary between a client's build and the statement
    /// that made it. With the deferral of 2026-10-18, a cut of the matrix
    /// fixtures after any event gives the same result as one read: every
    /// event handled once, every build and internal statement left out.
    #[test]
    fn fixtures_split_at_any_read_boundary_match_one_read() {
        for file in [
            "statistics-15.0.4500.2.xml",
            "statistics-16.0.4305.5.xml",
            "statistics-17.0.5015.4.xml",
            "sysguidrefs-16.0.4305.5.xml",
            "sysguidrefs-17.0.5015.4.xml",
            "sysaudacts-16.0.4305.5.xml",
        ] {
            let mut whole = fixture(file);
            context(&mut whole, true, &own);
            let want: Vec<(i64, bool)> = whole.iter().map(|r| (r.time_us, r.skip)).collect();
            let n = whole.len();
            for k in 1..n {
                let got = split_reads(file, &[&[k][..], &[n; 7]].concat(), Duration::from_secs(5));
                assert_eq!(got, want, "{file}: cut after {k} events");
                // Several read boundaries (review L3).
                for k2 in k + 1..n {
                    let got = split_reads(
                        file,
                        &[&[k, k2][..], &[n; 8]].concat(),
                        Duration::from_secs(5),
                    );
                    assert_eq!(got, want, "{file}: cuts after {k} and {k2} events");
                    // Three boundaries on the fixture of the CI failure.
                    let three = if file == "statistics-16.0.4305.5.xml" {
                        n
                    } else {
                        0
                    };
                    for k3 in k2 + 1..three {
                        let got = split_reads(
                            file,
                            &[&[k, k2, k3][..], &[n; 9]].concat(),
                            Duration::from_secs(5),
                        );
                        assert_eq!(got, want, "{file}: cuts after {k}, {k2} and {k3} events");
                    }
                }
            }
        }
        // Without a deferral (a zero bound), the cut after the client's
        // build in a batch (event 5 of the 2022 fixture) reports it.
        let file = "statistics-16.0.4305.5.xml";
        let got = split_reads(file, &[6, 12], Duration::ZERO);
        assert_eq!(got.len(), 12);
        assert_eq!(
            got[5],
            (5, false),
            "the build reported without the deferral"
        );
        assert_eq!(
            split_reads(file, &[6, 12, 12], Duration::from_secs(5))[5],
            (5, true),
            "left out with it"
        );
    }

    /// At most 4 096 builds remembered (case 1 and case 2 together): a
    /// build first seen past that is not deferred, and is reported.
    #[test]
    fn deferrals_past_the_memory_cap_are_reported() {
        let t0 = Instant::now();
        let bound = Duration::from_secs(30);
        let mut d = Deferrals::default();
        let build = |seq: u64| {
            let mut v = vec![sp("app", USER_BUILD, Some(GUID2), seq, CLIENT_BUILD_SHAPE)];
            context(&mut v, true, &own);
            v
        };
        for seq in 0..4096 {
            assert_eq!(
                d.cut(&build(seq * 8), true, t0, bound, None).map(|c| c.at),
                Some(0),
                "{seq}"
            );
        }
        let over = build(4096 * 8);
        assert_eq!(
            d.cut(&over, true, t0, bound, None).map(|c| c.at),
            None,
            "past the cap"
        );
        assert_eq!(reported(&over), [0], "reported");
        // A remembered build is still deferred within its bound.
        assert_eq!(
            d.cut(&build(8), true, t0, bound, None).map(|c| c.at),
            Some(0)
        );
    }

    /// The stream is held behind deferrals for at most 60 s in a row: a
    /// client writing a new unpaired build before every read delays what
    /// follows by at most that long, then a read goes through (its builds
    /// reported) and deferrals start again.
    #[test]
    fn a_chain_of_deferrals_holds_the_stream_for_60_s_at_most() {
        let t0 = Instant::now();
        let bound = Duration::from_secs(60);
        let mut d = Deferrals::default();
        let build = |seq: u64| {
            let mut v = vec![sp("app", USER_BUILD, Some(GUID2), seq, CLIENT_BUILD_SHAPE)];
            context(&mut v, true, &own);
            v
        };
        let at = |s: u64| t0 + Duration::from_secs(s);
        for s in (0..60).step_by(10) {
            assert_eq!(
                d.cut(&build(s * 8), true, at(s), bound, None).map(|c| c.at),
                Some(0),
                "{s}"
            );
        }
        assert_eq!(
            d.cut(&build(60 * 8), true, at(60), bound, None)
                .map(|c| c.at),
            None,
            "held 60 s"
        );
        assert_eq!(
            d.cut(&build(70 * 8), true, at(70), bound, None)
                .map(|c| c.at),
            Some(0),
            "again"
        );
        // A read that ends uncut starts the count again.
        assert_eq!(d.cut(&[], true, at(100), bound, None).map(|c| c.at), None);
        assert_eq!(
            d.cut(&build(110 * 8), true, at(110), bound, None)
                .map(|c| c.at),
            Some(0)
        );
        assert_eq!(
            d.cut(&build(160 * 8), true, at(160), bound, None)
                .map(|c| c.at),
            Some(0)
        );
    }

    /// One event of a simulated session file, written at `at_ms`.
    #[derive(Clone)]
    struct Spec {
        id: i64,
        at_ms: u64,
        kind: SpecKind,
        session: u32,
        guid: String,
        seq: u64,
    }

    #[derive(Clone)]
    enum SpecKind {
        /// A statistics build on `crm.<table>`.
        Build(String),
        /// A build's internal statement.
        Internal,
        /// A client's read of `crm.<table>` (a build's pair when the same
        /// request holds the build).
        Read(String),
    }

    impl Spec {
        fn record(&self, index: usize) -> XeRecord {
            let session = self.session.to_string();
            let guid = Some(self.guid.as_str());
            let mut r = match &self.kind {
                SpecKind::Build(t) => sp_on(
                    "app",
                    &session,
                    &USER_BUILD.replace("[crm].[t]", &format!("[crm].[{t}]")),
                    guid,
                    self.seq,
                    CLIENT_BUILD_SHAPE,
                ),
                SpecKind::Internal => sp_on("app", &session, "", guid, self.seq, CLIENT_INTERNAL),
                SpecKind::Read(t) => stmt_on(
                    "app",
                    &session,
                    &format!("SELECT TOP (5) id FROM crm.{t}"),
                    guid,
                    self.seq,
                ),
            };
            r.time_us = self.id;
            r.index = index;
            r
        }
    }

    /// The stream over `file` (sorted by `at_ms`) as `read` and `cycle`
    /// run it: reads of at most `batch` rows from the position; a full read
    /// that is not a deferral reads on at once (5 ms), at most 20 s in a
    /// cycle (`CATCH_UP`); a deferral or a read that reached the end waits
    /// `poll_ms`. Returns, per event id, when it was handled and whether it
    /// was left out; asserts that none is handled twice.
    fn simulate(
        file: &[Spec],
        batch: usize,
        poll_ms: u64,
        bound: Duration,
        end_ms: u64,
    ) -> std::collections::BTreeMap<i64, (u64, bool)> {
        let t0 = Instant::now();
        let mut d = Deferrals::default();
        let mut handled = std::collections::BTreeMap::new();
        let (mut t, mut pos, mut cycle) = (0u64, 0usize, 0u64);
        while t <= end_ms {
            let written = file.iter().take_while(|s| s.at_ms <= t).count();
            let mut recs: Vec<XeRecord> = file[pos..written]
                .iter()
                .take(batch)
                .enumerate()
                .map(|(i, s)| s.record(i))
                .collect();
            let len = recs.len();
            let full = len == batch;
            context(&mut recs, true, &own);
            let now = t0 + Duration::from_millis(t);
            let cut = d.cut(&recs, true, now, bound, full.then_some(len));
            if let Some(c) = cut {
                assert!(c.at > 0 || c.wait, "a full read always moves");
                recs.truncate(c.at);
                for r in &mut recs {
                    r.skip = false;
                }
                context(&mut recs, true, &own);
            }
            pos += recs.len();
            for r in &recs {
                assert!(
                    handled.insert(r.time_us, (t, r.skip)).is_none(),
                    "event {} handled twice",
                    r.time_us
                );
            }
            let waits = cut.is_some_and(|c| c.wait) || !full || t - cycle >= 20_000;
            if waits {
                t += poll_ms;
                cycle = t;
            } else {
                t += 5;
            }
        }
        handled
    }

    /// Writes `n` requests of a session: a build on `table`, its internal
    /// statement and, `pair_ms` later (if any), the read that made it.
    fn requests(
        file: &mut Vec<Spec>,
        session: u32,
        every_ms: u64,
        until_ms: u64,
        pair_ms: Option<u64>,
        table: &str,
    ) {
        let mut at = every_ms;
        while at < until_ms {
            let guid = format!("{session:08X}-0000-0000-0000-{at:012X}");
            let t = format!("{table}{at}");
            let mut push = |at_ms: u64, kind: SpecKind, seq: u64| {
                file.push(Spec {
                    id: 0,
                    at_ms,
                    kind,
                    session,
                    guid: guid.clone(),
                    seq,
                });
            };
            push(at, SpecKind::Build(t.clone()), 1);
            push(at, SpecKind::Internal, 2);
            if let Some(p) = pair_ms {
                push(at + p, SpecKind::Read(t), 3);
            }
            at += every_ms;
        }
    }

    /// Other clients' reads, `per_s` a second over sessions 60 to 63.
    fn fillers(file: &mut Vec<Spec>, per_s: u64, until_ms: u64) {
        let step = 1000 / per_s;
        for (i, at) in (0..until_ms)
            .step_by(usize::try_from(step).unwrap())
            .enumerate()
        {
            file.push(Spec {
                id: 0,
                at_ms: at,
                kind: SpecKind::Read("f".to_owned()),
                session: 60 + u32::try_from(i % 4).unwrap(),
                guid: format!("F0000000-0000-0000-0000-{i:012X}"),
                seq: 1,
            });
        }
    }

    fn sorted(mut file: Vec<Spec>) -> Vec<Spec> {
        file.sort_by_key(|s| s.at_ms);
        for (i, s) in file.iter_mut().enumerate() {
            s.id = i64::try_from(i).unwrap();
        }
        file
    }

    /// Security review of the 2026-10-18 refinement, H1 and L3: under a
    /// constant load (other clients' reads, clients whose builds are paired
    /// 300 ms later, interleaved) and a client writing a new unpaired build
    /// every second, every event is handled once, within `MAX_DEFERRAL` +
    /// the bound + a poll interval (+ 1 s of catch-up) of being written;
    /// without that client, every paired build is left out.
    #[test]
    fn continuous_load_handles_every_event_within_the_bound() {
        let (poll, bound) = (1000u64, Duration::from_secs(2));
        let limit = u64::try_from(MAX_DEFERRAL.as_millis()).unwrap() + 2000 + poll + 1000;
        // (name, other clients' reads a second, the hostile client, length):
        // at 5 reads a second, the rows behind the hostile builds stay
        // below a full read for minutes, so only the hold bound applies.
        for (name, per_s, attacked, end) in [
            ("quiet", 100, false, 240_000u64),
            ("attacked", 100, true, 240_000),
            ("attacked, slow", 5, true, 480_000),
        ] {
            let mut file = Vec::new();
            fillers(&mut file, per_s, end);
            requests(&mut file, 80, 7000, end, Some(300), "l");
            requests(&mut file, 81, 13_000, end, Some(250), "m");
            if attacked {
                requests(&mut file, 70, 1000, end, None, "tmp");
            }
            let file = sorted(file);
            let handled = simulate(&file, BATCH_FOR_TESTS, poll, bound, end + limit + 5000);
            for s in &file {
                let Some((at, skip)) = handled.get(&s.id) else {
                    panic!("{name}: event {} lost", s.id);
                };
                assert!(
                    at - s.at_ms <= limit,
                    "{name}: event {} handled {} ms after it was written",
                    s.id,
                    at - s.at_ms
                );
                match (&s.kind, s.session) {
                    (SpecKind::Read(_), _) => assert!(!skip, "{name}: a read is reported"),
                    (_, 70) => assert!(!skip, "{name}: an unpaired build is reported"),
                    _ if !attacked => {
                        assert!(skip, "{name}: a paired build and its internal statement");
                    }
                    _ => {}
                }
            }
        }
    }

    const BATCH_FOR_TESTS: usize = crate::audit::BATCH;

    /// Review M1: a full read (more rows on the server) whose build's pair
    /// is in the rows not fetched yet ends before the build and reads on at
    /// once, using none of the build's deferral; a build at the start of a
    /// full read is handled as it stands (the position always moves).
    #[test]
    fn full_reads_cut_before_a_late_build_and_read_on() {
        let filler = |at: u64| Spec {
            id: 0,
            at_ms: at,
            kind: SpecKind::Read("f".to_owned()),
            session: 60,
            guid: "F0000000-0000-0000-0000-000000000000".to_owned(),
            seq: 1,
        };
        let request = |kind: SpecKind, seq: u64| Spec {
            id: 0,
            at_ms: 0,
            kind,
            session: 80,
            guid: "A0000000-0000-0000-0000-000000000000".to_owned(),
            seq,
        };
        // 1 000 rows written at once: the build at 410, its pair at 600.
        let mut file: Vec<Spec> = (0..1000).map(|_| filler(0)).collect();
        file[410] = request(SpecKind::Build("x".to_owned()), 1);
        file[411] = request(SpecKind::Internal, 2);
        file[600] = request(SpecKind::Read("x".to_owned()), 3);
        let file = sorted(file);
        let handled = simulate(&file, 500, 1000, Duration::from_secs(2), 10);
        assert_eq!(handled.len(), 1000, "every event once");
        assert_eq!(handled[&410], (5, true), "paired by the next read, at once");
        assert_eq!(handled[&411], (5, true));
        assert!(!handled[&600].1);
        // The deferral memory is untouched by a full read's cut.
        let mut d = Deferrals::default();
        let mut recs: Vec<XeRecord> = file
            .iter()
            .take(500)
            .enumerate()
            .map(|(i, s)| s.record(i))
            .collect();
        context(&mut recs, true, &own);
        let t0 = Instant::now();
        let bound = Duration::from_secs(2);
        assert_eq!(
            d.cut(&recs, true, t0, bound, Some(500)),
            Some(Cut {
                at: 410,
                wait: false
            })
        );
        assert!(d.until.is_empty() && d.held_since.is_none());
        // Paired in the read: no cut.
        let mut early: Vec<XeRecord> = file
            .iter()
            .skip(300)
            .take(500)
            .enumerate()
            .map(|(i, s)| s.record(i))
            .collect();
        context(&mut early, true, &own);
        assert_eq!(d.cut(&early, true, t0, bound, Some(500)), None);
        // A batch smaller than the distance to the pair (16 rows, the pair
        // 200 rows on): the full read ends before the build; the next one
        // starts at it and cannot cut at 0, so the build is reported, once.
        let handled = simulate(&file, 16, 1000, Duration::from_secs(2), 2000);
        assert_eq!(handled.len(), 1000, "every event once");
        assert!(!handled[&410].1, "reported (fail closed)");
        assert!(!handled[&411].1);
    }
}
