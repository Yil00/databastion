//! SQL Server Audit (ADR-0051 decision 6 and its refinement of 2026-10-14,
//! option (a')): the operator's server audit, `FILE` target, read through
//! `sys.fn_get_audit_file` over the stream's own connection; **Partial at
//! best**, never Full ([`probe`]).
//!
//! - **Source**: SQL Server 2022 and later, with `VIEW SERVER SECURITY
//!   AUDIT` and `VIEW ANY SECURITY DEFINITION`. The audit and its
//!   specifications are the operator's; the agent never creates, alters,
//!   starts or stops them (I4). The other source, an Extended Events
//!   session, is described below ([`xe`]); it is the only one on SQL
//!   Server 2019.
//! - **Polls**: one `sp_executesql` RPC each, whose text is constant for
//!   a given catalog state: the file pattern (from the catalog's folder,
//!   the audit's name and GUID) is a literal of the text, never a
//!   parameter (M1); the file name, the buffer offset and the row bound
//!   and the records of the next buffer already handled (skipped on the
//!   server) are parameters. At most [`BATCH`] records per read (halved after a
//!   response over [`POLL_BYTES`]), each turned into a record as its row
//!   ends; a full read is followed by another, within [`CATCH_UP`] (and
//!   [`HISTORY_READS`] reads while the first start skips the history). Each poll gets a credit
//!   (its own record is left out only for this session and this text).
//! - **Position** (M4), persisted through the core: the file and the
//!   offset of the last buffer read whole (a read starts after it,
//!   measured), and how many records of the next buffer were already
//!   handled (skipped on the server by the next read, so a buffer of any
//!   size is walked by reads of at most [`BATCH`]), and the file pattern
//!   it belongs to. Another pattern (the
//!   folder moved, the audit renamed or recreated) is another file set:
//!   read from its start, a gap. A position the server refuses (error
//!   33225) in the same set (rolled over) restarts at the oldest file,
//!   skipping what was read by file key (partition, timestamp) and
//!   offset, never by path; a gap. An unreadable cursor is a gap too. The audit's own start and stop records (`AUSC`)
//!   after the position are gaps too: `audit.records_dropped` and Limited
//!   for 24 h. The first start skips the audit's history (no replay).
//! - **Records** ([`records`]): one event per statement, objects from the
//!   records, the text analysed only for reads and writes and never sent.
//! - **The agent's own statements** ([`own`], decision 6, H1): only from
//!   one of the agent's own sessions within its lifetime, with both
//!   principals and the client address the agent's, and then only for its
//!   exact constant texts (no credit) or a credited sampling, ticket-count
//!   or poll text; sampling is charged the whole per-object budget. Its
//!   writes, DDL and DCL are always reported.
//! - Per-record panic isolation: each row is parsed, and each statement
//!   converted, under `databastion_core::isolate`, so a parser panic costs
//!   that record and is counted (`audit.records_dropped`). The core's
//!   isolation mode (`CursorStore::isolate`, a save after every record)
//!   is not followed: the position is a buffer of the audit file, not a
//!   record, so it cannot be saved between two records of one buffer; a
//!   skip the core asks for drops the first statement of the next read.
//! - **Extended Events** ([`xe`]): the other source of decision 6, the
//!   only one on SQL Server 2019. With `source: auto`, SQL Server Audit is
//!   read when usable, else the Extended Events session (the preference
//!   rule shared by `check()` and the stream, re-evaluated every 5
//!   minutes: a stream whose choice changes ends and is restarted).

pub(crate) mod objects;
pub(crate) mod own;
pub(crate) mod probe;
pub(crate) mod records;
pub(crate) mod xe;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::{ClientSeen, OwnAccount, SharedOwnUsage};
use databastion_core::config::TargetConfig;
use databastion_core::{AuditConfig, ConnectorError, Engine, EventSink, FailureCode};

use crate::check::{self, CheckState};
use crate::conn::{self, Cell, Flow, Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql::{self, OwnText};
use crate::tds::Param;
use crate::tls;
use crate::token::Value;
use records::{Mapped, Record, Statement};

/// Records read per poll (decision 6: at most 1 000). A record is at most
/// about 9.3 KiB on the wire (an `nvarchar(4000)` statement, five
/// `nvarchar(128)` names, a 260-character file name and the numbers), so a
/// read of `BATCH` rows stays under [`POLL_BYTES`] (security review of
/// P9-A lot 2, L5: the agent's measured peak RSS is 42 MiB).
pub(crate) const BATCH: usize = 500;
/// Records of one buffer handled across reads at most; beyond, the rest
/// of that buffer is dropped (a gap). The handled records are skipped on
/// the server (`sql::AUDIT_POLL_FROM`), so a read returns at most
/// [`BATCH`] records whatever the buffer's size. A buffer holds about
/// 500 KiB of records, often more than a read (measured on 2022 at 300
/// statements/s: about 300 records, 789 after the stall of a rollover, up
/// to 1 047 with other sessions' records; the P9-D load run lost the rest
/// of such buffers while the bound was 500).
pub(crate) const MAX_SKIP: u32 = 1_000_000;
/// Smallest read after responses over [`POLL_BYTES`] (the read halves).
const MIN_BATCH: usize = 16;
/// Time spent catching up (full reads one after the other) per cycle.
const CATCH_UP: Duration = Duration::from_secs(20);
/// Reads of the audit's history (first start) per cycle: the scan to the
/// end of the file set is spread over cycles.
const HISTORY_READS: usize = 20;
/// Bound of one poll's response.
const POLL_BYTES: usize = 12 * 1024 * 1024;
/// The catalog proofs are read again this often (decision 6).
const REPROBE: Duration = Duration::from_secs(300);
/// The account's evaluation (refusal list) is read again this often.
const REEVALUATE: Duration = Duration::from_secs(600);
/// Statement timeout of the stream's statements.
const POLL_TIMEOUT: Duration = Duration::from_secs(15);
/// The level proofs last this long.
pub(crate) const FRESHNESS: Duration = Duration::from_secs(24 * 3600);
/// Cursor and own-sessions file names.
const CURSOR: &str = "sqlserver_audit";
const OWN_SESSIONS: &str = "sqlserver_own_sessions";
/// Largest own-sessions file written (the core's counters bound).
const OWN_FILE_BYTES: usize = 2 * 1024 * 1024 - 4096;
/// The server's error for a position outside the audit's file set.
const ERR_BAD_POSITION: i32 = 33_225;
/// The agent's application name (`LOGIN7` `AppName`).
const APP: &str = "databastion-agent";

fn target_error(code: FailureCode) -> ConnectorError {
    ConnectorError::Target {
        engine: Engine::Sqlserver,
        code,
        engine_code: None,
    }
}

/// Per-target Audit facts, shared by `check()` and the stream.
#[derive(Default)]
pub(crate) struct Shared {
    running: Mutex<HashMap<String, usize>>,
    fresh: Mutex<HashMap<String, Instant>>,
    gap: Mutex<HashMap<String, Instant>>,
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
    own_usage: Mutex<HashMap<String, SharedOwnUsage>>,
    chosen: Mutex<HashMap<String, Source>>,
    /// The source the last stream of the target read.
    streamed: Mutex<HashMap<String, Source>>,
    /// Extended Events session counters last seen per target (`check()`
    /// and the stream): (`create_time`, dropped events, dropped buffers).
    xe_seen: Mutex<HashMap<String, (i64, i64, i64)>>,
    /// Statements left out as the agent's own: (exact texts, credited
    /// sampling, credited polls, statistics builds and their internal
    /// statements), for the logs and the tests.
    own_left_out: Mutex<HashMap<String, [u64; 4]>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A running stream; unregistered on drop.
pub(crate) struct Running<'a> {
    shared: &'a Shared,
    target: String,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut map = lock(&self.shared.running);
        if let Some(n) = map.get_mut(&self.target) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.target);
            }
        }
    }
}

impl Shared {
    fn started(&self, target_id: &str) -> Running<'_> {
        *lock(&self.running).entry(target_id.to_owned()).or_insert(0) += 1;
        Running {
            shared: self,
            target: target_id.to_owned(),
        }
    }

    pub(crate) fn is_running(&self, target_id: &str) -> bool {
        lock(&self.running).contains_key(target_id)
    }

    fn note_record(&self, target_id: &str) {
        lock(&self.fresh).insert(target_id.to_owned(), Instant::now());
    }

    fn note_gap(&self, target_id: &str) {
        lock(&self.gap).insert(target_id.to_owned(), Instant::now());
    }

    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        if n == 0 {
            return;
        }
        let mut map = lock(&self.dropped);
        let e = map
            .entry(target_id.to_owned())
            .or_insert((0, Instant::now()));
        if e.1.elapsed() >= FRESHNESS {
            *e = (0, Instant::now());
        }
        e.0 = e.0.saturating_add(n);
    }

    /// The facts of the level rule.
    pub(crate) fn facts(&self, target_id: &str) -> probe::StreamFacts {
        let within = |m: &Mutex<HashMap<String, Instant>>| {
            lock(m)
                .get(target_id)
                .is_some_and(|t| t.elapsed() < FRESHNESS)
        };
        probe::StreamFacts {
            running: self.is_running(target_id),
            fresh: within(&self.fresh),
            gap: within(&self.gap),
            dropped: lock(&self.dropped)
                .get(target_id)
                .filter(|(_, at)| at.elapsed() < FRESHNESS)
                .map_or(0, |(n, _)| *n),
        }
    }

    pub(crate) fn own_usage(&self, target_id: &str) -> SharedOwnUsage {
        lock(&self.own_usage)
            .entry(target_id.to_owned())
            .or_default()
            .clone()
    }

    /// The source the last `check()` chose (`None`: no usable source).
    pub(crate) fn set_chosen(&self, target_id: &str, source: Option<Source>) {
        let mut map = lock(&self.chosen);
        match source {
            Some(s) => map.insert(target_id.to_owned(), s),
            None => map.remove(target_id),
        };
    }

    pub(crate) fn chosen(&self, target_id: &str) -> Option<Source> {
        lock(&self.chosen).get(target_id).copied()
    }

    /// Records the source a stream starts on; on a switch from the other
    /// source, a gap (security review of lot 3, L3): what was written to
    /// the old source after its last read, and to the new one before its
    /// position or, on its first start, before now (no history replay), is
    /// read by neither.
    pub(crate) fn stream_source(&self, target_id: &str, source: Source) {
        let before = lock(&self.streamed).insert(target_id.to_owned(), source);
        if before.is_some_and(|b| b != source) {
            tracing::warn!(target_id = %target_id, "SQL Server Audit: the stream switched between SQL Server Audit and Extended Events: events around the switch may be read by neither (a gap)");
            self.note_gap(target_id);
            self.note_dropped(target_id, 1);
        }
    }

    /// Records the Extended Events session counters seen now; `true` (and a
    /// gap noted, decision 6 proof 4) when the session was restarted
    /// (another `create_time`) or its drop counters grew since last seen.
    pub(crate) fn observe_xe(&self, target_id: &str, seen: (i64, i64, i64)) -> bool {
        let before = lock(&self.xe_seen).insert(target_id.to_owned(), seen);
        let gap = before.is_some_and(|(create, events, buffers)| {
            !xe::probe::same_start(create, seen.0) || seen.1 > events || seen.2 > buffers
        });
        if gap {
            self.note_gap(target_id);
            self.note_dropped(target_id, 1);
        }
        gap
    }

    fn note_own(&self, target_id: &str, which: usize) {
        if let Some(n) = lock(&self.own_left_out)
            .entry(target_id.to_owned())
            .or_default()
            .get_mut(which)
        {
            *n += 1;
        }
    }

    /// Statistics statements left out (item 4, refinement of 2026-10-15).
    pub(crate) fn note_statistics(&self, target_id: &str, n: usize) {
        if let Some(c) = lock(&self.own_left_out)
            .entry(target_id.to_owned())
            .or_default()
            .get_mut(3)
        {
            *c = c.saturating_add(n as u64);
        }
    }

    /// Statements left out: exact texts, credited sampling, credited
    /// polls, statistics statements.
    #[cfg(test)]
    pub(crate) fn own_left_out(&self, target_id: &str) -> [u64; 4] {
        lock(&self.own_left_out)
            .get(target_id)
            .copied()
            .unwrap_or_default()
    }
}

/// An Audit source of SQL Server (contract `AuditSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// SQL Server Audit (`sqlserver_audit`).
    Audit,
    /// An Extended Events session (`sqlserver_xevents`).
    Xevents,
}

/// A record with a position in an audit or event file set.
pub(crate) trait Positioned {
    fn file(&self) -> &str;
    fn offset(&self) -> i64;
}

impl Positioned for Record {
    fn file(&self) -> &str {
        &self.file
    }
    fn offset(&self) -> i64 {
        self.offset
    }
}

/// The order key of a file of a file set (`file_key`, `sql::xe_file_key`).
pub(crate) type FileKey = fn(&str) -> Option<(i64, i64)>;

/// The persisted position (file names hex-encoded, numbers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    /// File and offset of the last buffer read whole (`None`: from the
    /// start of the file set).
    pub(crate) file: Option<String>,
    pub(crate) offset: i64,
    /// Records of the buffer after it already handled (skipped on the
    /// server by the next read).
    pub(crate) skip: u32,
    /// The file pattern (folder, audit name and GUID) the position belongs
    /// to: positions are never compared across file sets.
    pub(crate) pattern: Option<String>,
    /// After a refused position in the same file set: records at or before
    /// this (file key, offset) were read already ([`file_key`]).
    pub(crate) after: Option<((i64, i64), i64)>,
    /// First start: records older than this (server µs) are history, not
    /// reported.
    pub(crate) history_us: Option<i64>,
    /// Extended Events: the session's `create_time` (server µs) the
    /// position was read under; another one is a restart (a gap).
    pub(crate) session: Option<i64>,
    /// First start: records stamped before this (server µs) are not
    /// reported, even when they reach the source after it was read to its
    /// end (`QUEUE_DELAY`, `MAX_DISPATCH_LATENCY`). Bounded (re-review N1):
    /// dropped once the stream caught up and the source's delivery delay
    /// passed since the first start ([`Cursor::settle`]); a record it
    /// leaves out after the first caught-up read is counted as dropped.
    pub(crate) floor: Option<i64>,
    /// The agent's wall clock (Unix ms) at the first start the floor was
    /// set at.
    pub(crate) floor_set_ms: i64,
    /// The buffer (file, offset) whose first `skip` records were handled
    /// (the server skips them, `sql::AUDIT_POLL_FROM`,
    /// `sql::XE_POLL_FROM`).
    pub(crate) buffer: Option<(String, i64)>,
    /// The latest time (server µs) of the records the stream handled,
    /// those a refused position left out (`after`) excepted: the history
    /// boundary by order of a first catch-up ([`Cursor::below`]).
    pub(crate) max_seen_us: Option<i64>,
}

/// How far below the latest record handled a record of the history phase
/// may be stamped and still be history (disorder of the source's writers),
/// at least: the delivery delay when larger, at most [`FLOOR_MAX`].
pub(crate) const HISTORY_DISORDER: Duration = Duration::from_secs(5);

/// The longest the floor is kept after the first start (re-review N1),
/// whatever delivery delay the source states.
pub(crate) const FLOOR_MAX: Duration = Duration::from_secs(300);

/// The agent's wall clock, Unix ms (the floor's bound, never the server's
/// clock, which is what may step).
pub(crate) fn agent_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What the first start's history and floor say of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Below {
    /// Stamped before the first start, read in the history phase: not
    /// reported, not counted.
    History,
    /// Stamped below the floor after the first caught-up read (late
    /// history, or the server's clock stepped back): not reported,
    /// counted as dropped.
    Dropped,
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) || s.len() > 2048 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

impl Cursor {
    /// Sets the history and the floor of a first start: `server_now`
    /// (server µs) plus `skew_us`, the source's clock lead.
    pub(crate) fn first_start(&mut self, server_now: Option<i64>, skew_us: i64) {
        self.history_us = server_now;
        self.floor = server_now.map(|h| h.saturating_add(skew_us));
        self.floor_set_ms = agent_now_ms();
    }

    /// After a read that reached the end of the source (`self` its next
    /// position, so no history phase any more) and started at
    /// `read_started_ms` on the agent's clock: the floor ends when `delay`
    /// (the source's delivery delay, at most [`FLOOR_MAX`]) had passed
    /// since the first start when the read started, since every record
    /// stamped before the first start had then reached the source and was
    /// read; at once if the agent's clock went back past the first start.
    pub(crate) fn expire_floor(&mut self, read_started_ms: i64, delay: Duration) {
        if self.floor.is_none() || self.history_us.is_some() {
            return;
        }
        let delay_ms = i64::try_from(delay.min(FLOOR_MAX).as_millis()).unwrap_or(i64::MAX);
        let since = read_started_ms.saturating_sub(self.floor_set_ms);
        if since >= delay_ms || since < 0 {
            self.floor = None;
        }
    }

    /// After a read that reached the end of the source, `self` its next
    /// position (the history phase cleared) and `prev_history` the history
    /// before it: while the source's delivery `delay` has not passed since
    /// the first start, records stamped before it may still come, so the
    /// history phase goes on (they are history, not counted); once it has,
    /// the history phase and the floor end together
    /// ([`Self::expire_floor`]).
    pub(crate) fn settle(
        &mut self,
        prev_history: Option<i64>,
        read_started_ms: i64,
        delay: Duration,
    ) {
        let delay_ms = i64::try_from(delay.min(FLOOR_MAX).as_millis()).unwrap_or(i64::MAX);
        let since = read_started_ms.saturating_sub(self.floor_set_ms);
        if prev_history.is_some() && (0..delay_ms).contains(&since) {
            self.history_us = prev_history;
            return;
        }
        self.expire_floor(read_started_ms, delay);
    }

    /// Whether a record stamped `time_us` (server µs) is left out, and how,
    /// `seen_us` being the latest time of the records handled before it
    /// ([`Self::max_seen_us`], updated through the read). In the history
    /// phase (it ends with the first caught-up read once the delivery
    /// delay has passed, [`Self::settle`]), a record below the start or the
    /// floor is history unless it is stamped more than the tolerance
    /// (`delay`, at least [`HISTORY_DISORDER`], at most [`FLOOR_MAX`])
    /// below `seen_us`: a step back of the server's clock, counted as
    /// dropped. After it, a record below the floor is counted as dropped.
    pub(crate) fn below(
        &self,
        time_us: i64,
        seen_us: Option<i64>,
        delay: Duration,
    ) -> Option<Below> {
        let threshold = match (self.history_us, self.floor) {
            (Some(h), f) => f.map_or(h, |f| f.max(h)),
            (None, Some(f)) => f,
            (None, None) => return None,
        };
        if time_us >= threshold {
            return None;
        }
        if self.history_us.is_none() {
            return Some(Below::Dropped);
        }
        // The history phase, however long the catch-up: by order (security
        // review of lot 3, follow-up of L1). A record stamped within the
        // tolerance below the latest one handled is history (the backlog
        // read in order, or the writers' disorder); one further below is a
        // step back of the server's clock: counted.
        let tolerance = delay.max(HISTORY_DISORDER).min(FLOOR_MAX);
        let tolerance_us = i64::try_from(tolerance.as_micros()).unwrap_or(i64::MAX);
        match seen_us {
            Some(m) if time_us < m.saturating_sub(tolerance_us) => Some(Below::Dropped),
            _ => Some(Below::History),
        }
    }

    /// `seen` with a record handled at `time_us`.
    pub(crate) fn seen(seen: Option<i64>, time_us: i64) -> Option<i64> {
        Some(seen.map_or(time_us, |m| m.max(time_us)))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = String::from("v1\n");
        out.push_str(&format!(
            "file {}\noffset {}\nskip {}\npattern {}\n",
            self.file.as_deref().map_or("-".to_owned(), hex),
            self.offset,
            self.skip,
            self.pattern.as_deref().map_or("-".to_owned(), hex),
        ));
        if let Some(((part, ts), o)) = &self.after {
            out.push_str(&format!("after {part} {ts} {o}\n"));
        }
        if let Some(h) = self.history_us {
            out.push_str(&format!("history {h}\n"));
        }
        if let Some(c) = self.session {
            out.push_str(&format!("session {c}\n"));
        }
        if let Some(f) = self.floor {
            out.push_str(&format!("floor {f} {}\n", self.floor_set_ms));
        }
        if let Some((f, o)) = &self.buffer {
            out.push_str(&format!("buffer {} {o}\n", hex(f)));
        }
        if let Some(m) = self.max_seen_us {
            out.push_str(&format!("seen {m}\n"));
        }
        out.into_bytes()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        if lines.next()? != "v1" {
            return None;
        }
        let mut c = Self::default();
        for l in lines {
            let mut p = l.split(' ');
            match (p.next()?, p.next()?) {
                ("file", "-") => c.file = None,
                ("file", f) => c.file = Some(unhex(f)?),
                ("offset", o) => c.offset = o.parse().ok()?,
                ("skip", s) => c.skip = s.parse::<u32>().ok()?.min(MAX_SKIP),
                ("pattern", "-") => c.pattern = None,
                ("pattern", f) => c.pattern = Some(unhex(f)?),
                ("after", part) => {
                    c.after = Some((
                        (part.parse().ok()?, p.next()?.parse().ok()?),
                        p.next()?.parse().ok()?,
                    ));
                }
                ("history", h) => c.history_us = Some(h.parse().ok()?),
                ("session", v) => c.session = Some(v.parse().ok()?),
                ("floor", v) => {
                    c.floor = Some(v.parse().ok()?);
                    // Without its first start (an older cursor): ends once
                    // caught up.
                    c.floor_set_ms = match p.next() {
                        Some(t) => t.parse().ok()?,
                        None => 0,
                    };
                }
                ("buffer", f) => c.buffer = Some((unhex(f)?, p.next()?.parse().ok()?)),
                ("seen", v) => c.max_seen_us = Some(v.parse().ok()?),
                _ => return None,
            }
        }
        Some(c)
    }
}

/// The position after a read from `cursor` that returned records at
/// `positions` (in order), `full` when more may follow; and whether one
/// buffer went over [`MAX_SKIP`] (a gap). Both sources: the server skipped
/// the first `cursor.skip` records after the position, all of the buffer
/// `cursor.buffer`, and `key` orders the files of the set.
///
/// A read starts after the buffer at the position (measured), so the
/// position stays before a buffer whose records may not all have come (a
/// full read); its handled records are counted in `skip` and skipped by
/// the server next time, so a buffer of any size is walked with reads of
/// at most a batch, none read twice, none lost.
///
/// The skip counts the records read, while the server skips rows: a row
/// of the last buffer that could not be parsed (dropped and counted as
/// such) makes the next read start one row early. That row is then met
/// again (counted again), or, when it came before the buffer's first
/// record read, that record is read twice (reported twice, never lost):
/// at most one per such row (lot 3 final review L2; the same holds for
/// any full read).
pub(crate) fn next_position(
    cursor: &Cursor,
    positions: &[(String, i64)],
    full: bool,
    key: FileKey,
) -> (Cursor, bool) {
    let mut next = cursor.clone();
    if let Some(last) = positions.last() {
        let in_last = positions.iter().rev().take_while(|p| *p == last).count();
        let before = positions.len() - in_last;
        let skipped_buffer = cursor.buffer.as_ref().filter(|_| cursor.skip > 0);
        if !full {
            next.file = Some(last.0.clone());
            next.offset = last.1;
            next.skip = 0;
            next.buffer = None;
        } else if skipped_buffer == Some(last) {
            // Still the buffer whose first records were skipped.
            next.skip = cursor
                .skip
                .saturating_add(u32::try_from(in_last).unwrap_or(u32::MAX));
        } else {
            // The last buffer may continue: the position goes to the
            // buffer before it (a returned one, else the skipped one, now
            // read whole, else the position stays).
            let prev = if before > 0 {
                positions.get(before - 1).cloned()
            } else {
                skipped_buffer.cloned()
            };
            if let Some((f, o)) = prev {
                next.file = Some(f);
                next.offset = o;
            }
            next.skip = u32::try_from(in_last).unwrap_or(u32::MAX);
            next.buffer = Some(last.clone());
        }
    }
    // Nothing returned: the position and the skipped records stay. The
    // filter of a refused position ends once the read passed it, and after
    // any read that is not full (the set was read to its end).
    let passed = cursor.after.is_some_and(|(k, offset)| {
        positions
            .last()
            .and_then(|(f, o)| key(f).map(|lk| (lk, *o)))
            .is_some_and(|last| last > (k, offset))
    });
    if passed || !full {
        next.after = None;
    }
    let mut gap = false;
    if next.skip > MAX_SKIP {
        // One buffer larger than the bound: the rest of it is dropped.
        if let Some(b) = next.buffer.take() {
            next.file = Some(b.0);
            next.offset = b.1;
        }
        next.skip = 0;
        gap = true;
    }
    if !full {
        // Caught up: no history any more.
        next.history_us = None;
    }
    (next, gap)
}

/// What a read from `cursor` asks the server for: (rows, rows of the
/// next buffer skipped on the server). The records of that buffer already
/// handled are skipped on the server, so a read returns at most `batch`
/// records however large the buffer (P9-D load run: a buffer of more than
/// a read's records, read again from its start with a client-side skip
/// over a bound, lost the rest of it).
pub(crate) fn request(cursor: &Cursor, batch: usize) -> (usize, u32) {
    (batch, cursor.skip)
}

/// The size of the next read after a failed one, asked again from the
/// same position, or `None` (the error ends the stream): a response over
/// [`POLL_BYTES`] (or more rows than asked) was cancelled with the session
/// still in step, and the read halves, never below [`MIN_BATCH`]; a
/// successful read doubles it back up to [`BATCH`]. Used by both sources.
///
/// The session tells, not [`SsError::fatal`]: every client-side bound
/// sets `fatal`, so the check `!e.fatal` of 0.8.0 never halved, and a run
/// of large Extended Events events failed every read from the same
/// position until the files rolled over (fixed in 0.8.1).
pub(crate) fn halved(e: &SsError, poisoned: bool, batch: usize) -> Option<usize> {
    (e.code == FailureCode::ResourceLimit && !poisoned && batch > MIN_BATCH)
        .then(|| (batch / 2).max(MIN_BATCH))
}

/// The order key of an audit file of one file set, (timestamp,
/// partition), from `…_<partition>_<timestamp>.sqlaudit` (measured: the
/// name of the audit and its GUID, then the partition and an 18-digit
/// timestamp). Within one
/// set, files are ordered by this key, never by their path string (review
/// H1). `None` when the name has another form.
pub(crate) fn file_key(name: &str) -> Option<(i64, i64)> {
    let stem = name.strip_suffix(".sqlaudit")?;
    let (rest, ts) = stem.rsplit_once('_')?;
    let (_, part) = rest.rsplit_once('_')?;
    let num = |s: &str| {
        (!s.is_empty() && s.len() <= 18 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<i64>().ok())
            .flatten()
    };
    // Ordered by timestamp first, then partition (re-review Low).
    Some((num(ts)?, num(part)?))
}

/// The catalog's file pattern seen by a reprobe. Another pattern (the
/// folder moved, the audit renamed or recreated) is another file set: the
/// position, and any refused-position filter, are dropped and the stream
/// reads the new set from its start; `true` (a gap) when a position of
/// another set was held (review H1).
pub(crate) fn on_pattern(cursor: &mut Cursor, pattern: &str) -> bool {
    let changed = cursor.pattern.as_deref().is_some_and(|p| p != pattern);
    if changed {
        cursor.file = None;
        cursor.offset = 0;
        cursor.skip = 0;
        cursor.after = None;
        cursor.buffer = None;
    }
    cursor.pattern = Some(pattern.to_owned());
    changed
}

/// A position the server refused (error 33225) in the same file set: read
/// from the oldest file again, leaving out what was read up to the
/// position, by file key and offset. A file name of another form keeps no
/// filter (what was read is read again: loud, never lost).
pub(crate) fn on_bad_position(cursor: &mut Cursor, key: FileKey) {
    cursor.after = cursor
        .file
        .as_deref()
        .and_then(key)
        .map(|k| (k, cursor.offset));
    cursor.file = None;
    cursor.offset = 0;
    cursor.skip = 0;
    cursor.buffer = None;
}

/// What one read gives: the records to handle, the next position, and
/// the gap (records lost) it reveals.
#[derive(Debug)]
pub(crate) struct Batch<T> {
    pub(crate) kept: Vec<T>,
    pub(crate) next: Cursor,
    /// A buffer above [`MAX_SKIP`] records: the rest of it is lost.
    pub(crate) gap: bool,
    pub(crate) full: bool,
}

/// The records of a read from `cursor` (the server skipped the first
/// `cursor.skip` records after the position, [`request`]), `returned`
/// rows asked with `asked`: those at or before a refused position left
/// out, the next position, and the gap ([`next_position`]).
pub(crate) fn batch<T: Positioned>(
    cursor: &Cursor,
    records: Vec<T>,
    returned: usize,
    asked: usize,
    key: FileKey,
) -> Batch<T> {
    let positions: Vec<(String, i64)> = records
        .iter()
        .map(|r| (r.file().to_owned(), r.offset()))
        .collect();
    let mut kept = records;
    if let Some((k, offset)) = cursor.after {
        // A record of another form of name is kept (read again, loud).
        kept.retain(|r| key(r.file()).is_none_or(|rk| (rk, r.offset()) > (k, offset)));
    }
    let full = returned >= asked;
    let (next, gap) = next_position(cursor, &positions, full, key);
    Batch {
        kept,
        next,
        gap,
        full,
    }
}

/// The stream's per-run state.
struct Stream<'a> {
    target: &'a TargetConfig,
    state: &'a CheckState,
    own: OwnAccount,
    store: Option<CursorStore>,
    own_store: Option<CursorStore>,
    cursor: Cursor,
    saved: Option<Vec<u8>>,
    skip: u32,
    /// The audit named in `agent.yaml` (the catalog's name is used for the
    /// file pattern, review L6).
    name: String,
    probe: Option<probe::Probe>,
    poll_start: String,
    poll_from: String,
    reprobe_at: Instant,
    evaluated_at: Option<Instant>,
    /// Records asked per read (halved after an oversized response).
    batch: usize,
}

impl Stream<'_> {
    fn save(&mut self) {
        if let Some(store) = &self.store {
            let bytes = self.cursor.encode();
            if self.saved.as_ref() != Some(&bytes) {
                match store.save(&bytes) {
                    Ok(()) => self.saved = Some(bytes),
                    Err(e) => tracing::warn!(error = %e, "SQL Server Audit cursor not saved"),
                }
            }
        }
        if let Some(store) = &self.own_store
            && let Err(e) = store.save(&own::encode(&self.target.id, OWN_FILE_BYTES))
        {
            tracing::warn!(error = %e, "SQL Server own sessions not saved");
        }
    }

    /// Whether a statement of one of the agent's sessions is its own
    /// routine (left out), per decision 6.
    fn own_routine(&mut self, s: &Statement, ev: &MaskedEvent) -> bool {
        let verdict = self.own_verdict(s, ev);
        if let Ok(which) = verdict {
            self.state.audit.note_own(&self.target.id, which);
        }
        if let Err(why) = verdict
            && s.head.principal.eq_ignore_ascii_case(&self.target.account)
        {
            // Closed reasons, no text (the statement never reaches a log).
            tracing::debug!(
                target_id = %self.target.id,
                session_id = s.head.session_id,
                reason = why,
                "SQL Server Audit: a record of the agent's login is not its own routine"
            );
        }
        verdict.is_ok()
    }

    /// `Ok` when the statement is the agent's own routine (0: an exact
    /// text, 1: credited sampling, 2: a credited poll); otherwise the
    /// closed reason.
    fn own_verdict(&mut self, s: &Statement, ev: &MaskedEvent) -> Result<usize, &'static str> {
        let h = &s.head;
        if h.cut {
            return Err("cut text");
        }
        let Some(session) = own::session_at(&self.target.id, h.session_id, h.time_us, &h.statement)
        else {
            return Err("not one of the agent's sessions at that time");
        };
        let account = &self.target.account;
        if !h.principal.eq_ignore_ascii_case(account)
            || !h.session_principal.eq_ignore_ascii_case(account)
        {
            return Err("principals");
        }
        // Only an IP literal counts, and it must be the one the server saw
        // for that session.
        match (session.addr, h.ip()) {
            (Some(a), Some(b)) if a == b => {}
            _ => return Err("client address"),
        }
        if !h.application.is_empty() && h.application != APP {
            return Err("application name");
        }
        let user = account.as_str();
        let unbudgeted = |own: &OwnAccount, which: usize| {
            if own.routine_unbudgeted(user, None, ClientSeen::NotRecorded, ev) {
                Ok(which)
            } else {
                Err("not a read, or a signal")
            }
        };
        if ev.action() == EventAction::Connect {
            return unbudgeted(&self.own, 0);
        }
        match sql::own_text(&h.statement) {
            OwnText::Exact => {
                // A listed (always-reported) object is the agent's only
                // through its one-bit password_hash probe or its Extended
                // Events status read.
                if ev.always_report() && !sql::own_listed_read(&h.statement) {
                    return Err("always-reported object");
                }
                unbudgeted(&self.own, 0)
            }
            OwnText::NeedsCredit | OwnText::No => {
                let poll = if *h.statement == *self.poll_start && !self.poll_start.is_empty() {
                    Some(own::PollKind::Start)
                } else if *h.statement == *self.poll_from && !self.poll_from.is_empty() {
                    Some(own::PollKind::From)
                } else {
                    None
                };
                if !own::take_credit(
                    &self.target.id,
                    h.session_id,
                    &h.statement,
                    poll,
                    h.time_us,
                    h.transaction,
                ) {
                    return Err("no credit for this text");
                }
                if poll.is_some() {
                    // Its record names fn_get_audit_file (a statement-text
                    // object): the agent's own only through the credit of
                    // this exact text from its session (decision 6).
                    unbudgeted(&self.own, 2)
                } else if ev.always_report() {
                    Err("always-reported object")
                } else if self
                    .own
                    .routine(user, None, ClientSeen::NotRecorded, ev, Instant::now())
                {
                    // Sampling: charged the whole per-object budget (no
                    // row count on this source).
                    Ok(1)
                } else {
                    Err("over the own-read budget, or a signal")
                }
            }
        }
    }
}

/// `Connector::audit_stream` for SQL Server.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg
        .target()
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    let settings = target.sqlserver_settings();
    let audit_name = probe::audit_name(settings.audit.as_ref()).map(str::to_owned);
    let xe_name = xe::probe::session_name(settings.audit.as_ref()).map(str::to_owned);
    if audit_name.is_none() && xe_name.is_none() {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: no server audit nor Extended Events session named in agent.yaml (sqlserver.audit)");
        return Err(target_error(FailureCode::Unsupported));
    }
    let _running = state.audit.started(&target.id);
    let _streaming = own::stream_started(&target.id);
    let own_store = cfg.counters(OWN_SESSIONS);
    if let Some(Ok(Some(bytes))) = own_store.as_ref().map(CursorStore::load)
        && let Some(persisted) = own::decode(&bytes)
    {
        own::restore(&target.id, persisted);
    }
    let tls = tls::configs(settings.ca_file.as_deref())
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    let mut session = conn::connect(target, &tls, &state.choice, POLL_TIMEOUT)
        .await
        .map_err(SsError::into_connector_error)?;
    // The preference rule (decision 6): SQL Server Audit when usable, then
    // the Extended Events session.
    let use_audit = match (&audit_name, &xe_name) {
        (Some(_), None) => true,
        (None, _) => false,
        (Some(_), Some(_)) => {
            let chosen = async {
                let v = check::version(&mut session).await?;
                let ev = Box::pin(check::evaluate(&mut session, target)).await?;
                Box::pin(xe::audit_usable(
                    &mut session,
                    target,
                    v.major,
                    &ev.server_perms,
                ))
                .await
            };
            match Box::pin(chosen).await {
                Ok(usable) => usable,
                Err(e) => {
                    session.close().await;
                    return Err(e.into_connector_error());
                }
            }
        }
    };
    let name = match (use_audit, audit_name, xe_name) {
        (true, Some(name), _) => name,
        (_, _, Some(xe)) => {
            state.audit.stream_source(&target.id, Source::Xevents);
            return Box::pin(xe::stream(cfg, sink, state, target, session, xe)).await;
        }
        (_, Some(name), None) => name,
        (_, None, None) => return Err(target_error(FailureCode::Unsupported)),
    };
    state.audit.stream_source(&target.id, Source::Audit);
    let store = cfg.cursor(CURSOR);
    let loaded = match store.as_ref().map(CursorStore::load) {
        Some(Ok(Some(bytes))) => {
            let c = Cursor::decode(&bytes);
            if c.is_none() {
                // A position that cannot be used: what was not read is
                // lost (review L1).
                tracing::warn!(target_id = %target.id, "SQL Server Audit cursor not understood: starting at the end of the audit (a gap)");
                state.audit.note_gap(&target.id);
                state.audit.note_dropped(&target.id, 1);
            }
            c
        }
        Some(Err(e)) => {
            tracing::warn!(error = %e, "SQL Server Audit cursor not readable: starting at the end of the audit (a gap)");
            state.audit.note_gap(&target.id);
            state.audit.note_dropped(&target.id, 1);
            None
        }
        _ => None,
    };
    let skip = store.as_ref().map_or(0, CursorStore::skip_records);
    let first_start = loaded.is_none();
    let mut cursor = loaded.unwrap_or_default();
    if cursor.skip > 0 && cursor.buffer.is_none() {
        // A position saved before the server-side skip, without its
        // buffer: that buffer is read again from its start (read twice,
        // loud, never lost).
        cursor.skip = 0;
    }
    if first_start {
        // No history replay: what the audit holds from before now.
        cursor.first_start(session.own.as_ref().map(own::Handle::server_now), 0);
    }
    let mut st = Stream {
        name,
        target,
        state,
        own: OwnAccount::new(
            &target.account,
            None,
            None,
            u64::from(cfg.max_sample_rows()),
            state.audit.own_usage(&target.id),
        )
        .persisted(cfg),
        store,
        own_store,
        cursor,
        saved: None,
        skip,
        probe: None,
        poll_start: String::new(),
        poll_from: String::new(),
        reprobe_at: Instant::now(),
        evaluated_at: None,
        batch: BATCH,
    };
    loop {
        if session.is_poisoned() || session.is_stale() {
            let old = std::mem::replace(
                &mut session,
                conn::connect(target, &tls, &state.choice, POLL_TIMEOUT)
                    .await
                    .map_err(SsError::into_connector_error)?,
            );
            old.close().await;
        }
        let r = Box::pin(cycle(&mut st, &mut session, sink)).await;
        if let Err(e) = r {
            st.save();
            session.close().await;
            return Err(e);
        }
        st.save();
        tokio::time::sleep(cfg.poll_interval()).await;
    }
}

/// One cycle: the proofs when due, then reads until caught up.
async fn cycle(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
) -> Result<(), ConnectorError> {
    let target = st.target;
    if st.evaluated_at.is_none_or(|t| t.elapsed() >= REEVALUATE) {
        let v = check::version(s)
            .await
            .map_err(SsError::into_connector_error)?;
        if v.major < probe::MIN_AUDIT_MAJOR {
            tracing::warn!(target_id = %target.id, "SQL Server Audit needs SQL Server 2022 or later (CONTROL SERVER before): no Audit source");
            return Err(target_error(FailureCode::Unsupported));
        }
        let ev = Box::pin(check::evaluate(s, target))
            .await
            .map_err(SsError::into_connector_error)?;
        if ev.blocks() {
            tracing::warn!(target_id = %target.id, "the account holds a right of the refusal list (privilege.refused): Audit refused");
            return Err(target_error(FailureCode::PermissionDenied));
        }
        if !probe::SOURCE_GRANTS
            .iter()
            .all(|g| ev.server_perms.contains(*g))
        {
            tracing::warn!(target_id = %target.id, "SQL Server Audit needs VIEW SERVER SECURITY AUDIT and VIEW ANY SECURITY DEFINITION");
            return Err(target_error(FailureCode::PermissionDenied));
        }
        st.evaluated_at = Some(Instant::now());
        st.probe = None;
    }
    if st.probe.is_none() || st.reprobe_at.elapsed() >= REPROBE {
        Box::pin(reprobe(st, s)).await?;
    }
    let started = Instant::now();
    let mut history_reads = 0usize;
    loop {
        let in_history = st.cursor.history_us.is_some();
        let full = Box::pin(read(st, s, sink)).await?;
        st.save();
        history_reads += usize::from(in_history);
        if !full || started.elapsed() >= CATCH_UP || history_reads >= HISTORY_READS {
            break;
        }
        if st.probe.is_none() {
            Box::pin(reprobe(st, s)).await?;
        }
    }
    Ok(())
}

/// Reads the catalog proofs and rebuilds the poll texts.
async fn reprobe(st: &mut Stream<'_>, s: &mut Session) -> Result<(), ConnectorError> {
    let target = st.target;
    let (dbs, _) = check::monitored_databases(s, target)
        .await
        .map_err(SsError::into_connector_error)?;
    let p = Box::pin(probe::probe(s, &st.name, &dbs, Stage::Introspection))
        .await
        .map_err(SsError::into_connector_error)?;
    if !p.found {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the named server audit has no FILE target or is invisible");
        return Err(target_error(FailureCode::Unsupported));
    }
    let Some(pattern) = p.pattern() else {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the audit's folder or name cannot be used in a file pattern");
        return Err(target_error(FailureCode::Unsupported));
    };
    let (Some(start), Some(from)) = (
        sql::audit_poll(&pattern, false),
        sql::audit_poll(&pattern, true),
    ) else {
        return Err(target_error(FailureCode::Internal));
    };
    if on_pattern(&mut st.cursor, &pattern) {
        // Another file set (the folder moved, the audit recreated or
        // renamed): read from its start; what was written meanwhile in
        // the old set after the position is lost (review H1).
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the audit's file set changed (folder, name or GUID): reading the new set from its start");
        st.state.audit.note_gap(&target.id);
        st.state.audit.note_dropped(&target.id, 1);
    }
    st.poll_start = start;
    st.poll_from = from;
    st.probe = Some(p);
    st.reprobe_at = Instant::now();
    Ok(())
}

/// What one poll returned: the records, the rows, the malformed rows.
struct Polled {
    records: Vec<Record>,
    returned: usize,
    malformed: u64,
}

/// Sends one poll (the first `skip` records after the position skipped on
/// the server, at most `top` returned); each row becomes a record as it
/// ends (review L5: no copy of the rows is held), alone under panic
/// isolation.
async fn poll_records(
    s: &mut Session,
    text: &str,
    kind: own::PollKind,
    file: &str,
    offset: i64,
    top: usize,
    skip: u32,
) -> Result<Polled, SsError> {
    let params = [
        Param::NVarChar(file.to_owned()),
        Param::BigInt(offset),
        Param::BigInt(i64::try_from(top).unwrap_or(i64::MAX)),
        Param::BigInt(i64::from(skip)),
    ];
    s.credit_poll(text, kind);
    let mut out = Polled {
        records: Vec::new(),
        returned: 0,
        malformed: 0,
    };
    let mut row: Vec<Value> = Vec::with_capacity(sql::AUDIT_POLL_COLUMNS);
    s.rpc(
        text,
        &params,
        Stage::Introspection,
        Shape {
            columns: sql::AUDIT_POLL_COLUMNS,
            max_rows: top,
            max_bytes: POLL_BYTES,
            plp_cap: 0,
        },
        |cell| {
            match cell {
                Cell::Value(_, v) => row.push(v),
                Cell::RowEnd => {
                    out.returned += 1;
                    let r = std::mem::take(&mut row);
                    match databastion_core::isolate(|| Record::from_row(r)) {
                        Some(Ok(rec)) => out.records.push(rec),
                        _ => out.malformed += 1,
                    }
                }
            }
            Flow::Continue
        },
    )
    .await?;
    Ok(out)
}

/// One read from the position; `true` when it was full (more to read).
async fn read(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
) -> Result<bool, ConnectorError> {
    let target_id = st.target.id.clone();
    let read_started_ms = agent_now_ms();
    // The audit's delivery delay (`QUEUE_DELAY`): the history and floor
    // bound.
    let delay = st.probe.as_ref().map_or(FLOOR_MAX, |p| p.queue_delay);
    // The server skips the records of the next buffer already handled.
    let (top, skip) = request(&st.cursor, st.batch);
    let polled = match st.cursor.file.clone() {
        // Boxed: the poll's future is large (a debug build's stack).
        None => {
            Box::pin(poll_records(
                s,
                &st.poll_start.clone(),
                own::PollKind::Start,
                "",
                0,
                top,
                skip,
            ))
            .await
        }
        Some(f) => {
            Box::pin(poll_records(
                s,
                &st.poll_from.clone(),
                own::PollKind::From,
                &f,
                st.cursor.offset,
                top,
                skip,
            ))
            .await
        }
    };
    let polled = match polled {
        Ok(p) => {
            st.batch = (st.batch * 2).min(BATCH);
            p
        }
        Err(e) if e.number == Some(ERR_BAD_POSITION) && st.cursor.file.is_some() => {
            // The position is no longer in the file set. Another set (the
            // folder moved…) is found by the proofs first; in the same set
            // (rolled over), read from the oldest file, leaving out what
            // was read; whatever was between is lost (M4, review H1).
            let before = st.cursor.pattern.clone();
            // Boxed: the proofs' future is large (a debug build's stack).
            Box::pin(reprobe(st, s)).await?;
            if st.cursor.pattern == before && st.cursor.file.is_some() {
                tracing::warn!(target_id = %target_id, "SQL Server Audit: the saved position is no longer in the audit's file set (rollover): reading from the oldest file");
                on_bad_position(&mut st.cursor, file_key);
                st.state.audit.note_gap(&target_id);
                st.state.audit.note_dropped(&target_id, 1);
            }
            return Ok(true);
        }
        Err(e) => {
            if let Some(smaller) = halved(&e, s.is_poisoned(), st.batch) {
                // A response over the bound: smaller reads, same position.
                st.batch = smaller;
                return Ok(true);
            }
            return Err(e.into_connector_error());
        }
    };
    st.state.audit.note_dropped(&target_id, polled.malformed);
    let b = batch(&st.cursor, polled.records, polled.returned, top, file_key);
    // Freshness from parsed records only (re-review Low).
    if !b.kept.is_empty() {
        st.state.audit.note_record(&target_id);
    }
    let mut statements = records::group(records::reassemble(b.kept));
    if st.skip > 0 {
        let n = (st.skip as usize).min(statements.len());
        statements.drain(..n);
        st.state.audit.note_dropped(&target_id, n as u64);
        st.skip = 0;
    }
    let mut reprobe = false;
    let mut below_floor = 0u64;
    let mut seen = st.cursor.max_seen_us;
    for stmt in &statements {
        let class = st.cursor.below(stmt.head.time_us, seen, delay);
        seen = Cursor::seen(seen, stmt.head.time_us);
        match class {
            Some(Below::History) => continue,
            Some(Below::Dropped) => {
                below_floor += 1;
                continue;
            }
            None => {}
        }
        match records::map(&stmt.head.action, &stmt.head.class) {
            Mapped::Restart => {
                tracing::warn!(target_id = %target_id, "SQL Server Audit: the audit was started or stopped (AUSC record): what happened in between was not recorded");
                st.state.audit.note_gap(&target_id);
                st.state.audit.note_dropped(&target_id, 1);
                continue;
            }
            Mapped::Ignored => continue,
            Mapped::Event(_) => {}
        }
        if records::is_audit_change(stmt) {
            reprobe = true;
        }
        let out = databastion_core::isolate(|| {
            let (ev, _) = records::convert(stmt)?;
            if st.own_routine(stmt, &ev) {
                return None;
            }
            Some(ev)
        });
        match out {
            Some(Some(ev)) => sink.submit(ev).await?,
            Some(None) => {}
            None => st.state.audit.note_dropped(&target_id, 1),
        }
    }
    if below_floor > 0 {
        tracing::warn!(target_id = %target_id, below_floor, "SQL Server Audit: records stamped before the first start read after the stream caught up (late, or the server's clock stepped back): not reported, counted as dropped");
        st.state.audit.note_dropped(&target_id, below_floor);
    }
    let prev_history = st.cursor.history_us;
    st.cursor = b.next;
    st.cursor.max_seen_us = seen;
    if !b.full {
        st.cursor.settle(prev_history, read_started_ms, delay);
    }
    if b.gap {
        tracing::warn!(target_id = %target_id, "SQL Server Audit: one buffer holds more records than the bound: the rest of it is dropped");
        st.state.audit.note_gap(&target_id);
        st.state.audit.note_dropped(&target_id, 1);
    }
    if reprobe {
        // An AUDIT_CHANGE_GROUP record: the proofs at once (re-review N3).
        st.probe = None;
    }
    Ok(b.full)
}

#[cfg(test)]
mod tests;
