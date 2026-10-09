//! Degraded Audit through `performance_schema` (level Partial with
//! `events_statements_history_long`, Limited with the per-thread
//! `events_statements_history` or `events_statements_current`): the
//! statement history is polled and each new statement becomes an event.
//!
//! What it can attribute: the statement (its digest text, or its text when
//! the server computed no digest), its current database, the rows it
//! returned or affected, its error, and, while the session is still
//! connected, its account, client host and `program_name`. What it cannot:
//! the account of a session that ended before the poll (reported as an
//! unidentified account, a `db_user` fingerprint), and statements pushed
//! out of the ring buffer between two polls (counted and logged).
//!
//! Queries: one statement each, autocommit under the session's read-only
//! default, `performance_schema` tables only (the ADR-0018 Audit grant).
//! `DIGEST_TEXT` is read first: the server has already replaced its
//! literals; `SQL_TEXT` (which holds literals, and on MariaDB clear-text
//! passwords of `CREATE USER` / `SET PASSWORD` / `CHANGE MASTER`) is only
//! read when a statement has no digest. Both go to the query normalizer
//! only, in zeroizing buffers.
//!
//! Cursor: the end timer (`TIMER_END`, picoseconds since the server
//! started) of the newest statement read, and the statements already read
//! within the overlap. Statements finishing out of order are caught by
//! re-reading the last [`OVERLAP_PS`] picoseconds, deduplicated on
//! (thread, event id). A restarted server (timers back at zero) is read
//! from its start.
//!
//! The cursor is persisted through the core (`performance_schema` cursor
//! file: timers and ids only, never a statement) with the server's start
//! time (`Uptime` against the agent's clock), after the events of each
//! poll are handed over, so an agent restart resumes where it stopped:
//! - same server run (start times within [`BOOT_TOLERANCE_S`]): the
//!   statements since the saved cursor are read (what the history still
//!   holds; the ring buffer may have wrapped meanwhile, which is counted);
//! - another server run: its statements are read from its start;
//! - no saved cursor, or the start time unknown: the first poll starts at
//!   the newest statement (no history is replayed).
//!
//! The sessions' accounts are not persisted: a statement of a session that
//! ended while the agent was stopped is reported as an unidentified
//! account.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::{ClientAddr, EventPrincipal, EventSource};
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::ClientSeen;
use databastion_core::{EventSink, FailureCode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::events::{Access, EventBuilder};
use crate::conn::{Flow, Session, Streamed};
use crate::error::{MyError, Stage};
use crate::sql;

/// Statements read per query.
const BATCH: usize = 2000;
/// Queries per poll at most (then the next poll continues).
const MAX_BATCHES: usize = 10;
/// Re-read window for statements finishing out of order.
const OVERLAP_PS: u64 = 2_000_000_000_000;
/// Sessions whose account is remembered after they end.
const MAX_THREADS: usize = 4096;
/// Default text limits (`performance_schema_max_sql_text_length`,
/// `performance_schema_max_digest_length`).
const DEFAULT_TEXT_LIMIT: usize = 1024;
/// Largest text read per statement, whatever the server limits say.
const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Name of the persisted cursor.
pub(crate) const CURSOR: &str = "performance_schema";
/// Two server start times (Unix seconds, from `Uptime` and the agent's
/// clock) this close are the same server run.
const BOOT_TOLERANCE_S: u64 = 120;
/// Statements of the overlap kept in the saved cursor at most (the newest;
/// the saved `floor` then keeps the older ones from being read again).
const MAX_SAVED_SEEN: usize = 800;
/// Version of the saved cursor.
const CURSOR_VERSION: u32 = 1;

/// The saved cursor: timers and ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    v: u32,
    /// Server start time (Unix seconds).
    boot: u64,
    /// End timer of the newest statement read.
    last: u64,
    /// Statements before this timer are not read again (the saved `seen`
    /// was cut).
    floor: Option<u64>,
    /// (thread, event id, end timer) of the statements read within the
    /// overlap.
    seen: Vec<(u64, u64, u64)>,
}

/// Statement table polled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PsTable {
    HistoryLong,
    History,
    Current,
}

impl PsTable {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::HistoryLong => "events_statements_history_long",
            Self::History => "events_statements_history",
            Self::Current => "events_statements_current",
        }
    }
}

/// Why a poll stopped.
#[derive(Debug)]
pub(crate) enum PollError {
    Db(MyError),
    SinkClosed,
}

impl From<MyError> for PollError {
    fn from(e: MyError) -> Self {
        Self::Db(e)
    }
}

#[derive(Clone)]
struct ThreadInfo {
    user: String,
    host: String,
    program: Option<String>,
}

/// Largest token of a stored digest: an identifier of 64 characters of 4
/// bytes and its 4-byte header.
pub(crate) const MAX_DIGEST_TOKEN: usize = 4 + 64 * 4;

/// Upper estimate of the bytes a rendered `DIGEST_TEXT` took in the
/// server's digest token storage, which is what the digest limit bounds
/// (security review of 914c9d2, N1): an identifier is stored in 4 bytes
/// plus its name but rendered in its name plus 3 (`` `a` ``), other tokens
/// in 2 bytes. Each space-separated chunk counts 2, a backquoted
/// identifier 4 plus its name, and a chunk holding a backquote or `@`
/// that is not one identifier 4 plus its length. Never more than 3 times
/// the rendered length plus 3 (see [`sql_text_from`]).
pub(crate) fn digest_stored_estimate(d: &[u8]) -> usize {
    let mut est = 0usize;
    let mut i = 0;
    while i < d.len() {
        if d[i] == b' ' {
            i += 1;
            continue;
        }
        let start = i;
        if d[i] == b'`' {
            // `…` with doubled backquotes inside.
            let mut j = i + 1;
            let mut name = 0usize;
            while j < d.len() {
                if d[j] == b'`' {
                    if d.get(j + 1) == Some(&b'`') {
                        name += 1;
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                name += 1;
                j += 1;
            }
            if j >= d.len() || d[j] == b' ' {
                est = est.saturating_add(4 + name);
                i = j;
                continue;
            }
        }
        while i < d.len() && d[i] != b' ' {
            i += 1;
        }
        let chunk = &d[start..i];
        est = est.saturating_add(if chunk.iter().any(|b| matches!(b, b'`' | b'@')) {
            4 + chunk.len()
        } else {
            2
        });
    }
    est
}

/// Whether a `DIGEST_TEXT` may have been cut: its estimated storage is
/// within one largest token of `limit`, or [`text_cut`] holds.
pub(crate) fn digest_cut(d: &[u8], limit: usize) -> bool {
    text_cut(d, true, limit) || digest_stored_estimate(d).saturating_add(MAX_DIGEST_TOKEN) >= limit
}

/// Digest length (bytes) from which the poll also reads `SQL_TEXT`: every
/// digest that [`digest_cut`] may judge cut by its estimate is at least
/// this long (the estimate is at most 3 times the length plus 3).
pub(crate) fn sql_text_from(digest_limit: usize) -> usize {
    digest_limit.saturating_sub(MAX_DIGEST_TOKEN + 3) / 3
}

/// The text a statement row is analyzed with, and whether it may have been
/// cut (security review of 914c9d2, N1): `SQL_TEXT` when the poll read it
/// and it is not cut (whole, literals included: the analyzer normalizes
/// them); else the digest when it is not cut; else a cut text (the digest,
/// or `SQL_TEXT` without a digest), reported as a read of `*` when it has
/// no table record. A text past [`MAX_TEXT_BYTES`] is dropped, and cut.
pub(crate) fn choose_text<'a>(
    digest: Option<&'a [u8]>,
    sql_text: Option<&'a [u8]>,
    text_limit: usize,
    digest_limit: usize,
) -> (Option<&'a [u8]>, bool) {
    let (text, cut) = match (digest, sql_text) {
        (_, Some(s)) if !text_cut(s, false, text_limit) => (Some(s), false),
        (Some(d), _) => (Some(d), digest_cut(d, digest_limit)),
        (None, Some(s)) => (Some(s), true),
        (None, None) => (None, false),
    };
    match text {
        Some(t) if t.len() > MAX_TEXT_BYTES => (None, true),
        t => (t, cut),
    }
}

/// Whether a statement text (`SQL_TEXT`) or digest text (`DIGEST_TEXT`) of
/// `performance_schema` may have been cut at the server's `limit` (bytes):
/// within 4 bytes of it, or longer than it (a text past
/// [`MAX_TEXT_BYTES`] is dropped, and still cut), or a digest ending in
/// `...`. A digest spaces its tokens: one cut at its token storage limit
/// can render longer than the limit, without `...` (measured on MySQL 8.4
/// and MariaDB 11.4). A cut text with no table record is reported as a
/// read of `*` (`events::EventBuilder::statement`).
pub(crate) fn text_cut(t: &[u8], is_digest: bool, limit: usize) -> bool {
    t.len() + 4 >= limit || t.len() > MAX_TEXT_BYTES || (is_digest && t.ends_with(b"..."))
}

/// One statement row (the text in a zeroizing buffer).
struct Row {
    thread: u64,
    event: u64,
    timer_end: u64,
    schema: String,
    /// Raw bytes (analyzed by `query::analyze_raw`).
    text: Option<Zeroizing<Vec<u8>>>,
    /// The text may have been cut at the server's limit.
    truncated: bool,
    rows: u64,
    errno: u32,
    thread_info: Option<ThreadInfo>,
    background: bool,
}

/// Poller state kept across polls.
pub(crate) struct PsPoller {
    table: PsTable,
    own_thread: u64,
    text_limit: usize,
    digest_limit: usize,
    with_program: bool,
    last: Option<u64>,
    seen: HashMap<(u64, u64), u64>,
    threads: HashMap<u64, ThreadInfo>,
    thread_order: VecDeque<u64>,
    builder: EventBuilder,
    /// Polls where the ring buffer had wrapped past the cursor.
    pub(crate) wrapped: u64,
    /// Statements whose conversion failed (dropped, counted).
    pub(crate) panicked: u64,
    /// Where the cursor is persisted (`None`: in memory only).
    store: Option<CursorStore>,
    /// Server start time (Unix seconds), `None` when unknown (the cursor
    /// is then not saved).
    boot: Option<u64>,
    /// First poll after a restore from a cut `seen`: no statement before.
    floor: Option<u64>,
    /// The cursor last saved.
    saved: Option<Saved>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The server's start time: now minus `Uptime`.
async fn server_boot(session: &mut Session) -> Result<Option<u64>, MyError> {
    let rows = match session.query(Stage::Audit, sql::SERVER_UPTIME).await {
        Ok(rows) => rows,
        Err(e) if !e.fatal => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(rows
        .first()
        .and_then(|r| r.get(1).cloned().flatten())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|uptime| unix_now().saturating_sub(uptime)))
}

/// Where polling resumes after a restart: `(last, seen, floor)`.
type Resume = (Option<u64>, HashMap<(u64, u64), u64>, Option<u64>);

/// The resume point from a saved cursor (see the module documentation).
fn resume(saved: Option<Saved>, boot: Option<u64>) -> Resume {
    match (saved, boot) {
        (Some(s), Some(b)) if s.v == CURSOR_VERSION && s.boot.abs_diff(b) <= BOOT_TOLERANCE_S => {
            let seen = s.seen.iter().map(|(t, e, te)| ((*t, *e), *te)).collect();
            (Some(s.last), seen, s.floor)
        }
        (Some(s), Some(_)) if s.v == CURSOR_VERSION => {
            tracing::info!(
                "performance_schema: the server restarted while the agent was stopped; \
                 reading its statements from its start"
            );
            (Some(0), HashMap::new(), None)
        }
        _ => (None, HashMap::new(), None),
    }
}

/// The cursor to save: the newest [`MAX_SAVED_SEEN`] statements of the
/// overlap, and a floor when some were left out. `None` while the server's
/// start time or the position is unknown.
fn to_save(boot: Option<u64>, last: Option<u64>, seen: &HashMap<(u64, u64), u64>) -> Option<Saved> {
    let (boot, last) = (boot?, last?);
    let mut seen: Vec<(u64, u64, u64)> = seen.iter().map(|((t, e), te)| (*t, *e, *te)).collect();
    seen.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
    let floor = (seen.len() > MAX_SAVED_SEEN).then(|| seen[MAX_SAVED_SEEN - 1].2);
    seen.truncate(MAX_SAVED_SEEN);
    Some(Saved {
        v: CURSOR_VERSION,
        boot,
        last,
        floor,
        seen,
    })
}

fn load(store: Option<&CursorStore>) -> Option<Saved> {
    match store?.load() {
        Ok(Some(bytes)) => match serde_json::from_slice::<Saved>(&bytes) {
            Ok(s) => Some(s),
            Err(_) => {
                tracing::warn!("performance_schema cursor not understood: starting at the newest");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "performance_schema cursor not readable");
            None
        }
    }
}

fn num(v: Option<&[u8]>) -> Option<u64> {
    std::str::from_utf8(v?).ok()?.parse().ok()
}

fn text(v: Option<&[u8]>, limit: usize) -> Option<String> {
    let v = v?;
    if v.len() > limit {
        return None;
    }
    Some(String::from_utf8_lossy(v).into_owned())
}

async fn scalar(session: &mut Session, statement: &str) -> Result<Option<String>, MyError> {
    match session.query(Stage::Audit, statement).await {
        Ok(rows) => Ok(rows
            .into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .flatten()),
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

impl PsPoller {
    /// Starts polling `table` on `session` (its own thread is left out),
    /// from the cursor saved in `store` when it is of the same server run
    /// (see the module documentation).
    pub(crate) async fn start(
        session: &mut Session,
        table: PsTable,
        builder: EventBuilder,
        store: Option<CursorStore>,
    ) -> Result<Self, MyError> {
        let own_thread = scalar(session, sql::PS_OWN_THREAD)
            .await?
            .and_then(|v| v.parse().ok())
            .ok_or(MyError::new(FailureCode::Unsupported, Stage::Audit))?;
        let limit = |v: Option<String>| {
            v.and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_TEXT_LIMIT)
                .min(MAX_TEXT_BYTES)
        };
        let text_limit = limit(scalar(session, sql::PS_TEXT_LIMIT).await?);
        if text_limit < sql::CAS_GUARD_MAX_STATEMENT + 4 {
            tracing::warn!(
                limit = text_limit,
                "performance_schema_max_sql_text_length below the agent's longest statement: \
                 its CAS store guard statements are cut and reported as its own reads; keep \
                 it at 1024 or more"
            );
        }
        // A digest is cut at the smaller of the parser's storage and
        // performance_schema's limit (security review of 914c9d2, N1).
        let ps_digest = scalar(session, sql::PS_DIGEST_LIMIT).await?;
        let parser_digest = scalar(session, sql::MAX_DIGEST_LIMIT).await?;
        let digest_limit = limit(ps_digest).min(limit(parser_digest));
        let boot = server_boot(session).await?;
        let mut saved = load(store.as_ref());
        let (last, seen, floor) = resume(saved.clone(), boot);
        if boot.is_none() && saved.is_some() {
            // The saved cursor cannot be matched to a server run: it is
            // not used, and removed rather than left to be resumed later
            // against another run (#88 review L4).
            tracing::warn!(
                "performance_schema: server start time unknown; the saved cursor is dropped \
                 and reading starts at the newest statement"
            );
            if let Some(Err(e)) = store.as_ref().map(CursorStore::remove) {
                tracing::warn!(error = %e, "performance_schema cursor not removed");
            }
            saved = None;
        }
        Ok(Self {
            table,
            own_thread,
            text_limit,
            digest_limit,
            with_program: true,
            last,
            seen,
            threads: HashMap::new(),
            thread_order: VecDeque::new(),
            builder,
            wrapped: 0,
            panicked: 0,
            store,
            boot,
            floor,
            saved,
        })
    }

    /// Saves the cursor when it moved (after the poll's events were handed
    /// over: delivery stays at most once).
    fn save(&mut self) {
        let Some(store) = &self.store else {
            return;
        };
        let Some(cursor) = to_save(self.boot, self.last, &self.seen) else {
            return;
        };
        if self.saved.as_ref() == Some(&cursor) {
            return;
        }
        let Ok(bytes) = serde_json::to_vec(&cursor) else {
            return;
        };
        match store.save(&bytes) {
            Ok(()) => self.saved = Some(cursor),
            Err(e) => tracing::warn!(error = %e, "performance_schema cursor not saved"),
        }
    }

    /// The agent's address as the server sees it (refreshed at each
    /// re-probe).
    pub(crate) fn set_own_addr(&mut self, addr: Option<ClientAddr>) {
        self.builder.set_own_addr(addr);
    }

    /// Re-attaches the poller to a new session (reconnection): the
    /// cursor is kept, the own thread is read again.
    pub(crate) async fn reattach(&mut self, session: &mut Session) -> Result<(), MyError> {
        self.own_thread = scalar(session, sql::PS_OWN_THREAD)
            .await?
            .and_then(|v| v.parse().ok())
            .ok_or(MyError::new(FailureCode::Unsupported, Stage::Audit))?;
        Ok(())
    }

    fn remember(&mut self, thread: u64, info: &ThreadInfo) {
        if !self.threads.contains_key(&thread) {
            if self.threads.len() >= MAX_THREADS
                && let Some(old) = self.thread_order.pop_front()
            {
                self.threads.remove(&old);
            }
            self.thread_order.push_back(thread);
        }
        self.threads.insert(thread, info.clone());
    }

    /// Reads one batch of rows.
    async fn read_rows(&mut self, session: &mut Session, from: u64) -> Result<Vec<Row>, MyError> {
        let statement = sql::ps_statements(
            self.table.name(),
            self.own_thread,
            from,
            BATCH,
            self.with_program,
            sql_text_from(self.digest_limit),
        );
        let (text_limit, digest_limit) = (self.text_limit, self.digest_limit);
        let mut rows: Vec<Row> = Vec::new();
        let streamed = session
            .query_stream(Stage::Audit, &statement, |r| {
                if rows.len() >= BATCH {
                    return Flow::Stop;
                }
                let get = |i: usize| r.get(i).copied().flatten();
                let (Some(thread), Some(event), Some(timer_end)) =
                    (num(get(0)), num(get(1)), num(get(2)))
                else {
                    return Flow::Continue;
                };
                let (chosen, truncated) = choose_text(get(4), get(5), text_limit, digest_limit);
                let body = chosen.map(|t| Zeroizing::new(t.to_vec()));
                let user = text_of(get(9));
                let thread_info = user.map(|user| ThreadInfo {
                    user,
                    host: text_of(get(10)).unwrap_or_default(),
                    program: text_of(get(12)),
                });
                rows.push(Row {
                    thread,
                    event,
                    timer_end,
                    schema: text(get(3), 1024).unwrap_or_default(),
                    truncated,
                    text: body,
                    rows: num(get(6)).unwrap_or(0).max(num(get(7)).unwrap_or(0)),
                    errno: num(get(8)).and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
                    thread_info,
                    background: get(11) == Some(b"BACKGROUND".as_slice()),
                });
                Flow::Continue
            })
            .await;
        match streamed {
            Ok(Streamed::Complete) => Ok(rows),
            Ok(Streamed::Stopped) => Err(MyError::new(FailureCode::ResourceLimit, Stage::Audit)),
            Err(e) if !e.fatal && self.with_program => {
                // `session_connect_attrs` not readable: poll without the
                // program name.
                self.with_program = false;
                tracing::info!("performance_schema session attributes not readable");
                Box::pin(self.read_rows(session, from)).await
            }
            Err(e) => Err(e),
        }
    }

    /// One poll: new statements to events, submitted to `sink`.
    pub(crate) async fn poll(
        &mut self,
        session: &mut Session,
        sink: &EventSink,
    ) -> Result<(), PollError> {
        let stats = sql::ps_stats(self.table.name(), self.own_thread);
        let row = session
            .query(Stage::Audit, &stats)
            .await?
            .into_iter()
            .next()
            .unwrap_or_default();
        let now = SystemTime::now();
        let cell = |i: usize| -> Option<u64> { row.get(i)?.as_deref()?.parse().ok() };
        let (current, min, max) = (cell(0), cell(1), cell(2));
        let Some(mut last) = self.last else {
            // First poll: start at the newest statement.
            self.last = Some(max.unwrap_or(0));
            self.save();
            return Ok(());
        };
        if max.is_some_and(|m| m < last) || current.is_some_and(|c| c < last) {
            tracing::info!(
                "performance_schema timers restarted (server restart); reading from the start"
            );
            last = 0;
            self.seen.clear();
            self.floor = None;
            // A new server run: its start time goes with the cursor.
            self.boot = server_boot(session).await?;
        }
        if self.table == PsTable::HistoryLong && last > 0 && min.is_some_and(|m| m > last) {
            self.wrapped += 1;
            tracing::warn!(
                "performance_schema statement history wrapped between two polls: statements \
                 may be missing (poll more often or raise \
                 performance_schema_events_statements_history_long_size)"
            );
        }
        let ts_of = |timer_end: u64| -> SystemTime {
            match current {
                Some(c) if c >= timer_end => now
                    .checked_sub(Duration::from_nanos((c - timer_end) / 1000))
                    .unwrap_or(now),
                _ => now,
            }
        };
        let mut from = last.saturating_sub(OVERLAP_PS);
        if let Some(floor) = self.floor.take() {
            from = from.max(floor);
        }
        let mut events = Vec::new();
        for _ in 0..MAX_BATCHES {
            let rows = self.read_rows(session, from).await?;
            let full = rows.len() >= BATCH;
            let mut batch_max = from;
            for r in rows {
                batch_max = batch_max.max(r.timer_end);
                if self.seen.insert((r.thread, r.event), r.timer_end).is_some() {
                    continue;
                }
                last = last.max(r.timer_end);
                if r.background {
                    continue;
                }
                let info = match &r.thread_info {
                    Some(i) => {
                        self.remember(r.thread, i);
                        Some(i.clone())
                    }
                    None => self.threads.get(&r.thread).cloned(),
                };
                let client = info.as_ref().and_then(|i| ClientAddr::parse(&i.host));
                let principal = match &info {
                    Some(i) => {
                        let p = EventPrincipal::account(&i.user).with_client(client);
                        match &i.program {
                            Some(prog) => p.with_application(prog),
                            None => p,
                        }
                    }
                    None => EventPrincipal::unidentified(),
                };
                let access = Access {
                    session: format!("t{}", r.thread),
                    user: info.as_ref().map_or("", |i| i.user.as_str()),
                    principal,
                    client: ClientSeen::Logged(client),
                    application: info.as_ref().and_then(|i| i.program.as_deref()),
                    database: &r.schema,
                    text: r.text.as_deref().map(Vec::as_slice),
                    opaque: false,
                    truncated: r.truncated,
                    tables: Vec::new(),
                    rows: Some(r.rows),
                    status: r.errno,
                    ts: ts_of(r.timer_end),
                    source: EventSource::PerformanceSchema,
                };
                // Per-statement isolation: a statement that makes the
                // conversion panic is dropped alone and counted (the
                // cursor is persisted, so a panic that ended the stream
                // would come back at every restart).
                match convert(&mut self.builder, access, now) {
                    Ok(Some(e)) => events.push(e),
                    Ok(None) => {}
                    Err(()) => self.panicked = self.panicked.saturating_add(1),
                }
            }
            if !full {
                break;
            }
            from = batch_max;
        }
        self.last = Some(last);
        let floor = last.saturating_sub(OVERLAP_PS);
        self.seen.retain(|_, t| *t >= floor);
        for e in events {
            sink.submit(e).await.map_err(|_| PollError::SinkClosed)?;
        }
        self.save();
        Ok(())
    }
}

/// Tests: a statement text holding this marker makes its conversion
/// panic (a bug on one statement).
#[cfg(test)]
const TEST_POISON: &[u8] = b"TEST-ANALYZER-PANIC";

/// One statement's event, converted in isolation
/// (`databastion_core::isolate`, as the file sources do; security review
/// of #85): `Err(())` when the conversion panicked (the statement is
/// dropped alone and counted).
fn convert(
    builder: &mut EventBuilder,
    access: Access<'_>,
    now: SystemTime,
) -> Result<Option<databastion_classifiers::masking::MaskedEvent>, ()> {
    databastion_core::isolate(|| {
        #[cfg(test)]
        #[allow(clippy::panic)]
        if access
            .text
            .is_some_and(|t| t.windows(TEST_POISON.len()).any(|w| w == TEST_POISON))
        {
            panic!("conversion bug on a statement");
        }
        builder.statement(access, now)
    })
    .ok_or(())
}

fn text_of(v: Option<&[u8]>) -> Option<String> {
    text(v, 1024).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Security review of 914c9d2, N1: one-letter identifier padding fills
    /// the digest storage (1024 bytes) while the rendered digest stays at
    /// 895 bytes on MySQL 8.4 (896 on MariaDB 11.4), with no `...`; with
    /// `max_digest_length = 300` (MySQL 8.4) it renders at 275 bytes.
    #[test]
    fn digests_cut_at_their_token_storage_are_cut() {
        let head = "SELECT * FROM ( SELECT ? `a` ) `x` WHERE `a` IN ( `a`";
        let mut d = head.to_owned();
        while d.len() + 6 <= 895 {
            d.push_str(" , `a`");
        }
        d.push_str(" ,");
        assert_eq!(d.len(), 895);
        assert!(!text_cut(d.as_bytes(), true, 1024));
        assert!(digest_stored_estimate(d.as_bytes()) > 900);
        assert!(digest_cut(d.as_bytes(), 1024));
        // The same with a lowered parser limit.
        let low = &d[..275];
        assert!(!digest_cut(low.as_bytes(), 1024));
        assert!(digest_cut(low.as_bytes(), 300));
        // Short digests are not cut at the default limits.
        let short = "SELECT * FROM `information_schema` . `TABLES` WHERE TABLE_NAME = ? \
                     AND `TABLE_SCHEMA` = ? UNION ALL SELECT * FROM `hr` . `customers`";
        assert!(!digest_cut(short.as_bytes(), 1024));
        // Doubled backquotes and odd chunks.
        assert_eq!(digest_stored_estimate(b"`a``b` ?"), 4 + 3 + 2);
        assert_eq!(digest_stored_estimate(b"@x"), 4 + 2);
        assert_eq!(digest_stored_estimate(b"`a`.`b`"), 4 + 7);
        assert_eq!(digest_stored_estimate(b"`open"), 4 + 4);
    }

    /// Every digest the estimate may judge cut is long enough for the poll
    /// to have read its `SQL_TEXT` ([`sql_text_from`]).
    #[test]
    fn the_estimate_stays_within_three_times_the_length() {
        let parts: [&[u8]; 9] = [
            b"`a` ", b"` ", b"@", b"? ", b", ", b"SELECT ", b"`", b"``", b" ",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            let mut d = Vec::new();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut x = seed;
            for _ in 0..(seed % 64) {
                d.extend_from_slice(parts[(x % 9) as usize]);
                x = x.rotate_right(5).wrapping_mul(31);
            }
            assert!(digest_stored_estimate(&d) <= 3 * d.len() + 3, "{d:?}");
        }
        for limit in [0, 256, 300, 1024, 4096] {
            let from = sql_text_from(limit);
            // est + token >= limit and est <= 3 len + 3 imply len >= from.
            assert!(3 * from + 3 + MAX_DIGEST_TOKEN <= limit.max(MAX_DIGEST_TOKEN + 3));
        }
        assert_eq!(sql_text_from(1024), 253);
    }

    /// `SQL_TEXT` first when the poll read it and it is not cut, else the
    /// digest, cut or not; both cut: cut.
    #[test]
    fn the_text_of_a_row_is_chosen_fail_closed() {
        let cut_digest = format!("SELECT `a`{}", " , `a`".repeat(160));
        let whole_sql = "SELECT a FROM t WHERE a IN (a, a) UNION SELECT 1";
        let cut_sql = "x".repeat(1021);
        let c = |d: Option<&str>, s: Option<&str>| {
            let (t, cut) = choose_text(d.map(str::as_bytes), s.map(str::as_bytes), 1024, 1024);
            (t.map(|t| String::from_utf8_lossy(t).into_owned()), cut)
        };
        assert_eq!(
            c(Some(&cut_digest), Some(whole_sql)),
            (Some(whole_sql.to_owned()), false)
        );
        assert_eq!(c(Some(&cut_digest), None), (Some(cut_digest.clone()), true));
        assert_eq!(
            c(Some(&cut_digest), Some(&cut_sql)),
            (Some(cut_digest.clone()), true)
        );
        assert_eq!(
            c(Some("SELECT ?"), None),
            (Some("SELECT ?".to_owned()), false)
        );
        assert_eq!(
            c(Some("SELECT ?"), Some(&cut_sql)),
            (Some("SELECT ?".to_owned()), false)
        );
        assert_eq!(c(None, Some(&cut_sql)), (Some(cut_sql.clone()), true));
        assert_eq!(
            c(None, Some(whole_sql)),
            (Some(whole_sql.to_owned()), false)
        );
        assert_eq!(c(None, None), (None, false));
        let huge = "y".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(c(None, Some(&huge)), (None, true));
    }

    fn saved(boot: u64, last: u64) -> Saved {
        Saved {
            v: CURSOR_VERSION,
            boot,
            last,
            floor: None,
            seen: vec![(7, 1, last)],
        }
    }

    /// Phase 7: an agent restart resumes at the saved cursor of the same
    /// server run, reads a new server run from its start, and starts at
    /// the newest statement without a usable cursor.
    #[test]
    fn a_saved_cursor_resumes_the_same_server_run_only() {
        let (last, seen, floor) = resume(Some(saved(1_000_000, 42)), Some(1_000_060));
        assert_eq!(last, Some(42));
        assert_eq!(seen.get(&(7, 1)), Some(&42));
        assert_eq!(floor, None);
        // Another server run (restarted while the agent was stopped).
        let (last, seen, _) = resume(Some(saved(1_000_000, 42)), Some(1_090_000));
        assert_eq!(last, Some(0));
        assert!(seen.is_empty());
        // Start time unknown, nothing saved, or another format version.
        assert_eq!(resume(Some(saved(1_000_000, 42)), None).0, None);
        assert_eq!(resume(None, Some(1_000_000)).0, None);
        let mut other = saved(1_000_000, 42);
        other.v = 2;
        assert_eq!(resume(Some(other), Some(1_000_000)).0, None);
    }

    #[test]
    fn the_saved_cursor_is_bounded_and_keeps_a_floor() {
        assert!(to_save(None, Some(1), &HashMap::new()).is_none());
        assert!(to_save(Some(1), None, &HashMap::new()).is_none());
        let seen: HashMap<(u64, u64), u64> =
            (0..2000u64).map(|i| ((i % 7, i), 1_000 + i)).collect();
        let s = to_save(Some(5), Some(2_999), &seen).unwrap();
        assert_eq!(s.seen.len(), MAX_SAVED_SEEN);
        // The newest are kept; the floor is the oldest kept.
        assert_eq!(s.seen[0].2, 2_999);
        assert_eq!(s.floor, Some(s.seen.last().unwrap().2));
        let bytes = serde_json::to_vec(&s).unwrap();
        assert!(bytes.len() < 64 * 1024, "{}", bytes.len());
        let back: Saved = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, s);
        let (_, restored, floor) = resume(Some(back), Some(5));
        assert_eq!(restored.len(), MAX_SAVED_SEEN);
        assert_eq!(floor, s.floor);
        // Small overlaps are kept whole.
        let few: HashMap<(u64, u64), u64> = [((1, 2), 10), ((1, 3), 11)].into();
        let s = to_save(Some(5), Some(11), &few).unwrap();
        assert_eq!((s.seen.len(), s.floor), (2, None));
    }

    #[test]
    fn the_worst_case_cursor_fits_the_cursor_bound() {
        let seen: HashMap<(u64, u64), u64> = (0..MAX_SAVED_SEEN as u64)
            .map(|i| ((u64::MAX - i, u64::MAX - i), u64::MAX - i))
            .collect();
        let s = to_save(Some(u64::MAX), Some(u64::MAX), &seen).unwrap();
        assert!(serde_json::to_vec(&s).unwrap().len() <= 64 * 1024);
    }

    /// Security review of #85: a statement whose conversion panics is
    /// dropped alone; the next one is converted.
    #[test]
    fn a_panicking_statement_is_dropped_alone() {
        use databastion_core::audit::own::{OwnAccount, SharedOwnUsage};
        let mut b = EventBuilder::new(OwnAccount::new(
            "databastion",
            Some("databastion-agent"),
            ClientAddr::parse("172.18.0.1"),
            1000,
            SharedOwnUsage::default(),
        ));
        let access = |text: &'static [u8]| Access {
            session: "t1".into(),
            user: "app",
            principal: EventPrincipal::account("app"),
            client: ClientSeen::Logged(None),
            application: None,
            database: "hr",
            text: Some(text),
            opaque: false,
            truncated: false,
            tables: Vec::new(),
            rows: Some(5),
            status: 0,
            ts: SystemTime::now(),
            source: EventSource::PerformanceSchema,
        };
        let now = SystemTime::now();
        assert!(
            convert(
                &mut b,
                access(b"select * from employees /* TEST-ANALYZER-PANIC */"),
                now
            )
            .is_err()
        );
        let e = convert(&mut b, access(b"select * from employees"), now)
            .unwrap()
            .unwrap();
        assert_eq!(e.principal().account_name(), "app");
    }
}
