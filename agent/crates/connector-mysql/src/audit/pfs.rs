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
//! started) of the newest statement read, kept in memory. The first poll
//! starts at the newest statement (no history is replayed); a restarted
//! server (timers back at zero) is read from its start. Statements
//! finishing out of order are caught by re-reading the last
//! [`OVERLAP_PS`] picoseconds, deduplicated on (thread, event id).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::{ClientAddr, EventPrincipal, EventSource};
use databastion_core::audit::own::ClientSeen;
use databastion_core::{EventSink, FailureCode};
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
    /// Starts polling `table` on `session` (its own thread is left out).
    pub(crate) async fn start(
        session: &mut Session,
        table: PsTable,
        builder: EventBuilder,
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
        let digest_limit = limit(scalar(session, sql::PS_DIGEST_LIMIT).await?);
        Ok(Self {
            table,
            own_thread,
            text_limit,
            digest_limit,
            with_program: true,
            last: None,
            seen: HashMap::new(),
            threads: HashMap::new(),
            thread_order: VecDeque::new(),
            builder,
            wrapped: 0,
        })
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
            if self.threads.len() >= MAX_THREADS {
                if let Some(old) = self.thread_order.pop_front() {
                    self.threads.remove(&old);
                }
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
                let (body, is_digest) = match get(4) {
                    Some(d) => (Some(Zeroizing::new(d.to_vec())), true),
                    None => (get(5).map(|t| Zeroizing::new(t.to_vec())), false),
                };
                let limit = if is_digest { digest_limit } else { text_limit };
                let body = body.filter(|t| t.len() <= MAX_TEXT_BYTES);
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
                    // At the server's limit, or a digest the server cut
                    // (it ends with `...`).
                    truncated: body.as_ref().is_some_and(|t| {
                        t.len() + 4 >= limit || (is_digest && t.ends_with(b"..."))
                    }),
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
            return Ok(());
        };
        if max.is_some_and(|m| m < last) || current.is_some_and(|c| c < last) {
            tracing::info!(
                "performance_schema timers restarted (server restart); reading from the start"
            );
            last = 0;
            self.seen.clear();
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
                if let Some(e) = self.builder.statement(access, now) {
                    events.push(e);
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
        Ok(())
    }
}

fn text_of(v: Option<&[u8]>) -> Option<String> {
    text(v, 1024).filter(|s| !s.is_empty())
}
