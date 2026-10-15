//! SQL Server Audit (ADR-0051 decision 6 and its refinement of 2026-10-14,
//! option (a')): the operator's server audit, `FILE` target, read through
//! `sys.fn_get_audit_file` over the stream's own connection; **Partial at
//! best**, never Full ([`probe`]).
//!
//! - **Source**: SQL Server 2022 and later, with `VIEW SERVER SECURITY
//!   AUDIT` and `VIEW ANY SECURITY DEFINITION`. The audit and its
//!   specifications are the operator's; the agent never creates, alters,
//!   starts or stops them (I4). The Extended Events source (SQL Server
//!   2019) is not implemented in this build: such a target reports None.
//! - **Polls**: one `sp_executesql` RPC each, whose text is constant for
//!   a given catalog state: the file pattern (from the catalog's folder,
//!   the audit's name and GUID) is a literal of the text, never a
//!   parameter (M1); the file name, the buffer offset and the row bound
//!   are parameters. At most [`BATCH`] records per read; a full read is
//!   followed by another, within [`CATCH_UP`]. Each poll gets a credit
//!   (its own record is left out only for this session and this text).
//! - **Position** (M4), persisted through the core: the file and the
//!   offset of the last buffer read whole (a read starts after it,
//!   measured), and how many records of the next buffer were already
//!   handled. A position the server refuses (error 33225: the file left
//!   the set, rolled over) restarts at the oldest file, skipping what was
//!   read, and is a gap. The audit's own start and stop records (`AUSC`)
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
//!   converted, under `databastion_core::isolate`.

pub(crate) mod own;
pub(crate) mod probe;
pub(crate) mod records;

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

/// Records read per poll (decision 6).
pub(crate) const BATCH: usize = 1000;
/// Records of one buffer handled across polls at most; beyond, the rest
/// of that buffer is dropped (counted).
const MAX_SKIP: u32 = 4000;
/// Time spent catching up (full reads one after the other) per cycle.
const CATCH_UP: Duration = Duration::from_secs(20);
/// Bound of one poll's response.
const POLL_BYTES: usize = 48 * 1024 * 1024;
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
    usable: Mutex<HashMap<String, bool>>,
    /// Statements left out as the agent's own: (exact texts, credited
    /// sampling, credited polls), for the logs and the tests.
    own_left_out: Mutex<HashMap<String, [u64; 3]>>,
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

    /// The last `check()` found the SQL Server Audit source usable.
    pub(crate) fn set_usable(&self, target_id: &str, usable: bool) {
        lock(&self.usable).insert(target_id.to_owned(), usable);
    }

    pub(crate) fn usable(&self, target_id: &str) -> bool {
        lock(&self.usable).get(target_id).copied().unwrap_or(false)
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

    /// Statements left out as the agent's own: exact texts, credited
    /// sampling, credited polls.
    #[cfg(test)]
    pub(crate) fn own_left_out(&self, target_id: &str) -> [u64; 3] {
        lock(&self.own_left_out)
            .get(target_id)
            .copied()
            .unwrap_or_default()
    }
}

/// The persisted position (file names hex-encoded, numbers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    /// File and offset of the last buffer read whole (`None`: from the
    /// start of the file set).
    pub(crate) file: Option<String>,
    pub(crate) offset: i64,
    /// Records of the buffer after it already handled.
    pub(crate) skip: u32,
    /// The audit's GUID the position belongs to.
    pub(crate) guid: Option<String>,
    /// After a refused position: records at or before this (file, offset)
    /// were read already.
    pub(crate) after: Option<(String, i64)>,
    /// First start: records older than this (server µs) are history, not
    /// reported.
    pub(crate) history_us: Option<i64>,
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
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = String::from("v1\n");
        out.push_str(&format!(
            "file {}\noffset {}\nskip {}\nguid {}\n",
            self.file.as_deref().map_or("-".to_owned(), hex),
            self.offset,
            self.skip,
            self.guid.as_deref().unwrap_or("-"),
        ));
        if let Some((f, o)) = &self.after {
            out.push_str(&format!("after {} {o}\n", hex(f)));
        }
        if let Some(h) = self.history_us {
            out.push_str(&format!("history {h}\n"));
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
                ("guid", "-") => c.guid = None,
                ("guid", g) => c.guid = Some(sql::quote_guid(g).map(|_| g.to_owned())?),
                ("after", f) => c.after = Some((unhex(f)?, p.next()?.parse().ok()?)),
                ("history", h) => c.history_us = Some(h.parse().ok()?),
                _ => return None,
            }
        }
        Some(c)
    }
}

/// Where the next read starts, from what a read returned (`(file,
/// offset)` of each record in order) and how many it asked for.
///
/// A read starts after the buffer at the position (measured), so a
/// buffer whose records may not all have come (the read was full) is
/// read again next time, its records already handled skipped.
pub(crate) fn advance(cursor: &Cursor, positions: &[(String, i64)], top: usize) -> Cursor {
    let mut next = cursor.clone();
    let Some(last) = positions.last() else {
        return next;
    };
    let full = positions.len() >= top;
    if !full {
        next.file = Some(last.0.clone());
        next.offset = last.1;
        next.skip = 0;
        return next;
    }
    // The last buffer may continue: keep the position before it.
    let in_last = positions.iter().rev().take_while(|p| *p == last).count();
    let before = positions.len() - in_last;
    if before == 0 {
        // The whole read is one buffer (the first one after the position).
        next.skip = cursor
            .skip
            .saturating_add(u32::try_from(in_last).unwrap_or(u32::MAX));
    } else {
        let prev = &positions[before - 1];
        next.file = Some(prev.0.clone());
        next.offset = prev.1;
        next.skip = u32::try_from(in_last).unwrap_or(u32::MAX);
    }
    next
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
    name: String,
    probe: Option<probe::Probe>,
    poll_start: String,
    poll_from: String,
    reprobe_at: Instant,
    evaluated_at: Option<Instant>,
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
        let Some(session) = own::session_at(&self.target.id, h.session_id, h.time_us) else {
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
                // through its one-bit password_hash probe.
                if ev.always_report() && *h.statement != *sql::PASSWORD_HASH_PROBE {
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
                if !own::take_credit(&self.target.id, h.session_id, &h.statement, poll, h.time_us) {
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
    let Some(name) = probe::audit_name(settings.audit.as_ref()).map(str::to_owned) else {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: no server audit named in agent.yaml (sqlserver.audit.audit_name)");
        return Err(target_error(FailureCode::Unsupported));
    };
    let _running = state.audit.started(&target.id);
    let _streaming = own::stream_started(&target.id, cfg.poll_interval());
    let own_store = cfg.counters(OWN_SESSIONS);
    if let Some(Ok(Some(bytes))) = own_store.as_ref().map(CursorStore::load)
        && let Some(persisted) = own::decode(&bytes)
    {
        own::restore(&target.id, persisted);
    }
    let store = cfg.cursor(CURSOR);
    let loaded = match store.as_ref().map(CursorStore::load) {
        Some(Ok(Some(bytes))) => Cursor::decode(&bytes),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "SQL Server Audit cursor not readable: the audit's history is skipped");
            None
        }
        _ => None,
    };
    let skip = store.as_ref().map_or(0, CursorStore::skip_records);
    let tls = tls::configs(settings.ca_file.as_deref())
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    let mut session = conn::connect(target, &tls, &state.choice, POLL_TIMEOUT)
        .await
        .map_err(SsError::into_connector_error)?;
    let first_start = loaded.is_none();
    let mut cursor = loaded.unwrap_or_default();
    if first_start {
        // No history replay: what the audit holds from before now.
        cursor.history_us = session.own.as_ref().map(own::Handle::server_now);
    }
    let mut st = Stream {
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
        name,
        probe: None,
        poll_start: String::new(),
        poll_from: String::new(),
        reprobe_at: Instant::now(),
        evaluated_at: None,
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
        let r = cycle(&mut st, &mut session, sink).await;
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
        let ev = check::evaluate(s, target)
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
        reprobe(st, s).await?;
    }
    let started = Instant::now();
    loop {
        let full = read(st, s, sink).await?;
        st.save();
        if !full || started.elapsed() >= CATCH_UP {
            break;
        }
        if st.probe.is_none() {
            reprobe(st, s).await?;
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
    let p = probe::probe(s, &st.name, &dbs, Stage::Introspection)
        .await
        .map_err(SsError::into_connector_error)?;
    if !p.found {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the named server audit has no FILE target or is invisible");
        return Err(target_error(FailureCode::Unsupported));
    }
    let Some(pattern) = p.pattern(&st.name) else {
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the audit's folder or name cannot be used in a file pattern");
        return Err(target_error(FailureCode::Unsupported));
    };
    let (Some(start), Some(from)) = (
        sql::audit_poll(&pattern, false),
        sql::audit_poll(&pattern, true),
    ) else {
        return Err(target_error(FailureCode::Internal));
    };
    if st
        .cursor
        .guid
        .as_deref()
        .is_some_and(|g| !g.eq_ignore_ascii_case(&p.guid))
    {
        // Another audit under that name: its files are another set.
        tracing::warn!(target_id = %target.id, "SQL Server Audit: the server audit was recreated (new GUID): reading its files from the start");
        st.cursor.file = None;
        st.cursor.skip = 0;
        st.cursor.after = None;
        st.state.audit.note_gap(&target.id);
        st.state.audit.note_dropped(&target.id, 1);
    }
    st.cursor.guid = Some(p.guid.clone());
    own::set_queue_delay(&target.id, p.queue_delay);
    st.poll_start = start;
    st.poll_from = from;
    st.probe = Some(p);
    st.reprobe_at = Instant::now();
    Ok(())
}

/// Sends one poll and returns its rows.
async fn poll_rows(
    s: &mut Session,
    text: &str,
    kind: own::PollKind,
    file: &str,
    offset: i64,
    top: usize,
) -> Result<Vec<Vec<Value>>, SsError> {
    let params = [
        Param::NVarChar(file.to_owned()),
        Param::BigInt(offset),
        Param::BigInt(i64::try_from(top).unwrap_or(i64::MAX)),
    ];
    s.credit_poll(text, kind);
    let mut rows = Vec::new();
    let mut row = Vec::with_capacity(sql::AUDIT_POLL_COLUMNS);
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
                Cell::RowEnd => rows.push(std::mem::take(&mut row)),
            }
            Flow::Continue
        },
    )
    .await?;
    Ok(rows)
}

/// One read from the position; `true` when it was full (more to read).
async fn read(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
) -> Result<bool, ConnectorError> {
    let target_id = st.target.id.clone();
    let top = BATCH + st.cursor.skip as usize;
    let rows = match st.cursor.file.clone() {
        None => poll_rows(s, &st.poll_start.clone(), own::PollKind::Start, "", 0, top).await,
        Some(f) => {
            poll_rows(
                s,
                &st.poll_from.clone(),
                own::PollKind::From,
                &f,
                st.cursor.offset,
                top,
            )
            .await
        }
    };
    let rows = match rows {
        Ok(r) => r,
        Err(e) if e.number == Some(ERR_BAD_POSITION) && st.cursor.file.is_some() => {
            // The position left the file set (rolled over, deleted) or
            // the file changed: from the oldest file, skipping what was
            // read; whatever was between is lost (M4).
            tracing::warn!(target_id = %target_id, "SQL Server Audit: the saved position is no longer in the audit's file set (rollover): reading from the oldest file");
            st.cursor.after = st.cursor.file.clone().map(|f| (f, st.cursor.offset));
            st.cursor.file = None;
            st.cursor.skip = 0;
            st.state.audit.note_gap(&target_id);
            st.state.audit.note_dropped(&target_id, 1);
            return Ok(true);
        }
        Err(e) => return Err(e.into_connector_error()),
    };
    let returned = rows.len();
    // Parse each row alone.
    let mut parsed: Vec<Record> = Vec::with_capacity(rows.len());
    let mut malformed = 0u64;
    for row in rows {
        match databastion_core::isolate(|| Record::from_row(row)) {
            Some(Ok(r)) => parsed.push(r),
            _ => malformed += 1,
        }
    }
    st.state.audit.note_dropped(&target_id, malformed);
    let positions: Vec<(String, i64)> = parsed.iter().map(|r| (r.file.clone(), r.offset)).collect();
    // The records of the first buffer already handled.
    let mut skip_first = st.cursor.skip as usize;
    let first = positions.first().cloned();
    parsed.retain(|r| {
        if skip_first > 0 && Some((&r.file, r.offset)) == first.as_ref().map(|(f, o)| (f, *o)) {
            skip_first -= 1;
            return false;
        }
        true
    });
    // Records already read before a refused position.
    if let Some((f, o)) = st.cursor.after.clone() {
        parsed.retain(|r| (r.file.as_str(), r.offset) > (f.as_str(), o));
    }
    let next = advance(&st.cursor, &positions, top);
    let after_done = st
        .cursor
        .after
        .as_ref()
        .is_some_and(|(f, o)| positions.last().is_some_and(|(lf, lo)| (lf, *lo) > (f, *o)));
    if !parsed.is_empty() {
        st.state.audit.note_record(&target_id);
    }
    let history = st.cursor.history_us;
    let mut statements = records::group(records::reassemble(parsed));
    if st.skip > 0 {
        let n = (st.skip as usize).min(statements.len());
        statements.drain(..n);
        st.state.audit.note_dropped(&target_id, n as u64);
        st.skip = 0;
    }
    let mut reprobe = false;
    for stmt in &statements {
        if history.is_some_and(|h| stmt.head.time_us < h) {
            continue;
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
    st.cursor = next;
    if after_done {
        st.cursor.after = None;
    }
    let full = returned >= top;
    if st.cursor.skip > MAX_SKIP {
        // One buffer larger than the bound: the rest of it is dropped.
        if let Some((f, o)) = positions.last() {
            st.cursor.file = Some(f.clone());
            st.cursor.offset = *o;
        }
        st.cursor.skip = 0;
        st.state.audit.note_dropped(&target_id, 1);
    }
    if !full {
        // Caught up: no history any more.
        st.cursor.history_us = None;
    }
    if reprobe {
        // An AUDIT_CHANGE_GROUP record: the proofs at once (re-review N3).
        st.probe = None;
    }
    Ok(full)
}

#[cfg(test)]
mod tests;
