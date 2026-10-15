//! The Extended Events source (ADR-0051 decision 6, `sqlserver_xevents`):
//! the operator's session, `event_file` target, read through
//! `sys.fn_xe_file_target_read_file` over the stream's own connection;
//! **Partial at best**, never Full ([`probe`]). The only Audit source on
//! SQL Server 2019, where reading SQL Server Audit needs `CONTROL SERVER`.
//!
//! - **The session is the operator's**: the agent never creates, alters,
//!   starts or stops it (I4). Its name comes from `agent.yaml`
//!   (`sqlserver.audit.xe_session`); the file pattern of the poll from the
//!   session's current file as the server names it, a literal of the poll
//!   text (M1), never from configuration.
//! - **Polls**: one `sp_executesql` RPC each, text constant for a given
//!   catalog state, the file name, the buffer offset and the row bound as
//!   parameters; at most `BATCH` events per read, halved after a response
//!   over `POLL_BYTES`; each poll gets a credit (its own events are left
//!   out only for this session and this text). Each event's XML is read by
//!   the bounded reader of [`xml`], under panic isolation, and is at most
//!   `sql::XE_EVENT_BYTES` on the wire (the server sends larger ones
//!   without their XML).
//! - **Position**, persisted through the core (cursor `sqlserver_xevents`):
//!   the file and offset of the last buffer read whole (a read starts after
//!   it, measured on 2019), the events of the next buffer already handled,
//!   the file pattern, and the session's `create_time`. Another pattern is
//!   another file set (read from its start, a gap); a position the server
//!   refuses (error 25722, an offset that is not a buffer; 25717, a file
//!   gone) in the same set restarts at the oldest file, leaving out what
//!   was read by file key and offset, never by path (lot 2 review H1), a
//!   gap. At every cycle the session's `create_time` and drop counters are
//!   read: another `create_time` (the session was stopped and started) or
//!   grown counters are a gap (`audit.records_dropped`, Limited for 24 h).
//!   The first start skips the session's history.
//! - **Events** ([`events`]): one event per statement, objects from the
//!   text, rows from `row_count`.
//! - **The agent's own statements** (decision 6, H1): only from one of the
//!   agent's own sessions within its lifetime, with both principals the
//!   agent's login (the source records no client address), then only for
//!   its exact constant texts or a credited sampling, ticket-count or poll
//!   text; sampling is charged its rows on the per-object budget. Writes,
//!   DDL and DCL are always reported.
//! - **Preference** (decision 6): with `source: auto` and a server audit
//!   named, the stream ends at a re-probe that finds SQL Server Audit
//!   usable, and the core restarts it on that source.

pub(crate) mod events;
pub(crate) mod probe;
pub(crate) mod xml;

use std::time::Instant;

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::config::TargetConfig;
use databastion_core::{AuditConfig, ConnectorError, EventSink, FailureCode};

use super::own;
use super::{
    APP, BATCH, CATCH_UP, Cursor, HISTORY_READS, MIN_BATCH, OWN_FILE_BYTES, OWN_SESSIONS,
    POLL_BYTES, REEVALUATE, REPROBE, batch, on_bad_position, on_pattern, target_error,
};
use crate::check::{self, CheckState};
use crate::conn::{Cell, Flow, Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql::{self, OwnText};
use crate::tds::Param;
use crate::token::Value;
use events::XeRecord;

/// Cursor file name.
const CURSOR: &str = "sqlserver_xevents";
/// The server's errors for a position outside the session's file set: an
/// offset that is not a buffer, a file that is gone (measured on 2019).
const ERR_BAD_OFFSET: i32 = 25_722;
const ERR_FILE_GONE: i32 = 25_717;

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
    /// The session named in `agent.yaml`.
    name: String,
    probe: Option<probe::Probe>,
    poll_start: String,
    poll_from: String,
    reprobe_at: Instant,
    evaluated_at: Option<Instant>,
    batch: usize,
    /// The statistics exclusion applies (an allow-listed build).
    statman: bool,
    /// The server's major version and the account's server permissions at
    /// the last evaluation (the preference rule at each re-probe).
    major: i64,
    perms: std::collections::BTreeSet<String>,
}

impl Stream<'_> {
    fn save(&mut self) {
        if let Some(store) = &self.store {
            let bytes = self.cursor.encode();
            if self.saved.as_ref() != Some(&bytes) {
                match store.save(&bytes) {
                    Ok(()) => self.saved = Some(bytes),
                    Err(e) => tracing::warn!(error = %e, "Extended Events cursor not saved"),
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
    fn own_routine(&mut self, r: &XeRecord, ev: &MaskedEvent) -> bool {
        let verdict = self.own_verdict(r, ev);
        if let Ok(which) = verdict {
            self.state.audit.note_own(&self.target.id, which);
        }
        if let Err(why) = verdict
            && r.login().eq_ignore_ascii_case(&self.target.account)
        {
            // Closed reasons, no text.
            tracing::debug!(
                target_id = %self.target.id,
                session_id = r.event.as_ref().and_then(|e| e.session_id),
                reason = why,
                "Extended Events: an event of the agent's login is not its own routine"
            );
        }
        verdict.is_ok()
    }

    /// `Ok` when the event is the agent's own routine (0: an exact text,
    /// 1: credited sampling, 2: a credited poll); otherwise the reason.
    fn own_verdict(&mut self, r: &XeRecord, ev: &MaskedEvent) -> Result<usize, &'static str> {
        let Some(e) = &r.event else {
            return Err("no event data");
        };
        if e.statement_cut {
            return Err("cut text");
        }
        let text = e.statement.as_deref().map_or("", |s| s.as_str());
        let Some(spid) = e.session_id else {
            return Err("no session");
        };
        if own::session_at(&self.target.id, spid, r.time_us, text).is_none() {
            return Err("not one of the agent's sessions at that time");
        }
        let account = &self.target.account;
        let both = |p: &Option<String>| {
            p.as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(account))
        };
        if !both(&e.server_principal) || !both(&e.session_principal) {
            return Err("principals");
        }
        if e.client_app
            .as_deref()
            .is_some_and(|a| !a.is_empty() && a != APP)
        {
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
        match sql::own_text(text) {
            OwnText::Exact => {
                if ev.always_report() && !sql::own_listed_read(text) {
                    return Err("always-reported object");
                }
                unbudgeted(&self.own, 0)
            }
            OwnText::NeedsCredit | OwnText::No => {
                let poll = if text == self.poll_start && !self.poll_start.is_empty() {
                    Some(own::PollKind::Start)
                } else if text == self.poll_from && !self.poll_from.is_empty() {
                    Some(own::PollKind::From)
                } else {
                    None
                };
                // One event per statement on this source: a credit is
                // consumed by one event (no transaction id).
                if !own::take_credit(&self.target.id, spid, text, poll, r.time_us, 0) {
                    return Err("no credit for this text");
                }
                if poll.is_some() {
                    // It names fn_xe_file_target_read_file (a statement-text
                    // object): the agent's own only through the credit of
                    // this exact text from its session (decision 6).
                    unbudgeted(&self.own, 2)
                } else if ev.always_report() {
                    Err("always-reported object")
                } else if self
                    .own
                    .routine(user, None, ClientSeen::NotRecorded, ev, Instant::now())
                {
                    Ok(1)
                } else {
                    Err("over the own-read budget, or a signal")
                }
            }
        }
    }
}

/// Whether the SQL Server Audit source is usable on `s` now (the
/// preference rule of decision 6): an audit named, SQL Server 2022 or
/// later, its grants held and the audit found.
pub(crate) async fn audit_usable(
    s: &mut Session,
    target: &TargetConfig,
    major: i64,
    perms: &std::collections::BTreeSet<String>,
) -> Result<bool, SsError> {
    let settings = target.sqlserver_settings();
    let Some(name) = super::probe::audit_name(settings.audit.as_ref()) else {
        return Ok(false);
    };
    if major < super::probe::MIN_AUDIT_MAJOR
        || !super::probe::SOURCE_GRANTS
            .iter()
            .all(|g| perms.contains(*g))
    {
        return Ok(false);
    }
    let (dbs, _) = check::monitored_databases(s, target).await?;
    let p = Box::pin(super::probe::probe(s, name, &dbs, Stage::Introspection)).await?;
    Ok(p.found && p.pattern().is_some())
}

/// `Connector::audit_stream` on the Extended Events source, on the
/// stream's open session `session`.
pub(crate) async fn stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
    target: &TargetConfig,
    mut session: Session,
    name: String,
) -> Result<(), ConnectorError> {
    let own_store = cfg.counters(OWN_SESSIONS);
    let store = cfg.cursor(CURSOR);
    let loaded = match store.as_ref().map(CursorStore::load) {
        Some(Ok(Some(bytes))) => {
            let c = Cursor::decode(&bytes);
            if c.is_none() {
                tracing::warn!(target_id = %target.id, "Extended Events cursor not understood: starting at the end of the session's files (a gap)");
                state.audit.note_gap(&target.id);
                state.audit.note_dropped(&target.id, 1);
            }
            c
        }
        Some(Err(e)) => {
            tracing::warn!(error = %e, "Extended Events cursor not readable: starting at the end of the session's files (a gap)");
            state.audit.note_gap(&target.id);
            state.audit.note_dropped(&target.id, 1);
            None
        }
        _ => None,
    };
    let skip = store.as_ref().map_or(0, CursorStore::skip_records);
    let first_start = loaded.is_none();
    let mut cursor = loaded.unwrap_or_default();
    if first_start {
        // No history replay.
        cursor.history_us = session.own.as_ref().map(own::Handle::server_now);
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
        statman: false,
        major: 0,
        perms: std::collections::BTreeSet::new(),
    };
    let tls = crate::tls::configs(target.sqlserver_settings().ca_file.as_deref())
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    loop {
        if session.is_poisoned() || session.is_stale() {
            let old = std::mem::replace(
                &mut session,
                crate::conn::connect(target, &tls, &state.choice, super::POLL_TIMEOUT)
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

/// One cycle: the account and proofs when due, the session's counters,
/// then reads until caught up.
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
        let ev = Box::pin(check::evaluate(s, target))
            .await
            .map_err(SsError::into_connector_error)?;
        if ev.blocks() {
            tracing::warn!(target_id = %target.id, "the account holds a right of the refusal list (privilege.refused): Audit refused");
            return Err(target_error(FailureCode::PermissionDenied));
        }
        if !ev.server_perms.contains(probe::grant(v.major)) {
            tracing::warn!(target_id = %target.id, grant = probe::grant(v.major), "Extended Events needs this grant");
            return Err(target_error(FailureCode::PermissionDenied));
        }
        st.statman = events::STATMAN_BUILDS.contains(&v.product.as_str());
        st.major = v.major;
        st.perms = ev.server_perms;
        st.evaluated_at = Some(Instant::now());
        st.probe = None;
    }
    if st.probe.is_none() || st.reprobe_at.elapsed() >= REPROBE {
        Box::pin(reprobe(st, s)).await?;
    } else {
        // The session's counters at every cycle (decision 6, "Position and
        // gaps").
        let name = st.name.clone();
        let p = Box::pin(probe::probe(s, &name, Stage::Introspection))
            .await
            .map_err(SsError::into_connector_error)?;
        if !p.running {
            tracing::warn!(target_id = %target.id, "Extended Events: the session is not running");
            return Err(target_error(FailureCode::Unsupported));
        }
        observe(st, &p);
        st.probe = Some(p);
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

/// A restart of the session or grown drop counters: a gap.
fn observe(st: &mut Stream<'_>, p: &probe::Probe) {
    let target_id = &st.target.id;
    if st
        .cursor
        .session
        .is_some_and(|c| !probe::same_start(c, p.create_us))
    {
        tracing::warn!(target_id = %target_id, "Extended Events: the session was stopped and started (create_time changed): what happened in between was not recorded");
        st.state.audit.note_gap(target_id);
        st.state.audit.note_dropped(target_id, 1);
    }
    st.cursor.session = Some(p.create_us);
    if st.state.audit.observe_xe(target_id, p.counters()) {
        tracing::warn!(target_id = %target_id, "Extended Events: the session dropped events or was restarted");
    }
}

/// Reads the session's proofs and rebuilds the poll texts; first, the
/// preference rule (decision 6, every 5 minutes): SQL Server Audit, when
/// usable, ends this stream (the core restarts it on that source).
async fn reprobe(st: &mut Stream<'_>, s: &mut Session) -> Result<(), ConnectorError> {
    let target = st.target;
    if Box::pin(audit_usable(s, target, st.major, &st.perms))
        .await
        .map_err(SsError::into_connector_error)?
    {
        tracing::info!(target_id = %target.id, "SQL Server Audit is usable: the Audit stream moves to it (preference rule)");
        return Err(target_error(FailureCode::Unsupported));
    }
    let name = st.name.clone();
    let p = Box::pin(probe::probe(s, &name, Stage::Introspection))
        .await
        .map_err(SsError::into_connector_error)?;
    if !p.running {
        tracing::warn!(target_id = %target.id, "Extended Events: the named session is not running or has no event_file target");
        return Err(target_error(FailureCode::Unsupported));
    }
    let Some(pattern) = p.pattern() else {
        tracing::warn!(target_id = %target.id, "Extended Events: the session's file name cannot be used in a file pattern");
        return Err(target_error(FailureCode::Unsupported));
    };
    let (Some(start), Some(from)) = (sql::xe_poll(&pattern, false), sql::xe_poll(&pattern, true))
    else {
        return Err(target_error(FailureCode::Internal));
    };
    if on_pattern(&mut st.cursor, &pattern) {
        tracing::warn!(target_id = %target.id, "Extended Events: the session's file set changed (folder or file name): reading the new set from its start");
        st.state.audit.note_gap(&target.id);
        st.state.audit.note_dropped(&target.id, 1);
    }
    observe(st, &p);
    st.poll_start = start;
    st.poll_from = from;
    st.probe = Some(p);
    st.reprobe_at = Instant::now();
    Ok(())
}

/// What one poll returned.
struct Polled {
    records: Vec<XeRecord>,
    returned: usize,
    malformed: u64,
}

/// Sends one poll; each row becomes a record as it ends, alone under panic
/// isolation.
async fn poll_records(
    s: &mut Session,
    text: &str,
    kind: own::PollKind,
    file: &str,
    offset: i64,
    top: usize,
) -> Result<Polled, SsError> {
    let params = [
        Param::NVarChar(file.to_owned()),
        Param::BigInt(offset),
        Param::BigInt(i64::try_from(top).unwrap_or(i64::MAX)),
    ];
    s.credit_poll(text, kind);
    let mut out = Polled {
        records: Vec::new(),
        returned: 0,
        malformed: 0,
    };
    let mut row: Vec<Value> = Vec::with_capacity(sql::XE_POLL_COLUMNS);
    s.rpc(
        text,
        &params,
        Stage::Introspection,
        Shape {
            columns: sql::XE_POLL_COLUMNS,
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
                    match databastion_core::isolate(|| XeRecord::from_row(r)) {
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
    let top = st.batch + st.cursor.skip as usize;
    let polled = match st.cursor.file.clone() {
        None => {
            Box::pin(poll_records(
                s,
                &st.poll_start.clone(),
                own::PollKind::Start,
                "",
                0,
                top,
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
            ))
            .await
        }
    };
    let polled = match polled {
        Ok(p) => {
            st.batch = (st.batch * 2).min(BATCH);
            p
        }
        Err(e)
            if matches!(e.number, Some(ERR_BAD_OFFSET | ERR_FILE_GONE))
                && st.cursor.file.is_some() =>
        {
            // The position is no longer in the file set (rollover, a file
            // deleted): from the oldest file, leaving out what was read;
            // whatever was between is lost (M4).
            let before = st.cursor.pattern.clone();
            Box::pin(reprobe(st, s)).await?;
            if st.cursor.pattern == before && st.cursor.file.is_some() {
                tracing::warn!(target_id = %target_id, "Extended Events: the saved position is no longer in the session's files (rollover): reading from the oldest file");
                on_bad_position(&mut st.cursor, sql::xe_file_key);
                st.state.audit.note_gap(&target_id);
                st.state.audit.note_dropped(&target_id, 1);
            }
            return Ok(true);
        }
        Err(e) if e.code == FailureCode::ResourceLimit && !e.fatal && st.batch > MIN_BATCH => {
            st.batch = (st.batch / 2).max(MIN_BATCH);
            return Ok(true);
        }
        Err(e) => return Err(e.into_connector_error()),
    };
    st.state.audit.note_dropped(&target_id, polled.malformed);
    let b = batch(
        &st.cursor,
        polled.records,
        polled.returned,
        top,
        sql::xe_file_key,
    );
    if !b.kept.is_empty() {
        st.state.audit.note_record(&target_id);
    }
    let history = st.cursor.history_us;
    let mut records = b.kept;
    if let Some(h) = history {
        records.retain(|r| r.time_us >= h);
    }
    if st.skip > 0 {
        let n = (st.skip as usize).min(records.len());
        records.drain(..n);
        st.state.audit.note_dropped(&target_id, n as u64);
        st.skip = 0;
    }
    let statman = st.statman;
    if databastion_core::isolate(|| events::context(&mut records, statman)).is_none() {
        // The context pass panicked: every record of the read is converted
        // without it (counted twice at worst, never dropped).
        for r in &mut records {
            r.skip = false;
            r.procedure = None;
        }
        st.state.audit.note_dropped(&target_id, 1);
    }
    for r in &records {
        let out = databastion_core::isolate(|| {
            let (ev, _) = events::convert(r)?;
            if st.own_routine(r, &ev) {
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
    st.cursor = b.next;
    if b.gap {
        tracing::warn!(target_id = %target_id, "Extended Events: one buffer holds more events than the bound: the rest of it is dropped");
        st.state.audit.note_gap(&target_id);
        st.state.audit.note_dropped(&target_id, 1);
    }
    Ok(b.full)
}
