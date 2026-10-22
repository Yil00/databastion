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
//!   parameters. The row bound is stream state set inside `read`
//!   ([`size`], ADR-0051 refinement of 2026-10-22, option (b)): `BATCH`
//!   (500) first and after any read that is not full (a deferral, a clamp,
//!   a restart at the oldest file, a re-probe that moved the cursor
//!   included); after a full read, the sized bound: at most
//!   [`size::XE_MAX_ROWS`] and at most 0.75 × `POLL_BYTES` over the largest
//!   row of that read (in wire bytes), never below `BATCH`. A response
//!   over `POLL_BYTES` is cancelled before any of it is handled and read
//!   again at half the size, kept for 10 minutes; a cancel, or a retried
//!   client statement timeout, of a read above `BATCH` caps the reads at
//!   `BATCH` for 10 minutes. Full reads follow one another within a cycle,
//!   and a cycle that ends behind the session's files is followed by the
//!   next one after a bounded pause (`super::cycle`); each poll gets a
//!   credit (its own events are left out only for this session and this
//!   text). Each event's XML is read by
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
//!   usable, and the core restarts it on that source; a switch between the
//!   sources is a gap (`audit.records_dropped`).

pub(crate) mod events;
pub(crate) mod probe;
#[cfg(test)]
mod sim_tests;
pub(crate) mod size;
pub(crate) mod xml;

use std::time::{Duration, Instant};

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::config::TargetConfig;
use databastion_core::{AuditConfig, ConnectorError, EventSink, FailureCode};

use super::own;
use super::{
    APP, Batch, Below, Cursor, FLOOR_MAX, OWN_FILE_BYTES, OWN_SESSIONS, POLL_BYTES, REEVALUATE,
    REPROBE, on_bad_position, on_pattern, target_error,
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
/// How far Extended Events' `timestamp_utc` can run ahead of the
/// `SYSUTCDATETIME()` an own session's end is computed on: measured up to
/// 0.9 ms (2019), 3.5 ms (2022) and 2.8 ms (2025); every statement of an
/// own session is matched up to this long after its clean end (a session
/// that reuses the SPID within it, with the agent's login and one of its
/// exact texts or credits, is the residual of decision 6).
pub(crate) const XE_CLOCK_SKEW_US: i64 = 20_000;
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
    gap_store: Option<CursorStore>,
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
    /// The size of the next read ([`size`]), set inside [`read`].
    size: size::ReadSize,
    /// Time spent in poll statements, summed ([`super::cycle::Read::statements`]).
    poll_time: Duration,
    /// The statistics exclusion applies (an allow-listed build).
    statman: bool,
    /// The server's major version and the account's server permissions at
    /// the last evaluation (the preference rule at each re-probe).
    major: i64,
    perms: std::collections::BTreeSet<String>,
    /// The poll interval (the bound of a deferral).
    poll: std::time::Duration,
    /// Unpaired statistics builds deferred (refinement of 2026-10-16,
    /// item 4, for case 2 builds; of 2026-10-18 for any session's).
    deferrals: events::Deferrals,
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
        super::save_gap(self.gap_store.as_ref(), self.state, &self.target.id);
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
        if own::session_at_skewed(&self.target.id, spid, r.time_us, text, XE_CLOCK_SKEW_US)
            .is_none()
        {
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

/// Whether a record comes from one of the agent's own sessions within its
/// lifetime, with both principals the agent's login and, when present, its
/// application name (decision 6; the source records no client address):
/// the own-session part of the rule, without the text and credit part.
/// The event time (µs) of the latest failed login (error 18456) among
/// `records` whose name tried is not the agent's `account` (re-review of
/// #280, N3).
fn failed_login_proof<'a>(
    records: impl IntoIterator<Item = &'a XeRecord>,
    account: &str,
) -> Option<i64> {
    records
        .into_iter()
        .filter(|r| r.is_failed_login_18456() && !r.login().eq_ignore_ascii_case(account))
        .map(|r| r.time_us)
        .max()
}

fn own_session(target: &TargetConfig, r: &XeRecord) -> bool {
    let Some(e) = &r.event else { return false };
    if e.statement_cut {
        return false;
    }
    let Some(spid) = e.session_id else {
        return false;
    };
    let text = e.statement.as_deref().map_or("", |s| s.as_str());
    let account = &target.account;
    let both = |p: &Option<String>| {
        p.as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(account))
    };
    own::session_at_skewed(&target.id, spid, r.time_us, text, XE_CLOCK_SKEW_US).is_some()
        && both(&e.server_principal)
        && both(&e.session_principal)
        && e.client_app
            .as_deref()
            .is_none_or(|a| a.is_empty() || a == APP)
}

/// The read-back events of a read, as `(spid, stamp)`, for
/// [`own::calibrate`]: `sql_statement_completed` with exactly the
/// read-back text (not cut), a session id, both principals the agent's
/// login and the agent's application name (or none), the checks of
/// [`own_session`] (review L1). Another login's read-back is ignored: it
/// gives neither a difference nor an ambiguity.
pub(crate) fn readbacks(records: &[XeRecord], account: &str) -> Vec<(i64, i64)> {
    let agent = |p: &Option<String>| {
        p.as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(account))
    };
    records
        .iter()
        .filter(|r| r.kind() == xml::Kind::SqlStatementCompleted)
        .filter_map(|r| {
            let e = r.event.as_ref()?;
            let ok = !e.statement_cut
                && e.statement.as_deref().map(|t| t.as_str())
                    == Some(crate::conn::SESSION_READBACK)
                && agent(&e.server_principal)
                && agent(&e.session_principal)
                && e.client_app
                    .as_deref()
                    .is_none_or(|a| a.is_empty() || a == APP);
            ok.then_some((e.session_id?, r.time_us))
        })
        .collect()
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
        // No history replay. The event clock runs ahead of the server time
        // the first start is read on by up to the skew: what ran just
        // before the start can be stamped just after it (measured: 2 ms).
        cursor.first_start(
            session.own.as_ref().map(own::Handle::server_now),
            XE_CLOCK_SKEW_US,
        );
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
        gap_store: cfg.counters(super::GAP_FACTS),
        cursor,
        saved: None,
        skip,
        probe: None,
        poll_start: String::new(),
        poll_from: String::new(),
        reprobe_at: Instant::now(),
        evaluated_at: None,
        size: size::ReadSize::default(),
        poll_time: Duration::ZERO,
        statman: false,
        major: 0,
        perms: std::collections::BTreeSet::new(),
        poll: cfg.poll_interval(),
        deferrals: events::Deferrals::default(),
    };
    let tls = crate::tls::configs(target.sqlserver_settings().ca_file.as_deref())
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    let mut log = super::cycle::BehindLog::default();
    loop {
        if session.is_poisoned() || session.is_stale() {
            let old = std::mem::replace(
                &mut session,
                crate::conn::connect(target, &tls, &state.choice, super::POLL_TIMEOUT)
                    .await
                    .map_err(SsError::into_connector_error)?,
            );
            old.close().await;
            Box::pin(super::observe_server_run(state, &target.id, &mut session)).await;
        }
        let end = match Box::pin(cycle(&mut st, &mut session, sink, &mut log)).await {
            Ok(end) => end,
            Err(e) => {
                st.save();
                session.close().await;
                return Err(e);
            }
        };
        st.save();
        tokio::time::sleep(end.pause(cfg.poll_interval())).await;
    }
}

/// One cycle: the account and proofs when due, the session's counters,
/// then reads until caught up.
async fn cycle(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
    log: &mut super::cycle::BehindLog,
) -> Result<super::cycle::End, ConnectorError> {
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
        observe(st, &p, s.own.as_ref().map(own::Handle::server_now));
        st.probe = Some(p);
    }
    // A deferral or a clamped position ends the cycle as a read that
    // reached the end (`read` returns `false`): the poll interval.
    let mut reads = Reads { st, s, sink };
    Box::pin(super::cycle::run(&mut reads, log)).await
}

/// One cycle's reads ([`super::cycle::run`]).
struct Reads<'r, 's> {
    st: &'r mut Stream<'s>,
    s: &'r mut Session,
    sink: &'r EventSink,
}

impl super::cycle::Reads for Reads<'_, '_> {
    fn target_id(&self) -> &str {
        &self.st.target.id
    }

    fn source(&self) -> &'static str {
        "Extended Events"
    }

    fn walking_history(&self) -> bool {
        self.st.cursor.walking_history()
    }

    async fn read_once(&mut self) -> Result<super::cycle::Read, ConnectorError> {
        let before = self.st.poll_time;
        let full = Box::pin(read(self.st, self.s, self.sink)).await?;
        self.st.save();
        Ok(super::cycle::Read {
            full,
            statements: self.st.poll_time.saturating_sub(before),
        })
    }

    async fn between(&mut self) -> Result<(), ConnectorError> {
        if self.st.probe.is_none() {
            Box::pin(reprobe(self.st, self.s)).await?;
        }
        Ok(())
    }
}

/// A restart of the session or grown drop counters: a gap.
/// `server_now`: the server's time on the stream's session (the floor of
/// the failed-login proof when it is cleared here).
fn observe(st: &mut Stream<'_>, p: &probe::Probe, server_now: Option<i64>) {
    let target_id = &st.target.id;
    if st
        .cursor
        .session
        .is_some_and(|c| !probe::same_start(c, p.create_us))
    {
        tracing::warn!(target_id = %target_id, "Extended Events: the session was stopped and started (create_time changed): what happened in between was not recorded");
        st.state.audit.note_gap(target_id);
        // Its events may have changed: the failed-login proof starts over.
        st.state.audit.clear_failed_login(target_id, server_now);
        st.state.audit.note_dropped(target_id, 1);
    }
    st.cursor.session = Some(p.create_us);
    // #280 re-review L-b: the events the agent can see changed (one added
    // or dropped, a predicate added or removed, a catalog read that failed):
    // a predicate it cannot read may have changed too.
    // The last facts are kept per target with the proof (security review
    // L2): a new stream compares with them; with none, the proof is taken
    // again.
    match st.state.audit.swap_event_facts(target_id, p.event_facts()) {
        Some(prev) if prev == p.event_facts() => {}
        Some(_) => {
            tracing::info!(target_id = %target_id, "Extended Events: the session's events changed: the failed-login proof is taken again");
            st.state.audit.clear_failed_login(target_id, server_now);
        }
        None => st.state.audit.clear_failed_login(target_id, server_now),
    }
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
        st.state
            .audit
            .clear_failed_login(&target.id, s.own.as_ref().map(own::Handle::server_now));
        st.state.audit.note_dropped(&target.id, 1);
    }
    observe(st, &p, s.own.as_ref().map(own::Handle::server_now));
    st.poll_start = start;
    st.poll_from = from;
    st.probe = Some(p);
    st.reprobe_at = Instant::now();
    Ok(())
}

/// The records of an Extended Events read from `cursor` (the server
/// skipped the first `cursor.skip` events after the position, all of the
/// buffer `cursor.buffer`), `returned` rows asked with `asked`: those at
/// or before a refused position left out, the next position, and the gap
/// ([`super::batch`]; a buffer of any size is walked with reads of at most
/// `asked` events, none read twice, none lost).
pub(crate) fn xe_batch(
    cursor: &Cursor,
    records: Vec<XeRecord>,
    returned: usize,
    asked: usize,
) -> Batch<XeRecord> {
    super::batch(cursor, records, returned, asked, sql::xe_file_key)
}

/// The position after a read from `cursor` that returned events at
/// `positions` (in order), `full` when more may follow; and whether one
/// buffer went over [`super::MAX_SKIP`] (a gap; an event buffer holds
/// at most a few thousand events, `MAX_MEMORY` 4 MB by default, three
/// buffers) ([`super::next_position`]). A
/// read cut before one of its events (the deferral of a build) is a full
/// read of the events before it.
pub(crate) fn xe_next(cursor: &Cursor, positions: &[(String, i64)], full: bool) -> (Cursor, bool) {
    super::next_position(cursor, positions, full, sql::xe_file_key)
}

/// What one poll returned.
pub(crate) struct Polled {
    pub(crate) records: Vec<XeRecord>,
    pub(crate) returned: usize,
    pub(crate) malformed: u64,
    /// The largest row of the response, in wire bytes ([`row_wire_bytes`]).
    pub(crate) largest_row: usize,
    /// Every row's wire bytes, summed.
    pub(crate) bytes: usize,
}

/// The bytes a row took on the wire, as the client counts them: each
/// value's bytes (UTF-16 for text, as sent) and its length prefix (2
/// bytes, the widest of the poll's column types), and the row token. An
/// estimate within a few bytes per column of the TDS framing, used to
/// size the next read (refinement of 2026-10-22, M2).
pub(crate) fn row_wire_bytes(row: &[Value]) -> usize {
    1 + row
        .iter()
        .map(|v| {
            2 + match v {
                Value::Null => 0,
                Value::Bit(_) => 1,
                Value::Int(_) => 8,
                Value::Text(t) => t.encode_utf16().count() * 2,
                Value::Binary(b) | Value::DateTime2(b) => b.len(),
            }
        })
        .sum::<usize>()
}

/// Sends one poll; each row becomes a record as it ends, alone under panic
/// isolation.
pub(crate) async fn poll_records(
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
        largest_row: 0,
        bytes: 0,
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
                    let wire = row_wire_bytes(&r);
                    out.largest_row = out.largest_row.max(wire);
                    out.bytes = out.bytes.saturating_add(wire);
                    match databastion_core::isolate(|| XeRecord::from_row(r)) {
                        Some(Ok(mut rec)) => {
                            rec.index = out.records.len();
                            out.records.push(rec);
                        }
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

/// One read from the position; `true` when more is to be read at once (a
/// full read, or a read retried smaller). Sets the size of the next read
/// (`st.size`, ADR-0051 refinement of 2026-10-22, M1) on every path.
async fn read(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
) -> Result<bool, ConnectorError> {
    let target_id = st.target.id.clone();
    let read_started_ms = super::agent_now_ms();
    // An event stamped below the floor reaches the file at most the
    // dispatch latency after its stamp (`INFINITE` or not visible: the
    // bound): the history and floor bound.
    let delay = st
        .probe
        .as_ref()
        .and_then(|p| p.dispatch_latency)
        .map_or(FLOOR_MAX, |d| {
            d.saturating_add(std::time::Duration::from_micros(
                XE_CLOCK_SKEW_US.unsigned_abs(),
            ))
        });
    // The server skips the events of the next buffer already handled
    // (`sql::XE_POLL_FROM`): a read returns at most `top` events, the size
    // the last read set (`size`: `BATCH`, the sized bound up to
    // `XE_MAX_ROWS` after a full read, less after a cancel).
    let top = st.size.rows();
    let skip = st.cursor.skip;
    let poll_started = Instant::now();
    let polled = match st.cursor.file.clone() {
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
    st.poll_time = st.poll_time.saturating_add(poll_started.elapsed());
    let polled = match polled {
        Ok(p) => p,
        Err(e)
            if matches!(e.number, Some(ERR_BAD_OFFSET | ERR_FILE_GONE))
                && st.cursor.file.is_some() =>
        {
            // The position is no longer in the file set (rollover, a file
            // deleted): from the oldest file, leaving out what was read;
            // whatever was between is lost (M4).
            st.size.restarted(Instant::now());
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
        Err(e) => {
            // A response above `POLL_BYTES` (nothing of it handled), or the
            // client's deadline on a read above `BATCH` rows, on a session
            // the cancel left usable: read again smaller, from the same
            // position (refinement of 2026-10-22, M2). Anything else fails
            // the stream, as before.
            let now = Instant::now();
            return match st.size.failed(&e, s.is_poisoned(), now) {
                Some(retry) => {
                    st.state.audit.note_xe_retry(&target_id, retry);
                    st.size.log(&target_id, retry, top, now);
                    Ok(true)
                }
                None => Err(e.into_connector_error()),
            };
        }
    };
    let largest_row = polled.largest_row;
    st.state
        .audit
        .note_xe_read(&target_id, top, polled.returned);
    let positions: Vec<(String, i64)> = polled
        .records
        .iter()
        .map(|r| (r.file.clone(), r.offset))
        .collect();
    let mut b = xe_batch(&st.cursor, polled.records, polled.returned, top);
    let mut positions = positions;
    // Security review of #276, L7: a file of the set whose order key is
    // above the session's current file is not one the session wrote yet (a
    // file named by someone else in its folder): the position must not
    // move past the current file, or what the session writes next would be
    // skipped. The current file is read again first (a rollover since the
    // last re-probe); a file still beyond it is a gap, its events are left
    // out and the position stays before it.
    if beyond_current(st.probe.as_ref(), &positions).is_some() {
        let before = (st.cursor.pattern.clone(), st.cursor.session);
        Box::pin(reprobe(st, s)).await?;
        // #276 re-review N1: a re-probe that moved to a new file set (the
        // cursor was reset to its start) or found the session started
        // again: this batch was read from the cursor before it, and its
        // next position must not replace the reset one. The read ends
        // without consuming it; the next read starts from the cursor the
        // re-probe left (the gap is already noted).
        if reprobe_moved(&before, &st.cursor) {
            tracing::info!(target_id = %target_id, "Extended Events: the session's file set or start changed during a read: reading again from the new position");
            st.size
                .received(largest_row, size::Path::Base, Instant::now());
            return Ok(true);
        }
    }
    st.state.audit.note_dropped(&target_id, polled.malformed);
    let clamped = beyond_current(st.probe.as_ref(), &positions);
    if let Some(at) = clamped {
        tracing::warn!(target_id = %target_id, "Extended Events: a file of the session's set is named after the session's current file: its events are left out and the position stays before it (a gap)");
        b.kept.retain(|r| r.index < at);
        positions.truncate(at);
        (b.next, b.gap) = xe_next(&st.cursor, &positions, true);
        // No settle of the history phase on a clamped read.
        b.full = true;
        st.state.audit.note_gap(&target_id);
        st.state.audit.note_dropped(&target_id, 1);
    }
    if !b.kept.is_empty() {
        st.state.audit.note_record(&target_id);
    }
    // Events stamped before the first start are history, whenever they
    // reach the file (the dispatch latency delays them past the first,
    // caught-up read); after that read, until the floor ends, they are
    // counted as dropped (re-review N1: the server's clock may have
    // stepped back).
    let mut records = b.kept;
    // #280 re-review L-b (security review L1 of the follow-up): a statement
    // that may change an event session, found among every record of the
    // read, those the history, floor and skip filters then drop included;
    // its place and time cut the failed-login proof below.
    let changed = records
        .iter()
        .rev()
        .find(|r| r.may_change_event_session())
        .map(|r| (r.index, r.time_us));
    // The agent's sessions on this source's clock: each read-back event
    // calibrates its session (own::calibrate), before any own rule.
    own::calibrate(&target_id, &readbacks(&records, &st.target.account));
    let mut below_floor: Vec<usize> = Vec::new();
    // The records handled, by order (`max_seen_us`): those of this read
    // before a cut only, set below.
    let handled: Vec<(usize, i64)> = records.iter().map(|r| (r.index, r.time_us)).collect();
    let mut seen = st.cursor.max_seen_us;
    records.retain(|r| {
        let class = st.cursor.below(r.time_us, seen, delay);
        seen = Cursor::seen(seen, r.time_us);
        match class {
            Some(Below::History) => false,
            Some(Below::Dropped) => {
                below_floor.push(r.index);
                false
            }
            None => true,
        }
    });
    if st.skip > 0 {
        let n = (st.skip as usize).min(records.len());
        records.drain(..n);
        st.state.audit.note_dropped(&target_id, n as u64);
        st.skip = 0;
    }
    // The proof that a filtered `error_reported` admits failed logins
    // (re-review of #280, N3): from records past the history and floor
    // filter only, never a failed login of the agent's own account. A
    // statement that may change an event session (#280 re-review L-b)
    // clears it, and only what follows it in the file proves it again.
    // Only a failed login after it, in the file and in time (file order
    // follows the session's per-CPU buffers, security review L4), proves
    // it again.
    // Across reads too: the proof is then taken only from a failed login
    // stamped after the change, whichever read it comes in (a later read
    // can hold an earlier event: fail closed).
    if let Some((_, t)) = changed {
        tracing::info!(target_id = %target_id, "Extended Events: a statement that may change an event session was read: the failed-login proof is taken again");
        st.state.audit.clear_failed_login(&target_id, Some(t));
    }
    let after = records
        .iter()
        .filter(|r| changed.is_none_or(|(i, t)| r.index > i && r.time_us > t));
    if let Some(at) = failed_login_proof(after, &st.target.account) {
        // Aged on the server's clock against the agent's own session's
        // read-back of it, so that the 24 h window does not depend on the
        // skew between the two clocks (#280 re-review L-b).
        let server_now = s.own.as_ref().map(own::Handle::server_now);
        st.state.audit.note_failed_login(&target_id, at, server_now);
    }
    let unreadable = records.iter().filter(|r| r.unreadable).count();
    if unreadable > 0 {
        tracing::warn!(target_id = %target_id, unreadable, "Extended Events: statement events whose data could not be read: reported as reads of *");
    }
    let statman = st.statman;
    let target = st.target;
    let own = |r: &XeRecord| own_session(target, r);
    let mut context = databastion_core::isolate(|| events::context(&mut records, statman, &own));
    // An unpaired statistics build (case 2's of the agent's sessions, or
    // any session's): the read ends just before it, once and for a bounded
    // time (refinement of 2026-10-16, item 4, and of 2026-10-18); what
    // follows it is read again by the next read, from it. The position
    // stays before it, so a restart reads it again: never lost.
    let mut next = b.next;
    let mut gap = b.gap;
    let mut cut = None;
    if context.is_some() {
        let latency = st
            .probe
            .as_ref()
            .and_then(|p| p.dispatch_latency)
            .unwrap_or(events::MAX_DEFERRAL);
        let bound = latency.min(st.poll.saturating_mul(2));
        // A full read: more rows follow on the server (its index space is
        // every row it returned and read).
        let full = b.full.then_some(positions.len());
        cut = st
            .deferrals
            .cut(&records, statman, Instant::now(), bound, full);
    }
    // A deferral waits a poll interval; a cut of a full read reads on at
    // once.
    let waits = cut.is_some_and(|c| c.wait);
    let cut = cut.map(|c| c.at);
    if let Some(at) = cut {
        records.retain(|r| r.index < at);
        for r in &mut records {
            r.skip = false;
            r.procedure = None;
        }
        context = databastion_core::isolate(|| events::context(&mut records, statman, &own));
        (next, gap) = xe_next(&st.cursor, positions.get(..at).unwrap_or_default(), true);
        tracing::debug!(target_id = %target_id, "Extended Events: a statistics build not paired yet: the read ends before it");
    }
    let below_floor = below_floor
        .iter()
        .filter(|i| cut.is_none_or(|at| **i < at))
        .count() as u64;
    if below_floor > 0 {
        tracing::warn!(target_id = %target_id, below_floor, "Extended Events: events stamped before the first start read after the stream caught up (late, or the server's clock stepped back): not reported, counted as dropped");
        st.state.audit.note_dropped(&target_id, below_floor);
    }
    if let Some(n) = context {
        st.state.audit.note_statistics(&target_id, n);
    } else {
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
    let prev_history = st.cursor.history_us;
    let seen = super::advance_seen(st.cursor.max_seen_us, &handled, cut);
    st.cursor = next;
    st.cursor.max_seen_us = seen;
    if !b.full && cut.is_none() {
        st.cursor.settle(prev_history, read_started_ms, delay);
    }
    super::note_read_faults(
        st.state,
        &target_id,
        super::Source::Xevents,
        gap,
        b.out_of_order,
    );
    // A deferral ends the cycle: the next read waits a poll interval. A
    // full read cut before a build whose pair may be in the rows that
    // follow reads on (it moved the position by half the read at least).
    // That read, and a full read not cut, set the next one to the sized
    // bound; any other read to `BATCH` (M1).
    let more = b.full && !waits && clamped.is_none();
    let path = if more {
        size::Path::Sized
    } else {
        size::Path::Base
    };
    st.size.received(largest_row, path, Instant::now());
    Ok(more)
}

/// Whether the re-probe inside a read changed what `before` (the cursor's
/// pattern and session start before it) described (#276 re-review N1): a
/// new file pattern (the cursor was reset, as [`super::on_pattern`]
/// reports it) or another start of the session (beyond the `create_time`
/// jitter, as [`observe`] reports it). A first pattern or start is not a
/// change.
pub(crate) fn reprobe_moved(before: &(Option<String>, Option<i64>), after: &Cursor) -> bool {
    let pattern = before
        .0
        .as_deref()
        .is_some_and(|p| after.pattern.as_deref() != Some(p));
    let session = matches!(
        (before.1, after.session),
        (Some(a), Some(b)) if !probe::same_start(a, b)
    );
    pattern || session
}

/// The index of the first read position in a file whose order key is
/// above that of the session's current file (`probe`), if any.
pub(crate) fn beyond_current(
    probe: Option<&probe::Probe>,
    positions: &[(String, i64)],
) -> Option<usize> {
    let current = sql::xe_file_key(&probe?.current_file)?;
    positions
        .iter()
        .position(|(f, _)| sql::xe_file_key(f).is_some_and(|k| k > current))
}

#[cfg(test)]
mod readback_tests {
    use super::events::tests::rec;
    use super::*;

    fn readback(name: &str, text: &str, login: &str, app: &str, cut: bool) -> XeRecord {
        let t = text.replace('&', "&amp;").replace('<', "&lt;");
        let mut r = rec(
            name,
            &[("statement", &t)],
            &[
                ("session_id", "81"),
                ("server_principal_name", login),
                ("session_server_principal_name", login),
                ("client_app_name", app),
            ],
        );
        r.time_us = 7;
        if let Some(e) = r.event.as_mut() {
            e.statement_cut = cut;
        }
        r
    }

    /// Review L1 and L2: only the agent's own read-back events calibrate.
    #[test]
    fn only_the_agents_read_back_events_calibrate() {
        let rb = crate::conn::SESSION_READBACK;
        let ok = readback("sql_statement_completed", rb, "databastion", APP, false);
        assert_eq!(readbacks(&[ok], "databastion"), [(81, 7)]);
        let none = readback("sql_statement_completed", rb, "databastion", "", false);
        assert_eq!(
            readbacks(&[none], "DataBastion"),
            [(81, 7)],
            "no application name"
        );
        let near = format!("{rb} ");
        for (r, why) in [
            (
                readback("sql_statement_completed", rb, "databastion", APP, true),
                "cut",
            ),
            (
                readback("sql_statement_completed", &near, "databastion", APP, false),
                "a near copy",
            ),
            (
                readback("sp_statement_completed", rb, "databastion", APP, false),
                "sp_statement_completed",
            ),
            (
                readback("sql_statement_completed", rb, "mallory", APP, false),
                "another login",
            ),
            (
                readback(
                    "sql_statement_completed",
                    rb,
                    "databastion",
                    "SQLCMD",
                    false,
                ),
                "another application",
            ),
        ] {
            assert!(readbacks(&[r], "databastion").is_empty(), "{why}");
        }
        // Another login's read-back is ignored: no ambiguity with the
        // agent's.
        let t = "xe-readback-foreign";
        own::reset(t);
        let at = 9_000_000_000;
        let _h = own::opened(t, 81, at, 3_000, None, Instant::now());
        let mut mine = readback("sql_statement_completed", rb, "databastion", APP, false);
        mine.time_us = at - 38_000;
        let mut theirs = readback("sql_statement_completed", rb, "mallory", APP, false);
        theirs.time_us = at - 20_000;
        own::calibrate(t, &readbacks(&[mine, theirs], "databastion"));
        assert_eq!(
            own::session_at(t, 81, at, "").unwrap().clock,
            own::SourceClock::Offset(38_000)
        );
    }
}

#[cfg(test)]
mod current_file_tests {
    use super::*;

    /// Security review of #276, L7: a read position in a file named after
    /// the session's current file is found; files up to the current one,
    /// names of another form and an unknown current file are not.
    #[test]
    fn positions_beyond_the_current_file_are_found() {
        let p = probe::Probe {
            current_file: "/x/databastion_xe_0_134.xel".to_owned(),
            ..probe::Probe::default()
        };
        let pos = |list: &[&str]| -> Vec<(String, i64)> {
            list.iter().map(|f| ((*f).to_owned(), 4096)).collect()
        };
        let ok = pos(&["/x/databastion_xe_0_133.xel", "/x/databastion_xe_0_134.xel"]);
        assert_eq!(beyond_current(Some(&p), &ok), None);
        let crafted = pos(&[
            "/x/databastion_xe_0_133.xel",
            "/x/databastion_xe_0_134.xel",
            "/x/databastion_xe_0_999999999999999999.xel",
        ]);
        assert_eq!(beyond_current(Some(&p), &crafted), Some(2));
        assert_eq!(beyond_current(None, &crafted), None);
        let odd = probe::Probe {
            current_file: "/x/other.xel".to_owned(),
            ..probe::Probe::default()
        };
        assert_eq!(beyond_current(Some(&odd), &crafted), None);
        // The position stays before the file: the read is cut there.
        let (next, gap) = xe_next(&Cursor::default(), &crafted[..2], true);
        assert!(!gap);
        assert_ne!(next.file.as_deref(), Some(crafted[2].0.as_str()));
    }

    /// #276 re-review N1: the re-probe of a read that finds a new file set
    /// or another start of the session ends the read without its batch;
    /// the next read starts from the cursor the re-probe left, not from the
    /// position computed before it.
    #[test]
    fn a_reprobe_that_moves_ends_the_read() {
        let mut c = Cursor {
            file: Some("/x/databastion_xe_0_133.xel".to_owned()),
            offset: 4096,
            pattern: Some("/x/databastion_xe*.xel".to_owned()),
            session: Some(1_000_000),
            ..Cursor::default()
        };
        let snapshot = |c: &Cursor| (c.pattern.clone(), c.session);
        // The batch's next position, computed before the re-probe.
        let positions = vec![("/x/databastion_xe_0_133.xel".to_owned(), 8192)];
        let (next, _) = xe_next(&c, &positions, true);
        assert!(next.file.is_some(), "a position in the old set");
        // Same set, the same start within the jitter: the batch is kept.
        let before = snapshot(&c);
        assert!(!on_pattern(&mut c, "/x/databastion_xe*.xel"));
        c.session = Some(1_000_000 + 3_000);
        assert!(!reprobe_moved(&before, &c));
        // A new file set: the cursor is reset, and the read must end so
        // that `next` does not overwrite it.
        let before = snapshot(&c);
        assert!(on_pattern(&mut c, "/y/databastion_xe*.xel"));
        assert!(reprobe_moved(&before, &c));
        assert_eq!((c.file.as_deref(), c.offset), (None, 0));
        assert_ne!(
            next.file, c.file,
            "writing `next` back would undo the reset"
        );
        assert_ne!(
            next.pattern, c.pattern,
            "the old position belongs to the old set"
        );
        // The session started again (same set): the read ends too.
        let before = snapshot(&c);
        c.session = Some(9_000_000);
        assert!(reprobe_moved(&before, &c));
        // A first pattern or start is not a change.
        let first = Cursor {
            pattern: Some("/x/databastion_xe*.xel".to_owned()),
            session: Some(1),
            ..Cursor::default()
        };
        assert!(!reprobe_moved(&(None, None), &first));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod failed_login_proof_tests {
    use super::*;
    use crate::audit::xe::events::tests::rec;

    fn failed(login: &str, number: &str, time_us: i64) -> XeRecord {
        let mut r = rec(
            "error_reported",
            &[("error_number", number)],
            &[
                ("session_id", "51"),
                ("session_server_principal_name", login),
            ],
        );
        r.time_us = time_us;
        r
    }

    /// Re-review of #280, N3: the latest 18456 by event time, never a
    /// failed login of the agent's own account nor another error.
    #[test]
    fn the_proof_is_an_18456_of_another_account_by_event_time() {
        let recs = vec![
            failed("jane", "18456", 10),
            failed("Databastion_Agent", "18456", 30),
            failed("bob", "18452", 40),
            failed("bob", "18456", 20),
        ];
        assert_eq!(failed_login_proof(&recs, "databastion_agent"), Some(20));
        assert_eq!(failed_login_proof(&recs[1..3], "databastion_agent"), None);
        assert_eq!(failed_login_proof(&[], "databastion_agent"), None);
    }

    /// #280 re-review L-b: the age is taken on the server's clock (the
    /// event time against the read-back's server time), so the window does
    /// not move with the skew between the two clocks.
    #[test]
    fn the_proof_is_aged_on_the_server_clock_and_cleared_on_a_change() {
        let day = 24 * 3_600 * 1_000_000i64;
        for skew in [0, 3 * day, -3 * day, 25 * day] {
            // The server's clock, `skew` away from the agent's.
            let server_now = 1_800_000_000_000_000i64 + skew;
            let shared = crate::audit::Shared::default();
            // An old event read now proves nothing, whatever the skew.
            shared.note_failed_login("t", server_now - day - 1_000_000, Some(server_now));
            assert!(!shared.facts("t").failed_login_seen, "skew {skew}");
            // A recent one does.
            shared.note_failed_login("t", server_now - 1_000_000, Some(server_now));
            assert!(shared.facts("t").failed_login_seen, "skew {skew}");
            // An older event read later does not move the proof back.
            shared.note_failed_login("t", server_now - 2 * day, Some(server_now));
            assert!(shared.facts("t").failed_login_seen, "skew {skew}");
            // A session restart, a new file set or changed events: taken
            // again.
            shared.clear_failed_login("t", None);
            assert!(!shared.facts("t").failed_login_seen);
            assert!(!shared.facts("other").failed_login_seen);
            // Stamped ahead of the read-back (the event clock's lead): fresh.
            shared.note_failed_login("t", server_now + 2_000, Some(server_now));
            assert!(shared.facts("t").failed_login_seen, "skew {skew}");
            // Without the server's time: nothing proven.
            let none = crate::audit::Shared::default();
            none.note_failed_login("t", server_now, None);
            assert!(!none.facts("t").failed_login_seen);
        }
    }

    /// Engine-matrix failures of the predicate test on PR #316: a change
    /// read in one read sets a floor, and a failed login stamped at or
    /// before it proves nothing in any later read (a later read can hold an
    /// earlier event); one stamped after it does. A clear without a time
    /// keeps the floor.
    #[test]
    fn a_failed_login_before_the_change_proves_nothing_in_a_later_read() {
        let now = 1_800_000_000_000_000i64;
        let shared = crate::audit::Shared::default();
        shared.note_failed_login("t", now - 10_000_000, Some(now));
        assert!(shared.facts("t").failed_login_seen);
        // The ALTER EVENT SESSION, stamped 5 s ago, read now.
        shared.clear_failed_login("t", Some(now - 5_000_000));
        assert!(!shared.facts("t").failed_login_seen);
        // A later read holds a failed login stamped before it, or at it.
        shared.note_failed_login("t", now - 6_000_000, Some(now));
        shared.note_failed_login("t", now - 5_000_000, Some(now));
        assert!(
            !shared.facts("t").failed_login_seen,
            "stamped before the change"
        );
        // A plain clear keeps the floor; an earlier floor does not lower it.
        shared.clear_failed_login("t", None);
        shared.clear_failed_login("t", Some(now - 9_000_000));
        shared.note_failed_login("t", now - 5_500_000, Some(now));
        assert!(!shared.facts("t").failed_login_seen);
        // One stamped after it proves again; another target is apart.
        shared.note_failed_login("t", now - 4_000_000, Some(now));
        assert!(shared.facts("t").failed_login_seen);
        shared.note_failed_login("u", now - 6_000_000, Some(now));
        assert!(shared.facts("u").failed_login_seen);
    }

    /// #280 re-review L-b: a statement that may change an event session
    /// clears the proof; only a failed login after it in the file proves
    /// it again.
    #[test]
    fn an_event_session_statement_before_the_failed_login_is_required() {
        use crate::audit::xe::events::tests::rec;
        let stmt = |text: &str| {
            rec(
                "sql_statement_completed",
                &[("statement", text)],
                &[("session_server_principal_name", "admin")],
            )
        };
        let mut recs = vec![
            failed("jane", "18456", 10),
            stmt(
                "ALTER EVENT SESSION databastion_xe ON SERVER DROP EVENT sqlserver.error_reported",
            ),
            stmt("SELECT 1"),
            failed("bob", "18456", 30),
            failed("ann", "18456", 40),
        ];
        for (i, r) in recs.iter_mut().enumerate() {
            r.index = i;
        }
        recs[1].time_us = 35;
        let changed = recs
            .iter()
            .rev()
            .find(|r| r.may_change_event_session())
            .map(|r| (r.index, r.time_us));
        assert_eq!(changed, Some((1, 35)));
        // After it in the file and in time: `ann` only (`bob` is later in
        // the file but stamped before it, another CPU's buffer).
        let after = recs
            .iter()
            .filter(|r| changed.is_none_or(|(i, t)| r.index > i && r.time_us > t));
        assert_eq!(failed_login_proof(after, "databastion"), Some(40));
        let after = recs[..4]
            .iter()
            .filter(|r| changed.is_none_or(|(i, t)| r.index > i && r.time_us > t));
        assert_eq!(failed_login_proof(after, "databastion"), None);
        assert_eq!(failed_login_proof(&recs, "databastion"), Some(40));
    }

    /// Security review L2: the last event facts live with the proof, per
    /// target, across streams.
    #[test]
    fn event_facts_are_kept_per_target() {
        let shared = crate::audit::Shared::default();
        let a = probe::Probe::default().event_facts();
        let b = probe::Probe {
            missing: 1,
            ..probe::Probe::default()
        }
        .event_facts();
        assert_eq!(shared.swap_event_facts("t", a), None);
        assert_eq!(shared.swap_event_facts("t", a), Some(a));
        assert_eq!(shared.swap_event_facts("t", b), Some(a));
        assert_eq!(shared.swap_event_facts("other", b), None);
    }

    #[test]
    fn event_facts_tell_a_changed_session_apart() {
        let base = probe::Probe {
            failed_logins: true,
            failed_logins_filtered: true,
            ..probe::Probe::default()
        };
        assert_eq!(base.event_facts(), base.clone().event_facts());
        for other in [
            probe::Probe {
                failed_logins_filtered: false,
                ..base.clone()
            },
            probe::Probe {
                failed_logins: false,
                failed_logins_filtered: false,
                ..base.clone()
            },
            probe::Probe {
                filtered: true,
                ..base.clone()
            },
            probe::Probe {
                missing: 1,
                ..base.clone()
            },
            probe::Probe {
                incomplete: true,
                ..base.clone()
            },
        ] {
            assert_ne!(base.event_facts(), other.event_facts());
        }
    }
}
