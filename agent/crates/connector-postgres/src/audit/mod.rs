//! PostgreSQL Audit (P4-A): access events from the pgaudit log (level
//! Full / Partial) or, without a readable log, from `pg_stat_statements`
//! (level Limited, see [`pss`]).
//!
//! - The pgaudit log is read locally from `targets[].postgres.audit_log`
//!   (`jsonlog` or `csvlog`), incrementally, with a cursor persisted
//!   through the core (`databastion_core::audit::tail`); only `AUDIT:`
//!   records are parsed
//!   ([`records`], ADR-0012 obligation 7).
//! - Statement text never leaves the agent (the contract `AccessEvent` has
//!   no field for it): it is only analyzed locally by
//!   `classifiers::query` (literal-free tokens) to name objects the log
//!   does not name and to compute the signals ([`events`]).
//! - The source is chosen with the same probe and rule as `check()`: the
//!   pgaudit log when the level is Full or Partial (log readable, pgaudit
//!   loaded and logging), `pg_stat_statements` when Limited; re-evaluated
//!   every 5 minutes. `check()` reports Full only once the stream has
//!   parsed a pgaudit record in the last 24 h.
//! - Delivery is at most once: the cursor advances when events are handed
//!   to the core, which aggregates them for up to `aggregation_window_s`
//!   before spooling; an agent crash in that window loses those events.

pub(crate) mod events;
pub(crate) mod pss;
pub(crate) mod records;

use std::time::{Duration, Instant, SystemTime};

use databastion_core::config::{PgLogFormat, TargetConfig};
use databastion_core::{AuditConfig, AuditLevel, ConnectorError, EventSink, FailureCode};

use crate::check::{self, CheckState};
use crate::conn::Timeouts;
use crate::error::{PgError, Stage};
use databastion_core::audit::own::OwnAccount;
use databastion_core::audit::tail::{self, TailError, Tailer};
use events::PgOwn;
use records::{AuditRecord, Format, Skip, parse_record_checked};

/// Name of the pgaudit cursor in the core's cursor store.
const CURSOR: &str = "pgaudit";
/// How often the source choice is re-evaluated while streaming.
#[cfg(not(test))]
const REPROBE: Duration = Duration::from_secs(300);
/// Tests: often enough for an integration test to see re-probes.
#[cfg(test)]
const REPROBE: Duration = Duration::from_secs(3);

fn internal() -> ConnectorError {
    PgError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

fn format_of(f: PgLogFormat) -> Format {
    match f {
        PgLogFormat::Jsonlog => Format::Jsonlog,
        PgLogFormat::Csvlog => Format::Csvlog,
    }
}

/// Whether the configured audit log of `target` can be read now (file I/O
/// on a blocking thread).
pub(crate) async fn log_readable(target: &TargetConfig) -> bool {
    let Some(log) = target.postgres_settings().audit_log else {
        return false;
    };
    tokio::task::spawn_blocking(move || tail::readable(&log.path))
        .await
        .unwrap_or(false)
}

/// Source of the stream for a level (the same choice as `check()`'s
/// `audit_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Pgaudit,
    PgStatStatements,
    None,
}

pub(crate) fn source_for(level: AuditLevel) -> Source {
    match level {
        AuditLevel::Full | AuditLevel::Partial => Source::Pgaudit,
        AuditLevel::Limited => Source::PgStatStatements,
        AuditLevel::None => Source::None,
    }
}

/// The agent's own activity for this target (see
/// `databastion_core::audit::own`).
fn own_account(
    cfg: &AuditConfig,
    target: &TargetConfig,
    pre: &check::Prerequisites,
    state: &CheckState,
) -> PgOwn {
    let core = OwnAccount::new(
        &target.account,
        Some(crate::conn::APPLICATION_NAME),
        pre.own_addr,
        u64::from(cfg.max_sample_rows()),
        state.own_usage(&target.id),
    )
    .persisted(cfg);
    PgOwn::new(core, state.own_statements(&target.id))
}

/// State kept across source re-evaluations.
struct PgauditState {
    tailer: Option<Tailer>,
    format: Format,
    builder: events::PgauditEvents,
    reported_oversized: u64,
}

/// `Connector::audit_stream` for PostgreSQL.
///
/// The source is chosen from the same probe and rule as `check()`
/// (`check::prerequisites`): the pgaudit log for Full / Partial,
/// `pg_stat_statements` for Limited, none otherwise (an error: the core
/// retries later). The choice is re-evaluated every [`REPROBE`].
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg.target().ok_or_else(internal)?;
    let timeouts = Timeouts::new(cfg.statement_timeout().min(Duration::from_secs(30)));
    let mut pgaudit: Option<PgauditState> = None;
    let mut pss_session: Option<(crate::conn::Session, pss::PssPoller)> = None;
    // A poller whose session was closed for a re-probe.
    let mut pss_idle: Option<pss::PssPoller> = None;
    let several = target.postgres_settings().databases.len() > 1;
    loop {
        // One Audit connection at a time (phase 7, ADR-0025 decision 11):
        // the held pg_stat_statements session probes its own database;
        // with other databases to probe, it is closed first and reopened
        // after.
        if several {
            if let Some((session, poller)) = pss_session.take() {
                drop(session);
                pss_idle = Some(poller);
            }
        }
        let held = pss_session.as_ref().map(|(s, p)| (p.database(), s));
        let pre = check::prerequisites_with(target, timeouts, held)
            .await
            .map_err(PgError::into_connector_error)?;
        match source_for(pre.level) {
            Source::Pgaudit => {
                pss_session = None;
                pss_idle = None;
                let st = match pgaudit.as_mut() {
                    Some(st) => st,
                    None => {
                        let log = target.postgres_settings().audit_log.ok_or_else(internal)?;
                        tracing::info!(target_id = %target.id, "audit source: pgaudit log");
                        let format = format_of(log.format);
                        pgaudit.insert(PgauditState {
                            tailer: Some(Tailer::new(
                                log.path,
                                format.framing(),
                                cfg.cursor(CURSOR),
                            )),
                            format,
                            builder: events::PgauditEvents::new(own_account(
                                cfg, target, &pre, state,
                            )),
                            reported_oversized: 0,
                        })
                    }
                };
                st.builder.set_catalogs(pre.catalogs.clone());
                if let Err(kind) = pgaudit_run(cfg, target, sink, state, st, &pre.severity).await? {
                    tracing::warn!(
                        target_id = %target.id,
                        kind = %kind,
                        "pgaudit log unreadable; re-evaluating the audit source"
                    );
                    pgaudit = None;
                    tokio::time::sleep(cfg.poll_interval()).await;
                }
            }
            Source::PgStatStatements => {
                pgaudit = None;
                if let Some(poller) = pss_idle.take() {
                    let session = pss::reopen(target, timeouts, &poller)
                        .await
                        .map_err(PgError::into_connector_error)?;
                    pss_session = Some((session, poller));
                }
                if pss_session.is_none() {
                    let conn =
                        pss::connect(target, timeouts, own_account(cfg, target, &pre, state))
                            .await
                            .map_err(PgError::into_connector_error)?;
                    tracing::info!(target_id = %target.id, "audit source: pg_stat_statements (Limited)");
                    pss_session = Some(conn);
                }
                if let Some((session, poller)) = pss_session.as_mut() {
                    poller.set_catalogs(pre.catalogs.clone());
                    pss_run(cfg, target, sink, session, poller, timeouts).await?;
                }
            }
            Source::None => {
                return Err(
                    PgError::new(FailureCode::Unsupported, Stage::Audit).into_connector_error()
                );
            }
        }
    }
}

/// Tails the pgaudit log for up to [`REPROBE`]. `Ok(Err(kind))` when the
/// log became unreadable.
async fn pgaudit_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    st: &mut PgauditState,
    severity: &str,
) -> Result<Result<(), std::io::ErrorKind>, ConnectorError> {
    let started = Instant::now();
    let format = st.format;
    loop {
        let mut t = st.tailer.take().ok_or_else(internal)?;
        let severity_owned = severity.to_owned();
        let (t, polled) = tokio::task::spawn_blocking(move || {
            let polled = t.poll().map(|p| {
                let more = p.more;
                let mut mismatched = 0u64;
                let mut forged = 0u64;
                let mut panicked = 0u64;
                let mut records: Vec<AuditRecord> = Vec::new();
                for r in &p.records {
                    // Per-record isolation: a record that makes the parser
                    // panic is dropped alone (phase-7 review H1).
                    match databastion_core::isolate(|| {
                        parse_record_checked(format, r, &severity_owned)
                    }) {
                        Some(Ok(rec)) => records.push(rec),
                        Some(Err(Skip::Severity)) => mismatched += 1,
                        Some(Err(Skip::Context)) => forged += 1,
                        Some(Err(Skip::NotAudit)) => {}
                        None => panicked += 1,
                    }
                }
                (records, more, mismatched, forged, panicked)
            });
            (t, polled)
        })
        .await
        .map_err(|e| {
            // A panic in the task reaches the core's guard; anything else
            // is an internal error.
            let _ = databastion_core::resume_panic(e);
            internal()
        })?;
        let (records, more, mismatched, forged, panicked) = match polled {
            Ok(p) => p,
            Err(TailError::Unreadable(kind)) => return Ok(Err(kind)),
        };
        if mismatched > 0 {
            state.note_severity_mismatch(&target.id, mismatched);
            tracing::warn!(
                target_id = %target.id,
                dropped = mismatched,
                "pgaudit records with another severity than pgaudit.log_level dropped \
                 (check pgaudit.log_level per database and role)"
            );
        }
        if panicked > 0 {
            state.note_dropped(&target.id, panicked);
            tracing::warn!(
                target_id = %target.id,
                dropped = panicked,
                "log records that make the parser fail dropped (internal error)"
            );
        }
        if forged > 0 {
            state.note_dropped(&target.id, forged);
            tracing::warn!(
                target_id = %target.id,
                dropped = forged,
                "AUDIT records with an error context dropped (not written by pgaudit)"
            );
        }
        if !records.is_empty() {
            state.note_record(&target.id);
        }
        if t.oversized > st.reported_oversized {
            state.note_dropped(&target.id, t.oversized - st.reported_oversized);
            tracing::warn!(
                target_id = %target.id,
                skipped = t.oversized - st.reported_oversized,
                "oversized log records skipped"
            );
            st.reported_oversized = t.oversized;
        }
        let panicked_before = st.builder.panicked;
        let events = st.builder.convert(records, SystemTime::now());
        {
            let panicked = st.builder.panicked.saturating_sub(panicked_before);
            if panicked > 0 {
                state.note_dropped(&target.id, panicked);
                tracing::warn!(
                    target_id = %target.id,
                    dropped = panicked,
                    "audit records whose conversion failed dropped (internal error)"
                );
            }
        }
        for e in events {
            sink.submit(e).await?;
        }
        // Everything read so far was handed over: move the cursor.
        let t = tokio::task::spawn_blocking(move || {
            t.commit();
            t
        })
        .await
        .map_err(|e| {
            // A panic in the task reaches the core's guard; anything else
            // is an internal error.
            let _ = databastion_core::resume_panic(e);
            internal()
        })?;
        st.tailer = Some(t);
        if !more {
            if started.elapsed() >= REPROBE {
                return Ok(Ok(()));
            }
            tokio::time::sleep(cfg.poll_interval()).await;
        }
    }
}

/// Polls `pg_stat_statements` for up to [`REPROBE`].
async fn pss_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    session: &crate::conn::Session,
    poller: &mut pss::PssPoller,
    timeouts: Timeouts,
) -> Result<(), ConnectorError> {
    let started = Instant::now();
    loop {
        let unanalyzed_before = poller.unanalyzed;
        let polled = poller.poll(session, timeouts, sink).await;
        let unanalyzed = poller.unanalyzed.saturating_sub(unanalyzed_before);
        if unanalyzed > 0 {
            // Not dropped (#90): their deltas are reported as reads of
            // `*`, so they are not counted in `audit.records_dropped`
            // (security review of #93, L7); each panic is in the
            // `audit_record_panics_total` metric.
            tracing::warn!(
                target_id = %target.id,
                statements = unanalyzed,
                "pg_stat_statements statements whose analysis or conversion failed (internal \
                 error): reported as reads of unknown objects (*) from now on"
            );
        }
        match polled {
            Ok(()) => {}
            Err(pss::PollError::Db(e)) => {
                tracing::warn!(
                    target_id = %target.id,
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    code = %e.code,
                    "pg_stat_statements poll failed"
                );
                return Err(e.into_connector_error());
            }
            Err(pss::PollError::SinkClosed) => {
                return Err(databastion_core::sink::SinkClosed.into());
            }
            Err(pss::PollError::Internal) => return Err(internal()),
        }
        tokio::time::sleep(cfg.poll_interval()).await;
        if started.elapsed() >= REPROBE {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_source_follows_the_check_level() {
        assert_eq!(source_for(AuditLevel::Full), Source::Pgaudit);
        assert_eq!(source_for(AuditLevel::Partial), Source::Pgaudit);
        assert_eq!(source_for(AuditLevel::Limited), Source::PgStatStatements);
        assert_eq!(source_for(AuditLevel::None), Source::None);
    }
}
