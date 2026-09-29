//! PostgreSQL Audit (P4-A): access events from the pgaudit log (level
//! Full / Partial) or, without a readable log, from `pg_stat_statements`
//! (level Limited, see [`pss`]).
//!
//! - The pgaudit log is read locally from `targets[].postgres.audit_log`
//!   (`jsonlog` or `csvlog`), incrementally, with a cursor persisted
//!   through the core ([`tail`]); only `AUDIT:` records are parsed
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
pub(crate) mod tail;

use std::time::{Duration, Instant, SystemTime};

use databastion_core::config::{PgLogFormat, TargetConfig};
use databastion_core::{AuditConfig, AuditLevel, ConnectorError, EventSink, FailureCode};

use crate::check::{self, CheckState};
use crate::conn::Timeouts;
use crate::error::{PgError, Stage};
use records::{AuditRecord, Format, Skip, parse_record_checked};
use tail::{TailError, Tailer};

/// Name of the pgaudit cursor in the core's cursor store.
const CURSOR: &str = "pgaudit";
/// How often the source choice is re-evaluated while streaming.
const REPROBE: Duration = Duration::from_secs(300);

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

/// The agent's own activity for this target (see `events::OwnAccount`).
fn own_account(
    cfg: &AuditConfig,
    target: &TargetConfig,
    pre: &check::Prerequisites,
) -> events::OwnAccount {
    events::OwnAccount::new(
        &target.account,
        pre.own_addr,
        u64::from(cfg.max_sample_rows()),
    )
}

/// State kept across source re-evaluations.
struct PgauditState {
    tailer: Option<Tailer>,
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
    loop {
        let pre = check::prerequisites(target, timeouts)
            .await
            .map_err(PgError::into_connector_error)?;
        match source_for(pre.level) {
            Source::Pgaudit => {
                pss_session = None;
                let st = match pgaudit.as_mut() {
                    Some(st) => st,
                    None => {
                        let log = target.postgres_settings().audit_log.ok_or_else(internal)?;
                        tracing::info!(target_id = %target.id, "audit source: pgaudit log");
                        pgaudit.insert(PgauditState {
                            tailer: Some(Tailer::new(
                                log.path,
                                format_of(log.format),
                                cfg.cursor(CURSOR),
                            )),
                            builder: events::PgauditEvents::new(own_account(cfg, target, &pre)),
                            reported_oversized: 0,
                        })
                    }
                };
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
                if pss_session.is_none() {
                    let conn = pss::connect(target, timeouts, own_account(cfg, target, &pre))
                        .await
                        .map_err(PgError::into_connector_error)?;
                    tracing::info!(target_id = %target.id, "audit source: pg_stat_statements (Limited)");
                    pss_session = Some(conn);
                }
                if let Some((session, poller)) = pss_session.as_mut() {
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
    let format = st
        .tailer
        .as_ref()
        .map(Tailer::format)
        .ok_or_else(internal)?;
    loop {
        let mut t = st.tailer.take().ok_or_else(internal)?;
        let severity_owned = severity.to_owned();
        let (t, polled) = tokio::task::spawn_blocking(move || {
            let polled = t.poll().map(|p| {
                let more = p.more;
                let mut mismatched = 0u64;
                let mut forged = 0u64;
                let mut records: Vec<AuditRecord> = Vec::new();
                for r in &p.records {
                    match parse_record_checked(format, r, &severity_owned) {
                        Ok(rec) => records.push(rec),
                        Err(Skip::Severity) => mismatched += 1,
                        Err(Skip::Context) => forged += 1,
                        Err(Skip::NotAudit) => {}
                    }
                }
                (records, more, mismatched, forged)
            });
            (t, polled)
        })
        .await
        .map_err(|_| internal())?;
        let (records, more, mismatched, forged) = match polled {
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
        if forged > 0 {
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
            tracing::warn!(
                target_id = %target.id,
                skipped = t.oversized - st.reported_oversized,
                "oversized log records skipped"
            );
            st.reported_oversized = t.oversized;
        }
        let events = st.builder.convert(records, SystemTime::now());
        for e in events {
            sink.submit(e).await?;
        }
        // Everything read so far was handed over: move the cursor.
        let t = tokio::task::spawn_blocking(move || {
            t.commit();
            t
        })
        .await
        .map_err(|_| internal())?;
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
        match poller.poll(session, timeouts, sink).await {
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
