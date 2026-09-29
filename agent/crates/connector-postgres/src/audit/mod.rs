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
//! - The source is chosen at every (re)start and re-evaluated while
//!   running: the log when configured and readable, `pg_stat_statements`
//!   otherwise, back to the log as soon as it becomes readable.

pub(crate) mod events;
pub(crate) mod pss;
pub(crate) mod records;
pub(crate) mod tail;

use std::time::{Duration, SystemTime};

use databastion_core::config::{PgLogFormat, TargetConfig};
use databastion_core::{AuditConfig, ConnectorError, EventSink, FailureCode};

use crate::conn::Timeouts;
use crate::error::{PgError, Stage};
use records::{AuditRecord, Format, parse_record};
use tail::{TailError, Tailer};

/// Name of the pgaudit cursor in the core's cursor store.
const CURSOR: &str = "pgaudit";

fn internal() -> ConnectorError {
    PgError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

fn format_of(f: PgLogFormat) -> Format {
    match f {
        PgLogFormat::Jsonlog => Format::Jsonlog,
        PgLogFormat::Csvlog => Format::Csvlog,
    }
}

/// Whether the configured audit log of `target` can be read now.
pub(crate) fn log_readable(target: &TargetConfig) -> bool {
    target
        .postgres_settings()
        .audit_log
        .is_some_and(|l| tail::readable(&l.path))
}

/// `Connector::audit_stream` for PostgreSQL.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
) -> Result<(), ConnectorError> {
    let target = cfg.target().ok_or_else(internal)?;
    loop {
        if log_readable(target) {
            match pgaudit_stream(cfg, target, sink).await? {
                // The log became unreadable: fall back until it is back.
                Fallback::Unreadable(kind) => {
                    tracing::warn!(
                        target_id = %target.id,
                        kind = %kind,
                        "pgaudit log unreadable; falling back to pg_stat_statements (Limited)"
                    );
                }
            }
        }
        pss_stream(cfg, target, sink).await?;
    }
}

enum Fallback {
    Unreadable(std::io::ErrorKind),
}

/// Tails the pgaudit log until it becomes unreadable.
async fn pgaudit_stream(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
) -> Result<Fallback, ConnectorError> {
    let log = target.postgres_settings().audit_log.ok_or_else(internal)?;
    let format = format_of(log.format);
    let mut tailer = Some(Tailer::new(log.path, format, cfg.cursor(CURSOR)));
    let mut builder = events::PgauditEvents::new(&target.account);
    tracing::info!(target_id = %target.id, "audit source: pgaudit log");
    let mut reported_oversized = 0;
    loop {
        let mut t = tailer.take().ok_or_else(internal)?;
        let (t, polled) = tokio::task::spawn_blocking(move || {
            let polled = t.poll().map(|p| {
                let more = p.more;
                let records: Vec<AuditRecord> = p
                    .records
                    .iter()
                    .filter_map(|r| parse_record(format, r))
                    .collect();
                (records, more)
            });
            (t, polled)
        })
        .await
        .map_err(|_| internal())?;
        let (records, more) = match polled {
            Ok(p) => p,
            Err(TailError::Unreadable(kind)) => return Ok(Fallback::Unreadable(kind)),
        };
        if t.oversized > reported_oversized {
            tracing::warn!(
                target_id = %target.id,
                skipped = t.oversized - reported_oversized,
                "oversized log records skipped"
            );
            reported_oversized = t.oversized;
        }
        let events = builder.convert(records, SystemTime::now());
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
        tailer = Some(t);
        if !more {
            tokio::time::sleep(cfg.poll_interval()).await;
        }
    }
}

/// Polls `pg_stat_statements` until the pgaudit log becomes readable.
async fn pss_stream(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
) -> Result<(), ConnectorError> {
    let timeouts = Timeouts::new(cfg.statement_timeout().min(Duration::from_secs(30)));
    let (session, mut poller) = pss::connect(target, timeouts)
        .await
        .map_err(PgError::into_connector_error)?;
    tracing::info!(target_id = %target.id, "audit source: pg_stat_statements (Limited)");
    loop {
        match poller.poll(&session, timeouts, sink).await {
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
        if log_readable(target) {
            return Ok(());
        }
    }
}
