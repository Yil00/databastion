//! MySQL / MariaDB Audit (P4-B): access events from the MariaDB
//! `server_audit` log or the Percona / MySQL Enterprise `audit_log` JSON
//! file (level Partial), or, without a usable audit log, from
//! `performance_schema` (Partial with `events_statements_history_long`,
//! Limited with the per-thread tables, see [`pfs`]).
//!
//! - The audit log is read locally from `targets[].mysql.audit_log`,
//!   incrementally, with a cursor persisted through the core
//!   (`databastion_core::audit::tail`); records are parsed by [`records`].
//! - Statement text never leaves the agent (the contract `AccessEvent` has
//!   no field for it): it is only analyzed locally by `classifiers::query`
//!   (MySQL dialect, literal-free tokens) to name objects and compute
//!   signals ([`events`]).
//! - The source is chosen with the same probe and rule as `check()`
//!   (`check::choose`), re-evaluated every 5 minutes. While a stream runs,
//!   `check()` counts `SELECT` on `performance_schema` as the Audit grant
//!   (ADR-0018), not as over-privilege.
//! - The agent's own reads are left out only when they come from its
//!   account, its client address as the server sees it (`USER()`; a host
//!   name there, e.g. `localhost` on a Unix socket, leaves nothing out),
//!   its `program_name` when the source shows one, carry no signal, and
//!   stay within the Discovery row budget (`databastion_core::audit::own`).
//! - Delivery is at most once, as for PostgreSQL: the cursor advances once
//!   the events are handed to the core, which aggregates them before
//!   spooling.

pub(crate) mod events;
pub(crate) mod pfs;
pub(crate) mod records;

use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::{ClientAddr, EventSource};
use databastion_core::audit::own::OwnAccount;
use databastion_core::audit::tail::{Framing, TailError, Tailer};
use databastion_core::config::{MysqlLogFormat, TargetConfig};
use databastion_core::{AuditConfig, ConnectorError, EventSink, FailureCode};

use crate::check::{self, CheckState, Source};
use crate::conn::{Session, Timeouts};
use crate::error::{MyError, Stage};
use crate::sql;
use events::EventBuilder;
use pfs::{PollError, PsPoller};

/// How often the source choice is re-evaluated while streaming.
#[cfg(not(test))]
const REPROBE: Duration = Duration::from_secs(300);
/// Tests: often enough for an integration test to see re-probes.
#[cfg(test)]
const REPROBE: Duration = Duration::from_secs(3);
/// `program_name` the connector sends (`proto`).
const PROGRAM_NAME: &str = "databastion-agent";
/// `server_audit_query_log_limit` when it cannot be read.
const DEFAULT_QUERY_LIMIT: usize = 1024;

fn internal() -> ConnectorError {
    MyError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

fn cursor_name(format: MysqlLogFormat) -> &'static str {
    match format {
        MysqlLogFormat::ServerAudit => "server_audit",
        MysqlLogFormat::Json => "audit_log",
    }
}

/// Audit prerequisites of a target, from the same probe and rule as
/// `check()`.
pub(crate) struct Prerequisites {
    pub(crate) source: Source,
    /// Client address the server sees for the agent (`None`: unknown, or a
    /// host name).
    pub(crate) own_addr: Option<ClientAddr>,
    /// Seconds the server's system time zone is ahead of UTC.
    utc_offset: i64,
    query_limit: usize,
}

async fn optional_scalar(
    session: &mut Session,
    statement: &str,
) -> Result<Option<String>, MyError> {
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

/// The client address in `USER()` (`user@host`): an IP literal only.
pub(crate) fn own_address(user: &str) -> Option<ClientAddr> {
    let (_, host) = user.rsplit_once('@')?;
    match ClientAddr::parse(host)? {
        ClientAddr::Ip(ip) => Some(ClientAddr::Ip(ip)),
        ClientAddr::Local => None,
    }
}

/// [`probe_prerequisites`] on a session of its own (tests).
#[cfg(test)]
pub(crate) async fn prerequisites(
    state: &CheckState,
    target: &TargetConfig,
    timeouts: Timeouts,
) -> Result<Prerequisites, MyError> {
    let mut session = Session::connect(target, timeouts).await?;
    let pre = probe_prerequisites(state, target, &mut session).await;
    session.close().await;
    pre
}

/// The Audit prerequisites, probed on `session`: the held
/// `performance_schema` session when there is one, so a re-probe opens no
/// second Audit connection (phase 7, ADR-0025 decision 11).
pub(crate) async fn probe_prerequisites(
    state: &CheckState,
    target: &TargetConfig,
    session: &mut Session,
) -> Result<Prerequisites, MyError> {
    let probe = check::audit_probe(session).await?;
    let file = check::file_state(state, target).await;
    let (_, source) = check::choose(&probe, file);
    let own_addr = optional_scalar(session, sql::SESSION_USER)
        .await?
        .as_deref()
        .and_then(own_address);
    let (utc_offset, query_limit) = if source == Source::File(MysqlLogFormat::ServerAudit) {
        let offset = optional_scalar(session, sql::SYSTEM_UTC_OFFSET)
            .await?
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|o| o.abs() <= 18 * 3600);
        if offset.is_none() {
            tracing::warn!(
                target_id = %target.id,
                "server time zone offset unknown; server_audit times read as UTC"
            );
        }
        let limit = optional_scalar(session, sql::SERVER_AUDIT_QUERY_LIMIT)
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_QUERY_LIMIT);
        (offset.unwrap_or(0), limit)
    } else {
        (0, DEFAULT_QUERY_LIMIT)
    };
    Ok(Prerequisites {
        source,
        own_addr,
        utc_offset,
        query_limit,
    })
}

fn own_account(
    cfg: &AuditConfig,
    target: &TargetConfig,
    pre: &Prerequisites,
    state: &CheckState,
) -> OwnAccount {
    OwnAccount::new(
        &target.account,
        Some(PROGRAM_NAME),
        pre.own_addr,
        u64::from(cfg.max_sample_rows()),
        state.own_usage(&target.id),
    )
    .persisted(cfg)
}

struct FileStream {
    format: MysqlLogFormat,
    tailer: Option<Tailer>,
    builder: EventBuilder,
    reported: (u64, u64),
    unparsed: u64,
}

struct PsStream {
    table: pfs::PsTable,
    /// The held session (`None` only between closing a stale one and
    /// opening its replacement).
    session: Option<Session>,
    poller: PsPoller,
}

impl PsStream {
    /// The held session, usable: a stale or poisoned one is **closed
    /// before** its replacement is opened, so the stream never holds two
    /// Audit connections (phase 7, ADR-0025 decision 11). The poller is
    /// re-attached to the new session (its cursor is kept).
    async fn fresh_session(
        &mut self,
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<&mut Session, ConnectorError> {
        if self
            .session
            .as_ref()
            .is_none_or(|s| s.is_stale() || s.is_poisoned())
        {
            if let Some(old) = self.session.take() {
                old.close().await;
            }
            let mut session = Session::connect(target, timeouts)
                .await
                .map_err(MyError::into_connector_error)?;
            self.poller
                .reattach(&mut session)
                .await
                .map_err(MyError::into_connector_error)?;
            self.session = Some(session);
        }
        self.session.as_mut().ok_or_else(internal)
    }
}

/// `Connector::audit_stream` for MySQL / MariaDB.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg.target().ok_or_else(internal)?;
    let _running = state.stream_started(&target.id);
    let timeouts = Timeouts::new(cfg.statement_timeout().min(Duration::from_secs(30)));
    let mut file: Option<FileStream> = None;
    let mut ps: Option<PsStream> = None;
    loop {
        // The prerequisites are probed on the held performance_schema
        // session when there is one, else on a session opened for the
        // probe, which becomes the performance_schema session when that
        // is the source (phase 7): one Audit connection at a time.
        let mut probe_session: Option<Session> = None;
        let pre = match ps.as_mut() {
            Some(st) => {
                let session = st.fresh_session(target, timeouts).await?;
                probe_prerequisites(state, target, session).await
            }
            None => {
                let session = probe_session.insert(
                    Session::connect(target, timeouts)
                        .await
                        .map_err(MyError::into_connector_error)?,
                );
                probe_prerequisites(state, target, session).await
            }
        }
        .map_err(MyError::into_connector_error)?;
        match pre.source {
            Source::File(format) => {
                if let Some(s) = probe_session.take() {
                    s.close().await;
                }
                if let Some(old) = ps.take().and_then(|p| p.session) {
                    old.close().await;
                }
                let st = match file.as_mut() {
                    Some(st) if st.format == format => st,
                    _ => {
                        let log = target.mysql_settings().audit_log.ok_or_else(internal)?;
                        tracing::info!(target_id = %target.id, "audit source: audit log file");
                        // The log covers what performance_schema would: a
                        // later switch back starts at its newest statement
                        // rather than re-reading this period.
                        forget_ps_cursor(cfg);
                        let framing = match format {
                            MysqlLogFormat::ServerAudit => Framing::Lines,
                            MysqlLogFormat::Json => Framing::JsonObjects,
                        };
                        file.insert(FileStream {
                            format,
                            tailer: Some(Tailer::new(
                                log.path,
                                framing,
                                cfg.cursor(cursor_name(format)),
                            )),
                            builder: EventBuilder::new(own_account(cfg, target, &pre, state)),
                            reported: (0, 0),
                            unparsed: 0,
                        })
                    }
                };
                // The agent's address may change (a new route, a DHCP
                // lease): refreshed at each re-probe.
                st.builder.set_own_addr(pre.own_addr);
                if let Err(kind) = file_run(cfg, target, sink, state, st, &pre).await? {
                    tracing::warn!(
                        target_id = %target.id,
                        kind = %kind,
                        "audit log unreadable; re-evaluating the audit source"
                    );
                    file = None;
                    tokio::time::sleep(cfg.poll_interval()).await;
                }
            }
            Source::Ps(table) => {
                file = None;
                if ps.as_ref().is_none_or(|p| p.table != table) {
                    // The probe's session, or the held one (another
                    // statement table): no new connection.
                    let held = ps.take().and_then(|p| p.session);
                    let mut session = match probe_session.take().or(held) {
                        Some(s) => s,
                        None => Session::connect(target, timeouts)
                            .await
                            .map_err(MyError::into_connector_error)?,
                    };
                    let builder = EventBuilder::new(own_account(cfg, target, &pre, state));
                    let poller =
                        PsPoller::start(&mut session, table, builder, cfg.cursor(pfs::CURSOR))
                            .await
                            .map_err(MyError::into_connector_error)?;
                    tracing::info!(
                        target_id = %target.id,
                        table = table.name(),
                        "audit source: performance_schema"
                    );
                    ps = Some(PsStream {
                        table,
                        session: Some(session),
                        poller,
                    });
                }
                if let Some(st) = ps.as_mut() {
                    st.poller.set_own_addr(pre.own_addr);
                    ps_run(cfg, target, sink, state, st, timeouts).await?;
                }
            }
            Source::None => {
                if let Some(s) = probe_session.take() {
                    s.close().await;
                }
                return Err(
                    MyError::new(FailureCode::Unsupported, Stage::Audit).into_connector_error()
                );
            }
        }
    }
}

/// Removes the saved `performance_schema` cursor.
fn forget_ps_cursor(cfg: &AuditConfig) {
    if let Some(store) = cfg.cursor(pfs::CURSOR) {
        if let Err(e) = store.remove() {
            tracing::warn!(error = %e, "performance_schema cursor not removed");
        }
    }
}

/// Tails the audit log for up to [`REPROBE`]. `Ok(Err(kind))` when the log
/// became unreadable.
async fn file_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    st: &mut FileStream,
    pre: &Prerequisites,
) -> Result<Result<(), std::io::ErrorKind>, ConnectorError> {
    let started = Instant::now();
    let (format, utc_offset, query_limit) = (st.format, pre.utc_offset, pre.query_limit);
    let source = match format {
        MysqlLogFormat::ServerAudit => EventSource::MariadbServerAudit,
        MysqlLogFormat::Json => EventSource::MysqlAuditLog,
    };
    loop {
        let mut t = st.tailer.take().ok_or_else(internal)?;
        let (t, polled) = tokio::task::spawn_blocking(move || {
            let polled = t.poll().map(|p| {
                let mut unparsed = 0u64;
                let mut records = Vec::with_capacity(p.records.len());
                for r in &p.records {
                    // Per-record isolation: a record that makes the parser
                    // panic is dropped alone, counted (phase-7 review H1).
                    let parsed = databastion_core::isolate(|| match format {
                        MysqlLogFormat::ServerAudit => {
                            records::parse_server_audit(r, utc_offset, query_limit)
                        }
                        MysqlLogFormat::Json => records::parse_json(r),
                    })
                    .flatten();
                    match parsed {
                        Some(rec) => records.push(rec),
                        None => unparsed += 1,
                    }
                }
                (records, p.more, unparsed)
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
        let (records, more, unparsed) = match polled {
            Ok(p) => p,
            Err(TailError::Unreadable(kind)) => return Ok(Err(kind)),
        };
        if !records.is_empty() {
            state.note_record(&target.id);
        }
        if unparsed > 0 {
            state.note_dropped(&target.id, unparsed);
            st.unparsed += unparsed;
            tracing::warn!(
                target_id = %target.id,
                dropped = unparsed,
                "audit log records that do not parse dropped"
            );
        }
        if (t.oversized, t.malformed()) != st.reported {
            let skipped = (t.oversized - st.reported.0)
                .saturating_add(t.malformed().saturating_sub(st.reported.1));
            state.note_dropped(&target.id, skipped);
            tracing::warn!(
                target_id = %target.id,
                oversized = t.oversized - st.reported.0,
                damaged = t.malformed().saturating_sub(st.reported.1),
                "audit log records skipped"
            );
            st.reported = (t.oversized, t.malformed());
        }
        let panicked_before = st.builder.panicked;
        let events = st.builder.convert_file(records, source, SystemTime::now());
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

/// Polls `performance_schema` for up to [`REPROBE`], reconnecting when the
/// session went stale between polls.
async fn ps_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    st: &mut PsStream,
    timeouts: Timeouts,
) -> Result<(), ConnectorError> {
    let started = Instant::now();
    loop {
        st.fresh_session(target, timeouts).await?;
        let panicked_before = st.poller.panicked;
        let Some(session) = st.session.as_mut() else {
            return Err(internal());
        };
        let polled = st.poller.poll(session, sink).await;
        let panicked = st.poller.panicked.saturating_sub(panicked_before);
        if panicked > 0 {
            state.note_dropped(&target.id, panicked);
            tracing::warn!(
                target_id = %target.id,
                dropped = panicked,
                "performance_schema statements whose conversion failed dropped (internal error)"
            );
        }
        match polled {
            Ok(()) => {}
            Err(PollError::Db(e)) => {
                tracing::warn!(
                    target_id = %target.id,
                    stage = e.stage.as_str(),
                    errno = e.errno,
                    sqlstate = e.sqlstate(),
                    code = %e.code,
                    "performance_schema poll failed"
                );
                return Err(e.into_connector_error());
            }
            Err(PollError::SinkClosed) => {
                return Err(databastion_core::sink::SinkClosed.into());
            }
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
    fn own_address_is_an_ip_literal_only() {
        assert_eq!(
            own_address("databastion@172.18.0.1"),
            ClientAddr::parse("172.18.0.1")
        );
        assert_eq!(own_address("a@b@::1"), ClientAddr::parse("::1"));
        assert_eq!(own_address("databastion@localhost"), None);
        assert_eq!(own_address("databastion@db.example"), None);
        assert_eq!(own_address("nohost"), None);
    }
}
