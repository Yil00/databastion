//! MongoDB Audit (P5-B, P5-C, ADR-0027, ADR-0030): access events from the
//! Enterprise / Percona `auditLog` JSON file (Partial once a successful
//! `authCheck` was read, Limited once any record was read, None before),
//! the structured JSON server log (Limited) or the profiler (Limited).
//! Full is never reported.
//!
//! - The files are read locally from `targets[].mongodb.audit_log`,
//!   incrementally, with a cursor persisted through the core
//!   (`databastion_core::audit::tail`); records are parsed by [`records`].
//! - The profiler is polled over the agent's connection ([`profiler`]):
//!   a fixed projection computes the closed-shape facts on the server, so
//!   command documents never reach the agent.
//! - Command documents never leave the agent (the contract `AccessEvent`
//!   has no field for them), nor are they kept: only closed-shape facts
//!   are extracted ([`records`]), and turned into events and signals by
//!   [`events`].
//! - The source is chosen with the same rule as `check()` ([`choose`]),
//!   re-evaluated every 5 minutes.
//! - The agent's own reads are left out only when they come from its
//!   account (`account@auth_source`), its client address as the server
//!   sees it (`whatsmyuri`), its application name when the source shows
//!   one, carry no signal, and stay within the Discovery budget
//!   (`databastion_core::audit::own`).
//! - Delivery is at most once, as for the other connectors.

pub(crate) mod events;
pub(crate) mod profiler;
pub(crate) mod records;

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::{ClientAddr, EventSource};
use databastion_core::audit::own::OwnAccount;
use databastion_core::audit::tail::{Framing, TailError, Tailer};
use databastion_core::config::{MongodbLogFormat, TargetConfig};
use databastion_core::{
    AuditConfig, AuditLevel, ConnectorError, EventSink, FailureCode, NoteCode, TargetNote,
};

use crate::bson::DocBuf;
use crate::catalog::{self, is_system_database};
use crate::check::{self, CheckState};
use crate::conn::{APP_NAME, Kind as CmdKind, Session, Timeouts};
use crate::error::{MgError, Stage};
use crate::privileges::PrivilegeReport;
use events::EventBuilder;
use profiler::DbCursor;
use records::{Cmd, Kind, Record};

/// How often the source choice is re-evaluated while streaming.
const REPROBE: Duration = Duration::from_secs(300);
/// Polls of one database in a row while its batches are full.
const MAX_ROUNDS: usize = 16;

fn internal() -> ConnectorError {
    MgError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

/// The Audit source of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    AuditLog,
    ServerLog,
    Profiler,
    None,
}

impl Source {
    pub(crate) fn event_source(self) -> Option<EventSource> {
        match self {
            Self::AuditLog => Some(EventSource::MongodbAuditLog),
            Self::ServerLog => Some(EventSource::MongodbLog),
            Self::Profiler => Some(EventSource::MongodbProfiler),
            Self::None => None,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::AuditLog => "auditLog JSON file",
            Self::ServerLog => "structured JSON server log",
            Self::Profiler => "profiler (system.profile)",
            Self::None => "none",
        }
    }
}

/// What the agent knows of the configured log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileState {
    pub(crate) format: MongodbLogFormat,
    pub(crate) readable: bool,
    /// In the last 24 h, the stream parsed a successful `authCheck` record
    /// (`auditLog`), or an audit record (server log).
    pub(crate) recent: bool,
    /// In the last 24 h, the stream parsed a record of the file, of any
    /// kind (ADR-0030: the `auditLog` is None until then).
    pub(crate) seen: bool,
}

/// What the server and the account allow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Probe {
    /// `community`, `enterprise` or `percona`; `None` when `buildInfo`
    /// could not be read.
    pub(crate) edition: Option<&'static str>,
    pub(crate) mongos: bool,
    /// The account can `find` on some database's `system.profile`.
    pub(crate) profiler: bool,
    /// The stream read a profiler entry in the last 24 h.
    pub(crate) profiler_recent: bool,
}

impl Probe {
    fn audit_log_edition(self) -> bool {
        matches!(self.edition, Some("enterprise" | "percona"))
    }
}

/// The level and source of a target (ADR-0027 decisions 1 and 2, refined
/// by ADR-0030): the `auditLog` on Enterprise / Percona when readable
/// (Partial once a successful `authCheck` was read, Limited once any
/// record was read, None before: a stale file proves nothing), the server
/// log when
/// readable, the profiler when the account can read it and the target is
/// not a `mongos`, else none. The server log and the profiler are Limited
/// once the stream read a record of them in the last 24 h, None before
/// (a readable source that records nothing proves nothing). `check()` and
/// the Audit stream use this same rule.
pub(crate) fn choose(probe: Probe, file: Option<FileState>) -> (AuditLevel, Source) {
    if let Some(f) = file.filter(|f| f.readable) {
        match f.format {
            MongodbLogFormat::AuditLog if probe.audit_log_edition() => {
                let level = if f.recent {
                    AuditLevel::Partial
                } else if f.seen {
                    AuditLevel::Limited
                } else {
                    AuditLevel::None
                };
                return (level, Source::AuditLog);
            }
            MongodbLogFormat::AuditLog => {}
            MongodbLogFormat::ServerLog => return (limited(f.recent), Source::ServerLog),
        }
    }
    if probe.profiler && !probe.mongos {
        return (limited(probe.profiler_recent), Source::Profiler);
    }
    (AuditLevel::None, Source::None)
}

fn limited(recent: bool) -> AuditLevel {
    if recent {
        AuditLevel::Limited
    } else {
        AuditLevel::None
    }
}

/// Explanations of the level: the log detail, and the same as closed
/// notes.
pub(crate) fn explain(
    probe: Probe,
    file: Option<FileState>,
    source: Source,
) -> (Vec<String>, Vec<TargetNote>) {
    let mut out = Vec::new();
    let mut codes = Vec::new();
    if let Some(f) = file {
        if !f.readable {
            out.push("the configured log file is not readable by the agent".to_owned());
            codes.push(TargetNote::new(NoteCode::AuditLogNotReadable));
        } else if f.format == MongodbLogFormat::AuditLog && !probe.audit_log_edition() {
            out.push(match probe.edition {
                Some(_) => "the auditLog needs MongoDB Enterprise or Percona Server for \
                            MongoDB: the server is Community, the file is not used"
                    .to_owned(),
                None => "the server edition is unknown (buildInfo not readable): the \
                         auditLog is not used"
                    .to_owned(),
            });
            if probe.edition.is_some() {
                codes.push(TargetNote::new(NoteCode::AuditAuditlogOnCommunity));
            }
        }
    }
    if probe.profiler && probe.mongos && source == Source::None {
        out.push("a mongos has no profiler for data operations".to_owned());
    }
    out.push(format!("audit source: {}", source.describe()));
    match source {
        Source::AuditLog => {
            if !file.is_some_and(|f| f.seen || f.recent) {
                out.push(
                    "Limited once the Audit stream has read an auditLog record (none in the \
                     last 24 h; the agent's own authentication at each check writes one)"
                        .to_owned(),
                );
                codes.push(TargetNote::new(NoteCode::AuditLimitedPendingFirstRecord));
            }
            if !file.is_some_and(|f| f.recent) {
                out.push(
                    "Partial once the Audit stream has read a successful authCheck record \
                     (auditAuthorizationSuccess; none in the last 24 h)"
                        .to_owned(),
                );
                codes.push(TargetNote::new(NoteCode::AuditAuthcheckSuccessPending));
            }
            out.push("the auditLog carries no document counts (volumes unknown)".to_owned());
            codes.push(TargetNote::new(NoteCode::AuditLogWithoutRowCounts));
        }
        Source::ServerLog | Source::Profiler => {
            let recent = if source == Source::Profiler {
                probe.profiler_recent
            } else {
                file.is_some_and(|f| f.recent)
            };
            if !recent {
                out.push(
                    "Limited once the Audit stream has read a record of the source (none in \
                     the last 24 h)"
                        .to_owned(),
                );
                codes.push(TargetNote::new(NoteCode::AuditLimitedPendingFirstRecord));
            }
            out.push(
                "only operations the server logs or profiles (slower than slowms, or sampled) \
                 are seen"
                    .to_owned(),
            );
            codes.push(TargetNote::new(NoteCode::AuditSlowOperationsOnly));
        }
        Source::None => {
            out.push(
                "no Audit source: declare mongodb.audit_log in agent.yaml, or grant find on \
                 system.profile"
                    .to_owned(),
            );
            codes.push(TargetNote::new(NoteCode::AuditSourceNotConfigured));
        }
    }
    (out, codes)
}

/// Whether the configured log of `target` can be read now (file I/O on a
/// blocking thread), and whether a successful `authCheck` was read
/// recently.
pub(crate) async fn file_state(state: &CheckState, target: &TargetConfig) -> Option<FileState> {
    let log = target.mongodb_settings().audit_log?;
    let path = log.path.clone();
    let readable =
        tokio::task::spawn_blocking(move || databastion_core::audit::tail::readable(&path))
            .await
            .unwrap_or(false);
    let (recent, seen) = match log.format {
        MongodbLogFormat::AuditLog => (
            state.recent_authcheck(&target.id),
            state.recent_record(&target.id, Source::AuditLog),
        ),
        MongodbLogFormat::ServerLog => {
            let seen = state.recent_record(&target.id, Source::ServerLog);
            (seen, seen)
        }
    };
    Some(FileState {
        format: log.format,
        readable,
        recent,
        seen,
    })
}

/// The client address in a `whatsmyuri` reply: an IP literal only.
pub(crate) fn own_address(you: &str) -> Option<ClientAddr> {
    records::address(you).map(|(ip, _)| ClientAddr::Ip(ip))
}

/// The client address the server sees for this session (`whatsmyuri`,
/// no privilege needed); `None` when unknown or not an IP address.
pub(crate) async fn whoami<S>(session: &mut Session<S>) -> Option<ClientAddr>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match session
        .command(
            Stage::Audit,
            "admin",
            DocBuf::new().i32("whatsmyuri", 1),
            CmdKind::Setup,
        )
        .await
    {
        Ok(reply) => reply.doc().str("you").ok().flatten().and_then(own_address),
        Err(e) => {
            tracing::warn!(
                server_code = e.server_code,
                "whatsmyuri failed: the agent's own reads are not left out"
            );
            None
        }
    }
}

/// Databases whose profiler the account can read (named ones; every
/// listed database for a grant on all of them), at most
/// [`profiler::MAX_DATABASES`].
async fn profile_databases<S>(session: &mut Session<S>, report: &PrivilegeReport) -> Vec<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut dbs: Vec<String> = report
        .profile_find
        .iter()
        .filter(|d| !d.is_empty() && !is_system_database(d))
        .cloned()
        .collect();
    if report.profile_find.contains("") {
        if let Ok((listed, _)) = catalog::list_databases(session).await {
            for d in listed {
                if !is_system_database(&d) && !dbs.contains(&d) {
                    dbs.push(d);
                }
            }
        }
    }
    dbs.truncate(profiler::MAX_DATABASES);
    dbs
}

/// Audit prerequisites of a target, from the same probe and rule as
/// `check()`.
pub(crate) struct Prerequisites {
    pub(crate) source: Source,
    pub(crate) own_addr: Option<ClientAddr>,
    pub(crate) profile_dbs: Vec<String>,
}

pub(crate) async fn prerequisites(
    state: &CheckState,
    target: &TargetConfig,
    session: &mut Session,
) -> Result<Prerequisites, MgError> {
    let edition = match check::build_info(session).await {
        Ok(b) => Some(b.edition),
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    let own_addr = whoami(session).await;
    let report = match session
        .command(
            Stage::Audit,
            "admin",
            DocBuf::new()
                .i32("connectionStatus", 1)
                .bool("showPrivileges", true),
            CmdKind::Read,
        )
        .await
    {
        Ok(reply) => PrivilegeReport::from_connection_status(reply.doc()).ok(),
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    let profile_dbs = match &report {
        Some(r) if r.can_read_profiler() && !session.info.mongos => {
            profile_databases(session, r).await
        }
        _ => Vec::new(),
    };
    let probe = Probe {
        edition,
        mongos: session.info.mongos,
        profiler: !profile_dbs.is_empty(),
        profiler_recent: state.recent_record(&target.id, Source::Profiler),
    };
    let (_, source) = choose(probe, file_state(state, target).await);
    Ok(Prerequisites {
        source,
        own_addr,
        profile_dbs,
    })
}

fn own_user(target: &TargetConfig) -> String {
    format!(
        "{}@{}",
        target.account,
        target.mongodb_settings().auth_source
    )
}

fn builder(
    cfg: &AuditConfig,
    target: &TargetConfig,
    pre: &Prerequisites,
    state: &CheckState,
) -> EventBuilder {
    let user = own_user(target);
    EventBuilder::new(
        OwnAccount::new(
            &user,
            Some(APP_NAME),
            pre.own_addr,
            u64::from(cfg.max_sample_rows()),
            state.own_usage(&target.id),
        ),
        user,
        u64::from(cfg.max_sample_rows()),
    )
}

struct FileStream {
    format: MongodbLogFormat,
    tailer: Option<Tailer>,
    builder: EventBuilder,
    reported: (u64, u64),
}

struct ProfilerStream {
    session: Option<Session>,
    cursors: HashMap<String, DbCursor>,
    builder: EventBuilder,
}

fn cursor_name(format: MongodbLogFormat) -> &'static str {
    match format {
        MongodbLogFormat::AuditLog => "mongodb_audit_log",
        MongodbLogFormat::ServerLog => "mongodb_log",
    }
}

/// `Connector::audit_stream` for MongoDB.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg.target().ok_or_else(internal)?;
    let _running = state.stream_started(&target.id);
    let timeouts = Timeouts::new(cfg.statement_timeout().min(Duration::from_secs(30)));
    let mut file: Option<FileStream> = None;
    let mut prof: Option<ProfilerStream> = None;
    loop {
        let mut session = Session::connect(target, timeouts)
            .await
            .map_err(MgError::into_connector_error)?;
        let pre = prerequisites(state, target, &mut session)
            .await
            .map_err(MgError::into_connector_error)?;
        state.set_stream_source(&target.id, pre.source);
        match pre.source {
            Source::AuditLog | Source::ServerLog => {
                session.close().await;
                prof = None;
                let format = if pre.source == Source::AuditLog {
                    MongodbLogFormat::AuditLog
                } else {
                    MongodbLogFormat::ServerLog
                };
                let st = match file.as_mut() {
                    Some(st) if st.format == format => st,
                    _ => {
                        let log = target.mongodb_settings().audit_log.ok_or_else(internal)?;
                        tracing::info!(
                            target_id = %target.id,
                            source = pre.source.describe(),
                            "audit source: log file"
                        );
                        let framing = match format {
                            MongodbLogFormat::AuditLog => Framing::JsonObjects,
                            MongodbLogFormat::ServerLog => Framing::Lines,
                        };
                        file.insert(FileStream {
                            format,
                            tailer: Some(Tailer::new(
                                log.path,
                                framing,
                                cfg.cursor(cursor_name(format)),
                            )),
                            builder: builder(cfg, target, &pre, state),
                            reported: (0, 0),
                        })
                    }
                };
                st.builder.set_own_addr(pre.own_addr);
                if let Err(kind) = file_run(cfg, target, sink, state, st).await? {
                    tracing::warn!(
                        target_id = %target.id,
                        kind = %kind,
                        "audit log unreadable; re-evaluating the audit source"
                    );
                    file = None;
                    tokio::time::sleep(cfg.poll_interval()).await;
                }
            }
            Source::Profiler => {
                file = None;
                let st = match prof.as_mut() {
                    Some(st) => st,
                    None => {
                        tracing::info!(target_id = %target.id, "audit source: profiler");
                        prof.insert(ProfilerStream {
                            session: None,
                            cursors: HashMap::new(),
                            builder: builder(cfg, target, &pre, state),
                        })
                    }
                };
                st.builder.set_own_addr(pre.own_addr);
                // Databases that lost the grant are forgotten.
                st.cursors.retain(|db, _| pre.profile_dbs.contains(db));
                if let Some(old) = st.session.replace(session) {
                    old.close().await;
                }
                profiler_run(cfg, target, sink, state, st, &pre.profile_dbs, timeouts).await?;
            }
            Source::None => {
                session.close().await;
                return Err(
                    MgError::new(FailureCode::Unsupported, Stage::Audit).into_connector_error()
                );
            }
        }
    }
}

/// Records of one poll of a log file.
struct Parsed {
    records: Vec<Record>,
    /// Records that do not parse (dropped, counted).
    unparsed: u64,
    /// Valid records, those that yield nothing included (another
    /// `atype`): ADR-0030's proof that the `auditLog` is written.
    valid: u64,
}

fn parse_all<R: AsRef<[u8]>>(format: MongodbLogFormat, raw: &[R]) -> Parsed {
    let mut out = Parsed {
        records: Vec::with_capacity(raw.len()),
        unparsed: 0,
        valid: 0,
    };
    for r in raw {
        let parsed = match format {
            MongodbLogFormat::AuditLog => records::parse_audit_log(r.as_ref()),
            MongodbLogFormat::ServerLog => records::parse_server_log(r.as_ref()),
        };
        match parsed {
            Ok(Some(rec)) => {
                out.valid += 1;
                out.records.push(rec);
            }
            Ok(None) => out.valid += 1,
            Err(()) => out.unparsed += 1,
        }
    }
    out
}

/// Whether a record proves that reads are logged (a successful
/// `authCheck` of a read or write).
fn proves_reads(r: &Record) -> bool {
    matches!(r.kind, Kind::Op(c) if !matches!(c, Cmd::Ddl | Cmd::Dcl | Cmd::Other)) && !r.failed
}

/// Tails the log for up to [`REPROBE`]. `Ok(Err(kind))` when the log
/// became unreadable.
async fn file_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    st: &mut FileStream,
) -> Result<Result<(), std::io::ErrorKind>, ConnectorError> {
    let started = Instant::now();
    let format = st.format;
    let source = match format {
        MongodbLogFormat::AuditLog => EventSource::MongodbAuditLog,
        MongodbLogFormat::ServerLog => EventSource::MongodbLog,
    };
    loop {
        let mut t = st.tailer.take().ok_or_else(internal)?;
        let (t, polled) = tokio::task::spawn_blocking(move || {
            let polled = t.poll().map(|p| {
                let parsed = parse_all(format, &p.records);
                (parsed.records, p.more, parsed.unparsed, parsed.valid)
            });
            (t, polled)
        })
        .await
        .map_err(|_| internal())?;
        let (records, more, unparsed, valid) = match polled {
            Ok(p) => p,
            Err(TailError::Unreadable(kind)) => return Ok(Err(kind)),
        };
        // ADR-0030: any valid `auditLog` record (the agent's own
        // `authenticate` at each check included) proves the file is
        // written; Limited from then on.
        if format == MongodbLogFormat::AuditLog && valid > 0 {
            state.note_record(&target.id, Source::AuditLog);
        }
        if format == MongodbLogFormat::AuditLog && records.iter().any(proves_reads) {
            state.note_authcheck(&target.id);
        }
        if format == MongodbLogFormat::ServerLog && !records.is_empty() {
            state.note_record(&target.id, Source::ServerLog);
        }
        if unparsed > 0 {
            state.note_dropped(&target.id, unparsed);
            tracing::warn!(
                target_id = %target.id,
                dropped = unparsed,
                "audit log records that do not parse dropped"
            );
        }
        if (t.oversized, t.malformed()) != st.reported {
            let skipped = t
                .oversized
                .saturating_sub(st.reported.0)
                .saturating_add(t.malformed().saturating_sub(st.reported.1));
            state.note_dropped(&target.id, skipped);
            tracing::warn!(
                target_id = %target.id,
                oversized = t.oversized.saturating_sub(st.reported.0),
                damaged = t.malformed().saturating_sub(st.reported.1),
                "audit log records skipped"
            );
            st.reported = (t.oversized, t.malformed());
        }
        let events = st.builder.convert(records, source, SystemTime::now());
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

/// Polls the profiler of `dbs` for up to [`REPROBE`], reconnecting when
/// the session is broken or stale.
async fn profiler_run(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    st: &mut ProfilerStream,
    dbs: &[String],
    timeouts: Timeouts,
) -> Result<(), ConnectorError> {
    let started = Instant::now();
    loop {
        if st
            .session
            .as_ref()
            .is_none_or(|s| s.is_broken() || s.is_stale())
        {
            let fresh = Session::connect(target, timeouts)
                .await
                .map_err(MgError::into_connector_error)?;
            if let Some(old) = st.session.replace(fresh) {
                if !old.is_broken() {
                    old.close().await;
                }
            }
        }
        let session = st.session.as_mut().ok_or_else(internal)?;
        for db in dbs {
            if !st.cursors.contains_key(db) {
                st.builder.grant_poll(db);
                match profiler::newest(session, db).await {
                    Ok(ts) => {
                        st.cursors.insert(db.clone(), DbCursor::after(ts));
                    }
                    Err(e) if !e.fatal => {
                        tracing::warn!(
                            target_id = %target.id,
                            server_code = e.server_code,
                            "profiler not readable in one database"
                        );
                        continue;
                    }
                    Err(e) => return Err(e.into_connector_error()),
                }
                continue;
            }
            for _ in 0..MAX_ROUNDS {
                let Some(cursor) = st.cursors.get_mut(db) else {
                    break;
                };
                st.builder.grant_poll(db);
                let polled = match profiler::poll(session, db, cursor).await {
                    Ok(p) => p,
                    Err(e) if !e.fatal => {
                        tracing::warn!(
                            target_id = %target.id,
                            server_code = e.server_code,
                            "profiler poll failed in one database"
                        );
                        break;
                    }
                    Err(e) => return Err(e.into_connector_error()),
                };
                if !polled.records.is_empty() {
                    state.note_record(&target.id, Source::Profiler);
                }
                if polled.dropped > 0 {
                    state.note_dropped(&target.id, polled.dropped);
                    tracing::warn!(
                        target_id = %target.id,
                        dropped = polled.dropped,
                        "profiler entries that do not parse dropped"
                    );
                }
                let events = st.builder.convert(
                    polled.records,
                    EventSource::MongodbProfiler,
                    SystemTime::now(),
                );
                for e in events {
                    sink.submit(e).await?;
                }
                if !polled.more {
                    break;
                }
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

    fn probe(edition: Option<&'static str>, profiler: bool) -> Probe {
        Probe {
            edition,
            mongos: false,
            profiler,
            profiler_recent: true,
        }
    }

    fn file(format: MongodbLogFormat, readable: bool, recent: bool) -> Option<FileState> {
        Some(FileState {
            format,
            readable,
            recent,
            seen: recent,
        })
    }

    /// A readable `auditLog` with a record, but no successful `authCheck`,
    /// in the last 24 h.
    fn seen_only() -> Option<FileState> {
        Some(FileState {
            format: MongodbLogFormat::AuditLog,
            readable: true,
            recent: false,
            seen: true,
        })
    }

    /// ADR-0030: every valid `auditLog` record counts as a proof that the
    /// file is written (the agent's own `authenticate` at each check, a
    /// `logout`, an `atype` that yields no event); a damaged one does not.
    #[test]
    fn valid_audit_log_records_prove_the_file_is_written() {
        let auth = br#"{"atype":"authenticate","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.15","port":51000},"users":[{"user":"databastion","db":"admin"}],"param":{"user":"databastion","db":"admin","mechanism":"SCRAM-SHA-256"},"result":0}"#;
        let other = br#"{"atype":"shutdown","ts":{"$date":"2026-09-29T10:00:00.000Z"},"users":[],"param":{},"result":0}"#;
        let damaged = br#"{"atype":"authCheck","ts":"#;
        let p = parse_all(
            MongodbLogFormat::AuditLog,
            &[&auth[..], &other[..], &damaged[..]],
        );
        assert_eq!((p.records.len(), p.valid, p.unparsed), (1, 2, 1));
        assert!(!p.records.iter().any(proves_reads));
        let p = parse_all(MongodbLogFormat::AuditLog, &[&damaged[..]]);
        assert_eq!(p.valid, 0);
    }

    /// ADR-0030: the `auditLog` is None until a record of it was parsed in
    /// the last 24 h, Limited then, Partial with a successful `authCheck`.
    #[test]
    fn a_stale_audit_log_is_none() {
        use MongodbLogFormat::AuditLog;
        let enterprise = probe(Some("enterprise"), false);
        let codes = |f| {
            let (_, s) = choose(enterprise, f);
            explain(enterprise, f, s)
                .1
                .iter()
                .map(|n| n.code())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            choose(enterprise, file(AuditLog, true, false)),
            (AuditLevel::None, Source::AuditLog)
        );
        let stale = codes(file(AuditLog, true, false));
        assert!(stale.contains(&NoteCode::AuditLimitedPendingFirstRecord));
        assert!(stale.contains(&NoteCode::AuditAuthcheckSuccessPending));
        assert_eq!(
            choose(enterprise, seen_only()),
            (AuditLevel::Limited, Source::AuditLog)
        );
        let seen = codes(seen_only());
        assert!(!seen.contains(&NoteCode::AuditLimitedPendingFirstRecord));
        assert!(seen.contains(&NoteCode::AuditAuthcheckSuccessPending));
        assert_eq!(
            choose(enterprise, file(AuditLog, true, true)),
            (AuditLevel::Partial, Source::AuditLog)
        );
        let proven = codes(file(AuditLog, true, true));
        assert!(!proven.contains(&NoteCode::AuditLimitedPendingFirstRecord));
        assert!(!proven.contains(&NoteCode::AuditAuthcheckSuccessPending));
    }

    #[test]
    fn levels_are_proven_never_full() {
        use MongodbLogFormat::{AuditLog, ServerLog};
        let enterprise = probe(Some("enterprise"), false);
        assert_eq!(
            choose(enterprise, file(AuditLog, true, true)),
            (AuditLevel::Partial, Source::AuditLog)
        );
        assert_eq!(
            choose(enterprise, seen_only()),
            (AuditLevel::Limited, Source::AuditLog)
        );
        assert_eq!(
            choose(probe(Some("percona"), false), file(AuditLog, true, true)).0,
            AuditLevel::Partial
        );
        // Community (or unknown edition) with an auditLog: not used.
        assert_eq!(
            choose(probe(Some("community"), false), file(AuditLog, true, true)),
            (AuditLevel::None, Source::None)
        );
        assert_eq!(
            choose(probe(None, true), file(AuditLog, true, true)),
            (AuditLevel::Limited, Source::Profiler)
        );
        assert_eq!(
            choose(probe(Some("community"), true), file(ServerLog, true, true)),
            (AuditLevel::Limited, Source::ServerLog)
        );
        // Nothing read yet from the server log or the profiler: None, but
        // the source is kept (the stream reads it).
        assert_eq!(
            choose(probe(Some("community"), true), file(ServerLog, true, false)),
            (AuditLevel::None, Source::ServerLog)
        );
        let pending = Probe {
            profiler_recent: false,
            ..probe(Some("community"), true)
        };
        assert_eq!(choose(pending, None), (AuditLevel::None, Source::Profiler));
        let (_, notes) = explain(pending, None, Source::Profiler);
        assert!(
            notes
                .iter()
                .any(|n| n.code() == NoteCode::AuditLimitedPendingFirstRecord)
        );
        // Unreadable file: the profiler, else nothing.
        assert_eq!(
            choose(enterprise, file(AuditLog, false, true)),
            (AuditLevel::None, Source::None)
        );
        assert_eq!(
            choose(probe(Some("community"), true), None),
            (AuditLevel::Limited, Source::Profiler)
        );
        // A mongos has no profiler.
        let mongos = Probe {
            mongos: true,
            ..probe(Some("community"), true)
        };
        assert_eq!(choose(mongos, None), (AuditLevel::None, Source::None));
        for p in [probe(Some("enterprise"), true), probe(None, true)] {
            for f in [
                None,
                file(AuditLog, true, true),
                file(ServerLog, true, true),
            ] {
                assert_ne!(choose(p, f).0, AuditLevel::Full);
            }
        }
    }

    #[test]
    fn notes_follow_the_choice() {
        use MongodbLogFormat::{AuditLog, ServerLog};
        let codes = |p, f| {
            let (_, s) = choose(p, f);
            explain(p, f, s)
                .1
                .iter()
                .map(|n| n.code().as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            codes(
                probe(Some("enterprise"), false),
                file(AuditLog, true, false)
            ),
            [
                "audit.limited_pending_first_record",
                "audit.authcheck_success_pending",
                "audit.log_without_row_counts"
            ]
        );
        assert_eq!(
            codes(probe(Some("enterprise"), false), seen_only()),
            [
                "audit.authcheck_success_pending",
                "audit.log_without_row_counts"
            ]
        );
        assert_eq!(
            codes(probe(Some("enterprise"), false), file(AuditLog, true, true)),
            ["audit.log_without_row_counts"]
        );
        assert_eq!(
            codes(probe(Some("community"), false), file(AuditLog, true, true)),
            ["audit.auditlog_on_community", "audit.source_not_configured"]
        );
        assert_eq!(
            codes(
                probe(Some("community"), false),
                file(ServerLog, false, false)
            ),
            ["audit.log_not_readable", "audit.source_not_configured"]
        );
        assert_eq!(
            codes(probe(Some("community"), true), None),
            ["audit.slow_operations_only"]
        );
    }

    #[test]
    fn own_address_is_an_ip_literal() {
        assert_eq!(
            own_address("172.18.0.1:40000"),
            ClientAddr::parse("172.18.0.1")
        );
        assert_eq!(own_address("[::1]:40000"), ClientAddr::parse("::1"));
        assert_eq!(own_address("anonymous unix socket:27017"), None);
    }
}
