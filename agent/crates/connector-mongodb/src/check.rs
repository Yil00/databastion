//! `check()`: reachability, honest audit level, over-privilege and
//! coverage (ADR-0026 decisions 5, 10 and 11).
//!
//! - Reachability: TLS, `hello` (MongoDB 5.0 or later), SCRAM-SHA-256.
//! - Version and edition from `buildInfo`, for the agent's log only.
//! - Audit level and source (ADR-0027): the same rule as the Audit stream
//!   (`audit::choose`), proven from what the agent can read (the edition,
//!   the configured log file, a successful `authCheck` read in the last
//!   24 h, the account's `find` on `system.profile`), never from server
//!   settings the account cannot see. Full is never reported.
//! - Over-privilege from `connectionStatus` (see [`crate::privileges`]),
//!   and coverage: views (never sampled) in the databases the account
//!   sees. This report is recomputed at most every [`REPORT_INTERVAL`] per
//!   target and logged when it changes.
//!
//! Every explanation is also a closed note (`TargetHealth::notes`,
//! `shared/protocol/target-notes.json`): a code and a count, never a name
//! or any text from the server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::EventSource;
use databastion_core::audit::own::SharedOwnUsage;
use databastion_core::config::{MongodbTlsMode, TargetConfig};
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::audit::{self, Probe, Source};
use crate::bson::{DocBuf, Value};
use crate::catalog::{self, CollKind};
use crate::conn::{Kind, Session, Timeouts};
use crate::error::{MgError, Stage};
use crate::privileges::PrivilegeReport;

/// Timeout of each `check()` command.
const CHECK_STATEMENT_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Period of the detailed report.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);
/// Databases whose collections are listed for the coverage report.
const MAX_CHECKED_DATABASES: usize = 64;

/// The detailed report of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) privileges: PrivilegeReport,
    /// Whether `connectionStatus` could be evaluated.
    pub(crate) privileges_known: bool,
    pub(crate) databases: usize,
    pub(crate) views: u64,
    pub(crate) other_kinds: u64,
    /// Databases beyond [`MAX_CHECKED_DATABASES`], or listings cut or
    /// failed.
    pub(crate) coverage_truncated: bool,
    /// Whether the databases could be listed at all.
    pub(crate) coverage_known: bool,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            privileges: PrivilegeReport::default(),
            privileges_known: false,
            databases: 0,
            views: 0,
            other_kinds: 0,
            coverage_truncated: false,
            coverage_known: true,
        }
    }
}

impl Report {
    /// Closed notes: privileges and views (counts only).
    /// `profiler_in_use`: an Audit stream reads the profiler (its grant is
    /// then expected).
    pub(crate) fn notes(&self, profiler_in_use: bool) -> Vec<TargetNote> {
        let mut out = if self.privileges_known {
            self.privileges.notes(profiler_in_use)
        } else {
            vec![TargetNote::new(NoteCode::PrivilegeNotEvaluated)]
        };
        if self.views > 0 {
            out.push(TargetNote::new(NoteCode::CoverageViewsNotSampled).with_count(self.views));
        }
        out
    }

    fn summary(&self, profiler_in_use: bool) -> Vec<String> {
        let mut out = Vec::new();
        if !self.privileges_known {
            out.push("privileges not evaluated (connectionStatus not readable)".to_owned());
        } else if !self.privileges.is_minimal(profiler_in_use) {
            out.push(format!(
                "over-privileged: {}",
                self.privileges.summary(profiler_in_use).join("; ")
            ));
        }
        if !self.coverage_known {
            out.push("coverage not evaluated (databases not listed)".to_owned());
        } else if self.databases == 0 {
            out.push("the account holds privileges on no database: nothing to scan".to_owned());
        }
        if self.views > 0 || self.other_kinds > 0 {
            out.push(format!(
                "not covered: {} view(s) and {} collection(s) of another type not sampled",
                self.views, self.other_kinds
            ));
        }
        out
    }
}

struct Cached {
    at: Instant,
    report: Report,
}

/// Per-target state of `check()`: the last detailed report, what the
/// Audit stream observed (the last successful `authCheck`, dropped
/// records, its source) and the agent's own reads (shared by every stream
/// of the target).
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<String, Cached>>,
    /// Per target: time-series collections the server refused to the
    /// account (`Unauthorized`) in the last scan, and when.
    timeseries_refused: Mutex<HashMap<String, (u64, Instant)>>,
    /// Source of the level last reported by `check()`.
    sources: Mutex<HashMap<String, EventSource>>,
    /// When the stream last parsed a successful `authCheck` record.
    authchecks: Mutex<HashMap<String, Instant>>,
    /// Running streams (count) and the source of the latest one.
    streams: Mutex<HashMap<String, (usize, Source)>>,
    own_usage: Mutex<HashMap<String, SharedOwnUsage>>,
    /// Records dropped (not parsable, oversized or damaged), and when the
    /// count started (reported for 24 h).
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
}

/// A successful `authCheck` parsed within this period makes the
/// `auditLog` source Partial.
pub(crate) const RECORD_FRESHNESS: Duration = Duration::from_secs(24 * 3600);

/// Marks an Audit stream as running for a target while alive.
pub(crate) struct StreamGuard<'a> {
    state: &'a CheckState,
    target_id: String,
}

impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        let mut map = lock(&self.state.streams);
        if let Some((n, _)) = map.get_mut(&self.target_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.target_id);
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How long a scan's time-series refusals are reported.
const SCAN_OBSERVATION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

impl CheckState {
    /// The Audit stream of `target_id` starts (its source is set by
    /// [`Self::set_stream_source`] at each re-probe).
    pub(crate) fn stream_started(&self, target_id: &str) -> StreamGuard<'_> {
        lock(&self.streams)
            .entry(target_id.to_owned())
            .or_insert((0, Source::None))
            .0 += 1;
        StreamGuard {
            state: self,
            target_id: target_id.to_owned(),
        }
    }

    /// The source the running stream of `target_id` reads.
    pub(crate) fn set_stream_source(&self, target_id: &str, source: Source) {
        if let Some(entry) = lock(&self.streams).get_mut(target_id) {
            entry.1 = source;
        }
    }

    /// Whether a running Audit stream of `target_id` reads the profiler.
    pub(crate) fn profiler_in_use(&self, target_id: &str) -> bool {
        lock(&self.streams)
            .get(target_id)
            .is_some_and(|(_, s)| *s == Source::Profiler)
    }

    /// The stream of `target_id` parsed a successful `authCheck`.
    pub(crate) fn note_authcheck(&self, target_id: &str) {
        lock(&self.authchecks).insert(target_id.to_owned(), Instant::now());
    }

    /// Whether a successful `authCheck` of `target_id` was parsed
    /// recently.
    pub(crate) fn recent_authcheck(&self, target_id: &str) -> bool {
        lock(&self.authchecks)
            .get(target_id)
            .is_some_and(|t| t.elapsed() < RECORD_FRESHNESS)
    }

    /// Records of `target_id` dropped by the stream.
    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        let mut map = lock(&self.dropped);
        let entry = map
            .entry(target_id.to_owned())
            .or_insert((0, Instant::now()));
        if entry.1.elapsed() >= RECORD_FRESHNESS {
            *entry = (0, Instant::now());
        }
        entry.0 = entry.0.saturating_add(n);
    }

    fn dropped(&self, target_id: &str) -> u64 {
        lock(&self.dropped)
            .get(target_id)
            .filter(|(_, since)| since.elapsed() < RECORD_FRESHNESS)
            .map_or(0, |(n, _)| *n)
    }

    /// The agent's own-read counters of `target_id`, kept for the life of
    /// the connector.
    pub(crate) fn own_usage(&self, target_id: &str) -> SharedOwnUsage {
        std::sync::Arc::clone(
            lock(&self.own_usage)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// Source of the level last reported for `target_id`.
    pub(crate) fn audit_source(&self, target_id: &str) -> Option<EventSource> {
        lock(&self.sources).get(target_id).copied()
    }

    fn set_source(&self, target_id: &str, source: Option<EventSource>) {
        let mut map = lock(&self.sources);
        match source {
            Some(s) => {
                map.insert(target_id.to_owned(), s);
            }
            None => {
                map.remove(target_id);
            }
        }
    }

    /// Records what the last scan of `target_id` observed: how many
    /// time-series collections the server refused to the account.
    pub(crate) fn record_scan(&self, target_id: &str, timeseries_refused: u64) {
        self.timeseries_refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), (timeseries_refused, Instant::now()));
    }

    fn timeseries_refused(&self, target_id: &str) -> u64 {
        self.timeseries_refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .filter(|(_, at)| at.elapsed() < SCAN_OBSERVATION_TTL)
            .map_or(0, |(n, _)| *n)
    }

    fn due(&self, key: &str) -> bool {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .is_none_or(|c| c.at.elapsed() >= REPORT_INTERVAL)
    }

    /// Stores a report; `true` if it differs from the previous one.
    fn store(&self, key: String, report: Report) -> bool {
        let mut map = self
            .reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = map.get(&key).is_none_or(|c| c.report != report);
        map.insert(
            key,
            Cached {
                at: Instant::now(),
                report,
            },
        );
        changed
    }

    fn cached(&self, key: &str) -> Option<Report> {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .map(|c| c.report.clone())
    }
}

fn unreachable(e: &MgError, mut notes: Vec<TargetNote>) -> TargetHealth {
    notes.push(
        TargetNote::new(NoteCode::CheckStageFailed)
            .with_labels([NoteLabel::stage(e.stage.as_str())]),
    );
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "{} failed (error {})",
            e.stage.as_str(),
            e.engine_code().unwrap_or_else(|| "none".to_owned())
        )),
        notes,
    }
}

/// `check()` of a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TIMEOUT, check_inner(state, target)).await {
        Ok((h, source)) => {
            state.set_source(&target.id, source.event_source());
            h
        }
        Err(_) => {
            state.set_source(&target.id, None);
            TargetHealth {
                reachable: false,
                audit_level: AuditLevel::None,
                failure: Some(FailureCode::Timeout),
                detail: Some("check timed out".to_owned()),
                notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
            }
        }
    }
}

/// Server version and edition, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Build {
    pub(crate) version: String,
    pub(crate) edition: &'static str,
}

/// `buildInfo` (no privilege needed).
pub(crate) async fn build_info<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
) -> Result<Build, MgError> {
    let reply = session
        .command(
            Stage::Check,
            "admin",
            DocBuf::new().i32("buildInfo", 1),
            Kind::Setup,
        )
        .await?;
    let doc = reply.doc();
    let bad = |_| MgError {
        fatal: false,
        ..MgError::new(FailureCode::Internal, Stage::Check)
    };
    // Logged: a short version made of version characters only.
    let version = doc
        .str("version")
        .map_err(bad)?
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 32
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
        })
        .unwrap_or("unknown")
        .to_owned();
    let enterprise = match doc.array("modules").map_err(bad)? {
        Some(modules) => modules
            .iter()
            .any(|m| matches!(m, Ok((_, Value::Str(s))) if s == b"enterprise")),
        None => false,
    };
    let edition = if doc.get("psmdbVersion").map_err(bad)?.is_some() {
        "percona"
    } else if enterprise {
        "enterprise"
    } else {
        "community"
    };
    Ok(Build { version, edition })
}

/// Privileges and coverage.
pub(crate) async fn report<S: AsyncRead + AsyncWrite + Unpin>(session: &mut Session<S>) -> Report {
    let mut r = Report::default();
    let status = session
        .command(
            Stage::Check,
            "admin",
            DocBuf::new()
                .i32("connectionStatus", 1)
                .bool("showPrivileges", true),
            Kind::Read,
        )
        .await;
    match status {
        Ok(reply) => match PrivilegeReport::from_connection_status(reply.doc()) {
            Ok(p) => {
                r.privileges = p;
                r.privileges_known = true;
            }
            Err(_) => {
                tracing::warn!("connectionStatus reply not understood: privileges not evaluated")
            }
        },
        Err(e) => tracing::warn!(
            server_code = e.server_code,
            "connectionStatus failed: privileges not evaluated"
        ),
    }
    // Coverage: a failure here keeps the privilege evaluation above.
    let databases = match catalog::list_databases(session).await {
        Ok((databases, truncated)) => {
            r.coverage_truncated = truncated;
            databases
        }
        Err(e) => {
            tracing::warn!(
                server_code = e.server_code,
                "databases not listed: coverage not evaluated"
            );
            r.coverage_known = false;
            return r;
        }
    };
    r.databases = databases.len();
    r.coverage_truncated |= databases.len() > MAX_CHECKED_DATABASES;
    for db in databases.iter().take(MAX_CHECKED_DATABASES) {
        match catalog::list_collections(session, db).await {
            Ok((collections, truncated)) => {
                r.coverage_truncated |= truncated;
                for c in collections {
                    match c.kind {
                        CollKind::View => r.views += 1,
                        CollKind::Other => r.other_kinds += 1,
                        CollKind::Collection | CollKind::Timeseries => {}
                    }
                }
            }
            Err(e) if !e.fatal => r.coverage_truncated = true,
            Err(_) => {
                r.coverage_truncated = true;
                break;
            }
        }
    }
    r
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> (TargetHealth, Source) {
    // `detail`: the local log detail; `codes`: the same as closed notes.
    let mut detail: Vec<String> = Vec::new();
    let mut codes = Notes::default();
    if target.mongodb_settings().tls == MongodbTlsMode::DisableInsecure {
        detail.push(
            "INSECURE: TLS disabled on a network connection (tls: disable_insecure): traffic in \
             clear, read-only not guaranteed"
                .to_owned(),
        );
        codes.add(TargetNote::new(NoteCode::SecurityTlsDisabled));
    }
    let mut session = match Session::connect(target, Timeouts::new(CHECK_STATEMENT_TIMEOUT)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target_id = %target.id,
                stage = e.stage.as_str(),
                server_code = e.server_code,
                code = %e.code,
                "target check failed"
            );
            return (unreachable(&e, codes.into_vec()), Source::None);
        }
    };
    let edition = match build_info(&mut session).await {
        Ok(b) => {
            detail.push(format!(
                "MongoDB {} ({}{})",
                b.version,
                b.edition,
                if session.info.mongos { ", mongos" } else { "" }
            ));
            Some(b.edition)
        }
        Err(e) if !e.fatal => {
            detail.push("buildInfo not readable".to_owned());
            None
        }
        Err(e) => return (unreachable(&e, codes.into_vec()), Source::None),
    };
    let profiler_in_use = state.profiler_in_use(&target.id);
    if state.due(&target.id) && !session.is_broken() {
        let r = report(&mut session).await;
        if state.store(target.id.clone(), r.clone()) {
            log_report(target, &r, profiler_in_use);
        }
    }
    let cached = state.cached(&target.id);
    let probe = Probe {
        edition,
        mongos: session.info.mongos,
        profiler: cached
            .as_ref()
            .is_some_and(|r| r.privileges_known && r.privileges.can_read_profiler()),
    };
    let file = audit::file_state(state, target).await;
    let (level, source) = audit::choose(probe, file);
    let (text, audit_codes) = audit::explain(probe, file, source);
    detail.extend(text);
    codes.extend(audit_codes);
    let dropped = state.dropped(&target.id);
    if dropped > 0 {
        detail.push(format!(
            "{dropped} audit record(s) dropped in the last 24 h (not parsable, oversized or \
             damaged)"
        ));
        codes.add(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(dropped));
    }
    match cached {
        Some(r) => {
            detail.extend(r.summary(profiler_in_use));
            codes.extend(r.notes(profiler_in_use));
        }
        // No report yet (the session broke before it): the privileges are
        // not evaluated, which must not read as least privilege.
        None => {
            detail.push("privileges not evaluated".to_owned());
            codes.add(TargetNote::new(NoteCode::PrivilegeNotEvaluated));
        }
    }
    // Observed, not predicted: what the server refused in the last scan.
    let refused = state.timeseries_refused(&target.id);
    if refused > 0 {
        let granted = state
            .cached(&target.id)
            .is_some_and(|r| r.privileges.has_bucket_grant());
        detail.push(format!(
            "not covered: {refused} time-series collection(s) refused to the account in the last \
             scan{}",
            if granted {
                ""
            } else {
                " (the account holds no find on bucket collections: see ADR-0026)"
            }
        ));
        codes.add(TargetNote::new(NoteCode::CoverageTimeseriesNotReadable).with_count(refused));
    }
    if !session.is_broken() {
        session.close().await;
    }
    (
        TargetHealth {
            reachable: true,
            audit_level: level,
            failure: None,
            detail: Some(format!("audit level {level:?}; {}", detail.join("; "))),
            notes: codes.into_vec(),
        },
        source,
    )
}

fn log_report(target: &TargetConfig, r: &Report, profiler_in_use: bool) {
    if !r.privileges_known {
        tracing::warn!(target_id = %target.id, "account privileges not evaluated");
    } else if r.privileges.is_minimal(profiler_in_use) {
        tracing::info!(
            target_id = %target.id,
            "account privileges: find and listCollections only"
        );
    } else {
        tracing::warn!(
            target_id = %target.id,
            over_privileged = r.privileges.summary(profiler_in_use).join("; "),
            "the agent account is over-privileged"
        );
    }
    if r.views > 0 || r.other_kinds > 0 {
        tracing::info!(
            target_id = %target.id,
            views = r.views,
            other = r.other_kinds,
            truncated = r.coverage_truncated,
            "collections not sampled by Discovery"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_notes_are_codes_and_counts_only() {
        let r = Report {
            privileges_known: true,
            databases: 2,
            views: 3,
            ..Report::default()
        };
        let notes = r.notes(false);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].code(), NoteCode::CoverageViewsNotSampled);
        assert_eq!(notes[0].count(), Some(3));
        assert!(notes[0].labels().is_empty());
        let text = r.summary(false).join("; ");
        assert!(text.contains("3 view(s)"), "{text}");
    }

    #[test]
    fn every_note_is_registered_for_mongodb() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../shared/protocol/target-notes.json"
        ))
        .unwrap();
        for code in [
            NoteCode::AuditAuditlogOnCommunity,
            NoteCode::AuditAuthcheckSuccessPending,
            NoteCode::AuditSlowOperationsOnly,
            NoteCode::AuditSourceNotConfigured,
            NoteCode::AuditLogNotReadable,
            NoteCode::AuditLogWithoutRowCounts,
            NoteCode::AuditRecordsDropped,
            NoteCode::CheckStageFailed,
            NoteCode::CheckTimedOut,
            NoteCode::SecurityTlsDisabled,
            NoteCode::CoverageViewsNotSampled,
            NoteCode::CoverageTimeseriesNotReadable,
            NoteCode::PrivilegeNotEvaluated,
            NoteCode::PrivilegeWriteActions,
            NoteCode::PrivilegeReadBeyondDiscovery,
            NoteCode::PrivilegeClusterActions,
            NoteCode::PrivilegeAnyDatabase,
            NoteCode::PrivilegeSystemCollections,
        ] {
            let engines = v[code.as_str()]["engines"]
                .as_array()
                .unwrap_or_else(|| panic!("{} is not registered", code.as_str()));
            assert!(
                engines.iter().any(|e| e == "mongodb"),
                "{} is not registered for mongodb",
                code.as_str()
            );
        }
    }

    #[test]
    fn check_failures_are_noted_with_their_stage_only() {
        let e = MgError::server(Some(18), Stage::Auth);
        let h = unreachable(&e, Vec::new());
        assert!(!h.reachable);
        assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(h.notes.len(), 1);
        assert_eq!(h.notes[0].code(), NoteCode::CheckStageFailed);
        assert_eq!(h.notes[0].labels()[0].as_str(), "stage_auth");
        assert_eq!(h.detail.as_deref(), Some("auth failed (error 18)"));
    }

    #[test]
    fn time_series_refusals_come_from_the_last_scan() {
        let state = CheckState::default();
        assert_eq!(state.timeseries_refused("t"), 0);
        state.record_scan("t", 2);
        assert_eq!(state.timeseries_refused("t"), 2);
        state.record_scan("t", 0);
        assert_eq!(state.timeseries_refused("t"), 0);
    }

    #[test]
    fn reports_are_cached_per_target() {
        let state = CheckState::default();
        assert!(state.due("t"));
        assert!(state.store("t".to_owned(), Report::default()));
        assert!(!state.due("t"));
        assert!(!state.store("t".to_owned(), Report::default()));
        assert_eq!(state.cached("t"), Some(Report::default()));
        assert!(state.due("other"));
    }
}
