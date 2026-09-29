//! `check()`: reachability, honest audit level, over-privilege and
//! coverage (ADR-0026 decisions 5, 10 and 11).
//!
//! - Reachability: TLS, `hello` (MongoDB 5.0 or later), SCRAM-SHA-256.
//! - Version and edition from `buildInfo`, for the agent's log only.
//! - Audit level: **None**, with the note `audit.stream_not_available`.
//!   This build has no MongoDB Audit stream (P5-B, P5-C), and the
//!   Discovery account cannot read the profiler level nor the audit
//!   settings: reporting the level a server could give would let an absent
//!   audit pass for a working one (docs/08).
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

use databastion_core::config::{MongodbTlsMode, TargetConfig};
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};
use tokio::io::{AsyncRead, AsyncWrite};

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) privileges: PrivilegeReport,
    /// Whether `connectionStatus` could be evaluated.
    pub(crate) privileges_known: bool,
    pub(crate) databases: usize,
    pub(crate) views: u64,
    pub(crate) other_kinds: u64,
    /// Time-series collections the account cannot read (no `find` on
    /// their bucket collections); counted only when the privileges are
    /// known.
    pub(crate) timeseries_unreadable: u64,
    /// Databases beyond [`MAX_CHECKED_DATABASES`], or listings cut.
    pub(crate) coverage_truncated: bool,
}

impl Report {
    /// Closed notes: privileges and views (counts only).
    pub(crate) fn notes(&self) -> Vec<TargetNote> {
        let mut out = self.privileges.notes();
        if self.views > 0 {
            out.push(TargetNote::new(NoteCode::CoverageViewsNotSampled).with_count(self.views));
        }
        if self.timeseries_unreadable > 0 {
            out.push(
                TargetNote::new(NoteCode::CoverageTimeseriesNotReadable)
                    .with_count(self.timeseries_unreadable),
            );
        }
        out
    }

    fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.privileges_known {
            out.push("privileges not evaluated (connectionStatus not readable)".to_owned());
        } else if !self.privileges.is_minimal() {
            out.push(format!(
                "over-privileged: {}",
                self.privileges.summary().join("; ")
            ));
        }
        if self.databases == 0 {
            out.push("the account holds privileges on no database: nothing to scan".to_owned());
        }
        if self.timeseries_unreadable > 0 {
            out.push(format!(
                "not covered: {} time-series collection(s) not readable (no find on their \
                 bucket collections, the optional system_buckets grant of ADR-0026)",
                self.timeseries_unreadable
            ));
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

/// Per-target state of `check()`: the last detailed report.
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<String, Cached>>,
}

impl CheckState {
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
        Ok(h) => h,
        Err(_) => TargetHealth {
            reachable: false,
            audit_level: AuditLevel::None,
            failure: Some(FailureCode::Timeout),
            detail: Some("check timed out".to_owned()),
            notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
        },
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
pub(crate) async fn report<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
) -> Result<Report, MgError> {
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
            Err(_) => tracing::warn!("connectionStatus reply not understood"),
        },
        Err(e) if !e.fatal => tracing::warn!(
            server_code = e.server_code,
            "connectionStatus failed: privileges not evaluated"
        ),
        Err(e) => return Err(e),
    }
    let (databases, truncated) = catalog::list_databases(session).await?;
    r.databases = databases.len();
    r.coverage_truncated = truncated || databases.len() > MAX_CHECKED_DATABASES;
    for db in databases.iter().take(MAX_CHECKED_DATABASES) {
        match catalog::list_collections(session, db).await {
            Ok((collections, truncated)) => {
                r.coverage_truncated |= truncated;
                for c in collections {
                    match c.kind {
                        CollKind::View => r.views += 1,
                        CollKind::Other => r.other_kinds += 1,
                        CollKind::Timeseries
                            if r.privileges_known && !r.privileges.can_read_buckets(db) =>
                        {
                            r.timeseries_unreadable += 1;
                        }
                        CollKind::Collection | CollKind::Timeseries => {}
                    }
                }
            }
            Err(e) if !e.fatal => {}
            Err(e) => return Err(e),
        }
    }
    Ok(r)
}

async fn check_inner(state: &CheckState, target: &TargetConfig) -> TargetHealth {
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
            return unreachable(&e, codes.into_vec());
        }
    };
    match build_info(&mut session).await {
        Ok(b) => detail.push(format!(
            "MongoDB {} ({}{})",
            b.version,
            b.edition,
            if session.info.mongos { ", mongos" } else { "" }
        )),
        Err(e) if !e.fatal => detail.push("buildInfo not readable".to_owned()),
        Err(e) => return unreachable(&e, codes.into_vec()),
    }
    detail.push(
        "no MongoDB Audit stream in this agent build (P5-B, P5-C): audit level None".to_owned(),
    );
    codes.add(TargetNote::new(NoteCode::AuditStreamNotAvailable));
    if state.due(&target.id) && !session.is_broken() {
        match report(&mut session).await {
            Ok(r) => {
                if state.store(target.id.clone(), r.clone()) {
                    log_report(target, &r);
                }
            }
            Err(e) => tracing::warn!(
                target_id = %target.id,
                stage = e.stage.as_str(),
                server_code = e.server_code,
                "privilege and coverage report failed"
            ),
        }
    }
    if let Some(r) = state.cached(&target.id) {
        detail.extend(r.summary());
        codes.extend(r.notes());
    }
    if !session.is_broken() {
        session.close().await;
    }
    TargetHealth {
        reachable: true,
        audit_level: AuditLevel::None,
        failure: None,
        detail: Some(format!("audit level None; {}", detail.join("; "))),
        notes: codes.into_vec(),
    }
}

fn log_report(target: &TargetConfig, r: &Report) {
    if !r.privileges_known {
        tracing::warn!(target_id = %target.id, "account privileges not evaluated");
    } else if r.privileges.is_minimal() {
        tracing::info!(
            target_id = %target.id,
            "account privileges: find and listCollections only"
        );
    } else {
        tracing::warn!(
            target_id = %target.id,
            over_privileged = r.privileges.summary().join("; "),
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
        let notes = r.notes();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].code(), NoteCode::CoverageViewsNotSampled);
        assert_eq!(notes[0].count(), Some(3));
        assert!(notes[0].labels().is_empty());
        let text = r.summary().join("; ");
        assert!(text.contains("3 view(s)"), "{text}");
    }

    #[test]
    fn every_note_is_registered_for_mongodb() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../shared/protocol/target-notes.json"
        ))
        .unwrap();
        for code in [
            NoteCode::AuditStreamNotAvailable,
            NoteCode::CheckStageFailed,
            NoteCode::CheckTimedOut,
            NoteCode::SecurityTlsDisabled,
            NoteCode::CoverageViewsNotSampled,
            NoteCode::CoverageTimeseriesNotReadable,
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
