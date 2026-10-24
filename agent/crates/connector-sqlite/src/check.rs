//! `check()` and the target state (ADR-0059 decision 7).
//!
//! - Audit level `none`, no audit source, no server version.
//! - **Full check** (a short-lived reader: the open procedure, the
//!   connection setup, the catalog statement and the check pragmas) at the
//!   first heartbeat, when the file's `(st_dev, st_ino)`, size, `mtime` or
//!   header change counter changed, and otherwise at most every 10 minutes.
//! - **Light check** at every other heartbeat: the path and file checks and
//!   the header pre-check, with no SQLite connection, run by the agent with
//!   the target's lock taken **without waiting**; when the lock is busy (a
//!   scan's reader holds the target, and re-runs these checks itself before
//!   each unit of work), the check is skipped and the last result reported.
//! - Budget: 2 s per check.
//! - The closed failure-code and stage table of decision 7 ([`outcome`]).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_core::config::sqlite::{RollbackMode, SqliteSettings, is_refused_location};
use databastion_core::notes::{NoteCode, NoteLabel, TargetNote};
use databastion_core::{AuditLevel, FailureCode, TargetHealth};

use crate::files::{self, Identity, Policy};
use crate::ipc::{Code, Failure, OpenRequest, Request, Response, Rule};
use crate::process::{DEADLINE_SLACK, Death, ReaderProcess};

/// A full check at least this often.
pub const FULL_CHECK_EVERY: Duration = Duration::from_secs(600);
/// The budget of one check (decision 7).
pub const CHECK_BUDGET: Duration = Duration::from_secs(2);

/// The stage a request belongs to (the `check.stage_failed` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The file checks and the open.
    Connect,
    /// The sandbox, the self-check and the connection setup.
    SessionSetup,
    /// The catalog.
    Introspection,
    /// `table_xinfo`.
    Columns,
    /// Sampling.
    Sample,
    /// The check pragmas.
    Check,
}

impl Stage {
    /// The label's stage name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::SessionSetup => "session_setup",
            Self::Introspection => "introspection",
            Self::Columns => "columns",
            Self::Sample => "sample",
            Self::Check => "check",
        }
    }
}

/// Decision 7's table: the failure code, the stage (when the cause fixes
/// it) and the note of a reader failure.
#[must_use]
pub fn outcome(code: Code) -> (FailureCode, Option<Stage>, Option<NoteCode>) {
    use FailureCode as F;
    match code {
        Code::NotFound => (F::TargetUnreachable, Some(Stage::Connect), None),
        Code::NotReadable => (F::PermissionDenied, Some(Stage::Connect), None),
        Code::PathRefused | Code::FileChanged => (
            F::Unsupported,
            Some(Stage::Connect),
            Some(NoteCode::CoverageFilePathRefused),
        ),
        Code::Writable => (
            F::Unsupported,
            Some(Stage::Connect),
            Some(NoteCode::PrivilegeDatabaseFileWritable),
        ),
        Code::NotReadOnlyFs => (
            F::Unsupported,
            Some(Stage::Connect),
            Some(NoteCode::CoverageFilesystemNotReadOnly),
        ),
        Code::NetworkFs => (
            F::Unsupported,
            Some(Stage::Connect),
            Some(NoteCode::CoverageNetworkFilesystemRefused),
        ),
        Code::SandboxUnavailable => (
            F::Unsupported,
            Some(Stage::SessionSetup),
            Some(NoteCode::CoverageReaderSandboxUnavailable),
        ),
        Code::SelfCheckFailed => (F::Unsupported, Some(Stage::SessionSetup), None),
        Code::UnrecognizedFormat => (
            F::Unsupported,
            Some(Stage::Introspection),
            Some(NoteCode::CoverageUnrecognizedFileFormat),
        ),
        Code::WalNotReadable | Code::WalTooLarge => (
            F::TargetUnreachable,
            Some(Stage::Connect),
            Some(NoteCode::CoverageWalFilesNotReadable),
        ),
        Code::HotJournal => (
            F::TargetUnreachable,
            Some(Stage::Connect),
            Some(NoteCode::CoverageHotJournalPending),
        ),
        // Reachable: handled by the callers.
        Code::RollbackNotRead => (
            F::Unsupported,
            Some(Stage::Connect),
            Some(NoteCode::CoverageRollbackModeNotRead),
        ),
        Code::Busy | Code::Interrupted => (F::Timeout, None, Some(NoteCode::CheckTimedOut)),
        Code::NoMemory | Code::TooBig => (F::ResourceLimit, None, None),
        Code::Corrupt
        | Code::NoRowid
        | Code::NoSuchTable
        | Code::ViewProhibited
        | Code::Auth
        | Code::Protocol
        | Code::Internal => (F::Internal, None, None),
    }
}

/// Decision 7's table for a reader that is gone.
#[must_use]
pub fn death_outcome(death: Death) -> (FailureCode, Option<NoteCode>) {
    match death {
        Death::Deadline => (FailureCode::Timeout, Some(NoteCode::CheckTimedOut)),
        Death::Died | Death::Protocol => (
            FailureCode::Internal,
            Some(NoteCode::CoverageReaderProcessFailed),
        ),
        Death::Spawn => (FailureCode::Internal, None),
    }
}

/// Notes of the last scan, reported by the next checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanNotes {
    /// Views not sampled.
    pub views: u64,
    /// Virtual tables not sampled.
    pub virtual_tables: u64,
    /// `VIRTUAL` generated columns not sampled.
    pub computed_columns: u64,
    /// Readers that died or were killed.
    pub reader_failures: u64,
}

/// What changes trigger a full check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    id: Identity,
    size: u64,
    mtime: (i64, i64),
    change_counter: u32,
}

#[derive(Debug, Default)]
struct Inner {
    last: Option<TargetHealth>,
    last_full: Option<(Instant, Fingerprint)>,
    scan: ScanNotes,
}

/// One target's state: its lock (decision 2: no descriptor on the
/// database or a side file outside it) and its last results.
#[derive(Debug, Default)]
pub struct TargetState {
    /// Held for the whole life of a reader of this target, and by the
    /// agent's own light check.
    pub lock: tokio::sync::Mutex<()>,
    inner: std::sync::Mutex<Inner>,
}

impl TargetState {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Records the notes of a finished scan.
    pub fn record_scan(&self, notes: ScanNotes) {
        self.with(|i| i.scan = notes);
    }
}

/// A failure as a target health: the code, its note and
/// `check.stage_failed` with the stage.
#[must_use]
pub fn failed_health(code: FailureCode, stage: Stage, note: Option<NoteCode>) -> TargetHealth {
    let mut notes = Vec::new();
    if let Some(n) = note {
        notes.push(TargetNote::new(n));
    }
    notes.push(
        TargetNote::new(NoteCode::CheckStageFailed).with_labels([NoteLabel::stage(stage.as_str())]),
    );
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(code),
        detail: None,
        notes,
    }
}

/// The health of a reader failure at `stage`.
#[must_use]
pub fn failure_health(f: Failure, stage: Stage) -> TargetHealth {
    let (code, fixed, note) = outcome(f.code);
    failed_health(code, fixed.unwrap_or(stage), note)
}

/// The path-based rules the agent checks before any descriptor: the
/// refused locations and the other targets' files (duplicates). No
/// descriptor is opened.
///
/// # Errors
/// [`Code::PathRefused`] with its rule.
pub fn pre_check(settings: &SqliteSettings) -> Result<(), Failure> {
    let path = settings.path();
    if is_refused_location(path, settings.refused()) {
        return Err(Failure::rule(Code::PathRefused, Rule::RefusedLocation));
    }
    if let Some(mine) = files::identity_of(path)
        && settings
            .others()
            .iter()
            .any(|o| files::identity_of(o) == Some(mine))
    {
        return Err(Failure::rule(Code::PathRefused, Rule::DuplicateFile));
    }
    Ok(())
}

/// The open request of a target.
#[must_use]
pub fn open_request(settings: &SqliteSettings) -> OpenRequest {
    OpenRequest {
        path: zeroize::Zeroizing::new(files::path_bytes(settings.path())),
        max_statement_ms: settings.max_statement_ms(),
        rollback_read: settings.rollback_mode() == RollbackMode::Read,
    }
}

/// The deadline of one request.
#[must_use]
pub fn request_deadline(settings: &SqliteSettings) -> Duration {
    Duration::from_millis(u64::from(settings.max_statement_ms())) + DEADLINE_SLACK
}

fn log_refusal(target_id: &str, f: Failure, stage: Stage) {
    tracing::warn!(
        target_id,
        code = f.code.as_str(),
        rule = f.rule.map(Rule::as_str),
        engine_code = f.engine_code,
        stage = stage.as_str(),
        "sqlite target refused or not readable"
    );
}

/// The light check, by the agent itself under the target's lock: the
/// file rules on a descriptor opened, checked and closed here.
fn light(path: &Path) -> Result<(Fingerprint, bool, bool, bool), Failure> {
    #[allow(unused_mut)]
    let mut policy = Policy::AGENT;
    #[cfg(any(test, feature = "test-support"))]
    if crate::process::test_credentials() {
        policy.refuse_agent_writable = false;
    }
    let c = files::open_checked(path, policy)?;
    let fp = Fingerprint {
        id: c.id,
        size: c.size,
        mtime: c.mtime,
        change_counter: c.header.change_counter,
    };
    let wal = c.header.wal || c.side.wal.is_some();
    let wal_ok = !wal
        || matches!((c.side.wal, c.side.shm), (Some(w), Some(_)) if w.size <= files::MAX_WAL_BYTES);
    Ok((fp, wal, wal_ok, c.world_readable))
}

/// A full check: a short-lived reader opens the file, reads the catalog
/// and the check pragmas, and exits.
async fn full(settings: &SqliteSettings, budget: Instant) -> Result<(), TargetHealth> {
    let mut reader = ReaderProcess::spawn().map_err(|d| {
        let (code, note) = death_outcome(d);
        failed_health(code, Stage::SessionSetup, note)
    })?;
    let per = request_deadline(settings);
    let left = || budget.saturating_duration_since(Instant::now()).min(per);
    let steps = [
        (Request::Open(open_request(settings)), Stage::Connect),
        (Request::Catalog, Stage::Introspection),
        (Request::Pragmas, Stage::Check),
    ];
    for (req, stage) in steps {
        match reader.call(&req, left()).await {
            Ok(Response::Failed(f)) => {
                reader.kill().await;
                return Err(failure_health(f, stage));
            }
            Ok(_) => {}
            Err(d) => {
                databastion_core::connector::count_sqlite_reader_failure();
                let (code, note) = death_outcome(d);
                return Err(failed_health(code, stage, note));
            }
        }
    }
    reader.close().await;
    Ok(())
}

/// `check()` of one target.
pub async fn check(
    target_id: &str,
    settings: &SqliteSettings,
    st: Arc<TargetState>,
) -> TargetHealth {
    let Ok(guard) = st.lock.try_lock() else {
        // A scan's reader holds the target: the last result.
        return st.with(|i| i.last.clone()).unwrap_or_else(|| {
            failed_health(
                FailureCode::Timeout,
                Stage::Connect,
                Some(NoteCode::CheckTimedOut),
            )
        });
    };
    let budget = Instant::now() + CHECK_BUDGET;
    let health =
        match tokio::time::timeout(CHECK_BUDGET, run(target_id, settings, &st, budget)).await {
            Ok(h) => h,
            Err(_) => failed_health(
                FailureCode::Timeout,
                Stage::Connect,
                Some(NoteCode::CheckTimedOut),
            ),
        };
    drop(guard);
    st.with(|i| i.last = Some(health.clone()));
    health
}

async fn run(
    target_id: &str,
    settings: &SqliteSettings,
    st: &TargetState,
    budget: Instant,
) -> TargetHealth {
    if let Err(f) = pre_check(settings) {
        log_refusal(target_id, f, Stage::Connect);
        return failure_health(f, Stage::Connect);
    }
    let path = settings.path().to_owned();
    let lit = tokio::task::spawn_blocking(move || light(&path)).await;
    let (fp, wal, wal_ok, world_readable) = match lit {
        Ok(Ok(x)) => x,
        Ok(Err(f)) => {
            log_refusal(target_id, f, Stage::Connect);
            return failure_health(f, Stage::Connect);
        }
        Err(_) => return failed_health(FailureCode::Internal, Stage::Connect, None),
    };
    let mut notes = Vec::new();
    if world_readable {
        notes.push(TargetNote::new(NoteCode::SecurityFileWorldReadable));
    }
    let scan = st.with(|i| i.scan);
    for (code, n) in [
        (NoteCode::CoverageViewsNotSampled, scan.views),
        (
            NoteCode::CoverageVirtualTablesNotSampled,
            scan.virtual_tables,
        ),
        (
            NoteCode::CoverageComputedColumnsNotSampled,
            scan.computed_columns,
        ),
        (NoteCode::CoverageReaderProcessFailed, scan.reader_failures),
    ] {
        if n > 0 {
            notes.push(TargetNote::new(code).with_count(n));
        }
    }
    if !wal && settings.rollback_mode() == RollbackMode::Skip {
        // Reachable, not read: no SQLite connection is opened.
        notes.push(TargetNote::new(NoteCode::CoverageRollbackModeNotRead));
        return TargetHealth {
            reachable: true,
            audit_level: AuditLevel::None,
            failure: None,
            detail: None,
            notes,
        };
    }
    if !wal_ok {
        return failure_health(Failure::new(Code::WalNotReadable), Stage::Connect);
    }
    let due = st.with(|i| match i.last_full {
        Some((at, prev)) => prev != fp || at.elapsed() >= FULL_CHECK_EVERY,
        None => true,
    });
    let last_ok = st.with(|i| i.last.as_ref().is_some_and(|h| h.reachable));
    if due || !last_ok {
        if let Err(mut h) = full(settings, budget).await {
            tracing::warn!(target_id, failure = ?h.failure, "sqlite target check failed");
            h.notes.extend(
                notes
                    .into_iter()
                    .filter(|n| n.code() == NoteCode::SecurityFileWorldReadable),
            );
            return h;
        }
        st.with(|i| i.last_full = Some((Instant::now(), fp)));
    }
    TargetHealth {
        reachable: true,
        audit_level: AuditLevel::None,
        failure: None,
        detail: None,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code has a row of decision 7's table, and the notes are the
    /// registered SQLite ones.
    #[test]
    fn every_code_maps_to_the_table() {
        for c in Code::ALL {
            let (code, _, note) = outcome(*c);
            if matches!(
                c,
                Code::Writable | Code::NetworkFs | Code::NotReadOnlyFs | Code::PathRefused
            ) {
                assert_eq!(code, FailureCode::Unsupported, "{c:?}");
                assert!(note.is_some());
            }
        }
        assert_eq!(outcome(Code::NotFound).0, FailureCode::TargetUnreachable);
        assert_eq!(outcome(Code::NotReadable).0, FailureCode::PermissionDenied);
        assert_eq!(
            outcome(Code::HotJournal).2,
            Some(NoteCode::CoverageHotJournalPending)
        );
        assert_eq!(outcome(Code::Busy).0, FailureCode::Timeout);
        assert_eq!(outcome(Code::NoMemory).0, FailureCode::ResourceLimit);
        assert_eq!(outcome(Code::Auth).0, FailureCode::Internal);
        assert_eq!(
            outcome(Code::SandboxUnavailable).1,
            Some(Stage::SessionSetup)
        );
        assert_eq!(
            death_outcome(Death::Died).1,
            Some(NoteCode::CoverageReaderProcessFailed)
        );
        assert_eq!(death_outcome(Death::Deadline).0, FailureCode::Timeout);
    }

    #[test]
    fn failures_carry_their_stage() {
        let h = failure_health(Failure::new(Code::Corrupt), Stage::Sample);
        assert!(!h.reachable);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert!(
            h.notes
                .iter()
                .any(|n| n.code() == NoteCode::CheckStageFailed)
        );
    }
}
