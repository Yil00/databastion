//! Discovery (ADR-0059 decision 6), on the agent's side: every unit of
//! work is one paced IPC request to the reader process (the catalog read;
//! then, per table, `table_xinfo`, the rowid bounds and the sampling
//! statements). The reader returns raw names and values; they are
//! normalized here (ADR-0009, ADR-0056, ADR-0057) and classified and masked
//! by `ScanJob::classify_guarded` (I2).
//!
//! - One database, `main`; `Location` = `database: main`, no schema, the
//!   table, the column.
//! - Ordinary tables only (rowid, `WITHOUT ROWID`, `STRICT`, FTS shadow
//!   tables): views, virtual tables, internal `sqlite_%` tables and CAS
//!   stores are never read. `VIRTUAL` generated columns are not sampled.
//! - At most 10 000 objects per scan, 64 columns per statement,
//!   `job.sample_rows()` rows and 32 MiB of value bytes per table.
//! - Rowid tables from a start key drawn between `min` and `max` of the
//!   rowid, then wrapped around; `WITHOUT ROWID` tables by the plain
//!   `LIMIT` read, the scan order reversed by the seed's parity.
//! - A reader that dies costs one unit (`skipped_error`); after 3 deaths
//!   the scan stops for the target (`coverage.reader_process_failed`).
//! - The reader is closed before a pause of 30 s or more (before each
//!   unit, review L1), and when its CPU time reaches 45 s (review L6,
//!   below its 60 s `RLIMIT_CPU`), and started again with the full
//!   procedure at the next unit; a file whose `(st_dev, st_ino)` changed
//!   ends the scan (the rest `skipped_error`).
//! - Every statement's deadline is `sqlite.max_statement_ms`, and never more
//!   than the job's clamped statement timeout (review L2).
//! - A unit that gets `SQLITE_BUSY` is retried once at its next paced turn,
//!   then counted `skipped_error` (decision 3, review L7): the catalog,
//!   the statistics, `table_xinfo`, the rowid bounds and the sampling
//!   statements alike.

use std::collections::HashMap;
use std::time::Duration;

use databastion_classifiers::masking::{FindingLocation, RawSample, RawValue};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_core::cas_guard::{self, ColumnRule};
use databastion_core::config::TargetConfig;
use databastion_core::config::sqlite::SqliteSettings;
use databastion_core::{
    ConnectorError, Engine, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob,
};
use zeroize::Zeroizing;

use crate::check::{
    self, ScanNotes, Stage, TargetState, deadline_for, death_outcome, open_request_with, outcome,
    scan_statement_ms,
};
use crate::ipc::{
    CatalogRow, Code, ColumnRow, Failure, MAX_COLUMNS, MAX_ROWS, OpenInfo, Request, Response,
    RowidAlias, SampleRange, SampleRequest, Sampled,
};
use crate::process::{Death, ReaderProcess};
use crate::sql;

/// Most objects read per scan (decision 6).
pub const MAX_OBJECTS: usize = 10_000;
/// Most value bytes read per table (decision 6).
pub const MAX_TABLE_BYTES: usize = 32 * 1024 * 1024;
/// Reader deaths per scan before the scan stops for the target.
pub const MAX_DEATHS: u64 = 3;
/// A reader is closed before a pause at least this long.
pub const CLOSE_BEFORE_PAUSE: Duration = Duration::from_secs(30);
/// A reader is restarted between units once its CPU time reaches this
/// (review L6): below its `RLIMIT_CPU` ([`crate::sandbox::CPU_SECONDS`]),
/// so a reader that lives for a whole scan (a duty cycle near 100 %, where
/// the pacing debt never reaches [`CLOSE_BEFORE_PAUSE`]) never gets
/// `SIGXCPU` on a legitimate large file.
pub const RESTART_AFTER_CPU: Duration = Duration::from_secs(45);
/// SQLite's own name for the file's database (decision 6).
pub const DATABASE: &str = "main";

/// Normalizes a name as one key (decision 6, as on MySQL / MariaDB): a name
/// containing `.` or matched by a classifier becomes `*`.
#[must_use]
pub fn normalize(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

fn cov(f: impl FnOnce(&mut ScanCoverage)) -> ScanCoverage {
    let mut c = ScanCoverage::default();
    f(&mut c);
    c
}

/// Why a unit did not complete.
enum UnitError {
    /// The reader answered with a failure.
    Failed(Failure),
    /// The reader is gone.
    Dead(Death),
}

/// The scan's reader, started again when needed.
struct Scan<'a> {
    job: &'a ScanJob,
    sink: &'a FindingSink,
    target: &'a TargetConfig,
    settings: &'a SqliteSettings,
    reader: Option<ReaderProcess>,
    opened: Option<OpenInfo>,
    /// The agent's own view of the file, checked against every reader's
    /// open answer (review N2).
    view: Option<check::AgentView>,
    /// Every statement's deadline (review L2, [`scan_statement_ms`]).
    statement_ms: u32,
    deaths: u64,
    notes: ScanNotes,
}

/// Whether the reader is closed before the next unit (reviews L1 and L6):
/// the pause owed before it is 30 s or more, or the reader's CPU time
/// reached [`RESTART_AFTER_CPU`] or cannot be read (fail closed: a new
/// reader).
fn restart_due(debt: Duration, cpu: Option<Duration>) -> bool {
    debt >= CLOSE_BEFORE_PAUSE || cpu.is_none_or(|c| c >= RESTART_AFTER_CPU)
}

/// Whether a failed unit is retried once, at its next paced turn
/// (decision 3): `SQLITE_BUSY`.
fn retried(e: &UnitError) -> bool {
    matches!(e, UnitError::Failed(f) if f.code == Code::Busy)
}

/// One paced unit of work (the scan's reader, or a test's script).
trait Units {
    async fn unit(
        &mut self,
        req: Request,
    ) -> Result<Paced<Result<Response, UnitError>>, ConnectorError>;
}

/// Review L7: every unit goes through this. A unit that gets
/// `SQLITE_BUSY` is sent once more, at its next paced turn (the second
/// `unit` pays the pause first); its second answer is final, `SQLITE_BUSY`
/// again included (counted `skipped_error` by the caller).
async fn unit_retried<U: Units>(
    u: &mut U,
    req: Request,
) -> Result<Paced<Result<Response, UnitError>>, ConnectorError> {
    match u.unit(req.clone()).await? {
        Paced::Done(Err(e)) if retried(&e) => u.unit(req).await,
        other => Ok(other),
    }
}

/// A reader the idle check can stop and look up (the scan's reader
/// process, or a test's stand-in).
trait Pausable {
    /// `SIGSTOP`, and whether the kernel reports it stopped.
    async fn pause(&mut self) -> bool;
    /// Its process id.
    fn pid(&self) -> Option<u32>;
}

impl Pausable for ReaderProcess {
    async fn pause(&mut self) -> bool {
        ReaderProcess::pause(self).await
    }

    fn pid(&self) -> Option<u32> {
        ReaderProcess::pid(self)
    }
}

/// What the idle check decided for the reader after a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdleAction {
    /// No check: the reader is gone (or was never opened), or the unit did
    /// not run.
    NotChecked,
    /// Stopped, holding no more than an idle connection: kept, stopped
    /// until its next request.
    Keep,
    /// Holding more: killed (counted as a death).
    Kill,
    /// Not stopped, or its locks not readable: restarted (fail closed).
    Restart,
}

/// Whether the reader is checked after a unit's outcome (review M1): after
/// any answer, a failure answer included, since a reader that answered is
/// still alive and would otherwise run unchecked through the pause; not
/// after a death (it is gone) or a unit that did not run.
fn idle_check_due(paced: &Paced<Result<Response, UnitError>>) -> bool {
    matches!(paced, Paced::Done(Ok(_) | Err(UnitError::Failed(_))))
}

/// The idle check after a unit (reviews L3, N1, N2 and M1): when
/// [`idle_check_due`] and a reader is alive, it is stopped first, then its
/// locks are read (`locks`, `/proc/locks` in production) against the
/// agent's own view of the file.
async fn idle_check<R: Pausable>(
    paced: &Paced<Result<Response, UnitError>>,
    reader: Option<&mut R>,
    view: Option<check::AgentView>,
    locks: impl FnOnce(u32, check::AgentView) -> Option<bool>,
) -> IdleAction {
    if !idle_check_due(paced) {
        return IdleAction::NotChecked;
    }
    let (Some(reader), Some(view)) = (reader, view) else {
        return IdleAction::NotChecked;
    };
    let verdict = if reader.pause().await {
        reader.pid().and_then(|pid| locks(pid, view))
    } else {
        None
    };
    match verdict {
        Some(true) => IdleAction::Keep,
        Some(false) => IdleAction::Kill,
        None => IdleAction::Restart,
    }
}

/// What a whole-scan stop means for the objects left.
enum Stop {
    /// `skipped_error`.
    Error,
    /// `skipped_limit`.
    Limit,
    /// Out of time (`job.skip_out_of_time`).
    OutOfTime,
}

impl Scan<'_> {
    fn target_error(&self, f: Failure, stage: Stage) -> ConnectorError {
        let (code, fixed, _) = outcome(f.code);
        tracing::warn!(
            target_id = %self.target.id,
            code = f.code.as_str(),
            rule = f.rule.map(crate::ipc::Rule::as_str),
            engine_code = f.engine_code,
            stage = fixed.unwrap_or(stage).as_str(),
            "sqlite scan failed"
        );
        ConnectorError::Target {
            engine: Engine::Sqlite,
            code,
            engine_code: f.engine_code.map(|c| sql::decimal(i64::from(c))),
        }
    }

    fn died(&mut self, d: Death) {
        self.deaths += 1;
        self.notes.reader_failures += 1;
        databastion_core::connector::count_sqlite_reader_failure();
        self.reader = None;
        tracing::warn!(
            target_id = %self.target.id,
            cause = d.as_str(),
            deaths = self.deaths,
            "sqlite reader process lost: the unit is counted skipped_error"
        );
    }

    /// Starts a reader and runs the open procedure; the file must be the
    /// one the scan started on.
    async fn ensure(&mut self) -> Result<(), UnitError> {
        if self.reader.is_some() {
            return Ok(());
        }
        let mut r = ReaderProcess::spawn().map_err(UnitError::Dead)?;
        let deadline = deadline_for(self.statement_ms);
        match r
            .call(
                &Request::Open(open_request_with(self.settings, self.statement_ms)),
                deadline,
            )
            .await
        {
            Ok(Response::Opened(info)) => {
                if let Some(prev) = self.opened
                    && (prev.dev, prev.ino) != (info.dev, info.ino)
                {
                    r.kill().await;
                    return Err(UnitError::Failed(Failure::new(Code::FileChanged)));
                }
                // Review N2: the reader's answer must match what the agent
                // sees itself; the lock policy uses the agent's view.
                let path = self.settings.path().to_owned();
                let view = tokio::task::spawn_blocking(move || check::agent_view(&path)).await;
                let view = match view {
                    Ok(Ok(v)) => v,
                    Ok(Err(f)) => {
                        r.kill().await;
                        return Err(UnitError::Failed(f));
                    }
                    Err(_) => {
                        r.kill().await;
                        return Err(UnitError::Failed(Failure::new(Code::Internal)));
                    }
                };
                if (view.id.dev, view.id.ino, view.wal, view.shm_ino)
                    != (info.dev, info.ino, info.wal, info.shm_ino)
                {
                    r.kill().await;
                    return Err(UnitError::Failed(Failure::new(Code::FileChanged)));
                }
                self.view = Some(view);
                if self.opened.is_none() {
                    tracing::info!(
                        target_id = %self.target.id,
                        wal = info.wal,
                        writer_version = info.writer_version,
                        "sqlite file opened by its reader"
                    );
                }
                self.opened = Some(info);
                self.reader = Some(r);
                Ok(())
            }
            Ok(Response::Failed(f)) => {
                r.kill().await;
                Err(UnitError::Failed(f))
            }
            Ok(_) => {
                r.kill().await;
                Err(UnitError::Dead(Death::Protocol))
            }
            Err(d) => Err(UnitError::Dead(d)),
        }
    }

    /// Closes the reader before the next unit when [`restart_due`]: it is
    /// started again (and checked against the scan's `(st_dev, st_ino)`)
    /// by that unit.
    async fn before_unit(&mut self) {
        let Some(reader) = self.reader.as_ref() else {
            return;
        };
        let cpu = reader.cpu_time();
        if restart_due(self.job.pacer().debt(), cpu) {
            if cpu.is_none_or(|c| c >= RESTART_AFTER_CPU) {
                tracing::info!(
                    target_id = %self.target.id,
                    "sqlite reader restarted: CPU time limit near, or not readable"
                );
            }
            self.close().await;
        }
    }

    /// One request to the reader (started first if needed), paced. The
    /// reader is closed first when [`restart_due`].
    async fn unit(
        &mut self,
        req: Request,
    ) -> Result<Paced<Result<Response, UnitError>>, ConnectorError> {
        self.before_unit().await;
        let deadline = deadline_for(self.statement_ms);
        let paced = self
            .job
            .paced(async {
                self.ensure().await?;
                let Some(reader) = self.reader.as_mut() else {
                    return Err(UnitError::Dead(Death::Died));
                };
                match reader.call(&req, deadline).await {
                    Ok(Response::Failed(f)) => Err(UnitError::Failed(f)),
                    Ok(r) => Ok(r),
                    Err(d) => Err(UnitError::Dead(d)),
                }
            })
            .await?;
        // Review L3 and N1: an idle reader holds no more than an idle
        // connection. It is stopped first, and stays stopped until its next
        // request, so it cannot drop its locks for the check and take them
        // again during the pause; the policy is the agent's view (N2).
        // Review M1: after a failure answer too, whenever the reader is
        // still alive.
        let action = idle_check(&paced, self.reader.as_mut(), self.view, |pid, view| {
            crate::locks::idle_ok_now(pid, view.id, view.shm_ino, view.wal)
        })
        .await;
        match action {
            IdleAction::NotChecked | IdleAction::Keep => {}
            IdleAction::Kill => {
                tracing::warn!(
                    target_id = %self.target.id,
                    "sqlite reader held a lock while idle: killed"
                );
                if let Some(mut r) = self.reader.take() {
                    r.kill().await;
                }
                self.died(Death::Protocol);
                return Ok(Paced::Done(Err(UnitError::Dead(Death::Protocol))));
            }
            // Not stopped, or not readable: fail closed, the reader is
            // restarted.
            IdleAction::Restart => self.close().await,
        }
        match &paced {
            Paced::Done(Err(UnitError::Dead(d))) => self.died(*d),
            // A side file the grant does not cover: a new reader, a new
            // grant (review L4).
            Paced::Done(Err(UnitError::Failed(f))) if f.code == Code::SideFileAppeared => {
                self.close().await;
            }
            _ => {}
        }
        Ok(paced)
    }

    async fn close(&mut self) {
        if let Some(r) = self.reader.take() {
            r.close().await;
        }
    }
}

impl Units for Scan<'_> {
    async fn unit(
        &mut self,
        req: Request,
    ) -> Result<Paced<Result<Response, UnitError>>, ConnectorError> {
        Scan::unit(self, req).await
    }
}

/// Runs a Discovery scan of one `sqlite` target.
pub async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    target: &TargetConfig,
    settings: &SqliteSettings,
    st: &TargetState,
) -> Result<(), ConnectorError> {
    let _lock = st.lock.lock().await;
    let mut scan = Scan {
        job,
        sink,
        target,
        settings,
        reader: None,
        opened: None,
        view: None,
        statement_ms: scan_statement_ms(settings, job.statement_timeout_ms()),
        deaths: 0,
        notes: ScanNotes::default(),
    };
    let r = run(&mut scan).await;
    scan.close().await;
    st.record_scan(scan.notes);
    r
}

async fn run(scan: &mut Scan<'_>) -> Result<(), ConnectorError> {
    let (job, sink) = (scan.job, scan.sink);
    if job.out_of_time() {
        job.skip_out_of_time(sink, 1);
        return Ok(());
    }
    if let Err(f) = check::pre_check(scan.settings) {
        return Err(scan.target_error(f, Stage::Connect));
    }
    if !job.includes_database(DATABASE) {
        return Ok(());
    }
    // The open procedure and the catalog: the first statement reads the
    // schema.
    let rows = match unit_retried(scan, Request::Catalog).await? {
        Paced::OutOfTime => {
            job.skip_out_of_time(sink, 1);
            return Ok(());
        }
        Paced::Done(Ok(Response::Catalog(rows, cut))) => {
            if cut {
                sink.add_coverage(cov(|c| c.limit = 1));
            }
            rows
        }
        Paced::Done(Ok(_)) => {
            return Err(scan.target_error(Failure::new(Code::Protocol), Stage::Introspection));
        }
        Paced::Done(Err(UnitError::Failed(f))) if f.code == Code::RollbackNotRead => {
            // Reachable, not read (decision 3): the database counted once.
            sink.add_coverage(cov(|c| c.unsupported = 1));
            tracing::info!(
                target_id = %scan.target.id,
                "sqlite file in rollback-journal mode not read (sqlite.rollback_mode: skip)"
            );
            return Ok(());
        }
        Paced::Done(Err(UnitError::Failed(f))) if f.code == Code::Busy => {
            // `SQLITE_BUSY` twice (decision 3): the database counted
            // `skipped_error`, the scan goes on to its end.
            sink.add_coverage(cov(|c| c.error = 1));
            tracing::info!(
                target_id = %scan.target.id,
                "sqlite catalog busy twice: the file is counted skipped_error"
            );
            return Ok(());
        }
        Paced::Done(Err(UnitError::Failed(f))) => {
            return Err(scan.target_error(f, Stage::Introspection));
        }
        Paced::Done(Err(UnitError::Dead(d))) => {
            let (code, _) = death_outcome(d);
            return Err(ConnectorError::Target {
                engine: Engine::Sqlite,
                code,
                engine_code: None,
            });
        }
    };
    let (mut tables, views, virtuals, stat1) = partition(rows);
    scan.notes.views = views;
    scan.notes.virtual_tables = virtuals;
    sink.add_coverage(cov(|c| c.unsupported = virtuals));
    tables.retain(|t| match std::str::from_utf8(&t.name) {
        Ok(n) => job.includes_object(n),
        Err(_) => true,
    });
    if tables.len() > MAX_OBJECTS {
        let over = tables.len() - MAX_OBJECTS;
        tables.truncate(MAX_OBJECTS);
        sink.add_coverage(cov(|c| c.limit = over as u64));
    }
    job.rotate(&mut tables);
    // Counts only, never a name: the end of the scan's first unit (the
    // end-to-end run truncates a -shm after it, ADR-0059 decision 10).
    tracing::info!(
        target_id = %scan.target.id,
        tables = tables.len(),
        views,
        virtual_tables = virtuals,
        "sqlite catalog read"
    );
    let estimated = if stat1 {
        match unit_retried(scan, Request::Stats).await? {
            Paced::Done(Ok(Response::Stats(rows))) => rows
                .into_iter()
                .filter_map(|r| Some((std::str::from_utf8(&r.name).ok()?.to_owned(), r.rows)))
                .collect(),
            Paced::OutOfTime => {
                job.skip_out_of_time(sink, tables.len());
                return Ok(());
            }
            // No row estimates, noted rather than hidden: a `sqlite_stat1`
            // without the shape SQLite writes (`stats_unusable`, ADR-0059
            // refinement of 2026-11-07), a schema text that is not UTF-8,
            // or another failure. A code only, never a name.
            Paced::Done(Err(UnitError::Failed(f))) => {
                tracing::info!(
                    target_id = %scan.target.id,
                    code = f.code.as_str(),
                    "sqlite_stat1 not used: no row estimates"
                );
                HashMap::new()
            }
            _ => HashMap::new(),
        }
    } else {
        HashMap::new()
    };
    for (i, table) in tables.iter().enumerate() {
        // The turn below pays the pause: the reader is closed before it.
        scan.before_unit().await;
        if job.turn().await? == Paced::OutOfTime {
            job.skip_out_of_time(sink, tables.len() - i);
            return Ok(());
        }
        match sample_table(scan, table, &estimated).await? {
            None => {}
            Some(Stop::OutOfTime) => {
                job.skip_out_of_time(sink, tables.len() - i);
                return Ok(());
            }
            Some(stop) => {
                let left = (tables.len() - i - 1) as u64;
                sink.add_coverage(cov(|c| match stop {
                    Stop::Limit => c.limit = left,
                    _ => c.error = left,
                }));
                if scan.deaths >= MAX_DEATHS {
                    tracing::warn!(
                        target_id = %scan.target.id,
                        deaths = scan.deaths,
                        "sqlite scan stopped for this target: its reader died 3 times \
                         (coverage.reader_process_failed)"
                    );
                }
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Ordinary tables, the view count, the virtual table count, and whether
/// `sqlite_stat1` exists.
fn partition(rows: Vec<CatalogRow>) -> (Vec<CatalogRow>, u64, u64, bool) {
    let mut tables = Vec::new();
    let (mut views, mut virtuals, mut stat1) = (0, 0, false);
    for r in rows {
        let internal = r.name.len() >= 7
            && r.name
                .get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"sqlite_"));
        if r.view {
            views += 1;
        } else if internal {
            stat1 |= r.name.eq_ignore_ascii_case(b"sqlite_stat1");
        } else if r.rootpage <= 0 {
            virtuals += 1;
        } else {
            tables.push(r);
        }
    }
    (tables, views, virtuals, stat1)
}

/// The rowid alias: the first of `rowid`, `_rowid_`, `oid` that is not a
/// declared column name (SQLite compares names without ASCII case).
fn rowid_alias(columns: &[ColumnRow]) -> Option<RowidAlias> {
    [
        RowidAlias::Rowid,
        RowidAlias::UnderscoreRowid,
        RowidAlias::Oid,
    ]
    .into_iter()
    .find(|a| {
        !columns
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(a.as_str().as_bytes()))
    })
}

/// The start key of a rowid table: drawn from the scan's seed between `lo`
/// and `hi`.
fn start_key(job: &ScanJob, lo: i64, hi: i64) -> i64 {
    let span = i128::from(hi) - i128::from(lo) + 1;
    let len = usize::try_from(span.clamp(1, i128::from(u32::MAX))).unwrap_or(1);
    let off = job.rotation_offset(len).unwrap_or(0);
    lo.saturating_add(i64::try_from(off).unwrap_or(0))
}

/// Whether a sampling response fits its request (review L8): at most
/// `limit` rows, one value list per requested column, each with one value
/// per row; on a rowid range, the last rowid inside the range (a
/// continuation starts after it, so the rowids read strictly increase),
/// none on an empty response or the plain read; a cut response is not
/// empty.
fn response_fits(range: SampleRange, limit: u32, columns: usize, got: &Sampled) -> bool {
    let rows = got.rows;
    let shape = rows <= limit
        && got.values.len() == columns
        && got.values.iter().all(|c| c.len() == rows as usize)
        && (!got.truncated || rows > 0);
    let rowid = match (range, got.last_rowid) {
        (SampleRange::Plain { .. }, last) => last.is_none(),
        (_, None) => rows == 0,
        (_, Some(_)) if rows == 0 => false,
        (SampleRange::From(a), Some(l)) => l >= a,
        (SampleRange::Below(b), Some(l)) => l < b,
        (SampleRange::Between(a, b), Some(l)) => a <= l && l < b,
    };
    shape && rowid
}

/// A sampled TEXT (or INTEGER) value as text for the classifiers (review
/// L3). SQLite does not check that TEXT is UTF-8: a value written in
/// Latin-1 or another 8-bit encoding is classified with each invalid
/// sequence replaced by U+FFFD, as `String::from_utf8_lossy` does
/// (decision 6 samples every TEXT value; dropping it would hide its
/// ASCII-only content, an e-mail address or an IBAN, from Discovery).
/// The string is allocated once at its final size, so no partial copy is
/// left behind by a reallocation; the source is the caller's zeroizing
/// buffer and the result is a `RawValue`, zeroized on drop.
pub(crate) fn text_value(v: &[u8]) -> RawValue {
    RawValue::new(lossy_utf8(v))
}

/// [`text_value`]'s text: `v` itself when it is UTF-8, otherwise each
/// invalid sequence replaced by U+FFFD, in one allocation of the final
/// size.
fn lossy_utf8(v: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(v) {
        return s.to_owned();
    }
    let size: usize = v
        .utf8_chunks()
        .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { 3 })
        .sum();
    let mut s = String::with_capacity(size);
    for c in v.utf8_chunks() {
        s.push_str(c.valid());
        if !c.invalid().is_empty() {
            s.push(char::REPLACEMENT_CHARACTER);
        }
    }
    s
}

/// The per-table outcome counters.
fn count_failure(sink: &FindingSink, f: &Failure) {
    sink.add_coverage(cov(|c| match f.code {
        Code::Corrupt | Code::NotReadable => c.not_readable = 1,
        Code::ViewProhibited | Code::NameNotUtf8 | Code::SchemaFunctionRefused => {
            c.unsupported = 1;
        }
        Code::TooBig | Code::NoMemory | Code::WalTooLarge => c.limit = 1,
        _ => c.error = 1,
    }));
}

/// What a failed unit means for the rest of the scan.
fn stop_for(scan: &Scan<'_>, e: &UnitError) -> Option<Stop> {
    match e {
        UnitError::Dead(_) if scan.deaths >= MAX_DEATHS => Some(Stop::Error),
        UnitError::Dead(_) => None,
        UnitError::Failed(f) => match f.code {
            Code::WalTooLarge => Some(Stop::Limit),
            Code::FileChanged
            | Code::PathRefused
            | Code::Writable
            | Code::NotReadOnlyFs
            | Code::NetworkFs
            | Code::NotFound
            | Code::SandboxUnavailable
            | Code::SelfCheckFailed
            | Code::WalNotReadable
            | Code::HotJournal
            | Code::RollbackNotRead
            | Code::UnrecognizedFormat => Some(Stop::Error),
            _ => None,
        },
    }
}

/// Handles a failed unit of one table: counted, logged, and whether the
/// scan stops.
fn table_failed(scan: &Scan<'_>, e: &UnitError, table: &str) -> Option<Stop> {
    match e {
        UnitError::Failed(f) => {
            count_failure(scan.sink, f);
            tracing::info!(
                target_id = %scan.target.id,
                object = normalize(table).as_str(),
                code = f.code.as_str(),
                engine_code = f.engine_code,
                "sqlite object skipped"
            );
        }
        UnitError::Dead(_) => scan.sink.add_coverage(cov(|c| c.error = 1)),
    }
    stop_for(scan, e)
}

macro_rules! unit_or {
    ($scan:expr, $req:expr, $table:expr) => {
        match unit_retried($scan, $req).await? {
            Paced::OutOfTime => return Ok(Some(Stop::OutOfTime)),
            Paced::Done(Ok(r)) => Ok(r),
            Paced::Done(Err(e)) => Err(e),
        }
    };
}

/// Samples one table; `Some` when the scan stops.
async fn sample_table(
    scan: &mut Scan<'_>,
    table: &CatalogRow,
    estimated: &HashMap<String, u64>,
) -> Result<Option<Stop>, ConnectorError> {
    let (job, sink) = (scan.job, scan.sink);
    let Ok(name) = std::str::from_utf8(&table.name) else {
        sink.add_coverage(cov(|c| c.unsupported = 1));
        return Ok(None);
    };
    if sql::quote(&table.name).is_none() {
        sink.add_coverage(cov(|c| c.unsupported = 1));
        return Ok(None);
    }
    let columns = match unit_or!(scan, Request::Columns(table.name.clone()), name) {
        Ok(Response::Columns(c)) => c,
        Ok(_) => return Ok(table_failed(scan, &UnitError::Dead(Death::Protocol), name)),
        Err(e) => return Ok(table_failed(scan, &e, name)),
    };
    // CAS store guard (ADR-0041 decision 5): a recognized store is not read
    // at all on SQLite (the metadata aggregate of the other engines would
    // be a full table scan here).
    let names: Vec<String> = columns
        .iter()
        .filter_map(|c| std::str::from_utf8(&c.name).ok().map(str::to_owned))
        .collect();
    let kind = cas_guard::recognize(job.cas_stores(), [name], names.iter().map(String::as_str));
    if kind.is_some() {
        sink.add_coverage(cov(|c| c.unsupported = 1));
        tracing::info!(
            target_id = %scan.target.id,
            object = normalize(name).as_str(),
            "CAS store: not read (CAS store guard)"
        );
        return Ok(None);
    }
    let mut selected: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for c in &columns {
        // VIRTUAL generated columns, and (ADR-0059 refinement of
        // 2026-11-07) columns whose DEFAULT or STORED expression names a
        // function off the authorizer's list, or whose table's schema text
        // is not UTF-8: not sampled, counted in
        // `coverage.computed_columns_not_sampled`; the other columns are.
        if c.hidden == 2 || c.expr.excluded() {
            scan.notes.computed_columns += 1;
            continue;
        }
        if c.hidden == 1 || sql::quote(&c.name).is_none() {
            continue;
        }
        let Ok(raw) = std::str::from_utf8(&c.name) else {
            continue;
        };
        if cas_guard::column_rule(kind, raw) == ColumnRule::NeverRead {
            continue;
        }
        selected.push(c.name.clone());
    }
    if selected.is_empty() {
        sink.add_coverage(cov(|c| c.sampled = 1));
        return Ok(None);
    }
    let n = job.sample_rows().min(MAX_ROWS);
    // The rows to read: rowid ranges from a drawn start key, or the plain
    // read.
    let alias = rowid_alias(&columns);
    let mut plan: Option<(i64, i64)> = None;
    let mut plain = alias.is_none();
    if let Some(a) = alias {
        match unit_or!(scan, Request::Bounds(table.name.clone(), a), name) {
            Ok(Response::Bounds(None)) => {
                sink.add_coverage(cov(|c| c.sampled = 1));
                return Ok(None);
            }
            Ok(Response::Bounds(Some(b))) => plan = Some(b),
            Ok(_) => return Ok(table_failed(scan, &UnitError::Dead(Death::Protocol), name)),
            // A column name that is not UTF-8: the rowid is not read
            // (`Db::bounds`), the table is, by the plain read.
            Err(UnitError::Failed(f)) if matches!(f.code, Code::NoRowid | Code::NameNotUtf8) => {
                if f.code == Code::NameNotUtf8 {
                    tracing::info!(
                        target_id = %scan.target.id,
                        object = normalize(name).as_str(),
                        code = f.code.as_str(),
                        "sqlite table read without its rowid"
                    );
                }
                plain = true;
            }
            Err(e) => return Ok(table_failed(scan, &e, name)),
        }
    }
    let reverse = job.rotation_offset(2) == Some(1);
    let mut bytes = 0usize;
    let mut limited = false;
    let mut any = false;
    let object = normalize(name);
    let estimated_rows = estimated.get(name).copied();
    // The column groups to sample, in order: chunks of at most 64; a chunk
    // that fails with SQLITE_TOOBIG is retried column by column (decision
    // 6), and a single column that fails again counts the table in
    // `skipped_limit`.
    let mut work: Vec<Vec<Zeroizing<Vec<u8>>>> = selected
        .chunks(MAX_COLUMNS)
        .rev()
        .map(<[_]>::to_vec)
        .collect();
    'chunks: while let Some(chunk) = work.pop() {
        let mut values: Vec<Vec<RawValue>> = chunk.iter().map(|_| Vec::new()).collect();
        let mut rows = 0u32;
        // The ranges of this chunk, in order.
        let mut ranges: Vec<SampleRange> = if plain {
            vec![SampleRange::Plain { reverse }]
        } else if let Some((lo, hi)) = plan {
            let start = start_key(job, lo, hi);
            if start > lo {
                vec![SampleRange::From(start), SampleRange::Below(start)]
            } else {
                vec![SampleRange::From(lo)]
            }
        } else {
            Vec::new()
        };
        ranges.reverse();
        while let Some(range) = ranges.pop() {
            if rows >= n || bytes >= MAX_TABLE_BYTES {
                break;
            }
            let req = SampleRequest {
                table: table.name.clone(),
                alias: if plain { None } else { alias },
                columns: chunk.to_vec(),
                range,
                limit: n - rows,
            };
            let got: Sampled = match unit_or!(scan, Request::Sample(req), name) {
                Ok(Response::Sample(s)) => s,
                Ok(_) => return Ok(table_failed(scan, &UnitError::Dead(Death::Protocol), name)),
                Err(UnitError::Failed(f)) if f.code == Code::TooBig => {
                    if chunk.len() > 1 {
                        work.extend(chunk.iter().rev().map(|c| vec![c.clone()]));
                    } else {
                        limited = true;
                    }
                    continue 'chunks;
                }
                Err(e) => return Ok(table_failed(scan, &e, name)),
            };
            // Review L8: a response that does not fit its request is a
            // protocol violation: the reader is killed.
            if !response_fits(range, n - rows, chunk.len(), &got) {
                tracing::warn!(
                    target_id = %scan.target.id,
                    "sqlite reader answered outside its request: killed"
                );
                if let Some(mut r) = scan.reader.take() {
                    r.kill().await;
                }
                scan.died(Death::Protocol);
                return Ok(table_failed(scan, &UnitError::Dead(Death::Protocol), name));
            }
            any = true;
            rows += got.rows;
            for (col, vals) in values.iter_mut().zip(got.values) {
                for v in vals.into_iter().flatten() {
                    bytes += v.len();
                    if bytes > MAX_TABLE_BYTES {
                        limited = true;
                        break;
                    }
                    col.push(text_value(&v));
                }
            }
            // Continue a range the response bound cut.
            if got.truncated
                && let Some(last) = got.last_rowid
                && let Some(next) = last.checked_add(1)
            {
                match range {
                    SampleRange::From(_) => ranges.push(SampleRange::From(next)),
                    SampleRange::Below(b) | SampleRange::Between(_, b) if next < b => {
                        ranges.push(SampleRange::Between(next, b));
                    }
                    _ => {}
                }
            } else if got.truncated {
                limited = true;
            }
        }
        for (col, vals) in chunk.iter().zip(&values) {
            let Ok(raw) = std::str::from_utf8(col) else {
                continue;
            };
            let samples: Vec<RawSample<'_>> = vals.iter().map(RawValue::as_sample).collect();
            for finding in job.classify_guarded(raw, &samples, cas_guard::column_rule(kind, raw)) {
                let mut finding = finding.into_finding(FindingLocation {
                    database: normalize(DATABASE),
                    schema: None,
                    object: object.clone(),
                    field: normalize(raw),
                });
                if let Some(r) = estimated_rows {
                    finding = finding.with_estimated_rows(r);
                }
                sink.submit(finding).await?;
            }
        }
    }
    sink.add_coverage(cov(|c| {
        if any {
            c.sampled = 1;
            c.limit = u64::from(limited);
        } else {
            c.limit = 1;
        }
    }));
    let _ = FailureCode::Internal;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ColumnExpr;

    fn row(name: &str, view: bool, rootpage: i64) -> CatalogRow {
        CatalogRow {
            view,
            name: Zeroizing::new(name.as_bytes().to_vec()),
            rootpage,
        }
    }

    fn col(name: &str) -> ColumnRow {
        ColumnRow {
            name: Zeroizing::new(name.as_bytes().to_vec()),
            pk: 0,
            hidden: 0,
            expr: ColumnExpr::None,
        }
    }

    #[test]
    fn the_catalog_is_partitioned() {
        let (t, views, virtuals, stat1) = partition(vec![
            row("clients", false, 2),
            row("v", true, 0),
            row("fts", false, 0),
            row("sqlite_stat1", false, 5),
            row("SQLITE_sequence", false, 6),
            row("fts_content", false, 7),
        ]);
        let names: Vec<&[u8]> = t.iter().map(|r| r.name.as_slice()).collect();
        assert_eq!(names, [b"clients".as_slice(), b"fts_content".as_slice()]);
        assert_eq!((views, virtuals, stat1), (1, 1, true));
    }

    #[test]
    fn the_rowid_alias_avoids_declared_names() {
        assert_eq!(rowid_alias(&[col("a")]), Some(RowidAlias::Rowid));
        assert_eq!(
            rowid_alias(&[col("ROWID")]),
            Some(RowidAlias::UnderscoreRowid)
        );
        assert_eq!(
            rowid_alias(&[col("rowid"), col("_rowid_")]),
            Some(RowidAlias::Oid)
        );
        assert_eq!(
            rowid_alias(&[col("rowid"), col("_rowid_"), col("Oid")]),
            None
        );
    }

    #[test]
    fn start_keys_stay_in_bounds() {
        let job = ScanJob::default().with_rotation(123_456_789);
        for (lo, hi) in [(1, 1), (1, 100), (i64::MIN, i64::MAX), (-5, 5)] {
            let s = start_key(&job, lo, hi);
            assert!(s >= lo && s <= hi, "{lo} {hi} {s}");
        }
        assert_eq!(start_key(&ScanJob::default(), 7, 100), 7);
    }

    #[test]
    fn responses_must_fit_their_request() {
        let ok = |rows: u32, last: Option<i64>| Sampled {
            rows,
            last_rowid: last,
            truncated: false,
            values: vec![vec![None; rows as usize]],
        };
        assert!(response_fits(SampleRange::From(5), 10, 1, &ok(2, Some(9))));
        assert!(response_fits(SampleRange::From(5), 10, 1, &ok(0, None)));
        assert!(
            !response_fits(SampleRange::From(5), 1, 1, &ok(2, Some(9))),
            "over the limit"
        );
        assert!(
            !response_fits(SampleRange::From(5), 10, 2, &ok(2, Some(9))),
            "columns"
        );
        assert!(
            !response_fits(SampleRange::From(5), 10, 1, &ok(2, Some(4))),
            "below the range"
        );
        assert!(
            !response_fits(SampleRange::Below(5), 10, 1, &ok(2, Some(5))),
            "above the range"
        );
        assert!(response_fits(
            SampleRange::Between(1, 5),
            10,
            1,
            &ok(2, Some(4))
        ));
        assert!(!response_fits(
            SampleRange::Between(1, 5),
            10,
            1,
            &ok(2, Some(0))
        ));
        assert!(
            !response_fits(SampleRange::From(5), 10, 1, &ok(2, None)),
            "rows without rowid"
        );
        assert!(!response_fits(
            SampleRange::Plain { reverse: false },
            10,
            1,
            &ok(2, Some(1))
        ));
        let mut bad = ok(2, Some(9));
        bad.values[0].pop();
        assert!(!response_fits(SampleRange::From(5), 10, 1, &bad), "ragged");
    }

    /// Reviews L1 and L6: the reader is closed before a pause of 30 s or
    /// more, and once its CPU time reaches 45 s (or cannot be read), never
    /// otherwise.
    #[test]
    fn the_reader_restarts_before_long_pauses_and_near_its_cpu_limit() {
        let s = Duration::from_secs;
        assert!(!restart_due(Duration::ZERO, Some(Duration::ZERO)));
        assert!(!restart_due(s(29), Some(s(44))));
        assert!(!restart_due(
            Duration::from_millis(29_999),
            Some(Duration::from_millis(44_999))
        ));
        assert!(restart_due(s(30), Some(Duration::ZERO)), "a 30 s pause");
        assert!(restart_due(s(700), Some(s(1))), "a killed unit's pause");
        assert!(restart_due(Duration::ZERO, Some(s(45))), "near RLIMIT_CPU");
        assert!(restart_due(Duration::ZERO, Some(s(59))));
        assert!(restart_due(Duration::ZERO, None), "CPU time not readable");
        // A 0.5 s unit at a 1 % duty cycle owes about 50 s.
        assert!(restart_due(
            databastion_core::pacing::pause_after(Duration::from_millis(500), 1),
            Some(Duration::ZERO)
        ));
        let cpu_limit = Duration::from_secs(crate::sandbox::CPU_SECONDS);
        assert!(RESTART_AFTER_CPU < cpu_limit);
        // A unit runs at most its statement deadline plus 2 s before it is
        // killed: a reader under the restart point never reaches the limit.
        let longest =
            check::deadline_for(databastion_core::config::sqlite::MAX_STATEMENT_MS_RANGE.1);
        assert!(RESTART_AFTER_CPU + longest < cpu_limit);
    }

    /// A stand-in reader: this test process (so a lock the test holds is
    /// "the reader's"), recording whether it was stopped.
    struct FakeReader {
        stops: bool,
        paused: u32,
    }

    impl Pausable for FakeReader {
        async fn pause(&mut self) -> bool {
            self.paused += 1;
            self.stops
        }

        fn pid(&self) -> Option<u32> {
            Some(std::process::id())
        }
    }

    fn failed(code: Code) -> Paced<Result<Response, UnitError>> {
        Paced::Done(Err(UnitError::Failed(Failure::new(code))))
    }

    /// Review M1: after a failure answer, the reader that is still alive is
    /// stopped and its locks checked, exactly as after a success; it is
    /// killed when it holds a lock, kept when idle, restarted when it
    /// cannot be judged. A dead reader and a unit that did not run are not
    /// checked.
    #[tokio::test]
    async fn a_reader_that_answers_a_failure_is_stopped_and_checked() {
        let view = check::AgentView {
            id: crate::files::Identity { dev: 1, ino: 2 },
            wal: false,
            shm_ino: 0,
        };
        let non_terminal = [
            Code::Busy,
            Code::Corrupt,
            Code::TooBig,
            Code::NoMemory,
            Code::NoSuchTable,
            Code::ViewProhibited,
            Code::Interrupted,
            Code::Internal,
            Code::SideFileAppeared,
        ];
        for code in non_terminal {
            for (verdict, want) in [
                (Some(false), IdleAction::Kill),
                (Some(true), IdleAction::Keep),
                (None, IdleAction::Restart),
            ] {
                let mut r = FakeReader {
                    stops: true,
                    paused: 0,
                };
                let got = idle_check(&failed(code), Some(&mut r), Some(view), |pid, v| {
                    assert_eq!((pid, v), (std::process::id(), view));
                    verdict
                })
                .await;
                assert_eq!((got, r.paused), (want, 1), "{code:?}");
            }
            // Not stopped: restarted, its locks never read.
            let mut r = FakeReader {
                stops: false,
                paused: 0,
            };
            let got = idle_check(&failed(code), Some(&mut r), Some(view), |_, _| {
                unreachable!("locks read without the reader stopped")
            })
            .await;
            assert_eq!((got, r.paused), (IdleAction::Restart, 1));
        }
        // A success, as before.
        let mut r = FakeReader {
            stops: true,
            paused: 0,
        };
        let ok = Paced::Done(Ok(Response::Bounds(None)));
        assert_eq!(
            idle_check(&ok, Some(&mut r), Some(view), |_, _| Some(false)).await,
            IdleAction::Kill
        );
        // Not checked: a death, a unit that did not run, no reader.
        for paced in [
            Paced::Done(Err(UnitError::Dead(Death::Deadline))),
            Paced::OutOfTime,
        ] {
            let mut r = FakeReader {
                stops: true,
                paused: 0,
            };
            let got = idle_check(&paced, Some(&mut r), Some(view), |_, _| Some(false)).await;
            assert_eq!((got, r.paused), (IdleAction::NotChecked, 0));
        }
        assert_eq!(
            idle_check::<FakeReader>(&failed(Code::Corrupt), None, Some(view), |_, _| Some(false))
                .await,
            IdleAction::NotChecked
        );
    }

    /// Review M1 with a real lock: the stand-in reader (this process) holds
    /// SQLite's `SHARED` lock on a rollback-mode file, inside a read
    /// transaction, and "answers" `Failed(Corrupt)`; the check reads the
    /// real `/proc/locks` and the reader is killed.
    #[tokio::test]
    async fn a_failing_reader_holding_a_shared_lock_is_killed() {
        use std::os::unix::fs::MetadataExt;
        let d = crate::it::Dir::new("m1-lock");
        let p = d.path("held.db");
        let c = rusqlite::Connection::open(&p).unwrap_or_else(|_| unreachable!());
        c.execute_batch(
            "PRAGMA journal_mode = DELETE; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x');",
        )
        .unwrap_or_else(|_| unreachable!());
        let m = std::fs::metadata(&p).unwrap_or_else(|_| unreachable!());
        let view = check::AgentView {
            id: crate::files::Identity {
                dev: m.dev(),
                ino: m.ino(),
            },
            wal: false,
            shm_ino: 0,
        };
        // A read transaction: SQLite holds the SHARED lock until it ends.
        c.execute_batch("BEGIN; SELECT count(*) FROM t;")
            .unwrap_or_else(|_| unreachable!());
        let mut r = FakeReader {
            stops: true,
            paused: 0,
        };
        let got = idle_check(
            &failed(Code::Corrupt),
            Some(&mut r),
            Some(view),
            |pid, v| crate::locks::idle_ok_now(pid, v.id, v.shm_ino, v.wal),
        )
        .await;
        assert_eq!((got, r.paused), (IdleAction::Kill, 1));
        // The RESERVED byte of a write transaction (another rollback-mode
        // lock an idle reader never holds).
        c.execute_batch("COMMIT; BEGIN IMMEDIATE;")
            .unwrap_or_else(|_| unreachable!());
        let got = idle_check(&failed(Code::Busy), Some(&mut r), Some(view), |pid, v| {
            crate::locks::idle_ok_now(pid, v.id, v.shm_ino, v.wal)
        })
        .await;
        assert_eq!(got, IdleAction::Kill);
        c.execute_batch("ROLLBACK;")
            .unwrap_or_else(|_| unreachable!());
    }

    /// A scripted reader: the answers of successive units, and the requests
    /// it got.
    struct Script {
        answers: std::collections::VecDeque<Result<Response, UnitError>>,
        got: Vec<Request>,
    }

    impl Units for Script {
        async fn unit(
            &mut self,
            req: Request,
        ) -> Result<Paced<Result<Response, UnitError>>, ConnectorError> {
            self.got.push(req);
            Ok(Paced::Done(self.answers.pop_front().unwrap_or_else(|| {
                unreachable!("more units than scripted")
            })))
        }
    }

    fn busy() -> Result<Response, UnitError> {
        Err(UnitError::Failed(Failure::new(Code::Busy)))
    }

    async fn run_script(
        req: Request,
        answers: Vec<Result<Response, UnitError>>,
    ) -> (Result<Response, UnitError>, Vec<Request>) {
        let mut s = Script {
            answers: answers.into(),
            got: Vec::new(),
        };
        let out = match unit_retried(&mut s, req).await {
            Ok(Paced::Done(r)) => r,
            _ => unreachable!("scripted units are done"),
        };
        assert!(s.answers.is_empty(), "every scripted answer used");
        (out, s.got)
    }

    /// Review L7: every kind of unit that gets `SQLITE_BUSY` is sent once
    /// more (the same request), and its second answer is final; other
    /// failures and deaths are not retried.
    #[tokio::test]
    async fn busy_units_are_retried_once() {
        let t = || Zeroizing::new(b"clients".to_vec());
        let requests = [
            Request::Catalog,
            Request::Stats,
            Request::Columns(t()),
            Request::Bounds(t(), RowidAlias::Rowid),
            Request::Sample(SampleRequest {
                table: t(),
                alias: Some(RowidAlias::Rowid),
                columns: vec![Zeroizing::new(b"email".to_vec())],
                range: SampleRange::From(1),
                limit: 10,
            }),
        ];
        for req in requests {
            // Busy, then an answer: the answer.
            let (out, got) =
                run_script(req.clone(), vec![busy(), Ok(Response::Bounds(None))]).await;
            assert!(matches!(out, Ok(Response::Bounds(None))));
            assert!(got.len() == 2 && got.iter().all(|g| *g == req));
            // Busy twice: the second Busy is final (skipped_error).
            let (out, got) = run_script(req.clone(), vec![busy(), busy()]).await;
            assert!(matches!(out, Err(UnitError::Failed(f)) if f.code == Code::Busy));
            assert_eq!(got.len(), 2);
            // Any other failure, or a death: not retried.
            let (out, got) = run_script(
                req.clone(),
                vec![Err(UnitError::Failed(Failure::new(Code::Corrupt)))],
            )
            .await;
            assert!(matches!(out, Err(UnitError::Failed(f)) if f.code == Code::Corrupt));
            assert_eq!(got.len(), 1);
            let (out, got) =
                run_script(req.clone(), vec![Err(UnitError::Dead(Death::Deadline))]).await;
            assert!(matches!(out, Err(UnitError::Dead(Death::Deadline))));
            assert_eq!(got.len(), 1);
        }
        // A Busy failure is counted `skipped_error` once it is final.
        let (sink, _rx) = FindingSink::channel(4);
        count_failure(&sink, &Failure::new(Code::Busy));
        assert_eq!(sink.coverage_for_tests().unwrap_or_default().error, 1);
    }

    /// Review L3: invalid UTF-8 is replaced, one U+FFFD per invalid
    /// sequence, as `String::from_utf8_lossy`; valid text is unchanged.
    #[test]
    fn text_values_are_decoded_lossily() {
        for v in [
            b"jos\xe9@example.fr".as_slice(),
            b"M\xfcller",
            b"\xff\xfe",
            b"\xe2\x82",
            b"plain@example.com",
            "\u{e9}lodie".as_bytes(),
            b"",
        ] {
            let want = String::from_utf8_lossy(v);
            let got = lossy_utf8(v);
            assert_eq!(got, want.as_ref(), "{v:?}");
            // One allocation of the final size: no reallocation left a
            // partial copy behind.
            assert_eq!(got.capacity(), got.len(), "{v:?}");
        }
    }

    #[test]
    fn locations_are_main_without_schema() {
        assert_eq!(normalize(DATABASE).as_str(), "main");
        assert!(!normalize(DATABASE).altered());
        assert_eq!(normalize("export.v1").as_str(), "*");
    }
}
