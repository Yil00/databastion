//! Discovery scan: introspection, bounded sampling, classification.
//!
//! One connection per scan (replaced after a budget stop or when idle for
//! [`STALE_AFTER`](crate::conn::STALE_AFTER)); one read-only transaction for
//! the introspection; then per table one read-only transaction that reads
//! its columns and a bounded sample, committed before anything else. Only
//! then are the values classified (`ScanJob::classify`), names normalized,
//! and findings submitted: no transaction or unread result is open across
//! `FindingSink::submit().await`.
//!
//! Sampling (I4): at most `job.sample_rows()` rows per table (`LIMIT`),
//! text values cut to 4096 characters on the server (`LEFT`) and 4096 bytes
//! in Rust, at most [`MAX_SAMPLE_BYTES`] read per table (checked per row;
//! on overflow the statement is killed and the session dropped), every
//! statement under the session statement timeout plus a per-statement one.
//! Virtual generated columns are never selected (computed on read).

use databastion_classifiers::masking::{FindingLocation, RawSample, RawValue};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_core::cas_guard::{self, CasStores, StoreKind, TicketCounts};
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob};

use crate::audit::credits::SharedCredits;

/// Where Discovery grants its sampling credits, with the scan's statement
/// timeout (`None`: no Audit stream runs for the target).
type Credits<'a> = Option<(&'a SharedCredits, std::time::Duration)>;
use crate::catalog::{self, Coverage, EngineSkip, Table};
use crate::check::CheckState;
use crate::conn::{Flow, ReadTx, Session, Streamed, Timeouts};
use crate::error::{MyError, Stage};
use crate::sql::{self, Sampled};

/// Most bytes of sampled values read from one table.
pub(crate) const MAX_SAMPLE_BYTES: usize = 32 * 1024 * 1024;
/// Longest value handed to the classifiers, in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 4096;
/// Bytes charged to the budget for every sampled value on top of its
/// length (NULL and empty values included).
pub(crate) const VALUE_OVERHEAD: usize = 16;
/// Most columns per sampling statement: a text value is at most 4096
/// characters (16 KiB in utf8mb4, plus its length prefix), so a row of a
/// batch stays under 17 MiB, below `proto::MAX_LOGICAL`.
pub(crate) const MAX_BATCH_COLUMNS: usize = 1024;

/// Normalizes a catalog name (ADR-0009). A MySQL identifier is one key: a
/// name containing a dot becomes `*`.
pub(crate) fn normalize(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

/// How a column type is sampled: character types and JSON as text, the
/// integer / decimal types that can hold phone or card numbers, and dates
/// (birth dates). Other types (binary, blobs, enums, sets, spatial, bit,
/// small integers, floats, times, MariaDB `inet6` / `uuid`…) are not
/// selected at all.
pub(crate) fn sampled_kind(data_type: &str) -> Option<Sampled> {
    match data_type.to_ascii_lowercase().as_str() {
        "char" | "varchar" | "tinytext" | "text" | "mediumtext" | "longtext" | "json" => {
            Some(Sampled::Text)
        }
        "int" | "bigint" | "decimal" | "date" => Some(Sampled::Plain),
        _ => None,
    }
}

/// Cuts a sampled value to [`MAX_VALUE_BYTES`] at a character boundary.
/// `None` for a value that is not UTF-8 (skipped, never logged).
pub(crate) fn decode_value(raw: &[u8]) -> Option<String> {
    let s = match std::str::from_utf8(raw) {
        Ok(s) => s,
        // A multi-byte character cut by the server-side bound cannot
        // happen (`LEFT` counts characters); anything else is skipped.
        Err(_) => return None,
    };
    let mut end = s.len().min(MAX_VALUE_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_owned())
}

/// Runs a Discovery scan of the job's target.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(MyError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    let shared_credits = state.sample_credits(&target.id);
    // Credits only while the target's Audit stream runs (security review
    // of 09e93da, L1), checked per table.
    let credits_now = || {
        state
            .stream_running(&target.id)
            .then_some((&shared_credits, job.statement_timeout()))
    };
    let timeouts = Timeouts::new(job.statement_timeout());
    if job.out_of_time() {
        job.skip_out_of_time(sink, 1);
        return Ok(());
    }
    let mut first = Session::connect(target, timeouts)
        .await
        .map_err(|e| fail(target, e))?;
    // Paced (ADR-0035 proposed): the introspection, then each table.
    let tables = match job
        .paced(async {
            let mut tx = first.begin().await.map_err(|e| fail(target, e))?;
            match catalog::introspect(&mut tx).await {
                Ok(t) => {
                    tx.commit().await.map_err(|e| fail(target, e))?;
                    Ok(t)
                }
                Err(e) => {
                    tx.rollback().await;
                    Err(fail(target, e))
                }
            }
        })
        .await?
    {
        Paced::Done(t) => t?,
        Paced::OutOfTime => {
            job.skip_out_of_time(sink, 1);
            return Ok(());
        }
    };
    let (mut units, coverage) = catalog::plan(&tables, |schema, name| {
        // MySQL has no schema level: the job's `schemas` filter
        // (PostgreSQL) does not apply.
        job.includes_database(schema) && job.includes_object(name)
    });
    // Another starting table at each scan (security review of #93, M3).
    job.rotate(&mut units);
    log_coverage(target, &coverage);
    sink.add_coverage(planned_coverage(&coverage));
    let mut session = Some(first);
    let mut skipped = 0usize;
    let mut not_readable = 0usize;
    for (i, unit) in units.iter().enumerate() {
        // An idle session is closed before a long pause rather than kept
        // open through it (L6 of the #93 security review; it would be
        // stale after it anyway).
        if job.pacer().debt() >= crate::conn::STALE_AFTER
            && let Some(s) = session.take()
        {
            s.close().await;
        }
        // The pause the previous tables owe, before the session is
        // checked for staleness and reused or reopened.
        if job.turn().await? == Paced::OutOfTime {
            job.skip_out_of_time(sink, units.len() - i);
            break;
        }
        let mut current = match session.take() {
            Some(s) if !s.is_poisoned() && !s.is_stale() => s,
            stale => {
                if let Some(s) = stale {
                    s.close().await;
                }
                Session::connect(target, timeouts)
                    .await
                    .map_err(|e| fail(target, e))?
            }
        };
        job.begin_database(&unit.schema);
        let db = normalize(&unit.schema);
        let object = normalize(&unit.name);
        let sampled = match job
            .paced(sample_table(
                &mut current,
                unit,
                job.sample_rows(),
                job.cas_stores(),
                credits_now(),
            ))
            .await?
        {
            Paced::Done(s) => s,
            Paced::OutOfTime => {
                current.close().await;
                job.skip_out_of_time(sink, units.len() - i);
                break;
            }
        };
        // A poisoned session (budget stop: kill in flight, unread result)
        // is closed here, before any submit; the next table reconnects.
        if current.is_poisoned() {
            drop(current);
        } else {
            session = Some(current);
        }
        let mut sample = match sampled {
            Ok(s) => s,
            Err(e) if !e.fatal && e.code == FailureCode::ResourceLimit => {
                skipped += 1;
                sink.add_coverage(ScanCoverage {
                    limit: 1,
                    ..ScanCoverage::default()
                });
                tracing::warn!(
                    target_id = %target.id,
                    database = db.as_str(),
                    object = object.as_str(),
                    reason = "a row larger than the connector accepts",
                    "object not covered"
                );
                continue;
            }
            Err(e) if !e.fatal => {
                skipped += 1;
                sink.add_coverage(ScanCoverage {
                    error: 1,
                    ..ScanCoverage::default()
                });
                tracing::warn!(
                    target_id = %target.id,
                    database = db.as_str(),
                    object = object.as_str(),
                    stage = e.stage.as_str(),
                    errno = e.errno,
                    sqlstate = e.sqlstate(),
                    "object skipped"
                );
                continue;
            }
            Err(e) => return Err(fail(target, e)),
        };
        if !sample.readable {
            not_readable += 1;
            sink.add_coverage(ScanCoverage {
                not_readable: 1,
                ..ScanCoverage::default()
            });
            tracing::warn!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                reason = "no SELECT privilege on any column",
                "object not covered"
            );
            continue;
        }
        // Batches left after a budget stop (its session was dropped): on a
        // new session, each within its share of the table's byte budget.
        while sample.batches.next < sample.batches.statements.len() && !sample.batches.exhausted() {
            if job.turn().await? == Paced::OutOfTime {
                break;
            }
            let mut s = Session::connect(target, timeouts)
                .await
                .map_err(|e| fail(target, e))?;
            let resumed = match job
                .paced(resume_table(
                    &mut s,
                    &mut sample,
                    job.sample_rows(),
                    credits_now(),
                ))
                .await?
            {
                Paced::Done(r) => r,
                Paced::OutOfTime => {
                    s.close().await;
                    break;
                }
            };
            if s.is_poisoned() {
                drop(s);
            } else {
                session = Some(s);
            }
            match resumed {
                Ok(()) => {}
                Err(e) if !e.fatal => {
                    tracing::warn!(
                        target_id = %target.id,
                        database = db.as_str(),
                        object = object.as_str(),
                        stage = e.stage.as_str(),
                        errno = e.errno,
                        "sample batch skipped"
                    );
                    break;
                }
                Err(e) => return Err(fail(target, e)),
            }
        }
        sample.finish();
        if sample.batches.short() {
            // Some columns got fewer rows than others, or none (security
            // review of 914c9d2, N2): a gap of the connector's bounds.
            sink.add_coverage(ScanCoverage {
                limit: 1,
                ..ScanCoverage::default()
            });
            tracing::warn!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                batches = sample.batches.statements.len(),
                not_run = sample.batches.statements.len() - sample.batches.next,
                reason = "sample byte budget reached in a column batch",
                "object partly covered: some columns sampled short"
            );
        }
        if sample.virtual_columns > 0 {
            tracing::info!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                count = sample.virtual_columns,
                "virtual generated columns not sampled (computed on read)"
            );
        }
        if sample.kind == Some(StoreKind::TicketRegistry) {
            // CAS store guard (ADR-0041 decision 5): metadata only, never
            // sampled: a kind of object the connector does not sample.
            sink.add_coverage(ScanCoverage {
                unsupported: 1,
                ..ScanCoverage::default()
            });
            match &sample.tickets {
                Some(counts) => job.record_ticket_registry(counts),
                None => tracing::info!(
                    target_id = %target.id,
                    database = db.as_str(),
                    object = object.as_str(),
                    "CAS ticket registry without a readable type column: encryption not \
                     evaluated"
                ),
            }
            tracing::info!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                "CAS ticket registry: not sampled (CAS store guard, metadata only)"
            );
            continue;
        }
        if let Some(kind) = sample.kind {
            tracing::info!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                store = kind.as_str(),
                "CAS store guard applied"
            );
        }
        sink.add_coverage(ScanCoverage {
            sampled: 1,
            ..ScanCoverage::default()
        });
        // No transaction is open from here on.
        for (column, values) in &sample.columns {
            let samples: Vec<RawSample<'_>> = values.iter().map(RawValue::as_sample).collect();
            let rule = cas_guard::column_rule(sample.kind, column);
            for finding in job.classify_guarded(column, &samples, rule) {
                let mut finding = finding.into_finding(FindingLocation {
                    database: db.clone(),
                    schema: None,
                    object: object.clone(),
                    field: normalize(column),
                });
                if let Some(rows) = sample.estimated_rows {
                    finding = finding.with_estimated_rows(rows);
                }
                sink.submit(finding).await?;
            }
        }
    }
    if let Some(s) = session {
        s.close().await;
    }
    tracing::info!(
        target_id = %target.id,
        tables = units.len(),
        skipped,
        not_readable,
        not_covered = coverage.not_covered(),
        "target scanned"
    );
    Ok(())
}

fn fail(target: &TargetConfig, e: MyError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        errno = e.errno,
        sqlstate = e.sqlstate(),
        code = %e.code,
        "scan failed"
    );
    e.into_connector_error()
}

/// The objects of the job's scope skipped by the plan, as coverage
/// counters (`JobProgress` `skipped_*`): tables on a remote-access engine
/// are remote (never read, I5); views, sequences, other object kinds and
/// tables on an engine outside the allow-list (merge tables included:
/// their tables are sampled directly) are kinds the connector does not
/// sample. An introspection cut at its table limit counts 1 under the
/// connector bound (`limit`): how many tables it left out is unknown.
/// Counts only, never a name.
pub(crate) fn planned_coverage(c: &Coverage) -> ScanCoverage {
    let remote = c
        .engines
        .iter()
        .filter(|(_, _, k)| *k == EngineSkip::Remote)
        .count();
    let unsupported = c.views.len() + (c.engines.len() - remote) + c.sequences + c.other;
    ScanCoverage {
        remote: remote as u64,
        unsupported: unsupported as u64,
        limit: u64::from(c.truncated),
        ..ScanCoverage::default()
    }
}

pub(crate) fn log_coverage(target: &TargetConfig, c: &Coverage) {
    for (schema, name) in &c.views {
        tracing::info!(
            target_id = %target.id,
            database = normalize(schema).as_str(),
            object = normalize(name).as_str(),
            reason = "view (runs its definition with the definer's rights)",
            "object not sampled"
        );
    }
    for (schema, name, skip) in &c.engines {
        tracing::warn!(
            target_id = %target.id,
            database = normalize(schema).as_str(),
            object = normalize(name).as_str(),
            reason = skip.as_str(),
            "object not covered"
        );
    }
    if c.sequences > 0 || c.other > 0 {
        tracing::info!(
            target_id = %target.id,
            sequences = c.sequences,
            other = c.other,
            "objects not sampled"
        );
    }
}

/// Sampled values of one table, per column (raw column names; values
/// zeroized on drop). `Debug` shows counts only.
pub(crate) struct TableSample {
    pub(crate) columns: Vec<(String, Vec<RawValue>)>,
    /// The sampling statements of the table and how far they ran.
    pub(crate) batches: Batches,
    /// Sampled column names and their values, filled batch by batch
    /// ([`TableSample::finish`] moves them to `columns`).
    names: Vec<String>,
    values: Vec<Vec<RawValue>>,
    schema: String,
    table: String,
    /// At least one column is readable (`SELECT` privilege).
    pub(crate) readable: bool,
    pub(crate) virtual_columns: usize,
    pub(crate) rows: u32,
    /// `TABLE_ROWS` (an estimate for InnoDB).
    pub(crate) estimated_rows: Option<u64>,
    /// The CAS store the table is (CAS store guard), if any.
    pub(crate) kind: Option<StoreKind>,
    /// A ticket registry's metadata (`None`: not a ticket registry, or its
    /// `type` column is not readable).
    pub(crate) tickets: Option<TicketCounts>,
}

impl TableSample {
    /// Moves the sampled values to `columns`, once every batch ran.
    pub(crate) fn finish(&mut self) {
        let names = std::mem::take(&mut self.names);
        let values = std::mem::take(&mut self.values);
        self.columns = names.into_iter().zip(values).collect();
    }
}

impl std::fmt::Debug for TableSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableSample")
            .field("columns", &self.columns.len())
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

/// The column batches of a table (`sql::sample_statements`) and their
/// progress. Each batch gets a share of what is left of
/// [`MAX_SAMPLE_BYTES`] in proportion to its columns, so that a batch of
/// large values cannot take the whole budget (security review of
/// 914c9d2, N2). A batch stopped on its share kills its statement: the
/// next batches run on a new session.
#[derive(Default)]
pub(crate) struct Batches {
    /// Per batch: its columns (range in `TableSample::columns`) and text.
    pub(crate) statements: Vec<(std::ops::Range<usize>, String)>,
    /// The next batch to run.
    pub(crate) next: usize,
    /// Rows read per batch run.
    pub(crate) rows: Vec<u32>,
    /// Bytes charged so far (all batches).
    pub(crate) bytes: usize,
}

impl Batches {
    /// Byte share of batch `i`: what is left of the budget, in proportion
    /// to its columns among the batches not run yet.
    fn share(&self, i: usize) -> usize {
        let left = MAX_SAMPLE_BYTES.saturating_sub(self.bytes);
        let cols = |r: &std::ops::Range<usize>| r.len().max(1);
        let rest: usize = self.statements[i..].iter().map(|(r, _)| cols(r)).sum();
        let mine = cols(&self.statements[i].0);
        // `left * mine / rest` without overflow (`left` is at most 32 MiB).
        left / rest.max(1) * mine + left % rest.max(1) * mine / rest.max(1)
    }

    /// What is left of the table's byte budget.
    pub(crate) fn left(&self) -> usize {
        MAX_SAMPLE_BYTES.saturating_sub(self.bytes)
    }

    /// Nothing left of the table's byte budget (the remaining batches are
    /// not run).
    pub(crate) fn exhausted(&self) -> bool {
        self.left() == 0
    }

    /// Some columns got fewer rows than others, or were not sampled.
    pub(crate) fn short(&self) -> bool {
        self.next < self.statements.len()
            || self.rows.iter().any(|r| Some(r) != self.rows.iter().max())
    }
}

/// Accepts the rows of one sampling statement: at most `limit` rows (a
/// server that ignores the `LIMIT` is stopped), and at most `cap` bytes
/// (the batch's share of [`MAX_SAMPLE_BYTES`]), counting every value's
/// length plus [`VALUE_OVERHEAD`] (so rows of NULL or empty values are
/// bounded too).
pub(crate) struct RowSampler<'v> {
    limit: u32,
    pub(crate) rows: u32,
    /// Bytes charged by this statement.
    pub(crate) bytes: usize,
    cap: usize,
    /// Bound of the first row ([`RowSampler::first_row_within`]).
    first_cap: usize,
    pub(crate) stop: Option<&'static str>,
    values: &'v mut [Vec<RawValue>],
}

impl<'v> RowSampler<'v> {
    pub(crate) fn new(limit: u32, cap: usize, values: &'v mut [Vec<RawValue>]) -> Self {
        Self {
            limit,
            rows: 0,
            bytes: 0,
            cap,
            first_cap: cap,
            stop: None,
            values,
        }
    }

    /// Accepts a first row of up to `left` bytes (what is left of the
    /// table's budget) even past the share: a batch whose single row is
    /// larger than its share still samples one row.
    #[must_use]
    pub(crate) fn first_row_within(mut self, left: usize) -> Self {
        self.first_cap = left.max(self.cap);
        self
    }

    pub(crate) fn accept(&mut self, row: &[Option<&[u8]>]) -> Flow {
        if self.rows >= self.limit {
            self.stop = Some("the server sent more rows than the LIMIT");
            return Flow::Stop;
        }
        let row_bytes: usize = row
            .iter()
            .map(|v| v.map_or(0, <[u8]>::len).saturating_add(VALUE_OVERHEAD))
            .fold(0, usize::saturating_add);
        // Budget checked per row, before decoding it. The row itself was
        // already received whole: one row is the residual peak.
        let cap = if self.rows == 0 {
            self.first_cap
        } else {
            self.cap
        };
        if self.bytes.saturating_add(row_bytes) > cap {
            self.stop = Some("sample byte budget reached");
            return Flow::Stop;
        }
        self.bytes = self.bytes.saturating_add(row_bytes);
        self.rows = self.rows.saturating_add(1);
        for (raw, out) in row.iter().zip(self.values.iter_mut()) {
            if let Some(v) = raw.and_then(decode_value) {
                out.push(RawValue::new(v));
            }
        }
        Flow::Continue
    }
}

/// Reads the columns and a sample of one table in one read-only
/// transaction, committed (or, after a budget stop, abandoned with the
/// session) before returning.
pub(crate) async fn sample_table(
    session: &mut Session,
    table: &Table,
    limit: u32,
    stores: Option<&CasStores>,
    credits: Credits<'_>,
) -> Result<TableSample, MyError> {
    let mut tx = session.begin().await?;
    match read_table(&mut tx, table, limit, stores, credits).await {
        Ok(sample) => {
            tx.commit().await?;
            Ok(sample)
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

/// Runs the batches of `sample` left after a budget stop, in one
/// read-only transaction on `session` (a new one: the stopped statement's
/// session was dropped), until done or the next stop.
pub(crate) async fn resume_table(
    session: &mut Session,
    sample: &mut TableSample,
    limit: u32,
    credits: Credits<'_>,
) -> Result<(), MyError> {
    let mut tx = session.begin().await?;
    match run_batches(&mut tx, sample, limit, credits).await {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

/// Runs the batches of `sample` from `sample.batches.next`, each within
/// its byte share, until done or a stop (the statement killed: the
/// session is then poisoned). Before each batch but the table's first,
/// a credit with its exact text is granted to the Audit stream
/// (`audit::credits`): one scan of a table is charged once to the
/// agent's own-account budget.
async fn run_batches(
    tx: &mut ReadTx<'_>,
    sample: &mut TableSample,
    limit: u32,
    credits: Credits<'_>,
) -> Result<(), MyError> {
    while sample.batches.next < sample.batches.statements.len() {
        let i = sample.batches.next;
        if sample.batches.exhausted() {
            // Nothing left of the table's budget: the remaining batches
            // are not run (reported as short).
            break;
        }
        let cap = sample.batches.share(i);
        let left = sample.batches.left();
        let (range, statement) = sample.batches.statements[i].clone();
        if i > 0
            && let Some((credits, timeout)) = credits
        {
            credits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .grant(
                    &statement,
                    &sample.schema,
                    &sample.table,
                    timeout,
                    std::time::Instant::now(),
                );
        }
        let mut sampler =
            RowSampler::new(limit, cap, &mut sample.values[range]).first_row_within(left);
        let streamed = tx
            .query_stream(Stage::Sample, &statement, |row| sampler.accept(row))
            .await?;
        let (rows, used, stop) = (sampler.rows, sampler.bytes, sampler.stop);
        sample.batches.bytes = sample.batches.bytes.saturating_add(used);
        sample.batches.rows.push(rows);
        sample.batches.next = i + 1;
        sample.rows = sample.rows.max(rows);
        if streamed == Streamed::Stopped {
            if rows == 0 {
                // A single row larger than what is left: no later batch
                // runs (each would cost a new session for nothing).
                sample.batches.bytes = MAX_SAMPLE_BYTES;
            }
            tracing::info!(
                rows,
                batch = i,
                reason = stop.unwrap_or("stopped"),
                "sample stopped: statement killed"
            );
            break;
        }
    }
    Ok(())
}

async fn read_table(
    tx: &mut ReadTx<'_>,
    table: &Table,
    limit: u32,
    stores: Option<&CasStores>,
    credits: Credits<'_>,
) -> Result<TableSample, MyError> {
    let mut sample = TableSample {
        columns: Vec::new(),
        batches: Batches::default(),
        names: Vec::new(),
        values: Vec::new(),
        schema: table.schema.clone(),
        table: table.name.clone(),
        readable: false,
        virtual_columns: 0,
        rows: 0,
        estimated_rows: None,
        kind: None,
        tickets: None,
    };
    // The engine is checked again in this transaction (a table altered to
    // a remote engine since the introspection is not read). The engine is
    // read alone first: computing `TABLE_ROWS` opens the table's handler
    // (a FEDERATED handler connects out), so it is only asked for a table
    // whose engine is local.
    let statement = sql::table_engine(&table.schema, &table.name)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Columns))?;
    let engine = tx
        .query(Stage::Columns, &statement)
        .await?
        .into_iter()
        .next()
        .and_then(|row| {
            let kind = row.first().cloned().flatten().unwrap_or_default();
            let engine = row.get(1).cloned().flatten();
            matches!(kind.as_str(), "BASE TABLE" | "SYSTEM VERSIONED").then_some(engine)
        });
    if engine.is_none_or(|e| catalog::engine_skip(e.as_deref()).is_some()) {
        tracing::warn!("table gone or no longer on a local engine: not sampled");
        return Err(MyError {
            fatal: false,
            ..MyError::new(FailureCode::Internal, Stage::Columns)
        });
    }
    let statement = sql::table_rows(&table.schema, &table.name)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Columns))?;
    sample.estimated_rows = tx
        .query(Stage::Columns, &statement)
        .await?
        .into_iter()
        .next()
        .and_then(|row| row.first().cloned().flatten())
        .and_then(|r| r.parse().ok());
    let statement = sql::columns(&table.schema, &table.name)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Columns))?;
    let rows = tx.query(Stage::Columns, &statement).await?;
    // CAS store guard (ADR-0041 decision 5): by name, else by the shape of
    // the columns the account can see.
    sample.kind = cas_guard::recognize(
        stores,
        [table.name.as_str()],
        rows.iter()
            .filter_map(|r| r.first().and_then(|v| v.as_deref())),
    );
    if sample.kind == Some(StoreKind::TicketRegistry) {
        let type_column = rows
            .iter()
            .filter(|r| {
                r.get(3)
                    .and_then(|v| v.as_deref())
                    .is_some_and(|p| p.split(',').any(|p| p.trim() == "select"))
            })
            .filter_map(|r| r.first().and_then(|v| v.as_deref()))
            .find(|c| cas_guard::name_key(c) == "type")
            .map(str::to_owned);
        sample.readable = true;
        if let Some(column) = type_column {
            let statement = sql::ticket_type_counts(
                tx.flavor(),
                tx.timeouts().statement_ms(),
                &table.schema,
                &table.name,
                &column,
            )
            .ok_or(MyError::new(FailureCode::Internal, Stage::Sample))?;
            let mut counts = TicketCounts::default();
            for row in tx.query(Stage::Sample, &statement).await? {
                let kind = row.first().cloned().flatten().unwrap_or_default();
                let n = row
                    .get(1)
                    .cloned()
                    .flatten()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
                counts.add(&kind, n);
            }
            sample.tickets = Some(counts);
        }
        return Ok(sample);
    }
    let mut cols: Vec<(String, Sampled)> = Vec::new();
    let mut readable = false;
    let mut virtual_columns = 0usize;
    for row in rows {
        let text = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
        let (name, data_type, extra, privileges) = (text(0), text(1), text(2), text(3));
        if !privileges.split(',').any(|p| p.trim() == "select") {
            continue;
        }
        readable = true;
        // `VIRTUAL GENERATED` (MySQL, MariaDB) / `VIRTUAL` (older MariaDB):
        // computed on read; `STORED GENERATED` / `PERSISTENT` values are
        // stored and read as they are.
        if extra.to_ascii_uppercase().contains("VIRTUAL") {
            virtual_columns += 1;
            continue;
        }
        if name.is_empty()
            || cas_guard::column_rule(sample.kind, &name) == cas_guard::ColumnRule::NeverRead
        {
            continue;
        }
        if let Some(kind) = sampled_kind(&data_type) {
            cols.push((name, kind));
        }
    }
    sample.readable = readable;
    sample.virtual_columns = virtual_columns;
    if cols.is_empty() {
        return Ok(sample);
    }
    // Columns in batches, so that one row of a batch stays well under the
    // largest packet the connector accepts (a table with thousands of text
    // columns cannot make a single row oversized and abort the scan), and
    // each statement under the audit logs' default text limits
    // (`sql::MAX_OWN_STATEMENT`: a cut text is reported as a read of `*`).
    let selected: Vec<(&str, Sampled)> = cols.iter().map(|(n, k)| (n.as_str(), *k)).collect();
    sample.batches.statements = sql::sample_statements(
        tx.flavor(),
        tx.timeouts().statement_ms(),
        &table.schema,
        &table.name,
        &selected,
        limit,
        MAX_BATCH_COLUMNS,
    )
    .ok_or(MyError::new(FailureCode::Internal, Stage::Sample))?;
    sample.values = cols.iter().map(|_| Vec::new()).collect();
    sample.names = cols.into_iter().map(|(n, _)| n).collect();
    run_batches(tx, &mut sample, limit, credits).await?;
    Ok(sample)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Security review of 914c9d2, N2: each batch gets a share of what is
    /// left of the byte budget in proportion to its columns; columns
    /// sampled short or not at all are reported.
    #[test]
    fn batches_share_the_byte_budget_and_report_short_columns() {
        let mut b = Batches {
            statements: vec![
                (0..30, String::new()),
                (30..60, String::new()),
                (60..65, String::new()),
            ],
            ..Batches::default()
        };
        assert_eq!(
            b.share(0),
            MAX_SAMPLE_BYTES / 65 * 30 + MAX_SAMPLE_BYTES % 65 * 30 / 65
        );
        // The first batch used less than its share: the rest is shared.
        b.bytes = 1024;
        b.rows.push(40);
        b.next = 1;
        let left = MAX_SAMPLE_BYTES - 1024;
        assert!(b.share(1).abs_diff(left * 30 / 35) <= 1);
        assert!(b.short(), "batches not run");
        b.rows.extend([40, 40]);
        b.next = 3;
        assert!(!b.short());
        b.rows[1] = 12;
        assert!(b.short(), "a batch stopped on its share");
        // Shares never exceed what is left.
        b.bytes = MAX_SAMPLE_BYTES;
        assert_eq!(b.share(2), 0);
        // A first row past the share but within what is left is read.
        let mut values = vec![Vec::new()];
        let mut sampler = RowSampler::new(10, 20, &mut values).first_row_within(100);
        assert_eq!(sampler.accept(&[Some(&[b'x'; 60][..])]), Flow::Continue);
        assert_eq!(sampler.accept(&[Some(&b"x"[..])]), Flow::Stop);
        assert_eq!(sampler.rows, 1);
        let one = Batches {
            statements: vec![(0..1, String::new())],
            ..Batches::default()
        };
        assert_eq!(one.share(0), MAX_SAMPLE_BYTES);
    }

    #[test]
    fn planned_coverage_counts_each_skip_reason() {
        let pair = || ("secret_db".to_owned(), "t".to_owned());
        let engine = |k| ("secret_db".to_owned(), "t".to_owned(), k);
        let c = Coverage {
            views: vec![pair(); 2],
            engines: vec![
                engine(EngineSkip::Remote),
                engine(EngineSkip::Remote),
                engine(EngineSkip::Remote),
                engine(EngineSkip::Merge),
                engine(EngineSkip::Other),
            ],
            sequences: 4,
            other: 1,
            truncated: true,
        };
        assert_eq!(
            planned_coverage(&c),
            ScanCoverage {
                sampled: 0,
                not_readable: 0,
                row_level_security: 0,
                remote: 3,
                unsupported: 2 + 2 + 4 + 1,
                limit: 1,
                error: 0,
            }
        );
        assert_eq!(
            planned_coverage(&Coverage::default()),
            ScanCoverage::default()
        );
    }

    #[test]
    fn value_bearing_names_are_normalized() {
        assert_eq!(normalize("employees").as_str(), "employees");
        assert_eq!(
            normalize("escalations_jean.richard@example.com").as_str(),
            "*"
        );
        assert_eq!(normalize("export_client_0639988384").as_str(), "*");
        assert_eq!(normalize("a.b").as_str(), "*");
    }

    #[test]
    fn sampled_types() {
        for t in [
            "varchar", "CHAR", "longtext", "json", "int", "bigint", "decimal", "date",
        ] {
            assert!(sampled_kind(t).is_some(), "{t}");
        }
        for t in [
            "blob",
            "varbinary",
            "binary",
            "enum",
            "set",
            "geometry",
            "bit",
            "tinyint",
            "smallint",
            "float",
            "double",
            "datetime",
            "timestamp",
            "time",
            "inet6",
            "uuid",
        ] {
            assert!(sampled_kind(t).is_none(), "{t}");
        }
        assert_eq!(sampled_kind("text"), Some(Sampled::Text));
        assert_eq!(sampled_kind("date"), Some(Sampled::Plain));
    }

    #[test]
    fn a_batch_row_fits_in_a_packet() {
        let text_value = 4 * sql::MAX_VALUE_CHARS as usize + 9;
        assert!(MAX_BATCH_COLUMNS * text_value < crate::proto::MAX_LOGICAL / 2);
    }

    #[test]
    fn values_are_cut_at_4096_bytes_on_a_char_boundary() {
        assert_eq!(decode_value(b"abc").unwrap(), "abc");
        let long = "é".repeat(3000);
        let cut = decode_value(long.as_bytes()).unwrap();
        assert!(cut.len() <= MAX_VALUE_BYTES && cut.len() >= MAX_VALUE_BYTES - 1);
        assert!(cut.chars().all(|c| c == 'é'));
        assert!(decode_value(&[0xFF, 0xFE]).is_none());
    }
}
