//! Discovery scan: introspection, bounded sampling, classification.
//!
//! Per database of the target (in the job's `databases` filter): one
//! connection; one read-only transaction for the introspection; then per
//! object ([`Unit`]) and per member relation one read-only transaction that
//! reads the columns and a bounded sample, committed before anything else.
//! Only then are the values classified (`ScanJob::classify`), names
//! normalized, and findings submitted: no transaction or cursor is open
//! across `FindingSink::submit().await`.
//!
//! Sampling (I4): at most `job.sample_rows()` rows per object, with
//! `TABLESAMPLE SYSTEM` on large relations (by `reltuples`) and a plain
//! `LIMIT` otherwise or when the sample comes back short; every statement
//! under `SET LOCAL statement_timeout` from the clamped job parameter; at
//! most [`MAX_SAMPLE_BYTES`] read per relation.

use databastion_classifiers::masking::{FindingLocation, RawSample, RawValue};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FindingSink, ScanCoverage, ScanJob};
use futures_util::StreamExt;
use tokio_postgres::types::Type;

use crate::catalog::{self, Coverage, Member, Unit};
use crate::conn::{ReadTx, Session, Streamed, Timeouts};
use crate::error::{PgError, Stage};
use crate::sql;
use crate::wire::{Decoder, WireBytes};

/// Most bytes of sampled values read from one relation.
pub(crate) const MAX_SAMPLE_BYTES: usize = 32 * 1024 * 1024;
/// `TABLESAMPLE` only above this many estimated rows (and ten times the
/// sample size); smaller relations are read with `LIMIT`.
const TABLESAMPLE_MIN_ROWS: f64 = 10_000.0;
/// Oversampling factor of the `TABLESAMPLE SYSTEM` percentage.
const TABLESAMPLE_OVERSAMPLING: f64 = 3.0;

/// Normalizes a catalog name (ADR-0009). A PostgreSQL identifier is one
/// key: a name containing a dot becomes `*`.
pub(crate) fn normalize(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

/// Runs a Discovery scan of the job's target.
pub(crate) async fn discover(job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(
            PgError::new(databastion_core::FailureCode::Internal, Stage::Connect)
                .into_connector_error(),
        );
    };
    let timeouts = Timeouts::new(job.statement_timeout());
    for database in &target.postgres_settings().databases {
        if !job.includes_database(database) {
            continue;
        }
        scan_database(job, target, database, timeouts, sink).await?;
    }
    Ok(())
}

fn fail(target: &TargetConfig, database: &NormalizedName, e: PgError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        database = database.as_str(),
        stage = e.stage.as_str(),
        sqlstate = e.sqlstate(),
        code = %e.code,
        "scan failed"
    );
    e.into_connector_error()
}

async fn scan_database(
    job: &ScanJob,
    target: &TargetConfig,
    database: &str,
    timeouts: Timeouts,
    sink: &FindingSink,
) -> Result<(), ConnectorError> {
    let db_name = normalize(database);
    let first = Session::connect(target, database, timeouts)
        .await
        .map_err(|e| fail(target, &db_name, e))?;
    let relations = {
        let tx = first
            .begin(timeouts)
            .await
            .map_err(|e| fail(target, &db_name, e))?;
        match catalog::introspect(&tx).await {
            Ok(r) => {
                tx.commit().await.map_err(|e| fail(target, &db_name, e))?;
                r
            }
            Err(e) => {
                tx.rollback().await;
                return Err(fail(target, &db_name, e));
            }
        }
    };
    let mut session = Some(first);
    let (units, coverage) = catalog::plan(&relations, |schema, name| {
        job.includes_schema(schema) && job.includes_object(name)
    });
    log_coverage(target, &db_name, &coverage);
    sink.add_coverage(planned_coverage(&coverage));
    let mut skipped = 0usize;
    for unit in &units {
        let current = match session.take() {
            Some(s) => s,
            // Replaced after a budget stop.
            None => Session::connect(target, database, timeouts)
                .await
                .map_err(|e| fail(target, &db_name, e))?,
        };
        let schema = normalize(&unit.schema);
        let object = normalize(&unit.name);
        let sampled = sample_unit(&current, unit, job.sample_rows(), timeouts).await;
        // A poisoned session (budget stop: cancel in flight, aborted
        // transaction still open, AccessShareLock held) is closed here,
        // before any submit (L-new-1); the next object reconnects.
        if current.is_poisoned() {
            drop(current);
        } else {
            session = Some(current);
        }
        let sample = match sampled {
            Ok(s) => s,
            Err(e) if !e.fatal => {
                skipped += 1;
                sink.add_coverage(ScanCoverage {
                    error: 1,
                    ..ScanCoverage::default()
                });
                tracing::warn!(
                    target_id = %target.id,
                    database = db_name.as_str(),
                    schema = schema.as_str(),
                    object = object.as_str(),
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    "object skipped"
                );
                continue;
            }
            Err(e) => return Err(fail(target, &db_name, e)),
        };
        sink.add_coverage(ScanCoverage {
            sampled: 1,
            ..ScanCoverage::default()
        });
        if unit.rls {
            // Obligation 2: sampled under row-level security.
            tracing::info!(
                target_id = %target.id,
                database = db_name.as_str(),
                schema = schema.as_str(),
                object = object.as_str(),
                "object sampled under row-level security: the sample may be incomplete"
            );
        }
        // No transaction is open from here on.
        for (column, values) in &sample.columns {
            let samples: Vec<RawSample<'_>> = values.iter().map(RawValue::as_sample).collect();
            for finding in job.classify(column, &samples) {
                let mut finding = finding.into_finding(FindingLocation {
                    database: db_name.clone(),
                    schema: Some(schema.clone()),
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
    tracing::info!(
        target_id = %target.id,
        database = db_name.as_str(),
        objects = units.len(),
        skipped,
        not_covered = coverage.not_covered(),
        "database scanned"
    );
    Ok(())
}

/// The objects of a database's scope skipped by the plan, as coverage
/// counters (`JobProgress` `skipped_*`): foreign tables are remote (never
/// read, I5), partition leaves over the per-root cap a connector bound. An
/// introspection cut at its relation limit counts 1 more under the bound:
/// how many relations it left out is unknown.
pub(crate) fn planned_coverage(c: &Coverage) -> ScanCoverage {
    ScanCoverage {
        not_readable: c.not_readable.len() as u64,
        row_level_security: (c.rls_policy.len() + c.rls_ancestor.len()) as u64,
        remote: c.foreign as u64,
        limit: c.leaves_over_limit as u64 + u64::from(c.truncated),
        ..ScanCoverage::default()
    }
}

fn log_coverage(target: &TargetConfig, db: &NormalizedName, c: &Coverage) {
    for (reason, list) in [
        ("no SELECT privilege", &c.not_readable),
        (
            "row-level security policy with user code or another relation",
            &c.rls_policy,
        ),
        ("row-level security on an ancestor", &c.rls_ancestor),
    ] {
        for (schema, name) in list {
            tracing::warn!(
                target_id = %target.id,
                database = db.as_str(),
                schema = normalize(schema).as_str(),
                object = normalize(name).as_str(),
                reason,
                "object not covered"
            );
        }
    }
    if c.foreign > 0 || c.leaves_over_limit > 0 {
        tracing::info!(
            target_id = %target.id,
            database = db.as_str(),
            foreign_tables = c.foreign,
            leaves_over_limit = c.leaves_over_limit,
            "relations not sampled"
        );
    }
}

/// Sampled values of one object, per column (raw column names; values
/// zeroized on drop). `Debug` shows counts only.
pub(crate) struct UnitSample {
    pub(crate) columns: Vec<(String, Vec<RawValue>)>,
    pub(crate) estimated_rows: Option<u64>,
}

impl std::fmt::Debug for UnitSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitSample")
            .field("columns", &self.columns.len())
            .field("estimated_rows", &self.estimated_rows)
            .finish()
    }
}

/// Samples the members of a unit within a budget of `sample_rows` rows.
async fn sample_unit(
    session: &Session,
    unit: &Unit,
    sample_rows: u32,
    timeouts: Timeouts,
) -> Result<UnitSample, PgError> {
    let mut columns: Vec<(String, Vec<RawValue>)> = Vec::new();
    let mut remaining = sample_rows;
    let n = unit.members.len();
    let mut sampled_any = false;
    let mut last_error = None;
    for (i, member) in unit.members.iter().enumerate() {
        if remaining == 0 || session.is_poisoned() {
            break;
        }
        let left = u32::try_from(n - i).unwrap_or(u32::MAX);
        let quota = remaining.div_ceil(left);
        match sample_member(session, member, quota, timeouts, &mut columns).await {
            Ok(rows) => {
                sampled_any = true;
                remaining = remaining.saturating_sub(rows);
            }
            // A leaf that cannot be read does not stop its siblings.
            Err(e) if !e.fatal && n > 1 => {
                tracing::warn!(
                    schema = normalize(&member.schema).as_str(),
                    object = normalize(&member.name).as_str(),
                    stage = e.stage.as_str(),
                    sqlstate = e.sqlstate(),
                    "partition skipped"
                );
                last_error = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    if !sampled_any {
        if let Some(e) = last_error {
            return Err(e);
        }
    }
    Ok(UnitSample {
        columns,
        estimated_rows: unit.estimated_rows(),
    })
}

/// `TABLESAMPLE SYSTEM` percentage for a relation, or `None` for a plain
/// `LIMIT` read.
pub(crate) fn tablesample_percent(reltuples: f32, limit: u32) -> Option<f32> {
    let rows = f64::from(reltuples);
    let limit = f64::from(limit);
    if rows < TABLESAMPLE_MIN_ROWS || rows < 10.0 * limit {
        return None;
    }
    let pct = (100.0 * TABLESAMPLE_OVERSAMPLING * limit / rows).clamp(0.0001, 100.0);
    #[allow(clippy::cast_possible_truncation)]
    Some(pct as f32)
}

/// Reads the columns and a sample of one relation in one read-only
/// transaction, committed before returning. Appends the values to
/// `columns` (by column name). Returns the number of rows read.
async fn sample_member(
    session: &Session,
    member: &Member,
    limit: u32,
    timeouts: Timeouts,
    columns: &mut Vec<(String, Vec<RawValue>)>,
) -> Result<u32, PgError> {
    let tx = session.begin(timeouts).await?;
    let result = read_member(&tx, member, limit).await;
    match result {
        Ok((names, values, rows)) => {
            tx.commit().await?;
            for (name, vals) in names.into_iter().zip(values) {
                match columns.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, existing)) => existing.extend(vals),
                    None => columns.push((name, vals)),
                }
            }
            Ok(rows)
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

type MemberSample = (Vec<String>, Vec<Vec<RawValue>>, u32);

async fn read_member(
    tx: &ReadTx<'_>,
    member: &Member,
    limit: u32,
) -> Result<MemberSample, PgError> {
    let rows = tx
        .query(
            Stage::Columns,
            sql::COLUMNS,
            &[(&vec![member.oid], Type::OID_ARRAY)],
        )
        .await?;
    let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Columns);
    let mut cols: Vec<(String, Decoder)> = Vec::new();
    for row in rows {
        let typtype: i8 = row.try_get(3).map_err(get)?;
        let decoder = Decoder::for_type(
            row.try_get(2).map_err(get)?,
            typtype.to_ne_bytes()[0],
            row.try_get(4).map_err(get)?,
            row.try_get(5).map_err(get)?,
        );
        if let Some(d) = decoder {
            // A column name that is not UTF-8 (L1): not sampled.
            if let Some(name) = crate::wire::catalog_text(&row, 1).map_err(get)? {
                cols.push((name, d));
            }
        }
    }
    if cols.is_empty() {
        return Ok((Vec::new(), Vec::new(), 0));
    }
    let names: Vec<&str> = cols.iter().map(|(n, _)| n.as_str()).collect();
    let decoders: Vec<Decoder> = cols.iter().map(|(_, d)| *d).collect();
    let limit_param = i64::from(limit);
    if let Some(pct) = tablesample_percent(member.reltuples, limit) {
        let statement = sql::sample_statement(&member.schema, &member.name, &names, true).ok_or(
            PgError::new(databastion_core::FailureCode::Internal, Stage::Sample),
        )?;
        let (values, rows) = read_rows(
            tx,
            &statement,
            &[(&pct, Type::FLOAT4), (&limit_param, Type::INT8)],
            &decoders,
        )
        .await?;
        // A short sample (stale statistics, clustered free space): fall
        // back to a plain bounded read, unless the byte budget stopped it.
        if rows.saturating_mul(2) >= limit || tx.is_poisoned() {
            return Ok((cols.into_iter().map(|(n, _)| n).collect(), values, rows));
        }
    }
    let statement = sql::sample_statement(&member.schema, &member.name, &names, false).ok_or(
        PgError::new(databastion_core::FailureCode::Internal, Stage::Sample),
    )?;
    let (values, rows) =
        read_rows(tx, &statement, &[(&limit_param, Type::INT8)], &decoders).await?;
    Ok((cols.into_iter().map(|(n, _)| n).collect(), values, rows))
}

/// Streams the rows of a sampling statement and decodes them per column.
async fn read_rows(
    tx: &ReadTx<'_>,
    statement: &str,
    params: &[(&(dyn tokio_postgres::types::ToSql + Sync), Type)],
    decoders: &[Decoder],
) -> Result<(Vec<Vec<RawValue>>, u32), PgError> {
    tx.query_stream(Stage::Sample, statement, params, |stream| async move {
        let mut stream = std::pin::pin!(stream);
        let mut values: Vec<Vec<RawValue>> = decoders.iter().map(|_| Vec::new()).collect();
        let mut rows = 0u32;
        let mut bytes = 0usize;
        while let Some(row) = stream.next().await {
            let row = row?;
            let mut raws = Vec::with_capacity(decoders.len());
            let mut row_bytes = 0usize;
            for i in 0..decoders.len() {
                let raw = row.try_get::<_, Option<WireBytes<'_>>>(i)?;
                row_bytes = row_bytes.saturating_add(raw.as_ref().map_or(0, |r| r.0.len()));
                raws.push(raw);
            }
            // Budget checked per row, before decoding it (M1). The row
            // itself was already received whole by the driver: one row is
            // the residual peak. The statement is cancelled, the rest is
            // not read.
            if bytes.saturating_add(row_bytes) > MAX_SAMPLE_BYTES {
                tracing::info!(rows, "sample byte budget reached: statement cancelled");
                return Ok(Streamed::Stopped((values, rows)));
            }
            bytes += row_bytes;
            rows += 1;
            for ((raw, decoder), out) in raws.into_iter().zip(decoders).zip(values.iter_mut()) {
                if let Some(v) = raw.and_then(|WireBytes(r)| decoder.decode(r)) {
                    out.push(RawValue::new(v));
                }
            }
        }
        Ok(Streamed::Complete((values, rows)))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_coverage_counts_each_skip_reason() {
        let pair = || ("s".to_owned(), "t".to_owned());
        let c = Coverage {
            not_readable: vec![pair(); 2],
            rls_policy: vec![pair(); 3],
            rls_ancestor: vec![pair()],
            foreign: 4,
            leaves_over_limit: 5,
            truncated: false,
        };
        assert_eq!(
            planned_coverage(&c),
            ScanCoverage {
                sampled: 0,
                not_readable: 2,
                row_level_security: 4,
                remote: 4,
                unsupported: 0,
                limit: 5,
                error: 0,
            }
        );
        assert_eq!(
            planned_coverage(&Coverage::default()),
            ScanCoverage::default()
        );
        // A truncated introspection: its unknown remainder counts 1.
        let cut = Coverage {
            truncated: true,
            ..Coverage::default()
        };
        assert_eq!(planned_coverage(&cut).limit, 1);
    }

    #[test]
    fn value_bearing_names_are_normalized() {
        assert_eq!(normalize("customers").as_str(), "customers");
        assert_eq!(normalize("export_client_0639988384").as_str(), "*");
        assert_eq!(normalize("archive_lucas_martin").as_str(), "*");
        assert_eq!(normalize("jane.doe@example.com").as_str(), "*");
        assert_eq!(normalize("a.b").as_str(), "*");
    }

    #[test]
    fn tablesample_only_on_large_relations() {
        assert_eq!(tablesample_percent(-1.0, 200), None);
        assert_eq!(tablesample_percent(150.0, 200), None);
        assert_eq!(tablesample_percent(9_999.0, 200), None);
        assert_eq!(tablesample_percent(15_000.0, 2_000), None);
        let p = tablesample_percent(1_000_000.0, 200).unwrap();
        assert!((p - 0.06).abs() < 1e-6, "{p}");
        let p = tablesample_percent(1e12, 1).unwrap();
        assert!((p - 0.0001).abs() < 1e-9, "{p}");
        let p = tablesample_percent(10_000.0, 1_000).unwrap();
        assert!((p - 30.0).abs() < 1e-4, "{p}");
    }
}
