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
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FailureCode, FindingSink, ScanJob};

use crate::catalog::{self, Coverage, Table};
use crate::conn::{Flow, ReadTx, Session, Streamed, Timeouts};
use crate::error::{MyError, Stage};
use crate::sql::{self, Sampled};

/// Most bytes of sampled values read from one table.
pub(crate) const MAX_SAMPLE_BYTES: usize = 32 * 1024 * 1024;
/// Longest value handed to the classifiers, in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 4096;

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
pub(crate) async fn discover(job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(MyError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    let timeouts = Timeouts::new(job.statement_timeout());
    let mut first = Session::connect(target, timeouts)
        .await
        .map_err(|e| fail(target, e))?;
    let tables = {
        let mut tx = first.begin().await.map_err(|e| fail(target, e))?;
        match catalog::introspect(&mut tx).await {
            Ok(t) => {
                tx.commit().await.map_err(|e| fail(target, e))?;
                t
            }
            Err(e) => {
                tx.rollback().await;
                return Err(fail(target, e));
            }
        }
    };
    let (units, coverage) = catalog::plan(&tables, |schema, name| {
        // MySQL has no schema level: the job's `schemas` filter
        // (PostgreSQL) does not apply.
        job.includes_database(schema) && job.includes_object(name)
    });
    log_coverage(target, &coverage);
    let mut session = Some(first);
    let mut skipped = 0usize;
    let mut not_readable = 0usize;
    for unit in &units {
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
        let db = normalize(&unit.schema);
        let object = normalize(&unit.name);
        let sampled = sample_table(&mut current, unit, job.sample_rows()).await;
        // A poisoned session (budget stop: kill in flight, unread result)
        // is closed here, before any submit; the next table reconnects.
        if current.is_poisoned() {
            drop(current);
        } else {
            session = Some(current);
        }
        let sample = match sampled {
            Ok(s) => s,
            Err(e) if !e.fatal => {
                skipped += 1;
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
            tracing::warn!(
                target_id = %target.id,
                database = db.as_str(),
                object = object.as_str(),
                reason = "no SELECT privilege on any column",
                "object not covered"
            );
            continue;
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
        // No transaction is open from here on.
        for (column, values) in &sample.columns {
            let samples: Vec<RawSample<'_>> = values.iter().map(RawValue::as_sample).collect();
            for finding in job.classify(column, &samples) {
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
    /// At least one column is readable (`SELECT` privilege).
    pub(crate) readable: bool,
    pub(crate) virtual_columns: usize,
    pub(crate) rows: u32,
    /// `TABLE_ROWS` (an estimate for InnoDB).
    pub(crate) estimated_rows: Option<u64>,
}

impl std::fmt::Debug for TableSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableSample")
            .field("columns", &self.columns.len())
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

/// Reads the columns and a sample of one table in one read-only
/// transaction, committed (or, after a budget stop, abandoned with the
/// session) before returning.
pub(crate) async fn sample_table(
    session: &mut Session,
    table: &Table,
    limit: u32,
) -> Result<TableSample, MyError> {
    let mut tx = session.begin().await?;
    match read_table(&mut tx, table, limit).await {
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

async fn read_table(
    tx: &mut ReadTx<'_>,
    table: &Table,
    limit: u32,
) -> Result<TableSample, MyError> {
    let mut sample = TableSample {
        columns: Vec::new(),
        readable: false,
        virtual_columns: 0,
        rows: 0,
        estimated_rows: None,
    };
    // The engine is checked again in this transaction (a table altered to
    // a remote engine since the introspection is not read).
    let statement = sql::table_rows(&table.schema, &table.name)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Columns))?;
    let Some(row) = tx
        .query(Stage::Columns, &statement)
        .await?
        .into_iter()
        .next()
    else {
        tracing::warn!("table gone or no longer on a local engine: not sampled");
        return Err(MyError {
            fatal: false,
            ..MyError::new(FailureCode::Internal, Stage::Columns)
        });
    };
    sample.estimated_rows = row.get(1).cloned().flatten().and_then(|r| r.parse().ok());
    let statement = sql::columns(&table.schema, &table.name)
        .ok_or(MyError::new(FailureCode::Internal, Stage::Columns))?;
    let rows = tx.query(Stage::Columns, &statement).await?;
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
        if name.is_empty() {
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
    let selected: Vec<(&str, Sampled)> = cols.iter().map(|(n, k)| (n.as_str(), *k)).collect();
    let statement = sql::sample_statement(
        tx.flavor(),
        tx.timeouts().statement_ms(),
        &table.schema,
        &table.name,
        &selected,
        limit,
    )
    .ok_or(MyError::new(FailureCode::Internal, Stage::Sample))?;
    let mut values: Vec<Vec<RawValue>> = cols.iter().map(|_| Vec::new()).collect();
    let mut rows = 0u32;
    let mut bytes = 0usize;
    let streamed = tx
        .query_stream(Stage::Sample, &statement, |row| {
            let row_bytes: usize = row.iter().map(|v| v.map_or(0, <[u8]>::len)).sum();
            // Budget checked per row, before decoding it. The row itself
            // was already received whole: one row is the residual peak.
            if bytes.saturating_add(row_bytes) > MAX_SAMPLE_BYTES {
                return Flow::Stop;
            }
            bytes += row_bytes;
            rows += 1;
            for (raw, out) in row.iter().zip(values.iter_mut()) {
                if let Some(v) = raw.and_then(decode_value) {
                    out.push(RawValue::new(v));
                }
            }
            Flow::Continue
        })
        .await?;
    if streamed == Streamed::Stopped {
        tracing::info!(rows, "sample byte budget reached: statement killed");
    }
    sample.rows = rows;
    sample.columns = cols.into_iter().map(|(n, _)| n).zip(values).collect();
    Ok(sample)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn values_are_cut_at_4096_bytes_on_a_char_boundary() {
        assert_eq!(decode_value(b"abc").unwrap(), "abc");
        let long = "é".repeat(3000);
        let cut = decode_value(long.as_bytes()).unwrap();
        assert!(cut.len() <= MAX_VALUE_BYTES && cut.len() >= MAX_VALUE_BYTES - 1);
        assert!(cut.chars().all(|c| c == 'é'));
        assert!(decode_value(&[0xFF, 0xFE]).is_none());
    }
}
