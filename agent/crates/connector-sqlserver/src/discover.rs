//! Discovery (ADR-0051 decision 5, refinement item 2): catalogs read with
//! three-part names in the monitored databases, then per table one bounded
//! sampling statement (`TOP (n)`, `TABLESAMPLE SYSTEM` for large tables,
//! `OPTION (MAXDOP 1)`) in autocommit at `READ UNCOMMITTED` with
//! `LOCK_TIMEOUT 2000` (the session settings), a per-table deadline of the
//! job's statement timeout bounded at 30 s, and 32 MiB of sampled values
//! per table checked value by value. Each unit of work is paced
//! ([`ScanJob::paced`], ADR-0035).
//!
//! Never sampled: views, synonyms, external and Stretch tables
//! (`skipped_remote`), tables of a database whose RLS policies cannot be
//! proven visible, tables with an enabled RLS predicate
//! (`skipped_row_level_security`), computed columns, column sets, CLR,
//! `xml`, `sql_variant` and every type outside [`sql::sampled_kind`], and
//! Always Encrypted columns. The CAS store guard applies.
//!
//! Only after a table's statement is fully read (or cancelled) are its
//! values classified and the findings submitted.

use std::collections::HashSet;
use std::time::Duration;

use databastion_classifiers::masking::{FindingLocation, RawSample, RawValue};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_core::cas_guard::{self, CasStores, StoreKind, TicketCounts};
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob};

use crate::check::{self, CheckState, RlsTier};
use crate::conn::{self, Cell, Ended, Flow, Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql::{self, Sampled};
use crate::tls;
use crate::token::Value;

/// Most bytes of sampled values read from one table (decision 5).
pub(crate) const MAX_SAMPLE_BYTES: usize = 32 * 1024 * 1024;
/// Bytes charged per value on top of its length.
pub(crate) const VALUE_OVERHEAD: usize = 16;
/// Per-table sampling deadline bound (L9).
pub(crate) const MAX_TABLE_DEADLINE: Duration = Duration::from_secs(30);
/// A session is closed before a pause at least this long (decision 5).
pub(crate) const CLOSE_BEFORE_PAUSE: Duration = Duration::from_secs(45);
/// Most columns sampled per table (the statement stays under the
/// client's text bound); the rest is reported as `skipped_limit`.
pub(crate) const MAX_SAMPLED_COLUMNS: usize = 512;
/// The CLR types' `system_type_id` (`hierarchyid`, `geometry`,
/// `geography`, user CLR types).
const CLR_TYPE: i64 = 240;

/// Normalizes a catalog name (ADR-0009): one key; a name with a dot or a
/// value in it becomes `*`.
pub(crate) fn normalize(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

/// A table of the catalog.
#[derive(Debug, Clone)]
pub(crate) struct Table {
    pub(crate) id: i64,
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) stretch: bool,
    pub(crate) memory_optimized: bool,
    pub(crate) estimated_rows: Option<u64>,
    pub(crate) readable: bool,
}

/// One column as the catalog describes it.
#[derive(Debug, Clone)]
pub(crate) struct Column {
    pub(crate) name: String,
    pub(crate) system_type_id: i64,
    pub(crate) computed: bool,
    pub(crate) column_set: bool,
    pub(crate) encrypted: bool,
    pub(crate) graph: bool,
    pub(crate) user_type_id: i64,
    pub(crate) readable: bool,
}

impl Column {
    /// How the column is sampled, `None` when it is not.
    pub(crate) fn sampled(&self) -> Option<Sampled> {
        if !self.readable
            || self.computed
            || self.column_set
            || self.encrypted
            || self.graph
            || self.system_type_id == CLR_TYPE
            // An alias type keeps its base `system_type_id`; a CLR UDT
            // has 240 there. `user_type_id` above 256 with a system type
            // id of a sampled base type is an alias: sampled as its base.
            || self.user_type_id == CLR_TYPE
        {
            return None;
        }
        sql::sampled_kind(self.system_type_id)
    }
}

/// The sampled values of one table (zeroized on drop by `RawValue`).
pub(crate) struct TableSample {
    pub(crate) columns: Vec<(String, Vec<RawValue>)>,
    pub(crate) kind: Option<StoreKind>,
    pub(crate) tickets: Option<TicketCounts>,
    pub(crate) unsampled: usize,
    pub(crate) truncated_columns: bool,
    pub(crate) stopped: bool,
    pub(crate) any_readable: bool,
}

impl std::fmt::Debug for TableSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableSample")
            .field("columns", &self.columns.len())
            .finish_non_exhaustive()
    }
}

fn parse_tables(rows: &[Vec<Value>]) -> Vec<Table> {
    rows.iter()
        .filter_map(|r| {
            let int = |i: usize| r.get(i).and_then(Value::as_int);
            let text = |i: usize| r.get(i).and_then(Value::as_text).map(str::to_owned);
            Some(Table {
                id: int(0)?,
                schema: text(1)?,
                name: text(2)?,
                stretch: int(3) == Some(1),
                memory_optimized: int(4) == Some(1),
                estimated_rows: int(5).and_then(|n| u64::try_from(n).ok()),
                readable: int(6) == Some(1),
            })
        })
        .collect()
}

fn parse_columns(rows: &[Vec<Value>]) -> Vec<Column> {
    rows.iter()
        .filter_map(|r| {
            let int = |i: usize| r.get(i).and_then(Value::as_int);
            Some(Column {
                name: r.first().and_then(Value::as_text)?.to_owned(),
                system_type_id: int(1)?,
                computed: int(2) == Some(1),
                column_set: int(3) == Some(1),
                encrypted: int(4) == Some(1),
                graph: int(6) == Some(1),
                user_type_id: int(7).unwrap_or(0),
                readable: int(8) == Some(1),
            })
        })
        .collect()
}

/// Reads the columns and a sample of one table.
pub(crate) async fn sample_table(
    s: &mut Session,
    db: &str,
    table: &Table,
    n: u32,
    stores: Option<&CasStores>,
) -> Result<TableSample, SsError> {
    let mut out = TableSample {
        columns: Vec::new(),
        kind: None,
        tickets: None,
        unsampled: 0,
        truncated_columns: false,
        stopped: false,
        any_readable: false,
    };
    let stmt =
        sql::columns(db, table.id).ok_or(SsError::new(FailureCode::Internal, Stage::Columns))?;
    let rows = s.rows(&stmt, Stage::Columns, Shape::rows(9, 4096)).await?;
    let cols = parse_columns(&rows);
    out.any_readable = cols.iter().any(|c| c.readable);
    // CAS store guard (ADR-0041 decision 5): by name, else by the shape of
    // the columns the account can read.
    out.kind = cas_guard::recognize(
        stores,
        [table.name.as_str()],
        cols.iter().filter(|c| c.readable).map(|c| c.name.as_str()),
    );
    if out.kind == Some(StoreKind::TicketRegistry) {
        if let Some(col) = cols
            .iter()
            .find(|c| c.readable && cas_guard::name_key(&c.name) == "type")
        {
            let stmt = sql::ticket_type_counts(db, &table.schema, &table.name, &col.name)
                .ok_or(SsError::new(FailureCode::Internal, Stage::Sample))?;
            let rows = s.rows(&stmt, Stage::Sample, Shape::rows(2, 256)).await?;
            let mut counts = TicketCounts::default();
            for r in &rows {
                let kind = r.first().and_then(Value::as_text).unwrap_or_default();
                let n = r.get(1).and_then(Value::as_int).unwrap_or(0);
                counts.add(kind, u64::try_from(n).unwrap_or(0));
            }
            out.tickets = Some(counts);
        }
        return Ok(out);
    }
    let mut selected: Vec<(&str, Sampled)> = Vec::new();
    for c in &cols {
        if cas_guard::column_rule(out.kind, &c.name) == cas_guard::ColumnRule::NeverRead {
            continue;
        }
        match c.sampled() {
            Some(k) => selected.push((c.name.as_str(), k)),
            None => out.unsampled += 1,
        }
    }
    if selected.len() > MAX_SAMPLED_COLUMNS {
        selected.truncate(MAX_SAMPLED_COLUMNS);
        out.truncated_columns = true;
    }
    if selected.is_empty() {
        return Ok(out);
    }
    let percent = if table.memory_optimized {
        None
    } else {
        sql::tablesample_percent(n, table.estimated_rows)
    };
    let stmt = sql::sample_statement(db, &table.schema, &table.name, &selected, n, percent)
        .ok_or(SsError::new(FailureCode::Internal, Stage::Sample))?;
    let mut values: Vec<Vec<RawValue>> = selected.iter().map(|_| Vec::new()).collect();
    let mut bytes = 0usize;
    let ended = s
        .run(
            &stmt,
            Stage::Sample,
            Shape {
                columns: selected.len(),
                max_rows: n as usize,
                max_bytes: MAX_SAMPLE_BYTES * 2,
                plp_cap: 0,
            },
            |cell| {
                let Cell::Value(i, mut v) = cell else {
                    return Flow::Continue;
                };
                // Budget checked per value as it arrives (decision 5).
                bytes = bytes.saturating_add(v.wire_len() + VALUE_OVERHEAD);
                if bytes > MAX_SAMPLE_BYTES {
                    return Flow::Stop;
                }
                if let (Value::Text(t), Some(col)) = (&mut v, values.get_mut(i)) {
                    col.push(RawValue::new(std::mem::take(t)));
                }
                Flow::Continue
            },
        )
        .await?;
    out.stopped = ended == Ended::Stopped;
    out.columns = selected
        .iter()
        .map(|(c, _)| (*c).to_owned())
        .zip(values)
        .collect();
    Ok(out)
}

fn fail(target: &TargetConfig, e: SsError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        number = e.number,
        code = %e.code,
        detail = e.detail.map(crate::error::Detail::as_str),
        "scan failed"
    );
    e.into_connector_error()
}

fn cov(f: impl FnOnce(&mut ScanCoverage)) -> ScanCoverage {
    let mut c = ScanCoverage::default();
    f(&mut c);
    c
}

/// Runs a Discovery scan.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(SsError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    if job.out_of_time() {
        job.skip_out_of_time(sink, 1);
        return Ok(());
    }
    let settings = target.sqlserver_settings();
    let tls = tls::configs(settings.ca_file.as_deref())
        .ok_or_else(|| fail(target, SsError::new(FailureCode::Internal, Stage::Tls)))?;
    let timeout = job.statement_timeout().min(MAX_TABLE_DEADLINE);
    let connect = || conn::connect(target, &tls, &state.choice, timeout);
    // Version, refusal list and the monitored databases, paced.
    let mut first = connect().await.map_err(|e| fail(target, e))?;
    let start = match job
        .paced(async {
            check::version(&mut first).await?;
            let ev = check::evaluate(&mut first, target).await?;
            let dbs = check::monitored_databases(&mut first, target).await?;
            Ok::<_, SsError>((ev, dbs))
        })
        .await?
    {
        Paced::Done(r) => r.map_err(|e| fail(target, e))?,
        Paced::OutOfTime => {
            first.close().await;
            job.skip_out_of_time(sink, 1);
            return Ok(());
        }
    };
    let (ev, (mut dbs, cut)) = start;
    if ev.is_refused() {
        first.close().await;
        tracing::warn!(
            target_id = %target.id,
            "the account holds a right of the refusal list (privilege.refused): Discovery \
             refused (ADR-0051 open question 4)"
        );
        return Err(
            SsError::new(FailureCode::PermissionDenied, Stage::Check).into_connector_error()
        );
    }
    if cut {
        sink.add_coverage(cov(|c| c.limit = 1));
    }
    dbs.retain(|d| job.includes_database(d));
    job.rotate(&mut dbs);
    let mut session = Some(first);
    for (i, db) in dbs.iter().enumerate() {
        // An idle session is closed before a long pause (ADR-0051
        // decision 5, as MySQL).
        if job.pacer().debt() >= CLOSE_BEFORE_PAUSE
            && let Some(s) = session.take()
        {
            s.close().await;
        }
        if job.turn().await? == Paced::OutOfTime {
            job.skip_out_of_time(sink, dbs.len() - i);
            break;
        }
        let mut s = match session.take() {
            Some(s) if !s.is_poisoned() && !s.is_stale() => s,
            stale => {
                if let Some(s) = stale {
                    s.close().await;
                }
                connect().await.map_err(|e| fail(target, e))?
            }
        };
        job.begin_database(db);
        let catalog = match job.paced(read_catalog(&mut s, db, target)).await? {
            Paced::Done(c) => c,
            Paced::OutOfTime => {
                s.close().await;
                job.skip_out_of_time(sink, dbs.len() - i);
                break;
            }
        };
        let (tier, rls_tables, mut tables, counts, cut) = match catalog {
            Ok(c) => c,
            Err(e) if !e.fatal => {
                sink.add_coverage(cov(|c| c.error = 1));
                tracing::warn!(target_id = %target.id, database = normalize(db).as_str(), stage = e.stage.as_str(), number = e.number, "database skipped");
                session = Some(s);
                continue;
            }
            Err(e) => return Err(fail(target, e)),
        };
        sink.add_coverage(cov(|c| {
            c.unsupported = counts.0 + counts.1;
            c.remote = counts.2;
            c.limit = u64::from(cut);
        }));
        tables.retain(|t| job.includes_schema(&t.schema) && job.includes_object(&t.name));
        if let RlsTier::NotVerifiable(why) = tier {
            sink.add_coverage(cov(|c| c.row_level_security = tables.len() as u64));
            tracing::warn!(
                target_id = %target.id,
                database = normalize(db).as_str(),
                tables = tables.len(),
                reason = why,
                "database not sampled: row-level security not verifiable (coverage.rls_not_verifiable)"
            );
            session = Some(s);
            continue;
        }
        job.rotate(&mut tables);
        let mut current = Some(s);
        for (j, table) in tables.iter().enumerate() {
            if job.pacer().debt() >= CLOSE_BEFORE_PAUSE
                && let Some(s) = current.take()
            {
                s.close().await;
            }
            if job.turn().await? == Paced::OutOfTime {
                if let Some(s) = current.take() {
                    s.close().await;
                }
                job.skip_out_of_time(sink, tables.len() - j);
                return Ok(());
            }
            if table.stretch {
                sink.add_coverage(cov(|c| c.remote = 1));
                continue;
            }
            if rls_tables.contains(&table.id) {
                sink.add_coverage(cov(|c| c.row_level_security = 1));
                continue;
            }
            // `table.readable` is the table-level `SELECT`; column grants
            // (SQL Server has column `DENY` and column `GRANT`) are read
            // per column by `sample_table`.
            let mut s = match current.take() {
                Some(s) if !s.is_poisoned() && !s.is_stale() => s,
                stale => {
                    if let Some(s) = stale {
                        s.close().await;
                    }
                    connect().await.map_err(|e| fail(target, e))?
                }
            };
            let sampled = match job
                .paced(sample_table(
                    &mut s,
                    db,
                    table,
                    job.sample_rows(),
                    job.cas_stores(),
                ))
                .await?
            {
                Paced::Done(r) => r,
                Paced::OutOfTime => {
                    s.close().await;
                    job.skip_out_of_time(sink, tables.len() - j);
                    return Ok(());
                }
            };
            // A poisoned session is closed before any submit.
            if s.is_poisoned() {
                s.close().await;
            } else {
                current = Some(s);
            }
            let dbn = normalize(db);
            let schema = normalize(&table.schema);
            let object = normalize(&table.name);
            let sample = match sampled {
                Ok(x) => x,
                Err(e) if !e.fatal || e.code == FailureCode::Timeout => {
                    sink.add_coverage(cov(|c| {
                        if e.code == FailureCode::ResourceLimit {
                            c.limit = 1;
                        } else if e.code == FailureCode::PermissionDenied {
                            c.not_readable = 1;
                        } else {
                            c.error = 1;
                        }
                    }));
                    tracing::warn!(target_id = %target.id, database = dbn.as_str(), schema = schema.as_str(), object = object.as_str(), stage = e.stage.as_str(), number = e.number, code = %e.code, "object skipped");
                    continue;
                }
                Err(e) => return Err(fail(target, e)),
            };
            if sample.kind == Some(StoreKind::TicketRegistry) {
                sink.add_coverage(cov(|c| c.unsupported = 1));
                if let Some(counts) = &sample.tickets {
                    job.record_ticket_registry(counts);
                }
                tracing::info!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), "CAS ticket registry: not sampled (CAS store guard, metadata only)");
                continue;
            }
            if sample.columns.is_empty() {
                sink.add_coverage(cov(|c| {
                    if sample.any_readable || table.readable {
                        c.unsupported = 1;
                    } else {
                        c.not_readable = 1;
                    }
                }));
                continue;
            }
            sink.add_coverage(cov(|c| {
                c.sampled = 1;
                c.limit = u64::from(sample.stopped || sample.truncated_columns);
            }));
            if sample.unsampled > 0 {
                tracing::info!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), columns = sample.unsampled, "columns not sampled (type, computed, encrypted, not readable)");
            }
            for (column, values) in &sample.columns {
                let samples: Vec<RawSample<'_>> = values.iter().map(RawValue::as_sample).collect();
                let rule = cas_guard::column_rule(sample.kind, column);
                for finding in job.classify_guarded(column, &samples, rule) {
                    let mut finding = finding.into_finding(FindingLocation {
                        database: dbn.clone(),
                        schema: Some(schema.clone()),
                        object: object.clone(),
                        field: normalize(column),
                    });
                    if let Some(rows) = table.estimated_rows {
                        finding = finding.with_estimated_rows(rows);
                    }
                    sink.submit(finding).await?;
                }
            }
        }
        session = current;
    }
    if let Some(s) = session {
        s.close().await;
    }
    Ok(())
}

type Catalog = (RlsTier, HashSet<i64>, Vec<Table>, (u64, u64, u64), bool);

async fn read_catalog(
    s: &mut Session,
    db: &str,
    target: &TargetConfig,
) -> Result<Catalog, SsError> {
    let tier = check::rls_tier(s, db, target).await?;
    let mut rls = HashSet::new();
    if tier == RlsTier::Visible {
        let stmt = sql::in_database(sql::RLS_TABLES, db)
            .ok_or(SsError::new(FailureCode::Internal, Stage::Introspection))?;
        let rows = s
            .rows(&stmt, Stage::Introspection, Shape::rows(1, 16_385))
            .await?;
        if rows.len() > 16_384 {
            return Err(SsError {
                fatal: false,
                ..SsError::new(FailureCode::ResourceLimit, Stage::Introspection)
            });
        }
        rls = rows
            .iter()
            .filter_map(|r| r.first().and_then(Value::as_int))
            .collect();
    }
    let stmt = sql::in_database(sql::UNSAMPLED_OBJECTS, db)
        .ok_or(SsError::new(FailureCode::Internal, Stage::Introspection))?;
    let rows = s
        .rows(&stmt, Stage::Introspection, Shape::rows(3, 1))
        .await?;
    let n = |i: usize| {
        rows.first()
            .and_then(|r| r.get(i))
            .and_then(Value::as_int)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0)
    };
    let counts = (n(0), n(1), n(2));
    let limit = target.sqlserver_settings().max_tables;
    let stmt =
        sql::tables(db, limit).ok_or(SsError::new(FailureCode::Internal, Stage::Introspection))?;
    let rows = s
        .rows(
            &stmt,
            Stage::Introspection,
            Shape::rows(7, limit as usize + 1),
        )
        .await?;
    let mut tables = parse_tables(&rows);
    let cut = tables.len() > limit as usize;
    tables.truncate(limit as usize);
    Ok((tier, rls, tables, counts, cut))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsampled_columns() {
        let base = Column {
            name: "c".into(),
            system_type_id: 231,
            computed: false,
            column_set: false,
            encrypted: false,
            graph: false,
            user_type_id: 231,
            readable: true,
        };
        assert_eq!(base.sampled(), Some(Sampled::Text));
        for c in [
            Column {
                computed: true,
                ..base.clone()
            },
            Column {
                encrypted: true,
                ..base.clone()
            },
            Column {
                column_set: true,
                ..base.clone()
            },
            Column {
                graph: true,
                ..base.clone()
            },
            Column {
                readable: false,
                ..base.clone()
            },
            Column {
                system_type_id: 240,
                ..base.clone()
            },
            Column {
                system_type_id: 241,
                ..base.clone()
            },
            Column {
                system_type_id: 98,
                ..base.clone()
            },
        ] {
            assert_eq!(c.sampled(), None, "{c:?}");
        }
        // An alias type of nvarchar: sampled by its system type.
        assert_eq!(
            Column {
                user_type_id: 257,
                ..base
            }
            .sampled(),
            Some(Sampled::Text)
        );
    }

    #[test]
    fn value_bearing_names_are_normalized() {
        assert_eq!(normalize("customers").as_str(), "customers");
        assert_eq!(normalize("export_jean.richard@example.com").as_str(), "*");
    }
}
