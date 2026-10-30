//! Discovery (ADR-0060 decision 5, refinement R3), lot 2 of decision 10.
//!
//! - **Declared databases only** (I5): one attachment per declared database
//!   (`attach` sent to the server only), `Location.database` the declared
//!   name, never the path or alias; the job's `databases` filter on the
//!   declared names.
//! - Every attachment is prepared as `check()`'s ([`check::prepare`]: the
//!   version, the wire encryption and the read-only read-committed
//!   transaction as the server reports them, the forwarder rule, the idle
//!   timeout), and the account is evaluated again against the refusal list
//!   at the database's first attachment: a refused or unevaluated account
//!   ends the scan (`permission_denied`, open question 4).
//! - The catalog ([`catalog::read`]): user relations (system flag 0) and the
//!   columns of persistent tables. **Sampled**: persistent tables the
//!   account can read, not on the never-sampled list, not a CAS ticket
//!   registry; columns of the conversion list only, not computed, not
//!   arrays. **Never sampled**: views, external-file tables
//!   (`skipped_remote`), global temporary tables, the never-sampled list
//!   (`skipped_unsupported`), CAS ticket registries (their type counts
//!   only, `skipped_unsupported`).
//! - Per table, `SELECT FIRST n` with the server-side conversions of
//!   [`sql::Conv`], in column batches of at most 255 columns and 64 KiB of
//!   declared row; each batch is a unit of work under pacing
//!   ([`ScanJob::paced`], ADR-0035) in its own read-only transaction,
//!   committed before the next pause; the attachment is detached before a
//!   pause of 45 s or more. 32 MiB of sampled values per table, checked
//!   value by value: past it the fetch stops at the round in flight
//!   (`skipped_limit` added).
//! - Values are classified and masked by `ScanJob::classify_guarded` (I2,
//!   the CAS ticket-id tripwire first) once the table's last batch is read;
//!   a batch the server refuses (a conversion or transliteration failure, a
//!   permission, a lock conflict, a timeout) skips the table
//!   (`skipped_error`, `skipped_not_readable`), with the column types in the
//!   local detail, never a value.
//! - Catalog names are read as raw bytes: a relation whose name, or one of
//!   whose column names, is not UTF-8 or cannot be quoted is
//!   `skipped_error` alone (review L3), never the database, and leaves the
//!   CAS store guard not evaluated.
//! - Names: trailing spaces dropped (the engine's rule, no marker), then
//!   ADR-0009 normalization with the ADR-0056 marker and the ADR-0057 rules
//!   (`normalize_field_path`).

use std::time::Duration;

use async_trait::async_trait;
use databastion_classifiers::masking::{FindingLocation, MaskedFinding, RawSample, RawValue};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_core::cas_guard::{self, ColumnRule, StoreKind, TicketCounts};
use databastion_core::config::TargetConfig;
use databastion_core::config::firebird::FirebirdDatabase;
use databastion_core::{ConnectorError, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::catalog::{self, Catalog, Kind};
use crate::check::{self, CheckState};
use crate::conn::{self, Endpoint, Flow, Session};
use crate::error::{FbError, Stage};
use crate::privileges::Evaluation;
use crate::sql::{self, Col, Conv, Value};

/// Most bytes of sampled values read from one table (decision 5).
pub(crate) const MAX_SAMPLE_BYTES: usize = 32 * 1024 * 1024;
/// Bytes charged per value on top of its length.
pub(crate) const VALUE_OVERHEAD: usize = 16;
/// Sampling statements time out at most after this (decision 4: 30 s).
pub(crate) const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// The attachment is detached before a pause at least this long
/// (decision 5, as MySQL).
pub(crate) const CLOSE_BEFORE_PAUSE: Duration = Duration::from_secs(45);
/// Rows of a ticket registry's type aggregate read.
const MAX_TICKET_TYPES: usize = 256;
/// A unit's own deadline past its statement timeout (connect, prepare,
/// commit).
const UNIT_MARGIN: Duration = Duration::from_secs(15);

/// Normalizes a catalog name (ADR-0009, ADR-0056, ADR-0057): trailing
/// spaces dropped first (not significant in a Firebird name, decision 5),
/// then one key; a name with a `.` or a value in it becomes `*`.
#[must_use]
pub(crate) fn normalize(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(catalog::trimmed(raw))])
}

/// Opens a prepared attachment to a declared database.
#[async_trait]
pub(crate) trait Opener: Send + Sync {
    async fn open(&self, attach: &str, deadline: Instant) -> Result<Session, FbError>;
}

/// The agent's TCP opener (decision 3: loopback, the peer rule).
struct Tcp {
    endpoint: Endpoint,
    password: Zeroizing<String>,
    timeout: Duration,
}

#[async_trait]
impl Opener for Tcp {
    async fn open(&self, attach: &str, deadline: Instant) -> Result<Session, FbError> {
        conn::connect(
            &self.endpoint,
            self.password.as_bytes(),
            attach,
            deadline,
            self.timeout,
        )
        .await
    }
}

fn cov(f: impl FnOnce(&mut ScanCoverage)) -> ScanCoverage {
    let mut c = ScanCoverage::default();
    f(&mut c);
    c
}

fn fail(target: &TargetConfig, e: FbError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        gds = e.gds,
        code = %e.code,
        detail = e.detail.map(crate::error::Detail::as_str),
        "Firebird scan failed"
    );
    e.into_connector_error()
}

fn refused() -> ConnectorError {
    FbError::new(FailureCode::PermissionDenied, Stage::Check).into_connector_error()
}

/// Runs a Discovery scan over TCP.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(FbError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    let password = target.secret.read().map_err(|_| {
        fail(
            target,
            FbError::new(FailureCode::AuthenticationFailed, Stage::Secret),
        )
    })?;
    let endpoint = Endpoint::of(target).map_err(|e| fail(target, e))?;
    let opener = Tcp {
        endpoint,
        password,
        timeout: job.statement_timeout().min(MAX_STATEMENT_TIMEOUT),
    };
    run(job, sink, state, &opener).await
}

/// One database's attachment during the scan.
struct Db<'a> {
    job: &'a ScanJob,
    target: &'a TargetConfig,
    opener: &'a dyn Opener,
    db: &'a FirebirdDatabase,
    tunnel: bool,
    session: Option<Session>,
}

impl Db<'_> {
    fn unit_deadline(&self) -> Instant {
        Instant::now() + self.job.statement_timeout().min(MAX_STATEMENT_TIMEOUT) + UNIT_MARGIN
    }

    /// The prepared session, opened again if it was closed or broken.
    async fn session(&mut self) -> Result<&mut Session, FbError> {
        if self.session.as_ref().is_some_and(Session::is_broken)
            && let Some(s) = self.session.take()
        {
            s.close().await;
        }
        if self.session.is_none() {
            let deadline = self.unit_deadline();
            let mut s = self.opener.open(&self.db.attach, deadline).await?;
            if let Err(e) = check::prepare(&mut s, self.tunnel, deadline).await {
                s.close().await;
                return Err(e);
            }
            if let Err(e) = s.commit(deadline).await {
                s.close().await;
                return Err(e);
            }
            self.session = Some(s);
        }
        self.session
            .as_mut()
            .ok_or(FbError::new(FailureCode::Internal, Stage::Check))
    }

    /// Detaches before a long pause (decision 5).
    async fn before_pause(&mut self) {
        if self.job.pacer().debt() >= CLOSE_BEFORE_PAUSE
            && let Some(s) = self.session.take()
        {
            s.close().await;
        }
    }

    async fn close(&mut self) {
        if let Some(s) = self.session.take() {
            s.close().await;
        }
    }

    /// Commits a unit's transaction; on a failure the session is closed
    /// (review N2): the transaction handle is spent by the attempt, so
    /// whether the server ended it is unknown, and none may survive into
    /// the next pause.
    async fn commit(&mut self, deadline: Instant) -> Result<(), FbError> {
        let result = self.session().await?.commit(deadline).await;
        if result.is_err() {
            self.close().await;
        }
        result
    }

    /// After a unit's failure: the session ends when the failure left it
    /// unusable; otherwise the unit's transaction is ended, so that none
    /// spans the next pause (decision 4).
    async fn after(&mut self, e: &FbError) {
        let ended = match self.session.as_mut() {
            Some(s) if !e.fatal && !s.is_broken() => {
                let deadline = Instant::now() + UNIT_MARGIN;
                s.commit(deadline).await.is_ok()
            }
            _ => false,
        };
        if !ended {
            self.close().await;
        }
    }
}

/// Runs a Discovery scan with `opener`.
pub(crate) async fn run(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
    opener: &dyn Opener,
) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(FbError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    let Some(settings) = target.firebird_settings() else {
        return Err(FbError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    if job.out_of_time() {
        job.skip_out_of_time(sink, 1);
        return Ok(());
    }
    let mut dbs: Vec<&FirebirdDatabase> = settings
        .databases
        .iter()
        .filter(|d| job.includes_database(&d.name))
        .collect();
    job.rotate(&mut dbs);
    let mut eval = Evaluation::default();
    for (i, db) in dbs.iter().enumerate() {
        if job.turn().await? == Paced::OutOfTime {
            job.skip_out_of_time(sink, dbs.len() - i);
            break;
        }
        let dbn = normalize(&db.name);
        // R9: a database the last check excluded as its own security
        // database (or not shown not to be one) is not scanned; the other
        // databases are.
        if state.excluded(&target.id, &db.attach) {
            tracing::warn!(target_id = %target.id, database = dbn.as_str(), "database excluded from Discovery (coverage.security_database_excluded)");
            continue;
        }
        job.begin_database(dbn.as_str());
        let mut d = Db {
            job,
            target,
            opener,
            db,
            tunnel: settings.tunnel,
            session: None,
        };
        // Unit 1: the attachment, the refusal list, the catalog.
        let first = job
            .paced(async {
                let deadline = d.unit_deadline();
                let mut s = opener.open(&db.attach, deadline).await?;
                // R9 rules 1 and 2 before any probe (rule 3 is the check's,
                // where Audit reads `databases.conf`).
                let read = check::attached(
                    &mut s,
                    settings.tunnel,
                    settings.extended_grants,
                    &db.attach,
                    None,
                    deadline,
                )
                .await;
                match read {
                    Ok(r) => {
                        d.session = Some(s);
                        Ok(r)
                    }
                    Err(e) => {
                        s.close().await;
                        Err(e)
                    }
                }
            })
            .await?;
        let (facts, read) = match first {
            Paced::OutOfTime => {
                d.close().await;
                job.skip_out_of_time(sink, dbs.len() - i);
                break;
            }
            Paced::Done(Ok(check::Attached::Checked { facts, read, .. })) => (facts, read),
            Paced::Done(Ok(check::Attached::Excluded { reason, .. })) => {
                d.close().await;
                tracing::warn!(target_id = %target.id, database = dbn.as_str(), reason, "database excluded from Discovery (coverage.security_database_excluded)");
                continue;
            }
            Paced::Done(Err(e)) => {
                d.close().await;
                // The attachment itself failed (unknown database, refused):
                // this database is skipped; the transport or the
                // authentication failing ends the scan.
                if matches!(e.stage, Stage::SessionSetup) || !e.fatal {
                    sink.add_coverage(cov(|c| c.error = 1));
                    tracing::warn!(target_id = %target.id, database = dbn.as_str(), stage = e.stage.as_str(), gds = e.gds, code = %e.code, "database skipped");
                    continue;
                }
                return Err(fail(target, e));
            }
        };
        eval.add(&facts.facts);
        if eval.blocks() {
            d.close().await;
            state.set_blocked(&target.id, true);
            tracing::warn!(
                target_id = %target.id,
                "the account holds a right of the refusal list, or the list could not be \
                 evaluated (privilege.refused / privilege.not_evaluated): Discovery refused \
                 (ADR-0060 open question 4)"
            );
            return Err(refused());
        }
        let done = database(&mut d, sink, &read, &dbn).await;
        d.close().await;
        match done? {
            Next::Continue => {}
            Next::OutOfTime(left) => {
                job.skip_out_of_time(sink, left + (dbs.len() - i - 1));
                break;
            }
        }
    }
    Ok(())
}

/// Whether the scan goes on after a database.
enum Next {
    Continue,
    /// Out of time, with this many objects of the database left.
    OutOfTime(usize),
}

/// A table to sample, with its columns.
struct Table<'c> {
    name: &'c str,
    columns: Vec<&'c catalog::Column>,
    kind: Option<StoreKind>,
}

async fn database(
    d: &mut Db<'_>,
    sink: &FindingSink,
    read: &Catalog,
    dbn: &NormalizedName,
) -> Result<Next, ConnectorError> {
    let job = d.job;
    let target = d.target;
    let Some(relations) = &read.relations else {
        sink.add_coverage(cov(|c| c.error = 1));
        tracing::warn!(target_id = %target.id, database = dbn.as_str(), "relation list not read: database skipped");
        return Ok(Next::Continue);
    };
    if read.relations_cut {
        sink.add_coverage(cov(|c| c.limit = 1));
    }
    if read.relations_dropped > 0 {
        // Review L3: only these relations are lost, never the list; their
        // names are not logged (not UTF-8 or not quotable).
        let n = read.relations_dropped;
        sink.add_coverage(cov(|c| c.error = n));
        tracing::warn!(target_id = %target.id, database = dbn.as_str(), relations = n, "relations with a name that is not UTF-8 or cannot be quoted: not sampled");
    }
    let mut tables: Vec<&catalog::Relation> = Vec::new();
    let (mut views, mut temporary, mut prefixed) = (0u64, 0u64, 0u64);
    for r in relations {
        if !job.includes_object(&r.name) {
            continue;
        }
        match r.kind {
            Kind::View => views += 1,
            Kind::External => sink.add_coverage(cov(|c| c.remote = 1)),
            Kind::Temporary => temporary += 1,
            Kind::Other => sink.add_coverage(cov(|c| c.unsupported = 1)),
            Kind::Table if catalog::never_sampled(&r.name) => {
                sink.add_coverage(cov(|c| c.unsupported = 1));
                tracing::info!(target_id = %target.id, database = dbn.as_str(), object = normalize(&r.name).as_str(), "user relation named like a system or credential relation: never sampled (ADR-0060 decision 5)");
            }
            Kind::Table => {
                if catalog::system_prefixed(&r.name) {
                    prefixed += 1;
                }
                tables.push(r);
            }
        }
    }
    if views + temporary + prefixed > 0 {
        tracing::info!(target_id = %target.id, database = dbn.as_str(), views, temporary, system_prefixed = prefixed, "relations not sampled (views, global temporary tables); user tables named with a system prefix sampled");
    }
    job.rotate(&mut tables);
    for (j, r) in tables.iter().enumerate() {
        d.before_pause().await;
        if job.turn().await? == Paced::OutOfTime {
            return Ok(Next::OutOfTime(tables.len() - j));
        }
        let object = normalize(&r.name);
        if !r.readable {
            sink.add_coverage(cov(|c| c.not_readable = 1));
            continue;
        }
        let columns = match read.columns_of(&r.name) {
            Ok(c) => c,
            Err(catalog::Missing::Cut) => {
                sink.add_coverage(cov(|c| c.limit = 1));
                continue;
            }
            Err(catalog::Missing::Error) => {
                sink.add_coverage(cov(|c| c.error = 1));
                tracing::warn!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), "column list not read, or a column name that is not UTF-8 or cannot be quoted: table not sampled");
                continue;
            }
        };
        let names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
        let table = Table {
            name: &r.name,
            kind: cas_guard::recognize(job.cas_stores(), [r.name.as_str()], names.iter().copied()),
            columns,
        };
        if table.kind == Some(StoreKind::TicketRegistry) {
            match tickets(d, &table).await? {
                Some(Paced::OutOfTime) => return Ok(Next::OutOfTime(tables.len() - j)),
                Some(Paced::Done(())) | None => {}
            }
            sink.add_coverage(cov(|c| c.unsupported = 1));
            tracing::info!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), "CAS ticket registry: not sampled (CAS store guard, metadata only)");
            continue;
        }
        match sample_table(d, sink, &table, dbn, &object).await? {
            Paced::Done(()) => {}
            Paced::OutOfTime => return Ok(Next::OutOfTime(tables.len() - j)),
        }
    }
    Ok(Next::Continue)
}

/// The ticket registry's type counts (ADR-0041 decision 6), as its own
/// paced unit; `None` without a `type` column.
async fn tickets(d: &mut Db<'_>, table: &Table<'_>) -> Result<Option<Paced<()>>, ConnectorError> {
    let job = d.job;
    let Some(column) = table
        .columns
        .iter()
        .find(|c| cas_guard::name_key(&c.name) == "type")
    else {
        return Ok(None);
    };
    let Some(stmt) = sql::ticket_type_counts(table.name, &column.name) else {
        return Ok(None);
    };
    let out = job
        .paced(async {
            let deadline = d.unit_deadline();
            let s = d.session().await?;
            let rows = s
                .query_built(
                    &stmt,
                    &[Col::Text(1020), Col::Int],
                    MAX_TICKET_TYPES,
                    deadline,
                )
                .await;
            let rows = match rows {
                Ok(r) => r,
                Err(e) => {
                    d.after(&e).await;
                    return Err(e);
                }
            };
            d.commit(deadline).await?;
            let mut counts = TicketCounts::default();
            for r in &rows.rows {
                let kind = r.first().and_then(Value::as_text).unwrap_or_default();
                let n = r.get(1).and_then(Value::as_int).unwrap_or(0);
                counts.add(kind, u64::try_from(n).unwrap_or(0));
            }
            Ok::<_, FbError>(counts)
        })
        .await?;
    Ok(Some(match out {
        Paced::OutOfTime => Paced::OutOfTime,
        Paced::Done(Ok(counts)) => {
            job.record_ticket_registry(&counts);
            Paced::Done(())
        }
        Paced::Done(Err(e)) => {
            tracing::warn!(target_id = %d.target.id, gds = e.gds, code = %e.code, "CAS ticket registry type counts not read");
            if e.stage != Stage::Check {
                return Err(fail(d.target, e));
            }
            Paced::Done(())
        }
    }))
}

/// What one batch of a table gave.
struct Batch {
    values: Vec<Vec<RawValue>>,
    stopped: bool,
}

/// Samples one table, batch by batch, then classifies and submits.
async fn sample_table(
    d: &mut Db<'_>,
    sink: &FindingSink,
    table: &Table<'_>,
    dbn: &NormalizedName,
    object: &NormalizedName,
) -> Result<Paced<()>, ConnectorError> {
    let job = d.job;
    let target = d.target;
    let mut selected: Vec<(usize, Conv)> = Vec::new();
    let mut unsampled = 0u64;
    for (i, c) in table.columns.iter().enumerate() {
        if cas_guard::column_rule(table.kind, &c.name) == ColumnRule::NeverRead {
            continue;
        }
        match c.conv() {
            Some(conv) => selected.push((i, conv)),
            None => unsampled += 1,
        }
    }
    if unsampled > 0 {
        tracing::info!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), columns = unsampled, "columns not sampled (computed, array, or a type outside the conversion list)");
    }
    if selected.is_empty() {
        sink.add_coverage(cov(|c| c.unsupported = 1));
        return Ok(Paced::Done(()));
    }
    let batches = catalog::batches(&selected);
    let n = job.sample_rows();
    let mut bytes = 0usize;
    let mut findings: Vec<MaskedFinding> = Vec::new();
    let mut stopped = false;
    for (k, batch) in batches.iter().enumerate() {
        if k > 0 {
            d.before_pause().await;
            if job.turn().await? == Paced::OutOfTime {
                return Ok(Paced::OutOfTime);
            }
        }
        let cols: Vec<(&str, Conv)> = batch
            .iter()
            .map(|(i, conv)| (table.columns[*i].name.as_str(), *conv))
            .collect();
        let Some(stmt) = sql::sample_statement(table.name, &cols, n) else {
            sink.add_coverage(cov(|c| c.error = 1));
            return Ok(Paced::Done(()));
        };
        let shape: Vec<Col> = batch.iter().map(|(_, c)| c.shape()).collect();
        let padded: Vec<bool> = batch
            .iter()
            .map(|(i, _)| table.columns[*i].padded())
            .collect();
        let budget = MAX_SAMPLE_BYTES.saturating_sub(bytes);
        let out = job
            .paced(async {
                let deadline = d.unit_deadline();
                let mut values: Vec<Vec<RawValue>> = batch.iter().map(|_| Vec::new()).collect();
                let mut used = 0usize;
                let mut over = false;
                let s = d.session().await?;
                let fetched = s
                    .sample(&stmt, &shape, n as usize, deadline, &mut |row| {
                        for (i, v) in row.into_iter().enumerate() {
                            let len = match &v {
                                Value::Text(t) => t.len(),
                                Value::Bytes(b) => b.len(),
                                _ => 0,
                            };
                            used = used.saturating_add(len + VALUE_OVERHEAD);
                            if used > budget {
                                over = true;
                                return Flow::Stop;
                            }
                            let (Some(conv), Some(col)) = (batch.get(i), values.get_mut(i)) else {
                                continue;
                            };
                            if let Some(text) = catalog::value_text(
                                v,
                                conv.1,
                                padded.get(i).copied().unwrap_or(false),
                            ) {
                                col.push(RawValue::new(text));
                            }
                        }
                        Flow::Continue
                    })
                    .await;
                match fetched {
                    Ok(f) => {
                        d.commit(deadline).await?;
                        Ok((
                            Batch {
                                values,
                                stopped: over || f.stopped,
                            },
                            used,
                        ))
                    }
                    Err(e) => {
                        d.after(&e).await;
                        Err(e)
                    }
                }
            })
            .await?;
        match out {
            Paced::OutOfTime => return Ok(Paced::OutOfTime),
            Paced::Done(Ok((b, used))) => {
                bytes = bytes.saturating_add(used);
                stopped |= b.stopped;
                for ((i, _), values) in batch.iter().zip(b.values) {
                    let column = &table.columns[*i];
                    let samples: Vec<RawSample<'_>> =
                        values.iter().map(RawValue::as_sample).collect();
                    let rule = cas_guard::column_rule(table.kind, &column.name);
                    for f in job.classify_guarded(&column.name, &samples, rule) {
                        findings.push(f.into_finding(FindingLocation {
                            database: dbn.clone(),
                            schema: None,
                            object: object.clone(),
                            field: normalize(&column.name),
                        }));
                    }
                }
                if stopped {
                    break;
                }
            }
            Paced::Done(Err(e)) => {
                let types: Vec<String> = batch
                    .iter()
                    .map(|(i, _)| {
                        let c = table.columns[*i];
                        format!("{}/{}/{}", c.field_type, c.sub_type, c.charset)
                    })
                    .collect();
                tracing::warn!(target_id = %target.id, database = dbn.as_str(), object = object.as_str(), stage = e.stage.as_str(), gds = e.gds, code = %e.code, column_types = %types.join(","), "object skipped");
                // The session could not be opened again: the transport or
                // the authentication fails, the scan ends.
                if e.stage != Stage::Check {
                    return Err(fail(target, e));
                }
                sink.add_coverage(cov(|c| {
                    if e.code == FailureCode::PermissionDenied {
                        c.not_readable = 1;
                    } else {
                        c.error = 1;
                    }
                }));
                return Ok(Paced::Done(()));
            }
        }
    }
    sink.add_coverage(cov(|c| {
        c.sampled = 1;
        c.limit = u64::from(stopped);
    }));
    for f in findings {
        sink.submit(f).await?;
    }
    Ok(Paced::Done(()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::{Arc, Mutex};

    use databastion_classifiers::masking::HmacKey;
    use databastion_core::config::Limits;
    use databastion_core::{ScanJob, ScanParams};

    use super::*;
    use crate::fake::{self, Canned, Script, int_col, text_col};
    use crate::sql::{Column as Described, charset, sqltype};
    use crate::wire;

    fn bool_col() -> Described {
        Described {
            sqltype: sqltype::BOOLEAN,
            sub_type: 0,
            scale: 0,
            length: 1,
        }
    }

    fn octets_col(len: u32) -> Described {
        Described {
            sqltype: sqltype::VARYING,
            sub_type: charset::OCTETS,
            scale: 0,
            length: len,
        }
    }

    fn v(s: &str) -> Value {
        Value::Text(Zeroizing::new(s.to_owned()))
    }

    fn canned(text: &str, columns: Vec<Described>, rows: Vec<Vec<Value>>) -> Canned {
        Canned {
            text: Box::leak(text.to_owned().into_boxed_str()),
            columns,
            rows,
            error: None,
        }
    }

    /// What `check::prepare` and the privilege reads of the minimal account
    /// see (decision 4), as the 5.0.4 server answers them.
    fn session_statements(user: &str) -> Vec<Canned> {
        vec![
            canned(sql::VERSION, vec![text_col(128)], vec![vec![v("5.0.4")]]),
            canned(
                sql::SESSION,
                vec![text_col(32), text_col(252), text_col(32), text_col(124)],
                vec![vec![
                    v("TRUE"),
                    v("ChaCha64"),
                    v("TRUE"),
                    v("READ COMMITTED"),
                ]],
            ),
            canned(
                sql::OWN_ATTACHMENT,
                vec![int_col(), text_col(64), text_col(1020), int_col()],
                vec![vec![
                    Value::Int(7),
                    v("TCPv4"),
                    v("127.0.0.1/1"),
                    Value::Int(1),
                ]],
            ),
            canned(sql::IDLE_TIMEOUT, vec![], vec![]),
            canned(
                sql::DATABASE_FILE,
                vec![text_col(4080), text_col(28)],
                vec![vec![v("/var/lib/firebird/data/app.fdb"), v("Default")]],
            ),
            canned(
                sql::IDENTITY,
                vec![
                    text_col(252),
                    text_col(252),
                    bool_col(),
                    text_col(252),
                    int_col(),
                ],
                vec![vec![
                    v(user),
                    v("NONE"),
                    Value::Bool(false),
                    v("SYSDBA"),
                    Value::Int(0),
                ]],
            ),
            canned(
                sql::SYSTEM_PRIVILEGES_4,
                vec![bool_col(); 26],
                vec![vec![Value::Bool(false); 26]],
            ),
            canned(
                sql::SYSTEM_PRIVILEGES_5,
                vec![bool_col()],
                vec![vec![Value::Bool(false)]],
            ),
            canned(
                sql::ROLE_MEMBERSHIPS,
                vec![text_col(252), int_col(), text_col(252), int_col()],
                vec![vec![
                    v(user),
                    Value::Int(8),
                    v("DATABASTION_READER"),
                    Value::Int(0),
                ]],
            ),
            canned(
                sql::ROLE_PRIVILEGES,
                vec![text_col(252), octets_col(8)],
                vec![vec![
                    v("DATABASTION_READER"),
                    Value::Bytes(Zeroizing::new(vec![0; 8])),
                ]],
            ),
            canned(
                sql::OBJECT_GRANTS,
                vec![
                    text_col(252),
                    int_col(),
                    text_col(24),
                    int_col(),
                    text_col(252),
                    int_col(),
                    bool_col(),
                    int_col(),
                ],
                vec![],
            ),
            canned(
                sql::AUTH_MAPPINGS,
                vec![
                    text_col(16),
                    text_col(252),
                    text_col(252),
                    bool_col(),
                    int_col(),
                    text_col(252),
                ],
                vec![],
            ),
            canned(
                sql::GLOBAL_AUTH_MAPPINGS,
                vec![
                    text_col(16),
                    text_col(252),
                    text_col(252),
                    bool_col(),
                    int_col(),
                    text_col(252),
                ],
                vec![],
            ),
            canned(
                sql::OWNED_OBJECTS,
                vec![int_col()],
                vec![vec![Value::Int(0)]],
            ),
            canned(
                sql::DATABASE_TRIGGERS,
                vec![int_col(), int_col()],
                vec![vec![Value::Int(0), Value::Int(0)]],
            ),
            canned(sql::CREDENTIAL_RELATIONS, vec![text_col(252)], vec![]),
        ]
    }

    /// A catalog name as the server sends it: raw bytes, padded with
    /// spaces as a `CHAR(63)`.
    fn nb(name: &str) -> Value {
        let mut b = name.as_bytes().to_vec();
        b.resize(b.len().max(63), b' ');
        Value::Bytes(Zeroizing::new(b))
    }

    fn relation(name: &str, kind: i64, view: bool, external: bool, readable: bool) -> Vec<Value> {
        vec![
            nb(name),
            Value::Int(kind),
            Value::Bool(view),
            Value::Bool(external),
            Value::Bool(readable),
        ]
    }

    fn column(
        rel: &str,
        name: &str,
        pos: i64,
        ft: i64,
        sub: i64,
        cs: i64,
        computed: bool,
    ) -> Vec<Value> {
        vec![
            nb(rel),
            nb(name),
            Value::Int(pos),
            Value::Int(ft),
            Value::Int(sub),
            Value::Int(0),
            Value::Int(100),
            Value::Int(cs),
            Value::Bool(false),
            Value::Bool(computed),
        ]
    }

    fn catalog_statements(relations: Vec<Vec<Value>>, columns: Vec<Vec<Value>>) -> Vec<Canned> {
        vec![
            canned(
                sql::RELATIONS,
                vec![
                    octets_col(252),
                    int_col(),
                    bool_col(),
                    bool_col(),
                    bool_col(),
                ],
                relations,
            ),
            canned(
                sql::COLUMNS,
                vec![
                    octets_col(252),
                    octets_col(252),
                    int_col(),
                    int_col(),
                    int_col(),
                    int_col(),
                    int_col(),
                    int_col(),
                    bool_col(),
                    bool_col(),
                ],
                columns,
            ),
        ]
    }

    struct FakeOpener {
        script: Script,
        servers: Mutex<Vec<tokio::task::JoinHandle<fake::Seen>>>,
    }

    #[async_trait]
    impl Opener for FakeOpener {
        async fn open(&self, attach: &str, deadline: Instant) -> Result<Session, FbError> {
            let (client, server) = tokio::io::duplex(1 << 20);
            self.servers
                .lock()
                .unwrap()
                .push(tokio::spawn(fake::serve(server, self.script.clone())));
            conn::handshake(
                Box::new(client),
                fake::LOGIN,
                fake::PASSWORD,
                attach,
                deadline,
                Duration::from_secs(5),
            )
            .await
        }
    }

    impl FakeOpener {
        async fn seen(self) -> Vec<fake::Seen> {
            let handles = std::mem::take(&mut *self.servers.lock().unwrap());
            let mut out = Vec::new();
            for h in handles {
                out.push(h.await.unwrap());
            }
            out
        }

        async fn prepared(self) -> Vec<String> {
            let handles = std::mem::take(&mut *self.servers.lock().unwrap());
            let mut out = Vec::new();
            for h in handles {
                out.extend(h.await.unwrap().prepared);
            }
            out
        }
    }

    fn job(sample_rows: u32) -> ScanJob {
        let t = databastion_core::AgentConfig::parse(
            "{console: {url: \"https://c.example\"}, state_dir: /s, targets: [{id: t, \
             engine: firebird, host: 127.0.0.1, port: 9, account: AGENT, \
             secret: {env: DATABASTION_TEST_UNSET_FIREBIRD_SECRET}, firebird: {peer_uid: 84, \
             tunnel: true, databases: [{name: crm, attach: crm}]}}]}",
        )
        .unwrap()
        .targets
        .remove(0);
        let limits = Limits {
            discovery_duty_cycle_percent: 100,
            max_sample_rows: sample_rows,
            ..Limits::default()
        };
        ScanJob::new(
            ScanParams::contract_defaults(),
            &t,
            &limits,
            Arc::new(HmacKey::new(&[7u8; 32]).unwrap()),
        )
    }

    const EMAILS: [&str; 3] = [
        "jean.martin@example.org",
        "lea.durand@example.net",
        "hugo.petit@example.com",
    ];

    /// Review N2: a commit that fails after a successful fetch ends the
    /// session, so that no server transaction survives into a pause.
    #[tokio::test]
    async fn a_failed_commit_after_a_fetch_closes_the_session() {
        let mut statements = session_statements("AGENT");
        statements.extend(catalog_statements(
            vec![
                relation("A", 0, false, false, true),
                relation("B", 0, false, false, true),
            ],
            vec![
                column("A", "EMAIL", 0, 37, 0, 4, false),
                column("B", "EMAIL", 0, 37, 0, 4, false),
            ],
        ));
        let a = sql::sample_statement("A", &[("EMAIL", Conv::Text)], 3).unwrap();
        let b = sql::sample_statement("B", &[("EMAIL", Conv::Text)], 3).unwrap();
        for stmt in [&a, &b] {
            statements.push(canned(
                stmt.text(),
                vec![text_col(16_000)],
                EMAILS.iter().map(|e| vec![v(e)]).collect(),
            ));
        }
        let opener = FakeOpener {
            script: Script {
                statements,
                fail_commit_after: Some(Box::leak(a.text().to_owned().into_boxed_str())),
                ..Script::default()
            },
            servers: Mutex::default(),
        };
        let job = job(3);
        let (sink, _rx) = FindingSink::channel(64);
        let state = CheckState::default();
        run(&job, &sink, &state, &opener).await.unwrap();
        let cov = sink.coverage_for_tests().unwrap();
        let seen = opener.seen().await;
        let with_a: Vec<&fake::Seen> = seen
            .iter()
            .filter(|s| s.prepared.iter().any(|t| t == a.text()))
            .collect();
        assert_eq!(with_a.len(), 1);
        let ops = &with_a[0].ops;
        let commit = ops.iter().rposition(|&o| o == wire::op::COMMIT).unwrap();
        assert!(
            ops[commit..].contains(&wire::op::DETACH),
            "the session was not closed after the failed commit: {ops:?}"
        );
        assert!(
            !with_a[0].prepared.iter().any(|t| t == b.text()),
            "B was read in the session whose commit failed"
        );
        // B is read in a new session.
        assert!(
            seen.iter()
                .any(|s| s.prepared.iter().any(|t| t == b.text()))
        );
        assert_eq!(cov.sampled + cov.error, 2, "{cov:?}");
    }

    #[tokio::test]
    async fn a_hostile_name_skips_its_relation_not_the_database() {
        let hostile = || Value::Bytes(Zeroizing::new(vec![b'T', 0xC3, 0x28, b' ', b' ']));
        let mut statements = session_statements("AGENT");
        let mut bad_rel = relation("X", 0, false, false, true);
        bad_rel[0] = hostile();
        let mut bad_col_rel = column("HALF", "X", 0, 37, 0, 4, false);
        bad_col_rel[0] = hostile();
        let mut bad_col = column("HALF", "X", 1, 37, 0, 4, false);
        bad_col[1] = Value::Bytes(Zeroizing::new(vec![0xff]));
        statements.extend(catalog_statements(
            vec![
                relation("CUSTOMERS", 0, false, false, true),
                relation("HALF", 0, false, false, true),
                bad_rel,
            ],
            vec![
                column("CUSTOMERS", "EMAIL", 0, 37, 0, 4, false),
                column("HALF", "EMAIL", 0, 37, 0, 4, false),
                bad_col,
                bad_col_rel,
            ],
        ));
        let sample = sql::sample_statement("CUSTOMERS", &[("EMAIL", Conv::Text)], 3).unwrap();
        statements.push(canned(
            sample.text(),
            vec![text_col(16_000)],
            EMAILS.iter().map(|e| vec![v(e)]).collect(),
        ));
        let opener = FakeOpener {
            script: Script {
                statements,
                ..Script::default()
            },
            servers: Mutex::default(),
        };
        let job = job(3);
        let (sink, mut rx) = FindingSink::channel(64);
        let state = CheckState::default();
        run(&job, &sink, &state, &opener).await.unwrap();
        let cov = sink.coverage_for_tests().unwrap();
        drop(sink);
        let mut findings = Vec::new();
        while let Some(f) = rx.recv().await {
            findings.push(f);
        }
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].location().unwrap().object.as_str(), "CUSTOMERS");
        assert_eq!(cov.sampled, 1);
        // The hostile relation, and HALF (a column row dropped).
        assert_eq!(cov.error, 2);
        let prepared = opener.prepared().await;
        assert!(
            !prepared.iter().any(|t| t.contains("\"HALF\"")),
            "HALF was read"
        );
    }

    #[tokio::test]
    async fn samples_readable_tables_and_never_the_others() {
        let mut statements = session_statements("AGENT");
        statements.extend(catalog_statements(
            vec![
                relation("CASTICKETS", 0, false, false, true),
                relation("Customers Mixed", 0, false, false, true),
                relation("EXT_EXPORT", 2, false, true, true),
                relation("GTT_SESSION", 4, false, false, true),
                relation("NOGRANT", 0, false, false, false),
                relation("PLG$SRP", 0, false, false, true),
                relation("V_CUSTOMERS", 1, true, false, true),
            ],
            vec![
                column("CASTICKETS", "ID", 0, 37, 0, 4, false),
                column("CASTICKETS", "TYPE", 1, 37, 0, 4, false),
                column("Customers Mixed", "E-Mail", 0, 37, 0, 4, false),
                column("Customers Mixed", "LOUD", 1, 37, 0, 4, true),
                column("Customers Mixed", "FLAG", 2, 23, 0, -1, false),
                column("Customers Mixed", "RAW", 3, 37, 0, 0, false),
                column("NOGRANT", "SECRET", 0, 37, 0, 4, false),
                column("PLG$SRP", "PLG$VERIFIER", 0, 37, 0, 4, false),
            ],
        ));
        let sample = sql::sample_statement(
            "Customers Mixed",
            &[("E-Mail", Conv::Text), ("RAW", Conv::Octets)],
            3,
        )
        .unwrap();
        let tickets = sql::ticket_type_counts("CASTICKETS", "TYPE").unwrap();
        statements.push(canned(
            sample.text(),
            vec![text_col(16_000), octets_col(4_000)],
            EMAILS
                .iter()
                .map(|e| vec![v(e), Value::Bytes(Zeroizing::new(vec![0xff, 0x01]))])
                .collect(),
        ));
        statements.push(canned(
            tickets.text(),
            vec![text_col(1020), int_col()],
            vec![vec![
                v("org.apereo.cas.ticket.TicketGrantingTicketImpl"),
                Value::Int(2),
            ]],
        ));
        let opener = FakeOpener {
            script: Script {
                statements,
                ..Script::default()
            },
            servers: Mutex::default(),
        };
        let job = job(3);
        let (sink, mut rx) = FindingSink::channel(64);
        let state = CheckState::default();
        run(&job, &sink, &state, &opener).await.unwrap();
        let cov = sink.coverage_for_tests().unwrap();
        drop(sink);
        let mut findings = Vec::new();
        while let Some(f) = rx.recv().await {
            findings.push(f);
        }
        // The e-mail column only (the octets were not UTF-8).
        assert_eq!(findings.len(), 1, "{findings:?}");
        let loc = findings[0].location().unwrap();
        assert_eq!(loc.database.as_str(), "crm");
        assert!(loc.schema.is_none());
        assert_eq!(loc.object.as_str(), "Customers Mixed");
        assert_eq!(loc.field.as_str(), "E-Mail");
        assert_eq!(findings[0].classifier().as_str(), "pii.email");
        for s in findings[0].masked_samples() {
            for e in EMAILS {
                assert!(!format!("{s:?}").contains(e));
            }
        }
        assert_eq!(cov.sampled, 1);
        assert_eq!(cov.not_readable, 1, "NOGRANT");
        assert_eq!(cov.remote, 1, "EXT_EXPORT");
        // PLG$SRP and the ticket registry.
        assert_eq!(cov.unsupported, 2);
        assert_eq!(cov.error, 0);
        assert_eq!(job.cas_guard().registries(), 1);
        let prepared = opener.prepared().await;
        for name in [
            "NOGRANT",
            "PLG$SRP",
            "EXT_EXPORT",
            "GTT_SESSION",
            "V_CUSTOMERS",
            "LOUD",
            "FLAG",
        ] {
            assert!(
                !prepared.iter().any(|t| t.contains(&format!("\"{name}\""))),
                "{name} was read"
            );
        }
        assert!(prepared.iter().any(|t| t == tickets.text()));
        assert!(
            !prepared.iter().any(|t| t.contains("\"ID\"")),
            "a ticket id was read"
        );
    }

    #[tokio::test]
    async fn a_refused_account_samples_nothing() {
        let mut statements = session_statements("SYSDBA");
        statements.extend(catalog_statements(
            vec![relation("CUSTOMERS", 0, false, false, true)],
            vec![column("CUSTOMERS", "EMAIL", 0, 37, 0, 4, false)],
        ));
        let opener = FakeOpener {
            script: Script {
                statements,
                ..Script::default()
            },
            servers: Mutex::default(),
        };
        let job = job(3);
        let (sink, _rx) = FindingSink::channel(8);
        let state = CheckState::default();
        state.set_blocked("t", false);
        let e = run(&job, &sink, &state, &opener).await.unwrap_err();
        assert!(matches!(
            e,
            ConnectorError::Target {
                code: FailureCode::PermissionDenied,
                ..
            }
        ));
        assert!(state.blocks("t"));
        let prepared = opener.prepared().await;
        assert!(!prepared.iter().any(|t| t.contains("\"CUSTOMERS\"")));
    }

    #[tokio::test]
    async fn a_conversion_failure_skips_the_table_and_the_budget_stops_the_fetch() {
        let mut statements = session_statements("AGENT");
        statements.extend(catalog_statements(
            vec![
                relation("BAD", 0, false, false, true),
                relation("BIG", 0, false, false, true),
            ],
            std::iter::once(column("BAD", "NOTE", 0, 37, 0, 53, false))
                .chain((0..12).map(|i| column("BIG", &format!("C{i:02}"), i, 37, 0, 4, false)))
                .collect(),
        ));
        let bad = sql::sample_statement("BAD", &[("NOTE", Conv::Text)], 200).unwrap();
        statements.push(Canned {
            error: Some(crate::error::gds::TRANSLITERATION_FAILED),
            ..canned(bad.text(), vec![text_col(16_000)], vec![])
        });
        // 12 text columns: 3 batches of 4, 200 rows of about 15 KB each:
        // past 32 MiB in the third.
        let names: Vec<String> = (0..12).map(|i| format!("C{i:02}")).collect();
        let cols: Vec<(&str, Conv)> = names.iter().map(|n| (n.as_str(), Conv::Text)).collect();
        let value = format!("{}{}", "x".repeat(15_000), "@example.org");
        for batch in cols.chunks(4) {
            let stmt = sql::sample_statement("BIG", batch, 200).unwrap();
            statements.push(canned(
                stmt.text(),
                vec![text_col(16_000); 4],
                (0..200).map(|_| vec![v(&value); 4]).collect(),
            ));
        }
        let opener = FakeOpener {
            script: Script {
                statements,
                ..Script::default()
            },
            servers: Mutex::default(),
        };
        let job = job(200);
        let (sink, _rx) = FindingSink::channel(64);
        let state = CheckState::default();
        run(&job, &sink, &state, &opener).await.unwrap();
        let cov = sink.coverage_for_tests().unwrap();
        assert_eq!(cov.error, 1, "BAD");
        assert_eq!(cov.sampled, 1, "BIG");
        assert_eq!(cov.limit, 1, "BIG stopped at 32 MiB");
    }

    #[test]
    fn names_drop_trailing_spaces_and_values() {
        assert_eq!(normalize("CUSTOMERS   ").as_str(), "CUSTOMERS");
        assert_eq!(normalize(" LEAD").as_str(), " LEAD");
        assert_eq!(normalize("Customers Mixed").as_str(), "Customers Mixed");
        assert!(!normalize("CUSTOMERS ").altered());
        assert_eq!(normalize("EXPORT_jean.martin@example.org").as_str(), "*");
    }
}
