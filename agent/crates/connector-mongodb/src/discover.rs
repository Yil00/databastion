//! Discovery scan: databases and collections in scope, one bounded read
//! per collection, document walk, classification (ADR-0026 decisions 6 to
//! 9).
//!
//! One connection per scan (replaced when it breaks or when idle for
//! [`STALE_AFTER`](crate::conn::STALE_AFTER)). Each collection is read by
//! one command whose reply is parsed whole before anything is submitted:
//! no cursor, server session or transaction is open across
//! `FindingSink::submit().await`. A reply with an open cursor is followed
//! at once by `killCursors`.
//!
//! Sampling (I4): at most `job.sample_rows()` documents per collection,
//! with `$sample` when the collection holds more than 20 times that
//! (random cursor, no scan) and natural order otherwise; every command
//! under `maxTimeMS` from the job's clamped statement timeout.

use databastion_classifiers::masking::{FindingLocation, RawSample};
use databastion_classifiers::names::{
    NormalizedName, PathPart, normalize_field_path, normalize_path,
};
use databastion_core::cas_guard::{self, StoreKind, TicketCounts};
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob};
use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::bson::{DocBuf, Value};
use crate::catalog::{self, CollKind, Collection};
use crate::check::CheckState;
use crate::conn::{Kind, Session, Timeouts};
use crate::error::{MgError, Stage};
use crate::paths::{Collector, Shape, WalkStats};

/// `$sample` is used above this many times the sample size (below, it
/// would scan and sort the whole collection).
pub(crate) const SAMPLE_RATIO: u64 = 20;
/// ... and above this many documents.
pub(crate) const SAMPLE_MIN_DOCUMENTS: u64 = 100;

/// Normalized database name (one key: MongoDB database names have no dot).
pub(crate) fn normalize_database(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

/// Normalized collection name: dots are separators (`fs.files`).
pub(crate) fn normalize_collection(raw: &str) -> NormalizedName {
    normalize_path(raw)
}

/// How a collection is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    /// `aggregate` with `$sample`.
    Sample,
    /// `find` in natural order with `limit`, in a single batch.
    Natural,
    /// `find` with `limit` on a view-backed collection (time-series): the
    /// server turns a `find` on a view into an aggregation, which refuses
    /// `singleBatch` (`InvalidPipelineOperator`, 168); a batch of `n + 1`
    /// exhausts it in the first reply instead.
    NaturalView,
}

/// The read method for a collection of `estimated` documents.
pub(crate) fn method(estimated: Option<u64>, n: u32) -> Method {
    match estimated {
        Some(count) if count > SAMPLE_MIN_DOCUMENTS && count > SAMPLE_RATIO * u64::from(n) => {
            Method::Sample
        }
        _ => Method::Natural,
    }
}

/// Fields of a CAS audit trail document never returned by the server
/// (CAS store guard, ADR-0041 decision 5: ticket ids, request headers with
/// cookies, extra info), excluded by projection.
pub(crate) const AUDIT_EXCLUDED: [&str; 8] = [
    "resourceOperatedUpon",
    "AUD_RESOURCE",
    "headers",
    "AUD_HEADERS",
    "extraInfo",
    "AUD_EXTRA_INFO",
    "clientInfo.headers",
    "clientInfo.extraInfo",
];

fn audit_projection() -> DocBuf {
    AUDIT_EXCLUDED
        .iter()
        .fold(DocBuf::new(), |d, f| d.i32(f, 0))
}

/// The read command of one collection (tests: the scan uses
/// [`read_command_for`]).
#[cfg(test)]
pub(crate) fn read_command(collection: &str, method: Method, n: u32) -> DocBuf {
    read_command_for(collection, method, n, None)
}

/// [`read_command`] for a collection the CAS store guard recognized by
/// name: an audit trail is read without the fields it must never give.
pub(crate) fn read_command_for(
    collection: &str,
    method: Method,
    n: u32,
    kind: Option<StoreKind>,
) -> DocBuf {
    let n = i64::from(n.max(1));
    let audit = kind == Some(StoreKind::AuditTrail);
    let find = |d: DocBuf| {
        if audit {
            d.doc("projection", audit_projection())
        } else {
            d
        }
    };
    match method {
        Method::Sample => DocBuf::new()
            .str("aggregate", collection)
            .array("pipeline", {
                let mut stages = vec![DocBuf::new().doc("$sample", DocBuf::new().i64("size", n))];
                if audit {
                    stages.push(DocBuf::new().doc("$project", audit_projection()));
                }
                stages
            })
            // One more than the sample: the pipeline is exhausted in the
            // first reply, so the server closes the cursor.
            .doc("cursor", DocBuf::new().i64("batchSize", n + 1))
            .bool("allowDiskUse", false),
        Method::Natural => find(
            DocBuf::new()
                .str("find", collection)
                .doc("filter", DocBuf::new()),
        )
        .i64("limit", n)
        .i64("batchSize", n)
        .bool("singleBatch", true),
        Method::NaturalView => find(
            DocBuf::new()
                .str("find", collection)
                .doc("filter", DocBuf::new()),
        )
        .i64("limit", n)
        .i64("batchSize", n + 1),
    }
}

/// Most `type` values read from a ticket registry collection.
const MAX_TICKET_TYPES: i64 = 256;

/// The ticket type field of a ticket registry: `type` in any ASCII case
/// among the keys probed (PR #141 review L5), else `type`. Only letters,
/// so the `$` path built from it is a plain field path.
pub(crate) fn ticket_type_field(keys: &[String]) -> &str {
    keys.iter()
        .map(String::as_str)
        .find(|k| *k == "type")
        .or_else(|| {
            keys.iter()
                .map(String::as_str)
                .find(|k| k.eq_ignore_ascii_case("type"))
        })
        .unwrap_or("type")
}

/// The CAS store guard's only read of a ticket registry collection
/// (ADR-0041 decision 5): `$group` on the type field (`type`, any case)
/// with a count, nothing else.
pub(crate) fn ticket_types_command(collection: &str, type_field: &str) -> DocBuf {
    DocBuf::new()
        .str("aggregate", collection)
        .array(
            "pipeline",
            vec![
                DocBuf::new().doc(
                    "$group",
                    DocBuf::new()
                        .str("_id", &format!("${type_field}"))
                        .doc("n", DocBuf::new().i32("$sum", 1)),
                ),
                DocBuf::new().i64("$limit", MAX_TICKET_TYPES),
            ],
        )
        .doc(
            "cursor",
            DocBuf::new().i64("batchSize", MAX_TICKET_TYPES + 1),
        )
        .bool("allowDiskUse", false)
}

/// Runs [`ticket_types_command`]: ticket counts per `type`. An open
/// cursor in the reply is killed.
pub(crate) async fn ticket_metadata<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    collection: &str,
    type_field: &str,
) -> Result<TicketCounts, MgError> {
    let reply = session
        .command(
            Stage::Sample,
            db,
            ticket_types_command(collection, type_field),
            Kind::Read,
        )
        .await?;
    let bad = |_| non_fatal(FailureCode::Internal);
    let (cursor_id, counts) = {
        let doc = reply.doc();
        let cursor = doc.doc("cursor").ok().flatten();
        let cursor_id = cursor.and_then(|c| c.int("id").ok().flatten()).unwrap_or(0);
        let counts = (|| {
            let batch = cursor
                .ok_or(non_fatal(FailureCode::Internal))?
                .array("firstBatch")
                .map_err(bad)?
                .ok_or(non_fatal(FailureCode::Internal))?;
            let mut counts = TicketCounts::default();
            for element in batch.iter() {
                let (_, Value::Doc(group)) = element.map_err(bad)? else {
                    return Err(non_fatal(FailureCode::Internal));
                };
                // A `type` that is not a string (or absent) counts as an
                // unknown kind stored in clear.
                let kind = group.str("_id").ok().flatten().unwrap_or("");
                let n = group.int("n").map_err(bad)?.unwrap_or(0);
                counts.add(kind, u64::try_from(n).unwrap_or(0));
            }
            Ok(counts)
        })();
        (cursor_id, counts)
    };
    drop(reply);
    if cursor_id != 0 {
        session.kill_cursor(db, collection, cursor_id).await;
    }
    counts
}

/// The CAS store guard's key probe of a collection (PR #141 review L4):
/// the top-level field **names** of one random document, never a value
/// (`$objectToArray` mapped to its keys), read before any document so a
/// renamed ticket registry or audit trail is recognized by its shape
/// first.
pub(crate) fn key_probe_command(collection: &str) -> DocBuf {
    DocBuf::new()
        .str("aggregate", collection)
        .array(
            "pipeline",
            vec![
                DocBuf::new().doc("$sample", DocBuf::new().i64("size", 1)),
                DocBuf::new().doc(
                    "$project",
                    DocBuf::new().i32("_id", 0).doc(
                        "k",
                        DocBuf::new().doc(
                            "$map",
                            DocBuf::new()
                                .doc("input", DocBuf::new().str("$objectToArray", "$$ROOT"))
                                .str("as", "f")
                                .str("in", "$$f.k"),
                        ),
                    ),
                ),
            ],
        )
        .doc("cursor", DocBuf::new().i64("batchSize", 2))
        .bool("allowDiskUse", false)
}

/// Runs [`key_probe_command`]: at most [`MAX_TOP_KEYS`] field names. An
/// open cursor in the reply is killed.
pub(crate) async fn probe_keys<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    collection: &str,
) -> Result<Vec<String>, MgError> {
    let reply = session
        .command(Stage::Sample, db, key_probe_command(collection), Kind::Read)
        .await?;
    let bad = |_| non_fatal(FailureCode::Internal);
    let (cursor_id, keys) = {
        let doc = reply.doc();
        let cursor = doc.doc("cursor").ok().flatten();
        let cursor_id = cursor.and_then(|c| c.int("id").ok().flatten()).unwrap_or(0);
        let keys = (|| {
            let batch = cursor
                .ok_or(non_fatal(FailureCode::Internal))?
                .array("firstBatch")
                .map_err(bad)?
                .ok_or(non_fatal(FailureCode::Internal))?;
            let mut keys: Vec<String> = Vec::new();
            for element in batch.iter() {
                let (_, Value::Doc(d)) = element.map_err(bad)? else {
                    return Err(non_fatal(FailureCode::Internal));
                };
                let Some(list) = d.array("k").map_err(bad)? else {
                    continue;
                };
                for k in list.iter() {
                    if let (_, Value::Str(k)) = k.map_err(bad)?
                        && keys.len() < MAX_TOP_KEYS
                        && let Ok(k) = std::str::from_utf8(k)
                        && !keys.iter().any(|t| t == k)
                    {
                        keys.push(k.to_owned());
                    }
                }
            }
            Ok(keys)
        })();
        (cursor_id, keys)
    };
    drop(reply);
    if cursor_id != 0 {
        session.kill_cursor(db, collection, cursor_id).await;
    }
    keys
}

/// A sampled collection: the values by normalized path, the estimate.
pub(crate) struct Sampled {
    pub(crate) collector: Collector,
    pub(crate) estimated_rows: Option<u64>,
    pub(crate) method: Method,
    /// Top-level field names of the documents read (at most
    /// [`MAX_TOP_KEYS`]), for the CAS store guard's shape recognition;
    /// only compared, never logged.
    pub(crate) top_keys: Vec<String>,
}

/// Most top-level field names kept per collection.
const MAX_TOP_KEYS: usize = 64;

impl std::fmt::Debug for Sampled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sampled")
            .field("stats", &self.collector.stats)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// `count` without a filter (collection metadata).
async fn count<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    collection: &str,
) -> Result<u64, MgError> {
    let reply = session
        .command(
            Stage::Sample,
            db,
            DocBuf::new().str("count", collection),
            Kind::Read,
        )
        .await?;
    let n = reply
        .doc()
        .int("n")
        .map_err(|_| non_fatal(FailureCode::Internal))?
        .unwrap_or(0);
    Ok(u64::try_from(n).unwrap_or(0))
}

fn non_fatal(code: FailureCode) -> MgError {
    MgError {
        fatal: false,
        ..MgError::new(code, Stage::Sample)
    }
}

/// Reads one collection: `count` (plain collections only: on a
/// time-series collection it would unpack every bucket), then one `find`
/// or `aggregate`, walked into a [`Collector`] of at most `n` values per
/// path. An open cursor in the reply is killed.
#[cfg(test)]
pub(crate) async fn sample_collection<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    collection: &Collection,
    n: u32,
) -> Result<Sampled, MgError> {
    sample_collection_for(session, db, collection, n, None).await
}

/// [`sample_collection`] for a collection the CAS store guard recognized
/// by name (`kind`): an audit trail is read without the fields it must
/// never give ([`read_command_for`]).
pub(crate) async fn sample_collection_for<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    collection: &Collection,
    n: u32,
    kind: Option<StoreKind>,
) -> Result<Sampled, MgError> {
    let estimated_rows = match collection.kind {
        CollKind::Collection => Some(count(session, db, &collection.name).await?),
        _ => None,
    };
    let method = match collection.kind {
        CollKind::Timeseries => Method::NaturalView,
        _ => method(estimated_rows, n),
    };
    let reply = session
        .command(
            Stage::Sample,
            db,
            read_command_for(&collection.name, method, n, kind),
            Kind::Read,
        )
        .await?;
    // The cursor id is read first: whatever happens to the documents, an
    // open cursor is killed before returning (no session id is sent, so
    // closing the connection would not release it).
    let mut top_keys: Vec<String> = Vec::new();
    let (cursor_id, parsed) = {
        let doc = reply.doc();
        let bad = |_| non_fatal(FailureCode::Internal);
        let cursor = doc.doc("cursor").ok().flatten();
        let cursor_id = cursor.and_then(|c| c.int("id").ok().flatten()).unwrap_or(0);
        let parsed = (|| {
            let cursor = cursor.ok_or(non_fatal(FailureCode::Internal))?;
            let batch = cursor
                .array("firstBatch")
                .map_err(bad)?
                .ok_or(non_fatal(FailureCode::Internal))?;
            let mut documents = Vec::new();
            for element in batch.iter() {
                // A server that ignores the limit is not read further.
                if documents.len() >= n as usize {
                    break;
                }
                let (_, value) = element.map_err(bad)?;
                let Value::Doc(document) = value else {
                    return Err(non_fatal(FailureCode::Internal));
                };
                documents.push(document);
            }
            for document in &documents {
                for element in document.iter() {
                    let (key, _) = element.map_err(bad)?;
                    if top_keys.len() < MAX_TOP_KEYS
                        && let Ok(k) = std::str::from_utf8(key)
                        && !top_keys.iter().any(|t| t == k)
                    {
                        top_keys.push(k.to_owned());
                    }
                }
            }
            // First the shape (which object levels are maps keyed by
            // data), then the values.
            let mut collector = Collector::with_shape(n as usize, Shape::learn(&documents));
            for document in documents {
                collector.add_document(document).map_err(bad)?;
            }
            Ok(collector)
        })();
        (cursor_id, parsed)
    };
    drop(reply);
    if cursor_id != 0 {
        session.kill_cursor(db, &collection.name, cursor_id).await;
    }
    Ok(Sampled {
        collector: parsed?,
        estimated_rows,
        method,
        top_keys,
    })
}

/// Makes sure `slot` holds a usable session: a broken or stale one is
/// replaced through `connect`.
async fn ensure<'s, S, F, Fut>(
    slot: &'s mut Option<Session<S>>,
    target: &TargetConfig,
    connect: &mut F,
) -> Result<&'s mut Session<S>, ConnectorError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Session<S>, MgError>>,
{
    if let Some(s) = slot.take() {
        if s.is_broken() {
            drop(s);
        } else if s.is_stale() {
            s.close().await;
        } else {
            return Ok(slot.insert(s));
        }
    }
    let s = connect().await.map_err(|e| fail(target, e))?;
    Ok(slot.insert(s))
}

/// Runs a Discovery scan of the job's target.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let Some(target) = job.target() else {
        return Err(MgError::new(FailureCode::Internal, Stage::Connect).into_connector_error());
    };
    let timeouts = Timeouts::new(job.statement_timeout());
    let outcome = scan(job, sink, target, || Session::connect(target, timeouts)).await?;
    // What the server refused is reported by `check()` (observed, never
    // predicted from the privileges).
    state.record_scan(&target.id, outcome.timeseries_refused);
    state.record_cas_stores(&target.id, outcome.cas_stores);
    Ok(())
}

/// What a scan leaves for `check()`.
#[derive(Debug, Default)]
pub(crate) struct ScanOutcome {
    /// Time-series collections the server refused to the account.
    pub(crate) timeseries_refused: u64,
    /// CAS ticket registries and audit trails recognized (raw database and
    /// collection names, never logged), for the guard's privilege check.
    pub(crate) cas_stores: Vec<(String, String, StoreKind)>,
}

/// The scan, with the way sessions are opened (tests use a scripted
/// server). Returns how many time-series collections the server refused
/// to the account, and the CAS stores it recognized.
pub(crate) async fn scan<S, F, Fut>(
    job: &ScanJob,
    sink: &FindingSink,
    target: &TargetConfig,
    mut connect: F,
) -> Result<ScanOutcome, ConnectorError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Session<S>, MgError>>,
{
    let n = job.sample_rows();
    let mut slot: Option<Session<S>> = None;
    // Paced (ADR-0035 proposed): each listing and each collection's
    // sampling. The pause owed is paid (`turn`) before a session is
    // checked or opened, so a session never goes stale during it.
    if job.turn().await? == Paced::OutOfTime {
        job.skip_out_of_time(sink, 1);
        return Ok(ScanOutcome::default());
    }
    let (databases, truncated) = {
        let s = ensure(&mut slot, target, &mut connect).await?;
        match job.paced(catalog::list_databases(s)).await? {
            Paced::Done(r) => r.map_err(|e| fail(target, e))?,
            Paced::OutOfTime => {
                job.skip_out_of_time(sink, 1);
                return Ok(ScanOutcome::default());
            }
        }
    };
    if truncated {
        tracing::warn!(
            target_id = %target.id,
            limit = catalog::MAX_DATABASES,
            "database listing cut at its limit: the other databases are not covered"
        );
        sink.add_coverage(ScanCoverage {
            limit: 1,
            ..ScanCoverage::default()
        });
    }
    let mut totals = Totals::default();
    let stores = job.cas_stores();
    let mut cas_stores: Vec<(String, String, StoreKind)> = Vec::new();
    let mut selected: Vec<&String> = databases
        .iter()
        .filter(|d| job.includes_database(d))
        .collect();
    // Another starting database and collection at each scan (security
    // review of #93, M3).
    job.rotate(&mut selected);
    for (di, db) in selected.iter().copied().enumerate() {
        let db_name = normalize_database(db);
        if job.turn().await? == Paced::OutOfTime {
            job.skip_out_of_time(sink, selected.len() - di);
            break;
        }
        job.begin_database(db);
        let listed = {
            let s = ensure(&mut slot, target, &mut connect).await?;
            match job.paced(catalog::list_collections(s, db)).await? {
                Paced::Done(l) => l,
                Paced::OutOfTime => {
                    job.skip_out_of_time(sink, selected.len() - di);
                    break;
                }
            }
        };
        let (collections, truncated) = match listed {
            Ok(l) => l,
            Err(e) if !e.fatal => {
                sink.add_coverage(ScanCoverage {
                    error: 1,
                    ..ScanCoverage::default()
                });
                tracing::warn!(
                    target_id = %target.id,
                    database = db_name.as_str(),
                    stage = e.stage.as_str(),
                    server_code = e.server_code,
                    "collections not listed: database skipped"
                );
                continue;
            }
            Err(e) => return Err(fail(target, e)),
        };
        if truncated {
            tracing::warn!(
                target_id = %target.id,
                database = db_name.as_str(),
                limit = catalog::MAX_COLLECTIONS,
                "collection listing cut at its limit: the other collections are not covered"
            );
            sink.add_coverage(ScanCoverage {
                limit: 1,
                ..ScanCoverage::default()
            });
        }
        let mut units = Vec::new();
        let mut unsupported = 0u64;
        for c in collections {
            if !job.includes_object(&c.name) {
                continue;
            }
            match c.kind {
                CollKind::Collection | CollKind::Timeseries => units.push(c),
                CollKind::View | CollKind::Other => {
                    unsupported += 1;
                    tracing::info!(
                        target_id = %target.id,
                        database = db_name.as_str(),
                        object = normalize_collection(&c.name).as_str(),
                        reason = if c.kind == CollKind::View {
                            "view (runs its pipeline)"
                        } else {
                            "collection type not sampled"
                        },
                        "object not sampled"
                    );
                }
            }
        }
        sink.add_coverage(ScanCoverage {
            unsupported,
            ..ScanCoverage::default()
        });
        totals.unsupported += unsupported;
        job.rotate(&mut units);
        let mut out_of_time = false;
        for (i, unit) in units.iter().enumerate() {
            let object = normalize_collection(&unit.name);
            if job.turn().await? == Paced::OutOfTime {
                job.skip_out_of_time(sink, units.len() - i);
                out_of_time = true;
                break;
            }
            // CAS store guard (ADR-0041 decision 5): a ticket registry
            // known by name is never sampled. Otherwise the field names of
            // one document are probed first (PR #141 review L4): a renamed
            // ticket registry or audit trail is recognized by its shape
            // before any document is read. A probe that fails leaves the
            // shape check on the documents read.
            let named = cas_guard::recognize_name(stores, [unit.name.as_str()]);
            let probed = if named == Some(StoreKind::ServiceRegistry) {
                Vec::new()
            } else {
                let s = ensure(&mut slot, target, &mut connect).await?;
                match job.paced(probe_keys(s, db, &unit.name)).await? {
                    Paced::Done(Ok(keys)) => keys,
                    // The session is broken: the collection is skipped, as
                    // a failed read would be.
                    Paced::Done(Err(e)) if e.fatal => {
                        sink.add_coverage(ScanCoverage {
                            error: 1,
                            ..ScanCoverage::default()
                        });
                        totals.skipped += 1;
                        tracing::warn!(
                            target_id = %target.id,
                            database = db_name.as_str(),
                            object = object.as_str(),
                            stage = e.stage.as_str(),
                            server_code = e.server_code,
                            code = %e.code,
                            reason = "key probe failed",
                            "object not covered"
                        );
                        continue;
                    }
                    Paced::Done(Err(_)) => Vec::new(),
                    Paced::OutOfTime => {
                        job.skip_out_of_time(sink, units.len() - i);
                        out_of_time = true;
                        break;
                    }
                }
            };
            let named =
                named.or_else(|| cas_guard::recognize_shape(probed.iter().map(String::as_str)));
            if named == Some(StoreKind::TicketRegistry) {
                let s = ensure(&mut slot, target, &mut connect).await?;
                let field = ticket_type_field(&probed);
                match job.paced(ticket_metadata(s, db, &unit.name, field)).await? {
                    Paced::Done(r) => {
                        ticket_registry(job, sink, target, &db_name, &object, r);
                        cas_stores.push((db.clone(), unit.name.clone(), StoreKind::TicketRegistry));
                        continue;
                    }
                    Paced::OutOfTime => {
                        job.skip_out_of_time(sink, units.len() - i);
                        out_of_time = true;
                        break;
                    }
                }
            }
            let sampled = {
                let s = ensure(&mut slot, target, &mut connect).await?;
                match job
                    .paced(sample_collection_for(s, db, unit, n, named))
                    .await?
                {
                    Paced::Done(r) => r,
                    Paced::OutOfTime => {
                        job.skip_out_of_time(sink, units.len() - i);
                        out_of_time = true;
                        break;
                    }
                }
            };
            let sampled = match sampled {
                Ok(s) => s,
                Err(e) => {
                    // One collection's failure (permission, timeout, a
                    // reply over the limit, a malformed document) skips
                    // that collection; a broken session is replaced for
                    // the next one, and a target that is gone fails the
                    // scan when reconnecting.
                    let not_readable = e.code == FailureCode::PermissionDenied;
                    sink.add_coverage(if not_readable {
                        ScanCoverage {
                            not_readable: 1,
                            ..ScanCoverage::default()
                        }
                    } else {
                        ScanCoverage {
                            error: 1,
                            ..ScanCoverage::default()
                        }
                    });
                    totals.skipped += 1;
                    let reason = match (unit.kind, not_readable) {
                        (CollKind::Timeseries, true) => {
                            totals.timeseries_refused += 1;
                            "time-series collection refused: its reads may need find on its \
                             bucket collection (system_buckets resource, ADR-0026)"
                        }
                        (_, true) => "no find privilege",
                        _ => "read failed",
                    };
                    tracing::warn!(
                        target_id = %target.id,
                        database = db_name.as_str(),
                        object = object.as_str(),
                        stage = e.stage.as_str(),
                        server_code = e.server_code,
                        code = %e.code,
                        reason,
                        "object not covered"
                    );
                    continue;
                }
            };
            let kind = named.or_else(|| {
                cas_guard::recognize_shape(sampled.top_keys.iter().map(String::as_str))
            });
            if kind == Some(StoreKind::TicketRegistry) {
                // Recognized by its document shape: the documents read are
                // dropped (zeroized) unclassified; its metadata only.
                let field = ticket_type_field(&sampled.top_keys).to_owned();
                drop(sampled);
                let s = ensure(&mut slot, target, &mut connect).await?;
                match job
                    .paced(ticket_metadata(s, db, &unit.name, &field))
                    .await?
                {
                    Paced::Done(r) => ticket_registry(job, sink, target, &db_name, &object, r),
                    Paced::OutOfTime => {
                        job.skip_out_of_time(sink, units.len() - i);
                        out_of_time = true;
                        break;
                    }
                }
                cas_stores.push((db.clone(), unit.name.clone(), StoreKind::TicketRegistry));
                continue;
            }
            if let Some(kind) = kind {
                if kind == StoreKind::AuditTrail {
                    cas_stores.push((db.clone(), unit.name.clone(), kind));
                }
                tracing::info!(
                    target_id = %target.id,
                    database = db_name.as_str(),
                    object = object.as_str(),
                    store = kind.as_str(),
                    "CAS store guard applied"
                );
            }
            sink.add_coverage(ScanCoverage {
                sampled: 1,
                ..ScanCoverage::default()
            });
            totals.sampled += 1;
            log_walk(target, &db_name, &object, &sampled);
            let estimated_rows = sampled.estimated_rows;
            // Nothing is open on the server from here on.
            for (field, values) in sampled.collector.into_paths() {
                let samples: Vec<RawSample<'_>> = values.iter().map(|v| v.as_sample()).collect();
                let rule = cas_guard::document_rule(kind, field.as_str());
                for finding in job.classify_guarded(field.as_str(), &samples, rule) {
                    let mut finding = finding.into_finding(FindingLocation {
                        database: db_name.clone(),
                        schema: None,
                        object: object.clone(),
                        field: field.clone(),
                    });
                    if let Some(rows) = estimated_rows {
                        finding = finding.with_estimated_rows(rows);
                    }
                    sink.submit(finding).await?;
                }
            }
        }
        if out_of_time {
            job.skip_out_of_time(sink, selected.len() - di - 1);
            break;
        }
    }
    if let Some(s) = slot
        && !s.is_broken()
    {
        s.close().await;
    }
    tracing::info!(
        target_id = %target.id,
        sampled = totals.sampled,
        skipped = totals.skipped,
        not_sampled = totals.unsupported,
        "target scanned"
    );
    Ok(ScanOutcome {
        timeseries_refused: totals.timeseries_refused,
        cas_stores,
    })
}

/// Reports a CAS ticket registry collection (metadata only): counted as a
/// kind the connector does not sample; its ticket counts kept for the
/// target's notes. A failed aggregate leaves the encryption not evaluated.
fn ticket_registry(
    job: &ScanJob,
    sink: &FindingSink,
    target: &TargetConfig,
    db: &NormalizedName,
    object: &NormalizedName,
    counts: Result<TicketCounts, MgError>,
) {
    sink.add_coverage(ScanCoverage {
        unsupported: 1,
        ..ScanCoverage::default()
    });
    match counts {
        Ok(c) => job.record_ticket_registry(&c),
        Err(e) => tracing::info!(
            target_id = %target.id,
            database = db.as_str(),
            object = object.as_str(),
            server_code = e.server_code,
            "CAS ticket registry: type counts not readable, encryption not evaluated"
        ),
    }
    tracing::info!(
        target_id = %target.id,
        database = db.as_str(),
        object = object.as_str(),
        "CAS ticket registry: not sampled (CAS store guard, metadata only)"
    );
}

#[derive(Debug, Default)]
struct Totals {
    timeseries_refused: u64,
    sampled: u64,
    skipped: u64,
    unsupported: u64,
}

fn log_walk(target: &TargetConfig, db: &NormalizedName, object: &NormalizedName, s: &Sampled) {
    let WalkStats {
        documents,
        too_deep,
        arrays_cut,
        documents_cut,
        paths_dropped,
    } = s.collector.stats;
    if too_deep + arrays_cut + documents_cut + paths_dropped > 0 {
        tracing::info!(
            target_id = %target.id,
            database = db.as_str(),
            object = object.as_str(),
            documents,
            too_deep,
            arrays_cut,
            documents_cut,
            paths_dropped,
            "documents partly read (walk bounds)"
        );
    }
}

fn fail(target: &TargetConfig, e: MgError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        server_code = e.server_code,
        code = %e.code,
        "scan failed"
    );
    e.into_connector_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bson::Doc;

    #[test]
    fn sample_only_large_collections() {
        assert_eq!(method(None, 200), Method::Natural);
        assert_eq!(method(Some(0), 200), Method::Natural);
        assert_eq!(method(Some(4000), 200), Method::Natural);
        assert_eq!(method(Some(4001), 200), Method::Sample);
        // Tiny samples still need more than 100 documents.
        assert_eq!(method(Some(100), 1), Method::Natural);
        assert_eq!(method(Some(101), 1), Method::Sample);
    }

    #[test]
    fn read_commands_are_bounded_and_read_only() {
        let find = read_command("users", Method::Natural, 200).finish();
        let d = Doc::new(&find).unwrap();
        assert_eq!(d.str("find").unwrap(), Some("users"));
        assert_eq!(d.int("limit").unwrap(), Some(200));
        assert_eq!(d.int("batchSize").unwrap(), Some(200));
        assert_eq!(d.flag("singleBatch").unwrap(), Some(true));
        let agg = read_command("users", Method::Sample, 200).finish();
        let d = Doc::new(&agg).unwrap();
        assert_eq!(d.str("aggregate").unwrap(), Some("users"));
        assert_eq!(d.flag("allowDiskUse").unwrap(), Some(false));
        assert_eq!(
            d.doc("cursor").unwrap().unwrap().int("batchSize").unwrap(),
            Some(201)
        );
        // A time-series (view) read has no `singleBatch`.
        let view = read_command("metrics", Method::NaturalView, 200).finish();
        let d_view = Doc::new(&view).unwrap();
        assert_eq!(d_view.flag("singleBatch").unwrap(), None);
        assert_eq!(d_view.int("batchSize").unwrap(), Some(201));
        let pipeline = d.array("pipeline").unwrap().unwrap();
        let stages: Vec<_> = pipeline.iter().map(Result::unwrap).collect();
        assert_eq!(stages.len(), 1);
        let Value::Doc(stage) = stages[0].1 else {
            panic!("a stage is a document")
        };
        let names: Vec<Vec<u8>> = stage.iter().map(|e| e.unwrap().0.to_vec()).collect();
        assert_eq!(names, [b"$sample".to_vec()]);
    }

    #[test]
    fn names_are_normalized() {
        assert_eq!(normalize_database("app").as_str(), "app");
        assert_eq!(normalize_collection("users").as_str(), "users");
        assert_eq!(normalize_collection("fs.files").as_str(), "fs.files");
        assert_eq!(
            normalize_collection("export_jane.doe@example.com").as_str(),
            "*"
        );
        assert_eq!(normalize_database("client_0612345678").as_str(), "*");
    }
}
