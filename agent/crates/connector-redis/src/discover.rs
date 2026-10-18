//! Discovery (ADR-0052 decisions 4, 6 and 7): per logical database, a
//! bounded `SCAN` walk, key names filtered locally against the declared
//! patterns and the CAS guard **before** any `TYPE`, normalized into
//! patterns emitted after the walk ([`databastion_classifiers::keys`]),
//! then a bounded sample of each pattern's first keys by type. Values go
//! only through `ScanJob::classify` and `classifiers::masking` (I2); key
//! names, values and declared patterns are never logged.
//!
//! Bounds: `redis.max_keys` keys and `4 × max_keys / 500` `SCAN` calls per
//! database (L7), at most 1 024 patterns, `sample_rows` keys per pattern, 16
//! members per key, 4 KiB per value; the job's statement timeout on every
//! exchange; each `SCAN` batch and each pattern's sampling is one paced
//! unit (ADR-0035).

use std::collections::BTreeMap;

use databastion_classifiers::keys::{self, EmittedPattern, PatternBuilder, SecretBytes};
use databastion_classifiers::masking::{FindingLocation, RawSample};
use databastion_classifiers::names::{self, NormalizedName};
use databastion_core::config::TargetConfig;
use databastion_core::{
    ConnectorError, Engine, FailureCode, FindingSink, Paced, ScanCoverage, ScanJob,
};
use zeroize::Zeroizing;

use crate::check::{CheckState, ScanFacts};
use crate::cmd::{Cmd, InfoSection, MEMBERS_PER_KEY, SCAN_COUNT, VALUE_BYTES};
use crate::conn::{MAX_PIPELINE, Session};
use crate::error::{RdError, Stage};
use crate::families::Families;
use crate::guard;
use crate::info;
use crate::node::{self, NodeInfo, Refusal, Which};
use crate::resp::{ErrorWord, Value};

/// The Redis types sampled, as the builder's kind codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Kind {
    String = 0,
    Hash = 1,
    List = 2,
    Set = 3,
    Zset = 4,
    Stream = 5,
    /// A module type (`ReJSON-RL`, `vectorset`…): not read.
    Module = 6,
}

impl Kind {
    fn of(t: &[u8]) -> Option<Self> {
        Some(match t {
            b"string" => Self::String,
            b"hash" => Self::Hash,
            b"list" => Self::List,
            b"set" => Self::Set,
            b"zset" => Self::Zset,
            b"stream" => Self::Stream,
            b"none" => return None,
            _ => Self::Module,
        })
    }

    fn from_code(c: u8) -> Self {
        match c {
            0 => Self::String,
            1 => Self::Hash,
            2 => Self::List,
            3 => Self::Set,
            4 => Self::Zset,
            5 => Self::Stream,
            _ => Self::Module,
        }
    }

    /// The `Location.schema` of the type.
    fn schema(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Hash => "hash",
            Self::List => "list",
            Self::Set => "set",
            Self::Zset => "zset",
            Self::Stream => "stream",
            Self::Module => "module",
        }
    }
}

fn target_error(code: FailureCode) -> ConnectorError {
    ConnectorError::Target {
        engine: Engine::Redis,
        code,
        engine_code: None,
    }
}

/// A connection that is reopened after a fatal error (the next unit
/// reconnects, decision 1), with the current database selected again.
struct Conn<'a> {
    target: &'a TargetConfig,
    session: Option<Session>,
    db: Option<u16>,
    no_touch: bool,
    readonly: bool,
}

impl Conn<'_> {
    async fn get(&mut self, job: &ScanJob) -> Result<&mut Session, RdError> {
        let timeout = job.statement_timeout();
        let usable = self.session.is_some();
        if !usable {
            let (mut s, _) = node::open(self.target, Which::Discovery, timeout).await?;
            setup(&mut s, self.no_touch, self.readonly, job).await?;
            if let Some(db) = self.db {
                select(&mut s, db, job).await?;
            }
            self.session = Some(s);
        }
        self.session
            .as_mut()
            .ok_or_else(|| RdError::new(FailureCode::Internal, Stage::Connect))
    }

    /// The session failed fatally: dropped, reopened on next use.
    fn drop_session(&mut self) {
        self.session = None;
    }
}

async fn setup(
    s: &mut Session,
    no_touch: bool,
    readonly: bool,
    job: &ScanJob,
) -> Result<(), RdError> {
    let timeout = job.statement_timeout();
    if no_touch {
        let r = s
            .call(&Cmd::ClientNoTouchOn, timeout, Stage::SessionSetup)
            .await?;
        if let Some(w) = r.error() {
            return Err(RdError::reply(w, Stage::SessionSetup));
        }
    }
    if readonly {
        let r = s.call(&Cmd::ReadOnly, timeout, Stage::SessionSetup).await?;
        if let Some(w) = r.error() {
            return Err(RdError::reply(w, Stage::SessionSetup));
        }
    }
    Ok(())
}

async fn select(s: &mut Session, db: u16, job: &ScanJob) -> Result<(), RdError> {
    let r = s
        .call(
            &Cmd::Select(db),
            job.statement_timeout(),
            Stage::Introspection,
        )
        .await?;
    match r.error() {
        Some(w) => Err(RdError::reply(w, Stage::Introspection)),
        None => Ok(()),
    }
}

fn database_name(db: u16) -> String {
    format!("db{db}")
}

/// Runs a Discovery scan.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = job.target().ok_or(ConnectorError::Target {
        engine: Engine::Redis,
        code: FailureCode::Internal,
        engine_code: None,
    })?;
    let settings = target.redis_settings();
    let timeout = job.statement_timeout();
    let (mut session, info) = node::open(target, Which::Discovery, timeout)
        .await
        .map_err(RdError::into_connector_error)?;
    if settings.discovery_node.is_some() && !info.replica {
        tracing::warn!(
            target_id = target.id.as_str(),
            "Redis / Valkey: redis.discovery_node does not report a replica role"
        );
    }
    // The account's evaluation on the node Discovery reads and, with a
    // declared Discovery node, on the target's node too: ACLs are per node
    // (not replicated), so Discovery runs only when neither node refuses
    // (decision 4; security review M2).
    let report = match state
        .reports
        .of_session(&mut session, target, Which::Discovery, info, timeout)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            session.close().await;
            return Err(e.into_connector_error());
        }
    };
    let mut refusal = report.refusal(&settings, info.server);
    if refusal.is_none() && settings.discovery_node.is_some() {
        match state.reports.of_target(target, timeout).await {
            Ok((t, server)) => refusal = t.refusal(&settings, server),
            Err(e) => {
                session.close().await;
                return Err(e.into_connector_error());
            }
        }
    }
    if let Some(refusal) = refusal {
        session.close().await;
        tracing::warn!(
            target_id = target.id.as_str(),
            "Redis / Valkey: Discovery refused for this target (see check())"
        );
        return Err(target_error(match refusal {
            Refusal::Listed => FailureCode::PermissionDenied,
            _ => FailureCode::Unsupported,
        }));
    }
    let eval = report.eval.clone().unwrap_or_default();
    let no_touch = info.server.has_no_touch() && eval.no_touch;
    let readonly = info.cluster && info.replica && eval.readonly;
    setup(&mut session, no_touch, readonly, job)
        .await
        .map_err(RdError::into_connector_error)?;

    // Declared key patterns the account can read (decision 4).
    let not_readable = report.patterns_not_readable.clone().unwrap_or_default();
    let patterns: Vec<Vec<u8>> = settings
        .key_patterns
        .iter()
        .enumerate()
        .filter(|(i, _)| !not_readable.contains(i))
        .map(|(_, p)| p.as_bytes().to_vec())
        .collect();
    let mut coverage = ScanCoverage {
        not_readable: not_readable.len() as u64,
        ..ScanCoverage::default()
    };

    // The databases holding keys, filtered by the declaration and the job.
    let keyspace = session
        .call(
            &Cmd::Info(InfoSection::Keyspace),
            timeout,
            Stage::Introspection,
        )
        .await
        .map_err(RdError::into_connector_error)?;
    let text = keyspace
        .as_bytes()
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let dbs_not_readable = report.databases_not_readable.clone().unwrap_or_default();
    let mut databases: Vec<u16> = Vec::new();
    for (db, _) in info::keyspace(&text) {
        let declared = settings.databases.as_ref().is_none_or(|d| d.contains(&db));
        if !declared || !job.includes_database(&database_name(db)) {
            continue;
        }
        if dbs_not_readable.contains(&db) {
            coverage.not_readable += 1;
            continue;
        }
        databases.push(db);
    }
    job.rotate(&mut databases);
    sink.add_coverage(std::mem::take(&mut coverage));

    let mut conn = Conn {
        target,
        session: Some(session),
        db: None,
        no_touch,
        readonly,
    };
    // Databases whose walk or sampling an unexpected NOPERM ended (the
    // declared patterns not confirmed by `check()` are in its report).
    let mut facts = ScanFacts::default();
    for (i, db) in databases.iter().enumerate() {
        if job.out_of_time() {
            job.skip_out_of_time(sink, databases.len() - i);
            break;
        }
        let name = database_name(*db);
        job.begin_database(&name);
        conn.db = Some(*db);
        let selected = match conn.get(job).await {
            Ok(s) => select(s, *db, job).await,
            Err(e) => Err(e),
        };
        if let Err(e) = selected {
            if e.fatal {
                conn.drop_session();
            }
            sink.add_coverage(ScanCoverage {
                error: 1,
                ..ScanCoverage::default()
            });
            continue;
        }
        let walked = walk(&mut conn, job, sink, &patterns, &settings, &info).await?;
        let Some((emitted, complete)) = walked else {
            facts.declared_not_readable += 1;
            continue;
        };
        // The patterns Audit maps log keys to (decision 8, H1).
        let learned: Vec<String> = emitted
            .iter()
            .map(|p| p.pattern.as_str().to_owned())
            .collect();
        state.audit.learn(&target.id, *db, &learned, complete);
        sample_database(&mut conn, job, sink, &name, emitted, &mut facts).await?;
    }
    state.record_scan(&target.id, facts);
    if let Some(s) = conn.session.take() {
        s.close().await;
    }
    Ok(())
}

/// Walks one database (decision 6): its patterns, and whether the walk
/// was complete. `None` when the walk ended on an unexpected `NOPERM`
/// (the database counts in `skipped_not_readable`).
async fn walk(
    conn: &mut Conn<'_>,
    job: &ScanJob,
    sink: &FindingSink,
    patterns: &[Vec<u8>],
    settings: &databastion_core::config::redis::RedisTargetConfig,
    info: &NodeInfo,
) -> Result<Option<(Vec<EmittedPattern>, bool)>, ConnectorError> {
    let max_keys = u64::from(settings.max_keys);
    let max_calls = (4 * max_keys / u64::from(SCAN_COUNT)).max(1);
    let stores = job.cas_stores();
    let mut builder = PatternBuilder::new(job.sample_rows() as usize);
    // Round-robin sampling across the families a pattern merges (#237).
    let mut families = Families::new(job.sample_rows() as usize);
    let (mut cursor, mut calls, mut examined) = (0u64, 0u64, 0u64);
    let mut limited = false;
    let mut cov = ScanCoverage::default();
    loop {
        let unit = job
            .paced(scan_batch(conn, job, cursor, patterns, stores))
            .await?;
        let batch = match unit {
            Paced::Done(b) => b,
            Paced::OutOfTime => {
                limited = true;
                break;
            }
        };
        calls += 1;
        let batch = match batch {
            Ok(b) => b,
            Err(Walk::NoPerm) => {
                tracing::warn!(
                    target_id = job.target().map_or("", |t| t.id.as_str()),
                    "Redis / Valkey: a command was refused (NOPERM): the declared key \
                     patterns do not match the account's ACL; this database's walk ends"
                );
                cov.not_readable += 1;
                sink.add_coverage(cov);
                return Ok(None);
            }
            Err(Walk::Failed(e)) => {
                // A SCAN reply that closed the connection ends this
                // database's walk; the connector never retries the cursor
                // (M5).
                if e.fatal {
                    conn.drop_session();
                }
                limited = true;
                break;
            }
        };
        cov.limit += batch.oversized;
        cov.remote += batch.remote;
        cov.unsupported += batch.guarded;
        for _ in 0..batch.guarded {
            job.record_cas_guard_trip();
        }
        examined += batch.listed;
        for (raw, kind) in batch.keys {
            let units = keys::split_key(raw.expose());
            families.add(raw.expose(), units.pattern().as_str(), kind as u8);
            builder.add(raw.expose(), units, kind as u8);
        }
        cursor = batch.next;
        if cursor == 0 {
            break;
        }
        if examined >= max_keys || calls >= max_calls {
            limited = true;
            break;
        }
    }
    if limited {
        // The remaining keys are unknown: the database counts 1 (ADR-0035
        // decision 3).
        cov.limit += 1;
    }
    cov.limit += builder.overflow().min(1);
    let _ = info;
    sink.add_coverage(cov);
    let complete = !limited && builder.overflow() == 0;
    let mut emitted = builder.finish();
    families.rebalance(&mut emitted);
    Ok(Some((emitted, complete)))
}

enum Walk {
    NoPerm,
    Failed(RdError),
}

struct Batch {
    next: u64,
    listed: u64,
    keys: Vec<(SecretBytes, Kind)>,
    oversized: u64,
    guarded: u64,
    remote: u64,
}

/// One `SCAN` call and the `TYPE` of the keys kept (one paced unit).
async fn scan_batch(
    conn: &mut Conn<'_>,
    job: &ScanJob,
    cursor: u64,
    patterns: &[Vec<u8>],
    stores: Option<&databastion_core::cas_guard::CasStores>,
) -> Result<Batch, Walk> {
    let timeout = job.statement_timeout();
    let s = conn.get(job).await.map_err(Walk::Failed)?;
    let reply = s
        .call(&Cmd::Scan { cursor }, timeout, Stage::Introspection)
        .await
        .map_err(Walk::Failed)?;
    if reply.error() == Some(ErrorWord::Noperm) {
        return Err(Walk::NoPerm);
    }
    let Value::Array(parts) = reply else {
        return Err(Walk::Failed(match reply.error() {
            Some(w) => RdError::reply(w, Stage::Introspection),
            None => RdError::new(FailureCode::Unsupported, Stage::Introspection),
        }));
    };
    let mut parts = parts.into_iter();
    let (Some(next), Some(Value::Array(names))) = (parts.next(), parts.next()) else {
        return Err(Walk::Failed(RdError::new(
            FailureCode::Unsupported,
            Stage::Introspection,
        )));
    };
    let next = next
        .as_bytes()
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|t| t.parse::<u64>().ok())
        .ok_or(Walk::Failed(RdError::new(
            FailureCode::Unsupported,
            Stage::Introspection,
        )))?;
    let mut batch = Batch {
        next,
        listed: names.len() as u64,
        keys: Vec::new(),
        oversized: 0,
        guarded: 0,
        remote: 0,
    };
    // Local filters before any TYPE (decision 4, H3; decision 6, M6):
    // names outside the declared patterns are dropped at once.
    let mut kept: Vec<SecretBytes> = Vec::new();
    for v in names {
        match v {
            Value::Str(b) => {
                let name = b.as_slice();
                if !patterns.iter().any(|p| crate::glob::matches(p, name)) {
                    continue;
                }
                if guard::key_guarded(name, stores) {
                    batch.guarded += 1;
                    continue;
                }
                kept.push(SecretBytes::new(name));
            }
            Value::Skipped => batch.oversized += 1,
            _ => {
                return Err(Walk::Failed(RdError::new(
                    FailureCode::Unsupported,
                    Stage::Introspection,
                )));
            }
        }
    }
    for chunk in kept.chunks(MAX_PIPELINE) {
        let cmds: Vec<Cmd<'_>> = chunk.iter().map(|k| Cmd::Type(k.expose())).collect();
        let replies = s
            .pipeline(&cmds, timeout, Stage::Introspection)
            .await
            .map_err(Walk::Failed)?;
        for (k, r) in chunk.iter().zip(replies) {
            match &r {
                Value::Str(t) => {
                    if let Some(kind) = Kind::of(t.as_slice()) {
                        batch.keys.push((k.clone(), kind));
                    }
                }
                Value::Error(ErrorWord::Noperm) => return Err(Walk::NoPerm),
                Value::Error(ErrorWord::Moved | ErrorWord::Ask) => batch.remote += 1,
                _ => {}
            }
        }
    }
    Ok(batch)
}

/// The values read from one pattern's keys, per normalized field.
#[derive(Default)]
struct Pool {
    /// Field name (normalized) -> values.
    fields: BTreeMap<String, Vec<Zeroizing<String>>>,
    /// Raw field names that normalized to `*` (values found in names).
    field_names: Vec<Zeroizing<String>>,
}

impl Pool {
    /// A hash or stream keyed by data (more than 16 distinct field names
    /// across the pattern's keys, or one hash of more than 16 fields):
    /// every field becomes `*` (decision 7's cardinality rule on field
    /// names).
    fn collapse_fields(&mut self, cap: usize) {
        let fields = std::mem::take(&mut self.fields);
        for (_, values) in fields {
            for v in values {
                self.push("*", v, cap);
            }
        }
    }

    fn push(&mut self, field: &str, value: Zeroizing<String>, cap: usize) {
        let slot = self.fields.entry(field.to_owned()).or_default();
        if slot.len() < cap {
            slot.push(value);
        }
    }
}

/// Cuts a value to 4 096 bytes on a character boundary; `None` when it is
/// not UTF-8 (skipped, as MongoDB binaries are).
fn value_text(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let cut = bytes.get(..VALUE_BYTES.min(bytes.len())).unwrap_or(bytes);
    let text = match std::str::from_utf8(cut) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(cut.get(..e.valid_up_to()).unwrap_or_default()).ok()?
        }
        Err(_) => return None,
    };
    Some(Zeroizing::new(text.to_owned()))
}

/// The normalized name of a hash or stream field (an `Identifier`).
fn field_name(raw: &[u8], pool: &mut Pool) -> Option<String> {
    let text = std::str::from_utf8(raw).ok();
    let normalized = text.map_or_else(NormalizedName::wildcard, names::normalize_path);
    if normalized.as_str() == "*"
        && let Some(t) = text
    {
        pool.field_names.push(Zeroizing::new(t.to_owned()));
    }
    Some(normalized.as_str().to_owned())
}

async fn sample_database(
    conn: &mut Conn<'_>,
    job: &ScanJob,
    sink: &FindingSink,
    database: &str,
    emitted: Vec<EmittedPattern>,
    facts: &mut ScanFacts,
) -> Result<(), ConnectorError> {
    let mut emitted = emitted;
    job.rotate(&mut emitted);
    let total = emitted.len();
    for (i, pattern) in emitted.into_iter().enumerate() {
        let kind = Kind::from_code(pattern.kind);
        if kind == Kind::Module {
            facts.module_patterns += 1;
            sink.add_coverage(ScanCoverage {
                unsupported: 1,
                ..ScanCoverage::default()
            });
            continue;
        }
        let unit = job.paced(sample_pattern(conn, job, kind, &pattern)).await?;
        let outcome = match unit {
            Paced::Done(o) => o,
            Paced::OutOfTime => {
                job.skip_out_of_time(sink, total - i);
                return Ok(());
            }
        };
        let pool = match outcome {
            Ok(p) => p,
            Err(Walk::NoPerm) => {
                facts.declared_not_readable += 1;
                sink.add_coverage(ScanCoverage {
                    not_readable: 1,
                    ..ScanCoverage::default()
                });
                // The first NOPERM ends the database (decision 4, N4).
                return Ok(());
            }
            Err(Walk::Failed(e)) => {
                if e.fatal {
                    conn.drop_session();
                }
                sink.add_coverage(ScanCoverage {
                    error: 1,
                    ..ScanCoverage::default()
                });
                continue;
            }
        };
        sink.add_coverage(ScanCoverage {
            sampled: 1,
            ..ScanCoverage::default()
        });
        emit(job, sink, database, kind, &pattern, pool).await?;
    }
    Ok(())
}

/// The hint given to the classifier for a value field: the pattern's last
/// literal segment (`customer:*:email` -> `email`,
/// `integration:*:secret_access_key` -> `secret_access_key`).
fn hint(pattern: &str) -> &str {
    pattern
        .rsplit([':', '/', '|', '.'])
        .find(|t| !t.is_empty() && !t.contains('*'))
        .unwrap_or("value")
}

async fn emit(
    job: &ScanJob,
    sink: &FindingSink,
    database: &str,
    kind: Kind,
    pattern: &EmittedPattern,
    pool: Pool,
) -> Result<(), ConnectorError> {
    let location = |field: &str| FindingLocation {
        database: names::normalize_path(database),
        schema: Some(names::normalize_path(kind.schema())),
        object: pattern.pattern.clone(),
        field: names::normalize_path(field),
    };
    let rows = pattern.group.count;
    let mut submit = Vec::new();
    for (field, values) in &pool.fields {
        let raws: Vec<RawSample<'_>> = values.iter().map(|v| RawSample::new(v.as_str())).collect();
        let column = if field == "value" {
            hint(pattern.pattern.as_str())
        } else {
            field.as_str()
        };
        for f in job.classify(column, &raws) {
            submit.push(f.into_finding(location(field)).with_estimated_rows(rows));
        }
    }
    // Values found in key names (`#key`) and hash / stream field names
    // (`#field`), classified like values (decision 7).
    let key_values: Vec<RawSample<'_>> = pattern
        .group
        .name_values
        .iter()
        .map(|v| RawSample::new(v.expose()))
        .collect();
    if !key_values.is_empty() {
        for f in job.classify("key", &key_values) {
            submit.push(f.into_finding(location("#key")).with_estimated_rows(rows));
        }
    }
    let field_values: Vec<RawSample<'_>> = pool
        .field_names
        .iter()
        .map(|v| RawSample::new(v.as_str()))
        .collect();
    if !field_values.is_empty() {
        for f in job.classify("field", &field_values) {
            submit.push(f.into_finding(location("#field")).with_estimated_rows(rows));
        }
    }
    for f in submit {
        sink.submit(f)
            .await
            .map_err(|_| ConnectorError::Cancelled)?;
    }
    Ok(())
}

/// Samples the first keys of one pattern (one paced unit).
async fn sample_pattern(
    conn: &mut Conn<'_>,
    job: &ScanJob,
    kind: Kind,
    pattern: &EmittedPattern,
) -> Result<Pool, Walk> {
    let cap = job.sample_rows() as usize;
    let timeout = job.statement_timeout();
    let mut pool = Pool::default();
    let mut distinct_fields: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // A hash of more than 16 fields: keyed by data (H2).
    let mut data_keyed = false;
    for key in pattern.group.samples.iter().take(cap) {
        let s = conn.get(job).await.map_err(Walk::Failed)?;
        let k = key.expose();
        // Per key: (field, value) pairs read.
        let mut read: Vec<(String, Zeroizing<String>)> = Vec::new();
        let mut tripped = false;
        let mut check = |bytes: &[u8]| {
            if guard::value_trips(bytes) {
                tripped = true;
            }
        };
        match kind {
            Kind::String => {
                let r = s
                    .call(&Cmd::GetRange(k), timeout, Stage::Sample)
                    .await
                    .map_err(Walk::Failed)?;
                if let Some(e) = noperm_or_skip(&r)? {
                    let _ = e;
                    continue;
                }
                if let Some(b) = r.as_bytes() {
                    check(b);
                    if let Some(t) = value_text(b) {
                        read.push(("value".to_owned(), t));
                    }
                }
            }
            Kind::List | Kind::Set | Kind::Zset => {
                let cmd = match kind {
                    Kind::List => Cmd::LRange(k),
                    Kind::Set => Cmd::SRandMember(k),
                    _ => Cmd::ZRandMember(k),
                };
                let r = s
                    .call(&cmd, timeout, Stage::Sample)
                    .await
                    .map_err(Walk::Failed)?;
                if noperm_or_skip(&r)?.is_some() {
                    continue;
                }
                if let Value::Array(items) = &r {
                    for item in items.iter().take(MEMBERS_PER_KEY as usize) {
                        if let Some(b) = item.as_bytes() {
                            check(b);
                            if let Some(t) = value_text(b) {
                                read.push(("value".to_owned(), t));
                            }
                        }
                    }
                }
            }
            Kind::Hash => {
                let r = s
                    .call(&Cmd::HRandField(k), timeout, Stage::Sample)
                    .await
                    .map_err(Walk::Failed)?;
                if noperm_or_skip(&r)?.is_some() {
                    continue;
                }
                let Value::Array(fields) = r else { continue };
                if fields.len() > keys::COLLAPSE_THRESHOLD {
                    data_keyed = true;
                }
                let fields: Vec<SecretBytes> = fields
                    .iter()
                    .filter_map(Value::as_bytes)
                    .take(MEMBERS_PER_KEY as usize)
                    .map(SecretBytes::new)
                    .collect();
                if fields.is_empty() {
                    continue;
                }
                let lens = s
                    .pipeline(
                        &fields
                            .iter()
                            .map(|f| Cmd::HStrLen(k, f.expose()))
                            .collect::<Vec<_>>(),
                        timeout,
                        Stage::Sample,
                    )
                    .await
                    .map_err(Walk::Failed)?;
                let small: Vec<&SecretBytes> = fields
                    .iter()
                    .zip(&lens)
                    .filter(|(_, l)| matches!(l, Value::Int(n) if *n >= 0 && (*n as usize) <= VALUE_BYTES))
                    .map(|(f, _)| f)
                    .collect();
                if small.is_empty() {
                    continue;
                }
                let names: Vec<&[u8]> = small.iter().map(|f| f.expose()).collect();
                let r = s
                    .call(&Cmd::HMGet(k, &names), timeout, Stage::Sample)
                    .await
                    .map_err(Walk::Failed)?;
                if noperm_or_skip(&r)?.is_some() {
                    continue;
                }
                if let Value::Array(values) = r {
                    for (f, v) in names.iter().zip(values.iter()) {
                        check(f);
                        let Some(b) = v.as_bytes() else { continue };
                        check(b);
                        let Some(field) = field_name(f, &mut pool) else {
                            continue;
                        };
                        if let Some(t) = value_text(b) {
                            read.push((field, t));
                        }
                    }
                }
            }
            Kind::Stream => {
                let r = s
                    .call(&Cmd::XRevRange(k), timeout, Stage::Sample)
                    .await
                    .map_err(Walk::Failed)?;
                if noperm_or_skip(&r)?.is_some() {
                    continue;
                }
                if let Value::Array(entries) = r {
                    for e in &entries {
                        let Value::Array(parts) = e else { continue };
                        let Some(Value::Array(fv)) = parts.get(1) else {
                            continue;
                        };
                        for pair in fv.chunks(2) {
                            let (Some(f), Some(v)) = (
                                pair.first().and_then(Value::as_bytes),
                                pair.get(1).and_then(Value::as_bytes),
                            ) else {
                                continue;
                            };
                            check(f);
                            check(v);
                            let Some(field) = field_name(f, &mut pool) else {
                                continue;
                            };
                            if let Some(t) = value_text(v) {
                                read.push((field, t));
                            }
                        }
                    }
                }
            }
            Kind::Module => {}
        }
        if tripped {
            // The value tripwire guards this key only (N5): its values are
            // dropped before classification and it is not read again.
            job.record_cas_guard_trip();
            continue;
        }
        for (field, value) in read {
            if field != "value" && field != "*" {
                distinct_fields.insert(field.clone());
            }
            pool.push(&field, value, cap);
        }
    }
    if data_keyed || distinct_fields.len() > keys::COLLAPSE_THRESHOLD {
        pool.collapse_fields(cap);
    }
    Ok(pool)
}

/// `NOPERM` ends the database; `MOVED` / `ASK` and other per-key errors
/// skip the key (`Some`).
fn noperm_or_skip(v: &Value) -> Result<Option<ErrorWord>, Walk> {
    match v.error() {
        Some(ErrorWord::Noperm) => Err(Walk::NoPerm),
        Some(w) => Ok(Some(w)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_keyed_hash_keeps_no_field_name() {
        let mut pool = Pool::default();
        for name in ["jdupont", "amartin", "lucas"] {
            pool.push(name, Zeroizing::new("v".to_owned()), 16);
        }
        pool.collapse_fields(16);
        assert_eq!(pool.fields.keys().collect::<Vec<_>>(), ["*"]);
        assert_eq!(pool.fields["*"].len(), 3);
    }

    #[test]
    fn hints_and_values() {
        assert_eq!(hint("customer:*:email"), "email");
        assert_eq!(hint("user:*:profile"), "profile");
        assert_eq!(hint("*"), "value");
        assert_eq!(hint("integration:*:secret_access_key"), "secret_access_key");
        assert_eq!(value_text(b"abc").unwrap().as_str(), "abc");
        assert!(value_text(&[0xff, 0xfe]).is_none());
        let mut long = "é".repeat(3000).into_bytes();
        long.truncate(5000);
        let t = value_text(&long).unwrap();
        assert!(t.len() <= VALUE_BYTES && t.len() >= VALUE_BYTES - 1);
        assert_eq!(names::normalize_path("#key").as_str(), "#key");
        assert_eq!(names::normalize_path("#field").as_str(), "#field");
        assert_eq!(names::normalize_path("db0").as_str(), "db0");
    }

    #[test]
    fn kinds() {
        assert_eq!(Kind::of(b"string"), Some(Kind::String));
        assert_eq!(Kind::of(b"ReJSON-RL"), Some(Kind::Module));
        assert_eq!(Kind::of(b"vectorset"), Some(Kind::Module));
        assert_eq!(Kind::of(b"none"), None);
        for k in 0..7u8 {
            assert_eq!(Kind::from_code(k) as u8, k);
        }
    }
}
