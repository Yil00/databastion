//! Job parameters handed to connectors (I4, ADR-0012 obligation 4).
//!
//! Console job parameters reach a connector **only** through this module:
//!
//! 1. `TryFrom<&DiscoveryScanParams>` for [`ScanParams`] and
//!    `TryFrom<&AuditConfigureParams>` for [`AuditParams`] enforce the
//!    contract ranges and the keywords serde does not (`minItems`,
//!    `maxItems`, `uniqueItems` of classifier lists, the `Identifier` `not`
//!    rule), and map classifier ids through `ClassifierId::parse` (unknown
//!    or duplicate id = error). An empty filter list (`Some([])`) is
//!    rejected: it never means "all". Duplicate name patterns in
//!    `databases` / `schemas` / `include_objects` / `exclude_objects` (no
//!    `uniqueItems` in the contract) are removed.
//! 2. [`ScanJob::new`] / [`AuditConfig::new`] then clamp the values to the
//!    local hard limits of `agent.yaml` (`limits`). A statement timeout is
//!    never `0` (unlimited on PostgreSQL / MySQL): a requested `0` becomes
//!    the local cap.
//!
//! [`ScanJob`] and [`AuditConfig`] have private fields and no other
//! constructor, so a connector always gets clamped values. Connectors never
//! see the generated protocol types.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_classifiers::column::{ColumnClassifier, ColumnFinding};
use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{HmacKey, PhoneRegion, RawSample};
use databastion_classifiers::names::violates_numeric_rule;
use databastion_protocol::{AuditConfigureParams, DiscoveryScanParams, IdentifierPattern};

use crate::config::{Limits, SAMPLE_ROWS_RANGE, STATEMENT_TIMEOUT_MS_RANGE, TargetConfig};
use crate::pacing::{Cancelled, Paced, Pacer, ScanCancel};

/// Contract range of `max_duration_s` (seconds).
pub const MAX_DURATION_S_RANGE: (u32, u32) = (10, 86_400);
/// Contract range of `aggregation_window_s` (seconds).
pub const AGGREGATION_WINDOW_S_RANGE: (u32, u32) = (1, 300);
/// Contract range of `poll_interval_s` (seconds).
pub const POLL_INTERVAL_S_RANGE: (u32, u32) = (1, 3_600);
/// Contract `maxItems` of `databases` and `schemas`.
const MAX_DATABASE_FILTERS: usize = 100;
/// Contract `maxItems` of `include_objects` and `exclude_objects`.
const MAX_OBJECT_FILTERS: usize = 500;
/// Contract `maxItems` of the scan `classifiers` filter.
const MAX_SCAN_CLASSIFIERS: usize = 200;
/// Contract `maxItems` of `sensitive_objects`.
const MAX_SENSITIVE_OBJECTS: usize = 1_000;
/// Contract `maxItems` of `SensitiveObject.classifiers`.
const MAX_OBJECT_CLASSIFIERS: usize = 32;
/// Contract `Count` maximum.
const MAX_COUNT: i64 = 9_007_199_254_740_991;

/// Why job parameters were refused (the job is reported `invalid_params`).
/// Carries the parameter name only, never its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid job parameter `{field}`: {reason}")]
pub struct ParamsError {
    /// Parameter name.
    pub field: &'static str,
    /// Why it is refused.
    pub reason: &'static str,
}

const fn err(field: &'static str, reason: &'static str) -> ParamsError {
    ParamsError { field, reason }
}

fn in_range(field: &'static str, v: i64, (lo, hi): (u32, u32)) -> Result<u32, ParamsError> {
    u32::try_from(v)
        .ok()
        .filter(|v| (lo..=hi).contains(v))
        .ok_or(err(field, "out of the contract range"))
}

/// Patterns without duplicates, in their first-seen order (the contract
/// has no `uniqueItems` on name filters: duplicates are harmless, removed).
fn dedup(list: &[IdentifierPattern]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for p in list {
        if !out.iter().any(|x| x == p.as_str()) {
            out.push(p.as_str().to_owned());
        }
    }
    out
}

/// An optional include filter: absent = all, `Some([])` is refused, above
/// `maxItems` is refused, duplicates are removed.
fn include_filter(
    field: &'static str,
    list: Option<&Vec<IdentifierPattern>>,
    max: usize,
) -> Result<Option<Vec<String>>, ParamsError> {
    match list {
        None => Ok(None),
        Some(l) if l.is_empty() => Err(err(field, "empty list (absent means all)")),
        Some(l) if l.len() > max => Err(err(field, "too many items")),
        Some(l) => Ok(Some(dedup(l))),
    }
}

/// Maps classifier ids through the closed set; unknown or duplicate ids
/// are refused.
fn classifier_list<'a>(
    field: &'static str,
    ids: impl ExactSizeIterator<Item = &'a str>,
    max: usize,
) -> Result<Vec<ClassifierId>, ParamsError> {
    if ids.len() == 0 {
        return Err(err(field, "empty list"));
    }
    if ids.len() > max {
        return Err(err(field, "too many items"));
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let c = ClassifierId::parse(id).ok_or(err(field, "unknown classifier id"))?;
        if out.contains(&c) {
            return Err(err(field, "duplicate classifier id"));
        }
        out.push(c);
    }
    Ok(out)
}

/// `discovery.scan` parameters checked against the contract, before the
/// local clamp. Only built by `TryFrom<&DiscoveryScanParams>` or
/// [`ScanParams::contract_defaults`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanParams {
    sample_rows: u32,
    /// `0`: no bound requested (becomes the local cap).
    max_duration_s: u32,
    /// `0`: no bound requested (becomes the local cap, never sent).
    statement_timeout_ms: u32,
    databases: Option<Vec<String>>,
    schemas: Option<Vec<String>>,
    include_objects: Option<Vec<String>>,
    exclude_objects: Vec<String>,
    classifiers: Option<Vec<ClassifierId>>,
}

impl ScanParams {
    /// The contract defaults (`sample_rows` 200, `max_duration_s` 900,
    /// `statement_timeout_ms` 30000, no filter), e.g. for connector tests.
    #[must_use]
    pub fn contract_defaults() -> Self {
        Self {
            sample_rows: 200,
            max_duration_s: 900,
            statement_timeout_ms: 30_000,
            databases: None,
            schemas: None,
            include_objects: None,
            exclude_objects: Vec::new(),
            classifiers: None,
        }
    }

    /// Restricts the classifiers (tests and local tooling; the console
    /// filter goes through `TryFrom`).
    ///
    /// # Errors
    /// An empty or duplicated list, like the `TryFrom` gate: an empty
    /// filter never means "all".
    pub fn with_classifiers(mut self, classifiers: &[ClassifierId]) -> Result<Self, ParamsError> {
        self.classifiers = Some(classifier_list(
            "classifiers",
            classifiers.iter().map(|c| c.as_str()),
            MAX_SCAN_CLASSIFIERS,
        )?);
        Ok(self)
    }
}

impl TryFrom<&DiscoveryScanParams> for ScanParams {
    type Error = ParamsError;

    fn try_from(p: &DiscoveryScanParams) -> Result<Self, Self::Error> {
        let sample_rows = in_range(
            "sample_rows",
            i64::try_from(p.sample_rows.get()).unwrap_or(i64::MAX),
            SAMPLE_ROWS_RANGE,
        )?;
        // `0` is outside the contract; read as "no bound requested" and
        // replaced by the local cap in `ScanJob::new`, never sent as is.
        let max_duration_s = if p.max_duration_s == 0 {
            0
        } else {
            in_range("max_duration_s", p.max_duration_s, MAX_DURATION_S_RANGE)?
        };
        let statement_timeout_ms = if p.statement_timeout_ms == 0 {
            0
        } else {
            in_range(
                "statement_timeout_ms",
                p.statement_timeout_ms,
                STATEMENT_TIMEOUT_MS_RANGE,
            )?
        };
        if p.exclude_objects.len() > MAX_OBJECT_FILTERS {
            return Err(err("exclude_objects", "too many items"));
        }
        let classifiers = match &p.classifiers {
            None => None,
            Some(ids) => Some(classifier_list(
                "classifiers",
                ids.iter().map(|c| c.as_str()),
                MAX_SCAN_CLASSIFIERS,
            )?),
        };
        Ok(Self {
            sample_rows,
            max_duration_s,
            statement_timeout_ms,
            databases: include_filter("databases", p.databases.as_ref(), MAX_DATABASE_FILTERS)?,
            schemas: include_filter("schemas", p.schemas.as_ref(), MAX_DATABASE_FILTERS)?,
            include_objects: include_filter(
                "include_objects",
                p.include_objects.as_ref(),
                MAX_OBJECT_FILTERS,
            )?,
            exclude_objects: dedup(&p.exclude_objects),
            classifiers,
        })
    }
}

/// A `discovery.scan` job for one target, clamped to the local limits.
///
/// Connectors read the bounds from here and classify every sampled column
/// through [`ScanJob::classify`], which applies the job's classifier
/// filter, the agent HMAC key and the target phone region. Findings are
/// then built with `ColumnFinding::into_finding` and names normalized with
/// `databastion_classifiers::names`.
///
/// `ScanJob::default()` (connector unit tests only) has the contract
/// defaults clamped to the default limits, no target and no HMAC key (no
/// fingerprints, random sample order); the core never uses it.
#[derive(Clone)]
pub struct ScanJob {
    target: Option<TargetConfig>,
    sample_rows: u32,
    statement_timeout: Duration,
    max_duration: Duration,
    params: ScanParams,
    key: Option<Arc<HmacKey>>,
    pacer: Pacer,
    /// Where the object order starts (see [`ScanJob::rotate`]).
    rotation: u64,
}

impl Default for ScanJob {
    fn default() -> Self {
        let limits = Limits::default();
        let params = ScanParams::contract_defaults();
        Self {
            target: None,
            sample_rows: limits.clamp_sample_rows(u64::from(params.sample_rows)),
            statement_timeout: limits
                .clamp_statement_timeout(u64::from(params.statement_timeout_ms)),
            max_duration: limits.clamp_scan_duration(u64::from(params.max_duration_s)),
            params,
            key: None,
            pacer: Pacer::new(limits.discovery_duty_cycle_percent),
            rotation: 0,
        }
    }
}

impl std::fmt::Debug for ScanJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanJob")
            .field("target", &self.target.as_ref().map(|t| t.id.as_str()))
            .field("sample_rows", &self.sample_rows)
            .field("statement_timeout", &self.statement_timeout)
            .field("max_duration", &self.max_duration)
            .field("classifiers", &self.params.classifiers)
            .field("duty_cycle_percent", &self.pacer.duty_percent())
            .finish_non_exhaustive()
    }
}

impl ScanJob {
    /// Clamps contract-checked parameters to the local hard limits for
    /// `target`.
    #[must_use]
    pub fn new(
        params: ScanParams,
        target: &TargetConfig,
        limits: &Limits,
        key: Arc<HmacKey>,
    ) -> Self {
        let max_duration = limits.clamp_scan_duration(u64::from(params.max_duration_s));
        Self {
            target: Some(target.clone()),
            sample_rows: limits.clamp_sample_rows(u64::from(params.sample_rows)),
            statement_timeout: limits
                .clamp_statement_timeout(u64::from(params.statement_timeout_ms)),
            max_duration,
            params,
            key: Some(key),
            // The scan's window runs from its reception, as the core's
            // deadline does.
            pacer: Pacer::new(limits.discovery_duty_cycle_percent)
                .with_deadline(Instant::now() + max_duration),
            rotation: 0,
        }
    }

    /// The same job, its object order starting at `seed` (the core derives
    /// it from the job id, so successive scans of a target start at
    /// different objects; connectors' tests set it directly).
    #[must_use]
    pub fn with_rotation(mut self, seed: u64) -> Self {
        self.rotation = seed;
        self
    }

    /// Pays the pause owed by the previous units now, before the setup of
    /// the next one (checking or opening a session that may have gone
    /// stale during the pause); the unit then goes through
    /// [`Self::paced`]. [`Paced::OutOfTime`] as for [`Self::paced`].
    ///
    /// # Errors
    /// [`Cancelled`], as [`Self::paced`].
    pub async fn turn(&self) -> Result<Paced<()>, Cancelled> {
        self.pacer.turn().await
    }

    /// Whether the scan ran out of time (see [`Self::paced`]): a connector
    /// checks it before opening a connection for more objects.
    #[must_use]
    pub fn out_of_time(&self) -> bool {
        self.pacer.out_of_time()
    }

    /// Reports `objects` left unsampled because the scan ran out of time
    /// ([`Paced::OutOfTime`]): skipped for a limit (`skipped_limit` in the
    /// job's coverage), logged with counts only.
    pub fn skip_out_of_time(&self, sink: &crate::FindingSink, objects: usize) {
        let n = u64::try_from(objects).unwrap_or(u64::MAX);
        if n == 0 {
            return;
        }
        sink.add_coverage(crate::ScanCoverage {
            limit: n,
            ..crate::ScanCoverage::default()
        });
        tracing::warn!(
            target_id = self.target.as_ref().map_or("", |t| t.id.as_str()),
            objects = n,
            duty_cycle_percent = self.pacer.duty_percent(),
            "scan stopped before its deadline (Discovery pacing): objects not sampled, \
             reported as skipped (limit); raise max_duration_s or the duty cycle"
        );
    }

    /// Rotates a list of objects to scan so that it starts at a position
    /// that changes from scan to scan (security review of #93, M3): an
    /// object that uses up the scan's time (paced at the duty cycle) cannot
    /// hide the same objects after it at every scan. `0` for jobs built
    /// outside the core (tests): no rotation.
    pub fn rotate<T>(&self, items: &mut [T]) {
        if let Some(n) = self.rotation_offset(items.len()) {
            items.rotate_left(n);
        }
    }

    /// Where a list of `len` objects starts for this scan (see
    /// [`Self::rotate`]); `None` without rotation or for an empty list.
    #[must_use]
    pub fn rotation_offset(&self, len: usize) -> Option<usize> {
        let len = u64::try_from(len).ok().filter(|l| *l > 0)?;
        usize::try_from(self.rotation % len).ok().filter(|n| *n > 0)
    }

    /// The same job, its pauses ended by `cancel` (the core, when the scan
    /// stops).
    #[must_use]
    pub(crate) fn with_cancel(mut self, cancel: ScanCancel) -> Self {
        self.pacer = self.pacer.with_cancel(cancel);
        self
    }

    /// The scan's pacer (duty cycle `limits.discovery_duty_cycle_percent`).
    #[must_use]
    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    /// Runs one unit of work against the target (an object's sampling, a
    /// catalog read) after paying the pause the previous units owe, so that
    /// the scan's time in queries stays within the duty cycle
    /// (`crate::pacing`, ADR-0035 proposed). Every connector paces its
    /// per-object sampling and catalog reads through this, releasing what a
    /// unit held (a poisoned session, its samples) before the next call.
    /// [`Paced::OutOfTime`]: the unit did not run because the pause would
    /// reach the scan's deadline; the connector stops sampling and reports
    /// the objects left as skipped for a limit (`ScanCoverage::limit`).
    ///
    /// # Errors
    /// [`Cancelled`] when the scan is cancelled (before the work, or during
    /// the pause): the connector stops (`?` turns it into
    /// [`crate::ConnectorError::Cancelled`]).
    pub async fn paced<F: std::future::Future>(
        &self,
        work: F,
    ) -> Result<Paced<F::Output>, Cancelled> {
        self.pacer.paced(work).await
    }

    /// The declared target (connection settings; never sent to the
    /// console). `None` only for `ScanJob::default()` (tests).
    #[must_use]
    pub fn target(&self) -> Option<&TargetConfig> {
        self.target.as_ref()
    }

    /// Maximum rows (documents, entries) sampled per object, in
    /// `1..=limits.max_sample_rows`.
    #[must_use]
    pub fn sample_rows(&self) -> u32 {
        self.sample_rows
    }

    /// Timeout of every statement: `SET LOCAL statement_timeout` /
    /// `max_execution_time`. At least 100 ms, never `0`.
    #[must_use]
    pub fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }

    /// [`Self::statement_timeout`] in milliseconds (`>= 100`).
    #[must_use]
    pub fn statement_timeout_ms(&self) -> u32 {
        u32::try_from(self.statement_timeout.as_millis())
            .unwrap_or(STATEMENT_TIMEOUT_MS_RANGE.1)
            .max(STATEMENT_TIMEOUT_MS_RANGE.0)
    }

    /// Wall-clock budget of the whole scan (also enforced by the core).
    #[must_use]
    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Classifiers of the job; `None` = all.
    #[must_use]
    pub fn classifiers(&self) -> Option<&[ClassifierId]> {
        self.params.classifiers.as_deref()
    }

    /// Phone region configured for the target (`agent.yaml`).
    #[must_use]
    pub fn phone_region(&self) -> PhoneRegion {
        self.target
            .as_ref()
            .map_or(PhoneRegion::Unknown, TargetConfig::phone_region)
    }

    /// Whether a database (or LDAP suffix) is in scope.
    #[must_use]
    pub fn includes_database(&self, name: &str) -> bool {
        included(self.params.databases.as_deref(), name)
    }

    /// Whether a schema (PostgreSQL) is in scope.
    #[must_use]
    pub fn includes_schema(&self, name: &str) -> bool {
        included(self.params.schemas.as_deref(), name)
    }

    /// Whether a table / collection / objectClass is in scope (include
    /// filter, then exclude filter).
    #[must_use]
    pub fn includes_object(&self, name: &str) -> bool {
        included(self.params.include_objects.as_deref(), name)
            && !self
                .params
                .exclude_objects
                .iter()
                .any(|p| glob_match(p, name))
    }

    /// The column classifier for this job: job classifier filter, agent HMAC
    /// key (fingerprints, stable sample order) and target phone region.
    #[must_use]
    pub fn column_classifier(&self) -> ColumnClassifier<'_> {
        let c = ColumnClassifier::new().phone_region(self.phone_region());
        let c = match &self.key {
            Some(key) => c.with_key(key),
            None => c,
        };
        match &self.params.classifiers {
            Some(only) => c.only(only),
            None => c,
        }
    }

    /// Classifies one column (name + sampled values). At most
    /// [`Self::sample_rows`] values are examined.
    #[must_use]
    pub fn classify(&self, column_name: &str, values: &[RawSample<'_>]) -> Vec<ColumnFinding> {
        let n = values.len().min(self.sample_rows as usize);
        self.column_classifier().classify(column_name, &values[..n])
    }
}

fn included(filter: Option<&[String]>, name: &str) -> bool {
    filter.is_none_or(|f| f.iter().any(|p| glob_match(p, name)))
}

/// Contract `IdentifierPattern`: an exact name, or a glob with `*` (any
/// run) and `?` (one character). Only ever compared, never put in a query.
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// An object whose accesses are always reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveObject {
    /// Database (normalized name, as sent by the console).
    pub database: String,
    /// Schema (PostgreSQL).
    pub schema: Option<String>,
    /// Table / collection.
    pub object: String,
    /// Classifiers found there by Discovery.
    pub classifiers: Vec<ClassifierId>,
}

/// `audit.configure` parameters checked against the contract, before the
/// local clamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditParams {
    enabled: bool,
    aggregation_window_s: u32,
    poll_interval_s: u32,
    min_rows: Option<u64>,
    sensitive_objects: Vec<SensitiveObject>,
}

impl AuditParams {
    /// Whether audit collection is requested.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

fn identifier(field: &'static str, id: &str) -> Result<String, ParamsError> {
    if violates_numeric_rule(id) {
        return Err(err(field, "violates the Identifier `not` rule"));
    }
    Ok(id.to_owned())
}

impl TryFrom<&AuditConfigureParams> for AuditParams {
    type Error = ParamsError;

    fn try_from(p: &AuditConfigureParams) -> Result<Self, Self::Error> {
        let window = i64::try_from(p.aggregation_window_s.get()).unwrap_or(i64::MAX);
        let poll = i64::try_from(p.poll_interval_s.get()).unwrap_or(i64::MAX);
        let min_rows = match &p.min_rows {
            None => None,
            Some(c) if (0..=MAX_COUNT).contains(&c.0) => u64::try_from(c.0).ok(),
            Some(_) => return Err(err("min_rows", "out of the contract range")),
        };
        if p.sensitive_objects.len() > MAX_SENSITIVE_OBJECTS {
            return Err(err("sensitive_objects", "too many items"));
        }
        let mut sensitive_objects = Vec::with_capacity(p.sensitive_objects.len());
        for o in &p.sensitive_objects {
            sensitive_objects.push(SensitiveObject {
                database: identifier("sensitive_objects.database", o.database.as_str())?,
                schema: match &o.schema {
                    Some(s) => Some(identifier("sensitive_objects.schema", s.as_str())?),
                    None => None,
                },
                object: identifier("sensitive_objects.object", o.object.as_str())?,
                classifiers: classifier_list(
                    "sensitive_objects.classifiers",
                    o.classifiers.iter().map(|c| c.as_str()),
                    MAX_OBJECT_CLASSIFIERS,
                )?,
            });
        }
        Ok(Self {
            enabled: p.enabled,
            aggregation_window_s: in_range(
                "aggregation_window_s",
                window,
                AGGREGATION_WINDOW_S_RANGE,
            )?,
            poll_interval_s: in_range("poll_interval_s", poll, POLL_INTERVAL_S_RANGE)?,
            min_rows,
            sensitive_objects,
        })
    }
}

/// Audit configuration of a target (`audit.configure` job), clamped to the
/// local limits. `AuditConfig::default()` (tests) is disabled, with the
/// contract defaults and the default limits, and no target.
#[derive(Clone)]
pub struct AuditConfig {
    target_id: String,
    target: Option<TargetConfig>,
    state_dir: Option<PathBuf>,
    enabled: bool,
    aggregation_window: Duration,
    poll_interval: Duration,
    statement_timeout: Duration,
    min_rows: Option<u64>,
    sensitive_objects: Vec<SensitiveObject>,
    max_sample_rows: u32,
    /// The cursors used by the stream, and the core's isolation / skip
    /// request (see [`crate::audit::CursorStore::skip_records`]).
    positions: Option<crate::audit::PositionRegistry>,
    isolate: bool,
    skip_records: u32,
    /// Sub-key for the integrity tags of the cursors (see
    /// [`crate::audit::CursorStore::with_tag_key`]).
    tag_key: Option<std::sync::Arc<databastion_classifiers::masking::LocalTagKey>>,
}

impl std::fmt::Debug for AuditConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditConfig")
            .field("target_id", &self.target_id)
            .field("enabled", &self.enabled)
            .field("aggregation_window", &self.aggregation_window)
            .field("poll_interval", &self.poll_interval)
            .field("min_rows", &self.min_rows)
            .field("sensitive_objects", &self.sensitive_objects.len())
            .finish_non_exhaustive()
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            target_id: String::new(),
            target: None,
            state_dir: None,
            enabled: false,
            aggregation_window: Duration::from_secs(60),
            poll_interval: Duration::from_secs(u64::from(limits.min_audit_poll_interval_s.max(10))),
            statement_timeout: limits.clamp_statement_timeout(0),
            min_rows: None,
            sensitive_objects: Vec::new(),
            max_sample_rows: limits.max_sample_rows,
            positions: None,
            isolate: false,
            skip_records: 0,
            tag_key: None,
        }
    }
}

impl AuditConfig {
    /// Clamps contract-checked parameters to the local hard limits for
    /// `target`: the poll interval is at least
    /// `limits.min_audit_poll_interval_s`.
    #[must_use]
    pub fn new(params: AuditParams, target: &TargetConfig, limits: &Limits) -> Self {
        Self {
            target_id: target.id.clone(),
            target: Some(target.clone()),
            state_dir: None,
            enabled: params.enabled,
            aggregation_window: Duration::from_secs(u64::from(params.aggregation_window_s)),
            poll_interval: Duration::from_secs(u64::from(
                params.poll_interval_s.max(limits.min_audit_poll_interval_s),
            )),
            statement_timeout: limits.clamp_statement_timeout(0),
            min_rows: params.min_rows,
            sensitive_objects: params.sensitive_objects,
            max_sample_rows: limits.max_sample_rows,
            positions: None,
            isolate: false,
            skip_records: 0,
            tag_key: None,
        }
    }

    /// `limits.max_sample_rows`: the most rows the agent's own Discovery
    /// reads per object. Audit connectors report the agent's own account
    /// once it reads more than this per object within a window.
    #[must_use]
    pub fn max_sample_rows(&self) -> u32 {
        self.max_sample_rows
    }

    /// Audit settings built locally (integration tests, tools): enabled,
    /// contract defaults (60 s aggregation window, no `min_rows`, no
    /// sensitive object), and `poll_interval_s` clamped exactly like a job's
    /// (contract range, then the `min_audit_poll_interval_s` floor).
    #[must_use]
    pub fn local(target: &TargetConfig, poll_interval_s: u32, limits: &Limits) -> Self {
        let poll = poll_interval_s.clamp(POLL_INTERVAL_S_RANGE.0, POLL_INTERVAL_S_RANGE.1);
        Self::new(
            AuditParams {
                enabled: true,
                aggregation_window_s: 60,
                poll_interval_s: poll,
                min_rows: None,
                sensitive_objects: Vec::new(),
            },
            target,
            limits,
        )
    }

    /// Sets the directory where the connector keeps its audit cursors
    /// (`<state_dir>/audit`, created `0700` by the core; see
    /// [`Self::cursor`]).
    #[must_use]
    pub fn with_state_dir(mut self, dir: PathBuf) -> Self {
        self.state_dir = Some(dir);
        self
    }

    /// The declared target (connection settings, audit log path; never
    /// sent to the console). `None` only for `AuditConfig::default()`.
    #[must_use]
    pub fn target(&self) -> Option<&TargetConfig> {
        self.target.as_ref()
    }

    /// The persisted cursor `name` (`[a-z0-9_.-]`, e.g. `pgaudit`) of this
    /// target's audit source: a `0600` file under `<state_dir>/audit/`.
    /// `None` without a state directory (tests) or for an invalid name.
    #[must_use]
    pub fn cursor(&self, name: &str) -> Option<crate::audit::CursorStore> {
        let store =
            crate::audit::CursorStore::new(self.state_dir.as_deref()?, &self.target_id, name)?;
        let store = match &self.tag_key {
            Some(key) => store.with_tag_key(std::sync::Arc::clone(key)),
            None => store,
        };
        Some(match &self.positions {
            Some(p) => p.register(store, self.isolate, self.skip_records),
            None => store,
        })
    }

    /// The persisted counters `name` (`[a-z0-9_.-]`, e.g. `own_usage`) of
    /// this target: a `0600` file under `<state_dir>/audit/` (see
    /// [`crate::audit::CursorStore::counters`]), kept across agent restarts
    /// but never part of the stream's read position (a panic does not pin
    /// it). `None` without a state directory (tests) or for an invalid
    /// name.
    #[must_use]
    pub fn counters(&self, name: &str) -> Option<crate::audit::CursorStore> {
        crate::audit::CursorStore::counters(self.state_dir.as_deref()?, &self.target_id, name)
    }

    /// The core's registry of the cursors this stream uses, and its
    /// request after panics (isolation mode, one record to skip at the
    /// exact position it panicked at; see
    /// [`crate::audit::CursorStore::skip_records`]).
    #[must_use]
    pub(crate) fn with_positions(
        mut self,
        positions: crate::audit::PositionRegistry,
        isolate: bool,
        skip: u32,
    ) -> Self {
        self.positions = Some(positions);
        self.isolate = isolate;
        self.skip_records = skip;
        self
    }

    /// The sub-key of the agent key the cursors use for their integrity
    /// tags (see [`crate::audit::CursorStore::with_tag_key`]).
    #[must_use]
    pub(crate) fn with_tag_key(
        mut self,
        key: Option<std::sync::Arc<databastion_classifiers::masking::LocalTagKey>>,
    ) -> Self {
        self.tag_key = key;
        self
    }

    /// Target id.
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Whether audit collection is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Pre-aggregation window.
    #[must_use]
    pub fn aggregation_window(&self) -> Duration {
        self.aggregation_window
    }

    /// Polling interval of polled sources.
    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Timeout of every statement against the target (local cap, never 0).
    #[must_use]
    pub fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }

    /// Row threshold for non-sensitive objects without a signal.
    #[must_use]
    pub fn min_rows(&self) -> Option<u64> {
        self.min_rows
    }

    /// Objects whose accesses are always reported.
    #[must_use]
    pub fn sensitive_objects(&self) -> &[SensitiveObject] {
        &self.sensitive_objects
    }

    /// Whether an object (normalized names, as sent in events) is listed
    /// in `sensitive_objects`. A listed object without a schema matches
    /// any schema.
    #[must_use]
    pub fn is_sensitive(&self, database: &str, schema: Option<&str>, object: &str) -> bool {
        self.sensitive_objects.iter().any(|o| {
            o.database == database
                && o.object == object
                && o.schema.as_deref().is_none_or(|s| Some(s) == schema)
        })
    }
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod tests;
