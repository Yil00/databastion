//! Job parameters handed to connectors (I4, ADR-0012 obligation 4).
//!
//! Console job parameters reach a connector **only** through this module:
//!
//! 1. `TryFrom<&DiscoveryScanParams>` for [`ScanParams`] and
//!    `TryFrom<&AuditConfigureParams>` for [`AuditParams`] enforce the
//!    contract ranges and the keywords serde does not (`minItems`,
//!    `maxItems`, `uniqueItems`, the `Identifier` `not` rule), and map
//!    classifier ids through `ClassifierId::parse` (unknown id = error). An
//!    empty filter list (`Some([])`) is rejected: it never means "all".
//! 2. [`ScanJob::new`] / [`AuditConfig::new`] then clamp the values to the
//!    local hard limits of `agent.yaml` (`limits`). A statement timeout is
//!    never `0` (unlimited on PostgreSQL / MySQL): a requested `0` becomes
//!    the local cap.
//!
//! [`ScanJob`] and [`AuditConfig`] have private fields and no other
//! constructor, so a connector always gets clamped values. Connectors never
//! see the generated protocol types.

use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::column::{ColumnClassifier, ColumnFinding};
use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{HmacKey, PhoneRegion, RawSample};
use databastion_classifiers::names::violates_numeric_rule;
use databastion_protocol::{AuditConfigureParams, DiscoveryScanParams, IdentifierPattern};

use crate::config::{Limits, SAMPLE_ROWS_RANGE, STATEMENT_TIMEOUT_MS_RANGE, TargetConfig};

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

/// An optional include filter: absent = all, `Some([])` is refused.
fn include_filter(
    field: &'static str,
    list: Option<&Vec<IdentifierPattern>>,
    max: usize,
) -> Result<Option<Vec<String>>, ParamsError> {
    match list {
        None => Ok(None),
        Some(l) if l.is_empty() => Err(err(field, "empty list (absent means all)")),
        Some(l) if l.len() > max => Err(err(field, "too many items")),
        Some(l) => Ok(Some(l.iter().map(|p| p.as_str().to_owned()).collect())),
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
    #[must_use]
    pub fn with_classifiers(mut self, classifiers: &[ClassifierId]) -> Self {
        self.classifiers = (!classifiers.is_empty()).then(|| classifiers.to_vec());
        self
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
            exclude_objects: p
                .exclude_objects
                .iter()
                .map(|x| x.as_str().to_owned())
                .collect(),
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
        Self {
            target: Some(target.clone()),
            sample_rows: limits.clamp_sample_rows(u64::from(params.sample_rows)),
            statement_timeout: limits
                .clamp_statement_timeout(u64::from(params.statement_timeout_ms)),
            max_duration: limits.clamp_scan_duration(u64::from(params.max_duration_s)),
            params,
            key: Some(key),
        }
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
/// contract defaults and the default limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    target_id: String,
    enabled: bool,
    aggregation_window: Duration,
    poll_interval: Duration,
    statement_timeout: Duration,
    min_rows: Option<u64>,
    sensitive_objects: Vec<SensitiveObject>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            target_id: String::new(),
            enabled: false,
            aggregation_window: Duration::from_secs(60),
            poll_interval: Duration::from_secs(u64::from(limits.min_audit_poll_interval_s.max(10))),
            statement_timeout: limits.clamp_statement_timeout(0),
            min_rows: None,
            sensitive_objects: Vec::new(),
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
            enabled: params.enabled,
            aggregation_window: Duration::from_secs(u64::from(params.aggregation_window_s)),
            poll_interval: Duration::from_secs(u64::from(
                params.poll_interval_s.max(limits.min_audit_poll_interval_s),
            )),
            statement_timeout: limits.clamp_statement_timeout(0),
            min_rows: params.min_rows,
            sensitive_objects: params.sensitive_objects,
        }
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
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod tests;
