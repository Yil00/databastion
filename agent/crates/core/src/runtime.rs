//! Agent runtime: enrollment, heartbeat loop and jobs long-poll loop.
//!
//! The binary only gets [`enroll`] and [`run`]; the uplink, the session and
//! the generated protocol types stay private to this crate.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::id::CLASSIFIERS_VERSION;
use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_protocol::{
    AgentVersion, ClassifiersVersion, Connector as ProtoConnector, ConnectorList, DetectedTarget,
    EnrollRequest, EnrollRequestArch, EnrollRequestOs, EnrollResponse, EnrollmentToken,
    FailureCode, HeartbeatRequest, HeartbeatResponse, Hostname, Job, JobError, JobStatusUpdate,
    MetricsMap, MetricsMapKey, TargetId, TargetStatus, Timestamp, Uuid,
};
use reqwest::Method;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::audit::{self, Aggregator};
use crate::backoff;
use crate::config::{AgentConfig, ConfigError, TargetEngine};
use crate::connector::Connector;
use crate::detect;
use crate::engine::{AuditLevel, Engine};
use crate::identity::{Identity, IdentityError, StateDir};
use crate::job::{AuditConfig, AuditParams, ScanJob, ScanParams};
use crate::jobs::{self, Ledger, LedgerEntry, Outcome, PolledJob};
use crate::session::{CallError, RotateOutcome, Session};
use crate::sink::{EventSink, FindingSink};
use crate::spool::Spool;
use crate::uplink::{self, Auth, ResultBatch, Uplink, UplinkError};

/// Errors returned to the binary. Messages never contain a secret or a
/// configuration value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// Invalid configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Identity / state directory problem.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Enrollment failed.
    #[error("enrollment failed: {0}")]
    Enrollment(String),
    /// Uplink setup or unrecoverable uplink error.
    #[error("uplink: {0}")]
    Uplink(String),
    /// The console locked this agent (`rotation_conflict`).
    #[error("rotation conflict: the console locked this agent; revoke and re-enroll it")]
    RotationConflict,
}

impl From<UplinkError> for AgentError {
    fn from(e: UplinkError) -> Self {
        Self::Uplink(e.to_string())
    }
}

impl From<CallError> for AgentError {
    fn from(e: CallError) -> Self {
        match e {
            CallError::RotationConflict => Self::RotationConflict,
            CallError::Identity(e) => Self::Identity(e),
            other => Self::Uplink(other.to_string()),
        }
    }
}

fn now() -> Timestamp {
    Timestamp(chrono::DateTime::<chrono::Utc>::from(SystemTime::now()))
}

/// The classifier set of this build (`CLASSIFIERS_VERSION`), reported in
/// heartbeats and findings batches.
fn classifiers_version() -> Option<ClassifiersVersion> {
    ClassifiersVersion::try_from(CLASSIFIERS_VERSION).ok()
}

/// Findings of a scan converted and spooled per chunk of this many.
const FINDINGS_CHUNK: usize = 500;
/// Capacity of the finding channel between a connector and the core.
const FINDINGS_CHANNEL: usize = 64;
/// Contract per-job findings cap (`MAX_FINDINGS_PER_JOB`, docs/09
/// "Console-side checks"): a scan stops producing at this many findings and
/// ends `failed` / `resource_limit`, so the console never has to answer `400`
/// `maxItems`.
pub(crate) const MAX_FINDINGS_PER_JOB: usize = 50_000;

fn agent_version() -> Result<AgentVersion, AgentError> {
    AgentVersion::try_from(env!("CARGO_PKG_VERSION"))
        .map_err(|_| AgentError::Uplink("invalid agent version".to_owned()))
}

fn proto_connector(engine: Engine) -> ProtoConnector {
    match engine {
        Engine::Postgres => ProtoConnector::Postgres,
        Engine::Mysql => ProtoConnector::Mysql,
        Engine::Mongodb => ProtoConnector::Mongodb,
        Engine::Openldap => ProtoConnector::Openldap,
    }
}

fn connector_list(engines: &[Engine]) -> ConnectorList {
    ConnectorList(engines.iter().copied().map(proto_connector).collect())
}

fn hostname() -> Hostname {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|h| Hostname::try_from(h.trim()).ok())
        .or_else(|| Hostname::try_from("localhost").ok())
        .unwrap_or_else(fallback_hostname)
}

#[allow(clippy::expect_used, reason = "constant literal matching the pattern")]
fn fallback_hostname() -> Hostname {
    Hostname::try_from("unknown").expect("valid hostname literal")
}

/// Reads the enrollment token from a file (surrounding whitespace ignored).
/// Refused if others can read it; warns if the group can.
fn read_token(path: &Path) -> Result<EnrollmentToken, AgentError> {
    use std::os::unix::fs::MetadataExt as _;
    let mode = std::fs::metadata(path)
        .map_err(|e| {
            AgentError::Enrollment(format!(
                "cannot read the token file {}: {}",
                path.display(),
                e.kind()
            ))
        })?
        .mode();
    if mode & 0o007 != 0 {
        return Err(AgentError::Enrollment(
            "the token file is readable by others; restrict it to 0600 (and \
             revoke the token in the console if it may have been read)"
                .into(),
        ));
    }
    if mode & 0o070 != 0 {
        tracing::warn!("the token file is accessible by its group; 0600 is recommended");
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        AgentError::Enrollment(format!(
            "cannot read the token file {}: {}",
            path.display(),
            e.kind()
        ))
    })?);
    EnrollmentToken::try_from(text.trim()).map_err(|_| {
        AgentError::Enrollment("the token file does not contain a valid enrollment token".into())
    })
}

/// Maximum attempts for `POST /enroll` on retryable errors.
const ENROLL_ATTEMPTS: u32 = 5;

/// Enrollment options.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrollOptions {
    /// Replace an existing identity. Revoke the old agent in the console
    /// first: its secret stays valid until then.
    pub force: bool,
    /// Also replace an existing local HMAC key (fingerprints computed
    /// before will no longer correlate). Without it, an existing key is
    /// kept.
    pub new_hmac_key: bool,
}

/// Enrolls the agent: exchanges the token for an identity, stores it
/// (`0600`, atomic) and generates the local HMAC key (never transmitted)
/// unless one exists and `new_hmac_key` is not set. Returns the agent id.
///
/// # Errors
/// [`AgentError`]; an existing identity is only replaced with `force`.
pub async fn enroll(
    config: &AgentConfig,
    token_file: &Path,
    options: EnrollOptions,
    engines: &[Engine],
) -> Result<String, AgentError> {
    let force = options.force;
    let state = StateDir::new(&config.state_dir);
    if state.has_identity() && !force {
        return Err(IdentityError::AlreadyEnrolled(state.identity_path()).into());
    }
    state.ensure()?;
    let token = read_token(token_file)?;
    let uplink = Uplink::new(config)?;
    let request = EnrollRequest {
        agent_version: agent_version()?,
        arch: EnrollRequestArch::try_from(std::env::consts::ARCH).ok(),
        connectors: connector_list(engines),
        hostname: hostname(),
        os: Some(EnrollRequestOs::Linux),
        token,
    };
    let body = Zeroizing::new(
        serde_json::to_vec(&request)
            .map_err(|_| AgentError::Enrollment("cannot encode the request".into()))?,
    );
    drop(request);
    let mut attempt = 0;
    let reply = loop {
        match uplink
            .request(
                Method::POST,
                "/enroll",
                &[],
                Auth::Anonymous,
                Some(&body),
                uplink::REQUEST_TIMEOUT,
            )
            .await
        {
            Ok(reply) => break reply,
            Err(UplinkError::Unauthorized) => {
                return Err(AgentError::Enrollment(
                    "token rejected (unknown, expired or already used); not retried. If a \
                     previous attempt with this token lost its response, the console may hold \
                     an orphan agent: revoke it and create a new token"
                        .into(),
                ));
            }
            Err(e) if e.is_retryable() && attempt + 1 < ENROLL_ATTEMPTS => {
                let delay = e.retry_delay(attempt);
                tracing::warn!(error = %e, delay_ms = delay.as_millis() as u64, "enrollment retry");
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let response: EnrollResponse = serde_json::from_slice(&reply.body)
        .map_err(|_| AgentError::Enrollment("invalid enrollment response".into()))?;
    let interval = backoff::clamp_heartbeat_interval(response.heartbeat_interval_s.0)
        .unwrap_or(backoff::HEARTBEAT_DEFAULT_S);
    let identity = Identity {
        agent_id: response.agent_id,
        secret: response.agent_secret,
        pending: None,
        rotation_jobs: Vec::new(),
        heartbeat_interval_s: interval,
    };
    state.save_identity(&identity)?;
    if options.new_hmac_key || !state.has_hmac_key() {
        state.create_hmac_key()?;
    } else {
        // Validates permissions and length of the kept key.
        state.load_hmac_key()?;
        tracing::info!("existing local HMAC key kept");
    }
    tracing::info!(agent_id = %identity.agent_id, "agent enrolled");
    Ok(identity.agent_id.to_string())
}

/// Run state shared by the loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunState {
    /// Normal operation.
    Active,
    /// Fatal `401`: no job polling; one heartbeat every 15 min.
    Suspended,
}

#[derive(Default)]
struct Counters {
    heartbeats_sent: AtomicU64,
    heartbeat_failures: AtomicU64,
    jobs_received: AtomicU64,
    jobs_failed: AtomicU64,
    jobs_unparseable: AtomicU64,
    jobs_deferred: AtomicU64,
    batches_sent: AtomicU64,
    batches_duplicate: AtomicU64,
    batches_rejected: AtomicU64,
    batch_conflicts: AtomicU64,
    batches_unexpected_response: AtomicU64,
    /// Batches lost because their serialization failed (on spooling or when
    /// splitting a spooled batch).
    batches_serialization_failed: AtomicU64,
    /// Jobs refused by the parameter gates (`invalid_params`).
    jobs_invalid_params: AtomicU64,
    /// Findings received from connectors (before sanitization).
    findings_received: AtomicU64,
    /// Findings lost because they could not be spooled.
    findings_lost: AtomicU64,
    /// Batches answered `501` (endpoint parked, batch kept).
    batches_parked: AtomicU64,
    /// Scans stopped at the per-job findings cap.
    scans_findings_capped: AtomicU64,
    /// Scans refused: classifier set not supported by this build.
    jobs_unsupported_classifiers: AtomicU64,
    /// Access events received from connectors (before aggregation).
    events_received: AtomicU64,
    /// Aggregated events not reported (`audit.configure` filter).
    events_filtered: AtomicU64,
    /// Aggregated events lost because they could not be spooled.
    events_lost: AtomicU64,
    /// Audit streams that ended with an error (restarted with backoff).
    audit_stream_failures: AtomicU64,
}

/// Capacity of the event channel between a connector and the core.
const EVENTS_CHANNEL: usize = 256;
/// Longest backoff before restarting a failed audit stream.
const AUDIT_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Audit settings per target (`audit.configure`), with a generation that
/// changes on every update so the audit worker restarts that stream.
#[derive(Default)]
struct AuditTable {
    next_generation: u64,
    entries: std::collections::HashMap<String, (u64, AuditParams)>,
}

impl AuditTable {
    fn set(&mut self, target_id: &str, params: Option<AuditParams>) {
        match params {
            Some(p) => {
                self.next_generation += 1;
                self.entries
                    .insert(target_id.to_owned(), (self.next_generation, p));
            }
            None => {
                self.entries.remove(target_id);
            }
        }
    }

    /// Restarts every stream (configuration reloaded).
    fn bump_all(&mut self) {
        for entry in self.entries.values_mut() {
            self.next_generation += 1;
            entry.0 = self.next_generation;
        }
    }

    fn snapshot(&self) -> Vec<(String, u64, AuditParams)> {
        self.entries
            .iter()
            .map(|(id, (g, p))| (id.clone(), *g, p.clone()))
            .collect()
    }
}

/// How an audit session ended.
enum AuditEnd {
    /// Stopped by the audit worker (disabled, reconfigured, shutdown).
    Stopped,
    /// The connector returned (an error, or unexpectedly).
    Failed(Option<crate::ConnectorError>),
}

/// A `discovery.scan` that passed the gates, waiting for the scan worker.
struct PreparedScan {
    id: Uuid,
    target_id: TargetId,
    engine: databastion_protocol::Engine,
    /// Index in `Runtime::connectors`.
    connector: usize,
    scan: ScanJob,
    /// When the job was received: its (clamped) `max_duration_s` runs from
    /// here, whether the scan waits in the queue or runs, so it never
    /// outlives the console's findings window for the job.
    received: Instant,
}

/// Scans waiting for the worker, and the ids queued or running (a
/// redelivered job is not queued twice).
#[derive(Default)]
struct ScanQueue {
    queued: std::collections::VecDeque<PreparedScan>,
    in_flight: std::collections::HashSet<Uuid>,
}

/// Scans queued at most; more are left unacknowledged and redelivered.
const MAX_QUEUED_SCANS: usize = 16;

fn bump(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

struct Runtime {
    config_path: PathBuf,
    config: RwLock<AgentConfig>,
    session: Session,
    connectors: Vec<Box<dyn Connector>>,
    started: Instant,
    counters: Counters,
    ledger: Mutex<Ledger>,
    state: watch::Sender<RunState>,
    spool: Mutex<Spool>,
    /// Agent-local HMAC key (fingerprints, sample order), loaded once at
    /// startup from `<state_dir>/hmac.key`. Never sent, logged or
    /// serialized (redacted `Debug`, zeroized on drop).
    hmac: Arc<HmacKey>,
    /// Scans waiting for, or run by, the scan worker.
    scans: Mutex<ScanQueue>,
    /// Wakes the scan worker when a scan is queued.
    scan_ready: tokio::sync::Notify,
    /// Host root for local detection (`/`; a fixture tree in tests).
    host_root: PathBuf,
    /// Heartbeats refused with a fatal `401` since the last success.
    unauthorized_heartbeats: std::sync::atomic::AtomicU32,
    /// Optional request fields the console accepts (ADR-0022).
    console_caps: crate::capabilities::ConsoleCapabilities,
    /// Last local detection result and when it was computed.
    detection: Mutex<Option<(Instant, Vec<DetectedTarget>)>>,
    /// Result endpoints parked after a `501`.
    parked: Mutex<Parked>,
    /// Findings emitted per job at most ([`MAX_FINDINGS_PER_JOB`]; lowered
    /// in tests).
    findings_cap: usize,
    /// Audit settings per target.
    audits: Mutex<AuditTable>,
    /// Wakes the audit worker when `audits` changes.
    audit_changed: tokio::sync::Notify,
}

/// A result endpoint parked after a `501` (not implemented by this
/// console): its batches stay spooled and are not sent before `until`.
#[derive(Debug, Clone, Copy, Default)]
struct Park {
    until: Option<Instant>,
    /// Consecutive `501`s (own backoff without `Retry-After`).
    strikes: u32,
}

/// Parking state of `/findings` and `/events` (docs/09, "Agent handling",
/// `501`): per endpoint, so a parked `/events` never blocks `/findings`.
#[derive(Debug, Default)]
struct Parked {
    findings: Park,
    events: Park,
}

impl Parked {
    fn get(&mut self, findings: bool) -> &mut Park {
        if findings {
            &mut self.findings
        } else {
            &mut self.events
        }
    }

    /// Whether the endpoint is parked at `now` (an elapsed park is cleared).
    fn is_parked(&mut self, findings: bool, now: Instant) -> bool {
        let park = self.get(findings);
        match park.until {
            Some(until) if until > now => true,
            Some(_) => {
                park.until = None;
                false
            }
            None => false,
        }
    }

    /// Parks the endpoint after a `501`; returns the parking delay:
    /// `Retry-After` (already clamped to `1..=3600` s) plus jitter, else the
    /// spool backoff of the consecutive `501`s.
    fn park(
        &mut self,
        findings: bool,
        retry_after: Option<Duration>,
        now: Instant,
        fraction: f64,
    ) -> Duration {
        let park = self.get(findings);
        park.strikes = park.strikes.saturating_add(1);
        let delay = retry_after.map_or_else(
            || spool_backoff(park.strikes, fraction),
            |ra| backoff::retry_after_delay(ra, fraction),
        );
        park.until = Some(now + delay);
        delay
    }

    /// A batch of the endpoint was answered: its `501` streak ends.
    fn answered(&mut self, findings: bool) {
        *self.get(findings) = Park::default();
    }
}

/// How long a local detection result is reused.
const DETECTION_TTL: Duration = Duration::from_secs(300);

/// Longest delay between two attempts to send the same spooled batch.
const SPOOL_MAX_RETRY: Duration = Duration::from_secs(300);

/// Backoff before retrying a spooled batch after `failures` consecutive
/// failures (1-based): 1 s doubling up to 5 min, full jitter.
fn spool_backoff(failures: u32, fraction: f64) -> Duration {
    backoff::Backoff::CONSOLE
        .delay(failures.saturating_sub(1), fraction)
        .min(SPOOL_MAX_RETRY)
}

/// A spool write failed (logged by kind only).
struct SpoolIo;

/// Result of one spool flush step.
#[derive(Debug, PartialEq, Eq)]
enum Flush {
    /// Nothing to send.
    Idle,
    /// A batch was sent, dropped or replaced; continue.
    Progress,
    /// Retry the same batch later.
    Retry(Duration),
}

/// Runs the agent until `shutdown` becomes `true`.
///
/// # Errors
/// Startup errors (configuration, identity, uplink setup) and fatal errors
/// (`rotation_conflict`).
pub async fn run(
    config_path: &Path,
    connectors: Vec<Box<dyn Connector>>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), AgentError> {
    // Compile every classifier pattern before anything else: a pattern that
    // does not compile (a build defect, e.g. a missing `regex` feature)
    // stops the agent here with the pattern name, never silently disabling
    // a detector during a scan.
    databastion_classifiers::detect::check_patterns();
    let config = AgentConfig::load(config_path)?;
    let runtime = Runtime::new(config_path, config, connectors)?;
    runtime.run(shutdown).await
}

impl Runtime {
    fn new(
        config_path: &Path,
        config: AgentConfig,
        connectors: Vec<Box<dyn Connector>>,
    ) -> Result<Self, AgentError> {
        let state = StateDir::new(&config.state_dir);
        let identity = state.load_identity()?;
        // The HMAC key (fingerprints); it is never sent. The raw bytes are
        // zeroized once the keyed HMAC state is built.
        let hmac = {
            let bytes = state.load_hmac_key()?;
            HmacKey::new(&bytes)
                .map(Arc::new)
                .map_err(|_| IdentityError::Corrupt(state.hmac_key_path()))?
        };
        let uplink = Uplink::new(&config)?;
        tracing::info!(agent_id = %identity.agent_id, "identity loaded");
        let spool = Spool::open(&config.state_dir, &config.spool).map_err(|e| {
            AgentError::Identity(IdentityError::Io {
                path: config.state_dir.join("spool"),
                kind: e.kind(),
                detail: "",
            })
        })?;
        Ok(Self {
            config_path: config_path.to_owned(),
            config: RwLock::new(config),
            session: Session::new(uplink, state, identity),
            connectors,
            started: Instant::now(),
            counters: Counters::default(),
            ledger: Mutex::new(Ledger::default()),
            state: watch::channel(RunState::Active).0,
            spool: Mutex::new(spool),
            hmac,
            scans: Mutex::new(ScanQueue::default()),
            scan_ready: tokio::sync::Notify::new(),
            host_root: PathBuf::from("/"),
            detection: Mutex::new(None),
            unauthorized_heartbeats: std::sync::atomic::AtomicU32::new(0),
            console_caps: crate::capabilities::ConsoleCapabilities::default(),
            parked: Mutex::new(Parked::default()),
            findings_cap: MAX_FINDINGS_PER_JOB,
            audits: Mutex::new(AuditTable::default()),
            audit_changed: tokio::sync::Notify::new(),
        })
    }

    async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let heartbeat = self.heartbeat_loop(shutdown.clone());
        let jobs = self.jobs_loop(shutdown.clone());
        let scans = self.scan_loop(shutdown.clone());
        let audits = self.audit_loop(shutdown.clone());
        let spool = self.spool_loop(shutdown);
        tokio::select! {
            r = heartbeat => r,
            r = jobs => r,
            r = scans => r,
            r = audits => r,
            r = spool => r,
        }
    }

    fn config(&self) -> AgentConfig {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set_state(&self, state: RunState) {
        self.state.send_if_modified(|s| {
            let changed = *s != state;
            *s = state;
            changed
        });
    }

    // ------------------------------------------------------------ heartbeat

    async fn target_statuses(&self, config: &AgentConfig) -> Vec<TargetStatus> {
        let mut out = Vec::with_capacity(config.targets.len());
        for target in &config.targets {
            let Ok(target_id) = TargetId::try_from(target.id.as_str()) else {
                continue; // validated by config; unreachable in practice
            };
            let connector = self
                .connectors
                .iter()
                .find(|c| c.engine() == target.engine.connector());
            let (reachable, level, last_error) = match connector {
                None => (false, AuditLevel::None, Some(FailureCode::Unsupported)),
                Some(c) => {
                    match tokio::time::timeout(Duration::from_secs(10), c.check(target)).await {
                        Ok(h) => (h.reachable, h.audit_level, h.failure),
                        Err(_) => (false, AuditLevel::None, Some(FailureCode::Timeout)),
                    }
                }
            };
            let audit_source = match connector {
                Some(c) if level != AuditLevel::None => c.audit_source(target).and_then(|s| {
                    serde_json::from_value::<databastion_protocol::AuditSource>(
                        serde_json::Value::from(s.as_str()),
                    )
                    .ok()
                }),
                _ => None,
            };
            // `notes` (closed codes from the connector's `check()`) are not produced yet
            // (ROADMAP P2-G); when they are, they are sent only if the console accepts
            // `target_status.notes` (ADR-0022, `capabilities`).
            out.push(TargetStatus {
                audit_level: proto_audit_level(level),
                audit_source,
                edition: None,
                engine: proto_engine(target.engine),
                last_error,
                metrics: None,
                notes: Vec::new(),
                reachable,
                server_version: None,
                target_id,
            });
        }
        out
    }

    fn metrics(&self) -> MetricsMap {
        let c = &self.counters;
        let mut map = std::collections::HashMap::new();
        for (name, value) in [
            ("heartbeats_sent_total", &c.heartbeats_sent),
            ("heartbeat_failures_total", &c.heartbeat_failures),
            ("jobs_received_total", &c.jobs_received),
            ("jobs_failed_total", &c.jobs_failed),
            ("jobs_unparseable_total", &c.jobs_unparseable),
            ("jobs_deferred_total", &c.jobs_deferred),
            ("jobs_invalid_params_total", &c.jobs_invalid_params),
            ("findings_received_total", &c.findings_received),
            ("findings_lost_total", &c.findings_lost),
            ("batches_sent_total", &c.batches_sent),
            ("batches_duplicate_total", &c.batches_duplicate),
            ("batches_rejected_total", &c.batches_rejected),
            ("batch_conflicts_total", &c.batch_conflicts),
            ("batches_parked_total", &c.batches_parked),
            ("scans_findings_capped_total", &c.scans_findings_capped),
            (
                "jobs_unsupported_classifiers_total",
                &c.jobs_unsupported_classifiers,
            ),
            (
                "batches_unexpected_response_total",
                &c.batches_unexpected_response,
            ),
            (
                "batches_serialization_failed_total",
                &c.batches_serialization_failed,
            ),
            ("events_received_total", &c.events_received),
            ("events_filtered_total", &c.events_filtered),
            ("events_lost_total", &c.events_lost),
            ("audit_stream_failures_total", &c.audit_stream_failures),
        ] {
            if let Ok(key) = MetricsMapKey::try_from(name) {
                #[allow(clippy::cast_precision_loss, reason = "metric counters")]
                map.insert(key, value.load(Ordering::Relaxed) as f64);
            }
        }
        let quarantined = self.lock_spool().counters.quarantined;
        if let Ok(key) = MetricsMapKey::try_from("spool_quarantined_total") {
            #[allow(clippy::cast_precision_loss, reason = "metric counters")]
            map.insert(key, quarantined as f64);
        }
        MetricsMap(map)
    }

    /// Local detection (ADR-0006), off the async threads and cached for
    /// [`DETECTION_TTL`]: it walks `/proc`.
    async fn detected_targets(&self, config: &AgentConfig) -> Vec<DetectedTarget> {
        {
            let cache = self
                .detection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((at, found)) = cache.as_ref() {
                if at.elapsed() < DETECTION_TTL {
                    return found.clone();
                }
            }
        }
        let root = self.host_root.clone();
        let targets = config.targets.clone();
        let found = tokio::task::spawn_blocking(move || {
            detect::detect(
                &detect::HostView {
                    root: &root,
                    is_socket: detect::is_unix_socket,
                },
                &targets,
            )
        })
        .await
        .unwrap_or_default();
        *self
            .detection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((Instant::now(), found.clone()));
        found
    }

    async fn build_heartbeat(&self) -> Result<HeartbeatRequest, AgentError> {
        let config = self.config();
        let engines: Vec<Engine> = self.connectors.iter().map(|c| c.engine()).collect();
        let spool = self.lock_spool().status();
        let detected_targets = self.detected_targets(&config).await;
        Ok(HeartbeatRequest {
            // No console -> agent field needs negotiating yet (ADR-0022).
            accepts: None,
            agent_version: agent_version()?,
            classifiers_version: classifiers_version(),
            connectors: connector_list(&engines),
            detected_targets,
            metrics: Some(self.metrics()),
            running_jobs: None,
            spool,
            targets: self.target_statuses(&config).await,
            ts: now(),
            uptime_s: crate::sanitize::clamped_count(self.started.elapsed().as_secs()),
        })
    }

    /// Serialized heartbeat, used as the probe request before re-sending a
    /// `/rotate` whose outcome is unknown.
    async fn heartbeat_body(&self) -> Option<Vec<u8>> {
        let request = self.build_heartbeat().await.ok()?;
        serde_json::to_vec(&request).ok()
    }

    /// Sends one heartbeat; returns the clamped interval from the console.
    async fn heartbeat_once(&self) -> Result<Option<u64>, CallError> {
        let request = self
            .build_heartbeat()
            .await
            .map_err(|_| CallError::Uplink(UplinkError::Setup("heartbeat body")))?;
        let body = serde_json::to_vec(&request)
            .map_err(|_| CallError::Uplink(UplinkError::Setup("heartbeat body")))?;
        let response: HeartbeatResponse = self
            .session
            .call(
                Method::POST,
                "/heartbeat",
                &[],
                Some(&body),
                uplink::REQUEST_TIMEOUT,
                uplink::accept::heartbeat,
            )
            .await?;
        self.console_caps.record(response.accepts.as_ref());
        let value = response.heartbeat_interval_s.0;
        let clamped = backoff::clamp_heartbeat_interval(value);
        if clamped.is_none() {
            tracing::warn!(
                value,
                "ignoring invalid heartbeat_interval_s from the console"
            );
        }
        Ok(clamped)
    }

    async fn heartbeat_loop(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let mut failures: u32 = 0;
        loop {
            let interval = Duration::from_secs(self.session.heartbeat_interval_s());
            let delay = match self.heartbeat_once().await {
                Ok(new_interval) => {
                    failures = 0;
                    bump(&self.counters.heartbeats_sent, 1);
                    self.unauthorized_heartbeats.store(0, Ordering::Relaxed);
                    if *self.state.borrow() == RunState::Suspended {
                        tracing::info!("console accepted the agent again; resuming");
                    }
                    self.set_state(RunState::Active);
                    if let Some(s) = new_interval {
                        self.session.set_heartbeat_interval(s);
                    }
                    self.retry_pending_rotation().await?;
                    Duration::from_secs(self.session.heartbeat_interval_s())
                }
                Err(e) => {
                    bump(&self.counters.heartbeat_failures, 1);
                    failures = failures.saturating_add(1);
                    if matches!(
                        e,
                        CallError::Uplink(UplinkError::Rejected { status: 400, .. })
                    ) {
                        // The console may not accept a negotiated field any more
                        // (rolled back): send none until a response lists them.
                        self.console_caps.clear();
                    }
                    self.on_call_error("heartbeat", &e, failures, interval)?
                }
            };
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => return Ok(()),
            }
            if *shutdown.borrow() {
                return Ok(());
            }
        }
    }

    async fn retry_pending_rotation(&self) -> Result<(), AgentError> {
        if !self.session.needs_rotation_retry() {
            return Ok(());
        }
        let probe = self.heartbeat_body().await;
        match self.session.rotate_probed(None, probe.as_deref()).await {
            Ok(_) => Ok(()),
            Err(CallError::RotationConflict) => Err(AgentError::RotationConflict),
            Err(e) => {
                tracing::warn!(error = %e, "pending secret registration failed; will retry");
                Ok(())
            }
        }
    }

    /// Common error handling; returns the delay before the next attempt.
    fn on_call_error(
        &self,
        what: &'static str,
        e: &CallError,
        failures: u32,
        normal: Duration,
    ) -> Result<Duration, AgentError> {
        match e {
            CallError::RotationConflict => {
                tracing::error!("rotation_conflict: the console locked this agent; stopping");
                Err(AgentError::RotationConflict)
            }
            CallError::Unauthorized => {
                tracing::error!(
                    what,
                    "console rejected the current secret (401): normal operation stopped, \
                     slow retry every 15 min"
                );
                self.set_state(RunState::Suspended);
                // The first heartbeat retry after a fatal 401 comes quickly
                // (a transient console-side issue), then every 15 min.
                let first = what == "heartbeat"
                    && self.unauthorized_heartbeats.fetch_add(1, Ordering::Relaxed) == 0;
                let fraction = backoff::random_fraction();
                Ok(if first {
                    backoff::first_unauthorized_retry_delay(fraction)
                } else {
                    backoff::unauthorized_retry_delay(fraction)
                })
            }
            CallError::Uplink(UplinkError::UpgradeRequired { min_protocol }) => {
                tracing::error!(
                    what,
                    min_protocol,
                    "console requires a newer protocol (426); upgrade the agent. Results keep \
                     being spooled"
                );
                Ok(normal.max(Duration::from_secs(300)))
            }
            CallError::Uplink(u @ UplinkError::Throttled { .. }) => {
                Ok(u.retry_delay(failures.saturating_sub(1)))
            }
            CallError::Uplink(u) if u.is_retryable() => {
                tracing::warn!(what, error = %u, "console unreachable; backing off");
                Ok(u.retry_delay(failures.saturating_sub(1)).min(normal))
            }
            other => {
                tracing::warn!(what, error = %other, "request failed");
                Ok(normal)
            }
        }
    }

    // ---------------------------------------------------------------- spool

    /// Counts batches lost to a serialization failure, with a warning that
    /// carries only the count (never any content).
    fn count_unserializable(&self, batches: u64) {
        if batches > 0 {
            bump(&self.counters.batches_serialization_failed, batches);
            tracing::warn!(batches, "result batches could not be serialized; dropped");
        }
    }

    fn lock_parked(&self) -> std::sync::MutexGuard<'_, Parked> {
        self.parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `/findings` (`true`) or `/events` (`false`) is parked after
    /// a `501`: no new batches are produced for it meanwhile.
    fn endpoint_parked(&self, findings: bool) -> bool {
        self.lock_parked().is_parked(findings, Instant::now())
    }

    /// Resolves once `/findings` is no longer parked (at once if it is not).
    async fn findings_unparked(&self) {
        loop {
            let until = {
                let mut parked = self.lock_parked();
                if parked.is_parked(true, Instant::now()) {
                    parked.findings.until
                } else {
                    None
                }
            };
            let Some(until) = until else {
                return;
            };
            tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
        }
    }

    fn lock_spool(&self) -> std::sync::MutexGuard<'_, Spool> {
        self.spool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Converts masked findings of a job (the single conversion in
    /// `uplink::to_batches`) and spools them.
    pub(crate) fn spool_findings(
        &self,
        job_id: Uuid,
        target_id: &TargetId,
        engine: databastion_protocol::Engine,
        classifiers_version: &databastion_protocol::ClassifiersVersion,
        findings: &[databastion_classifiers::masking::MaskedFinding],
    ) -> std::io::Result<()> {
        let built = uplink::to_batches(uplink::MaskedResults::Findings {
            job_id,
            classifiers_version,
            target_id,
            engine,
            findings,
        });
        self.count_unserializable(built.unserializable_batches);
        let mut spool = self.lock_spool();
        spool.counters.dropped_items += built.dropped_items;
        if built.dropped_items > 0 {
            tracing::warn!(
                items = built.dropped_items,
                "invalid findings dropped before spooling"
            );
        }
        for batch in &built.batches {
            spool.push(batch)?;
        }
        Ok(())
    }

    async fn spool_loop(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let mut state = self.state.subscribe();
        let mut failures: u32 = 0;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if *state.borrow_and_update() != RunState::Active {
                tokio::select! {
                    _ = state.changed() => continue,
                    _ = shutdown.changed() => continue,
                }
            }
            let delay = match self.flush_once(failures.saturating_add(1)).await? {
                Flush::Progress => {
                    failures = 0;
                    continue;
                }
                Flush::Idle => Duration::from_secs(2),
                Flush::Retry(d) => {
                    failures = failures.saturating_add(1);
                    d
                }
            };
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => {}
            }
        }
    }

    /// Sends the batch at the head of the spool and applies the outcome
    /// (docs/09 error table).
    /// Sends the batch at the head of the spool and applies the outcome
    /// (docs/09 error table). `failures` counts consecutive failed attempts,
    /// including this one (backoff).
    ///
    /// A batch is only removed on a valid `BatchAck` for its `batch_id`, and
    /// only dropped on a contract answer: a `4xx` with a parseable `Error`
    /// body, valid item pointers, or `413` (split, no data lost). Anything
    /// else (a proxy's HTML page, a bare `404`, an unparseable or mismatched
    /// ack) is retried with backoff and counted, so a misbehaving middlebox
    /// cannot empty the spool.
    ///
    /// A `501` parks the batch's endpoint (`/findings` or `/events`) until
    /// `Retry-After` (or the backoff) has elapsed; the batch stays spooled,
    /// and the other endpoint's batches are still sent meanwhile (each
    /// endpoint stays FIFO).
    async fn flush_once(&self, failures: u32) -> Result<Flush, AgentError> {
        let front = {
            let now = Instant::now();
            let mut parked = self.lock_parked();
            self.lock_spool()
                .front_where(|findings| !parked.is_parked(findings, now))
        };
        let Some((key, batch)) = front else {
            return Ok(Flush::Idle);
        };
        let result = self
            .session
            .call(
                Method::POST,
                batch.path(),
                &[],
                Some(batch.bytes()),
                uplink::REQUEST_TIMEOUT,
                uplink::accept::batch_ack(batch.batch_id()),
            )
            .await;
        let io = |e: std::io::Error| {
            tracing::warn!(kind = %e.kind(), "spool write failed; will retry");
            SpoolIo
        };
        let retry = || Flush::Retry(spool_backoff(failures, backoff::random_fraction()));
        if let Err(CallError::Uplink(UplinkError::Throttled {
            status: 501,
            retry_after,
        })) = &result
        {
            let delay = self.lock_parked().park(
                batch.is_findings(),
                *retry_after,
                Instant::now(),
                backoff::random_fraction(),
            );
            bump(&self.counters.batches_parked, 1);
            tracing::warn!(
                path = batch.path(),
                status = 501,
                code = "unavailable",
                parked_s = delay.as_secs(),
                "endpoint not implemented by the console (501): parked, batches kept spooled"
            );
            return Ok(Flush::Progress);
        }
        if matches!(
            result,
            Ok(_)
                | Err(CallError::Uplink(
                    UplinkError::Rejected { .. } | UplinkError::ItemsRejected { .. }
                ))
        ) {
            // The endpoint is implemented: its `501` streak ends.
            self.lock_parked().answered(batch.is_findings());
        }
        match result {
            Ok(ack) => {
                if ack.duplicate {
                    bump(&self.counters.batches_duplicate, 1);
                    tracing::info!(batch_id = %ack.batch_id, "batch already received (duplicate)");
                }
                bump(&self.counters.batches_sent, 1);
                self.lock_spool().remove(&key);
                Ok(Flush::Progress)
            }
            Err(CallError::Uplink(UplinkError::ItemsRejected { items, .. }))
                if items.iter().any(|&i| i >= batch.len()) =>
            {
                // Pointers outside the batch: resending would loop.
                bump(&self.counters.batches_rejected, 1);
                tracing::warn!("console rejected items outside the batch; batch dropped");
                self.lock_spool().drop_batch(&key);
                Ok(Flush::Progress)
            }
            Err(CallError::Uplink(UplinkError::ItemsRejected { items, .. })) => {
                let dropped = u64::try_from(items.len()).unwrap_or(u64::MAX);
                tracing::warn!(
                    items = dropped,
                    "console rejected batch items; resending the rest"
                );
                let rest: Vec<ResultBatch> = match batch.without(&items) {
                    Ok(rest) => rest.into_iter().collect(),
                    Err(uplink::Unserializable) => {
                        self.count_unserializable(1);
                        Vec::new()
                    }
                };
                let left_out = u64::try_from(batch.len()).unwrap_or(u64::MAX)
                    - u64::try_from(rest.iter().map(ResultBatch::len).sum::<usize>()).unwrap_or(0);
                if self
                    .lock_spool()
                    .replace(&key, &rest, left_out)
                    .map_err(io)
                    .is_err()
                {
                    return Ok(retry());
                }
                Ok(Flush::Progress)
            }
            Err(CallError::Uplink(UplinkError::Rejected { status: 413, .. })) => {
                let mut spool = self.lock_spool();
                match batch.halves() {
                    Ok(Some((a, b))) => {
                        if spool.replace(&key, &[a, b], 0).map_err(io).is_err() {
                            return Ok(retry());
                        }
                    }
                    Ok(None) => {
                        tracing::warn!("single-item batch too large; dropped");
                        spool.drop_batch(&key);
                    }
                    Err(uplink::Unserializable) => {
                        self.count_unserializable(1);
                        spool.drop_batch(&key);
                    }
                }
                Ok(Flush::Progress)
            }
            Err(CallError::Uplink(UplinkError::Rejected {
                status,
                code: Some(code),
            })) => {
                if code == databastion_protocol::ErrorCode::BatchConflict {
                    bump(&self.counters.batch_conflicts, 1);
                    tracing::warn!(
                        batch_id = %batch.batch_id(),
                        "batch_conflict: the console holds different content for this batch_id; dropped"
                    );
                } else {
                    bump(&self.counters.batches_rejected, 1);
                    tracing::warn!(status, %code, "batch rejected (not retryable); dropped");
                }
                self.lock_spool().drop_batch(&key);
                Ok(Flush::Progress)
            }
            Err(CallError::Uplink(
                UplinkError::Rejected { status, code: None }
                | UplinkError::UnexpectedResponse { status },
            )) => {
                bump(&self.counters.batches_unexpected_response, 1);
                tracing::warn!(
                    status,
                    "batch answered without a contract error body; kept for retry"
                );
                Ok(retry())
            }
            Err(e) => {
                let delay = self.on_call_error("spool", &e, failures, SPOOL_MAX_RETRY)?;
                Ok(Flush::Retry(delay))
            }
        }
    }

    // ----------------------------------------------------------------- jobs

    async fn jobs_loop(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let mut state = self.state.subscribe();
        let mut failures: u32 = 0;
        let mut fast_empty: u32 = 0;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if *state.borrow_and_update() != RunState::Active {
                tokio::select! {
                    _ = state.changed() => continue,
                    _ = shutdown.changed() => continue,
                }
            }
            let wait = self.config().console.long_poll_wait_s;
            let timeout = Duration::from_secs(u64::from(wait) + 15);
            let query = [("wait", wait.to_string())];
            let started = Instant::now();
            let poll = self.session.call(
                Method::GET,
                "/jobs",
                &query,
                None,
                timeout,
                uplink::accept::job_list,
            );
            let result = tokio::select! {
                r = poll => r,
                _ = shutdown.changed() => return Ok(()),
            };
            let delay = match result {
                Ok(list) => {
                    failures = 0;
                    let got_jobs = list.is_some();
                    if let Some(list) = list {
                        self.handle_polled_list(list).await?;
                    }
                    poll_gap(
                        started.elapsed(),
                        got_jobs,
                        &mut fast_empty,
                        backoff::random_fraction(),
                    )
                }
                Err(CallError::Uplink(u @ UplinkError::UnexpectedResponse { .. })) => {
                    // Not a contract answer (malformed list, proxy page):
                    // counted, then retried with backoff.
                    failures = failures.saturating_add(1);
                    bump(&self.counters.jobs_unparseable, 1);
                    u.retry_delay(failures.saturating_sub(1))
                        .min(Duration::from_secs(300))
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    let d = self.on_call_error("jobs", &e, failures, Duration::from_secs(300))?;
                    if matches!(e, CallError::Unauthorized) {
                        Duration::ZERO // wait on the state change instead
                    } else {
                        d
                    }
                }
            };
            if !delay.is_zero() {
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    _ = shutdown.changed() => return Ok(()),
                }
            }
        }
    }

    /// Parses and handles a job list body (tests; the poll loop gets the
    /// list already parsed by `uplink::accept::job_list`).
    #[cfg(test)]
    async fn handle_job_list(&self, body: &[u8]) -> Result<(), AgentError> {
        let list = match jobs::parse_job_list(body) {
            Ok(list) => list,
            Err(e) => {
                bump(&self.counters.jobs_unparseable, 1);
                tracing::warn!(error = %e, "ignoring a malformed job list");
                return Ok(());
            }
        };
        self.handle_polled_list(list).await
    }

    async fn handle_polled_list(&self, list: jobs::PolledList) -> Result<(), AgentError> {
        if list.deferred > 0 {
            bump(&self.counters.jobs_deferred, list.deferred as u64);
            tracing::warn!(
                deferred = list.deferred,
                "more jobs than the per-poll cap; the rest will be redelivered"
            );
        }
        for polled in list.jobs {
            bump(&self.counters.jobs_received, 1);
            match polled {
                PolledJob::Unparseable {
                    job_id: Some(id),
                    code,
                } => {
                    bump(&self.counters.jobs_unparseable, 1);
                    tracing::warn!(job_id = %id, code = %code, "unparseable job reported as failed");
                    self.finish(id, Outcome::failed(code)).await;
                }
                PolledJob::Unparseable { job_id: None, .. } => {
                    bump(&self.counters.jobs_unparseable, 1);
                    tracing::warn!("unparseable job without a valid job_id ignored");
                }
                PolledJob::Parsed(job) => self.handle_job(&job).await?,
            }
        }
        Ok(())
    }

    async fn handle_job(&self, job: &Job) -> Result<(), AgentError> {
        let id = jobs::job_id(job);
        let kind = jobs::job_type(job);
        let known = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id);
        if let Some(entry) = known {
            if !entry.reported {
                self.finish(id, entry.outcome).await;
            }
            tracing::debug!(job_id = %id, kind, "duplicate job delivery ignored");
            return Ok(());
        }
        tracing::info!(job_id = %id, kind, "job received");
        let expired = jobs::expires_at(job).is_some_and(|t| t < now().0);
        let outcome = if expired {
            Some(Outcome::failed(FailureCode::Expired))
        } else {
            self.execute(job, id).await?
        };
        if let Some(outcome) = outcome {
            self.finish(id, outcome).await;
        }
        Ok(())
    }

    /// Executes a job. `None`: leave it unacknowledged (redelivered later).
    async fn execute(&self, job: &Job, id: Uuid) -> Result<Option<Outcome>, AgentError> {
        match job {
            Job::DiscoveryScanJob(scan) => Ok(self.queue_scan(scan, id)),
            Job::AuditConfigureJob(audit) => Ok(Some(self.configure_audit(audit, id))),
            Job::AgentConfigReloadJob(_) => Ok(Some(self.reload_config())),
            Job::AgentRotateSecretJob(_) => self.rotate_for_job(id).await,
        }
    }

    fn invalid_params(&self, id: Uuid, e: &crate::job::ParamsError) -> Outcome {
        bump(&self.counters.jobs_invalid_params, 1);
        tracing::warn!(job_id = %id, field = e.field, reason = e.reason, "job parameters refused");
        Outcome::failed(FailureCode::InvalidParams)
    }

    /// Checks a `discovery.scan` and queues it for the scan worker.
    /// Parameters go through the contract gate (`ScanParams::try_from`) and
    /// the `agent.yaml` clamp (`ScanJob::new`) here, so a refused job is
    /// reported at once. `None`: queued, already running, or queue full
    /// (left unacknowledged, redelivered later).
    fn queue_scan(
        &self,
        job: &databastion_protocol::DiscoveryScanJob,
        id: Uuid,
    ) -> Option<Outcome> {
        // Capability check first, before any other work on the target (no
        // connection, no query): the classifier set of this build.
        if let Some(reason) = unsupported_classifiers(job) {
            bump(&self.counters.jobs_unsupported_classifiers, 1);
            tracing::warn!(
                job_id = %id,
                reason,
                "scan refused: classifier set not supported by this agent build"
            );
            return Some(Outcome::failed(FailureCode::Unsupported));
        }
        let params = match ScanParams::try_from(&job.params) {
            Ok(p) => p,
            Err(e) => return Some(self.invalid_params(id, &e)),
        };
        let config = self.config();
        let Some(target) = config
            .targets
            .iter()
            .find(|t| t.id == job.target_id.as_str())
        else {
            tracing::warn!(job_id = %id, "scan job for an undeclared target");
            return Some(Outcome::failed(FailureCode::UnknownTarget));
        };
        let Some(connector) = self
            .connectors
            .iter()
            .position(|c| c.engine() == target.engine.connector())
        else {
            return Some(Outcome::failed(FailureCode::Unsupported));
        };
        let mut queue = self.lock_scans();
        if queue.in_flight.contains(&id) {
            return None;
        }
        if queue.queued.len() >= MAX_QUEUED_SCANS {
            tracing::warn!(job_id = %id, "scan queue full; the job will be redelivered");
            return None;
        }
        queue.in_flight.insert(id);
        queue.queued.push_back(PreparedScan {
            id,
            target_id: job.target_id.clone(),
            engine: proto_engine(target.engine),
            connector,
            scan: ScanJob::new(params, target, &config.limits, Arc::clone(&self.hmac)),
            received: Instant::now(),
        });
        drop(queue);
        self.scan_ready.notify_one();
        None
    }

    // ---------------------------------------------------------------- audit

    fn lock_audits(&self) -> std::sync::MutexGuard<'_, AuditTable> {
        self.audits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn audit_dir(config: &AgentConfig) -> PathBuf {
        config.state_dir.join(audit::AUDIT_DIR)
    }

    /// `audit.configure`: contract gate, declared target, connector with
    /// Audit support; then the settings replace the previous ones as a
    /// whole, are saved (`<state_dir>/audit/<target>.settings.json`, `0600`)
    /// so that collection resumes after a restart, and the audit worker
    /// starts, restarts or stops the target's stream. The job succeeds once
    /// the settings are installed; collection problems show in the logs,
    /// the metrics and the heartbeat audit level.
    fn configure_audit(&self, job: &databastion_protocol::AuditConfigureJob, id: Uuid) -> Outcome {
        let params = match AuditParams::try_from(&job.params) {
            Ok(p) => p,
            Err(e) => return self.invalid_params(id, &e),
        };
        let config = self.config();
        let Some(target) = config
            .targets
            .iter()
            .find(|t| t.id == job.target_id.as_str())
        else {
            tracing::warn!(job_id = %id, "audit.configure for an undeclared target");
            return Outcome::failed(FailureCode::UnknownTarget);
        };
        let supported = self
            .connectors
            .iter()
            .any(|c| c.engine() == target.engine.connector() && c.supports_audit());
        if !supported {
            return Outcome::failed(FailureCode::Unsupported);
        }
        let dir = Self::audit_dir(&config);
        let enabled = params.enabled();
        if enabled {
            match serde_json::to_vec(&job.params) {
                Ok(json) => {
                    if let Err(e) = audit::save_settings(&dir, &target.id, &json) {
                        tracing::warn!(
                            job_id = %id,
                            kind = %e.kind(),
                            "audit settings not saved: collection will not resume after a restart"
                        );
                    }
                }
                Err(_) => tracing::warn!(job_id = %id, "audit settings not saved"),
            }
        } else {
            audit::remove_settings(&dir, &target.id);
        }
        let sensitive = params_sensitive_count(&job.params);
        self.lock_audits()
            .set(&target.id, enabled.then_some(params));
        self.audit_changed.notify_one();
        tracing::info!(
            job_id = %id,
            target_id = %target.id,
            enabled,
            sensitive_objects = sensitive,
            "audit configured"
        );
        Outcome::SUCCEEDED
    }

    /// Reinstalls the saved settings of the declared targets (startup).
    fn restore_audits(&self) {
        let config = self.config();
        let dir = Self::audit_dir(&config);
        for target in &config.targets {
            let supported = self
                .connectors
                .iter()
                .any(|c| c.engine() == target.engine.connector() && c.supports_audit());
            if !supported {
                continue;
            }
            let Some(json) = audit::load_settings(&dir, &target.id) else {
                continue;
            };
            let params =
                serde_json::from_slice::<databastion_protocol::AuditConfigureParams>(&json)
                    .ok()
                    .and_then(|p| AuditParams::try_from(&p).ok());
            match params {
                Some(p) if p.enabled() => {
                    tracing::info!(target_id = %target.id, "audit settings restored");
                    self.lock_audits().set(&target.id, Some(p));
                }
                Some(_) => {}
                None => tracing::warn!(
                    target_id = %target.id,
                    "saved audit settings are invalid; ignored until the next audit.configure"
                ),
            }
        }
    }

    /// Whether new event batches may be produced: the agent is active and
    /// `/events` is not parked after a `501`. Otherwise events are held
    /// (bounded), and the connector is back-pressured on `submit()`.
    fn events_can_emit(&self) -> bool {
        *self.state.borrow() == RunState::Active && !self.endpoint_parked(false)
    }

    /// Converts and spools aggregated events of a target (the single
    /// conversion in `uplink::to_batches`).
    fn spool_events(
        &self,
        target_id: &TargetId,
        events: &[databastion_classifiers::masking::MaskedEvent],
    ) {
        if events.is_empty() {
            return;
        }
        let fingerprints = crate::sanitize::HmacFingerprints(&self.hmac);
        let built = uplink::to_batches(uplink::MaskedResults::Events {
            target_id,
            events,
            fingerprints: &fingerprints,
        });
        self.count_unserializable(built.unserializable_batches);
        let mut spool = self.lock_spool();
        spool.counters.dropped_items += built.dropped_items;
        if built.dropped_items > 0 {
            tracing::warn!(
                items = built.dropped_items,
                "invalid events dropped before spooling"
            );
        }
        for batch in &built.batches {
            if let Err(e) = spool.push(batch) {
                let lost = u64::try_from(batch.len()).unwrap_or(u64::MAX);
                bump(&self.counters.events_lost, lost);
                tracing::error!(
                    target_id = target_id.as_str(),
                    error = %e.kind(),
                    lost,
                    "cannot spool events"
                );
            }
        }
    }

    /// Filters and spools what the aggregator holds.
    fn flush_events(&self, cfg: &AuditConfig, target_id: &TargetId, agg: &mut Aggregator) {
        let (keep, drop): (Vec<_>, Vec<_>) = agg
            .drain()
            .into_iter()
            .partition(|e| audit::reportable(cfg, e));
        bump(
            &self.counters.events_filtered,
            u64::try_from(drop.len()).unwrap_or(u64::MAX),
        );
        self.spool_events(target_id, &keep);
    }

    /// Audit worker: runs one stream per target with enabled settings,
    /// restarts a stream whose settings (or the configuration) changed and
    /// stops the others. A stopped stream flushes its held events first.
    async fn audit_loop(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        use futures_util::StreamExt as _;
        self.restore_audits();
        let mut running: std::collections::HashMap<String, (u64, watch::Sender<bool>)> =
            std::collections::HashMap::new();
        let mut tasks = futures_util::stream::FuturesUnordered::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            let wanted = self.lock_audits().snapshot();
            running.retain(|id, (generation, stop)| {
                let keep = wanted.iter().any(|(w, g, _)| w == id && g == generation);
                if !keep {
                    let _ = stop.send(true);
                }
                keep
            });
            for (id, generation, params) in wanted {
                if running.contains_key(&id) {
                    continue;
                }
                let (stop_tx, stop_rx) = watch::channel(false);
                running.insert(id.clone(), (generation, stop_tx));
                tasks.push(self.run_audit(id, params, stop_rx));
            }
            tokio::select! {
                () = self.audit_changed.notified() => {}
                Some(()) = tasks.next(), if !tasks.is_empty() => {}
                _ = shutdown.changed() => {}
            }
        }
        for (_, (_, stop)) in running.drain() {
            let _ = stop.send(true);
        }
        // Let the streams flush their held events (bounded wait).
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while tasks.next().await.is_some() {}
        })
        .await;
        Ok(())
    }

    /// Runs the audit stream of a target until `stop`, restarting it with
    /// backoff when the connector fails.
    async fn run_audit(
        &self,
        target_id: String,
        params: AuditParams,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut failures: u32 = 0;
        loop {
            if *stop.borrow() {
                return;
            }
            let config = self.config();
            let Some(target) = config.targets.iter().find(|t| t.id == target_id) else {
                tracing::warn!(target_id, "audit target no longer declared; stream stopped");
                return;
            };
            let Some(connector) = self
                .connectors
                .iter()
                .find(|c| c.engine() == target.engine.connector() && c.supports_audit())
            else {
                return;
            };
            let Ok(tid) = TargetId::try_from(target.id.as_str()) else {
                return;
            };
            let dir = Self::audit_dir(&config);
            let mut cfg = AuditConfig::new(params.clone(), target, &config.limits);
            match crate::fsutil::ensure_private_dir(&dir) {
                Ok(()) => cfg = cfg.with_state_dir(dir),
                Err(e) => tracing::warn!(
                    target_id,
                    kind = %e.kind(),
                    "audit state directory unusable: the read position is not persisted"
                ),
            }
            tracing::info!(target_id, "audit stream started");
            match self
                .audit_session(connector.as_ref(), &cfg, &tid, &mut stop)
                .await
            {
                AuditEnd::Stopped => {
                    tracing::info!(target_id, "audit stream stopped");
                    return;
                }
                AuditEnd::Failed(Some(crate::ConnectorError::NotImplemented { .. })) => {
                    tracing::warn!(target_id, "audit is not implemented for this target");
                    return;
                }
                AuditEnd::Failed(e) => {
                    bump(&self.counters.audit_stream_failures, 1);
                    failures = failures.saturating_add(1);
                    let delay = backoff::Backoff::CONSOLE
                        .delay(failures.saturating_sub(1), backoff::random_fraction())
                        .clamp(cfg.poll_interval(), AUDIT_MAX_BACKOFF);
                    match &e {
                        Some(crate::ConnectorError::Target {
                            code, engine_code, ..
                        }) => {
                            tracing::warn!(
                                target_id,
                                code = %code,
                                engine_code = engine_code.as_deref(),
                                retry_s = delay.as_secs(),
                                "audit stream failed; restarting"
                            );
                        }
                        Some(other) => tracing::warn!(
                            target_id,
                            error = %other,
                            retry_s = delay.as_secs(),
                            "audit stream failed; restarting"
                        ),
                        None => tracing::warn!(
                            target_id,
                            retry_s = delay.as_secs(),
                            "audit stream ended; restarting"
                        ),
                    }
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = stop.wait_for(|s| *s) => return,
                    }
                }
            }
        }
    }

    /// One run of a connector's audit stream: events are pre-aggregated
    /// over the aggregation window, filtered and spooled. While events
    /// cannot be emitted (`/events` parked, agent suspended), nothing is
    /// received: the bounded channel back-pressures the connector.
    async fn audit_session(
        &self,
        connector: &dyn Connector,
        cfg: &AuditConfig,
        target_id: &TargetId,
        stop: &mut watch::Receiver<bool>,
    ) -> AuditEnd {
        let (sink, mut rx) = EventSink::channel(EVENTS_CHANNEL);
        let mut agg = Aggregator::new(cfg.aggregation_window());
        let mut stream = Box::pin(connector.audit_stream(cfg, &sink));
        let end = loop {
            let can_emit = self.events_can_emit();
            let deadline = agg.deadline();
            let sleep_to = deadline.map_or_else(
                || tokio::time::Instant::now() + Duration::from_secs(3600),
                tokio::time::Instant::from_std,
            );
            tokio::select! {
                biased;
                _ = stop.wait_for(|s| *s) => break AuditEnd::Stopped,
                r = &mut stream => {
                    break AuditEnd::Failed(r.err());
                }
                ev = rx.recv(), if can_emit && !agg.is_full() => {
                    if let Some(e) = ev {
                        bump(&self.counters.events_received, 1);
                        agg.push(e, Instant::now());
                    }
                }
                () = tokio::time::sleep_until(sleep_to), if can_emit && deadline.is_some() => {
                    self.flush_events(cfg, target_id, &mut agg);
                }
                () = tokio::time::sleep(Duration::from_secs(1)), if !can_emit => {}
            }
            if agg.is_full() && self.events_can_emit() {
                self.flush_events(cfg, target_id, &mut agg);
            }
        };
        // The connector future is dropped here (no more cursor updates);
        // what it handed over is kept.
        drop(stream);
        drop(sink);
        while let Ok(e) = rx.try_recv() {
            bump(&self.counters.events_received, 1);
            agg.push(e, Instant::now());
            if agg.is_full() {
                self.flush_events(cfg, target_id, &mut agg);
            }
        }
        self.flush_events(cfg, target_id, &mut agg);
        end
    }

    fn lock_scans(&self) -> std::sync::MutexGuard<'_, ScanQueue> {
        self.scans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Scan worker: runs queued scans one at a time, next to the jobs loop,
    /// so that `rotate` / `reload` jobs never wait behind a scan.
    async fn scan_loop(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if self.endpoint_parked(true) {
                // `/findings` parked after a `501`: no new findings are
                // produced meanwhile; queued scans wait (their window keeps
                // running, see `discovery_scan`).
                tokio::select! {
                    () = self.findings_unparked() => {}
                    _ = shutdown.changed() => {}
                }
                continue;
            }
            let next = self.lock_scans().queued.pop_front();
            let Some(prepared) = next else {
                tokio::select! {
                    () = self.scan_ready.notified() => {}
                    _ = shutdown.changed() => {}
                }
                continue;
            };
            let cancel = {
                let mut shutdown = shutdown.clone();
                async move {
                    let _ = shutdown.wait_for(|stop| *stop).await;
                }
            };
            self.run_prepared_scan(prepared, cancel).await;
        }
    }

    /// Runs one prepared scan and reports its outcome.
    async fn run_prepared_scan(
        &self,
        prepared: PreparedScan,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        let id = prepared.id;
        let outcome = self.discovery_scan(prepared, shutdown).await;
        self.lock_scans().in_flight.remove(&id);
        self.finish(id, outcome).await;
    }

    /// Resolves once the agent leaves [`RunState::Active`] (suspension
    /// after a fatal `401`, i.e. revocation).
    fn inactive(&self) -> impl std::future::Future<Output = ()> + use<> {
        let mut state = self.state.subscribe();
        async move {
            if state.wait_for(|s| *s != RunState::Active).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Runs a queued scan. Findings are spooled per chunk while it runs.
    /// The connector future is dropped at the clamped deadline (`timeout`),
    /// when the agent is suspended or revoked, or on shutdown (`cancelled`);
    /// findings already handed over are flushed first. Findings that cannot
    /// be spooled are counted as lost.
    ///
    /// The scan's window is its clamped `max_duration_s` counted from the
    /// job's reception: a scan popped after it (held behind a parked
    /// `/findings`, or a long queue) ends `failed` / `timeout` without
    /// touching the target, and a partly elapsed window shortens the
    /// deadline.
    ///
    /// While `/findings` is parked, a full chunk is held (the connector is
    /// back-pressured through the bounded channel) until the park ends or
    /// the scan stops; the findings held when the scan stops are spooled
    /// (bounded spool), never dropped.
    ///
    /// At most `findings_cap` ([`MAX_FINDINGS_PER_JOB`]) findings are
    /// emitted for the job: the next one stops the scan (the connector
    /// future is dropped), the findings kept so far are flushed and the job
    /// ends `failed` / `resource_limit`.
    async fn discovery_scan(
        &self,
        prepared: PreparedScan,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Outcome {
        let PreparedScan {
            id,
            target_id,
            engine,
            connector,
            scan,
            received,
        } = prepared;
        let Some(deadline) = scan
            .max_duration()
            .checked_sub(received.elapsed())
            .filter(|d| !d.is_zero())
        else {
            tracing::warn!(job_id = %id, "scan window elapsed before it could start");
            return Outcome::failed(FailureCode::Timeout);
        };
        let Some(connector) = self.connectors.get(connector) else {
            return Outcome::failed(FailureCode::Unsupported);
        };
        let Some(version) = classifiers_version() else {
            return Outcome::failed(FailureCode::Internal);
        };
        let (sink, mut rx) = FindingSink::channel(FINDINGS_CHANNEL);
        let chunk: Mutex<Vec<MaskedFinding>> = Mutex::new(Vec::new());
        let spool_failed = std::sync::atomic::AtomicBool::new(false);
        // Findings emitted for this job (per-job cap).
        let emitted = std::sync::atomic::AtomicUsize::new(0);
        let capped = std::sync::atomic::AtomicBool::new(false);
        let flush = || {
            let mut chunk = chunk
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if chunk.is_empty() {
                return;
            }
            if let Err(e) = self.spool_findings(id, &target_id, engine, &version, &chunk) {
                let lost = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                bump(&self.counters.findings_lost, lost);
                tracing::error!(job_id = %id, error = %e.kind(), lost, "cannot spool findings");
                spool_failed.store(true, Ordering::Relaxed);
            }
            chunk.clear();
        };
        // Takes a finding into the current chunk. `Capped` once the per-job
        // cap is reached (the finding is not kept, the scan must stop);
        // `Full` when the chunk should be flushed.
        let take = |f: MaskedFinding| -> Take {
            bump(&self.counters.findings_received, 1);
            if emitted.load(Ordering::Relaxed) >= self.findings_cap {
                capped.store(true, Ordering::Relaxed);
                return Take::Capped;
            }
            emitted.fetch_add(1, Ordering::Relaxed);
            let mut c = chunk
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            c.push(f);
            if c.len() >= FINDINGS_CHUNK {
                Take::Full
            } else {
                Take::Kept
            }
        };
        // Set once the connector has returned: a chunk held for a parked
        // `/findings` stops waiting then (the drain below spools it).
        let (done_tx, done_rx) = watch::channel(false);
        let outcome = {
            let run = async {
                let r = connector.discover(&scan, &sink).await;
                drop(sink);
                let _ = done_tx.send(true);
                r
            };
            // Resolves when the channel closes (`false`), or at the cap
            // (`true`).
            let collect = async {
                while let Some(f) = rx.recv().await {
                    match take(f) {
                        Take::Capped => return true,
                        Take::Full => {
                            // No new batch for a parked `/findings`: hold
                            // the chunk (the connector blocks on the full
                            // channel) until the park ends, or until the
                            // connector has returned (its result is then
                            // known; the drain below spools the rest).
                            let mut done = done_rx.clone();
                            tokio::select! {
                                () = self.findings_unparked() => flush(),
                                _ = done.wait_for(|d| *d) => return false,
                            }
                        }
                        Take::Kept => {}
                    }
                }
                false
            };
            let work = async {
                tokio::pin!(run);
                tokio::pin!(collect);
                let mut ran = None;
                loop {
                    tokio::select! {
                        r = &mut run, if ran.is_none() => ran = Some(r),
                        at_cap = &mut collect => {
                            if at_cap {
                                return None;
                            }
                            return Some(match ran {
                                Some(r) => r,
                                None => run.await,
                            });
                        }
                    }
                }
            };
            tokio::select! {
                r = work => match r {
                    None => {
                        bump(&self.counters.scans_findings_capped, 1);
                        tracing::warn!(
                            job_id = %id,
                            cap = self.findings_cap,
                            "scan stopped at the per-job findings cap"
                        );
                        Outcome::failed(FailureCode::ResourceLimit)
                    }
                    Some(Ok(())) => Outcome::SUCCEEDED,
                    Some(Err(crate::ConnectorError::NotImplemented { .. })) => {
                        Outcome::failed(FailureCode::Unsupported)
                    }
                    Some(Err(crate::ConnectorError::Target { code, engine_code, .. })) => {
                        tracing::warn!(
                            job_id = %id,
                            code = %code,
                            engine_code = engine_code.as_deref(),
                            "scan failed"
                        );
                        Outcome::failed(code)
                    }
                    Some(Err(e)) => {
                        tracing::warn!(job_id = %id, error = %e, "scan failed");
                        Outcome::failed(FailureCode::Internal)
                    }
                },
                () = tokio::time::sleep(deadline) => {
                    tracing::warn!(job_id = %id, "scan stopped at its maximum duration");
                    Outcome::failed(FailureCode::Timeout)
                }
                () = self.inactive() => {
                    tracing::warn!(job_id = %id, "scan cancelled: the agent is no longer active");
                    Outcome::failed(FailureCode::Cancelled)
                }
                () = shutdown => Outcome::failed(FailureCode::Cancelled),
            }
        };
        // The connector future (and its sink) is dropped: drain what it
        // handed over (within the cap), then flush the partial chunk.
        while let Ok(f) = rx.try_recv() {
            match take(f) {
                Take::Capped => break,
                Take::Full => flush(),
                Take::Kept => {}
            }
        }
        flush();
        if spool_failed.load(Ordering::Relaxed) && outcome.error.is_none() {
            return Outcome::failed(FailureCode::ResourceLimit);
        }
        if capped.load(Ordering::Relaxed) && outcome.error.is_none() {
            return Outcome::failed(FailureCode::ResourceLimit);
        }
        outcome
    }

    fn reload_config(&self) -> Outcome {
        match AgentConfig::load(&self.config_path) {
            Ok(new) => {
                // Declared targets may change: detect again next heartbeat.
                *self
                    .detection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                let mut current = self
                    .config
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if new.console.url != current.console.url
                    || new.console.ca_file != current.console.ca_file
                    || new.console.insecure_dev_http != current.console.insecure_dev_http
                    || new.state_dir != current.state_dir
                {
                    tracing::error!(
                        "reload refused: console.url, console.ca_file, \
                         console.insecure_dev_http and state_dir require a restart; \
                         keeping the previous configuration"
                    );
                    return Outcome::failed(FailureCode::InvalidParams);
                }
                *current = new;
                drop(current);
                // Audit streams pick up the new target settings.
                self.lock_audits().bump_all();
                self.audit_changed.notify_one();
                tracing::info!("configuration reloaded");
                Outcome::SUCCEEDED
            }
            Err(e) => {
                tracing::error!(error = %e, "configuration reload failed; keeping the previous one");
                Outcome::failed(FailureCode::Internal)
            }
        }
    }

    async fn rotate_for_job(&self, id: Uuid) -> Result<Option<Outcome>, AgentError> {
        let probe = self.heartbeat_body().await;
        for attempt in 0..3 {
            match self.session.rotate_probed(Some(id), probe.as_deref()).await {
                Ok(RotateOutcome::Registered { duplicate }) => {
                    tracing::info!(job_id = %id, duplicate, "new secret registered as pending");
                    return Ok(Some(Outcome::SUCCEEDED));
                }
                Ok(RotateOutcome::AlreadyDone) => return Ok(Some(Outcome::SUCCEEDED)),
                Ok(RotateOutcome::Deferred) => {
                    tracing::info!(
                        job_id = %id,
                        "rotation deferred: previous promotion less than 60 s ago"
                    );
                    return Ok(None);
                }
                Err(CallError::Uplink(UplinkError::Rejected {
                    code: Some(databastion_protocol::ErrorCode::InvalidSecret),
                    ..
                })) => {
                    tracing::error!(job_id = %id, "console refused the new secret (invalid_secret)");
                    return Ok(Some(Outcome::failed(FailureCode::Internal)));
                }
                Err(CallError::RotationConflict) => {
                    tracing::error!("rotation_conflict: the console locked this agent; stopping");
                    return Err(AgentError::RotationConflict);
                }
                Err(CallError::Uplink(e)) if e.is_retryable() => {
                    tokio::time::sleep(e.retry_delay(attempt)).await;
                }
                Err(e) => {
                    tracing::warn!(job_id = %id, error = %e, "secret rotation failed");
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// Records the outcome and reports it (`POST /jobs/{id}/status`).
    async fn finish(&self, id: Uuid, outcome: Outcome) {
        if outcome.error.is_some() {
            bump(&self.counters.jobs_failed, 1);
        }
        let reported = self.report(id, outcome).await;
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(id, LedgerEntry { outcome, reported });
    }

    async fn report(&self, id: Uuid, outcome: Outcome) -> bool {
        let update = JobStatusUpdate {
            error: outcome.error.map(|code| JobError {
                code,
                engine_code: None,
            }),
            progress: None,
            status: outcome.status,
            ts: now(),
        };
        let Ok(body) = serde_json::to_vec(&update) else {
            return false;
        };
        let path = format!("/jobs/{id}/status");
        for attempt in 0..3 {
            match self
                .session
                .call(
                    Method::POST,
                    &path,
                    &[],
                    Some(&body),
                    uplink::REQUEST_TIMEOUT,
                    uplink::accept::no_content,
                )
                .await
            {
                Ok(()) => return true,
                // Terminal already, or not ours: nothing more to report.
                Err(CallError::Uplink(UplinkError::Rejected {
                    status: 404 | 409, ..
                })) => return true,
                Err(CallError::Uplink(e)) if e.is_retryable() => {
                    tokio::time::sleep(e.retry_delay(attempt)).await;
                }
                Err(e) => {
                    tracing::warn!(job_id = %id, error = %e, "job status not reported");
                    return false;
                }
            }
        }
        false
    }
}

/// Number of `sensitive_objects` in audit settings (logged; never their names).
fn params_sensitive_count(p: &databastion_protocol::AuditConfigureParams) -> usize {
    p.sensitive_objects.len()
}

/// Why a `discovery.scan` cannot run with this build's classifier set:
/// its `classifiers_version` is not the compiled [`CLASSIFIERS_VERSION`], or
/// `params.classifiers` names an id outside the compiled set. Reported
/// `failed` / `unsupported` (docs/09: a capability mismatch of the agent
/// build, not invalid parameters). The reason is a static text; the job's
/// values are never logged.
fn unsupported_classifiers(job: &databastion_protocol::DiscoveryScanJob) -> Option<&'static str> {
    if job.classifiers_version.as_str() != CLASSIFIERS_VERSION {
        return Some("classifiers_version differs from the compiled one");
    }
    let unknown = job.params.classifiers.as_ref().is_some_and(|ids| {
        ids.iter()
            .any(|id| databastion_classifiers::id::ClassifierId::parse(id.as_str()).is_none())
    });
    unknown.then_some("classifier id outside the compiled set")
}

/// What happened to a finding taken into a scan chunk.
enum Take {
    Kept,
    /// Kept; the chunk is full.
    Full,
    /// Not kept: the per-job findings cap is reached.
    Capped,
}

/// Minimum gap between two job polls. A poll that returns without jobs in
/// less than 1 s (console ignoring `wait`, `wait=0`, proxy) is followed by
/// `max(1 s, jittered backoff)` so the agent never hot-loops; a long-poll
/// that was held, or a poll that delivered jobs, polls again immediately.
fn poll_gap(elapsed: Duration, got_jobs: bool, fast_empty: &mut u32, fraction: f64) -> Duration {
    if got_jobs || elapsed >= Duration::from_secs(1) {
        *fast_empty = 0;
        return Duration::ZERO;
    }
    let gap = backoff::Backoff::CONSOLE
        .delay(*fast_empty, fraction)
        .max(Duration::from_secs(1));
    *fast_empty = fast_empty.saturating_add(1);
    gap
}

fn proto_audit_level(level: AuditLevel) -> databastion_protocol::AuditLevel {
    match level {
        AuditLevel::None => databastion_protocol::AuditLevel::None,
        AuditLevel::Limited => databastion_protocol::AuditLevel::Limited,
        AuditLevel::Partial => databastion_protocol::AuditLevel::Partial,
        AuditLevel::Full => databastion_protocol::AuditLevel::Full,
    }
}

fn proto_engine(engine: TargetEngine) -> databastion_protocol::Engine {
    match engine {
        TargetEngine::Postgres => databastion_protocol::Engine::Postgres,
        TargetEngine::Mysql => databastion_protocol::Engine::Mysql,
        TargetEngine::Mariadb => databastion_protocol::Engine::Mariadb,
        TargetEngine::Mongodb => databastion_protocol::Engine::Mongodb,
        TargetEngine::Openldap => databastion_protocol::Engine::Openldap,
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
