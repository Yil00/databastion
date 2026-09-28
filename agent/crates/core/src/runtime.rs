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
    AgentVersion, ClassifiersVersion, Connector as ProtoConnector, ConnectorList, Count,
    DetectedTarget, EnrollRequest, EnrollRequestArch, EnrollRequestOs, EnrollResponse,
    EnrollmentToken, FailureCode, HeartbeatRequest, HeartbeatResponse, Hostname, Job, JobError,
    JobStatusUpdate, MetricsMap, MetricsMapKey, TargetId, TargetStatus, Timestamp, Uuid,
};
use reqwest::Method;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::backoff;
use crate::config::{AgentConfig, ConfigError, TargetEngine};
use crate::connector::Connector;
use crate::detect;
use crate::engine::{AuditLevel, Engine};
use crate::identity::{Identity, IdentityError, StateDir};
use crate::job::{ScanJob, ScanParams};
use crate::jobs::{self, Ledger, LedgerEntry, Outcome, PolledJob};
use crate::session::{CallError, RotateOutcome, Session};
use crate::sink::FindingSink;
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
}

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
    /// Host root for local detection (`/`; a fixture tree in tests).
    host_root: PathBuf,
    /// Heartbeats refused with a fatal `401` since the last success.
    unauthorized_heartbeats: std::sync::atomic::AtomicU32,
    /// Last local detection result and when it was computed.
    detection: Mutex<Option<(Instant, Vec<DetectedTarget>)>>,
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
            host_root: PathBuf::from("/"),
            detection: Mutex::new(None),
            unauthorized_heartbeats: std::sync::atomic::AtomicU32::new(0),
        })
    }

    async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let heartbeat = self.heartbeat_loop(shutdown.clone());
        let jobs = self.jobs_loop(shutdown.clone());
        let spool = self.spool_loop(shutdown);
        tokio::select! {
            r = heartbeat => r,
            r = jobs => r,
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
                Some(c) => match tokio::time::timeout(Duration::from_secs(10), c.check()).await {
                    Ok(h) => (h.reachable, h.audit_level, h.failure),
                    Err(_) => (false, AuditLevel::None, Some(FailureCode::Timeout)),
                },
            };
            out.push(TargetStatus {
                audit_level: proto_audit_level(level),
                audit_source: None,
                edition: None,
                engine: proto_engine(target.engine),
                last_error,
                metrics: None,
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
            ("batches_sent_total", &c.batches_sent),
            ("batches_duplicate_total", &c.batches_duplicate),
            ("batches_rejected_total", &c.batches_rejected),
            ("batch_conflicts_total", &c.batch_conflicts),
            (
                "batches_unexpected_response_total",
                &c.batches_unexpected_response,
            ),
            (
                "batches_serialization_failed_total",
                &c.batches_serialization_failed,
            ),
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
        let uptime = i64::try_from(self.started.elapsed().as_secs()).unwrap_or(i64::MAX);
        let spool = self.lock_spool().status();
        let detected_targets = self.detected_targets(&config).await;
        Ok(HeartbeatRequest {
            agent_version: agent_version()?,
            classifiers_version: classifiers_version(),
            connectors: connector_list(&engines),
            detected_targets,
            metrics: Some(self.metrics()),
            running_jobs: None,
            spool,
            targets: self.target_statuses(&config).await,
            ts: now(),
            uptime_s: Count(uptime),
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
    async fn flush_once(&self, failures: u32) -> Result<Flush, AgentError> {
        let front = self.lock_spool().front();
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
            Job::DiscoveryScanJob(scan) => Ok(Some(self.discovery_scan(scan, id).await)),
            Job::AuditConfigureJob(audit) => {
                // Gate now; audit collection lands in P4.
                let outcome = match crate::job::AuditParams::try_from(&audit.params) {
                    Ok(_) => Outcome::failed(FailureCode::Unsupported),
                    Err(e) => self.invalid_params(id, &e),
                };
                Ok(Some(outcome))
            }
            Job::AgentConfigReloadJob(_) => Ok(Some(self.reload_config())),
            Job::AgentRotateSecretJob(_) => self.rotate_for_job(id).await,
        }
    }

    fn invalid_params(&self, id: Uuid, e: &crate::job::ParamsError) -> Outcome {
        bump(&self.counters.jobs_invalid_params, 1);
        tracing::warn!(job_id = %id, field = e.field, reason = e.reason, "job parameters refused");
        Outcome::failed(FailureCode::InvalidParams)
    }

    /// Runs a `discovery.scan`: parameters go through the contract gate
    /// (`ScanParams::try_from`) and the `agent.yaml` clamp (`ScanJob::new`)
    /// before the connector sees them; findings are spooled per chunk while
    /// the scan runs, and the scan is stopped after its clamped duration.
    async fn discovery_scan(
        &self,
        job: &databastion_protocol::DiscoveryScanJob,
        id: Uuid,
    ) -> Outcome {
        let params = match ScanParams::try_from(&job.params) {
            Ok(p) => p,
            Err(e) => return self.invalid_params(id, &e),
        };
        let config = self.config();
        let Some(target) = config
            .targets
            .iter()
            .find(|t| t.id == job.target_id.as_str())
        else {
            tracing::warn!(job_id = %id, "scan job for an undeclared target");
            return Outcome::failed(FailureCode::UnknownTarget);
        };
        let Some(connector) = self
            .connectors
            .iter()
            .find(|c| c.engine() == target.engine.connector())
        else {
            return Outcome::failed(FailureCode::Unsupported);
        };
        let scan = ScanJob::new(params, target, &config.limits, Arc::clone(&self.hmac));
        let engine = proto_engine(target.engine);
        let Some(version) = classifiers_version() else {
            return Outcome::failed(FailureCode::Internal);
        };
        let (sink, mut rx) = FindingSink::channel(FINDINGS_CHANNEL);
        let deadline = scan.max_duration();
        let run = async move {
            let r = connector.discover(&scan, &sink).await;
            drop(sink);
            r
        };
        let collect = async {
            let mut chunk: Vec<MaskedFinding> = Vec::new();
            let mut spool_failed = false;
            loop {
                let next = rx.recv().await;
                let done = next.is_none();
                if let Some(f) = next {
                    bump(&self.counters.findings_received, 1);
                    chunk.push(f);
                }
                if !chunk.is_empty() && (done || chunk.len() >= FINDINGS_CHUNK) {
                    if let Err(e) =
                        self.spool_findings(id, &job.target_id, engine, &version, &chunk)
                    {
                        tracing::error!(job_id = %id, error = %e.kind(), "cannot spool findings");
                        spool_failed = true;
                    }
                    chunk.clear();
                }
                if done {
                    return spool_failed;
                }
            }
        };
        let scan_and_collect = async { tokio::join!(run, collect) };
        match tokio::time::timeout(deadline, scan_and_collect).await {
            Err(_) => {
                tracing::warn!(job_id = %id, "scan stopped at its maximum duration");
                Outcome::failed(FailureCode::Timeout)
            }
            Ok((_, true)) => Outcome::failed(FailureCode::ResourceLimit),
            Ok((Ok(()), false)) => Outcome::SUCCEEDED,
            Ok((Err(crate::ConnectorError::NotImplemented { .. }), false)) => {
                Outcome::failed(FailureCode::Unsupported)
            }
            Ok((Err(e), false)) => {
                tracing::warn!(job_id = %id, error = %e, "scan failed");
                Outcome::failed(FailureCode::Internal)
            }
        }
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
