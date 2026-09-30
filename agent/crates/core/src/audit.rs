//! Audit collection support (P4-A): persisted cursors for connectors,
//! pre-aggregation and the `audit.configure` reporting filter, plus the
//! engine-agnostic pieces connectors share: the log file tailer
//! ([`tail`]) and the agent's own-account rule ([`own`]).
//!
//! - [`CursorStore`]: a small private file (`0600`, atomic write, no
//!   symlink) under `<state_dir>/audit/`, where a connector keeps its read
//!   position in an audit source. Connectors never get a path.
//! - `Aggregator` (crate-private): merges events of the same principal,
//!   object set, action and source within the aggregation window (docs/09),
//!   bounded in groups.
//! - `reportable` (crate-private): the `audit.configure` filter. An event
//!   is reported when it carries a signal, touches an object listed in
//!   `sensitive_objects`, is not a `read` / `write` (connections, DDL,
//!   DCL), or when `min_rows` is absent or reached. It is applied after
//!   aggregation, so many small reads of one group add up.

pub mod own;
pub mod tail;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use databastion_classifiers::masking::{EventAction, EventGroupKey, MaskedEvent};

use crate::fsutil;
use crate::job::AuditConfig;

/// Largest cursor file read, in bytes.
const MAX_CURSOR_BYTES: usize = 64 * 1024;

/// Subdirectory of `state_dir` holding audit cursors and settings.
pub(crate) const AUDIT_DIR: &str = "audit";

/// A connector's persisted position in an audit source (opaque bytes it
/// serializes itself; never a sampled value or a query text).
#[derive(Debug, Clone)]
pub struct CursorStore {
    path: PathBuf,
    /// Records to skip from the saved position (see
    /// [`Self::skip_records`]).
    skip: u32,
    /// Isolation mode (see [`Self::isolate`]).
    isolate: bool,
    /// Set when the connector reads [`Self::skip_records`]: its source can
    /// skip a record (the core's registry, `None` outside the core).
    skip_reader: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// Why a cursor could not be read or written (logged by kind only).
#[derive(Debug, thiserror::Error)]
#[error("audit cursor {op} failed: {kind}")]
pub struct CursorError {
    op: &'static str,
    kind: std::io::ErrorKind,
}

impl CursorStore {
    /// The cursor `name` of `target_id` in `dir` (normally obtained through
    /// `AuditConfig::cursor`). `None` unless both are `[a-z0-9_.-]{1,64}`
    /// and do not start with a dot.
    #[must_use]
    pub fn new(dir: &Path, target_id: &str, name: &str) -> Option<Self> {
        let ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
                && !s.starts_with('.')
        };
        (ok(target_id) && ok(name)).then(|| Self {
            path: dir.join(format!("{target_id}.{name}.cursor")),
            skip: 0,
            isolate: false,
            skip_reader: None,
        })
    }

    /// With a request to skip `n` records (see [`Self::skip_records`]).
    /// Set by the core through the `AuditConfig`; public for the
    /// connectors' tests.
    #[must_use]
    pub fn with_skip(mut self, n: u32) -> Self {
        self.skip = n;
        self
    }

    /// In isolation mode (see [`Self::isolate`]). Set by the core; public
    /// for the connectors' tests.
    #[must_use]
    pub fn with_isolation(mut self) -> Self {
        self.isolate = true;
        self
    }

    /// Records the core asks the stream to skip from the saved position,
    /// normally 0, else 1: the stream panicked repeatedly **at exactly this
    /// saved position** (the request is dropped when the saved bytes
    /// differ from those the panics happened at), in isolation mode, so the
    /// record at fault is the first one read from it. The connector drops
    /// that record without handling it, counts it as dropped
    /// (`audit.records_dropped`), and goes on.
    #[must_use]
    pub fn skip_records(&self) -> u32 {
        if let Some(flag) = &self.skip_reader {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.skip
    }

    /// Isolation mode: the stream panicked after this position; for its
    /// next read (at least the entries a normal read from here would
    /// cover), it hands over and saves its position after **every
    /// record**, so a panic that comes again is at the exact record at
    /// fault, and a skip ([`Self::skip_records`]) drops that record only.
    #[must_use]
    pub fn isolate(&self) -> bool {
        self.isolate
    }

    /// Reads the cursor. `Ok(None)` when none was saved yet.
    ///
    /// # Errors
    /// [`CursorError`] when the file exists but is not a private regular
    /// file of the agent user, is larger than 64 KiB, or cannot be read.
    pub fn load(&self) -> Result<Option<Vec<u8>>, CursorError> {
        match fsutil::read_private(&self.path) {
            Ok(bytes) if bytes.len() <= MAX_CURSOR_BYTES => Ok(Some(bytes)),
            Ok(_) => Err(CursorError {
                op: "read",
                kind: std::io::ErrorKind::InvalidData,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CursorError {
                op: "read",
                kind: e.kind(),
            }),
        }
    }

    /// Saves the cursor atomically (`0600`, fsync).
    ///
    /// # Errors
    /// [`CursorError`] on a write failure or a cursor above 64 KiB.
    pub fn save(&self, bytes: &[u8]) -> Result<(), CursorError> {
        if bytes.len() > MAX_CURSOR_BYTES {
            return Err(CursorError {
                op: "write",
                kind: std::io::ErrorKind::InvalidInput,
            });
        }
        fsutil::write_private_atomic(&self.path, bytes).map_err(|e| CursorError {
            op: "write",
            kind: e.kind(),
        })
    }
}

/// The cursors one audit stream uses (every `AuditConfig::cursor` it
/// asked for), shared by the core across the restarts of that stream: the
/// stream's position is the content of these files only, and a skip
/// request is bound to their exact content when the panics happened.
#[derive(Debug, Clone, Default)]
pub(crate) struct PositionRegistry {
    inner: std::sync::Arc<std::sync::Mutex<PositionState>>,
}

#[derive(Debug, Default)]
struct PositionState {
    /// Cursor files used by the stream.
    used: std::collections::BTreeSet<PathBuf>,
    /// Their content hashes at the last panic.
    at_panic: HashMap<PathBuf, u64>,
    /// The stream's source reads skip requests.
    skips: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn content_hash(path: &Path) -> Option<u64> {
    use std::hash::{Hash as _, Hasher as _};
    let bytes = fsutil::read_private(path).ok()?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return None;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    Some(h.finish())
}

impl PositionRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, PositionState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers `store` as used by the stream and applies the core's
    /// request: isolation mode, and the skip only when the file holds the
    /// exact position the panics happened at.
    pub(crate) fn register(&self, store: CursorStore, isolate: bool, skip: u32) -> CursorStore {
        let mut state = self.lock();
        state.used.insert(store.path.clone());
        let mut store = store;
        store.skip_reader = Some(std::sync::Arc::clone(&state.skips));
        if isolate {
            store = store.with_isolation();
        }
        if skip > 0 {
            let expected = state.at_panic.get(&store.path).copied();
            if expected.is_some() && expected == content_hash(&store.path) {
                store = store.with_skip(skip);
            }
        }
        store
    }

    /// Whether the stream's source reads skip requests
    /// ([`CursorStore::skip_records`]): only then is a skip announced.
    pub(crate) fn skips_supported(&self) -> bool {
        self.lock().skips.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The stream's saved position after a panic (a hash of its cursor
    /// files, remembered for [`Self::register`]); `None` when it saved
    /// none (a position in memory, or nothing saved yet).
    pub(crate) fn snapshot(&self) -> Option<u64> {
        use std::hash::{Hash as _, Hasher as _};
        let mut state = self.lock();
        let hashes: Vec<(PathBuf, u64)> = state
            .used
            .iter()
            .filter_map(|p| content_hash(p).map(|h| (p.clone(), h)))
            .collect();
        state.at_panic = hashes.iter().cloned().collect();
        if hashes.is_empty() {
            return None;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        hashes.hash(&mut h);
        Some(h.finish())
    }
}

/// Most groups held by one aggregator; a full aggregator is flushed early.
pub(crate) const MAX_GROUPS: usize = 10_000;

/// Pre-aggregation of one target's events.
pub(crate) struct Aggregator {
    window: Duration,
    groups: HashMap<EventGroupKey, MaskedEvent>,
    opened: Option<Instant>,
}

impl Aggregator {
    pub(crate) fn new(window: Duration) -> Self {
        Self {
            window,
            groups: HashMap::new(),
            opened: None,
        }
    }

    pub(crate) fn push(&mut self, event: MaskedEvent, now: Instant) {
        if self.opened.is_none() {
            self.opened = Some(now);
        }
        let key = event.group_key();
        match self.groups.get_mut(&key) {
            Some(existing) => existing.merge(event),
            None => {
                self.groups.insert(key, event);
            }
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.groups.len() >= MAX_GROUPS
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// When the current window closes, if any event is held.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.opened.map(|t| t + self.window)
    }

    pub(crate) fn drain(&mut self) -> Vec<MaskedEvent> {
        self.opened = None;
        let mut out: Vec<MaskedEvent> = self.groups.drain().map(|(_, e)| e).collect();
        out.sort_by_key(MaskedEvent::ts);
        out
    }
}

/// The `audit.configure` reporting filter (see the module documentation).
pub(crate) fn reportable(cfg: &AuditConfig, e: &MaskedEvent) -> bool {
    if !e.signals().is_empty() {
        return true;
    }
    if !matches!(e.action(), EventAction::Read | EventAction::Write) {
        return true;
    }
    let sensitive = e.objects().iter().any(|o| {
        cfg.is_sensitive(
            o.database().as_str(),
            o.schema().map(|s| s.as_str()),
            o.object().as_str(),
        )
    });
    sensitive
        || match cfg.min_rows() {
            None => true,
            Some(min) => e.rows().is_some_and(|r| r >= min),
        }
}

/// Path of the persisted `audit.configure` settings of a target.
pub(crate) fn settings_path(audit_dir: &Path, target_id: &str) -> Option<PathBuf> {
    CursorStore::new(audit_dir, target_id, "settings").map(|c| c.path.with_extension("json"))
}

/// Saves the settings of a target (the contract parameters as received;
/// they hold normalized names and numbers only).
pub(crate) fn save_settings(audit_dir: &Path, target_id: &str, json: &[u8]) -> std::io::Result<()> {
    let path = settings_path(audit_dir, target_id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "target id"))?;
    fsutil::ensure_private_dir(audit_dir)?;
    fsutil::write_private_atomic(&path, json)
}

/// Loads the settings of a target, `None` when absent or unreadable.
pub(crate) fn load_settings(audit_dir: &Path, target_id: &str) -> Option<Vec<u8>> {
    let path = settings_path(audit_dir, target_id)?;
    match fsutil::read_private(&path) {
        Ok(bytes) if bytes.len() <= MAX_CURSOR_BYTES * 16 => Some(bytes),
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(target_id, kind = %e.kind(), "cannot read the saved audit settings");
            None
        }
    }
}

/// Removes the settings of a target (audit disabled).
pub(crate) fn remove_settings(audit_dir: &Path, target_id: &str) {
    if let Some(path) = settings_path(audit_dir, target_id) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::time::SystemTime;

    use databastion_classifiers::masking::{EventObject, EventPrincipal, EventSource, Signal};
    use databastion_classifiers::names::normalize_path;

    use super::*;
    use crate::config::{Limits, TargetConfig};
    use crate::job::AuditParams;

    fn ev(user: &str, object: &str, rows: Option<u64>) -> MaskedEvent {
        MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account(user),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .with_object(EventObject::new(
            normalize_path("shop"),
            Some(normalize_path("crm")),
            normalize_path(object),
        ))
        .with_rows(rows)
    }

    fn cfg(json: serde_json::Value) -> AuditConfig {
        let params: databastion_protocol::AuditConfigureParams =
            serde_json::from_value(json).unwrap();
        let target: TargetConfig = serde_yaml_ng::from_str(
            "{id: pg, engine: postgres, host: db, account: a, secret: {env: PW}}",
        )
        .unwrap();
        AuditConfig::new(
            AuditParams::try_from(&params).unwrap(),
            &target,
            &Limits::default(),
        )
    }

    #[test]
    fn aggregation_merges_same_group_only() {
        let mut a = Aggregator::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(a.deadline().is_none());
        a.push(ev("u", "customers", Some(5)), now);
        a.push(
            ev("u", "customers", Some(7)).with_signal(Signal::FullTableRead),
            now,
        );
        a.push(ev("v", "customers", None), now);
        assert_eq!(a.deadline(), Some(now + Duration::from_secs(60)));
        let out = a.drain();
        assert_eq!(out.len(), 2);
        let u = out
            .iter()
            .find(|e| e.principal().account_name() == "u")
            .unwrap();
        assert_eq!(u.aggregated_count(), 2);
        assert_eq!(u.rows(), Some(12));
        assert_eq!(u.signals(), [Signal::FullTableRead]);
        assert!(a.is_empty() && a.deadline().is_none());
    }

    #[test]
    fn reporting_filter_follows_the_contract() {
        let c = cfg(serde_json::json!({
            "enabled": true, "min_rows": 100,
            "sensitive_objects": [{"database": "shop", "schema": "crm", "object": "customers",
                                   "classifiers": ["pii.email"]}]
        }));
        assert!(reportable(&c, &ev("u", "customers", Some(1))), "sensitive");
        assert!(
            !reportable(&c, &ev("u", "other", Some(99))),
            "below min_rows"
        );
        assert!(!reportable(&c, &ev("u", "other", None)), "unknown rows");
        assert!(reportable(&c, &ev("u", "other", Some(100))));
        assert!(reportable(
            &c,
            &ev("u", "other", Some(1)).with_signal(Signal::PgDump)
        ));
        // Empty list and no min_rows: everything.
        let c = cfg(serde_json::json!({"enabled": true, "sensitive_objects": []}));
        assert!(reportable(&c, &ev("u", "other", None)));
    }

    #[test]
    fn cursor_store_is_private_and_bounded() {
        let dir = std::env::temp_dir().join(format!(
            "databastion-cursor-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fsutil::ensure_private_dir(&dir).unwrap();
        assert!(CursorStore::new(&dir, "../x", "c").is_none());
        assert!(CursorStore::new(&dir, "pg", "a/b").is_none());
        let c = CursorStore::new(&dir, "pg", "pgaudit").unwrap();
        assert!(c.load().unwrap().is_none());
        c.save(b"{\"offset\":1}").unwrap();
        assert_eq!(c.load().unwrap().unwrap(), b"{\"offset\":1}");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.join("pg.pgaudit.cursor"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(c.save(&vec![b'x'; MAX_CURSOR_BYTES + 1]).is_err());
        save_settings(&dir, "pg", b"{}").unwrap();
        assert_eq!(load_settings(&dir, "pg").unwrap(), b"{}");
        remove_settings(&dir, "pg");
        assert!(load_settings(&dir, "pg").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
