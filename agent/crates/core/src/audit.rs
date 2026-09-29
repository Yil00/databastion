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

    /// Records the core asks the stream to skip from the saved position,
    /// normally 0. The stream panicked repeatedly at this position (a
    /// record that crashes a parser would otherwise stop Audit of the
    /// target for good): the connector drops the first `n` records it
    /// reads from the saved position, counts them as dropped
    /// (`audit.records_dropped`), and goes on. The core raises `n` (1, 2,
    /// 4…) while the stream keeps panicking at the same position, and
    /// stops the stream when panics go on at different positions.
    #[must_use]
    pub fn skip_records(&self) -> u32 {
        self.skip
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

/// A fingerprint of the saved read positions of `target_id` (every
/// cursor file of the target in `dir`, names and contents): equal while
/// the stream has not moved. `None` when the target has no saved cursor
/// (a source whose position is in memory, or nothing saved yet).
pub(crate) fn position_fingerprint(dir: &Path, target_id: &str) -> Option<u64> {
    use std::hash::{Hash as _, Hasher as _};
    let prefix = format!("{target_id}.");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".cursor"))
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for n in &names {
        n.hash(&mut h);
        match fsutil::read_private(&dir.join(n)) {
            Ok(bytes) if bytes.len() <= MAX_CURSOR_BYTES => bytes.hash(&mut h),
            _ => 0u8.hash(&mut h),
        }
    }
    Some(h.finish())
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
