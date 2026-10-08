//! Agent identity storage (`<state_dir>/identity.json`) and the local HMAC
//! key (`<state_dir>/hmac.key`).
//!
//! - Both files are `0600`, written atomically (see `fsutil`), and refused
//!   on load if group or others can access them.
//! - `identity.json` holds the agent id, the current secret and, during a
//!   rotation (ADR-0008), the **pending** secret generated locally.
//! - The HMAC key (32 bytes from the OS CSPRNG) is generated at enrollment
//!   and never transmitted (ADR-0003, I2).
//! - [`Identity`] has a redacted `Debug`: secrets are never printed.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use databastion_protocol::{AgentSecret, Uuid};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::fsutil;

const IDENTITY_FILE: &str = "identity.json";
const HMAC_KEY_FILE: &str = "hmac.key";
/// Rotate job ids remembered in `identity.json`.
pub(crate) const MAX_ROTATION_JOBS: usize = 8;
/// Length of the local HMAC key, in bytes.
pub(crate) const HMAC_KEY_LEN: usize = 32;

/// Identity storage errors. Never carry a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// No identity: the agent must be enrolled first.
    #[error("agent is not enrolled: {0} not found (run `databastion-agent enroll`)")]
    NotEnrolled(PathBuf),
    /// An identity already exists and `--force` was not given.
    #[error("an identity already exists in {0}; use --force to replace it")]
    AlreadyEnrolled(PathBuf),
    /// A state file could not be read or written.
    #[error("{path}: {kind}{detail}")]
    Io {
        /// File or directory.
        path: PathBuf,
        /// I/O error kind.
        kind: io::ErrorKind,
        /// Extra detail for permission problems.
        detail: &'static str,
    },
    /// A state file is corrupt.
    #[error("{0}: corrupt state file")]
    Corrupt(PathBuf),
    /// The OS random generator failed.
    #[error("OS random generator unavailable")]
    Random,
}

fn io_err(path: &Path, e: &io::Error) -> IdentityError {
    IdentityError::Io {
        path: path.to_owned(),
        kind: e.kind(),
        detail: if e.kind() == io::ErrorKind::PermissionDenied {
            " (state_dir must be owned by the agent user and not group/world writable; \
             state files must be regular 0600 files owned by the agent user, not symlinks)"
        } else {
            ""
        },
    }
}

/// The agent identity. Secrets are only readable inside this crate.
#[derive(Clone)]
pub struct Identity {
    pub(crate) agent_id: Uuid,
    pub(crate) secret: AgentSecret,
    pub(crate) pending: Option<AgentSecret>,
    /// Rotate jobs satisfied by the current pending or promoted secret
    /// (redelivery guard, ADR-0008), most recent last, at most
    /// [`MAX_ROTATION_JOBS`].
    pub(crate) rotation_jobs: Vec<Uuid>,
    pub(crate) heartbeat_interval_s: u64,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("agent_id", &self.agent_id)
            .field("secret", &"[REDACTED]")
            .field("pending", &self.pending.as_ref().map(|_| "[REDACTED]"))
            .field("heartbeat_interval_s", &self.heartbeat_interval_s)
            .finish()
    }
}

impl Identity {
    /// Agent identifier (not a secret).
    #[must_use]
    pub fn agent_id(&self) -> String {
        self.agent_id.to_string()
    }
}

/// On-disk format of `identity.json`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    agent_id: Uuid,
    agent_secret: AgentSecret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_secret: Option<AgentSecret>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rotation_job_ids: Vec<Uuid>,
    heartbeat_interval_s: u64,
}

/// Files of the state directory.
#[derive(Debug, Clone)]
pub(crate) struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    pub(crate) fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
        }
    }

    pub(crate) fn identity_path(&self) -> PathBuf {
        self.dir.join(IDENTITY_FILE)
    }

    pub(crate) fn hmac_key_path(&self) -> PathBuf {
        self.dir.join(HMAC_KEY_FILE)
    }

    pub(crate) fn has_identity(&self) -> bool {
        self.identity_path().exists()
    }

    pub(crate) fn ensure(&self) -> Result<(), IdentityError> {
        fsutil::ensure_private_dir(&self.dir).map_err(|e| io_err(&self.dir, &e))
    }

    /// Checks the state directory (owner, not group / world writable).
    fn check_dir(&self) -> Result<(), IdentityError> {
        match fsutil::check_private_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(IdentityError::NotEnrolled(self.identity_path()))
            }
            Err(e) => Err(io_err(&self.dir, &e)),
        }
    }

    pub(crate) fn has_hmac_key(&self) -> bool {
        self.hmac_key_path().exists()
    }

    pub(crate) fn load_identity(&self) -> Result<Identity, IdentityError> {
        self.check_dir()?;
        let path = self.identity_path();
        let bytes = match fsutil::read_private(&path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(IdentityError::NotEnrolled(path));
            }
            Err(e) => return Err(io_err(&path, &e)),
        };
        let file: IdentityFile =
            serde_json::from_slice(&bytes).map_err(|_| IdentityError::Corrupt(path))?;
        Ok(Identity {
            agent_id: file.agent_id,
            secret: file.agent_secret,
            pending: file.pending_secret,
            rotation_jobs: {
                let mut jobs = file.rotation_job_ids;
                let excess = jobs.len().saturating_sub(MAX_ROTATION_JOBS);
                jobs.drain(..excess);
                jobs
            },
            heartbeat_interval_s: file.heartbeat_interval_s,
        })
    }

    /// Persists the identity atomically (`0600`, fsync, rename, dir fsync).
    pub(crate) fn save_identity(&self, identity: &Identity) -> Result<(), IdentityError> {
        self.ensure()?;
        let path = self.identity_path();
        let file = IdentityFile {
            agent_id: identity.agent_id,
            agent_secret: identity.secret.clone(),
            pending_secret: identity.pending.clone(),
            rotation_job_ids: identity.rotation_jobs.clone(),
            heartbeat_interval_s: identity.heartbeat_interval_s,
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec_pretty(&file).map_err(|_| IdentityError::Corrupt(path.clone()))?,
        );
        fsutil::write_private_atomic(&path, &bytes).map_err(|e| io_err(&path, &e))
    }

    /// Generates a fresh local HMAC key (never transmitted).
    pub(crate) fn create_hmac_key(&self) -> Result<(), IdentityError> {
        self.ensure()?;
        let mut key = Zeroizing::new([0u8; HMAC_KEY_LEN]);
        getrandom::fill(key.as_mut()).map_err(|_| IdentityError::Random)?;
        let path = self.hmac_key_path();
        fsutil::write_private_atomic(&path, key.as_ref()).map_err(|e| io_err(&path, &e))
    }

    /// Loads the local HMAC key, checking its permissions and length.
    pub(crate) fn load_hmac_key(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        self.check_dir()?;
        let path = self.hmac_key_path();
        let key = Zeroizing::new(fsutil::read_private(&path).map_err(|e| io_err(&path, &e))?);
        if key.len() == HMAC_KEY_LEN {
            Ok(key)
        } else {
            Err(IdentityError::Corrupt(path))
        }
    }
}

/// The body of an agent secret: base64url without padding (RFC 4648
/// section 5), 43 characters for 32 bytes. Pinned by a fixed vector test so
/// that a `base64` upgrade cannot change it.
fn encode_secret_body(raw: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Generates a new agent secret: `dbs_` + base64url of 32 bytes from the OS
/// CSPRNG (ADR-0008). Retries in the (astronomically unlikely) case of a
/// body with fewer than 16 distinct characters, which the console rejects.
pub(crate) fn generate_secret() -> Result<AgentSecret, IdentityError> {
    for _ in 0..8 {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(raw.as_mut()).map_err(|_| IdentityError::Random)?;
        let body = encode_secret_body(&raw);
        let distinct = body.bytes().collect::<std::collections::HashSet<_>>().len();
        if distinct < 16 {
            continue;
        }
        let mut value = String::with_capacity(47);
        value.push_str("dbs_");
        value.push_str(&body);
        if let Ok(secret) = AgentSecret::try_from(value) {
            return Ok(secret);
        }
    }
    Err(IdentityError::Random)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fsutil::test_dir::TempDir;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) const S0: &str = "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE0";

    pub(crate) fn identity() -> Identity {
        Identity {
            agent_id: Uuid::try_from("01920f5f-0c30-7e6f-a043-2b3c4d5e6f70").unwrap(),
            secret: AgentSecret::try_from(S0).unwrap(),
            pending: None,
            rotation_jobs: Vec::new(),
            heartbeat_interval_s: 30,
        }
    }

    #[test]
    fn identity_round_trips_with_0600() {
        let dir = TempDir::new();
        let state = StateDir::new(&dir.path().join("state"));
        assert!(!state.has_identity());
        let mut id = identity();
        id.pending = Some(generate_secret().unwrap());
        state.save_identity(&id).unwrap();
        let mode = std::fs::metadata(state.identity_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let back = state.load_identity().unwrap();
        assert_eq!(back.agent_id, id.agent_id);
        assert_eq!(back.secret.expose(), S0);
        assert_eq!(back.pending.unwrap().expose(), id.pending.unwrap().expose());
    }

    #[test]
    fn missing_identity_is_not_enrolled() {
        let dir = TempDir::new();
        let state = StateDir::new(dir.path());
        assert!(matches!(
            state.load_identity(),
            Err(IdentityError::NotEnrolled(_))
        ));
    }

    #[test]
    fn world_readable_identity_is_refused() {
        let dir = TempDir::new();
        let state = StateDir::new(dir.path());
        state.save_identity(&identity()).unwrap();
        std::fs::set_permissions(
            state.identity_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let err = state.load_identity().unwrap_err().to_string();
        assert!(err.contains("0600"), "{err}");
    }

    #[test]
    fn debug_and_errors_never_show_secrets() {
        let mut id = identity();
        let pending = generate_secret().unwrap();
        let pending_text = pending.expose().to_owned();
        id.pending = Some(pending);
        let debug = format!("{id:?}");
        assert!(!debug.contains(S0), "{debug}");
        assert!(!debug.contains(&pending_text), "{debug}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn symlinked_hmac_key_is_refused() {
        let dir = TempDir::new();
        let state = StateDir::new(&dir.path().join("state"));
        state.create_hmac_key().unwrap();
        let real = dir.path().join("elsewhere.key");
        std::fs::rename(state.hmac_key_path(), &real).unwrap();
        std::os::unix::fs::symlink(&real, state.hmac_key_path()).unwrap();
        assert!(matches!(
            state.load_hmac_key(),
            Err(IdentityError::Io { .. })
        ));
    }

    #[test]
    fn group_writable_state_dir_is_refused() {
        let dir = TempDir::new();
        let state = StateDir::new(&dir.path().join("state"));
        state.save_identity(&identity()).unwrap();
        std::fs::set_permissions(
            dir.path().join("state"),
            std::fs::Permissions::from_mode(0o775),
        )
        .unwrap();
        assert!(matches!(
            state.load_identity(),
            Err(IdentityError::Io { .. })
        ));
        assert!(state.save_identity(&identity()).is_err());
    }

    #[test]
    fn hmac_key_is_32_random_bytes_0600() {
        let dir = TempDir::new();
        let state = StateDir::new(dir.path());
        state.create_hmac_key().unwrap();
        let first = state.load_hmac_key().unwrap();
        assert_eq!(first.len(), HMAC_KEY_LEN);
        state.create_hmac_key().unwrap();
        assert_ne!(*first, *state.load_hmac_key().unwrap());
        let mode = std::fs::metadata(state.hmac_key_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn generated_secrets_match_contract_and_differ() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_eq!(a.expose().len(), 47);
        assert!(a.expose().starts_with("dbs_"));
        assert_ne!(a.expose(), b.expose());
    }

    /// Fixed vectors for the secret body: URL-safe alphabet (`-` and `_`,
    /// never `+` or `/`), no `=` padding, 43 characters.
    #[test]
    fn secret_body_encoding_is_pinned() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        assert_eq!(
            encode_secret_body(&raw).as_str(),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert_eq!(
            encode_secret_body(&[0xfb; 32]).as_str(),
            "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
        );
        assert_eq!(
            encode_secret_body(&[0xff; 32]).as_str(),
            "__________________________________________8"
        );
    }
}
