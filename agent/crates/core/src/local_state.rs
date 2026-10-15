//! Small per-target marks a connector keeps in the agent's `state_dir`
//! (for example the SQL Server "strict seen" mark, ADR-0051 decision 2):
//! private files (`0600`, atomic write, never following a symlink, owned
//! by the agent's user), read fail-safe.

use std::io;
use std::path::Path;

use crate::fsutil;

/// Largest mark read.
const MAX_MARK: usize = 4096;

/// Reads the mark at `dir/name`: `None` when it is absent, unreadable, not
/// private, or larger than 4 KiB (the caller treats that as "not set").
#[must_use]
pub fn load(dir: &Path, name: &str) -> Option<Vec<u8>> {
    if !valid_name(name) {
        return None;
    }
    let bytes = fsutil::read_private(&dir.join(name)).ok()?;
    (bytes.len() <= MAX_MARK).then_some(bytes)
}

/// Writes the mark at `dir/name` atomically, `0600`, creating `dir`
/// (`0700`) if needed.
///
/// # Errors
/// An invalid name, a mark over 4 KiB, or an I/O error.
pub fn store(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    if !valid_name(name) || bytes.len() > MAX_MARK {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid mark"));
    }
    fsutil::ensure_private_dir(dir)?;
    fsutil::write_private_atomic(&dir.join(name), bytes)
}

/// A file name of `[a-z0-9_.-]`, 1 to 128 bytes, not starting with a dot.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn marks_are_private_and_fail_safe() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let sub = dir.path().join("marks");
        assert_eq!(load(&sub, "t1"), None);
        store(&sub, "t1", b"x").unwrap();
        assert_eq!(load(&sub, "t1").as_deref(), Some(&b"x"[..]));
        assert!(store(&sub, "../t", b"x").is_err());
        assert!(store(&sub, ".t", b"x").is_err());
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sub.join("t1"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load(&sub, "t1"), None, "not private: not set");
    }
}
