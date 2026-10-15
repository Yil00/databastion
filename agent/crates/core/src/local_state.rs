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
    // Bounded read (re-review R3): a larger file is never read whole.
    fsutil::read_private_bounded(&dir.join(name), MAX_MARK).ok()
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

/// Removes the mark at `dir/name`, if any: `Ok(true)` when one was
/// removed, `Ok(false)` when there was none (or no `dir`). `dir` must be a
/// private directory (not a symlink, owned by the agent's user, not
/// writable by others); the mark itself is unlinked, never followed.
///
/// # Errors
/// An invalid name, a `dir` that is not private, or an I/O error.
pub fn remove(dir: &Path, name: &str) -> io::Result<bool> {
    if !valid_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid mark"));
    }
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    fsutil::check_private_dir(dir)?;
    match std::fs::remove_file(dir.join(name)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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

    /// Re-review R3: a mark over 4 KiB is refused without being read
    /// whole; exactly 4 KiB is read.
    #[test]
    fn large_marks_are_refused() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let sub = dir.path().join("marks");
        store(&sub, "t1", &[b'x'; MAX_MARK]).unwrap();
        assert_eq!(load(&sub, "t1").map(|m| m.len()), Some(MAX_MARK));
        assert!(store(&sub, "t2", &[b'x'; MAX_MARK + 1]).is_err());
        // Written around `store`, as a planted file would be.
        crate::fsutil::write_private_atomic(&sub.join("t2"), &vec![b'x'; 1 << 20]).unwrap();
        assert_eq!(load(&sub, "t2"), None);
    }

    #[test]
    fn marks_are_removed_without_following_links() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let sub = dir.path().join("marks");
        assert!(
            !remove(&sub, "t1").unwrap(),
            "no directory: nothing to remove"
        );
        store(&sub, "t1", b"x").unwrap();
        assert!(remove(&sub, "t1").unwrap());
        assert_eq!(load(&sub, "t1"), None);
        assert!(!remove(&sub, "t1").unwrap());
        assert!(remove(&sub, "../t1").is_err());
        // A symlinked mark is unlinked, its target kept.
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, sub.join("t3")).unwrap();
        assert!(remove(&sub, "t3").unwrap());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        // A symlinked directory is refused.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&sub, &link).unwrap();
        store(&sub, "t4", b"x").unwrap();
        assert!(remove(&link, "t4").is_err());
        assert_eq!(load(&sub, "t4").as_deref(), Some(&b"x"[..]));
    }
}
