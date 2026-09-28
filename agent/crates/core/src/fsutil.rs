//! Private-file helpers for the state directory (identity, pending secret,
//! HMAC key). Unix only: files are `0600`, the directory `0700`.
//!
//! - The state directory must be a real directory (not a symlink) owned by
//!   the effective uid and not writable by group or others; a mode other
//!   than `0700` only warns.
//! - State files are opened with `O_NOFOLLOW` (rustix, no `unsafe`) and
//!   checked on the open handle (`fstat`): regular file, owned by the
//!   effective uid, no group / other access.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustix::fs::{Mode, OFlags};

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Checks that `dir` is a directory (not a symlink) owned by the effective
/// uid and not writable by group or others.
pub(crate) fn check_private_dir(dir: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(denied("state_dir must be a directory, not a symlink"));
    }
    if meta.uid() != euid() {
        return Err(denied("state_dir must be owned by the agent user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(denied("state_dir must not be writable by group or others"));
    }
    if meta.mode() & 0o077 != 0 {
        tracing::warn!(
            mode = format!("{:o}", meta.mode() & 0o777),
            "state_dir should be 0700"
        );
    }
    Ok(())
}

/// Creates `dir` (and parents) with mode `0700` if it does not exist, then
/// checks it with [`check_private_dir`].
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if fs::symlink_metadata(dir).is_err() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    check_private_dir(dir)
}

/// Writes `bytes` to `path` atomically with mode `0600`: temporary file in
/// the same directory (created `0600`, never world-readable), `fsync`,
/// `rename`, then `fsync` of the directory so the rename is durable.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    // A stale temporary file from a crash is replaced.
    let _ = fs::remove_file(&tmp);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        // `mode` is filtered by the umask; enforce 0600 explicitly.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Opens a private file without following symlinks and checks the handle:
/// regular file, owned by the effective uid, no group / other access.
pub(crate) fn open_private(path: &Path) -> io::Result<File> {
    let fd = rustix::fs::open(
        path,
        // NONBLOCK: a FIFO planted in the state directory cannot block
        // the open; the handle is then checked to be a regular file.
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            denied("state file is a symlink")
        } else {
            io::Error::from(e)
        }
    })?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(denied("state file is not a regular file"));
    }
    if meta.uid() != euid() {
        return Err(denied("state file is not owned by the agent user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(denied(
            "file is accessible by group or others (expected 0600)",
        ));
    }
    Ok(file)
}

/// Reads a private file (see [`open_private`]).
pub(crate) fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = open_private(path)?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
pub(crate) mod test_dir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temporary directory removed on drop (tests only).
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "databastion-core-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_dir::TempDir;
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn atomic_write_creates_0600_and_replaces() {
        let dir = TempDir::new();
        let path = dir.path().join("identity.json");
        write_private_atomic(&path, b"one").unwrap();
        assert_eq!(mode(&path), 0o600);
        write_private_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(mode(&path), 0o600);
        // No temporary file left behind.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["identity.json"]);
    }

    #[test]
    fn atomic_write_tightens_existing_permissive_file() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_atomic(&path, b"y").unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn read_private_refuses_group_or_world_access() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_private_atomic(&path, b"x").unwrap();
        assert_eq!(read_private(&path).unwrap(), b"x");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read_private(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn symlinked_state_file_is_refused() {
        let dir = TempDir::new();
        let real = dir.path().join("real.key");
        write_private_atomic(&real, b"k").unwrap();
        let link = dir.path().join("hmac.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = read_private(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
    }

    #[test]
    fn non_regular_state_file_is_refused() {
        let dir = TempDir::new();
        let sub = dir.path().join("identity.json");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_private(&sub).is_err());
    }

    #[test]
    fn group_writable_or_symlinked_state_dir_is_refused() {
        let dir = TempDir::new();
        let state = dir.path().join("state");
        ensure_private_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            ensure_private_dir(&state).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        ensure_private_dir(&state).unwrap(); // warns only
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        assert!(check_private_dir(&link).is_err());
    }

    #[test]
    fn private_dir_is_0700() {
        let dir = TempDir::new();
        let state = dir.path().join("a/b");
        ensure_private_dir(&state).unwrap();
        assert_eq!(mode(&state), 0o700);
    }
}
