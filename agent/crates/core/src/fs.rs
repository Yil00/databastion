//! Opening a path with no symbolic link followed anywhere in it, for the
//! connectors that check a file on its handle (the SQLite reader's grant,
//! ADR-0059 review M1; the Firebird host identity files, ADR-0060 R45
//! items 1 and 2).
//!
//! [`open_no_links`] calls `openat2` with `RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS`. Where `openat2` answers `ENOSYS`, the same
//! resolution is done one component at a time from `/` with `openat` and
//! `O_NOFOLLOW`, with the same result and the same errors. Every kernel the
//! agent supports has `openat2` (Linux 5.6); a seccomp filter is what gives
//! `ENOSYS`: systemd's `RestrictSUIDSGID=yes`, in the agent's unit
//! (`deploy/deb/databastion-agent.service`), refuses `openat2` with that
//! error because it cannot inspect the mode inside `struct open_how`.
//!
//! Read-only opens only, of canonical absolute paths. Nothing here logs
//! (I2): a path or an error is only returned to the caller, which maps it
//! to its own closed reasons.

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// The flags of a directory handle: [`open_no_links`] with them opens a
/// directory, or fails (`ENOTDIR`; `ELOOP` for a symbolic link).
pub const DIRECTORY: OFlags = OFlags::PATH.union(OFlags::DIRECTORY);

/// Opens `path` with `flags` (and `O_CLOEXEC`), no symbolic or magic link
/// followed anywhere in it: `openat2(RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS)`, or, where `openat2` answers `ENOSYS`, the
/// component walk, with the same answers:
///
/// - a symbolic link before the last component: `ELOOP`;
/// - a symbolic link as the last component: the link itself when `flags`
///   has both `O_PATH` and `O_NOFOLLOW` (the caller checks the handle's
///   type), `ELOOP` otherwise (a read open, or [`DIRECTORY`]);
/// - a component before the last that is not a directory, or the last one
///   with `O_DIRECTORY`: `ENOTDIR`;
/// - every other error of the kernel, unchanged (`ENOENT`, `EACCES`…).
///
/// The path is checked as text first, on either path, so that both give
/// the same answer: it must start with `/`, not end with `/`, and have no
/// empty, `.` or `..` segment (`Path::components()` would drop an interior
/// `.`, a repeated `/` and a trailing `/`); `EINVAL` otherwise. `flags`
/// must not create, truncate or write (`O_CREAT`, `O_TMPFILE`, `O_TRUNC`,
/// `O_APPEND`, `O_WRONLY`, `O_RDWR`): `EINVAL`.
pub fn open_no_links(path: &Path, flags: OFlags) -> Result<OwnedFd, Errno> {
    let names = segments(path)?;
    if !read_only(flags) {
        return Err(Errno::INVAL);
    }
    let flags = flags | OFlags::CLOEXEC;
    match rustix::fs::openat2(
        CWD,
        path,
        flags,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Err(Errno::NOSYS) => walk(&names, flags),
        other => other,
    }
}

/// The segments of a canonical absolute path, or `EINVAL`.
fn segments(path: &Path) -> Result<Vec<&OsStr>, Errno> {
    let text = path.as_os_str().as_bytes();
    let Some(rest) = text.strip_prefix(b"/") else {
        return Err(Errno::INVAL);
    };
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<&[u8]> = rest.split(|b| *b == b'/').collect();
    if names
        .iter()
        .any(|n| n.is_empty() || *n == b"." || *n == b"..")
    {
        return Err(Errno::INVAL);
    }
    Ok(names.into_iter().map(OsStr::from_bytes).collect())
}

/// Whether `flags` neither creates, truncates nor writes.
fn read_only(flags: OFlags) -> bool {
    !flags.contains(OFlags::TMPFILE)
        && !flags.intersects(
            OFlags::CREATE | OFlags::TRUNC | OFlags::APPEND | OFlags::WRONLY | OFlags::RDWR,
        )
}

/// [`open_no_links`] without `openat2`: from `/`, every component before
/// the last opened `O_PATH | O_NOFOLLOW` relative to the previous one and
/// checked with `fstat` (a symbolic link: `ELOOP`; anything else that is
/// not a directory: `ENOTDIR`), so no link, magic links included, is ever
/// followed; then the last one relative to its parent's handle.
fn walk(names: &[&OsStr], flags: OFlags) -> Result<OwnedFd, Errno> {
    let step = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let Some((last, before)) = names.split_last() else {
        // `/` itself: never a link.
        return rustix::fs::open("/", flags | OFlags::NOFOLLOW, Mode::empty());
    };
    let mut dir = rustix::fs::open("/", step | OFlags::DIRECTORY, Mode::empty())?;
    for name in before {
        let next = rustix::fs::openat(&dir, *name, step, Mode::empty())?;
        match FileType::from_raw_mode(rustix::fs::fstat(&next)?.st_mode) {
            FileType::Directory => dir = next,
            FileType::Symlink => return Err(Errno::LOOP),
            _ => return Err(Errno::NOTDIR),
        }
    }
    let fd = match rustix::fs::openat(&dir, *last, flags | OFlags::NOFOLLOW, Mode::empty()) {
        // `O_DIRECTORY` is checked before `O_NOFOLLOW` (`ENOTDIR`, where
        // `openat2` gives `ELOOP` for a link).
        Err(Errno::NOTDIR) if flags.contains(OFlags::DIRECTORY) => {
            return match rustix::fs::statat(&dir, *last, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
                    Err(Errno::LOOP)
                }
                _ => Err(Errno::NOTDIR),
            };
        }
        // A read open of a final link: `ELOOP` (`O_NOFOLLOW`).
        other => other?,
    };
    if flags.contains(OFlags::PATH) {
        // `O_PATH | O_NOFOLLOW` opens a final link itself: `openat2` gives
        // it only when the caller asked for `O_NOFOLLOW` and no directory.
        let link = FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) == FileType::Symlink;
        if link && (!flags.contains(OFlags::NOFOLLOW) || flags.contains(OFlags::DIRECTORY)) {
            return Err(Errno::LOOP);
        }
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::path::PathBuf;

    use super::*;

    /// `openat2` itself, as [`open_no_links`] calls it.
    fn resolve(path: &Path, flags: OFlags) -> Result<OwnedFd, Errno> {
        rustix::fs::openat2(
            CWD,
            path,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    }

    /// The component walk on the same input.
    fn walked(path: &Path, flags: OFlags) -> Result<OwnedFd, Errno> {
        let names = segments(path)?;
        walk(&names, flags | OFlags::CLOEXEC)
    }

    /// What a handle names: its inode and its type (a link opened as
    /// itself is told apart from its target).
    fn id(r: Result<OwnedFd, Errno>) -> Result<(u64, u64, FileType), Errno> {
        r.map(|fd| {
            let st = rustix::fs::fstat(&fd).unwrap();
            (st.st_dev, st.st_ino, FileType::from_raw_mode(st.st_mode))
        })
    }

    /// The flag sets of the callers: the SQLite grant (an `O_PATH` file
    /// that may be a final link, an `O_PATH` directory), the Firebird host
    /// identity files (a read open) and their directories.
    fn flag_sets() -> [(&'static str, OFlags); 5] {
        [
            ("sqlite file", OFlags::PATH | OFlags::NOFOLLOW),
            ("sqlite directory", OFlags::PATH | OFlags::DIRECTORY),
            (
                "firebird file",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            ),
            ("directory handle", DIRECTORY),
            ("read directory", OFlags::RDONLY | OFlags::DIRECTORY),
        ]
    }

    /// The fallback (`ENOSYS` under the systemd unit's
    /// `RestrictSUIDSGID=yes`) resolves every path as `openat2` with
    /// `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` does, for every flag
    /// set of the callers: the same inode and type, or the same error.
    #[test]
    fn the_component_walk_resolves_as_openat2() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("databastion-core-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("x.db"), b"x").unwrap();
        symlink(&dir, base.join("dir-link")).unwrap();
        symlink(dir.join("x.db"), dir.join("file-link")).unwrap();
        symlink("missing", dir.join("dangling")).unwrap();
        let pid = std::process::id();
        let proc_root = PathBuf::from("/proc/self/root").join(dir.strip_prefix("/").unwrap());
        let cases: Vec<PathBuf> = vec![
            PathBuf::from("/"),
            dir.clone(),
            dir.join("x.db"),
            dir.join("missing.db"),
            dir.join("x.db").join("below"),
            base.join("dir-link"),
            base.join("dir-link").join("x.db"),
            dir.join("file-link"),
            dir.join("dangling"),
            proc_root.clone(),
            proc_root.join("x.db"),
            PathBuf::from("/proc/self/fd"),
            PathBuf::from("/proc/self/exe"),
            PathBuf::from("/proc/self/cwd"),
            PathBuf::from("/proc/self/fd/0"),
            PathBuf::from("/proc/self/root/etc"),
            // Magic links, without the `/proc/self` link before them.
            PathBuf::from(format!("/proc/{pid}/fd/0")),
            PathBuf::from(format!("/proc/{pid}/exe")),
            PathBuf::from(format!("/proc/{pid}/cwd")),
            PathBuf::from(format!("/proc/{pid}/root")),
            PathBuf::from(format!("/proc/{pid}/root/etc")),
            PathBuf::from(format!("/proc/{pid}/fd")),
        ];
        for (what, flags) in flag_sets() {
            for path in &cases {
                let w = id(walked(path, flags));
                let r = id(resolve(path, flags));
                assert_eq!(w, r, "{what}: {path:?}");
            }
        }
        // Through the public entry point (openat2 here) too.
        for (what, flags) in flag_sets() {
            for path in &cases {
                assert_eq!(
                    id(open_no_links(path, flags)),
                    id(resolve(path, flags)),
                    "{what}: {path:?}"
                );
            }
        }
        // A final link opened as itself only with O_PATH | O_NOFOLLOW.
        let link = walked(&dir.join("file-link"), OFlags::PATH | OFlags::NOFOLLOW).unwrap();
        assert_eq!(
            FileType::from_raw_mode(rustix::fs::fstat(&link).unwrap().st_mode),
            FileType::Symlink
        );
        let read = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY;
        assert_eq!(id(walked(&dir.join("file-link"), read)), Err(Errno::LOOP));
        assert_eq!(
            id(walked(&dir.join("file-link"), DIRECTORY)),
            Err(Errno::LOOP)
        );
        assert_eq!(id(walked(&dir.join("x.db"), DIRECTORY)), Err(Errno::NOTDIR));
        // Not canonical: refused before any open, where `openat2` errors
        // (`/d/x.db/`: ENOTDIR) or normalizes (`/d/./x.db`, `/d//x.db`).
        let d = dir.to_str().unwrap();
        for (what, flags) in flag_sets() {
            for path in [
                "relative/x.db".to_owned(),
                String::new(),
                "/srv/../etc/x.db".to_owned(),
                format!("{d}/./x.db"),
                format!("{d}//x.db"),
                format!("{d}/x.db/"),
                format!("{d}/"),
                format!("{d}/."),
                format!("{d}/.."),
                "//".to_owned(),
            ] {
                let r = id(resolve(Path::new(&path), flags));
                assert_eq!(
                    id(walked(Path::new(&path), flags)),
                    Err(Errno::INVAL),
                    "{what}: {path} (openat2: {r:?})"
                );
                assert_eq!(
                    id(open_no_links(Path::new(&path), flags)),
                    Err(Errno::INVAL),
                    "{what}: {path}"
                );
            }
        }
        assert_eq!(
            id(resolve(Path::new(&format!("{d}/x.db/")), OFlags::PATH)),
            Err(Errno::NOTDIR)
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Opens that create, truncate or write are refused before any open.
    #[test]
    fn only_read_opens() {
        let file = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("databastion-core-ro-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        for flags in [
            OFlags::WRONLY,
            OFlags::RDWR,
            OFlags::RDONLY | OFlags::CREATE,
            OFlags::RDONLY | OFlags::TRUNC,
            OFlags::RDONLY | OFlags::APPEND,
            OFlags::TMPFILE | OFlags::RDWR,
        ] {
            assert_eq!(
                id(open_no_links(&file, flags)),
                Err(Errno::INVAL),
                "{flags:?}"
            );
        }
        assert_eq!(std::fs::read(&file).unwrap(), b"x");
        assert!(open_no_links(&file, OFlags::RDONLY | OFlags::NOFOLLOW).is_ok());
        assert!(open_no_links(&file, OFlags::PATH | OFlags::NOFOLLOW).is_ok());
        std::fs::remove_file(&file).unwrap();
    }
}
