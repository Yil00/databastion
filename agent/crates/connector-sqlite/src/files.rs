//! The file rules of ADR-0059 decision 2 (and decision 3's layers 1, 2 and
//! 5): blocking I/O, no `unsafe` (`rustix`).
//!
//! - Every ancestor directory `lstat`ed from `/` down: a directory, not a
//!   symlink, not writable by the agent's account, not writable by every
//!   local user unless it has the sticky bit.
//! - The **check descriptor** (`O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
//!   O_NOCTTY | O_CLOEXEC`), then on it: `fstat` (a regular file, one link,
//!   not writable by the agent, at least 512 bytes), `fstatfs` (no network
//!   or FUSE file system), `fstatvfs` (`ST_RDONLY` required), and the
//!   header pre-check through `pread`.
//! - The side files `-wal`, `-shm`, `-journal` `lstat`ed and bound by
//!   `(st_dev, st_ino)`: regular, one link, not a symlink, not writable by
//!   the agent, owned by the database's owner or group, on the same file
//!   system.
//! - The descriptor bindings of steps 6 and 8 through `/proc/self/fd` and
//!   `/proc/self/fdinfo`.
//!
//! Rule (decision 2): no descriptor on a target's database or side files is
//! opened outside that target's lock; path-based checks (`lstat`,
//! `faccessat`) open none. Paths are never logged nor returned in an error:
//! a refusal is a closed [`Failure`].

use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Access, AtFlags, CWD, Mode, OFlags, StatVfsMountFlags};

use crate::header::{self, HEADER_LEN, Header};
use crate::ipc::{Code, Failure, Rule};

/// Largest `-wal` read (decision 3): the heap-index build reads all of it.
pub const MAX_WAL_BYTES: u64 = 128 * 1024 * 1024;

/// `f_type` values of network and FUSE file systems (Linux `magic.h`, and
/// the Lustre and GPFS values of their client modules).
pub const NETWORK_FS_MAGIC: [u64; 11] = [
    0x6969,      // NFS
    0x517B,      // SMB
    0xFF53_4D42, // CIFS
    0xFE53_4D42, // SMB2
    0x6573_5546, // FUSE
    0x0102_1997, // 9P (V9FS)
    0x00C3_6400, // Ceph
    0x5346_414F, // AFS (OpenAFS / kAFS)
    0x7375_7245, // Coda
    0x0BD0_0BD0, // Lustre
    0x4750_4653, // GPFS
];

/// How strict the checks are. Only this crate's in-process tests relax
/// them (every file a test creates is its own, tests may run as root, and
/// a test harness holds descriptors of its own): never the reader process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Refuse what the agent's account could write.
    pub refuse_agent_writable: bool,
    /// Require a read-only mount (`ST_RDONLY`).
    pub require_read_only_fs: bool,
    /// Step 8: every descriptor of the process must be a known one.
    pub exact_descriptor_set: bool,
}

impl Policy {
    /// The policy of the reader process and of the agent's light check.
    pub const STRICT: Self = Self {
        refuse_agent_writable: true,
        require_read_only_fs: true,
        exact_descriptor_set: true,
    };

    /// The policy of the agent's own light check: the agent's process holds
    /// other descriptors (its sockets, files), so step 8 is the reader's.
    pub const AGENT: Self = Self {
        exact_descriptor_set: false,
        ..Self::STRICT
    };

    /// In-process tests only.
    #[cfg(test)]
    pub const TESTS: Self = Self {
        refuse_agent_writable: false,
        require_read_only_fs: false,
        exact_descriptor_set: false,
    };
}

/// A file's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

/// A checked side file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideFile {
    /// Its identity.
    pub id: Identity,
    /// Its size.
    pub size: u64,
}

/// The side files present at the check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SideFiles {
    /// `<path>-wal`.
    pub wal: Option<SideFile>,
    /// `<path>-shm`.
    pub shm: Option<SideFile>,
    /// `<path>-journal`.
    pub journal: Option<SideFile>,
}

impl SideFiles {
    fn all(&self) -> impl Iterator<Item = &SideFile> {
        [&self.wal, &self.shm, &self.journal].into_iter().flatten()
    }
}

/// The result of the open procedure's steps 1 to 4.
#[derive(Debug)]
pub struct Checked {
    /// The check descriptor, held while the connection is open.
    pub fd: OwnedFd,
    /// The file's identity.
    pub id: Identity,
    /// Its owner and group.
    pub owner: (u32, u32),
    /// Its size.
    pub size: u64,
    /// Its `mtime` (seconds, nanoseconds).
    pub mtime: (i64, i64),
    /// The header.
    pub header: Header,
    /// The side files.
    pub side: SideFiles,
    /// Readable by every local user.
    pub world_readable: bool,
}

/// The agent's identity, for the writability rule.
#[derive(Debug, Clone)]
struct Me {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

fn me() -> Me {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let groups = rustix::process::getgroups()
        .map(|g| g.into_iter().map(rustix::process::Gid::as_raw).collect())
        .unwrap_or_default();
    Me { uid, gid, groups }
}

/// Whether the agent's account could write a file of this owner and mode
/// (decision 2, step 1): it owns it, a group-write bit for one of its
/// groups, the other-write bit, or `faccessat(W_OK, AT_EACCESS)` (POSIX
/// ACLs; `EROFS` on a read-only mount).
fn writable(path: &Path, uid: u32, gid: u32, mode: u32, me: &Me) -> bool {
    uid == me.uid
        || (mode & 0o020 != 0 && (gid == me.gid || me.groups.contains(&gid)))
        || mode & 0o002 != 0
        || rustix::fs::accessat(CWD, path, Access::WRITE_OK, AtFlags::EACCESS).is_ok()
}

fn io_failure(e: rustix::io::Errno) -> Failure {
    match e {
        rustix::io::Errno::NOENT => Failure::new(Code::NotFound),
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => Failure::new(Code::NotReadable),
        rustix::io::Errno::LOOP => Failure::rule(Code::PathRefused, Rule::SymlinkComponent),
        rustix::io::Errno::NOTDIR => Failure::rule(Code::PathRefused, Rule::NotDirectory),
        _ => Failure::new(Code::NotReadable),
    }
}

fn std_failure(e: &std::io::Error) -> Failure {
    match e.kind() {
        std::io::ErrorKind::NotFound => Failure::new(Code::NotFound),
        std::io::ErrorKind::PermissionDenied => Failure::new(Code::NotReadable),
        _ => Failure::new(Code::NotReadable),
    }
}

/// Steps 1 (ancestors) of decision 2, and the final component not a
/// symlink. Path-based only: no descriptor.
///
/// # Errors
/// The rule broken.
pub fn check_ancestors(path: &Path, policy: Policy) -> Result<(), Failure> {
    if !databastion_core::config::sqlite::is_canonical_path(path) {
        return Err(Failure::rule(Code::PathRefused, Rule::NotCanonical));
    }
    let me = me();
    let mut prefix = PathBuf::from("/");
    let components: Vec<_> = path.components().skip(1).collect();
    let last = components.len().saturating_sub(1);
    for (i, c) in components.iter().enumerate() {
        // The file's own directory gets the full rule; an ancestor above it
        // with the sticky bit, owned by another account, is accepted (the
        // sticky bit stops the agent from renaming or removing entries it
        // does not own, as `/tmp`).
        let parent = i + 1 == last || (last == 0 && i == 0);
        let check_dir = |p: &Path| -> Result<(), Failure> {
            let m = std::fs::symlink_metadata(p).map_err(|e| std_failure(&e))?;
            if m.file_type().is_symlink() {
                return Err(Failure::rule(Code::PathRefused, Rule::SymlinkComponent));
            }
            if !m.is_dir() {
                return Err(Failure::rule(Code::PathRefused, Rule::NotDirectory));
            }
            let mode = m.permissions().mode();
            if mode & 0o002 != 0 && mode & 0o1000 == 0 {
                return Err(Failure::rule(
                    Code::PathRefused,
                    Rule::WorldWritableDirectory,
                ));
            }
            let sticky_ancestor = !parent && mode & 0o1000 != 0 && m.uid() != me.uid;
            if policy.refuse_agent_writable
                && !sticky_ancestor
                && writable(p, m.uid(), m.gid(), mode, &me)
            {
                return Err(Failure::new(Code::Writable));
            }
            Ok(())
        };
        if i == 0 {
            check_dir(Path::new("/"))?;
        }
        prefix.push(c);
        if i < last {
            check_dir(&prefix)?;
        } else {
            // The file itself: not a symlink, and a regular file before
            // anything opens it (review L7: never a FIFO or a device).
            let m = std::fs::symlink_metadata(&prefix).map_err(|e| std_failure(&e))?;
            if m.file_type().is_symlink() {
                return Err(Failure::rule(Code::PathRefused, Rule::SymlinkComponent));
            }
            if !m.is_file() {
                return Err(Failure::rule(Code::PathRefused, Rule::NotRegularFile));
            }
        }
    }
    Ok(())
}

/// The path of a side file.
#[must_use]
pub fn side_path(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Step 4 for one side file: `lstat` only.
fn check_side(
    path: &Path,
    db: (u32, u32),
    dev: u64,
    policy: Policy,
    me: &Me,
) -> Result<Option<SideFile>, Failure> {
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(std_failure(&e)),
    };
    if m.file_type().is_symlink() {
        return Err(Failure::rule(Code::PathRefused, Rule::SymlinkComponent));
    }
    if !m.is_file() {
        return Err(Failure::rule(Code::PathRefused, Rule::NotRegularFile));
    }
    if m.nlink() != 1 {
        return Err(Failure::rule(Code::PathRefused, Rule::HardLink));
    }
    if policy.refuse_agent_writable && writable(path, m.uid(), m.gid(), m.mode(), me) {
        return Err(Failure::new(Code::Writable));
    }
    if (m.uid() != db.0 && m.gid() != db.1) || m.dev() != dev {
        return Err(Failure::rule(Code::PathRefused, Rule::SideFileForeign));
    }
    Ok(Some(SideFile {
        id: Identity {
            dev: m.dev(),
            ino: m.ino(),
        },
        size: m.size(),
    }))
}

/// The side files (step 4).
///
/// # Errors
/// The rule broken.
pub fn check_side_files(
    path: &Path,
    owner: (u32, u32),
    dev: u64,
    policy: Policy,
) -> Result<SideFiles, Failure> {
    let me = me();
    Ok(SideFiles {
        wal: check_side(&side_path(path, "-wal"), owner, dev, policy, &me)?,
        shm: check_side(&side_path(path, "-shm"), owner, dev, policy, &me)?,
        journal: check_side(&side_path(path, "-journal"), owner, dev, policy, &me)?,
    })
}

/// Steps 2 and 3 on a descriptor: `fstat`, `fstatfs`, `fstatvfs`, the
/// header through `pread`.
fn check_descriptor(
    fd: BorrowedFd<'_>,
    path: &Path,
    policy: Policy,
) -> Result<(rustix::fs::Stat, Header), Failure> {
    let st = rustix::fs::fstat(fd).map_err(io_failure)?;
    let kind = rustix::fs::FileType::from_raw_mode(st.st_mode);
    if kind != rustix::fs::FileType::RegularFile {
        return Err(Failure::rule(Code::PathRefused, Rule::NotRegularFile));
    }
    if st.st_nlink != 1 {
        return Err(Failure::rule(Code::PathRefused, Rule::HardLink));
    }
    let me = me();
    let mode = st.st_mode;
    if policy.refuse_agent_writable && writable(path, st.st_uid, st.st_gid, mode, &me) {
        return Err(Failure::new(Code::Writable));
    }
    let fs = rustix::fs::fstatfs(fd).map_err(io_failure)?;
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        reason = "f_type is a magic number"
    )]
    let magic = (fs.f_type as u64) & 0xFFFF_FFFF;
    if NETWORK_FS_MAGIC.contains(&magic) {
        return Err(Failure::new(Code::NetworkFs));
    }
    let vfs = rustix::fs::fstatvfs(fd).map_err(io_failure)?;
    if policy.require_read_only_fs && !vfs.f_flag.contains(StatVfsMountFlags::RDONLY) {
        return Err(Failure::new(Code::NotReadOnlyFs));
    }
    let size = u64::try_from(st.st_size).unwrap_or(0);
    let mut buf = [0u8; HEADER_LEN];
    let mut got = 0;
    while got < HEADER_LEN {
        let rest = buf.get_mut(got..).unwrap_or_default();
        match rustix::io::pread(fd, rest, u64::try_from(got).unwrap_or(0)) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(io_failure(e)),
        }
    }
    let head = buf.get(..got).unwrap_or_default();
    let header = header::check(head, size).ok_or_else(|| Failure::new(Code::UnrecognizedFormat))?;
    Ok((st, header))
}

/// Steps 1 to 4 of decision 2: the ancestors, the check descriptor and its
/// checks, the header, the side files. The descriptor is returned held.
///
/// # Errors
/// The rule broken.
pub fn open_checked(path: &Path, policy: Policy) -> Result<Checked, Failure> {
    check_ancestors(path, policy)?;
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_failure)?;
    let (st, header) = check_descriptor(fd.as_fd(), path, policy)?;
    let id = Identity {
        dev: st.st_dev,
        ino: st.st_ino,
    };
    let owner = (st.st_uid, st.st_gid);
    let side = check_side_files(path, owner, id.dev, policy)?;
    Ok(Checked {
        fd,
        id,
        owner,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mtime: (st.st_mtime, i64::try_from(st.st_mtime_nsec).unwrap_or(0)),
        header,
        side,
        world_readable: st.st_mode & 0o004 != 0,
    })
}

/// The light check on a held descriptor (decision 7): the path checks, then
/// `fstat` and `pread` on the held check descriptor; the file at the path
/// must still be the one held.
///
/// # Errors
/// The rule broken, or [`Code::FileChanged`].
pub fn recheck(path: &Path, checked: &Checked, policy: Policy) -> Result<SideFiles, Failure> {
    check_ancestors(path, policy)?;
    let (st, _) = check_descriptor(checked.fd.as_fd(), path, policy)?;
    let now = std::fs::symlink_metadata(path).map_err(|e| std_failure(&e))?;
    if (now.dev(), now.ino()) != (checked.id.dev, checked.id.ino)
        || (st.st_dev, st.st_ino) != (checked.id.dev, checked.id.ino)
    {
        return Err(Failure::new(Code::FileChanged));
    }
    check_side_files(path, checked.owner, checked.id.dev, policy)
}

/// The identity of the file at `path`, without opening it (`stat`, path
/// based; the duplicate rule).
#[must_use]
pub fn identity_of(path: &Path) -> Option<Identity> {
    std::fs::metadata(path).ok().map(|m| Identity {
        dev: m.dev(),
        ino: m.ino(),
    })
}

/// The open descriptors of this process: `(fd, target identity, target is
/// a socket, target is a character device)`. Each entry's target is read
/// through the `/proc/self/fd/<n>` magic link (`stat`, no open).
/// An open descriptor: its number and its target's identity, mode and
/// `st_rdev` (when it could be read).
type Descriptor = (i32, Option<(Identity, u32, u64)>);

fn descriptors() -> Result<Vec<Descriptor>, Failure> {
    let dir = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| Failure::rule(Code::PathRefused, Rule::DescriptorBinding))?;
    let mut out = Vec::new();
    for entry in dir {
        let entry = entry.map_err(|_| Failure::rule(Code::PathRefused, Rule::DescriptorBinding))?;
        let name = entry.file_name();
        let Some(n) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let target = std::fs::metadata(entry.path()).ok().map(|m| {
            (
                Identity {
                    dev: m.dev(),
                    ino: m.ino(),
                },
                m.mode(),
                m.rdev(),
            )
        });
        out.push((n, target));
    }
    Ok(out)
}

/// The access mode of descriptor `fd` from `/proc/self/fdinfo/<fd>`:
/// `flags` in octal, `& O_ACCMODE`.
fn access_mode(fd: i32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    let flags = text.lines().find_map(|l| l.strip_prefix("flags:"))?.trim();
    let v = u32::from_str_radix(flags, 8).ok()?;
    Some(v & 0o3)
}

/// Step 6: right after `sqlite3_open_v2`, exactly two descriptors of the
/// process have the checked identity (the check descriptor and SQLite's),
/// and none of them is open for writing.
///
/// # Errors
/// [`Rule::DescriptorBinding`] / [`Rule::DescriptorWritable`].
pub fn bind_main(id: Identity, policy: Policy) -> Result<(), Failure> {
    let on_file: Vec<i32> = descriptors()?
        .into_iter()
        .filter(|(_, t)| t.is_some_and(|(i, _, _)| i == id))
        .map(|(n, _)| n)
        .collect();
    // In-process tests may hold the file open themselves (a writer
    // connection in the test process): at least the two.
    let count_ok = if policy.exact_descriptor_set {
        on_file.len() == 2
    } else {
        on_file.len() >= 2
    };
    if !count_ok {
        return Err(Failure::rule(Code::PathRefused, Rule::DescriptorBinding));
    }
    // Every descriptor on the file is read-only (a writer of the tests'
    // own process aside).
    if policy.exact_descriptor_set {
        for n in on_file {
            if access_mode(n) != Some(0) {
                return Err(Failure::rule(Code::PathRefused, Rule::DescriptorWritable));
            }
        }
    }
    Ok(())
}

/// Step 8: every descriptor is the IPC socket (descriptor 0), `/dev/null`
/// (1 and 2), the check descriptor, SQLite's descriptor on the database,
/// or a descriptor on a checked side file (a side file that appeared since
/// is checked first); every descriptor on the database or a side file is
/// `O_RDONLY`. Without [`Policy::exact_descriptor_set`] only the second
/// part is checked (in-process tests). Returns the side files, updated.
///
/// # Errors
/// [`Rule::DescriptorBinding`] / [`Rule::DescriptorWritable`], or a side
/// file rule.
pub fn bind_all(path: &Path, checked: &Checked, policy: Policy) -> Result<SideFiles, Failure> {
    let mut side = checked.side;
    let proc_fd = identity_of(Path::new("/proc/self/fd"));
    let null = std::fs::metadata("/dev/null").ok().map(|m| m.rdev());
    let mut rechecked = false;
    for (n, target) in descriptors()? {
        let Some((id, mode, rdev)) = target else {
            if policy.exact_descriptor_set {
                return Err(Failure::rule(Code::PathRefused, Rule::DescriptorBinding));
            }
            continue;
        };
        let on_db = id == checked.id;
        let mut on_side = side.all().any(|s| s.id == id);
        if !on_db && !on_side && !rechecked && id.dev == checked.id.dev {
            // A side file that appeared since the check.
            side = check_side_files(path, checked.owner, checked.id.dev, policy)?;
            rechecked = true;
            on_side = side.all().any(|s| s.id == id);
        }
        if on_db || on_side {
            if policy.exact_descriptor_set && access_mode(n) != Some(0) {
                return Err(Failure::rule(Code::PathRefused, Rule::DescriptorWritable));
            }
            continue;
        }
        if !policy.exact_descriptor_set {
            continue;
        }
        let kind = rustix::fs::FileType::from_raw_mode(mode);
        let known = (n == 0 && kind == rustix::fs::FileType::Socket)
            || ((n == 1 || n == 2)
                && kind == rustix::fs::FileType::CharacterDevice
                && Some(rdev) == null)
            || Some(id) == proc_fd;
        if !known {
            return Err(Failure::rule(Code::PathRefused, Rule::DescriptorBinding));
        }
    }
    let _ = checked.fd.as_raw_fd();
    Ok(side)
}

/// The declared path as bytes (it travels to the reader in the open
/// request, never anywhere else).
#[must_use]
pub fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_owned().into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writability_rules() {
        let me = Me {
            uid: 1000,
            gid: 1000,
            groups: vec![1000, 50],
        };
        let p = Path::new("/nonexistent-databastion/x");
        assert!(writable(p, 1000, 0, 0o400, &me), "owner");
        assert!(
            writable(p, 0, 50, 0o460, &me),
            "group write, one of its groups"
        );
        assert!(
            !writable(p, 0, 51, 0o460, &me),
            "group write, another group"
        );
        assert!(writable(p, 0, 0, 0o602, &me), "other write");
        assert!(!writable(p, 0, 50, 0o640, &me), "read only");
    }

    #[test]
    fn side_paths() {
        assert_eq!(
            side_path(Path::new("/srv/a.db"), "-wal"),
            PathBuf::from("/srv/a.db-wal")
        );
    }

    #[test]
    fn network_magics_are_distinct() {
        let mut v = NETWORK_FS_MAGIC.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), NETWORK_FS_MAGIC.len());
    }
}
