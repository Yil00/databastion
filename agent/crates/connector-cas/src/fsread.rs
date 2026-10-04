//! Local file access of the CAS connector (ADR-0041 decision 3, security
//! review L1 and M1). Blocking I/O: call from a blocking thread.
//!
//! - The registry directory is opened once with `O_DIRECTORY | O_NOFOLLOW`
//!   and listed **non-recursively**; each entry is opened relative to it
//!   with `openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
//!   O_CLOEXEC)` (a symlinked entry fails), and every check is made with
//!   `fstat` on the opened descriptor, never on the path: regular file,
//!   size, owner, mode, and `st_nlink` = 1 (a file with several hard links
//!   could be a link to the CAS configuration).
//! - A directory holding CAS configuration (`cas.properties`, `cas.yml`,
//!   `application.yml`, `application.properties`, compared
//!   case-insensitively) is refused as a whole; those files are never
//!   opened.
//! - Nothing the agent could write is read: a file or directory owned by
//!   the agent's effective uid, world-writable, or group-writable for one
//!   of its groups, or writable according to `faccessat(W_OK,
//!   AT_EACCESS)` (POSIX ACLs), and no ancestor directory of a declared
//!   path may be writable by the agent either.
//! - File names never leave this module's callers and are never logged.
//!
//! No `unsafe`: `rustix` wraps the system calls.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{Access, AtFlags, CWD, Mode, OFlags};
use zeroize::Zeroizing;

/// Most registry files read per scan.
pub const MAX_REGISTRY_FILES: usize = 4096;
/// Largest registry file read, in bytes.
pub const MAX_REGISTRY_FILE_BYTES: u64 = 1024 * 1024;
/// CAS configuration file names: their presence refuses the directory.
const CONFIG_FILE_NAMES: [&str; 5] = [
    "cas.properties",
    "cas.yml",
    "application.yml",
    "application.properties",
    "thekeystore",
];
/// Configuration name stems (`<stem>.<ext>` and `<stem>-<profile>.<ext>`)
/// and their extensions (review of #138 I1).
const CONFIG_STEMS: [(&str, &[&str]); 3] = [
    ("application", &["yml", "yaml", "properties"]),
    ("bootstrap", &["yml", "yaml", "properties"]),
    ("cas", &["yml", "yaml", "properties"]),
];
/// Extensions of key material: their presence refuses the directory.
const KEY_EXTENSIONS: [&str; 9] = [
    "jwks", "jks", "p12", "pem", "key", "pfx", "jceks", "keystore", "bcfks",
];

/// Why a declared source is not read (kinds only, never a path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Missing, not the right kind of file, or not readable.
    NotReadable,
    /// The agent's account could write it (or an ancestor directory).
    Writable,
    /// The registry directory holds CAS configuration files.
    ConfigFiles,
    /// The declared path no longer resolves where it did at load.
    ResolvedChanged,
}

/// Why one registry file was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSkip {
    /// Cannot be opened (a symlink, removed meanwhile, no permission), or
    /// not a regular file.
    NotReadable,
    /// The agent's account could write it.
    Writable,
    /// More than one hard link.
    HardLinked,
    /// Larger than [`MAX_REGISTRY_FILE_BYTES`].
    TooLarge,
}

/// How strict the writability checks are. Only the tests of this crate
/// relax them (every file a test creates is its own, and the tests may run
/// as root, which can write anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) refuse_agent_writable: bool,
}

impl Policy {
    pub(crate) const STRICT: Self = Self {
        refuse_agent_writable: true,
    };

    #[cfg(test)]
    pub(crate) const TESTS: Self = Self {
        refuse_agent_writable: false,
    };
}

/// Ownership and mode facts of a file, for [`writable_by`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
}

/// The agent's identity, for [`writable_by`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Me {
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    /// Supplementary groups (`None`: unknown, every group assumed).
    pub(crate) groups: Option<Vec<u32>>,
}

impl Me {
    pub(crate) fn current() -> Self {
        Self {
            euid: rustix::process::geteuid().as_raw(),
            egid: rustix::process::getegid().as_raw(),
            groups: rustix::process::getgroups()
                .ok()
                .map(|g| g.iter().map(|g| g.as_raw()).collect()),
        }
    }
}

/// Whether the mode bits let the agent write: owned by its effective uid,
/// world-writable, or group-writable for one of its groups (an unknown
/// group list counts as a match: fail closed). Root (`euid` 0) can write
/// anything.
pub(crate) fn writable_by(o: Owner, me: &Me) -> bool {
    if me.euid == 0 || o.uid == me.euid || o.mode & 0o002 != 0 {
        return true;
    }
    o.mode & 0o020 != 0
        && (o.gid == me.egid
            || me
                .groups
                .as_ref()
                .is_none_or(|groups| groups.contains(&o.gid)))
}

fn owner(meta: &std::fs::Metadata) -> Owner {
    Owner {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    }
}

/// Whether `faccessat(dirfd, name, W_OK, AT_EACCESS)` grants write access
/// (ACLs included). An error other than `EACCES` / `EROFS` counts as
/// writable (fail closed).
fn access_writable<Fd: AsFd>(dirfd: Fd, name: &CStr) -> bool {
    match rustix::fs::accessat(dirfd, name, Access::WRITE_OK, AtFlags::EACCESS) {
        Ok(()) => true,
        Err(e) => e != rustix::io::Errno::ACCESS && e != rustix::io::Errno::ROFS,
    }
}

/// Whether an ancestor directory of `path` (not `path` itself) is
/// writable by the agent.
fn ancestor_writable(path: &Path, me: &Me) -> bool {
    path.ancestors().skip(1).any(|dir| {
        let Ok(meta) = std::fs::metadata(dir) else {
            return true;
        };
        let Ok(c) = CString::new(dir.as_os_str().as_encoded_bytes()) else {
            return true;
        };
        writable_by(owner(&meta), me) || access_writable(CWD, &c)
    })
}

/// An opened registry directory and the service definition files it lists.
pub(crate) struct Listing {
    dir: OwnedFd,
    /// Device of the directory: an entry on another device (a mount point
    /// in the directory) is skipped (review of #138 I2).
    dev: u64,
    /// Names of the `.json` entries, in directory order, at most
    /// [`MAX_REGISTRY_FILES`].
    pub(crate) files: Vec<CString>,
    /// `.json` entries beyond [`MAX_REGISTRY_FILES`].
    pub(crate) over_cap: u64,
}

impl std::fmt::Debug for Listing {
    // File names are never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listing")
            .field("files", &self.files.len())
            .field("over_cap", &self.over_cap)
            .finish_non_exhaustive()
    }
}

/// Whether an entry name is CAS configuration or key material (compared
/// case-insensitively): `cas.properties`, `cas.yml`, `application.yml`,
/// `application.properties`, `application[-*].{yml,yaml,properties}`,
/// `cas[-*].{yml,yaml,properties}`, `bootstrap[-*].{yml,yaml,properties}`,
/// `thekeystore`, `*.jwks`, `*.jks`, `*.p12`, `*.pem`, `*.key`, `*.pfx`,
/// `*.jceks`, `*.keystore`, `*.bcfks`.
fn is_config_name(name: &[u8]) -> bool {
    if CONFIG_FILE_NAMES
        .iter()
        .any(|c| c.as_bytes().eq_ignore_ascii_case(name))
    {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    let Some(dot) = lower.iter().rposition(|b| *b == b'.') else {
        return false;
    };
    let (base, ext) = lower.split_at(dot);
    let ext = ext.get(1..).unwrap_or(&[]);
    if KEY_EXTENSIONS.iter().any(|k| k.as_bytes() == ext) {
        return true;
    }
    CONFIG_STEMS.iter().any(|(stem, exts)| {
        exts.iter().any(|e| e.as_bytes() == ext)
            && (base == stem.as_bytes()
                || base
                    .strip_prefix(stem.as_bytes())
                    .is_some_and(|r| r.first() == Some(&b'-')))
    })
}

fn has_json_extension(name: &[u8]) -> bool {
    name.len() > 5
        && name
            .rsplit(|b| *b == b'.')
            .next()
            .is_some_and(|ext| ext.eq_ignore_ascii_case(b"json"))
}

/// Opens and lists the registry directory at `path` (see the module
/// documentation).
pub(crate) fn list_registry(path: &Path, policy: Policy) -> Result<Listing, Refusal> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Refusal::NotReadable)?;
    let meta = File::from(fd.try_clone().map_err(|_| Refusal::NotReadable)?)
        .metadata()
        .map_err(|_| Refusal::NotReadable)?;
    if !meta.file_type().is_dir() {
        return Err(Refusal::NotReadable);
    }
    if policy.refuse_agent_writable {
        let me = Me::current();
        if writable_by(owner(&meta), &me)
            || access_writable(&fd, c".")
            || ancestor_writable(path, &me)
        {
            return Err(Refusal::Writable);
        }
    }
    let dir = rustix::fs::Dir::read_from(&fd).map_err(|_| Refusal::NotReadable)?;
    let mut files = Vec::new();
    let mut over_cap = 0u64;
    let mut config = false;
    for entry in dir {
        let Ok(entry) = entry else {
            return Err(Refusal::NotReadable);
        };
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if is_config_name(name) {
            config = true;
            // Keep listing: nothing of the directory is read anyway.
            continue;
        }
        if !has_json_extension(name) {
            continue;
        }
        if files.len() < MAX_REGISTRY_FILES {
            files.push(entry.file_name().to_owned());
        } else {
            over_cap = over_cap.saturating_add(1);
        }
    }
    if config {
        return Err(Refusal::ConfigFiles);
    }
    Ok(Listing {
        dir: fd,
        dev: meta.dev(),
        files,
        over_cap,
    })
}

impl Listing {
    /// Reads one listed file into a zeroizing buffer (see the module
    /// documentation for the checks).
    pub(crate) fn read(&self, name: &CStr, policy: Policy) -> Result<Zeroizing<Vec<u8>>, FileSkip> {
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|_| FileSkip::NotReadable)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(|_| FileSkip::NotReadable)?;
        if !meta.file_type().is_file() {
            return Err(FileSkip::NotReadable);
        }
        if meta.dev() != self.dev {
            return Err(FileSkip::NotReadable);
        }
        if meta.nlink() != 1 {
            return Err(FileSkip::HardLinked);
        }
        if policy.refuse_agent_writable
            && (writable_by(owner(&meta), &Me::current()) || access_writable(&self.dir, name))
        {
            return Err(FileSkip::Writable);
        }
        if meta.len() > MAX_REGISTRY_FILE_BYTES {
            return Err(FileSkip::TooLarge);
        }
        read_bounded(file, MAX_REGISTRY_FILE_BYTES).ok_or(FileSkip::TooLarge)
    }
}

/// Reads at most `max` bytes into a buffer allocated once (no
/// reallocation leaves unzeroized copies); `None` when the file holds more
/// (it grew meanwhile) or a read fails.
fn read_bounded(file: File, max: u64) -> Option<Zeroizing<Vec<u8>>> {
    let cap = usize::try_from(max).ok()?.checked_add(1)?;
    let mut out = Zeroizing::new(Vec::with_capacity(cap));
    let n = file.take(max + 1).read_to_end(&mut out).ok()?;
    (u64::try_from(n).ok()? <= max).then_some(out)
}

/// The last bytes of a log file.
pub(crate) struct Tail {
    /// At most the requested bytes, from a line start when the read began
    /// mid-file (the partial first line is dropped).
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}

/// Opens the audit log at `path` (resolved at load: the final component is
/// not followed) with the checks of the module documentation.
fn open_log(path: &Path, policy: Policy) -> Result<(File, u64), Refusal> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|_| Refusal::NotReadable)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| Refusal::NotReadable)?;
    if !meta.file_type().is_file() {
        return Err(Refusal::NotReadable);
    }
    if policy.refuse_agent_writable {
        let me = Me::current();
        let name =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Refusal::NotReadable)?;
        if writable_by(owner(&meta), &me)
            || access_writable(CWD, &name)
            || ancestor_writable(path, &me)
        {
            return Err(Refusal::Writable);
        }
    }
    Ok((file, meta.len()))
}

/// Reads the last `max` bytes of the audit log at `path` (see
/// [`open_log`]). A partial first line is dropped.
pub(crate) fn read_log_tail(path: &Path, max: u64, policy: Policy) -> Result<Tail, Refusal> {
    let (mut file, len) = open_log(path, policy)?;
    let start = len.saturating_sub(max);
    file.seek(SeekFrom::Start(start))
        .map_err(|_| Refusal::NotReadable)?;
    // The file may have grown since `fstat`: at most `max` bytes are kept.
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(max.min(len)).map_err(|_| Refusal::NotReadable)?,
    ));
    file.take(max.min(len))
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::NotReadable)?;
    if start > 0 {
        // Drop the partial first line (it may also be the end of a record
        // the read started in).
        match bytes.iter().position(|b| *b == b'\n') {
            Some(i) => {
                bytes.drain(..=i);
            }
            None => bytes.clear(),
        }
    }
    Ok(Tail { bytes })
}

/// Checks the audit log before the core tailer opens it: regular file not
/// writable by the agent, no writable ancestor. The tailer repeats the
/// owner and mode checks on its own handle.
pub(crate) fn check_log(path: &Path, policy: Policy) -> Result<(), Refusal> {
    open_log(path, policy).map(|_| ())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct TempDir(std::path::PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "databastion-cas-fs-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
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

    fn me(euid: u32, egid: u32, groups: Option<Vec<u32>>) -> Me {
        Me { euid, egid, groups }
    }

    #[test]
    fn writability_from_mode_bits() {
        let o = |uid, gid, mode| Owner { uid, gid, mode };
        let agent = me(1000, 1000, Some(vec![1000, 50]));
        assert!(writable_by(o(1000, 0, 0o400), &agent), "owned by the agent");
        assert!(writable_by(o(0, 0, 0o602), &agent), "world-writable");
        assert!(writable_by(o(0, 50, 0o660), &agent), "group of the agent");
        assert!(writable_by(o(0, 1000, 0o660), &agent), "primary group");
        assert!(!writable_by(o(0, 51, 0o660), &agent), "another group");
        assert!(!writable_by(o(0, 50, 0o640), &agent), "group read-only");
        assert!(
            writable_by(o(0, 51, 0o660), &me(1000, 1000, None)),
            "unknown groups: fail closed"
        );
        assert!(writable_by(o(5, 5, 0o400), &me(0, 0, None)), "root");
    }

    #[test]
    fn the_strict_policy_refuses_what_the_agent_owns() {
        // Every file a test creates is its own (or root's).
        let dir = TempDir::new("strict");
        let reg = dir.path().join("services");
        std::fs::create_dir(&reg).unwrap();
        std::fs::write(reg.join("App-1.json"), b"{}").unwrap();
        assert_eq!(
            list_registry(&reg, Policy::STRICT).unwrap_err(),
            Refusal::Writable
        );
        let log = dir.path().join("cas_audit.log");
        std::fs::write(&log, b"{}\n").unwrap();
        assert_eq!(check_log(&log, Policy::STRICT), Err(Refusal::Writable));
    }

    #[test]
    fn listing_is_flat_and_json_only() {
        let dir = TempDir::new("list");
        let reg = dir.path();
        std::fs::write(reg.join("App-1.json"), b"{}").unwrap();
        std::fs::write(reg.join("Other-2.JSON"), b"{}").unwrap();
        std::fs::write(reg.join("README.md"), b"x").unwrap();
        std::fs::write(reg.join(".json"), b"x").unwrap();
        std::fs::create_dir(reg.join("nested.json")).unwrap();
        std::fs::write(reg.join("nested.json/Inner-3.json"), b"{}").unwrap();
        let l = list_registry(reg, Policy::TESTS).unwrap();
        let mut names: Vec<_> = l
            .files
            .iter()
            .map(|n| n.to_str().unwrap().to_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["App-1.json", "Other-2.JSON", "nested.json"]);
        assert_eq!(l.over_cap, 0);
        // The nested directory is listed by name but never read as a file.
        assert_eq!(
            l.read(c"nested.json", Policy::TESTS).unwrap_err(),
            FileSkip::NotReadable
        );
        assert_eq!(&*l.read(c"App-1.json", Policy::TESTS).unwrap(), b"{}");
    }

    #[test]
    fn configuration_files_refuse_the_directory() {
        for name in [
            "cas.properties",
            "CAS.yml",
            "application.YML",
            "Application.properties",
        ] {
            let dir = TempDir::new("config");
            std::fs::write(dir.path().join("App-1.json"), b"{}").unwrap();
            std::fs::write(dir.path().join(name), b"cas.secret=hunter2-SECRET").unwrap();
            assert_eq!(
                list_registry(dir.path(), Policy::TESTS).unwrap_err(),
                Refusal::ConfigFiles,
                "{name}"
            );
        }
    }

    #[test]
    fn other_names_are_not_configuration() {
        for name in [
            "application.json",
            "casino.yml",
            "cas_audit.log",
            "App-1.json",
            "key",
            "applications.yml",
        ] {
            assert!(!is_config_name(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn symlinks_hard_links_and_large_files_are_skipped() {
        let dir = TempDir::new("links");
        let outside = TempDir::new("outside");
        let secret = outside.path().join("cas.properties");
        std::fs::write(&secret, b"cas.secret=hunter2-SECRET").unwrap();
        let reg = dir.path();
        std::os::unix::fs::symlink(&secret, reg.join("Sym-1.json")).unwrap();
        std::fs::hard_link(&secret, reg.join("Hard-2.json")).unwrap();
        let big = vec![b' '; usize::try_from(MAX_REGISTRY_FILE_BYTES).unwrap() + 1];
        std::fs::write(reg.join("Big-3.json"), big).unwrap();
        let l = list_registry(reg, Policy::TESTS).unwrap();
        assert_eq!(
            l.read(c"Sym-1.json", Policy::TESTS).unwrap_err(),
            FileSkip::NotReadable
        );
        assert_eq!(
            l.read(c"Hard-2.json", Policy::TESTS).unwrap_err(),
            FileSkip::HardLinked
        );
        assert_eq!(
            l.read(c"Big-3.json", Policy::TESTS).unwrap_err(),
            FileSkip::TooLarge
        );
        // A symlinked directory is refused too (O_NOFOLLOW).
        let link = outside.path().join("link");
        std::os::unix::fs::symlink(reg, &link).unwrap();
        assert_eq!(
            list_registry(&link, Policy::TESTS).unwrap_err(),
            Refusal::NotReadable
        );
        // A FIFO never blocks the open and is not read.
        let st = std::process::Command::new("mkfifo")
            .arg(reg.join("Fifo-4.json"))
            .status();
        if st.is_ok_and(|s| s.success()) {
            assert_eq!(
                l.read(c"Fifo-4.json", Policy::TESTS).unwrap_err(),
                FileSkip::NotReadable
            );
        }
    }

    #[test]
    fn the_file_cap_is_counted() {
        let dir = TempDir::new("cap");
        for i in 0..(MAX_REGISTRY_FILES + 3) {
            std::fs::write(dir.path().join(format!("S-{i}.json")), b"{}").unwrap();
        }
        let l = list_registry(dir.path(), Policy::TESTS).unwrap();
        assert_eq!(l.files.len(), MAX_REGISTRY_FILES);
        assert_eq!(l.over_cap, 3);
    }

    #[test]
    fn log_tails_start_at_a_line() {
        let dir = TempDir::new("tail");
        let log = dir.path().join("cas_audit.log");
        std::fs::write(&log, b"first line\nsecond\nthird\n").unwrap();
        let t = read_log_tail(&log, 1024, Policy::TESTS).unwrap();
        assert_eq!(&*t.bytes, b"first line\nsecond\nthird\n");
        let t = read_log_tail(&log, 10, Policy::TESTS).unwrap();
        assert_eq!(&*t.bytes, b"third\n");
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads anyway; another user gets NotReadable.
        let _ = read_log_tail(&log, 10, Policy::TESTS);
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&log, &link).unwrap();
        assert_eq!(
            read_log_tail(&link, 10, Policy::TESTS).err(),
            Some(Refusal::NotReadable)
        );
        assert_eq!(
            read_log_tail(dir.path(), 10, Policy::TESTS).err(),
            Some(Refusal::NotReadable)
        );
    }
}
