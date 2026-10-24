//! The reader process's sandbox (ADR-0059 decision 4, security review H1,
//! and the implementation review of 2026-10-24, M1 to M3, L2 and L4).
//!
//! 1. [`early`], first thing in reader mode: `PR_SET_NO_NEW_PRIVS`,
//!    `PR_SET_DUMPABLE` = 0, the resource limits `RLIMIT_AS` (512 MiB),
//!    `RLIMIT_CPU` (60 s), `RLIMIT_NOFILE` (16), `RLIMIT_FSIZE` (0),
//!    `RLIMIT_CORE` (0), and no descriptor but 0, 1 and 2.
//! 2. [`restrict`], once the open request is read and the path checked by
//!    `files::check_ancestors` (decision 2, path based):
//!    - the declared file's directory, the file and its side files present
//!      now are opened `O_PATH` with `openat2(RESOLVE_NO_SYMLINKS |
//!      RESOLVE_NO_MAGICLINKS)`, so no symbolic link is followed while the
//!      grant is built (review M1);
//!    - a Landlock ruleset handling every file system right (ABI 1 required,
//!      later rights and the TCP rules best effort) grants, on those
//!      descriptors only, `ReadDir` on the directory and `ReadFile` on the
//!      files, and read access to the reader's own `/proc/self/fd` and
//!      `/proc/self/fdinfo`; no `Execute`, no write right anywhere (L4);
//!      signals and abstract Unix sockets are scoped on ABI 6 and later
//!      (best effort);
//!    - after `restrict_self`, each descriptor's `(st_dev, st_ino)` must be
//!      what an `lstat` of its declared path gives now, or the grant is
//!      refused;
//!    - then a seccomp **allow-list** ([`filter`]): every other system call
//!      returns `EPERM`, x32 numbers first (M2); `openat` / `open` only
//!      without a write flag, `O_CREAT` or `O_TRUNC`; `mmap` / `mprotect`
//!      never executable; `fcntl` only for record locks and descriptor
//!      flags; `tgkill` only on the reader itself (M3).
//!
//!    Without Landlock, or when the ruleset is not enforced, the reader
//!    refuses to open anything ([`Code::SandboxUnavailable`]).
//!
//! The `unsafe` code is inside `rustix`, `landlock` and `seccompiler`.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
use rustix::process::{Resource, Rlimit};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, sock_filter,
};

use crate::ipc::{Code, Failure, Rule};

/// `RLIMIT_AS` of a reader.
pub const ADDRESS_SPACE: u64 = 512 * 1024 * 1024;
/// `RLIMIT_CPU` of a reader, in seconds.
pub const CPU_SECONDS: u64 = 60;
/// `RLIMIT_NOFILE` of a reader.
pub const OPEN_FILES: u64 = 16;
/// The side files a grant covers when they exist at open.
pub const SIDE_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

fn unavailable<E>(_: E) -> Failure {
    Failure::new(Code::SandboxUnavailable)
}

fn limit(resource: Resource, value: u64) -> Result<(), Failure> {
    rustix::process::setrlimit(
        resource,
        Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .map_err(unavailable)
}

/// Step 3 of the reader (decision 4): no new privileges, not dumpable, the
/// resource limits, and only descriptors 0, 1 and 2 inherited.
///
/// # Errors
/// [`Code::SandboxUnavailable`].
pub fn early() -> Result<(), Failure> {
    rustix::thread::set_no_new_privs(true).map_err(unavailable)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(unavailable)?;
    limit(Resource::Core, 0)?;
    limit(Resource::Fsize, 0)?;
    limit(Resource::Nofile, OPEN_FILES)?;
    limit(Resource::Cpu, CPU_SECONDS)?;
    limit(Resource::As, ADDRESS_SPACE)?;
    only_standard_descriptors()
}

/// Defence in depth: the reader inherits nothing but its IPC channel and
/// `/dev/null` (everything the agent opens is `O_CLOEXEC`).
fn only_standard_descriptors() -> Result<(), Failure> {
    let listing = std::fs::metadata("/proc/self/fd").map_err(unavailable)?;
    for entry in std::fs::read_dir("/proc/self/fd").map_err(unavailable)? {
        let entry = entry.map_err(unavailable)?;
        let Some(n) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            return Err(Failure::new(Code::SandboxUnavailable));
        };
        if (0..=2).contains(&n) {
            continue;
        }
        // The listing's own descriptor.
        let target = std::fs::metadata(entry.path()).map_err(unavailable)?;
        if (target.dev(), target.ino()) != (listing.dev(), listing.ino()) {
            return Err(Failure::new(Code::SandboxUnavailable));
        }
    }
    Ok(())
}

/// An `O_PATH` descriptor of `path`, no symbolic link followed anywhere in
/// it (`openat2`, review M1).
fn open_path(path: &Path, directory: bool) -> Result<OwnedFd, rustix::io::Errno> {
    let kind = if directory {
        OFlags::DIRECTORY
    } else {
        OFlags::NOFOLLOW
    };
    rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC | kind,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

fn grant_failure(e: rustix::io::Errno) -> Failure {
    match e {
        rustix::io::Errno::NOENT => Failure::new(Code::NotFound),
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => Failure::new(Code::NotReadable),
        rustix::io::Errno::LOOP | rustix::io::Errno::XDEV => {
            Failure::rule(Code::PathRefused, Rule::SymlinkComponent)
        }
        rustix::io::Errno::NOTDIR => Failure::rule(Code::PathRefused, Rule::NotDirectory),
        _ => Failure::new(Code::SandboxUnavailable),
    }
}

/// What the grant covers: the directory, the file and its side files
/// present now, each with the path it was opened at.
#[derive(Debug)]
pub struct Grant {
    dir: (OwnedFd, PathBuf),
    files: Vec<(OwnedFd, PathBuf)>,
}

impl Grant {
    /// Opens the descriptors of the grant (`openat2`, no symlink).
    ///
    /// # Errors
    /// The rule broken, [`Code::NotFound`], or [`Code::SandboxUnavailable`].
    pub fn open(database: &Path) -> Result<Self, Failure> {
        let parent = database
            .parent()
            .ok_or_else(|| Failure::rule(Code::PathRefused, Rule::NotCanonical))?;
        let dir = (
            open_path(parent, true).map_err(grant_failure)?,
            parent.to_owned(),
        );
        let mut files = vec![(
            open_path(database, false).map_err(grant_failure)?,
            database.to_owned(),
        )];
        for suffix in SIDE_SUFFIXES {
            let side = crate::files::side_path(database, suffix);
            match open_path(&side, false) {
                Ok(fd) => files.push((fd, side)),
                Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(grant_failure(e)),
            }
        }
        Ok(Self { dir, files })
    }

    /// Each descriptor is still what its declared path names (`lstat`): the
    /// directory a directory, the files regular files.
    ///
    /// # Errors
    /// [`Rule::DescriptorBinding`].
    pub fn verify(&self) -> Result<(), Failure> {
        let same = |fd: &OwnedFd, path: &Path, dir: bool| -> bool {
            let (Ok(st), Ok(m)) = (
                rustix::fs::fstat(fd.as_fd()),
                std::fs::symlink_metadata(path),
            ) else {
                return false;
            };
            let kind_ok = if dir { m.is_dir() } else { m.is_file() };
            kind_ok && (st.st_dev, st.st_ino) == (m.dev(), m.ino())
        };
        let ok = same(&self.dir.0, &self.dir.1, true)
            && self.files.iter().all(|(fd, p)| same(fd, p, false));
        if ok {
            Ok(())
        } else {
            Err(Failure::rule(Code::PathRefused, Rule::DescriptorBinding))
        }
    }

    /// The side files the grant covers, with their identity (the
    /// descriptor's, equal to the path's after [`Self::verify`]).
    #[must_use]
    pub fn side_files(&self) -> Vec<(PathBuf, crate::files::Identity)> {
        self.files
            .iter()
            .skip(1)
            .filter_map(|(fd, p)| {
                let st = rustix::fs::fstat(fd.as_fd()).ok()?;
                Some((
                    p.clone(),
                    crate::files::Identity {
                        dev: st.st_dev,
                        ino: st.st_ino,
                    },
                ))
            })
            .collect()
    }
}

/// Steps 4 and 5 of the reader: the grant (opened without following any
/// symlink), Landlock, the grant verified, then seccomp. The `O_PATH`
/// descriptors are closed before seccomp (Landlock keeps its own
/// references), so the descriptor bindings of decision 2 stay exact.
/// Returns the side files the grant covers: one that appears later cannot
/// be read (`Code::FileChanged`).
///
/// # Errors
/// [`Code::SandboxUnavailable`], or the rule the path breaks.
pub fn restrict(database: &Path) -> Result<Vec<(PathBuf, crate::files::Identity)>, Failure> {
    let grant = Grant::open(database)?;
    landlock(&grant)?;
    grant.verify()?;
    let sides = grant.side_files();
    drop(grant);
    seccomp()?;
    Ok(sides)
}

fn landlock(grant: &Grant) -> Result<(), Failure> {
    let latest = ABI::V6;
    let mut created = Ruleset::default()
        // ABI 1 is required: every file system right of the first ABI
        // (read, write, create, remove, execute) is handled, or nothing is
        // opened.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(unavailable)?
        // Later rights (refer, truncate, device ioctl), the TCP rules and
        // the scopes, where the kernel has them.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(latest))
        .map_err(unavailable)?
        .handle_access(AccessNet::from_all(latest))
        .map_err(unavailable)?
        .scope(Scope::from_all(latest))
        .map_err(unavailable)?
        .create()
        .map_err(unavailable)?
        .set_compatibility(CompatLevel::HardRequirement)
        .add_rule(PathBeneath::new(grant.dir.0.as_fd(), AccessFs::ReadDir))
        .map_err(unavailable)?;
    for (fd, _) in &grant.files {
        created = created
            .add_rule(PathBeneath::new(fd.as_fd(), AccessFs::ReadFile))
            .map_err(unavailable)?;
    }
    let proc_fd = PathFd::new("/proc/self/fd").map_err(unavailable)?;
    let proc_fdinfo = PathFd::new("/proc/self/fdinfo").map_err(unavailable)?;
    let status = created
        .add_rule(PathBeneath::new(proc_fd, AccessFs::ReadDir))
        .map_err(unavailable)?
        .add_rule(PathBeneath::new(
            proc_fdinfo,
            AccessFs::ReadDir | AccessFs::ReadFile,
        ))
        .map_err(unavailable)?
        .restrict_self()
        .map_err(unavailable)?;
    if status.ruleset == RulesetStatus::NotEnforced || !status.no_new_privs {
        return Err(Failure::new(Code::SandboxUnavailable));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

/// The system calls the reader may make whatever their arguments, each
/// measured (strace of the reader under the integration tests) or needed
/// by the Rust runtime and glibc on an error path:
///
/// | Call | Why |
/// |---|---|
/// | `read`, `write` | the IPC channel (descriptor 0), `/proc/self/fdinfo` (measured) |
/// | `pread64` | SQLite's page reads, the header pre-check (measured) |
/// | `close` | the checks' descriptors, SQLite's on close (measured) |
/// | `fstat`, `newfstatat`, `statx` | the file rules, Rust `std::fs::metadata` (measured) |
/// | `fstatfs` | the network file system rule (measured) |
/// | `lseek` | SQLite's VFS (not measured) |
/// | `getdents64` | `/proc/self/fd`, the descriptor bindings (measured) |
/// | `readlinkat` | SQLite's `unixFullPathname` (not measured) |
/// | `faccessat`, `faccessat2` | the writability rule, SQLite's `access` (measured) |
/// | `getpid` | SQLite (measured) |
/// | `gettid` | `abort` on a panic, with `tgkill` |
/// | `geteuid`, `getegid`, `getgroups` | the writability rule (measured) |
/// | `munmap`, `mremap`, `madvise`, `brk` | the allocator, the `-shm` mapping (`munmap`, `brk` measured) |
/// | `futex` | glibc locks |
/// | `getrandom` | Rust std |
/// | `clock_gettime`, `clock_nanosleep`, `nanosleep` | SQLite's busy handler (vDSO fallback) |
/// | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack` | the Rust runtime's handlers, `abort` |
/// | `exit`, `exit_group` | exit (`exit_group` measured) |
fn always_allowed() -> Vec<i64> {
    vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fstatfs,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
}

type Rules = Vec<SeccompRule>;

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, Failure> {
    SeccompRule::new(conditions).map_err(unavailable)
}

fn masked(index: u8, mask: u64, value: u64) -> Result<SeccompCondition, Failure> {
    SeccompCondition::new(
        index,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(mask),
        value,
    )
    .map_err(unavailable)
}

fn equal(index: u8, value: u64) -> Result<SeccompCondition, Failure> {
    SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
        .map_err(unavailable)
}

fn bits(v: i32) -> u64 {
    u64::from(v.cast_unsigned())
}

/// `open` flags (argument `index`) without a write access mode, `O_CREAT`
/// or `O_TRUNC`.
fn read_only_open(index: u8) -> Result<Rules, Failure> {
    let mask = bits(libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC);
    Ok(vec![rule(vec![masked(index, mask, 0)?])?])
}

/// The filter: an allow-list, `EPERM` for everything else (M2, M3).
///
/// # Errors
/// [`Code::SandboxUnavailable`] if it cannot be built.
pub fn filter() -> Result<BpfProgram, Failure> {
    let mut rules: BTreeMap<i64, Rules> = always_allowed()
        .into_iter()
        .map(|c| (c, Vec::new()))
        .collect();
    rules.insert(libc::SYS_openat, read_only_open(2)?);
    #[cfg(target_arch = "x86_64")]
    rules.insert(libc::SYS_open, read_only_open(1)?);
    // Never an executable mapping (W^X, as MemoryDenyWriteExecute).
    let no_exec = |index: u8| -> Result<Rules, Failure> {
        Ok(vec![rule(vec![masked(index, bits(libc::PROT_EXEC), 0)?])?])
    };
    rules.insert(libc::SYS_mmap, no_exec(2)?);
    rules.insert(libc::SYS_mprotect, no_exec(2)?);
    // fcntl: SQLite's record locks (F_GETLK, F_SETLK; never F_SETLKW, so a
    // reader cannot wait on the application) and descriptor flags.
    let mut fcntl = Vec::new();
    for cmd in [
        libc::F_GETLK,
        libc::F_SETLK,
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
    ] {
        fcntl.push(rule(vec![equal(1, bits(cmd))?])?);
    }
    rules.insert(libc::SYS_fcntl, fcntl);
    // tgkill only on the reader itself (abort on a panic).
    let pid = u64::from(
        rustix::process::getpid()
            .as_raw_nonzero()
            .get()
            .cast_unsigned(),
    );
    rules.insert(libc::SYS_tgkill, vec![rule(vec![equal(0, pid)?])?]);
    let eperm = u32::try_from(libc::EPERM).unwrap_or(1);
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Errno(eperm),
        SeccompAction::Allow,
        ARCH,
    )
    .map_err(unavailable)?;
    let program = BpfProgram::try_from(f).map_err(unavailable)?;
    Ok(with_x32_refused(program, eperm))
}

/// `BPF_LD | BPF_W | BPF_ABS`.
const BPF_LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JGE | BPF_K`.
const BPF_JMP_JGE_K: u16 = 0x35;
/// `BPF_RET | BPF_K`.
const BPF_RET_K: u16 = 0x06;

/// The first rule (M2): on x86_64, a system call number with the x32 bit
/// (`nr >= 0x4000_0000`) returns `EPERM` before anything else; seccompiler
/// only checks `AUDIT_ARCH_X86_64`, which x32 calls share. Prepended to
/// seccompiler's program (its jumps are relative).
fn with_x32_refused(program: BpfProgram, eperm: u32) -> BpfProgram {
    if cfg!(not(target_arch = "x86_64")) {
        return program;
    }
    let mut out = vec![
        sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: BPF_JMP_JGE_K,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        },
        sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | eperm,
        },
    ];
    out.extend(program);
    out
}

fn seccomp() -> Result<(), Failure> {
    let program = filter()?;
    seccompiler::apply_filter(&program).map_err(unavailable)
}

/// Whether this kernel enforces Landlock (any ABI), for the agent's notes
/// and the tests. Opens nothing.
#[must_use]
pub fn landlock_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(Ruleset::create)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small classic-BPF interpreter for the opcodes seccompiler and
    /// [`with_x32_refused`] emit, over a `seccomp_data`.
    fn run(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let mut data = Vec::new();
        data.extend_from_slice(&nr.to_le_bytes());
        data.extend_from_slice(&arch.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        for a in args {
            data.extend_from_slice(&a.to_le_bytes());
        }
        let (mut acc, mut pc) = (0u32, 0usize);
        loop {
            let i = &program[pc];
            match i.code & 0x07 {
                0x00 => {
                    let k = i.k as usize;
                    acc = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                    pc += 1;
                }
                0x04 => {
                    assert_eq!(i.code & 0xf0, 0x50, "only AND");
                    acc &= i.k;
                    pc += 1;
                }
                0x05 => {
                    let taken = match i.code & 0xf0 {
                        0x00 => {
                            pc += 1 + i.k as usize;
                            continue;
                        }
                        0x10 => acc == i.k,
                        0x20 => acc > i.k,
                        0x30 => acc >= i.k,
                        0x40 => acc & i.k != 0,
                        op => panic!("jump {op:#x}"),
                    };
                    pc += 1 + usize::from(if taken { i.jt } else { i.jf });
                }
                0x06 => return i.k,
                class => panic!("class {class:#x}"),
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    const ALLOW: u32 = 0x7fff_0000;
    const EPERM: u32 = 0x0005_0000 | 1;

    fn nr(n: i64) -> u32 {
        u32::try_from(n).unwrap()
    }

    fn arg(i: usize, v: i32) -> [u64; 6] {
        let mut a = [0u64; 6];
        a[i] = u64::from(v.cast_unsigned());
        a
    }

    #[test]
    fn the_allow_list_refuses_everything_else() {
        let p = filter().unwrap();
        let none = [0u64; 6];
        assert_eq!(run(&p, nr(libc::SYS_read), AUDIT_ARCH, none), ALLOW);
        assert_eq!(run(&p, nr(libc::SYS_pread64), AUDIT_ARCH, none), ALLOW);
        for denied in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_kill,
            libc::SYS_prlimit64,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_keyctl,
            libc::SYS_fanotify_init,
            libc::SYS_flock,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_ptrace,
            libc::SYS_unlinkat,
            libc::SYS_ftruncate,
            libc::SYS_pwrite64,
            libc::SYS_openat2,
            libc::SYS_getppid,
            libc::SYS_setrlimit,
            libc::SYS_ioctl,
        ] {
            assert_eq!(run(&p, nr(denied), AUDIT_ARCH, none), EPERM, "{denied}");
        }
        // openat: read-only only.
        let ro = arg(2, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
        assert_eq!(run(&p, nr(libc::SYS_openat), AUDIT_ARCH, ro), ALLOW);
        for flags in [libc::O_RDWR, libc::O_WRONLY, libc::O_CREAT, libc::O_TRUNC] {
            assert_eq!(
                run(&p, nr(libc::SYS_openat), AUDIT_ARCH, arg(2, flags)),
                EPERM,
                "{flags}"
            );
        }
        // No executable mapping; fcntl locks but not F_SETLKW.
        let exec = arg(2, libc::PROT_EXEC | libc::PROT_READ);
        assert_eq!(run(&p, nr(libc::SYS_mmap), AUDIT_ARCH, exec), EPERM);
        assert_eq!(run(&p, nr(libc::SYS_mprotect), AUDIT_ARCH, exec), EPERM);
        let read = arg(2, libc::PROT_READ);
        assert_eq!(run(&p, nr(libc::SYS_mmap), AUDIT_ARCH, read), ALLOW);
        assert_eq!(
            run(&p, nr(libc::SYS_fcntl), AUDIT_ARCH, arg(1, libc::F_SETLK)),
            ALLOW
        );
        assert_eq!(
            run(&p, nr(libc::SYS_fcntl), AUDIT_ARCH, arg(1, libc::F_SETLKW)),
            EPERM
        );
        // tgkill only on this process.
        let me = i32::try_from(std::process::id()).unwrap();
        assert_eq!(
            run(&p, nr(libc::SYS_tgkill), AUDIT_ARCH, arg(0, me + 1)),
            EPERM
        );
        assert_eq!(run(&p, nr(libc::SYS_tgkill), AUDIT_ARCH, arg(0, me)), ALLOW);
    }

    /// M2: an x32 system call number is refused first, even for an allowed
    /// call.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_calls_are_refused_first() {
        let p = filter().unwrap();
        for n in [libc::SYS_read, libc::SYS_socket, libc::SYS_openat] {
            assert_eq!(
                run(&p, nr(n) | 0x4000_0000, AUDIT_ARCH, [0; 6]),
                EPERM,
                "{n}"
            );
        }
    }

    /// M1: the grant is refused when a descriptor no longer names what its
    /// path names (a parent swapped after the open), and never follows a
    /// symbolic link while it is built.
    #[test]
    fn the_grant_is_bound_to_its_paths() {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("databastion-sqlite-grant-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("x.db"), b"x").unwrap();
        std::fs::write(b.join("x.db"), b"x").unwrap();
        let g = Grant::open(&a.join("x.db")).unwrap();
        g.verify().unwrap();
        // The directory swapped for another one after the open.
        std::fs::rename(&a, base.join("a-old")).unwrap();
        std::fs::rename(&b, &a).unwrap();
        assert_eq!(g.verify().unwrap_err().rule, Some(Rule::DescriptorBinding));
        // A symlinked parent is never followed.
        let link = base.join("link");
        std::os::unix::fs::symlink("/", &link).unwrap();
        let e = Grant::open(&link.join("x.db")).unwrap_err();
        assert_eq!(e.rule, Some(Rule::SymlinkComponent), "{e:?}");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
