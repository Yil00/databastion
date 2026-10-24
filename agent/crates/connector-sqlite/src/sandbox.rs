//! The reader process's sandbox (ADR-0059 decision 4, security review H1).
//!
//! 1. [`early`], first thing in reader mode: `PR_SET_NO_NEW_PRIVS`,
//!    `PR_SET_DUMPABLE` = 0, and the resource limits `RLIMIT_AS` (512 MiB),
//!    `RLIMIT_CPU` (60 s), `RLIMIT_NOFILE` (16), `RLIMIT_FSIZE` (0),
//!    `RLIMIT_CORE` (0).
//! 2. [`restrict`], once the open request is read: a Landlock ruleset
//!    granting read access only to the declared file's directory and to
//!    the reader's own `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` (no write
//!    right anywhere; Landlock's TCP rules too on ABI 4 and later), then a
//!    seccomp filter refusing with `EPERM` the socket, process, tracing,
//!    mount and namespace calls, `io_uring_*`, and every writing call
//!    (`open*` with a write flag or `O_CREAT` / `O_TRUNC`, `unlink*`,
//!    `rename*`, `truncate`, `fallocate`, `chmod`, `chown`, writes by
//!    position). Without Landlock, or when the ruleset is not enforced,
//!    the reader refuses to open anything ([`Code::SandboxUnavailable`]).
//!
//! The `unsafe` code is inside `rustix`, `landlock` and `seccompiler`.

use std::collections::BTreeMap;
use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};
use rustix::process::{Resource, Rlimit};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::ipc::{Code, Failure};

/// `RLIMIT_AS` of a reader.
pub const ADDRESS_SPACE: u64 = 512 * 1024 * 1024;
/// `RLIMIT_CPU` of a reader, in seconds.
pub const CPU_SECONDS: u64 = 60;
/// `RLIMIT_NOFILE` of a reader.
pub const OPEN_FILES: u64 = 16;

fn limit(resource: Resource, value: u64) -> Result<(), Failure> {
    rustix::process::setrlimit(
        resource,
        Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .map_err(|_| Failure::new(Code::SandboxUnavailable))
}

/// Step 3 of the reader (decision 4): no new privileges, not dumpable, the
/// resource limits.
///
/// # Errors
/// [`Code::SandboxUnavailable`].
pub fn early() -> Result<(), Failure> {
    let fail = |_| Failure::new(Code::SandboxUnavailable);
    rustix::thread::set_no_new_privs(true).map_err(fail)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(fail)?;
    limit(Resource::Core, 0)?;
    limit(Resource::Fsize, 0)?;
    limit(Resource::Nofile, OPEN_FILES)?;
    limit(Resource::Cpu, CPU_SECONDS)?;
    limit(Resource::As, ADDRESS_SPACE)?;
    Ok(())
}

/// Steps 4 and 5 of the reader: Landlock, then seccomp.
///
/// # Errors
/// [`Code::SandboxUnavailable`].
pub fn restrict(database: &Path) -> Result<(), Failure> {
    landlock(database)?;
    seccomp()
}

fn landlock(database: &Path) -> Result<(), Failure> {
    let fail = |_| Failure::new(Code::SandboxUnavailable);
    let dir = database
        .parent()
        .ok_or_else(|| Failure::new(Code::SandboxUnavailable))?;
    let latest = ABI::V6;
    let status = Ruleset::default()
        // ABI 1 is required: every file system right of the first ABI
        // (read, write, create, remove, execute) is handled, or nothing is
        // opened.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(fail)?
        // Later rights (refer, truncate, device ioctl) and the TCP rules
        // where the kernel has them.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(latest))
        .map_err(fail)?
        .handle_access(AccessNet::from_all(latest))
        .map_err(fail)?
        .create()
        .map_err(fail)?
        .set_compatibility(CompatLevel::HardRequirement)
        .add_rules(path_beneath_rules([dir], AccessFs::from_read(ABI::V1)))
        .map_err(fail)?
        .add_rules(path_beneath_rules(
            ["/proc/self/fd", "/proc/self/fdinfo"],
            AccessFs::from_read(ABI::V1),
        ))
        .map_err(fail)?
        .restrict_self()
        .map_err(fail)?;
    if status.ruleset == RulesetStatus::NotEnforced || !status.no_new_privs {
        return Err(Failure::new(Code::SandboxUnavailable));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

/// Calls refused whatever their arguments.
fn denied_calls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_mkdirat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_mknodat,
        libc::SYS_pwrite64,
        libc::SYS_pwritev,
        libc::SYS_pwritev2,
        libc::SYS_openat2,
        libc::SYS_memfd_create,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_accept,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_rmdir,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_mkdir,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_mknod,
        libc::SYS_creat,
    ]);
    #[cfg(target_arch = "aarch64")]
    v.push(libc::SYS_accept);
    v
}

/// Conditions matching an `open` flags argument (argument `index`) that
/// writes, creates or truncates.
fn write_flag_rules(index: u8) -> Result<Vec<SeccompRule>, seccompiler::BackendError> {
    let flags = |mask: i32, value: i32| -> Result<SeccompRule, seccompiler::BackendError> {
        SeccompRule::new(vec![SeccompCondition::new(
            index,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(u64::from(mask.cast_unsigned())),
            u64::from(value.cast_unsigned()),
        )?])
    };
    Ok(vec![
        flags(libc::O_ACCMODE, libc::O_WRONLY)?,
        flags(libc::O_ACCMODE, libc::O_RDWR)?,
        flags(libc::O_CREAT, libc::O_CREAT)?,
        flags(libc::O_TRUNC, libc::O_TRUNC)?,
    ])
}

/// The filter: [`denied_calls`] and the writing `open` calls refused with
/// `EPERM` (so SQLite falls back to read-only), everything else allowed.
///
/// # Errors
/// [`Code::SandboxUnavailable`] if it cannot be built.
pub fn filter() -> Result<BpfProgram, Failure> {
    let fail = |_| Failure::new(Code::SandboxUnavailable);
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = denied_calls()
        .into_iter()
        .map(|c| (c, Vec::new()))
        .collect();
    rules.insert(libc::SYS_openat, write_flag_rules(2).map_err(fail)?);
    #[cfg(target_arch = "x86_64")]
    rules.insert(libc::SYS_open, write_flag_rules(1).map_err(fail)?);
    let eperm = u32::try_from(libc::EPERM).unwrap_or(1);
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(eperm),
        ARCH,
    )
    .map_err(|_| Failure::new(Code::SandboxUnavailable))?;
    BpfProgram::try_from(f).map_err(|_| Failure::new(Code::SandboxUnavailable))
}

fn seccomp() -> Result<(), Failure> {
    let program = filter()?;
    seccompiler::apply_filter(&program).map_err(|_| Failure::new(Code::SandboxUnavailable))
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

    #[test]
    fn the_filter_builds() {
        let p = filter().unwrap();
        assert!(p.len() > denied_calls().len());
    }
}
