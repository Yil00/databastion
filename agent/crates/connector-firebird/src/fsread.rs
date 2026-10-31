//! Local files of the Firebird Audit source (ADR-0060 decision 6, the
//! file rules and proofs 1 and 2; R4's readers check; R5's start times).
//! Blocking I/O: call from a blocking thread.
//!
//! - Every file is opened with `O_NOFOLLOW` and checked on its handle: a
//!   regular file with one hard link, not writable by the agent (owner,
//!   mode bits, `faccessat(W_OK)`, no writable ancestor), the path naming
//!   the handle before and after the checks (ADR-0043 decision 5).
//! - [`readers_check`] (R4, proof 1): who other than root, the server's
//!   account and the agent can read the log, its rotated files or its
//!   directory, or the next log file through the directory's default ACL,
//!   from the mode bits, the owner and group, the POSIX ACLs (mask
//!   applied) and the members of every group with read access
//!   (the identity files of [`crate::host_identity`]: the bare host's own,
//!   or in a container the declared host files, R44 to R50). The server's
//!   uid is the server process's (`/proc/<pid>/status`) or the declared
//!   `peer_uid`, never a default. An agent in a container without
//!   declared host files proves nothing.
//! - [`process_start`] (R1 rule 1, R5): field 22 of `/proc/<pid>/stat`,
//!   converted with the boot time and the clock ticks.
//!
//! No path or file content is logged or returned in an error.

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use databastion_core::config::firebird::FirebirdHostIdentity;
use rustix::fs::{Access, AtFlags, CWD, Mode, OFlags};
use zeroize::Zeroizing;

use crate::host_identity::{self, Fail, Identity};

/// Why a file is refused (kinds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    NotReadable,
    Writable,
    Links,
    Changed,
    TooLarge,
}

/// Test support: accept files the test's own user could write.
#[cfg(test)]
static RELAXED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn allow_own_files_for_tests() {
    RELAXED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn strict() -> bool {
    #[cfg(test)]
    if RELAXED.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    true
}

fn me() -> (u32, u32, Option<Vec<u32>>) {
    (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        rustix::process::getgroups()
            .ok()
            .map(|g| g.iter().map(|g| g.as_raw()).collect()),
    )
}

fn writable_by(uid: u32, gid: u32, mode: u32) -> bool {
    let (euid, egid, groups) = me();
    if euid == 0 || uid == euid || mode & 0o002 != 0 {
        return true;
    }
    mode & 0o020 != 0 && (gid == egid || groups.as_ref().is_none_or(|g| g.contains(&gid)))
}

fn access_writable(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return true;
    };
    match rustix::fs::accessat(CWD, c.as_c_str(), Access::WRITE_OK, AtFlags::EACCESS) {
        Ok(()) => true,
        Err(e) => e != rustix::io::Errno::ACCESS && e != rustix::io::Errno::ROFS,
    }
}

fn ancestor_writable(path: &Path) -> bool {
    path.ancestors().skip(1).any(|dir| {
        std::fs::metadata(dir).map_or(true, |m| writable_by(m.uid(), m.gid(), m.mode()))
            || access_writable(dir)
    })
}

fn names(path: &Path, meta: &std::fs::Metadata) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|now| {
        now.file_type().is_file() && (now.dev(), now.ino()) == (meta.dev(), meta.ino())
    })
}

/// Whether the agent could write the file `path` names (`meta` from
/// `fstat` on its handle): owner, mode bits, `faccessat(W_OK)`, a
/// writable ancestor directory (ADR-0060 R45 item 3).
pub(crate) fn agent_can_write(path: &Path, meta: &std::fs::Metadata) -> bool {
    strict()
        && (writable_by(meta.uid(), meta.gid(), meta.mode())
            || access_writable(path)
            || ancestor_writable(path))
}

/// The checks of an opened file (`meta` from `fstat` on its handle).
pub(crate) fn check_opened(path: &Path, meta: &std::fs::Metadata) -> Result<(), Refusal> {
    if !meta.file_type().is_file() {
        return Err(Refusal::NotReadable);
    }
    if meta.nlink() != 1 {
        return Err(Refusal::Links);
    }
    if !names(path, meta) {
        return Err(Refusal::Changed);
    }
    if strict()
        && (writable_by(meta.uid(), meta.gid(), meta.mode())
            || access_writable(path)
            || ancestor_writable(path))
    {
        return Err(Refusal::Writable);
    }
    if !names(path, meta) {
        return Err(Refusal::Changed);
    }
    Ok(())
}

/// Opens `path` under the file rules and checks it on its handle, without
/// reading its content (the audit log, proof 1; review H3: the log is
/// never read into memory by `check()`).
pub(crate) fn check_file(path: &Path) -> Result<(), Refusal> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|_| Refusal::NotReadable)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| Refusal::NotReadable)?;
    check_opened(path, &meta)
}

/// Reads a configuration file under the file rules (at most `max`
/// bytes), with its modification and change times.
pub(crate) fn read_checked(
    path: &Path,
    max: usize,
) -> Result<(Zeroizing<Vec<u8>>, SystemTime), Refusal> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|_| Refusal::NotReadable)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| Refusal::NotReadable)?;
    check_opened(path, &meta)?;
    if meta.len() > max as u64 {
        return Err(Refusal::TooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0)));
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::NotReadable)?;
    if bytes.len() > max {
        return Err(Refusal::TooLarge);
    }
    Ok((bytes, changed_at(&meta)))
}

/// The later of a file's modification and status-change times.
fn changed_at(meta: &std::fs::Metadata) -> SystemTime {
    let at = |s: i64, ns: i64| {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(u64::try_from(s).unwrap_or(0))
            + Duration::from_nanos(u64::try_from(ns).unwrap_or(0))
    };
    at(meta.mtime(), meta.mtime_nsec()).max(at(meta.ctime(), meta.ctime_nsec()))
}

/// The `(st_dev, st_ino)` and link count of a path, without opening it
/// (proof 11, M4).
pub(crate) fn identity(path: &Path) -> Option<((u64, u64), u64)> {
    std::fs::metadata(path)
        .ok()
        .map(|m| ((m.dev(), m.ino()), m.nlink()))
}

/// The start of a process (R1 rule 1, R5 item 4): field 22 of
/// `/proc/<pid>/stat` in clock ticks since boot, returned as the raw tick
/// count (compared as is between samples) and as a wall-clock time (for
/// the configuration files' times, proof 2). `None` when not visible.
pub(crate) fn process_start(pid: u32) -> Option<(u64, SystemTime)> {
    if !is_firebird(pid) {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let ticks = stat_start_ticks(&stat)?;
    let btime = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ")?.trim().parse::<u64>().ok())?;
    let hz = rustix::param::clock_ticks_per_second().max(1);
    let started = SystemTime::UNIX_EPOCH
        + Duration::from_secs(btime)
        + Duration::from_millis(ticks.saturating_mul(1000) / hz);
    Some((ticks, started))
}

/// Field 22 of a `/proc/<pid>/stat` line (after the last `)`, the command
/// name being free text).
pub(crate) fn stat_start_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // Fields 3.. follow; field 22 is the 20th of them.
    after.split_whitespace().nth(19)?.parse().ok()
}

/// The server process's effective uid and gid (`/proc/<pid>/status`),
/// only when the process is a Firebird server (`comm` `firebird`): a pid
/// read from another pid namespace names an unrelated process here.
pub(crate) fn server_ids(pid: u32) -> Option<(u32, u32)> {
    if !is_firebird(pid) {
        return None;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status_ids(&status)
}

/// Whether `pid` is a Firebird server process (`comm` `firebird`): a pid
/// read from `MON$SERVER_PID` in another pid namespace names an unrelated
/// process here (review N2).
pub(crate) fn is_firebird(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim_end() == "firebird")
}

/// The effective uid and gid of a `/proc/<pid>/status` text.
pub(crate) fn status_ids(status: &str) -> Option<(u32, u32)> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u32>().ok())
    };
    Some((field("Uid:")?, field("Gid:")?))
}

/// The directory of the server's binary (`argv[0]` of
/// `/proc/<pid>/cmdline`, absolute only), for the layout check (review
/// L4).
pub(crate) fn server_binary_dir(pid: u32) -> Option<std::path::PathBuf> {
    if !is_firebird(pid) {
        return None;
    }
    // The executable itself when its link is readable (the server's uid or
    // ptrace rights; `comm` and `argv[0]` are the process's to set, re-review
    // note), else `argv[0]`.
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        return exe.parent().map(Path::to_path_buf);
    }
    let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    binary_dir(&cmd)
}

pub(crate) fn binary_dir(cmdline: &[u8]) -> Option<std::path::PathBuf> {
    let argv0 = cmdline.split(|b| *b == 0).next()?;
    let p = Path::new(std::str::from_utf8(argv0).ok()?);
    if !p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir) {
        return None;
    }
    p.parent().map(Path::to_path_buf)
}

/// Rotated files examined at most next to the log (R4).
const MAX_DIR_ENTRIES: usize = 4096;

/// Where the readers check runs (ADR-0060 R44 item 3): whether a
/// container is detected at this check, and the declared host identity
/// files.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Place<'a> {
    pub(crate) in_container: bool,
    pub(crate) host_identity: Option<&'a FirebirdHostIdentity>,
}

/// Who can read `path` (R4, proof 1): `Ok` when no uid other than root,
/// the server's and the agent's can read the log, the files rotated from
/// it (next to it, named as the server or an external rotation names
/// them, [`rotated_name`]: the files the server may still write and the
/// ones the agent may still be reading), or its
/// directory, nor will the next log file through the directory's
/// default ACL; otherwise the reason (local detail only). `server`: the
/// server's uid and gid as `/proc` shows them, `peer`: the declared
/// `peer_uid`; neither, or both differing, is a refusal (never a default
/// uid). The identity files are the bare host's own or, in a container,
/// the declared ones (refinement of 2026-10-31, R44 to R50), read at this
/// check.
pub(crate) fn readers_check(
    path: &Path,
    server: Option<(u32, u32)>,
    peer: Option<u32>,
    place: Place<'_>,
) -> Result<(), String> {
    let declared = match (place.in_container, place.host_identity) {
        (false, Some(_)) => return Err(host_identity::not_in_container().reason()),
        (true, None) => return Err("agent_in_container".to_owned()),
        (true, Some(h)) => Some(h),
        (false, None) => None,
    };
    let (server_uid, server_gid) = match (server, peer) {
        (Some((u, g)), Some(p)) if u == p => (u, Some(g)),
        (Some(_), Some(_)) => return Err("server_uid_mismatch".to_owned()),
        (Some((u, g)), None) => (u, Some(g)),
        (None, Some(p)) => (p, None),
        (None, None) => return Err("server_uid_unknown".to_owned()),
    };
    let agent = rustix::process::geteuid().as_raw();
    let identity = match declared {
        Some(h) => host_identity::load_declared(h),
        None => host_identity::load_bare_host(),
    }
    .map_err(Fail::reason)?;
    identity
        .uid_rules(
            server_uid,
            agent,
            declared.map(|h| (h.server_account.as_deref(), h.agent_account.as_deref())),
        )
        .map_err(Fail::reason)?;
    readers_with(path, server_uid, server_gid, agent, &identity).map_err(str::to_owned)
}

/// The permission part of the readers check, with the identity read.
/// Every file is examined without following links (`symlink_metadata`,
/// `lgetxattr`; security review N6): a symbolic link counts as open.
pub(crate) fn readers_with(
    path: &Path,
    server_uid: u32,
    server_gid: Option<u32>,
    agent: u32,
    identity: &Identity,
) -> Result<(), &'static str> {
    let allowed = |uid: u32| uid == 0 || uid == server_uid || uid == agent;
    let groups = GroupMemo::new(identity, &allowed);
    let check = |p: &Path, need: u32| -> bool {
        let Ok(m) = std::fs::symlink_metadata(p) else {
            return true;
        };
        if m.file_type().is_symlink() {
            return true;
        }
        let acl = acl_entries(p, "system.posix_acl_access");
        others_can(&m, need, acl.as_deref(), &groups, &allowed)
    };
    let Some(dir) = path.parent() else {
        return Err("log_directory_unknown");
    };
    // Security review N3: a directory that is a symbolic link has its own
    // reason (and counts as open).
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("log_directory_is_a_symlink");
    }
    if check(path, 0o4) {
        return Err("log_readable_by_others");
    }
    if check(dir, 0o4) {
        return Err("log_directory_readable_by_others");
    }
    // The next log file's access, from the directory's default ACL.
    if let Some(def) = acl_entries(dir, "system.posix_acl_default") {
        let Ok(dm) = std::fs::symlink_metadata(dir) else {
            return Err("log_directory_unreadable");
        };
        let gids: Vec<u32> = server_gid.into_iter().chain([dm.gid()]).collect();
        if default_acl_open(&def, &gids, &groups, &allowed) {
            return Err("log_directory_default_acl");
        }
    }
    // Rotated files.
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Err("log_name_not_utf8");
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Err("log_directory_unreadable");
    };
    for (n, e) in entries.enumerate() {
        if n >= MAX_DIR_ENTRIES {
            return Err("log_directory_too_large");
        }
        let Ok(e) = e else {
            return Err("log_directory_unreadable");
        };
        let f = e.file_name();
        let rotated = rotated_name(name, f.as_encoded_bytes());
        // Security review N5: a rotated name that is not UTF-8 counts as
        // open rather than being skipped.
        if rotated && (f.to_str().is_none() || check(&dir.join(&f), 0o4)) {
            return Err("rotated_log_readable_by_others");
        }
    }
    Ok(())
}

/// Whether `f`, a name in the log's directory, is a file rotated from the
/// log `name` (R4): the server's own rotated names, and the names an
/// external rotation gives.
///
/// - The server (`PluginLogWriter::write`, `max_log_size`, the same in
///   4.0.7 and 5.0.4) renames the log at the last `.` of its path:
///   `<stem>.<YYYY-MM-DD>T<hh-mm-ss>.<ffff>.<ext>` for `<stem>.<ext>`
///   (`audit.log` gives `audit.2026-10-31T10-00-00.1234.log`). Matched as
///   any name `<stem>.*.<ext>` other than the log (wider than the
///   server's, so that nothing it writes is missed). For a file name
///   without a `.`, the target is a path under a directory that does not
///   exist (cut at a `.` of a directory of its path, or, with no `.` at
///   all, `<path>.<timestamp>.<path>`, read from the sources): the
///   server's `rename` fails with `ENOENT`, which it ignores, and the log
///   is never rotated; nothing to match here.
/// - An external rotation (`logrotate` and the like): `<name>.*` and
///   `<name>-*`.
fn rotated_name(name: &str, f: &[u8]) -> bool {
    let name = name.as_bytes();
    if f == name {
        return false;
    }
    if f.strip_prefix(name)
        .is_some_and(|rest| rest.starts_with(b".") || rest.starts_with(b"-"))
    {
        return true;
    }
    let Some(dot) = name.iter().rposition(|b| *b == b'.') else {
        return false;
    };
    let (stem, ext) = (&name[..=dot], &name[dot..]);
    f.len() > stem.len() + ext.len() && f.starts_with(stem) && f.ends_with(ext)
}

/// Whether each group that grants read is open, computed once per gid
/// within one readers check (security review L3: the log, its directory,
/// its default ACL and every rotated file ask for the same gids; ACL
/// xattrs are read into 4 KiB, at most 511 entries each).
pub(crate) struct GroupMemo<'a> {
    identity: &'a Identity,
    allowed: &'a dyn Fn(u32) -> bool,
    cache: std::cell::RefCell<std::collections::HashMap<u32, bool>>,
}

impl<'a> GroupMemo<'a> {
    pub(crate) fn new(identity: &'a Identity, allowed: &'a dyn Fn(u32) -> bool) -> Self {
        Self {
            identity,
            allowed,
            cache: std::cell::RefCell::default(),
        }
    }

    pub(crate) fn open(&self, gid: u32) -> bool {
        if let Some(v) = self.cache.borrow().get(&gid) {
            return *v;
        }
        let v = self.identity.group_open(gid, self.allowed);
        self.cache.borrow_mut().insert(gid, v);
        v
    }

    /// How many gids were evaluated.
    #[cfg(test)]
    pub(crate) fn evaluated(&self) -> usize {
        self.cache.borrow().len()
    }
}

/// Whether a default ACL gives read to a uid outside `allowed` on the
/// files created in the directory: named users and groups and other
/// (under the mask), the owning group (the creating server's group or
/// the directory's) when it is open. The owner entry is the creating
/// server's own.
fn default_acl_open(
    entries: &[(u16, u16, u32)],
    gids: &[u32],
    groups: &GroupMemo<'_>,
    allowed: &dyn Fn(u32) -> bool,
) -> bool {
    let group_open = |gid: u32| groups.open(gid);
    let mask = entries.iter().find(|e| e.0 == 0x10).map_or(7, |e| e.1);
    entries.iter().any(|&(tag, perm, id)| match tag {
        0x02 => perm & mask & 4 != 0 && !allowed(id),
        0x04 => perm & mask & 4 != 0 && gids.iter().any(|g| group_open(*g)),
        0x08 => perm & mask & 4 != 0 && group_open(id),
        0x20 => perm & 4 != 0,
        _ => false,
    })
}

/// The ACL entries `(tag, perm, id)` of `xattr` (`system.posix_acl_access`
/// or `system.posix_acl_default`) of `path` itself, never following a
/// link (`lgetxattr`), `None` without one; an ACL that does not parse, or
/// an error other than "no ACL", counts as open.
fn acl_entries(path: &Path, xattr: &str) -> Option<Vec<(u16, u16, u32)>> {
    let mut buf = vec![0u8; 4096];
    match rustix::fs::lgetxattr(path, xattr, &mut buf) {
        Ok(n) => parse_acl(&buf[..n]).or(Some(vec![(0x20, 7, 0)])),
        Err(e) if e == rustix::io::Errno::NODATA || e == rustix::io::Errno::NOTSUP => None,
        Err(_) => Some(vec![(0x20, 7, 0)]),
    }
}

/// The Linux ACL xattr format: version 2, then 8-byte entries.
pub(crate) fn parse_acl(b: &[u8]) -> Option<Vec<(u16, u16, u32)>> {
    if b.len() < 4
        || u32::from_le_bytes(b[..4].try_into().ok()?) != 2
        || !(b.len() - 4).is_multiple_of(8)
    {
        return None;
    }
    Some(
        b[4..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|e| {
                (
                    u16::from_le_bytes([e[0], e[1]]),
                    u16::from_le_bytes([e[2], e[3]]),
                    u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
                )
            })
            .collect(),
    )
}

fn others_can(
    m: &std::fs::Metadata,
    need: u32,
    acl: Option<&[(u16, u16, u32)]>,
    groups: &GroupMemo<'_>,
    allowed: &dyn Fn(u32) -> bool,
) -> bool {
    let mode = m.mode();
    if mode & need != 0 {
        // Other.
        return true;
    }
    let group_open = |gid: u32| groups.open(gid);
    let need16 = u16::try_from(need).unwrap_or(4);
    match acl {
        None => {
            (!allowed(m.uid()) && mode & (need << 6) != 0)
                || (mode & (need << 3) != 0 && group_open(m.gid()))
        }
        Some(entries) => {
            let mask = entries.iter().find(|e| e.0 == 0x10).map_or(7, |e| e.1);
            entries.iter().any(|&(tag, perm, id)| match tag {
                0x01 => perm & need16 != 0 && !allowed(m.uid()),
                0x02 => perm & mask & need16 != 0 && !allowed(id),
                0x04 => perm & mask & need16 != 0 && group_open(m.gid()),
                0x08 => perm & mask & need16 != 0 && group_open(id),
                0x20 => perm & need16 != 0,
                _ => false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_and_acl_formats() {
        let stat = "84 (fire bird) S 1 84 84 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 9 0 123456 1 2";
        assert_eq!(stat_start_ticks(stat), Some(123_456));
        assert_eq!(stat_start_ticks("x"), None);
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (t, p, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 1001),
            (4, 0, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&t.to_le_bytes());
            acl.extend_from_slice(&p.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let e = parse_acl(&acl).unwrap();
        assert_eq!(e.len(), 5);
        assert_eq!(e[1], (2, 4, 1001));
        assert!(parse_acl(&acl[..7]).is_none());
        // Review N2: only a Firebird server process (this test is not one).
        assert!(process_start(std::process::id()).is_none());
        assert!(server_binary_dir(std::process::id()).is_none());
    }

    #[test]
    fn server_ids_and_layout() {
        let status = "Name:\tfirebird\nUid:\t84\t85\t85\t85\nGid:\t90\t91\t91\t91\n";
        assert_eq!(status_ids(status), Some((85, 91)));
        assert_eq!(status_ids("Name:\tx\n"), None);
        assert_eq!(
            binary_dir(b"/opt/firebird/bin/firebird\0-a\0"),
            Some(std::path::PathBuf::from("/opt/firebird/bin"))
        );
        assert_eq!(binary_dir(b"firebird\0"), None);
        assert_eq!(binary_dir(b"/opt/x/../firebird/bin/firebird\0"), None);
        // This test process is not a Firebird server.
        assert_eq!(server_ids(std::process::id()), None);
    }

    fn identity(passwd: &str, group: &str) -> Identity {
        crate::host_identity::identity_for_tests(
            passwd,
            group,
            Some("passwd: files\ngroup: files\n"),
            None,
            None,
            crate::host_identity::Place::BareHost,
        )
        .unwrap()
    }

    const BARE: Place<'static> = Place {
        in_container: false,
        host_identity: None,
    };

    /// R39 (i): no default uid; a mismatch between the process and the
    /// declared account refuses; a default ACL that gives the next log to
    /// another account refuses. R44 items 3 and 5: in a container, the
    /// declared files or nothing; the block without a container refuses.
    #[test]
    fn the_readers_check_needs_the_servers_uid() {
        let p = Path::new("/nonexistent/fb/audit.log");
        assert_eq!(
            readers_check(p, None, None, BARE),
            Err("server_uid_unknown".to_owned())
        );
        assert_eq!(
            readers_check(p, Some((84, 84)), Some(85), BARE),
            Err("server_uid_mismatch".to_owned())
        );
        let container = Place {
            in_container: true,
            host_identity: None,
        };
        assert_eq!(
            readers_check(p, Some((84, 84)), Some(84), container),
            Err("agent_in_container".to_owned())
        );
        let h = FirebirdHostIdentity {
            passwd: "/run/databastion/host/passwd".into(),
            group: "/run/databastion/host/group".into(),
            nsswitch: "/run/databastion/host/nsswitch.conf".into(),
            subuid: None,
            subgid: None,
            server_account: None,
            agent_account: None,
        };
        let bare_with_block = Place {
            in_container: false,
            host_identity: Some(&h),
        };
        assert_eq!(
            readers_check(p, Some((84, 84)), Some(84), bare_with_block),
            Err("host_identity_refused (host_identity: not_in_container)".to_owned())
        );
        // In a container with the block, files that are not mounts (here
        // missing) are refused before anything is read.
        let declared = Place {
            in_container: true,
            host_identity: Some(&h),
        };
        let why = readers_check(p, Some((84, 84)), Some(84), declared).unwrap_err();
        assert!(
            why.starts_with("host_identity_refused (") || why == "user_namespace",
            "{why}"
        );
        let passwd =
            "root:x:0:0::/:/bin/sh\nfirebird:x:84:84::/:/bin/false\neve:x:1002:1002::/:/bin/sh\n";
        let group = "firebird:x:84:\nstaff:x:50:eve\n";
        let id = identity(passwd, group);
        let allowed = |u: u32| u == 0 || u == 84;
        // Owner and owning group of server-only membership: closed.
        let closed = [
            (1u16, 6u16, u32::MAX),
            (4, 4, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ];
        assert!(!default_acl_open(
            &closed,
            &[84],
            &GroupMemo::new(&id, &allowed),
            &allowed
        ));
        // A named user, a named group with another member, other: open.
        assert!(default_acl_open(
            &[(2, 4, 1002)],
            &[84],
            &GroupMemo::new(&id, &allowed),
            &allowed
        ));
        assert!(default_acl_open(
            &[(8, 4, 50)],
            &[84],
            &GroupMemo::new(&id, &allowed),
            &allowed
        ));
        assert!(default_acl_open(
            &[(0x20, 4, u32::MAX)],
            &[84],
            &GroupMemo::new(&id, &allowed),
            &allowed
        ));
        // Under a mask without read: closed.
        assert!(!default_acl_open(
            &[(2, 4, 1002), (0x10, 0, u32::MAX)],
            &[84],
            &GroupMemo::new(&id, &allowed),
            &allowed
        ));
        // R52 item 1: the dev layout's default ACL (u::rw, g::---, m::r,
        // o::---, u:10001:r) with the agent as 10001: closed.
        let agent = |u: u32| u == 0 || u == 84 || u == 10_001;
        let dev = [
            (1u16, 6u16, u32::MAX),
            (2, 4, 10_001),
            (4, 0, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ];
        assert!(!default_acl_open(
            &dev,
            &[84],
            &GroupMemo::new(&id, &agent),
            &agent
        ));
        // Groups not provable (R47): an owning group with read is open.
        let open_groups = crate::host_identity::identity_for_tests(
            passwd,
            group,
            Some("passwd: files systemd\ngroup: files systemd\n"),
            None,
            None,
            crate::host_identity::Place::BareHost,
        )
        .unwrap();
        assert!(default_acl_open(
            &closed,
            &[84],
            &GroupMemo::new(&open_groups, &allowed),
            &allowed
        ));
        assert!(!default_acl_open(
            &dev,
            &[84],
            &GroupMemo::new(&open_groups, &agent),
            &agent
        ));
    }

    /// Security review L3: a gid is evaluated once per readers check.
    #[test]
    fn group_answers_are_memoized() {
        let id = identity(
            "root:x:0:0::/:/bin/sh\neve:x:1002:1002::/:/bin/sh\n",
            "staff:x:50:eve\nfb:x:84:\n",
        );
        let allowed = |u: u32| u == 0 || u == 84;
        let memo = GroupMemo::new(&id, &allowed);
        let entries: Vec<(u16, u16, u32)> = (0..500)
            .map(|i| (8, 4, if i % 2 == 0 { 50 } else { 84 }))
            .collect();
        assert!(default_acl_open(&entries, &[84], &memo, &allowed));
        assert!(memo.open(50) && !memo.open(84));
        assert_eq!(memo.evaluated(), 2);
    }

    /// R48 item 3 (and N6): the readers check on real files, with an
    /// injected identity; a symbolic link among the rotated files counts
    /// as open.
    #[test]
    fn rotated_symlinks_count_as_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fb-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, b"x").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let id = identity("root:x:0:0::/:/bin/sh\n", "root:x:0:\n");
        assert_eq!(readers_with(&log, me, None, me, &id), Ok(()));
        let target = dir.join("other");
        std::fs::write(&target, b"y").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("audit.log.1")).unwrap();
        assert_eq!(
            readers_with(&log, me, None, me, &id),
            Err("rotated_log_readable_by_others")
        );
        std::fs::remove_file(dir.join("audit.log.1")).unwrap();
        assert_eq!(readers_with(&log, me, None, me, &id), Ok(()));
        // Review N5: a rotated name that is not UTF-8 counts as open.
        use std::os::unix::ffi::OsStrExt;
        let odd = dir.join(std::ffi::OsStr::from_bytes(b"audit.log.\xff"));
        std::fs::write(&odd, b"z").unwrap();
        std::fs::set_permissions(&odd, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            readers_with(&log, me, None, me, &id),
            Err("rotated_log_readable_by_others")
        );
        std::fs::remove_file(&odd).unwrap();
        // Review N3: a log directory that is a symbolic link.
        let alias = dir.with_extension("alias");
        let _ = std::fs::remove_file(&alias);
        std::os::unix::fs::symlink(&dir, &alias).unwrap();
        assert_eq!(
            readers_with(&alias.join("audit.log"), me, None, me, &id),
            Err("log_directory_is_a_symlink")
        );
        let _ = std::fs::remove_file(&alias);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R4: the server's rotated names (`audit.<timestamp>.log` for
    /// `audit.log`, measured on 4.0.7 and 5.0.4) and an external
    /// rotation's are rotated files; other names are not.
    #[test]
    fn rotated_names_are_the_servers_and_external_ones() {
        for (name, f, rotated) in [
            ("audit.log", "audit.2026-10-31T10-00-00.1234.log", true),
            ("audit.log", "audit.2026-10-31T10-00-00.0001.log", true),
            ("audit.log", "audit.log.1", true),
            ("audit.log", "audit.log-20261031", true),
            ("audit.log", "audit.log.2026-10-31T10-00-00.1234.gz", true),
            ("audit.log", "audit.x.log", true),
            ("audit.log", "audit.log", false),
            ("audit.log", "audit.log2", false),
            ("audit.log", "other.2026-10-31T10-00-00.1234.log", false),
            ("audit.log", "audit.2026-10-31T10-00-00.1234.txt", false),
            ("audit.log", "audit..log", false),
            (
                "fb.trace.log",
                "fb.trace.2026-10-31T10-00-00.1234.log",
                true,
            ),
            (
                "fb.trace.log",
                "fb.2026-10-31T10-00-00.1234.trace.log",
                false,
            ),
            ("trace", "trace.2026-10-31T10-00-00.1234", true),
            ("trace", "trace-1", true),
            ("trace", "tracex", false),
            (".log", ".2026-10-31T10-00-00.1234.log", true),
        ] {
            assert_eq!(rotated_name(name, f.as_bytes()), rotated, "{name} {f}");
        }
        // A name that is not UTF-8 with the server's shape is rotated.
        assert!(rotated_name("audit.log", b"audit.\xff.log"));
    }

    /// R4 on real files: a file rotated by the server (its name) and
    /// readable by others withholds Partial; 0600, it does not.
    #[test]
    fn a_server_rotated_file_readable_by_others_is_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fb-srvrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, b"x").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let id = identity("root:x:0:0::/:/bin/sh\n", "root:x:0:\n");
        let rotated = dir.join("audit.2026-10-31T10-00-00.1234.log");
        std::fs::write(&rotated, b"y").unwrap();
        std::fs::set_permissions(&rotated, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(readers_with(&log, me, None, me, &id), Ok(()));
        std::fs::set_permissions(&rotated, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            readers_with(&log, me, None, me, &id),
            Err("rotated_log_readable_by_others")
        );
        // An unrelated file next to the log is not examined.
        std::fs::set_permissions(&rotated, std::fs::Permissions::from_mode(0o600)).unwrap();
        let other = dir.join("notes.txt");
        std::fs::write(&other, b"z").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(readers_with(&log, me, None, me, &id), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review H3: the log check opens and checks without reading, and a
    /// symbolic link is refused.
    #[test]
    fn the_log_check_neither_reads_nor_follows() {
        allow_own_files_for_tests();
        let dir = std::env::temp_dir().join(format!("fb-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, b"x").unwrap();
        assert_eq!(check_file(&log), Ok(()));
        // Reads nothing: an 8 GiB (sparse) log is checked at once.
        let big = dir.join("big.log");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(8 << 30)
            .unwrap();
        let t = std::time::Instant::now();
        assert_eq!(check_file(&big), Ok(()));
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&log, &link).unwrap();
        assert_eq!(check_file(&link), Err(Refusal::NotReadable));
        assert_eq!(
            check_file(&dir.join("missing.log")),
            Err(Refusal::NotReadable)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
