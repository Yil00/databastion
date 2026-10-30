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
//!   (`/etc/group`, `/etc/passwd`). The server's uid is the server
//!   process's (`/proc/<pid>/status`) or the declared `peer_uid`, never a
//!   default. An agent whose identity files are not the host's (a
//!   container, a user namespace) proves nothing.
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

use rustix::fs::{Access, AtFlags, CWD, Mode, OFlags};
use zeroize::Zeroizing;

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

/// Who can read `path` (R4, proof 1): `Ok` when no uid other than root,
/// the server's and the agent's can read the log, the files rotated from
/// it (`<name>.*` and `<name>-*` next to it: the files the server may
/// still write and the ones the agent may still be reading), or its
/// directory, nor will the next log file through the directory's
/// default ACL; otherwise the reason. `server`: the server's uid and gid
/// as `/proc` shows them, `peer`: the declared `peer_uid`; neither, or
/// both differing, is a refusal (never a default uid).
pub(crate) fn readers_check(
    path: &Path,
    server: Option<(u32, u32)>,
    peer: Option<u32>,
    in_container: bool,
) -> Result<(), &'static str> {
    if in_container {
        return Err("agent_in_container");
    }
    let (server_uid, server_gid) = match (server, peer) {
        (Some((u, g)), Some(p)) if u == p => (u, Some(g)),
        (Some(_), Some(_)) => return Err("server_uid_mismatch"),
        (Some((u, g)), None) => (u, Some(g)),
        (None, Some(p)) => (p, None),
        (None, None) => return Err("server_uid_unknown"),
    };
    let agent = rustix::process::geteuid().as_raw();
    let passwd = std::fs::read_to_string("/etc/passwd").ok();
    let group = std::fs::read_to_string("/etc/group").ok();
    let (Some(passwd), Some(group)) = (passwd, group) else {
        return Err("identity_files_unreadable");
    };
    let allowed = |uid: u32| uid == 0 || uid == server_uid || uid == agent;
    let check = |p: &Path, need: u32| -> bool {
        let Ok(m) = std::fs::metadata(p) else {
            return true;
        };
        let acl = acl_entries(p, "system.posix_acl_access");
        others_can(&m, need, acl.as_deref(), &passwd, &group, &allowed)
    };
    if check(path, 0o4) {
        return Err("log_readable_by_others");
    }
    let Some(dir) = path.parent() else {
        return Err("log_directory_unknown");
    };
    if check(dir, 0o4) {
        return Err("log_directory_readable_by_others");
    }
    // The next log file's access, from the directory's default ACL.
    if let Some(def) = acl_entries(dir, "system.posix_acl_default") {
        let Ok(dm) = std::fs::metadata(dir) else {
            return Err("log_directory_unreadable");
        };
        let gids: Vec<u32> = server_gid.into_iter().chain([dm.gid()]).collect();
        if default_acl_open(&def, &gids, &passwd, &group, &allowed) {
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
        let Some(f) = f.to_str() else { continue };
        let rotated = f
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('-'));
        if rotated && check(&dir.join(f), 0o4) {
            return Err("rotated_log_readable_by_others");
        }
    }
    Ok(())
}

/// Whether a default ACL gives read to a uid outside `allowed` on the
/// files created in the directory: named users and groups and other
/// (under the mask), the owning group (the creating server's group or
/// the directory's) when one of its members is not allowed. The owner
/// entry is the creating server's own.
fn default_acl_open(
    entries: &[(u16, u16, u32)],
    gids: &[u32],
    passwd: &str,
    group: &str,
    allowed: &dyn Fn(u32) -> bool,
) -> bool {
    let group_ok =
        |gid: u32| members(group, passwd, gid).is_none_or(|u| u.iter().any(|x| !allowed(*x)));
    let mask = entries.iter().find(|e| e.0 == 0x10).map_or(7, |e| e.1);
    entries.iter().any(|&(tag, perm, id)| match tag {
        0x02 => perm & mask & 4 != 0 && !allowed(id),
        0x04 => perm & mask & 4 != 0 && gids.iter().any(|g| group_ok(*g)),
        0x08 => perm & mask & 4 != 0 && group_ok(id),
        0x20 => perm & 4 != 0,
        _ => false,
    })
}

/// The ACL entries `(tag, perm, id)` of `xattr` (`system.posix_acl_access`
/// or `system.posix_acl_default`), `None` without one; an ACL that does
/// not parse, or an error other than "no ACL", counts as open.
fn acl_entries(path: &Path, xattr: &str) -> Option<Vec<(u16, u16, u32)>> {
    let mut buf = vec![0u8; 4096];
    match rustix::fs::getxattr(path, xattr, &mut buf) {
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

fn members(group: &str, passwd: &str, gid: u32) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    let mut found = false;
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() == 4 && f[2].parse() == Ok(gid) {
            found = true;
            for name in f[3].split(',').filter(|n| !n.is_empty()) {
                let uid = passwd.lines().find_map(|p| {
                    let pf: Vec<&str> = p.split(':').collect();
                    (pf.len() >= 4 && pf[0] == name).then(|| pf[2].parse::<u32>().ok())?
                })?;
                out.push(uid);
            }
        }
    }
    // Users whose primary group it is.
    for p in passwd.lines() {
        let pf: Vec<&str> = p.split(':').collect();
        if pf.len() >= 4 && pf[3].parse() == Ok(gid) {
            out.push(pf[2].parse().ok()?);
        }
    }
    // A group not in /etc/group (NSS): not enumerable, open.
    found.then_some(out)
}

fn others_can(
    m: &std::fs::Metadata,
    need: u32,
    acl: Option<&[(u16, u16, u32)]>,
    passwd: &str,
    group: &str,
    allowed: &dyn Fn(u32) -> bool,
) -> bool {
    let mode = m.mode();
    if mode & need != 0 {
        // Other.
        return true;
    }
    let group_ok =
        |gid: u32| members(group, passwd, gid).is_none_or(|u| u.iter().any(|x| !allowed(*x)));
    let need16 = u16::try_from(need).unwrap_or(4);
    match acl {
        None => {
            (!allowed(m.uid()) && mode & (need << 6) != 0)
                || (mode & (need << 3) != 0 && group_ok(m.gid()))
        }
        Some(entries) => {
            let mask = entries.iter().find(|e| e.0 == 0x10).map_or(7, |e| e.1);
            entries.iter().any(|&(tag, perm, id)| match tag {
                0x01 => perm & need16 != 0 && !allowed(m.uid()),
                0x02 => perm & mask & need16 != 0 && !allowed(id),
                0x04 => perm & mask & need16 != 0 && group_ok(m.gid()),
                0x08 => perm & mask & need16 != 0 && group_ok(id),
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

    /// R39 (i): no default uid; a mismatch between the process and the
    /// declared account refuses; a default ACL that gives the next log to
    /// another account refuses.
    #[test]
    fn the_readers_check_needs_the_servers_uid() {
        let p = Path::new("/nonexistent/fb/audit.log");
        assert_eq!(
            readers_check(p, None, None, false),
            Err("server_uid_unknown")
        );
        assert_eq!(
            readers_check(p, Some((84, 84)), Some(85), false),
            Err("server_uid_mismatch")
        );
        assert_eq!(
            readers_check(p, Some((84, 84)), Some(84), true),
            Err("agent_in_container")
        );
        let passwd =
            "root:x:0:0::/:/bin/sh\nfirebird:x:84:84::/:/bin/false\neve:x:1002:1002::/:/bin/sh\n";
        let group = "firebird:x:84:\nstaff:x:50:eve\n";
        let allowed = |u: u32| u == 0 || u == 84;
        // Owner and owning group of server-only membership: closed.
        let closed = [
            (1u16, 6u16, u32::MAX),
            (4, 4, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ];
        assert!(!default_acl_open(&closed, &[84], passwd, group, &allowed));
        // A named user, a named group with another member, other: open.
        assert!(default_acl_open(
            &[(2, 4, 1002)],
            &[84],
            passwd,
            group,
            &allowed
        ));
        assert!(default_acl_open(
            &[(8, 4, 50)],
            &[84],
            passwd,
            group,
            &allowed
        ));
        assert!(default_acl_open(
            &[(0x20, 4, u32::MAX)],
            &[84],
            passwd,
            group,
            &allowed
        ));
        // Under a mask without read: closed.
        assert!(!default_acl_open(
            &[(2, 4, 1002), (0x10, 0, u32::MAX)],
            &[84],
            passwd,
            group,
            &allowed
        ));
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

    #[test]
    fn group_members() {
        let passwd = "root:x:0:0::/:/bin/sh\nfirebird:x:84:84::/:/bin/false\nagent:x:1001:1001::/:/bin/false\neve:x:1002:84::/:/bin/sh\n";
        let group = "firebird:x:84:\naudit:x:900:agent\n";
        assert_eq!(members(group, passwd, 900), Some(vec![1001]));
        assert_eq!(members(group, passwd, 84), Some(vec![84, 1002]));
        assert_eq!(members(group, passwd, 5), None);
    }
}
