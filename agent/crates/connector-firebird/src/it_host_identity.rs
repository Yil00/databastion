//! Integration tests of the host identity files of the readers check on a
//! real kernel (ADR-0060 refinement of 2026-10-31, R52 items 1 to 3):
//! `dev/firebird/it.sh` runs them in a private mount namespace (`unshare
//! --mount`) on a tmpfs at `FIREBIRD_IT_HOSTID_DIR`, with single-file bind
//! mounts of the calling host's own `/etc/passwd`, `/etc/group` and
//! `/etc/nsswitch.conf`, read-only, and the negative cases next to them:
//! `rw-passwd` (the host's passwd mounted read-write), `plain` (a file of
//! the tmpfs, not a mount), `stale` (a read-only mount whose source was
//! renamed over), `link` (a symbolic link to the good mount), `owned` (a
//! mount of a file owned by uid 5) and `gw` (a mount of a group-writable
//! root file). Two phases:
//!
//! - `prepare` (as root, `FIREBIRD_IT_HOSTID_PREPARE=1`): the two log
//!   layouts under `<dir>/fb`, the dev service's named-user ACLs (R52 item
//!   1) and the earlier group layout, the negative case;
//! - `checks` (as uid 10001, the agent image's, with no supplementary
//!   group): the file and mount rules on every mount, and the readers
//!   check with the declared files on both layouts.
//!
//! Skipped unless `FIREBIRD_IT_HOSTID_DIR` is set. No server is needed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use databastion_core::config::firebird::FirebirdHostIdentity;

use crate::fsread::{Place, readers_check};
use crate::host_identity::{Fail, Kind, Role, load_declared};

const SERVER: u32 = 84;
const AGENT: u32 = 10_001;

fn dir() -> Option<PathBuf> {
    std::env::var_os("FIREBIRD_IT_HOSTID_DIR").map(PathBuf::from)
}

/// An ACL xattr (version 2, entries sorted by tag then id).
fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut b = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&perm.to_le_bytes());
        b.extend_from_slice(&id.to_le_bytes());
    }
    b
}

const U: u32 = u32::MAX;

fn set_acl(p: &Path, name: &str, entries: &[(u16, u16, u32)]) {
    rustix::fs::setxattr(p, name, &acl(entries), rustix::fs::XattrFlags::empty())
        .unwrap_or_else(|e| panic!("setting an ACL on the tmpfs: {e} (CONFIG_TMPFS_POSIX_ACL?)"));
}

/// Root phase: the two log layouts.
#[test]
fn prepare() {
    let Some(d) = dir() else { return };
    if std::env::var("FIREBIRD_IT_HOSTID_PREPARE").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "the prepare phase runs as root"
    );
    let fb = d.join("fb");
    std::fs::create_dir_all(&fb).unwrap();
    std::fs::set_permissions(&fb, std::fs::Permissions::from_mode(0o755)).unwrap();
    // R52 item 1: owner the server, named-user ACLs for the agent.
    let a = fb.join("acl");
    std::fs::create_dir(&a).unwrap();
    std::fs::write(a.join("audit.log"), b"").unwrap();
    std::fs::write(a.join("audit.log.1"), b"").unwrap();
    for (p, mode) in [
        (a.clone(), 0o700),
        (a.join("audit.log"), 0o600),
        (a.join("audit.log.1"), 0o600),
    ] {
        std::os::unix::fs::chown(&p, Some(SERVER), Some(SERVER)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    // log: u::rw,g::---,o::---,u:10001:r (mask r)
    let log = [
        (0x01, 6, U),
        (0x02, 4, AGENT),
        (0x04, 0, U),
        (0x10, 4, U),
        (0x20, 0, U),
    ];
    set_acl(&a.join("audit.log"), "system.posix_acl_access", &log);
    set_acl(&a.join("audit.log.1"), "system.posix_acl_access", &log);
    // directory: u::rwx,g::---,o::---,u:10001:rx (mask rx), and the
    // default u::rw,g::---,m::r,o::---,u:10001:r
    set_acl(
        &a,
        "system.posix_acl_access",
        &[
            (0x01, 7, U),
            (0x02, 5, AGENT),
            (0x04, 0, U),
            (0x10, 5, U),
            (0x20, 0, U),
        ],
    );
    set_acl(&a, "system.posix_acl_default", &log);
    // The earlier group layout: 2750 / 0640 with the agent's gid.
    let g = fb.join("group");
    std::fs::create_dir(&g).unwrap();
    std::fs::write(g.join("audit.log"), b"").unwrap();
    std::os::unix::fs::chown(&g, Some(SERVER), Some(AGENT)).unwrap();
    std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o2750)).unwrap();
    std::os::unix::fs::chown(g.join("audit.log"), Some(SERVER), Some(AGENT)).unwrap();
    std::fs::set_permissions(g.join("audit.log"), std::fs::Permissions::from_mode(0o640)).unwrap();
}

fn declared(d: &Path, passwd: &str) -> FirebirdHostIdentity {
    let h = d.join("host");
    FirebirdHostIdentity {
        passwd: h.join(passwd),
        group: h.join("group"),
        nsswitch: h.join("nsswitch.conf"),
        subuid: None,
        subgid: None,
        server_account: None,
        agent_account: None,
    }
}

/// Agent phase: every rule on the real mounts.
#[test]
fn checks() {
    let Some(d) = dir() else { return };
    if std::env::var("FIREBIRD_IT_HOSTID_PREPARE").as_deref() == Ok("1") {
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        AGENT,
        "the checks run as the agent image's uid"
    );
    // The host's own files, single-file read-only bind mounts: accepted.
    let good = declared(&d, "passwd");
    let identity = load_declared(&good).unwrap_or_else(|f| panic!("{}", f.reason()));
    assert!(!identity.users.is_empty());
    eprintln!(
        "[it] host identity: {} passwd lines, groups {}",
        identity.users.len(),
        if identity.groups.is_some() {
            "proven from the group file"
        } else {
            "open (another NSS source)"
        }
    );
    // The negative mounts (R52 item 2: an image file, `:rw`; R45).
    for (name, kind) in [
        ("rw-passwd", Kind::Mount),
        ("plain", Kind::Mount),
        ("stale", Kind::Links),
        ("link", Kind::NotReadable),
        ("owned", Kind::Owner),
        ("gw", Kind::Mode),
        ("missing", Kind::NotReadable),
    ] {
        assert_eq!(
            load_declared(&declared(&d, name)).unwrap_err(),
            Fail::Refused(Role::Passwd, kind),
            "{name}"
        );
        eprintln!("[it] host identity: {name} refused ({})", kind.as_str());
    }
    // A symbolic link in an ancestor of the declared path.
    let mut via = good.clone();
    via.passwd = d.join("hostlink/passwd");
    assert_eq!(
        load_declared(&via).unwrap_err(),
        Fail::Refused(Role::Passwd, Kind::NotReadable)
    );
    // The readers check with the declared files, as in a container: the
    // named-user ACL layout passes, the group layout does not.
    let in_container = Place {
        in_container: true,
        host_identity: Some(&good),
    };
    let acl_log = d.join("fb/acl/audit.log");
    assert_eq!(
        readers_check(&acl_log, Some((SERVER, SERVER)), Some(SERVER), in_container),
        Ok(()),
        "the dev layout's named-user ACLs"
    );
    let group_log = d.join("fb/group/audit.log");
    assert_eq!(
        readers_check(
            &group_log,
            Some((SERVER, SERVER)),
            Some(SERVER),
            in_container
        ),
        Err("log_readable_by_others".to_owned()),
        "the group layout"
    );
    // Without the block (R44 item 5) and with a refused file.
    let bare = Place {
        in_container: true,
        host_identity: None,
    };
    assert_eq!(
        readers_check(&acl_log, Some((SERVER, SERVER)), Some(SERVER), bare),
        Err("agent_in_container".to_owned())
    );
    let rw = declared(&d, "rw-passwd");
    assert_eq!(
        readers_check(
            &acl_log,
            Some((SERVER, SERVER)),
            Some(SERVER),
            Place {
                in_container: true,
                host_identity: Some(&rw),
            }
        ),
        Err("host_identity_refused (passwd: mount)".to_owned())
    );
    // R48 item 4: an agent running as an account of the host's passwd
    // file (the first user of uid 1000 or more) collides.
    if let Some(u) = identity
        .users
        .iter()
        .find(|u| u.uid >= 1000 && u.uid < 60_000)
    {
        assert_eq!(
            identity.uid_rules(SERVER, u.uid, Some((None, None))),
            Err(Fail::UidCollision)
        );
        eprintln!("[it] host identity: an agent as a host user's uid refused (uid_collision)");
    }
}
