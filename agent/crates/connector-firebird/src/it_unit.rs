//! The bare-host identity load and the readers check under the shipped
//! systemd unit (security review F1; `e2e/firebird-unit.sh`, run in the
//! `deb-install` legs of `.github/workflows/packaging.yml`).
//!
//! `deploy/deb/databastion-agent.service` has `RestrictSUIDSGID=yes`, so
//! systemd's seccomp filter answers `ENOSYS` to `openat2`; the Firebird
//! connector runs in the agent's process, so its identity files are opened
//! by `databastion_core::fs::open_no_links`'s component walk there. The
//! script starts this test binary as the unit's `ExecStart` (a drop-in
//! replaces `ExecStart`, `Restart`, `Environment` and the output only; every
//! sandbox property of the unit applies, its `SystemCallFilter` included).
//! Two phases, selected by `FIREBIRD_UNIT_CHECK`:
//!
//! - `prepare` (as root, before the unit starts): under
//!   `FIREBIRD_UNIT_CHECK_DIR`, the user guide's named-user ACL log layout
//!   (owner the server account, `FIREBIRD_UNIT_SERVER_UID` / `_GID`, read
//!   for the agent account, `FIREBIRD_UNIT_AGENT_UID`), and an `etc`
//!   directory of root-owned link chains and refused links;
//! - `check` (under the unit, as the agent's account): `openat2` answers
//!   `ENOSYS`; the host's own `/etc` files load under the production rules
//!   (no `host_identity_refused`); the readers check of the seeded log
//!   passes (no `audit.log_readable_by_others`, which `audit.rs` adds
//!   exactly when it fails); a root-owned link chain is followed, and a
//!   link of another owner, a link in an ancestor and a link out of the
//!   base are refused.
//!
//! Prints verdicts and closed reasons only, never a name or a line. Skipped
//! unless `FIREBIRD_UNIT_CHECK` is set. No server is needed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::fsread::{Place, readers_check};
use crate::host_identity::{ChainRules, Kind, OpenError, load_bare_host, open_bare_host};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn uid(name: &str) -> u32 {
    env(name).parse().unwrap()
}

fn phase() -> Option<String> {
    std::env::var("FIREBIRD_UNIT_CHECK").ok()
}

fn dir() -> PathBuf {
    PathBuf::from(env("FIREBIRD_UNIT_CHECK_DIR"))
}

const U: u32 = u32::MAX;

/// An ACL xattr (version 2, entries sorted by tag then id).
fn set_acl(p: &Path, name: &str, entries: &[(u16, u16, u32)]) {
    let mut b = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&perm.to_le_bytes());
        b.extend_from_slice(&id.to_le_bytes());
    }
    rustix::fs::setxattr(p, name, &b, rustix::fs::XattrFlags::empty())
        .unwrap_or_else(|e| panic!("setting an ACL: {e}"));
}

fn mode(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

/// Root phase: the log layout and the link chains.
#[test]
fn prepare() {
    if phase().as_deref() != Some("prepare") {
        eprintln!("skipped: FIREBIRD_UNIT_CHECK is not prepare (a phase of dev/firebird/it.sh)");
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "prepare runs as root"
    );
    let (server, server_gid, agent) = (
        uid("FIREBIRD_UNIT_SERVER_UID"),
        uid("FIREBIRD_UNIT_SERVER_GID"),
        uid("FIREBIRD_UNIT_AGENT_UID"),
    );
    let d = dir();
    // The user guide's layout: owner the server, named-user ACLs for the
    // agent, a default ACL for the next log file.
    let log_dir = d.join("log");
    std::fs::create_dir(&log_dir).unwrap();
    for f in ["audit.log", "audit.log.1"] {
        std::fs::write(log_dir.join(f), b"").unwrap();
    }
    let file_acl = [
        (0x01, 6, U),
        (0x02, 4, agent),
        (0x04, 0, U),
        (0x10, 4, U),
        (0x20, 0, U),
    ];
    for (p, m) in [
        (log_dir.clone(), 0o700),
        (log_dir.join("audit.log"), 0o600),
        (log_dir.join("audit.log.1"), 0o600),
    ] {
        std::os::unix::fs::chown(&p, Some(server), Some(server_gid)).unwrap();
        mode(&p, m);
    }
    set_acl(
        &log_dir.join("audit.log"),
        "system.posix_acl_access",
        &file_acl,
    );
    set_acl(
        &log_dir.join("audit.log.1"),
        "system.posix_acl_access",
        &file_acl,
    );
    set_acl(
        &log_dir,
        "system.posix_acl_access",
        &[
            (0x01, 7, U),
            (0x02, 5, agent),
            (0x04, 0, U),
            (0x10, 5, U),
            (0x20, 0, U),
        ],
    );
    set_acl(&log_dir, "system.posix_acl_default", &file_acl);
    // Link chains under a root-owned `etc` (R45 item 2, option (a)).
    let etc = d.join("etc");
    let real = etc.join("real");
    std::fs::create_dir_all(&real).unwrap();
    mode(&etc, 0o755);
    mode(&real, 0o755);
    std::fs::write(real.join("nsswitch.conf"), b"passwd: files\ngroup: files\n").unwrap();
    mode(&real.join("nsswitch.conf"), 0o644);
    std::os::unix::fs::symlink("real/nsswitch.conf", etc.join("nsswitch.conf")).unwrap();
    std::os::unix::fs::symlink(etc.join("nsswitch.conf"), etc.join("hop")).unwrap();
    std::os::unix::fs::symlink("real/nsswitch.conf", etc.join("foreign")).unwrap();
    std::os::unix::fs::lchown(etc.join("foreign"), Some(server), Some(server_gid)).unwrap();
    std::os::unix::fs::symlink("real", etc.join("alias")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", etc.join("out")).unwrap();
}

/// Under the unit: the answers a correct setup must give.
#[test]
fn check() {
    if phase().as_deref() != Some("check") {
        eprintln!("skipped: FIREBIRD_UNIT_CHECK is not check (a phase of dev/firebird/it.sh)");
        return;
    }
    let (server, server_gid) = (
        uid("FIREBIRD_UNIT_SERVER_UID"),
        uid("FIREBIRD_UNIT_SERVER_GID"),
    );
    let me = rustix::process::geteuid().as_raw();
    assert_ne!(me, 0, "the check runs as the unit's user");
    // The unit's filter: openat2 answers ENOSYS (RestrictSUIDSGID=yes).
    let r = rustix::fs::openat2(
        rustix::fs::CWD,
        "/",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::empty(),
    );
    assert_eq!(
        r.err(),
        Some(rustix::io::Errno::NOSYS),
        "openat2 is not refused with ENOSYS here: the component walk is not exercised"
    );
    eprintln!("[firebird-unit] openat2 ENOSYS: identity files opened by the component walk");
    // The host's own files, production rules (root-owned, under /etc).
    let identity = load_bare_host().unwrap_or_else(|f| panic!("{}", f.reason()));
    eprintln!(
        "[firebird-unit] bare host identity loaded: {} passwd line(s), groups {}",
        identity.users.len(),
        if identity.groups.is_some() {
            "proven from /etc/group"
        } else {
            "open (another NSS source on group:)"
        }
    );
    // The readers check of the seeded log, as audit.rs runs it on the bare
    // host (container detection forced off: this runs in a container).
    let log = dir().join("log/audit.log");
    let place = Place {
        in_container: false,
        host_identity: None,
    };
    if let Err(why) = readers_check(&log, Some((server, server_gid)), Some(server), place) {
        panic!("readers check: {why} (audit.log_readable_by_others)");
    }
    eprintln!("[firebird-unit] readers check passed on the seeded log (no readers note)");
    // The link rules under the walk, on root-owned chains.
    let etc = dir().join("etc");
    let rules = ChainRules {
        base: &etc,
        dir_owner: 0,
        link_owner: 0,
        file_owner: 0,
    };
    for n in ["nsswitch.conf", "hop"] {
        let (_, at) = open_bare_host(&etc.join(n), rules)
            .unwrap_or_else(|e| panic!("root-owned chain {n}: {e:?}"));
        assert_eq!(at, etc.join("real/nsswitch.conf"), "{n}");
    }
    for n in ["foreign", "alias/nsswitch.conf", "out"] {
        assert_eq!(
            open_bare_host(&etc.join(n), rules).unwrap_err(),
            OpenError::Refused(Kind::Links),
            "{n}"
        );
    }
    eprintln!(
        "[firebird-unit] root-owned link chains followed; a foreign link, an ancestor link and a link out of the base refused (links)"
    );
    eprintln!(
        "[firebird-unit] container detected: {} (informational; the bare-host path was run)",
        databastion_core::config::firebird::agent_in_container()
    );
    eprintln!("firebird-unit-check-ok");
}
