//! Tests of the identity files of the readers check (ADR-0060 refinement
//! of 2026-10-31, R52 item 3): one per refusal, with injected `statx`
//! facts, `mountinfo`, maps and file contents, and the kernel's own
//! answers where a test process can produce them.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use crate::host_identity::{
    ChainRules, Fail, HandleFacts, Identity, Kind, MountEntry, MountFacts, Nss, OpenError, Place,
    Ranges, Role, Source, SubFile, User, decode_octal, find_mount, identity_for_tests,
    in_systemd_range, is_identity_map, judge_handle, judge_mount, open_bare_host, open_no_links,
    parse_group, parse_mountinfo, parse_nsswitch, parse_passwd, parse_subid, read_proc, switched,
};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                      firebird:x:84:84:Firebird Database Owner:/opt/firebird:/sbin/nologin\n\
                      databastion:x:10001:10001::/var/lib/databastion:/usr/sbin/nologin\n\
                      eve:x:1002:1002:Eve,,,:/home/eve:/bin/bash\n";
const GROUP: &str = "root:x:0:\nfirebird:x:84:\ndatabastion:x:10001:\nstaff:x:50:eve\n";
const FILES: &str = "passwd: files\ngroup: files\n";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fb-hi-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn id_with(nss: &str, place: Place) -> Identity {
    identity_for_tests(PASSWD, GROUP, Some(nss), None, None, place).unwrap()
}

fn good_handle() -> HandleFacts {
    HandleFacts {
        regular: true,
        nlink: 1,
        uid: 0,
        mode: 0o100_644,
        names_handle: true,
        agent_can_write: false,
    }
}

fn good_mount() -> (MountFacts, Vec<MountEntry>) {
    (
        MountFacts {
            mnt_id: Some(812),
            mount_root: Some(true),
            fs_rdonly: true,
            unique_before: Some(0x1_0000_0321),
            unique_after: Some(0x1_0000_0321),
        },
        parse_mountinfo(
            b"500 400 0:52 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/x\n\
              812 500 254:1 /etc/passwd /run/databastion/host/passwd ro,nosuid,nodev,relatime - ext4 /dev/vda1 rw\n\
              813 500 254:1 /etc/group /run/databastion/host/gr\\040oup ro,relatime - ext4 /dev/vda1 rw\n",
        )
        .unwrap(),
    )
}

type HandleEdit = fn(&mut HandleFacts);
type MountEdit = fn(&mut MountFacts);

const DECLARED: &[u8] = b"/run/databastion/host/passwd";

// ---------------------------------------------------------------- files

/// R45 items 1, 3 and 4 on the handle's facts.
#[test]
fn handle_refusals() {
    assert_eq!(judge_handle(&good_handle()), Ok(()));
    let cases: [(HandleEdit, Kind); 8] = [
        (|f| f.regular = false, Kind::NotReadable),
        (|f| f.nlink = 2, Kind::Links),
        // A stale mount: the source renamed over, link count 0.
        (|f| f.nlink = 0, Kind::Links),
        (|f| f.names_handle = false, Kind::Changed),
        (|f| f.agent_can_write = true, Kind::Writable),
        (|f| f.uid = 1000, Kind::Owner),
        (|f| f.mode = 0o100_664, Kind::Mode),
        (|f| f.mode = 0o100_646, Kind::Mode),
    ];
    for (edit, kind) in cases {
        let mut f = good_handle();
        edit(&mut f);
        assert_eq!(judge_handle(&f), Err(kind), "{f:?}");
    }
}

/// R45 item 1 on the kernel: a symbolic link as the last component or in
/// an ancestor is refused by `openat2`; a missing file is told apart.
#[test]
fn symlinks_are_refused_anywhere_on_the_path() {
    let d = tmp("links");
    let file = d.join("passwd");
    std::fs::write(&file, PASSWD).unwrap();
    assert!(open_no_links(&file).is_ok());
    let link = d.join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_eq!(
        open_no_links(&link).unwrap_err(),
        OpenError::Refused(Kind::NotReadable)
    );
    let sub = d.join("real");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("group"), GROUP).unwrap();
    std::os::unix::fs::symlink(&sub, d.join("alias")).unwrap();
    assert_eq!(
        open_no_links(&d.join("alias/group")).unwrap_err(),
        OpenError::Refused(Kind::NotReadable)
    );
    assert_eq!(
        open_no_links(&d.join("missing")).unwrap_err(),
        OpenError::Missing
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Two hard links, seen on the handle of a real file.
#[test]
fn a_second_hard_link_is_seen_on_the_handle() {
    let d = tmp("hard");
    let file = d.join("group");
    std::fs::write(&file, GROUP).unwrap();
    std::fs::hard_link(&file, d.join("group2")).unwrap();
    let f = std::fs::File::from(open_no_links(&file).unwrap());
    let meta = f.metadata().unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(meta.nlink(), 2);
    let facts = HandleFacts {
        nlink: meta.nlink(),
        ..good_handle()
    };
    assert_eq!(judge_handle(&facts), Err(Kind::Links));
    let _ = std::fs::remove_dir_all(&d);
}

/// R45 item 2, option (a): a chain is followed under the base with links
/// of the expected owner in directories without a group or other write
/// bit; anything else is refused.
#[test]
fn bare_host_chains() {
    let d = tmp("chain");
    let me = rustix::process::geteuid().as_raw();
    let rules = ChainRules {
        base: &d,
        owner: me,
    };
    let real = d.join("authselect");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(real.join("nsswitch.conf"), FILES).unwrap();
    // Relative and absolute links, two hops.
    std::os::unix::fs::symlink("authselect/nsswitch.conf", d.join("nsswitch.conf")).unwrap();
    std::os::unix::fs::symlink(d.join("nsswitch.conf"), d.join("hop")).unwrap();
    let (_, at) = open_bare_host(&d.join("nsswitch.conf"), rules).unwrap();
    assert_eq!(at, real.join("nsswitch.conf"));
    let (_, at) = open_bare_host(&d.join("hop"), rules).unwrap();
    assert_eq!(at, real.join("nsswitch.conf"));
    // Out of the base, by `..` or absolute.
    let outside = std::env::temp_dir().join(format!("fb-hi-out-{}", std::process::id()));
    std::fs::write(&outside, FILES).unwrap();
    std::os::unix::fs::symlink(&outside, d.join("out")).unwrap();
    std::os::unix::fs::symlink("../x", d.join("up")).unwrap();
    for n in ["out", "up"] {
        assert_eq!(
            open_bare_host(&d.join(n), rules).unwrap_err(),
            OpenError::Refused(Kind::Links),
            "{n}"
        );
    }
    // A link of another owner.
    let other = ChainRules {
        base: &d,
        owner: me.wrapping_add(1),
    };
    assert_eq!(
        open_bare_host(&d.join("nsswitch.conf"), other).unwrap_err(),
        OpenError::Refused(Kind::Links)
    );
    // A link in a group-writable directory.
    let gw = d.join("gw");
    std::fs::create_dir(&gw).unwrap();
    std::fs::set_permissions(&gw, std::fs::Permissions::from_mode(0o775)).unwrap();
    std::os::unix::fs::symlink(real.join("nsswitch.conf"), gw.join("l")).unwrap();
    assert_eq!(
        open_bare_host(&gw.join("l"), rules).unwrap_err(),
        OpenError::Refused(Kind::Links)
    );
    // A link in an ancestor is never followed.
    std::os::unix::fs::symlink(&real, d.join("dirlink")).unwrap();
    assert_eq!(
        open_bare_host(&d.join("dirlink/nsswitch.conf"), rules).unwrap_err(),
        OpenError::Refused(Kind::Links)
    );
    // A loop ends.
    std::os::unix::fs::symlink("loop2", d.join("loop1")).unwrap();
    std::os::unix::fs::symlink("loop1", d.join("loop2")).unwrap();
    assert_eq!(
        open_bare_host(&d.join("loop1"), rules).unwrap_err(),
        OpenError::Refused(Kind::Links)
    );
    assert_eq!(
        open_bare_host(&d.join("missing"), rules).unwrap_err(),
        OpenError::Missing
    );
    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&d);
}

/// R45 item 2 and R49 item 3 on real files: the bare host's set read
/// under the rules (here a directory standing for `/etc`); a missing
/// `nsswitch.conf` fails with `host_identity_nss`, a missing `subuid`
/// means no range.
#[test]
fn bare_host_files_on_disk() {
    crate::fsread::allow_own_files_for_tests();
    let d = tmp("bare");
    let me = rustix::process::geteuid().as_raw();
    let rules = ChainRules {
        base: &d,
        owner: me,
    };
    for (n, c) in [("passwd", PASSWD), ("group", GROUP)] {
        std::fs::write(d.join(n), c).unwrap();
        std::fs::set_permissions(d.join(n), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let r = crate::host_identity::load_bare_host_under(&d, rules);
    if me == 0 {
        assert_eq!(r.unwrap_err(), Fail::Nss);
        std::fs::write(d.join("nsswitch.conf"), FILES).unwrap();
        let id = crate::host_identity::load_bare_host_under(&d, rules).unwrap();
        assert_eq!(id.sub_uid, Ranges::Known(Vec::new()));
        assert_eq!(id.users.len(), 4);
        std::fs::write(d.join("subuid"), "ubuntu:100000:65536\n").unwrap();
        let id = crate::host_identity::load_bare_host_under(&d, rules).unwrap();
        assert_eq!(id.sub_uid, Ranges::Known(vec![(100_000, 65_536)]));
        // Oversized.
        std::fs::write(d.join("group"), vec![b'a'; (4 << 20) + 1]).unwrap();
        assert_eq!(
            crate::host_identity::load_bare_host_under(&d, rules).unwrap_err(),
            Fail::Refused(Role::Group, Kind::TooLarge)
        );
    } else {
        // Owned by the test's user, not root.
        assert_eq!(r.unwrap_err(), Fail::Refused(Role::Passwd, Kind::Owner));
    }
    let _ = std::fs::remove_dir_all(&d);
}

// --------------------------------------------------------------- mounts

/// R45 item 5 with injected `statx` and `mountinfo` results.
#[test]
fn mount_refusals() {
    let (m, table) = good_mount();
    assert_eq!(judge_mount(&m, &table, DECLARED), Ok(()));
    // Without the unique id (older kernels): accepted on the mount id.
    let old = MountFacts {
        unique_before: None,
        unique_after: None,
        ..m
    };
    assert_eq!(judge_mount(&old, &table, DECLARED), Ok(()));
    let cases: [(MountEdit, &str); 6] = [
        (|f| f.mnt_id = None, "no STATX_MNT_ID"),
        (|f| f.mount_root = None, "no MOUNT_ROOT in the mask"),
        (|f| f.mount_root = Some(false), "not a mount root"),
        (|f| f.fs_rdonly = false, "read-write file system"),
        (
            |f| f.unique_after = Some(0x1_0000_0999),
            "unique id changed",
        ),
        (|f| f.unique_after = None, "unique id lost"),
    ];
    for (edit, what) in cases {
        let mut f = m;
        edit(&mut f);
        assert_eq!(
            judge_mount(&f, &table, DECLARED),
            Err(Kind::Mount),
            "{what}"
        );
    }
    // An entry without `ro` in its per-mount options (the super options
    // say `ro`: not enough).
    let rw = parse_mountinfo(
        b"812 500 254:1 /etc/passwd /run/databastion/host/passwd rw,relatime - ext4 /dev/vda1 ro\n",
    )
    .unwrap();
    assert_eq!(judge_mount(&m, &rw, DECLARED), Err(Kind::Mount));
    // The root mount.
    let root = MountFacts {
        mnt_id: Some(500),
        ..m
    };
    let ro_root = parse_mountinfo(b"500 400 0:52 / / ro - overlay overlay ro\n").unwrap();
    assert_eq!(judge_mount(&root, &ro_root, b"/"), Err(Kind::Mount));
    // A mount point that is not the declared path, byte for byte.
    assert_eq!(
        judge_mount(&m, &table, b"/run/databastion/host/passwd2"),
        Err(Kind::Mount)
    );
    assert_eq!(
        judge_mount(&m, &table, b"/run/databastion/host/"),
        Err(Kind::Mount)
    );
    // The escaped mount point is decoded before the comparison.
    let gr = MountFacts {
        mnt_id: Some(813),
        ..m
    };
    assert_eq!(
        judge_mount(&gr, &table, b"/run/databastion/host/gr oup"),
        Ok(())
    );
    // No entry with the id, or two.
    let missing = MountFacts {
        mnt_id: Some(9),
        ..m
    };
    assert_eq!(judge_mount(&missing, &table, DECLARED), Err(Kind::Mount));
    let twice = parse_mountinfo(
        b"812 500 254:1 / /run/databastion/host/passwd ro - ext4 /dev/vda1 rw\n\
          812 500 254:1 / /run/databastion/host/passwd ro - ext4 /dev/vda1 rw\n",
    )
    .unwrap();
    assert_eq!(judge_mount(&m, &twice, DECLARED), Err(Kind::Mount));
}

/// R45 item 5: escapes decoded, invalid ones refused, every line parsed,
/// the bound refusing the table.
#[test]
fn mountinfo_grammar_and_bound() {
    assert_eq!(
        decode_octal(b"/a\\040b\\011c\\012d\\134e").unwrap(),
        b"/a b\tc\nd\\e"
    );
    for bad in [&b"/a\\04"[..], b"/a\\", b"/a\\x41", b"/a\\400", b"/a\\8aa"] {
        assert!(decode_octal(bad).is_none(), "{bad:?}");
    }
    for bad in [
        &b"812 500 254:1 / /run/x\\9 ro - ext4 /dev/vda1 rw\n"[..],
        b"812 500 254:1 / /run/x ro ext4 /dev/vda1 rw\n",
        b"812 500 254:1 / /run/x - ext4 /dev/vda1 rw\n",
        b"x 500 254:1 / /run/x ro - ext4 /dev/vda1 rw\n",
        b"812 500 254:1 / /run/x ro - ext4 /dev/vda1\n",
        b"812  500 254:1 / /run/x ro - ext4 /dev/vda1 rw\n",
    ] {
        assert_eq!(
            parse_mountinfo(bad),
            Err(Kind::Mount),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // Optional fields before the separator.
    let t = parse_mountinfo(b"7 1 0:1 / /p ro shared:3 master:2 - tmpfs t ro\n").unwrap();
    assert_eq!(t.len(), 1);
    assert!(t[0].ro);
    // At the line bound: refused, never read as if complete.
    let line = "1 0 0:1 / /p ro - tmpfs t ro\n";
    let at_bound = line.repeat(65_536);
    assert_eq!(parse_mountinfo(at_bound.as_bytes()), Err(Kind::Mount));
    let under = line.repeat(65_535);
    assert!(parse_mountinfo(under.as_bytes()).is_ok());
}

/// R52 item 4: the mount-id lookup on the kernel's own table finds the
/// entry of a real handle's mount id (here the test directory's file
/// system, not a single-file mount, so the rules refuse it).
#[test]
fn mount_id_lookup_on_the_kernel_table() {
    let d = tmp("mntid");
    let file = d.join("passwd");
    std::fs::write(&file, PASSWD).unwrap();
    let fd = open_no_links(&file).unwrap();
    let sx = rustix::fs::statx(
        &fd,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    if sx.stx_mask & rustix::fs::StatxFlags::MNT_ID.bits() != 0 {
        let text = read_proc(
            "/proc/self/mountinfo",
            crate::host_identity::MOUNTINFO_BOUNDS,
        )
        .expect("procfs");
        let table = parse_mountinfo(&text).expect("the kernel's table parses");
        let e = find_mount(&table, sx.stx_mnt_id).expect("the handle's mount");
        assert_eq!(e.id, sx.stx_mnt_id);
        // A plain file is not the root of its own mount.
        assert!(
            !sx.stx_attributes
                .contains(rustix::fs::StatxAttributes::MOUNT_ROOT)
        );
    }
    // A `/proc` path off procfs is refused (N3).
    assert!(
        read_proc(
            file.to_str().unwrap(),
            crate::host_identity::MOUNTINFO_BOUNDS
        )
        .is_none()
    );
    let _ = std::fs::remove_dir_all(&d);
}

proptest! {
    /// R52 item 4: the entry found for a mount id is the only entry with
    /// that id, or none, whatever the table holds.
    #[test]
    fn mount_lookup_is_the_entry_or_none(
        ids in proptest::collection::vec(0u64..8, 0..12),
        want in 0u64..8,
    ) {
        let table: Vec<MountEntry> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| MountEntry {
                id: *id,
                mount_point: format!("/m{i}").into_bytes(),
                ro: i % 2 == 0,
            })
            .collect();
        let n = table.iter().filter(|e| e.id == want).count();
        match find_mount(&table, want) {
            Some(e) => {
                prop_assert_eq!(e.id, want);
                prop_assert_eq!(n, 1);
            }
            None => prop_assert!(n != 1),
        }
    }

    /// The parsers never panic, and the mountinfo text the agent would
    /// accept round-trips the mount ids.
    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_passwd(&data);
        let _ = parse_group(&data);
        let _ = parse_subid(&data);
        let _ = parse_nsswitch(&data);
        if let Ok(t) = parse_mountinfo(&data) {
            for e in &t {
                prop_assert!(find_mount(&t, e.id).is_none_or(|f| f.id == e.id));
            }
        }
    }
}

// -------------------------------------------------------------- parsing

/// R45 item 7: the strict grammars, every malformed case.
#[test]
fn malformed_files() {
    let users = parse_passwd(PASSWD.as_bytes()).unwrap();
    assert_eq!(users.len(), 4);
    assert_eq!(users[1].name, b"firebird");
    assert_eq!((users[1].uid, users[1].gid), (84, 84));
    // Empty lines skipped.
    assert_eq!(
        parse_passwd(b"\nroot:x:0:0::/:/bin/sh\n\n").unwrap().len(),
        1
    );
    for bad in [
        "# comment\n",
        "root:x:0:0::/:/bin/sh\n#x:x:1:1::/:/bin/sh\n",
        "ro ot:x:0:0::/:/bin/sh\n",
        "root\t:x:0:0::/:/bin/sh\n",
        "+::::::\n",
        "+nisuser:x:1:1::/:/bin/sh\n",
        "-eve:x:1:1::/:/bin/sh\n",
        "root:x:0:0::/\n",
        "root:x:0:0::/:/bin/sh:extra\n",
        "root:x:-1:0::/:/bin/sh\n",
        "root:x:0x1:0::/:/bin/sh\n",
        "root:x:4294967295:0::/:/bin/sh\n",
        "root:x:0: 0::/:/bin/sh\n",
        "root:x::0::/:/bin/sh\n",
        " \n",
    ] {
        assert_eq!(
            parse_passwd(bad.as_bytes()),
            Err(Kind::Malformed),
            "{bad:?}"
        );
    }
    assert_eq!(
        parse_passwd(b"a:x:4294967294:0::/:/x\n").unwrap()[0].uid,
        u32::MAX - 1
    );
    let groups = parse_group(GROUP.as_bytes()).unwrap();
    assert_eq!(groups[3].members, vec![b"eve".to_vec()]);
    assert_eq!(parse_group(b"g:x:5:a,,b,\n").unwrap()[0].members.len(), 2);
    for bad in [
        "# c\n",
        "g x:x:5:\n",
        "g:x:5:a, b\n",
        "g:x:5:a,b c\n",
        "+:::\n",
        "-g:x:5:\n",
        "g:x:5\n",
        "g:x:5::\n",
        "g:x:five:\n",
    ] {
        assert_eq!(parse_group(bad.as_bytes()), Err(Kind::Malformed), "{bad:?}");
    }
    assert_eq!(
        parse_subid(b"ubuntu:100000:65536\n1000:165536:65536\n").unwrap(),
        vec![(100_000, 65_536), (165_536, 65_536)]
    );
    for bad in [
        "ubuntu:100000\n",
        "ubuntu:1e5:1\n",
        "# x\n",
        "u:1:2:3\n",
        "u :1:2\n",
    ] {
        assert_eq!(parse_subid(bad.as_bytes()), Err(Kind::Malformed), "{bad:?}");
    }
    // nsswitch: comments, action items, exact names, duplicates.
    let n = parse_nsswitch(
        b"# Debian\npasswd:  files systemd # trailing\ngroup: files [NOTFOUND=return] ldap\n\
          initgroups: files [ SUCCESS=merge ] sss\nhosts: files dns\n",
    )
    .unwrap();
    assert_eq!(n.passwd, Some(vec![b"files".to_vec(), b"systemd".to_vec()]));
    assert_eq!(n.group, Some(vec![b"files".to_vec(), b"ldap".to_vec()]));
    assert_eq!(n.initgroups, Some(vec![b"files".to_vec(), b"sss".to_vec()]));
    for bad in [
        "passwd: files\npasswd: files\n",
        "passwd files\n",
        "passwd:\n",
        "passwd: files [NOTFOUND=return\n",
        "passwd: files [a=[b]]\n",
        "passwd: files [NOTFOUND=return]sss systemd]\n",
        "passwd: files\ngroup: files [NOTFOUND=return]ldap x]\n",
        "passwd: files [ NOTFOUND=return ]sss\n",
        "passwd: files [NOTFOUND=return] ]\n",
        "passwd: files sss]\n",
        "pass wd: files\n",
        "passwd: fi/les\n",
    ] {
        assert_eq!(
            parse_nsswitch(bad.as_bytes()),
            Err(Kind::Malformed),
            "{bad:?}"
        );
    }
    // Case-different names are other names (not `passwd:`, not `files`).
    let n = parse_nsswitch(b"Passwd: files\npasswd: Files\ngroup: files\n").unwrap();
    assert_eq!(n.passwd, Some(vec![b"Files".to_vec()]));
    assert_eq!(
        identity_for_tests(
            PASSWD,
            GROUP,
            Some("passwd: Files\ngroup: files\n"),
            None,
            None,
            Place::BareHost
        )
        .unwrap_err(),
        Fail::Nss
    );
    // Line bounds.
    let many = "a:x:1:1::/:/x\n".repeat(65_537);
    assert_eq!(parse_passwd(many.as_bytes()), Err(Kind::TooLarge));
    let ok = "a:x:1:1::/:/x\n".repeat(65_536);
    assert!(parse_passwd(ok.as_bytes()).is_ok());
}

/// N2: the GECOS field and the other dropped fields are never kept.
#[test]
fn passwd_keeps_three_fields_only() {
    let users =
        parse_passwd(b"eve:secret-marker:1002:1002:Eve Marker,room 7:/home/eve:/bin/sh\n").unwrap();
    let dbg = format!("{users:?}");
    assert!(!dbg.contains("Marker") && !dbg.contains("eve") && !dbg.contains("secret"));
    assert_eq!(
        users,
        vec![User {
            name: b"eve".to_vec(),
            uid: 1002,
            gid: 1002
        }]
    );
}

// ------------------------------------------------------------------ NSS

/// R47: the accepted sources, groups opened by other sources, the
/// failure on `passwd:` on the bare host as in a container.
#[test]
fn nss_rules() {
    let allowed = |u: u32| u == 0 || u == 84;
    // Missing (or refused on the bare host): `host_identity_nss`.
    assert_eq!(
        identity_for_tests(PASSWD, GROUP, None, None, None, Place::BareHost).unwrap_err(),
        Fail::Nss
    );
    assert_eq!(
        identity_for_tests(
            PASSWD,
            GROUP,
            Some("passwd: files [x\n"),
            None,
            None,
            Place::BareHost
        )
        .unwrap_err(),
        Fail::Nss
    );
    assert_eq!(
        identity_for_tests(
            PASSWD,
            GROUP,
            Some("passwd: files [x\n"),
            None,
            None,
            Place::Container
        )
        .unwrap_err(),
        Fail::Refused(Role::Nsswitch, Kind::Malformed)
    );
    // No `passwd:` line, another passwd source: fails everywhere.
    for (nss, place) in [
        ("group: files\n", Place::BareHost),
        ("passwd: files ldap\ngroup: files\n", Place::BareHost),
        ("passwd: sss files\ngroup: files\n", Place::Container),
        ("passwd: compat\ngroup: files\n", Place::BareHost),
    ] {
        assert_eq!(
            identity_for_tests(PASSWD, GROUP, Some(nss), None, None, place).unwrap_err(),
            Fail::Nss,
            "{nss}"
        );
    }
    // `systemd` on passwd: accepted; groups proven with `files` only.
    let id = id_with("passwd: files systemd\ngroup: files\n", Place::BareHost);
    assert!(id.groups.is_some());
    assert!(!id.group_open(84, &allowed));
    assert!(id.group_open(50, &allowed));
    // No group line, `systemd`, `ldap` or `sss` on group or initgroups
    // only: every group open, uids still compared by number.
    for nss in [
        "passwd: files\n",
        "passwd: files\ngroup: files systemd\n",
        "passwd: files\ngroup: files ldap\n",
        "passwd: files\ngroup: files\ninitgroups: files sss\n",
        "passwd: files\ngroup: files [NOTFOUND=return] sss\n",
    ] {
        let id = id_with(nss, Place::BareHost);
        assert!(id.groups.is_none(), "{nss}");
        assert!(id.group_open(84, &allowed), "{nss}");
    }
    // Action items alone are skipped.
    let id = id_with(
        "passwd: files [NOTFOUND=return]\ngroup: files [!UNAVAIL=return]\ninitgroups: files\n",
        Place::BareHost,
    );
    assert!(id.groups.is_some());
    // A `subid:` line with another source: every id of 100000 or more.
    let id = identity_for_tests(
        PASSWD,
        GROUP,
        Some("passwd: files\ngroup: files\nsubid: sss\n"),
        Some("u:200000:10\n"),
        None,
        Place::BareHost,
    )
    .unwrap();
    assert_eq!(id.sub_uid, Ranges::Unprovable);
    assert_eq!(id.sub_gid, Ranges::Unprovable);
    let id = identity_for_tests(
        PASSWD,
        GROUP,
        Some("passwd: files\ngroup: files\nsubid: files\n"),
        Some("u:200000:10\n"),
        None,
        Place::BareHost,
    )
    .unwrap();
    assert_eq!(id.sub_uid, Ranges::Known(vec![(200_000, 10)]));
    assert_eq!(id.sub_gid, Ranges::Known(Vec::new()));
}

// --------------------------------------------------------------- maps

/// R46: only the identity map of the initial user namespace.
#[test]
fn user_namespace_maps() {
    assert!(is_identity_map(b"         0          0 4294967295\n"));
    for bad in [
        &b"         0     100000      65536\n"[..],
        b"0 0 4294967295\n1 2 3\n",
        b"0 0 4294967294\n",
        b"",
        b"\xff",
    ] {
        assert!(!is_identity_map(bad), "{bad:?}");
    }
}

// ----------------------------------------------------------------- uids

/// R48 items 3, 4 and 4a.
#[test]
fn uid_rules() {
    let id = id_with(FILES, Place::Container);
    let both = |s: Option<&'static str>, a: Option<&'static str>| Some((s, a));
    // Absent from the passwd file.
    assert_eq!(id.uid_rules(85, 10_002, both(None, None)), Ok(()));
    // Present only under the declared names.
    assert_eq!(
        id.uid_rules(84, 10_001, both(Some("firebird"), Some("databastion"))),
        Ok(())
    );
    // Present under an undeclared name, or no name declared.
    assert_eq!(
        id.uid_rules(84, 10_001, both(Some("fb"), Some("databastion"))),
        Err(Fail::UidCollision)
    );
    assert_eq!(
        id.uid_rules(84, 10_001, both(None, Some("databastion"))),
        Err(Fail::UidCollision)
    );
    assert_eq!(
        id.uid_rules(85, 1002, both(None, None)),
        Err(Fail::UidCollision)
    );
    // Under two names (duplicate lines): every line must carry the name.
    let dup = identity_for_tests(
        &format!("{PASSWD}fb2:x:84:84::/:/sbin/nologin\n"),
        GROUP,
        Some(FILES),
        None,
        None,
        Place::Container,
    )
    .unwrap();
    assert_eq!(
        dup.uid_rules(84, 10_001, both(Some("firebird"), Some("databastion"))),
        Err(Fail::UidCollision)
    );
    // Item 4 does not apply on the bare host.
    let bare = id_with(FILES, Place::BareHost);
    assert_eq!(bare.uid_rules(84, 1002, None), Ok(()));
    // Item 3: the reserved uids, everywhere, for either account.
    for r in [65_534, 4_294_967_294, 4_294_967_295] {
        assert_eq!(
            bare.uid_rules(r, 1002, None),
            Err(Fail::UidCollision),
            "{r}"
        );
        assert_eq!(bare.uid_rules(84, r, None), Err(Fail::UidCollision), "{r}");
    }
    // Item 4a: each systemd range, everywhere.
    for u in [
        60_001,
        60_513,
        61_184,
        65_519,
        524_288,
        1_879_048_191,
        2_147_352_576,
        2_147_418_111,
    ] {
        assert!(in_systemd_range(u), "{u}");
        assert_eq!(
            bare.uid_rules(u, 1002, None),
            Err(Fail::UidCollision),
            "{u}"
        );
        assert_eq!(bare.uid_rules(84, u, None), Err(Fail::UidCollision), "{u}");
    }
    for u in [60_000, 60_514, 61_183, 65_520, 524_287, 1_879_048_192] {
        assert!(!in_systemd_range(u), "{u}");
    }
    // Subordinate ranges: with the file, only inside its ranges; without
    // it in a container, every id of 100000 or more; on the bare host, a
    // missing file means none.
    let with_sub = identity_for_tests(
        PASSWD,
        GROUP,
        Some(FILES),
        Some("ubuntu:100000:65536\n"),
        Some("ubuntu:100000:65536\n"),
        Place::Container,
    )
    .unwrap();
    assert_eq!(
        with_sub.uid_rules(100_000, 10_001, both(None, Some("databastion"))),
        Err(Fail::UidCollision)
    );
    assert_eq!(
        with_sub.uid_rules(165_535, 10_001, both(None, Some("databastion"))),
        Err(Fail::UidCollision)
    );
    assert_eq!(
        with_sub.uid_rules(165_536, 10_001, both(None, Some("databastion"))),
        Ok(())
    );
    assert_eq!(
        id.uid_rules(165_536, 10_001, both(None, Some("databastion"))),
        Err(Fail::UidCollision)
    );
    assert_eq!(bare.uid_rules(165_536, 1002, None), Ok(()));
    // Root is allowed as the server's uid (peer_uid_root).
    assert_eq!(
        id.uid_rules(0, 10_001, both(None, Some("databastion"))),
        Ok(())
    );
    // A gid that grants read inside a range is open.
    let allowed = |u: u32| u == 0 || u == 84;
    let g = identity_for_tests(
        PASSWD,
        "big:x:200000:\nsd:x:61200:\nok:x:900:\n",
        Some(FILES),
        Some("u:1:1\n"),
        Some("u:200000:1\n"),
        Place::Container,
    )
    .unwrap();
    assert!(g.group_open(200_000, &allowed));
    assert!(g.group_open(61_200, &allowed));
    assert!(!g.group_open(900, &allowed));
    let nosub = identity_for_tests(
        PASSWD,
        "big:x:300000:\n",
        Some(FILES),
        None,
        None,
        Place::Container,
    )
    .unwrap();
    assert!(nosub.group_open(300_000, &allowed));
}

// ---------------------------------------------------------------- other

/// R48 item 2: duplicate group and passwd lines united; a member with no
/// passwd line, or a gid with no line, is open.
#[test]
fn duplicates_are_united() {
    let allowed = |u: u32| u == 0 || u == 84 || u == 10_001;
    let id = identity_for_tests(
        "fb:x:84:84::/:/x\nagent:x:10001:10001::/:/x\nagent:x:1002:1002::/:/x\n",
        "audit:x:900:fb\naudit:x:900:agent\nempty:x:901:\nghost:x:902:nobody_here\n",
        Some(FILES),
        None,
        None,
        Place::BareHost,
    )
    .unwrap();
    // `agent` names uid 10001 and uid 1002: the second is not allowed.
    assert!(id.group_open(900, &allowed));
    assert!(!id.group_open(901, &allowed));
    assert!(id.group_open(902, &allowed));
    assert!(id.group_open(903, &allowed));
    // Primary members count.
    let p = identity_for_tests(
        "fb:x:84:84::/:/x\neve:x:1002:84::/:/x\n",
        "firebird:x:84:\n",
        Some(FILES),
        None,
        None,
        Place::BareHost,
    )
    .unwrap();
    assert!(p.group_open(84, &allowed));
}

/// R49: the files are read at every check; a change between two checks
/// is taken as it is, not an error.
#[test]
fn a_file_changed_between_two_checks() {
    let allowed = |u: u32| u == 0 || u == 84;
    let first = identity_for_tests(
        PASSWD,
        "audit:x:900:firebird\n",
        Some(FILES),
        None,
        None,
        Place::BareHost,
    )
    .unwrap();
    assert!(!first.group_open(900, &allowed));
    let second = identity_for_tests(
        PASSWD,
        "audit:x:900:firebird,eve\n",
        Some(FILES),
        None,
        None,
        Place::BareHost,
    )
    .unwrap();
    assert!(second.group_open(900, &allowed));
}

/// R44 item 6 (N7): one line when the source switches, none otherwise.
#[test]
fn the_source_switch_line() {
    assert_eq!(Source::of(false, false), Some(Source::HostFiles));
    assert_eq!(Source::of(true, true), Some(Source::DeclaredFiles));
    assert_eq!(Source::of(true, false), None);
    assert_eq!(Source::of(false, true), None);
    assert_eq!(
        switched(None, Some(Source::HostFiles)),
        Some(Source::HostFiles)
    );
    assert_eq!(
        switched(Some(Source::HostFiles), Some(Source::HostFiles)),
        None
    );
    assert_eq!(
        switched(Some(Source::HostFiles), Some(Source::DeclaredFiles)),
        Some(Source::DeclaredFiles)
    );
    assert_eq!(switched(Some(Source::DeclaredFiles), None), None);
    assert_eq!(Source::DeclaredFiles.as_str(), "declared_files");
}

/// The local detail names the reason and the kind, never a path.
#[test]
fn reasons_name_no_path() {
    assert_eq!(
        Fail::Refused(Role::Passwd, Kind::Mount).reason(),
        "host_identity_refused (passwd: mount)"
    );
    assert_eq!(Fail::Nss.reason(), "host_identity_nss");
    assert_eq!(Fail::UserNamespace.reason(), "user_namespace");
    assert_eq!(Fail::UidCollision.reason(), "uid_collision");
    let _ = (SubFile::Absent, Nss::default(), Path::new("/"));
}

/// R45 item 6: files at their line bounds are judged in one pass (a group
/// of 60 000 members over 65 000 passwd lines).
#[test]
fn a_large_group_is_judged_in_one_pass() {
    let passwd: String = (0..65_000u32)
        .map(|i| format!("u{i}:x:{}:{}::/:/x\n", 2000 + i, 2000 + i))
        .collect();
    let members: Vec<String> = (0..60_000u32).map(|i| format!("u{i}")).collect();
    let group = format!("big:x:900:{}\n", members.join(","));
    let id = identity_for_tests(&passwd, &group, Some(FILES), None, None, Place::BareHost).unwrap();
    let t = std::time::Instant::now();
    assert!(id.group_open(900, &|u| u == 0));
    assert!(!id.group_open(900, &|u| u < 70_000));
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t.elapsed()
    );
}
