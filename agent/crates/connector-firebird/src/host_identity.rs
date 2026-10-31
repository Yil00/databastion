//! The identity files of the readers check (ADR-0060 refinement of
//! 2026-10-31, R43 to R50): the host's passwd, group, NSS configuration
//! and subordinate id files, read at every check under the file rules.
//! Blocking I/O: call from a blocking thread.
//!
//! - **In a container** (`firebird.audit.host_identity`, R44): each
//!   declared file is opened with `openat2` and `RESOLVE_NO_SYMLINKS |
//!   RESOLVE_NO_MAGICLINKS`, checked on its handle (a regular file with
//!   one hard link, the path still naming it, not writable by the agent,
//!   owned by uid 0, no group or other write bit) and must be the root of
//!   its own read-only bind mount, found by the handle's mount id in
//!   `/proc/self/mountinfo` (R45). `/proc/self/uid_map` and `gid_map`
//!   must be the identity map (R46).
//! - **On the bare host**: `/etc/passwd`, `/etc/group`,
//!   `/etc/nsswitch.conf`, `/etc/subuid` and `/etc/subgid`, under the
//!   same handle rules; a symbolic link chain is followed only when every
//!   link is owned by uid 0 in a root-owned directory that is not group-
//!   or other-writable, and stays under `/etc` (R45 item 2, option (a)).
//! - **Strict grammars** (R45 item 7) and bounds (R45 item 6, R49): only
//!   the name, uid and gid of a passwd line are kept; the content stays
//!   in memory for the check only (zeroized), never logged nor sent.
//! - **NSS** (R47): `files` on every line and `systemd` on `passwd:`
//!   only; another source on `group:` or `initgroups:` opens every group
//!   that grants read, on `passwd:` it fails the check
//!   (`host_identity_nss`), on `subid:` it makes every id of 100000 or
//!   more unprovable.
//! - **Uids** (R48 items 3, 4 and 4a): 65534, 4294967294 and 4294967295
//!   refused as the server's or the agent's uid; those uids and every gid
//!   that grants read outside the subordinate and systemd ranges; in a
//!   container, the two uids absent from the declared passwd file or only
//!   under the declared account names.
//!
//! No path or file content is logged or returned in an error: the
//! reasons are closed kinds.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use databastion_core::config::firebird::FirebirdHostIdentity;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, ResolveFlags, StatVfsMountFlags, StatxFlags};
use zeroize::Zeroizing;

/// Why a declared (or bare-host) identity file is refused (R45; the
/// local detail names the kind, never the path or the content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    NotReadable,
    Links,
    Changed,
    Writable,
    Owner,
    Mode,
    Mount,
    TooLarge,
    Malformed,
    NotInContainer,
}

impl Kind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotReadable => "not_readable",
            Self::Links => "links",
            Self::Changed => "changed",
            Self::Writable => "writable",
            Self::Owner => "owner",
            Self::Mode => "mode",
            Self::Mount => "mount",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::NotInContainer => "not_in_container",
        }
    }
}

/// Which file a refusal is about (a role, never a path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Passwd,
    Group,
    Nsswitch,
    Subuid,
    Subgid,
    Mountinfo,
    Block,
}

impl Role {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Passwd => "passwd",
            Self::Group => "group",
            Self::Nsswitch => "nsswitch",
            Self::Subuid => "subuid",
            Self::Subgid => "subgid",
            Self::Mountinfo => "mountinfo",
            Self::Block => "host_identity",
        }
    }
}

/// Why the identity part of the readers check fails (R44 to R48).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
    /// `host_identity_refused` with the file and the kind (R44, R45).
    Refused(Role, Kind),
    /// `host_identity_nss` (R47 item 3).
    Nss,
    /// `user_namespace` (R46).
    UserNamespace,
    /// `uid_collision` (R48 items 3, 4 and 4a).
    UidCollision,
}

impl Fail {
    /// The local detail: the reason, then the file and the kind.
    pub(crate) fn reason(self) -> String {
        match self {
            Self::Refused(role, kind) => {
                format!(
                    "host_identity_refused ({}: {})",
                    role.as_str(),
                    kind.as_str()
                )
            }
            Self::Nss => "host_identity_nss".to_owned(),
            Self::UserNamespace => "user_namespace".to_owned(),
            Self::UidCollision => "uid_collision".to_owned(),
        }
    }
}

/// The size and line bounds of a file (R45 item 6).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    pub(crate) bytes: usize,
    pub(crate) lines: usize,
}

pub(crate) const PASSWD_BOUNDS: Bounds = Bounds {
    bytes: 4 << 20,
    lines: 65_536,
};
pub(crate) const GROUP_BOUNDS: Bounds = PASSWD_BOUNDS;
pub(crate) const SUBID_BOUNDS: Bounds = Bounds {
    bytes: 1 << 20,
    lines: 65_536,
};
pub(crate) const NSSWITCH_BOUNDS: Bounds = Bounds {
    bytes: 64 << 10,
    lines: 65_536,
};
/// `/proc/self/mountinfo` (R45 item 5): reaching either bound refuses.
pub(crate) const MOUNTINFO_BOUNDS: Bounds = Bounds {
    bytes: 16 << 20,
    lines: 65_536,
};
/// `/proc/self/uid_map` and `gid_map` (R46 item 1; the kernel allows 340
/// extents).
const MAP_BOUNDS: Bounds = Bounds {
    bytes: 64 << 10,
    lines: 512,
};

/// The uids never accepted as the server's or the agent's (R48 item 3):
/// the overflow uid and the two invalid ones.
pub(crate) const RESERVED_UIDS: [u32; 3] = [65_534, 4_294_967_294, 4_294_967_295];

/// systemd's id ranges (R48 item 4a): homed users, dynamic users,
/// container users and the foreign range.
pub(crate) const SYSTEMD_RANGES: [(u64, u64); 4] = [
    (60_001, 60_513),
    (61_184, 65_519),
    (524_288, 1_879_048_191),
    (2_147_352_576, 2_147_418_111),
];

/// Without the subordinate id files, every id of this or more is treated
/// as inside a subordinate range (R48 item 4a).
pub(crate) const SUBORDINATE_FLOOR: u64 = 100_000;

// ---------------------------------------------------------------- parsers

/// The lines of `b`, at most `max` of them (more is `too_large`). A final
/// newline ends the last line.
fn lines(b: &[u8], max: usize) -> Result<Vec<&[u8]>, Kind> {
    let b = b.strip_suffix(b"\n").unwrap_or(b);
    if b.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<&[u8]> = Vec::new();
    for l in b.split(|c| *c == b'\n') {
        if out.len() == max {
            return Err(Kind::TooLarge);
        }
        out.push(l);
    }
    Ok(out)
}

/// A decimal number (ASCII digits only, no sign), at most `max`.
fn dec(s: &[u8], max: u64) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: u64 = 0;
    for d in s {
        n = n.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
    }
    (n <= max).then_some(n)
}

/// A uid or gid of a passwd or group line: below 2^32 − 1.
fn id(s: &[u8]) -> Option<u32> {
    dec(s, u64::from(u32::MAX - 1)).and_then(|n| u32::try_from(n).ok())
}

/// A name field: not empty, no whitespace, not a comment or a NIS compat
/// entry.
fn name_ok(s: &[u8]) -> bool {
    !s.is_empty() && !matches!(s[0], b'#' | b'+' | b'-') && !s.iter().any(u8::is_ascii_whitespace)
}

/// One passwd line, fields 1, 3 and 4 only (R45 item 7, N2: the GECOS
/// field and the others are dropped at parse and never stored).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct User {
    pub(crate) name: Vec<u8>,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

/// A passwd file (R45 item 7): 7 fields, decimal uid and gid; a comment,
/// whitespace in the name, a compat line or any other non-empty line that
/// does not parse is `malformed`; empty lines are skipped.
pub(crate) fn parse_passwd(b: &[u8]) -> Result<Vec<User>, Kind> {
    let mut out = Vec::new();
    for l in lines(b, PASSWD_BOUNDS.lines)? {
        if l.is_empty() {
            continue;
        }
        let f: Vec<&[u8]> = l.split(|c| *c == b':').collect();
        if f.len() != 7 || !name_ok(f[0]) {
            return Err(Kind::Malformed);
        }
        let (Some(uid), Some(gid)) = (id(f[2]), id(f[3])) else {
            return Err(Kind::Malformed);
        };
        out.push(User {
            name: f[0].to_vec(),
            uid,
            gid,
        });
    }
    Ok(out)
}

/// One group line: its gid and member names (the group name is checked
/// and dropped).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Group {
    pub(crate) gid: u32,
    pub(crate) members: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("gid", &self.gid)
            .field("members", &self.members.len())
            .finish()
    }
}

/// A group file (R45 item 7): 4 fields with a decimal gid; a comment,
/// whitespace in the name or a member name, a compat line or any other
/// non-empty line that does not parse is `malformed`.
pub(crate) fn parse_group(b: &[u8]) -> Result<Vec<Group>, Kind> {
    let mut out = Vec::new();
    for l in lines(b, GROUP_BOUNDS.lines)? {
        if l.is_empty() {
            continue;
        }
        let f: Vec<&[u8]> = l.split(|c| *c == b':').collect();
        if f.len() != 4 || !name_ok(f[0]) {
            return Err(Kind::Malformed);
        }
        let Some(gid) = id(f[2]) else {
            return Err(Kind::Malformed);
        };
        let mut members = Vec::new();
        for m in f[3].split(|c| *c == b',').filter(|m| !m.is_empty()) {
            if m.iter().any(u8::is_ascii_whitespace) {
                return Err(Kind::Malformed);
            }
            members.push(m.to_vec());
        }
        out.push(Group { gid, members });
    }
    Ok(out)
}

/// A subordinate id file (R45 item 7): `name:start:count`, decimal; the
/// ranges `(start, count)`, names dropped.
pub(crate) fn parse_subid(b: &[u8]) -> Result<Vec<(u64, u64)>, Kind> {
    let mut out = Vec::new();
    for l in lines(b, SUBID_BOUNDS.lines)? {
        if l.is_empty() {
            continue;
        }
        let f: Vec<&[u8]> = l.split(|c| *c == b':').collect();
        if f.len() != 3 || !name_ok(f[0]) {
            return Err(Kind::Malformed);
        }
        let (Some(start), Some(count)) = (dec(f[1], u64::MAX), dec(f[2], u64::MAX)) else {
            return Err(Kind::Malformed);
        };
        out.push((start, count));
    }
    Ok(out)
}

/// The NSS lines the readers check reads (R47 item 1): the sources of
/// each database, action items skipped; `None` without a line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Nss {
    pub(crate) passwd: Option<Vec<Vec<u8>>>,
    pub(crate) group: Option<Vec<Vec<u8>>>,
    pub(crate) initgroups: Option<Vec<Vec<u8>>>,
    pub(crate) subid: Option<Vec<Vec<u8>>>,
}

/// An `nsswitch.conf` (R45 item 7): `#` comments stripped to the end of
/// the line; a database line is `<name>:` followed by sources and
/// bracketed action items; names compared exactly; a database named on
/// two lines, an unclosed action item, a line without `:` or without a
/// source is `malformed`.
pub(crate) fn parse_nsswitch(b: &[u8]) -> Result<Nss, Kind> {
    let mut nss = Nss::default();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for raw in lines(b, NSSWITCH_BOUNDS.lines)? {
        let l = raw.split(|c| *c == b'#').next().unwrap_or_default();
        let l = l.trim_ascii();
        if l.is_empty() {
            continue;
        }
        let Some(colon) = l.iter().position(|c| *c == b':') else {
            return Err(Kind::Malformed);
        };
        let db = &l[..colon];
        if db.is_empty() || db.iter().any(u8::is_ascii_whitespace) {
            return Err(Kind::Malformed);
        }
        if seen.iter().any(|s| s == db) {
            return Err(Kind::Malformed);
        }
        seen.push(db.to_vec());
        let mut sources = Vec::new();
        let mut in_action = false;
        for tok in l[colon + 1..]
            .split(u8::is_ascii_whitespace)
            .filter(|t| !t.is_empty())
        {
            // An action item: `[` only as a token's first byte, `]` only as
            // its last, nothing after `]` (security review L1: a source
            // glued after `]` is never hidden in an item).
            let opens = tok.first() == Some(&b'[');
            if opens && in_action {
                return Err(Kind::Malformed);
            }
            if opens || in_action {
                let body = if opens { &tok[1..] } else { tok };
                if body.contains(&b'[') {
                    return Err(Kind::Malformed);
                }
                match body.iter().position(|c| *c == b']') {
                    Some(i) if i + 1 == body.len() => in_action = false,
                    Some(_) => return Err(Kind::Malformed),
                    None => in_action = true,
                }
                continue;
            }
            if !tok
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            {
                return Err(Kind::Malformed);
            }
            sources.push(tok.to_vec());
        }
        if in_action || sources.is_empty() {
            return Err(Kind::Malformed);
        }
        match db {
            b"passwd" => nss.passwd = Some(sources),
            b"group" => nss.group = Some(sources),
            b"initgroups" => nss.initgroups = Some(sources),
            b"subid" => nss.subid = Some(sources),
            _ => {}
        }
    }
    Ok(nss)
}

/// One `/proc/self/mountinfo` entry: the mount id (field 1), the mount
/// point decoded (field 5), and whether the per-mount options (field 6)
/// carry `ro`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub(crate) id: u64,
    pub(crate) mount_point: Vec<u8>,
    pub(crate) ro: bool,
}

/// A mountinfo field with its `\ooo` octal escapes decoded; any other
/// backslash, or an escape above `\377`, is invalid (`None`).
pub(crate) fn decode_octal(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' {
            let e = s.get(i + 1..i + 4)?;
            if !e.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let v =
                u32::from(e[0] - b'0') * 64 + u32::from(e[1] - b'0') * 8 + u32::from(e[2] - b'0');
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Some(out)
}

/// A `/proc/self/mountinfo` text (R45 item 5): every line must parse
/// (mount id, parent id, device, root, mount point, per-mount options,
/// optional fields, `-`, file system type, source, super options); any
/// defect refuses the table (`mount`). Reaching the line bound refuses it
/// too: it is never read as if complete.
pub(crate) fn parse_mountinfo(b: &[u8]) -> Result<Vec<MountEntry>, Kind> {
    if b.len() >= MOUNTINFO_BOUNDS.bytes {
        return Err(Kind::Mount);
    }
    let ls = lines(b, MOUNTINFO_BOUNDS.lines - 1).map_err(|_| Kind::Mount)?;
    let mut out = Vec::with_capacity(ls.len());
    for l in ls {
        let f: Vec<&[u8]> = l.split(|c| *c == b' ').collect();
        let Some(sep) = f.iter().position(|x| *x == b"-") else {
            return Err(Kind::Mount);
        };
        if sep < 6 || f.len() != sep + 4 || f.iter().any(|x| x.is_empty()) {
            return Err(Kind::Mount);
        }
        let (Some(id), Some(_parent)) = (dec(f[0], u64::MAX), dec(f[1], u64::MAX)) else {
            return Err(Kind::Mount);
        };
        decode_octal(f[3]).ok_or(Kind::Mount)?;
        let mount_point = decode_octal(f[4]).ok_or(Kind::Mount)?;
        let ro = f[5].split(|c| *c == b',').any(|o| o == b"ro");
        out.push(MountEntry {
            id,
            mount_point,
            ro,
        });
    }
    Ok(out)
}

/// The entry with mount id `id`: exactly one, or none (a table with the
/// id twice proves nothing).
pub(crate) fn find_mount(table: &[MountEntry], id: u64) -> Option<&MountEntry> {
    let mut it = table.iter().filter(|e| e.id == id);
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

/// Whether a `uid_map` / `gid_map` text is the identity map of the
/// initial user namespace.
pub(crate) fn is_identity_map(text: &[u8]) -> bool {
    std::str::from_utf8(text)
        .is_ok_and(|t| !databastion_core::config::firebird::uid_map_is_namespaced(t))
}

// ---------------------------------------------------------- the identity

/// Subordinate ranges (R48 item 4a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ranges {
    /// The ranges of the file (no file on the bare host: none).
    Known(Vec<(u64, u64)>),
    /// Not provable: every id of 100000 or more is inside a range.
    Unprovable,
}

impl Ranges {
    pub(crate) fn contains(&self, id: u32) -> bool {
        let id = u64::from(id);
        match self {
            Self::Known(r) => r
                .iter()
                .any(|&(start, count)| id >= start && id - start < count),
            Self::Unprovable => id >= SUBORDINATE_FLOOR,
        }
    }
}

/// Whether `id` lies in one of systemd's ranges.
pub(crate) fn in_systemd_range(id: u32) -> bool {
    let id = u64::from(id);
    SYSTEMD_RANGES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&id))
}

/// What the readers check knows about the host's accounts (R48).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) users: Vec<User>,
    /// `None`: no membership is provable (R47 item 3: another source
    /// serves groups or initgroups).
    pub(crate) groups: Option<Vec<Group>>,
    pub(crate) sub_uid: Ranges,
    pub(crate) sub_gid: Ranges,
}

/// What the subordinate id file of one kind gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubFile {
    Ranges(Vec<(u64, u64)>),
    /// Not declared (container) or not there (bare host).
    Absent,
}

/// Whether the agent's process is in a container, for the absent
/// subordinate files: in a container they are unprovable, on the bare
/// host a missing file means no range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Place {
    BareHost,
    Container,
}

impl Identity {
    /// R47 and R48 item 4a: the identity from the parsed files and the
    /// NSS configuration (`None`: missing or refused).
    pub(crate) fn assemble(
        users: Vec<User>,
        groups: Vec<Group>,
        nss: Option<&Nss>,
        subuid: SubFile,
        subgid: SubFile,
        place: Place,
    ) -> Result<Self, Fail> {
        let Some(nss) = nss else {
            return Err(Fail::Nss);
        };
        let only = |line: &Option<Vec<Vec<u8>>>, ok: &[&[u8]]| {
            line.as_ref()
                .is_some_and(|s| s.iter().all(|x| ok.contains(&x.as_slice())))
        };
        // N2: `files` everywhere, `systemd` on `passwd:` only.
        if !only(&nss.passwd, &[b"files", b"systemd"]) {
            return Err(Fail::Nss);
        }
        let groups_provable = only(&nss.group, &[b"files"])
            && (nss.initgroups.is_none() || only(&nss.initgroups, &[b"files"]));
        let subid_provable = nss.subid.is_none() || only(&nss.subid, &[b"files"]);
        let ranges = |f: SubFile| match (f, subid_provable, place) {
            (_, false, _) | (SubFile::Absent, _, Place::Container) => Ranges::Unprovable,
            (SubFile::Absent, true, Place::BareHost) => Ranges::Known(Vec::new()),
            (SubFile::Ranges(r), true, _) => Ranges::Known(r),
        };
        Ok(Self {
            users,
            groups: groups_provable.then_some(groups),
            sub_uid: ranges(subuid),
            sub_gid: ranges(subgid),
        })
    }

    /// R48 items 3, 4 and 4a for the server's and the agent's uids.
    /// `accounts`: in a container, the declared `server_account` and
    /// `agent_account` (item 4); `None` on the bare host.
    pub(crate) fn uid_rules(
        &self,
        server: u32,
        agent: u32,
        accounts: Option<(Option<&str>, Option<&str>)>,
    ) -> Result<(), Fail> {
        for uid in [server, agent] {
            if RESERVED_UIDS.contains(&uid) {
                return Err(Fail::UidCollision);
            }
            if uid != 0 && (in_systemd_range(uid) || self.sub_uid.contains(uid)) {
                return Err(Fail::UidCollision);
            }
        }
        if let Some((server_account, agent_account)) = accounts {
            for (uid, name) in [(server, server_account), (agent, agent_account)] {
                if uid == 0 {
                    continue;
                }
                let foreign = self
                    .users
                    .iter()
                    .filter(|u| u.uid == uid)
                    .any(|u| name.is_none_or(|n| u.name.as_slice() != n.as_bytes()));
                if foreign {
                    return Err(Fail::UidCollision);
                }
            }
        }
        Ok(())
    }

    /// Whether a group that grants read is open (R48 item 2, R47 item 3,
    /// R48 item 4a): memberships not provable, a gid in a subordinate or
    /// systemd range, a gid with no line, a member name with no passwd
    /// line, or a member (named or primary) outside `allowed`.
    pub(crate) fn group_open(&self, gid: u32, allowed: &dyn Fn(u32) -> bool) -> bool {
        let Some(groups) = &self.groups else {
            return true;
        };
        if in_systemd_range(gid) || self.sub_gid.contains(gid) {
            return true;
        }
        // One pass over the files (bounded at 65 536 lines each).
        let mut found = false;
        let mut members: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        for g in groups.iter().filter(|g| g.gid == gid) {
            found = true;
            members.extend(g.members.iter().map(Vec::as_slice));
        }
        if !found {
            return true;
        }
        let mut resolved: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        for u in &self.users {
            let named = members.contains(u.name.as_slice());
            if named {
                resolved.insert(u.name.as_slice());
            }
            if (named || u.gid == gid) && !allowed(u.uid) {
                return true;
            }
        }
        // A member name with no passwd line.
        resolved.len() != members.len()
    }
}

// ------------------------------------------------------------- the files

/// What `fstat` and the path show about an opened handle (R45 items 1, 3
/// and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandleFacts {
    pub(crate) regular: bool,
    pub(crate) nlink: u64,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
    pub(crate) names_handle: bool,
    pub(crate) agent_can_write: bool,
}

/// R45 items 1, 3 and 4 on a handle's facts.
pub(crate) fn judge_handle(f: &HandleFacts) -> Result<(), Kind> {
    if !f.regular {
        return Err(Kind::NotReadable);
    }
    // A stale bind mount (the source renamed over): link count 0.
    if f.nlink != 1 {
        return Err(Kind::Links);
    }
    if !f.names_handle {
        return Err(Kind::Changed);
    }
    if f.agent_can_write {
        return Err(Kind::Writable);
    }
    if f.uid != 0 {
        return Err(Kind::Owner);
    }
    if f.mode & 0o022 != 0 {
        return Err(Kind::Mode);
    }
    Ok(())
}

/// What `statx` and `fstatvfs` show about a handle's mount (R45 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MountFacts {
    /// `None`: `STATX_MNT_ID` not in the result mask.
    pub(crate) mnt_id: Option<u64>,
    /// `None`: `STATX_ATTR_MOUNT_ROOT` not in the attributes mask.
    pub(crate) mount_root: Option<bool>,
    pub(crate) fs_rdonly: bool,
    /// `STATX_MNT_ID_UNIQUE` before and after the `mountinfo` read
    /// (`None` where the kernel does not offer it).
    pub(crate) unique_before: Option<u64>,
    pub(crate) unique_after: Option<u64>,
}

/// R45 item 5: the root of its own read-only single-file bind mount,
/// found by mount id, at the declared path, not the root mount.
pub(crate) fn judge_mount(
    f: &MountFacts,
    table: &[MountEntry],
    declared: &[u8],
) -> Result<(), Kind> {
    let Some(id) = f.mnt_id else {
        return Err(Kind::Mount);
    };
    if f.mount_root != Some(true) || !f.fs_rdonly || f.unique_before != f.unique_after {
        return Err(Kind::Mount);
    }
    let Some(entry) = find_mount(table, id) else {
        return Err(Kind::Mount);
    };
    if !entry.ro || entry.mount_point == b"/" || entry.mount_point != declared {
        return Err(Kind::Mount);
    }
    Ok(())
}

/// `STATX_MNT_ID_UNIQUE` (Linux 6.8).
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

/// The open flags of every identity file.
fn oflags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY
}

fn resolve() -> ResolveFlags {
    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

/// Why an open failed: the file is not there, or another refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    Missing,
    Refused(Kind),
}

/// R45 item 1: `openat2` without any symbolic or magic link on the path;
/// a kernel without `openat2` refuses the file.
pub(crate) fn open_no_links(path: &Path) -> Result<OwnedFd, OpenError> {
    rustix::fs::openat2(CWD, path, oflags(), Mode::empty(), resolve()).map_err(|e| {
        if e == rustix::io::Errno::NOENT {
            OpenError::Missing
        } else {
            OpenError::Refused(Kind::NotReadable)
        }
    })
}

/// The rules of the bare host's files and symbolic link chains (R45 item
/// 2, option (a); security review L2): every directory component from
/// `base` down to the final file and to each link owned by `dir_owner`
/// without a group or other write bit, every link owned by `link_owner`,
/// every step under `base`, no `..` in a link target. The owners are 0 in
/// production; tests set their own uid.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainRules<'a> {
    pub(crate) base: &'a Path,
    pub(crate) dir_owner: u32,
    pub(crate) link_owner: u32,
}

/// The production rules: root-owned links under `/etc`.
pub(crate) fn etc_chain() -> ChainRules<'static> {
    ChainRules {
        base: Path::new("/etc"),
        dir_owner: 0,
        link_owner: 0,
    }
}

/// Most links followed in one chain.
const MAX_HOPS: usize = 8;

/// The lexical resolution of a link target against the link's
/// directory, canonical, or `None` (a `..` component is refused).
fn lexical(dir: &Path, target: &Path) -> Option<PathBuf> {
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        dir.join(target)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            // Security review L2: a `..` in a link target is refused.
            Component::ParentDir => return None,
            Component::Normal(n) => out.push(n),
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Whether `p` is strictly under `base` (component-wise).
fn under(p: &Path, base: &Path) -> bool {
    p != base && p.starts_with(base)
}

/// Opens a bare-host file (R45 item 2, option (a)): `openat2` without
/// links; when the path's last component is a link, the chain is followed
/// only under `rules`. Returns the handle and the path that names it.
pub(crate) fn open_bare_host(
    path: &Path,
    rules: ChainRules<'_>,
) -> Result<(OwnedFd, PathBuf), OpenError> {
    let mut cur = path.to_path_buf();
    for _ in 0..=MAX_HOPS {
        if !under(&cur, rules.base) {
            return Err(OpenError::Refused(Kind::Links));
        }
        let Some(dir) = cur.parent() else {
            return Err(OpenError::Refused(Kind::NotReadable));
        };
        match rustix::fs::openat2(CWD, &cur, oflags(), Mode::empty(), resolve()) {
            Ok(fd) => {
                dirs_ok(dir, rules)?;
                return Ok((fd, cur));
            }
            Err(e) if e == rustix::io::Errno::NOENT => return Err(OpenError::Missing),
            Err(e) if e == rustix::io::Errno::LOOP => {}
            Err(_) => return Err(OpenError::Refused(Kind::NotReadable)),
        }
        // A link somewhere on the path: only the last component may be
        // one, and only under the rules.
        let Some(name) = cur.file_name() else {
            return Err(OpenError::Refused(Kind::NotReadable));
        };
        let dfd = dirs_ok(dir, rules)?;
        let l = rustix::fs::statat(&dfd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| OpenError::Refused(Kind::NotReadable))?;
        if rustix::fs::FileType::from_raw_mode(l.st_mode) != rustix::fs::FileType::Symlink
            || l.st_uid != rules.link_owner
        {
            return Err(OpenError::Refused(Kind::Links));
        }
        let target = rustix::fs::readlinkat(&dfd, name, Vec::new())
            .map_err(|_| OpenError::Refused(Kind::NotReadable))?;
        let target = Path::new(
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(target.as_bytes()),
        );
        cur = lexical(dir, target).ok_or(OpenError::Refused(Kind::Links))?;
    }
    Err(OpenError::Refused(Kind::Links))
}

/// Security review L2: every directory component from `rules.base` down
/// to `dir` (both included), each opened `O_PATH` without links and
/// checked on its handle: owned by `rules.dir_owner`, no group or other
/// write bit (`owner`, `mode`; a link among them, `links`). Returns the
/// handle of `dir`.
fn dirs_ok(dir: &Path, rules: ChainRules<'_>) -> Result<OwnedFd, OpenError> {
    if !dir.starts_with(rules.base) {
        return Err(OpenError::Refused(Kind::Links));
    }
    let mut last = None;
    let mut chain: Vec<&Path> = dir
        .ancestors()
        .take_while(|a| a.starts_with(rules.base))
        .collect();
    chain.reverse();
    for a in chain {
        let fd = rustix::fs::openat2(
            CWD,
            a,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolve(),
        )
        .map_err(|_| OpenError::Refused(Kind::Links))?;
        let st = rustix::fs::fstat(&fd).map_err(|_| OpenError::Refused(Kind::NotReadable))?;
        if st.st_uid != rules.dir_owner {
            return Err(OpenError::Refused(Kind::Owner));
        }
        if st.st_mode & 0o022 != 0 {
            return Err(OpenError::Refused(Kind::Mode));
        }
        last = Some(fd);
    }
    last.ok_or(OpenError::Refused(Kind::NotReadable))
}

/// The facts of an opened handle, the path re-resolved without links.
fn handle_facts(file: &File, path: &Path) -> Result<HandleFacts, Kind> {
    let meta = file.metadata().map_err(|_| Kind::NotReadable)?;
    Ok(HandleFacts {
        regular: meta.file_type().is_file(),
        nlink: meta.nlink(),
        uid: meta.uid(),
        mode: meta.mode(),
        names_handle: names(path, &meta),
        agent_can_write: crate::fsread::agent_can_write(path, &meta),
    })
}

/// Whether `path`, resolved without links, still names the handle.
fn names(path: &Path, meta: &std::fs::Metadata) -> bool {
    match rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        resolve(),
    ) {
        Ok(fd) => File::from(fd).metadata().is_ok_and(|now| {
            now.file_type().is_file() && (now.dev(), now.ino()) == (meta.dev(), meta.ino())
        }),
        Err(_) => false,
    }
}

/// The mount facts of a handle (without the unique id after).
fn mount_facts(fd: impl AsFd) -> MountFacts {
    let fd = fd.as_fd();
    let sx = rustix::fs::statx(
        fd,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .ok();
    let mnt_id = sx
        .as_ref()
        .filter(|s| s.stx_mask & StatxFlags::MNT_ID.bits() != 0)
        .map(|s| s.stx_mnt_id);
    let mount_root = sx.as_ref().and_then(|s| {
        s.stx_attributes_mask
            .contains(rustix::fs::StatxAttributes::MOUNT_ROOT)
            .then(|| {
                s.stx_attributes
                    .contains(rustix::fs::StatxAttributes::MOUNT_ROOT)
            })
    });
    let fs_rdonly =
        rustix::fs::fstatvfs(fd).is_ok_and(|v| v.f_flag.contains(StatVfsMountFlags::RDONLY));
    MountFacts {
        mnt_id,
        mount_root,
        fs_rdonly,
        unique_before: unique_mount_id(fd),
        unique_after: None,
    }
}

/// `STATX_MNT_ID_UNIQUE`, where the kernel offers it.
fn unique_mount_id(fd: impl AsFd) -> Option<u64> {
    let sx = rustix::fs::statx(
        fd,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE),
    )
    .ok()?;
    (sx.stx_mask & STATX_MNT_ID_UNIQUE != 0).then_some(sx.stx_mnt_id)
}

/// Reads an opened file, at most `bounds.bytes` (more is `too_large`).
fn read_bounded(file: &File, bounds: Bounds) -> Result<Zeroizing<Vec<u8>>, Kind> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(bounds.bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Kind::NotReadable)?;
    if bytes.len() > bounds.bytes {
        return Err(Kind::TooLarge);
    }
    Ok(bytes)
}

/// Reads a `/proc` file through one handle checked to be on procfs
/// (`fstatfs`, security review N3); reaching either bound refuses.
pub(crate) fn read_proc(path: &str, bounds: Bounds) -> Option<Zeroizing<Vec<u8>>> {
    databastion_core::config::firebird::read_proc_bounded(path, bounds.bytes, bounds.lines)
        .map(Zeroizing::new)
}

/// R46: both maps the identity map of the initial user namespace.
pub(crate) fn identity_maps() -> Result<(), Fail> {
    for p in ["/proc/self/uid_map", "/proc/self/gid_map"] {
        let Some(text) = read_proc(p, MAP_BOUNDS) else {
            return Err(Fail::UserNamespace);
        };
        if !is_identity_map(&text) {
            return Err(Fail::UserNamespace);
        }
    }
    Ok(())
}

/// One file to load: its role, path and bounds.
struct Spec<'a> {
    role: Role,
    path: &'a Path,
    bounds: Bounds,
}

/// The content of every file, in the order of the specs (`None`: absent
/// where allowed).
type Contents = Vec<Option<Zeroizing<Vec<u8>>>>;

/// The declared files (R45, container): opened and checked on their
/// handles, their mounts found in one bounded `mountinfo` read, then each
/// read once from its handle.
fn read_declared(specs: &[Spec<'_>]) -> Result<Contents, Fail> {
    let mut opened = Vec::with_capacity(specs.len());
    for s in specs {
        let fd = open_no_links(s.path).map_err(|e| match e {
            OpenError::Missing => Fail::Refused(s.role, Kind::NotReadable),
            OpenError::Refused(k) => Fail::Refused(s.role, k),
        })?;
        let file = File::from(fd);
        let facts = handle_facts(&file, s.path).map_err(|k| Fail::Refused(s.role, k))?;
        judge_handle(&facts).map_err(|k| Fail::Refused(s.role, k))?;
        let m = mount_facts(&file);
        opened.push((file, m));
    }
    let table = read_proc("/proc/self/mountinfo", MOUNTINFO_BOUNDS)
        .ok_or(Fail::Refused(Role::Mountinfo, Kind::Mount))?;
    let table = parse_mountinfo(&table).map_err(|_| Fail::Refused(Role::Mountinfo, Kind::Mount))?;
    let mut out = Vec::with_capacity(specs.len());
    for (s, (file, mut m)) in specs.iter().zip(opened) {
        m.unique_after = unique_mount_id(&file);
        judge_mount(&m, &table, s.path.as_os_str().as_encoded_bytes())
            .map_err(|k| Fail::Refused(s.role, k))?;
        let bytes = read_bounded(&file, s.bounds).map_err(|k| Fail::Refused(s.role, k))?;
        // The path still names the handle after the checks and the read.
        let facts = handle_facts(&file, s.path).map_err(|k| Fail::Refused(s.role, k))?;
        judge_handle(&facts).map_err(|k| Fail::Refused(s.role, k))?;
        out.push(Some(bytes));
    }
    Ok(out)
}

/// One bare-host file (R45 item 2): `None` when it is not there.
fn read_bare(
    path: &Path,
    bounds: Bounds,
    rules: ChainRules<'_>,
) -> Result<Option<Zeroizing<Vec<u8>>>, Kind> {
    let (fd, at) = match open_bare_host(path, rules) {
        Ok(x) => x,
        Err(OpenError::Missing) => return Ok(None),
        Err(OpenError::Refused(k)) => return Err(k),
    };
    let file = File::from(fd);
    judge_handle(&handle_facts(&file, &at)?)?;
    let bytes = read_bounded(&file, bounds)?;
    judge_handle(&handle_facts(&file, &at)?)?;
    Ok(Some(bytes))
}

/// Parses the files into an [`Identity`] (R47, R48).
fn identity_from(
    passwd: &[u8],
    group: &[u8],
    nss: Option<&[u8]>,
    subuid: Option<&[u8]>,
    subgid: Option<&[u8]>,
    place: Place,
) -> Result<Identity, Fail> {
    let users = parse_passwd(passwd).map_err(|k| Fail::Refused(Role::Passwd, k))?;
    let groups = parse_group(group).map_err(|k| Fail::Refused(Role::Group, k))?;
    let nss = match nss.map(parse_nsswitch) {
        Some(Ok(n)) => Some(n),
        // R47 item 3: a refused file proves no `passwd:` line.
        Some(Err(k)) if place == Place::Container => {
            return Err(Fail::Refused(Role::Nsswitch, k));
        }
        Some(Err(_)) | None => None,
    };
    let sub = |b: Option<&[u8]>, role: Role| match b {
        Some(b) => parse_subid(b)
            .map(SubFile::Ranges)
            .map_err(|k| Fail::Refused(role, k)),
        None => Ok(SubFile::Absent),
    };
    Identity::assemble(
        users,
        groups,
        nss.as_ref(),
        sub(subuid, Role::Subuid)?,
        sub(subgid, Role::Subgid)?,
        place,
    )
}

/// Test entry point: the identity from contents, as a check would build
/// it.
#[cfg(test)]
pub(crate) fn identity_for_tests(
    passwd: &str,
    group: &str,
    nss: Option<&str>,
    subuid: Option<&str>,
    subgid: Option<&str>,
    place: Place,
) -> Result<Identity, Fail> {
    identity_from(
        passwd.as_bytes(),
        group.as_bytes(),
        nss.map(str::as_bytes),
        subuid.map(str::as_bytes),
        subgid.map(str::as_bytes),
        place,
    )
}

/// The declared files of a container (R44 to R47): every file read once,
/// at this check.
pub(crate) fn load_declared(h: &FirebirdHostIdentity) -> Result<Identity, Fail> {
    identity_maps()?;
    let mut specs = vec![
        Spec {
            role: Role::Passwd,
            path: &h.passwd,
            bounds: PASSWD_BOUNDS,
        },
        Spec {
            role: Role::Group,
            path: &h.group,
            bounds: GROUP_BOUNDS,
        },
        Spec {
            role: Role::Nsswitch,
            path: &h.nsswitch,
            bounds: NSSWITCH_BOUNDS,
        },
    ];
    if let Some(p) = &h.subuid {
        specs.push(Spec {
            role: Role::Subuid,
            path: p,
            bounds: SUBID_BOUNDS,
        });
    }
    if let Some(p) = &h.subgid {
        specs.push(Spec {
            role: Role::Subgid,
            path: p,
            bounds: SUBID_BOUNDS,
        });
    }
    let c = read_declared(&specs)?;
    let get = |role: Role| {
        specs
            .iter()
            .position(|s| s.role == role)
            .and_then(|i| c[i].as_deref().map(Vec::as_slice))
    };
    identity_from(
        get(Role::Passwd).unwrap_or_default(),
        get(Role::Group).unwrap_or_default(),
        get(Role::Nsswitch),
        get(Role::Subuid),
        get(Role::Subgid),
        Place::Container,
    )
}

/// The bare host's own files (R45 item 2, R47, R48 item 4a, R49 item 3).
pub(crate) fn load_bare_host() -> Result<Identity, Fail> {
    load_bare_host_under(Path::new("/etc"), etc_chain())
}

/// [`load_bare_host`] with the files under `dir` (tests).
pub(crate) fn load_bare_host_under(dir: &Path, rules: ChainRules<'_>) -> Result<Identity, Fail> {
    let read = |name: &str, bounds: Bounds, role: Role| {
        read_bare(&dir.join(name), bounds, rules).map_err(|k| Fail::Refused(role, k))
    };
    let passwd = read("passwd", PASSWD_BOUNDS, Role::Passwd)?
        .ok_or(Fail::Refused(Role::Passwd, Kind::NotReadable))?;
    let group = read("group", GROUP_BOUNDS, Role::Group)?
        .ok_or(Fail::Refused(Role::Group, Kind::NotReadable))?;
    // R47 item 3: a missing or refused nsswitch.conf proves no line.
    let nss = read("nsswitch.conf", NSSWITCH_BOUNDS, Role::Nsswitch)
        .ok()
        .flatten();
    let subuid = read("subuid", SUBID_BOUNDS, Role::Subuid)?;
    let subgid = read("subgid", SUBID_BOUNDS, Role::Subgid)?;
    identity_from(
        &passwd,
        &group,
        nss.as_deref().map(Vec::as_slice),
        subuid.as_deref().map(Vec::as_slice),
        subgid.as_deref().map(Vec::as_slice),
        Place::BareHost,
    )
}

/// Which files the readers check of a target uses (R44 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    HostFiles,
    DeclaredFiles,
}

impl Source {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HostFiles => "host_files",
            Self::DeclaredFiles => "declared_files",
        }
    }

    /// The source a check uses: the host's own files on the bare host,
    /// the declared files in a container with the block, none otherwise.
    pub(crate) const fn of(in_container: bool, declared: bool) -> Option<Self> {
        match (in_container, declared) {
            (false, false) => Some(Self::HostFiles),
            (true, true) => Some(Self::DeclaredFiles),
            _ => None,
        }
    }
}

/// R44 item 6: the source to log when a check switches to it (`None`:
/// unchanged, or no source).
pub(crate) fn switched(previous: Option<Source>, now: Option<Source>) -> Option<Source> {
    now.filter(|n| previous != Some(*n))
}

/// R44 item 3: the block present on a check that detects no container.
pub(crate) const fn not_in_container() -> Fail {
    Fail::Refused(Role::Block, Kind::NotInContainer)
}
