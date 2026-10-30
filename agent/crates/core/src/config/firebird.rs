//! `targets[].firebird`: settings of a Firebird target (ADR-0060).
//!
//! - **Loopback only** (decision 3): the declared `host` is the IP literal
//!   `127.0.0.1` or `::1` (no name: `localhost` resolution is not trusted).
//!   A remote server is reached only through an operator-run tunnel that
//!   ends on the agent host's loopback, declared with `tunnel: true`.
//! - **The listening peer** (decision 3, security review L1): `peer_uid`
//!   is the account that must own the server side of every connection
//!   (default `firebird`; the tunnel process's account with `tunnel:
//!   true`, then required). Resolved when the configuration is loaded: a
//!   name through `/etc/passwd`, refused in a container (names resolve
//!   against the agent image's own `/etc/passwd`); `0` refused unless
//!   `peer_uid_root: true`; `65534` (`nobody`, what a uid outside the
//!   reader's user namespace shows as) always refused.
//! - **Declared databases only** (decision 5, I5): `databases: [{name,
//!   attach}]`. `attach` (a `databases.conf` alias or an absolute path) is
//!   sent to the server only, and **in clear**: `op_connect` names it
//!   before wire encryption starts (the server picks its per-database
//!   `AuthServer` and `WireCrypt` from it; measured on 4.0.7 and 5.0.4,
//!   ADR-0060 decision 5), and `op_attach` names it again encrypted. It is
//!   never sent to the console nor logged; an alias keeps the path off the
//!   loopback. `name` is the operator's label, sent as `Location.database`.
//!
//! The block has no field the console can set (I3). Errors name the key
//! and the rule, never the value.

use serde::Deserialize;

/// Default TCP port of the Firebird remote protocol.
pub const DEFAULT_PORT: u16 = 3050;
/// Most declared databases per target.
pub const MAX_DATABASES: usize = 64;
/// Longest database label, in characters.
pub const MAX_NAME_CHARS: usize = 128;
/// Longest `attach` string, in bytes.
pub const MAX_ATTACH_BYTES: usize = 1024;
/// The account of the Firebird server processes on the distributions and
/// the official images (decision 3).
pub const DEFAULT_PEER_USER: &str = "firebird";
/// The overflow uid (`nobody`): what a uid outside the reader's user
/// namespace shows as in `/proc/net/tcp`. Never a valid peer.
pub const OVERFLOW_UID: u32 = 65_534;

/// `firebird.peer_uid`: a user name resolved when the configuration is
/// loaded, or a number.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum PeerUid {
    /// A numeric uid.
    Number(u32),
    /// A user name (or a number written as a string).
    Name(String),
}

/// One declared database (decision 5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirebirdDatabase {
    /// The operator's label, sent as `Location.database` (normalized
    /// under ADR-0009). Never a path.
    pub name: String,
    /// A `databases.conf` alias or an absolute path, sent to the server
    /// only (never logged, never in a location or an error).
    pub attach: String,
}

/// `firebird.audit`: the system audit trace (ADR-0060 decision 6, M3, and
/// refinement R2 rule 2). Every path is absolute and on the agent host;
/// the agent only reads these files, under the file rules of ADR-0043
/// (`O_NOFOLLOW`, one hard link, nothing the agent could write), and never
/// sends a path anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirebirdAuditConfig {
    /// The trace log the server writes (`log_filename` of the applying
    /// sections).
    pub log: std::path::PathBuf,
    /// The trace configuration (`AuditTraceConfigFile`).
    pub trace_config: std::path::PathBuf,
    /// The server's `firebird.conf`.
    pub firebird_conf: std::path::PathBuf,
    /// The Firebird root directory (`$(root)`), against which relative
    /// names of the configuration files are resolved.
    pub root: std::path::PathBuf,
    /// `<root>/databases.conf` (refinement R2 rule 2): the alias map.
    /// Without it, aliases other than the declared ones are not evaluated
    /// (Limited, label `databases_conf`).
    #[serde(default)]
    pub databases_conf: Option<std::path::PathBuf>,
}

/// Longest declared path of `firebird.audit`, in bytes.
pub const MAX_AUDIT_PATH_BYTES: usize = 4096;

impl FirebirdAuditConfig {
    /// Local rules: `(key, reason)` on error, never the value.
    pub(crate) fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        let canonical = |p: &std::path::Path| {
            let s = p.as_os_str().as_encoded_bytes();
            p.is_absolute()
                && s.len() <= MAX_AUDIT_PATH_BYTES
                && !s.iter().any(|b| b.is_ascii_control())
                && s.len() > 1
                && s[1..]
                    .split(|b| *b == b'/')
                    .all(|part| !part.is_empty() && part != b"." && part != b"..")
        };
        for (key, p) in [
            ("audit.log", &self.log),
            ("audit.trace_config", &self.trace_config),
            ("audit.firebird_conf", &self.firebird_conf),
            ("audit.root", &self.root),
        ] {
            if !canonical(p) {
                return Err((
                    key,
                    "must be a canonical absolute path (no empty, . or .. component, no \
                     trailing /, no control character, at most 4096 bytes)",
                ));
            }
        }
        // The server reads `<root>/firebird.conf` (review of part 1, L2):
        // another file cannot be the configuration it runs with.
        if self.firebird_conf != self.root.join("firebird.conf") {
            return Err((
                "audit.firebird_conf",
                "must be <audit.root>/firebird.conf (the file the server reads)",
            ));
        }
        if let Some(d) = &self.databases_conf
            && *d != self.root.join("databases.conf")
        {
            return Err((
                "audit.databases_conf",
                "must be <audit.root>/databases.conf (ADR-0060 refinement R2 rule 2)",
            ));
        }
        let files = [&self.log, &self.trace_config, &self.firebird_conf];
        if files[0] == files[1] || files[0] == files[2] || files[1] == files[2] {
            return Err((
                "audit",
                "log, trace_config and firebird_conf must be distinct files",
            ));
        }
        Ok(())
    }
}

/// Firebird settings of a target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirebirdTargetConfig {
    /// The declared databases (1 to 64).
    pub databases: Vec<FirebirdDatabase>,
    /// The account that owns the server side of the connection (default
    /// `firebird`; required with `tunnel: true`).
    #[serde(default)]
    pub peer_uid: Option<PeerUid>,
    /// Allows `peer_uid: 0` (a root-owned socket is usually a proxy, and
    /// every root process matches it).
    #[serde(default)]
    pub peer_uid_root: bool,
    /// The target is reached through a tunnel the operator runs, ending on
    /// the agent host's loopback (decision 3, security review M2): the
    /// forwarder check is not applied, the permanent note
    /// `security.firebird_tunnel` is reported, and there is no Audit.
    #[serde(default)]
    pub tunnel: bool,
    /// The extended grant variant (`SELECT_ANY_OBJECT_IN_DATABASE` through
    /// a default role, decision 4 and refinement R3), reported as
    /// `privilege.extended_variant` instead of over-privilege.
    #[serde(default)]
    pub extended_grants: bool,
    /// Audit from the system audit trace (decision 6); absent: no Audit
    /// source (`audit.source_not_configured`). Refused with `tunnel: true`
    /// (decision 3: a tunnel is Discovery only).
    #[serde(default)]
    pub audit: Option<FirebirdAuditConfig>,
    /// `peer_uid` resolved when the configuration was loaded.
    #[serde(skip)]
    resolved_peer_uid: Option<u32>,
}

impl FirebirdTargetConfig {
    /// The uid the server side of every connection must be owned by,
    /// resolved when the configuration was loaded (`None` for a block that
    /// did not come from [`crate::AgentConfig::parse`]).
    #[must_use]
    pub const fn peer_uid(&self) -> Option<u32> {
        self.resolved_peer_uid
    }

    /// Test support: the block with a resolved `peer_uid`.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_peer_uid_for_tests(mut self, uid: u32) -> Self {
        self.resolved_peer_uid = Some(uid);
        self
    }

    /// Local rules of the block: `(key, reason)` on error.
    pub(crate) fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        if self.databases.is_empty() || self.databases.len() > MAX_DATABASES {
            return Err(("databases", "must list 1 to 64 databases"));
        }
        let mut names = std::collections::HashSet::new();
        let mut attaches = std::collections::HashSet::new();
        for db in &self.databases {
            if db.name.trim().is_empty()
                || db.name.chars().count() > MAX_NAME_CHARS
                || db.name.chars().any(char::is_control)
            {
                return Err((
                    "databases.name",
                    "each name must be 1 to 128 characters without control characters",
                ));
            }
            if !names.insert(db.name.to_lowercase()) {
                return Err(("databases.name", "listed twice"));
            }
            if !attach_ok(&db.attach) {
                return Err((
                    "databases.attach",
                    "must be a databases.conf alias ([A-Za-z0-9_][A-Za-z0-9_.$-]*) or a \
                     canonical absolute path (no //, . or .. component, no :, no \\, no \
                     control character, at most 1024 bytes)",
                ));
            }
            if !attaches.insert(db.attach.as_str()) {
                return Err(("databases.attach", "the same database is declared twice"));
            }
        }
        if let Some(a) = &self.audit {
            if self.tunnel {
                return Err((
                    "audit",
                    "is not available with tunnel: true (a tunnel is Discovery only, ADR-0060 \
                     decision 3)",
                ));
            }
            a.validate()?;
        }
        if self.tunnel && self.peer_uid.is_none() {
            return Err((
                "peer_uid",
                "is required with tunnel: true (the account of the tunnel process)",
            ));
        }
        Ok(())
    }

    /// Resolves `peer_uid` (decision 3): `passwd` is the content of the
    /// agent host's `/etc/passwd` (`None` when unreadable), `in_container`
    /// whether the agent runs in a container.
    pub(crate) fn resolve(
        &mut self,
        passwd: Option<&str>,
        in_container: bool,
    ) -> Result<(), (&'static str, &'static str)> {
        let uid = resolve_peer_uid(
            self.peer_uid.as_ref(),
            self.peer_uid_root,
            passwd,
            in_container,
        )?;
        self.resolved_peer_uid = Some(uid);
        Ok(())
    }
}

/// Whether `attach` is an alias or a canonical absolute path (decision 5).
/// The server resolves it; the agent only refuses forms that could name
/// another host (`:`), a Windows path (`\`) or a path that is not
/// canonical (the trace prints canonical paths, refinement R2).
#[must_use]
pub fn attach_ok(attach: &str) -> bool {
    if attach.is_empty()
        || attach.len() > MAX_ATTACH_BYTES
        || attach
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '\\')
    {
        return false;
    }
    if let Some(rest) = attach.strip_prefix('/') {
        return !rest.is_empty()
            && rest
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
    }
    let mut bytes = attach.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$' | b'-'))
        && attach.len() <= 128
}

/// Whether `account` is a Firebird regular identifier (decision 3): an
/// ASCII letter, then up to 62 ASCII letters, digits, `_` or `$`. The
/// server stores it upper-cased, and so does the SRP exchange; delimited
/// (quoted) user names are not supported.
#[must_use]
pub fn account_ok(account: &str) -> bool {
    let mut bytes = account.bytes();
    account.len() <= 63
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

/// Whether `host` is a loopback IP literal (decision 3): `127.0.0.1` or
/// `::1` exactly. `localhost` and other names are refused (their
/// resolution is not trusted), and so is any other address of `127/8`.
#[must_use]
pub fn host_is_loopback_literal(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1")
}

/// The resolution rule of `peer_uid` (decision 3, open question 10).
pub(crate) fn resolve_peer_uid(
    spec: Option<&PeerUid>,
    root_ok: bool,
    passwd: Option<&str>,
    in_container: bool,
) -> Result<u32, (&'static str, &'static str)> {
    let uid = match spec {
        Some(PeerUid::Number(n)) => *n,
        Some(PeerUid::Name(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s
            .parse::<u32>()
            .map_err(|_| ("peer_uid", "is not a valid uid"))?,
        named => {
            let name = match named {
                Some(PeerUid::Name(s)) => s.as_str(),
                _ => DEFAULT_PEER_USER,
            };
            if in_container {
                return Err((
                    "peer_uid",
                    "must be numeric when the agent runs in a container (names resolve against \
                     the agent image's own /etc/passwd)",
                ));
            }
            lookup_user(
                passwd.ok_or(("peer_uid", "/etc/passwd is not readable"))?,
                name,
            )
            .ok_or(("peer_uid", "names no user of /etc/passwd"))?
        }
    };
    if uid == 0 && !root_ok {
        return Err((
            "peer_uid",
            "0 (root) is refused unless peer_uid_root: true (a root-owned socket is usually a \
             proxy)",
        ));
    }
    if uid == OVERFLOW_UID {
        return Err((
            "peer_uid",
            "65534 (the overflow uid) is never accepted: declare the server's own account",
        ));
    }
    Ok(uid)
}

/// The uid of `name` in a `/etc/passwd` text (first match), bounded.
fn lookup_user(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().take(65_536).find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name)
            .then(|| fields.nth(1)?.parse::<u32>().ok())
            .flatten()
    })
}

/// Whether the agent runs in a container (decision 3, review L6): any of
/// `/.dockerenv`, `/run/.containerenv` (Podman), a container runtime named
/// in `/proc/1/cgroup`, a user namespace (`/proc/self/uid_map` not the
/// identity map), `KUBERNETES_SERVICE_HOST` set, an overlay file system as
/// the root (`/proc/self/mountinfo`), or a process 1 that is not pid 1 of
/// the kernel (`/proc/1/sched`, a pid namespace). Any signal is enough: in
/// a container a `peer_uid` name is refused (it would resolve against the
/// agent image's `/etc/passwd`). Read once per configuration load.
#[must_use]
pub fn agent_in_container() -> bool {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
        || read("/proc/1/cgroup").is_some_and(|t| cgroup_names_container(&t))
        || read("/proc/self/uid_map").is_some_and(|t| uid_map_is_namespaced(&t))
        || read("/proc/self/mountinfo").is_some_and(|t| root_is_overlay(&t))
        || read("/proc/1/sched").is_some_and(|t| sched_pid_is_not_1(&t))
}

/// Whether a `/proc/self/uid_map` text is anything but the identity map
/// of the initial user namespace (`0 0 4294967295`).
pub(crate) fn uid_map_is_namespaced(text: &str) -> bool {
    let lines: Vec<Vec<&str>> = text
        .lines()
        .take(340)
        .map(|l| l.split_whitespace().collect())
        .filter(|f: &Vec<&str>| !f.is_empty())
        .collect();
    lines != [vec!["0", "0", "4294967295"]]
}

/// Whether the root mount of a `/proc/self/mountinfo` text is an overlay
/// (or another union) file system.
pub(crate) fn root_is_overlay(text: &str) -> bool {
    text.lines().take(65_536).any(|l| {
        let mut halves = l.splitn(2, " - ");
        let (Some(head), Some(tail)) = (halves.next(), halves.next()) else {
            return false;
        };
        head.split_whitespace().nth(4) == Some("/")
            && tail
                .split_whitespace()
                .next()
                .is_some_and(|fs| ["overlay", "fuse-overlayfs", "aufs", "overlayfs"].contains(&fs))
    })
}

/// Whether the first line of `/proc/1/sched` (`name (pid, #threads: n)`)
/// gives a pid other than 1: process 1 of the agent's view is another
/// process of the kernel's (older kernels in a pid namespace).
pub(crate) fn sched_pid_is_not_1(text: &str) -> bool {
    let Some(first) = text.lines().next() else {
        return false;
    };
    let Some(open) = first.rfind(" (") else {
        return false;
    };
    first[open + 2..]
        .split(',')
        .next()
        .and_then(|p| p.trim().parse::<u64>().ok())
        .is_some_and(|pid| pid != 1)
}

/// Whether a `/proc/1/cgroup` text names a container runtime.
pub(crate) fn cgroup_names_container(text: &str) -> bool {
    text.lines().take(256).any(|l| {
        ["docker", "kubepods", "containerd", "libpod", "lxc", "crio"]
            .iter()
            .any(|m| l.contains(m))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn block(yaml: &str) -> FirebirdTargetConfig {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    /// Review L6: the container signals beyond the marker files.
    #[test]
    fn container_signals() {
        assert!(!uid_map_is_namespaced("         0          0 4294967295\n"));
        assert!(uid_map_is_namespaced("         0     100000      65536\n"));
        assert!(uid_map_is_namespaced("0 0 4294967295\n1 2 3\n"));
        assert!(uid_map_is_namespaced(""));
        let host = "28 1 254:0 / / rw,relatime - ext4 /dev/vda rw\n\
                    29 28 0:5 / /dev rw - devtmpfs udev rw\n";
        assert!(!root_is_overlay(host));
        let docker = "500 400 0:52 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/x\n";
        assert!(root_is_overlay(docker));
        // An overlay mounted elsewhere is not the root.
        assert!(!root_is_overlay(
            "28 1 254:0 / / rw - ext4 /dev/vda rw\n30 28 0:52 / /var/lib/x rw - overlay overlay rw\n"
        ));
        assert!(!sched_pid_is_not_1("systemd (1, #threads: 1)\n-----\n"));
        assert!(!sched_pid_is_not_1("process_api (1, #threads: 8)\n"));
        assert!(sched_pid_is_not_1("sh (12345, #threads: 1)\n"));
        assert!(sched_pid_is_not_1("my (odd) name (4242, #threads: 1)\n"));
        assert!(!sched_pid_is_not_1(""));
    }

    #[test]
    fn block_rules() {
        let ok = block("{databases: [{name: app, attach: appalias}]}");
        assert!(ok.validate().is_ok());
        assert!(!ok.tunnel && !ok.extended_grants && !ok.peer_uid_root);
        assert!(block("{databases: []}").validate().is_err());
        let dup = block("{databases: [{name: app, attach: a}, {name: APP, attach: b}]}");
        assert_eq!(dup.validate().unwrap_err().0, "databases.name");
        let same = block("{databases: [{name: a, attach: /d/x.fdb}, {name: b, attach: /d/x.fdb}]}");
        assert_eq!(same.validate().unwrap_err().0, "databases.attach");
        let tunnel = block("{tunnel: true, databases: [{name: a, attach: a}]}");
        assert_eq!(tunnel.validate().unwrap_err().0, "peer_uid");
        let tunnel = block("{tunnel: true, peer_uid: 1001, databases: [{name: a, attach: a}]}");
        assert!(tunnel.validate().is_ok());
        assert!(
            serde_yaml_ng::from_str::<FirebirdTargetConfig>(
                "{databases: [{name: a, attach: a, path: /x}]}"
            )
            .is_err()
        );
        assert!(
            serde_yaml_ng::from_str::<FirebirdTargetConfig>("{databases: [], audit: {}}").is_err()
        );
    }

    /// ADR-0060 decision 6 and R2 rule 2: the `audit` block.
    #[test]
    fn audit_block_rules() {
        let base = "databases: [{name: a, attach: a}]";
        let audit = "log: /var/log/fb/audit.log, trace_config: /opt/firebird/fbtrace.conf, \
                     firebird_conf: /opt/firebird/firebird.conf, root: /opt/firebird";
        let ok = block(&format!("{{{base}, audit: {{{audit}}}}}"));
        assert!(ok.validate().is_ok());
        assert!(ok.audit.as_ref().unwrap().databases_conf.is_none());
        let with_map = block(&format!(
            "{{{base}, audit: {{{audit}, databases_conf: /opt/firebird/databases.conf}}}}"
        ));
        assert!(with_map.validate().is_ok());
        let other_map = block(&format!(
            "{{{base}, audit: {{{audit}, databases_conf: /etc/databases.conf}}}}"
        ));
        assert_eq!(other_map.validate().unwrap_err().0, "audit.databases_conf");
        let tunnel = block(&format!(
            "{{{base}, tunnel: true, peer_uid: 1001, audit: {{{audit}}}}}"
        ));
        assert_eq!(tunnel.validate().unwrap_err().0, "audit");
        for (bad, key) in [
            ("log: audit.log", "audit.log"),
            ("log: /var/log/../x.log", "audit.log"),
            ("log: /var/log/fb/", "audit.log"),
            ("trace_config: fbtrace.conf", "audit.trace_config"),
            ("root: /opt/./firebird", "audit.root"),
            ("log: /opt/firebird/fbtrace.conf", "audit"),
        ] {
            let field = bad.split(':').next().unwrap();
            let rest: Vec<&str> = audit
                .split(", ")
                .filter(|kv| !kv.starts_with(&format!("{field}:")))
                .collect();
            let cfg = block(&format!(
                "{{{base}, audit: {{{bad}, {}}}}}",
                rest.join(", ")
            ));
            assert_eq!(cfg.validate().unwrap_err().0, key, "{bad}");
        }
        assert!(
            serde_yaml_ng::from_str::<FirebirdTargetConfig>(&format!(
                "{{{base}, audit: {{{audit}, extra: 1}}}}"
            ))
            .is_err()
        );
    }

    #[test]
    fn attach_forms() {
        for good in [
            "appalias",
            "app_db",
            "a.b-c$d",
            "/var/lib/firebird/data/app.fdb",
            "/d/a b.fdb",
        ] {
            assert!(attach_ok(good), "{good}");
        }
        for bad in [
            "",
            "/",
            "relative/x.fdb",
            "/d//x.fdb",
            "/d/./x.fdb",
            "/d/../x.fdb",
            "/d/x.fdb/",
            "host:/d/x.fdb",
            "inet://h/x",
            "C:\\x.fdb",
            "a\nb",
            "-alias",
            ".alias",
            "al ias",
        ] {
            assert!(!attach_ok(bad), "{bad:?}");
        }
        assert!(!attach_ok(&format!("/{}", "a".repeat(MAX_ATTACH_BYTES))));
    }

    #[test]
    fn accounts_are_regular_identifiers() {
        for good in ["DATABASTION_AGENT", "agent", "a$1"] {
            assert!(account_ok(good), "{good}");
        }
        for bad in ["", "1a", "_a", "a b", "a\"b", "é", &"a".repeat(64)] {
            assert!(!account_ok(bad), "{bad}");
        }
    }

    #[test]
    fn loopback_literals_only() {
        assert!(host_is_loopback_literal("127.0.0.1"));
        assert!(host_is_loopback_literal("::1"));
        for bad in [
            "localhost",
            "127.0.0.2",
            "[::1]",
            "0.0.0.0",
            "::",
            "db.example",
            "::ffff:127.0.0.1",
        ] {
            assert!(!host_is_loopback_literal(bad), "{bad}");
        }
    }

    #[test]
    fn peer_uid_resolution() {
        let passwd = "root:x:0:0::/root:/bin/sh\nfirebird:x:84:84::/opt/firebird:/bin/false\n";
        assert_eq!(resolve_peer_uid(None, false, Some(passwd), false), Ok(84));
        assert_eq!(
            resolve_peer_uid(Some(&PeerUid::Number(1001)), false, None, true),
            Ok(1001)
        );
        assert_eq!(
            resolve_peer_uid(Some(&PeerUid::Name("1001".into())), false, None, true),
            Ok(1001)
        );
        // Names are refused in a container, unknown names everywhere.
        assert!(resolve_peer_uid(None, false, Some(passwd), true).is_err());
        assert!(
            resolve_peer_uid(
                Some(&PeerUid::Name("nope".into())),
                false,
                Some(passwd),
                false
            )
            .is_err()
        );
        assert!(resolve_peer_uid(None, false, None, false).is_err());
        // Root only with the opt-in; the overflow uid never.
        assert!(resolve_peer_uid(Some(&PeerUid::Number(0)), false, None, false).is_err());
        assert!(
            resolve_peer_uid(
                Some(&PeerUid::Name("root".into())),
                false,
                Some(passwd),
                false
            )
            .is_err()
        );
        assert_eq!(
            resolve_peer_uid(Some(&PeerUid::Number(0)), true, None, false),
            Ok(0)
        );
        assert!(resolve_peer_uid(Some(&PeerUid::Number(OVERFLOW_UID)), true, None, false).is_err());
        let yaml: FirebirdTargetConfig =
            serde_yaml_ng::from_str("{peer_uid: firebird, databases: [{name: a, attach: a}]}")
                .unwrap();
        assert_eq!(yaml.peer_uid, Some(PeerUid::Name("firebird".into())));
        let yaml: FirebirdTargetConfig =
            serde_yaml_ng::from_str("{peer_uid: 84, databases: [{name: a, attach: a}]}").unwrap();
        assert_eq!(yaml.peer_uid, Some(PeerUid::Number(84)));
    }

    #[test]
    fn container_markers() {
        assert!(cgroup_names_container("0::/docker/abc\n"));
        assert!(cgroup_names_container(
            "1:name=systemd:/kubepods/burstable/pod1\n"
        ));
        assert!(!cgroup_names_container("0::/\n"));
        assert!(!cgroup_names_container("9:name=systemd:/\n"));
    }
}
