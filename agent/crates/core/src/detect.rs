//! Local engine detection (ADR-0006). Crate-private.
//!
//! Looks at the **agent host only**, read-only, without any network I/O (I5):
//! - a fixed list of Unix socket paths (contract `UnixSocketPath`
//!   directories: `/run`, `/var/run`, `/tmp`, `/var/lib/mysql`);
//! - `LISTEN` entries of `/proc/net/tcp` and `/proc/net/tcp6` for the ports
//!   5432, 3306, 27017, 389, 636 (only the port is kept; the listening
//!   address is never reported);
//! - `/proc/<pid>/comm` for `postgres`, `mysqld`, `mariadbd`, `mongod`,
//!   `slapd` (the process name only: the command line may contain secrets
//!   and is never read).
//!
//! The agent never connects to a detected engine. Engines already declared
//! in `agent.yaml` are excluded; the result is capped at the contract limit
//! (16). The root is injectable so tests use fixture trees.
//!
//! `/proc/net/tcp{,6}` only shows the agent's network namespace: a
//! containerized agent without host networking detects no host port.

use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use databastion_protocol::{DetectedTarget, DetectedTargetProcess, Engine, UnixSocketPath};

use crate::config::{TargetConfig, TargetEngine};

/// Contract `HeartbeatRequest.detected_targets.maxItems`.
pub(crate) const MAX_DETECTED: usize = 16;
/// Bound on the `/proc` entries examined.
const MAX_PROC_ENTRIES: usize = 65_536;
/// Bound on the `/proc/net/tcp*` bytes read.
const MAX_NET_BYTES: u64 = 8 * 1024 * 1024;

/// Fixed socket probe list.
const SOCKETS: &[(&str, Engine)] = &[
    ("/run/postgresql/.s.PGSQL.5432", Engine::Postgres),
    ("/var/run/postgresql/.s.PGSQL.5432", Engine::Postgres),
    ("/tmp/.s.PGSQL.5432", Engine::Postgres),
    ("/run/mysqld/mysqld.sock", Engine::Mysql),
    ("/var/run/mysqld/mysqld.sock", Engine::Mysql),
    ("/var/lib/mysql/mysql.sock", Engine::Mysql),
    ("/tmp/mysql.sock", Engine::Mysql),
    ("/tmp/mongodb-27017.sock", Engine::Mongodb),
    ("/run/slapd/ldapi", Engine::Openldap),
    ("/var/run/slapd/ldapi", Engine::Openldap),
    ("/run/openldap/ldapi", Engine::Openldap),
    ("/var/run/ldapi", Engine::Openldap),
];

const PORTS: &[(u16, Engine)] = &[
    (5432, Engine::Postgres),
    (3306, Engine::Mysql),
    (27017, Engine::Mongodb),
    (389, Engine::Openldap),
    (636, Engine::Openldap),
];

const PROCESSES: &[(&str, DetectedTargetProcess, Engine)] = &[
    (
        "postgres",
        DetectedTargetProcess::Postgres,
        Engine::Postgres,
    ),
    ("mysqld", DetectedTargetProcess::Mysqld, Engine::Mysql),
    ("mariadbd", DetectedTargetProcess::Mariadbd, Engine::Mariadb),
    ("mongod", DetectedTargetProcess::Mongod, Engine::Mongodb),
    ("slapd", DetectedTargetProcess::Slapd, Engine::Openldap),
];

/// Where to look. Production: `/` and `std::os::unix::fs::FileTypeExt`.
pub(crate) struct HostView<'a> {
    /// Host root (`/` in production, a fixture directory in tests).
    pub(crate) root: &'a Path,
    /// Whether a path is a Unix socket (tests cannot create sockets without
    /// binding one, which the agent never does).
    pub(crate) is_socket: fn(&Path) -> bool,
}

/// Production socket check (`lstat`, no connect).
pub(crate) fn is_unix_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

fn family(engine: Engine) -> u8 {
    match engine {
        Engine::Postgres => 0,
        Engine::Mysql | Engine::Mariadb => 1,
        Engine::Mongodb => 2,
        Engine::Openldap => 3,
    }
}

fn target_family(engine: TargetEngine) -> u8 {
    match engine {
        TargetEngine::Postgres => 0,
        TargetEngine::Mysql | TargetEngine::Mariadb => 1,
        TargetEngine::Mongodb => 2,
        TargetEngine::Openldap => 3,
    }
}

fn is_local_host(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn default_port(engine: TargetEngine) -> u16 {
    match engine {
        TargetEngine::Postgres => 5432,
        TargetEngine::Mysql | TargetEngine::Mariadb => 3306,
        TargetEngine::Mongodb => 27017,
        TargetEngine::Openldap => 389,
    }
}

/// Ports of `LISTEN` sockets in a `/proc/net/tcp{,6}` table.
fn listening_ports(table: &str) -> Vec<u16> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let local = cols.nth(1)?;
            let state = cols.nth(1)?;
            if state != "0A" {
                return None;
            }
            let port = local.rsplit_once(':')?.1;
            u16::from_str_radix(port, 16).ok()
        })
        .collect()
}

fn read_bounded(path: &Path, max: u64) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut out = String::new();
    file.take(max).read_to_string(&mut out).ok()?;
    Some(out)
}

fn processes(root: &Path) -> Vec<(DetectedTargetProcess, Engine)> {
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir(root.join("proc")) else {
        return out;
    };
    for entry in dir.take(MAX_PROC_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some(comm) = read_bounded(&entry.path().join("comm"), 64) else {
            continue;
        };
        let comm = comm.trim_end_matches('\n');
        if let Some((_, p, e)) = PROCESSES.iter().find(|(n, _, _)| *n == comm)
            && !out.contains(&(*p, *e))
        {
            out.push((*p, *e));
        }
    }
    out
}

/// Detects local engines not declared in `targets`.
pub(crate) fn detect(view: &HostView<'_>, targets: &[TargetConfig]) -> Vec<DetectedTarget> {
    let procs = processes(view.root);
    let mariadb_only = procs.iter().any(|(_, e)| *e == Engine::Mariadb)
        && !procs.iter().any(|(_, e)| *e == Engine::Mysql);
    let refine = |e: Engine| {
        if e == Engine::Mysql && mariadb_only {
            Engine::Mariadb
        } else {
            e
        }
    };
    let local_family = |f: u8| {
        targets.iter().any(|t| {
            target_family(t.engine) == f
                && (t.socket.is_some() || t.host.as_deref().is_some_and(is_local_host))
        })
    };
    let mut out: Vec<DetectedTarget> = Vec::new();
    let push = |d: DetectedTarget, out: &mut Vec<DetectedTarget>| {
        let same = |a: &DetectedTarget| {
            a.engine == d.engine
                && a.port == d.port
                && a.process == d.process
                && a.unix_socket == d.unix_socket
        };
        if out.len() < MAX_DETECTED && !out.iter().any(same) {
            out.push(d);
        }
    };

    for (path, engine) in SOCKETS {
        let configured = targets
            .iter()
            .any(|t| t.socket.as_deref() == Some(Path::new(path)));
        let on_host = view.root.join(path.trim_start_matches('/'));
        if configured || !(view.is_socket)(&on_host) {
            continue;
        }
        if let Ok(socket) = UnixSocketPath::try_from(*path) {
            let d = DetectedTarget {
                engine: refine(*engine),
                port: None,
                process: None,
                unix_socket: Some(socket),
            };
            push(d, &mut out);
        }
    }

    let mut ports = Vec::new();
    for table in ["proc/net/tcp", "proc/net/tcp6"] {
        if let Some(text) = read_bounded(&view.root.join(table), MAX_NET_BYTES) {
            ports.extend(listening_ports(&text));
        }
    }
    for (port, engine) in PORTS {
        let configured = targets.iter().any(|t| {
            t.host.as_deref().is_some_and(is_local_host)
                && t.port.unwrap_or_else(|| default_port(t.engine)) == *port
        });
        if configured || !ports.contains(port) {
            continue;
        }
        let d = DetectedTarget {
            engine: refine(*engine),
            port: std::num::NonZeroU64::new(u64::from(*port)),
            process: None,
            unix_socket: None,
        };
        push(d, &mut out);
    }

    for (process, engine) in procs {
        if local_family(family(engine)) {
            continue;
        }
        let d = DetectedTarget {
            engine,
            port: None,
            process: Some(process),
            unix_socket: None,
        };
        push(d, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::fsutil::test_dir::TempDir;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:6989 0200000A:D431 01 00000000:00000000 00:00000000 00000000   999        0 3 1 0000000000000000 100 0 0 10 0
   3: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
";
    const TCP6: &str = "  sl  local_address remote_address st
   0: 00000000000000000000000001000000:0185 00000000000000000000000000000000:0000 0A 00000000:00000000
";

    fn fixture() -> TempDir {
        let dir = TempDir::new();
        let root = dir.path();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::write(root.join("proc/net/tcp"), TCP).unwrap();
        fs::write(root.join("proc/net/tcp6"), TCP6).unwrap();
        for (pid, comm) in [
            ("1", "systemd"),
            ("200", "postgres"),
            ("201", "postgres"),
            ("300", "mariadbd"),
            ("400", "slapd"),
        ] {
            fs::create_dir_all(root.join("proc").join(pid)).unwrap();
            fs::write(
                root.join("proc").join(pid).join("comm"),
                format!("{comm}\n"),
            )
            .unwrap();
            // A command line with a secret must never be read.
            fs::write(
                root.join("proc").join(pid).join("cmdline"),
                "hunter2-SECRET",
            )
            .unwrap();
        }
        fs::create_dir_all(root.join("proc/self")).unwrap();
        fs::create_dir_all(root.join("run/mysqld")).unwrap();
        fs::write(root.join("run/mysqld/mysqld.sock"), "").unwrap();
        fs::create_dir_all(root.join("var/run/postgresql")).unwrap();
        fs::write(root.join("var/run/postgresql/.s.PGSQL.5432"), "").unwrap();
        dir
    }

    fn exists(p: &Path) -> bool {
        p.exists()
    }

    fn target(yaml: &str) -> TargetConfig {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn listening_ports_are_parsed_from_listen_entries_only() {
        assert_eq!(listening_ports(TCP), vec![5432, 3306, 22]);
        assert_eq!(listening_ports(TCP6), vec![389]);
    }

    #[test]
    fn detects_sockets_ports_and_processes_without_addresses() {
        let dir = fixture();
        let view = HostView {
            root: dir.path(),
            is_socket: exists,
        };
        let found = detect(&view, &[]);
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains("127.0.0.1") && !json.contains("0100007F"));
        assert!(!json.contains("hunter2"));
        assert!(json.contains(r#"{"engine":"mariadb","unix_socket":"/run/mysqld/mysqld.sock"}"#));
        assert!(json.contains(
            r#"{"engine":"postgres","unix_socket":"/var/run/postgresql/.s.PGSQL.5432"}"#
        ));
        assert!(json.contains(r#"{"engine":"postgres","port":5432}"#));
        assert!(json.contains(r#"{"engine":"mariadb","port":3306}"#));
        assert!(json.contains(r#"{"engine":"openldap","port":389}"#));
        assert!(json.contains(r#"{"engine":"postgres","process":"postgres"}"#));
        assert!(json.contains(r#"{"engine":"openldap","process":"slapd"}"#));
        assert!(!json.contains("27017") && !json.contains(":22"));
        assert_eq!(found.len(), 8, "{json}");
        for d in &found {
            // minProperties: 2 (engine + at least one endpoint).
            assert!(d.port.is_some() || d.process.is_some() || d.unix_socket.is_some());
        }
    }

    #[test]
    fn configured_targets_are_excluded() {
        let dir = fixture();
        let view = HostView {
            root: dir.path(),
            is_socket: exists,
        };
        let targets = [
            target("{id: pg, engine: postgres, host: 127.0.0.1, account: a, secret: {env: X}}"),
            target(
                "{id: my, engine: mariadb, socket: /run/mysqld/mysqld.sock, account: a, secret: {env: X}}",
            ),
        ];
        let json = serde_json::to_string(&detect(&view, &targets)).unwrap();
        assert!(!json.contains(r#""port":5432"#));
        assert!(!json.contains("mysqld.sock"));
        assert!(!json.contains(r#""process":"postgres""#));
        assert!(!json.contains(r#""process":"mariadbd""#));
        assert!(json.contains(r#""port":3306"#), "{json}");
        assert!(
            json.contains("PGSQL"),
            "a socket not declared is still reported"
        );
    }

    #[test]
    fn missing_proc_yields_nothing() {
        let dir = TempDir::new();
        let view = HostView {
            root: dir.path(),
            is_socket: is_unix_socket,
        };
        assert!(detect(&view, &[]).is_empty());
    }
}
