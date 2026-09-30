//! Heartbeat target checks: which targets reach the same database account
//! (their checks take turns, ADR-0025 decision 9), and the order of the
//! turns. Crate-private.
//!
//! - **Account key** (phase 7): engine family, account, the port the
//!   connector connects to (an omitted port is the engine's default one),
//!   and the endpoint: a Unix socket (its path with symlinks resolved), or
//!   a host. A host is lowercased without a trailing dot or brackets; an
//!   IP literal is canonical (`::ffff:192.0.2.1` is `192.0.2.1`);
//!   `localhost` is the loopback addresses. Two targets whose host names
//!   differ but that share the engine family, account and port are
//!   compared by address: their names are resolved through the system
//!   resolver (declared targets only, as the connectors resolve them
//!   anyway: no scan, I5), cached [`DNS_TTL`], each within [`DNS_TIMEOUT`]
//!   and the heartbeat's deadline; targets sharing an address share the
//!   turns. A name that does not resolve in time keeps its literal key.
//!   A socket and a TCP endpoint are never taken for the same server.
//! - **Turn order** (phase 7): within an account, the targets whose check
//!   timed out at the previous heartbeat go last, so a hung check no
//!   longer uses up the deadline of the others; the others take the first
//!   turn in rotation from one heartbeat to the next.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config::TargetConfig;
use crate::engine::Engine;

/// How long a host name resolution (or its failure) is reused.
pub(crate) const DNS_TTL: Duration = Duration::from_secs(300);
/// Longest wait for the resolutions of one heartbeat.
pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(1);
/// Addresses kept per name.
const MAX_ADDRS: usize = 16;
/// Names resolved per heartbeat at most (targets are at most 64).
const MAX_NAMES: usize = 64;

/// A host as written in a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Host {
    /// An IP literal (canonical).
    Ip(IpAddr),
    /// `localhost` (and `*.localhost`, RFC 6761).
    Loopback,
    /// A host name (lowercase, no trailing dot).
    Name(String),
}

fn host_of(raw: &str) -> Host {
    let lower = raw.trim().to_ascii_lowercase();
    let bare = lower
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&lower);
    let bare = bare.strip_suffix('.').unwrap_or(bare);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Host::Ip(ip.to_canonical());
    }
    if bare == "localhost" || bare.ends_with(".localhost") {
        return Host::Loopback;
    }
    Host::Name(bare.to_owned())
}

/// Engine family, account and port: targets can only share an account
/// within one of these.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Bucket {
    engine: Engine,
    account: String,
    /// `None`: a Unix socket.
    port: Option<u16>,
}

fn bucket(t: &TargetConfig) -> Bucket {
    Bucket {
        engine: t.engine.connector(),
        account: t.account.clone(),
        port: t.effective_port(),
    }
}

/// What makes two targets of one bucket the same account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Token {
    Socket(PathBuf),
    Name(String),
    Ip(IpAddr),
}

/// The socket path with symlinks resolved (a local file-system call),
/// else as written.
fn socket_key(path: &std::path::Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Host names worth resolving: those of a bucket holding at least two
/// distinct hosts (only then can an alias be found).
pub(crate) fn names_to_resolve(targets: &[TargetConfig]) -> Vec<String> {
    let mut hosts: HashMap<Bucket, HashSet<Host>> = HashMap::new();
    for t in targets {
        if let Some(h) = &t.host {
            hosts.entry(bucket(t)).or_default().insert(host_of(h));
        }
    }
    let mut names: Vec<String> = hosts
        .values()
        .filter(|set| set.len() > 1)
        .flat_map(|set| {
            set.iter().filter_map(|h| match h {
                Host::Name(n) => Some(n.clone()),
                _ => None,
            })
        })
        .collect::<HashSet<String>>()
        .into_iter()
        .collect();
    names.sort();
    names.truncate(MAX_NAMES);
    names
}

/// Group of each target (same group: same account, checks take turns);
/// `resolved` maps host names to their addresses.
pub(crate) fn account_groups(
    targets: &[TargetConfig],
    resolved: &HashMap<String, Vec<IpAddr>>,
) -> Vec<usize> {
    let mut parent: Vec<usize> = (0..targets.len()).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut owner: HashMap<(Bucket, Token), usize> = HashMap::new();
    for (i, t) in targets.iter().enumerate() {
        let b = bucket(t);
        let mut tokens = Vec::new();
        match (&t.host, &t.socket) {
            (Some(h), _) => match host_of(h) {
                Host::Ip(ip) => tokens.push(Token::Ip(ip)),
                Host::Loopback => {
                    tokens.push(Token::Ip(IpAddr::from([127, 0, 0, 1])));
                    tokens.push(Token::Ip(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])));
                }
                Host::Name(n) => {
                    for ip in resolved.get(&n).into_iter().flatten() {
                        tokens.push(Token::Ip(ip.to_canonical()));
                    }
                    tokens.push(Token::Name(n));
                }
            },
            (None, Some(p)) => tokens.push(Token::Socket(socket_key(p))),
            (None, None) => tokens.push(Token::Name(format!("\u{0}{}", t.id))),
        }
        for token in tokens {
            match owner.get(&(b.clone(), token.clone())) {
                Some(&j) => {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    parent[ri] = rj;
                }
                None => {
                    owner.insert((b.clone(), token), i);
                }
            }
        }
    }
    (0..targets.len()).map(|i| find(&mut parent, i)).collect()
}

/// How long a resolution that did not answer in time counts as
/// unresolved (#88 review L3).
pub(crate) const DNS_TIMEOUT_TTL: Duration = Duration::from_secs(60);

/// Resolutions kept between heartbeats, and the lookups in flight.
#[derive(Debug, Default)]
pub(crate) struct DnsCache {
    /// Name: (when, for how long, addresses; empty: unresolved).
    entries: HashMap<String, (Instant, Duration, Vec<IpAddr>)>,
    /// Names whose lookup still runs (never started twice).
    pending: HashSet<String>,
}

impl DnsCache {
    /// The cached addresses of `name`, when fresh.
    pub(crate) fn get(&self, name: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.entries
            .get(name)
            .filter(|(at, ttl, _)| now.saturating_duration_since(*at) < *ttl)
            .map(|(_, _, a)| a.clone())
    }

    /// Records a resolution (an empty list: it failed) for [`DNS_TTL`].
    pub(crate) fn put(&mut self, name: String, addrs: Vec<IpAddr>, now: Instant) {
        self.put_for(name, addrs, now, DNS_TTL);
    }

    /// Records `name` as unresolved for [`DNS_TIMEOUT_TTL`] (its lookup
    /// did not answer in time), unless a fresher result is there.
    pub(crate) fn put_timed_out(&mut self, name: String, now: Instant) {
        if self.get(&name, now).is_none() {
            self.put_for(name, Vec::new(), now, DNS_TIMEOUT_TTL);
        }
    }

    fn put_for(&mut self, name: String, mut addrs: Vec<IpAddr>, now: Instant, ttl: Duration) {
        addrs.truncate(MAX_ADDRS);
        self.entries
            .retain(|_, (at, ttl, _)| now.saturating_duration_since(*at) < *ttl);
        if self.entries.len() < 4 * MAX_NAMES {
            self.entries.insert(name, (now, ttl, addrs));
        }
    }

    /// Marks a lookup of `name` as started; `false` when one is already in
    /// flight (then none is started).
    pub(crate) fn start(&mut self, name: &str) -> bool {
        self.pending.len() < 4 * MAX_NAMES && self.pending.insert(name.to_owned())
    }

    /// A lookup ended with `addrs`.
    pub(crate) fn finish(&mut self, name: &str, addrs: Vec<IpAddr>, now: Instant) {
        self.pending.remove(name);
        self.put(name.to_owned(), addrs, now);
    }
}

/// Resolves `name` with the system resolver (blocking, on a blocking
/// thread): its addresses, empty on failure.
pub(crate) async fn resolve(name: String) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs as _;
    tokio::task::spawn_blocking(move || {
        (name.as_str(), 0u16)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).take(MAX_ADDRS).collect())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

/// Turn order state kept between heartbeats.
#[derive(Debug, Default)]
pub(crate) struct TurnState {
    /// Heartbeats so far (the rotation).
    pub(crate) seq: u64,
    /// Targets whose check timed out while running at the last heartbeat
    /// that ran it.
    pub(crate) slow: HashSet<String>,
}

/// The order of the turns of one account's targets (`members`: indexes in
/// declaration order): the others in rotation by `seq`, then those whose
/// check timed out last time.
pub(crate) fn turn_order(
    members: &[usize],
    targets: &[TargetConfig],
    seq: u64,
    slow: &HashSet<String>,
) -> Vec<usize> {
    let (late, first): (Vec<usize>, Vec<usize>) = members
        .iter()
        .partition(|&&i| slow.contains(&targets[i].id));
    let mut first = first;
    if !first.is_empty() {
        let shift = usize::try_from(seq % first.len() as u64).unwrap_or(0);
        first.rotate_left(shift);
    }
    first.into_iter().chain(late).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn t(id: &str, yaml: &str) -> TargetConfig {
        let mut t: TargetConfig = serde_yaml_ng::from_str(&format!(
            "{{id: {id}, account: a, secret: {{env: X}}, {yaml}}}"
        ))
        .unwrap();
        t.id = id.to_owned();
        t
    }

    fn groups<'a>(
        targets: &'a [TargetConfig],
        resolved: &HashMap<String, Vec<IpAddr>>,
    ) -> Vec<Vec<&'a str>> {
        let g = account_groups(targets, resolved);
        let mut out: HashMap<usize, Vec<&str>> = HashMap::new();
        for (i, k) in g.iter().enumerate() {
            out.entry(*k).or_default().push(targets[i].id.as_str());
        }
        let mut v: Vec<Vec<&str>> = out.into_values().collect();
        v.sort();
        v
    }

    /// Phase 7 (ADR-0025 consequence): aliases of one account take turns.
    #[test]
    fn aliases_of_one_account_share_the_turns() {
        let targets = [
            t("a", "engine: postgres, host: DB1.example., port: 5432"),
            t("b", "engine: postgres, host: db1.example"),
            t("c", "engine: postgres, host: 127.0.0.1"),
            t("d", "engine: postgres, host: localhost, port: 5432"),
            t("e", "engine: postgres, host: '[::1]'"),
            t("f", "engine: postgres, host: '::ffff:127.0.0.1'"),
            t("g", "engine: postgres, host: db1.example, port: 5433"),
            t("h", "engine: mysql, host: db1.example"),
            t("i", "engine: mariadb, host: db1.example, port: 3306"),
            t("j", "engine: openldap, host: ldap.example"),
            t("k", "engine: openldap, host: ldap.example, port: 636"),
            t(
                "l",
                "engine: openldap, host: ldap.example, port: 389, openldap: {tls: start_tls}",
            ),
            t(
                "m",
                "engine: openldap, host: ldap.example, openldap: {tls: start_tls}",
            ),
        ];
        assert_eq!(
            groups(&targets, &HashMap::new()),
            [
                vec!["a", "b"],
                vec!["c", "d", "e", "f"],
                vec!["g"],
                vec!["h", "i"],
                vec!["j", "k"],
                vec!["l", "m"],
            ]
        );
        // Another account, or another engine family: never shared.
        let mut other = t("z", "engine: postgres, host: db1.example");
        other.account = "b".to_owned();
        assert_eq!(
            groups(&[targets[0].clone(), other], &HashMap::new()),
            [vec!["a"], vec!["z"]]
        );
    }

    #[test]
    fn names_and_addresses_share_the_turns_once_resolved() {
        let targets = [
            t("a", "engine: postgres, host: db-a.example"),
            t("b", "engine: postgres, host: db-b.example"),
            t("c", "engine: postgres, host: 10.0.0.5"),
            t("d", "engine: postgres, host: db-d.example"),
            t("e", "engine: postgres, host: db-e.example, port: 6432"),
        ];
        // Only names that could be aliases are resolved: `e` is alone on
        // its port.
        assert_eq!(
            names_to_resolve(&targets),
            ["db-a.example", "db-b.example", "db-d.example"]
        );
        assert!(names_to_resolve(&targets[4..]).is_empty());
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let resolved: HashMap<String, Vec<IpAddr>> = [
            ("db-a.example".to_owned(), vec![ip("10.0.0.5")]),
            (
                "db-b.example".to_owned(),
                vec![ip("10.0.0.9"), ip("::ffff:10.0.0.5")],
            ),
            ("db-d.example".to_owned(), vec![ip("10.0.0.6")]),
        ]
        .into();
        assert_eq!(
            groups(&targets, &resolved),
            [vec!["a", "b", "c"], vec!["d"], vec!["e"]]
        );
        // Unresolved: literal keys only.
        assert_eq!(
            groups(&targets, &HashMap::new()),
            [vec!["a"], vec!["b"], vec!["c"], vec!["d"], vec!["e"]]
        );
    }

    #[test]
    fn sockets_share_the_turns_by_path_only() {
        let dir = std::env::temp_dir().join(format!("databastion-checks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        std::fs::write(dir.join("real/.s.PGSQL.5432"), b"").unwrap();
        let s = |id: &str, p: &str| {
            t(
                id,
                &format!("engine: postgres, socket: {}", dir.join(p).display()),
            )
        };
        let targets = [
            s("a", "real/.s.PGSQL.5432"),
            s("b", "link/.s.PGSQL.5432"),
            t("c", "engine: postgres, host: localhost"),
        ];
        assert_eq!(
            groups(&targets, &HashMap::new()),
            [vec!["a", "b"], vec!["c"]]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn turns_rotate_and_slow_checks_go_last() {
        let targets: Vec<TargetConfig> = ["a", "b", "c", "d"]
            .iter()
            .map(|id| t(id, "engine: postgres, host: db"))
            .collect();
        let members = [0, 1, 2, 3];
        let ids = |order: Vec<usize>| -> Vec<&str> {
            order.iter().map(|i| targets[*i].id.as_str()).collect()
        };
        let none = HashSet::new();
        assert_eq!(
            ids(turn_order(&members, &targets, 0, &none)),
            ["a", "b", "c", "d"]
        );
        assert_eq!(
            ids(turn_order(&members, &targets, 1, &none)),
            ["b", "c", "d", "a"]
        );
        assert_eq!(
            ids(turn_order(&members, &targets, 6, &none)),
            ["c", "d", "a", "b"]
        );
        let slow: HashSet<String> = ["a".to_owned(), "c".to_owned()].into();
        assert_eq!(
            ids(turn_order(&members, &targets, 0, &slow)),
            ["b", "d", "a", "c"]
        );
        assert_eq!(
            ids(turn_order(&members, &targets, 1, &slow)),
            ["d", "b", "a", "c"]
        );
    }

    #[test]
    fn the_cache_expires_and_is_bounded() {
        let mut c = DnsCache::default();
        let t0 = Instant::now();
        c.put("a".to_owned(), vec![IpAddr::from([10, 0, 0, 1])], t0);
        assert_eq!(c.get("a", t0).unwrap().len(), 1);
        assert!(c.get("a", t0 + DNS_TTL).is_none());
        // A lookup that did not answer in time: unresolved for a minute, a
        // later answer replaces it; a lookup in flight is not started again.
        c.put_timed_out("t".to_owned(), t0);
        assert_eq!(c.get("t", t0), Some(Vec::new()));
        assert!(c.get("t", t0 + DNS_TIMEOUT_TTL).is_none());
        assert!(c.start("t"));
        assert!(!c.start("t"));
        c.finish("t", vec![IpAddr::from([10, 0, 0, 3])], t0);
        assert_eq!(c.get("t", t0).unwrap().len(), 1);
        assert!(c.start("t"));
        c.put("b".to_owned(), vec![IpAddr::from([10, 0, 0, 2]); 40], t0);
        assert_eq!(c.get("b", t0).unwrap().len(), MAX_ADDRS);
    }
}
