//! `INFO` sections reduced to the facts the connector needs (ADR-0052
//! decisions 2, 5, 6 and 9): the engine and its version, the mode, the
//! role, Cluster, and the databases holding keys. `executable`,
//! `config_file`, the replication peers' addresses and every other field
//! are never kept nor logged.

/// The Redis refusal floor (decision 2, N1 gate): pending the maintainer's
/// decision, the first 6.2 patch measured to redact `CONFIG SET
/// masterauth` and `MIGRATE … AUTH` in the slow log (P9-D facts). One
/// constant: changing the floor is one line.
pub(crate) const REDIS_FLOOR: Version = Version(6, 2, 7);
/// The Valkey refusal floor (decision 2).
pub(crate) const VALKEY_FLOOR: Version = Version(7, 2, 0);
/// Most logical databases read (decision 6).
pub(crate) const MAX_DATABASES: usize = 16;

/// A server version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct Version(pub(crate) u32, pub(crate) u32, pub(crate) u32);

impl Version {
    /// `x.y.z` (a missing part is 0); `None` on anything else.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().splitn(3, '.');
        let mut next = || -> Option<u32> {
            match parts.next() {
                None => Some(0),
                Some(p) => {
                    let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
                    if digits.is_empty() || digits.len() > 6 {
                        None
                    } else {
                        digits.parse().ok()
                    }
                }
            }
        };
        Some(Self(next()?, next()?, next()?))
    }
}

/// The engine a server is (decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Server {
    Redis(Version),
    Valkey(Version),
}

impl Server {
    /// Whether the version is at or above its engine's floor.
    pub(crate) fn supported(self) -> bool {
        match self {
            Self::Redis(v) => v >= REDIS_FLOOR,
            Self::Valkey(v) => v >= VALKEY_FLOOR,
        }
    }

    /// `ACL DRYRUN` (Redis 7.0+, every supported Valkey).
    pub(crate) fn has_dryrun(self) -> bool {
        match self {
            Self::Redis(v) => v >= Version(7, 0, 0),
            Self::Valkey(_) => true,
        }
    }

    /// `CLIENT NO-TOUCH` (Redis 7.2+, every supported Valkey; P9-D facts).
    pub(crate) fn has_no_touch(self) -> bool {
        match self {
            Self::Redis(v) => v >= Version(7, 2, 0),
            Self::Valkey(_) => true,
        }
    }

    /// Valkey's command log (`COMMANDLOG`, Valkey 8.1+; P9-D facts): there
    /// `SLOWLOG GET` and `COMMANDLOG GET … slow` read the same log.
    pub(crate) fn has_commandlog(self) -> bool {
        matches!(self, Self::Valkey(v) if v >= Version(8, 1, 0))
    }

    /// Per-database ACL permissions (`db=`, Valkey 9.1+).
    pub(crate) fn has_db_acl(self) -> bool {
        matches!(self, Self::Valkey(v) if v >= Version(9, 1, 0))
    }

    pub(crate) fn is_valkey(self) -> bool {
        matches!(self, Self::Valkey(_))
    }

    pub(crate) fn version(self) -> Version {
        match self {
            Self::Redis(v) | Self::Valkey(v) => v,
        }
    }
}

/// The `key:value` fields of an `INFO` reply, looked up by name. Lines are
/// bounded by the reply cap; only the named fields are read.
pub(crate) fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k == name).then(|| v.trim_end_matches('\r'))
    })
}

/// The engine and version of `INFO server` (decision 9): Valkey when
/// `server_name:valkey` or `valkey_version` is present (its version from
/// `valkey_version`), Redis otherwise (from `redis_version`).
pub(crate) fn server(text: &str) -> Option<Server> {
    if let Some(v) = field(text, "valkey_version") {
        return Version::parse(v).map(Server::Valkey);
    }
    if field(text, "server_name") == Some("valkey") {
        // A Valkey server without `valkey_version`: its `redis_version` is
        // frozen at 7.2.4 (Context), the floor's own version.
        return Some(Server::Valkey(VALKEY_FLOOR));
    }
    field(text, "redis_version")
        .and_then(Version::parse)
        .map(Server::Redis)
}

/// The server run of `INFO server` (`run_id`, which changes at every
/// restart) as the first 8 bytes of its SHA-256: compared, persisted in
/// the Audit cursor, never sent nor logged (review L2).
pub(crate) fn run_hash(text: &str) -> Option<u64> {
    use sha2::Digest as _;
    let run = field(text, "run_id")?;
    let d = sha2::Sha256::digest(run.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(d.get(..8)?);
    Some(u64::from_be_bytes(b))
}

/// Whether `INFO server` reports Sentinel mode.
pub(crate) fn is_sentinel(text: &str) -> bool {
    field(text, "redis_mode") == Some("sentinel")
}

/// Whether `INFO cluster` reports Cluster mode.
pub(crate) fn cluster_enabled(text: &str) -> bool {
    field(text, "cluster_enabled") == Some("1")
}

/// Whether `INFO replication` reports a replica.
pub(crate) fn is_replica(text: &str) -> bool {
    matches!(field(text, "role"), Some("slave" | "replica"))
}

/// The databases of `INFO keyspace` that hold keys (`db<index>:keys=<n>,…`),
/// at most [`MAX_DATABASES`], by index.
pub(crate) fn keyspace(text: &str) -> Vec<(u16, u64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(index) = name.strip_prefix("db").and_then(|i| i.parse::<u16>().ok()) else {
            continue;
        };
        let keys = rest
            .split(',')
            .find_map(|kv| kv.strip_prefix("keys="))
            .and_then(|n| n.trim_end_matches('\r').parse::<u64>().ok())
            .unwrap_or(0);
        if keys > 0 && out.len() < MAX_DATABASES {
            out.push((index, keys));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_and_floors() {
        let valkey = "# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:9.0.6\r\nredis_mode:standalone\r\n";
        assert_eq!(server(valkey), Some(Server::Valkey(Version(9, 0, 6))));
        assert!(!is_sentinel(valkey));
        let redis = "# Server\r\nredis_version:8.10.2\r\nredis_mode:sentinel\r\n";
        assert_eq!(server(redis), Some(Server::Redis(Version(8, 10, 2))));
        assert!(is_sentinel(redis));
        assert!(Server::Redis(Version(6, 2, 7)).supported());
        assert!(!Server::Redis(Version(6, 2, 6)).supported());
        assert!(!Server::Redis(Version(6, 0, 20)).supported());
        assert!(Server::Valkey(Version(7, 2, 0)).supported());
        assert!(!Server::Valkey(Version(7, 0, 9)).supported());
        assert!(!Server::Redis(Version(6, 2, 24)).has_dryrun());
        assert!(Server::Redis(Version(7, 0, 0)).has_dryrun());
        assert!(!Server::Redis(Version(7, 0, 15)).has_no_touch());
        assert!(Server::Valkey(Version(9, 1, 2)).has_db_acl());
        assert!(!Server::Valkey(Version(9, 0, 6)).has_db_acl());
        assert_eq!(Version::parse("8.0"), Some(Version(8, 0, 0)));
        assert_eq!(Version::parse("x"), None);
    }

    #[test]
    fn keyspace_and_roles() {
        let ks = "# Keyspace\r\ndb0:keys=217,expires=0,avg_ttl=0\r\ndb1:keys=20,expires=0\r\ndb2:keys=0\r\n";
        assert_eq!(keyspace(ks), vec![(0, 217), (1, 20)]);
        assert!(is_replica("role:slave\r\n"));
        assert!(!is_replica("role:master\r\n"));
        assert!(cluster_enabled("cluster_enabled:1\r\n"));
        let a = run_hash("run_id:aa\r\n").unwrap();
        assert_ne!(Some(a), run_hash("run_id:ab\r\n"));
        assert_eq!(run_hash("redis_version:7\r\n"), None);
    }
}
