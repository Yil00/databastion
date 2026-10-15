//! `targets[].redis`: settings of a Redis or Valkey target (ADR-0052).
//!
//! One declared node (decision 5): the target's `host` / `port` or
//! `socket`, and optionally a separate Discovery node (`discovery_node`,
//! a replica), both declared here (I5). TLS from the first byte with
//! `verify_full`; `disable` only on a Unix socket or a loopback IP literal
//! (decision 3: `AUTH` sends the password itself, so there is no
//! `disable_insecure`). The account is a named ACL user (`default` is
//! refused) with a password.

use std::path::PathBuf;

use serde::Deserialize;

/// Most declared key patterns (decision 4).
pub const MAX_KEY_PATTERNS: usize = 64;
/// Longest declared key pattern, in bytes.
pub const MAX_KEY_PATTERN_BYTES: usize = 512;
/// Most declared logical databases.
pub const MAX_DATABASES: usize = 64;
/// Range of `redis.max_keys` (decision 6): a local limit the console cannot
/// raise.
pub const MAX_KEYS_RANGE: (u32, u32) = (1_000, 10_000_000);
/// Default `redis.max_keys`.
pub const DEFAULT_MAX_KEYS: u32 = 100_000;
/// Most declared replica addresses (`redis.replicas`).
pub const MAX_REPLICAS: usize = 64;
/// Default TCP port of Redis and Valkey.
pub const DEFAULT_PORT: u16 = 6379;

/// TLS mode of a Redis / Valkey target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisTlsMode {
    /// TLS 1.2 or 1.3 from the first byte, certificate and host name
    /// verified against `ca_file` (then the only trusted root) or the
    /// system store.
    #[default]
    VerifyFull,
    /// No TLS: a Unix socket (peer credentials checked against
    /// `server_uid`) or a loopback IP literal only.
    Disable,
}

/// `redis.unevaluated_acl`: the local opt-in for Redis 6.2, whose account
/// cannot be evaluated without `ACL DRYRUN` (decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnevaluatedAcl {
    /// The operator reviewed the account by hand: a Redis 6.2 target runs
    /// with `privilege.not_evaluated` shown permanently.
    Accept,
}

/// A separate Discovery node (decision 5): a replica, read with the
/// target's account and TLS settings.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisNode {
    /// Host name or address (exclusive with `socket`).
    #[serde(default)]
    pub host: Option<String>,
    /// TCP port, with `host` (default 6379).
    #[serde(default)]
    pub port: Option<u16>,
    /// Unix socket path (exclusive with `host`).
    #[serde(default)]
    pub socket: Option<PathBuf>,
}

/// Redis / Valkey settings of a target.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisTargetConfig {
    /// TLS to the server. Default: `verify_full`.
    #[serde(default)]
    pub tls: RedisTlsMode,
    /// PEM CA file trusted for the server certificate (`verify_full`).
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate (optional, with `client_key`), for servers
    /// with `tls-auth-clients yes`. The agent still authenticates with
    /// `AUTH`.
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// PEM private key of `client_cert`: owned by the agent's user, `0600`
    /// (or `0640` with the agent's group), opened without following a
    /// symlink.
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    /// Keys examined per database and scan (default 100 000, 1 000 to
    /// 10 000 000).
    #[serde(default = "default_max_keys")]
    pub max_keys: u32,
    /// The node Discovery reads instead of the target's (a replica).
    #[serde(default)]
    pub discovery_node: Option<RedisNode>,
    /// Key patterns the account may read (globs with the server's syntax,
    /// at most 64; default `["*"]`): Discovery filters key names against
    /// them before any `TYPE`, so it never sends a command the ACL refuses
    /// (decision 4). Never sent to the console nor logged.
    #[serde(default = "default_key_patterns")]
    pub key_patterns: Vec<String>,
    /// Logical databases the account may select (Valkey 9.1+ `db=`);
    /// default every database.
    #[serde(default)]
    pub databases: Option<Vec<u16>>,
    /// Expected uid of the server on a Unix socket (`SO_PEERCRED`). Default:
    /// the socket file's owner, trusted only when no other user can write
    /// to the socket's directory and the owner is not the agent's own uid.
    #[serde(default)]
    pub server_uid: Option<u32>,
    /// Redis 6.2 only: run although the account cannot be evaluated.
    #[serde(default)]
    pub unevaluated_acl: Option<UnevaluatedAcl>,
    /// CAS stores under custom names (ADR-0041 decision 5): key patterns
    /// (`ticket_registry`) the CAS store guard never reads.
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
    /// The replicas' addresses, as the server lists them in `INFO
    /// replication` (IP literals, at most 64): Audit compares them with
    /// the replica of a full synchronization, which is reported anyway;
    /// an address not listed here is sent as the event's client address
    /// (ADR-0052 decision 8). Compared only, never connected to (I5).
    #[serde(default)]
    pub replicas: Vec<std::net::IpAddr>,
}

const fn default_max_keys() -> u32 {
    DEFAULT_MAX_KEYS
}

fn default_key_patterns() -> Vec<String> {
    vec!["*".to_owned()]
}

impl Default for RedisTargetConfig {
    fn default() -> Self {
        Self {
            tls: RedisTlsMode::default(),
            ca_file: None,
            client_cert: None,
            client_key: None,
            max_keys: DEFAULT_MAX_KEYS,
            discovery_node: None,
            key_patterns: default_key_patterns(),
            databases: None,
            server_uid: None,
            unevaluated_acl: None,
            cas_stores: None,
            replicas: Vec::new(),
        }
    }
}

fn loopback_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Checks one endpoint (`host` / `port` or `socket`) against the TLS mode.
pub(crate) fn validate_endpoint(
    host: Option<&str>,
    port: Option<u16>,
    socket: Option<&std::path::Path>,
    tls: RedisTlsMode,
) -> Result<(), (&'static str, &'static str)> {
    match (host, socket) {
        (Some(h), None) => {
            if h.is_empty() || h.len() > 253 || h.chars().any(char::is_control) {
                return Err(("host", "must be a host name or address"));
            }
            if port == Some(0) {
                return Err(("port", "must be in 1..=65535"));
            }
            if tls == RedisTlsMode::Disable && !loopback_literal(h) {
                return Err((
                    "tls",
                    "`disable` is only for a Unix socket or a loopback IP literal; use \
                     `verify_full` (Redis / Valkey has no `disable_insecure`: AUTH sends the \
                     password itself)",
                ));
            }
        }
        (None, Some(s)) => {
            if !s.is_absolute() {
                return Err(("socket", "must be an absolute path"));
            }
            if port.is_some() {
                return Err(("port", "not allowed with socket"));
            }
            if tls != RedisTlsMode::Disable {
                return Err((
                    "tls",
                    "a Unix socket has no TLS: set `tls: disable` for this target",
                ));
            }
        }
        _ => return Err(("host", "exactly one of host or socket is required")),
    }
    Ok(())
}

impl RedisTargetConfig {
    /// Validates the block. `Err((key, reason))`, never a value.
    pub(crate) fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        let abs = |p: &Option<PathBuf>| p.as_ref().is_none_or(|p| p.is_absolute());
        if !abs(&self.ca_file) {
            return Err(("ca_file", "must be an absolute path"));
        }
        if !abs(&self.client_cert) {
            return Err(("client_cert", "must be an absolute path"));
        }
        if !abs(&self.client_key) {
            return Err(("client_key", "must be an absolute path"));
        }
        if self.tls != RedisTlsMode::VerifyFull
            && (self.ca_file.is_some() || self.client_cert.is_some() || self.client_key.is_some())
        {
            return Err((
                "tls",
                "ca_file, client_cert and client_key need tls: verify_full",
            ));
        }
        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(("client_key", "client_cert and client_key go together"));
        }
        if !(MAX_KEYS_RANGE.0..=MAX_KEYS_RANGE.1).contains(&self.max_keys) {
            return Err(("max_keys", "must be in 1000..=10000000"));
        }
        if self.key_patterns.is_empty() || self.key_patterns.len() > MAX_KEY_PATTERNS {
            return Err(("key_patterns", "must list 1 to 64 patterns"));
        }
        if self.key_patterns.iter().any(|p| {
            p.is_empty() || p.len() > MAX_KEY_PATTERN_BYTES || p.chars().any(char::is_control)
        }) {
            return Err((
                "key_patterns",
                "a pattern is 1 to 512 bytes without control characters",
            ));
        }
        if let Some(dbs) = &self.databases {
            if dbs.is_empty() || dbs.len() > MAX_DATABASES {
                return Err(("databases", "must list 1 to 64 database indices"));
            }
            let mut seen = std::collections::HashSet::new();
            if !dbs.iter().all(|d| seen.insert(*d)) {
                return Err(("databases", "duplicate database"));
            }
        }
        if let Some(stores) = &self.cas_stores {
            stores.validate()?;
        }
        if self.replicas.len() > MAX_REPLICAS {
            return Err(("replicas", "must list at most 64 addresses"));
        }
        if let Some(node) = &self.discovery_node {
            validate_endpoint(
                node.host.as_deref(),
                node.port,
                node.socket.as_deref(),
                self.tls,
            )
            .map_err(|(key, reason)| match key {
                "host" => ("discovery_node.host", reason),
                "port" => ("discovery_node.port", reason),
                "socket" => ("discovery_node.socket", reason),
                _ => ("discovery_node", reason),
            })?;
        }
        Ok(())
    }
}
