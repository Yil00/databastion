//! Local agent configuration (`agent.yaml`).
//!
//! The configuration is the source of truth for targets and credentials
//! (ADR-0006, I3): it never transits through the console. It holds
//! **references** to database secrets (an environment variable name or a
//! file path), never a secret inline.
//!
//! Every struct uses `deny_unknown_fields`, so a misplaced `password:` key is
//! rejected instead of being silently ignored. Error messages never contain
//! a configuration value: parse errors are reduced to their location and a
//! sanitized message where every quoted token that is not a known key of
//! this schema is redacted.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::engine::Engine;

/// Hard upper bound on the rows sampled per object (contract `sample_rows`
/// range is `1..=10000`).
pub const SAMPLE_ROWS_RANGE: (u32, u32) = (1, 10_000);
/// Statement timeout bounds, in milliseconds (contract range; never `0`).
pub const STATEMENT_TIMEOUT_MS_RANGE: (u32, u32) = (100, 600_000);
/// Scan duration bounds, in seconds.
pub const SCAN_DURATION_S_RANGE: (u32, u32) = (60, 86_400);
/// Maximum number of declared targets (contract `HeartbeatRequest.targets`).
pub const MAX_TARGETS: usize = 64;

/// Errors raised while loading or validating `agent.yaml`. They never carry
/// a configuration value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read configuration file {path}: {kind}")]
    Io {
        /// Path of the configuration file.
        path: PathBuf,
        /// I/O error kind (no message: it could echo content).
        kind: std::io::ErrorKind,
    },
    /// The YAML is malformed or does not match the schema.
    #[error("invalid configuration at line {line}, column {column}: {message}")]
    Parse {
        /// 1-based line, 0 when unknown.
        line: usize,
        /// 1-based column, 0 when unknown.
        column: usize,
        /// Sanitized message (values redacted).
        message: String,
    },
    /// A field has an invalid value.
    #[error("invalid configuration: {field}: {reason}")]
    Invalid {
        /// Path of the field, e.g. `targets[0].port`.
        field: String,
        /// Why the value is rejected (never the value itself).
        reason: &'static str,
    },
}

fn invalid(field: impl Into<String>, reason: &'static str) -> ConfigError {
    ConfigError::Invalid {
        field: field.into(),
        reason,
    }
}

/// Validated agent configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Console connection.
    pub console: ConsoleConfig,
    /// Directory holding the identity, the pending secret, the HMAC key and
    /// (later) the spool. Created with `0700` if missing.
    pub state_dir: PathBuf,
    /// Local hard limits; console job parameters are clamped to them (I4).
    #[serde(default)]
    pub limits: Limits,
    /// Declared targets (ADR-0006). The agent connects to nothing else.
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
    /// Local metrics options (ADR-0004).
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Console connection settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Base URL of the console, e.g. `https://console.example.internal`.
    /// The agent API path `/api/agent/v1` is appended.
    pub url: String,
    /// PEM file of the CA that signs the console certificate. When set, it
    /// is the **only** trusted root (pinning); otherwise the system store is
    /// used.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Long-poll `wait` for `GET /jobs`, `0..=25` (lower it behind a proxy
    /// with a short idle timeout).
    #[serde(default = "default_wait")]
    pub long_poll_wait_s: u8,
    /// Development only: allow `http://` for a console on `127.0.0.1`,
    /// `::1` or `localhost`. Rejected for any other host.
    #[serde(default)]
    pub insecure_dev_http: bool,
}

const fn default_wait() -> u8 {
    25
}

/// Local hard limits (I4). They cap what the console may request.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum rows sampled per object.
    #[serde(default = "default_sample_rows")]
    pub max_sample_rows: u32,
    /// Statement timeout applied to every query, in milliseconds (never 0).
    #[serde(default = "default_statement_timeout")]
    pub statement_timeout_ms: u32,
    /// Maximum duration of a scan, in seconds.
    #[serde(default = "default_scan_duration")]
    pub max_scan_duration_s: u32,
}

const fn default_sample_rows() -> u32 {
    1_000
}
const fn default_statement_timeout() -> u32 {
    30_000
}
const fn default_scan_duration() -> u32 {
    3_600
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sample_rows: default_sample_rows(),
            statement_timeout_ms: default_statement_timeout(),
            max_scan_duration_s: default_scan_duration(),
        }
    }
}

impl Limits {
    /// Clamps a console-requested sample size to `1..=max_sample_rows`.
    #[must_use]
    pub fn clamp_sample_rows(&self, requested: u64) -> u32 {
        let requested = u32::try_from(requested).unwrap_or(u32::MAX);
        requested.clamp(SAMPLE_ROWS_RANGE.0, self.max_sample_rows)
    }

    /// Clamps a console-requested statement timeout. `0` (unlimited) and
    /// anything above the local cap become the local cap; never `0`.
    #[must_use]
    pub fn clamp_statement_timeout(&self, requested_ms: u64) -> Duration {
        let cap = u64::from(self.statement_timeout_ms);
        let ms = if requested_ms == 0 {
            cap
        } else {
            requested_ms.clamp(u64::from(STATEMENT_TIMEOUT_MS_RANGE.0), cap)
        };
        Duration::from_millis(ms)
    }

    /// Clamps a console-requested scan duration; `0` means the local cap.
    #[must_use]
    pub fn clamp_scan_duration(&self, requested_s: u64) -> Duration {
        let cap = u64::from(self.max_scan_duration_s);
        let s = if requested_s == 0 {
            cap
        } else {
            requested_s.min(cap)
        };
        Duration::from_secs(s)
    }
}

/// Engine of a declared target. `mariadb` uses the MySQL connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetEngine {
    /// PostgreSQL.
    Postgres,
    /// MySQL.
    Mysql,
    /// MariaDB (MySQL connector).
    Mariadb,
    /// MongoDB.
    Mongodb,
    /// OpenLDAP.
    Openldap,
}

impl TargetEngine {
    /// Connector engine handling this target.
    #[must_use]
    pub const fn connector(self) -> Engine {
        match self {
            Self::Postgres => Engine::Postgres,
            Self::Mysql | Self::Mariadb => Engine::Mysql,
            Self::Mongodb => Engine::Mongodb,
            Self::Openldap => Engine::Openldap,
        }
    }
}

/// A declared target.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Stable slug reported to the console (`TargetId`); no host name.
    pub id: String,
    /// Engine.
    pub engine: TargetEngine,
    /// Host name or address (exclusive with `socket`). Never sent to the
    /// console.
    #[serde(default)]
    pub host: Option<String>,
    /// TCP port, with `host`.
    #[serde(default)]
    pub port: Option<u16>,
    /// Unix socket path (exclusive with `host`).
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// Least-privilege read-only account (I4).
    pub account: String,
    /// Where the account secret is read from. Never the secret itself (I3).
    pub secret: SecretRef,
}

/// Reference to a database secret: exactly one of `env` (variable name) or
/// `file` (absolute path, `0600`). The value is read on the agent host only
/// when a connector needs it (I3).
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Name of an environment variable.
    #[serde(default)]
    pub env: Option<String>,
    /// Absolute path of a file.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A reference is not a secret; the output stays minimal anyway.
        match (&self.env, &self.file) {
            (Some(name), _) => write!(f, "SecretRef::Env({name})"),
            (None, Some(path)) => write!(f, "SecretRef::File({})", path.display()),
            (None, None) => f.write_str("SecretRef::None"),
        }
    }
}

/// Local metrics options (ADR-0004).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Not implemented: a local listener is an I1 exception that needs a
    /// reviewed allowlist entry. Rejected if set.
    #[serde(default)]
    pub local_listen: Option<serde_yaml_ng::Value>,
}

/// Keys of this schema: the only quoted tokens kept in parse errors.
const KNOWN_KEYS: &[&str] = &[
    "console",
    "url",
    "ca_file",
    "long_poll_wait_s",
    "insecure_dev_http",
    "state_dir",
    "limits",
    "max_sample_rows",
    "statement_timeout_ms",
    "max_scan_duration_s",
    "targets",
    "id",
    "engine",
    "host",
    "port",
    "socket",
    "account",
    "secret",
    "env",
    "file",
    "metrics",
    "local_listen",
    "postgres",
    "mysql",
    "mariadb",
    "mongodb",
    "openldap",
];

/// Redacts every `` `quoted` `` or `"quoted"` token that is not a known key.
fn sanitize_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut chars = message.chars();
    while let Some(c) = chars.next() {
        if c == '`' || c == '"' {
            let token: String = chars.by_ref().take_while(|&d| d != c).collect();
            if KNOWN_KEYS.contains(&token.as_str()) {
                out.push(c);
                out.push_str(&token);
                out.push(c);
            } else {
                out.push_str("[redacted]");
            }
        } else {
            out.push(c);
        }
    }
    // Drop anything after a line break (serde_yaml_ng may append context).
    out.lines().next().unwrap_or("").chars().take(200).collect()
}

impl AgentConfig {
    /// Reads and validates `agent.yaml`.
    ///
    /// # Errors
    /// [`ConfigError`] without any configuration value.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_owned(),
            kind: e.kind(),
        })?;
        Self::parse(&text)
    }

    /// Parses and validates a YAML document.
    ///
    /// # Errors
    /// [`ConfigError`] without any configuration value.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml_ng::from_str(text).map_err(|e| {
            let (line, column) = e.location().map_or((0, 0), |l| (l.line(), l.column()));
            ConfigError::Parse {
                line,
                column,
                message: sanitize_message(&e.to_string()),
            }
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.metrics.local_listen.is_some() {
            return Err(invalid(
                "metrics.local_listen",
                "not implemented: a local metrics listener is an exception to I1 that \
                 requires a reviewed allowlist entry (ADR-0004, pending); remove this key",
            ));
        }
        self.console_url()?;
        if self.console.long_poll_wait_s > 25 {
            return Err(invalid("console.long_poll_wait_s", "must be in 0..=25"));
        }
        if self
            .console
            .ca_file
            .as_ref()
            .is_some_and(|ca| !ca.is_absolute())
        {
            return Err(invalid("console.ca_file", "must be an absolute path"));
        }
        if !self.state_dir.is_absolute() {
            return Err(invalid("state_dir", "must be an absolute path"));
        }
        self.validate_limits()?;
        if self.targets.len() > MAX_TARGETS {
            return Err(invalid("targets", "at most 64 targets"));
        }
        let mut ids = HashSet::new();
        for (i, target) in self.targets.iter().enumerate() {
            target.validate(i)?;
            if !ids.insert(target.id.as_str()) {
                return Err(invalid(format!("targets[{i}].id"), "duplicate target id"));
            }
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        let in_range = |v: u32, (lo, hi): (u32, u32)| (lo..=hi).contains(&v);
        if !in_range(l.max_sample_rows, SAMPLE_ROWS_RANGE) {
            return Err(invalid("limits.max_sample_rows", "must be in 1..=10000"));
        }
        if !in_range(l.statement_timeout_ms, STATEMENT_TIMEOUT_MS_RANGE) {
            return Err(invalid(
                "limits.statement_timeout_ms",
                "must be in 100..=600000 (never 0)",
            ));
        }
        if !in_range(l.max_scan_duration_s, SCAN_DURATION_S_RANGE) {
            return Err(invalid(
                "limits.max_scan_duration_s",
                "must be in 60..=86400",
            ));
        }
        Ok(())
    }

    /// Validated console base URL with the agent API path
    /// (`…/api/agent/v1`), without a trailing slash.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] on a non-HTTPS URL (except the loopback
    /// development exception), credentials, query or fragment.
    pub fn console_url(&self) -> Result<reqwest::Url, ConfigError> {
        const F: &str = "console.url";
        let url = reqwest::Url::parse(&self.console.url)
            .map_err(|_| invalid(F, "not a valid absolute URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(F, "must not contain credentials"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid(F, "must not contain a query or fragment"));
        }
        match url.scheme() {
            "https" => {
                if self.console.insecure_dev_http {
                    return Err(invalid(
                        "console.insecure_dev_http",
                        "only allowed with an http:// loopback URL",
                    ));
                }
            }
            "http" => {
                if !self.console.insecure_dev_http {
                    return Err(invalid(F, "must use https"));
                }
                if !is_loopback_host(&url) {
                    return Err(invalid(
                        F,
                        "http is only allowed for 127.0.0.1, ::1 or localhost \
                         (insecure_dev_http)",
                    ));
                }
            }
            _ => return Err(invalid(F, "must use https")),
        }
        let base = format!("{}/api/agent/v1", url.as_str().trim_end_matches('/'));
        reqwest::Url::parse(&base).map_err(|_| invalid(F, "not a valid absolute URL"))
    }
}

fn is_loopback_host(url: &reqwest::Url) -> bool {
    // `host_str` is normalized by the URL parser (lowercase, IPv6 in
    // brackets, IPv4 in dotted decimal).
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && name.len() <= 128
}

impl TargetConfig {
    fn validate(&self, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].{name}");
        if databastion_protocol::TargetId::try_from(self.id.as_str()).is_err() {
            return Err(invalid(
                f("id"),
                "must be a slug matching ^[a-z0-9][a-z0-9_.-]{0,62}$",
            ));
        }
        match (&self.host, &self.socket) {
            (Some(host), None) => {
                if host.is_empty() || host.len() > 253 || host.chars().any(char::is_control) {
                    return Err(invalid(f("host"), "must be a host name or address"));
                }
                if self.port == Some(0) {
                    return Err(invalid(f("port"), "must be in 1..=65535"));
                }
            }
            (None, Some(socket)) => {
                if !socket.is_absolute() {
                    return Err(invalid(f("socket"), "must be an absolute path"));
                }
                if self.port.is_some() {
                    return Err(invalid(f("port"), "not allowed with socket"));
                }
            }
            _ => {
                return Err(invalid(
                    f("host"),
                    "exactly one of host or socket is required",
                ));
            }
        }
        if self.account.is_empty()
            || self.account.len() > 128
            || self.account.chars().any(char::is_control)
        {
            return Err(invalid(
                f("account"),
                "must be 1 to 128 characters without control characters",
            ));
        }
        match (&self.secret.env, &self.secret.file) {
            (Some(name), None) if !is_env_name(name) => Err(invalid(
                f("secret.env"),
                "must be an environment variable name (^[A-Z_][A-Z0-9_]*$), never the secret",
            )),
            (None, Some(path)) if !path.is_absolute() => {
                Err(invalid(f("secret.file"), "must be an absolute path"))
            }
            (Some(_), None) | (None, Some(_)) => Ok(()),
            _ => Err(invalid(
                f("secret"),
                "exactly one of env or file is required",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: pg-main
    engine: postgres
    host: db1.internal
    port: 5432
    account: databastion
    secret:
      env: DATABASTION_PG_MAIN_PASSWORD
  - id: ldap
    engine: openldap
    socket: /run/slapd/ldapi
    account: cn=databastion,dc=example,dc=com
    secret:
      file: /etc/databastion/secrets/ldap
";

    fn parse(text: &str) -> Result<AgentConfig, ConfigError> {
        AgentConfig::parse(text)
    }

    fn err(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn example_file_is_valid() {
        let text = include_str!("../../../agent.example.yaml");
        let cfg = parse(text).unwrap();
        assert!(!cfg.targets.is_empty());
    }

    #[test]
    fn base_config_parses_with_defaults() {
        let cfg = parse(BASE).unwrap();
        assert_eq!(cfg.limits, Limits::default());
        assert_eq!(cfg.console.long_poll_wait_s, 25);
        assert_eq!(
            cfg.console_url().unwrap().as_str(),
            "https://console.example.internal/api/agent/v1"
        );
        assert_eq!(cfg.targets[1].engine.connector(), Engine::Openldap);
    }

    #[test]
    fn inline_password_is_rejected_without_echo() {
        let text = BASE.replace(
            "    account: databastion\n",
            "    account: databastion\n    password: hunter2-SECRET\n",
        );
        let message = err(&text);
        assert!(message.contains("unknown field"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn secret_given_inline_is_rejected_without_echo() {
        let text = BASE.replace(
            "    secret:\n      env: DATABASTION_PG_MAIN_PASSWORD\n",
            "    secret: hunter2-SECRET\n",
        );
        let message = err(&text);
        assert!(!message.contains("hunter2"), "{message}");
        let text = BASE.replace("DATABASTION_PG_MAIN_PASSWORD", "hunter2-SECRET");
        let message = err(&text);
        assert!(message.contains("secret.env"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn invalid_values_are_never_echoed() {
        for (from, to) in [
            ("port: 5432", "port: hunter2-SECRET"),
            ("engine: postgres", "engine: hunter2-SECRET"),
            ("id: pg-main", "id: \"hunter2-SECRET\""),
        ] {
            let message = err(&BASE.replace(from, to));
            assert!(!message.contains("hunter2"), "{message}");
        }
    }

    #[test]
    fn console_url_must_be_https() {
        for url in [
            "http://console.example.internal",
            "ftp://console.example.internal",
            "https://user:pw@console.example.internal",
            "https://console.example.internal/?a=b",
            "not a url",
        ] {
            let text = BASE.replace("https://console.example.internal", url);
            let message = err(&text);
            assert!(message.contains("console.url"), "{url}: {message}");
            assert!(!message.contains("pw@"), "{message}");
        }
    }

    #[test]
    fn insecure_dev_http_only_for_loopback() {
        let dev = |url: &str| {
            BASE.replace(
                "  url: https://console.example.internal\n",
                &format!("  url: {url}\n  insecure_dev_http: true\n"),
            )
        };
        for ok in [
            "http://127.0.0.1:8080",
            "http://localhost:3000",
            "http://[::1]:3000",
        ] {
            assert!(parse(&dev(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "http://10.0.0.1:8080",
            "http://console.example.internal",
            "http://127.0.0.2",
            "https://console.example.internal",
        ] {
            assert!(parse(&dev(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn local_listen_is_rejected_with_reference() {
        let text = format!("{BASE}metrics:\n  local_listen: 127.0.0.1:9464\n");
        let message = err(&text);
        assert!(message.contains("metrics.local_listen"), "{message}");
        assert!(message.contains("ADR-0004"), "{message}");
    }

    #[test]
    fn limits_are_bounded() {
        for (key, value) in [
            ("max_sample_rows", "0"),
            ("max_sample_rows", "10001"),
            ("statement_timeout_ms", "0"),
            ("statement_timeout_ms", "600001"),
            ("max_scan_duration_s", "10"),
        ] {
            let text = format!("{BASE}limits:\n  {key}: {value}\n");
            assert!(err(&text).contains(key), "{key}={value}");
        }
    }

    #[test]
    fn clamps_never_exceed_local_caps() {
        let limits = Limits {
            max_sample_rows: 500,
            statement_timeout_ms: 10_000,
            max_scan_duration_s: 600,
        };
        assert_eq!(limits.clamp_sample_rows(0), 1);
        assert_eq!(limits.clamp_sample_rows(10_000), 500);
        assert_eq!(limits.clamp_sample_rows(u64::MAX), 500);
        assert_eq!(limits.clamp_statement_timeout(0), Duration::from_secs(10));
        assert_eq!(
            limits.clamp_statement_timeout(1),
            Duration::from_millis(100)
        );
        assert_eq!(
            limits.clamp_statement_timeout(600_000),
            Duration::from_secs(10)
        );
        assert_eq!(limits.clamp_scan_duration(0), Duration::from_secs(600));
        assert_eq!(limits.clamp_scan_duration(60), Duration::from_secs(60));
    }

    #[test]
    fn target_rules() {
        let cases = [
            ("id: pg-main", "id: PG_Main", "targets[0].id"),
            (
                "    port: 5432\n",
                "    port: 5432\n    socket: /run/x\n",
                "targets[0].host",
            ),
            (
                "    host: db1.internal\n    port: 5432\n",
                "",
                "targets[0].host",
            ),
            (
                "socket: /run/slapd/ldapi",
                "socket: run/slapd",
                "targets[1].socket",
            ),
            (
                "file: /etc/databastion/secrets/ldap",
                "file: secrets/ldap",
                "targets[1].secret.file",
            ),
            (
                "account: databastion\n",
                "account: \"\"\n",
                "targets[0].account",
            ),
        ];
        for (from, to, field) in cases {
            let message = err(&BASE.replacen(from, to, 1));
            assert!(message.contains(field), "{field}: {message}");
        }
        let dup = BASE.replace("id: ldap", "id: pg-main");
        assert!(err(&dup).contains("duplicate"));
    }

    #[test]
    fn sanitizer_keeps_known_keys_only() {
        assert_eq!(
            sanitize_message("unknown field `password`, expected one of `id`, `engine`"),
            "unknown field [redacted], expected one of `id`, `engine`"
        );
        assert_eq!(
            sanitize_message("invalid type: string \"s3cr3t\", expected u16\nmore"),
            "invalid type: string [redacted], expected u16"
        );
    }
}
