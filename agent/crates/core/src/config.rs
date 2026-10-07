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

pub mod cas;

/// Hard upper bound on the rows sampled per object (contract `sample_rows`
/// range is `1..=10000`).
pub const SAMPLE_ROWS_RANGE: (u32, u32) = (1, 10_000);
/// Statement timeout bounds, in milliseconds (contract range; never `0`).
pub const STATEMENT_TIMEOUT_MS_RANGE: (u32, u32) = (100, 600_000);
/// Scan duration bounds, in seconds.
pub const SCAN_DURATION_S_RANGE: (u32, u32) = (60, 86_400);
/// Minimum long-poll wait outside the loopback development mode.
pub const MIN_LONG_POLL_WAIT_S: u8 = 5;
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
    /// Bounds of the disk spool (`<state_dir>/spool`).
    #[serde(default)]
    pub spool: SpoolConfig,
}

/// Bounds of the disk spool. When full, the oldest batches are dropped.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpoolConfig {
    /// Total bytes of spooled batches (default 256 MiB, 2 MiB..=64 GiB).
    #[serde(default = "default_spool_bytes")]
    pub max_bytes: u64,
    /// Number of spooled batches (default 10000, 1..=1000000).
    #[serde(default = "default_spool_batches")]
    pub max_batches: u32,
}

const fn default_spool_bytes() -> u64 {
    256 * 1024 * 1024
}
const fn default_spool_batches() -> u32 {
    10_000
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_spool_bytes(),
            max_batches: default_spool_batches(),
        }
    }
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
    /// Long-poll `wait` for `GET /jobs`, `5..=25` (lower it behind a proxy
    /// with a short idle timeout). Values below 5 are only accepted with
    /// `insecure_dev_http` (tests).
    #[serde(default = "default_wait")]
    pub long_poll_wait_s: u8,
    /// Development only: allow `http://` for a console on `127.0.0.1` or
    /// `[::1]` (IP literals only). Rejected for any other host.
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
    /// Shortest polling interval of audit sources, in seconds (console
    /// `poll_interval_s` values below it are raised to it).
    #[serde(default = "default_audit_poll")]
    pub min_audit_poll_interval_s: u32,
    /// Discovery duty cycle, in percent (1 to 100, `100`: no pacing):
    /// after each object's sampling (and each catalog read), the scan
    /// pauses so that the agent's time in queries is at most this share of
    /// the scan's time (`crate::pacing`, ADR-0035 proposed). Default 1: at
    /// most 1 % of one server core per scan (scans run one at a time), so
    /// under the 2 % MVP criterion even on a one-core server.
    #[serde(default = "default_duty_cycle")]
    pub discovery_duty_cycle_percent: u8,
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
const fn default_audit_poll() -> u32 {
    5
}
const fn default_duty_cycle() -> u8 {
    crate::pacing::DEFAULT_DUTY_CYCLE_PERCENT
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sample_rows: default_sample_rows(),
            statement_timeout_ms: default_statement_timeout(),
            max_scan_duration_s: default_scan_duration(),
            min_audit_poll_interval_s: default_audit_poll(),
            discovery_duty_cycle_percent: default_duty_cycle(),
        }
    }
}

impl Limits {
    /// Clamps a console-requested sample size to `1..=max_sample_rows`.
    #[must_use]
    pub fn clamp_sample_rows(&self, requested: u64) -> u32 {
        let requested = u32::try_from(requested).unwrap_or(u32::MAX);
        // Never `clamp`: its bounds come from the configuration (a panic
        // if they were ever inverted).
        requested.min(self.max_sample_rows).max(SAMPLE_ROWS_RANGE.0)
    }

    /// Clamps a console-requested statement timeout. `0` (unlimited) and
    /// anything above the local cap become the local cap; never `0`.
    #[must_use]
    pub fn clamp_statement_timeout(&self, requested_ms: u64) -> Duration {
        let cap = u64::from(self.statement_timeout_ms);
        let ms = if requested_ms == 0 {
            cap
        } else {
            requested_ms
                .min(cap)
                .max(u64::from(STATEMENT_TIMEOUT_MS_RANGE.0))
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
    /// Apereo CAS: local files only (`cas:` block; ADR-0041).
    Cas,
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
            Self::Cas => Engine::Cas,
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
    /// Least-privilege read-only account (I4). Required for every engine
    /// except `cas`, where it is refused (a `cas` target reads local files
    /// only, ADR-0041 decision 3).
    #[serde(default)]
    pub account: String,
    /// Where the account secret is read from. Never the secret itself (I3).
    /// Required for every target except an OpenLDAP target that binds with
    /// SASL `EXTERNAL` (`openldap.bind: sasl_external`) and a `cas` target,
    /// where it is refused.
    #[serde(default)]
    pub secret: SecretRef,
    /// Region of national phone numbers without `+` in this target (`fr`),
    /// used to normalize them before fingerprinting. Absent: unknown (the
    /// digits are fingerprinted as they are).
    #[serde(default)]
    pub phone_region: Option<PhoneRegionConfig>,
    /// PostgreSQL settings (`engine: postgres` only).
    #[serde(default)]
    pub postgres: Option<PostgresTargetConfig>,
    /// MySQL / MariaDB settings (`engine: mysql` or `mariadb` only).
    #[serde(default)]
    pub mysql: Option<MysqlTargetConfig>,
    /// MongoDB settings (`engine: mongodb` only).
    #[serde(default)]
    pub mongodb: Option<MongodbTargetConfig>,
    /// OpenLDAP settings (`engine: openldap` only).
    #[serde(default)]
    pub openldap: Option<OpenldapTargetConfig>,
    /// Apereo CAS settings (`engine: cas` only, required there): local
    /// paths only.
    #[serde(default)]
    pub cas: Option<cas::RawCasSettings>,
    /// The `cas` block validated and its paths resolved when the
    /// configuration was loaded ([`AgentConfig::parse`]).
    #[serde(skip)]
    cas_resolved: Option<cas::CasSettings>,
}

/// Maximum number of databases declared for one PostgreSQL target.
pub const MAX_PG_DATABASES: usize = 16;

/// PostgreSQL settings of a target.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresTargetConfig {
    /// Databases the agent connects to (1..=16), in order. A scan covers
    /// those matching the job's `databases` filter. Default: `postgres`.
    #[serde(default = "default_pg_databases")]
    pub databases: Vec<String>,
    /// TLS to the server. Default: `verify_full`.
    #[serde(default)]
    pub tls: PgTlsMode,
    /// PEM CA file trusted for the server certificate (`verify_full`).
    /// When set, it is the only trusted root; otherwise the system store.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// ADR-0012 extended grant variant: the role is expected to be a member
    /// of `pg_read_all_data` / `pg_read_all_settings`. `check()` then
    /// reports that membership as an expected warning instead of
    /// over-privilege.
    #[serde(default)]
    pub extended_grants: bool,
    /// pgaudit log read by the Audit connector (P4-A): the server log file
    /// (`log_destination` `jsonlog` or `csvlog`), read locally through the
    /// file system, never through SQL (ADR-0012 "Audit log files").
    /// Without it, Audit uses `pg_stat_statements` (Limited).
    #[serde(default)]
    pub audit_log: Option<PgAuditLogConfig>,
    /// CAS stores under custom names (ADR-0041 decision 5): tables or
    /// collections the CAS store guard treats as a ticket registry, a
    /// service registry or an audit trail, in addition to the built-in
    /// names, column shapes and the ticket-id tripwire (always on).
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
}

/// Format of a PostgreSQL server log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PgLogFormat {
    /// `log_destination = jsonlog` (PostgreSQL 15+), one JSON object per
    /// line.
    Jsonlog,
    /// `log_destination = csvlog`.
    Csvlog,
}

/// Server log file holding the pgaudit records of a PostgreSQL target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgAuditLogConfig {
    /// Absolute path of the current log file (a fixed `log_filename`, e.g.
    /// `/var/log/postgresql/postgresql.json`). Rotation by rename or
    /// truncation is followed.
    pub path: PathBuf,
    /// File format.
    pub format: PgLogFormat,
}

fn default_pg_databases() -> Vec<String> {
    vec!["postgres".to_owned()]
}

impl Default for PostgresTargetConfig {
    fn default() -> Self {
        Self {
            databases: default_pg_databases(),
            tls: PgTlsMode::default(),
            ca_file: None,
            extended_grants: false,
            audit_log: None,
            cas_stores: None,
        }
    }
}

/// TLS mode of a PostgreSQL target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgTlsMode {
    /// TLS required, certificate and host name verified (rustls).
    #[default]
    VerifyFull,
    /// No TLS: a Unix socket or a loopback IP literal only (rejected for
    /// any other host). Cleartext and MD5 password requests are refused by
    /// the connector.
    Disable,
    /// No TLS on a network connection: explicit, insecure opt-in (e.g. an
    /// isolated container network). Traffic is readable and alterable on
    /// the path; warned at every connection and in `check()`.
    DisableInsecure,
}

impl TargetConfig {
    /// PostgreSQL settings, defaults when absent.
    #[must_use]
    pub fn postgres_settings(&self) -> PostgresTargetConfig {
        self.postgres.clone().unwrap_or_default()
    }
}

/// MySQL / MariaDB settings of a target. One connection covers every
/// database (schema) of the server; the job's `databases` filter selects
/// the ones scanned.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlTargetConfig {
    /// TLS to the server. Default: `verify_full`.
    #[serde(default)]
    pub tls: MysqlTlsMode,
    /// PEM CA file trusted for the server certificate (`verify_full`).
    /// When set, it is the only trusted root; otherwise the system store.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Extended grant variant (`SELECT ON *.*`, opt-in): `check()` then
    /// reports the global `SELECT` as an expected warning instead of
    /// over-privilege. The connector never reads the system schemas either
    /// way.
    #[serde(default)]
    pub extended_grants: bool,
    /// Audit log file read by the Audit connector (P4-B): the MariaDB
    /// `server_audit` log, or the Percona / MySQL Enterprise `audit_log` /
    /// `audit_log_filter` JSON file, read locally through the file system,
    /// never through SQL. Without it, Audit uses `performance_schema`
    /// (Partial or Limited).
    #[serde(default)]
    pub audit_log: Option<MysqlAuditLogConfig>,
    /// CAS stores under custom names (ADR-0041 decision 5): tables or
    /// collections the CAS store guard treats as a ticket registry, a
    /// service registry or an audit trail, in addition to the built-in
    /// names, column shapes and the ticket-id tripwire (always on).
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
}

/// Format of a MySQL / MariaDB audit log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MysqlLogFormat {
    /// MariaDB `server_audit` plugin, `server_audit_output_type = file`.
    ServerAudit,
    /// Percona Server `audit_log` plugin (`audit_log_format = JSON`) or
    /// the `audit_log_filter` component (`audit_log_filter.format = JSON`,
    /// also MySQL Enterprise Audit JSON). The XML and CSV formats are not
    /// supported.
    Json,
}

/// Audit log file of a MySQL / MariaDB target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlAuditLogConfig {
    /// Absolute path of the current log file (`server_audit_file_path`,
    /// `audit_log_file`, `audit_log_filter.file`). Rotation by rename or
    /// truncation is followed.
    pub path: PathBuf,
    /// File format.
    pub format: MysqlLogFormat,
}

/// TLS mode of a MySQL / MariaDB target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MysqlTlsMode {
    /// TLS required, certificate and host name verified (rustls).
    #[default]
    VerifyFull,
    /// No TLS: a Unix socket or a loopback IP literal only (rejected for
    /// any other host). The connector never sends the password in clear
    /// nor through an RSA key exchange on such a connection, except
    /// `caching_sha2_password` full authentication on a Unix socket.
    Disable,
    /// No TLS on a network connection: explicit, insecure opt-in (e.g. an
    /// isolated container network). Traffic is readable and alterable on
    /// the path; warned at every connection and in `check()`. Only the
    /// `caching_sha2_password` fast path is accepted.
    DisableInsecure,
}

impl TargetConfig {
    /// MySQL / MariaDB settings, defaults when absent.
    #[must_use]
    pub fn mysql_settings(&self) -> MysqlTargetConfig {
        self.mysql.clone().unwrap_or_default()
    }
}

/// Longest `mongodb.auth_source` (MongoDB database names are at most 64
/// bytes).
pub const MAX_MONGODB_AUTH_SOURCE: usize = 64;

/// MongoDB settings of a target (ADR-0026). One connection to the declared
/// host covers every database the account holds privileges on; the job's
/// `databases` filter selects the ones scanned. The connector never
/// connects to another member of a replica set (I5).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MongodbTargetConfig {
    /// TLS to the server. Default: `verify_full`.
    #[serde(default)]
    pub tls: MongodbTlsMode,
    /// PEM CA file trusted for the server certificate (`verify_full`).
    /// When set, it is the only trusted root; otherwise the system store.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Database holding the account's credentials (SCRAM `authSource`).
    /// Default: `admin`.
    #[serde(default = "default_mongodb_auth_source")]
    pub auth_source: String,
    /// Log file read by the Audit connector (P5-B, P5-C, ADR-0027): the
    /// Enterprise / Percona `auditLog` JSON file, or the structured JSON
    /// server log, read locally through the file system. Without it, Audit
    /// uses the profiler when the account can read `system.profile`.
    #[serde(default)]
    pub audit_log: Option<MongodbAuditLogConfig>,
    /// CAS stores under custom names (ADR-0041 decision 5): tables or
    /// collections the CAS store guard treats as a ticket registry, a
    /// service registry or an audit trail, in addition to the built-in
    /// names, column shapes and the ticket-id tripwire (always on).
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
}

/// Format of a MongoDB log file read by the Audit connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MongodbLogFormat {
    /// MongoDB Enterprise / Percona Server for MongoDB `auditLog` with
    /// `destination: file`, `format: JSON` (schema `mongo`). BSON and OCSF
    /// are not supported.
    AuditLog,
    /// The structured JSON server log (`systemLog.destination: file`).
    ServerLog,
}

/// Log file of a MongoDB target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MongodbAuditLogConfig {
    /// Absolute path of the current log file (`auditLog.path`,
    /// `systemLog.path`). Rotation by rename or truncation is followed.
    pub path: PathBuf,
    /// File format.
    pub format: MongodbLogFormat,
}

fn default_mongodb_auth_source() -> String {
    "admin".to_owned()
}

impl Default for MongodbTargetConfig {
    fn default() -> Self {
        Self {
            tls: MongodbTlsMode::default(),
            ca_file: None,
            auth_source: default_mongodb_auth_source(),
            audit_log: None,
            cas_stores: None,
        }
    }
}

/// TLS mode of a MongoDB target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MongodbTlsMode {
    /// TLS required, certificate and host name verified (rustls).
    #[default]
    VerifyFull,
    /// No TLS: a Unix socket or a loopback IP literal only (rejected for
    /// any other host). Authentication is SCRAM-SHA-256 whatever the
    /// transport; the password itself is never sent.
    Disable,
    /// No TLS on a network connection: explicit, insecure opt-in (e.g. an
    /// isolated container network). Traffic is readable and alterable on
    /// the path; warned at every connection and in `check()`.
    DisableInsecure,
}

impl TargetConfig {
    /// MongoDB settings, defaults when absent.
    #[must_use]
    pub fn mongodb_settings(&self) -> MongodbTargetConfig {
        self.mongodb.clone().unwrap_or_default()
    }
}

/// Longest `openldap.accesslog_base` or `openldap.clear_principals` DN.
pub const MAX_OPENLDAP_DN: usize = 512;
/// Most `openldap.clear_principals`.
pub const MAX_CLEAR_PRINCIPALS: usize = 64;

/// A DN of `attr=value` RDNs, without control characters, at most
/// [`MAX_OPENLDAP_DN`] bytes.
fn is_dn(dn: &str) -> bool {
    !dn.is_empty()
        && dn.len() <= MAX_OPENLDAP_DN
        && !dn.chars().any(char::is_control)
        && dn.split(',').all(|rdn| {
            rdn.split_once('=')
                .is_some_and(|(t, v)| !t.trim().is_empty() && !v.trim().is_empty())
        })
}

/// OpenLDAP settings of a target (ADR-0029). One connection to the declared
/// server covers every naming context the account can read; the job's
/// `databases` filter selects the ones scanned. Referrals are never
/// followed (I5).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenldapTargetConfig {
    /// TLS to the server. Default: `verify_full` (LDAPS).
    #[serde(default)]
    pub tls: OpenldapTlsMode,
    /// PEM CA file trusted for the server certificate (`verify_full`,
    /// `start_tls`). When set, it is the only trusted root; otherwise the
    /// system store.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// How the agent authenticates. Default: `simple` (the service DN in
    /// `account`, its password in `secret`).
    #[serde(default)]
    pub bind: OpenldapBind,
    /// DN of the `slapo-accesslog` database read by the Audit connector
    /// (`olcAccessLogDB`). Never scanned by Discovery. Default:
    /// `cn=accesslog`.
    #[serde(default = "default_accesslog_base")]
    pub accesslog_base: String,
    /// Bind DNs whose Audit events carry the DN by name (service and
    /// administrator accounts). Every other DN names a person more often
    /// than not and is sent as its fingerprint (ADR-0029 decision 7). The
    /// agent's own DN is always sent by name.
    #[serde(default)]
    pub clear_principals: Vec<String>,
    /// CAS stores under custom names (ADR-0041 decision 5): LDAP object
    /// classes of service registry entries (`service_registry`; their
    /// entries are classified without masked samples nor `secret.*`
    /// fingerprints) and of ticket entries (`ticket_registry`; never
    /// read). `audit_trail` is not used on OpenLDAP.
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
}

fn default_accesslog_base() -> String {
    "cn=accesslog".to_owned()
}

impl Default for OpenldapTargetConfig {
    fn default() -> Self {
        Self {
            tls: OpenldapTlsMode::default(),
            ca_file: None,
            bind: OpenldapBind::default(),
            accesslog_base: default_accesslog_base(),
            clear_principals: Vec::new(),
            cas_stores: None,
        }
    }
}

/// TLS mode of an OpenLDAP target. There is no `disable_insecure`: a
/// simple bind sends the password itself, so cleartext on a network is
/// refused (ADR-0029 decision 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenldapTlsMode {
    /// LDAPS: TLS from the first byte (default port 636), certificate and
    /// host name verified (rustls).
    #[default]
    VerifyFull,
    /// StartTLS on the LDAP port (default 389), then verified as
    /// `verify_full`; no fallback to cleartext.
    StartTls,
    /// No TLS: an `ldapi://` Unix socket or a loopback IP literal only
    /// (rejected for any other host).
    Disable,
}

impl OpenldapTlsMode {
    /// Whether the server certificate is verified (`verify_full`,
    /// `start_tls`).
    #[must_use]
    pub const fn verified(self) -> bool {
        matches!(self, Self::VerifyFull | Self::StartTls)
    }
}

/// Authentication of an OpenLDAP target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenldapBind {
    /// Simple bind with the service DN (`account`) and its password
    /// (`secret`).
    #[default]
    Simple,
    /// SASL `EXTERNAL` over an `ldapi://` socket: slapd authenticates the
    /// agent's Unix uid / gid; `account` is the expected authorization DN,
    /// and no `secret` is set.
    SaslExternal,
}

impl TargetConfig {
    /// The `cas_stores` lists of the target's engine block (PostgreSQL,
    /// MySQL / MariaDB, MongoDB, OpenLDAP), if any.
    #[must_use]
    pub fn cas_stores(&self) -> Option<&crate::cas_guard::CasStores> {
        match self.engine {
            TargetEngine::Postgres => self.postgres.as_ref()?.cas_stores.as_ref(),
            TargetEngine::Mysql | TargetEngine::Mariadb => self.mysql.as_ref()?.cas_stores.as_ref(),
            TargetEngine::Mongodb => self.mongodb.as_ref()?.cas_stores.as_ref(),
            TargetEngine::Openldap => self.openldap.as_ref()?.cas_stores.as_ref(),
            TargetEngine::Cas => None,
        }
    }

    /// The validated `cas` block of an `engine: cas` target, its paths
    /// resolved when the configuration was loaded. `None` for other
    /// engines (and for a target that did not come from
    /// [`AgentConfig::parse`]).
    #[must_use]
    pub fn cas_settings(&self) -> Option<&cas::CasSettings> {
        self.cas_resolved.as_ref()
    }

    /// OpenLDAP settings, defaults when absent.
    #[must_use]
    pub fn openldap_settings(&self) -> OpenldapTargetConfig {
        self.openldap.clone().unwrap_or_default()
    }

    /// The TCP port the connector connects to: `port`, else the engine's
    /// default (PostgreSQL 5432, MySQL / MariaDB 3306, MongoDB 27017,
    /// OpenLDAP 636 with `verify_full`, else 389), as the connectors apply
    /// it. `None` for a Unix socket target.
    #[must_use]
    pub fn effective_port(&self) -> Option<u16> {
        self.host.as_ref()?;
        Some(self.port.unwrap_or(match self.engine {
            // A `cas` target has no host (refused by the validation).
            TargetEngine::Cas => return None,
            TargetEngine::Postgres => 5432,
            TargetEngine::Mysql | TargetEngine::Mariadb => 3306,
            TargetEngine::Mongodb => 27017,
            TargetEngine::Openldap => {
                if self.openldap_settings().tls == OpenldapTlsMode::VerifyFull {
                    636
                } else {
                    389
                }
            }
        }))
    }
}

/// Phone region of a target (`agent.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhoneRegionConfig {
    /// France: `0X XX XX XX XX` is `+33 X XX XX XX XX`.
    Fr,
}

impl TargetConfig {
    /// Phone region handed to the column classifier.
    #[must_use]
    pub fn phone_region(&self) -> databastion_classifiers::masking::PhoneRegion {
        use databastion_classifiers::masking::PhoneRegion;
        match self.phone_region {
            Some(PhoneRegionConfig::Fr) => PhoneRegion::Fr,
            None => PhoneRegion::Unknown,
        }
    }
}

/// Reference to a database secret: exactly one of `env` (variable name) or
/// `file` (absolute path, `0600`). The value is read on the agent host only
/// when a connector needs it (I3).
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Name of an environment variable.
    #[serde(default)]
    pub env: Option<String>,
    /// Absolute path of a file.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

/// Why a database secret could not be read. Never carries the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// Neither `env` nor `file` is set.
    #[error("no secret reference")]
    Missing,
    /// The environment variable is unset or not UTF-8.
    #[error("secret environment variable is unset or not valid UTF-8")]
    Env,
    /// The file cannot be read, or is not a private (`0600`, owned by the
    /// agent user, not a symlink) regular file.
    #[error("cannot read secret file: {0}")]
    File(std::io::ErrorKind),
    /// Empty, larger than 4 KiB, or not UTF-8.
    #[error("secret is empty, too large or not valid UTF-8")]
    Invalid,
}

/// Largest accepted secret, in bytes.
const MAX_SECRET_BYTES: usize = 4096;

impl SecretRef {
    /// Reads the secret on the agent host (I3). A file must be a private
    /// regular file (`0600`, owned by the agent user, not a symlink); one
    /// trailing newline is removed. The value is zeroized on drop.
    ///
    /// # Errors
    /// [`SecretError`], without the value.
    pub fn read(&self) -> Result<zeroize::Zeroizing<String>, SecretError> {
        let bytes = zeroize::Zeroizing::new(match (&self.env, &self.file) {
            (Some(name), _) => std::env::var_os(name)
                .ok_or(SecretError::Env)?
                .into_string()
                .map_err(|_| SecretError::Env)?
                .into_bytes(),
            (None, Some(path)) => {
                return Self::finish(
                    crate::fsutil::read_private_secret(path, MAX_SECRET_BYTES + 2)
                        .map_err(|e| SecretError::File(e.kind()))?,
                );
            }
            (None, None) => return Err(SecretError::Missing),
        });
        Self::finish(bytes)
    }

    /// Trims one trailing newline and checks the size and encoding.
    fn finish(
        bytes: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<zeroize::Zeroizing<String>, SecretError> {
        let mut end = bytes.len();
        if bytes[..end].ends_with(b"\n") {
            end -= 1;
            if bytes[..end].ends_with(b"\r") {
                end -= 1;
            }
        }
        if end == 0 || end > MAX_SECRET_BYTES {
            return Err(SecretError::Invalid);
        }
        let text = std::str::from_utf8(&bytes[..end]).map_err(|_| SecretError::Invalid)?;
        Ok(zeroize::Zeroizing::new(text.to_owned()))
    }
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
    "min_audit_poll_interval_s",
    "discovery_duty_cycle_percent",
    "phone_region",
    "databases",
    "tls",
    "verify_full",
    "disable",
    "disable_insecure",
    "extended_grants",
    "auth_source",
    "audit_log",
    "path",
    "format",
    "jsonlog",
    "csvlog",
    "server_audit",
    "json",
    "server_log",
    // Values of closed enums (`engine`, `phone_region`) are listed too, so
    // that an "unknown variant" error can name the expected ones; they are
    // schema constants, never user data.
    "fr",
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
    "start_tls",
    "bind",
    "simple",
    "sasl_external",
    "accesslog_base",
    "clear_principals",
    "cas",
    "service_registry",
    "json_dir",
    "yaml_dir",
    "timezone",
    "client_addr",
    "clear",
    "truncated",
    "omitted",
];

/// Renders a YAML / serde error without deriving any text from it: a
/// closed category, plus a key name and a path only when they are made of
/// keys of this schema. A value can therefore never be echoed, whatever
/// characters (quotes, backquotes, backslashes) it contains.
fn render_parse_error(message: &str) -> String {
    const CATEGORIES: [(&str, &str); 7] = [
        ("unknown field `", "unknown field"),
        ("missing field `", "missing field"),
        ("duplicate field `", "duplicate field"),
        ("unknown variant", "invalid value"),
        ("invalid value", "invalid value"),
        ("invalid length", "invalid value"),
        ("invalid type", "invalid type"),
    ];
    let (category, key) = CATEGORIES
        .iter()
        .find_map(|(needle, category)| {
            let pos = message.find(needle)?;
            let key = needle
                .ends_with('`')
                .then(|| known_key_at(&message[pos + needle.len()..]))
                .flatten();
            Some((*category, key))
        })
        .unwrap_or(("syntax error", None));
    let mut out = String::from(category);
    if let Some(key) = key {
        out.push_str(" `");
        out.push_str(key);
        out.push('`');
    }
    if let Some(path) = known_path(message) {
        out.push_str(" at ");
        out.push_str(path);
    }
    out
}

/// The known key that `rest` starts with, if it is followed by the closing
/// backquote.
fn known_key_at(rest: &str) -> Option<&'static str> {
    KNOWN_KEYS
        .iter()
        .copied()
        .filter(|k| {
            rest.strip_prefix(k)
                .is_some_and(|after| after.starts_with('`'))
        })
        .max_by_key(|k| k.len())
}

/// The `a.b[0].c: ` path prefix serde_yaml_ng puts in front of a message,
/// if every name segment is a known key.
fn known_path(message: &str) -> Option<&str> {
    let (path, _) = message.split_once(": ")?;
    let valid = !path.is_empty()
        && path.len() <= 64
        && path.split('.').all(|segment| {
            let name = segment.split('[').next().unwrap_or("");
            let index = &segment[name.len()..];
            KNOWN_KEYS.contains(&name)
                && index
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'[' || b == b']')
        });
    valid.then_some(path)
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
                message: render_parse_error(&e.to_string()),
            }
        })?;
        config.validate()?;
        let mut config = config;
        config.resolve_cas()?;
        Ok(config)
    }

    /// Validates the `cas:` blocks and resolves their paths (blocking I/O:
    /// `canonicalize`), refusing paths under the agent's own state
    /// directory (ADR-0041 decision 3).
    fn resolve_cas(&mut self) -> Result<(), ConfigError> {
        let state_dir = self.state_dir.clone();
        for (i, target) in self.targets.iter_mut().enumerate() {
            if let Some(raw) = target.cas.clone() {
                let settings =
                    cas::CasSettings::validate(raw, &[state_dir.as_path()]).map_err(|e| {
                        ConfigError::Invalid {
                            field: if e.key.is_empty() {
                                format!("targets[{i}].cas")
                            } else {
                                format!("targets[{i}].cas.{}", e.key)
                            },
                            reason: e.reason,
                        }
                    })?;
                target.cas_resolved = Some(settings);
            }
        }
        Ok(())
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
        let wait = self.console.long_poll_wait_s;
        if wait > 25 || (wait < MIN_LONG_POLL_WAIT_S && !self.console.insecure_dev_http) {
            // Below 5 s only for the loopback development console (tests).
            return Err(invalid("console.long_poll_wait_s", "must be in 5..=25"));
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
        if !in_range(l.min_audit_poll_interval_s, (1, 3_600)) {
            return Err(invalid(
                "limits.min_audit_poll_interval_s",
                "must be in 1..=3600",
            ));
        }
        let (lo, hi) = crate::pacing::DUTY_CYCLE_PERCENT_RANGE;
        if !(lo..=hi).contains(&l.discovery_duty_cycle_percent) {
            return Err(invalid(
                "limits.discovery_duty_cycle_percent",
                "must be in 1..=100 (100: no pacing)",
            ));
        }
        if !(2 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.spool.max_bytes) {
            return Err(invalid(
                "spool.max_bytes",
                "must be in 2097152..=68719476736 (2 MiB to 64 GiB)",
            ));
        }
        if !(1..=1_000_000).contains(&self.spool.max_batches) {
            return Err(invalid("spool.max_batches", "must be in 1..=1000000"));
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
                        "http is only allowed for 127.0.0.1 or [::1] (insecure_dev_http)",
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
    // IP literals only: `localhost` could resolve elsewhere (hosts file,
    // resolver), so it is not accepted.
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
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
        if self.cas.is_some() && self.engine != TargetEngine::Cas {
            return Err(invalid(f("cas"), "only for engine cas"));
        }
        if self.engine == TargetEngine::Cas {
            return self.validate_cas(i);
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
        for (block, stores) in [
            (
                "postgres",
                self.postgres.as_ref().and_then(|c| c.cas_stores.as_ref()),
            ),
            (
                "mysql",
                self.mysql.as_ref().and_then(|c| c.cas_stores.as_ref()),
            ),
            (
                "mongodb",
                self.mongodb.as_ref().and_then(|c| c.cas_stores.as_ref()),
            ),
            (
                "openldap",
                self.openldap.as_ref().and_then(|c| c.cas_stores.as_ref()),
            ),
        ] {
            if let Some(Err((key, reason))) = stores.map(crate::cas_guard::CasStores::validate) {
                return Err(invalid(f(&format!("{block}.cas_stores.{key}")), reason));
            }
        }
        if let Some(pg) = &self.postgres {
            self.validate_postgres(pg, i)?;
        }
        if self.engine == TargetEngine::Postgres {
            self.validate_postgres_tls(i)?;
        }
        if let Some(my) = &self.mysql {
            self.validate_mysql(my, i)?;
        }
        if matches!(self.engine, TargetEngine::Mysql | TargetEngine::Mariadb) {
            let tls = self.mysql_settings().tls;
            self.validate_tls_placement(
                format!("targets[{i}].mysql.tls"),
                tls == MysqlTlsMode::VerifyFull,
                tls == MysqlTlsMode::Disable,
            )?;
        }
        if let Some(mongo) = &self.mongodb {
            self.validate_mongodb(mongo, i)?;
        }
        if self.engine == TargetEngine::Mongodb {
            let tls = self.mongodb_settings().tls;
            self.validate_tls_placement(
                format!("targets[{i}].mongodb.tls"),
                tls == MongodbTlsMode::VerifyFull,
                tls == MongodbTlsMode::Disable,
            )?;
        }
        if let Some(ldap) = &self.openldap {
            self.validate_openldap(ldap, i)?;
        }
        if self.engine == TargetEngine::Openldap {
            let tls = self.openldap_settings().tls;
            self.validate_tls_placement(
                format!("targets[{i}].openldap.tls"),
                tls.verified(),
                tls == OpenldapTlsMode::Disable,
            )?;
            if self.openldap_settings().bind == OpenldapBind::SaslExternal {
                // The peer credentials of the socket authenticate the
                // agent: a password would never be used.
                if self.secret != SecretRef::default() {
                    return Err(invalid(
                        f("secret"),
                        "not used with openldap.bind: sasl_external (remove it)",
                    ));
                }
                return Ok(());
            }
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

    /// A `cas` target is a set of local paths (ADR-0041 decision 3, I3,
    /// I5): no host, port, socket, account, secret nor engine block of
    /// another engine. The `cas` block itself is validated and resolved by
    /// [`AgentConfig::resolve_cas`].
    fn validate_cas(&self, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].{name}");
        let refused = [
            ("host", self.host.is_some()),
            ("port", self.port.is_some()),
            ("socket", self.socket.is_some()),
            ("account", !self.account.is_empty()),
            ("secret", self.secret != SecretRef::default()),
            ("postgres", self.postgres.is_some()),
            ("mysql", self.mysql.is_some()),
            ("mongodb", self.mongodb.is_some()),
            ("openldap", self.openldap.is_some()),
        ];
        if let Some((name, _)) = refused.iter().find(|(_, set)| *set) {
            return Err(invalid(
                f(name),
                "not used by a cas target, which reads local files only (remove it)",
            ));
        }
        if self.cas.is_none() {
            return Err(invalid(f("cas"), "required for engine cas"));
        }
        Ok(())
    }

    fn validate_postgres_tls(&self, i: usize) -> Result<(), ConfigError> {
        let tls = self.postgres_settings().tls;
        self.validate_tls_placement(
            format!("targets[{i}].postgres.tls"),
            tls == PgTlsMode::VerifyFull,
            tls == PgTlsMode::Disable,
        )
    }

    /// A Unix socket needs `disable`; `disable` is only for a Unix socket
    /// or a loopback IP literal (never `localhost`).
    fn validate_tls_placement(
        &self,
        field: String,
        verify_full: bool,
        disable: bool,
    ) -> Result<(), ConfigError> {
        let loopback = self
            .host
            .as_deref()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        match (verify_full, disable, self.socket.is_some()) {
            (true, _, true) => Err(invalid(
                field,
                "a Unix socket has no TLS: set `tls: disable` for this target",
            )),
            (_, true, false) if !loopback && self.engine == TargetEngine::Openldap => Err(invalid(
                field,
                "`disable` is only for an ldapi:// Unix socket or a loopback IP literal; use \
                 `verify_full` (LDAPS) or `start_tls` (OpenLDAP has no `disable_insecure`: a \
                 simple bind would send the password in clear)",
            )),
            (_, true, false) if !loopback => Err(invalid(
                field,
                "`disable` is only for a Unix socket or a loopback IP literal; use \
                 `verify_full`, or `disable_insecure` to accept cleartext on this network",
            )),
            _ => Ok(()),
        }
    }

    fn validate_mysql(&self, my: &MysqlTargetConfig, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].mysql.{name}");
        if !matches!(self.engine, TargetEngine::Mysql | TargetEngine::Mariadb) {
            return Err(invalid(
                format!("targets[{i}].mysql"),
                "only for engine mysql or mariadb",
            ));
        }
        if my.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute()) {
            return Err(invalid(f("ca_file"), "must be an absolute path"));
        }
        if my.ca_file.is_some() && my.tls != MysqlTlsMode::VerifyFull {
            return Err(invalid(f("ca_file"), "only with tls: verify_full"));
        }
        if let Some(log) = &my.audit_log
            && (!log.path.is_absolute() || log.path.as_os_str().len() > 4096)
        {
            return Err(invalid(f("audit_log.path"), "must be an absolute path"));
        }
        Ok(())
    }

    fn validate_mongodb(&self, mongo: &MongodbTargetConfig, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].mongodb.{name}");
        if self.engine != TargetEngine::Mongodb {
            return Err(invalid(
                format!("targets[{i}].mongodb"),
                "only for engine mongodb",
            ));
        }
        if mongo.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute()) {
            return Err(invalid(f("ca_file"), "must be an absolute path"));
        }
        if mongo.ca_file.is_some() && mongo.tls != MongodbTlsMode::VerifyFull {
            return Err(invalid(f("ca_file"), "only with tls: verify_full"));
        }
        if let Some(log) = &mongo.audit_log
            && (!log.path.is_absolute() || log.path.as_os_str().len() > 4096)
        {
            return Err(invalid(f("audit_log.path"), "must be an absolute path"));
        }
        // A MongoDB database name: 1 to 64 bytes, none of `/\. "$`, no NUL
        // or control character.
        let a = &mongo.auth_source;
        if a.is_empty()
            || a.len() > MAX_MONGODB_AUTH_SOURCE
            || a.chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\' | '.' | ' ' | '"' | '$'))
        {
            return Err(invalid(
                f("auth_source"),
                "must be a database name (1 to 64 bytes, none of / \\ . space \" $)",
            ));
        }
        Ok(())
    }

    fn validate_openldap(&self, ldap: &OpenldapTargetConfig, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].openldap.{name}");
        if self.engine != TargetEngine::Openldap {
            return Err(invalid(
                format!("targets[{i}].openldap"),
                "only for engine openldap",
            ));
        }
        if ldap.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute()) {
            return Err(invalid(f("ca_file"), "must be an absolute path"));
        }
        if ldap.ca_file.is_some() && !ldap.tls.verified() {
            return Err(invalid(
                f("ca_file"),
                "only with tls: verify_full or start_tls",
            ));
        }
        if ldap.bind == OpenldapBind::SaslExternal && self.socket.is_none() {
            return Err(invalid(
                f("bind"),
                "sasl_external needs an ldapi:// Unix socket (socket, tls: disable)",
            ));
        }
        if ldap.clear_principals.len() > MAX_CLEAR_PRINCIPALS {
            return Err(invalid(f("clear_principals"), "at most 64 DNs"));
        }
        if !ldap.clear_principals.iter().all(|d| is_dn(d)) {
            return Err(invalid(
                f("clear_principals"),
                "each must be a DN (attr=value[,attr=value…]), at most 512 bytes",
            ));
        }
        if !is_dn(&ldap.accesslog_base) {
            return Err(invalid(
                f("accesslog_base"),
                "must be a DN (attr=value[,attr=value…]), at most 512 bytes",
            ));
        }
        Ok(())
    }

    fn validate_postgres(&self, pg: &PostgresTargetConfig, i: usize) -> Result<(), ConfigError> {
        let f = |name: &str| format!("targets[{i}].postgres.{name}");
        if self.engine != TargetEngine::Postgres {
            return Err(invalid(f("databases"), "only for engine postgres"));
        }
        if pg.databases.is_empty() || pg.databases.len() > MAX_PG_DATABASES {
            return Err(invalid(f("databases"), "must list 1 to 16 databases"));
        }
        let mut seen = HashSet::new();
        for db in &pg.databases {
            if db.is_empty() || db.len() > 63 || db.chars().any(char::is_control) {
                return Err(invalid(
                    f("databases"),
                    "a database name is 1 to 63 bytes without control characters",
                ));
            }
            if !seen.insert(db.as_str()) {
                return Err(invalid(f("databases"), "duplicate database"));
            }
        }
        if pg.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute()) {
            return Err(invalid(f("ca_file"), "must be an absolute path"));
        }
        if pg.ca_file.is_some() && pg.tls != PgTlsMode::VerifyFull {
            return Err(invalid(f("ca_file"), "only with tls: verify_full"));
        }
        if let Some(log) = &pg.audit_log
            && (!log.path.is_absolute() || log.path.as_os_str().len() > 4096)
        {
            return Err(invalid(f("audit_log.path"), "must be an absolute path"));
        }
        Ok(())
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
    openldap:
      tls: disable
";

    fn parse(text: &str) -> Result<AgentConfig, ConfigError> {
        AgentConfig::parse(text)
    }

    fn err(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    const CAS: &str = "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: cas-prod
    engine: cas
    cas:
      service_registry:
        json_dir: /etc/cas/services
      audit_log:
        path: /var/log/cas/cas_audit.log
        timezone: \"+02:00\"
      clear_principals: [svc-monitoring]
";

    #[test]
    fn cas_targets_are_local_paths_only() {
        let cfg = parse(CAS).unwrap();
        let t = &cfg.targets[0];
        assert_eq!(t.engine, TargetEngine::Cas);
        assert_eq!(t.engine.connector(), Engine::Cas);
        assert_eq!(t.effective_port(), None);
        let s = t.cas_settings().unwrap();
        assert!(s.registry_dir.is_some());
        let log = s.audit_log.as_ref().unwrap();
        assert_eq!(log.offset, cas::UtcOffset(7200));
        assert_eq!(s.client_addr, cas::ClientAddrMode::Truncated);
        assert_eq!(s.clear_principals, ["svc-monitoring"]);
        // No host, port, socket, account, secret nor another engine's block.
        for (extra, key) in [
            ("    host: cas.example.org\n", "targets[0].host"),
            ("    port: 8443\n", "targets[0].port"),
            ("    socket: /run/cas.sock\n", "targets[0].socket"),
            ("    account: databastion\n", "targets[0].account"),
            (
                "    secret:\n      env: DATABASTION_CAS\n",
                "targets[0].secret",
            ),
            ("    openldap: {tls: start_tls}\n", "targets[0].openldap"),
        ] {
            let text = CAS.replace("    engine: cas\n", &format!("    engine: cas\n{extra}"));
            assert!(err(&text).contains(key), "{extra}: {}", err(&text));
        }
        // The block is required, and only for engine cas.
        let bare = "console:\n  url: https://c.example\nstate_dir: /s\ntargets:\n  - id: c\n    engine: cas\n";
        assert!(err(bare).contains("targets[0].cas"));
        let misplaced = BASE.replace(
            "    port: 5432\n",
            "    port: 5432\n    cas: {audit_log: {path: /var/log/cas/a.log}}\n",
        );
        assert!(err(&misplaced).contains("targets[0].cas"));
        // The block's own rules, named by key, never by value.
        for (from, to, key) in [
            (
                "        path: /var/log/cas/cas_audit.log",
                "        path: var/log/hunter2-SECRET.log",
                "targets[0].cas.audit_log.path",
            ),
            (
                "      clear_principals: [svc-monitoring]",
                "      clear_principals: [\"*\"]",
                "targets[0].cas.clear_principals",
            ),
            (
                "        json_dir: /etc/cas/services",
                "        json_dir: /var/lib/databastion/services",
                "targets[0].cas.service_registry.json_dir",
            ),
            (
                "        json_dir: /etc/cas/services",
                "        yaml_dir: /etc/cas/services",
                "targets[0].cas.service_registry.yaml_dir",
            ),
            (
                "        timezone: \"+02:00\"",
                "        timezone: Europe/Paris",
                "targets[0].cas.audit_log.timezone",
            ),
        ] {
            let message = err(&CAS.replace(from, to));
            assert!(message.contains(key), "{to}: {message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
        assert!(
            err(&CAS.replace(
                "      clear_principals",
                "      password: x\n      clear_principals"
            ))
            .contains("unknown field")
        );
        // Other engines still need an account.
        let no_account = BASE.replacen("    account: databastion\n", "", 1);
        assert!(err(&no_account).contains("account"), "{}", err(&no_account));
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
        assert_eq!(
            cfg.targets[0].phone_region(),
            databastion_classifiers::masking::PhoneRegion::Unknown
        );
        let fr = parse(&BASE.replace("    port: 5432\n", "    port: 5432\n    phone_region: fr\n"))
            .unwrap();
        assert_eq!(
            fr.targets[0].phone_region(),
            databastion_classifiers::masking::PhoneRegion::Fr
        );
        assert!(
            err(&BASE.replace("    port: 5432\n", "    port: 5432\n    phone_region: xx\n"))
                .contains("phone_region")
        );
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

    /// ADR-0041 decision 5: `targets[].<engine>.cas_stores`, bounded.
    #[test]
    fn cas_stores_are_per_engine_block_and_bounded() {
        let yaml = |block: &str| {
            format!(
                "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - {{id: t, \
                 engine: postgres, host: db, account: a, secret: {{env: PW}}, postgres: {{{block}}}}}\n"
            )
        };
        let c = AgentConfig::parse(&yaml(
            "cas_stores: {ticket_registry: [sso_tix], service_registry: [Apps], audit_trail: [Trail]}",
        ))
        .unwrap();
        let stores = c.targets[0].cas_stores().unwrap();
        assert_eq!(stores.ticket_registry, ["sso_tix"]);
        assert_eq!(stores.audit_trail, ["Trail"]);
        assert!(
            AgentConfig::parse(&yaml("databases: [shop]"))
                .unwrap()
                .targets[0]
                .cas_stores()
                .is_none()
        );
        let e = AgentConfig::parse(&yaml("cas_stores: {ticket_registry: [\"\"]}")).unwrap_err();
        assert!(
            e.to_string()
                .contains("postgres.cas_stores.ticket_registry"),
            "{e}"
        );
        assert!(AgentConfig::parse(&yaml("cas_stores: {tickets: [x]}")).is_err());
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
        for ok in ["http://127.0.0.1:8080", "http://[::1]:3000"] {
            assert!(parse(&dev(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "http://10.0.0.1:8080",
            "http://console.example.internal",
            "http://127.0.0.2",
            "http://localhost:3000",
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
            ("min_audit_poll_interval_s", "0"),
            ("discovery_duty_cycle_percent", "0"),
            ("discovery_duty_cycle_percent", "101"),
            ("discovery_duty_cycle_percent", "-1"),
            ("discovery_duty_cycle_percent", "1.5"),
        ] {
            let text = format!("{BASE}limits:\n  {key}: {value}\n");
            assert!(err(&text).contains(key), "{key}={value}");
        }
    }

    #[test]
    fn discovery_duty_cycle_default_and_bounds() {
        assert_eq!(parse(BASE).unwrap().limits.discovery_duty_cycle_percent, 1);
        for v in [1u8, 2, 50, 100] {
            let text = format!("{BASE}limits:\n  discovery_duty_cycle_percent: {v}\n");
            assert_eq!(parse(&text).unwrap().limits.discovery_duty_cycle_percent, v);
        }
    }

    #[test]
    fn clamps_never_exceed_local_caps() {
        let limits = Limits {
            max_sample_rows: 500,
            statement_timeout_ms: 10_000,
            max_scan_duration_s: 600,
            min_audit_poll_interval_s: 5,
            discovery_duty_cycle_percent: 1,
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
    fn postgres_settings() {
        let cfg = parse(BASE).unwrap();
        assert_eq!(
            cfg.targets[0].postgres_settings(),
            PostgresTargetConfig::default()
        );
        assert_eq!(cfg.targets[0].postgres_settings().databases, ["postgres"]);
        let with =
            |block: &str| BASE.replace("    port: 5432\n", &format!("    port: 5432\n{block}"));
        let cfg = parse(&with(
            "    postgres:\n      databases: [shop, crm]\n      tls: disable_insecure\n      extended_grants: true\n",
        ))
        .unwrap();
        let pg = cfg.targets[0].postgres_settings();
        assert_eq!(pg.databases, ["shop", "crm"]);
        assert_eq!(pg.tls, PgTlsMode::DisableInsecure);
        assert!(pg.extended_grants);
        assert!(pg.audit_log.is_none());
        let cfg = parse(&with(
            "    postgres:\n      audit_log: {path: /var/log/postgresql/postgresql.json, format: jsonlog}\n",
        ))
        .unwrap();
        let log = cfg.targets[0].postgres_settings().audit_log.unwrap();
        assert_eq!(log.format, PgLogFormat::Jsonlog);
        assert_eq!(
            log.path,
            PathBuf::from("/var/log/postgresql/postgresql.json")
        );
        let cases = [
            (
                "    postgres:\n      audit_log: {path: pg.json, format: jsonlog}\n",
                "postgres.audit_log.path",
            ),
            (
                "    postgres:\n      audit_log: {path: /x.log, format: stderr}\n",
                "invalid value",
            ),
            (
                "    postgres:\n      audit_log: {format: csvlog}\n",
                "missing field",
            ),
            ("    postgres:\n      databases: []\n", "postgres.databases"),
            ("    postgres:\n      databases: [a, a]\n", "duplicate"),
            ("    postgres:\n      ca_file: ca.pem\n", "postgres.ca_file"),
            (
                "    postgres:\n      tls: disable_insecure\n      ca_file: /etc/ca.pem\n",
                "postgres.ca_file",
            ),
            // M2: `disable` only for a socket or a loopback literal.
            ("    postgres:\n      tls: disable\n", "postgres.tls"),
            ("    postgres:\n      tls: prefer\n", "invalid value"),
            (
                "    postgres:\n      password: hunter2-SECRET\n",
                "unknown field",
            ),
        ];
        for (block, expected) in cases {
            let message = err(&with(block));
            assert!(message.contains(expected), "{expected}: {message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
        // `disable` on a loopback literal; never `localhost`.
        let local = |host: &str, tls: &str| {
            BASE.replace("host: db1.internal", &format!("host: \"{host}\""))
                .replace(
                    "    port: 5432\n",
                    &format!("    port: 5432\n    postgres: {{tls: {tls}}}\n"),
                )
        };
        assert!(parse(&local("127.0.0.1", "disable")).is_ok());
        assert!(parse(&local("::1", "disable")).is_ok());
        assert!(err(&local("localhost", "disable")).contains("postgres.tls"));
        // L4: a Unix socket needs `tls: disable` (fail closed, clear message).
        let socket = BASE.replace(
            "    host: db1.internal\n    port: 5432\n",
            "    socket: /run/postgresql\n",
        );
        assert!(
            err(&socket).contains("a Unix socket has no TLS"),
            "{}",
            err(&socket)
        );
        let socket = socket.replace(
            "    socket: /run/postgresql\n",
            "    socket: /run/postgresql\n    postgres: {tls: disable}\n",
        );
        assert!(parse(&socket).is_ok());
        // Only for engine postgres.
        let ldap = BASE.replace(
            "      file: /etc/databastion/secrets/ldap\n",
            "      file: /etc/databastion/secrets/ldap\n    postgres:\n      databases: [x]\n",
        );
        assert!(err(&ldap).contains("targets[1].postgres"), "{}", err(&ldap));
    }

    #[test]
    fn openldap_settings() {
        const LDAP: &str = "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: ldap
    engine: openldap
    host: ldap1.internal
    account: cn=databastion,ou=services,dc=example,dc=org
    secret:
      env: DATABASTION_LDAP_PASSWORD
";
        let cfg = parse(LDAP).unwrap();
        let settings = cfg.targets[0].openldap_settings();
        assert_eq!(settings, OpenldapTargetConfig::default());
        assert_eq!(settings.tls, OpenldapTlsMode::VerifyFull);
        assert_eq!(settings.bind, OpenldapBind::Simple);
        assert_eq!(settings.accesslog_base, "cn=accesslog");
        let with = |block: &str| {
            LDAP.replace(
                "    host: ldap1.internal\n",
                &format!("    host: ldap1.internal\n{block}"),
            )
        };
        let cfg = parse(&with(
            "    openldap:\n      tls: start_tls\n      ca_file: /etc/databastion/ldap-ca.pem\n      \
             accesslog_base: cn=log\n",
        ))
        .unwrap();
        let settings = cfg.targets[0].openldap_settings();
        assert_eq!(settings.tls, OpenldapTlsMode::StartTls);
        assert!(settings.tls.verified());
        assert_eq!(settings.accesslog_base, "cn=log");
        // No cleartext on a network, and no `disable_insecure` at all.
        assert!(err(&with("    openldap: {tls: disable}\n")).contains("openldap.tls"));
        assert!(!err(&with("    openldap: {tls: disable}\n")).contains("disable_insecure` to"));
        assert!(err(&with("    openldap: {tls: disable_insecure}\n")).contains("invalid value"));
        assert!(err(&with("    openldap: {tls: disable, ca_file: /x.pem}\n")).contains("ca_file"));
        assert!(
            err(&with("    openldap: {accesslog_base: accesslog}\n")).contains("accesslog_base")
        );
        assert!(err(&with("    openldap: {accesslog_base: \"cn=\"}\n")).contains("accesslog_base"));
        let cfg = parse(&with(
            "    openldap: {clear_principals: [\"cn=admin,dc=example,dc=org\"]}\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.targets[0].openldap_settings().clear_principals,
            ["cn=admin,dc=example,dc=org"]
        );
        assert!(
            err(&with("    openldap: {clear_principals: [admin]}\n")).contains("clear_principals")
        );
        // SASL EXTERNAL: ldapi only, and no secret.
        assert!(err(&with("    openldap: {bind: sasl_external}\n")).contains("openldap.bind"));
        let socket = LDAP.replace(
            "    host: ldap1.internal\n",
            "    socket: /run/slapd/ldapi\n",
        );
        let external = socket.replace(
            "    secret:\n      env: DATABASTION_LDAP_PASSWORD\n",
            "    openldap: {tls: disable, bind: sasl_external}\n",
        );
        let cfg = parse(&external).unwrap();
        assert_eq!(
            cfg.targets[0].openldap_settings().bind,
            OpenldapBind::SaslExternal
        );
        assert_eq!(cfg.targets[0].secret, SecretRef::default());
        let both = socket.replace(
            "    secret:\n",
            "    openldap: {tls: disable, bind: sasl_external}\n    secret:\n",
        );
        assert!(err(&both).contains("targets[0].secret"), "{}", err(&both));
        // Every other target still needs its secret.
        let none = socket.replace(
            "    secret:\n      env: DATABASTION_LDAP_PASSWORD\n",
            "    openldap: {tls: disable}\n",
        );
        assert!(err(&none).contains("targets[0].secret"), "{}", err(&none));
        // The block belongs to openldap targets only.
        assert!(
            err(&BASE.replace(
                "      env: DATABASTION_PG_MAIN_PASSWORD\n",
                "      env: DATABASTION_PG_MAIN_PASSWORD\n    openldap: {tls: start_tls}\n",
            ))
            .contains("targets[0].openldap")
        );
    }

    #[test]
    fn mongodb_settings() {
        const MONGO: &str = "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: mongo
    engine: mongodb
    host: db3.internal
    port: 27017
    account: databastion
    secret:
      env: DATABASTION_MONGO_PASSWORD
";
        let cfg = parse(MONGO).unwrap();
        let settings = cfg.targets[0].mongodb_settings();
        assert_eq!(settings, MongodbTargetConfig::default());
        assert_eq!(settings.tls, MongodbTlsMode::VerifyFull);
        assert_eq!(settings.auth_source, "admin");
        let with =
            |block: &str| MONGO.replace("    port: 27017\n", &format!("    port: 27017\n{block}"));
        let cfg = parse(&with(
            "    mongodb:\n      ca_file: /etc/databastion/mongo-ca.pem\n      auth_source: appdb\n",
        ))
        .unwrap();
        let settings = cfg.targets[0].mongodb_settings();
        assert!(settings.ca_file.is_some());
        assert_eq!(settings.auth_source, "appdb");
        let cfg = parse(&with(
            "    mongodb:\n      audit_log: {path: /var/log/mongodb/mongod.log, format: server_log}\n",
        ))
        .unwrap();
        let log = cfg.targets[0].mongodb_settings().audit_log.unwrap();
        assert_eq!(log.format, MongodbLogFormat::ServerLog);
        assert_eq!(log.path, PathBuf::from("/var/log/mongodb/mongod.log"));
        let cfg = parse(&with(
            "    mongodb: {audit_log: {path: /var/log/mongodb/audit.json, format: audit_log}}\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.targets[0].mongodb_settings().audit_log.unwrap().format,
            MongodbLogFormat::AuditLog
        );
        let cfg = parse(&with("    mongodb: {tls: disable_insecure}\n")).unwrap();
        assert_eq!(
            cfg.targets[0].mongodb_settings().tls,
            MongodbTlsMode::DisableInsecure
        );
        // `disable` on a loopback literal.
        let loopback = with("    mongodb: {tls: disable}\n").replace("db3.internal", "127.0.0.1");
        assert_eq!(
            parse(&loopback).unwrap().targets[0].mongodb_settings().tls,
            MongodbTlsMode::Disable
        );
        for (block, expected) in [
            ("    mongodb: {ca_file: ca.pem}\n", "mongodb.ca_file"),
            (
                "    mongodb: {tls: disable_insecure, ca_file: /etc/ca.pem}\n",
                "mongodb.ca_file",
            ),
            ("    mongodb: {tls: disable}\n", "mongodb.tls"),
            ("    mongodb: {tls: prefer}\n", "invalid value"),
            ("    mongodb: {auth_source: \"\"}\n", "mongodb.auth_source"),
            ("    mongodb: {auth_source: a.b}\n", "mongodb.auth_source"),
            (
                "    mongodb: {auth_source: \"a$b\"}\n",
                "mongodb.auth_source",
            ),
            ("    mongodb: {password: hunter2-SECRET}\n", "unknown field"),
            (
                "    mongodb: {audit_log: {path: audit.json, format: audit_log}}\n",
                "mongodb.audit_log.path",
            ),
            (
                "    mongodb: {audit_log: {path: /a.bson, format: bson}}\n",
                "invalid value",
            ),
            (
                "    mongodb: {audit_log: {path: /a.json}}\n",
                "missing field",
            ),
        ] {
            let e = err(&with(block));
            assert!(e.contains(expected), "{block}: {e}");
            assert!(!e.contains("SECRET"), "{e}");
        }
        let long = format!("    mongodb: {{auth_source: {}}}\n", "a".repeat(65));
        assert!(err(&with(&long)).contains("mongodb.auth_source"));
        // A Unix socket needs `disable`.
        let socket = MONGO.replace(
            "    host: db3.internal\n    port: 27017\n",
            "    socket: /tmp/mongodb-27017.sock\n",
        );
        assert!(
            err(&socket).contains("a Unix socket has no TLS"),
            "{}",
            err(&socket)
        );
        let socket = socket.replace(
            "    socket: /tmp/mongodb-27017.sock\n",
            "    socket: /tmp/mongodb-27017.sock\n    mongodb: {tls: disable}\n",
        );
        assert!(parse(&socket).is_ok());
        // The block belongs to MongoDB targets only.
        let pg = BASE.replace(
            "    port: 5432\n",
            "    port: 5432\n    mongodb: {tls: verify_full}\n",
        );
        assert!(err(&pg).contains("targets[0].mongodb"), "{}", err(&pg));
    }

    #[test]
    fn mysql_settings() {
        const MY: &str = "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: my
    engine: mariadb
    host: db2.internal
    port: 3306
    account: databastion
    secret:
      env: DATABASTION_MY_PASSWORD
";
        let cfg = parse(MY).unwrap();
        assert_eq!(
            cfg.targets[0].mysql_settings(),
            MysqlTargetConfig::default()
        );
        assert_eq!(
            cfg.targets[0].mysql_settings().tls,
            MysqlTlsMode::VerifyFull
        );
        let with =
            |block: &str| MY.replace("    port: 3306\n", &format!("    port: 3306\n{block}"));
        let cfg = parse(&with(
            "    mysql:\n      tls: verify_full\n      ca_file: /etc/databastion/my-ca.pem\n",
        ))
        .unwrap();
        assert!(cfg.targets[0].mysql_settings().ca_file.is_some());
        let cfg = parse(&with(
            "    mysql: {tls: disable_insecure, extended_grants: true}\n",
        ))
        .unwrap();
        assert!(cfg.targets[0].mysql_settings().extended_grants);
        assert_eq!(
            cfg.targets[0].mysql_settings().tls,
            MysqlTlsMode::DisableInsecure
        );
        assert!(cfg.targets[0].mysql_settings().audit_log.is_none());
        let cfg = parse(&with(
            "    mysql:\n      audit_log: {path: /var/log/mysql/server_audit.log, format: server_audit}\n",
        ))
        .unwrap();
        let log = cfg.targets[0].mysql_settings().audit_log.unwrap();
        assert_eq!(log.format, MysqlLogFormat::ServerAudit);
        assert_eq!(log.path, PathBuf::from("/var/log/mysql/server_audit.log"));
        let cfg = parse(&with(
            "    mysql: {audit_log: {path: /var/lib/mysql/audit.log, format: json}}\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.targets[0].mysql_settings().audit_log.unwrap().format,
            MysqlLogFormat::Json
        );
        for (block, expected) in [
            ("    mysql: {ca_file: ca.pem}\n", "mysql.ca_file"),
            (
                "    mysql: {tls: disable_insecure, ca_file: /etc/ca.pem}\n",
                "mysql.ca_file",
            ),
            ("    mysql: {tls: disable}\n", "mysql.tls"),
            (
                "    mysql: {audit_log: {path: audit.log, format: json}}\n",
                "mysql.audit_log.path",
            ),
            (
                "    mysql: {audit_log: {path: /a.log, format: xml}}\n",
                "invalid value",
            ),
            ("    mysql: {audit_log: {format: json}}\n", "missing field"),
            ("    mysql: {tls: preferred}\n", "invalid value"),
            ("    mysql: {password: hunter2-SECRET}\n", "unknown field"),
            (
                "    postgres: {tls: disable_insecure}\n",
                "only for engine postgres",
            ),
        ] {
            let message = err(&with(block));
            assert!(message.contains(expected), "{expected}: {message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
        let local = MY
            .replace("host: db2.internal", "host: \"127.0.0.1\"")
            .replace(
                "    port: 3306\n",
                "    port: 3306\n    mysql: {tls: disable}\n",
            );
        assert!(parse(&local).is_ok());
        assert!(err(&local.replace("127.0.0.1", "localhost")).contains("mysql.tls"));
        let socket = MY.replace(
            "    host: db2.internal\n    port: 3306\n",
            "    socket: /run/mysqld/mysqld.sock\n",
        );
        assert!(err(&socket).contains("a Unix socket has no TLS"));
        assert!(
            parse(&socket.replace(
                "    socket: /run/mysqld/mysqld.sock\n",
                "    socket: /run/mysqld/mysqld.sock\n    mysql: {tls: disable}\n",
            ))
            .is_ok()
        );
        // The block is for MySQL / MariaDB targets only.
        let pg = BASE.replace(
            "    port: 5432\n",
            "    port: 5432\n    mysql: {tls: verify_full}\n",
        );
        let message = err(&pg);
        assert!(
            message.contains("targets[0].mysql") && !message.contains("mysql.tls"),
            "{message}"
        );
    }

    #[test]
    fn secret_file_is_read_private_and_trimmed() {
        use crate::fsutil::test_dir::TempDir;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let path = dir.path().join("pw");
        crate::fsutil::write_private_atomic(&path, b"s3cret-FAKE\n").unwrap();
        let secret = SecretRef {
            env: None,
            file: Some(path.clone()),
        };
        assert_eq!(secret.read().unwrap().as_str(), "s3cret-FAKE");
        crate::fsutil::write_private_atomic(&path, b"\n").unwrap();
        assert_eq!(secret.read().unwrap_err(), SecretError::Invalid);
        crate::fsutil::write_private_atomic(&path, b"s3cret-FAKE").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let e = secret.read().unwrap_err();
        assert!(matches!(e, SecretError::File(_)), "{e:?}");
        assert!(!e.to_string().contains("s3cret"));
        let unset = SecretRef {
            env: Some("DATABASTION_TEST_UNSET_SECRET_VARIABLE".to_owned()),
            file: None,
        };
        assert_eq!(unset.read().unwrap_err(), SecretError::Env);
    }

    #[test]
    fn parse_errors_are_closed_categories() {
        assert_eq!(
            render_parse_error("targets[0]: unknown field `password`, expected one of `id`"),
            "unknown field at targets[0]"
        );
        assert_eq!(
            render_parse_error("console: unknown field `port`, expected `url`"),
            "unknown field `port` at console"
        );
        assert_eq!(
            render_parse_error("missing field `url` at line 2 column 3"),
            "missing field `url`"
        );
        assert_eq!(
            render_parse_error("targets[0].port: invalid type: string \"x\", expected u16"),
            "invalid type at targets[0].port"
        );
        assert_eq!(render_parse_error("hunter2: something odd"), "syntax error");
    }

    /// Single-quoted YAML scalar (any character allowed).
    fn yaml_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    #[test]
    fn values_with_quotes_backquotes_backslashes_never_echo() {
        const ALPHABET: &[u8] = b"\"`\\abcXYZ019 -_:,{}[]#&*!|>%@$";
        for round in 0..300u32 {
            let mut noise = [0u8; 12];
            getrandom::fill(&mut noise).unwrap();
            let noise: String = noise
                .iter()
                .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
                .collect();
            // Always contains `"`, a backquote and `\`; the marker is what
            // must never appear.
            let marker = format!("SEKRET{round}");
            let value = match round % 3 {
                0 => format!("\"{marker}`{noise}\\"),
                1 => format!("`{noise}\\{marker}\""),
                _ => format!("{noise}\\\"`{marker}"),
            };
            let quoted = yaml_quote(&value);
            let variants = [
                BASE.replace("port: 5432", &format!("port: {quoted}")),
                BASE.replace("engine: postgres", &format!("engine: {quoted}")),
                BASE.replace("id: pg-main", &format!("id: {quoted}")),
                BASE.replace("DATABASTION_PG_MAIN_PASSWORD", &quoted),
                BASE.replace(
                    "    account: databastion\n",
                    &format!("    account: databastion\n    password: {quoted}\n"),
                ),
                BASE.replace(
                    "    account: databastion\n",
                    &format!("    account: databastion\n    {quoted}: x\n"),
                ),
                BASE.replace(
                    "    secret:\n      env: DATABASTION_PG_MAIN_PASSWORD\n",
                    &format!("    secret: {quoted}\n"),
                ),
                format!("{BASE}limits:\n  max_sample_rows: {quoted}\n"),
            ];
            for text in variants {
                let message = parse(&text).unwrap_err().to_string();
                assert!(!message.contains(&marker), "{value:?} -> {message}");
            }
        }
    }
}
