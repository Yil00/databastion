//! The `cas:` block of a target in `agent.yaml` (ADR-0041 decision 3),
//! validated and resolved when the configuration is loaded (moved here from
//! `connector-cas` when the CAS connector was wired in, P8-B: the core owns
//! the target schema).
//!
//! ```yaml
//! targets:
//!   - id: cas-prod
//!     engine: cas
//!     cas:
//!       service_registry:
//!         json_dir: /etc/cas/services   # or yaml_dir (exclusive)
//!       audit_log:
//!         path: /var/log/cas/cas_audit.log
//!         timezone: UTC
//!       clear_principals: [svc-monitoring]
//!       client_addr: truncated
//! ```
//!
//! A `cas` target is a set of absolute local paths, nothing else (I5, I3):
//! no host, port, socket, account or secret (refused by the target
//! validation for `engine: cas`). Every key is closed
//! (`deny_unknown_fields`). Paths are resolved once when the configuration
//! is loaded or reloaded (symlinks followed once) and refused under
//! `/proc`, `/sys`, `/dev` and under the agent's own state directory (the
//! identity, the HMAC key, the spool and the audit cursors live there);
//! [`ResolvedPath::still_resolves`] tells whether the path still leads to
//! the same place (a later change refuses the source until the next
//! reload).

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// Most `clear_principals`.
pub const MAX_CLEAR_PRINCIPALS: usize = 64;
/// Longest `clear_principals` entry, in bytes.
pub const MAX_PRINCIPAL_BYTES: usize = 256;
/// Longest declared path, in bytes.
const MAX_PATH_BYTES: usize = 4096;
/// Principal names `clear_principals` refuses (security review L4): `*` is
/// the aggregate of failed logins over several accounts, `unidentified` the
/// token of unparsable principals.
const RESERVED_PRINCIPALS: [&str; 2] = ["*", "unidentified"];
/// Directories a declared path may never resolve under.
const SYSTEM_ROOTS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// Invalid `cas:` settings. The message names the key, never its value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cas.{key}: {reason}")]
pub struct CasConfigError {
    /// Dotted key under `cas`.
    pub key: &'static str,
    /// Why it is refused.
    pub reason: &'static str,
}

fn invalid(key: &'static str, reason: &'static str) -> CasConfigError {
    CasConfigError { key, reason }
}

/// How client addresses leave the agent (ADR-0041 open question 8,
/// confirmed): signals are always computed on the full address first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAddrMode {
    /// The address as logged (an IP literal).
    Clear,
    /// IPv4 cut to its /24, IPv6 to its /56 (default for `cas` targets).
    #[default]
    Truncated,
    /// Never sent.
    Omitted,
}

/// `cas.service_registry`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawServiceRegistry {
    /// Directory of JSON service definitions.
    #[serde(default)]
    pub json_dir: Option<PathBuf>,
    /// Directory of YAML service definitions.
    #[serde(default)]
    pub yaml_dir: Option<PathBuf>,
}

/// `cas.audit_log`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAuditLog {
    /// The JSON audit log file.
    pub path: PathBuf,
    /// Zone of the `when` field when it has no offset: `UTC` (default) or
    /// a fixed offset `±HH:MM`.
    #[serde(default)]
    pub timezone: Option<String>,
}

/// The `cas:` block as written.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCasSettings {
    /// Service registry source.
    #[serde(default)]
    pub service_registry: Option<RawServiceRegistry>,
    /// Audit log source.
    #[serde(default)]
    pub audit_log: Option<RawAuditLog>,
    /// Principals sent by name (service and administrator accounts).
    #[serde(default)]
    pub clear_principals: Vec<String>,
    /// Client address reduction.
    #[serde(default)]
    pub client_addr: ClientAddrMode,
}

/// A declared path and what it resolved to when the configuration was
/// loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    declared: PathBuf,
    resolved: PathBuf,
}

impl ResolvedPath {
    /// The path the agent opens (resolved at load).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.resolved
    }

    /// Whether the declared path still resolves to the same place. A path
    /// missing at load resolves to itself, and must then be reached
    /// without symlinks. Blocking I/O.
    #[must_use]
    pub fn still_resolves(&self) -> bool {
        resolve(&self.declared).is_some_and(|now| now == self.resolved)
    }
}

/// UTC offset of the audit log's `when` field, in seconds east of UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UtcOffset(pub i32);

/// The audit log source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogSettings {
    /// The log file.
    pub path: ResolvedPath,
    /// Zone of `when` without an offset.
    pub offset: UtcOffset,
}

/// Format of the service registry directory's definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistryFormat {
    /// `json_dir`: `*.json` files, one definition each.
    #[default]
    Json,
    /// `yaml_dir`: `*.yml` / `*.yaml` files, one definition each, read only
    /// after a pre-scan that refuses anchors, aliases, merge keys and tags
    /// other than CAS class hints (ADR-0041 decision 4, security review L8).
    Yaml,
}

/// The validated `cas:` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasSettings {
    /// Service registry directory (`json_dir` or `yaml_dir`).
    pub registry_dir: Option<ResolvedPath>,
    /// Format of `registry_dir` (meaningless without it).
    pub registry_format: RegistryFormat,
    /// JSON audit log.
    pub audit_log: Option<AuditLogSettings>,
    /// Principals sent in clear (exact names).
    pub clear_principals: Vec<String>,
    /// Client address reduction.
    pub client_addr: ClientAddrMode,
}

impl CasSettings {
    /// Parses and validates a `cas:` block given as YAML (tests and tools;
    /// the agent validates the `targets[].cas` block of `agent.yaml`).
    /// `agent_dirs` are the agent's own directories (its state directory).
    ///
    /// # Errors
    /// [`CasConfigError`] naming the offending key.
    pub fn from_yaml(yaml: &str, agent_dirs: &[&Path]) -> Result<Self, CasConfigError> {
        let raw: RawCasSettings =
            serde_yaml_ng::from_str(yaml).map_err(|_| invalid("", "not a valid cas block"))?;
        Self::validate(raw, agent_dirs)
    }

    /// Validates the raw block (see the module documentation). Blocking
    /// I/O (path resolution).
    ///
    /// # Errors
    /// [`CasConfigError`] naming the offending key.
    pub fn validate(raw: RawCasSettings, agent_dirs: &[&Path]) -> Result<Self, CasConfigError> {
        let (registry_dir, registry_format) = match raw.service_registry {
            None => (None, RegistryFormat::Json),
            Some(r) => match (r.json_dir, r.yaml_dir) {
                (Some(_), Some(_)) => {
                    return Err(invalid(
                        "service_registry",
                        "json_dir and yaml_dir are exclusive",
                    ));
                }
                (None, None) => {
                    return Err(invalid(
                        "service_registry",
                        "one of json_dir and yaml_dir is required",
                    ));
                }
                (Some(dir), None) => (
                    Some(checked_path(&dir, "service_registry.json_dir", agent_dirs)?),
                    RegistryFormat::Json,
                ),
                (None, Some(dir)) => (
                    Some(checked_path(&dir, "service_registry.yaml_dir", agent_dirs)?),
                    RegistryFormat::Yaml,
                ),
            },
        };
        let audit_log = match raw.audit_log {
            None => None,
            Some(a) => Some(AuditLogSettings {
                path: checked_path(&a.path, "audit_log.path", agent_dirs)?,
                offset: match a.timezone.as_deref() {
                    None => UtcOffset(0),
                    Some(tz) => parse_timezone(tz).ok_or_else(|| {
                        invalid("audit_log.timezone", "expected UTC or an offset ±HH:MM")
                    })?,
                },
            }),
        };
        if registry_dir.is_none() && audit_log.is_none() {
            return Err(invalid(
                "",
                "declare at least one of service_registry and audit_log",
            ));
        }
        if raw.clear_principals.len() > MAX_CLEAR_PRINCIPALS {
            return Err(invalid("clear_principals", "at most 64 principals"));
        }
        for p in &raw.clear_principals {
            if p.is_empty()
                || p.len() > MAX_PRINCIPAL_BYTES
                || p.chars().any(char::is_control)
                || p.trim() != p
            {
                return Err(invalid(
                    "clear_principals",
                    "entries must be non-empty names of at most 256 bytes, without control \
                     characters or surrounding blanks",
                ));
            }
            if RESERVED_PRINCIPALS
                .iter()
                .any(|r| r.eq_ignore_ascii_case(p))
            {
                return Err(invalid(
                    "clear_principals",
                    "`*` and `unidentified` are reserved",
                ));
            }
        }
        Ok(Self {
            registry_dir,
            registry_format,
            audit_log,
            clear_principals: raw.clear_principals,
            client_addr: raw.client_addr,
        })
    }
}

/// `UTC`, `Z`, `GMT` or `±HH:MM` (at most ±18:00).
#[must_use]
pub fn parse_timezone(tz: &str) -> Option<UtcOffset> {
    if ["UTC", "Z", "GMT", "Etc/UTC"].contains(&tz) {
        return Some(UtcOffset(0));
    }
    let b = tz.as_bytes();
    let [sign, h1, h2, b':', m1, m2] = *b else {
        return None;
    };
    let digit = |c: u8| c.is_ascii_digit().then(|| i32::from(c - b'0'));
    let hours = digit(h1)? * 10 + digit(h2)?;
    let minutes = digit(m1)? * 10 + digit(m2)?;
    if minutes > 59 || hours * 60 + minutes > 18 * 60 {
        return None;
    }
    let secs = (hours * 60 + minutes) * 60;
    match sign {
        b'+' => Some(UtcOffset(secs)),
        b'-' => Some(UtcOffset(-secs)),
        _ => None,
    }
}

/// Resolves a path: the canonical form when it exists; else its canonical
/// parent and file name (a log not created yet); else the path itself.
fn resolve(path: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::fs::canonicalize(path) {
        return Some(p);
    }
    let parent = path.parent()?;
    let name = path.file_name()?;
    match std::fs::canonicalize(parent) {
        Ok(p) => Some(p.join(name)),
        Err(_) => Some(path.to_path_buf()),
    }
}

fn checked_path(
    path: &Path,
    key: &'static str,
    agent_dirs: &[&Path],
) -> Result<ResolvedPath, CasConfigError> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid(key, "must be valid UTF-8"))?;
    if text.len() > MAX_PATH_BYTES || text.contains('\0') {
        return Err(invalid(key, "path too long or holding a NUL byte"));
    }
    if !path.is_absolute() {
        return Err(invalid(key, "must be an absolute local path"));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(key, "must not contain `.` or `..` components"));
    }
    let resolved = resolve(path).ok_or_else(|| invalid(key, "must name a file or directory"))?;
    let refused = SYSTEM_ROOTS
        .iter()
        .map(|r| PathBuf::from(*r))
        .chain(
            agent_dirs
                .iter()
                .map(|d| std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf())),
        )
        .any(|root| resolved.starts_with(&root) || path.starts_with(&root));
    if refused {
        return Err(invalid(
            key,
            "must not be under /proc, /sys, /dev or the agent's own directories",
        ));
    }
    Ok(ResolvedPath {
        declared: path.to_path_buf(),
        resolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "databastion-cas-config-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("services")).unwrap();
        p
    }

    #[test]
    fn a_full_block_is_accepted_and_resolved() {
        let dir = tmp();
        let yaml = format!(
            "{{service_registry: {{json_dir: {d}/services}}, \
             audit_log: {{path: {d}/cas_audit.log, timezone: \"+02:00\"}}, \
             clear_principals: [svc-monitoring], client_addr: omitted}}",
            d = dir.display()
        );
        let s = CasSettings::from_yaml(&yaml, &[]).unwrap();
        let canon = std::fs::canonicalize(&dir).unwrap();
        assert_eq!(
            s.registry_dir.as_ref().unwrap().path(),
            canon.join("services")
        );
        let log = s.audit_log.as_ref().unwrap();
        assert_eq!(log.path.path(), canon.join("cas_audit.log"));
        assert_eq!(log.offset, UtcOffset(7200));
        assert!(log.path.still_resolves());
        assert_eq!(s.client_addr, ClientAddrMode::Omitted);
        assert_eq!(s.clear_principals, ["svc-monitoring"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn defaults_are_utc_and_truncated() {
        let s = CasSettings::from_yaml("{audit_log: {path: /var/log/cas/a.log}}", &[]).unwrap();
        assert_eq!(s.client_addr, ClientAddrMode::Truncated);
        assert_eq!(s.audit_log.unwrap().offset, UtcOffset(0));
        assert!(s.registry_dir.is_none());
    }

    #[test]
    fn yaml_dir_selects_the_yaml_format() {
        let dir = tmp();
        let json = CasSettings::from_yaml(
            &format!(
                "{{service_registry: {{json_dir: {}/services}}}}",
                dir.display()
            ),
            &[],
        )
        .unwrap();
        assert_eq!(json.registry_format, RegistryFormat::Json);
        let yaml = CasSettings::from_yaml(
            &format!(
                "{{service_registry: {{yaml_dir: {}/services}}}}",
                dir.display()
            ),
            &[],
        )
        .unwrap();
        assert_eq!(yaml.registry_format, RegistryFormat::Yaml);
        assert_eq!(
            yaml.registry_dir.unwrap().path(),
            std::fs::canonicalize(&dir).unwrap().join("services")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn network_and_credential_keys_are_refused() {
        for extra in [
            "host: cas.example.org",
            "port: 8443",
            "account: a",
            "secret: {env: X}",
            "base_url: https://cas.example.org",
        ] {
            let yaml = format!("{{audit_log: {{path: /var/log/a.log}}, {extra}}}");
            assert!(CasSettings::from_yaml(&yaml, &[]).is_err(), "{extra}");
        }
        assert!(CasSettings::from_yaml("{audit_log: {path: /a.log, socket: /x}}", &[]).is_err());
    }

    #[test]
    fn paths_are_checked() {
        let e = |yaml: &str| CasSettings::from_yaml(yaml, &[]).unwrap_err();
        assert_eq!(e("{}").key, "");
        assert_eq!(
            e("{audit_log: {path: var/log/a.log}}").key,
            "audit_log.path"
        );
        assert_eq!(
            e("{audit_log: {path: /var/log/../etc/a.log}}").key,
            "audit_log.path"
        );
        assert_eq!(
            e("{audit_log: {path: /proc/self/environ}}").key,
            "audit_log.path"
        );
        assert_eq!(
            e("{service_registry: {json_dir: /dev/shm}}").key,
            "service_registry.json_dir"
        );
        assert_eq!(
            e("{service_registry: {yaml_dir: /dev/shm}}").key,
            "service_registry.yaml_dir"
        );
        assert_eq!(e("{service_registry: {}}").key, "service_registry");
        assert_eq!(
            e("{service_registry: {json_dir: /a, yaml_dir: /b}}").key,
            "service_registry"
        );
        assert_eq!(
            e("{audit_log: {path: /a.log, timezone: Europe/Paris}}").key,
            "audit_log.timezone"
        );
        // Under the agent's own directories.
        let state = Path::new("/var/lib/databastion");
        assert!(
            CasSettings::from_yaml("{audit_log: {path: /var/lib/databastion/x.log}}", &[state])
                .is_err()
        );
    }

    #[test]
    fn reserved_or_malformed_clear_principals_are_refused() {
        for p in ["\"*\"", "unidentified", "UNIDENTIFIED", "\"\"", "\" a\""] {
            let yaml = format!("{{audit_log: {{path: /a.log}}, clear_principals: [{p}]}}");
            assert_eq!(
                CasSettings::from_yaml(&yaml, &[]).unwrap_err().key,
                "clear_principals",
                "{p}"
            );
        }
        let many: Vec<String> = (0..65).map(|i| format!("svc{i}")).collect();
        let yaml = format!(
            "{{audit_log: {{path: /a.log}}, clear_principals: [{}]}}",
            many.join(",")
        );
        assert!(CasSettings::from_yaml(&yaml, &[]).is_err());
    }

    #[test]
    fn errors_never_quote_values() {
        let e = CasSettings::from_yaml(
            "{audit_log: {path: /a.log}, clear_principals: [\"hunter2-SECRET\\u0001\"]}",
            &[],
        )
        .unwrap_err();
        assert!(!e.to_string().contains("hunter2"));
    }

    #[test]
    fn timezones() {
        assert_eq!(parse_timezone("UTC"), Some(UtcOffset(0)));
        assert_eq!(parse_timezone("-05:30"), Some(UtcOffset(-19_800)));
        assert_eq!(parse_timezone("+18:00"), Some(UtcOffset(64_800)));
        for bad in ["+18:01", "+1:00", "+01:60", "01:00", "CET", "", "+0é:00"] {
            assert_eq!(parse_timezone(bad), None, "{bad}");
        }
    }
}
