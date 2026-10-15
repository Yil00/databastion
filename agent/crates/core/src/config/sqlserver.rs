//! `targets[].sqlserver`: settings of a Microsoft SQL Server target
//! (ADR-0051).
//!
//! One declared `host` / `port` (decision 2: no SQL Server Browser, no
//! routing, no named-instance resolution; I5). TLS on every transport,
//! loopback included, because `LOGIN7` carries the password in a reversible
//! form: there is no `disable` mode. SQL logins only.

use std::path::PathBuf;

use serde::Deserialize;

/// Default TCP port of SQL Server.
pub const DEFAULT_PORT: u16 = 1433;
/// Most declared databases.
pub const MAX_DATABASES: usize = 1024;
/// Longest database name (`sysname`).
pub const MAX_NAME_CHARS: usize = 128;
/// Range of `sqlserver.max_tables` (tables per database, decision 5).
pub const MAX_TABLES_RANGE: (u32, u32) = (1, 16_384);

/// TLS mode of a SQL Server target (decision 2, refinement item 3). Every
/// mode verifies the certificate against `ca_file` (then the only trusted
/// root) or the system store, and the declared host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlserverTlsMode {
    /// Strict first (TDS 8.0); one fallback to `mandatory` when the strict
    /// handshake fails before any TDS byte, retried strict at least hourly
    /// and at every start; never after a strict session was seen.
    #[default]
    Auto,
    /// TDS 8.0: TLS from the first byte, ALPN `tds/8.0`.
    Strict,
    /// TDS 7.x: `PRELOGIN` with encryption required, the TLS handshake in
    /// `PRELOGIN` packets, then the whole session encrypted.
    Mandatory,
}

/// `sqlserver.rls_visibility` (refinement item 2, option (iv)): the local
/// opt-in that makes row-level security policies visible to the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RlsVisibility {
    /// The account holds database `VIEW DEFINITION` in each monitored
    /// database, proven effective and not hidden by a `DENY`.
    ViewDefinition,
}

/// `sqlserver.audit.source` (ADR-0051 decision 6): which operator-created
/// source the Audit stream reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlserverAuditSource {
    /// The preference rule of decision 6: SQL Server Audit when usable,
    /// then Extended Events.
    #[default]
    Auto,
    /// SQL Server Audit, `FILE` target (`audit_name`).
    SqlserverAudit,
    /// An Extended Events session with an `event_file` target
    /// (`xe_session`).
    SqlserverXevents,
}

/// `sqlserver.audit`: the operator-created audit sources the agent reads
/// (decision 6). The agent never creates, alters, starts or stops them;
/// the audit file pattern is read from the server's catalog, never from
/// here (a path from configuration would make the agent a file-read
/// primitive).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SqlserverAuditConfig {
    /// Which source. Default: `auto`.
    #[serde(default)]
    pub source: SqlserverAuditSource,
    /// Name of the server audit (`sys.server_file_audits.name`).
    #[serde(default)]
    pub audit_name: Option<String>,
    /// Name of the Extended Events session.
    #[serde(default)]
    pub xe_session: Option<String>,
}

impl SqlserverAuditConfig {
    fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        for (key, name) in [
            ("audit.audit_name", &self.audit_name),
            ("audit.xe_session", &self.xe_session),
        ] {
            if let Some(n) = name
                && (n.is_empty()
                    || n.chars().count() > MAX_NAME_CHARS
                    || n.chars().any(char::is_control))
            {
                return Err((
                    key,
                    "must be 1 to 128 characters without control characters",
                ));
            }
        }
        match self.source {
            SqlserverAuditSource::SqlserverAudit if self.audit_name.is_none() => Err((
                "audit.audit_name",
                "is required with source: sqlserver_audit",
            )),
            SqlserverAuditSource::SqlserverXevents if self.xe_session.is_none() => Err((
                "audit.xe_session",
                "is required with source: sqlserver_xevents",
            )),
            SqlserverAuditSource::Auto
                if self.audit_name.is_none() && self.xe_session.is_none() =>
            {
                Err(("audit", "names no source (audit_name or xe_session)"))
            }
            _ => Ok(()),
        }
    }
}

/// SQL Server settings of a target.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SqlserverTargetConfig {
    /// TLS to the server. Default: `auto`.
    #[serde(default)]
    pub tls: SqlserverTlsMode,
    /// PEM CA file trusted for the server certificate (then the only
    /// trusted root); otherwise the system store.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Databases Discovery may read (default: every accessible user
    /// database). Names as the server lists them; never sent.
    #[serde(default)]
    pub databases: Option<Vec<String>>,
    /// Row-level security visibility opt-in (refinement item 2).
    #[serde(default)]
    pub rls_visibility: Option<RlsVisibility>,
    /// Extended grant variant (`db_datareader`), reported as
    /// `privilege.extended_variant` instead of over-privilege.
    #[serde(default)]
    pub extended_grants: bool,
    /// Tables read per database and scan (default and maximum 16 384).
    #[serde(default = "default_max_tables")]
    pub max_tables: u32,
    /// CAS stores under custom names (ADR-0041 decision 5).
    #[serde(default)]
    pub cas_stores: Option<crate::cas_guard::CasStores>,
    /// The Audit sources (decision 6); absent: no Audit source.
    #[serde(default)]
    pub audit: Option<SqlserverAuditConfig>,
}

const fn default_max_tables() -> u32 {
    MAX_TABLES_RANGE.1
}

impl Default for SqlserverTargetConfig {
    fn default() -> Self {
        Self {
            tls: SqlserverTlsMode::default(),
            ca_file: None,
            databases: None,
            rls_visibility: None,
            extended_grants: false,
            max_tables: default_max_tables(),
            cas_stores: None,
            audit: None,
        }
    }
}

impl SqlserverTargetConfig {
    /// Local rules of the block: `(key, reason)` on error.
    pub(crate) fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        if let Some(path) = &self.ca_file
            && !path.is_absolute()
        {
            return Err(("ca_file", "must be an absolute path"));
        }
        if let Some(dbs) = &self.databases {
            if dbs.is_empty() || dbs.len() > MAX_DATABASES {
                return Err(("databases", "must list 1 to 1024 databases"));
            }
            let mut seen = std::collections::HashSet::new();
            for db in dbs {
                if db.is_empty()
                    || db.chars().count() > MAX_NAME_CHARS
                    || db.chars().any(char::is_control)
                {
                    return Err((
                        "databases",
                        "each name must be 1 to 128 characters without control characters",
                    ));
                }
                if !seen.insert(db.to_lowercase()) {
                    return Err(("databases", "listed twice"));
                }
            }
        }
        if !(MAX_TABLES_RANGE.0..=MAX_TABLES_RANGE.1).contains(&self.max_tables) {
            return Err(("max_tables", "must be in 1..=16384"));
        }
        if let Some(Err(e)) = self.audit.as_ref().map(SqlserverAuditConfig::validate) {
            return Err(e);
        }
        if let Some(Err(e)) = self
            .cas_stores
            .as_ref()
            .map(crate::cas_guard::CasStores::validate)
        {
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn block_rules() {
        assert!(SqlserverTargetConfig::default().validate().is_ok());
        let c = SqlserverTargetConfig {
            databases: Some(vec!["retail".into(), "RETAIL".into()]),
            ..SqlserverTargetConfig::default()
        };
        assert!(c.validate().is_err());
        let c = SqlserverTargetConfig {
            databases: Some(vec![]),
            ..SqlserverTargetConfig::default()
        };
        assert!(c.validate().is_err());
        let c = SqlserverTargetConfig {
            max_tables: 0,
            ..SqlserverTargetConfig::default()
        };
        assert!(c.validate().is_err());
        let c = SqlserverTargetConfig {
            ca_file: Some("ca.pem".into()),
            ..SqlserverTargetConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn audit_block_rules() {
        let with = |audit: SqlserverAuditConfig| SqlserverTargetConfig {
            audit: Some(audit),
            ..SqlserverTargetConfig::default()
        };
        let ok = SqlserverAuditConfig {
            source: SqlserverAuditSource::SqlserverAudit,
            audit_name: Some("databastion_audit".into()),
            xe_session: None,
        };
        assert!(with(ok.clone()).validate().is_ok());
        assert!(
            with(SqlserverAuditConfig {
                audit_name: None,
                ..ok.clone()
            })
            .validate()
            .is_err()
        );
        assert!(
            with(SqlserverAuditConfig {
                audit_name: Some("a\nb".to_owned()),
                ..ok.clone()
            })
            .validate()
            .is_err()
        );
        assert!(
            with(SqlserverAuditConfig {
                source: SqlserverAuditSource::Auto,
                audit_name: None,
                xe_session: None,
            })
            .validate()
            .is_err()
        );
        let yaml: SqlserverTargetConfig =
            serde_yaml_ng::from_str("{audit: {audit_name: databastion_audit}}").unwrap();
        assert_eq!(yaml.audit.unwrap().source, SqlserverAuditSource::Auto);
        assert!(
            serde_yaml_ng::from_str::<SqlserverTargetConfig>("{audit: {audit_name: a, path: /x}}")
                .is_err()
        );
    }
}
