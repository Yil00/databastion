//! Engines, audit levels and target health (docs/08-engine-capabilities.md).

use std::fmt;

pub use databastion_protocol::FailureCode;

/// A database or directory engine supported by a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// PostgreSQL.
    Postgres,
    /// MySQL and MariaDB.
    Mysql,
    /// MongoDB.
    Mongodb,
    /// OpenLDAP.
    Openldap,
    /// Apereo CAS (local files only, ADR-0041).
    Cas,
}

impl Engine {
    /// Stable lowercase identifier, as used in configuration and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Mongodb => "mongodb",
            Self::Openldap => "openldap",
            Self::Cas => "cas",
        }
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Audit level reachable on a target, ordered from weakest to strongest.
///
/// A degraded level must be reported honestly: a `Limited` audit never passes
/// for a `Full` one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditLevel {
    /// Discovery only.
    None,
    /// Only slow accesses or aggregated statistics are visible.
    Limited,
    /// Accesses are visible but some information is missing.
    Partial,
    /// Every access is logged with user, object and volume.
    Full,
}

/// Result of [`Connector::check`](crate::Connector::check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHealth {
    /// Whether the target could be reached with the configured account.
    pub reachable: bool,
    /// Audit level actually reachable on this target.
    pub audit_level: AuditLevel,
    /// Why the target is unreachable or degraded, as reported to the
    /// console (`TargetStatus.last_error`). `None` when healthy.
    pub failure: Option<FailureCode>,
    /// Human-readable explanation, e.g. why the audit level is degraded,
    /// for the agent's logs only (never sent). Must never contain a
    /// sampled value or a credential.
    pub detail: Option<String>,
    /// The same explanations as closed notes, sent to the console
    /// (`TargetStatus.notes`) when it accepts them (ADR-0022).
    pub notes: Vec<crate::notes::TargetNote>,
}

impl TargetHealth {
    /// Health reported by a connector that is not implemented yet.
    #[must_use]
    pub fn not_implemented(engine: Engine) -> Self {
        Self {
            reachable: false,
            audit_level: AuditLevel::None,
            failure: Some(FailureCode::Unsupported),
            detail: Some(format!("{engine} connector is not implemented yet")),
            notes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_levels_are_ordered_from_none_to_full() {
        assert!(AuditLevel::None < AuditLevel::Limited);
        assert!(AuditLevel::Limited < AuditLevel::Partial);
        assert!(AuditLevel::Partial < AuditLevel::Full);
    }

    #[test]
    fn engine_identifiers_are_stable() {
        assert_eq!(Engine::Postgres.to_string(), "postgres");
        assert_eq!(Engine::Mysql.to_string(), "mysql");
        assert_eq!(Engine::Mongodb.to_string(), "mongodb");
        assert_eq!(Engine::Openldap.to_string(), "openldap");
    }

    #[test]
    fn not_implemented_health_is_unreachable_without_audit() {
        let health = TargetHealth::not_implemented(Engine::Mysql);
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::Unsupported));
    }
}
