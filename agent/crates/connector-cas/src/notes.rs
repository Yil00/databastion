//! Closed target notes and signals of a `cas` target (ADR-0041 decisions 8
//! and 11), as crate-internal types.
//!
//! TODO(P8-C): wired to the protocol types in P8-C. The `cas` engine, the
//! new notes (`target-notes.json`) and the two signals (`signals.json`) are
//! added to the contract on another branch; until it merges, this crate
//! keeps its own closed enums with the contract spellings, and nothing here
//! reaches the uplink (the crate is not wired into the agent core yet).

use std::fmt;

/// Closed note codes a `cas` target reports (ADR-0041 decision 11). Counts
/// only: a note never carries a path, a file name or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CasNoteCode {
    /// The audit log cannot be opened, or is refused (agent-writable,
    /// not a regular file, resolved target changed).
    AuditLogNotReadable,
    /// The audit log has records but none parses as one JSON object
    /// (`DEFAULT` format, or a layout that adds a prefix).
    AuditLogFormatUnsupported,
    /// No valid record parsed yet.
    AuditLimitedPendingFirstRecord,
    /// No `AUTHENTICATION_SUCCESS` record in the last 24 h.
    AuditAuthRecordsNotSeen,
    /// No `AUTHENTICATION_FAILED` record in the last 7 days.
    AuditAuthFailuresNotSeen,
    /// No service-ticket (or token) issuance record in the last 24 h.
    AuditServiceTicketRecordsNotSeen,
    /// Records dropped (unparsable, oversized, parser failure); count.
    AuditRecordsDropped,
    /// The audit stream was stopped (panics, ADR-0032).
    AuditStreamStopped,
    /// Registry files skipped (unreadable, refused, too large, not a
    /// service definition, unparsable); count.
    CoverageRegistryFilesSkipped,
    /// Services whose `clientSecret` is stored in clear; count.
    SecurityClientSecretsInClear,
    /// Audit records carry a `headers` key (cookies in the log).
    SecurityAuditHeadersLogged,
    /// A registry file or directory (or an ancestor) is writable by the
    /// agent's account, so it is refused.
    PrivilegeRegistryWritable,
    /// CAS configuration files in the registry directory: the source is
    /// refused (existing code, `cas` added to its engines in P8-C).
    PrivilegeConfigReadable,
    /// A check stage failed.
    CheckStageFailed,
    /// The check ran out of time.
    CheckTimedOut,
}

impl CasNoteCode {
    /// Every code.
    pub const ALL: [Self; 15] = [
        Self::AuditLogNotReadable,
        Self::AuditLogFormatUnsupported,
        Self::AuditLimitedPendingFirstRecord,
        Self::AuditAuthRecordsNotSeen,
        Self::AuditAuthFailuresNotSeen,
        Self::AuditServiceTicketRecordsNotSeen,
        Self::AuditRecordsDropped,
        Self::AuditStreamStopped,
        Self::CoverageRegistryFilesSkipped,
        Self::SecurityClientSecretsInClear,
        Self::SecurityAuditHeadersLogged,
        Self::PrivilegeRegistryWritable,
        Self::PrivilegeConfigReadable,
        Self::CheckStageFailed,
        Self::CheckTimedOut,
    ];

    /// Contract spelling (ADR-0041 decision 11).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditLogNotReadable => "audit.log_not_readable",
            Self::AuditLogFormatUnsupported => "audit.log_format_unsupported",
            Self::AuditLimitedPendingFirstRecord => "audit.limited_pending_first_record",
            Self::AuditAuthRecordsNotSeen => "audit.auth_records_not_seen",
            Self::AuditAuthFailuresNotSeen => "audit.auth_failures_not_seen",
            Self::AuditServiceTicketRecordsNotSeen => "audit.service_ticket_records_not_seen",
            Self::AuditRecordsDropped => "audit.records_dropped",
            Self::AuditStreamStopped => "audit.stream_stopped",
            Self::CoverageRegistryFilesSkipped => "coverage.registry_files_skipped",
            Self::SecurityClientSecretsInClear => "security.client_secrets_in_clear",
            Self::SecurityAuditHeadersLogged => "security.audit_headers_logged",
            Self::PrivilegeRegistryWritable => "privilege.registry_writable",
            Self::PrivilegeConfigReadable => "privilege.config_readable",
            Self::CheckStageFailed => "check.stage_failed",
            Self::CheckTimedOut => "check.timed_out",
        }
    }
}

impl fmt::Display for CasNoteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A note with its optional count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CasNote {
    /// Closed code.
    pub code: CasNoteCode,
    /// Count, for the codes that carry one.
    pub count: Option<u64>,
}

impl CasNote {
    /// A note without a count.
    #[must_use]
    pub const fn flag(code: CasNoteCode) -> Self {
        Self { code, count: None }
    }

    /// A note with a count.
    #[must_use]
    pub const fn counted(code: CasNoteCode, count: u64) -> Self {
        Self {
            code,
            count: Some(count),
        }
    }
}

/// Signals of a `cas` target (ADR-0041 decision 8; heuristics).
///
/// TODO(P8-C): wired to the protocol types in P8-C (appended to
/// `signals.json` with engine `cas`, then to
/// `databastion_classifiers::masking::Signal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CasSignal {
    /// One client address, failed authentications for at least
    /// [`crate::audit::events::MANY_ACCOUNTS`] distinct principals within
    /// [`crate::audit::events::WINDOW`].
    FailedLoginsManyAccounts,
    /// One principal, at least [`crate::audit::events::ONE_ACCOUNT_FAILURES`]
    /// failed authentications within [`crate::audit::events::WINDOW`].
    FailedLoginsOneAccount,
}

impl CasSignal {
    /// Contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailedLoginsManyAccounts => "volume.failed_logins_many_accounts",
            Self::FailedLoginsOneAccount => "volume.failed_logins_one_account",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_are_unique_and_shaped_like_the_contract() {
        let mut seen = std::collections::HashSet::new();
        for c in CasNoteCode::ALL {
            let s = c.as_str();
            assert!(seen.insert(s), "{s}");
            let (prefix, rest) = s.split_once('.').unwrap();
            assert!(
                ["audit", "coverage", "security", "privilege", "check"].contains(&prefix),
                "{s}"
            );
            assert!(
                rest.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{s}"
            );
        }
        for s in [
            CasSignal::FailedLoginsManyAccounts,
            CasSignal::FailedLoginsOneAccount,
        ] {
            assert!(s.as_str().starts_with("volume."));
        }
    }
}
