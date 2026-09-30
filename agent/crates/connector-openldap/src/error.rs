//! Errors reduced to a closed failure code, the LDAP result code and a
//! stage (ADR-0029 decision 12).
//!
//! `diagnosticMessage`, `matchedDN` and referral URIs are never read into
//! an error: they can quote values and entry DNs. Only the numeric result
//! code, the stage (a closed set) and the closed failure code reach logs
//! and the console.

use databastion_core::{ConnectorError, Engine, FailureCode};

/// What the connector was doing. The names are the `stage_*` note labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    /// StartTLS, Who am I?
    SessionSetup,
    Auth,
    /// Root DSE, schema, container listing.
    Introspection,
    /// Entry sampling.
    Sample,
    Check,
    /// `cn=accesslog` reads.
    Audit,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Tls => "tls",
            Self::Connect => "connect",
            Self::SessionSetup => "session_setup",
            Self::Auth => "auth",
            Self::Introspection => "introspection",
            Self::Sample => "sample",
            Self::Check => "check",
            Self::Audit => "audit",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LdError {
    pub(crate) code: FailureCode,
    /// LDAP result code of a failed operation.
    pub(crate) result: Option<u32>,
    pub(crate) stage: Stage,
    /// The connection is unusable (I/O, protocol or setup error).
    pub(crate) fatal: bool,
}

impl LdError {
    /// A local or transport failure: the connection is unusable.
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code,
            result: None,
            stage,
            fatal: true,
        }
    }

    /// A failed operation with its result code. Setup stages and
    /// codes after which the server closes the connection are fatal.
    pub(crate) fn result(code: u32, stage: Stage) -> Self {
        let setup = matches!(
            stage,
            Stage::Connect | Stage::Tls | Stage::SessionSetup | Stage::Auth | Stage::Secret
        );
        Self {
            code: failure_of(code),
            result: Some(code),
            stage,
            fatal: setup || matches!(code, 1 | 2 | 52 | 80),
        }
    }

    /// The code reported to the console (contract `EngineCode`).
    pub(crate) fn engine_code(&self) -> Option<String> {
        self.result.map(|c| c.to_string())
    }

    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Openldap,
            code: self.code,
            engine_code: self.engine_code(),
        }
    }
}

/// LDAP result code (RFC 4511 appendix A) to closed failure code.
pub(crate) fn failure_of(code: u32) -> FailureCode {
    match code {
        // authMethodNotSupported, strongerAuthRequired, confidentialityRequired,
        // inappropriateAuthentication, invalidCredentials.
        7 | 8 | 13 | 48 | 49 => FailureCode::AuthenticationFailed,
        // insufficientAccessRights.
        50 => FailureCode::PermissionDenied,
        // timeLimitExceeded.
        3 => FailureCode::Timeout,
        // busy, unavailable, other (server shutting down).
        51 | 52 | 80 => FailureCode::TargetUnreachable,
        // sizeLimitExceeded, adminLimitExceeded.
        4 | 11 => FailureCode::ResourceLimit,
        // protocolError, unavailableCriticalExtension, unwillingToPerform.
        2 | 12 | 53 => FailureCode::Unsupported,
        // noSuchObject.
        32 => FailureCode::UnknownTarget,
        _ => FailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_codes_map_to_closed_codes() {
        assert_eq!(failure_of(49), FailureCode::AuthenticationFailed);
        assert_eq!(failure_of(50), FailureCode::PermissionDenied);
        assert_eq!(failure_of(3), FailureCode::Timeout);
        assert_eq!(failure_of(52), FailureCode::TargetUnreachable);
        assert_eq!(failure_of(4), FailureCode::ResourceLimit);
        assert_eq!(failure_of(53), FailureCode::Unsupported);
        assert_eq!(failure_of(32), FailureCode::UnknownTarget);
        assert_eq!(failure_of(64), FailureCode::Internal);
    }

    #[test]
    fn errors_carry_the_code_only() {
        let e = LdError::result(49, Stage::Auth);
        assert!(e.fatal);
        let e = LdError::result(50, Stage::Sample);
        assert!(!e.fatal);
        let text = e.into_connector_error().to_string();
        assert!(
            text.contains("permission_denied") && text.contains("50"),
            "{text}"
        );
        assert!(LdError::result(52, Stage::Sample).fatal);
        assert_eq!(
            LdError::new(FailureCode::Internal, Stage::Sample).engine_code(),
            None
        );
    }
}
