//! Server errors reduced to a closed failure code, the server's numeric
//! error code and a stage (ADR-0026 decision 12).
//!
//! `errmsg`, `codeName` and any other text of an error reply are never
//! read: they can quote values, names or the command. Only the numeric
//! code, the stage (a closed set, used in logs instead of the command) and
//! the closed failure code reach logs and the console.

use databastion_core::{ConnectorError, Engine, FailureCode};

use crate::scram::ScramError;
use crate::wire::WireError;

/// What the connector was doing when an error occurred. The names are the
/// `stage_*` note labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    /// `hello`.
    SessionSetup,
    Auth,
    /// `listDatabases`, `listCollections`.
    Introspection,
    /// `count`, `find`, `aggregate`.
    Sample,
    Check,
    /// Audit: prerequisites and profiler polls.
    Audit,
    /// `killCursors`.
    Kill,
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
            Self::Kill => "kill",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MgError {
    pub(crate) code: FailureCode,
    /// Server error code (`code` of an error reply).
    pub(crate) server_code: Option<i32>,
    pub(crate) stage: Stage,
    /// The connection is unusable (I/O or protocol error, error during
    /// connection setup, or an error after which the server closes it).
    pub(crate) fatal: bool,
}

impl MgError {
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code,
            server_code: None,
            stage,
            fatal: true,
        }
    }

    /// An error reply (`ok: 0`) with its numeric code.
    pub(crate) fn server(server_code: Option<i32>, stage: Stage) -> Self {
        let setup = matches!(
            stage,
            Stage::Connect | Stage::Tls | Stage::SessionSetup | Stage::Auth | Stage::Secret
        );
        Self {
            code: server_code.map_or(FailureCode::Internal, failure_of),
            server_code,
            stage,
            fatal: setup || server_code.is_some_and(closes_connection),
        }
    }

    pub(crate) fn from_wire(e: WireError, stage: Stage) -> Self {
        match e {
            WireError::Io(kind) => {
                tracing::debug!(%kind, stage = stage.as_str(), "connection error");
                let code = if kind == std::io::ErrorKind::TimedOut {
                    FailureCode::Timeout
                } else {
                    FailureCode::TargetUnreachable
                };
                Self::new(code, stage)
            }
            WireError::TooLarge => Self::new(FailureCode::ResourceLimit, stage),
            WireError::Malformed => Self::new(FailureCode::Internal, stage),
        }
    }

    pub(crate) fn from_scram(e: ScramError) -> Self {
        tracing::debug!(reason = %e, "SCRAM exchange refused");
        Self::new(FailureCode::AuthenticationFailed, Stage::Auth)
    }

    /// The code reported to the console (contract `EngineCode`: digits
    /// only here).
    pub(crate) fn engine_code(&self) -> Option<String> {
        self.server_code.filter(|c| *c >= 0).map(|c| c.to_string())
    }

    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Mongodb,
            code: self.code,
            engine_code: self.engine_code(),
        }
    }
}

/// Errors after which the server closes (or is closing) the connection.
fn closes_connection(code: i32) -> bool {
    matches!(
        code,
        // ShutdownInProgress, InterruptedAtShutdown, PrimarySteppedDown,
        // ClientDisconnect, InterruptedDueToReplStateChange.
        91 | 11600 | 189 | 279 | 11602
    )
}

/// Server error code to closed failure code.
pub(crate) fn failure_of(code: i32) -> FailureCode {
    match code {
        // AuthenticationFailed, UserNotFound, MechanismUnavailable,
        // AuthenticationRestrictionUnmet.
        18 | 11 | 334 | 16436 => FailureCode::AuthenticationFailed,
        // Unauthorized.
        13 => FailureCode::PermissionDenied,
        // ExceededTimeLimit, NetworkTimeout, LockTimeout,
        // MaxTimeMSExpired, NetworkInterfaceExceededTimeLimit.
        262 | 89 | 24 | 50 | 202 => FailureCode::Timeout,
        // Interrupted, InterruptedDueToReplStateChange, ClientDisconnect.
        11601 | 11602 | 279 => FailureCode::Cancelled,
        // HostUnreachable, HostNotFound, ShutdownInProgress,
        // PrimarySteppedDown, FailedToSatisfyReadPreference,
        // NotWritablePrimary, InterruptedAtShutdown, NotPrimaryNoSecondaryOk,
        // NotPrimaryOrSecondary.
        6 | 7 | 91 | 189 | 133 | 10107 | 11600 | 13435 | 13436 => FailureCode::TargetUnreachable,
        // ExceededMemoryLimit, QueryExceededMemoryLimitNoDiskUseAllowed,
        // BSONObjectTooLarge.
        146 | 292 | 10334 => FailureCode::ResourceLimit,
        // CommandNotFound, CommandNotSupported, CommandNotSupportedOnView,
        // InvalidOptions.
        59 | 115 | 166 | 72 => FailureCode::Unsupported,
        _ => FailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_codes_map_to_closed_codes() {
        assert_eq!(failure_of(18), FailureCode::AuthenticationFailed);
        assert_eq!(failure_of(13), FailureCode::PermissionDenied);
        assert_eq!(failure_of(50), FailureCode::Timeout);
        assert_eq!(failure_of(11601), FailureCode::Cancelled);
        assert_eq!(failure_of(13435), FailureCode::TargetUnreachable);
        assert_eq!(failure_of(292), FailureCode::ResourceLimit);
        assert_eq!(failure_of(166), FailureCode::Unsupported);
        assert_eq!(failure_of(26), FailureCode::Internal);
    }

    #[test]
    fn setup_errors_are_fatal_and_carry_the_code_only() {
        let e = MgError::server(Some(18), Stage::Auth);
        assert!(e.fatal);
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
        let e = MgError::server(Some(13), Stage::Sample);
        assert!(!e.fatal);
        let text = e.into_connector_error().to_string();
        assert!(
            text.contains("permission_denied") && text.contains("13"),
            "{text}"
        );
        assert!(MgError::server(Some(91), Stage::Sample).fatal);
        // A negative code is not an `EngineCode`.
        assert_eq!(MgError::server(Some(-3), Stage::Sample).engine_code(), None);
        assert_eq!(
            MgError::server(None, Stage::Sample).code,
            FailureCode::Internal
        );
    }

    #[test]
    fn wire_errors() {
        let e = MgError::from_wire(WireError::TooLarge, Stage::Sample);
        assert_eq!(e.code, FailureCode::ResourceLimit);
        assert!(e.fatal);
        let e = MgError::from_wire(WireError::Io(std::io::ErrorKind::TimedOut), Stage::Sample);
        assert_eq!(e.code, FailureCode::Timeout);
        let e = MgError::from_wire(
            WireError::Io(std::io::ErrorKind::ConnectionReset),
            Stage::Connect,
        );
        assert_eq!(e.code, FailureCode::TargetUnreachable);
    }
}
