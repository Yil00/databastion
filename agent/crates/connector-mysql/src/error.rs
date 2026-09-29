//! Server errors reduced to a closed failure code, an error number and a
//! SQLSTATE (the MySQL counterpart of ADR-0012 obligation 7).
//!
//! Error packets are parsed by `proto` without keeping their message: the
//! text can quote values, statement text, account or host names. Only the
//! error number, the SQLSTATE and the stage (a closed set, used in logs
//! instead of the statement) reach logs and the console.

use databastion_core::{ConnectorError, Engine, FailureCode};

use crate::proto::{ProtoError, ServerError};

/// What the connector was doing when an error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    Auth,
    SessionSetup,
    Begin,
    Commit,
    Introspection,
    Columns,
    Sample,
    Check,
    Kill,
    Audit,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Tls => "tls",
            Self::Connect => "connect",
            Self::Auth => "auth",
            Self::SessionSetup => "session_setup",
            Self::Begin => "begin",
            Self::Commit => "commit",
            Self::Introspection => "introspection",
            Self::Columns => "columns",
            Self::Sample => "sample",
            Self::Check => "check",
            Self::Kill => "kill",
            Self::Audit => "audit",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MyError {
    pub(crate) code: FailureCode,
    /// Server error number (e.g. `1142`).
    pub(crate) errno: Option<u16>,
    /// SQLSTATE (five `[0-9A-Z]`).
    pub(crate) sqlstate: Option<String>,
    pub(crate) stage: Stage,
    /// The session is unusable (I/O or protocol error, closed connection,
    /// error during connection setup).
    pub(crate) fatal: bool,
}

impl MyError {
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code,
            errno: None,
            sqlstate: None,
            stage,
            fatal: true,
        }
    }

    /// A server error packet. Fatal during connection setup, or for the
    /// errors after which the server closes the connection.
    pub(crate) fn server(e: ServerError, stage: Stage) -> Self {
        let setup = matches!(
            stage,
            Stage::Connect | Stage::Auth | Stage::Tls | Stage::SessionSetup
        );
        Self {
            code: failure_of(e.errno),
            errno: Some(e.errno),
            sqlstate: e.sqlstate().map(str::to_owned),
            stage,
            fatal: setup || closes_connection(e.errno),
        }
    }

    /// Reduces a protocol failure.
    pub(crate) fn from_proto(e: ProtoError, stage: Stage) -> Self {
        match e {
            ProtoError::Server(s) => Self::server(s, stage),
            // Closed or broken connection.
            ProtoError::Io(kind) => {
                tracing::debug!(%kind, stage = stage.as_str(), "connection error");
                Self::new(FailureCode::TargetUnreachable, stage)
            }
            // An oversized row while sampling ends that table only (the
            // session is poisoned and replaced); anywhere else the session
            // is unusable.
            ProtoError::TooLarge => Self {
                fatal: stage != Stage::Sample,
                ..Self::new(FailureCode::ResourceLimit, stage)
            },
            ProtoError::Malformed => Self::new(FailureCode::Internal, stage),
        }
    }

    pub(crate) fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }

    /// The engine code reported to the console: the error number
    /// (`[0-9]{1,5}`, contract `EngineCode`), else the SQLSTATE.
    pub(crate) fn engine_code(&self) -> Option<String> {
        self.errno
            .map(|n| n.to_string())
            .or_else(|| self.sqlstate.clone())
    }

    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Mysql,
            code: self.code,
            engine_code: self.engine_code(),
        }
    }
}

/// Errors after which the server has closed (or is closing) the session.
fn closes_connection(errno: u16) -> bool {
    matches!(
        errno,
        // ER_SERVER_SHUTDOWN, ER_CONNECTION_KILLED (MariaDB),
        // ER_CLIENT_INTERACTION_TIMEOUT (MySQL 8.0.24+), ER_NET_* read /
        // write errors and timeouts.
        1053 | 1927 | 4031 | 1152..=1161 | 1184
    )
}

/// Error number to closed failure code.
pub(crate) fn failure_of(errno: u16) -> FailureCode {
    match errno {
        // ER_ACCESS_DENIED_ERROR, ER_NOT_SUPPORTED_AUTH_MODE,
        // ER_MUST_CHANGE_PASSWORD(_LOGIN), ER_ACCOUNT_HAS_BEEN_LOCKED,
        // ER_ACCESS_DENIED_NO_PASSWORD_ERROR, ER_SECURE_TRANSPORT_REQUIRED
        1045 | 1251 | 1820 | 1862 | 3118 | 1698 | 3159 => FailureCode::AuthenticationFailed,
        // ER_DBACCESS_DENIED_ERROR, ER_TABLEACCESS_DENIED_ERROR,
        // ER_COLUMNACCESS_DENIED_ERROR, ER_SPECIFIC_ACCESS_DENIED_ERROR,
        // ER_PROCACCESS_DENIED_ERROR, ER_KILL_DENIED_ERROR,
        // ER_TABLEACCESS_DENIED_ERROR variants
        1044 | 1142 | 1143 | 1227 | 1370 | 1095 | 3530 => FailureCode::PermissionDenied,
        // ER_QUERY_INTERRUPTED (KILL QUERY), ER_LOCK_WAIT_TIMEOUT,
        // ER_QUERY_TIMEOUT (MySQL max_execution_time),
        // ER_STATEMENT_TIMEOUT (MariaDB max_statement_time),
        // ER_LOCK_WAIT_TIMEOUT for metadata locks, idle timeouts
        1317 | 1205 | 3024 | 1969 | 4031 => FailureCode::Timeout,
        // ER_CON_COUNT_ERROR, ER_TOO_MANY_USER_CONNECTIONS,
        // ER_USER_LIMIT_REACHED, ER_OUT_OF_RESOURCES, ER_OUTOFMEMORY
        1040 | 1203 | 1226 | 1041 | 1037 | 1038 => FailureCode::ResourceLimit,
        // ER_HOST_NOT_PRIVILEGED, ER_HOST_IS_BLOCKED, ER_SERVER_SHUTDOWN,
        // ER_CONNECTION_KILLED, ER_BAD_DB_ERROR
        1130 | 1129 | 1053 | 1927 | 1049 => FailureCode::TargetUnreachable,
        _ => FailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_row_only_skips_its_table() {
        let e = MyError::from_proto(ProtoError::TooLarge, Stage::Sample);
        assert_eq!((e.code, e.fatal), (FailureCode::ResourceLimit, false));
        assert!(MyError::from_proto(ProtoError::TooLarge, Stage::Introspection).fatal);
    }

    #[test]
    fn error_numbers_map_to_closed_codes() {
        assert_eq!(failure_of(1045), FailureCode::AuthenticationFailed);
        assert_eq!(failure_of(1142), FailureCode::PermissionDenied);
        assert_eq!(failure_of(3024), FailureCode::Timeout);
        assert_eq!(failure_of(1969), FailureCode::Timeout);
        assert_eq!(failure_of(1317), FailureCode::Timeout);
        assert_eq!(failure_of(1040), FailureCode::ResourceLimit);
        assert_eq!(failure_of(1130), FailureCode::TargetUnreachable);
        assert_eq!(failure_of(1792), FailureCode::Internal);
    }

    #[test]
    fn connector_error_carries_code_and_errno_only() {
        let e = MyError::server(
            ServerError {
                errno: 1142,
                sqlstate: Some(*b"42000"),
            },
            Stage::Sample,
        );
        assert!(!e.fatal);
        assert_eq!(e.sqlstate(), Some("42000"));
        let text = e.into_connector_error().to_string();
        assert!(text.contains("permission_denied"), "{text}");
        assert!(text.contains("1142"), "{text}");
        // Errors during setup are fatal.
        let e = MyError::server(
            ServerError {
                errno: 1045,
                sqlstate: None,
            },
            Stage::Auth,
        );
        assert!(e.fatal);
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
    }
}
