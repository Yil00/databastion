//! Server errors reduced to a closed failure code and a SQLSTATE (ADR-0012
//! obligation 7).
//!
//! A `tokio_postgres::Error` renders the server's message, detail and
//! context, which can quote values, query text or host names (a foreign
//! server's `DETAIL`). It is never formatted, logged or returned: only its
//! SQLSTATE and the kind of statement that failed are kept.

use databastion_core::{ConnectorError, Engine, FailureCode};

/// What the connector was doing when an error occurred. Closed set, used
/// in logs instead of the statement text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    SessionSetup,
    Begin,
    Commit,
    Introspection,
    Columns,
    Sample,
    Check,
    Audit,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Tls => "tls",
            Self::Connect => "connect",
            Self::SessionSetup => "session_setup",
            Self::Begin => "begin",
            Self::Commit => "commit",
            Self::Introspection => "introspection",
            Self::Columns => "columns",
            Self::Sample => "sample",
            Self::Check => "check",
            Self::Audit => "audit",
        }
    }
}

/// A connector error: failure code, SQLSTATE (5 characters `[0-9A-Z]`) and
/// stage. No text from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PgError {
    pub(crate) code: FailureCode,
    pub(crate) sqlstate: Option<String>,
    pub(crate) stage: Stage,
    /// The connection is unusable (closed, broken, or the session was
    /// terminated by the server).
    pub(crate) fatal: bool,
}

impl PgError {
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code,
            sqlstate: None,
            stage,
            fatal: true,
        }
    }

    /// Reduces a driver error. The error itself is dropped here.
    pub(crate) fn from_driver(e: &tokio_postgres::Error, stage: Stage) -> Self {
        let sqlstate = e.code().map(|c| c.code()).filter(|c| is_sqlstate(c));
        let code = match sqlstate {
            Some(s) => failure_of(s),
            None if e.is_closed() => FailureCode::TargetUnreachable,
            // No SQLSTATE: I/O, TLS or protocol error.
            None => match stage {
                Stage::Connect | Stage::Tls => FailureCode::TargetUnreachable,
                _ => FailureCode::Internal,
            },
        };
        // The session is unusable after an I/O or protocol error (no server
        // error), a closed connection, or a server error of severity FATAL
        // or PANIC (authentication, idle-in-transaction timeout, shutdown).
        // Any other server error only aborts the transaction, including a
        // class 08 error reported for another connection (an FDW).
        let fatal = e.is_closed()
            || stage == Stage::Connect
            || e.as_db_error().is_none_or(|db| {
                matches!(
                    db.parsed_severity(),
                    Some(
                        tokio_postgres::error::Severity::Fatal
                            | tokio_postgres::error::Severity::Panic
                    )
                )
            });
        Self {
            code,
            sqlstate: sqlstate.map(str::to_owned),
            stage,
            fatal,
        }
    }

    pub(crate) fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }

    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Postgres,
            code: self.code,
            engine_code: self.sqlstate,
        }
    }
}

/// A SQLSTATE is exactly five characters `[0-9A-Z]` (also the contract
/// `EngineCode` pattern).
fn is_sqlstate(s: &str) -> bool {
    s.len() == 5
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

fn failure_of(sqlstate: &str) -> FailureCode {
    match sqlstate {
        // insufficient_privilege
        "42501" => FailureCode::PermissionDenied,
        // query_canceled (statement_timeout, cancel request),
        // lock_not_available (lock_timeout),
        // idle_in_transaction_session_timeout
        "57014" | "55P03" | "25P03" => FailureCode::Timeout,
        // too_many_connections (role CONNECTION LIMIT, max_connections)
        "53300" => FailureCode::ResourceLimit,
        // invalid_catalog_name (database does not exist)
        "3D000" => FailureCode::TargetUnreachable,
        s if s.starts_with("28") => FailureCode::AuthenticationFailed,
        s if s.starts_with("08") || s.starts_with("57P") => FailureCode::TargetUnreachable,
        s if s.starts_with("53") => FailureCode::ResourceLimit,
        _ => FailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlstates_map_to_closed_codes() {
        assert_eq!(failure_of("42501"), FailureCode::PermissionDenied);
        assert_eq!(failure_of("57014"), FailureCode::Timeout);
        assert_eq!(failure_of("55P03"), FailureCode::Timeout);
        assert_eq!(failure_of("28P01"), FailureCode::AuthenticationFailed);
        assert_eq!(failure_of("28000"), FailureCode::AuthenticationFailed);
        assert_eq!(failure_of("08006"), FailureCode::TargetUnreachable);
        assert_eq!(failure_of("53300"), FailureCode::ResourceLimit);
        assert_eq!(failure_of("42P01"), FailureCode::Internal);
    }

    #[test]
    fn only_well_formed_sqlstates_are_kept() {
        assert!(is_sqlstate("42P01"));
        assert!(!is_sqlstate("42p01"));
        assert!(!is_sqlstate("4201"));
        assert!(!is_sqlstate("42501 x"));
    }

    #[test]
    fn connector_error_carries_code_and_sqlstate_only() {
        let e = PgError {
            code: FailureCode::PermissionDenied,
            sqlstate: Some("42501".to_owned()),
            stage: Stage::Sample,
            fatal: false,
        };
        let text = e.into_connector_error().to_string();
        assert!(text.contains("permission_denied"), "{text}");
        assert!(text.contains("42501"), "{text}");
    }
}
