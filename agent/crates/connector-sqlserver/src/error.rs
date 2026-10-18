//! Errors reduced to a closed failure code, the server's error number as
//! `EngineCode` and a closed stage (ADR-0051 decision 1: no server text is
//! ever kept; message, server and procedure names are dropped at parse).

use databastion_core::{ConnectorError, Engine, FailureCode};

/// What the connector was doing. The names are the `stage_*` note labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    Auth,
    SessionSetup,
    Introspection,
    Columns,
    Sample,
    Check,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Tls => "tls",
            Self::Connect => "connect",
            Self::Auth => "auth",
            Self::SessionSetup => "session_setup",
            Self::Introspection => "introspection",
            Self::Columns => "columns",
            Self::Sample => "sample",
            Self::Check => "check",
        }
    }
}

/// Local details (agent logs only, never sent): closed texts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detail {
    /// SQL Server's fallback self-signed certificate (decision 2, M9).
    FallbackCertificate,
    /// `tls: strict` against a server that does not speak TDS 8.0.
    StrictUnavailable,
    /// The TLS handshake failed before any TDS byte (I/O, alert, protocol):
    /// the only failure after which `auto` falls back to `mandatory`.
    HandshakeFailed,
    /// The server certificate did not verify (never a reason to fall back).
    CertificateRejected,
    /// The server answered `ENCRYPT_OFF` / `ENCRYPT_NOT_SUP`.
    EncryptionRefused,
    /// Error 18486 (decision 2, L7).
    LoginLockedOut,
    /// A routing `ENVCHANGE` (I5).
    Routing,
    /// A transaction `ENVCHANGE`.
    Transaction,
    /// A version below 2019, or an edition outside 2, 3, 4.
    UnsupportedServer,
    /// A response outside the closed token or type sets, or a bound.
    Protocol,
}

impl Detail {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::FallbackCertificate => {
                "the server presents SQL Server's fallback self-signed certificate \
                 (SSL_Self_Signed_Fallback, no subject alternative name, new at each start): \
                 install a certificate issued by a trusted CA that names the declared host"
            }
            Self::StrictUnavailable => "strict encryption not available on this server",
            Self::HandshakeFailed => "the TLS handshake failed",
            Self::CertificateRejected => {
                "the server certificate did not verify against the trusted roots and the declared host"
            }
            Self::EncryptionRefused => {
                "the server does not encrypt the whole session (ENCRYPT_OFF or ENCRYPT_NOT_SUP)"
            }
            Self::LoginLockedOut => "login locked out",
            Self::Routing => "the server redirected the connection (routing is never followed)",
            Self::Transaction => "the server reported a transaction; the connector never opens one",
            Self::UnsupportedServer => {
                "unsupported server: SQL Server 2019 or later, Standard, Enterprise, Developer \
                 or Express only (Azure refused)"
            }
            Self::Protocol => "unexpected response from the server",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SsError {
    pub(crate) code: FailureCode,
    /// The server's error number, if the server reported one.
    pub(crate) number: Option<i32>,
    pub(crate) stage: Stage,
    /// The connection is unusable.
    pub(crate) fatal: bool,
    pub(crate) detail: Option<Detail>,
}

impl SsError {
    /// A local, transport or protocol failure: the connection is unusable.
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code: at_stage(code, stage),
            number: None,
            stage,
            fatal: true,
            detail: None,
        }
    }

    pub(crate) fn with_detail(mut self, detail: Detail) -> Self {
        self.detail = Some(detail);
        self
    }

    /// A protocol violation: unusable connection.
    pub(crate) fn protocol(stage: Stage) -> Self {
        Self::new(FailureCode::Unsupported, stage).with_detail(Detail::Protocol)
    }

    /// An `ERROR` token (class 11 and above). Class 20 and above closes the
    /// connection on the server side.
    pub(crate) fn server(number: i32, class: u8, stage: Stage) -> Self {
        let code = at_stage(failure_of(number), stage);
        Self {
            code,
            number: Some(number),
            stage,
            fatal: class >= 20 || matches!(stage, Stage::Auth | Stage::Connect | Stage::Tls),
            detail: (number == 18486).then_some(Detail::LoginLockedOut),
        }
    }

    /// An I/O failure.
    pub(crate) fn io(e: &std::io::Error, stage: Stage) -> Self {
        Self::new(
            if e.kind() == std::io::ErrorKind::TimedOut {
                FailureCode::Timeout
            } else {
                FailureCode::TargetUnreachable
            },
            stage,
        )
    }

    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Sqlserver,
            code: self.code,
            engine_code: self.number.map(|n| n.to_string()),
        }
    }
}

/// Server error number to closed failure code.
pub(crate) fn failure_of(number: i32) -> FailureCode {
    match number {
        // Login failed; login locked out; password expired / must change.
        18456 | 18486 | 18487 | 18488 | 18470 => FailureCode::AuthenticationFailed,
        // Permission denied on an object, a column, a server state, a
        // database (4060: cannot open database).
        229 | 230 | 262 | 297 | 300 | 916 | 4060 => FailureCode::PermissionDenied,
        // Lock request time out; deadlock victim; data movement.
        1222 | 1205 | 601 | 605 => FailureCode::Timeout,
        // Invalid object or column name.
        207 | 208 => FailureCode::UnknownTarget,
        _ => FailureCode::Internal,
    }
}

/// The code of a failure at `stage`: at the TLS stage, the same mapping on
/// every engine ([`databastion_core::connector::tls_stage_failure`]).
fn at_stage(code: FailureCode, stage: Stage) -> FailureCode {
    if stage == Stage::Tls {
        databastion_core::connector::tls_stage_failure(code)
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_map_to_closed_codes() {
        assert_eq!(failure_of(18456), FailureCode::AuthenticationFailed);
        let locked = SsError::server(18486, 14, Stage::Auth);
        assert_eq!(locked.detail, Some(Detail::LoginLockedOut));
        assert!(locked.fatal);
        assert_eq!(failure_of(229), FailureCode::PermissionDenied);
        assert!(!SsError::server(229, 14, Stage::Sample).fatal);
        assert!(SsError::server(1, 20, Stage::Sample).fatal);
        let text = SsError::server(1222, 16, Stage::Sample)
            .into_connector_error()
            .to_string();
        assert!(text.contains("1222"), "{text}");
    }
}
