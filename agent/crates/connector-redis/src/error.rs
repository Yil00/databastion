//! Errors reduced to a closed failure code, the error reply's first word
//! as `EngineCode` and a closed stage (ADR-0052 decision 10). No server
//! text, key, value or path is ever kept.

use databastion_core::{ConnectorError, Engine, FailureCode};

use crate::resp::{DecodeError, ErrorWord};

/// What the connector was doing. The names are the `stage_*` note labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Tls,
    Connect,
    Auth,
    /// `HELLO`, `CLIENT NO-TOUCH`, `READONLY`.
    SessionSetup,
    /// `INFO`, `SCAN`, `TYPE`, `SELECT`.
    Introspection,
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
            Self::Sample => "sample",
            Self::Check => "check",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RdError {
    pub(crate) code: FailureCode,
    pub(crate) word: Option<ErrorWord>,
    pub(crate) stage: Stage,
    /// The connection is unusable.
    pub(crate) fatal: bool,
}

impl RdError {
    /// A local, transport or protocol failure: the connection is unusable.
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code,
            word: None,
            stage,
            fatal: true,
        }
    }

    /// An error reply. Fatal during the handshake.
    pub(crate) fn reply(word: ErrorWord, stage: Stage) -> Self {
        Self {
            code: failure_of(word),
            word: Some(word),
            stage,
            fatal: matches!(stage, Stage::Auth | Stage::SessionSetup | Stage::Connect),
        }
    }

    /// A reply the decoder refused.
    pub(crate) fn decode(e: DecodeError, stage: Stage) -> Self {
        Self::new(
            match e {
                DecodeError::Limit => FailureCode::ResourceLimit,
                DecodeError::Protocol | DecodeError::Push => FailureCode::Unsupported,
            },
            stage,
        )
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
            engine: Engine::Redis,
            code: self.code,
            engine_code: self.word.map(|w| w.as_str().to_owned()),
        }
    }
}

/// Error word to closed failure code (decision 10).
pub(crate) fn failure_of(word: ErrorWord) -> FailureCode {
    match word {
        ErrorWord::Wrongpass | ErrorWord::Noauth => FailureCode::AuthenticationFailed,
        ErrorWord::Noperm => FailureCode::PermissionDenied,
        ErrorWord::Loading
        | ErrorWord::Busy
        | ErrorWord::Masterdown
        | ErrorWord::Clusterdown
        | ErrorWord::Tryagain => FailureCode::TargetUnreachable,
        ErrorWord::Moved | ErrorWord::Ask => FailureCode::UnknownTarget,
        _ => FailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_map_to_closed_codes() {
        assert_eq!(
            failure_of(ErrorWord::Wrongpass),
            FailureCode::AuthenticationFailed
        );
        assert_eq!(failure_of(ErrorWord::Noperm), FailureCode::PermissionDenied);
        assert_eq!(
            failure_of(ErrorWord::Loading),
            FailureCode::TargetUnreachable
        );
        let e = RdError::reply(ErrorWord::Noperm, Stage::Sample);
        assert!(!e.fatal);
        let text = e.into_connector_error().to_string();
        assert!(
            text.contains("permission_denied") && text.contains("NOPERM"),
            "{text}"
        );
        assert!(RdError::reply(ErrorWord::Wrongpass, Stage::Auth).fatal);
        assert_eq!(
            RdError::decode(DecodeError::Limit, Stage::Sample).code,
            FailureCode::ResourceLimit
        );
    }
}
