//! Errors reduced to a closed failure code, the server's GDS code as
//! `EngineCode` and a closed stage (ADR-0060 decision 1): status-vector
//! strings are skipped while parsing, never kept, logged or sent
//! (conversion errors quote values: an I2 rule).

use databastion_core::{ConnectorError, Engine, FailureCode};

/// What the connector was doing. The names are the `stage_*` note labels;
/// the wire-encryption negotiation is the contract's TLS stage
/// (`stage_tls`, decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Secret,
    Connect,
    Tls,
    Auth,
    SessionSetup,
    Check,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::SessionSetup => "session_setup",
            Self::Check => "check",
        }
    }
}

/// Local details (agent logs only, never sent): closed texts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detail {
    /// No server-side socket of this connection in `/proc/net/tcp{,6}`.
    PeerNotFound,
    /// More than one server-side socket matched the 4-tuple.
    PeerAmbiguous,
    /// The server-side socket is owned by another uid than `peer_uid`.
    PeerUidMismatch,
    /// The server-side socket shows the overflow uid (outside the agent's
    /// user namespace).
    PeerOverflowUid,
    /// The peer check needs Linux `/proc/net/tcp`.
    PeerPlatform,
    /// The server saw the connection come from another address or port:
    /// a forwarder (decision 3, security review M2).
    Forwarder,
    /// The server did not accept protocol 16 exactly (or rejected it).
    ProtocolVersion,
    /// The server asked for another authentication plugin than `Srp256`.
    AuthPlugin,
    /// The server reported the client authenticated before the proof.
    AuthenticatedEarly,
    /// The server's SRP data failed a check (salt, `B`, `u = 0`).
    SrpData,
    /// The server offers neither `ChaCha64` nor `ChaCha` (Arc4 refused).
    NoChacha,
    /// The answer to `op_crypt` was not the expected encrypted response:
    /// the server does not know the verifier, or the path altered it.
    KeyConfirmation,
    /// `WIRE_ENCRYPTED` / `WIRE_CRYPT_PLUGIN` do not show the negotiated
    /// cipher.
    WireCryptNotVerified,
    /// The read-only read-committed transaction is not what the server
    /// reports.
    TransactionNotVerified,
    /// A Firebird major version other than 4 or 5 (3.0 and 6.0 refused).
    UnsupportedVersion,
    /// The server asked the client for a database encryption key
    /// (`op_crypt_key_callback`): the agent has none and sends none.
    CryptKeyCallback,
    /// The declared host is not a loopback IP literal (checked at load).
    NotLoopback,
    /// A response outside the closed operation or type sets, or a bound.
    Protocol,
    /// The keystream of the cipher reached its end.
    KeystreamEnd,
}

impl Detail {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PeerNotFound => {
                "no server-side socket of this connection was found in /proc/net/tcp{,6}: the \
                 listener is not visible from the agent's network namespace"
            }
            Self::PeerAmbiguous => "two server-side sockets matched this connection",
            Self::PeerUidMismatch => {
                "the server side of the connection is owned by another account than \
                 firebird.peer_uid: another process may listen on the port"
            }
            Self::PeerOverflowUid => {
                "the server side of the connection shows the overflow uid (65534): the server \
                 runs outside the agent's user namespace"
            }
            Self::PeerPlatform => "the peer check needs Linux /proc/net/tcp",
            Self::Forwarder => {
                "the server saw the connection come from another address or port: a forwarder \
                 is in the path (declare an operator-run tunnel with firebird.tunnel: true)"
            }
            Self::ProtocolVersion => {
                "the server does not accept the Firebird remote protocol 16 (Firebird 4.0 or \
                 5.0 needed; 3.0 is refused)"
            }
            Self::AuthPlugin => {
                "the server asked for an authentication plugin other than Srp256 (AuthServer \
                 must list Srp256)"
            }
            Self::AuthenticatedEarly => {
                "the server reported the client authenticated before the SRP proof was sent"
            }
            Self::SrpData => "the server's SRP data failed a check",
            Self::NoChacha => {
                "the server offers neither ChaCha64 nor ChaCha wire encryption (Arc4 and no \
                 encryption are refused): set WireCryptPlugin and WireCrypt = Required"
            }
            Self::KeyConfirmation => {
                "the encrypted answer to op_crypt was not the expected response: the server \
                 does not know the account's verifier, or the path altered the traffic"
            }
            Self::WireCryptNotVerified => {
                "the server does not report the negotiated wire encryption for the attachment"
            }
            Self::TransactionNotVerified => {
                "the server does not report the read-only read-committed transaction"
            }
            Self::UnsupportedVersion => "unsupported server: Firebird 4.0 or 5.0 only",
            Self::CryptKeyCallback => {
                "the server asked the client for a database encryption key (never sent)"
            }
            Self::NotLoopback => "the declared host is not a loopback IP literal",
            Self::Protocol => "unexpected response from the server",
            Self::KeystreamEnd => "the wire-encryption keystream reached its end",
        }
    }
}

/// A connector error. No text from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FbError {
    pub(crate) code: FailureCode,
    /// The first GDS code of the server's status vector, if any.
    pub(crate) gds: Option<u32>,
    pub(crate) stage: Stage,
    /// `false` only for a server error after which the attachment stays
    /// usable (a statement refused, a permission denied); `true` for every
    /// client-side, transport and protocol failure.
    pub(crate) fatal: bool,
    pub(crate) detail: Option<Detail>,
}

impl FbError {
    /// A local, transport or protocol failure: the connection is unusable.
    pub(crate) fn new(code: FailureCode, stage: Stage) -> Self {
        Self {
            code: at_stage(code, stage),
            gds: None,
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

    /// A failed status vector from the server (`gds`: its codes in order).
    pub(crate) fn server(gds: &[u32], stage: Stage) -> Self {
        let code = at_stage(failure_of(gds), stage);
        Self {
            code,
            gds: gds.first().copied(),
            stage,
            // Before the attachment exists, every failure ends the
            // connection; after it, a statement error leaves it usable.
            fatal: matches!(
                stage,
                Stage::Connect | Stage::Tls | Stage::Auth | Stage::Secret
            ) || gds.iter().any(|c| FATAL_GDS.contains(c)),
            detail: None,
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

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "Discovery (lot 2) and Audit (lot 3)")
    )]
    pub(crate) fn into_connector_error(self) -> ConnectorError {
        ConnectorError::Target {
            engine: Engine::Firebird,
            code: self.code,
            engine_code: self.gds.map(|n| n.to_string()),
        }
    }
}

/// GDS codes of the closed table (ADR-0060 decision 1, security review L8).
pub(crate) mod gds {
    pub(crate) const ARITH_EXCEPT: u32 = 335_544_321;
    pub(crate) const BAD_DB_FORMAT: u32 = 335_544_323;
    pub(crate) const DEADLOCK: u32 = 335_544_336;
    pub(crate) const IO_ERROR: u32 = 335_544_344;
    pub(crate) const LOCK_CONFLICT: u32 = 335_544_345;
    pub(crate) const NO_PRIV: u32 = 335_544_352;
    pub(crate) const UNAVAILABLE: u32 = 335_544_375;
    pub(crate) const CONNECT_REJECT: u32 = 335_544_421;
    pub(crate) const UPDATE_CONFLICT: u32 = 335_544_451;
    pub(crate) const LOGIN: u32 = 335_544_472;
    /// `isc_login_error`: the server found no usable authentication plugin
    /// (for example `Srp256` enabled only for another database).
    pub(crate) const LOGIN_ERROR: u32 = 335_545_106;
    pub(crate) const SHUTDOWN: u32 = 335_544_528;
    pub(crate) const TRANSLITERATION_FAILED: u32 = 335_544_565;
    pub(crate) const DSQL_FIELD_ERR: u32 = 335_544_578;
    pub(crate) const DSQL_RELATION_ERR: u32 = 335_544_580;
    pub(crate) const NETWORK_ERROR: u32 = 335_544_721;
    pub(crate) const NET_READ_ERR: u32 = 335_544_726;
    pub(crate) const NET_WRITE_ERR: u32 = 335_544_727;
    pub(crate) const CANCELLED: u32 = 335_544_794;
    pub(crate) const MALFORMED_STRING: u32 = 335_544_849;
    pub(crate) const ATT_SHUTDOWN: u32 = 335_544_856;
    pub(crate) const STRING_TRUNCATION: u32 = 335_544_914;
    pub(crate) const WIRECRYPT_INCOMPATIBLE: u32 = 335_545_064;
    pub(crate) const MISS_WIRECRYPT: u32 = 335_545_065;
    pub(crate) const WIRECRYPT_KEY: u32 = 335_545_066;
    pub(crate) const WIRECRYPT_PLUGIN: u32 = 335_545_067;
    pub(crate) const CFG_STMT_TIMEOUT: u32 = 335_545_127;
    pub(crate) const ATT_STMT_TIMEOUT: u32 = 335_545_128;
    pub(crate) const REQ_STMT_TIMEOUT: u32 = 335_545_129;
}

/// Codes after which the server has ended the attachment.
const FATAL_GDS: &[u32] = &[
    gds::SHUTDOWN,
    gds::ATT_SHUTDOWN,
    gds::NETWORK_ERROR,
    gds::NET_READ_ERR,
    gds::NET_WRITE_ERR,
];

/// The one closed table from a status vector's GDS codes to a failure
/// code: the first code of the vector found in the table decides (Firebird
/// puts a generic code such as `isc_dsql_error` before the specific one);
/// none: `internal`.
pub(crate) fn failure_of(codes: &[u32]) -> FailureCode {
    codes
        .iter()
        .find_map(|c| table(*c))
        .unwrap_or(FailureCode::Internal)
}

fn table(code: u32) -> Option<FailureCode> {
    use FailureCode as F;
    Some(match code {
        gds::LOGIN | gds::LOGIN_ERROR => F::AuthenticationFailed,
        gds::NO_PRIV => F::PermissionDenied,
        gds::CANCELLED => F::Cancelled,
        gds::CFG_STMT_TIMEOUT | gds::ATT_STMT_TIMEOUT | gds::REQ_STMT_TIMEOUT => F::Timeout,
        // `nowait`: a conflict is not waited for.
        gds::LOCK_CONFLICT | gds::DEADLOCK | gds::UPDATE_CONFLICT => F::Timeout,
        gds::IO_ERROR | gds::BAD_DB_FORMAT | gds::DSQL_RELATION_ERR | gds::DSQL_FIELD_ERR => {
            F::UnknownTarget
        }
        gds::WIRECRYPT_INCOMPATIBLE
        | gds::MISS_WIRECRYPT
        | gds::WIRECRYPT_KEY
        | gds::WIRECRYPT_PLUGIN
        | gds::NETWORK_ERROR
        | gds::NET_READ_ERR
        | gds::NET_WRITE_ERR
        | gds::UNAVAILABLE
        | gds::SHUTDOWN
        | gds::ATT_SHUTDOWN => F::TargetUnreachable,
        gds::CONNECT_REJECT => F::Unsupported,
        gds::TRANSLITERATION_FAILED
        | gds::MALFORMED_STRING
        | gds::STRING_TRUNCATION
        | gds::ARITH_EXCEPT => F::Internal,
        _ => return None,
    })
}

/// The code of a failure at `stage`: at the TLS stage (the wire
/// encryption), the same mapping on every engine
/// ([`databastion_core::connector::tls_stage_failure`]).
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
    fn codes_map_through_the_closed_table() {
        assert_eq!(failure_of(&[gds::LOGIN]), FailureCode::AuthenticationFailed);
        assert_eq!(
            failure_of(&[gds::LOGIN_ERROR]),
            FailureCode::AuthenticationFailed
        );
        // The generic code first, the specific one after it.
        assert_eq!(
            failure_of(&[335_544_569, 335_544_436, gds::DSQL_RELATION_ERR]),
            FailureCode::UnknownTarget
        );
        assert_eq!(
            failure_of(&[gds::NO_PRIV, 335_545_254]),
            FailureCode::PermissionDenied
        );
        assert_eq!(failure_of(&[gds::REQ_STMT_TIMEOUT]), FailureCode::Timeout);
        assert_eq!(failure_of(&[gds::CANCELLED]), FailureCode::Cancelled);
        assert_eq!(failure_of(&[1, 2, 3]), FailureCode::Internal);
        assert_eq!(failure_of(&[]), FailureCode::Internal);
        let e = FbError::server(&[gds::LOGIN], Stage::Auth);
        assert!(e.fatal);
        assert_eq!(e.gds, Some(gds::LOGIN));
        assert!(!FbError::server(&[gds::NO_PRIV], Stage::Check).fatal);
        assert!(FbError::server(&[gds::ATT_SHUTDOWN], Stage::Check).fatal);
        // The TLS stage maps like every engine's.
        assert_eq!(
            FbError::server(&[gds::WIRECRYPT_INCOMPATIBLE], Stage::Tls).code,
            FailureCode::TargetUnreachable
        );
        assert_eq!(
            FbError::new(FailureCode::Unsupported, Stage::Tls).code,
            FailureCode::TargetUnreachable
        );
        let text = FbError::server(&[gds::NO_PRIV], Stage::Check)
            .into_connector_error()
            .to_string();
        assert!(text.contains("335544352"), "{text}");
    }
}
