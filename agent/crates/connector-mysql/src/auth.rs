//! Authentication plugins and the transport policy (security review
//! requirements of P2-C).
//!
//! Accepted exchanges, by transport:
//!
//! | Plugin | TLS (`verify_full`) | Unix socket | loopback, no TLS (`disable`) | network, no TLS (`disable_insecure`) |
//! |---|---|---|---|---|
//! | `caching_sha2_password`, fast path (scramble) | yes | yes | yes | yes |
//! | `caching_sha2_password`, full authentication (password sent) | yes | yes | **refused** | **refused** |
//! | `mysql_native_password` (SHA-1 scramble) | yes | yes | yes | **refused** |
//! | anything else (`mysql_clear_password`, `dialog`, `sha256_password`, `client_ed25519`, GSSAPI, old password…) | **refused** | **refused** | **refused** | **refused** |
//!
//! - The RSA public-key exchange of `caching_sha2_password` /
//!   `sha256_password` is never used: the agent never asks for the
//!   server's key (an attacker on the path would answer with its own and
//!   decrypt the password), and never sends the password on a TCP
//!   connection without TLS.
//! - `mysql_native_password` over a network without TLS is refused like
//!   MD5 on PostgreSQL: an observer gets a SHA-1 challenge-response that is
//!   cheap to attack offline.
//! - A refusal ends the connection before any password-derived byte is
//!   sent for the refused exchange.

use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How the connection reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    /// TLS, certificate and host name verified.
    Tls,
    /// Unix socket (local, no TLS).
    Unix,
    /// TCP to a loopback IP literal without TLS (`tls: disable`).
    LoopbackPlain,
    /// TCP on a network without TLS (`tls: disable_insecure`).
    NetworkPlain,
}

impl Channel {
    /// Whether the password itself may be sent (cleartext full
    /// authentication of `caching_sha2_password`).
    pub(crate) fn may_send_password(self) -> bool {
        matches!(self, Self::Tls | Self::Unix)
    }
}

pub(crate) const CACHING_SHA2: &[u8] = b"caching_sha2_password";
pub(crate) const NATIVE: &[u8] = b"mysql_native_password";

/// Why an authentication exchange was refused. Closed set, logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A plugin the agent never uses (cleartext, PAM dialog, RSA-only,
    /// unsupported).
    Plugin(KnownPlugin),
    /// `mysql_native_password` on a network connection without TLS.
    NativeWithoutTls,
    /// `caching_sha2_password` full authentication without TLS or a Unix
    /// socket (the RSA key exchange is never used).
    FullAuthWithoutTls,
    /// Malformed or unexpected exchange.
    Protocol,
}

impl Refusal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Plugin(p) => p.as_str(),
            Self::NativeWithoutTls => {
                "mysql_native_password on a network connection without TLS (SHA-1 \
                 challenge-response exposed to the path)"
            }
            Self::FullAuthWithoutTls => {
                "caching_sha2_password full authentication without TLS or a Unix socket (the \
                 password would be sent, and RSA public-key retrieval is never used): connect \
                 once over TLS, or use a Unix socket"
            }
            Self::Protocol => "malformed authentication exchange",
        }
    }
}

/// Plugin names that may be logged (server constants); any other name is
/// reported as `Other` (a malicious server could send arbitrary text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownPlugin {
    ClearPassword,
    Dialog,
    Sha256Password,
    Ed25519,
    Gssapi,
    OldPassword,
    Other,
}

impl KnownPlugin {
    fn of(name: &[u8]) -> Self {
        match name {
            b"mysql_clear_password" => Self::ClearPassword,
            b"dialog" => Self::Dialog,
            b"sha256_password" => Self::Sha256Password,
            b"client_ed25519" => Self::Ed25519,
            b"auth_gssapi_client" | b"authentication_kerberos_client" => Self::Gssapi,
            b"mysql_old_password" | b"" => Self::OldPassword,
            _ => Self::Other,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ClearPassword => "mysql_clear_password (cleartext password) is never used",
            Self::Dialog => "dialog (PAM, cleartext password) is never used",
            Self::Sha256Password => "sha256_password (RSA or cleartext) is not supported",
            Self::Ed25519 => "client_ed25519 is not supported",
            Self::Gssapi => "GSSAPI / Kerberos authentication is not supported",
            Self::OldPassword => "pre-4.1 password authentication is never used",
            Self::Other => "unsupported authentication plugin",
        }
    }
}

/// First answer of a plugin to a nonce, or a refusal.
pub(crate) fn answer(
    plugin: &[u8],
    nonce: &[u8],
    password: &[u8],
    channel: Channel,
) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    match plugin {
        CACHING_SHA2 | NATIVE if nonce.len() != 20 => Err(Refusal::Protocol),
        CACHING_SHA2 => Ok(caching_sha2_scramble(password, nonce)),
        NATIVE if channel == Channel::NetworkPlain => Err(Refusal::NativeWithoutTls),
        NATIVE => Ok(native_scramble(password, nonce)),
        other => Err(Refusal::Plugin(KnownPlugin::of(other))),
    }
}

/// The plugin announced in the handshake response: the server's default
/// when the agent may use it on this channel, else
/// `caching_sha2_password` (the server then switches to the account's
/// plugin, which is checked again).
pub(crate) fn initial_plugin(server_default: &[u8], channel: Channel) -> &'static [u8] {
    match server_default {
        NATIVE if channel != Channel::NetworkPlain => NATIVE,
        _ => CACHING_SHA2,
    }
}

/// `SHA1(password) XOR SHA1(nonce || SHA1(SHA1(password)))`.
pub(crate) fn native_scramble(password: &[u8], nonce: &[u8]) -> Zeroizing<Vec<u8>> {
    let stage1 = Zeroizing::new(Sha1::digest(password).to_vec());
    let stage2 = Sha1::digest(&stage1[..]);
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(stage2);
    let mix = h.finalize();
    Zeroizing::new(stage1.iter().zip(mix.iter()).map(|(a, b)| a ^ b).collect())
}

/// `SHA256(password) XOR SHA256(SHA256(SHA256(password)) || nonce)`.
pub(crate) fn caching_sha2_scramble(password: &[u8], nonce: &[u8]) -> Zeroizing<Vec<u8>> {
    let stage1 = Zeroizing::new(Sha256::digest(password).to_vec());
    let stage2 = Sha256::digest(&stage1[..]);
    let mut h = Sha256::new();
    h.update(stage2);
    h.update(nonce);
    let mix = h.finalize();
    Zeroizing::new(stage1.iter().zip(mix.iter()).map(|(a, b)| a ^ b).collect())
}

/// `caching_sha2_password` "more data" statuses.
pub(crate) const FAST_AUTH_OK: u8 = 3;
pub(crate) const PERFORM_FULL_AUTH: u8 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const NONCE: &[u8] = b"abcdefghijklmnopqrst";

    #[test]
    fn scrambles_match_reference_vectors() {
        // Computed with Python's hashlib from the protocol definitions.
        assert_eq!(
            hex(&native_scramble(b"secret-FAKE", NONCE)),
            "5b73cdf1982a776a3c4ad5b40c50f0bfd417b333"
        );
        assert_eq!(
            hex(&caching_sha2_scramble(b"secret-FAKE", NONCE)),
            "9bd456aeefeec1447ad918a607b6c5a0bad01843cffbbf644ac96631f32230f0"
        );
    }

    #[test]
    fn transport_policy() {
        for channel in [
            Channel::Tls,
            Channel::Unix,
            Channel::LoopbackPlain,
            Channel::NetworkPlain,
        ] {
            assert!(answer(CACHING_SHA2, NONCE, b"pw", channel).is_ok());
            for plugin in [
                &b"mysql_clear_password"[..],
                b"dialog",
                b"sha256_password",
                b"client_ed25519",
                b"auth_gssapi_client",
                b"mysql_old_password",
                b"",
                b"x' OR 1",
            ] {
                assert!(
                    matches!(
                        answer(plugin, NONCE, b"pw", channel),
                        Err(Refusal::Plugin(_))
                    ),
                    "{plugin:?} {channel:?}"
                );
            }
        }
        assert_eq!(
            answer(NATIVE, NONCE, b"pw", Channel::NetworkPlain).unwrap_err(),
            Refusal::NativeWithoutTls
        );
        assert!(answer(NATIVE, NONCE, b"pw", Channel::LoopbackPlain).is_ok());
        assert!(answer(NATIVE, NONCE, b"pw", Channel::Tls).is_ok());
        assert_eq!(
            answer(NATIVE, b"short", b"pw", Channel::Tls).unwrap_err(),
            Refusal::Protocol
        );
        // A refused plugin is named whatever its data (PAM `dialog` sends a
        // prompt, not a nonce).
        assert_eq!(
            answer(b"dialog", b"\x04Password: ", b"pw", Channel::Tls).unwrap_err(),
            Refusal::Plugin(KnownPlugin::Dialog)
        );
        assert!(Channel::Tls.may_send_password() && Channel::Unix.may_send_password());
        assert!(!Channel::LoopbackPlain.may_send_password());
        assert!(!Channel::NetworkPlain.may_send_password());
        assert_eq!(initial_plugin(NATIVE, Channel::NetworkPlain), CACHING_SHA2);
        assert_eq!(initial_plugin(NATIVE, Channel::Tls), NATIVE);
        assert_eq!(initial_plugin(b"dialog", Channel::Tls), CACHING_SHA2);
    }

    #[test]
    fn unknown_plugin_names_are_never_echoed() {
        let r = answer(b"evil-SECRET-name", NONCE, b"pw", Channel::Tls).unwrap_err();
        assert!(!format!("{r:?} {}", r.as_str()).contains("SECRET"));
    }
}
