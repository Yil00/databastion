//! Firebird wire encryption (ADR-0060 decisions 1 and 3): `ChaCha64`
//! (ChaCha20 with an 8-byte nonce and a 64-bit counter, `ChaCha20Legacy`)
//! or `ChaCha` (ChaCha20 with a 12-byte nonce and a 32-bit counter),
//! keyed with `SHA-256(K)` where `K` is the SRP session key, with the
//! nonce the server sent in its plugin-specific key data (measured on
//! 5.0.4: 8 bytes for `ChaCha64`; 16 for `ChaCha`, the 12-byte nonce then
//! a big-endian 32-bit initial counter), as the server specifies them.
//!
//! **No integrity and no server authentication** (Context of the ADR):
//! this cipher hides the session from a passive observer only, which is
//! why the connector runs on loopback only. The keystream is applied
//! through `try_apply_keystream` only: the end of the `ChaCha` keystream
//! (256 GiB, 32-bit counter) closes the connection instead of panicking or
//! wrapping.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, ChaCha20Legacy};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::wire::CryptPlugin;

/// One direction of an encrypted session.
pub(crate) enum Cipher {
    ChaCha64(Box<ChaCha20Legacy>),
    ChaCha(Box<ChaCha20>),
}

/// The keystream ended (or a key could not be built): the connection is
/// closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeystreamEnd;

impl Cipher {
    /// The cipher of `plugin` for the SRP session key `session_key` and
    /// the server's plugin-specific data `specific`; `None` when the data
    /// does not fit the plugin.
    pub(crate) fn new(plugin: CryptPlugin, session_key: &[u8], specific: &[u8]) -> Option<Self> {
        if session_key.len() < 16 {
            return None;
        }
        let key = Zeroizing::new(Sha256::digest(session_key).to_vec());
        match plugin {
            CryptPlugin::ChaCha64 => {
                if specific.len() != 8 {
                    return None;
                }
                ChaCha20Legacy::new_from_slices(&key, specific)
                    .ok()
                    .map(|c| Self::ChaCha64(Box::new(c)))
            }
            CryptPlugin::ChaCha => {
                let (nonce, counter) = match specific.len() {
                    12 => (specific, 0u32),
                    16 => (
                        &specific[..12],
                        u32::from_be_bytes([
                            specific[12],
                            specific[13],
                            specific[14],
                            specific[15],
                        ]),
                    ),
                    _ => return None,
                };
                let mut c = ChaCha20::new_from_slices(&key, nonce).ok()?;
                c.try_seek(u64::from(counter) * 64).ok()?;
                Some(Self::ChaCha(Box::new(c)))
            }
        }
    }

    /// Encrypts or decrypts `buf` in place.
    pub(crate) fn apply(&mut self, buf: &mut [u8]) -> Result<(), KeystreamEnd> {
        match self {
            Self::ChaCha64(c) => c.try_apply_keystream(buf),
            Self::ChaCha(c) => c.try_apply_keystream(buf),
        }
        .map_err(|_| KeystreamEnd)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_cipher_round_trips_with_the_specified_nonce() {
        let key = [7u8; 20];
        for (plugin, nonce) in [
            (CryptPlugin::ChaCha64, &[1u8; 8][..]),
            (CryptPlugin::ChaCha, &[2u8; 12][..]),
            (CryptPlugin::ChaCha, &[3u8; 16][..]),
        ] {
            let mut tx = Cipher::new(plugin, &key, nonce).unwrap();
            let mut rx = Cipher::new(plugin, &key, nonce).unwrap();
            let mut buf = b"op_response".to_vec();
            tx.apply(&mut buf).unwrap();
            assert_ne!(buf, b"op_response");
            rx.apply(&mut buf).unwrap();
            assert_eq!(buf, b"op_response");
        }
        // Wrong nonce lengths and short keys are refused.
        assert!(Cipher::new(CryptPlugin::ChaCha64, &key, &[0; 12]).is_none());
        assert!(Cipher::new(CryptPlugin::ChaCha, &key, &[0; 8]).is_none());
        assert!(Cipher::new(CryptPlugin::ChaCha, &[0; 8], &[0; 12]).is_none());
    }

    /// The ChaCha64 keystream for an all-zero 20-byte key and nonce,
    /// computed independently (a pure-Python ChaCha20 with an 8-byte
    /// nonce and a 64-bit counter, the layout the 5.0.4 server accepted).
    #[test]
    fn chacha64_known_answer() {
        let mut c = Cipher::new(CryptPlugin::ChaCha64, &[0u8; 20], &[0u8; 8]).unwrap();
        let mut buf = [0u8; 8];
        c.apply(&mut buf).unwrap();
        assert_eq!(buf, KNOWN_CHACHA64);
    }

    const KNOWN_CHACHA64: [u8; 8] = [221, 170, 82, 32, 15, 22, 150, 94];

    /// The `ChaCha` keystream ends at its 32-bit counter: an error, never
    /// a wrap.
    #[test]
    fn the_chacha_keystream_end_is_an_error() {
        let mut nonce = [0u8; 16];
        nonce[12..].copy_from_slice(&(u32::MAX - 1).to_be_bytes());
        let mut c = Cipher::new(CryptPlugin::ChaCha, &[1u8; 20], &nonce).unwrap();
        let mut block = [0u8; 64];
        assert!(c.apply(&mut block).is_ok());
        // Within the last block or two, the keystream ends: an error.
        let ended = (0..2).any(|_| c.apply(&mut block) == Err(KeystreamEnd));
        assert!(ended);
        assert_eq!(c.apply(&mut [0u8; 1]), Err(KeystreamEnd));
    }
}
