//! SCRAM-SHA-256 client (RFC 5802, RFC 7677), the only mechanism the
//! connector uses (ADR-0026 decision 3).
//!
//! - The mechanism is fixed by the client: no negotiation, so a server
//!   cannot downgrade the exchange to SCRAM-SHA-1 or `PLAIN`.
//! - The server's nonce must extend the client's, its iteration count must
//!   be between [`MIN_ITERATIONS`] and [`MAX_ITERATIONS`], and its final
//!   signature is verified (mutual authentication) before the caller runs
//!   any other command.
//! - The password is SASLprepped; the salted password, the keys, the HMAC
//!   states and outputs (the `hmac` / `sha2` `zeroize` features), the proof
//!   and its base64 text are zeroized on drop. No message of the exchange
//!   is logged.
//! - No channel binding (`c=biws`): MongoDB offers no `-PLUS` mechanism.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Mechanism name sent in `saslStart`.
pub(crate) const MECHANISM: &str = "SCRAM-SHA-256";
/// Lowest iteration count accepted (RFC 7677, and what an attacker on the
/// path could otherwise lower to make a captured proof cheap to attack).
pub(crate) const MIN_ITERATIONS: u32 = 4096;
/// Highest iteration count accepted: bounds the work a hostile server can
/// ask for. MongoDB's default (`scramSHA256IterationCount`) is 15000; a
/// server configured above this bound is refused.
pub(crate) const MAX_ITERATIONS: u32 = 100_000;
/// Longest server message accepted.
const MAX_MESSAGE: usize = 4096;

/// Why an exchange failed. No content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScramError {
    #[error("the server message is malformed")]
    Malformed,
    #[error("the server nonce does not extend the client nonce")]
    Nonce,
    #[error("the iteration count is out of the accepted range")]
    Iterations,
    #[error("the password is refused by SASLprep")]
    Password,
    #[error("the server reported an authentication error")]
    ServerError,
    #[error("the server signature does not verify")]
    Signature,
}

/// `saslname` of RFC 5802: `=` and `,` escaped.
fn sasl_name(user: &str) -> String {
    user.replace('=', "=3D").replace(',', "=2C")
}

/// The client side of one exchange.
pub(crate) struct Scram {
    nonce: String,
    first_bare: String,
}

impl std::fmt::Debug for Scram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scram")
    }
}

/// What the client must see in the server's final message.
pub(crate) struct Expected {
    server_signature: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Expected")
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // HMAC accepts keys of any length, so this cannot fail; if it ever
    // did, the all-zero output would only make authentication fail.
    if let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(key) {
        for p in parts {
            mac.update(p);
        }
        // Copied from the output, which zeroizes itself on drop (no
        // `into_bytes` copy left on the stack).
        let tag = mac.finalize();
        out.copy_from_slice(tag.as_bytes());
    }
    out
}

/// PBKDF2-HMAC-SHA-256 with a 32-byte output (`Hi` of RFC 5802).
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // Keyed once; each iteration clones the keyed state instead of
    // re-deriving the pads from the password. HMAC accepts keys of any
    // length (an all-zero output would only fail authentication).
    let Ok(keyed) = <HmacSha256 as KeyInit>::new_from_slice(password) else {
        return out;
    };
    let mut u = Zeroizing::new([0u8; 32]);
    let mut mac = keyed.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    u.copy_from_slice(mac.finalize().as_bytes());
    out.copy_from_slice(&u[..]);
    for _ in 1..iterations {
        let mut mac = keyed.clone();
        mac.update(&u[..]);
        u.copy_from_slice(mac.finalize().as_bytes());
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// SHA-256 of `data`, written straight into a zeroized buffer.
fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut h = Sha256::new();
    h.update(data);
    Digest::finalize_into(h, (&mut *out).into());
    out
}

/// Constant-time equality of two 32-byte values.
fn ct_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The attributes of a server message (`a=value` separated by `,`).
fn attributes(message: &[u8]) -> Result<Vec<(u8, &str)>, ScramError> {
    if message.is_empty() || message.len() > MAX_MESSAGE {
        return Err(ScramError::Malformed);
    }
    let text = std::str::from_utf8(message).map_err(|_| ScramError::Malformed)?;
    text.split(',')
        .map(|part| {
            let b = part.as_bytes();
            if b.len() < 2 || b[1] != b'=' || !b[0].is_ascii_alphabetic() {
                return Err(ScramError::Malformed);
            }
            Ok((b[0], &part[2..]))
        })
        .collect()
}

impl Scram {
    /// Starts an exchange for `user` with a nonce of 24 random bytes:
    /// the exchange and the client-first message.
    pub(crate) fn start(user: &str) -> Result<(Self, Vec<u8>), getrandom::Error> {
        let mut raw = [0u8; 24];
        getrandom::fill(&mut raw)?;
        Ok(Self::with_nonce(user, &B64.encode(raw)))
    }

    /// Same with a given nonce (tests use the RFC vectors).
    pub(crate) fn with_nonce(user: &str, nonce: &str) -> (Self, Vec<u8>) {
        let first_bare = format!("n={},r={nonce}", sasl_name(user));
        let message = format!("n,,{first_bare}").into_bytes();
        (
            Self {
                nonce: nonce.to_owned(),
                first_bare,
            },
            message,
        )
    }

    /// Answers the server-first message: the client-final message and the
    /// server signature to expect.
    pub(crate) fn client_final(
        &self,
        server_first: &[u8],
        password: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, Expected), ScramError> {
        let attrs = attributes(server_first)?;
        // A mandatory extension (`m=`) is not supported.
        let get = |name: u8| attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
        if get(b'm').is_some() {
            return Err(ScramError::Malformed);
        }
        let (Some(nonce), Some(salt), Some(iterations)) = (get(b'r'), get(b's'), get(b'i')) else {
            return Err(ScramError::Malformed);
        };
        if nonce.len() <= self.nonce.len() || !nonce.starts_with(&self.nonce) {
            return Err(ScramError::Nonce);
        }
        if !nonce
            .bytes()
            .all(|b| (0x21..=0x7E).contains(&b) && b != b',')
        {
            return Err(ScramError::Malformed);
        }
        let salt = B64.decode(salt).map_err(|_| ScramError::Malformed)?;
        if salt.is_empty() {
            return Err(ScramError::Malformed);
        }
        let iterations: u32 = iterations.parse().map_err(|_| ScramError::Malformed)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(ScramError::Iterations);
        }
        let prepped = stringprep::saslprep(password).map_err(|_| ScramError::Password)?;
        let prepped = Zeroizing::new(prepped.into_owned());
        let salted = hi(prepped.as_bytes(), &salt, iterations);
        let client_key = hmac(&salted[..], &[b"Client Key"]);
        let stored_key = sha256(&client_key[..]);
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!(
            "{},{},{without_proof}",
            self.first_bare,
            std::str::from_utf8(server_first).map_err(|_| ScramError::Malformed)?
        );
        let client_signature = hmac(&stored_key[..], &[auth_message.as_bytes()]);
        let mut proof = Zeroizing::new([0u8; 32]);
        for ((p, k), s) in proof
            .iter_mut()
            .zip(client_key.iter())
            .zip(client_signature.iter())
        {
            *p = k ^ s;
        }
        let server_key = hmac(&salted[..], &[b"Server Key"]);
        let server_signature = hmac(&server_key[..], &[auth_message.as_bytes()]);
        let proof_text = Zeroizing::new(B64.encode(&proof[..]));
        // Sized once: no reallocation leaves a copy of the proof behind.
        let mut message = Zeroizing::new(Vec::with_capacity(
            without_proof.len() + 3 + proof_text.len(),
        ));
        message.extend_from_slice(without_proof.as_bytes());
        message.extend_from_slice(b",p=");
        message.extend_from_slice(proof_text.as_bytes());
        Ok((message, Expected { server_signature }))
    }
}

impl Expected {
    /// Verifies the server-final message (`v=` signature; `e=` is an
    /// error).
    pub(crate) fn verify(&self, server_final: &[u8]) -> Result<(), ScramError> {
        let attrs = attributes(server_final)?;
        if attrs.iter().any(|(n, _)| *n == b'e') {
            return Err(ScramError::ServerError);
        }
        let v = attrs
            .iter()
            .find(|(n, _)| *n == b'v')
            .ok_or(ScramError::Malformed)?
            .1;
        let signature = B64.decode(v).map_err(|_| ScramError::Signature)?;
        if ct_eq(&self.server_signature, &signature) {
            Ok(())
        } else {
            Err(ScramError::Signature)
        }
    }
}

#[cfg(test)]
pub(crate) mod server {
    //! Server side of the exchange, for the scripted test server only.
    use super::*;

    /// The server's answers for one exchange, from the client's messages.
    pub(crate) struct Server {
        pub(crate) salt: Vec<u8>,
        pub(crate) iterations: u32,
        pub(crate) server_nonce: String,
        pub(crate) password: String,
    }

    impl Server {
        /// The client-first bare part and the server-first message.
        pub(crate) fn first(&self, client_first: &[u8]) -> (String, String) {
            let text = std::str::from_utf8(client_first).unwrap();
            let bare = text.strip_prefix("n,,").unwrap().to_owned();
            let nonce = bare.split(",r=").nth(1).unwrap();
            let first = format!(
                "r={nonce}{},s={},i={}",
                self.server_nonce,
                B64.encode(&self.salt),
                self.iterations
            );
            (bare, first)
        }

        /// Checks the client proof; the server-final message if it holds.
        pub(crate) fn last(&self, bare: &str, first: &str, client_final: &[u8]) -> Option<String> {
            let text = std::str::from_utf8(client_final).ok()?;
            let (without_proof, proof) = text.split_once(",p=")?;
            let auth_message = format!("{bare},{first},{without_proof}");
            let salted = hi(
                stringprep::saslprep(&self.password).ok()?.as_bytes(),
                &self.salt,
                self.iterations,
            );
            let client_key = hmac(&salted[..], &[b"Client Key"]);
            let stored: [u8; 32] = Sha256::digest(&client_key[..]).into();
            let signature = hmac(&stored, &[auth_message.as_bytes()]);
            let proof = B64.decode(proof).ok()?;
            let recovered: Vec<u8> = proof
                .iter()
                .zip(signature.iter())
                .map(|(a, b)| a ^ b)
                .collect();
            let recovered_stored: [u8; 32] = Sha256::digest(&recovered).into();
            if recovered_stored != stored {
                return None;
            }
            let server_key = hmac(&salted[..], &[b"Server Key"]);
            let v = hmac(&server_key[..], &[auth_message.as_bytes()]);
            Some(format!("v={}", B64.encode(&v[..])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HMAC and hash states and the MAC outputs zeroize themselves on
    /// drop (the `zeroize` features of `hmac` and `sha2`, end-of-phase-5
    /// review I4), checked at compile time: `Hmac<Sha256>` holds two
    /// SHA-256 cores (inner and outer pads) and an eager block buffer,
    /// each zeroized on drop; `hmac` 0.13 does not declare the marker on
    /// `Hmac` itself.
    #[test]
    fn hmac_and_hash_states_zeroize_on_drop() {
        use hmac::digest::block_api::EagerHash;
        fn zeroized_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroized_on_drop::<<Sha256 as EagerHash>::Core>();
        zeroized_on_drop::<Sha256>();
        zeroized_on_drop::<hmac::digest::CtOutput<HmacSha256>>();
    }

    /// RFC 7677 section 3 test vector (user `user`, password `pencil`).
    #[test]
    fn rfc_7677_vector() {
        let (scram, first) = Scram::with_nonce("user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let server_first = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (last, expected) = scram.client_final(server_first, "pencil").unwrap();
        assert_eq!(
            std::str::from_utf8(&last).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        expected
            .verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        assert_eq!(
            expected.verify(b"v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
            Err(ScramError::Signature)
        );
        assert_eq!(
            expected.verify(b"e=invalid-proof"),
            Err(ScramError::ServerError)
        );
        assert_eq!(expected.verify(b"x"), Err(ScramError::Malformed));
    }

    #[test]
    fn hostile_server_first_messages_are_refused() {
        let (scram, _) = Scram::with_nonce("user", "abcdef");
        let s = "s=W22ZaJ0SNY7soEsUEjb6gQ==";
        for (msg, err) in [
            // Nonce not extended, or not the client's.
            (format!("r=abcdef,{s},i=4096"), ScramError::Nonce),
            (format!("r=zzzzzzXYZ,{s},i=4096"), ScramError::Nonce),
            // Iteration count too low (a relayed proof cheap to attack) or
            // too high (work forced on the agent).
            (format!("r=abcdefXYZ,{s},i=1"), ScramError::Iterations),
            (format!("r=abcdefXYZ,{s},i=4095"), ScramError::Iterations),
            (format!("r=abcdefXYZ,{s},i=100001"), ScramError::Iterations),
            (format!("r=abcdefXYZ,{s},i=-5"), ScramError::Malformed),
            (
                format!("m=ext,r=abcdefXYZ,{s},i=4096"),
                ScramError::Malformed,
            ),
            ("r=abcdefXYZ,s=,i=4096".to_owned(), ScramError::Malformed),
            ("r=abcdefXYZ,s=!!,i=4096".to_owned(), ScramError::Malformed),
            // Standard alphabet with canonical padding only: an unpadded,
            // URL-safe or over-padded salt is refused.
            (
                "r=abcdefXYZ,s=W22ZaJ0SNY7soEsUEjb6gQ,i=4096".to_owned(),
                ScramError::Malformed,
            ),
            (
                "r=abcdefXYZ,s=W22ZaJ0SNY7soEsUEjb6g-_=,i=4096".to_owned(),
                ScramError::Malformed,
            ),
            (
                "r=abcdefXYZ,s=W22ZaJ0SNY7soEsUEjb6gQ===,i=4096".to_owned(),
                ScramError::Malformed,
            ),
            (format!("r=abcdefXYZ,{s}"), ScramError::Malformed),
            (String::new(), ScramError::Malformed),
        ] {
            assert_eq!(
                scram.client_final(msg.as_bytes(), "pw").map(|_| ()),
                Err(err),
                "{msg}"
            );
        }
    }

    #[test]
    fn names_are_escaped_and_passwords_sasl_prepped() {
        let (_, first) = Scram::with_nonce("a=b,c", "n");
        assert_eq!(first, b"n,,n=a=3Db=2Cc,r=n");
        // SASLprep maps a non-ASCII space to a space: both spellings of
        // the password give the same proof.
        let (scram, _) = Scram::with_nonce("u", "abc");
        let first = b"r=abcdef,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (a, _) = scram.client_final(first, "p w").unwrap();
        let (b, _) = scram.client_final(first, "p\u{00A0}w").unwrap();
        assert_eq!(*a, *b);
        // A prohibited character is refused.
        assert_eq!(
            scram.client_final(first, "p\u{0007}w").map(|_| ()),
            Err(ScramError::Password)
        );
    }

    #[test]
    fn the_test_server_accepts_the_client() {
        let srv = server::Server {
            salt: b"salt-salt".to_vec(),
            iterations: 4096,
            server_nonce: "SERVER".to_owned(),
            password: "dev-only-pw".to_owned(),
        };
        let (scram, first) = Scram::start("databastion").unwrap();
        let (bare, server_first) = srv.first(&first);
        let (last, expected) = scram
            .client_final(server_first.as_bytes(), "dev-only-pw")
            .unwrap();
        let v = srv.last(&bare, &server_first, &last).unwrap();
        expected.verify(v.as_bytes()).unwrap();
        // A wrong password gives a proof the server refuses.
        let (last, _) = scram
            .client_final(server_first.as_bytes(), "wrong")
            .unwrap();
        assert!(srv.last(&bare, &server_first, &last).is_none());
    }
}
