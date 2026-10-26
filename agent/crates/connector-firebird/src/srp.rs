//! The `Srp256` client (ADR-0060 decisions 1 and 3): SRP-6a with
//! Firebird's fixed 1024-bit group and `g = 2`, SHA-1 for the internal
//! hashes and the session key, SHA-256 for the client proof `M`.
//!
//! Firebird's forms, measured against the pinned 5.0.4 and 4.0.7 servers
//! (they differ from RFC 5054, as the ADR warns):
//!
//! - `k = SHA-1(N | PAD(g))`, `g` padded to the 128 bytes of `N`;
//! - big integers are hashed as their minimal big-endian bytes (Firebird's
//!   "pad" only cuts values longer than 128 bytes): `u = SHA-1(A | B)`;
//! - `x = SHA-1(salt | SHA-1(user ":" password))`, the salt as the bytes
//!   the server sent (its hexadecimal text) and the user upper-cased;
//! - `M = SHA-256(H | U | salt | A | B | K)` with `H = SHA-1(N) ^ SHA-1(g)
//!   mod N` (a modular power, not a XOR) and `U = SHA-1(user)` without its
//!   leading zero bytes.
//!
//! The exponentiations over the private value `a`, the password-derived
//! `x` and `a + u·x` run in constant time (`crypto-bigint`'s Montgomery
//! form, fixed-window); `num-bigint` (variable time) is not used. The
//! exponent `a + u·x` is not reduced: the server computes `(A·v^u)^b`, so
//! the unreduced exponent is always the right one. The password, `x`, `a`,
//! `S`, `K` and `M` live in zeroized buffers and are never written
//! anywhere else.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U256, U1024, U2048};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// The prime of Firebird's SRP group (`srp.cpp`), 1024 bits.
const N_HEX: &str = "E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7";
const N: U1024 = U1024::from_be_hex(N_HEX);
/// `k = SHA-1(N | PAD(g))` = 1277432915985975349439481660349303019122249719989.
const K_HEX: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DFC212B4BD69674855CFCEB30002B5C306AC60B5";
const K: U1024 = U1024::from_be_hex(K_HEX);
/// `g`.
const G: u64 = 2;
/// Size of `N` in bytes.
const KEY_BYTES: usize = 128;
/// Longest salt the server sends: 32 bytes as hexadecimal text.
const MAX_SALT: usize = 64;
/// Longest server data: `(32 + 128 + 2) * 2` (Firebird's own bound).
pub(crate) const MAX_SERVER_DATA: usize = (32 + KEY_BYTES + 2) * 2;

/// Why the server's SRP data is refused (decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SrpError {
    /// The data is longer than Firebird's bound, or the lengths inside it
    /// do not add up.
    Length,
    /// An empty or overlong salt, or one that is not hexadecimal text.
    Salt,
    /// `B` is not hexadecimal, longer than 128 bytes, or `B mod N` is 0
    /// or 1.
    PublicValue,
    /// The scrambler `u` is 0: the exchange is aborted.
    ZeroScrambler,
    /// The operating system's generator failed.
    Random,
}

fn params() -> FixedMontyParams<{ U1024::LIMBS }> {
    // `N` is odd (a prime): the `Odd` check cannot fail.
    let odd = Odd::new(N)
        .into_option()
        .unwrap_or(Odd::<U1024>::from_be_hex(N_HEX));
    FixedMontyParams::new_vartime(odd)
}

/// The minimal big-endian bytes of `v` (empty for 0).
fn min_bytes(v: &U1024) -> Zeroizing<Vec<u8>> {
    let bytes = v.to_be_bytes();
    let raw: &[u8] = bytes.as_ref();
    let start = raw.iter().position(|b| *b != 0).unwrap_or(raw.len());
    Zeroizing::new(raw[start..].to_vec())
}

/// `v` from at most 128 big-endian bytes.
fn from_be(bytes: &[u8]) -> Option<U1024> {
    if bytes.len() > KEY_BYTES {
        return None;
    }
    let mut buf = Zeroizing::new([0u8; KEY_BYTES]);
    buf[KEY_BYTES - bytes.len()..].copy_from_slice(bytes);
    Some(U1024::from_be_slice(&buf[..]))
}

/// The bytes of an uppercase hexadecimal text.
fn hex_upper(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)]);
        out.push(DIGITS[usize::from(b & 0x0F)]);
    }
    out
}

/// Bytes of a hexadecimal text (an odd length gets a leading `0`).
fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut digits = Vec::with_capacity(text.len() + 1);
    if text.len() % 2 == 1 {
        digits.push(0);
    }
    for c in text {
        digits.push(digit(*c)?);
    }
    Some(digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

/// The server's `p_acpt_data`: a 2-byte little-endian salt length, the
/// salt, a 2-byte little-endian length and `B` as hexadecimal text.
pub(crate) struct ServerData<'a> {
    pub(crate) salt: &'a [u8],
    b_bytes: Vec<u8>,
}

impl<'a> ServerData<'a> {
    /// Parses and checks the server data (decision 1): at most 324
    /// bytes, a salt of 1 to 64 hexadecimal characters, `B` of at most
    /// 128 bytes in
    /// hexadecimal with `B mod N` neither 0 nor 1.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, SrpError> {
        if data.len() > MAX_SERVER_DATA || data.len() < 4 {
            return Err(SrpError::Length);
        }
        let salt_len = usize::from(u16::from_le_bytes([data[0], data[1]]));
        if salt_len == 0 || salt_len > MAX_SALT {
            return Err(SrpError::Salt);
        }
        let salt = data.get(2..2 + salt_len).ok_or(SrpError::Length)?;
        if !salt.iter().all(u8::is_ascii_hexdigit) {
            return Err(SrpError::Salt);
        }
        let rest = data.get(2 + salt_len..).ok_or(SrpError::Length)?;
        if rest.len() < 2 {
            return Err(SrpError::Length);
        }
        let key_len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        let hex = &rest[2..];
        if key_len != hex.len() || key_len == 0 || key_len > KEY_BYTES * 2 {
            return Err(SrpError::Length);
        }
        let b_bytes = unhex(hex).ok_or(SrpError::PublicValue)?;
        let b = from_be(&b_bytes).ok_or(SrpError::PublicValue)?;
        // `B < 2^1024 < 2N`: one subtraction reduces it.
        let reduced = if b >= N { b.wrapping_sub(&N) } else { b };
        if reduced == U1024::ZERO || reduced == U1024::ONE {
            return Err(SrpError::PublicValue);
        }
        Ok(Self { salt, b_bytes })
    }

    fn b(&self) -> U1024 {
        from_be(&self.b_bytes).unwrap_or(U1024::ZERO)
    }
}

/// The client side of one exchange: the private `a` (zeroized) and the
/// public `A = g^a mod N`.
pub(crate) struct Client {
    a: Zeroizing<U1024>,
    public: U1024,
}

/// The client proof and the session key of a completed computation.
pub(crate) struct Proof {
    /// `M`, as the hexadecimal text sent in `op_cont_auth`.
    pub(crate) hex: Zeroizing<Vec<u8>>,
    /// `K = SHA-1(S)`, the key of the wire encryption.
    pub(crate) key: Zeroizing<Vec<u8>>,
}

impl Client {
    /// A fresh exchange: `a` drawn from the operating system's generator,
    /// 128 bytes, uniform in `[1, N)` by rejection.
    pub(crate) fn new() -> Result<Self, SrpError> {
        for _ in 0..64 {
            let mut raw = Zeroizing::new([0u8; KEY_BYTES]);
            getrandom::fill(&mut raw[..]).map_err(|_| SrpError::Random)?;
            let a = Zeroizing::new(U1024::from_be_slice(&raw[..]));
            if *a < N && *a != U1024::ZERO {
                return Ok(Self::with_private(a));
            }
        }
        Err(SrpError::Random)
    }

    /// An exchange with a given private value (`a < N`, not 0).
    pub(crate) fn with_private(a: Zeroizing<U1024>) -> Self {
        let p = params();
        let mut g = FixedMontyForm::new(&U1024::from_u64(G), &p);
        let mut pow = g.pow(&*a);
        let public = pow.retrieve();
        pow.zeroize();
        g.zeroize();
        Self { a, public }
    }

    /// `A` as the uppercase hexadecimal text of its minimal bytes (the
    /// `CNCT_specific_data` of `op_connect`).
    pub(crate) fn public_hex(&self) -> Zeroizing<Vec<u8>> {
        hex_upper(&min_bytes(&self.public))
    }

    /// `A`.
    #[cfg(test)]
    pub(crate) fn public(&self) -> U1024 {
        self.public
    }

    /// Computes `S`, `K` and `M` for `login` (upper-cased here, as the
    /// server stores it) and `password` (decision 1).
    pub(crate) fn proof(
        &self,
        login: &str,
        password: &[u8],
        server: &ServerData<'_>,
    ) -> Result<Proof, SrpError> {
        let p = params();
        let user = login.to_ascii_uppercase();
        let b = server.b();
        let a_bytes = min_bytes(&self.public);
        let b_bytes = min_bytes(&b);
        // u = SHA-1(A | B), aborted when 0.
        let mut h = Sha1::new();
        h.update(&a_bytes[..]);
        h.update(&b_bytes[..]);
        let u = from_be(&h.finalize()).ok_or(SrpError::PublicValue)?;
        if u == U1024::ZERO {
            return Err(SrpError::ZeroScrambler);
        }
        // x = SHA-1(salt | SHA-1(user ":" password)).
        let mut inner = Sha1::new();
        inner.update(user.as_bytes());
        inner.update(b":");
        inner.update(password);
        let mut inner = Zeroizing::new(inner.finalize().to_vec());
        let mut outer = Sha1::new();
        outer.update(server.salt);
        outer.update(&inner[..]);
        let mut x_hash = Zeroizing::new(outer.finalize().to_vec());
        inner.zeroize();
        let mut x_wide = Zeroizing::new([0u8; 32]);
        x_wide[32 - x_hash.len()..].copy_from_slice(&x_hash);
        x_hash.zeroize();
        let x = Zeroizing::new(U256::from_be_slice(&x_wide[..]));
        // S = (B - k·g^x)^(a + u·x) mod N.
        let g = FixedMontyForm::new(&U1024::from_u64(G), &p);
        let mut gx = g.pow(&*x);
        let k = FixedMontyForm::new(&K, &p);
        let reduced = if b >= N { b.wrapping_sub(&N) } else { b };
        let b_m = FixedMontyForm::new(&reduced, &p);
        let mut kgx = k.mul(&gx);
        let mut diff = b_m.sub(&kgx);
        let ux = Zeroizing::new(u.wrapping_mul(&x.resize::<{ U1024::LIMBS }>()));
        let exponent = Zeroizing::new(
            self.a
                .resize::<{ U2048::LIMBS }>()
                .wrapping_add(&ux.resize::<{ U2048::LIMBS }>()),
        );
        let mut s_m = diff.pow(&*exponent);
        let s = Zeroizing::new(s_m.retrieve());
        gx.zeroize();
        kgx.zeroize();
        diff.zeroize();
        s_m.zeroize();
        // K = SHA-1(S).
        let key = Zeroizing::new(Sha1::digest(&min_bytes(&s)[..]).to_vec());
        // M = SHA-256(H | U | salt | A | B | K).
        let n1 = from_be(&Sha1::digest(&min_bytes(&N)[..])).unwrap_or(U1024::ZERO);
        let n2 = from_be(&Sha1::digest([G as u8])).unwrap_or(U1024::ZERO);
        let h_ng = FixedMontyForm::new(&n1, &p).pow_vartime(&n2).retrieve();
        let user_hash = Sha1::digest(user.as_bytes());
        let start = user_hash
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(user_hash.len());
        let mut m = Sha256::new();
        m.update(&min_bytes(&h_ng)[..]);
        m.update(&user_hash[start..]);
        m.update(server.salt);
        m.update(&a_bytes[..]);
        m.update(&b_bytes[..]);
        m.update(&key[..]);
        let proof = Zeroizing::new(m.finalize().to_vec());
        Ok(Proof {
            hex: hex_upper(&proof),
            key,
        })
    }
}

/// The server side, for the tests (the fake server and the property
/// tests): the verifier `v = g^x`, `B = k·v + g^b`, and the session key
/// `K = SHA-1((A·v^u)^b)`, as the server computes them.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod server {
    use super::*;

    /// A private value from a seed (tests: deterministic, below `N`).
    pub(crate) fn private(seed: u64) -> U1024 {
        let mut bytes = [0u8; KEY_BYTES];
        for (i, chunk) in bytes.chunks_mut(8).enumerate() {
            let v = seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(i as u64)
                .rotate_left(i as u32 % 64);
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        bytes[0] &= 0x7F;
        U1024::from_be_slice(&bytes)
    }

    /// `B` for `login` / `password` / `salt` and the private `b`.
    #[cfg(test)]
    pub(crate) fn public(login: &str, password: &[u8], salt: &[u8], b: &U1024) -> U1024 {
        let p = params();
        let g = FixedMontyForm::new(&U1024::from_u64(G), &p);
        let v = g.pow(&verifier_exponent(login, password, salt));
        let k = FixedMontyForm::new(&K, &p);
        k.mul(&v).add(&g.pow(b)).retrieve()
    }

    #[cfg(test)]
    fn verifier_exponent(login: &str, password: &[u8], salt: &[u8]) -> U256 {
        let mut inner = Sha1::new();
        inner.update(login.to_ascii_uppercase().as_bytes());
        inner.update(b":");
        inner.update(password);
        let mut outer = Sha1::new();
        outer.update(salt);
        outer.update(inner.finalize());
        let mut wide = [0u8; 32];
        wide[12..].copy_from_slice(&outer.finalize());
        U256::from_be_slice(&wide)
    }

    /// The server's `K`.
    #[cfg(test)]
    pub(crate) fn session_key(
        login: &str,
        password: &[u8],
        salt: &[u8],
        a_public: &U1024,
        b_public: &U1024,
        b: &U1024,
    ) -> Vec<u8> {
        let p = params();
        let mut h = Sha1::new();
        h.update(&min_bytes(a_public)[..]);
        h.update(&min_bytes(b_public)[..]);
        let u = from_be(&h.finalize()).unwrap_or(U1024::ZERO);
        let g = FixedMontyForm::new(&U1024::from_u64(G), &p);
        let v = g.pow(&verifier_exponent(login, password, salt));
        let a = FixedMontyForm::new(a_public, &p);
        let s = a.mul(&v.pow(&u)).pow(b).retrieve();
        Sha1::digest(&min_bytes(&s)[..]).to_vec()
    }

    /// The server data of `p_acpt_data` for `salt` and `B`.
    #[cfg(test)]
    pub(crate) fn data(salt: &[u8], b_public: &U1024) -> Vec<u8> {
        let hex = hex_upper(&min_bytes(b_public));
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(salt.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(salt);
        out.extend_from_slice(&u16::try_from(hex.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&hex);
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_group_constants_are_firebirds() {
        // k = SHA-1(N | PAD(g)).
        let mut h = Sha1::new();
        h.update(&min_bytes(&N)[..]);
        let mut g = [0u8; KEY_BYTES];
        g[KEY_BYTES - 1] = 2;
        h.update(g);
        assert_eq!(from_be(&h.finalize()).unwrap(), K);
        assert_eq!(N.bits(), 1024);
    }

    #[test]
    fn client_and_server_derive_the_same_key() {
        let salt = b"C4452856DE3F0A11C4452856DE3F0A11C4452856DE3F0A11C4452856DE3F0A11";
        for seed in 1..6u64 {
            let client = Client::with_private(Zeroizing::new(server::private(seed)));
            let b = server::private(seed + 100);
            let b_public = server::public("databastion_agent", b"pw", salt, &b);
            let data = server::data(salt, &b_public);
            let parsed = ServerData::parse(&data).unwrap();
            let proof = client.proof("databastion_agent", b"pw", &parsed).unwrap();
            let server_key = server::session_key(
                "DATABASTION_AGENT",
                b"pw",
                salt,
                &client.public(),
                &b_public,
                &b,
            );
            assert_eq!(&proof.key[..], &server_key[..]);
            assert_eq!(proof.hex.len(), 64);
            // Another password gives another key.
            let other = client.proof("databastion_agent", b"px", &parsed).unwrap();
            assert_ne!(&other.key[..], &server_key[..]);
        }
    }

    /// A known answer computed independently (Python, the integers of the
    /// server's formulas) for `a = b = private(7)` and a fixed salt.
    #[test]
    fn a_known_answer() {
        let client = Client::with_private(Zeroizing::new(server::private(7)));
        let salt = b"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
        let b_public = server::public("AGENT", b"secret", salt, &server::private(8));
        let data = server::data(salt, &b_public);
        let proof = client
            .proof("agent", b"secret", &ServerData::parse(&data).unwrap())
            .unwrap();
        assert_eq!(std::str::from_utf8(&proof.hex).unwrap(), KNOWN_M);
    }

    /// See [`a_known_answer`].
    const KNOWN_M: &str = "49389B80AED8CECEC419864C16625D36465607059B1E16EF83DB650774E85502";

    #[test]
    fn hostile_server_data_is_refused() {
        let salt = b"abcd";
        let b_public = server::public("A", b"p", salt, &server::private(3));
        assert!(ServerData::parse(&server::data(salt, &b_public)).is_ok());
        // B = 0, 1, N, N + 1.
        for b in [U1024::ZERO, U1024::ONE, N, N.wrapping_add(&U1024::ONE)] {
            let mut data = Vec::new();
            data.extend_from_slice(&4u16.to_le_bytes());
            data.extend_from_slice(salt);
            let hex = if b == U1024::ZERO {
                Zeroizing::new(b"00".to_vec())
            } else {
                hex_upper(&min_bytes(&b))
            };
            data.extend_from_slice(&u16::try_from(hex.len()).unwrap().to_le_bytes());
            data.extend_from_slice(&hex);
            assert!(ServerData::parse(&data).is_err());
        }
        // A salt that is not hexadecimal text (decision 1).
        for bad in [b"abcg".as_slice(), b"ab d", b"ab\0d", "é1".as_bytes()] {
            let mut data = Vec::new();
            data.extend_from_slice(&u16::try_from(bad.len()).unwrap().to_le_bytes());
            data.extend_from_slice(bad);
            data.extend_from_slice(&2u16.to_le_bytes());
            data.extend_from_slice(b"05");
            assert_eq!(ServerData::parse(&data).err(), Some(SrpError::Salt));
        }
        // Lengths that do not add up, an empty or long salt, a non-hex B.
        assert_eq!(ServerData::parse(&[]).err(), Some(SrpError::Length));
        assert_eq!(
            ServerData::parse(&[0, 0, 2, 0, b'1', b'2']).err(),
            Some(SrpError::Salt)
        );
        let mut long = vec![65, 0];
        long.extend_from_slice(&[b'a'; 65]);
        long.extend_from_slice(&[2, 0, b'1', b'2']);
        assert_eq!(ServerData::parse(&long).err(), Some(SrpError::Salt));
        assert_eq!(
            ServerData::parse(&[1, 0, b'a', 3, 0, b'1', b'2']).err(),
            Some(SrpError::Length)
        );
        assert_eq!(
            ServerData::parse(&[1, 0, b'a', 2, 0, b'1', b'g']).err(),
            Some(SrpError::PublicValue)
        );
        assert_eq!(
            ServerData::parse(&vec![0u8; MAX_SERVER_DATA + 1]).err(),
            Some(SrpError::Length)
        );
    }

    #[test]
    fn the_public_value_is_fresh_and_in_the_group() {
        let a = Client::new().unwrap();
        let b = Client::new().unwrap();
        assert_ne!(a.public(), b.public());
        assert!(a.public() < N && a.public() > U1024::ONE);
        let hex = a.public_hex();
        assert!(hex.len() <= 256 && hex.iter().all(u8::is_ascii_hexdigit));
    }
}
