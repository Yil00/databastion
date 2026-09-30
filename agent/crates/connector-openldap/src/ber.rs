//! Bounded BER for the LDAPv3 subset the connector speaks (ADR-0029
//! decision 1).
//!
//! - Encoding: definite lengths, low tag numbers, into zeroized buffers
//!   (a bind request holds the password).
//! - Decoding: a [`Reader`] over one received message. Definite lengths
//!   only, at most 4 length octets, low tag numbers only, every length
//!   checked against what remains of the enclosing element; anything else
//!   is [`BerError`]. There is no generic tree: callers read the grammar
//!   they expect, so nesting is bounded by the code, never by the input.

use zeroize::Zeroizing;

/// Largest `LDAPMessage` accepted, header included (checked before the
/// body is read).
pub(crate) const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Universal tags.
pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const ENUMERATED: u8 = 0x0a;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// Malformed or out-of-bounds BER. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed BER")]
pub(crate) struct BerError;

/// Constructed application tag `n` (`[APPLICATION n]`, `n < 31`).
pub(crate) const fn app(n: u8) -> u8 {
    0x60 | n
}

/// Primitive application tag `n`.
pub(crate) const fn app_primitive(n: u8) -> u8 {
    0x40 | n
}

/// Primitive context tag `n` (`[n]`).
pub(crate) const fn ctx(n: u8) -> u8 {
    0x80 | n
}

/// Constructed context tag `n`.
pub(crate) const fn ctx_constructed(n: u8) -> u8 {
    0xa0 | n
}

/// An encoded element (tag, length, content), in a zeroized buffer.
#[derive(Clone, Default)]
pub(crate) struct Enc(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for Enc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enc").field("len", &self.0.len()).finish()
    }
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        // Fits in 7 bits.
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let n = bytes.len() - skip;
        out.push(0x80 | u8::try_from(n).unwrap_or(0));
        out.extend_from_slice(bytes.get(skip..).unwrap_or_default());
    }
}

impl Enc {
    /// An element with `tag` and raw `content`.
    pub(crate) fn raw(tag: u8, content: &[u8]) -> Self {
        let mut out = Zeroizing::new(Vec::with_capacity(content.len() + 6));
        out.push(tag);
        push_len(&mut out, content.len());
        out.extend_from_slice(content);
        Self(out)
    }

    /// A constructed element made of `parts`.
    pub(crate) fn constructed(tag: u8, parts: &[Enc]) -> Self {
        let len: usize = parts.iter().map(|p| p.0.len()).sum();
        let mut content = Zeroizing::new(Vec::with_capacity(len));
        for p in parts {
            content.extend_from_slice(&p.0);
        }
        Self::raw(tag, &content)
    }

    /// An INTEGER (or ENUMERATED with `tag`), minimal two's complement.
    pub(crate) fn int(tag: u8, value: i64) -> Self {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while let (Some(&b), Some(&next)) = (bytes.get(start), bytes.get(start + 1)) {
            if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
                start += 1;
            } else {
                break;
            }
        }
        Self::raw(tag, bytes.get(start..).unwrap_or_default())
    }

    /// A BOOLEAN.
    pub(crate) fn boolean(value: bool) -> Self {
        Self::raw(BOOLEAN, &[if value { 0xff } else { 0x00 }])
    }

    /// An OCTET STRING (or another primitive `tag`).
    pub(crate) fn octets(tag: u8, value: &[u8]) -> Self {
        Self::raw(tag, value)
    }

    /// The encoded bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Length of the whole message announced by the first bytes of `head` (a
/// SEQUENCE header): `Ok(None)` while more header bytes are needed.
pub(crate) fn message_len(head: &[u8]) -> Result<Option<usize>, BerError> {
    let Some(&tag) = head.first() else {
        return Ok(None);
    };
    if tag != SEQUENCE {
        return Err(BerError);
    }
    let Some(&first) = head.get(1) else {
        return Ok(None);
    };
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            // Indefinite length, or more than 4 GiB.
            return Err(BerError);
        }
        let Some(octets) = head.get(2..2 + n) else {
            return Ok(None);
        };
        let mut len = 0usize;
        for b in octets {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let total = len.checked_add(header).ok_or(BerError)?;
    if total > MAX_MESSAGE {
        return Err(BerError);
    }
    Ok(Some(total))
}

/// A cursor over BER elements.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl std::fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("remaining", &self.buf.len())
            .finish()
    }
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Whether every element was read.
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The tag of the next element, if any.
    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// The next element: its tag and content.
    pub(crate) fn tlv(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        let (&tag, rest) = self.buf.split_first().ok_or(BerError)?;
        if tag & 0x1f == 0x1f {
            // High tag number form: never used by LDAP.
            return Err(BerError);
        }
        let (&first, rest) = rest.split_first().ok_or(BerError)?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return Err(BerError);
            }
            let (octets, rest) = rest.split_at_checked(n).ok_or(BerError)?;
            let mut len = 0usize;
            for b in octets {
                len = (len << 8) | usize::from(*b);
            }
            (len, rest)
        };
        if len > rest.len() {
            return Err(BerError);
        }
        let (content, after) = rest.split_at(len);
        self.buf = after;
        Ok((tag, content))
    }

    /// The next element, which must have `tag`.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<&'a [u8], BerError> {
        match self.tlv()? {
            (t, content) if t == tag => Ok(content),
            _ => Err(BerError),
        }
    }

    /// The next element when it has `tag`; nothing is consumed otherwise.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, BerError> {
        if self.peek_tag() == Some(tag) {
            self.expect(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// A constructed element with `tag`, as a reader over its content.
    pub(crate) fn nested(&mut self, tag: u8) -> Result<Reader<'a>, BerError> {
        self.expect(tag).map(Reader::new)
    }

    /// An INTEGER (or ENUMERATED with `tag`) that fits in an `i64`.
    pub(crate) fn int(&mut self, tag: u8) -> Result<i64, BerError> {
        decode_int(self.expect(tag)?)
    }
}

/// A two's-complement integer of 1 to 8 bytes.
pub(crate) fn decode_int(content: &[u8]) -> Result<i64, BerError> {
    let first = *content.first().ok_or(BerError)?;
    if content.len() > 8 {
        return Err(BerError);
    }
    let mut v: i64 = if first & 0x80 != 0 { -1 } else { 0 };
    for b in content {
        v = (v << 8) | i64::from(*b);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_in_minimal_form() {
        for v in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            i64::MAX,
            i64::MIN,
        ] {
            let e = Enc::int(INTEGER, v);
            let mut r = Reader::new(e.as_bytes());
            assert_eq!(r.int(INTEGER).unwrap(), v);
            assert!(r.is_empty());
        }
        assert_eq!(Enc::int(INTEGER, 127).as_bytes(), &[0x02, 0x01, 0x7f]);
        assert_eq!(Enc::int(INTEGER, 128).as_bytes(), &[0x02, 0x02, 0x00, 0x80]);
        assert_eq!(Enc::int(INTEGER, -1).as_bytes(), &[0x02, 0x01, 0xff]);
    }

    #[test]
    fn long_lengths_are_encoded_and_read() {
        let content = vec![7u8; 300];
        let e = Enc::octets(OCTET_STRING, &content);
        assert_eq!(&e.as_bytes()[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let mut r = Reader::new(e.as_bytes());
        assert_eq!(r.expect(OCTET_STRING).unwrap(), &content[..]);
    }

    #[test]
    fn message_lengths_are_bounded_before_the_body() {
        assert_eq!(message_len(&[]), Ok(None));
        assert_eq!(message_len(&[0x30]), Ok(None));
        assert_eq!(message_len(&[0x30, 0x05]), Ok(Some(7)));
        assert_eq!(message_len(&[0x30, 0x82, 0x01]), Ok(None));
        assert_eq!(message_len(&[0x30, 0x82, 0x01, 0x00]), Ok(Some(260)));
        // Not a SEQUENCE, indefinite, more than 4 length octets, too big.
        assert!(message_len(&[0x04, 0x01]).is_err());
        assert!(message_len(&[0x30, 0x80]).is_err());
        assert!(message_len(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(message_len(&[0x30, 0x84, 0x01, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn malformed_elements_are_refused() {
        // Length beyond the buffer, high tag form, empty integer, 9-byte
        // integer, zero-length long form.
        for bad in [
            &[0x04, 0x05, 0x00][..],
            &[0x1f, 0x01, 0x00],
            &[0x02, 0x00],
            &[0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            &[0x04, 0x80],
            &[0x04, 0x81],
        ] {
            let mut r = Reader::new(bad);
            assert!(
                r.tlv()
                    .and_then(|(t, c)| if t == INTEGER {
                        decode_int(c).map(|_| ())
                    } else {
                        Ok(())
                    })
                    .is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn optional_elements_do_not_consume_others() {
        let e = Enc::constructed(SEQUENCE, &[Enc::boolean(true), Enc::octets(ctx(7), b"x")]);
        let mut r = Reader::new(e.as_bytes());
        let mut seq = r.nested(SEQUENCE).unwrap();
        assert_eq!(seq.optional(ctx(7)).unwrap(), None);
        assert_eq!(seq.expect(BOOLEAN).unwrap(), &[0xff]);
        assert_eq!(seq.optional(ctx(7)).unwrap(), Some(&b"x"[..]));
        assert!(seq.is_empty());
    }
}
