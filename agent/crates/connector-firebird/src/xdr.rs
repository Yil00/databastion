//! XDR, as the Firebird remote protocol uses it (ADR-0060 decision 1):
//! big-endian 32-bit integers, and opaque items as a 32-bit length, the
//! bytes and 0 to 3 padding bytes. XDR has no framing beyond its own items,
//! so every length is checked against a bound **before** anything is read
//! or allocated, and a message is parsed only once all of it has arrived
//! ([`XdrError::Incomplete`]: read more, then parse again from the start).

use zeroize::Zeroizing;

/// Why a read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XdrError {
    /// The buffer ends inside the item: more bytes are needed.
    Incomplete,
    /// A length above its bound, or a value outside its closed set: the
    /// connection is ended (fail closed).
    Bound,
}

/// A bounded reader over the received bytes.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub(crate) const fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes left in the buffer.
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// `n` raw bytes (no padding).
    pub(crate) fn raw(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let end = self.pos.checked_add(n).ok_or(XdrError::Bound)?;
        let out = self.buf.get(self.pos..end).ok_or(XdrError::Incomplete)?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, XdrError> {
        let b = self.raw(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, XdrError> {
        self.u32().map(|v| i32::from_be_bytes(v.to_be_bytes()))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, XdrError> {
        let b = self.raw(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }

    /// An XDR `short` (an object handle, a version): a 32-bit item whose
    /// upper half is the sign extension of the lower half. Anything else
    /// is a protocol violation.
    pub(crate) fn short(&mut self) -> Result<u16, XdrError> {
        let v = self.u32()?;
        let low = (v & 0xFFFF) as u16;
        let high = v >> 16;
        let expected = if low & 0x8000 == 0 { 0 } else { 0xFFFF };
        if high == expected {
            Ok(low)
        } else {
            Err(XdrError::Bound)
        }
    }

    /// Skips the padding of an item of `len` bytes.
    pub(crate) fn pad(&mut self, len: usize) -> Result<(), XdrError> {
        self.raw((4 - len % 4) % 4).map(|_| ())
    }

    /// An opaque item (`Buffer` / `String`) of at most `max` bytes.
    pub(crate) fn opaque(&mut self, max: usize) -> Result<&'a [u8], XdrError> {
        let len = usize::try_from(self.u32()?).map_err(|_| XdrError::Bound)?;
        if len > max {
            return Err(XdrError::Bound);
        }
        let out = self.raw(len)?;
        self.pad(len)?;
        Ok(out)
    }

    /// Skips an opaque item of at most `max` bytes without keeping it
    /// (status-vector strings: never stored, decision 1).
    pub(crate) fn skip_opaque(&mut self, max: usize) -> Result<(), XdrError> {
        self.opaque(max).map(|_| ())
    }
}

/// A message being built. The buffer is zeroized when dropped: messages
/// can carry the SRP proof and, from Discovery on, nothing else secret, but
/// one rule for every message is simpler to review.
#[derive(Default)]
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn opaque(&mut self, bytes: &[u8]) -> &mut Self {
        // Callers bound their items far below 4 GiB.
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.u32(len);
        self.buf.extend_from_slice(bytes);
        let pad = (4 - bytes.len() % 4) % 4;
        self.buf.extend_from_slice(&[0u8; 3][..pad]);
        self
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn items_round_trip_with_padding() {
        let mut w = Writer::new();
        w.u32(7).opaque(b"abcde").opaque(b"").u32(0xFFFF_8010);
        assert_eq!(w.len(), 4 + 4 + 8 + 4 + 4);
        let bytes = w.as_slice().to_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u32(), Ok(7));
        assert_eq!(r.opaque(16), Ok(&b"abcde"[..]));
        assert_eq!(r.opaque(16), Ok(&b""[..]));
        assert_eq!(r.short(), Ok(0x8010));
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.u32(), Err(XdrError::Incomplete));
    }

    #[test]
    fn lengths_are_checked_before_reading() {
        let mut bytes = 0xFFFF_FFF0u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0; 8]);
        assert_eq!(Reader::new(&bytes).opaque(1 << 20), Err(XdrError::Bound));
        let short = [0, 0, 0, 9, 1, 2];
        assert_eq!(Reader::new(&short).opaque(16), Err(XdrError::Incomplete));
        assert_eq!(Reader::new(&short).opaque(8), Err(XdrError::Bound));
        // A short whose upper half is not the sign extension.
        assert_eq!(
            Reader::new(&0x0001_0002u32.to_be_bytes()).short(),
            Err(XdrError::Bound)
        );
        assert_eq!(
            Reader::new(&0xFFFF_FFFFu32.to_be_bytes()).short(),
            Ok(0xFFFF)
        );
    }
}
