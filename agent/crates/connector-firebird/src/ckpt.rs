//! The persisted parser checkpoint of the Firebird Audit stream (ADR-0060
//! R25 items 7 and 9, R39 (a), R41 item 7, R42 item 4): a bounded binary
//! codec and its authenticated envelope.
//!
//! - **Envelope**: a magic, a version, the body length, the body, and an
//!   HMAC-SHA256 tag over all of it under the agent key's audit sub-key
//!   (the tailer's, separated by [`PURPOSE`]). A file that is not exactly
//!   that (another magic or version, a length that does not match, a tag
//!   that does not verify: corruption, a file of another agent key, a
//!   truncated write) is refused whole: nothing of it is used (fail
//!   closed).
//! - **Reader**: every read is bounded by what is left; every count is
//!   checked against a cap before anything is allocated; strings are UTF-8
//!   of at most [`MAX_NAME`] bytes; a body with bytes left over is refused.
//!   It never panics (fuzz target `firebird_checkpoint`).
//!
//! What the bodies hold is in [`crate::stream`] (the parser state) and
//! [`crate::own`] (the ledger): ids, tokens, positions, counters, times,
//! keyed tags of names and texts; never a statement text, a parameter or a
//! relation, routine or database name in clear (I2: a name can embed a
//! value).

use databastion_classifiers::masking::LocalTagKey;

/// Domain separation of the tags this module makes with the sub-key.
pub(crate) const PURPOSE: &[u8] = b"databastion.firebird.checkpoint.v1";
/// The longest name kept (R1 rule 11: a longer database name is
/// ambiguous and not kept; relation and routine names are far shorter).
pub(crate) const MAX_NAME: usize = 4096;
/// The format version (2: the ledger's fetch accounts carry the row-limit
/// cut of R22 item 6; a version 1 file is refused whole, fail closed).
pub(crate) const VERSION: u16 = 2;

/// Why a checkpoint was refused (kind only, logged as such).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not the envelope: magic, version, length.
    Envelope,
    /// The tag does not verify (corruption, another agent key).
    Tag,
    /// The body does not decode within its bounds.
    Body,
    /// The body decodes but does not hold for the stream it would restore
    /// (another run, other declared databases, a bound passed).
    State,
    /// Another position than the one the log resumed from.
    Position,
}

impl Refused {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Envelope => "envelope",
            Self::Tag => "tag",
            Self::Body => "body",
            Self::State => "state",
            Self::Position => "position",
        }
    }
}

/// A keyed tag of `parts` under `purpose` (the parts are never kept).
pub(crate) fn tag(key: &LocalTagKey, purpose: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len() * 2 + 2);
    let plen = u32::try_from(purpose.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    all.push(&plen);
    all.push(purpose);
    let lens: Vec<[u8; 4]> = parts
        .iter()
        .map(|p| u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes())
        .collect();
    for (p, l) in parts.iter().zip(&lens) {
        all.push(l);
        all.push(p);
    }
    key.tag(&all)
}

/// Seals `body` into the envelope.
pub(crate) fn seal(key: &LocalTagKey, magic: &[u8; 4], body: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(body.len()).ok()?;
    let mut out = Vec::with_capacity(body.len() + 42);
    out.extend_from_slice(magic);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    let t = tag(key, PURPOSE, &[&out]);
    out.extend_from_slice(&t);
    Some(out)
}

/// Opens an envelope: its body, when everything verifies.
pub(crate) fn open<'a>(
    key: &LocalTagKey,
    magic: &[u8; 4],
    bytes: &'a [u8],
) -> Result<&'a [u8], Refused> {
    let body = envelope_body(magic, bytes)?;
    let (head, t) = bytes.split_at(bytes.len() - 32);
    let want = tag(key, PURPOSE, &[head]);
    // Constant-time comparison of the tags.
    let diff = want.iter().zip(t).fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        return Err(Refused::Tag);
    }
    Ok(body)
}

/// The body of an envelope, its tag not checked (the fuzz target, and
/// [`open`] before the tag).
pub(crate) fn envelope_body<'a>(magic: &[u8; 4], bytes: &'a [u8]) -> Result<&'a [u8], Refused> {
    if bytes.len() < 4 + 2 + 4 + 32 || &bytes[..4] != magic {
        return Err(Refused::Envelope);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let len = usize::try_from(len).map_err(|_| Refused::Envelope)?;
    if version != VERSION || bytes.len() != 10 + len + 32 {
        return Err(Refused::Envelope);
    }
    Ok(&bytes[10..10 + len])
}

/// A bounded writer.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub(crate) fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }
    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    pub(crate) fn bytes32(&mut self, v: &[u8; 32]) {
        self.buf.extend_from_slice(v);
    }
    /// A name: callers keep only names of at most [`MAX_NAME`] bytes.
    pub(crate) fn str(&mut self, s: &str) {
        self.len(s.len());
        self.buf.extend_from_slice(s.as_bytes());
    }
    pub(crate) fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(v) => {
                self.u8(1);
                self.u64(v);
            }
            None => self.u8(0),
        }
    }
    pub(crate) fn opt_i64(&mut self, v: Option<i64>) {
        match v {
            Some(v) => {
                self.u8(1);
                self.i64(v);
            }
            None => self.u8(0),
        }
    }
}

/// A bounded reader: every read fails rather than reading past the end.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A decode failure (the body is refused whole).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bad;

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        let end = self.pos.checked_add(n).ok_or(Bad)?;
        let s = self.buf.get(self.pos..end).ok_or(Bad)?;
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn done(&self) -> Result<(), Bad> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Bad)
        }
    }
    pub(crate) fn u8(&mut self) -> Result<u8, Bad> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn bool(&mut self) -> Result<bool, Bad> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Bad),
        }
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Bad> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Bad> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    pub(crate) fn i64(&mut self) -> Result<i64, Bad> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }
    /// A count of at most `cap` items of at least `min` bytes each (so a
    /// forged count cannot make the caller allocate more than the body).
    pub(crate) fn len(&mut self, cap: usize, min: usize) -> Result<usize, Bad> {
        let n = usize::try_from(self.u32()?).map_err(|_| Bad)?;
        let left = self.buf.len() - self.pos;
        if n > cap || n.saturating_mul(min.max(1)) > left {
            return Err(Bad);
        }
        Ok(n)
    }
    /// `n` bytes as they are.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        self.take(n)
    }
    pub(crate) fn bytes32(&mut self) -> Result<[u8; 32], Bad> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
    pub(crate) fn str(&mut self) -> Result<String, Bad> {
        let n = usize::try_from(self.u32()?).map_err(|_| Bad)?;
        if n > MAX_NAME {
            return Err(Bad);
        }
        let b = self.take(n)?;
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| Bad)
    }
    pub(crate) fn opt_u64(&mut self) -> Result<Option<u64>, Bad> {
        Ok(if self.bool()? {
            Some(self.u64()?)
        } else {
            None
        })
    }
    pub(crate) fn opt_i64(&mut self) -> Result<Option<i64>, Bad> {
        Ok(if self.bool()? {
            Some(self.i64()?)
        } else {
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn key(seed: u8) -> LocalTagKey {
        databastion_classifiers::masking::HmacKey::new(&[seed; 32])
            .unwrap()
            .local_tag_key("databastion.audit.cursor")
            .unwrap()
    }

    #[test]
    fn the_envelope_refuses_anything_but_itself() {
        let k = key(1);
        let sealed = seal(&k, b"FBCK", b"body").unwrap();
        assert_eq!(open(&k, b"FBCK", &sealed), Ok(&b"body"[..]));
        // Another key, another magic, a flipped bit, a cut, an extension.
        assert_eq!(open(&key(2), b"FBCK", &sealed), Err(Refused::Tag));
        assert_eq!(open(&k, b"FBLG", &sealed), Err(Refused::Envelope));
        for i in 0..sealed.len() {
            let mut b = sealed.clone();
            b[i] ^= 1;
            assert!(open(&k, b"FBCK", &b).is_err(), "bit {i}");
        }
        for n in 0..sealed.len() {
            assert!(open(&k, b"FBCK", &sealed[..n]).is_err(), "cut {n}");
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(open(&k, b"FBCK", &longer).is_err());
        // Another version (an earlier one included: version 1's ledger had
        // no row-limit cut).
        for v in [1u8, 3] {
            let mut other = sealed.clone();
            other[5] = v;
            assert_eq!(open(&k, b"FBCK", &other), Err(Refused::Envelope));
        }
    }

    #[test]
    fn the_reader_stays_within_its_bounds() {
        let mut w = Writer::default();
        w.len(3);
        w.u64(1);
        let mut r = Reader::new(&w.buf);
        // Three items of 8 bytes do not fit in the 8 bytes left.
        assert_eq!(r.len(16, 8), Err(Bad));
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.len(2, 1), Err(Bad), "past the cap");
        let mut w = Writer::default();
        w.u32(u32::MAX);
        assert_eq!(Reader::new(&w.buf).str(), Err(Bad));
        let mut w = Writer::default();
        w.str("RDB$DATABASE");
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.str().as_deref(), Ok("RDB$DATABASE"));
        assert_eq!(r.done(), Ok(()));
        assert_eq!(Reader::new(&[2]).bool(), Err(Bad));
        let mut w = Writer::default();
        w.len(2);
        w.buf.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(Reader::new(&w.buf).str(), Err(Bad), "not UTF-8");
    }

    #[test]
    fn tags_separate_their_parts() {
        let k = key(3);
        assert_ne!(tag(&k, b"p", &[b"ab", b"c"]), tag(&k, b"p", &[b"a", b"bc"]));
        assert_ne!(tag(&k, b"p", &[b"a"]), tag(&k, b"q", &[b"a"]));
    }
}
