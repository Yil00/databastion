//! Bounded BSON reader and a minimal writer (ADR-0026 decision 1).
//!
//! The reader borrows from a reply buffer and never allocates: a [`Doc`]
//! is a slice whose length prefix and trailing zero were checked, and its
//! elements are decoded lazily, each one checked against the bytes left in
//! its document. Anything malformed (a length past its document, an
//! unknown type, a key without its terminator) is an error: the caller
//! drops the reply (fail closed). Nesting is walked by the callers, which
//! bound their own depth.
//!
//! The writer builds the connector's own commands only; keys are string
//! literals of this crate.

use std::fmt;

/// A BSON document or array that failed the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed BSON")]
pub(crate) struct Malformed;

fn read_i32(b: &[u8], at: usize) -> Result<i32, Malformed> {
    let bytes: [u8; 4] = b
        .get(at..at.checked_add(4).ok_or(Malformed)?)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)?;
    Ok(i32::from_le_bytes(bytes))
}

fn read_8(b: &[u8], at: usize) -> Result<[u8; 8], Malformed> {
    b.get(at..at.checked_add(8).ok_or(Malformed)?)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)
}

/// A checked BSON document (or array) borrowed from a buffer.
#[derive(Clone, Copy)]
pub(crate) struct Doc<'a> {
    bytes: &'a [u8],
}

impl fmt::Debug for Doc<'_> {
    // Never the content: it can hold sampled values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Doc")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl Doc<'static> {
    /// The empty document.
    pub(crate) const EMPTY: Self = Self {
        bytes: &[5, 0, 0, 0, 0],
    };
}

impl<'a> Doc<'a> {
    /// A document filling `bytes` exactly.
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, Malformed> {
        let len = read_i32(bytes, 0)?;
        let len = usize::try_from(len).map_err(|_| Malformed)?;
        if len < 5 || len != bytes.len() || bytes[len - 1] != 0 {
            return Err(Malformed);
        }
        Ok(Self { bytes })
    }

    /// The document at the start of `bytes`, and its length.
    pub(crate) fn prefix(bytes: &'a [u8]) -> Result<(Self, usize), Malformed> {
        let len = read_i32(bytes, 0)?;
        let len = usize::try_from(len).map_err(|_| Malformed)?;
        let doc = Self::new(bytes.get(..len).ok_or(Malformed)?)?;
        Ok((doc, len))
    }

    /// The encoded document.
    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Elements in order. The iterator yields one error and then stops.
    pub(crate) fn iter(&self) -> Iter<'a> {
        Iter {
            rest: &self.bytes[4..self.bytes.len() - 1],
            failed: false,
        }
    }

    /// The first element named `key`.
    pub(crate) fn get(&self, key: &str) -> Result<Option<Value<'a>>, Malformed> {
        for element in self.iter() {
            let (k, v) = element?;
            if k == key.as_bytes() {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// A string element (UTF-8), `None` when absent or of another type.
    pub(crate) fn str(&self, key: &str) -> Result<Option<&'a str>, Malformed> {
        Ok(match self.get(key)? {
            Some(Value::Str(s)) => Some(std::str::from_utf8(s).map_err(|_| Malformed)?),
            _ => None,
        })
    }

    /// An embedded document element.
    pub(crate) fn doc(&self, key: &str) -> Result<Option<Doc<'a>>, Malformed> {
        Ok(match self.get(key)? {
            Some(Value::Doc(d)) => Some(d),
            _ => None,
        })
    }

    /// An array element (as a document keyed `0`, `1`…).
    pub(crate) fn array(&self, key: &str) -> Result<Option<Doc<'a>>, Malformed> {
        Ok(match self.get(key)? {
            Some(Value::Array(d)) => Some(d),
            _ => None,
        })
    }

    /// A numeric element as an `i64` (int32, int64, or an integral double).
    pub(crate) fn int(&self, key: &str) -> Result<Option<i64>, Malformed> {
        Ok(self.get(key)?.and_then(|v| v.as_i64()))
    }

    /// A boolean element; numbers count as `true` when non-zero (`ok`).
    pub(crate) fn flag(&self, key: &str) -> Result<Option<bool>, Malformed> {
        Ok(match self.get(key)? {
            Some(Value::Bool(b)) => Some(b),
            Some(v) => v.as_f64().map(|n| n != 0.0),
            None => None,
        })
    }
}

/// A decoded element value. Kinds the connector never reads are
/// [`Value::Other`].
#[derive(Clone, Copy)]
pub(crate) enum Value<'a> {
    Double(f64),
    /// String bytes without the terminator (not checked as UTF-8 here).
    Str(&'a [u8]),
    Doc(Doc<'a>),
    Array(Doc<'a>),
    /// Subtype and data.
    Binary(u8, &'a [u8]),
    /// Milliseconds since the Unix epoch.
    Date(i64),
    Int32(i32),
    Int64(i64),
    /// IEEE 754-2008 decimal128, BID encoding, little-endian.
    Decimal128([u8; 16]),
    Bool(bool),
    /// Deprecated symbol type (a string).
    Symbol(&'a [u8]),
    /// ObjectId, null, undefined, regular expression, DBPointer,
    /// JavaScript code (with or without scope), timestamp, min / max key.
    Other,
}

impl fmt::Debug for Value<'_> {
    // The kind only, never the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Double(_) => "Double",
            Self::Str(_) => "Str",
            Self::Doc(_) => "Doc",
            Self::Array(_) => "Array",
            Self::Binary(..) => "Binary",
            Self::Date(_) => "Date",
            Self::Int32(_) => "Int32",
            Self::Int64(_) => "Int64",
            Self::Decimal128(_) => "Decimal128",
            Self::Bool(_) => "Bool",
            Self::Symbol(_) => "Symbol",
            Self::Other => "Other",
        })
    }
}

impl Value<'_> {
    /// Integer value (int32, int64, or a double without fraction that fits).
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Int32(n) => Some(i64::from(n)),
            Self::Int64(n) => Some(n),
            Self::Double(d) if d.is_finite() && d.fract() == 0.0 && d.abs() < 9.0e15 =>
            {
                #[allow(clippy::cast_possible_truncation)]
                Some(d as i64)
            }
            _ => None,
        }
    }

    /// Any numeric value as a double.
    pub(crate) fn as_f64(&self) -> Option<f64> {
        match *self {
            Self::Int32(n) => Some(f64::from(n)),
            #[allow(clippy::cast_precision_loss)]
            Self::Int64(n) => Some(n as f64),
            Self::Double(d) => Some(d),
            _ => None,
        }
    }
}

/// Iterator over the elements of a [`Doc`].
pub(crate) struct Iter<'a> {
    rest: &'a [u8],
    failed: bool,
}

/// A length-prefixed string (`int32` length including the terminator,
/// then the bytes and a zero): the bytes without the terminator, and the
/// total size.
fn string_at(b: &[u8]) -> Result<(&[u8], usize), Malformed> {
    let len = usize::try_from(read_i32(b, 0)?).map_err(|_| Malformed)?;
    if len < 1 {
        return Err(Malformed);
    }
    let end = 4usize.checked_add(len).ok_or(Malformed)?;
    let bytes = b.get(4..end).ok_or(Malformed)?;
    if bytes[len - 1] != 0 {
        return Err(Malformed);
    }
    Ok((&bytes[..len - 1], end))
}

/// A zero-terminated string: its bytes and the size with the terminator.
fn cstring_at(b: &[u8]) -> Result<(&[u8], usize), Malformed> {
    let end = b.iter().position(|&c| c == 0).ok_or(Malformed)?;
    Ok((&b[..end], end + 1))
}

/// Decodes one value of type `t` at the start of `b`: the value and its
/// size.
fn value_at(t: u8, b: &[u8]) -> Result<(Value<'_>, usize), Malformed> {
    Ok(match t {
        0x01 => (Value::Double(f64::from_le_bytes(read_8(b, 0)?)), 8),
        0x02 => {
            let (s, n) = string_at(b)?;
            (Value::Str(s), n)
        }
        0x0E => {
            let (s, n) = string_at(b)?;
            (Value::Symbol(s), n)
        }
        0x0D => (Value::Other, string_at(b)?.1),
        0x03 => {
            let (d, n) = Doc::prefix(b)?;
            (Value::Doc(d), n)
        }
        0x04 => {
            let (d, n) = Doc::prefix(b)?;
            (Value::Array(d), n)
        }
        0x05 => {
            let len = usize::try_from(read_i32(b, 0)?).map_err(|_| Malformed)?;
            let subtype = *b.get(4).ok_or(Malformed)?;
            let end = 5usize.checked_add(len).ok_or(Malformed)?;
            let data = b.get(5..end).ok_or(Malformed)?;
            (Value::Binary(subtype, data), end)
        }
        // Undefined, null, min key, max key: no payload.
        0x06 | 0x0A | 0xFF | 0x7F => (Value::Other, 0),
        0x07 => {
            b.get(..12).ok_or(Malformed)?;
            (Value::Other, 12)
        }
        0x08 => match b.first() {
            Some(0) => (Value::Bool(false), 1),
            Some(1) => (Value::Bool(true), 1),
            _ => return Err(Malformed),
        },
        0x09 => (Value::Date(i64::from_le_bytes(read_8(b, 0)?)), 8),
        0x0B => {
            let (_, a) = cstring_at(b)?;
            let (_, c) = cstring_at(&b[a..])?;
            (Value::Other, a + c)
        }
        0x0C => {
            let (_, n) = string_at(b)?;
            let end = n.checked_add(12).ok_or(Malformed)?;
            b.get(..end).ok_or(Malformed)?;
            (Value::Other, end)
        }
        0x0F => {
            // Code with scope: total length, string, document; the parts
            // must fill the total exactly.
            let total = usize::try_from(read_i32(b, 0)?).map_err(|_| Malformed)?;
            let body = b.get(..total).ok_or(Malformed)?;
            let (_, s) = string_at(body.get(4..).ok_or(Malformed)?)?;
            let (_, d) = Doc::prefix(body.get(4 + s..).ok_or(Malformed)?)?;
            if 4 + s + d != total {
                return Err(Malformed);
            }
            (Value::Other, total)
        }
        0x10 => (Value::Int32(read_i32(b, 0)?), 4),
        0x11 => {
            read_8(b, 0)?;
            (Value::Other, 8)
        }
        0x12 => (Value::Int64(i64::from_le_bytes(read_8(b, 0)?)), 8),
        0x13 => {
            let bytes: [u8; 16] = b
                .get(..16)
                .ok_or(Malformed)?
                .try_into()
                .map_err(|_| Malformed)?;
            (Value::Decimal128(bytes), 16)
        }
        _ => return Err(Malformed),
    })
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<(&'a [u8], Value<'a>), Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let r = (|| {
            let rest = self.rest;
            let t = rest[0];
            let (key, k) = cstring_at(&rest[1..])?;
            let at = 1 + k;
            let (value, n) = value_at(t, &rest[at..])?;
            self.rest = &rest[at + n..];
            Ok((key, value))
        })();
        if r.is_err() {
            self.failed = true;
        }
        Some(r)
    }
}

/// Builds a BSON document.
pub(crate) struct DocBuf(Vec<u8>);

impl fmt::Debug for DocBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DocBuf")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Default for DocBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl DocBuf {
    pub(crate) fn new() -> Self {
        Self(vec![0; 4])
    }

    fn key(&mut self, t: u8, key: &str) {
        self.0.push(t);
        // Keys are literals of this crate or array indices: no NUL.
        self.0
            .extend(key.as_bytes().iter().copied().filter(|&b| b != 0));
        self.0.push(0);
    }

    fn string(&mut self, value: &[u8]) {
        let len = i32::try_from(value.len() + 1).unwrap_or(i32::MAX);
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(value);
        self.0.push(0);
    }

    pub(crate) fn str(mut self, key: &str, value: &str) -> Self {
        self.key(0x02, key);
        self.string(value.as_bytes());
        self
    }

    pub(crate) fn i32(mut self, key: &str, value: i32) -> Self {
        self.key(0x10, key);
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(crate) fn i64(mut self, key: &str, value: i64) -> Self {
        self.key(0x12, key);
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(crate) fn bool(mut self, key: &str, value: bool) -> Self {
        self.key(0x08, key);
        self.0.push(u8::from(value));
        self
    }

    pub(crate) fn doc(mut self, key: &str, value: DocBuf) -> Self {
        self.key(0x03, key);
        self.0.extend_from_slice(&value.finish());
        self
    }

    pub(crate) fn array(mut self, key: &str, values: Vec<DocBuf>) -> Self {
        let mut array = DocBuf::new();
        for (i, v) in values.into_iter().enumerate() {
            array.key(0x03, &i.to_string());
            array.0.extend_from_slice(&v.finish());
        }
        self.key(0x04, key);
        self.0.extend_from_slice(&array.finish());
        self
    }

    pub(crate) fn array_i64(mut self, key: &str, values: &[i64]) -> Self {
        let mut array = DocBuf::new();
        for (i, v) in values.iter().enumerate() {
            array = array.i64(&i.to_string(), *v);
        }
        self.key(0x04, key);
        self.0.extend_from_slice(&array.finish());
        self
    }

    #[cfg(test)]
    pub(crate) fn array_str(mut self, key: &str, values: &[&str]) -> Self {
        let mut array = DocBuf::new();
        for (i, v) in values.iter().enumerate() {
            array = array.str(&i.to_string(), v);
        }
        self.key(0x04, key);
        self.0.extend_from_slice(&array.finish());
        self
    }

    /// UTC datetime (milliseconds since the epoch).
    pub(crate) fn date(mut self, key: &str, millis: i64) -> Self {
        self.key(0x09, key);
        self.0.extend_from_slice(&millis.to_le_bytes());
        self
    }

    /// Null.
    pub(crate) fn null(mut self, key: &str) -> Self {
        self.key(0x0A, key);
        self
    }

    /// An array whose elements are the elements of `items` (built with
    /// the keys `0`, `1`…), for mixed-type arrays (aggregation
    /// expressions).
    pub(crate) fn list(mut self, key: &str, items: DocBuf) -> Self {
        self.key(0x04, key);
        self.0.extend_from_slice(&items.finish());
        self
    }

    /// Generic binary (subtype 0).
    pub(crate) fn binary(mut self, key: &str, value: &[u8]) -> Self {
        self.key(0x05, key);
        let len = i32::try_from(value.len()).unwrap_or(i32::MAX);
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.push(0);
        self.0.extend_from_slice(value);
        self
    }

    /// Appends raw, already encoded BSON elements of another type (tests
    /// build replies with it).
    #[cfg(test)]
    pub(crate) fn raw(mut self, t: u8, key: &str, payload: &[u8]) -> Self {
        self.key(t, key);
        self.0.extend_from_slice(payload);
        self
    }

    /// The encoded document.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.0.push(0);
        let len = i32::try_from(self.0.len()).unwrap_or(i32::MAX);
        self.0[..4].copy_from_slice(&len.to_le_bytes());
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_of_the_written_types() {
        let bytes = DocBuf::new()
            .str("s", "abc")
            .i32("i", -7)
            .i64("l", 1 << 40)
            .bool("b", true)
            .doc("d", DocBuf::new().str("x", "y"))
            .array("a", vec![DocBuf::new().i32("n", 1), DocBuf::new()])
            .array_i64("ids", &[5, 6])
            .binary("bin", b"\x01\x02")
            .finish();
        let doc = Doc::new(&bytes).unwrap();
        assert_eq!(doc.str("s").unwrap(), Some("abc"));
        assert_eq!(doc.int("i").unwrap(), Some(-7));
        assert_eq!(doc.int("l").unwrap(), Some(1 << 40));
        assert_eq!(doc.flag("b").unwrap(), Some(true));
        assert_eq!(doc.doc("d").unwrap().unwrap().str("x").unwrap(), Some("y"));
        let a = doc.array("a").unwrap().unwrap();
        let items: Vec<_> = a.iter().map(Result::unwrap).collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, b"0");
        assert!(matches!(items[1].1, Value::Doc(_)));
        let ids = doc.array("ids").unwrap().unwrap();
        let ids: Vec<i64> = ids.iter().map(|e| e.unwrap().1.as_i64().unwrap()).collect();
        assert_eq!(ids, [5, 6]);
        assert!(matches!(
            doc.get("bin").unwrap(),
            Some(Value::Binary(0, b"\x01\x02"))
        ));
        assert!(doc.get("missing").unwrap().is_none());
    }

    #[test]
    fn every_type_is_decoded_or_skipped() {
        let mut regex = b"a.*\0i\0".to_vec();
        regex.shrink_to_fit();
        let scope = DocBuf::new().i32("x", 1).finish();
        let mut cws = Vec::new();
        let code = b"\x02\0\0\0f\0";
        let total = i32::try_from(4 + code.len() + scope.len()).unwrap();
        cws.extend_from_slice(&total.to_le_bytes());
        cws.extend_from_slice(code);
        cws.extend_from_slice(&scope);
        let mut dbp = b"\x02\0\0\0c\0".to_vec();
        dbp.extend_from_slice(&[7; 12]);
        let bytes = DocBuf::new()
            .raw(0x01, "double", &2.5f64.to_le_bytes())
            .raw(0x06, "undefined", &[])
            .raw(0x07, "oid", &[1; 12])
            .raw(0x09, "date", &86_400_000i64.to_le_bytes())
            .raw(0x0A, "null", &[])
            .raw(0x0B, "regex", &regex)
            .raw(0x0C, "dbpointer", &dbp)
            .raw(0x0D, "code", b"\x02\0\0\0f\0")
            .raw(0x0E, "symbol", b"\x04\0\0\0abc\0")
            .raw(0x0F, "cws", &cws)
            .raw(0x11, "ts", &[0; 8])
            .raw(0x13, "dec", &[0; 16])
            .raw(0xFF, "min", &[])
            .raw(0x7F, "max", &[])
            .finish();
        let doc = Doc::new(&bytes).unwrap();
        let kinds: Vec<String> = doc.iter().map(|e| format!("{:?}", e.unwrap().1)).collect();
        assert_eq!(
            kinds,
            [
                "Double",
                "Other",
                "Other",
                "Date",
                "Other",
                "Other",
                "Other",
                "Other",
                "Symbol",
                "Other",
                "Other",
                "Decimal128",
                "Other",
                "Other"
            ]
        );
    }

    #[test]
    fn malformed_documents_are_refused() {
        let good = DocBuf::new().str("k", "v").finish();
        assert!(Doc::new(&good).is_ok());
        // Wrong total length, missing terminator, trailing bytes.
        let mut bad = good.clone();
        bad[0] += 1;
        assert!(Doc::new(&bad).is_err());
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = 1;
        assert!(Doc::new(&bad).is_err());
        let mut bad = good.clone();
        bad.push(0);
        assert!(Doc::new(&bad).is_err());
        assert!(Doc::new(&[]).is_err());
        assert!(Doc::new(&[4, 0, 0, 0]).is_err());
        assert!(Doc::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0]).is_err());
        // A string length past the document.
        let mut bad = good.clone();
        bad[7] = 0x7F;
        assert!(Doc::new(&bad).unwrap().get("k").is_err());
        // An unknown type.
        let bad = DocBuf::new().raw(0x42, "k", &[]).finish();
        assert!(Doc::new(&bad).unwrap().get("k").is_err());
        // The iterator stops after its first error.
        let doc = Doc::new(&bad).unwrap();
        let items: Vec<_> = doc.iter().collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
        // A boolean that is neither 0 nor 1.
        let bad = DocBuf::new().raw(0x08, "b", &[2]).finish();
        assert!(Doc::new(&bad).unwrap().get("b").is_err());
    }

    #[test]
    fn debug_shows_no_content() {
        let bytes = DocBuf::new().str("email", "jane@example.com").finish();
        let doc = Doc::new(&bytes).unwrap();
        let text = format!("{doc:?} {:?}", doc.get("email").unwrap().unwrap());
        assert!(!text.contains("jane"), "{text}");
    }
}
