//! JSON values of an audit line read from the line's own bytes (ROADMAP
//! phase 8 follow-up: no unzeroized copy of a kept string).
//!
//! `serde_json` unescapes a string that holds an escape sequence (`\/`,
//! `A`…) into the deserializer's private scratch buffer, a plain
//! `Vec<u8>` that is reused, grown (leaving freed copies behind) and dropped
//! without being wiped, and that this crate cannot reach. The audit record
//! parser therefore never lets `serde_json` deserialize a kept string: every
//! kept key and value is taken as a [`RawValue`], which borrows the raw JSON
//! text from the caller's line (`serde_json` only *skips* it, without
//! copying a byte of it: its skip path validates the escapes in place), and
//! is unescaped here into a [`Zeroizing`] buffer allocated once at its final
//! capacity, so it never reallocates either.
//!
//! The caller holds the line itself in a zeroizing buffer (the core tailer's
//! `Zeroizing<Vec<u8>>` records). What `serde_json`'s scratch buffer still
//! receives while a line is parsed: the `[` / `{` nesting bytes of skipped
//! values, and nothing else (no number here is parsed as a float, the only
//! other use of that buffer).

use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// A kept JSON value: a string (unescaped, bounded, zeroized), an integer,
/// or anything else (`null`, a boolean, a float, an array, an object).
pub(crate) enum Scalar {
    /// A string, cut to the caller's bound on a character boundary.
    Str(Zeroizing<String>),
    /// An integer that fits an `i64`.
    Int(i64),
    /// Any other value (never examined further).
    Other,
}

/// Why a raw value was refused (an escape `serde_json` accepts when it
/// skips a string but refuses when it reads one: a lone surrogate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

/// Reads a raw value: a string is unescaped and cut to `max` bytes (the
/// whole string is still validated), an integer is parsed, anything else is
/// [`Scalar::Other`].
pub(crate) fn scalar(raw: &RawValue, max: usize) -> Result<Scalar, Invalid> {
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'"') => unescape(text, max).map(Scalar::Str),
        Some(b'-' | b'0'..=b'9') => Ok(text.parse::<i64>().map_or(Scalar::Other, Scalar::Int)),
        _ => Ok(Scalar::Other),
    }
}

/// The string of a raw value, or `None` for any other JSON type.
pub(crate) fn string(raw: &RawValue, max: usize) -> Result<Option<Zeroizing<String>>, Invalid> {
    Ok(match scalar(raw, max)? {
        Scalar::Str(s) => Some(s),
        Scalar::Int(_) | Scalar::Other => None,
    })
}

/// The four hexadecimal digits of a `\u` escape.
fn hex4(chars: &mut std::str::Chars<'_>) -> Result<u32, Invalid> {
    let mut n = 0u32;
    for _ in 0..4 {
        let d = chars.next().and_then(|c| c.to_digit(16)).ok_or(Invalid)?;
        n = (n << 4) | d;
    }
    Ok(n)
}

/// Unescapes a JSON string literal (`"…"`, quotes included, as
/// [`RawValue::get`] gives it) into a zeroizing buffer of at most `max`
/// bytes, cut on a character boundary like `bounded_owned`: the first
/// character that does not fit ends the copy, the rest is only validated.
/// The buffer is allocated once with a capacity no push can exceed (an
/// escape is never shorter than what it decodes to).
pub(crate) fn unescape(literal: &str, max: usize) -> Result<Zeroizing<String>, Invalid> {
    let inner = literal
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(Invalid)?;
    let mut out = Zeroizing::new(String::with_capacity(inner.len().min(max)));
    let mut full = false;
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        let c = match c {
            '\\' => match chars.next().ok_or(Invalid)? {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => {
                    let n = hex4(&mut chars)?;
                    match n {
                        0xD800..=0xDBFF => {
                            if chars.next() != Some('\\') || chars.next() != Some('u') {
                                return Err(Invalid);
                            }
                            let low = hex4(&mut chars)?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(Invalid);
                            }
                            char::from_u32(0x1_0000 + ((n - 0xD800) << 10) + (low - 0xDC00))
                                .ok_or(Invalid)?
                        }
                        0xDC00..=0xDFFF => return Err(Invalid),
                        _ => char::from_u32(n).ok_or(Invalid)?,
                    }
                }
                _ => return Err(Invalid),
            },
            // Never in a literal `serde_json` skipped successfully.
            '"' | '\u{0}'..='\u{1f}' => return Err(Invalid),
            c => c,
        };
        if !full {
            if out.len() + c.len_utf8() <= max {
                out.push(c);
            } else {
                full = true;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> Box<RawValue> {
        RawValue::from_string(json.to_owned()).unwrap()
    }

    #[test]
    fn strings_unescape_like_serde_json() {
        for (json, max) in [
            (r#""plain""#, 64),
            (r#""a\/b\\c\"d""#, 64),
            (r#""\b\f\n\r\t""#, 64),
            (r#""Aé€""#, 64),
            (r#""😀 smile""#, 64),
            (r#""https:\/\/app.example.org\/x?ticket=ST-1-FAKE""#, 64),
            (r#""é€😀""#, 64),
            (r#""""#, 64),
        ] {
            let ours = string(&raw(json), max).unwrap().unwrap();
            let theirs: String = serde_json::from_str(json).unwrap();
            assert_eq!(&*ours, &theirs, "{json}");
        }
    }

    #[test]
    fn strings_are_cut_on_a_boundary_but_fully_validated() {
        assert_eq!(&*unescape(r#""abcé""#, 4).unwrap(), "abc");
        assert_eq!(&*unescape(r#""abcé""#, 5).unwrap(), "abcé");
        assert_eq!(&*unescape(r#""abéc""#, 3).unwrap(), "ab");
        // A shorter character after the cut is not kept either.
        assert_eq!(&*unescape(r#""éa""#, 1).unwrap(), "");
        assert_eq!(unescape(r#""abc\ud800""#, 1), Err(Invalid));
    }

    #[test]
    fn the_buffer_never_grows() {
        for (json, max) in [
            (r#""ABC""#, 64),
            (r#""😀😀""#, 64),
            ("\"€€€€\"", 5),
            (r#""\/\/\/\/""#, 2),
        ] {
            let inner_len = json.len() - 2;
            let s = unescape(json, max).unwrap();
            let once = String::with_capacity(inner_len.min(max)).capacity();
            assert_eq!(s.capacity(), once, "{json}");
        }
    }

    #[test]
    fn invalid_escapes_are_refused() {
        for json in [
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800A""#,
            r#""\ud800x""#,
            r#""\x""#,
            r#""\u12""#,
            "\"a\u{1}\"",
            r#""a"b""#,
            "abc",
            "\"",
        ] {
            assert_eq!(unescape(json, 64), Err(Invalid), "{json}");
        }
    }

    #[test]
    fn other_values() {
        assert!(matches!(scalar(&raw("12"), 8), Ok(Scalar::Int(12))));
        assert!(matches!(scalar(&raw("-3"), 8), Ok(Scalar::Int(-3))));
        for json in [
            "1.5",
            "1e3",
            "18446744073709551615",
            "null",
            "true",
            "[1]",
            r#"{"a": "b"}"#,
        ] {
            assert!(matches!(scalar(&raw(json), 8), Ok(Scalar::Other)), "{json}");
        }
    }
}
