//! JSON values read from the caller's own bytes, without an unzeroized
//! copy of a kept string (ROADMAP phase 8 follow-ups). Shared by the
//! connectors that parse JSON holding credentials or statement texts: the
//! CAS audit record and service-definition parsers, and the MySQL / MariaDB
//! JSON audit-log records. It lives in the core because both connectors
//! already depend on it (and on `serde_json`), and it is not a classifier
//! nor a masking function (`databastion-classifiers` has no JSON parser).
//!
//! `serde_json` unescapes a string that holds an escape sequence (`\/`,
//! `\u0041`…) into the deserializer's private scratch buffer, a plain
//! `Vec<u8>` that is reused, grown (leaving freed copies behind) and dropped
//! without being wiped, and that no caller can reach. A parser built on
//! this module therefore never lets `serde_json` deserialize a kept string:
//! every kept key and value is taken as a [`RawValue`], which borrows the
//! raw JSON text from the caller's buffer (`serde_json` only *skips* it,
//! without copying a byte of it: its skip path validates the escapes in
//! place), and is unescaped here into a [`Zeroizing`] buffer allocated once
//! at its final capacity, so it never reallocates either.
//!
//! The caller holds the input itself in a zeroizing buffer. What
//! `serde_json`'s scratch buffer still receives while a value is parsed:
//! the `[` / `{` nesting bytes of skipped values, and nothing else (no
//! number is parsed as a float here, the only other use of that buffer).
//!
//! `serde_json`'s skip path is more lenient than its typed path: a lone
//! surrogate escape (`\ud800`) or an out-of-range number in a *skipped*
//! value is accepted. A kept string with a lone surrogate is refused here
//! ([`Invalid`]), as `serde_json` would refuse it.

use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// A kept JSON value: a string (unescaped, bounded, zeroized), an integer,
/// or anything else (`null`, a boolean, a float, an array, an object).
pub enum Scalar {
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
pub struct Invalid;

/// Reads a raw value: a string is unescaped and cut to `max` bytes (the
/// whole string is still validated), an integer is parsed, anything else is
/// [`Scalar::Other`].
pub fn scalar(raw: &RawValue, max: usize) -> Result<Scalar, Invalid> {
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'"') => unescape(text, max).map(Scalar::Str),
        Some(b'-' | b'0'..=b'9') => Ok(text.parse::<i64>().map_or(Scalar::Other, Scalar::Int)),
        _ => Ok(Scalar::Other),
    }
}

/// The string of a raw value, or `None` for any other JSON type.
pub fn string(raw: &RawValue, max: usize) -> Result<Option<Zeroizing<String>>, Invalid> {
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
pub fn unescape(literal: &str, max: usize) -> Result<Zeroizing<String>, Invalid> {
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

/// An unsigned integer value, as `serde_json` reads one into a `u64`: only
/// digits (no sign, fraction nor exponent: those are floats or negative
/// for `serde_json`), and within range. `None` for anything else.
#[must_use]
pub fn unsigned(raw: &RawValue) -> Option<u64> {
    let text = raw.get();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Whether a raw value is JSON `null`.
#[must_use]
pub fn is_null(raw: &RawValue) -> bool {
    raw.get() == "null"
}

/// The values of `keys` in one JSON object, borrowed from `json` (one JSON
/// value, surrounding white space allowed): `Ok(None)` when it is not an
/// object, `Err` when it is not valid JSON or a key does not unescape.
/// Keys are compared after unescaping (`"a\u0062"` is `ab`); a repeated
/// key keeps its last value, as `serde_json::Value` does. Every other value
/// is skipped (borrowed, never copied nor unescaped).
///
/// # Errors
/// [`Invalid`]: not JSON, or an invalid escape in a key.
pub fn object<'a, const N: usize>(
    json: &'a str,
    keys: &[&str; N],
) -> Result<Option<[Option<&'a RawValue>; N]>, Invalid> {
    let raw: &'a RawValue = serde_json::from_str(json).map_err(|_| Invalid)?;
    let text = raw.get();
    if !text.starts_with('{') {
        return Ok(None);
    }
    let mut de = serde_json::Deserializer::from_str(text);
    let fields =
        serde::Deserializer::deserialize_map(&mut de, Fields { keys }).map_err(|_| Invalid)?;
    Ok(Some(fields))
}

/// Reads an object's kept values (see [`object`]).
struct Fields<'k, const N: usize> {
    keys: &'k [&'k str; N],
}

impl<'de, const N: usize> serde::de::Visitor<'de> for Fields<'_, N> {
    type Value = [Option<&'de RawValue>; N];

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = [None; N];
        // A longer key cannot match: it is validated but not kept. The cut
        // keeps a whole character past the longest kept key (a character
        // is at most 4 bytes), so a longer key is always cut to more bytes
        // than any kept key and never to one of them (`useré` is not cut
        // back to `user`).
        let max = self.keys.iter().map(|k| k.len()).max().unwrap_or(0) + 4;
        while let Some(k) = map.next_key::<&'de RawValue>()? {
            let v = map.next_value::<&'de RawValue>()?;
            let name = unescape(k.get(), max)
                .map_err(|_| <A::Error as serde::de::Error>::custom("invalid key"))?;
            if let Some(slot) = self
                .keys
                .iter()
                .position(|w| *w == name.as_str())
                .and_then(|i| out.get_mut(i))
            {
                *slot = Some(v);
            }
        }
        Ok(out)
    }
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

    #[test]
    fn unsigned_reads_what_serde_json_reads_as_u64() {
        for json in ["0", "11", "18446744073709551615", "4294967296"] {
            let theirs: Option<u64> = serde_json::from_str(json).ok();
            assert_eq!(unsigned(&raw(json)), theirs, "{json}");
        }
        for json in [
            "-1",
            "-0",
            "1.0",
            "1e2",
            "18446744073709551616",
            "\"1\"",
            "null",
        ] {
            assert!(serde_json::from_str::<u64>(json).is_err(), "{json}");
            assert_eq!(unsigned(&raw(json)), None, "{json}");
        }
    }

    #[test]
    fn objects_keep_the_last_value_of_a_key() {
        let json = r#" {"a": 1, "b": "x\/y", "a\u0062": [1, {"c": 2}], "a": "last", "z": null} "#;
        let [a, b, ab, missing] = object(json, &["a", "b", "ab", "missing"]).unwrap().unwrap();
        assert_eq!(a.unwrap().get(), r#""last""#);
        assert_eq!(b.unwrap().get(), r#""x\/y""#);
        assert_eq!(ab.unwrap().get(), r#"[1, {"c": 2}]"#);
        assert!(missing.is_none());
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(value["a"], "last");
        // Not an object, not JSON, an invalid key escape.
        assert!(object("[1]", &["a"]).unwrap().is_none());
        assert!(object(r#""a""#, &["a"]).unwrap().is_none());
        assert!(object("{", &["a"]).is_err());
        assert!(object(r#"{"a": 1} x"#, &["a"]).is_err());
        assert!(object(r#"{"\ud800": 1}"#, &["a"]).is_err());
        assert!(is_null(&raw("null")) && !is_null(&raw("0")));
    }

    #[test]
    fn a_longer_key_is_never_cut_back_to_a_kept_one() {
        let [user] = object(r#"{"user":"real","useré":"alias"}"#, &["user"])
            .unwrap()
            .unwrap();
        assert_eq!(user.unwrap().get(), r#""real""#);
        for suffix in ["é", "€", "😀", "\\u00e9", "\\ud83d\\ude00"] {
            let json = format!(r#"{{"program_name":"real","program_name{suffix}":"alias"}}"#);
            let [name] = object(&json, &["program_name"]).unwrap().unwrap();
            assert_eq!(name.unwrap().get(), r#""real""#, "{json}");
        }
    }

    mod props {
        use super::object;
        use proptest::prelude::*;

        fn wide_char() -> impl Strategy<Value = char> {
            prop_oneof![
                proptest::char::range('a', 'z'),
                proptest::char::range('\u{80}', '\u{7ff}'),
                proptest::char::range('\u{800}', '\u{d7ff}'),
                proptest::char::range('\u{e000}', '\u{ffff}'),
                proptest::char::range('\u{10000}', '\u{10ffff}'),
            ]
        }

        proptest! {
            /// A kept key followed by any characters is never read as a
            /// kept key, whatever the characters' widths.
            #[test]
            fn suffixed_keys_never_alias(
                kept in proptest::collection::vec("[a-z_]{1,16}", 1..4),
                pick in any::<prop::sample::Index>(),
                suffix in proptest::collection::vec(wide_char(), 1..4),
            ) {
                let base = pick.get(&kept);
                let suffix: String = suffix.into_iter().collect();
                let alias = format!("{base}{suffix}");
                let json = serde_json::json!({ alias.as_str(): "alias" }).to_string();
                let keys: [&str; 3] = std::array::from_fn(|i| kept.get(i).map_or("", String::as_str));
                let got = object(&json, &keys).unwrap().unwrap();
                for (k, v) in keys.iter().zip(got) {
                    prop_assert!(v.is_none() || *k == alias, "{}", json);
                }
            }
        }
    }
}
