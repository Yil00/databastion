//! Decoding of sampled values from their binary wire format, in Rust
//! (ADR-0012 obligation 3: no cast or function applied to a sampled column
//! on the server).
//!
//! Only types that can hold the data the classifiers look for are sampled:
//! character types (`text`, `varchar`, `bpchar`, `name`, `citext` from the
//! `citext` extension), `json` / `jsonb`, `int4` / `int8` / `numeric`
//! (phone or card numbers stored as numbers) and `date` (birth dates), and
//! domains over them (one level). Other columns (booleans, timestamps,
//! binary, arrays, geometric, user-defined types) are not selected at all.
//!
//! Values are truncated to [`MAX_VALUE_BYTES`] and wrapped in
//! `RawValue` (zeroized on drop) by the caller. A value that fails to
//! decode is skipped, never logged.

use std::error::Error;

use tokio_postgres::types::{FromSql, Type};

/// Longest value handed to the classifiers, in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 4096;

/// Builtin type oids (`pg_type.dat`, stable across releases).
mod oid {
    pub(super) const NAME: u32 = 19;
    pub(super) const INT8: u32 = 20;
    pub(super) const INT4: u32 = 23;
    pub(super) const TEXT: u32 = 25;
    pub(super) const JSON: u32 = 114;
    pub(super) const BPCHAR: u32 = 1042;
    pub(super) const VARCHAR: u32 = 1043;
    pub(super) const DATE: u32 = 1082;
    pub(super) const NUMERIC: u32 = 1700;
    pub(super) const JSONB: u32 = 3802;
}

/// How a sampled column is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decoder {
    Text,
    Bpchar,
    Json,
    Jsonb,
    Int4,
    Int8,
    Numeric,
    Date,
}

impl Decoder {
    /// The decoder of a column type, from the catalog: `typtype` `d` is a
    /// domain over `base`. `None`: the column is not sampled.
    pub(crate) fn for_type(type_oid: u32, typtype: u8, base: u32, is_citext: bool) -> Option<Self> {
        if is_citext {
            return Some(Self::Text);
        }
        let oid = if typtype == b'd' { base } else { type_oid };
        Some(match oid {
            oid::TEXT | oid::VARCHAR | oid::NAME => Self::Text,
            oid::BPCHAR => Self::Bpchar,
            oid::JSON => Self::Json,
            oid::JSONB => Self::Jsonb,
            oid::INT4 => Self::Int4,
            oid::INT8 => Self::Int8,
            oid::NUMERIC => Self::Numeric,
            oid::DATE => Self::Date,
            _ => return None,
        })
    }

    /// Decodes one non-NULL binary value. `None`: not decodable (skipped).
    pub(crate) fn decode(self, raw: &[u8]) -> Option<String> {
        let s = match self {
            Self::Text | Self::Json => utf8(raw)?,
            Self::Bpchar => utf8(raw)?.trim_end_matches(' ').to_owned(),
            Self::Jsonb => match raw.split_first() {
                Some((1, rest)) => utf8(rest)?,
                _ => return None,
            },
            Self::Int4 => i32::from_be_bytes(raw.try_into().ok()?).to_string(),
            Self::Int8 => i64::from_be_bytes(raw.try_into().ok()?).to_string(),
            Self::Numeric => numeric(raw)?,
            Self::Date => date(i32::from_be_bytes(raw.try_into().ok()?))?,
        };
        (!s.is_empty()).then(|| truncate(s))
    }
}

fn utf8(raw: &[u8]) -> Option<String> {
    let raw = &raw[..floor_boundary(raw, MAX_VALUE_BYTES)];
    std::str::from_utf8(raw).ok().map(str::to_owned)
}

/// Largest `n <= max` that does not split a UTF-8 sequence of `raw`.
fn floor_boundary(raw: &[u8], max: usize) -> usize {
    if raw.len() <= max {
        return raw.len();
    }
    let mut n = max;
    while n > 0 && (raw[n] & 0xC0) == 0x80 {
        n -= 1;
    }
    n
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_VALUE_BYTES {
        let n = floor_boundary(s.as_bytes(), MAX_VALUE_BYTES);
        s.truncate(n);
    }
    s
}

/// Binary `numeric`: `ndigits`, `weight`, `sign`, `dscale` (i16 / u16 big
/// endian), then `ndigits` base-10000 digits. NaN and infinities are
/// skipped.
fn numeric(raw: &[u8]) -> Option<String> {
    let word = |i: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*raw.get(2 * i)?, *raw.get(2 * i + 1)?]))
    };
    let ndigits = usize::from(word(0)?);
    let weight = i64::from(i16::from_be_bytes(word(1)?.to_be_bytes()));
    let sign = word(2)?;
    let dscale = usize::from(word(3)?);
    if raw.len() != 8 + 2 * ndigits {
        return None;
    }
    let neg = match sign {
        0x0000 => false,
        0x4000 => true,
        _ => return None,
    };
    // Bounded output: at most MAX_VALUE_BYTES characters.
    let max_groups = (MAX_VALUE_BYTES / 4) as i64;
    if weight > max_groups || weight < -max_groups || dscale > MAX_VALUE_BYTES {
        return None;
    }
    let digit = |k: i64| -> u16 {
        usize::try_from(k)
            .ok()
            .filter(|k| *k < ndigits)
            .and_then(|k| word(4 + k))
            .unwrap_or(0)
    };
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if weight < 0 {
        out.push('0');
    } else {
        for k in 0..=weight {
            let d = digit(k);
            if d > 9999 {
                return None;
            }
            if k == 0 {
                out.push_str(&d.to_string());
            } else {
                out.push_str(&format!("{d:04}"));
            }
        }
    }
    if dscale > 0 {
        let mut frac = String::with_capacity(dscale + 4);
        let mut k = weight + 1;
        while frac.len() < dscale {
            let d = digit(k);
            if d > 9999 {
                return None;
            }
            frac.push_str(&format!("{d:04}"));
            k += 1;
        }
        frac.truncate(dscale);
        out.push('.');
        out.push_str(&frac);
    }
    Some(out)
}

/// Binary `date`: days since 2000-01-01; `YYYY-MM-DD` for years 1..=9999,
/// `None` otherwise (infinities, BC dates).
fn date(days_since_2000: i32) -> Option<String> {
    // Days since 1970-01-01, then Howard Hinnant's `civil_from_days`.
    let z = i64::from(days_since_2000) + 10_957 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (1..=9999)
        .contains(&y)
        .then(|| format!("{y:04}-{m:02}-{d:02}"))
}

/// A column value as sent by the server (binary format), borrowed from
/// the row. Accepts every type: the decoder comes from the catalog.
pub(crate) struct WireBytes<'a>(pub(crate) &'a [u8]);

impl<'a> FromSql<'a> for WireBytes<'a> {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Self(raw))
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

/// A text / `name` column of a catalog row. `Ok(None)` for NULL or for
/// bytes that are not UTF-8 (a `SQL_ASCII` database can hold any bytes in
/// names): the caller skips that row instead of failing the scan (L1).
pub(crate) fn catalog_text(
    row: &tokio_postgres::Row,
    i: usize,
) -> Result<Option<String>, tokio_postgres::Error> {
    Ok(row
        .try_get::<_, Option<WireBytes<'_>>>(i)?
        .and_then(|WireBytes(raw)| std::str::from_utf8(raw).ok().map(str::to_owned)))
}

impl std::fmt::Debug for WireBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WireBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_bytes(weight: i16, sign: u16, dscale: u16, digits: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u16::try_from(digits.len()).unwrap().to_be_bytes());
        v.extend_from_slice(&weight.to_be_bytes());
        v.extend_from_slice(&sign.to_be_bytes());
        v.extend_from_slice(&dscale.to_be_bytes());
        for d in digits {
            v.extend_from_slice(&d.to_be_bytes());
        }
        v
    }

    #[test]
    fn types_are_selected_from_the_catalog() {
        assert_eq!(Decoder::for_type(25, b'b', 0, false), Some(Decoder::Text));
        assert_eq!(Decoder::for_type(1082, b'b', 0, false), Some(Decoder::Date));
        // Domain over varchar.
        assert_eq!(
            Decoder::for_type(90_000, b'd', 1043, false),
            Some(Decoder::Text)
        );
        // citext (extension type, dynamic oid).
        assert_eq!(
            Decoder::for_type(90_001, b'b', 0, true),
            Some(Decoder::Text)
        );
        // bool, timestamptz, bytea, int2, text[]: not sampled.
        for o in [16, 1184, 17, 21, 1009] {
            assert_eq!(Decoder::for_type(o, b'b', 0, false), None);
        }
    }

    #[test]
    fn text_types() {
        assert_eq!(Decoder::Text.decode(b"a@b.example").unwrap(), "a@b.example");
        assert_eq!(Decoder::Bpchar.decode(b"FR  ").unwrap(), "FR");
        assert_eq!(
            Decoder::Jsonb.decode(b"\x01{\"a\":1}").unwrap(),
            "{\"a\":1}"
        );
        assert!(Decoder::Jsonb.decode(b"\x02{}").is_none());
        assert!(Decoder::Text.decode(b"\xff\xfe").is_none());
        assert!(Decoder::Text.decode(b"").is_none());
        let long = "é".repeat(MAX_VALUE_BYTES);
        let out = Decoder::Text.decode(long.as_bytes()).unwrap();
        assert!(out.len() <= MAX_VALUE_BYTES && out.chars().all(|c| c == 'é'));
    }

    #[test]
    fn integers() {
        assert_eq!(
            Decoder::Int4
                .decode(&612_345_678_i32.to_be_bytes())
                .unwrap(),
            "612345678"
        );
        assert_eq!(
            Decoder::Int8
                .decode(&4_111_111_111_111_111_i64.to_be_bytes())
                .unwrap(),
            "4111111111111111"
        );
        assert_eq!(Decoder::Int4.decode(&(-5_i32).to_be_bytes()).unwrap(), "-5");
        assert!(Decoder::Int4.decode(&[0, 1]).is_none());
    }

    #[test]
    fn numerics() {
        // 4111111111111111 = 4111 1111 1111 1111, weight 3.
        let n = numeric_bytes(3, 0, 0, &[4111, 1111, 1111, 1111]);
        assert_eq!(Decoder::Numeric.decode(&n).unwrap(), "4111111111111111");
        // 12.5 = 12 . 5000, dscale 1.
        let n = numeric_bytes(0, 0, 1, &[12, 5000]);
        assert_eq!(Decoder::Numeric.decode(&n).unwrap(), "12.5");
        // -0.0012 (weight -1: first digit is 0012), dscale 4.
        let n = numeric_bytes(-1, 0x4000, 4, &[12]);
        assert_eq!(Decoder::Numeric.decode(&n).unwrap(), "-0.0012");
        // 10000 = digit 1 at weight 1 (trailing zero groups omitted).
        let n = numeric_bytes(1, 0, 0, &[1]);
        assert_eq!(Decoder::Numeric.decode(&n).unwrap(), "10000");
        // 0
        assert_eq!(
            Decoder::Numeric
                .decode(&numeric_bytes(0, 0, 0, &[]))
                .unwrap(),
            "0"
        );
        // NaN, +inf, truncated, bad digit.
        assert!(
            Decoder::Numeric
                .decode(&numeric_bytes(0, 0xC000, 0, &[]))
                .is_none()
        );
        assert!(
            Decoder::Numeric
                .decode(&numeric_bytes(0, 0xD000, 0, &[]))
                .is_none()
        );
        assert!(
            Decoder::Numeric
                .decode(&numeric_bytes(0, 0, 0, &[1])[..9])
                .is_none()
        );
        assert!(
            Decoder::Numeric
                .decode(&numeric_bytes(0, 0, 0, &[10_000]))
                .is_none()
        );
        assert!(
            Decoder::Numeric
                .decode(&numeric_bytes(i16::MAX, 0, 0, &[1]))
                .is_none()
        );
    }

    #[test]
    fn dates() {
        assert_eq!(date(0).unwrap(), "2000-01-01");
        assert_eq!(date(-1).unwrap(), "1999-12-31");
        assert_eq!(date(59).unwrap(), "2000-02-29");
        assert_eq!(date(8_780).unwrap(), "2024-01-15");
        // 1951-01-15
        assert_eq!(date(-17_883).unwrap(), "1951-01-15");
        assert!(date(i32::MAX).is_none());
        assert!(date(i32::MIN).is_none());
        assert_eq!(
            Decoder::Date.decode(&0_i32.to_be_bytes()).unwrap(),
            "2000-01-01"
        );
    }
}
