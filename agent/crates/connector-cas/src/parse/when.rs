//! The `when` field of a CAS audit record (ADR-0041 decision 7).
//!
//! The exact JSON rendering of Inspektr's `whenActionWasPerformed` in CAS
//! 8.0 is to verify; these forms are accepted, every other one drops the
//! record:
//! - epoch milliseconds (a JSON integer of at least 10^11) or seconds;
//! - ISO 8601 `YYYY-MM-DD[T ]HH:MM:SS[.fraction][Z|±HH:MM|±HHMM]`, read in
//!   the declared zone when it has no offset;
//! - Java's `Date.toString()` (`EEE MMM dd HH:mm:ss zzz yyyy`) with the
//!   zone `UTC` or `GMT` only (other abbreviations are ambiguous).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::UtcOffset;

/// Epoch values at or above this are milliseconds.
const MILLIS_FROM: i64 = 100_000_000_000;
/// Latest year accepted.
const MAX_YEAR: i64 = 9999;

/// Days from 1970-01-01 to a civil date (proleptic Gregorian; Howard
/// Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Seconds since the epoch of a civil time, `None` when out of range.
fn epoch(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let valid = (1970..=MAX_YEAR).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=days_in_month(y, mo)).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..=60).contains(&s);
    valid.then(|| days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

fn to_time(secs: i64, nanos: u32) -> Option<SystemTime> {
    let secs = u64::try_from(secs).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

/// An epoch number: milliseconds from [`MILLIS_FROM`], else seconds.
#[must_use]
pub fn from_epoch(n: i64) -> Option<SystemTime> {
    if n < 0 {
        return None;
    }
    if n >= MILLIS_FROM {
        let ms = u32::try_from(n % 1000).ok()?;
        to_time(n / 1000, ms * 1_000_000)
    } else {
        to_time(n, 0)
    }
}

fn num(b: &[u8]) -> Option<i64> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// `±HH:MM`, `±HHMM` or `Z`, in seconds.
fn offset(b: &[u8]) -> Option<i64> {
    match b {
        b"Z" | b"z" => Some(0),
        [sign, h1, h2, b':', m1, m2] | [sign, h1, h2, m1, m2] => {
            let h = num(&[*h1, *h2])?;
            let m = num(&[*m1, *m2])?;
            if h > 18 || m > 59 {
                return None;
            }
            let secs = h * 3600 + m * 60;
            match sign {
                b'+' => Some(secs),
                b'-' => Some(-secs),
                _ => None,
            }
        }
        _ => None,
    }
}

fn iso(s: &[u8], zone: UtcOffset) -> Option<SystemTime> {
    // YYYY-MM-DD?HH:MM:SS
    let head = s.get(..19)?;
    let [
        y1,
        y2,
        y3,
        y4,
        b'-',
        mo1,
        mo2,
        b'-',
        d1,
        d2,
        sep,
        h1,
        h2,
        b':',
        mi1,
        mi2,
        b':',
        s1,
        s2,
    ] = *head
    else {
        return None;
    };
    if sep != b'T' && sep != b' ' {
        return None;
    }
    let mut secs = epoch(
        num(&[y1, y2, y3, y4])?,
        num(&[mo1, mo2])?,
        num(&[d1, d2])?,
        num(&[h1, h2])?,
        num(&[mi1, mi2])?,
        num(&[s1, s2])?,
    )?;
    let mut rest = s.get(19..)?;
    let mut nanos = 0u32;
    if let Some(frac) = rest.strip_prefix(b".").or_else(|| rest.strip_prefix(b",")) {
        let n = frac.iter().take_while(|b| b.is_ascii_digit()).count();
        if n == 0 || n > 9 {
            return None;
        }
        let digits = frac.get(..n)?;
        let mut v = u32::try_from(num(digits)?).ok()?;
        for _ in n..9 {
            v *= 10;
        }
        nanos = v;
        rest = frac.get(n..)?;
    }
    let off = if rest.is_empty() {
        i64::from(zone.0)
    } else {
        offset(rest)?
    };
    secs -= off;
    to_time(secs, nanos)
}

const MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const DAYS: [&[u8]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];

/// `EEE MMM dd HH:mm:ss zzz yyyy`, zone `UTC` or `GMT`.
fn java_date(s: &[u8]) -> Option<SystemTime> {
    let parts: Vec<&[u8]> = s.split(|b| *b == b' ').collect();
    let [day, mon, dd, hms, zone, year] = parts.as_slice() else {
        return None;
    };
    if !DAYS.contains(day) || !(*zone == b"UTC" || *zone == b"GMT") {
        return None;
    }
    let mo = MONTHS.iter().position(|m| m == mon)?;
    let [h1, h2, b':', m1, m2, b':', s1, s2] = **hms else {
        return None;
    };
    if dd.len() != 2 || year.len() != 4 {
        return None;
    }
    let secs = epoch(
        num(year)?,
        i64::try_from(mo).ok()? + 1,
        num(dd)?,
        num(&[h1, h2])?,
        num(&[m1, m2])?,
        num(&[s1, s2])?,
    )?;
    to_time(secs, 0)
}

/// Parses a textual `when` (see the module documentation).
#[must_use]
pub fn parse_when(s: &str, zone: UtcOffset) -> Option<SystemTime> {
    let b = s.trim().as_bytes();
    if b.len() > 64 {
        return None;
    }
    if !b.is_empty() && b.iter().all(u8::is_ascii_digit) {
        return from_epoch(num(b)?);
    }
    iso(b, zone).or_else(|| java_date(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(t: SystemTime) -> u64 {
        t.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    // 2026-10-04T12:00:00Z
    const T: u64 = 1_791_115_200;

    #[test]
    fn accepted_forms() {
        let utc = UtcOffset(0);
        for s in [
            "2026-10-04T12:00:00Z",
            "2026-10-04T12:00:00.123Z",
            "2026-10-04 12:00:00",
            "2026-10-04T14:00:00+02:00",
            "2026-10-04T14:00:00+0200",
            "2026-10-04T07:30:00,5-04:30",
            "Sun Oct 04 12:00:00 UTC 2026",
            "Sun Oct 04 12:00:00 GMT 2026",
            "1791115200",
            "1791115200000",
        ] {
            assert_eq!(parse_when(s, utc).map(secs), Some(T), "{s}");
        }
        assert_eq!(
            parse_when("2026-10-04T14:00:00", UtcOffset(7200)).map(secs),
            Some(T)
        );
        assert_eq!(from_epoch(1_791_115_200_123).map(secs), Some(T));
    }

    #[test]
    fn refused_forms() {
        let utc = UtcOffset(0);
        for s in [
            "",
            "2026-13-04T12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2026-10-04T24:00:00Z",
            "2026-10-04T12:00:00+19:00",
            "2026-10-04T12:00:00.Z",
            "2026-10-04T12:00:00.1234567890Z",
            "2026-10-04T12:00:00 junk",
            "Sun Oct 04 12:00:00 CEST 2026",
            "Fun Oct 04 12:00:00 UTC 2026",
            "1969-12-31T23:59:59Z",
            "99999999999999999999999",
            "２０２６-10-04T12:00:00Z",
        ] {
            assert_eq!(parse_when(s, utc), None, "{s}");
        }
        assert_eq!(from_epoch(-1), None);
        assert!(parse_when("2024-02-29T00:00:00Z", utc).is_some());
        assert!(parse_when("2100-02-29T00:00:00Z", utc).is_none());
    }
}
