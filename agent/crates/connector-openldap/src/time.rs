//! LDAP time values (Generalized Time, CSNs), without a date library.
//!
//! - `reqStart` / `reqEnd`: `YYYYMMDDHHMMSS[.ffffff]Z` (UTC).
//! - `entryCSN`: `YYYYMMDDHHMMSS.ffffffZ#cccccc#sid#mmmmmm`; CSNs of one
//!   server compare as strings in time order.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date of a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn digits(s: &str) -> Option<i64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// A UTC Generalized Time (`YYYYMMDDHHMMSS[.f…]Z`, years 1970 to 9999).
pub(crate) fn parse_generalized(s: &str) -> Option<SystemTime> {
    // ASCII only: the byte offsets below are then character boundaries
    // (a log value is server input).
    if !s.is_ascii() {
        return None;
    }
    let body = s.strip_suffix('Z')?;
    let (whole, fraction) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    if whole.len() != 14 {
        return None;
    }
    let (y, mo, d) = (
        digits(whole.get(0..4)?)?,
        digits(whole.get(4..6)?)?,
        digits(whole.get(6..8)?)?,
    );
    let (h, mi, se) = (
        digits(whole.get(8..10)?)?,
        digits(whole.get(10..12)?)?,
        digits(whole.get(12..14)?)?,
    );
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    let micros = match fraction {
        Some(f) if !f.is_empty() && f.len() <= 9 => {
            let v = digits(f)?;
            let scale = 10i64.pow(6u32.saturating_sub(u32::try_from(f.len()).ok()?));
            if f.len() > 6 {
                v / 10i64.pow(u32::try_from(f.len() - 6).ok()?)
            } else {
                v * scale
            }
        }
        Some(_) => return None,
        None => 0,
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se;
    let secs = u64::try_from(secs).ok()?;
    let micros = u64::try_from(micros).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros))
}

/// The CSN of an instant (`…Z#000000#000#000000`): a bound for `entryCSN`
/// filters, never a real CSN.
pub(crate) fn csn_at(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = i64::try_from(d.as_secs()).unwrap_or(0);
    let (y, m, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{day:02}{:02}{:02}{:02}.{:06}Z#000000#000#000000",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60,
        d.subsec_micros()
    )
}

/// Whether `s` has the form of an OpenLDAP CSN.
pub(crate) fn valid_csn(s: &str) -> bool {
    // `YYYYMMDDHHMMSS.ffffffZ#cccccc#sid#mmmmmm`, byte by byte.
    const SHAPE: &[u8; 40] = b"dddddddddddddd.ddddddZ#xxxxxx#xxx#xxxxxx";
    let b = s.as_bytes();
    b.len() == SHAPE.len()
        && b.iter().zip(SHAPE).all(|(c, k)| match k {
            b'd' => c.is_ascii_digit(),
            b'x' => c.is_ascii_hexdigit(),
            k => c == k,
        })
}

/// The time part of a CSN.
pub(crate) fn csn_time(csn: &str) -> Option<SystemTime> {
    valid_csn(csn)
        .then(|| csn.get(..22).and_then(parse_generalized))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_times() {
        let t = parse_generalized("20260929202642.000001Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_secs(1_790_713_602) + Duration::from_micros(1)
        );
        assert_eq!(parse_generalized("19700101000000Z").unwrap(), UNIX_EPOCH);
        assert!(parse_generalized("20261329000000Z").is_none());
        assert!(parse_generalized("2026092920264Z").is_none());
        assert!(parse_generalized("20260929202642").is_none());
        assert!(parse_generalized("20260929202642.Z").is_none());
        assert!(parse_generalized("+0260929202642Z").is_none());
        // Non-ASCII of the right byte length never panics (security review
        // H1: `é` straddles byte 4).
        assert!(parse_generalized("202é092920264Z").is_none());
        assert!(parse_generalized("20260929é0264Z").is_none());
        assert!(parse_generalized("20260929202642.é1Z").is_none());
    }

    #[test]
    fn csns_round_trip_and_order() {
        let t = parse_generalized("20260929202642.012954Z").unwrap();
        let csn = csn_at(t);
        assert_eq!(csn, "20260929202642.012954Z#000000#000#000000");
        assert!(valid_csn(&csn));
        assert_eq!(csn_time(&csn), Some(t));
        assert!(valid_csn("20260929202647.299090Z#000000#000#000000"));
        assert!(!valid_csn("20260929202647.299090Z#00000g#000#000000"));
        assert!(!valid_csn("x"));
        assert!(csn_at(t + Duration::from_secs(1)) > csn);
        // Civil conversions agree both ways over a wide range.
        for days in [-1, 0, 59, 60, 365, 11_016, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
