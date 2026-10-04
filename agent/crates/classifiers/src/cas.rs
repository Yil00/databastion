//! CAS ticket-id value tripwire (ADR-0041 decision 5, security review M9).
//!
//! A CAS ticket id (`TGT-12-…`, `ST-3-…`, `PT-…`, `PGT-…`, `OC-…`, `AT-…`,
//! `RT-…`) is a live bearer credential: it is never classified, masked,
//! fingerprinted nor logged. The shared sampling path of every connector
//! (`ScanJob::classify` in the agent core) asks [`is_ticket_id`] about each
//! value **before** classification; one match drops the whole column or
//! field for the rest of the scan.
//!
//! The pattern is the ADR's `^(TGT|ST|PT|PGT|OC|AT|RT|[A-Z]{2,4})-\d+-`,
//! i.e. two to four ASCII capital letters, a hyphen, at least one digit and
//! a hyphen. Leading white space is skipped first (a padded `CHAR` column
//! must not hide a ticket id). Unrelated identifiers of the same shape
//! (`INV-2024-…`) match too: that over-exclusion is accepted.

use crate::masking::RawSample;

/// Whether a sampled value has the shape of a CAS ticket id. The value is
/// only inspected, never copied.
#[must_use]
pub fn is_ticket_id(raw: &RawSample<'_>) -> bool {
    looks_like_ticket_id(raw.expose())
}

/// [`is_ticket_id`] on text (crate tests and property tests).
#[must_use]
pub(crate) fn looks_like_ticket_id(value: &str) -> bool {
    let mut bytes = value.trim_start().bytes().peekable();
    let mut letters = 0usize;
    while let Some(b) = bytes.peek() {
        if !b.is_ascii_uppercase() {
            break;
        }
        letters += 1;
        if letters > 4 {
            return false;
        }
        bytes.next();
    }
    if letters < 2 || bytes.next() != Some(b'-') {
        return false;
    }
    let mut digits = 0usize;
    for b in bytes {
        match b {
            b'0'..=b'9' => digits += 1,
            b'-' => return digits > 0,
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_ids_match() {
        for v in [
            "TGT-1-abcdef-cas01",
            "ST-12-Zx9q-cas",
            "PT-3-x",
            "PGT-44-y",
            "OC-5-code",
            "AT-6-token",
            "RT-7-refresh",
            "ABCD-0-",
            "  TGT-9-padded",
            "\tST-1-",
        ] {
            assert!(looks_like_ticket_id(v), "{v}");
            assert!(is_ticket_id(&RawSample::new(v)), "{v}");
        }
    }

    #[test]
    fn other_values_do_not_match() {
        for v in [
            "",
            "TGT",
            "TGT-",
            "TGT-1",
            "TGT--1-",
            "TGT-x-1",
            "T-1-x",
            "ABCDE-1-x",
            "tgt-1-x",
            "Tgt-1-x",
            "jane.doe@example.org",
            "FR76 3000 6000 0112 3456 7890 189",
            "ST-١-x",
            "x TGT-1-y",
        ] {
            assert!(!looks_like_ticket_id(v), "{v}");
        }
    }
}
