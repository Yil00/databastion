//! CAS ticket-id value tripwire (ADR-0041 decision 5, security review M9
//! and the PR #141 review M4 / L1).
//!
//! A CAS ticket id (`TGT-12-…`, `ST-3-…`, `PT-…`, `PGT-…`, `PGTIOU-…`,
//! `OC-…`, `AT-…`, `RT-…`) is a live bearer credential: it is never
//! classified, masked, fingerprinted nor logged. The shared sampling path
//! of every connector (`ScanJob::classify` in the agent core) screens each
//! column's values with [`screen`] **before** classification:
//!
//! - a value that **starts** with a named CAS ticket prefix
//!   ([`TICKET_PREFIXES`], then `-`, digits, `-`) is a ticket id: the whole
//!   column or field is dropped ([`Verdict::Column`]) and not read further
//!   in the scan;
//! - a value that only has the generic shape `^[A-Z]{2,8}-[0-9]+-` (an
//!   unknown or renamed prefix, or an unrelated identifier such as
//!   `INV-2026-…`), or that **contains** a named prefix anywhere
//!   (`…?ticket=ST-1-…`, a JSON document, a quoted value), is dropped on
//!   its own ([`Verdict::Value`]): never classified, masked nor
//!   fingerprinted (whole-value analyzers never see it), only counted; the
//!   rest of the column is classified as usual.
//!
//! Leading white space is skipped before the anchored tests (a padded
//! `CHAR` column must not hide a ticket id). Residuals (documented in
//! docs/08): a ticket id under a prefix outside the list and outside the
//! generic shape is classified like any value; values that merely share
//! the generic shape are lost to classification.

use crate::masking::RawSample;

/// Named CAS ticket prefixes: ADR-0041 decision 5 (`TGT`, `ST`, `PT`,
/// `PGT`, `OC`, `AT`, `RT`), plus the proxy-granting ticket IOU
/// (`PGTIOU`), the transient session ticket (`TST`) and `CT` (to verify
/// against CAS 8.0).
pub const TICKET_PREFIXES: &[&str] = &[
    "TGT", "ST", "PT", "PGT", "PGTIOU", "OC", "AT", "RT", "CT", "TST",
];

/// Shortest and longest prefix of the generic shape.
const GENERIC_LETTERS: std::ops::RangeInclusive<usize> = 2..=8;

/// What the tripwire decides for one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not a ticket id: classified as usual.
    Clean,
    /// Ticket-id-shaped or holding a ticket id: this value is dropped,
    /// the rest of the column is classified.
    Value,
    /// A ticket id under a named prefix: the whole column is dropped.
    Column,
}

/// The tripwire's verdict on one value. The value is only inspected,
/// never copied.
#[must_use]
pub fn verdict(raw: &RawSample<'_>) -> Verdict {
    verdict_of(raw.expose())
}

/// Whether a value is dropped by the tripwire (either verdict).
#[must_use]
pub fn is_ticket_id(raw: &RawSample<'_>) -> bool {
    verdict(raw) != Verdict::Clean
}

/// The values of one column after the tripwire.
#[derive(Debug)]
pub struct Screened<'a> {
    /// A named ticket id was seen: nothing of the column is classified.
    pub column_dropped: bool,
    /// Values dropped one by one ([`Verdict::Value`]); with
    /// `column_dropped`, every value.
    pub values_dropped: usize,
    /// The values left to classify (empty when `column_dropped`).
    pub kept: Vec<RawSample<'a>>,
}

/// Screens a column's values (see the module documentation).
#[must_use]
pub fn screen<'a>(values: &[RawSample<'a>]) -> Screened<'a> {
    let mut kept = Vec::with_capacity(values.len());
    let mut values_dropped = 0usize;
    for v in values {
        match verdict(v) {
            Verdict::Clean => kept.push(RawSample::new(v.expose())),
            Verdict::Value => values_dropped += 1,
            Verdict::Column => {
                return Screened {
                    column_dropped: true,
                    values_dropped: values.len(),
                    kept: Vec::new(),
                };
            }
        }
    }
    Screened {
        column_dropped: false,
        values_dropped,
        kept,
    }
}

/// [`verdict`] on text (crate tests, property tests and
/// [`crate::names`]).
#[must_use]
pub fn verdict_of(value: &str) -> Verdict {
    let t = value.trim_start();
    if let Some(letters) = shape_prefix(t) {
        if TICKET_PREFIXES.contains(&&t[..letters]) {
            return Verdict::Column;
        }
        if GENERIC_LETTERS.contains(&letters) {
            return Verdict::Value;
        }
    }
    if contains_named(value) {
        return Verdict::Value;
    }
    Verdict::Clean
}

/// Whether `text` starts with `[A-Z]+-[0-9]+-`; the number of letters.
fn shape_prefix(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let letters = b.iter().take_while(|c| c.is_ascii_uppercase()).count();
    if letters == 0 || b.get(letters) != Some(&b'-') {
        return None;
    }
    let digits = b[letters + 1..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    (digits > 0 && b.get(letters + 1 + digits) == Some(&b'-')).then_some(letters)
}

/// Whether `text` contains `(TGT|ST|…)-[0-9]+-` anywhere (unanchored).
fn contains_named(text: &str) -> bool {
    let b = text.as_bytes();
    // Every `-[0-9]+-`, then the letters just before it.
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == b'-') {
        let dash = i + off;
        let digits = b[dash + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits > 0 && b.get(dash + 1 + digits) == Some(&b'-') {
            let before = &b[..dash];
            if TICKET_PREFIXES
                .iter()
                .any(|p| before.ends_with(p.as_bytes()))
            {
                return true;
            }
        }
        i = dash + 1;
    }
    false
}

/// Where the first ticket id of a **name** starts (a column, a field path,
/// a MongoDB key, an LDAP DN; PR #141 review M3): a named prefix
/// (`TGT-1-…`) anywhere, or the generic shape `[A-Z]{2,8}-<digits>-` at the
/// start or after a character that is not an ASCII letter or digit. The
/// name normalizers mask from there to the end of the name (a ticket id's
/// suffix may hold dots).
#[must_use]
pub(crate) fn ticket_start_in_name(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut first: Option<usize> = None;
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == b'-') {
        let dash = i + off;
        i = dash + 1;
        let digits = b[dash + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 || b.get(dash + 1 + digits) != Some(&b'-') {
            continue;
        }
        let before = &b[..dash];
        let named = TICKET_PREFIXES
            .iter()
            .filter(|p| before.ends_with(p.as_bytes()))
            .map(|p| dash - p.len())
            .min();
        let run = before
            .iter()
            .rev()
            .take_while(|c| c.is_ascii_uppercase())
            .count();
        let run_start = dash - run;
        let generic = (GENERIC_LETTERS.contains(&run)
            && (run_start == 0 || !b[run_start - 1].is_ascii_alphanumeric()))
        .then_some(run_start);
        if let Some(start) = named.into_iter().chain(generic).min() {
            first = Some(first.map_or(start, |f: usize| f.min(start)));
            // Occurrences are met in order of their dash: no later one can
            // start before this one's letters.
            break;
        }
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_ticket_ids_drop_the_column() {
        for v in [
            "TGT-1-abcdef-cas01",
            "ST-12-Zx9q-cas",
            "PT-3-x",
            "PGT-44-y",
            "PGTIOU-4-z",
            "OC-5-code",
            "AT-6-token",
            "RT-7-refresh",
            "CT-8-x",
            "TST-9-x",
            "  TGT-9-padded",
            "\tST-1-",
        ] {
            assert_eq!(verdict_of(v), Verdict::Column, "{v}");
            assert!(is_ticket_id(&RawSample::new(v)), "{v}");
        }
    }

    #[test]
    fn generic_shapes_and_embedded_tickets_drop_the_value() {
        for v in [
            "ABCD-0-",
            "INV-2026-0001",
            "ABCDEFGH-1-x",
            "XTGT-1-x",
            "https://app.example.org/?ticket=ST-1-abc",
            "{\"what\":\"TGT-9-xyz\"}",
            "'PGTIOU-3-q'",
            "x TGT-1-y",
        ] {
            assert_eq!(verdict_of(v), Verdict::Value, "{v}");
        }
    }

    #[test]
    fn other_values_are_clean() {
        for v in [
            "",
            "TGT",
            "TGT-",
            "TGT-1",
            "TGT--1-",
            "TGT-x-1",
            "T-1-x",
            "ABCDEFGHI-1-x",
            "tgt-1-x",
            "Tgt-1-x",
            "jane.doe@example.org",
            "FR76 3000 6000 0112 3456 7890 189",
            "ST-١-x",
            "2026-10-04",
        ] {
            assert_eq!(verdict_of(v), Verdict::Clean, "{v}");
        }
    }

    #[test]
    fn screening_keeps_only_clean_values() {
        let vals = ["a@example.org", "INV-1-x", "b@example.org"];
        let raw: Vec<RawSample<'_>> = vals.iter().map(|v| RawSample::new(v)).collect();
        let s = screen(&raw);
        assert!(!s.column_dropped);
        assert_eq!(s.values_dropped, 1);
        let kept: Vec<&str> = s.kept.iter().map(RawSample::expose).collect();
        assert_eq!(kept, ["a@example.org", "b@example.org"]);

        let vals = ["a@example.org", "TGT-1-x"];
        let raw: Vec<RawSample<'_>> = vals.iter().map(|v| RawSample::new(v)).collect();
        let s = screen(&raw);
        assert!(s.column_dropped);
        assert!(s.kept.is_empty());
    }

    #[test]
    fn ticket_ids_are_found_in_names() {
        assert_eq!(ticket_start_in_name("TGT-1-x"), Some(0));
        assert_eq!(
            ticket_start_in_name("sessions.TGT-1-x.cas01.example"),
            Some(9)
        );
        assert_eq!(ticket_start_in_name("aST-1-x"), Some(1));
        assert_eq!(ticket_start_in_name("by_ABCD-12-x"), Some(3));
        assert_eq!(ticket_start_in_name("xABCD-12-x"), None);
        assert_eq!(ticket_start_in_name("orders.3.email"), None);
        assert_eq!(ticket_start_in_name("created-2026-10"), None);
    }
}
