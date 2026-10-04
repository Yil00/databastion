//! Property tests of the CAS ticket-id tripwire (ADR-0041 decision 5,
//! PR #141 review M4 / L1): the verdict agrees with reference regular
//! expressions on any input, every value built on a named prefix drops the
//! column, an embedded named ticket id is never kept, and screening keeps
//! exactly the clean values.

#![allow(clippy::unwrap_used)]

use databastion_classifiers::cas::{Verdict, is_ticket_id, screen, verdict};
use databastion_classifiers::masking::RawSample;
use proptest::prelude::*;
use std::sync::LazyLock;

const NAMED: &str = "(TGT|ST|PT|PGT|PGTIOU|OC|AT|RT|CT|TST)";

fn reference(v: &str) -> Verdict {
    // Leading white space skipped; the letter run is maximal (`XTGT-1-`
    // is not a `TGT` ticket at the start); `\d` read as ASCII digits.
    static RE: LazyLock<[regex::Regex; 3]> = LazyLock::new(|| {
        [
            regex::Regex::new(&format!(r"^\s*{NAMED}-[0-9]+-")).unwrap(),
            regex::Regex::new(r"^\s*[A-Z]{2,8}-[0-9]+-").unwrap(),
            regex::Regex::new(&format!(r"{NAMED}-[0-9]+-")).unwrap(),
        ]
    });
    let [column, generic, embedded] = &*RE;
    if column.is_match(v) {
        Verdict::Column
    } else if generic.is_match(v) || embedded.is_match(v) {
        Verdict::Value
    } else {
        Verdict::Clean
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn agrees_with_the_reference(v in "\\PC{0,24}") {
        prop_assert_eq!(verdict(&RawSample::new(&v)), reference(&v));
    }

    #[test]
    fn agrees_on_near_misses(v in "[ \t]{0,2}[A-Za-z]{1,9}-?[0-9x]{0,3}-?[A-Za-z0-9-]{0,8}") {
        prop_assert_eq!(verdict(&RawSample::new(&v)), reference(&v));
    }

    #[test]
    fn every_named_prefix_drops_the_column(
        prefix in NAMED,
        n in 0u64..u64::MAX,
        rest in "\\PC{0,64}",
    ) {
        let v = format!("{prefix}-{n}-{rest}");
        prop_assert_eq!(verdict(&RawSample::new(&v)), Verdict::Column);
    }

    #[test]
    fn an_embedded_ticket_id_is_never_kept(
        before in "\\PC{0,32}",
        prefix in NAMED,
        n in 0u64..u64::MAX,
        rest in "\\PC{0,32}",
    ) {
        let v = format!("{before}{prefix}-{n}-{rest}");
        prop_assert!(is_ticket_id(&RawSample::new(&v)));
    }

    #[test]
    fn screening_keeps_exactly_the_clean_values(vals in proptest::collection::vec(
        prop_oneof!["\\PC{0,16}", "[A-Z]{2,8}-[0-9]{1,3}-[a-z]{0,4}", "x?(ST|TGT)-1-y"], 0..12)
    ) {
        let raw: Vec<RawSample<'_>> = vals.iter().map(|v| RawSample::new(v)).collect();
        let s = screen(&raw);
        let column = vals.iter().any(|v| reference(v) == Verdict::Column);
        prop_assert_eq!(s.column_dropped, column);
        let clean = vals.iter().filter(|v| reference(v) == Verdict::Clean).count();
        if column {
            prop_assert!(s.kept.is_empty());
            prop_assert_eq!(s.values_dropped, vals.len());
        } else {
            prop_assert_eq!(s.kept.len(), clean);
            prop_assert_eq!(s.values_dropped, vals.len() - clean);
            prop_assert!(s.kept.iter().all(|k| !is_ticket_id(k)));
        }
    }
}
