//! Property tests of the CAS ticket-id tripwire (ADR-0041 decision 5): the
//! predicate agrees with the ADR's pattern on any input, and every value
//! built on a ticket-id prefix trips it whatever follows.

#![allow(clippy::unwrap_used)]

use databastion_classifiers::cas::is_ticket_id;
use databastion_classifiers::masking::RawSample;
use proptest::prelude::*;

fn adr_pattern() -> regex::Regex {
    // ADR-0041 decision 5, after the leading white space the predicate
    // skips; `\d` read as ASCII digits.
    regex::Regex::new(r"^\s*(TGT|ST|PT|PGT|OC|AT|RT|[A-Z]{2,4})-[0-9]+-").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn agrees_with_the_adr_pattern(v in "\\PC{0,24}") {
        prop_assert_eq!(is_ticket_id(&RawSample::new(&v)), adr_pattern().is_match(&v));
    }

    #[test]
    fn agrees_on_near_misses(v in "[ \t]{0,2}[A-Za-z]{1,5}-?[0-9x]{0,3}-?[A-Za-z0-9-]{0,8}") {
        prop_assert_eq!(is_ticket_id(&RawSample::new(&v)), adr_pattern().is_match(&v));
    }

    #[test]
    fn every_ticket_prefix_trips(
        prefix in "(TGT|ST|PT|PGT|OC|AT|RT|[A-Z]{2,4})",
        n in 0u64..u64::MAX,
        rest in "\\PC{0,64}",
    ) {
        let v = format!("{prefix}-{n}-{rest}");
        prop_assert!(is_ticket_id(&RawSample::new(&v)));
    }
}
