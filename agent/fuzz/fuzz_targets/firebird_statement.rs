//! Fuzz target: `databastion_classifiers::query::firebird::analyze_firebird`, the Firebird mode of the statement analysis (ADR-0060 decision 6): any text, lexed and analyzed; must never panic nor hang, and a password-bearing text keeps no name.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let a = databastion_classifiers::query::firebird::analyze_firebird(text);
        if a.credential {
            assert!(a.relations.is_empty() && a.procedures.is_empty());
        }
    }
});
