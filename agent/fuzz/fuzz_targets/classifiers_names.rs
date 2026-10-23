//! Fuzz target: `databastion_classifiers::names::fuzz_normalize`, the name normalizers (`normalize_path`, `normalize_field_path`, `normalize_ldap_dn`, `normalize_ldap_attribute`): never panic nor hang, and every name they emit is `*` or matches the contract `IdentifierProduced` (ADR-0057 decision 1), else the target panics.
#![no_main]

use databastion_classifiers::names;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for n in names::fuzz_normalize(data) {
        let s = n.as_str();
        assert!(names::is_identifier_produced(s), "{s:?}");
        assert!(s.chars().count() <= names::MAX_IDENTIFIER_CHARS);
    }
});
