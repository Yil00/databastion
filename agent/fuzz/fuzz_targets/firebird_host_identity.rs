//! Fuzz target: `databastion_connector_firebird::fuzz::host_identity`, the identity files of the Firebird readers check (passwd, group, subuid, nsswitch, mountinfo; ADR-0060 refinement of 2026-10-31, R45 item 7 and R52 item 4): the mount entry found for an id is the only one with that id, or none; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::host_identity(data);
});
