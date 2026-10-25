//! Fuzz target: `databastion_connector_firebird::fuzz::keys`, the wire-crypt key clumplets, the plugin choice (never Arc4) and the cipher it builds; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::keys(data);
});
