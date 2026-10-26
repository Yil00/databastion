//! Fuzz target: `databastion_connector_firebird::fuzz::srp_data`, the server's SRP data (salt, B) with its checks, and the client proof when accepted; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::srp_data(data);
});
