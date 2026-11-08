//! Fuzz target: `databastion_connector_firebird::fuzz::messages`, the server messages of the closed set (op_accept*, op_response and its status vector, op_cont_auth, op_fetch_response) in a phase chosen by the first byte, fed slice by slice; every step must make progress (ADR-0060 decision 1); must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::messages(data);
});
