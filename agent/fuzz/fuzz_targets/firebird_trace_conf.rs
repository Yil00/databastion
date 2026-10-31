//! Fuzz target: `databastion_connector_firebird::fuzz::trace_conf`, the Firebird configuration files (firebird.conf, databases.conf, the trace configuration and its proofs; decision 6, R2): must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::trace_conf(data);
});
