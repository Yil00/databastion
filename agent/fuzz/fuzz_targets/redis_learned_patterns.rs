//! Fuzz target: `databastion_connector_redis::fuzz::learned_patterns` (ADR-0052 decision 8), must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_redis::fuzz::learned_patterns(data);
});
