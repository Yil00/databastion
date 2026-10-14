//! Fuzz target: `databastion_connector_redis::fuzz::key_pattern`, the key-name normalizer (its output always passes the KeyPattern gate), the glob matcher and the CAS guard, must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_redis::fuzz::key_pattern(data);
});
