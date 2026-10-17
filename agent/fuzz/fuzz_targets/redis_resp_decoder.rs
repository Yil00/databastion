//! Fuzz target: `databastion_connector_redis::fuzz::resp_decoder`, the reply decoder (every request's limits, arbitrary chunking), must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_redis::fuzz::resp_decoder(data);
});
