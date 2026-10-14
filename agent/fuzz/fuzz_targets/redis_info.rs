//! Fuzz target: `databastion_connector_redis::fuzz::info`, the INFO section parsers, must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_redis::fuzz::info(data);
});
