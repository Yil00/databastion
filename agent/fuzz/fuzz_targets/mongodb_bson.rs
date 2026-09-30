//! Fuzz target: `databastion_connector_mongodb::fuzz::bson` must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_mongodb::fuzz::bson(data);
});
