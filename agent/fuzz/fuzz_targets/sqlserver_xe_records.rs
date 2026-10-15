//! Fuzz target: `databastion_connector_sqlserver::fuzz::xe_records`, the Extended Events record context pass and conversion (ADR-0051 decisions 1 and 6, refinement item 4), must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::xe_records(data);
});
