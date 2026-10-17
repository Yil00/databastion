//! Fuzz target: `databastion_connector_sqlserver::fuzz::plp`, PLP reassembly of an nvarchar(max) column, chunk by chunk under its cap, must never panic nor hang on any input (ADR-0051 decision 1, obligation L1).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::plp(data);
});
