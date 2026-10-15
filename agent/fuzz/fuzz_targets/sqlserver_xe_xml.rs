//! Fuzz target: `databastion_connector_sqlserver::fuzz::xe_event_xml`, the bounded Extended Events event XML reader (ADR-0051 decision 6), must never panic and keep only bounded, closed fields.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::xe_event_xml(data);
});
