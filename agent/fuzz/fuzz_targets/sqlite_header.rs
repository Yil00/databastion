//! Fuzz target: `databastion_connector_sqlite::fuzz::header`, the Rust
//! SQLite header pre-check (ADR-0059 decision 2), must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlite::fuzz::header(data);
});
