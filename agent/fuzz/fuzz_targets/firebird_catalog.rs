//! Fuzz target: `databastion_connector_firebird::fuzz::catalog`, Discovery's reads (ADR-0060 decision 5): rows of the relation list, the column list or a sampling statement through the catalog parsing, the conversions, the column batches, the built statements and the sampled values kept or dropped; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::catalog(data);
});
