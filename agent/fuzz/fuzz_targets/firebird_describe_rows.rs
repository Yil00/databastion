//! Fuzz target: `databastion_connector_firebird::fuzz::describe_and_rows`, the describe answer of op_prepare_statement (an info buffer) and rows of the described columns (null bitmap, bounded values); must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::describe_and_rows(data);
});
