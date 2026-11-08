//! Fuzz target: `databastion_connector_firebird::fuzz::trace_log`, the Firebird system audit trace log (decision 6, "Parsing a hostile text log"): records assembled, parsed under both name-line grammars, converted and made events; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::trace_log(data);
});
