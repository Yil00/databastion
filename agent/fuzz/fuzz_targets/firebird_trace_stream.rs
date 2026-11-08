//! Fuzz target: `databastion_connector_firebird::fuzz::trace_stream`, the Firebird Audit stream's multi-record state machine (ADR-0060 R1, R5, R7, R25, R29; review L1 of P10-F): records assembled from the input and pushed, with clock steps and run changes, into one stream with a fixed catalog and ledger; no record may panic and the state must stay within every cap.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::trace_stream(data);
});
