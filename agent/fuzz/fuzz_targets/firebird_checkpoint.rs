//! Fuzz target: `databastion_connector_firebird::fuzz::checkpoint`, the Firebird Audit parser checkpoint (ADR-0060 R25 items 7 and 9): the checkpoint body, the persisted ledger, the envelope and the parser state restored into a stream; must never panic nor hang, a refused body keeps nothing, and a restored state restores to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::checkpoint(data);
});
