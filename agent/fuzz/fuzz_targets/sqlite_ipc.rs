//! Fuzz target: `databastion_connector_sqlite::fuzz::ipc`, both decoders of
//! the reader IPC and its frame assembler (ADR-0059 decision 4), must never
//! panic nor allocate past their bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlite::fuzz::ipc(data);
});
