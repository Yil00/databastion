//! Fuzz target: `databastion_connector_sqlite::fuzz::file`: a hostile
//! SQLite file and its `-wal`, `-shm` and `-journal` files (length-prefixed
//! parts) through the reader's pipeline must never panic nor hang (ADR-0059
//! decision 5). The bundled SQLite runs in this process here; in the agent
//! it runs only in the sandboxed reader process.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlite::fuzz::file(data);
});
