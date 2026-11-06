//! Fuzz target: `databastion_connector_sqlite::fuzz::file`: a hostile
//! SQLite file and its `-wal`, `-shm` and `-journal` files (length-prefixed
//! parts) through the reader's pipeline must never panic nor hang (ADR-0059
//! decision 5). The bundled SQLite runs in this process here; in the agent
//! it runs only in the sandboxed reader process.
//!
//! A WAL file set runs twice: with nobody holding the `-shm` `DMS` lock (the
//! heap copy of the WAL index), then with a helper process holding it (the
//! reliable `-shm` path, as when the application's writer is open). The
//! helper is this binary started again with `DATABASTION_FUZZ_SHM_HELPER`
//! set: `init` makes it the helper before libFuzzer starts, and it exits
//! when this process ends (the end of its standard input), however it ends.
#![no_main]

use std::sync::{Mutex, OnceLock};

use databastion_connector_sqlite::fuzz::{self, ShmHelper};
use libfuzzer_sys::fuzz_target;

fn helper() -> &'static Mutex<ShmHelper> {
    static HELPER: OnceLock<Mutex<ShmHelper>> = OnceLock::new();
    HELPER.get_or_init(|| {
        let exe = std::env::current_exe().expect("the fuzz target's own binary");
        Mutex::new(ShmHelper::start(std::process::Command::new(exe)))
    })
}

fuzz_target!(
    init: fuzz::shm_helper_if_requested(),
    |data: &[u8]| {
        let mut h = helper().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        fuzz::file(data, Some(&mut h));
    }
);
