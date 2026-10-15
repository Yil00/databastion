//! Fuzz target: `databastion_connector_sqlserver::fuzz::prelogin_tls_framing`, the TLS-in-PRELOGIN packet header check, must never panic nor hang on any input (ADR-0051 decision 1, obligation L1).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::prelogin_tls_framing(data);
});
