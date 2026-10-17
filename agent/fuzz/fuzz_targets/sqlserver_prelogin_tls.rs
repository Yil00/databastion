//! Fuzz target: `databastion_connector_sqlserver::fuzz::prelogin_tls_framing`, the TLS-in-PRELOGIN packet header check, and `prelogin_wrap`, the `PreloginWrap` read / write state machine driven over an in-memory duplex stream by the input, must never panic nor hang on any input (ADR-0051 decision 1, obligation L1; P9-A lot 1 re-review R5).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::prelogin_tls_framing(data);
    let _ = databastion_connector_sqlserver::fuzz::prelogin_wrap(data);
});
