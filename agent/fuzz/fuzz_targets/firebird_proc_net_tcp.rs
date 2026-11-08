//! Fuzz target: `databastion_connector_firebird::fuzz::proc_net_tcp`, the /proc/net/tcp lookup of the peer-uid rule (decision 3, security review L1): the right row or none; must never panic nor hang on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_firebird::fuzz::proc_net_tcp(data);
});
