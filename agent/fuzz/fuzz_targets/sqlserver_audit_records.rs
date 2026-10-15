//! Fuzz target: `databastion_connector_sqlserver::fuzz::audit_records`, the SQL Server Audit record reassembly, grouping and conversion, must never panic (ADR-0051 decision 1 and 6, obligation L1).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::audit_records(data);
});
