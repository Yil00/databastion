//! Fuzz target: `databastion_connector_sqlserver::fuzz::tsql`, the T-SQL analysis of SQL Server Audit statement texts, must never panic and keeps password-bearing statements to their class (ADR-0051 decision 1 and 6).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_connector_sqlserver::fuzz::tsql(data);
});
