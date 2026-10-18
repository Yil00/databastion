//! Fuzz target: `databastion_core::audit::tail::fuzz::splitter`, the CSV splitter of the log-file
//! Audit sources over csvlog records quoted as PostgreSQL writes them (#267 review L3): aligned
//! input gives exactly the records with no realignment, a first start anywhere in a record
//! exactly the records after it, a record cut inside a quoted field only that record lost, and a
//! record bound never a forged record. An oracle that fails panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    databastion_core::audit::tail::fuzz::splitter(data);
});
