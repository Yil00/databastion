//! The committed `src/generated.rs` must match what the generator produces
//! from `shared/protocol/openapi.yaml` (invariant I6). Run by CI's
//! `cargo test`.

#![allow(clippy::unwrap_used, clippy::panic)]

use databastion_protocol_codegen::{default_openapi_path, generate_from_file};

#[test]
fn generated_code_matches_the_contract() {
    let expected = generate_from_file(&default_openapi_path()).unwrap();
    let committed =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated.rs")).unwrap();
    if committed != expected {
        panic!(
            "agent/crates/protocol/src/generated.rs is stale: it no longer matches \
             shared/protocol/openapi.yaml. Run `cargo run -p databastion-protocol-codegen` \
             from agent/ and commit the result."
        );
    }
}
