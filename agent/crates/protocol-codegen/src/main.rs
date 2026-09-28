//! Writes `crates/protocol/src/generated.rs` from `shared/protocol/openapi.yaml`.
//!
//! Usage (from `agent/`): `cargo run -p databastion-protocol-codegen`.

#![forbid(unsafe_code)]

use databastion_protocol_codegen::{
    CodegenError, default_openapi_path, default_output_path, generate_from_file,
};

fn main() -> Result<(), CodegenError> {
    let source = generate_from_file(&default_openapi_path())?;
    let output = default_output_path();
    std::fs::write(&output, source).map_err(|source| CodegenError::Io {
        path: output,
        source,
    })
}
