//! Shape guards on the committed generated code (text-level, like
//! `crates/agent/tests/architecture.rs`):
//! - every struct with named fields has `#[serde(deny_unknown_fields)]` (I2:
//!   `additionalProperties: false`);
//! - no struct with fields derives `Default`, and no `impl Default` exists
//!   (a protocol value is always built explicitly);
//! - no conversion from a generated type into a masked type can live here.

#![allow(clippy::unwrap_used)]

const GENERATED: &str = include_str!("../src/generated.rs");

/// `(attributes above the item, item line)` for every `pub struct`.
fn structs() -> Vec<(String, String)> {
    let lines: Vec<&str> = GENERATED.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with("pub struct ") {
            continue;
        }
        let mut attrs = Vec::new();
        let mut j = i;
        while j > 0 {
            j -= 1;
            let prev = lines[j];
            // Attributes (possibly multi-line derives) sit right above the
            // item; doc comments and the previous item end the block.
            if prev.starts_with("///") || prev.starts_with("*/") || prev.starts_with('}') {
                break;
            }
            attrs.push(prev);
        }
        out.push((attrs.join("\n"), (*line).to_owned()));
    }
    assert!(out.len() > 30, "struct discovery looks broken");
    out
}

#[test]
fn every_object_struct_denies_unknown_fields() {
    for (attrs, item) in structs() {
        let has_named_fields = item.trim_end().ends_with('{');
        if has_named_fields {
            assert!(
                attrs.contains("deny_unknown_fields"),
                "{item} lacks #[serde(deny_unknown_fields)]"
            );
        }
    }
}

#[test]
fn no_default_on_data_structs() {
    for (attrs, item) in structs() {
        let empty = item.trim_end().ends_with("{}");
        if !empty {
            assert!(!attrs.contains("Default"), "{item} derives Default");
        }
    }
    assert!(
        !GENERATED.contains("Default for"),
        "generated code implements Default"
    );
}

#[test]
fn protocol_crate_does_not_know_masked_types() {
    let manifest = include_str!("../Cargo.toml");
    for forbidden in ["databastion-classifiers", "databastion-core"] {
        assert!(
            !manifest.contains(forbidden),
            "protocol depends on {forbidden}"
        );
    }
    for forbidden in ["databastion_classifiers", "masking::"] {
        assert!(
            !GENERATED.contains(forbidden),
            "generated code mentions {forbidden}"
        );
    }
}
