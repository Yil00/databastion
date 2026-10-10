//! YAML service definitions (ADR-0041 decision 4, ADR-0046): an own
//! parser of the subset the pre-scan accepts, under
//! `#![forbid(unsafe_code)]`, with no YAML crate in the agent's CAS path.
//!
//! - `scan`: the pre-scan ([`prescan`]: refusals, blanking of class hints
//!   and credential values) and, in parse mode over the blanked copy,
//!   libyaml's tokens;
//! - `events`: libyaml's parser over those tokens, building the events of
//!   the one document;
//! - `de`: the `serde::Deserializer` over the events ([`Document`]), read
//!   by the closed visitor of `definition::parse_with`.
//!
//! The accepted subset, the refusals, the blanking and the values are
//! those of the previous `serde_yaml_ng` path: `serde_yaml_ng` 0.10 stays
//! a dev-dependency, the oracle of the differential property tests and of
//! the `cas_registry_yaml_diff` fuzz target.

mod de;
mod events;
mod scan;

pub use de::{Document, YamlError};
pub use scan::{
    MAX_CLASS_BYTES, MAX_FLOW_DEPTH, MAX_LINES, MAX_NESTING, MAX_TOKENS, Prescanned, Refusal,
    prescan,
};
