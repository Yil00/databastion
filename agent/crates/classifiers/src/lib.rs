//! Sensitive data classifiers and masking for the DataBastion agent.
//!
//! This crate is the **only** place where a raw value read from a target can
//! be turned into something that may leave the agent (invariant I2,
//! ADR-0003). See [`masking`] for the type boundary that enforces it.
//!
//! - [`id`]: the frozen classifier ids and [`id::CLASSIFIERS_VERSION`];
//! - [`column`]: column-level classification (name + bounded sample);
//! - [`detect`], [`validate`], [`hints`]: detectors, checksums, name hints;
//! - [`masking`]: masked samples, HMAC-SHA256 fingerprints, uplink types;
//! - [`names`]: name normalization (ADR-0009).
//!
//! See `README.md` for the classifier list and the masking formats.

#![forbid(unsafe_code)]

pub mod column;
pub mod detect;
pub mod hints;
pub mod id;
pub mod masking;
pub mod names;
pub mod validate;
