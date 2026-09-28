//! Sensitive data classifiers and masking for the DataBastion agent.
//!
//! This crate is the **only** place where a raw value read from a target can
//! be turned into something that may leave the agent (invariant I2,
//! ADR-0003). See [`masking`] for the type boundary that enforces it.
//!
//! Skeleton status (P0-D): no classifier is implemented yet.

#![forbid(unsafe_code)]

pub mod masking;
