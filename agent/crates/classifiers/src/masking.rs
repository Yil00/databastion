//! Masking and fingerprinting of sampled values (ADR-0003).
//!
//! # Type boundary
//!
//! - [`RawSample`] wraps a value read from a target. It has a redacted
//!   `Debug`, no `Display`, no `Clone`, and no serialization: it cannot be
//!   logged or sent by accident.
//! - [`MaskedSample`], [`MaskedFinding`] and [`MaskedEvent`] have **private
//!   fields** and no public constructor taking a string. The only way to
//!   obtain a [`MaskedSample`] is [`mask`]; the only way to build a
//!   [`MaskedFinding`] is from [`MaskedSample`]s; [`MaskedEvent`] cannot be
//!   built yet. They deliberately implement neither `From<String>` nor
//!   `Deserialize`.
//! - The uplink (`databastion_core::uplink`) and the connector sinks only
//!   accept [`MaskedFinding`] / [`MaskedEvent`], so a connector cannot hand an
//!   unmasked value to them: the compiler rejects it.
//!
//! Skeleton status (P0-D): [`mask`] fully redacts its input (safe default).
//! Format-preserving masking and HMAC-SHA256 fingerprints with the
//! agent-local key are implemented in a later phase, with property tests.

use std::fmt;

/// Placeholder emitted by the skeleton [`mask`] implementation.
const FULLY_REDACTED: &str = "***";

/// A raw value sampled from a target. Never leaves the agent, never logged.
pub struct RawSample<'a>(&'a str);

impl<'a> RawSample<'a> {
    /// Wraps a value read from a target.
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self(value)
    }

    /// Exposes the raw value, for classifiers only. Never log the result.
    #[must_use]
    pub fn expose(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for RawSample<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawSample(<redacted>)")
    }
}

/// A sample that went through [`mask`]. Safe to send to the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedSample(String);

impl MaskedSample {
    /// The masked representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Masks a raw sample. The only constructor of [`MaskedSample`].
///
/// Skeleton: returns a fixed, fully redacted placeholder that reveals nothing
/// about the input (not even its length).
#[must_use]
pub fn mask(_raw: &RawSample<'_>) -> MaskedSample {
    MaskedSample(FULLY_REDACTED.to_owned())
}

/// A finding whose samples have all been masked. The only finding type the
/// uplink accepts.
///
/// It will wrap the finding type generated from `shared/protocol/openapi.yaml`
/// (P0-B) once available; protocol fields are not hand-written here (I6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedFinding {
    classifier: String,
    masked_samples: Vec<MaskedSample>,
}

impl MaskedFinding {
    /// Builds a finding from already-masked samples.
    ///
    /// `classifier` is a classifier identifier such as `pii.email`, never a
    /// sampled value.
    #[must_use]
    pub fn new(classifier: impl Into<String>, masked_samples: Vec<MaskedSample>) -> Self {
        Self {
            classifier: classifier.into(),
            masked_samples,
        }
    }

    /// Classifier identifier (e.g. `pii.email`).
    #[must_use]
    pub fn classifier(&self) -> &str {
        &self.classifier
    }

    /// Masked samples.
    #[must_use]
    pub fn masked_samples(&self) -> &[MaskedSample] {
        &self.masked_samples
    }
}

/// A normalized access event whose free-text parts (query text, filters,
/// literals) have been masked. The only event type the uplink accepts.
///
/// Skeleton: opaque and **not constructible yet**. Until event masking is
/// implemented, no access event can reach the uplink (safe by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedEvent {
    _private: (),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_sample_debug_is_redacted() {
        let raw = RawSample::new("jane.doe@example.com");
        let debug = format!("{raw:?}");
        assert!(!debug.contains("jane"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn mask_never_returns_the_raw_value() {
        for value in [
            "jane.doe@example.com",
            "FR7630006000011234567890189",
            "4111 1111 1111 1111",
        ] {
            let masked = mask(&RawSample::new(value));
            assert!(!masked.as_str().contains(value));
        }
    }

    #[test]
    fn mask_does_not_leak_length() {
        let short = mask(&RawSample::new("a"));
        let long = mask(&RawSample::new("a-much-longer-secret-value"));
        assert_eq!(short, long);
    }

    #[test]
    fn masked_finding_debug_contains_no_raw_value() {
        let raw = RawSample::new("jane.doe@example.com");
        let finding = MaskedFinding::new("pii.email", vec![mask(&raw)]);
        assert_eq!(finding.classifier(), "pii.email");
        assert_eq!(finding.masked_samples().len(), 1);
        assert!(!format!("{finding:?}").contains("jane.doe"));
    }
}
