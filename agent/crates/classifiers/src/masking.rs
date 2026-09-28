//! Masking and fingerprinting of sampled values (ADR-0003).
//!
//! # Type boundary
//!
//! - [`RawSample`] wraps a value read from a target. It has a redacted
//!   `Debug`, no `Display`, no `Clone`, and no serialization: it cannot be
//!   logged or sent by accident.
//! - [`ClassifierId`], [`MaskedSample`], [`MaskedFinding`] and
//!   [`MaskedEvent`] have **private fields** and no public constructor taking
//!   a string. [`ClassifierId`] is a closed set owned by this crate; the only
//!   way to obtain a [`MaskedSample`] is [`mask`]; a [`MaskedFinding`] is
//!   built only from a [`ClassifierId`] and [`MaskedSample`]s;
//!   [`MaskedEvent`] cannot be built yet. None holds a caller-provided
//!   `String`, and none implements `From<String>` or `Deserialize`
//!   (compile-fail doctests below prove it).
//! - The core uplink (crate-private in `databastion-core`) and the connector
//!   sinks only
//!   accept [`MaskedFinding`] / [`MaskedEvent`], so a connector cannot hand an
//!   unmasked value to them: the compiler rejects it.
//!
//! Skeleton status (P0-D): [`mask`] fully redacts its input (safe default).
//! Format-preserving masking and HMAC-SHA256 fingerprints with the
//! agent-local key are implemented in a later phase, with property tests.

use std::fmt;

use crate::names::NormalizedName;

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

    /// Exposes the raw value, inside this crate only (classifiers and
    /// masking). Never log the result.
    #[must_use]
    #[allow(dead_code, reason = "used by classifiers once they are implemented")]
    pub(crate) fn expose(&self) -> &'a str {
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

/// Identifier of a classifier (e.g. `pii.email`).
///
/// Closed set: only this crate can create one, from a `&'static str` it
/// owns. A connector can therefore not smuggle a sampled value into a
/// finding through the classifier name. It deliberately implements neither
/// `From<&str>`, `From<String>` nor `Deserialize`.
///
/// ```compile_fail
/// use databastion_classifiers::masking::ClassifierId;
/// let _ = ClassifierId("jane.doe@example.com");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassifierId(&'static str);

impl ClassifierId {
    /// Email addresses.
    pub const PII_EMAIL: Self = Self::new("pii.email");
    /// IBAN bank account numbers.
    pub const PII_IBAN: Self = Self::new("pii.iban");
    /// AWS access keys.
    pub const SECRET_AWS_KEY: Self = Self::new("secret.aws_key");

    /// Every known classifier.
    pub const ALL: [Self; 3] = [Self::PII_EMAIL, Self::PII_IBAN, Self::SECRET_AWS_KEY];

    const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Stable identifier, e.g. `pii.email`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A finding whose samples have all been masked. The only finding type the
/// uplink accepts.
///
/// It will wrap the finding type generated from `shared/protocol/openapi.yaml`
/// (P0-B) once available; protocol fields are not hand-written here (I6).
///
/// Outside this crate it can only be built from a [`ClassifierId`] and
/// [`MaskedSample`]s, never from a string:
///
/// ```
/// use databastion_classifiers::masking::{ClassifierId, MaskedFinding, RawSample, mask};
/// let raw = RawSample::new("jane.doe@example.com");
/// let _ = MaskedFinding::new(ClassifierId::PII_EMAIL, vec![mask(&raw)]);
/// ```
///
/// ```compile_fail
/// use databastion_classifiers::masking::MaskedFinding;
/// let _ = MaskedFinding::new("jane.doe@example.com", Vec::new());
/// ```
///
/// ```compile_fail
/// use databastion_classifiers::masking::{ClassifierId, MaskedFinding, MaskedSample};
/// let sample = MaskedSample("jane.doe@example.com".to_owned());
/// let _ = MaskedFinding::new(ClassifierId::PII_EMAIL, vec![sample]);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct MaskedFinding {
    classifier: ClassifierId,
    masked_samples: Vec<MaskedSample>,
    location: Option<FindingLocation>,
    sampled: u32,
    matched: u32,
    confidence: f64,
    estimated_rows: Option<u64>,
}

/// Where a finding lives, down to the column / field / attribute. Built only
/// from [`NormalizedName`]s (ADR-0009): a connector cannot put a raw name
/// here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingLocation {
    /// Database (PostgreSQL / MySQL / MongoDB) or LDAP suffix.
    pub database: NormalizedName,
    /// Schema (PostgreSQL only).
    pub schema: Option<NormalizedName>,
    /// Table, collection, or LDAP container / objectClass.
    pub object: NormalizedName,
    /// Column, normalized field path, or attribute.
    pub field: NormalizedName,
}

impl MaskedFinding {
    /// Builds a finding from a known classifier and already-masked samples.
    #[must_use]
    pub fn new(classifier: ClassifierId, masked_samples: Vec<MaskedSample>) -> Self {
        Self {
            classifier,
            masked_samples,
            location: None,
            sampled: 0,
            matched: 0,
            confidence: 0.0,
            estimated_rows: None,
        }
    }

    /// Sets the location (normalized names only).
    #[must_use]
    pub fn with_location(mut self, location: FindingLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Sets the sampling counters and the confidence. The core validates the
    /// contract ranges before spooling (a finding out of range is dropped).
    #[must_use]
    pub fn with_counts(mut self, sampled: u32, matched: u32, confidence: f64) -> Self {
        self.sampled = sampled;
        self.matched = matched;
        self.confidence = confidence;
        self
    }

    /// Sets the estimated size of the object, from engine statistics.
    #[must_use]
    pub fn with_estimated_rows(mut self, rows: u64) -> Self {
        self.estimated_rows = Some(rows);
        self
    }

    /// Location, if set. A finding without location is never sent.
    #[must_use]
    pub fn location(&self) -> Option<&FindingLocation> {
        self.location.as_ref()
    }

    /// Values examined.
    #[must_use]
    pub fn sampled(&self) -> u32 {
        self.sampled
    }

    /// Values matching the classifier.
    #[must_use]
    pub fn matched(&self) -> u32 {
        self.matched
    }

    /// Confidence, expected in `0..=1`.
    #[must_use]
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// Estimated object size.
    #[must_use]
    pub fn estimated_rows(&self) -> Option<u64> {
        self.estimated_rows
    }

    /// Classifier that produced the finding.
    #[must_use]
    pub fn classifier(&self) -> ClassifierId {
        self.classifier
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
///
/// ```compile_fail
/// use databastion_classifiers::masking::MaskedEvent;
/// let _ = MaskedEvent { _private: () };
/// ```
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
    fn raw_sample_is_exposed_inside_the_crate_only() {
        assert_eq!(RawSample::new("x").expose(), "x");
    }

    #[test]
    fn classifier_ids_are_unique_and_namespaced() {
        let ids: std::collections::HashSet<&str> =
            ClassifierId::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(ids.len(), ClassifierId::ALL.len());
        assert!(
            ids.iter()
                .all(|id| id.starts_with("pii.") || id.starts_with("secret."))
        );
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
        let finding = MaskedFinding::new(ClassifierId::PII_EMAIL, vec![mask(&raw)]);
        assert_eq!(finding.classifier().as_str(), "pii.email");
        assert_eq!(finding.masked_samples().len(), 1);
        assert!(!format!("{finding:?}").contains("jane.doe"));
    }
}
