//! Column-level classification: a column name plus a bounded sample of its
//! values in, per-classifier results out.
//!
//! Deterministic (same input, same output, results in [`ClassifierId::ALL`]
//! order) and stateless: raw values are only borrowed for the duration of
//! the call. A [`ColumnFinding`] carries counts, a confidence, masked
//! samples and fingerprints, never a raw value.
//!
//! # Decision rules
//!
//! `sampled` counts the non-empty values examined (at most
//! [`MAX_SAMPLE_VALUES`]), `matched` the values in which the classifier
//! found a token (or that it recognized as a whole), and
//! `ratio = matched / sampled`.
//!
//! | Classifier | Reported when | Confidence |
//! |---|---|---|
//! | e-mail, IBAN, card, NIR, AWS access key id, password hash (validated tokens) | `matched ≥ 1` | `0.6 + 0.35·ratio (+0.05 name hint)` |
//! | phone (no checksum) | `ratio ≥ 0.2`, or `matched ≥ 1` with a name hint | `0.4 + 0.4·ratio (+0.2 hint)` |
//! | birth date, person name, postal address, AWS secret key (whole value) | name hint **and** `ratio ≥ 0.8` (address: `0.6`) | `0.3 + 0.5·ratio` |
//!
//! Confidences are rounded to 3 decimals and capped at 1.
//!
//! In a column named `siret` / `siren`, 14-digit card candidates are
//! dropped: SIRETs pass Luhn and may start with a Diners Club prefix.
//!
//! # Evidence selection
//!
//! Masked samples are **not** taken from the first rows: that would pick
//! the same rows in every column of a table and let the console rebuild
//! partial records. Each column keeps the [`MAX_MASKED_SAMPLES`] distinct
//! masked samples whose values have the smallest
//! `HMAC(key, "sample-order" 0x00 column_name 0x00 value)`: deterministic for
//! a key, but independent across columns. Without the agent key, a random
//! key is drawn for the call. Fingerprints are the [`MAX_FINGERPRINTS`]
//! smallest distinct ones, emitted sorted.

use std::collections::{BTreeMap, BTreeSet};

use crate::detect;
use crate::hints::NameHints;
use crate::id::ClassifierId;
use crate::masking::{
    FindingLocation, Fingerprint, HmacKey, MaskedFinding, MaskedSample, PhoneRegion, RawSample,
    mask_as,
};

/// Most values examined per column (contract `sample_rows` maximum).
pub const MAX_SAMPLE_VALUES: usize = 10_000;
/// Most masked samples per finding (contract `masked_samples.maxItems`).
pub const MAX_MASKED_SAMPLES: usize = 5;
/// Most fingerprints per finding (contract `fingerprints.maxItems`).
pub const MAX_FINGERPRINTS: usize = 50;

/// A whole-value detector: classifier, gate from the name hints, recognizer.
type WholeValue = (ClassifierId, bool, fn(&str) -> bool);

const PHONE_MIN_RATIO: f64 = 0.2;
const WHOLE_VALUE_MIN_RATIO: f64 = 0.8;
const ADDRESS_MIN_RATIO: f64 = 0.6;

/// Result for one classifier on one column. No raw value.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnFinding {
    classifier: ClassifierId,
    confidence: f64,
    sampled: u32,
    matched: u32,
    masked_samples: Vec<MaskedSample>,
    fingerprints: Vec<Fingerprint>,
}

impl ColumnFinding {
    /// Classifier.
    #[must_use]
    pub fn classifier(&self) -> ClassifierId {
        self.classifier
    }

    /// Confidence in `0..=1`.
    #[must_use]
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// Non-empty values examined.
    #[must_use]
    pub fn sampled(&self) -> u32 {
        self.sampled
    }

    /// Values in which the classifier matched.
    #[must_use]
    pub fn matched(&self) -> u32 {
        self.matched
    }

    /// Up to [`MAX_MASKED_SAMPLES`] distinct masked samples, in per-column
    /// pseudo-random order (never the first rows).
    #[must_use]
    pub fn masked_samples(&self) -> &[MaskedSample] {
        &self.masked_samples
    }

    /// Up to [`MAX_FINGERPRINTS`] distinct fingerprints, sorted (empty
    /// without an [`HmacKey`]).
    #[must_use]
    pub fn fingerprints(&self) -> &[Fingerprint] {
        &self.fingerprints
    }

    /// Turns the result into an uplink-ready finding at `location`.
    #[must_use]
    pub fn into_finding(self, location: FindingLocation) -> MaskedFinding {
        MaskedFinding::new(self.classifier, self.masked_samples)
            .with_fingerprints(self.fingerprints)
            .with_counts(self.sampled, self.matched, self.confidence)
            .with_location(location)
    }
}

/// Column classifier: optional classifier filter (job `classifiers`
/// parameter) and optional HMAC key for fingerprints.
#[derive(Debug, Default)]
pub struct ColumnClassifier<'k> {
    only: Option<Vec<ClassifierId>>,
    key: Option<&'k HmacKey>,
    region: PhoneRegion,
}

#[derive(Default)]
struct Acc {
    matched: u32,
    /// Smallest ordering key seen for each distinct masked sample.
    samples: BTreeMap<MaskedSample, [u8; 32]>,
    /// The smallest distinct fingerprints (at most [`MAX_FINGERPRINTS`]).
    fps: BTreeSet<Fingerprint>,
}

impl ColumnClassifier<'_> {
    /// All classifiers, no fingerprints.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the classifiers (a job's `classifiers` filter).
    #[must_use]
    pub fn only(mut self, classifiers: &[ClassifierId]) -> Self {
        self.only = Some(classifiers.to_vec());
        self
    }

    /// Phone region of the column or target (agent configuration), for the
    /// normalization of national numbers before fingerprinting.
    #[must_use]
    pub fn phone_region(mut self, region: PhoneRegion) -> Self {
        self.region = region;
        self
    }

    fn enabled(&self, c: ClassifierId) -> bool {
        self.only.as_ref().is_none_or(|o| o.contains(&c))
    }

    /// Classifies a column from its name (column, field path or attribute)
    /// and a sample of its values. Only the first [`MAX_SAMPLE_VALUES`]
    /// values are examined; empty and whitespace-only values are skipped.
    ///
    /// Production callers (the agent core) must set the agent key with
    /// [`Self::with_key`]: without it, the sample order is drawn from a
    /// random key per call, so each rescan would disclose a different set of
    /// masked samples, and there are no fingerprints. If the random source
    /// fails, the findings carry no samples (fail safe).
    #[must_use]
    pub fn classify(&self, column_name: &str, values: &[RawSample<'_>]) -> Vec<ColumnFinding> {
        let hints = NameHints::of(column_name);
        // Sample ordering key: the agent key, or a random one for this call.
        let ephemeral;
        let order: Option<&HmacKey> = match self.key {
            Some(k) => Some(k),
            None => {
                ephemeral = HmacKey::ephemeral();
                ephemeral.as_ref()
            }
        };
        let ctx = Ctx {
            column: column_name,
            order,
        };
        let mut acc: Vec<Acc> = ClassifierId::ALL.iter().map(|_| Acc::default()).collect();
        let mut sampled: u32 = 0;
        let whole_value: [WholeValue; 4] = [
            (
                ClassifierId::BirthDate,
                hints.gates(ClassifierId::BirthDate),
                detect::is_birth_date,
            ),
            (
                ClassifierId::PersonName,
                hints.gates(ClassifierId::PersonName),
                detect::is_person_name,
            ),
            (
                ClassifierId::PostalAddress,
                hints.gates(ClassifierId::PostalAddress),
                detect::is_postal_address,
            ),
            (
                ClassifierId::AwsKey,
                hints.aws_secret(),
                detect::is_aws_secret_key,
            ),
        ];

        for raw in values.iter().take(MAX_SAMPLE_VALUES) {
            let value = detect::bounded(raw.expose());
            if value.trim().is_empty() {
                continue;
            }
            sampled += 1;
            let tokens = detect::scan_tokens(value, &|c| self.enabled(c));
            let mut hit = [false; ClassifierId::ALL.len()];
            for t in &tokens {
                let token = &value[t.range.clone()];
                if t.classifier == ClassifierId::CardNumber
                    && hints.siret()
                    && token.chars().filter(char::is_ascii_digit).count() == 14
                {
                    continue;
                }
                self.record(&ctx, &mut acc, &mut hit, t.classifier, token);
            }
            if tokens.is_empty() {
                for (c, gated, recognize) in whole_value {
                    if gated && self.enabled(c) && recognize(value) {
                        self.record(&ctx, &mut acc, &mut hit, c, value);
                    }
                }
            }
        }
        if sampled == 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (i, c) in ClassifierId::ALL.into_iter().enumerate() {
            let a = &mut acc[i];
            if a.matched == 0 {
                continue;
            }
            let ratio = f64::from(a.matched) / f64::from(sampled);
            let hint = if hints.hints(c) { 1.0 } else { 0.0 };
            let confidence = match c {
                ClassifierId::Phone => {
                    if ratio < PHONE_MIN_RATIO && hint == 0.0 {
                        continue;
                    }
                    0.4 + 0.4 * ratio + 0.2 * hint
                }
                ClassifierId::BirthDate | ClassifierId::PersonName => {
                    if ratio < WHOLE_VALUE_MIN_RATIO {
                        continue;
                    }
                    0.3 + 0.5 * ratio
                }
                ClassifierId::PostalAddress => {
                    if ratio < ADDRESS_MIN_RATIO {
                        continue;
                    }
                    0.3 + 0.5 * ratio
                }
                ClassifierId::AwsKey if hints.aws_secret() => {
                    // Secret access keys (whole value) or key ids.
                    if ratio < WHOLE_VALUE_MIN_RATIO {
                        continue;
                    }
                    0.6 + 0.35 * ratio + 0.05 * hint
                }
                _ => 0.6 + 0.35 * ratio + 0.05 * hint,
            };
            out.push(ColumnFinding {
                classifier: c,
                confidence: (confidence.min(1.0) * 1000.0).round() / 1000.0,
                sampled,
                matched: a.matched,
                masked_samples: pick_samples(std::mem::take(&mut a.samples)),
                fingerprints: std::mem::take(&mut a.fps).into_iter().collect(),
            });
        }
        out
    }

    fn record(
        &self,
        ctx: &Ctx<'_, '_>,
        acc: &mut [Acc],
        hit: &mut [bool; ClassifierId::ALL.len()],
        c: ClassifierId,
        token: &str,
    ) {
        let Some(i) = ClassifierId::ALL.iter().position(|x| *x == c) else {
            return;
        };
        let a = &mut acc[i];
        if !hit[i] {
            hit[i] = true;
            a.matched += 1;
        }
        let raw = RawSample::new(token);
        if let Some(order) = ctx.order {
            let rank = order.sample_order(ctx.column, token);
            let m = mask_as(c, &raw);
            a.samples
                .entry(m)
                .and_modify(|best| *best = (*best).min(rank))
                .or_insert(rank);
        }
        if let Some(key) = self.key
            && let Some(fp) = key.fingerprint_in(c, &raw, self.region)
        {
            a.fps.insert(fp);
            if a.fps.len() > MAX_FINGERPRINTS {
                a.fps.pop_last();
            }
        }
    }
}

/// Per-call context of [`ColumnClassifier::classify`].
struct Ctx<'c, 'k> {
    column: &'c str,
    order: Option<&'k HmacKey>,
}

/// The [`MAX_MASKED_SAMPLES`] masked samples with the smallest ordering keys,
/// in that order.
fn pick_samples(samples: BTreeMap<MaskedSample, [u8; 32]>) -> Vec<MaskedSample> {
    let mut ranked: Vec<([u8; 32], MaskedSample)> =
        samples.into_iter().map(|(m, rank)| (rank, m)).collect();
    ranked.sort();
    ranked
        .into_iter()
        .take(MAX_MASKED_SAMPLES)
        .map(|(_, m)| m)
        .collect()
}

impl<'k> ColumnClassifier<'k> {
    /// Adds fingerprints computed with the agent-local key.
    #[must_use]
    pub fn with_key(mut self, key: &'k HmacKey) -> Self {
        self.key = Some(key);
        self
    }
}

/// Shorthand: all classifiers, no fingerprints.
#[must_use]
pub fn classify_column(column_name: &str, values: &[RawSample<'_>]) -> Vec<ColumnFinding> {
    ColumnClassifier::new().classify(column_name, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClassifierId as C;

    fn run(name: &str, values: &[&str]) -> Vec<(ClassifierId, u32, u32)> {
        let raws: Vec<RawSample<'_>> = values.iter().map(|v| RawSample::new(v)).collect();
        classify_column(name, &raws)
            .into_iter()
            .map(|f| (f.classifier(), f.matched(), f.sampled()))
            .collect()
    }

    #[test]
    fn structured_columns() {
        assert_eq!(
            run("email", &["jane@example.com", "john@example.org", ""]),
            [(C::Email, 2, 2)]
        );
        assert_eq!(
            run("contact", &["jane@example.com", "n/a"]),
            [(C::Email, 1, 2)]
        );
        assert_eq!(
            run("iban", &["FR7630006000011234567890189"]),
            [(C::Iban, 1, 1)]
        );
    }

    #[test]
    fn hint_gated_columns() {
        assert_eq!(
            run("first_name", &["Jane", "John", "Émile"]),
            [(C::PersonName, 3, 3)]
        );
        assert!(run("city", &["Paris", "Lyon"]).is_empty());
        assert!(run("product_name", &["Blue Widget", "Red Chair"]).is_empty());
        assert_eq!(
            run("date_naissance", &["1980-05-17", "01/12/1950"]),
            [(C::BirthDate, 2, 2)]
        );
        assert!(run("created_at", &["1980-05-17", "2020-01-01"]).is_empty());
        assert_eq!(
            run("adresse", &["10 rue des Lilas", "3 avenue Foch"]),
            [(C::PostalAddress, 2, 2)]
        );
        assert_eq!(
            run(
                "aws_secret_access_key",
                &["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
            ),
            [(C::AwsKey, 1, 1)]
        );
        assert!(run("token", &["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]).is_empty());
    }

    #[test]
    fn free_text_reports_every_classifier() {
        assert_eq!(
            run(
                "note",
                &[
                    "Customer called from 01 99 00 27 59 and asked to use jane@example.com.",
                    "Customer called from 01 99 00 27 69 and asked to use john@example.com.",
                ]
            ),
            [(C::Email, 2, 2), (C::Phone, 2, 2)]
        );
    }

    #[test]
    fn negatives() {
        assert!(run("email_opt_in", &["true", "false"]).is_empty());
        assert!(run("tracking_ref", &["9123456789012345"]).is_empty());
        assert!(run("phone_extension", &["1234", "0042"]).is_empty());
        assert!(run("badge_id", &["01234567"]).is_empty());
        assert!(run("x", &[]).is_empty());
        assert!(run("x", &["", "  "]).is_empty());
    }

    #[test]
    fn filter_restricts_classifiers() {
        let v = [RawSample::new("jane@example.com 01 99 00 27 59")];
        let only = ColumnClassifier::new()
            .only(&[C::Phone])
            .classify("note", &v);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].classifier(), C::Phone);
    }

    #[test]
    fn evidence_is_masked_bounded_and_deterministic() {
        let key = HmacKey::new(&[3; 32]).unwrap_or_else(|_| unreachable!());
        let values: Vec<String> = (0..200).map(|i| format!("user{i}@example.com")).collect();
        let raws: Vec<RawSample<'_>> = values.iter().map(|v| RawSample::new(v)).collect();
        let c = ColumnClassifier::new().with_key(&key);
        let a = c.classify("email", &raws);
        let b = c.classify("email", &raws);
        assert_eq!(a, b);
        assert_eq!(a.len(), 1);
        let f = &a[0];
        assert_eq!((f.matched(), f.sampled()), (200, 200));
        assert_eq!(f.confidence(), 1.0);
        // All masked the same way: one distinct sample.
        assert_eq!(f.masked_samples().len(), 1);
        assert_eq!(f.masked_samples()[0].as_str(), "u***@e***.com");
        assert_eq!(f.fingerprints().len(), MAX_FINGERPRINTS);
        assert!(f.fingerprints().windows(2).all(|w| w[0] < w[1]));
        let debug = format!("{a:?}");
        assert!(!debug.contains("user1@"));
    }

    fn card_for_row(i: usize) -> String {
        let partial = format!("411111111111{i:03}");
        (0..10)
            .map(|d| format!("{partial}{d}"))
            .find(|n| crate::validate::luhn_valid(n))
            .unwrap_or_default()
    }

    /// Row indices behind the masked samples of `name`.
    fn sampled_rows(
        c: &ColumnClassifier<'_>,
        name: &str,
        class: ClassifierId,
        rows: &[String],
    ) -> Vec<usize> {
        let raws: Vec<RawSample<'_>> = rows.iter().map(|v| RawSample::new(v)).collect();
        let found = c.classify(name, &raws);
        let f = found
            .iter()
            .find(|f| f.classifier() == class)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(f.masked_samples().len(), MAX_MASKED_SAMPLES);
        f.masked_samples()
            .iter()
            .map(|m| {
                rows.iter()
                    .position(|v| mask_as(class, &RawSample::new(v)) == *m)
                    .unwrap_or_else(|| unreachable!())
            })
            .collect()
    }

    #[test]
    fn samples_of_two_columns_are_not_row_aligned() {
        // Every row masks differently, so a masked sample identifies its row.
        let phones: Vec<String> = (0..100).map(|i| format!("+1 202 555 01{i:02}")).collect();
        let cards: Vec<String> = (0..100).map(card_for_row).collect();
        let key = HmacKey::new(&[8; 32]).unwrap_or_else(|_| unreachable!());
        let c = ColumnClassifier::new().with_key(&key);
        let a = sampled_rows(&c, "phone", C::Phone, &phones);
        let b = sampled_rows(&c, "card_number", C::CardNumber, &cards);
        let mut sa = a.clone();
        let mut sb = b.clone();
        sa.sort_unstable();
        sb.sort_unstable();
        assert_ne!(sa, sb, "same rows sampled in both columns");
        // Not the first rows either.
        assert_ne!(sa, [0, 1, 2, 3, 4]);
        // Deterministic for a key.
        assert_eq!(a, sampled_rows(&c, "phone", C::Phone, &phones));
        // The same values under another column name are ordered differently.
        let other = sampled_rows(&c, "mobile", C::Phone, &phones);
        let mut so = other.clone();
        so.sort_unstable();
        assert_ne!(sa, so);
        // Without a key: still bounded, random order per call.
        let unkeyed = sampled_rows(&ColumnClassifier::new(), "phone", C::Phone, &phones);
        assert_eq!(unkeyed.len(), MAX_MASKED_SAMPLES);
    }

    #[test]
    fn siret_and_siren_are_not_cards() {
        // Luhn-valid SIRETs starting with Diners prefixes 36 / 38 / 39, and
        // SIRENs (9 digits).
        let sirets: Vec<String> = ["3600000000000", "3800000000000", "3912345678901"]
            .iter()
            .map(|p| {
                (0..10)
                    .map(|d| format!("{p}{d}"))
                    .find(|n| crate::validate::luhn_valid(n))
                    .unwrap_or_default()
            })
            .collect();
        for s in &sirets {
            assert_eq!(s.len(), 14);
            assert!(
                crate::validate::card_prefix_valid(s),
                "{s} looks like Diners"
            );
        }
        let refs: Vec<&str> = sirets.iter().map(String::as_str).collect();
        assert!(run("siret", &refs).is_empty());
        assert!(run("num_siret", &refs).is_empty());
        assert!(run("siren", &["362521879", "732829320"]).is_empty());
        // Without the hint, a 14-digit Diners-shaped number is a card.
        assert_eq!(run("reference", &refs), [(C::CardNumber, 3, 3)]);
        // Real cards stay cards in a siret column.
        assert_eq!(
            run("siret", &["4111 1111 1111 1111"]),
            [(C::CardNumber, 1, 1)]
        );
    }
}
