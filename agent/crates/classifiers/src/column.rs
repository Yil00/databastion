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
//! [`MAX_SAMPLE_VALUES`]); `n` the informative ones among them (placeholders
//! such as `N/A`, `null`, `-`, `unknown`, `0000-00-00` excluded), `matched`
//! the values in which the classifier found a token (or that it recognized
//! as a whole), and `ratio = matched / n`. Values are detected first; the
//! column name only lowers thresholds (a *hint*, [`crate::hints`]).
//!
//! | Classifier | Reported when | Confidence |
//! |---|---|---|
//! | IBAN, card, NIR (checksums) | `matched ≥ 1` and at least half of the checksum-shaped candidates are valid; card: not under an order / tracking / IMEI / SIRET name | `0.6 + 0.35·ratio (+0.05 hint)` |
//! | AWS key id, secret key in context, password hash | `matched ≥ 1` | idem |
//! | e-mail (personal mailboxes only) | hint, `ratio ≥ 0.05` or `matched ≥ 3`; not a single address repeated (`matched ≥ 3`) | idem |
//! | phone | hint and `matched ≥ 1`; no hint: `≥ 0.3` of values with a formatted number (compact digits do not count, except a column of `≥ 0.8` whole compact numbers, 60 % with a mobile prefix `06` / `07` or `00` + country code + mobile prefix), or 3 values and `≥ 0.01` with a strong one (`+`, parentheses, a phone label before it), or 3 values and `≥ 0.01` with a formatted number among words (free text); a column of `≥ 0.95` compact North American numbers (20 at least, 3 area codes); the shares `0.3`, `0.8` and `0.95` are taken over the values with at least 6 digits that are not e-mail addresses (contact columns mixing e-mail addresses, user names, names; 3 values at least); `+` compact numbers among negative numbers are signed amounts | `0.4 + 0.4·ratio (+0.2 hint)` |
//! | birth date | labelled dates in text (`born …`): `ratio ≥ 0.05` or 3 values; hint: dates `≥ 0.5`; no hint: dates `≥ 0.7`, ≥ 3, an age distribution (median year ≤ 2002, 10-year spread, ≤ 15 % after 2014, not all on the 1st; with more than 20 % times of day: median ≤ 1995 and ≤ 5 % after 2014) | `0.3 + 0.5·ratio (+0.15 hint)` |
//! | person name | never under a name of something else (`pet_name`, `hostname`, `product.name`, `team_name`, `company_name`…); hint: name-shaped `≥ 0.6` (bare `name`: `≥ 0.7` and 25 % known names); no hint: name-shaped `≥ 0.7`, 40 % with a known given name, surname or surname ending, 25 % with a listed one, under 20 % well-known places or brands (`Austin`, `Hugo Boss`), 3 distinct | idem |
//! | postal address | hint: address-like `≥ 0.5`; no hint: strong addresses `≥ 0.5`, or address-like `≥ 0.8` with 25 % strong, or 3 strong addresses and `≥ 0.1` (free text) | idem |
//! | AWS secret key (whole value) | secret-key hint and `≥ 0.5`; no hint: `≥ 0.8` and 3 values, and under a token / session / digest name 30 % with `/` or `+` | `0.6 + 0.35·ratio` |
//! | password hash (raw hex / base64 digest) | password hint and `≥ 0.5` | idem |
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

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::BuildHasher;

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use zeroize::Zeroizing;

use crate::detect;
use crate::hints::NameHints;
use crate::id::ClassifierId;
use crate::lexicon;
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

/// Phone without a name hint: share of values holding a normal or strong
/// phone token (compact digits do not count).
const PHONE_MIN_RATIO: f64 = 0.3;
/// Phone without a name hint, in text: values with a strong token (`+`,
/// parentheses, a phone label), and their share.
const PHONE_STRONG_MIN_MATCHED: u32 = 3;
const PHONE_STRONG_MIN_RATIO: f64 = 0.01;
/// Share of whole negative numbers that makes `+` compact numbers signed
/// amounts.
const SIGNED_MIN_RATIO: f64 = 0.05;
/// Phone without a name hint, in free text: values where a normal or strong
/// number sits among words, and their share.
const PHONE_TEXT_MIN_MATCHED: u32 = 3;
const PHONE_TEXT_MIN_RATIO: f64 = 0.01;
/// Phone without a name hint: a column of compact North American numbers.
const PHONE_NANP_MIN_MATCHED: u32 = 20;
const PHONE_NANP_MIN_RATIO: f64 = 0.95;
/// Letters outside the phone tokens that make a value text.
const PHONE_TEXT_MIN_LETTERS: usize = 3;
/// E-mail and labelled dates in text: share of values without a hint.
const EMBEDDED_MIN_RATIO: f64 = 0.05;
/// Tokens found in text: values whatever the share.
const EMBEDDED_MIN_MATCHED: u32 = 3;
/// Reference year of the age distribution of birth dates (classifier set
/// `2026.09.1`; revised with [`crate::id::CLASSIFIERS_VERSION`]).
const REFERENCE_YEAR: u32 = 2026;

/// Values that stand for "no value" in sparse columns.
const PLACEHOLDERS: &[&str] = &[
    "n/a",
    "na",
    "n.a.",
    "n.a",
    "none",
    "null",
    "nil",
    "-",
    "--",
    "---",
    "?",
    "??",
    "unknown",
    "inconnu",
    "inconnue",
    "non renseigné",
    "non renseigne",
    "nr",
    "tbd",
    "todo",
    "0000-00-00",
    "0000-00-00 00:00:00",
    "undefined",
    "(null)",
    "<null>",
    "empty",
    "vide",
    "x",
    "xx",
    "xxx",
    "s/o",
    "sans objet",
    "not available",
    "not applicable",
    "redacted",
    "[redacted]",
    "***",
    "0",
    // Export artefacts: pandas, MySQL dumps, spreadsheets.
    "nan",
    "\\n",
    "#n/a",
    "#na",
    "#null!",
    "#value!",
    "(empty)",
    "<empty>",
    "(none)",
    "<none>",
    "—",
    "–",
    "_",
    "...",
    "…",
    "n.c.",
    "n.c",
    "nc",
    "n/c",
    "néant",
    "neant",
    "aucun",
    "aucune",
    "not provided",
    "none provided",
    "not set",
    "not specified",
    "missing",
    "no data",
    "sin datos",
    "keine",
    "k.a.",
    "withheld",
];

fn placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.len() <= 20 && PLACEHOLDERS.iter().any(|p| v.eq_ignore_ascii_case(p)) {
        return true;
    }
    // Fillers: one digit repeated, with or without separators
    // (`0000000000`, `00 00 00 00 00`, `000-000-0000`).
    let mut digits = v.bytes().filter(u8::is_ascii_digit);
    let first = digits.next();
    v.len() <= 24
        && first.is_some()
        && v.bytes().filter(u8::is_ascii_digit).count() >= 5
        && digits.all(|d| Some(d) == first)
        && v.bytes()
            .all(|b| b.is_ascii_digit() || b" .-/()+".contains(&b))
}

/// Per-column evidence beyond the matched counts.
#[derive(Default)]
struct Stats {
    /// Informative values (non-empty, not a placeholder).
    n: u32,
    card_cand: u32,
    iban_cand: u32,
    /// Values with a strong phone token, and with a normal one at best.
    phone_strong: u32,
    phone_normal: u32,
    /// Values with a normal or strong phone token among words.
    phone_text: u32,
    /// Values with an e-mail token and no phone token: the other half of a
    /// contact column ("e-mail or phone").
    email_only: u32,
    /// Values with at least 6 digits: the ones that could be phone numbers
    /// (not names, user names, handles or words).
    numeric: u32,
    /// Whole compact North American numbers, and up to 3 of their area
    /// codes.
    phone_nanp: u32,
    nanp_areas: Vec<u16>,
    /// Whole signed numbers: negative ones (`-12345`), and `+` compact
    /// numbers graded as strong phones (`+12345678`). With negative
    /// numbers around, the `+` ones are signed amounts.
    minus_numbers: u32,
    plus_compact: u32,
    /// Values that are a whole compact national number, and among them
    /// those with a mobile prefix (`06`, `07`).
    phone_compact: u32,
    phone_compact_mobile: u32,
    nir_cand: u32,
    /// Up to 2 distinct e-mail tokens, as in-memory hashes (never output).
    emails: Vec<u64>,
    /// Values with an AWS key id or a secret key in context.
    aws_tokens: u32,
    aws_whole: u32,
    aws_slash: u32,
    hash_tokens: u32,
    raw_digests: u32,
    /// Values with a labelled date of birth in text.
    birth_labelled: u32,
    /// Whole-value dates: year, time of day, day of month.
    dates: Vec<(u32, detect::TimeOfDay, u32)>,
    names_known: u32,
    names_listed: u32,
    /// Name-shaped values that name a well-known place or brand.
    names_entities: u32,
    /// Up to 3 distinct name values, as in-memory hashes (never output).
    names: Vec<u64>,
    addr_strong: u32,
    addr_weak: u32,
}

/// Remembers up to `max` distinct values by an in-memory SipHash keyed at
/// random for the call (`keys`): only compared within the call, never
/// output, and crafted values cannot collide on purpose.
fn remember(keys: &RandomState, set: &mut Vec<u64>, v: &str, max: usize) {
    let h = keys.hash_one(v);
    if set.len() < max && !set.contains(&h) {
        set.push(h);
    }
}

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
        let mut st = Stats::default();
        // Random SipHash keys for the distinct-value sets of this call.
        let hash_keys = RandomState::new();
        let on = |c| self.enabled(c);

        for raw in values.iter().take(MAX_SAMPLE_VALUES) {
            let original = detect::bounded(raw.expose());
            // Canonical composition (NFC): a name, address or month stored
            // decomposed (`e` + U+0301, macOS / some ETLs) is analyzed like
            // its composed form; tokens, masked samples and fingerprints
            // come from the NFC value. Zeroized on drop.
            let composed: Zeroizing<String>;
            let value: &str = if is_nfc_quick(original.chars()) == IsNormalized::Yes {
                original
            } else {
                // Pre-sized so that no reallocation leaves an unzeroized
                // copy of a raw prefix behind: NFC expands UTF-8 by at
                // most 3 times (UAX #15).
                let mut buf = String::with_capacity(original.len().saturating_mul(3));
                buf.extend(original.nfc());
                composed = Zeroizing::new(buf);
                detect::bounded(&composed)
            };
            // Typographic spaces and hyphens (no-break space, narrow
            // no-break space, non-breaking hyphen, en dash, minus sign),
            // as word processors and spreadsheets write numbers
            // (`06\u{a0}12\u{a0}34\u{a0}56\u{a0}78`), read as their ASCII
            // form. Zeroized on drop.
            let folded: Zeroizing<String>;
            let value: &str = if value.contains(typographic) {
                // Folding only shrinks the value: no reallocation.
                let mut buf = String::with_capacity(value.len());
                buf.extend(value.chars().map(fold_typographic));
                folded = Zeroizing::new(buf);
                detect::bounded(&folded)
            } else {
                value
            };
            if value.trim().is_empty() {
                continue;
            }
            sampled += 1;
            if placeholder(value) {
                continue;
            }
            st.n += 1;
            let (tokens, cand) = detect::scan(value, &on);
            st.card_cand += u32::from(cand.card);
            st.iban_cand += u32::from(cand.iban);
            st.nir_cand += u32::from(cand.nir);
            match cand.phone {
                Some(detect::PhoneStrength::Strong) => st.phone_strong += 1,
                Some(detect::PhoneStrength::Normal) => st.phone_normal += 1,
                _ => {}
            }
            let has = |c| tokens.iter().any(|t| t.classifier == c);
            if cand.phone >= Some(detect::PhoneStrength::Normal)
                && has(ClassifierId::Phone)
                && letters_outside_phones(value, &tokens) >= PHONE_TEXT_MIN_LETTERS
            {
                st.phone_text += 1;
            }
            st.email_only += u32::from(has(ClassifierId::Email) && !has(ClassifierId::Phone));
            st.numeric += u32::from(value.bytes().filter(u8::is_ascii_digit).count() >= 6);
            {
                let t = value.trim();
                let number = |x: &str| {
                    !x.is_empty()
                        && x.bytes()
                            .all(|b| b.is_ascii_digit() || b == b'.' || b == b',')
                };
                st.minus_numbers += u32::from(t.strip_prefix('-').is_some_and(number));
                st.plus_compact += u32::from(
                    cand.phone == Some(detect::PhoneStrength::Strong)
                        && t.strip_prefix('+').is_some_and(|x| {
                            !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit())
                        }),
                );
            }
            let mut hit = [false; ClassifierId::ALL.len()];
            let (mut aws, mut hash, mut labelled) = (false, false, false);
            for t in &tokens {
                let token = &value[t.range.clone()];
                match t.classifier {
                    ClassifierId::CardNumber
                        if hints.siret()
                            && token.chars().filter(char::is_ascii_digit).count() == 14 =>
                    {
                        continue;
                    }
                    ClassifierId::Email => remember(&hash_keys, &mut st.emails, token, 2),
                    ClassifierId::AwsKey => aws = true,
                    ClassifierId::PasswordHash => hash = true,
                    ClassifierId::BirthDate => labelled = true,
                    _ => {}
                }
                self.record(&ctx, &mut acc, &mut hit, t.classifier, token);
            }
            // Whole compact numbers, one or a list (`0612345678`,
            // `0612345678,0698765432`).
            if cand.phone == Some(detect::PhoneStrength::Weak)
                && !tokens.is_empty()
                && tokens.iter().all(|t| {
                    t.classifier == ClassifierId::Phone
                        && value[t.range.clone()].bytes().all(|b| b.is_ascii_digit())
                })
                && only_list_separators(value, &tokens)
            {
                st.phone_compact += 1;
                st.phone_compact_mobile += u32::from(
                    tokens
                        .iter()
                        .all(|t| compact_mobile(&value[t.range.clone()])),
                );
            }
            st.aws_tokens += u32::from(aws);
            st.hash_tokens += u32::from(hash);
            st.birth_labelled += u32::from(labelled);

            // Whole-value analyzers. An address may hold a token (a phone
            // number); the others are whole values only.
            if on(ClassifierId::PostalAddress) {
                match detect::address_kind(value) {
                    detect::AddressKind::Strong => {
                        st.addr_strong += 1;
                        self.record(&ctx, &mut acc, &mut hit, ClassifierId::PostalAddress, value);
                    }
                    detect::AddressKind::Weak if tokens.is_empty() => {
                        st.addr_weak += 1;
                        self.record(&ctx, &mut acc, &mut hit, ClassifierId::PostalAddress, value);
                    }
                    _ => {}
                }
            }
            if !tokens.is_empty() {
                continue;
            }
            if on(ClassifierId::BirthDate)
                && let Some(d) = detect::parse_date(value)
            {
                st.dates.push((d.year, d.time, d.day));
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::BirthDate, value);
            }
            if on(ClassifierId::PersonName)
                && let Some(e) = detect::name_evidence(value)
            {
                st.names_known += u32::from(e.known());
                st.names_listed += u32::from(e.given || e.surname);
                st.names_entities += u32::from(lexicon::is_entity(value));
                remember(&hash_keys, &mut st.names, value.trim(), 3);
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::PersonName, value);
            }
            if on(ClassifierId::AwsKey) && detect::is_aws_secret_key(value) {
                st.aws_whole += 1;
                st.aws_slash += u32::from(value.contains(['/', '+']));
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::AwsKey, value);
            }
            if on(ClassifierId::Phone)
                && let Some(kind) = detect::compact_phone(value)
            {
                match kind {
                    detect::CompactPhone::IntlMobile => {
                        st.phone_compact += 1;
                        st.phone_compact_mobile += 1;
                    }
                    detect::CompactPhone::Nanp { area } => {
                        st.phone_nanp += 1;
                        if st.nanp_areas.len() < 3 && !st.nanp_areas.contains(&area) {
                            st.nanp_areas.push(area);
                        }
                    }
                }
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::Phone, value.trim());
            }
            if on(ClassifierId::Phone)
                && hints.gates(ClassifierId::Phone)
                && let Some(r) = detect::phone_loose(value)
            {
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::Phone, &value[r]);
            }
            if on(ClassifierId::PasswordHash) && hints.password() && detect::is_raw_digest(value) {
                st.raw_digests += 1;
                self.record(&ctx, &mut acc, &mut hit, ClassifierId::PasswordHash, value);
            }
        }
        if sampled == 0 || st.n == 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (i, c) in ClassifierId::ALL.into_iter().enumerate() {
            let a = &mut acc[i];
            if a.matched == 0 || !decide(c, a.matched, &st, &hints) {
                continue;
            }
            let ratio = (f64::from(a.matched) / f64::from(st.n)).min(1.0);
            let h = if hints.hints(c) { 1.0 } else { 0.0 };
            let confidence = match c {
                ClassifierId::Phone => 0.4 + 0.4 * ratio + 0.2 * h,
                ClassifierId::BirthDate
                | ClassifierId::PersonName
                | ClassifierId::PostalAddress => 0.3 + 0.5 * ratio + 0.15 * h,
                _ => 0.6 + 0.35 * ratio + 0.05 * h,
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

/// Typographic spaces and hyphens folded by [`fold_typographic`].
fn typographic(c: char) -> bool {
    matches!(
        c,
        '\u{a0}' | '\u{2002}'..='\u{200a}' | '\u{202f}' | '\u{2010}'..='\u{2013}' | '\u{2212}'
    )
}

fn fold_typographic(c: char) -> char {
    match c {
        '\u{a0}' | '\u{2002}'..='\u{200a}' | '\u{202f}' => ' ',
        '\u{2010}'..='\u{2013}' | '\u{2212}' => '-',
        c => c,
    }
}

/// Only list separators (spaces, `,`, `;`, `/`, `|`) outside the tokens.
fn only_list_separators(value: &str, tokens: &[detect::Token]) -> bool {
    value.char_indices().all(|(i, c)| {
        tokens.iter().any(|t| t.range.contains(&i)) || matches!(c, ' ' | ',' | ';' | '/' | '|')
    })
}

/// Letters of a value outside its phone tokens (a number among words).
fn letters_outside_phones(value: &str, tokens: &[detect::Token]) -> usize {
    value
        .char_indices()
        .filter(|(i, c)| {
            c.is_alphabetic()
                && !tokens
                    .iter()
                    .any(|t| t.classifier == ClassifierId::Phone && t.range.contains(i))
        })
        .count()
}

/// A whole compact number with a mobile prefix: French `06` / `07`, or
/// `00` + a country code + its mobile prefix (`0033 6…`, `0044 7…`,
/// `0049 15…`–`17…`, `0032 4…`, `0041 7…`, `0034 6…` / `7…`, `0039 3…`,
/// `0031 6…`).
fn compact_mobile(v: &str) -> bool {
    if v.starts_with("06") || v.starts_with("07") {
        return true;
    }
    let Some(rest) = v.strip_prefix("00") else {
        return false;
    };
    [
        "336", "337", "447", "4915", "4916", "4917", "324", "417", "346", "347", "393", "316",
    ]
    .iter()
    .any(|p| rest.starts_with(p))
}

/// Whether classifier `c`, matched in `matched` values, is reported for the
/// column (module table).
fn decide(c: ClassifierId, matched: u32, st: &Stats, hints: &NameHints) -> bool {
    let hint = hints.hints(c);
    let share = |k: u32| f64::from(k) / f64::from(st.n);
    let ratio = share(matched);
    // At least half of the checksum-shaped candidates pass the checksum.
    let consistent = |cand: u32| matched * 2 >= cand;
    match c {
        ClassifierId::Iban => consistent(st.iban_cand),
        ClassifierId::Nir => consistent(st.nir_cand),
        ClassifierId::CardNumber => !hints.not_card() && consistent(st.card_cand),
        ClassifierId::Email => {
            let constant = st.emails.len() == 1 && matched >= EMBEDDED_MIN_MATCHED;
            !constant && (hint || ratio >= EMBEDDED_MIN_RATIO || matched >= EMBEDDED_MIN_MATCHED)
        }
        ClassifierId::Phone => {
            // In a contact column ("e-mail or phone"), the phone numbers
            // are the values that are not e-mail addresses.
            // Phone numbers among other contact data (e-mail addresses,
            // user names, names, handles): shares over the values with
            // digits that are not e-mail addresses.
            let others =
                st.n.saturating_sub(st.email_only)
                    .min(st.numeric.saturating_sub(st.email_only))
                    .max(1);
            let share_others = |k: u32| f64::from(k) / f64::from(others);
            // `+12345678` among `-2345678`: signed amounts.
            let signed = st.minus_numbers >= PHONE_STRONG_MIN_MATCHED
                && share(st.minus_numbers) >= SIGNED_MIN_RATIO;
            let strong = if signed {
                st.phone_strong.saturating_sub(st.plus_compact)
            } else {
                st.phone_strong
            };
            let formatted = strong + st.phone_normal;
            (hint && hints.gates(c))
                || share(formatted) >= PHONE_MIN_RATIO
                || (formatted >= PHONE_STRONG_MIN_MATCHED
                    && share_others(formatted) >= PHONE_MIN_RATIO)
                || (strong >= PHONE_STRONG_MIN_MATCHED
                    && share(strong) >= PHONE_STRONG_MIN_RATIO)
                // A column of compact North American numbers: all of them
                // fit the plan (a random 10-digit identifier does 3 times
                // in 4), from several area codes.
                || (st.phone_nanp >= PHONE_NANP_MIN_MATCHED
                    && share_others(st.phone_nanp) >= PHONE_NANP_MIN_RATIO
                    && st.nanp_areas.len() >= 3)
                // Free text: numbers that fit a numbering plan, among words.
                || (st.phone_text >= PHONE_TEXT_MIN_MATCHED
                    && share(st.phone_text) >= PHONE_TEXT_MIN_RATIO)
                // A column of compact mobile numbers (zero-padded
                // identifiers do not cluster on mobile prefixes).
                || (share_others(st.phone_compact) >= 0.8
                    && st.phone_compact >= 3
                    && st.phone_compact_mobile * 10 >= st.phone_compact * 6)
        }
        ClassifierId::AwsKey => {
            let whole = share(st.aws_whole);
            st.aws_tokens >= 1
                || (hints.aws_secret() && whole >= 0.5)
                || (whole >= 0.8
                    && st.aws_whole >= 3
                    && (!hints.other_token() || st.aws_slash * 10 >= st.aws_whole * 3))
        }
        ClassifierId::PasswordHash => st.hash_tokens >= 1 || share(st.raw_digests) >= 0.5,
        ClassifierId::BirthDate => birth_dates(st, hints.gates(c)),
        ClassifierId::PersonName => {
            if hints.not_person() {
                // `pet_name`, `hostname`, `company.name`: values alone
                // cannot tell `Max, Bella, Luna` from people.
                false
            } else if hints.gates(c) && !hints.person_name_weak() {
                ratio >= 0.6
            } else if hints.gates(c) {
                ratio >= 0.7 && share(st.names_known) >= 0.25
            } else {
                // Places and brands named after people (`Austin`, `Lincoln`,
                // `Hugo Boss`) make a column of places or brands.
                ratio >= 0.7
                    && share(st.names_entities) < 0.2
                    && share(st.names_known) >= 0.4
                    && share(st.names_listed) >= 0.25
                    && st.names.len() >= 3
            }
        }
        ClassifierId::PostalAddress => {
            let strong = share(st.addr_strong);
            let any = share(st.addr_strong + st.addr_weak);
            if hints.gates(c) {
                any >= 0.5
            } else {
                strong >= 0.5
                    || (any >= 0.8 && strong >= 0.25)
                    || (st.addr_strong >= EMBEDDED_MIN_MATCHED && strong >= 0.1)
            }
        }
    }
}

/// Birth-date decision: labelled dates in text, or a column of dates with
/// a hint, or without one a column whose dates are distributed like ages
/// (not event timestamps, not recent dates, spread over a lifetime).
fn birth_dates(st: &Stats, hint: bool) -> bool {
    let n = f64::from(st.n);
    if st.birth_labelled >= 1
        && (f64::from(st.birth_labelled) / n >= EMBEDDED_MIN_RATIO
            || st.birth_labelled >= EMBEDDED_MIN_MATCHED)
    {
        return true;
    }
    let d = st.dates.len();
    let plausible = st
        .dates
        .iter()
        .filter(|(_, t, _)| *t != detect::TimeOfDay::Other)
        .count();
    #[allow(clippy::cast_precision_loss)] // at most MAX_SAMPLE_VALUES
    let dates = d as f64;
    if hint {
        return (dates + f64::from(st.birth_labelled)) / n >= 0.5;
    }
    if d < 3 || dates / n < 0.7 {
        return false;
    }
    let timed = d - plausible;
    let mut years: Vec<u32> = st.dates.iter().map(|(y, _, _)| *y).collect();
    years.sort_unstable();
    let median = years[d / 2];
    let p10 = years[d / 10];
    let p90 = years[(d * 9 / 10).min(d - 1)];
    let recent = years.iter().filter(|y| **y >= 2015).count();
    let first_of_month = st.dates.iter().all(|(_, _, day)| *day == 1);
    let ages = years[d - 1] <= REFERENCE_YEAR
        && median <= 2002
        && p90 - p10 >= 10
        && recent * 100 <= d * 15
        && !first_of_month;
    // Timestamps with a time of day are usually events; birth dates with
    // a time part need a clearly adult distribution.
    ages && (timed * 5 <= d || (median <= 1995 && recent * 100 <= d * 5))
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

    fn phone_found(name: &str, values: &[String]) -> bool {
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        run(name, &refs).iter().any(|(c, _, _)| *c == C::Phone)
    }

    #[test]
    fn phones_in_contact_columns() {
        // "E-mail or phone": the numbers are the values that are not
        // addresses, compact mobile numbers included.
        let compact: Vec<String> = (0..40)
            .map(|i| {
                if i % 5 < 2 {
                    format!("06{:08}", 12_345_678 + i * 7919)
                } else {
                    format!("user{i}@example.com")
                }
            })
            .collect();
        assert!(phone_found("login", &compact));
        let formatted: Vec<String> = (0..40)
            .map(|i| {
                if i % 5 == 0 {
                    format!("01 99 00 {:02} {:02}", i, 99 - i)
                } else {
                    format!("user{i}@example.com")
                }
            })
            .collect();
        assert!(phone_found("contact", &formatted));
        // E-mail addresses and user ids: no phone.
        let ids: Vec<String> = (0..40)
            .map(|i| {
                if i % 2 == 0 {
                    format!("0{:09}", 123_456_789 + i * 104_729)
                } else {
                    format!("user{i}@example.com")
                }
            })
            .collect();
        assert!(!phone_found("login", &ids));
    }

    #[test]
    fn phones_in_free_text() {
        // 8 % of the notes hold a number in a national format, no label.
        let notes: Vec<String> = (0..100)
            .map(|i| {
                if i % 12 == 0 {
                    format!("Nouveau numéro 01 99 00 {i:02} 59 (ancien supprimé).")
                } else {
                    format!("Commande {} expédiée le 03/05/2024.", 1000 + i)
                }
            })
            .collect();
        assert!(phone_found("notes", &notes));
        // Two numbers in 100 notes are not enough.
        let rare: Vec<String> = (0..100)
            .map(|i| {
                if i % 50 == 0 {
                    format!("Nouveau numéro 01 99 00 {i:02} 59.")
                } else {
                    format!("Commande {} expédiée.", 1000 + i)
                }
            })
            .collect();
        assert!(!phone_found("notes", &rare));
        // Numbers among words that fit no numbering plan.
        let serials: Vec<String> = (0..100)
            .map(|i| format!("S/N 00{:02} 4567 {:02} returned, lot 0{:09}", i, i, i * 7))
            .collect();
        assert!(!phone_found("c1", &serials));
    }

    #[test]
    fn compact_phone_columns() {
        // North American numbers: every value fits the plan.
        let nanp: Vec<String> = (0..40)
            .map(|i| format!("{}{}{:04}", 202 + (i % 7) * 101, 555, i * 37))
            .collect();
        assert!(phone_found("c1", &nanp));
        // 10-digit identifiers: some do not fit (exchange `0XX` / `1XX`).
        let ids: Vec<String> = (0..40)
            .map(|i| format!("{}", 2_000_000_000u64 + i * 12_345_679))
            .collect();
        assert!(!phone_found("c1", &ids));
        // E.164 without `+`.
        let intl: Vec<String> = (0..20)
            .map(|i| format!("33{}{:08}", 6 + i % 2, i * 4_567_891))
            .collect();
        assert!(phone_found("c1", &intl));
        // Sparse, with export artefacts for "no value".
        let sparse: Vec<String> = (0..50)
            .map(|i| match i % 5 {
                0 => format!("01 99 00 {:02} 59", i),
                1 => "nan".to_owned(),
                2 => "\\N".to_owned(),
                3 => "00 00 00 00 00".to_owned(),
                _ => "#N/A".to_owned(),
            })
            .collect();
        assert!(phone_found("c1", &sparse));
    }

    #[test]
    fn phones_as_a_minority() {
        // Typographic separators.
        let nbsp: Vec<String> = (0..20)
            .map(|i| format!("06\u{a0}12\u{a0}34\u{a0}{:02}\u{a0}{:02}", i, 99 - i))
            .collect();
        assert!(phone_found("c1", &nbsp));
        // 20 % phones among user names.
        let users: Vec<String> = (0..50)
            .map(|i| {
                if i % 5 == 0 {
                    format!("01 99 00 {:02} 59", i)
                } else {
                    format!("user_{i}")
                }
            })
            .collect();
        assert!(phone_found("login", &users));
        // 2 % of notes with a labelled number.
        let notes: Vec<String> = (0..200)
            .map(|i| {
                if i % 50 == 1 {
                    format!("Rappeler au 06123456{:02}", i)
                } else {
                    format!("Commande {} expédiée.", 1000 + i)
                }
            })
            .collect();
        assert!(phone_found("notes", &notes));
        // Lists of compact mobile numbers.
        let lists: Vec<String> = (0..20)
            .map(|i| format!("06123456{i:02};07987654{i:02}"))
            .collect();
        assert!(phone_found("c1", &lists));
        // Codes among words do not become phones.
        let codes: Vec<String> = (0..50)
            .map(|i| {
                if i % 5 == 0 {
                    format!("0{:03} {:04} {:02}", i, i * 7, i % 100)
                } else {
                    "shipped".to_owned()
                }
            })
            .collect();
        assert!(!phone_found("c1", &codes));
    }

    #[test]
    fn signed_integers_are_not_phones() {
        let signed: Vec<String> = (0..60)
            .map(|i| {
                format!(
                    "{}{}",
                    if i % 2 == 0 { "+" } else { "-" },
                    12_345_678 + i * 991
                )
            })
            .collect();
        assert!(!phone_found("c1", &signed));
        // E.164 numbers alone stay phones.
        let e164: Vec<String> = (0..60)
            .map(|i| format!("+336{:08}", 12_345_678 + i * 991))
            .collect();
        assert!(phone_found("c1", &e164));
    }

    #[test]
    fn signed_decimals_are_not_phones() {
        let coords: Vec<String> = (0..50)
            .map(|i| format!("+48.{:06}, +2.{:06}", 850_000 + i * 17, 350_000 + i * 13))
            .collect();
        assert!(!phone_found("c1", &coords));
        let amounts: Vec<String> = (0..50)
            .map(|i| format!("+{}.{:02}", 1_234_567 + i * 1_013, i))
            .collect();
        assert!(!phone_found("delta", &amounts));
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
    fn values_decide_without_a_hint() {
        let names = [
            "Jean Dupont",
            "Marie Curie",
            "Paul Martin",
            "Lucie Bernard",
            "Hugo Petit",
        ];
        assert_eq!(run("col_17", &names), [(C::PersonName, 5, 5)]);
        let dates = [
            "1950-12-01",
            "17/05/1980",
            "1962-07-30",
            "2001-03-09",
            "1975-11-02",
        ];
        assert_eq!(run("f3", &dates), [(C::BirthDate, 5, 5)]);
        let addresses = [
            "10 rue des Lilas, 75011 Paris",
            "221B Baker Street, London NW1 6XE",
            "Musterstraße 12, 10115 Berlin",
        ];
        assert_eq!(run("attr_x", &addresses), [(C::PostalAddress, 3, 3)]);
        // Event timestamps, cities and products are not.
        let events = [
            "2024-05-03 10:22:31",
            "2025-01-17 08:01:02",
            "2023-11-30 23:59:10",
            "2024-02-29 12:00:01",
        ];
        assert!(run("f4", &events).is_empty());
        assert!(run("f5", &["Paris", "Lyon", "Marseille", "Toulouse", "Nice"]).is_empty());
        assert!(
            run(
                "f6",
                &["Blue Widget", "Red Chair", "Oak Table", "Desk Lamp"]
            )
            .is_empty()
        );
    }

    #[test]
    fn decomposed_values_are_read_like_composed_ones() {
        let key = HmacKey::new(&[5; 32]).unwrap_or_else(|_| unreachable!());
        let c = ColumnClassifier::new().with_key(&key);
        let composed = [
            "José García",
            "Hélène Lefèvre",
            "Chloé Dupré",
            "Anaïs Béranger",
        ];
        let decomposed: Vec<String> = composed.iter().map(|v| v.nfd().collect()).collect();
        let a: Vec<RawSample<'_>> = composed.iter().map(|v| RawSample::new(v)).collect();
        let b: Vec<RawSample<'_>> = decomposed.iter().map(|v| RawSample::new(v)).collect();
        let fa = c.classify("col_1", &a);
        let fb = c.classify("col_1", &b);
        assert_eq!(fa.len(), 1);
        assert_eq!(fa, fb);
        let emails = [
            "jose\u{301}.garci\u{301}a@example.com",
            "he\u{301}le\u{300}ne@example.org",
        ];
        let raws: Vec<RawSample<'_>> = emails.iter().map(|v| RawSample::new(v)).collect();
        let composed_emails = ["josé.garcía@example.com", "hélène@example.org"];
        let raws_c: Vec<RawSample<'_>> =
            composed_emails.iter().map(|v| RawSample::new(v)).collect();
        assert_eq!(c.classify("col_2", &raws), c.classify("col_2", &raws_c));
    }

    #[test]
    fn checksum_consistency_and_constants() {
        // Luhn-valid identifiers with random prefixes: a few look like
        // cards, most do not.
        let ids: Vec<String> = (0..40)
            .map(|i| {
                let partial = format!("{}{:014}", 1 + i % 9, i * 7_919_993);
                (0..10)
                    .map(|d| format!("{partial}{d}"))
                    .find(|n| crate::validate::luhn_valid(n))
                    .unwrap_or_default()
            })
            .collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert!(run("col_1", &refs).is_empty());
        // A single system address repeated is not a personal e-mail column.
        assert!(run("sender", &["support@example.com"; 5]).is_empty());
        assert!(run("sender", &["noreply@example.com"; 5]).is_empty());
        // Placeholders do not dilute a sparse column.
        assert_eq!(
            run(
                "c",
                &["N/A", "jane@example.com", "null", "-", "john@example.org"]
            ),
            [(C::Email, 2, 5)]
        );
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
