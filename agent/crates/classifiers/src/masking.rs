//! Masking and fingerprinting of sampled values (ADR-0003, ADR-0007).
//!
//! # Type boundary
//!
//! - [`RawSample`] (borrowed) and [`RawValue`] (owned, zeroized on drop)
//!   wrap a value read from a target. They have a redacted `Debug`, no
//!   `Display`, no `Clone`, and no serialization: they cannot be logged or
//!   sent by accident.
//! - [`ClassifierId`], [`MaskedSample`], [`Fingerprint`], [`MaskedFinding`]
//!   and [`MaskedEvent`] have **private fields** and no public constructor
//!   taking a string. [`ClassifierId`] is a closed set owned by this crate;
//!   a [`MaskedSample`] only comes from [`mask`] / [`mask_as`] (or the column
//!   API), a [`Fingerprint`] only from an [`HmacKey`]; a [`MaskedFinding`]
//!   is built only from a [`ClassifierId`], [`MaskedSample`]s and
//!   [`Fingerprint`]s; [`MaskedEvent`] cannot be built yet. None implements
//!   `From<String>` or `Deserialize` (compile-fail doctests below prove it).
//! - The core uplink (crate-private in `databastion-core`) and the connector
//!   sinks only accept [`MaskedFinding`] / [`MaskedEvent`], so a connector
//!   cannot hand an unmasked value to them: the compiler rejects it.
//!
//! # Masked samples
//!
//! Every masked sample is checked against the contract `MaskedSample` rules
//! before it is returned (ASCII only, at least one `*`, no run of more than
//! [`MAX_KEPT_RUN`] letters or digits, at least 50 % of the letters, digits
//! and `*` are `*`, at most 128 characters). A format that would break a rule
//! falls back to the fully redacted `***`. Formats (fixed length where the
//! length would reveal something):
//!
//! | Classifier | Example input | Masked |
//! |---|---|---|
//! | `pii.email` | `jane.doe@example.com` | `j***@e***.com` (TLD kept if 2–4 ASCII letters) |
//! | `pii.iban` | `FR76 3000 6000 0112 3456 7890 189` | `FR** **** **** **** **** ***0 189` (country + last 4) |
//! | `pii.card_number` | `4111 1111 1111 1111` | `**** **** **** 1111` (last 4) |
//! | `pii.phone` | `+33 6 12 34 56 78` / `06 12 34 56 78` | `+33 * ** ** ** 78` / `** ** ** ** 78` (country code after `+` and the last digits, at most 4 digits, separators kept) |
//! | `pii.nir` | `1 85 05 78 006 048 xx` | `* ** ** ** *** *** **` |
//! | `pii.birth_date` | `1950-12-01` | `****-**-**` |
//! | `pii.person_name` | `Jane Doe` | `J*** D***` (ASCII initials, at most 4 words) |
//! | `pii.postal_address` | `10 rue des Lilas` | `***` |
//! | `secret.aws_key` | `AKIAIOSFODNN7EXAMPLE` | `AKIA****************`; secret keys `********` |
//! | `secret.password_hash` | `$2b$12$…` | `********` |
//!
//! # Fingerprints
//!
//! `hmac-sha256:<hex>` =
//! `HMAC-SHA256(agent_local_key, "databastion/fp/v1" 0x00 domain 0x00 normalized_value)`
//! (contract `Fingerprint`), where `domain` is the classifier id
//! (`pii.email`…) or `db_user` for `db_user_fingerprint`. The domain keeps a
//! value fingerprinted under one classifier (or as an account name) from
//! correlating with the same string under another. The key is the
//! agent-local key loaded by the core (`<state_dir>/hmac.key`, 32 bytes) and
//! handed to [`HmacKey::new`]. Normalization before hashing, so that equal
//! values correlate: e-mail trimmed and lowercased; IBAN, card and NIR
//! without separators, uppercase; phone as `+<digits>` when written with `+`,
//! national digits as is (`0X…` becomes `+33X…` and `00…` becomes `+…` only
//! with [`PhoneRegion::Fr`]); birth date as ISO `YYYY-MM-DD`; names and
//! addresses NFC-normalized, trimmed, whitespace collapsed, lowercased; keys
//! and hashes trimmed only.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::detect;
pub use crate::id::ClassifierId;
use crate::names::NormalizedName;

/// Fully redacted placeholder, used when no format applies.
const FULLY_REDACTED: &str = "***";
/// Longest run of letters or digits a masked sample may keep (contract
/// `MaskedSample`: no run of more than 4). Also the bound of the property
/// tests: no run of more than 4 consecutive digits of the raw value can
/// survive masking.
pub const MAX_KEPT_RUN: usize = 4;
/// Contract `MaskedSample.maxLength`.
const MAX_MASKED_CHARS: usize = 128;
/// Minimum length of the agent-local HMAC key, in bytes.
pub const MIN_HMAC_KEY_LEN: usize = 32;
/// Fingerprint prefix (contract `Fingerprint`).
const FINGERPRINT_PREFIX: &str = "hmac-sha256:";

/// A raw value sampled from a target, borrowed. Never leaves the agent,
/// never logged.
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
    pub(crate) fn expose(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for RawSample<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawSample(<redacted>)")
    }
}

/// A raw value sampled from a target, owned by the connector. Zeroized on
/// drop, redacted `Debug`, no `Display`, no `Clone`.
pub struct RawValue(Zeroizing<String>);

impl RawValue {
    /// Takes ownership of a value read from a target.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrows it as a [`RawSample`] for the classifiers.
    #[must_use]
    pub fn as_sample(&self) -> RawSample<'_> {
        RawSample(self.0.as_str())
    }
}

impl fmt::Debug for RawValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawValue(<redacted>)")
    }
}

/// A sample that went through masking. Safe to send to the console.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MaskedSample(String);

impl MaskedSample {
    /// The masked representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn redacted() -> Self {
        Self(FULLY_REDACTED.to_owned())
    }

    /// Enforces the contract `MaskedSample` rules, plus at most
    /// [`MAX_KEPT_RUN`] digits in total; `***` otherwise.
    fn checked(candidate: String) -> Self {
        let digits = candidate.chars().filter(char::is_ascii_digit).count();
        if digits <= MAX_KEPT_RUN && masked_sample_conforms(&candidate) {
            Self(candidate)
        } else {
            Self::redacted()
        }
    }
}

/// Contract `MaskedSample` rules, restricted to ASCII output: printable
/// ASCII only, 1..=128 characters, at least one `*`, no run of more than
/// [`MAX_KEPT_RUN`] letters or digits, and at least half of the letters,
/// digits and `*` are `*` (the console-side 50 % rule).
#[must_use]
pub fn masked_sample_conforms(s: &str) -> bool {
    let len = s.chars().count();
    if len == 0 || len > MAX_MASKED_CHARS || !s.chars().all(|c| (' '..='~').contains(&c)) {
        return false;
    }
    let (mut run, mut stars, mut kept) = (0usize, 0usize, 0usize);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            run += 1;
            kept += 1;
            if run > MAX_KEPT_RUN {
                return false;
            }
        } else {
            run = 0;
            if c == '*' {
                stars += 1;
            }
        }
    }
    stars >= 1 && stars >= kept
}

/// Masks a raw sample without knowing its type: the fully redacted `***`,
/// which reveals nothing (not even the length).
#[must_use]
pub fn mask(_raw: &RawSample<'_>) -> MaskedSample {
    MaskedSample::redacted()
}

/// Masks a raw value known to belong to `classifier`, with the format of
/// the module table. A value that does not parse as the classifier is
/// fully redacted.
#[must_use]
pub fn mask_as(classifier: ClassifierId, raw: &RawSample<'_>) -> MaskedSample {
    match normalize(classifier, raw.expose(), PhoneRegion::Unknown) {
        Some(norm) => MaskedSample::checked(format_masked(classifier, raw.expose(), &norm)),
        None => MaskedSample::redacted(),
    }
}

/// Builds the masked form from the raw token (for its layout) and its
/// normalized form (for its content).
fn format_masked(classifier: ClassifierId, raw: &str, norm: &str) -> String {
    match classifier {
        ClassifierId::Email => mask_email(norm),
        ClassifierId::Iban => mask_iban(norm),
        ClassifierId::CardNumber => mask_card(norm),
        ClassifierId::Phone => mask_phone(raw.trim()),
        ClassifierId::Nir => "* ** ** ** *** *** **".to_owned(),
        ClassifierId::BirthDate => "****-**-**".to_owned(),
        ClassifierId::PersonName => mask_person_name(norm, raw),
        ClassifierId::PostalAddress => FULLY_REDACTED.to_owned(),
        ClassifierId::AwsKey => {
            if norm.len() == 20 && (norm.starts_with("AKIA") || norm.starts_with("ASIA")) {
                format!("{}{}", &norm[..4], "*".repeat(16))
            } else {
                "********".to_owned()
            }
        }
        ClassifierId::PasswordHash => "********".to_owned(),
    }
}

fn ascii_initial(s: &str) -> char {
    s.chars()
        .next()
        .filter(char::is_ascii_alphanumeric)
        .unwrap_or('*')
}

fn mask_email(norm: &str) -> String {
    let Some((local, domain)) = norm.rsplit_once('@') else {
        return FULLY_REDACTED.to_owned();
    };
    let tld = domain.rsplit('.').next().unwrap_or("");
    let tld = if (2..=4).contains(&tld.len()) && tld.chars().all(|c| c.is_ascii_alphabetic()) {
        tld
    } else {
        "***"
    };
    format!(
        "{}***@{}***.{tld}",
        ascii_initial(local),
        ascii_initial(domain)
    )
}

fn group4(chars: &[char]) -> String {
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn mask_iban(norm: &str) -> String {
    let chars: Vec<char> = norm.chars().collect();
    if chars.len() < 15 {
        return FULLY_REDACTED.to_owned();
    }
    let keep_from = chars.len() - 4;
    let masked: Vec<char> = chars
        .iter()
        .enumerate()
        .map(|(i, c)| if i < 2 || i >= keep_from { *c } else { '*' })
        .collect();
    group4(&masked)
}

fn mask_card(norm: &str) -> String {
    let chars: Vec<char> = norm.chars().collect();
    if chars.len() < 12 {
        return FULLY_REDACTED.to_owned();
    }
    let keep_from = chars.len() - 4;
    let masked: Vec<char> = chars
        .iter()
        .enumerate()
        .map(|(i, c)| if i >= keep_from { *c } else { '*' })
        .collect();
    group4(&masked)
}

/// E.164 country code length (1 to 3 digits) of an international number
/// given as digits after `+`.
fn country_code_len(digits: &str) -> usize {
    let two = digits
        .get(..2)
        .and_then(|d| d.parse::<u32>().ok())
        .unwrap_or(0);
    match digits.as_bytes().first() {
        Some(b'1' | b'7') => 1,
        _ if matches!(
            two,
            20 | 27
                | 30..=34
                | 36
                | 39
                | 40
                | 41
                | 43..=49
                | 51..=58
                | 60..=66
                | 81
                | 82
                | 84
                | 86
                | 90..=95
                | 98
        ) =>
        {
            2
        }
        _ => 3,
    }
}

/// Keeps the layout (`+`, spaces, dots, hyphens, slashes, parentheses), the country code after
/// `+` and the last digits, at most [`MAX_KEPT_RUN`] digits in total
/// (`+1 *** *** **25`, `+33 * ** ** ** 78`, `+351 *** *** **5`); a national
/// number keeps its last 2 digits only (`** ** ** ** 78`).
fn mask_phone(raw: &str) -> String {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    let total = digits.len();
    if total < 8 {
        return FULLY_REDACTED.to_owned();
    }
    let (head, tail) = if raw.starts_with('+') {
        let cc = country_code_len(&digits);
        (cc, MAX_KEPT_RUN.saturating_sub(cc).min(2))
    } else {
        (0, 2)
    };
    let mut seen = 0;
    raw.chars()
        .filter_map(|c| {
            if c.is_ascii_digit() {
                seen += 1;
                Some(if seen <= head || seen > total - tail {
                    c
                } else {
                    '*'
                })
            } else if matches!(c, '+' | ' ' | '.' | '-' | '/' | '(' | ')') {
                Some(c)
            } else {
                None
            }
        })
        .collect()
}

fn mask_person_name(norm: &str, raw: &str) -> String {
    let words: Vec<&str> = raw.split_whitespace().collect();
    if words.is_empty() || words.len() > 4 || norm.is_empty() {
        return FULLY_REDACTED.to_owned();
    }
    words
        .iter()
        .map(|w| format!("{}***", ascii_initial(w).to_ascii_uppercase()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// How a national phone number (without `+`) is normalized before hashing.
/// Comes from the column or the agent configuration, never guessed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PhoneRegion {
    /// Unknown region: national numbers are fingerprinted as their digits.
    #[default]
    Unknown,
    /// France: `0X XX XX XX XX` -> `+33X…`, international prefix `00` -> `+`.
    Fr,
}

/// Normalized form of a value for `classifier`, used for fingerprints and
/// masking. `None` when the value does not parse as that classifier.
/// Zeroized on drop, like its temporaries.
pub(crate) fn normalize(
    classifier: ClassifierId,
    raw: &str,
    region: PhoneRegion,
) -> Option<Zeroizing<String>> {
    let v = raw.trim();
    if v.is_empty() || v.len() > detect::MAX_SCAN_BYTES {
        return None;
    }
    let z = |s: String| Zeroizing::new(s);
    match classifier {
        ClassifierId::Email => {
            let lower = z(v.to_lowercase());
            crate::validate::email_valid(&lower).then_some(lower)
        }
        ClassifierId::Iban => {
            let compact = z(v
                .chars()
                .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '.'))
                .collect());
            let upper = z(compact.to_ascii_uppercase());
            crate::validate::iban_valid(&upper).then_some(upper)
        }
        ClassifierId::CardNumber => {
            let d = z(v.chars().filter(char::is_ascii_digit).collect());
            let seps_only = v
                .chars()
                .all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
            (seps_only && crate::validate::luhn_valid(&d) && crate::validate::card_prefix_valid(&d))
                .then_some(d)
        }
        ClassifierId::Nir => {
            let compact = z(v.chars().filter(char::is_ascii_alphanumeric).collect());
            if v.chars()
                .any(|c| !(c.is_ascii_alphanumeric() || " .-/".contains(c)))
            {
                return None;
            }
            let upper = z(compact.to_ascii_uppercase());
            crate::validate::nir_valid(&upper).then_some(upper)
        }
        ClassifierId::Phone => normalize_phone(v, region),
        ClassifierId::BirthDate => normalize_date(v).map(z),
        ClassifierId::PersonName | ClassifierId::PostalAddress => {
            let nfc = z(v.nfc().collect());
            let words: Vec<&str> = nfc
                .split(|c: char| c.is_whitespace() || c == '$')
                .filter(|w| !w.is_empty())
                .collect();
            let joined = z(words.join(" "));
            let lower = z(joined.to_lowercase());
            (!lower.is_empty()).then_some(lower)
        }
        ClassifierId::AwsKey | ClassifierId::PasswordHash => Some(z(v.to_owned())),
    }
}

fn normalize_phone(v: &str, region: PhoneRegion) -> Option<Zeroizing<String>> {
    let plus = v.starts_with('+');
    let body = v.strip_prefix('+').unwrap_or(v);
    if !body
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '.' | '-' | '/' | '(' | ')'))
    {
        return None;
    }
    // An international number's trunk `(0)` is not dialled: `+44 (0)20 …`.
    let body = if plus {
        Zeroizing::new(body.replace("(0)", ""))
    } else {
        Zeroizing::new(body.to_owned())
    };
    let digits = Zeroizing::new(
        body.chars()
            .filter(char::is_ascii_digit)
            .collect::<String>(),
    );
    if !(8..=15).contains(&digits.len()) {
        return None;
    }
    let out = match region {
        _ if plus => format!("+{}", digits.as_str()),
        PhoneRegion::Fr if digits.starts_with("00") => format!("+{}", &digits[2..]),
        PhoneRegion::Fr if digits.len() == 10 && digits.starts_with('0') => {
            format!("+33{}", &digits[1..])
        }
        _ => digits.as_str().to_owned(),
    };
    Some(Zeroizing::new(out))
}

/// ISO `YYYY-MM-DD` of any date format the detectors accept (an ambiguous
/// `01/02/1980` is read day first, like the detector).
fn normalize_date(v: &str) -> Option<String> {
    let d = detect::parse_date(v)?;
    Some(format!("{:04}-{:02}-{:02}", d.year, d.month, d.day))
}

/// Domain-separation prefix of fingerprints (contract `Fingerprint`).
const FINGERPRINT_DOMAIN: &[u8] = b"databastion/fp/v1\0";
/// Fingerprint domain of account names (`db_user_fingerprint`).
const DB_USER_DOMAIN: &str = "db_user";
/// Prefix of the per-column sample ordering (not a fingerprint).
const SAMPLE_ORDER_DOMAIN: &[u8] = b"sample-order\0";

/// The agent-local HMAC key, held as a keyed HMAC-SHA256 state built once
/// and cloned per value. Zeroized on drop (RustCrypto `zeroize` feature),
/// redacted `Debug`, no `Clone`, never serialized. Built by the core from
/// the bytes of `<state_dir>/hmac.key`.
pub struct HmacKey(Hmac<Sha256>);

/// Error building an [`HmacKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTooShort;

impl fmt::Display for KeyTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HMAC key shorter than {MIN_HMAC_KEY_LEN} bytes")
    }
}

impl std::error::Error for KeyTooShort {}

// The keyed HMAC state kept by `HmacKey` is key-equivalent: it must be wiped on drop. This fails
// to compile if a dependency change drops sha2's `zeroize` feature.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: sha2::digest::zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<sha2::block_api::Sha256VarCore>();
};

const HEX: &[u8; 16] = b"0123456789abcdef";

impl HmacKey {
    /// Keys an HMAC-SHA256 state with `bytes` (at least
    /// [`MIN_HMAC_KEY_LEN`]). The caller keeps and zeroizes its own copy.
    ///
    /// # Errors
    /// [`KeyTooShort`] when fewer than [`MIN_HMAC_KEY_LEN`] bytes are given.
    pub fn new(bytes: &[u8]) -> Result<Self, KeyTooShort> {
        if bytes.len() < MIN_HMAC_KEY_LEN {
            return Err(KeyTooShort);
        }
        <Hmac<Sha256> as KeyInit>::new_from_slice(bytes)
            .map(Self)
            .map_err(|_| KeyTooShort)
    }

    /// A fresh random key (OS CSPRNG) for one call, e.g. to order samples
    /// when the agent key is not available. `None` if the CSPRNG fails.
    pub(crate) fn ephemeral() -> Option<Self> {
        let mut bytes = Zeroizing::new([0u8; MIN_HMAC_KEY_LEN]);
        getrandom::fill(bytes.as_mut_slice()).ok()?;
        Self::new(bytes.as_slice()).ok()
    }

    /// Raw HMAC-SHA256 over the concatenation of `parts`.
    pub(crate) fn raw_mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = self.0.clone();
        for p in parts {
            mac.update(p);
        }
        let mut tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_slice());
        tag.as_mut_slice().zeroize();
        out
    }

    fn fingerprint_in_domain(&self, domain: &str, data: &[u8]) -> Fingerprint {
        let mut tag = self.raw_mac(&[FINGERPRINT_DOMAIN, domain.as_bytes(), b"\0", data]);
        let mut hex = String::with_capacity(FINGERPRINT_PREFIX.len() + 64);
        hex.push_str(FINGERPRINT_PREFIX);
        for b in &tag {
            hex.push(char::from(HEX[usize::from(b >> 4)]));
            hex.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        tag.zeroize();
        Fingerprint(hex)
    }

    /// Fingerprint of a value of `classifier`, after normalization, with an
    /// unknown phone region. `None` when the value does not parse as that
    /// classifier.
    #[must_use]
    pub fn fingerprint(
        &self,
        classifier: ClassifierId,
        raw: &RawSample<'_>,
    ) -> Option<Fingerprint> {
        self.fingerprint_in(classifier, raw, PhoneRegion::Unknown)
    }

    /// Fingerprint of a value of `classifier`, national phone numbers
    /// normalized for `region`.
    #[must_use]
    pub fn fingerprint_in(
        &self,
        classifier: ClassifierId,
        raw: &RawSample<'_>,
        region: PhoneRegion,
    ) -> Option<Fingerprint> {
        let norm = normalize(classifier, raw.expose(), region)?;
        Some(self.fingerprint_in_domain(classifier.as_str(), norm.as_bytes()))
    }

    /// Fingerprint of an account name for `db_user_fingerprint`: exact
    /// bytes (PostgreSQL role names are case-sensitive), in the `db_user`
    /// domain, so it never equals the fingerprint of a column value.
    #[must_use]
    pub fn fingerprint_db_user(&self, raw: &RawSample<'_>) -> Fingerprint {
        self.fingerprint_in_domain(DB_USER_DOMAIN, raw.expose().as_bytes())
    }

    /// Per-column ordering key of a sampled value: deterministic for a key,
    /// but different for every column, so the samples kept for two columns
    /// of the same table do not come from the same rows.
    pub(crate) fn sample_order(&self, column: &str, value: &str) -> [u8; 32] {
        self.raw_mac(&[
            SAMPLE_ORDER_DOMAIN,
            column.as_bytes(),
            b"\0",
            value.as_bytes(),
        ])
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacKey(<redacted>)")
    }
}

/// An `hmac-sha256:` fingerprint (contract `Fingerprint`). Only an
/// [`HmacKey`] can produce one.
///
/// ```compile_fail
/// use databastion_classifiers::masking::Fingerprint;
/// let _ = Fingerprint("jane.doe@example.com".to_owned());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// `hmac-sha256:` followed by 64 lowercase hex digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A finding whose samples have all been masked. The only finding type the
/// uplink accepts.
///
/// Outside this crate it can only be built from a [`ClassifierId`],
/// [`MaskedSample`]s and [`Fingerprint`]s, never from a string:
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
    fingerprints: Vec<Fingerprint>,
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
            fingerprints: Vec::new(),
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

    /// Sets the HMAC fingerprints of matched values.
    #[must_use]
    pub fn with_fingerprints(mut self, fingerprints: Vec<Fingerprint>) -> Self {
        self.fingerprints = fingerprints;
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

    /// HMAC fingerprints of matched values.
    #[must_use]
    pub fn fingerprints(&self) -> &[Fingerprint] {
        &self.fingerprints
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
    use ClassifierId as C;

    fn m(c: ClassifierId, v: &str) -> String {
        mask_as(c, &RawSample::new(v)).as_str().to_owned()
    }

    fn key(b: u8) -> HmacKey {
        HmacKey::new(&[b; 32]).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn raw_sample_debug_is_redacted() {
        let raw = RawSample::new("jane.doe@example.com");
        let debug = format!("{raw:?}");
        assert!(!debug.contains("jane"));
        assert!(debug.contains("<redacted>"));
        let owned = RawValue::new("jane.doe@example.com".to_owned());
        assert!(!format!("{owned:?}").contains("jane"));
        assert_eq!(owned.as_sample().expose(), "jane.doe@example.com");
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
        let fp = key(1).fingerprint(C::Email, &raw);
        let finding = MaskedFinding::new(ClassifierId::PII_EMAIL, vec![mask_as(C::Email, &raw)])
            .with_fingerprints(fp.into_iter().collect());
        assert_eq!(finding.classifier().as_str(), "pii.email");
        assert_eq!(finding.masked_samples().len(), 1);
        assert_eq!(finding.fingerprints().len(), 1);
        assert!(!format!("{finding:?}").contains("jane.doe"));
    }

    #[test]
    fn documented_formats() {
        assert_eq!(m(C::Email, "Jane.Doe@Example.COM"), "j***@e***.com");
        assert_eq!(m(C::Email, "a@b.museum"), "a***@b***.***");
        assert_eq!(
            m(C::Iban, "FR76 3000 6000 0112 3456 7890 189"),
            "FR** **** **** **** **** ***0 189"
        );
        assert_eq!(
            m(C::Iban, "DE89370400440532013000"),
            "DE** **** **** **** **30 00"
        );
        assert_eq!(
            m(C::CardNumber, "4111-1111-1111-1111"),
            "**** **** **** 1111"
        );
        assert_eq!(m(C::CardNumber, "378282246310005"), "**** **** ***0 005");
        assert_eq!(m(C::Phone, "06 12 34 56 78"), "** ** ** ** 78");
        assert_eq!(m(C::Phone, "+33 6 12 34 56 78"), "+33 * ** ** ** 78");
        assert_eq!(m(C::Phone, "+1 202 555 0125"), "+1 *** *** **25");
        assert_eq!(m(C::Phone, "+351 912 345 678"), "+351 *** *** **8");
        assert_eq!(m(C::Phone, "0612345678"), "********78");
        assert_eq!(m(C::BirthDate, "1950-12-01"), "****-**-**");
        assert_eq!(m(C::PersonName, "Jane Doe"), "J*** D***");
        assert_eq!(m(C::PersonName, "Élodie Vincent"), "**** V***");
        assert_eq!(m(C::PostalAddress, "10 rue des Lilas"), "***");
        assert_eq!(m(C::AwsKey, "AKIAIOSFODNN7EXAMPLE"), "AKIA****************");
        assert_eq!(
            m(C::AwsKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "********"
        );
        assert_eq!(m(C::PasswordHash, "$2b$12$abc"), "********");
        // Not parseable as the classifier: fully redacted.
        assert_eq!(m(C::Iban, "FR7630006000011234567890180"), "***");
        assert_eq!(m(C::Email, "not an email"), "***");
        assert_eq!(m(C::CardNumber, "4111 1111 1111 1112"), "***");
    }

    #[test]
    fn every_documented_format_conforms() {
        for s in [
            "j***@e***.com",
            "FR** **** **** **** **** ***0 189",
            "**** **** **** 1111",
            "** ** ** ** 78",
            "+33 * ** ** ** 78",
            "* ** ** ** *** *** **",
            "****-**-**",
            "J*** D***",
            "***",
            "AKIA****************",
            "********",
        ] {
            assert!(masked_sample_conforms(s), "{s}");
        }
        assert!(!masked_sample_conforms("jane@e***.com"));
        assert!(!masked_sample_conforms("06 12 34 ** 78"));
        assert!(!masked_sample_conforms("abc"));
        assert!(!masked_sample_conforms("é***"));
        assert!(!masked_sample_conforms(""));
    }

    #[test]
    fn fingerprints_normalize_equal_values() {
        let k = key(7);
        let fp = |c, v| k.fingerprint(c, &RawSample::new(v));
        assert_eq!(
            fp(C::Email, " Jane.Doe@Example.com "),
            fp(C::Email, "jane.doe@example.com")
        );
        assert_eq!(
            fp(C::Iban, "fr76 3000 6000 0112 3456 7890 189"),
            fp(C::Iban, "FR7630006000011234567890189")
        );
        assert_eq!(
            fp(C::CardNumber, "4111-1111-1111-1111"),
            fp(C::CardNumber, "4111 1111 1111 1111")
        );
        assert_eq!(
            fp(C::Phone, "+33 6 12 34 56 78"),
            fp(C::Phone, "+33612345678")
        );
        // National numbers map to +33 only when the region says FR.
        assert_ne!(
            fp(C::Phone, "06 12 34 56 78"),
            fp(C::Phone, "+33 6 12 34 56 78")
        );
        assert_eq!(fp(C::Phone, "06 12 34 56 78"), fp(C::Phone, "0612345678"));
        let fr = |v| k.fingerprint_in(C::Phone, &RawSample::new(v), PhoneRegion::Fr);
        assert_eq!(fr("06 12 34 56 78"), fp(C::Phone, "+33 6 12 34 56 78"));
        assert_eq!(fr("0033612345678"), fp(C::Phone, "+33612345678"));
        // NFC: precomposed and decomposed `é` are the same name.
        assert_eq!(
            fp(C::PersonName, "\u{e9}lodie"),
            fp(C::PersonName, "e\u{301}lodie")
        );
        assert_eq!(
            fp(C::BirthDate, "01/12/1950"),
            fp(C::BirthDate, "1950-12-01")
        );
        assert_eq!(
            fp(C::PersonName, " Jane   DOE"),
            fp(C::PersonName, "jane doe")
        );
        assert_ne!(
            fp(C::AwsKey, "AKIAIOSFODNN7EXAMPLE"),
            fp(C::AwsKey, "akiaiosfodnn7example")
        );
        assert!(fp(C::Iban, "FR7630006000011234567890180").is_none());
        let f = fp(C::Email, "jane@example.com").unwrap_or_else(|| unreachable!());
        assert!(f.as_str().starts_with("hmac-sha256:"));
        assert_eq!(f.as_str().len(), 76);
        assert!(
            f.as_str()[12..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    fn hex(tag: &[u8]) -> String {
        tag.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn raw_hmac_matches_rfc_4231_test_case_6() {
        // RFC 4231 section 4.7: 131-byte key 0xaa.
        let k = HmacKey::new(&[0xaa; 131]).unwrap_or_else(|_| unreachable!());
        let tag = k.raw_mac(&[b"Test Using Larger Than Block-Size Key - Hash Key First"]);
        assert_eq!(
            hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // RFC 4868 section 2.7.2.1 test case 1 (32-byte key), split input.
        let k = HmacKey::new(&[0x0b; 32]).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            hex(&k.raw_mac(&[b"Hi ", b"There"])),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }

    #[test]
    fn fingerprints_use_the_documented_domain_separation() {
        // HMAC(key, "databastion/fp/v1" 0x00 domain 0x00 value), computed with
        // Python's `hmac` module.
        let k = HmacKey::new(&[0x0b; 32]).unwrap_or_else(|_| unreachable!());
        let email = k
            .fingerprint(C::Email, &RawSample::new("Jane@Example.com"))
            .unwrap_or_else(|| unreachable!());
        assert_eq!(
            email.as_str(),
            "hmac-sha256:9476a5162ee0b25ec3bac28bf011feca60b3c044271bdc42608376722e899ce5"
        );
        assert_eq!(
            k.fingerprint_db_user(&RawSample::new("app_rw")).as_str(),
            "hmac-sha256:908c960374bebb25445345911cbad22785e24f7a31e86a50f90bb7393732f6c5"
        );
    }

    #[test]
    fn same_string_differs_across_domains() {
        let k = key(4);
        let fp = |c, v| k.fingerprint(c, &RawSample::new(v));
        // The account name never equals a column value's fingerprint.
        let v = "jane@example.com";
        let db_user = Some(k.fingerprint_db_user(&RawSample::new(v)));
        assert_ne!(fp(C::Email, v), db_user);
        // Same normalized string under two classifiers.
        let name = "jean martin";
        assert!(fp(C::PersonName, name).is_some());
        assert_ne!(fp(C::PersonName, name), fp(C::PostalAddress, name));
        assert_ne!(
            k.fingerprint_db_user(&RawSample::new(name)),
            fp(C::PersonName, name).unwrap_or_else(|| unreachable!())
        );
        let hash = "$2b$12$EjXXuZ0VGWGh0JSVANuaawsTPVLWNArLzyRPleGMlMiMsUopy5qt2";
        assert_ne!(fp(C::PasswordHash, hash), fp(C::AwsKey, hash));
        // Every pair of classifiers accepting the same string differs.
        for a in ClassifierId::ALL {
            for b in ClassifierId::ALL {
                if a != b
                    && let (Some(x), Some(y)) = (fp(a, name), fp(b, name))
                {
                    assert_ne!(x, y, "{a} {b}");
                }
            }
        }
    }

    #[test]
    fn masked_samples_keep_at_most_four_digits() {
        // Conforms to the contract (runs <= 4, 50 % stars) but keeps 8 digits.
        assert!(masked_sample_conforms("12** 34** 56** 78**"));
        assert_eq!(
            MaskedSample::checked("12** 34** 56** 78**".to_owned()).as_str(),
            "***"
        );
    }

    #[test]
    fn short_keys_are_rejected() {
        assert_eq!(HmacKey::new(&[0; 31]).err(), Some(KeyTooShort));
        assert!(!format!("{:?}", key(0x41)).contains("AAAA"));
    }
}
