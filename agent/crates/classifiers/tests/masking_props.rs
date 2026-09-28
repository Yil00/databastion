//! Property tests on masking and fingerprints (ADR-0003, ADR-0007, I2).
//!
//! - a masked sample always conforms to the contract `MaskedSample` rules;
//! - it never contains the raw value, and keeps at most `MAX_KEPT_RUN` (4)
//!   digits in total, so no run of more than 4 consecutive raw digits
//!   survives;
//! - masking is stable, and re-masking a masked sample never reveals more;
//! - fingerprints are deterministic per key, differ across keys and across
//!   domains (classifiers, `db_user`), and have the contract shape;
//! - no raw value appears in any `Debug` output.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::column::ColumnClassifier;
use databastion_classifiers::masking::{
    ClassifierId, HmacKey, MAX_KEPT_RUN, RawSample, RawValue, mask_as, masked_sample_conforms,
};
use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

fn luhn_digit(partial: &str) -> char {
    let mut sum = 0;
    for (i, b) in partial.bytes().rev().enumerate() {
        let mut d = u32::from(b - b'0');
        if i % 2 == 0 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    char::from_digit((10 - sum % 10) % 10, 10).unwrap()
}

fn iban_check(country: &str, bban: &str) -> String {
    let moved = format!("{bban}{country}00");
    let mut rem = 0u32;
    for c in moved.chars() {
        let v = c.to_digit(36).unwrap();
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    format!("{:02}", 98 - rem)
}

fn card() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("4"), Just("51"), Just("55")],
        "[0-9]{14}",
        prop_oneof![Just(""), Just(" "), Just("-")],
    )
        .prop_map(|(prefix, body, sep)| {
            let partial = format!("{prefix}{}", &body[..15 - prefix.len()]);
            let n = format!("{partial}{}", luhn_digit(&partial));
            n.as_bytes()
                .chunks(4)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(sep)
        })
}

fn iban() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just(("FR", 23)), Just(("DE", 18))],
        "[0-9]{23}",
        prop_oneof![Just(""), Just(" "), Just("-"), Just(".")],
        any::<bool>(),
    )
        .prop_map(|((country, len), digits, sep, lower)| {
            let bban = &digits[..len];
            let raw = format!("{country}{}{bban}", iban_check(country, bban));
            let v = raw
                .as_bytes()
                .chunks(4)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(sep);
            if lower { v.to_lowercase() } else { v }
        })
}

fn nir() -> impl Strategy<Value = String> {
    (
        "[12]",
        "[0-9]{2}",
        1u32..=12,
        "[0-9]{8}",
        prop_oneof![Just(""), Just(" "), Just("."), Just("-")],
        prop_oneof![Just(""), Just(" "), Just(" / "), Just("-")],
    )
        .prop_map(|(sex, year, month, rest, sep, key_sep)| {
            let body = format!("{sex}{year}{month:02}{rest}");
            let key = 97 - body.parse::<u64>().unwrap() % 97;
            let b = &body;
            format!(
                "{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{key_sep}{key:02}",
                &b[..1],
                &b[1..3],
                &b[3..5],
                &b[5..7],
                &b[7..10],
                &b[10..13]
            )
        })
}

fn phone() -> impl Strategy<Value = String> {
    prop_oneof![
        (
            "[1-9]",
            "[0-9]{8}",
            prop_oneof![Just(""), Just(" "), Just(".")]
        )
            .prop_map(|(d, rest, sep)| {
                let all = format!("0{d}{rest}");
                all.as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join(sep)
            }),
        ("[1-9][0-9]{0,2}", "[0-9]{3}", "[0-9]{3}", "[0-9]{4}")
            .prop_map(|(cc, a, b, c)| format!("+{cc} {a} {b} {c}")),
        // Parentheses, slashes and a trunk `(0)`.
        ("[2-9][0-9]{2}", "[2-9][0-9]{2}", "[0-9]{4}")
            .prop_map(|(a, b, c)| format!("({a}) {b}-{c}")),
        ("[0-9]{4}").prop_map(|c| format!("+44 (0)20 7946 {c}")),
        ("[1-9]", "[0-9]{8}").prop_map(|(d, r)| format!(
            "+33 (0){d} {} {} {} {}",
            &r[..2],
            &r[2..4],
            &r[4..6],
            &r[6..]
        )),
        ("[0-9]{7}").prop_map(|r| format!("030/{r}")),
        ("[1-9][0-9]{0,2}", "[0-9]{8}").prop_map(|(cc, r)| format!("+({cc}) {r}")),
    ]
}

fn email() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9]{1,6}(\\.[a-z0-9]{1,6})?@[a-z]{1,8}\\.(com|org|fr|museum)",
        // Accented local parts, composed or decomposed (NFD).
        (
            "(josé|hélène|chloé|anaïs|jürgen)",
            "[a-z]{1,6}",
            any::<bool>()
        )
            .prop_map(|(a, b, decompose)| {
                let v = format!("{a}.{b}@example.fr");
                if decompose { v.nfd().collect() } else { v }
            }),
    ]
}

const MONTHS: &[&str] = &[
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
];
const MONTHS_EN: &[&str] = &[
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn birth_date() -> impl Strategy<Value = String> {
    (
        1900u32..=2030,
        1u32..=12,
        1u32..=28,
        0u8..8,
        0u32..24,
        0u32..60,
    )
        .prop_map(|(y, m, d, fmt, h, min)| match fmt {
            0 => format!("{y}-{m:02}-{d:02}"),
            1 => format!("{d:02}/{m:02}/{y}"),
            2 => format!("{d:02}.{m:02}.{y}"),
            3 => format!("{y}{m:02}{d:02}"),
            4 => format!("{d} {} {y}", MONTHS[m as usize - 1]),
            // Textual month, decomposed (NFD).
            5 => format!("{d} {} {y}", MONTHS[m as usize - 1])
                .nfd()
                .collect(),
            6 => format!("{} {d}, {y}", MONTHS_EN[m as usize - 1]),
            _ => format!("{y}-{m:02}-{d:02} {h:02}:{min:02}:00"),
        })
}

fn person_name() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::collection::vec("[A-Z][a-z]{1,9}", 1..=3).prop_map(|w| w.join(" ")),
        // Accented names, composed or decomposed (NFD).
        (
            "(Élodie|Chloé|Anaïs|Jérôme|Hélène)",
            "(Lefèvre|Müller|Gómez|Béranger)",
            any::<bool>()
        )
            .prop_map(|(f, l, decompose)| {
                let v = format!("{f} {l}");
                if decompose { v.nfd().collect() } else { v }
            }),
    ]
}

fn address() -> impl Strategy<Value = String> {
    (
        "[1-9][0-9]{0,2}",
        "(rue|avenue|chemin) (des|du) [A-Z][a-z]{2,9}",
    )
        .prop_map(|(n, s)| format!("{n} {s}"))
}

fn aws_key() -> impl Strategy<Value = String> {
    prop_oneof![
        "(AKIA|ASIA)[A-Z0-9]{16}",
        "[A-Z]{5}[a-z]{5}[0-9]{5}[A-Za-z0-9/+]{25}",
    ]
}

fn password_hash() -> impl Strategy<Value = String> {
    prop_oneof![
        "\\$2b\\$1[0-4]\\$[./A-Za-z0-9]{53}",
        "\\$6\\$[./A-Za-z0-9]{8}\\$[./A-Za-z0-9]{86}",
    ]
}

/// A valid value for each classifier.
fn classified() -> impl Strategy<Value = (ClassifierId, String)> {
    prop_oneof![
        email().prop_map(|v| (ClassifierId::Email, v)),
        iban().prop_map(|v| (ClassifierId::Iban, v)),
        card().prop_map(|v| (ClassifierId::CardNumber, v)),
        nir().prop_map(|v| (ClassifierId::Nir, v)),
        phone().prop_map(|v| (ClassifierId::Phone, v)),
        birth_date().prop_map(|v| (ClassifierId::BirthDate, v)),
        person_name().prop_map(|v| (ClassifierId::PersonName, v)),
        address().prop_map(|v| (ClassifierId::PostalAddress, v)),
        aws_key().prop_map(|v| (ClassifierId::AwsKey, v)),
        password_hash().prop_map(|v| (ClassifierId::PasswordHash, v)),
    ]
}

fn any_classifier() -> impl Strategy<Value = ClassifierId> {
    proptest::sample::select(ClassifierId::ALL.to_vec())
}

fn alnum_count(s: &str) -> usize {
    s.chars().filter(char::is_ascii_alphanumeric).count()
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn key(seed: u8) -> HmacKey {
    HmacKey::new(&[seed; 32]).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn masked_samples_conform_and_hide_the_value((c, raw) in classified()) {
        let masked = mask_as(c, &RawSample::new(&raw));
        let m = masked.as_str();
        prop_assert!(masked_sample_conforms(m), "{c}: {m}");
        prop_assert!(!m.contains(raw.as_str()), "{c}");
        // At most 4 digits kept in total: no 5-digit run of the raw value
        // survives, even across separators.
        let kept = digits(m);
        prop_assert!(kept.len() <= MAX_KEPT_RUN, "{c}: {m}");
        let raw_digits = digits(&raw);
        if raw_digits.len() > MAX_KEPT_RUN {
            for w in raw_digits.as_bytes().windows(MAX_KEPT_RUN + 1) {
                prop_assert!(!kept.contains(std::str::from_utf8(w).unwrap()));
            }
        }
        // Valid values are recognized: never the generic `***` for the
        // formats that keep something.
        if !matches!(c, ClassifierId::PostalAddress) {
            prop_assert_ne!(m, "***", "{}", c);
        }
    }

    #[test]
    fn arbitrary_input_is_masked_safely(
        c in any_classifier(),
        raw in "[ -~é日\u{200B}]{0,60}",
    ) {
        let m = mask_as(c, &RawSample::new(&raw));
        prop_assert!(masked_sample_conforms(m.as_str()));
        prop_assert!(digits(m.as_str()).len() <= MAX_KEPT_RUN);
        if alnum_count(&raw) > MAX_KEPT_RUN && !raw.contains('*') {
            prop_assert!(!m.as_str().contains(raw.as_str()));
        }
    }

    #[test]
    fn masking_is_stable_and_remasking_reveals_nothing((c, raw) in classified()) {
        let once = mask_as(c, &RawSample::new(&raw));
        prop_assert_eq!(&once, &mask_as(c, &RawSample::new(&raw)));
        for c2 in ClassifierId::ALL {
            let twice = mask_as(c2, &RawSample::new(once.as_str()));
            prop_assert!(masked_sample_conforms(twice.as_str()));
            prop_assert!(alnum_count(twice.as_str()) <= alnum_count(once.as_str()).max(1));
        }
    }

    #[test]
    fn fingerprints_are_keyed_and_deterministic(
        (c, raw) in classified(),
        k1 in any::<u8>(),
        k2 in any::<u8>(),
    ) {
        let v = RawSample::new(&raw);
        let a = key(k1).fingerprint(c, &v);
        prop_assert!(a.is_some(), "{c}");
        prop_assert_eq!(&a, &key(k1).fingerprint(c, &v));
        let f = a.unwrap();
        prop_assert_eq!(f.as_str().len(), 76);
        prop_assert!(f.as_str().starts_with("hmac-sha256:"));
        prop_assert!(f.as_str()[12..].chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')));
        prop_assert!(!f.as_str().contains(raw.as_str()));
        if k1 != k2 {
            prop_assert_ne!(Some(f), key(k2).fingerprint(c, &v));
        }
    }

    #[test]
    fn fingerprints_are_domain_separated((c, raw) in classified(), k in any::<u8>()) {
        let v = RawSample::new(&raw);
        let key = key(k);
        let own = key.fingerprint(c, &v).unwrap();
        prop_assert_ne!(&own, &key.fingerprint_db_user(&v));
        for other in ClassifierId::ALL {
            if other != c
                && let Some(f) = key.fingerprint(other, &v)
            {
                prop_assert_ne!(&own, &f, "{} {}", c, other);
            }
        }
    }

    #[test]
    fn distinct_values_have_distinct_fingerprints(a in email(), b in email()) {
        prop_assume!(a != b);
        let k = key(9);
        prop_assert_ne!(
            k.fingerprint(ClassifierId::Email, &RawSample::new(&a)),
            k.fingerprint(ClassifierId::Email, &RawSample::new(&b))
        );
    }

    #[test]
    fn debug_output_never_contains_raw_values(
        values in proptest::collection::vec(classified(), 1..20),
    ) {
        let k = key(5);
        let raws: Vec<RawSample<'_>> = values.iter().map(|(_, v)| RawSample::new(v)).collect();
        let owned: Vec<RawValue> = values.iter().map(|(_, v)| RawValue::new(v.clone())).collect();
        let findings = ColumnClassifier::new().with_key(&k).classify("value", &raws);
        let debug = format!("{raws:?} {owned:?} {k:?} {findings:?}");
        for (_, v) in &values {
            // A single word of letters (`Ni`, `Phone`) can collide with type
            // and field names of the Debug output itself; every other value
            // must be absent.
            if v.chars().all(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            prop_assert!(!debug.contains(v.as_str()));
        }
        prop_assert_eq!(debug.matches("<redacted>").count(), raws.len() + owned.len() + 1);
        for f in &findings {
            prop_assert!(f.masked_samples().len() <= 5);
            prop_assert!(f.fingerprints().len() <= 50);
            prop_assert!(f.matched() <= f.sampled());
            prop_assert!((0.0..=1.0).contains(&f.confidence()));
            for m in f.masked_samples() {
                prop_assert!(masked_sample_conforms(m.as_str()));
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Decomposed (NFD) values keep the masking guarantees.
    #[test]
    fn decomposed_values_are_masked_safely((c, raw) in classified()) {
        let nfd: String = raw.nfd().collect();
        let m = mask_as(c, &RawSample::new(&nfd));
        prop_assert!(masked_sample_conforms(m.as_str()), "{c}: {}", m.as_str());
        prop_assert!(digits(m.as_str()).len() <= MAX_KEPT_RUN);
        prop_assert!(!m.as_str().contains(nfd.as_str()));
    }

    /// Fingerprints are defined on the composed form: every caller of
    /// `HmacKey::fingerprint` agrees with the column path.
    #[test]
    fn fingerprints_ignore_the_normalization_form((c, raw) in classified(), k in any::<u8>()) {
        let nfc: String = raw.nfc().collect();
        let nfd: String = raw.nfd().collect();
        let key = key(k);
        prop_assert_eq!(
            key.fingerprint(c, &RawSample::new(&nfc)),
            key.fingerprint(c, &RawSample::new(&nfd))
        );
    }

    /// A column stored decomposed gives the same findings, masked samples
    /// and fingerprints as the same column composed.
    #[test]
    fn decomposed_columns_classify_like_composed_ones(
        values in proptest::collection::vec(classified(), 1..12),
        k in any::<u8>(),
    ) {
        let nfc: Vec<String> = values.iter().map(|(_, v)| v.nfc().collect()).collect();
        let nfd: Vec<String> = values.iter().map(|(_, v)| v.nfd().collect()).collect();
        let a: Vec<RawSample<'_>> = nfc.iter().map(|v| RawSample::new(v)).collect();
        let b: Vec<RawSample<'_>> = nfd.iter().map(|v| RawSample::new(v)).collect();
        let key = key(k);
        let c = ColumnClassifier::new().with_key(&key);
        prop_assert_eq!(c.classify("col_1", &a), c.classify("col_1", &b));
    }
}
