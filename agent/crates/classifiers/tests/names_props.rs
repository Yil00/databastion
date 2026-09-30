//! Property tests for the name normalizer (ADR-0009): deterministic
//! pseudo-random inputs (no extra dependency), checked against the generated
//! contract `Identifier` type and its `not` rule.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::names::{
    MAX_INDEX_DIGITS, MAX_TOTAL_DIGITS, NormalizedName, PathPart, conforms, is_numeric_like,
    longest_digit_run, normalize_field_path, normalize_ldap_attribute, normalize_ldap_dn,
    normalize_path, violates_numeric_rule,
};

/// xorshift64*: reproducible, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

const ALPHABET: &[&str] = &[
    "a",
    "b",
    "Z",
    "_",
    "-",
    " ",
    "+",
    ".",
    ".",
    ".",
    "0",
    "1",
    "5",
    "9",
    "@",
    "=",
    ":",
    ";",
    "/",
    "\\",
    "'",
    "\"",
    "`",
    "<",
    ">",
    "(",
    ")",
    ",",
    "*",
    "[",
    "]",
    "é",
    "日",
    "\u{0}",
    "\u{7}",
    "\u{200B}",
    "\u{202E}",
    "\u{FEFF}",
    "\u{E000}",
    "\u{2028}",
    "\u{AD}",
    "ou=",
    "dc=",
    "uid=",
    "cn=",
    "0612345678",
    "4111 1111 1111 1111",
    "+33 6 12 34 56 78",
    "jane@example.com",
    // Security review H1 / H2: non-ASCII digits and compatibility forms.
    "０",
    "９",
    "٠",
    "٩",
    "𝟎",
    "＠",
    "．",
    "%40",
    // Security re-review of #39, L1 / L2 / L4: NFKC expansion, `%uXXXX`
    // escapes, CJK ideographic digits.
    "\u{FDFA}",
    "%u0040",
    "%U002E",
    "零",
    "〇",
    "一",
    "五",
    "九",
    "六一二三四五六七八",
    // Review of the follow-ups, L3: CJK financial numerals.
    "壹",
    "陆",
    "貳",
    "两",
    "拾",
    "陆壹贰叁肆伍陆柒捌",
];

fn random_input(rng: &mut Rng) -> String {
    let parts = rng.below(24);
    (0..parts)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

/// Segments of ≥ 9 digits / separators in the input.
fn numeric_segments(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in input.chars() {
        if c.is_ascii_digit() || matches!(c, ' ' | '+' | '-') {
            current.push(c);
        } else {
            if current.chars().filter(char::is_ascii_digit).count() >= 9 {
                out.push(current.trim().to_owned());
            }
            current.clear();
        }
    }
    if current.chars().filter(char::is_ascii_digit).count() >= 9 {
        out.push(current.trim().to_owned());
    }
    out
}

fn check(input: &str, name: &NormalizedName) {
    let s = name.as_str();
    assert!(
        databastion_protocol::Identifier::try_from(s).is_ok(),
        "{input:?} -> {s:?} does not match the Identifier pattern"
    );
    assert!(
        !violates_numeric_rule(s),
        "{input:?} -> {s:?} violates `not`"
    );
    assert!(conforms(s));
    assert!(
        longest_digit_run(s) <= MAX_INDEX_DIGITS,
        "{input:?} -> {s:?} keeps more than 6 consecutive digits"
    );
    assert!(
        s.chars().filter(|c| is_numeric_like(*c)).count() <= MAX_TOTAL_DIGITS,
        "{input:?} -> {s:?} keeps more than 8 digits"
    );
    assert!(
        !s.contains('%') || s == "*",
        "{input:?} -> {s:?} keeps a percent escape"
    );
    assert!(!s.contains('#'), "{input:?} -> {s:?} keeps a placeholder");
    for seg in numeric_segments(input) {
        assert!(!s.contains(&seg), "{input:?} -> {s:?} leaks {seg:?}");
    }
}

#[test]
fn normalized_names_always_match_the_contract() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let input = random_input(&mut rng);
        check(&input, &normalize_path(&input));
        check(&input, &normalize_ldap_dn(&input));
        check(&input, &normalize_ldap_attribute(&input));
        let keys: Vec<PathPart<'_>> = input
            .split('/')
            .map(|k| {
                if k == "*" {
                    PathPart::Index
                } else {
                    PathPart::Key(k)
                }
            })
            .collect();
        check(&input, &normalize_field_path(&keys));
    }
}

#[test]
fn nfkc_expansion_is_bounded() {
    // U+FDFA folds to 18 characters: bounded before and after folding.
    let mut rng = Rng(7);
    for _ in 0..200 {
        let n = 1 + rng.below(2000);
        let big = "\u{FDFA}".repeat(n);
        let out = normalize_path(&big);
        check(&big, &out);
        let keys = vec![PathPart::Key("a"); rng.below(4)]
            .into_iter()
            .chain([PathPart::Key(big.as_str())])
            .collect::<Vec<_>>();
        let out = normalize_field_path(&keys);
        check(&big, &out);
        check(&big, &normalize_ldap_dn(&format!("ou={big},dc=x")));
        if n * 33 > 4096 {
            assert_eq!(out.as_str(), "*", "{n}");
        }
    }
}

#[test]
fn conforms_agrees_with_the_generated_type() {
    let mut rng = Rng(42);
    for _ in 0..20_000 {
        let input = random_input(&mut rng);
        let generated = databastion_protocol::Identifier::try_from(input.as_str()).is_ok()
            && !violates_numeric_rule(&input);
        assert_eq!(conforms(&input), generated, "{input:?}");
    }
}

#[test]
fn long_inputs_are_bounded() {
    let long = "a.".repeat(5000);
    assert_eq!(normalize_path(&long).as_str(), "*");
    let long = "b".repeat(300);
    assert_eq!(normalize_path(&long).as_str(), "*");
}

// ------------------------------------------------------------------ Gate
//
// Contract `Identifier` `not` rule (card / phone numbers used as names) and
// ADR-0009 classifier matches: generated names embedding a card number, a
// phone number, an IBAN or an e-mail address, split across separators and
// glued to ordinary words, never keep any of it (I2).

mod gate {
    use databastion_classifiers::names::{
        PathPart, conforms, normalize_field_path, normalize_ldap_dn, normalize_path,
        violates_numeric_rule,
    };
    use proptest::prelude::*;

    const WORDS: &[&str] = &["contacts", "users", "archive", "export", "data", "points"];
    const SEPARATORS: &[&str] = &[".", " ", "-", "_"];
    const JOINERS: &[&str] = &[".", "_", ""];

    fn luhn_check_digit(body: &str) -> u32 {
        let sum: u32 = body
            .chars()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                let d = c.to_digit(10).unwrap();
                if i % 2 == 0 {
                    let x = d * 2;
                    if x > 9 { x - 9 } else { x }
                } else {
                    d
                }
            })
            .sum();
        (10 - sum % 10) % 10
    }

    fn digits(n: usize) -> impl Strategy<Value = String> {
        proptest::collection::vec(0u8..10, n)
            .prop_map(|v| v.into_iter().map(|d| char::from(b'0' + d)).collect())
    }

    /// Compact digit-bearing values: Visa / Mastercard numbers, French and
    /// international phones, French IBANs.
    fn compact_value() -> impl Strategy<Value = String> {
        prop_oneof![
            (prop_oneof![Just("4"), Just("51"), Just("55")], digits(14)).prop_map(|(p, d)| {
                let body = format!("{p}{d}")[..15].to_owned();
                format!("{body}{}", luhn_check_digit(&body))
            }),
            (1u8..10, digits(8)).prop_map(|(a, d)| format!("0{a}{d}")),
            (1u8..10, digits(8)).prop_map(|(a, d)| format!("+33{a}{d}")),
            (1u8..10, digits(8)).prop_map(|(a, d)| format!("33{a}{d}")),
            digits(23).prop_map(|bban| {
                // FR = 15 27; check digits = 98 - (bban FR00 mod 97).
                let n = format!("{bban}152700");
                let r = n
                    .chars()
                    .fold(0u32, |acc, c| (acc * 10 + c.to_digit(10).unwrap()) % 97);
                format!("FR{:02}{bban}", 98 - r)
            }),
        ]
    }

    /// Splits `value` into groups of 1..=6 characters joined by separators.
    fn split(value: String) -> impl Strategy<Value = String> {
        let n = value.chars().count();
        proptest::collection::vec((1usize..=6, 0..SEPARATORS.len()), n).prop_map(move |cuts| {
            let chars: Vec<char> = value.chars().collect();
            let mut out = String::new();
            let mut i = 0;
            for (len, sep) in cuts {
                if i >= chars.len() {
                    break;
                }
                if i > 0 {
                    out.push_str(SEPARATORS[sep]);
                }
                let end = (i + len).min(chars.len());
                out.extend(&chars[i..end]);
                i = end;
            }
            out
        })
    }

    fn embed(value: impl Strategy<Value = String>) -> impl Strategy<Value = String> {
        (
            proptest::option::of((0..WORDS.len(), 0..JOINERS.len())),
            value,
            proptest::option::of((0..WORDS.len(), 0..2usize)),
        )
            .prop_map(|(pre, v, post)| {
                let mut s = String::new();
                if let Some((w, j)) = pre {
                    s.push_str(WORDS[w]);
                    s.push_str(JOINERS[j]);
                }
                s.push_str(&v);
                if let Some((w, j)) = post {
                    s.push_str(JOINERS[j]);
                    s.push_str(WORDS[w]);
                }
                s
            })
    }

    fn assert_contract(input: &str, out: &str) {
        assert!(
            databastion_protocol::Identifier::try_from(out).is_ok() && conforms(out),
            "{input:?} -> {out:?} does not match Identifier"
        );
        assert!(
            !violates_numeric_rule(out),
            "{input:?} -> {out:?} violates `not`"
        );
    }

    fn keys(input: &str) -> Vec<PathPart<'_>> {
        input.split('.').map(PathPart::Key).collect()
    }

    /// Letters that never form a word of [`WORDS`], nor a first name.
    fn word() -> impl Strategy<Value = String> {
        "[bcdfghjklmnpqrstvwxz]{4,8}"
    }

    /// A number of 9 to 12 CJK numerals (ideographic and financial forms).
    fn cjk_number() -> impl Strategy<Value = String> {
        const NUMERALS: &[char] = &[
            '零', '〇', '一', '二', '三', '四', '五', '六', '七', '八', '九', '壹', '贰', '叁',
            '肆', '伍', '陆', '柒', '捌', '玖', '貳', '參', '陸', '两', '兩', '拾',
        ];
        proptest::collection::vec(0..NUMERALS.len(), 9..=12)
            .prop_map(|v| v.into_iter().map(|i| NUMERALS[i]).collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn cjk_numbers_never_survive(input in embed(cjk_number().prop_flat_map(split))) {
            use databastion_classifiers::names::is_numeric_like;
            for out in [
                normalize_path(&input),
                normalize_field_path(&keys(&input)),
            ] {
                let out = out.as_str();
                assert_contract(&input, out);
                let kept = out.chars().filter(|c| is_numeric_like(*c)).count();
                prop_assert!(kept <= 8, "{input:?} -> {out:?} keeps {kept} numerals");
            }
        }

        #[test]
        fn split_numbers_never_survive(input in embed(compact_value().prop_flat_map(split))) {
            for out in [
                normalize_path(&input),
                normalize_field_path(&keys(&input)),
            ] {
                let out = out.as_str();
                assert_contract(&input, out);
                prop_assert!(
                    !out.chars().any(|c| c.is_ascii_digit()),
                    "{input:?} -> {out:?} keeps digits"
                );
            }
            let dn = normalize_ldap_dn(&format!("uid=x,ou={input},dc=example"));
            prop_assert!(!dn.as_str().chars().any(|c| c.is_ascii_digit()), "{input:?} -> {dn:?}");
        }

        #[test]
        fn emails_never_survive(
            local in proptest::collection::vec(word(), 1..=3),
            domain in word(),
            tld in prop_oneof![Just("com"), Just("net"), Just("org"), Just("fr")],
            pre in proptest::option::of(0..WORDS.len()),
            post in proptest::option::of(0..WORDS.len()),
        ) {
            let email = format!("{}@{domain}.{tld}", local.join("."));
            let mut input = email.clone();
            if let Some(w) = pre {
                input = format!("{}.{input}", WORDS[w]);
            }
            if let Some(w) = post {
                input = format!("{input}.{}", WORDS[w]);
            }
            let as_keys: Vec<PathPart<'_>> = pre
                .map(|w| PathPart::Key(WORDS[w]))
                .into_iter()
                .chain([PathPart::Key(email.as_str())])
                .chain(post.map(|w| PathPart::Key(WORDS[w])))
                .collect();
            for out in [
                normalize_path(&input),
                normalize_field_path(&keys(&input)),
                normalize_field_path(&as_keys),
            ] {
                let out = out.as_str();
                assert_contract(&input, out);
                for secret in local.iter().chain([&domain]) {
                    prop_assert!(!out.contains(secret.as_str()), "{input:?} -> {out:?}");
                }
            }
            // With the real keys, the container keys are kept.
            if let Some(w) = pre {
                let out = normalize_field_path(&as_keys);
                prop_assert!(out.as_str().starts_with(WORDS[w]), "{input:?} -> {out:?}");
            }
        }
    }
}
