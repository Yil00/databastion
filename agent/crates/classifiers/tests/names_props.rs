//! Property tests for the name normalizer (ADR-0009): deterministic
//! pseudo-random inputs (no extra dependency), checked against the generated
//! contract `Identifier` type and its `not` rule.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::names::{
    NormalizedName, conforms, normalize_ldap_attribute, normalize_ldap_dn, normalize_path,
    violates_numeric_rule,
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
