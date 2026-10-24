//! The contract `IdentifierProduced` (ADR-0057 decision 1,
//! `shared/protocol/identifier-produced.schema.json`) against the agent:
//!
//! - the schema file holds the agent's rule patterns verbatim and refines
//!   the `Identifier` of `openapi.yaml`;
//! - the agent's check ([`names::is_identifier_produced`], the `regex`
//!   crate) accepts exactly what the contract accepts (the generated
//!   `Identifier` type, its `not` rule and the producer rules compiled with
//!   `regress` in ECMAScript `u` mode, as the console's Ajv);
//! - every name the normalizers emit matches it, and a dotted MAC, an IPv4
//!   address or a split digit run in the input leaves none of its parts in
//!   the output, index-like parts included (security review M1).
//!
//! The measurement of decision 2 item 4 is `identifier_produced_measure.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::LazyLock;

use databastion_classifiers::names::{
    self, IDENTIFIER_PRODUCED_RULES, PathPart, normalize_field_path, normalize_ldap_attribute,
    normalize_ldap_dn, normalize_path,
};
use databastion_protocol::Identifier;
use databastion_protocol_codegen::{default_openapi_path, json_schema_from_openapi};
use proptest::prelude::*;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read(rel: &str) -> String {
    let path = repo().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn schema() -> serde_json::Value {
    serde_json::from_str(&read("shared/protocol/identifier-produced.schema.json")).unwrap()
}

/// (rule id, pattern) of the schema file's `not.anyOf`, the id from its
/// `title` (`rule <id>`).
fn schema_rules() -> Vec<(String, String)> {
    schema()["not"]["anyOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let title = r["title"].as_str().unwrap();
            (
                title.strip_prefix("rule ").unwrap().to_owned(),
                r["pattern"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

struct Contract {
    identifier_not: regress::Regex,
    rules: Vec<(String, regress::Regex)>,
}

static CONTRACT: LazyLock<Contract> = LazyLock::new(|| {
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    let doc = json_schema_from_openapi(&yaml).unwrap();
    let not = doc["$defs"]["Identifier"]["not"]["pattern"]
        .as_str()
        .unwrap();
    Contract {
        identifier_not: regress::Regex::with_flags(not, "u").unwrap(),
        rules: schema_rules()
            .into_iter()
            .map(|(id, p)| (id, regress::Regex::with_flags(&p, "u").unwrap()))
            .collect(),
    }
});

/// What the contract accepts: the generated `Identifier` type, its `not`
/// rule, then every producer rule (`regress`).
fn contract_accepts(s: &str) -> bool {
    let c = &*CONTRACT;
    Identifier::try_from(s).is_ok()
        && c.identifier_not.find(s).is_none()
        && c.rules.iter().all(|(_, re)| re.find(s).is_none())
}

/// The contract's rule ids `s` violates (`regress`).
fn contract_violations(s: &str) -> Vec<String> {
    CONTRACT
        .rules
        .iter()
        .filter(|(_, re)| re.find(s).is_some())
        .map(|(id, _)| id.clone())
        .collect()
}

#[test]
fn schema_file_holds_the_agent_rules_and_refines_identifier() {
    let s = schema();
    assert_eq!(s["title"], "IdentifierProduced");
    assert_eq!(s["type"], "string");
    assert_eq!(s["allOf"][0]["$ref"], "schemas.json#/$defs/Identifier");
    assert_eq!(s["allOf"].as_array().unwrap().len(), 1);
    let want: Vec<(String, String)> = IDENTIFIER_PRODUCED_RULES
        .iter()
        .map(|(id, p)| ((*id).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(schema_rules(), want);
    // The file is not part of openapi.yaml: nothing the generators read.
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    assert!(!yaml.contains("IdentifierProduced"));
}

/// The ADR's examples, refused (with the rule) or kept.
#[test]
fn the_adr_examples() {
    for (s, rule) in [
        ("06.12.34.56.78", "2"),
        ("06_12_34_56_78", "2"),
        ("tel_06_12_34_56_78", "2"),
        ("1_2_3_4_5", "2"),
        ("v1-2-3-4-5", "2"),
        ("a1-2.3-4.5b", "2"),
        ("06\u{a0}12\u{a0}34\u{a0}56\u{a0}78", "2"),
        ("06\u{2010}12\u{2010}34\u{2010}56\u{2010}78", "2"),
        ("06\u{ff0e}12\u{ff0e}34\u{ff0e}56\u{ff0e}78", "2"),
        ("_________", "1"),
        ("a.1_2_3_4_5.b", "1"),
        ("ou=123456789,dc=x", "1"),
        ("host.10.0.0.1", "3-ipv4"),
        ("10.0.0.1", "3-ipv4"),
        ("ou=10.0.0.1,dc=x", "3-ipv4"),
        ("00-1a-2b-3c-4d-5e", "3-mac-dashed"),
        ("device_00-1a-2b-3c-4d-5e", "3-mac-dashed"),
        ("001a.2b3c.4d5e", "3-mac-dotted"),
        ("device.001a.2b3c.4d5e.port", "3-mac-dotted"),
        ("ou=001a.2b3c.4d5e,dc=x", "3-mac-dotted"),
        ("%41", "4"),
        ("x.name%u00e9", "4"),
        ("%u0041", "4"),
        ("a%U00E9", "4"),
        ("a1234567", "5-run"),
        (
            "a\u{0663}\u{0664}\u{0665}\u{0666}\u{0667}\u{0668}\u{0669}",
            "5-run",
        ),
        ("a12.b34.c56.d78.e9", "5-total"),
        ("ou=1234,dc=56789", "5-total"),
        (
            "x\u{2165}\u{2166}\u{2167}\u{2168}\u{2169}\u{216a}\u{216b}",
            "5-run",
        ),
    ] {
        let got = names::produced_violations(s);
        assert!(got.contains(&rule), "{s:?}: {got:?}");
        assert!(contract_violations(s).iter().any(|r| r == rule), "{s:?}");
        assert!(!names::is_identifier_produced(s), "{s:?}");
        assert!(!contract_accepts(s), "{s:?}");
    }
    for s in [
        "face.cafe.beef",
        "dead.beef.cafe",
        "orders",
        "orders[].email",
        "*",
        "*.phone",
        "v2.users",
        "events_2024_09",
        "orders_2024",
        "first_name",
        "1.2",
        "a.1.2.3",
        "matrix[][]",
        "ou=people,dc=example,dc=org",
        "第一名",
        "sales.一月",
        "%zz",
        "%u00",
        "a-b-c-d-e-f",
        "ab-cd",
        "v1.2.3",
        "abcd.ef01",
    ] {
        assert!(
            names::produced_violations(s).is_empty(),
            "{s:?}: {:?}",
            names::produced_violations(s)
        );
        assert!(names::is_identifier_produced(s), "{s:?}");
        assert!(contract_accepts(s), "{s:?}");
    }
}

/// The agent's rule ids are the contract's on every input of the alphabet
/// (rule by rule), and its check accepts exactly what the contract accepts.
fn alphabet() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "a", "b", "f", "E", "z", "0", "1", "9", "42", "001a", "2b3c", "face", ".", ".", "-", "_",
        "+", " ", "%", "%4", "%u", "u", "*", "[]", "ou=", "dc=", ",", "@", "\u{ff10}", "\u{ff0e}",
        "\u{a0}", "\u{2010}", "\u{200b}", "\u{663}", "\u{2165}", "\u{3007}", "一", "é",
    ]);
    prop::collection::vec(pieces, 0..24).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn agent_check_is_the_contract(s in alphabet()) {
        let agent: Vec<String> = names::produced_violations(&s)
            .into_iter()
            .filter(|r| *r != names::UNASSIGNED_RULE)
            .map(str::to_owned)
            .collect();
        prop_assert_eq!(agent, contract_violations(&s), "{:?}", s);
        prop_assert_eq!(names::is_identifier_produced(&s), contract_accepts(&s), "{:?}", s);
    }
}

// ------------------------------------------------- Emitted names (oracles)

/// Every normalizer's output on `input` matches the contract (generated
/// `Identifier`, its `not` rule and `IdentifierProduced` under `regress`).
fn assert_emitted(input: &str) {
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
    for out in [
        normalize_path(input),
        normalize_ldap_dn(input),
        normalize_ldap_attribute(input),
        normalize_field_path(&keys),
    ] {
        let out = out.as_str();
        assert!(names::is_identifier_produced(out), "{input:?} -> {out:?}");
        assert!(contract_accepts(out), "{input:?} -> {out:?}");
    }
}

fn name_alphabet() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "a", "b", "face", "cafe", "001a", "2b3c", "4d5e", "00", "1a", "0", "1", "9", "10", "255",
        "12", ".", ".", ".", "-", "_", "+", " ", "/", "%", "%4", "%u00", "41", "ou=", "dc=",
        "uid=", ",", "@", "*", "\u{ff10}", "\u{ff0e}", "\u{a0}", "\u{2010}", "\u{2212}", "\u{663}",
        "\u{2165}", "\u{378}", "一", "六", "é", "\u{200b}",
    ]);
    prop::collection::vec(pieces, 0..32).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn emitted_names_match_identifier_produced(s in name_alphabet()) {
        assert_emitted(&s);
    }

    /// No panic, and the contract holds, on arbitrary text.
    #[test]
    fn emitted_names_on_any_text(s in any::<String>()) {
        assert_emitted(&s);
    }

    #[test]
    fn emitted_names_on_any_bytes(b in prop::collection::vec(any::<u8>(), 0..96)) {
        assert_emitted(&String::from_utf8_lossy(&b));
    }
}

/// Neighbouring words: letters that are not hexadecimal (never part of a
/// match, so always kept unless a first name), 4 hexadecimal characters
/// and digit-only words (re-review N1: a MAC after `face` or `1234`).
fn plain_word() -> impl Strategy<Value = String> {
    prop_oneof!["[g-z]{2,6}", "[a-f]{4}", "[0-9a-f]{4}", "[0-9]{1,4}"]
}

fn hex_group(digit: bool) -> impl Strategy<Value = String> {
    if digit {
        "[0-9a-f]{3}[0-9]".prop_shuffle_string().boxed()
    } else {
        "[0-9a-f]{4}".boxed()
    }
}

trait ShuffleString {
    fn prop_shuffle_string(self) -> BoxedStrategy<String>;
}

impl ShuffleString for &'static str {
    fn prop_shuffle_string(self) -> BoxedStrategy<String> {
        self.prop_map(|s: String| s.chars().collect::<Vec<_>>())
            .prop_shuffle()
            .prop_map(|v| v.into_iter().collect())
            .boxed()
    }
}

/// A value the rules refuse: a dotted MAC (one group with a digit, the
/// others any 4 hexadecimal characters, digit-only ones included), an IPv4
/// address, or a digit-to-digit run of 9 or more characters split by
/// separators (at most 6 digits, below the older digit rules).
fn refused_value() -> impl Strategy<Value = String> {
    prop_oneof![
        (
            0usize..3,
            hex_group(true),
            hex_group(false),
            hex_group(false)
        )
            .prop_map(|(at, d, a, b)| {
                let mut g = vec![a, b];
                g.insert(at, d);
                g.join(".")
            }),
        prop::collection::vec(0u16..256, 4)
            .prop_map(|v| { v.iter().map(u16::to_string).collect::<Vec<_>>().join(".") }),
        (
            prop::collection::vec(
                (1u8..10, prop::sample::select(vec![".", "_", "-", "+", " "])),
                5..=6
            ),
            1u8..10
        )
            .prop_map(|(v, last)| {
                let mut s = String::new();
                for (d, sep) in v {
                    s.push_str(&d.to_string());
                    s.push_str(sep);
                }
                s.push_str(&last.to_string());
                s
            }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Review M1: no part of a refused value survives in the output, as a
    /// path or as the real keys of a field path, wherever it sits.
    #[test]
    fn refused_values_leave_no_part(
        pre in prop::collection::vec(plain_word(), 0..3),
        value in refused_value(),
        post in prop::collection::vec(plain_word(), 0..3),
    ) {
        let input = pre.iter().cloned().chain([value.clone()]).chain(post.iter().cloned())
            .collect::<Vec<_>>().join(".");
        let keys: Vec<PathPart<'_>> = input.split('.').map(PathPart::Key).collect();
        for out in [normalize_path(&input), normalize_field_path(&keys)] {
            let out = out.as_str();
            prop_assert!(names::is_identifier_produced(out), "{:?} -> {:?}", input, out);
            // No part of the value survives as a segment (a part equal to
            // a neighbouring word cannot be told apart and is skipped).
            for part in value.split('.') {
                if pre.iter().chain(&post).any(|w| w == part) {
                    continue;
                }
                prop_assert!(
                    !out.split('.').any(|seg| seg.trim_end_matches("[]") == part),
                    "{:?} -> {:?} keeps {:?}", input, out, part
                );
            }
            prop_assert!(!out.contains(&value), "{:?} -> {:?}", input, out);
            // Words of non-hexadecimal letters are kept (first names
            // excepted), unless the whole name is `*` (the digit bounds of
            // rule 5 count the neighbouring words' digits too).
            for w in pre.iter().chain(&post).filter(|w| {
                out != "*"
                    && w.chars().all(|c| ('g'..='z').contains(&c))
                    && !names::segment_looks_like_value(w)
            }) {
                prop_assert!(out.split('.').any(|s| s.trim_end_matches("[]") == w), "{:?} -> {:?} lost {:?}", input, out, w);
            }
        }
        let dn = normalize_ldap_dn(&format!("uid=x,ou={value},dc=example"));
        // `+` makes an RDN multi-valued: the whole DN is `*`.
        prop_assert!(
            dn.as_str() == "ou=*,dc=example" || dn.as_str() == "*",
            "{:?} -> {:?}", value, dn
        );
    }
}

/// Every Unicode scalar value, in the shapes the rules look at (inside a
/// segment, a run of 9, a digit-to-digit run, a dotted MAC with it): the
/// agent's check never accepts what the contract refuses (Unicode version
/// drift between the `regex` crate and `regress`), and the emitted names
/// pass. Seconds in release mode: `cargo test --release -p
/// databastion-classifiers --test identifier_produced -- --include-ignored`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "full code-point sweep: run in release mode"
)]
fn no_drift_on_any_code_point() {
    let mut drift = Vec::new();
    let mut emitted = Vec::new();
    for c in (0..=0x10_FFFF_u32).filter_map(char::from_u32) {
        let shapes = [
            format!("a{c}b"),
            c.to_string().repeat(9),
            format!("1{}2", c.to_string().repeat(7)),
            format!("x.{c}01a.2b3c.4d5e"),
            format!("ou=a{c},dc=x"),
        ];
        for s in &shapes {
            if names::is_identifier_produced(s) && !contract_accepts(s) {
                drift.push(format!("U+{:04X}", u32::from(c)));
            }
        }
        for s in &shapes[..4] {
            let out = normalize_path(s);
            if !contract_accepts(out.as_str()) {
                emitted.push(format!("U+{:04X}", u32::from(c)));
            }
        }
    }
    assert!(
        drift.is_empty(),
        "drift: {} {:?}",
        drift.len(),
        &drift[..drift.len().min(40)]
    );
    assert!(
        emitted.is_empty(),
        "emitted: {} {:?}",
        emitted.len(),
        &emitted[..emitted.len().min(40)]
    );
}
