//! The key-pattern gate (`keys::is_key_pattern`) against the contract
//! (ADR-0052 decision 7, P9-C): the constants are the `KeyPattern` patterns
//! of `shared/protocol/openapi.yaml` verbatim, and the gate (the `regex`
//! crate) accepts exactly what the generated `KeyPattern` type and the
//! contract's `not` rule (`regress`, ECMAScript `u` mode, as the console's
//! Ajv) accept. Every pattern the normalizer emits passes both.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::keys::{self, KEY_PATTERN_NOT, KEY_PATTERN_PATTERN};
use databastion_protocol::KeyPattern;
use databastion_protocol_codegen::{default_openapi_path, json_schema_from_openapi};
use proptest::prelude::*;

fn contract() -> (String, String) {
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    let schema = json_schema_from_openapi(&yaml).unwrap();
    let kp = &schema["$defs"]["KeyPattern"];
    (
        kp["pattern"].as_str().unwrap().to_owned(),
        kp["not"]["pattern"].as_str().unwrap().to_owned(),
    )
}

static NOT: std::sync::LazyLock<regress::Regex> =
    std::sync::LazyLock::new(|| regress::Regex::with_flags(&contract().1, "u").unwrap());

fn not_rule() -> &'static regress::Regex {
    &NOT
}

/// What the contract accepts (generated type, then the `not` rule).
fn contract_accepts(re: &regress::Regex, s: &str) -> bool {
    KeyPattern::try_from(s).is_ok() && re.find(s).is_none()
}

#[test]
fn constants_are_the_contract_patterns() {
    let (pattern, not) = contract();
    assert_eq!(KEY_PATTERN_PATTERN, pattern);
    assert_eq!(KEY_PATTERN_NOT, not);
}

#[test]
fn gate_agrees_on_the_contract_examples() {
    let re = not_rule();
    for s in [
        "user:*:email",
        "session:*",
        "cache:v2:page",
        "api:v1:item:42",
        "cafe:babe:dead:beef",
        "order_*_*",
        "db0",
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "device:00:1a:2b:3c:4d:5e",
        "phone:\u{ff10}\u{ff16}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}",
        "tel:06_12_34_56_78",
        "tel:06\u{a0}12\u{a0}34\u{a0}56\u{a0}78",
        "user:jane%40example",
        "javascript:x",
        " JavaScript:x",
        "host:10.0.0.1",
        "host.10.0.0.1",
        "device:00-1a-2b-3c-4d-5e",
        "device:001a.2b3c.4d5e",
        "tel:06\u{2010}12\u{2010}34\u{2010}56\u{2010}78",
        "tel:06\u{ff0e}12\u{ff0e}34\u{ff0e}56\u{ff0e}78",
        "a//b",
        ":a",
        "a:",
        "a@b",
        "x\u{200b}y",
    ] {
        assert_eq!(keys::is_key_pattern(s), contract_accepts(re, s), "{s:?}");
    }
}

fn alphabet() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "a",
        "b",
        "f",
        "E",
        "z",
        "0",
        "1",
        "9",
        "42",
        ":",
        "/",
        "|",
        ".",
        "-",
        "_",
        "+",
        " ",
        "%",
        "%4",
        "@",
        "*",
        "{",
        "}",
        "#",
        "\u{ff10}",
        "\u{ff0e}",
        "\u{a0}",
        "\u{2010}",
        "\u{200b}",
        "http",
        "data",
        "mailto",
        "javascript",
        "é",
        "ab12",
        "00:1a",
        "db8",
        "\u{663}",
    ]);
    prop::collection::vec(pieces, 0..24).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn gate_is_the_contract(s in alphabet()) {
        let re = not_rule();
        prop_assert_eq!(keys::is_key_pattern(&s), contract_accepts(re, &s), "{:?}", s);
    }

    #[test]
    fn emitted_patterns_pass_the_contract(s in alphabet()) {
        let re = not_rule();
        let p = keys::fuzz_normalize(s.as_bytes());
        prop_assert!(contract_accepts(re, &p), "{:?} -> {:?}", s, p);
    }

    #[test]
    fn emitted_patterns_pass_the_contract_on_any_bytes(
        b in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let re = not_rule();
        let p = keys::fuzz_normalize(&b);
        prop_assert!(contract_accepts(re, &p), "{:?}", p);
    }
}
