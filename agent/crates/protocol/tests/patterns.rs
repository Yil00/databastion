//! Every `pattern` of the contract, including those the generated types
//! drop (`not`, `if` / `then` / `else`), compiles with the ECMAScript `u`
//! flag in `regress`, the engine of the generated code. The console's Ajv
//! compiles the same patterns; this keeps the agent able to enforce any of
//! them later (e.g. `KeyPattern`'s `not` rules in the P9-B sanitizer).

#![allow(clippy::unwrap_used, clippy::panic)]

use databastion_protocol_codegen::{default_openapi_path, json_schema_from_openapi};

fn collect(value: &serde_json::Value, pointer: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "pattern"
                    && let Some(p) = v.as_str()
                {
                    out.push((pointer.to_owned(), p.to_owned()));
                } else {
                    collect(v, &format!("{pointer}/{k}"), out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect(v, &format!("{pointer}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn every_contract_pattern_compiles_in_unicode_mode() {
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    let schema = json_schema_from_openapi(&yaml).unwrap();
    let mut patterns = Vec::new();
    collect(&schema, "#", &mut patterns);
    assert!(patterns.len() > 20, "{}", patterns.len());
    for (pointer, pattern) in &patterns {
        if let Err(e) = regress::Regex::with_flags(pattern, "u") {
            panic!("{pointer}: pattern does not compile in regress (u flag): {e}");
        }
    }
    // The KeyPattern `not` rules, checked on the values the console rejects.
    let not = &schema["$defs"]["KeyPattern"]["not"]["pattern"];
    let re = regress::Regex::with_flags(not.as_str().unwrap(), "u").unwrap();
    for rejected in [
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "device:00:1a:2b:3c:4d:5e",
        "phone:\u{ff10}\u{ff16}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}",
        "tel:06_12_34_56_78",
        "tel:06\u{a0}12\u{a0}34\u{a0}56\u{a0}78",
        "user:jane%40example",
        "javascript:x",
    ] {
        assert!(re.find(rejected).is_some(), "{rejected}");
    }
    for kept in ["user:*:email", "cafe:babe:dead:beef", "order_*_*", "db0"] {
        assert!(re.find(kept).is_none(), "{kept}");
    }
}
