//! The contract's engine branches, evaluated on produced items (tests and
//! the connectors' `test-support` only, never the agent binary).
//!
//! The generated types do not express the `if` / `then` branches of
//! `shared/protocol/openapi.yaml` (they are removed before generation), so
//! the core enforces them itself (SQLite R1, Firebird C1) and these tests
//! check every item the agent produces against the branches read from the
//! contract. The evaluator understands a closed subset of JSON Schema
//! (`type`, `properties`, `const`, `enum`, `not`, `contains`, boolean
//! schemas, `description`): any other keyword fails the test, so a
//! contract change to a branch must be reflected here.

#![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;

const OPENAPI: &str = include_str!("../../../../shared/protocol/openapi.yaml");

/// The `then` schema of the `allOf` entry of `components.schemas.<def>`
/// whose `if` is `<key>: const <value>`.
///
/// # Panics
/// When the contract has no such branch (a contract change to reflect).
#[must_use]
pub fn branch(def: &str, key: &str, value: &str) -> Value {
    let doc: Value = serde_yaml_ng::from_str(OPENAPI).expect("openapi.yaml parses");
    let all = doc["components"]["schemas"][def]["allOf"]
        .as_array()
        .unwrap_or_else(|| panic!("{def}: no allOf"))
        .clone();
    let entry = all
        .into_iter()
        .find(|e| e["if"]["properties"][key]["const"] == value)
        .unwrap_or_else(|| panic!("{def}: no branch on {key} = {value}"));
    entry["then"].clone()
}

/// Whether `item` satisfies `schema` (the subset above).
///
/// # Errors
/// The first rule `item` breaks.
///
/// # Panics
/// On a keyword outside the subset.
pub fn conforms(schema: &Value, item: &Value) -> Result<(), String> {
    match schema {
        Value::Bool(true) => Ok(()),
        Value::Bool(false) => Err("a false schema".to_owned()),
        Value::Object(o) => {
            for (keyword, rule) in o {
                match keyword.as_str() {
                    "description" => {}
                    "type" => {
                        let ok = match rule.as_str() {
                            Some("object") => item.is_object(),
                            Some("array") => item.is_array(),
                            Some("string") => item.is_string(),
                            other => panic!("unsupported type {other:?}"),
                        };
                        if !ok {
                            return Err(format!("not of type {rule}"));
                        }
                    }
                    "const" => {
                        if item != rule {
                            return Err(format!("{item} is not {rule}"));
                        }
                    }
                    "enum" => {
                        let values = rule.as_array().expect("enum is an array");
                        if !values.contains(item) {
                            return Err(format!("{item} is not one of {rule}"));
                        }
                    }
                    "not" => {
                        if conforms(rule, item).is_ok() {
                            return Err(format!("{item} matches a `not`: {rule}"));
                        }
                    }
                    "contains" => {
                        let Some(items) = item.as_array() else {
                            continue;
                        };
                        if !items.iter().any(|i| conforms(rule, i).is_ok()) {
                            return Err(format!("no element of {item} matches {rule}"));
                        }
                    }
                    "properties" => {
                        let Some(map) = item.as_object() else {
                            continue;
                        };
                        let rules = rule.as_object().expect("properties is a map");
                        for (key, sub) in rules {
                            match (map.get(key), sub) {
                                (Some(_), Value::Bool(false)) => {
                                    return Err(format!("{key} must be absent"));
                                }
                                (Some(v), sub) => {
                                    conforms(sub, v).map_err(|e| format!("{key}: {e}"))?;
                                }
                                (None, _) => {}
                            }
                        }
                    }
                    other => panic!("unsupported keyword {other} in a contract branch"),
                }
            }
            Ok(())
        }
        other => panic!("unsupported schema {other}"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_evaluator_refuses_what_the_branches_refuse() {
        let status = branch("TargetStatus", "engine", "firebird");
        assert!(conforms(&status, &serde_json::json!({"audit_level": "partial"})).is_ok());
        assert!(conforms(&status, &serde_json::json!({"audit_level": "full"})).is_err());
        assert!(conforms(&status, &serde_json::json!({"edition": "x"})).is_err());
        let location = branch("Location", "engine", "firebird");
        assert!(conforms(&location, &serde_json::json!({"database": "app"})).is_ok());
        assert!(conforms(&location, &serde_json::json!({"schema": "s"})).is_err());
        let event = branch("AccessEvent", "source", "firebird_audit_trace");
        let ok = serde_json::json!({"principal": {"db_user": "u"},
            "objects": [{"database": "d", "object": "t"}]});
        conforms(&event, &ok).unwrap();
        let app = serde_json::json!({"principal": {"db_user": "u", "application": "x"},
            "objects": [{"database": "d", "object": "t"}]});
        assert!(conforms(&event, &app).is_err());
        let schema = serde_json::json!({"principal": {"db_user": "u"},
            "objects": [{"database": "d", "object": "t"},
                        {"database": "d", "schema": "s", "object": "t"}]});
        assert!(conforms(&event, &schema).is_err());
        let detected = branch("DetectedTarget", "engine", "firebird");
        assert!(conforms(&detected, &serde_json::json!({"port": 3050})).is_ok());
        assert!(conforms(&detected, &serde_json::json!({"unix_socket": "/tmp/x"})).is_err());
    }
}
