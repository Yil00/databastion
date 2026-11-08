//! The contract's engine branches, evaluated on produced items (tests and
//! the connectors' `test-support` only, never the agent binary).
//!
//! The generated types do not express the `if` / `then` branches of
//! `shared/protocol/openapi.yaml` (they are removed before generation), so
//! the core enforces them itself (SQLite R1, Firebird C1) and these tests
//! check every item the agent produces against the branches read from the
//! contract. The evaluator understands a closed subset of JSON Schema
//! (`type`, `properties`, `const`, `enum`, `not`, `contains`, `allOf`, boolean
//! schemas, `description`): any other keyword fails the test, so a
//! contract change to a branch must be reflected here.

#![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;

const OPENAPI: &str = include_str!("../../../../shared/protocol/openapi.yaml");

fn contract() -> Value {
    serde_yaml_ng::from_str(OPENAPI).expect("openapi.yaml parses")
}

/// Whether an `if` names `<key>: <value>` (`const`, or `enum` holding it).
fn names(cond: &Value, key: &str, value: &str) -> bool {
    let p = &cond["properties"][key];
    p["const"] == value
        || p["enum"]
            .as_array()
            .is_some_and(|v| v.iter().any(|x| x == value))
}

/// Every `then` schema of the `allOf` entries of `components.schemas.<def>`
/// whose `if` names `<key>: <value>` (review N5: not only the first), as
/// one `allOf`.
///
/// # Panics
/// When the contract has no such branch (a contract change to reflect).
#[must_use]
pub fn branch(def: &str, key: &str, value: &str) -> Value {
    let doc = contract();
    let all = doc["components"]["schemas"][def]["allOf"]
        .as_array()
        .unwrap_or_else(|| panic!("{def}: no allOf"))
        .clone();
    let thens: Vec<Value> = all
        .into_iter()
        .filter(|e| names(&e["if"], key, value))
        .map(|e| e["then"].clone())
        .collect();
    assert!(!thens.is_empty(), "{def}: no branch on {key} = {value}");
    serde_json::json!({ "allOf": thens })
}

/// The `if` / `then` entries anywhere under `components.schemas` that
/// mention Firebird (`firebird` or `firebird_audit_trace`, in their `if`
/// or `then`): the test below pins their number, so a new Firebird branch
/// cannot be added to the contract without the core's enforcement and
/// these tests being revisited.
#[must_use]
pub fn firebird_entries() -> Vec<String> {
    fn walk(node: &Value, path: &str, out: &mut Vec<String>) {
        match node {
            Value::Object(o) => {
                if let Some(Value::Array(entries)) = o.get("allOf") {
                    for (i, e) in entries.iter().enumerate() {
                        if e.get("if").is_some() && e.to_string().contains("firebird") {
                            out.push(format!("{path}/allOf/{i}"));
                        }
                    }
                }
                for (k, v) in o {
                    walk(v, &format!("{path}/{k}"), out);
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    walk(v, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(&contract()["components"]["schemas"], "", &mut out);
    out
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
                    "allOf" => {
                        for sub in rule.as_array().expect("allOf is an array") {
                            conforms(sub, item)?;
                        }
                    }
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

    /// Review N5: the number of Firebird branches is pinned; a change
    /// needs the core's C1 enforcement and these tests revisited.
    #[test]
    fn the_firebird_branches_are_counted() {
        let mut entries = firebird_entries();
        entries.sort();
        assert_eq!(
            entries,
            [
                "/AccessEvent/allOf/3",
                "/DetectedTarget/allOf/1",
                "/Location/allOf/2",
                "/TargetStatus/allOf/0",
                "/TargetStatus/allOf/2",
            ],
            "the contract's Firebird branches changed: revisit sanitize::firebird and \
             contract_rules"
        );
        // Every branch is returned, not only the first.
        let all = branch("TargetStatus", "engine", "firebird");
        assert_eq!(all["allOf"].as_array().unwrap().len(), 1);
    }
}
