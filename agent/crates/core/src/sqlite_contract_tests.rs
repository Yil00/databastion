//! ADR-0059 decisions 6 and 7 (P10-C contract review R1): every `sqlite`
//! item the core sends goes through the contract's own `sqlite` rules, read
//! from `shared/protocol/openapi.yaml` (the `if` / `then` branches on
//! `engine: sqlite` of `Location` and `TargetStatus`, which the generated
//! types do not enforce), in the style of the `identifier-produced` test of
//! ADR-0057:
//!
//! - findings, through the one conversion `uplink::to_batches` (the item
//!   breaking the rule dropped and counted, the others conforming);
//! - spooled findings batches, through `ResultBatch::parse` (a batch
//!   breaking the rule is never sent);
//! - target statuses, through `sanitize::enforce_sqlite_target_status`, the
//!   last step of the heartbeat builder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{FindingLocation, MaskedFinding, RawSample, mask};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_protocol::{ClassifiersVersion, Engine, TargetId, TargetStatus, Uuid};
use databastion_protocol_codegen::{default_openapi_path, json_schema_from_openapi};
use serde_json::Value;

use crate::uplink::{MaskedResults, ResultBatch, to_batches};

/// The `then` branch of the `allOf` entry of `$defs/<def>` whose `if` is
/// `engine: const sqlite`.
fn sqlite_branch(def: &str) -> serde_json::Map<String, Value> {
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    let doc = json_schema_from_openapi(&yaml).unwrap();
    let all = doc["$defs"][def]["allOf"].as_array().unwrap().clone();
    let branch = all
        .into_iter()
        .find(|e| e["if"]["properties"]["engine"]["const"] == "sqlite")
        .unwrap_or_else(|| panic!("{def}: no sqlite branch"));
    branch["then"]["properties"].as_object().unwrap().clone()
}

/// Evaluates the branch's property rules on `item`. Only `const` and
/// `false` are understood: any other keyword fails the test, so a contract
/// change to the branch must be reflected here.
fn conforms(rules: &serde_json::Map<String, Value>, item: &Value) -> Result<(), String> {
    for (key, rule) in rules {
        match rule {
            Value::Bool(false) => {
                if item.get(key).is_some() {
                    return Err(format!("{key} must be absent"));
                }
            }
            Value::Object(o) => {
                let keys: Vec<&String> = o.keys().collect();
                assert_eq!(keys, ["const"], "unsupported keyword under {key}");
                if item.get(key) != Some(&o["const"]) {
                    return Err(format!("{key} must be {}", o["const"]));
                }
            }
            other => panic!("unsupported rule {other} under {key}"),
        }
    }
    Ok(())
}

fn key(raw: &str) -> NormalizedName {
    normalize_field_path(&[PathPart::Key(raw)])
}

fn finding(database: &str, schema: Option<&str>, object: &str, field: &str) -> MaskedFinding {
    MaskedFinding::new(
        ClassifierId::PII_EMAIL,
        vec![mask(&RawSample::new("a@b.c"))],
    )
    .with_location(FindingLocation {
        database: key(database),
        schema: schema.map(key),
        object: key(object),
        field: key(field),
    })
    .with_counts(10, 5, 0.9)
}

fn sqlite_batches(findings: &[MaskedFinding]) -> crate::uplink::Built {
    to_batches(MaskedResults::Findings {
        job_id: Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        classifiers_version: &ClassifiersVersion::try_from("2026.09.1").unwrap(),
        target_id: &TargetId::try_from("crm-app").unwrap(),
        engine: Engine::Sqlite,
        findings,
    })
}

#[test]
fn sqlite_findings_conform_to_the_contract_rule_or_are_dropped() {
    let rules = sqlite_branch("Location");
    assert!(rules.contains_key("database") && rules.contains_key("schema"));
    let findings = [
        // What the connector builds: `main`, no schema, table, column, a
        // name altered by normalization in the column.
        finding("main", None, "customers", "email"),
        finding("main", None, "clients\u{200b}", "e\u{ff4d}ail"),
        // Never sent: a file name or a path as the database, a schema.
        finding("crm.db", None, "customers", "email"),
        finding("srv_crm_data", None, "customers", "email"),
        finding("main", Some("main"), "customers", "email"),
        finding("main", Some("public"), "customers", "email"),
    ];
    let built = sqlite_batches(&findings);
    assert_eq!(built.dropped_items, 4);
    let mut sent = 0;
    for batch in &built.batches {
        let v: Value = serde_json::from_slice(batch.bytes()).unwrap();
        for f in v["findings"].as_array().unwrap() {
            let location = &f["location"];
            conforms(&rules, location).unwrap_or_else(|e| panic!("{e}: {location}"));
            // The constant database and the absent schema are never
            // marked altered (ADR-0056 on sqlite).
            if let Some(parts) = location["altered"].as_array() {
                assert!(
                    !parts.iter().any(|p| p == "database" || p == "schema"),
                    "{location}"
                );
            }
            sent += 1;
        }
    }
    assert_eq!(sent, 2);
    // The evaluator itself refuses what the rule refuses.
    assert!(conforms(&rules, &serde_json::json!({"database": "crm.db"})).is_err());
    assert!(
        conforms(
            &rules,
            &serde_json::json!({"database": "main", "schema": "s"})
        )
        .is_err()
    );
}

#[test]
fn spooled_sqlite_batches_breaking_the_rule_are_never_sent() {
    let built = sqlite_batches(&[finding("main", None, "customers", "email")]);
    let good = built.batches[0].bytes().to_vec();
    assert!(ResultBatch::parse(true, good.clone()).is_some());
    for (from, to) in [
        (r#""database":"main""#, r#""database":"crm.db""#),
        (r#""database":"main""#, r#""database":"main","schema":"x""#),
    ] {
        let text = String::from_utf8(good.clone()).unwrap();
        assert!(text.contains(from), "{text}");
        let bad = text.replacen(from, to, 1).into_bytes();
        assert!(ResultBatch::parse(true, bad).is_none(), "{to}");
    }
}

#[test]
fn sqlite_target_statuses_conform_to_the_contract_rule() {
    let rules = sqlite_branch("TargetStatus");
    // Everything a connector could wrongly report.
    let mut status: TargetStatus = serde_json::from_value(serde_json::json!({
        "target_id": "crm-app",
        "engine": "sqlite",
        "reachable": true,
        "audit_level": "partial",
        "audit_source": "pgaudit",
        "server_version": "3.53.2",
        "edition": "community",
        "name_case": {"databases": "sensitive", "objects": "sensitive"},
    }))
    .unwrap();
    let before = serde_json::to_value(&status).unwrap();
    assert!(conforms(&rules, &before).is_err());
    crate::sanitize::enforce_sqlite_target_status(&mut status);
    let after = serde_json::to_value(&status).unwrap();
    conforms(&rules, &after).unwrap_or_else(|e| panic!("{e}: {after}"));
    assert!(after.get("name_case").is_none(), "{after}");
    assert_eq!(after["reachable"], true);
    // Another engine's status is left as it is.
    let mut pg: TargetStatus = serde_json::from_value(serde_json::json!({
        "target_id": "pg",
        "engine": "postgres",
        "reachable": true,
        "audit_level": "partial",
        "audit_source": "pgaudit",
    }))
    .unwrap();
    crate::sanitize::enforce_sqlite_target_status(&mut pg);
    assert_eq!(serde_json::to_value(&pg).unwrap()["audit_level"], "partial");
}
