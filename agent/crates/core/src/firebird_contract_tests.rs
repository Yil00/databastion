//! Merge condition C1 of the P10-C Firebird review (ADR-0060 decisions 2,
//! 5, 6 and 7): every `firebird` item the core sends goes through the
//! contract's own Firebird rules, read from `shared/protocol/openapi.yaml`
//! (the `if` / `then` branches the generated types do not enforce), as the
//! SQLite R1 tests do:
//!
//! - findings, through the one conversion `uplink::to_batches` (a location
//!   with a `schema` dropped and counted);
//! - spooled findings and events batches, through `ResultBatch::parse` (a
//!   batch breaking a rule is never sent);
//! - events of `firebird_audit_trace`, through `to_batches` (no
//!   `principal.application`, no object `schema`);
//! - target statuses, through `sanitize::enforce_target_status` (no
//!   `full`, no `edition`, no `name_case`; Firebird-only notes on
//!   `firebird` targets only);
//! - detected targets, through local detection and
//!   `sanitize::enforce_detected_targets` (no `unix_socket`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, SystemTime};

use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{
    EventAction, EventObject, EventPrincipal, EventSource, FindingLocation, MaskedEvent,
    MaskedFinding, RawSample, mask,
};
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use databastion_protocol::{ClassifiersVersion, Engine, TargetId, TargetStatus, Uuid};
use serde_json::Value;

use crate::contract_rules::{branch, conforms};
use crate::uplink::{MaskedResults, ResultBatch, to_batches};

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

fn findings_batches(findings: &[MaskedFinding]) -> crate::uplink::Built {
    to_batches(MaskedResults::Findings {
        job_id: Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        classifiers_version: &ClassifiersVersion::try_from("2026.09.1").unwrap(),
        target_id: &TargetId::try_from("fb-app").unwrap(),
        engine: Engine::Firebird,
        findings,
    })
}

#[test]
fn firebird_findings_conform_to_the_contract_rule_or_are_dropped() {
    let rules = branch("Location", "engine", "firebird");
    let findings = [
        // What the connector builds: the declared name, the relation, the
        // column, no schema; a quoted mixed-case name and an altered one.
        finding("app", None, "CUSTOMERS", "EMAIL"),
        finding("app", None, "Customers", "e\u{ff4d}ail"),
        // Never sent: a schema, whatever its value.
        finding("app", Some("PUBLIC"), "CUSTOMERS", "EMAIL"),
        finding("app", Some("app"), "CUSTOMERS", "EMAIL"),
    ];
    let built = findings_batches(&findings);
    assert_eq!(built.dropped_items, 2);
    let mut sent = 0;
    for batch in &built.batches {
        let v: Value = serde_json::from_slice(batch.bytes()).unwrap();
        for f in v["findings"].as_array().unwrap() {
            let location = &f["location"];
            assert_eq!(location["engine"], "firebird");
            conforms(&rules, location).unwrap_or_else(|e| panic!("{e}: {location}"));
            sent += 1;
        }
    }
    assert_eq!(sent, 2);
}

#[test]
fn spooled_firebird_findings_breaking_the_rule_are_never_sent() {
    let built = findings_batches(&[finding("app", None, "CUSTOMERS", "EMAIL")]);
    let good = built.batches[0].bytes().to_vec();
    assert!(ResultBatch::parse(true, good.clone()).is_some());
    let text = String::from_utf8(good).unwrap();
    let from = r#""database":"app""#;
    assert!(text.contains(from), "{text}");
    let bad = text
        .replacen(from, r#""database":"app","schema":"PUBLIC""#, 1)
        .into_bytes();
    assert!(ResultBatch::parse(true, bad).is_none());
}

fn trace_event(application: Option<&str>, schema: Option<&str>) -> MaskedEvent {
    let mut principal = EventPrincipal::account("APP_USER");
    if let Some(a) = application {
        principal = principal.with_application(a);
    }
    MaskedEvent::new(
        EventSource::FirebirdAuditTrace,
        EventAction::Read,
        principal,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
    )
    .with_object(EventObject::new(key("app"), None, key("CUSTOMERS")))
    .with_object(EventObject::new(key("app"), schema.map(key), key("ORDERS")))
    .with_rows(Some(12))
}

fn events_batches(events: &[MaskedEvent]) -> crate::uplink::Built {
    let key = databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap();
    let fps = crate::sanitize::HmacFingerprints(&key);
    to_batches(MaskedResults::Events {
        target_id: &TargetId::try_from("fb-app").unwrap(),
        events,
        fingerprints: &fps,
    })
}

#[test]
fn firebird_trace_events_conform_to_the_contract_rule() {
    let rules = branch("AccessEvent", "source", "firebird_audit_trace");
    // What a connector could wrongly build: a client-set process name, an
    // object with a schema.
    let built = events_batches(&[
        trace_event(Some("/home/alice/bin/isql"), Some("PUBLIC")),
        trace_event(None, None),
    ]);
    assert_eq!(built.dropped_items, 0);
    let mut sent = 0;
    for batch in &built.batches {
        let v: Value = serde_json::from_slice(batch.bytes()).unwrap();
        for e in v["events"].as_array().unwrap() {
            assert_eq!(e["source"], "firebird_audit_trace");
            conforms(&rules, e).unwrap_or_else(|err| panic!("{err}: {e}"));
            assert!(e["principal"].get("application").is_none(), "{e}");
            // The read stays reported: the object with a schema became `*`
            // of its database.
            let objects: Vec<&str> = e["objects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["object"].as_str().unwrap())
                .collect();
            assert!(objects.contains(&"CUSTOMERS"), "{e}");
            sent += 1;
        }
    }
    assert_eq!(sent, 2);
    // The other sources keep their application.
    let pg = MaskedEvent::new(
        EventSource::Pgaudit,
        EventAction::Read,
        EventPrincipal::account("u").with_application("psql"),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
    )
    .with_object(EventObject::new(key("crm"), Some(key("public")), key("t")));
    let built = events_batches(&[pg]);
    let v: Value = serde_json::from_slice(built.batches[0].bytes()).unwrap();
    assert_eq!(v["events"][0]["principal"]["application"], "psql");
    assert_eq!(v["events"][0]["objects"][0]["schema"], "public");
}

#[test]
fn spooled_firebird_events_breaking_the_rule_are_never_sent() {
    let built = events_batches(&[trace_event(None, None)]);
    let good = built.batches[0].bytes().to_vec();
    assert!(ResultBatch::parse(false, good.clone()).is_some());
    let text = String::from_utf8(good).unwrap();
    for (from, to) in [
        (
            r#""db_user":"APP_USER""#,
            r#""db_user":"APP_USER","application":"x""#,
        ),
        (
            r#""database":"app","object":"ORDERS""#,
            r#""database":"app","object":"ORDERS","schema":"S""#,
        ),
    ] {
        assert!(text.contains(from), "{text}");
        let bad = text.replacen(from, to, 1).into_bytes();
        assert!(ResultBatch::parse(false, bad).is_none(), "{to}");
    }
}

#[test]
fn firebird_target_statuses_conform_to_the_contract_rule() {
    let rules = branch("TargetStatus", "engine", "firebird");
    let firebird_only: Vec<&str> = crate::NoteCode::FIREBIRD_ONLY
        .iter()
        .map(|c| c.as_str())
        .collect();
    let notes: Vec<Value> = firebird_only
        .iter()
        .chain(["privilege.refused", "check.stage_failed"].iter())
        .map(|c| serde_json::json!({"code": c}))
        .collect();
    // Everything a connector could wrongly report.
    let mut status: TargetStatus = serde_json::from_value(serde_json::json!({
        "target_id": "fb-app",
        "engine": "firebird",
        "reachable": true,
        "audit_level": "full",
        "audit_source": "firebird_audit_trace",
        "server_version": "5.0.4",
        "edition": "community",
        "name_case": {"databases": "sensitive", "objects": "sensitive"},
        "notes": notes,
    }))
    .unwrap();
    assert!(conforms(&rules, &serde_json::to_value(&status).unwrap()).is_err());
    crate::sanitize::enforce_target_status(&mut status);
    let after = serde_json::to_value(&status).unwrap();
    conforms(&rules, &after).unwrap_or_else(|e| panic!("{e}: {after}"));
    assert_eq!(after["audit_level"], "partial");
    assert!(after.get("name_case").is_none() && after.get("edition").is_none());
    assert_eq!(after["server_version"], "5.0.4");
    assert_eq!(after["notes"].as_array().unwrap().len(), notes.len());
    // `limited` and `none` are kept as they are.
    for level in ["limited", "none", "partial"] {
        let mut s: TargetStatus = serde_json::from_value(serde_json::json!({
            "target_id": "fb-app", "engine": "firebird", "reachable": true,
            "audit_level": level,
        }))
        .unwrap();
        crate::sanitize::enforce_target_status(&mut s);
        assert_eq!(serde_json::to_value(&s).unwrap()["audit_level"], level);
    }
    // Another engine's status loses the Firebird-only notes and keeps the
    // others.
    let mut pg: TargetStatus = serde_json::from_value(serde_json::json!({
        "target_id": "pg", "engine": "postgres", "reachable": true,
        "audit_level": "full", "notes": notes,
    }))
    .unwrap();
    crate::sanitize::enforce_target_status(&mut pg);
    let pg = serde_json::to_value(&pg).unwrap();
    assert_eq!(pg["audit_level"], "full");
    let codes: Vec<&str> = pg["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["privilege.refused", "check.stage_failed"]);
}

#[test]
fn firebird_detected_targets_conform_to_the_contract_rule() {
    let rules = branch("DetectedTarget", "engine", "firebird");
    let mut detected: Vec<databastion_protocol::DetectedTarget> =
        serde_json::from_value(serde_json::json!([
            {"engine": "firebird", "port": 3050},
            {"engine": "firebird", "process": "firebird"},
            {"engine": "firebird", "unix_socket": "/tmp/firebird.sock", "port": 3050},
            {"engine": "firebird", "unix_socket": "/tmp/firebird.sock"},
            {"engine": "postgres", "unix_socket": "/run/postgresql/.s.PGSQL.5432"},
        ]))
        .unwrap();
    crate::sanitize::enforce_detected_targets(&mut detected);
    assert_eq!(detected.len(), 4);
    for d in &detected {
        let v = serde_json::to_value(d).unwrap();
        if v["engine"] == "firebird" {
            conforms(&rules, &v).unwrap_or_else(|e| panic!("{e}: {v}"));
        } else {
            assert!(v.get("unix_socket").is_some());
        }
    }
}
