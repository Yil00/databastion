//! Deserializes `shared/protocol/fixtures/` into the generated types.
//!
//! - Every `valid/<Schema>.<case>.json` must deserialize into `<Schema>`.
//! - Every `invalid/<Schema>.<case>.json` must be rejected by serde, except
//!   those in [`NOT_ENFORCED_BY_SERDE`], which rely on a JSON Schema keyword
//!   the generated types do not express. For those, the console's Ajv
//!   validation and the agent's sanitizer are the enforcement points. The
//!   allowlist is exact: a fixture listed here that starts failing (or an
//!   unlisted one that starts passing) fails the test, so it cannot rot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use databastion_protocol as p;

/// Invalid fixtures that serde accepts, with the keyword it does not enforce.
const NOT_ENFORCED_BY_SERDE: &[(&str, &str)] = &[
    (
        "EnrollResponse.uppercase-agent-id.json",
        "pattern: `Uuid` is mapped to uuid::Uuid, which accepts uppercase",
    ),
    (
        "EventsBatch.read-without-objects.json",
        "minItems (via if/then, removed before generation)",
    ),
    ("EventsBatch.too-many-events.json", "maxItems"),
    (
        "FindingsBatch.batch-id-not-uuidv7.json",
        "pattern: `UuidV7` is mapped to uuid::Uuid, any version accepted",
    ),
    (
        "FindingsBatch.card-number-as-table.json",
        "not (Identifier)",
    ),
    (
        "FindingsBatch.confidence-above-one.json",
        "maximum on a number",
    ),
    ("FindingsBatch.empty.json", "minItems"),
    (
        "FindingsBatch.negative-confidence.json",
        "minimum on a number",
    ),
    ("FindingsBatch.phone-number-as-key.json", "not (Identifier)"),
    ("FindingsBatch.too-many-findings.json", "maxItems"),
    ("FindingsBatch.too-many-fingerprints.json", "maxItems"),
    ("FindingsBatch.too-many-masked-samples.json", "maxItems"),
    (
        "HeartbeatRequest.detected-target-without-endpoint.json",
        "minProperties",
    ),
    ("HeartbeatRequest.too-many-metrics.json", "maxProperties"),
    ("HeartbeatRequest.too-many-targets.json", "maxItems"),
    (
        "HeartbeatResponse.interval-too-short.json",
        "minimum on an integer newtype",
    ),
    ("JobList.empty.json", "minItems"),
    (
        "JobList.sample-rows-too-large.json",
        "maximum on an integer",
    ),
    ("JobList.too-many-jobs.json", "maxItems"),
    (
        "JobStatusUpdate.failed-without-error.json",
        "required (via if/then, removed before generation)",
    ),
    (
        "JobStatusUpdate.ratio-above-one.json",
        "maximum on a number",
    ),
    (
        "JobStatusUpdate.running-with-error.json",
        "false schema (via if/else, removed before generation)",
    ),
];

fn fixtures_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared/protocol/fixtures")
        .join(kind)
}

fn fixtures(kind: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(fixtures_dir(kind)).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_str().unwrap().to_owned();
        let Some(stem) = file.strip_suffix(".json") else {
            continue;
        };
        let schema = stem.split('.').next().unwrap().to_owned();
        out.push((file.clone(), schema, fs::read_to_string(&path).unwrap()));
    }
    out.sort();
    assert!(out.len() > 10, "fixture discovery looks broken");
    out
}

/// Deserializes `json` into the type named `schema`, then checks that the
/// value serializes back to JSON (round trip through the generated type).
fn check(schema: &str, json: &str) -> Result<(), String> {
    macro_rules! parse {
        ($($name:ident),* $(,)?) => {
            match schema {
                $(stringify!($name) => {
                    let value: p::$name = serde_json::from_str(json).map_err(|e| e.to_string())?;
                    serde_json::to_string(&value).map_err(|e| e.to_string())?;
                    Ok(())
                })*
                other => panic!("no generated type for fixture schema {other}"),
            }
        };
    }
    parse!(
        BatchAck,
        EnrollRequest,
        EnrollResponse,
        Error,
        EventsBatch,
        FindingsBatch,
        HeartbeatRequest,
        HeartbeatResponse,
        JobList,
        JobStatusUpdate,
        RotateRequest,
        RotateResponse,
    )
}

#[test]
fn valid_fixtures_deserialize() {
    let failures: Vec<String> = fixtures("valid")
        .into_iter()
        .filter_map(|(file, schema, json)| {
            check(&schema, &json).err().map(|e| format!("{file}: {e}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "valid fixtures rejected:\n{}",
        failures.join("\n")
    );
}

#[test]
fn invalid_fixtures_are_rejected_or_allowlisted() {
    let mut accepted = Vec::new();
    for (file, schema, json) in fixtures("invalid") {
        if check(&schema, &json).is_ok() {
            accepted.push(file);
        }
    }
    let mut allowlisted: Vec<String> = NOT_ENFORCED_BY_SERDE
        .iter()
        .map(|(file, _)| (*file).to_owned())
        .collect();
    allowlisted.sort();
    assert_eq!(
        accepted, allowlisted,
        "invalid fixtures accepted by serde differ from NOT_ENFORCED_BY_SERDE"
    );
}
