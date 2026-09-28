//! Deserializes `shared/protocol/fixtures/` into the generated types.
//!
//! - Every `valid/<Schema>.<case>.json` must deserialize into `<Schema>`.
//! - Every `invalid/<Schema>.<case>.json` must be rejected by serde, except
//!   those in [`NOT_ENFORCED_BY_SERDE`], which rely on a JSON Schema keyword
//!   the generated types do not express. For those, the console's Ajv
//!   validation is the enforcement point; agent-side checks of received
//!   values are a required future step (P1-B, P2). The
//!   allowlist is exact: a fixture listed here that starts failing (or an
//!   unlisted one that starts passing) fails the test, so it cannot rot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use databastion_protocol as p;

/// Invalid fixtures that serde accepts, with the keyword it does not enforce.
const NOT_ENFORCED_BY_SERDE: &[(&str, &str)] = &[
    (
        "EventsBatch.read-without-objects.json",
        "minItems (via if/then, removed before generation)",
    ),
    ("EventsBatch.too-many-events.json", "maxItems"),
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
    // Empty scan filters: `Option<Vec<_>>` keeps `[]` distinct from absent
    // ("all"); see `empty_scan_filters_stay_distinct_from_absent`.
    (
        "JobList.scan-empty-classifiers.json",
        "minItems (Some([]), distinct from absent)",
    ),
    (
        "JobList.scan-empty-databases.json",
        "minItems (Some([]), distinct from absent)",
    ),
    (
        "JobList.scan-empty-include-objects.json",
        "minItems (Some([]), distinct from absent)",
    ),
    (
        "JobList.scan-empty-schemas.json",
        "minItems (Some([]), distinct from absent)",
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

/// `Debug` of every structure carrying a credential must not print it.
#[test]
fn debug_never_prints_credentials() {
    let valid = fixtures_dir("valid");
    type Render = fn(&str) -> String;
    let cases: [(&str, Render); 5] = [
        ("EnrollRequest.full.json", |j| {
            format!("{:?}", serde_json::from_str::<p::EnrollRequest>(j).unwrap())
        }),
        ("EnrollRequest.minimal.json", |j| {
            format!("{:?}", serde_json::from_str::<p::EnrollRequest>(j).unwrap())
        }),
        ("EnrollResponse.default.json", |j| {
            format!(
                "{:?}",
                serde_json::from_str::<p::EnrollResponse>(j).unwrap()
            )
        }),
        ("RotateRequest.agent-initiated.json", |j| {
            format!("{:?}", serde_json::from_str::<p::RotateRequest>(j).unwrap())
        }),
        ("RotateRequest.from-job.json", |j| {
            format!("{:?}", serde_json::from_str::<p::RotateRequest>(j).unwrap())
        }),
    ];
    for (file, debug) in cases {
        let json = fs::read_to_string(valid.join(file)).unwrap();
        let rendered = debug(&json);
        assert!(rendered.contains("[REDACTED]"), "{file}: {rendered}");
        for prefix in ["dbs_", "dbe_"] {
            assert!(
                !rendered.contains(prefix),
                "{file} leaks a credential in Debug"
            );
        }
        // The fixture really carries a credential.
        assert!(json.contains("dbs_") || json.contains("dbe_"), "{file}");
    }
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

/// Gate for the P2 `discovery.scan` mapping: an empty filter list must never
/// be read as "absent = all". serde accepts `[]` (it does not enforce
/// `minItems`), but the generated `Option<Vec<_>>` keeps it distinguishable.
///
/// TODO(P2): the `TryFrom<DiscoveryScanParams>` mapping into the scanner's
/// configuration must reject `Some(vec![])` for `databases`, `schemas`,
/// `include_objects` and `classifiers` (job reported `failed`), and this test
/// must then also assert that rejection.
#[test]
fn empty_scan_filters_stay_distinct_from_absent() {
    let invalid = fixtures_dir("invalid");
    type Field = fn(&p::DiscoveryScanParams) -> Option<usize>;
    let cases: [(&str, Field); 4] = [
        ("JobList.scan-empty-classifiers.json", |s| {
            s.classifiers.as_ref().map(Vec::len)
        }),
        ("JobList.scan-empty-databases.json", |s| {
            s.databases.as_ref().map(Vec::len)
        }),
        ("JobList.scan-empty-include-objects.json", |s| {
            s.include_objects.as_ref().map(Vec::len)
        }),
        ("JobList.scan-empty-schemas.json", |s| {
            s.schemas.as_ref().map(Vec::len)
        }),
    ];
    for (file, field) in cases {
        let json = fs::read_to_string(invalid.join(file)).unwrap();
        let list: p::JobList = serde_json::from_str(&json).unwrap();
        let p::Job::DiscoveryScanJob(job) = &list.jobs[0] else {
            panic!("{file}: not a discovery.scan job");
        };
        assert_eq!(
            field(&job.params),
            Some(0),
            "{file}: [] must be Some(empty)"
        );
    }
    // Absent stays `None`.
    let absent: p::DiscoveryScanParams =
        serde_json::from_str(r#"{"sample_rows": 200, "max_duration_s": 900}"#).unwrap();
    assert!(absent.databases.is_none());
    assert!(absent.schemas.is_none());
    assert!(absent.include_objects.is_none());
    assert!(absent.classifiers.is_none());
}
