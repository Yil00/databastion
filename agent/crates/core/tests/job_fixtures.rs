//! Gate (protocol contract review, #13; ROADMAP P2-A / P2-B / P2-C): the
//! job-parameter mapping against the shared protocol fixtures.
//!
//! serde accepts an empty filter list (`minItems` is not enforced, see
//! `databastion-protocol` `tests/fixtures.rs::NOT_ENFORCED_BY_SERDE`); the
//! `TryFrom` into the core job types is the enforcement point. An empty
//! `databases` / `schemas` / `include_objects` / `classifiers` list, or a
//! value out of the contract range, is `Err` (job reported `failed` with
//! `invalid_params`); every valid `JobList` fixture maps to `Ok`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use databastion_core::{AuditParams, ScanParams};
use databastion_protocol as p;

fn fixtures_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared/protocol/fixtures")
        .join(kind)
}

fn first_scan(file: &str) -> p::DiscoveryScanParams {
    let json = fs::read_to_string(fixtures_dir("invalid").join(file)).unwrap();
    let list: p::JobList = serde_json::from_str(&json).unwrap();
    let p::Job::DiscoveryScanJob(job) = &list.jobs[0] else {
        panic!("{file}: not a discovery.scan job");
    };
    job.params.clone()
}

#[test]
fn empty_scan_filters_and_out_of_range_values_are_refused() {
    for (file, field) in [
        ("JobList.scan-empty-classifiers.json", "classifiers"),
        ("JobList.scan-empty-databases.json", "databases"),
        ("JobList.scan-empty-include-objects.json", "include_objects"),
        ("JobList.scan-empty-schemas.json", "schemas"),
        ("JobList.sample-rows-too-large.json", "sample_rows"),
    ] {
        let e = ScanParams::try_from(&first_scan(file)).unwrap_err();
        assert_eq!(e.field, field, "{file}");
    }
}

#[test]
fn valid_job_fixtures_map() {
    let mut mapped = 0;
    for entry in fs::read_dir(fixtures_dir("valid")).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !file.starts_with("JobList.") {
            continue;
        }
        let list: p::JobList = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for job in &list.jobs {
            match job {
                p::Job::DiscoveryScanJob(j) => {
                    ScanParams::try_from(&j.params).unwrap_or_else(|e| panic!("{file}: {e}"));
                    mapped += 1;
                }
                p::Job::AuditConfigureJob(j) => {
                    AuditParams::try_from(&j.params).unwrap_or_else(|e| panic!("{file}: {e}"));
                    mapped += 1;
                }
                _ => {}
            }
        }
    }
    assert!(
        mapped >= 3,
        "valid scan / audit fixtures were found ({mapped})"
    );
}
