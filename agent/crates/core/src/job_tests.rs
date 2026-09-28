#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use databastion_classifiers::masking::RawSample;
use databastion_protocol as p;

fn scan(json: serde_json::Value) -> p::DiscoveryScanParams {
    serde_json::from_value(json).unwrap()
}

fn audit(json: serde_json::Value) -> p::AuditConfigureParams {
    serde_json::from_value(json).unwrap()
}

fn target() -> TargetConfig {
    crate::config::AgentConfig::parse(
        "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: pg-main
    engine: postgres
    host: db1.internal
    account: databastion
    phone_region: fr
    secret:
      env: PG_PASSWORD
",
    )
    .unwrap()
    .targets
    .remove(0)
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[9u8; 32]).unwrap())
}

fn limits(rows: u32, timeout_ms: u32, duration_s: u32) -> Limits {
    Limits {
        max_sample_rows: rows,
        statement_timeout_ms: timeout_ms,
        max_scan_duration_s: duration_s,
        ..Limits::default()
    }
}

#[test]
fn contract_ranges_are_enforced() {
    let base = serde_json::json!({"sample_rows": 200, "max_duration_s": 900});
    assert!(ScanParams::try_from(&scan(base.clone())).is_ok());
    for (field, value) in [
        ("sample_rows", serde_json::json!(10_001)),
        ("max_duration_s", serde_json::json!(9)),
        ("max_duration_s", serde_json::json!(86_401)),
        ("max_duration_s", serde_json::json!(-1)),
        ("statement_timeout_ms", serde_json::json!(99)),
        ("statement_timeout_ms", serde_json::json!(600_001)),
        ("statement_timeout_ms", serde_json::json!(-5)),
    ] {
        let mut json = base.clone();
        json[field] = value;
        let e = ScanParams::try_from(&scan(json)).unwrap_err();
        assert_eq!(e.field, field);
        assert!(!e.to_string().contains("600001"), "no value in errors");
    }
    for (field, value) in [
        ("sample_rows", 1),
        ("sample_rows", 10_000),
        ("max_duration_s", 10),
        ("max_duration_s", 86_400),
        ("statement_timeout_ms", 100),
        ("statement_timeout_ms", 600_000),
    ] {
        let mut json = base.clone();
        json[field] = serde_json::json!(value);
        assert!(ScanParams::try_from(&scan(json)).is_ok(), "{field}={value}");
    }
}

#[test]
fn zero_means_the_local_cap_and_is_never_sent() {
    let params = ScanParams::try_from(&scan(serde_json::json!({
        "sample_rows": 200, "max_duration_s": 0, "statement_timeout_ms": 0
    })))
    .unwrap();
    let job = ScanJob::new(params, &target(), &limits(1000, 5_000, 600), key());
    assert_eq!(job.statement_timeout(), Duration::from_secs(5));
    assert_eq!(job.statement_timeout_ms(), 5_000);
    assert_eq!(job.max_duration(), Duration::from_secs(600));
}

#[test]
fn values_are_clamped_to_local_limits() {
    let params = ScanParams::try_from(&scan(serde_json::json!({
        "sample_rows": 10_000, "max_duration_s": 86_400, "statement_timeout_ms": 600_000
    })))
    .unwrap();
    let job = ScanJob::new(params, &target(), &limits(500, 10_000, 120), key());
    assert_eq!(job.sample_rows(), 500);
    assert_eq!(job.statement_timeout_ms(), 10_000);
    assert_eq!(job.max_duration(), Duration::from_secs(120));
    // Defaults are also clamped and never 0.
    let d = ScanJob::default();
    assert!(d.statement_timeout_ms() >= 100);
    assert!(d.target().is_none());
}

#[test]
fn empty_filter_lists_are_refused() {
    for field in ["databases", "schemas", "include_objects", "classifiers"] {
        let mut json = serde_json::json!({"sample_rows": 200, "max_duration_s": 900});
        json[field] = serde_json::json!([]);
        let e = ScanParams::try_from(&scan(json)).unwrap_err();
        assert_eq!(e.field, field);
    }
    // An empty exclude list narrows nothing: accepted.
    let json =
        serde_json::json!({"sample_rows": 200, "max_duration_s": 900, "exclude_objects": []});
    assert!(ScanParams::try_from(&scan(json)).is_ok());
}

#[test]
fn classifier_ids_go_through_the_closed_set() {
    let with = |ids: serde_json::Value| {
        ScanParams::try_from(&scan(serde_json::json!({
            "sample_rows": 200, "max_duration_s": 900, "classifiers": ids
        })))
    };
    let ok = with(serde_json::json!(["pii.email", "pii.phone"])).unwrap();
    let job = ScanJob::new(ok, &target(), &Limits::default(), key());
    assert_eq!(
        job.classifiers(),
        Some(&[ClassifierId::Email, ClassifierId::Phone][..])
    );
    assert_eq!(
        with(serde_json::json!(["pii.unknown"])).unwrap_err().reason,
        "unknown classifier id"
    );
    assert_eq!(
        with(serde_json::json!(["pii.email", "pii.email"]))
            .unwrap_err()
            .reason,
        "duplicate classifier id"
    );
}

#[test]
fn filters_match_globs() {
    assert!(glob_match("crm", "crm"));
    assert!(!glob_match("crm", "crm2"));
    assert!(glob_match("cust*", "customers"));
    assert!(glob_match("*_archive", "x_archive"));
    assert!(glob_match("t?st", "test"));
    assert!(glob_match("*", ""));
    assert!(!glob_match("a*b", "acd"));
    let params = ScanParams::try_from(&scan(serde_json::json!({
        "sample_rows": 200, "max_duration_s": 900,
        "databases": ["shop"], "include_objects": ["cust*"], "exclude_objects": ["*_old"]
    })))
    .unwrap();
    let job = ScanJob::new(params, &target(), &Limits::default(), key());
    assert!(job.includes_database("shop"));
    assert!(!job.includes_database("hr"));
    assert!(job.includes_schema("anything"));
    assert!(job.includes_object("customers"));
    let dup = ScanParams::try_from(&scan(serde_json::json!({
        "sample_rows": 200, "max_duration_s": 900,
        "databases": ["shop", "shop"], "exclude_objects": ["a", "a", "b"]
    })))
    .unwrap();
    assert_eq!(dup.databases.as_deref(), Some(&["shop".to_owned()][..]));
    assert_eq!(dup.exclude_objects, ["a", "b"]);
    assert!(!job.includes_object("customers_old"));
    assert!(!job.includes_object("orders"));
}

#[test]
fn classify_uses_the_job_filter_key_region_and_bound() {
    assert!(
        ScanParams::contract_defaults()
            .with_classifiers(&[])
            .is_err()
    );
    let params = ScanParams::contract_defaults()
        .with_classifiers(&[ClassifierId::Phone])
        .unwrap();
    let job = ScanJob::new(params, &target(), &limits(3, 30_000, 3_600), key());
    let raw = [
        "06 12 34 56 78",
        "+33 6 12 34 56 78",
        "jane@example.com",
        "07 00 00 00 01",
    ];
    let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
    let found = job.classify("phone", &values);
    assert_eq!(found.len(), 1, "e-mail filtered out by the job");
    let f = &found[0];
    assert_eq!(f.classifier(), ClassifierId::Phone);
    assert_eq!(f.sampled(), 3, "bounded by sample_rows");
    // `fr` region: national and international forms share a fingerprint.
    assert_eq!(f.fingerprints().len(), 1);
    let k = key();
    let expected = k
        .fingerprint_in(
            ClassifierId::Phone,
            &RawSample::new("06 12 34 56 78"),
            PhoneRegion::Fr,
        )
        .unwrap();
    assert_eq!(f.fingerprints()[0], expected);
}

#[test]
fn debug_never_shows_the_key_or_the_secret_reference() {
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &target(),
        &Limits::default(),
        key(),
    );
    let debug = format!("{job:?}");
    assert!(debug.contains("pg-main"), "{debug}");
    assert!(!debug.contains("PG_PASSWORD"), "{debug}");
    assert!(!debug.contains("0909"), "{debug}");
    assert!(!debug.to_lowercase().contains("hmac"), "{debug}");
}

#[test]
fn audit_params_are_gated_and_clamped() {
    let ok = serde_json::json!({
        "enabled": true, "aggregation_window_s": 30, "poll_interval_s": 1, "min_rows": 100,
        "sensitive_objects": [{"database": "shop", "schema": "crm", "object": "customers",
                               "classifiers": ["pii.email"]}]
    });
    let params = AuditParams::try_from(&audit(ok.clone())).unwrap();
    let cfg = AuditConfig::new(params, &target(), &Limits::default());
    assert!(cfg.enabled());
    assert_eq!(cfg.poll_interval(), Duration::from_secs(5), "local floor");
    assert_eq!(cfg.aggregation_window(), Duration::from_secs(30));
    assert!(cfg.statement_timeout() >= Duration::from_millis(100));
    assert_eq!(cfg.min_rows(), Some(100));
    assert_eq!(
        cfg.sensitive_objects()[0].classifiers,
        vec![ClassifierId::Email]
    );

    for (pointer, value, field) in [
        (
            "/aggregation_window_s",
            serde_json::json!(301),
            "aggregation_window_s",
        ),
        (
            "/poll_interval_s",
            serde_json::json!(3601),
            "poll_interval_s",
        ),
        ("/min_rows", serde_json::json!(-1), "min_rows"),
        (
            "/sensitive_objects/0/classifiers",
            serde_json::json!([]),
            "sensitive_objects.classifiers",
        ),
        (
            "/sensitive_objects/0/classifiers",
            serde_json::json!(["pii.nope"]),
            "sensitive_objects.classifiers",
        ),
        (
            "/sensitive_objects/0/object",
            serde_json::json!("0612345678"),
            "sensitive_objects.object",
        ),
    ] {
        let mut json = ok.clone();
        *json.pointer_mut(pointer).unwrap() = value;
        let e = AuditParams::try_from(&audit(json)).unwrap_err();
        assert_eq!(e.field, field, "{pointer}");
    }
    // An empty `sensitive_objects` list legitimately clears them.
    let json = serde_json::json!({"enabled": false, "sensitive_objects": []});
    assert!(AuditParams::try_from(&audit(json)).is_ok());
}
