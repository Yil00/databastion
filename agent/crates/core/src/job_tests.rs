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

#[test]
fn object_order_rotates_per_scan() {
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &target(),
        &Limits::default(),
        key(),
    );
    // Built outside the core: no rotation.
    let mut v: Vec<u32> = (0..5).collect();
    job.rotate(&mut v);
    assert_eq!(v, [0, 1, 2, 3, 4]);
    let rotated = |seed: u64| {
        let job = job.clone().with_rotation(seed);
        let mut v: Vec<u32> = (0..5).collect();
        job.rotate(&mut v);
        v
    };
    assert_eq!(rotated(7), [2, 3, 4, 0, 1]);
    assert_eq!(rotated(10), [0, 1, 2, 3, 4]);
    // Every object leads for some seed, and nothing is lost.
    let firsts: std::collections::BTreeSet<u32> = (0..5).map(|s| rotated(s)[0]).collect();
    assert_eq!(firsts.len(), 5);
    let mut empty: Vec<u32> = Vec::new();
    job.clone().with_rotation(3).rotate(&mut empty);
    assert!(empty.is_empty());
    assert_eq!(job.clone().with_rotation(3).rotation_offset(0), None);
}

/// Log lines of a closure, as JSON (every level).
fn logs_of(f: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
}

/// ADR-0041 decision 5: one ticket-id-shaped value drops the whole column
/// before classification, and the drop is counted for the target note.
#[test]
fn ticket_id_tripwire_drops_the_column() {
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &target(),
        &limits(200, 30_000, 3_600),
        key(),
    );
    let raw = [
        "jane.doe@example.org",
        "john.smith@example.org",
        "TGT-42-q8XkLmZz0FAKE-cas01",
        "anna.berg@example.org",
    ];
    let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
    let logs = logs_of(|| assert!(job.classify("email", &values).is_empty()));
    assert!(!logs.contains("TGT-42"), "{logs}");
    assert!(!logs.contains("example.org"), "{logs}");
    assert!(logs.contains("CAS store guard"), "{logs}");
    assert_eq!(job.cas_guard().tripped(), 1);
    // The clones share the tally; another column without ticket ids is
    // classified as usual.
    let clone = job.clone();
    let clean: Vec<RawSample<'_>> = raw
        .iter()
        .filter(|v| !v.starts_with("TGT"))
        .map(|v| RawSample::new(v))
        .collect();
    assert_eq!(clone.classify("email", &clean).len(), 1);
    assert_eq!(
        clone
            .classify_guarded("x", &values, crate::cas_guard::ColumnRule::NoMaskedSamples)
            .len(),
        0
    );
    assert_eq!(job.cas_guard().tripped(), 2);
    let notes = job.cas_guard().notes();
    assert_eq!(notes[0].code(), crate::NoteCode::CoverageCasGuardTripped);
    assert_eq!(notes[0].count(), Some(2));
}

/// PR #141 review M4 / L1: a value with only the generic ticket shape, or
/// a named ticket id inside it, is dropped alone (never classified,
/// masked nor fingerprinted) and counted; the rest of the column is
/// classified; the column is not tripped.
#[test]
fn generic_or_embedded_ticket_ids_drop_the_value_only() {
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &target(),
        &limits(200, 30_000, 3_600),
        key(),
    );
    let raw = [
        "jane.doe@example.org",
        "INV-2026-jane.doe@example.org",
        "john.smith@example.org",
        "https://app.example.org/?ticket=ST-7-FAKEsecret-cas01",
        "anna.berg@example.org",
    ];
    let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
    let mut found = Vec::new();
    let logs = logs_of(|| found = job.classify("email", &values));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].sampled(), 3);
    assert_eq!(found[0].matched(), 3);
    for m in found[0].masked_samples() {
        let m = format!("{m:?}");
        assert!(!m.contains("INV") && !m.contains("ST-7"), "{m}");
    }
    assert!(
        !logs.contains("FAKEsecret") && !logs.contains("INV-2026"),
        "{logs}"
    );
    assert_eq!(job.cas_guard().tripped(), 0);
    assert_eq!(job.cas_guard().values_dropped(), 2);
    assert!(job.cas_guard().notes().is_empty());
}

/// ADR-0041 decision 5: the audit trail principal and the service registry
/// body keep no masked sample; the body keeps no `secret.*` fingerprint;
/// never-read columns give nothing.
#[test]
fn guarded_rules_strip_samples_and_secret_fingerprints() {
    use crate::cas_guard::ColumnRule;
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &target(),
        &limits(200, 30_000, 3_600),
        key(),
    );
    let body = [
        r#"{"@class":"org.apereo.cas.services.OidcRegisteredService","clientSecret":"AKIAIOSFODNN7EXAMPLE","contacts":[{"email":"jane.doe@example.org"}]}"#,
        r#"{"@class":"org.apereo.cas.services.CasRegisteredService","contacts":[{"email":"john.smith@example.org"}],"k":"AKIAI44QH8DHBEXAMPLE"}"#,
        r#"{"@class":"org.apereo.cas.services.CasRegisteredService","contacts":[{"email":"anna.berg@example.org"}],"k":"AKIAJ55QH8DHBEXAMPLE"}"#,
    ];
    let values: Vec<RawSample<'_>> = body.iter().map(|v| RawSample::new(v)).collect();
    let plain = job.classify("body", &values);
    assert!(
        plain.iter().any(|f| f.classifier().is_secret()),
        "{plain:?}"
    );
    let guarded = job.classify_guarded("body", &values, ColumnRule::NoSamplesNoSecretFingerprints);
    assert!(!guarded.is_empty());
    for f in &guarded {
        assert!(f.masked_samples().is_empty(), "{f:?}");
        if f.classifier().is_secret() {
            assert!(f.fingerprints().is_empty(), "{f:?}");
        }
    }
    assert!(
        guarded
            .iter()
            .any(|f| !f.classifier().is_secret() && !f.fingerprints().is_empty()),
        "non-secret fingerprints are kept: {guarded:?}"
    );
    let users = [
        "jane.doe@example.org",
        "john.smith@example.org",
        "anna.berg@example.org",
    ];
    let values: Vec<RawSample<'_>> = users.iter().map(|v| RawSample::new(v)).collect();
    let principal = job.classify_guarded("AUD_USER", &values, ColumnRule::NoMaskedSamples);
    assert_eq!(principal.len(), 1);
    assert!(principal[0].masked_samples().is_empty());
    assert!(!principal[0].fingerprints().is_empty());
    assert!(
        job.classify_guarded("AUD_RESOURCE", &values, ColumnRule::NeverRead)
            .is_empty()
    );
    assert_eq!(job.cas_guard().tripped(), 0);
}

mod guard_props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Wherever a ticket id sits among other values, and whatever the
        /// rule, nothing of the column reaches a finding, a masked sample,
        /// a fingerprint or a log line.
        #[test]
        fn a_ticket_id_never_reaches_a_finding_or_a_log(
            others in proptest::collection::vec("[a-z]{3,8}\\.[a-z]{3,8}@example\\.(org|com)", 1..20),
            prefix in "(TGT|ST|PT|PGT|PGTIOU|TST|OC|AT|RT|ODT|ODUC|CIBA|OPAR|SART|SATQ|STS)",
            n in 1u32..100_000,
            tail in "[A-Za-z0-9]{8,24}",
            pos in any::<prop::sample::Index>(),
            rule in prop::sample::select(vec![
                crate::cas_guard::ColumnRule::Sampled,
                crate::cas_guard::ColumnRule::NoMaskedSamples,
                crate::cas_guard::ColumnRule::NoSamplesNoSecretFingerprints,
            ]),
        ) {
            let job = ScanJob::new(
                ScanParams::contract_defaults(),
                &target(),
                &limits(200, 30_000, 3_600),
                key(),
            );
            let ticket = format!("{prefix}-{n}-{tail}");
            let mut raw = others.clone();
            raw.insert(pos.index(raw.len() + 1), ticket.clone());
            let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
            let mut found = Vec::new();
            let logs = logs_of(|| found = job.classify_guarded("email", &values, rule));
            prop_assert!(found.is_empty());
            prop_assert!(!logs.contains(&ticket));
            prop_assert!(!logs.contains(&tail));
            prop_assert_eq!(job.cas_guard().tripped(), 1);
        }
    }
}

fn redis_target() -> TargetConfig {
    crate::config::AgentConfig::parse(
        "
console:
  url: https://console.example.internal
state_dir: /var/lib/databastion
targets:
  - id: cache
    engine: valkey
    host: cache.internal
    account: databastion
    secret:
      env: VALKEY_PASSWORD
",
    )
    .unwrap()
    .targets
    .remove(0)
}

fn key_objects(objects: serde_json::Value) -> AuditParams {
    AuditParams::try_from(&audit(serde_json::json!({
        "enabled": true, "min_rows": 10, "sensitive_objects": objects
    })))
    .unwrap()
}

/// Phase 9 follow-ups (contract `SensitiveObject.object` as an
/// `ObjectName`): key patterns are accepted for Redis / Valkey targets
/// only, and checked against the whole `KeyPattern` schema.
#[test]
fn key_pattern_sensitive_objects_are_gated() {
    let params = key_objects(serde_json::json!([
        {"database": "db0", "object": "user:*:email", "classifiers": ["pii.email"]},
        {"database": "db0", "object": "orders", "classifiers": ["pii.email"]}
    ]));
    assert!(params.check_engine(TargetEngine::Valkey).is_ok());
    assert!(params.check_engine(TargetEngine::Redis).is_ok());
    for engine in [
        TargetEngine::Postgres,
        TargetEngine::Mysql,
        TargetEngine::Mariadb,
        TargetEngine::Mongodb,
        TargetEngine::Openldap,
        TargetEngine::Cas,
        TargetEngine::Sqlserver,
    ] {
        let e = params.check_engine(engine).unwrap_err();
        assert_eq!(e.field, "sensitive_objects.object", "{engine:?}");
    }
    // Identifiers only: every engine.
    let plain = key_objects(serde_json::json!([
        {"database": "db0", "object": "orders", "classifiers": ["pii.email"]}
    ]));
    assert!(plain.check_engine(TargetEngine::Postgres).is_ok());
    // The `KeyPattern` `not` rules, which serde does not check: a phone
    // number across segments, an IPv4 address, a URL scheme, a
    // percent-encoded byte.
    let mut refused = 0;
    for object in [
        "tel:06.12.34.56.78",
        "host:10.0.0.1",
        "javascript:alert",
        "user:%40:x",
    ] {
        let json = serde_json::json!({"enabled": true, "sensitive_objects": [
            {"database": "db0", "object": object, "classifiers": ["pii.email"]}
        ]});
        let parsed: Result<p::AuditConfigureParams, _> = serde_json::from_value(json);
        if let Ok(parsed) = parsed {
            let e = AuditParams::try_from(&parsed).unwrap_err();
            assert_eq!(e.field, "sensitive_objects.object", "{object}");
            refused += 1;
        }
    }
    // Serde accepts them (pattern only): the agent-side check refuses.
    assert_eq!(refused, 4);
}

#[test]
fn key_patterns_match_as_star_globs_on_redis_and_valkey() {
    let params = key_objects(serde_json::json!([
        {"database": "db0", "object": "user:*:email", "classifiers": ["pii.email"]},
        {"database": "db1", "object": "session:*", "classifiers": ["pii.email"]},
        {"database": "db2", "object": "Card|Num", "classifiers": ["pii.email"]}
    ]));
    let cfg = AuditConfig::new(params, &redis_target(), &Limits::default());
    // The same learned pattern.
    assert!(cfg.is_sensitive("db0", None, "user:*:email"));
    // A coarser event pattern (a key no learned pattern names, with a
    // learned literal prefix), and the unknown key `*`.
    assert!(cfg.is_sensitive("db0", None, "user:*"));
    assert!(cfg.is_sensitive("db0", None, "*"));
    // A finer event pattern under a listed coarse one.
    assert!(cfg.is_sensitive("db1", None, "session:*:token"));
    assert!(cfg.is_sensitive("db1", None, "session:*"));
    // `*` spans separators, as in a Redis glob.
    assert!(cfg.is_sensitive("db0", None, "user:*:profile:*:email"));
    // Unrelated patterns, another database.
    assert!(!cfg.is_sensitive("db0", None, "user:*:name"));
    assert!(!cfg.is_sensitive("db0", None, "order:*:email"));
    assert!(!cfg.is_sensitive("db1", None, "user:*:email"));
    assert!(!cfg.is_sensitive("db0", None, "sessions"));
    // The database `*` (a source that does not tell it) matches any.
    assert!(cfg.is_sensitive("*", None, "user:*:email"));
    assert!(cfg.is_sensitive("*", None, "session:*"));
    assert!(!cfg.is_sensitive("*", None, "order:*"));
    // The N1 fold: case and trailing spaces.
    assert!(cfg.is_sensitive("DB0", None, "USER:*:Email"));
    assert!(cfg.is_sensitive("db2", None, "card|num "));
    // No schema on Redis: a schema never narrows the match.
    assert!(cfg.is_sensitive("db0", Some("x"), "user:*:email"));
    // `?` and `[` are literal (never produced as wildcards).
    let params = key_objects(serde_json::json!([
        {"database": "db0", "object": "a?b", "classifiers": ["pii.email"]},
        {"database": "db0", "object": "c[x]", "classifiers": ["pii.email"]}
    ]));
    let cfg = AuditConfig::new(params, &redis_target(), &Limits::default());
    assert!(cfg.is_sensitive("db0", None, "a?b"));
    assert!(!cfg.is_sensitive("db0", None, "acb"));
    assert!(cfg.is_sensitive("db0", None, "c[x]"));
    assert!(!cfg.is_sensitive("db0", None, "cx"));
}

#[test]
fn identifier_targets_keep_the_exact_folded_match() {
    // On a PostgreSQL target `*` is a literal name, never a wildcard.
    let params = key_objects(serde_json::json!([
        {"database": "shop", "schema": "crm", "object": "customers", "classifiers": ["pii.email"]}
    ]));
    let cfg = AuditConfig::new(params, &target(), &Limits::default());
    assert!(cfg.is_sensitive("shop", Some("crm"), "Customers "));
    assert!(!cfg.is_sensitive("shop", Some("crm"), "*"));
    assert!(!cfg.is_sensitive("*", Some("crm"), "customers"));
    assert!(!cfg.is_sensitive("shop", Some("hr"), "customers"));
}

#[test]
fn star_glob_is_bounded_and_exact() {
    let c = |s: &str| s.chars().collect::<Vec<char>>();
    assert!(star_glob(&c("*"), &c("")));
    assert!(star_glob(&c(""), &c("")));
    assert!(!star_glob(&c(""), &c("a")));
    assert!(star_glob(&c("a*b*c"), &c("aXbYc")));
    assert!(!star_glob(&c("a*b*c"), &c("aXbY")));
    assert!(star_glob(&c("**"), &c("abc")));
    // The worst case of the contract's bound stays fast.
    let long_pattern = c(&"*a".repeat(128));
    let long_name = c(&"a".repeat(255));
    let t = std::time::Instant::now();
    let _ = star_glob(&long_pattern, &long_name);
    assert!(t.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn the_key_pattern_fixture_is_accepted_for_a_valkey_target() {
    let list: p::JobList = serde_json::from_str(include_str!(
        "../../../../shared/protocol/fixtures/valid/JobList.audit-configure-key-patterns.json"
    ))
    .unwrap();
    let p::Job::AuditConfigureJob(job) = &list.jobs[0] else {
        panic!("audit.configure expected");
    };
    let params = AuditParams::try_from(&job.params).unwrap();
    params.check_engine(TargetEngine::Valkey).unwrap();
    assert!(params.check_engine(TargetEngine::Postgres).is_err());
    let cfg = AuditConfig::new(params, &redis_target(), &Limits::default());
    assert!(cfg.is_sensitive("db0", None, "session|*|card.number"));
    assert!(cfg.is_sensitive("db1", None, "orders"));
    assert!(!cfg.is_sensitive("db1", None, "user:*:email"));
}
