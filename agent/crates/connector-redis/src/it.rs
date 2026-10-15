//! Integration tests against the dev `redis` profile (`make dev-redis`,
//! dev/README.md "Valkey and Redis"): Valkey 9.0 and Redis 8.10 over TLS
//! with the dev CA, the ACL users `databastion` and `databastion_scoped`.
//!
//! On Redis 6.2 (no `ACL DRYRUN`, engine matrix with
//! `DATABASTION_DEV_REDIS_IMAGE`), the Redis targets carry the local opt-in
//! `unevaluated_acl: accept` (ADR-0052 decision 4) and the checks expect
//! `privilege.not_evaluated` in place of the evaluated notes.
//!
//! Skipped unless `DATABASTION_IT_REDIS=1`. Variables:
//! - `DATABASTION_IT_REDIS_CA`: the dev CA (`docker compose … exec -T
//!   valkey cat /tls/ca.pem`);
//! - `DATABASTION_DB_PASSWORD`: the agent users' password (dev/.env);
//! - `VALKEY_PORT` / `REDIS_PORT`: default 6379 / 6389.
//!
//! The tests read the server's `ACL LOG` through a test-only raw client
//! with the agent's own user (`+acl|log` is part of the dev ACL); the
//! connector itself has no encoder for it.

use std::sync::Arc;

use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig, TargetEngine};
use databastion_core::{
    Connector, ConnectorError, FailureCode, FindingSink, NoteCode, ScanCoverage, ScanJob,
    ScanParams,
};

use crate::RedisConnector;
use crate::net::Endpoint;
use crate::resp::{Decoder, Limits as RespLimits, Value};

fn enabled() -> bool {
    std::env::var("DATABASTION_IT_REDIS").as_deref() == Ok("1")
}

fn port(engine: TargetEngine) -> u16 {
    let (var, default) = match engine {
        TargetEngine::Redis => ("REDIS_PORT", 6389),
        _ => ("VALKEY_PORT", 6379),
    };
    std::env::var(var)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default)
}

fn ca() -> String {
    std::env::var("DATABASTION_IT_REDIS_CA").expect("DATABASTION_IT_REDIS_CA")
}

/// A target of the dev profile: `engine` is the declared engine, `server`
/// the service reached.
fn target(engine: &str, server: TargetEngine, account: &str, redis: &str) -> TargetConfig {
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{{id: it, \
         engine: {engine}, host: 127.0.0.1, port: {port}, account: {account}, \
         secret: {{env: DATABASTION_DB_PASSWORD}}, \
         redis: {{ca_file: \"{ca}\"{sep}{redis}}}}}]}}",
        port = port(server),
        ca = ca(),
        sep = if redis.is_empty() { "" } else { ", " },
    );
    databastion_core::AgentConfig::parse(&yaml).unwrap().targets[0].clone()
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[7u8; 32]).unwrap())
}

fn unpaced() -> Limits {
    Limits {
        discovery_duty_cycle_percent: 100,
        ..Limits::default()
    }
}

struct Scan {
    result: Result<(), ConnectorError>,
    findings: Vec<MaskedFinding>,
    coverage: ScanCoverage,
    tripped: u64,
}

async fn scan(t: &TargetConfig) -> Scan {
    let connector = RedisConnector::new();
    let job = ScanJob::new(ScanParams::contract_defaults(), t, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(4096);
    let result = connector.discover(&job, &sink).await;
    let coverage = databastion_core::test_support::coverage_of(&sink);
    drop(sink);
    let mut findings = Vec::new();
    while let Some(f) = rx.recv().await {
        findings.push(f);
    }
    Scan {
        result,
        findings,
        coverage,
        tripped: job.cas_guard().tripped(),
    }
}

/// A test-only raw command (the connector cannot encode it), as the
/// target's account.
async fn raw(t: &TargetConfig, args: &[&[u8]]) -> Value {
    let password = t.secret.read().unwrap();
    let mut out = raw_as(t, &t.account, &password, &[args.to_vec()]).await;
    out.pop().unwrap()
}

/// Test-only raw commands as `user`, on one connection; their replies.
async fn raw_as(t: &TargetConfig, user: &str, password: &str, cmds: &[Vec<&[u8]>]) -> Vec<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tls = crate::node::tls_of(&t.redis_settings()).unwrap();
    let ep = Endpoint::Tcp {
        host: "127.0.0.1".to_owned(),
        port: t.port.unwrap(),
    };
    let mut io = ep.open(tls).await.unwrap();
    let mut req = Vec::new();
    crate::resp::encode(&[b"AUTH", user.as_bytes(), password.as_bytes()], &mut req);
    crate::resp::encode(&[b"HELLO", b"3"], &mut req);
    for c in cmds {
        crate::resp::encode(c, &mut req);
    }
    io.write_all(&req).await.unwrap();
    let limits = RespLimits {
        bulk: 1 << 20,
        items: 1 << 16,
        skip_oversized: false,
        reply: 64 << 20,
    };
    let mut d = Decoder::new(limits);
    let mut buf = vec![0u8; 65536];
    let mut replies = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    while replies.len() < cmds.len() + 2 {
        let n = io.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed");
        pending.extend_from_slice(&buf[..n]);
        while !pending.is_empty() {
            let (used, v) = d.feed(&pending).unwrap();
            pending.drain(..used);
            match v {
                Some(v) => replies.push(v),
                None => break,
            }
        }
    }
    assert!(replies[0].error().is_none(), "AUTH as {user}");
    replies.split_off(2)
}

/// Commands as the dev `admin` user (seeding the scratch databases).
async fn admin(t: &TargetConfig, cmds: &[Vec<&[u8]>]) -> Vec<Value> {
    let password =
        std::env::var("REDIS_ADMIN_PASSWORD").unwrap_or_else(|_| "dev-only-redis-admin".to_owned());
    raw_as(t, "admin", &password, cmds).await
}

/// Whether the server reached for `engine` is Redis before 7.0 (no
/// `ACL DRYRUN`: the 6.2 path of decision 4).
async fn legacy(engine: TargetEngine) -> bool {
    if engine != TargetEngine::Redis {
        return false;
    }
    let t = target("redis", engine, "databastion", "");
    let r = admin(&t, &[vec![b"INFO", b"server"]]).await;
    let text = r[0]
        .as_bytes()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    matches!(
        crate::info::server(&text),
        Some(crate::info::Server::Redis(v)) if v < crate::info::Version(7, 0, 0)
    )
}

/// [`target`], with `unevaluated_acl: accept` on Redis 6.2 (the opt-in an
/// operator sets after reviewing the account by hand).
async fn tgt(engine: &str, server: TargetEngine, account: &str, redis: &str) -> TargetConfig {
    if legacy(server).await {
        let sep = if redis.is_empty() { "" } else { ", " };
        target(
            engine,
            server,
            account,
            &format!("{redis}{sep}unevaluated_acl: accept"),
        )
    } else {
        target(engine, server, account, redis)
    }
}

/// `ACL LOG` entries of `user` (their `count` summed).
async fn acl_log_count(t: &TargetConfig, user: &str) -> i64 {
    let Value::Array(entries) = raw(t, &[b"ACL", b"LOG", b"128"]).await else {
        panic!("ACL LOG reply")
    };
    let mut total = 0;
    for e in entries {
        let Value::Map(fields) = e else { continue };
        let mut count = 0;
        let mut name = None;
        for (k, v) in fields {
            match (k.as_bytes(), v) {
                (Some(b"count"), Value::Int(n)) => count = n,
                (Some(b"username"), v) => name = v.as_bytes().map(<[u8]>::to_vec),
                _ => {}
            }
        }
        if name.as_deref() == Some(user.as_bytes()) {
            total += count;
        }
    }
    total
}

fn codes(h: &databastion_core::TargetHealth) -> Vec<NoteCode> {
    h.notes.iter().map(|n| n.code()).collect()
}

#[tokio::test]
async fn check_reports_a_healthy_account_on_both_engines() {
    if !enabled() {
        return;
    }
    for (declared, server) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let old = legacy(server).await;
        let t = tgt(declared, server, "databastion", "").await;
        let h = RedisConnector::new().check(&t).await;
        let codes = codes(&h);
        assert!(h.reachable, "{declared}: {h:?}");
        assert_eq!(h.failure, None, "{declared}: {codes:?}");
        assert!(codes.contains(&NoteCode::AuditStreamNotAvailable));
        for over in [
            NoteCode::PrivilegeWriteActions,
            NoteCode::PrivilegeAdminCommands,
            NoteCode::PrivilegeScripting,
            NoteCode::PrivilegePubsubChannels,
            NoteCode::PrivilegeDeclaredKeysNotReadable,
            NoteCode::SecurityDefaultUserNopass,
            NoteCode::CheckServerIsRedis,
            NoteCode::CheckServerIsValkey,
        ] {
            assert!(!codes.contains(&over), "{declared}: {over:?} in {codes:?}");
        }
        if old {
            // Redis 6.2: nothing evaluated, shown permanently; the CAS
            // key privilege and the declarations are not evaluated either
            // (never reported as passed nor as failed).
            assert!(
                codes.contains(&NoteCode::PrivilegeNotEvaluated),
                "{codes:?}"
            );
            assert!(
                !codes.contains(&NoteCode::PrivilegeTicketCredentialsReadable),
                "{codes:?}"
            );
        } else {
            assert!(
                !codes.contains(&NoteCode::PrivilegeNotEvaluated),
                "{codes:?}"
            );
            // `%R~*` lets the account read any key, the CAS guard probes
            // too.
            assert!(codes.contains(&NoteCode::PrivilegeTicketCredentialsReadable));
        }
    }
    // The declared engine differs from the server's.
    let t = target("redis", TargetEngine::Valkey, "databastion", "");
    let codes = codes(&RedisConnector::new().check(&t).await);
    assert!(codes.contains(&NoteCode::CheckServerIsValkey), "{codes:?}");
}

#[tokio::test]
async fn declared_patterns_are_confirmed_and_opt_in_is_refused_on_dryrun_servers() {
    if !enabled() {
        return;
    }
    let ok = target(
        "valkey",
        TargetEngine::Valkey,
        "databastion_scoped",
        "key_patterns: ['customer:*', 'user:*']",
    );
    let h = RedisConnector::new().check(&ok).await;
    let c = codes(&h);
    assert_eq!(h.failure, None, "{c:?}");
    assert!(!c.contains(&NoteCode::PrivilegeDeclaredKeysNotReadable));
    // The scoped account cannot read the CAS guard probe keys.
    assert!(
        !c.contains(&NoteCode::PrivilegeTicketCredentialsReadable),
        "{c:?}"
    );
    let wide = target("valkey", TargetEngine::Valkey, "databastion_scoped", "");
    let h = RedisConnector::new().check(&wide).await;
    let note = h
        .notes
        .iter()
        .find(|n| n.code() == NoteCode::PrivilegeDeclaredKeysNotReadable)
        .expect("declared `*` not readable");
    assert_eq!(note.count(), Some(1));
    let opt_in = target(
        "redis",
        TargetEngine::Redis,
        "databastion",
        "unevaluated_acl: accept",
    );
    let h = RedisConnector::new().check(&opt_in).await;
    if legacy(TargetEngine::Redis).await {
        // Redis 6.2: the opt-in is what lets the target run, with
        // `privilege.not_evaluated` shown permanently.
        assert_eq!(h.failure, None, "{:?}", codes(&h));
        assert!(codes(&h).contains(&NoteCode::PrivilegeNotEvaluated));
        // Without it, refused.
        let plain = target("redis", TargetEngine::Redis, "databastion", "");
        let h = RedisConnector::new().check(&plain).await;
        assert_eq!(h.failure, Some(FailureCode::Unsupported));
    } else {
        assert_eq!(h.failure, Some(FailureCode::Unsupported));
    }
}

/// The contract findings, as the core would send them.
fn findings_json(findings: &[MaskedFinding], engine: TargetEngine) -> Vec<serde_json::Value> {
    databastion_core::test_support::contract_findings_json(findings, engine)
        .lines()
        .flat_map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["findings"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

async fn discovery_matches_the_ground_truth(engine: TargetEngine, name: &str) {
    let t = tgt(name, engine, "databastion", "").await;
    let s = scan(&t).await;
    assert!(s.result.is_ok(), "{name}: {:?}", s.result);
    assert!(s.coverage.sampled > 0, "{:?}", s.coverage);
    // The three `sso:TGT-…` keys: guarded by name, never read.
    assert_eq!(s.tripped, 3, "{name}");
    let json = findings_json(&s.findings, engine);
    let text = serde_json::to_string(&json).unwrap();
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    let mut missing = Vec::new();
    for l in gt["locations"].as_array().unwrap() {
        if l["engine"] != name {
            continue;
        }
        // I2: no ground-truth value, and no value found in a name, in
        // clear (the value itself is never printed).
        for k in ["values", "name_values"] {
            for v in l[k].as_array().into_iter().flatten() {
                let v = v.as_str().unwrap();
                if v.chars().count() >= 4 {
                    assert!(
                        !text.contains(v),
                        "{name}: a ground-truth value left in clear"
                    );
                }
            }
        }
        // The pattern expected on the uplink (exact).
        let object = l["expected_normalized_name"]
            .as_str()
            .or(l["object"].as_str())
            .unwrap();
        for c in l["expected_classifiers"].as_array().unwrap() {
            let found = json.iter().any(|f| {
                let loc = &f["location"];
                f["classifier"] == *c
                    && loc["database"] == l["database"]
                    && loc["schema"] == l["container"]
                    && loc["field"] == l["field"]
                    && loc["object"] == object
            });
            if !found {
                missing.push(format!("{} {} {} {}", l["database"], object, l["field"], c));
            }
        }
    }
    assert!(missing.is_empty(), "{name}: not found: {missing:#?}");
    // The patterns of decision 7 on the seeded names.
    let objects: std::collections::BTreeSet<&str> = json
        .iter()
        .filter_map(|f| f["location"]["object"].as_str())
        .collect();
    for expected in [
        "customer:*:email",
        "user:*:profile",
        // `phone:<n>` and `addressbook:<n>`: the record-id rule at the
        // first position too (security review H1).
        "*:*",
        "session:*",
        "queue:sms_outbox",
        "integration:*:secret_access_key",
    ] {
        assert!(
            objects.contains(expected),
            "{name}: {expected} in {objects:?}"
        );
    }
    // Every two-segment name of db0 shares `*:*` with `phone:<n>`
    // (one per Redis type).
    let two: std::collections::BTreeSet<&str> = json
        .iter()
        .filter(|f| f["location"]["object"] == "*:*")
        .filter_map(|f| f["location"]["schema"].as_str())
        .collect();
    assert_eq!(
        two.into_iter().collect::<Vec<_>>(),
        ["hash", "set", "stream", "string", "zset"],
        "{name}"
    );
    // Every value-carrying key name gave a `#key` or `#field` finding.
    assert!(json.iter().any(|f| f["location"]["field"] == "#key"));
    assert!(json.iter().any(|f| f["location"]["field"] == "#field"));
    // Three guarded keys, never read.
    assert_eq!(s.coverage.unsupported, 3, "{:?}", s.coverage);
    for f in &json {
        let o = f["location"]["object"].as_str().unwrap();
        // Patterns only: no address, no digit, never a guarded key.
        assert!(
            !o.contains('@') && !o.chars().any(|c| c.is_ascii_digit()),
            "{o}"
        );
        assert!(!o.starts_with("sso"), "{o}");
    }
}

#[tokio::test]
async fn discovery_on_valkey() {
    if !enabled() {
        return;
    }
    discovery_matches_the_ground_truth(TargetEngine::Valkey, "valkey").await;
}

#[tokio::test]
async fn discovery_on_redis() {
    if !enabled() {
        return;
    }
    discovery_matches_the_ground_truth(TargetEngine::Redis, "redis").await;
}

#[tokio::test]
async fn narrowed_patterns_write_no_acl_log_entry() {
    if !enabled() {
        return;
    }
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(
            name,
            engine,
            "databastion_scoped",
            "key_patterns: ['customer:*', 'user:*']",
        )
        .await;
        let before = acl_log_count(&t, "databastion_scoped").await;
        let h = RedisConnector::new().check(&t).await;
        assert_eq!(h.failure, None, "{name}");
        let s = scan(&t).await;
        assert!(s.result.is_ok(), "{:?}", s.result);
        assert!(!s.findings.is_empty());
        assert_eq!(s.coverage.not_readable, 0, "{:?}", s.coverage);
        for f in &findings_json(&s.findings, engine) {
            let o = f["location"]["object"].as_str().unwrap();
            assert!(o.starts_with("customer") || o.starts_with("user"), "{o}");
        }
        let after = acl_log_count(&t, "databastion_scoped").await;
        assert_eq!(before, after, "{name}: the agent wrote ACL LOG entries");
    }
}

/// Every string of a reply, joined (test only).
fn strings(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Str(b) => {
            out.extend_from_slice(b.as_slice());
            out.push(b'\n');
        }
        Value::Array(items) => items.iter().for_each(|i| strings(i, out)),
        Value::Map(pairs) => pairs.iter().for_each(|(k, v)| {
            strings(k, out);
            strings(v, out);
        }),
        _ => {}
    }
}

#[tokio::test]
async fn the_password_never_reaches_the_slow_log() {
    if !enabled() {
        return;
    }
    // The dev servers log every command (`slowlog-log-slower-than 0`).
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = target(name, engine, "databastion", "");
        let h = RedisConnector::new().check(&t).await;
        assert!(h.reachable, "{name}");
        let log = raw(&t, &[b"SLOWLOG", b"GET", b"128"]).await;
        let mut text = Vec::new();
        strings(&log, &mut text);
        let password = t.secret.read().unwrap();
        assert!(
            !text
                .windows(password.len())
                .any(|w| w == password.as_bytes()),
            "{name}: the password is in SLOWLOG"
        );
        // HELLO carried no credential; the agent's own commands are there.
        assert!(text.windows(5).any(|w| w == b"HELLO"), "{name}");
    }
}

/// A small deterministic generator (test only).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) % n as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], max: usize) -> Vec<u8> {
        let len = self.next(max) + 1;
        (0..len)
            .map(|_| alphabet[self.next(alphabet.len())])
            .collect()
    }
}

/// ADR-0052 obligation (security review M5): the local glob matcher agrees
/// with the server's `SCAN … MATCH` on generated names and patterns
/// (classes, ranges, negation, escapes, malformed classes), on both
/// engines. Uses the scratch database 15, seeded and flushed by `admin`.
#[tokio::test]
async fn local_glob_matcher_agrees_with_scan_match() {
    if !enabled() {
        return;
    }
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = target(name, engine, "databastion", "");
        let mut rng = Lcg(0x5eed_0052 ^ u64::from(port(engine)));
        let keys: Vec<Vec<u8>> = {
            let mut k: Vec<Vec<u8>> = (0..300).map(|_| rng.string(b"abc:-x^]\\[*?", 7)).collect();
            k.sort();
            k.dedup();
            k
        };
        let mut seed: Vec<Vec<&[u8]>> = vec![vec![b"SELECT", b"15"], vec![b"FLUSHDB"]];
        for k in &keys {
            seed.push(vec![b"SET", k, b"v"]);
        }
        admin(&t, &seed).await;
        let patterns: Vec<Vec<u8>> = (0..300).map(|_| rng.string(b"abc:-x*?[]^\\", 6)).collect();
        let mut cmds: Vec<Vec<&[u8]>> = vec![vec![b"SELECT", b"15"]];
        for p in &patterns {
            cmds.push(vec![b"SCAN", b"0", b"MATCH", p, b"COUNT", b"100000"]);
        }
        let replies = admin(&t, &cmds).await;
        let mut disagree = Vec::new();
        for (p, r) in patterns.iter().zip(replies.iter().skip(1)) {
            let Value::Array(parts) = r else {
                panic!("SCAN reply")
            };
            assert_eq!(parts[0].as_bytes(), Some(&b"0"[..]), "one SCAN call");
            let Value::Array(found) = &parts[1] else {
                panic!("SCAN keys")
            };
            let mut server: Vec<&[u8]> = found.iter().filter_map(Value::as_bytes).collect();
            server.sort_unstable();
            let local: Vec<&[u8]> = keys
                .iter()
                .filter(|k| crate::glob::matches(p, k))
                .map(Vec::as_slice)
                .collect();
            if server != local {
                disagree.push(String::from_utf8_lossy(p).into_owned());
            }
        }
        admin(&t, &[vec![b"SELECT", b"15"], vec![b"FLUSHDB"]]).await;
        assert!(
            disagree.is_empty(),
            "{name}: {} patterns disagree: {disagree:?}",
            disagree.len()
        );
    }
}

/// Security review H2: a hash keyed by data, alone in its pattern, keeps
/// none of its field names (it has more than 16). Scratch database 14.
#[tokio::test]
async fn a_large_data_keyed_hash_reports_no_field_name() {
    if !enabled() {
        return;
    }
    let names = [
        "jdupont", "amartin", "lucas", "bernard", "dubois", "thomas", "robert", "richard", "petit",
        "durand", "leroy", "moreau", "simon", "laurent", "lefebvre", "michel", "garcia", "david",
        "bertrand", "roux", "vincent", "fournier", "morel", "girard", "andre",
    ];
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "databases: [14]").await;
        let values: Vec<String> = (0..names.len())
            .map(|i| format!("support.desk{i}@example.org"))
            .collect();
        let mut hset: Vec<&[u8]> = vec![b"HSET", b"accounts:directory"];
        for (n, v) in names.iter().zip(&values) {
            hset.push(n.as_bytes());
            hset.push(v.as_bytes());
        }
        admin(&t, &[vec![b"SELECT", b"14"], vec![b"FLUSHDB"], hset]).await;
        let s = scan(&t).await;
        admin(&t, &[vec![b"SELECT", b"14"], vec![b"FLUSHDB"]]).await;
        assert!(s.result.is_ok(), "{:?}", s.result);
        let json = findings_json(&s.findings, engine);
        let text = serde_json::to_string(&json).unwrap();
        let ours: Vec<&serde_json::Value> = json
            .iter()
            .filter(|f| f["location"]["object"] == "accounts:directory")
            .collect();
        assert!(!ours.is_empty(), "{name}: no finding on the hash");
        // Values under `*`; field names that look like values themselves
        // (first names here) only as masked `#field` findings.
        assert!(ours.iter().any(|f| f["location"]["field"] == "*"), "{name}");
        for f in &ours {
            let field = f["location"]["field"].as_str().unwrap();
            assert!(field == "*" || field == "#field", "{name}: {field}");
        }
        for n in names {
            assert!(!text.contains(n), "{name}: a field name left in clear");
        }
    }
}

// ---------------------------------------------------------------------
// Audit (ADR-0052 decision 8).
// ---------------------------------------------------------------------

/// A raw TLS connection as `user` (test only): `AUTH`, `HELLO 3`, then,
/// after `before`, `cmds`; their replies are read, the connection is held
/// for `after`. `AUTH` must succeed.
async fn raw_held(
    t: &TargetConfig,
    user: &str,
    password: &str,
    before: std::time::Duration,
    cmds: &[Vec<&[u8]>],
    after: std::time::Duration,
) -> Vec<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tls = crate::node::tls_of(&t.redis_settings()).unwrap();
    let ep = Endpoint::Tcp {
        host: "127.0.0.1".to_owned(),
        port: t.port.unwrap(),
    };
    let mut io = ep.open(tls).await.unwrap();
    let mut req = Vec::new();
    crate::resp::encode(&[b"AUTH", user.as_bytes(), password.as_bytes()], &mut req);
    crate::resp::encode(&[b"HELLO", b"3"], &mut req);
    io.write_all(&req).await.unwrap();
    let limits = RespLimits {
        bulk: 1 << 20,
        items: 1 << 16,
        skip_oversized: false,
        reply: 64 << 20,
    };
    let mut d = Decoder::new(limits);
    let mut buf = vec![0u8; 65536];
    let mut pending: Vec<u8> = Vec::new();
    let mut replies = Vec::new();
    let mut want = 2;
    let mut sent = false;
    loop {
        while replies.len() < want {
            let (used, v) = d.feed(&pending).unwrap();
            pending.drain(..used);
            match v {
                Some(v) => replies.push(v),
                None => {
                    let n = io.read(&mut buf).await.unwrap();
                    assert!(n > 0, "connection closed");
                    pending.extend_from_slice(&buf[..n]);
                }
            }
        }
        if sent {
            break;
        }
        assert!(replies[0].error().is_none(), "AUTH as {user}");
        tokio::time::sleep(before).await;
        let mut req = Vec::new();
        for c in cmds {
            crate::resp::encode(c, &mut req);
        }
        io.write_all(&req).await.unwrap();
        want += cmds.len();
        sent = true;
    }
    tokio::time::sleep(after).await;
    replies.split_off(2)
}

/// Raw bytes received for `secs` after sending `cmds` on a raw TLS
/// connection (test only; `MONITOR`, `SYNC`, a failed `AUTH`).
async fn raw_bytes(t: &TargetConfig, cmds: &[Vec<&[u8]>], secs: u64) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tls = crate::node::tls_of(&t.redis_settings()).unwrap();
    let ep = Endpoint::Tcp {
        host: "127.0.0.1".to_owned(),
        port: t.port.unwrap(),
    };
    let mut io = ep.open(tls).await.unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    // One command at a time, each reply read first (`SYNC` is refused
    // with pending output).
    let (last, first) = cmds.split_last().unwrap();
    for c in first {
        let mut req = Vec::new();
        crate::resp::encode(c, &mut req);
        io.write_all(&req).await.unwrap();
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), io.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    let mut req = Vec::new();
    crate::resp::encode(last, &mut req);
    io.write_all(&req).await.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, io.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        if out.len() < (1 << 20) {
            out.extend_from_slice(&buf[..n]);
        }
    }
    out
}

fn admin_password() -> String {
    std::env::var("REDIS_ADMIN_PASSWORD").unwrap_or_else(|_| "dev-only-redis-admin".to_owned())
}

/// `INFO stats` `sync_full` (as `admin`).
async fn sync_full(t: &TargetConfig) -> u64 {
    let r = admin(t, &[vec![b"INFO", b"stats"]]).await;
    let text = String::from_utf8_lossy(r[0].as_bytes().unwrap()).into_owned();
    crate::info::field(&text, "sync_full")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Every string of the ground truth's values and names (I2 markers).
fn ground_truth_values(engine: &str) -> Vec<String> {
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    let mut out = Vec::new();
    for l in gt["locations"].as_array().unwrap() {
        if l["engine"] != engine {
            continue;
        }
        for k in ["values", "name_values"] {
            for v in l[k].as_array().into_iter().flatten() {
                if let Some(v) = v.as_str().filter(|v| v.chars().count() >= 4) {
                    out.push(v.to_owned());
                }
            }
        }
    }
    out
}

fn events_json(events: &[databastion_classifiers::masking::MaskedEvent]) -> Vec<serde_json::Value> {
    databastion_core::test_support::contract_events_json(events, &key())
        .lines()
        .flat_map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["events"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

/// Slow commands on sensitive keys become events under learned patterns
/// (H1), with no value in the contract JSON (I2); the agent's own reads,
/// from a Discovery scan run while the stream polls, are never reported
/// (H3); failed authentications are reported; `KEYS` and a large `SCAN`
/// set `shape.keyspace_enumeration`; on Valkey 8.1+ the large-reply log
/// gives `volume.large_reply` with `bytes`; a `SYNC` gives
/// `signature.full_sync` where `sync_full` grows; `check()` then reports
/// Limited.
#[tokio::test(flavor = "multi_thread")]
async fn audit_reports_slow_reads_and_never_the_agents_own() {
    if !enabled() {
        return;
    }
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        let connector = Arc::new(RedisConnector::new());
        // The patterns the stream maps keys to.
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (fs, mut frx) = FindingSink::channel(4096);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        connector.discover(&job, &fs).await.unwrap();
        drop(fs);
        drain.await.unwrap();

        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-audit-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let limits = Limits {
            min_audit_poll_interval_s: 1,
            ..Limits::default()
        };
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
        let (sink, mut rx) = databastion_core::EventSink::channel(8192);
        let c2 = Arc::clone(&connector);
        let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert!(!stream.is_finished(), "{name}: {:?}", stream.await);

        // The agent's own Discovery while the stream polls (paced, so it
        // lasts several polls).
        let paced = Limits {
            discovery_duty_cycle_percent: 30,
            ..Limits::default()
        };
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &paced, key());
        let (fs, mut frx) = FindingSink::channel(4096);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        connector.discover(&job, &fs).await.unwrap();
        drop(fs);
        drain.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Valkey 8.1+: a large-reply threshold the `KEYS` reply reaches
        // (default 1 MiB), restored below.
        if name == "valkey" {
            admin(
                &t,
                &[vec![
                    b"CONFIG",
                    b"SET",
                    b"commandlog-reply-larger-than",
                    b"1024",
                ]],
            )
            .await;
        }
        // Another client, connected well before its commands (L2).
        let pw = admin_password();
        let replies = raw_held(
            &t,
            "admin",
            &pw,
            std::time::Duration::from_secs(3),
            &[
                vec![b"HGETALL", b"session:jdupont"],
                vec![b"GET", b"customer:1000:email"],
                vec![b"KEYS", b"customer:*"],
                vec![b"SCAN", b"0", b"MATCH", b"user:jdupont*", b"COUNT", b"5000"],
            ],
            std::time::Duration::from_secs(3),
        )
        .await;
        assert_eq!(replies.len(), 4);
        // A failed authentication.
        raw_bytes(&t, &[vec![b"AUTH", b"intruder", b"wrong-password-0052"]], 1).await;
        // A full synchronization (`redis-cli --rdb` does the same).
        let syncs = sync_full(&t).await;
        raw_bytes(
            &t,
            &[vec![b"AUTH", b"admin", pw.as_bytes()], vec![b"SYNC"]],
            // Diskless sync waits `repl-diskless-sync-delay` (5 s) for
            // other replicas before the transfer starts.
            9,
        )
        .await;
        let synced = sync_full(&t).await > syncs;
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        if name == "valkey" {
            admin(
                &t,
                &[vec![
                    b"CONFIG",
                    b"SET",
                    b"commandlog-reply-larger-than",
                    b"1048576",
                ]],
            )
            .await;
        }
        let h = connector.check(&t).await;
        stream.abort();
        let _ = stream.await;
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        let _ = std::fs::remove_dir_all(&dir);

        let json = events_json(&events);
        let text = serde_json::to_string(&json).unwrap();
        // I2: no ground-truth value, no raw key name, no argument.
        for v in ground_truth_values(name) {
            assert!(
                !text.contains(&v),
                "{name}: a ground-truth value in an event"
            );
        }
        for raw in [
            "jdupont",
            "customer:1000",
            "wrong-password-0052",
            "intruder",
        ] {
            assert!(!text.contains(raw), "{name}: {raw} in an event");
        }
        for e in &json {
            for o in e["objects"].as_array().into_iter().flatten() {
                let o = o["object"].as_str().unwrap();
                assert!(
                    o == "*" || crate::audit::entries::tests_support::is_learned_shape(o),
                    "{name}: {o}"
                );
            }
        }
        // The agent's own reads: never reported (H3).
        for e in &json {
            assert_ne!(e["principal"]["db_user"], "databastion", "{name}: {e}");
            assert_ne!(
                e["principal"]["application"], "databastion-agent",
                "{name}: {e}"
            );
        }
        // The other client's reads, attributed to its user.
        let admin_reads: Vec<&serde_json::Value> = json
            .iter()
            .filter(|e| {
                e["principal"]["db_user"] == "admin"
                    && e["action"] == "read"
                    && e["source"] == "redis_slowlog"
            })
            .collect();
        assert!(admin_reads.len() >= 2, "{name}: {json:#?}");
        let has_signal = |e: &serde_json::Value, s: &str| {
            e["signals"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == s))
        };
        assert!(
            admin_reads
                .iter()
                .filter(|e| has_signal(e, "shape.keyspace_enumeration"))
                .count()
                >= 1,
            "{name}: {json:#?}"
        );
        // A failed authentication, the name tried fingerprinted.
        assert!(
            json.iter().any(|e| e["action"] == "auth_failure"
                && e["source"] == "redis_acl_log"
                && e["principal"]["db_user_fingerprint"].is_string()),
            "{name}: {json:#?}"
        );
        if name == "valkey" {
            assert!(
                json.iter().any(|e| e["source"] == "redis_commandlog"
                    && has_signal(e, "volume.large_reply")
                    && e["bytes"].as_i64().is_some_and(|b| b > 0)),
                "{name}: {json:#?}"
            );
        }
        if synced {
            assert!(
                json.iter().any(|e| e["source"] == "redis_sync"
                    && has_signal(e, "signature.full_sync")
                    && e["principal"]["account_not_recorded"] == true),
                "{name}: {json:#?}"
            );
        } else {
            panic!("{name}: SYNC did not grow sync_full");
        }
        // Limited at best, once a slow-log entry was read.
        assert_eq!(
            h.audit_level,
            databastion_core::AuditLevel::Limited,
            "{name}: {:?}",
            codes(&h)
        );
        assert!(codes(&h).contains(&NoteCode::AuditSlowOperationsOnly));
    }
}

/// ADR-0052 decision 1 (H2, L5), widened: with every command logged, and a
/// `MONITOR` session open, the agent's password never appears in the
/// `MONITOR` stream, `SLOWLOG GET` or (Valkey 8.1+) any `COMMANDLOG` type,
/// over a `check()`, a scan and Audit polls.
#[tokio::test(flavor = "multi_thread")]
async fn the_password_never_reaches_monitor_or_the_command_log() {
    if !enabled() {
        return;
    }
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        let pw = admin_password();
        let tm = t.clone();
        let monitor = tokio::spawn(async move {
            raw_bytes(
                &tm,
                &[vec![b"AUTH", b"admin", pw.as_bytes()], vec![b"MONITOR"]],
                6,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let connector = Arc::new(RedisConnector::new());
        assert!(connector.check(&t).await.reachable);
        let limits = Limits {
            min_audit_poll_interval_s: 1,
            ..Limits::default()
        };
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits);
        let (sink, _rx) = databastion_core::EventSink::channel(8192);
        let c2 = Arc::clone(&connector);
        let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        stream.abort();
        let seen = monitor.await.unwrap();
        let password = t.secret.read().unwrap();
        let has = |bytes: &[u8]| {
            bytes
                .windows(password.len())
                .any(|w| w == password.as_bytes())
        };
        assert!(seen.len() > 100, "{name}: MONITOR saw nothing");
        assert!(!has(&seen), "{name}: the password is in the MONITOR stream");
        let mut logs: Vec<Vec<&[u8]>> = vec![vec![b"SLOWLOG", b"GET", b"128"]];
        let commandlog = matches!(
            connector.state.reports.of_target(&t, std::time::Duration::from_secs(3)).await,
            Ok((_, s)) if s.has_commandlog()
        );
        if commandlog {
            for kind in [&b"slow"[..], b"large-request", b"large-reply"] {
                logs.push(vec![b"COMMANDLOG", b"GET", b"128", kind]);
            }
        }
        for r in admin(&t, &logs).await {
            let mut text = Vec::new();
            strings(&r, &mut text);
            assert!(!has(&text), "{name}: the password is in a server log");
        }
    }
}
