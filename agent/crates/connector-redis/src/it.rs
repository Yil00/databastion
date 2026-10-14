//! Integration tests against the dev `redis` profile (`make dev-redis`,
//! dev/README.md "Valkey and Redis"): Valkey 9.0 and Redis 8.10 over TLS
//! with the dev CA, the ACL users `databastion` and `databastion_scoped`.
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
        let t = target(declared, server, "databastion", "");
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
            NoteCode::PrivilegeNotEvaluated,
            NoteCode::PrivilegeDeclaredKeysNotReadable,
            NoteCode::SecurityDefaultUserNopass,
            NoteCode::CheckServerIsRedis,
            NoteCode::CheckServerIsValkey,
        ] {
            assert!(!codes.contains(&over), "{declared}: {over:?} in {codes:?}");
        }
        // `%R~*` lets the account read any key, the CAS guard probes too.
        assert!(codes.contains(&NoteCode::PrivilegeTicketCredentialsReadable));
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
    assert_eq!(h.failure, Some(FailureCode::Unsupported));
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
    let t = target(name, engine, "databastion", "");
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
        let t = target(
            name,
            engine,
            "databastion_scoped",
            "key_patterns: ['customer:*', 'user:*']",
        );
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
        let t = target(name, engine, "databastion", "databases: [14]");
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
