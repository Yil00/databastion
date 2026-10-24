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
//! - `VALKEY_PORT` / `REDIS_PORT`: default 6379 / 6389;
//! - `DATABASTION_IT_REDIS_EXEC_VALKEY` (optional): a command prefix that
//!   runs a command in the Valkey container (e.g. `docker compose -f
//!   dev/docker-compose.yml exec -T valkey`), for the test with clients on
//!   the server's Unix socket; skipped without it;
//! - `DATABASTION_IT_REDIS_SOCKET_VALKEY` / `DATABASTION_IT_REDIS_SOCKET_REDIS`
//!   (optional): the servers' Unix sockets published to the host
//!   (`dev/redis/compose.socket.yml`), for the socket target test, with
//!   `DATABASTION_IT_REDIS_SERVER_UID` (default 999); skipped without them
//!   unless `DATABASTION_IT_REDIS_REQUIRE_SOCKET=1`.
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

/// The tests share two servers whose slow log, `ACL LOG` and connection
/// list every test changes: they run one at a time, so an Audit test
/// never sees another test's agent connections (short-lived ones, closed
/// before any poll, are reported as not the agent's: review M1).
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
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

/// A test-only raw connection to the target's node: TCP and TLS, or its
/// Unix socket (peer credentials checked as the connector does).
async fn open(t: &TargetConfig) -> crate::net::Transport {
    let tls = crate::node::tls_of(&t.redis_settings()).unwrap();
    let ep = crate::node::endpoint(t, crate::node::Which::Target).unwrap();
    ep.open(tls).await.unwrap()
}

/// Test-only raw commands as `user`, on one connection; their replies.
async fn raw_as(t: &TargetConfig, user: &str, password: &str, cmds: &[Vec<&[u8]>]) -> Vec<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut io = open(t).await;
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

/// Whether the server reached for `engine` has Valkey's command log (8.1+):
/// the large-reply source exists only there.
async fn has_commandlog(engine: TargetEngine) -> bool {
    let t = target("valkey", engine, "databastion", "");
    let r = admin(&t, &[vec![b"INFO", b"server"]]).await;
    let text = r[0]
        .as_bytes()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    crate::info::server(&text).is_some_and(crate::info::Server::has_commandlog)
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
    let _serial = serial().await;
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
    let _serial = serial().await;
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

/// #237: a declared Discovery node that is down does not make the target
/// unreachable: the target's node answers, so `check()` reports it
/// reachable, with the Discovery node's failure as a `check.stage_failed`
/// note and as the target's failure; the scan fails.
#[tokio::test]
async fn a_discovery_node_down_is_a_note_not_an_unreachable_target() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    // Nothing listens on port 1.
    let t = target(
        "valkey",
        TargetEngine::Valkey,
        "databastion",
        "discovery_node: {host: 127.0.0.1, port: 1}",
    );
    let h = RedisConnector::new().check(&t).await;
    let c = codes(&h);
    assert!(h.reachable, "{h:?}");
    assert_eq!(h.failure, Some(FailureCode::TargetUnreachable), "{c:?}");
    let stage = databastion_core::NoteLabel::stage(crate::error::Stage::Connect.as_str());
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CheckStageFailed && n.labels().contains(&stage)),
        "{c:?}"
    );
    // The target's node was evaluated: its notes are there.
    assert!(c.contains(&NoteCode::AuditStreamNotAvailable), "{c:?}");
    assert!(
        c.contains(&NoteCode::PrivilegeTicketCredentialsReadable),
        "{c:?}"
    );
    // Discovery reads the Discovery node: it cannot run.
    let s = scan(&t).await;
    assert!(
        matches!(
            s.result,
            Err(ConnectorError::Target {
                code: FailureCode::TargetUnreachable,
                ..
            })
        ),
        "{:?}",
        s.result
    );
    assert!(s.findings.is_empty());
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
    let _serial = serial().await;
    discovery_matches_the_ground_truth(TargetEngine::Valkey, "valkey").await;
}

#[tokio::test]
async fn discovery_on_redis() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    discovery_matches_the_ground_truth(TargetEngine::Redis, "redis").await;
}

#[tokio::test]
async fn narrowed_patterns_write_no_acl_log_entry() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
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
    let _serial = serial().await;
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
    let _serial = serial().await;
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
    let _serial = serial().await;
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
    let mut io = open(t).await;
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
    let _serial = serial().await;
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        // Valkey 8.1+ only: the large-reply log (`COMMANDLOG`); Valkey 7.2
        // and 8.0 have the slow log alone.
        let large_reply_log = has_commandlog(engine).await;
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

        // Sessions of the agent that read and close within a few
        // milliseconds, between two of the stream's `CLIENT LIST`: their
        // entries carry only the address the server reports for them
        // (behind Docker's port publishing, not their local one), recorded
        // at connect time (the engine-matrix flake: a paced Discovery that
        // fell between two polls).
        for _ in 0..3 {
            let (mut s, info) = crate::node::open(
                &t,
                crate::node::Which::Target,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();
            // Its address was recorded at connect time (not vacuous
            // without NAT: the local address alone would not do before
            // the server was seen to report it unchanged).
            assert!(
                crate::audit::own::is_seen(&t.id, s.hello.id.unwrap(), info.run),
                "{name}: own address not recorded at connect time"
            );
            let r = s
                .call(
                    &crate::cmd::Cmd::Scan { cursor: 0 },
                    std::time::Duration::from_secs(5),
                    crate::error::Stage::Introspection,
                )
                .await
                .unwrap();
            assert!(r.error().is_none(), "{name}: SCAN refused");
            s.close().await;
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Valkey 8.1+: a large-reply threshold the `KEYS` reply reaches
        // (default 1 MiB), restored below.
        if large_reply_log {
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
        if large_reply_log {
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
        if large_reply_log {
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
    let _serial = serial().await;
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

/// Review M4 (ADR-0052 obligation): the key positions of the closed
/// command table agree with the server's own `COMMAND GETKEYS`, row by row,
/// on this server version (the engine matrix runs it per version). The
/// agent never reads as a key an argument the server does not take for
/// one; commands the server does not know (older versions) are skipped.
#[tokio::test]
async fn key_positions_match_command_getkeys() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    // One example per keyed row: keys `k1`, `k2`, `k3`; nothing else
    // looks like them.
    const EXAMPLES: &[(&str, Option<&str>, &str)] = &[
        ("get", None, "get k1"),
        ("getrange", None, "getrange k1 0 1"),
        ("substr", None, "substr k1 0 1"),
        ("strlen", None, "strlen k1"),
        ("mget", None, "mget k1 k2"),
        ("getbit", None, "getbit k1 0"),
        ("bitcount", None, "bitcount k1"),
        ("bitpos", None, "bitpos k1 1"),
        ("bitfield_ro", None, "bitfield_ro k1 GET u8 0"),
        ("lcs", None, "lcs k1 k2"),
        ("set", None, "set k1 v"),
        ("setnx", None, "setnx k1 v"),
        ("setex", None, "setex k1 10 v"),
        ("psetex", None, "psetex k1 10 v"),
        ("getset", None, "getset k1 v"),
        ("getdel", None, "getdel k1"),
        ("getex", None, "getex k1"),
        ("append", None, "append k1 v"),
        ("incr", None, "incr k1"),
        ("incrby", None, "incrby k1 1"),
        ("incrbyfloat", None, "incrbyfloat k1 1"),
        ("decr", None, "decr k1"),
        ("decrby", None, "decrby k1 1"),
        ("setrange", None, "setrange k1 0 v"),
        ("setbit", None, "setbit k1 0 1"),
        ("bitfield", None, "bitfield k1 GET u8 0"),
        ("mset", None, "mset k1 v k2 w"),
        ("msetnx", None, "msetnx k1 v k2 w"),
        ("bitop", None, "bitop AND k1 k2 k3"),
        ("exists", None, "exists k1 k2"),
        ("type", None, "type k1"),
        ("ttl", None, "ttl k1"),
        ("pttl", None, "pttl k1"),
        ("expiretime", None, "expiretime k1"),
        ("pexpiretime", None, "pexpiretime k1"),
        ("dump", None, "dump k1"),
        ("touch", None, "touch k1 k2"),
        ("sort_ro", None, "sort_ro k1 BY w_* GET o_*"),
        ("sort", None, "sort k1 BY w_* GET o_*"),
        ("del", None, "del k1 k2"),
        ("unlink", None, "unlink k1 k2"),
        ("expire", None, "expire k1 10"),
        ("pexpire", None, "pexpire k1 10"),
        ("expireat", None, "expireat k1 10"),
        ("pexpireat", None, "pexpireat k1 10"),
        ("persist", None, "persist k1"),
        ("rename", None, "rename k1 k2"),
        ("renamenx", None, "renamenx k1 k2"),
        ("copy", None, "copy k1 k2"),
        ("move", None, "move k1 1"),
        ("restore", None, "restore k1 0 x"),
        ("hget", None, "hget k1 f"),
        ("hmget", None, "hmget k1 f g"),
        ("hgetall", None, "hgetall k1"),
        ("hkeys", None, "hkeys k1"),
        ("hvals", None, "hvals k1"),
        ("hlen", None, "hlen k1"),
        ("hexists", None, "hexists k1 f"),
        ("hstrlen", None, "hstrlen k1 f"),
        ("hrandfield", None, "hrandfield k1"),
        ("hscan", None, "hscan k1 0"),
        ("hset", None, "hset k1 f v"),
        ("hsetnx", None, "hsetnx k1 f v"),
        ("hmset", None, "hmset k1 f v"),
        ("hdel", None, "hdel k1 f"),
        ("hincrby", None, "hincrby k1 f 1"),
        ("hincrbyfloat", None, "hincrbyfloat k1 f 1"),
        ("lrange", None, "lrange k1 0 1"),
        ("lindex", None, "lindex k1 0"),
        ("llen", None, "llen k1"),
        ("lpos", None, "lpos k1 e"),
        ("lpush", None, "lpush k1 v"),
        ("rpush", None, "rpush k1 v"),
        ("lpushx", None, "lpushx k1 v"),
        ("rpushx", None, "rpushx k1 v"),
        ("lpop", None, "lpop k1"),
        ("rpop", None, "rpop k1"),
        ("linsert", None, "linsert k1 BEFORE p v"),
        ("lset", None, "lset k1 0 v"),
        ("lrem", None, "lrem k1 0 v"),
        ("ltrim", None, "ltrim k1 0 1"),
        ("lmove", None, "lmove k1 k2 LEFT RIGHT"),
        ("blmove", None, "blmove k1 k2 LEFT RIGHT 0"),
        ("rpoplpush", None, "rpoplpush k1 k2"),
        ("brpoplpush", None, "brpoplpush k1 k2 0"),
        ("blpop", None, "blpop k1 k2 0"),
        ("brpop", None, "brpop k1 k2 0"),
        ("lmpop", None, "lmpop 2 k1 k2 LEFT"),
        ("blmpop", None, "blmpop 0 2 k1 k2 LEFT"),
        ("smembers", None, "smembers k1"),
        ("sismember", None, "sismember k1 m"),
        ("smismember", None, "smismember k1 m"),
        ("scard", None, "scard k1"),
        ("srandmember", None, "srandmember k1"),
        ("sscan", None, "sscan k1 0"),
        ("sunion", None, "sunion k1 k2"),
        ("sinter", None, "sinter k1 k2"),
        ("sdiff", None, "sdiff k1 k2"),
        ("sintercard", None, "sintercard 2 k1 k2"),
        ("sadd", None, "sadd k1 m"),
        ("srem", None, "srem k1 m"),
        ("spop", None, "spop k1"),
        ("smove", None, "smove k1 k2 m"),
        ("sunionstore", None, "sunionstore k1 k2 k3"),
        ("sinterstore", None, "sinterstore k1 k2 k3"),
        ("sdiffstore", None, "sdiffstore k1 k2 k3"),
        ("zrange", None, "zrange k1 0 1"),
        ("zrangebyscore", None, "zrangebyscore k1 0 1"),
        ("zrangebylex", None, "zrangebylex k1 - +"),
        ("zrevrange", None, "zrevrange k1 0 1"),
        ("zrevrangebyscore", None, "zrevrangebyscore k1 1 0"),
        ("zrevrangebylex", None, "zrevrangebylex k1 + -"),
        ("zscore", None, "zscore k1 m"),
        ("zmscore", None, "zmscore k1 m"),
        ("zcard", None, "zcard k1"),
        ("zcount", None, "zcount k1 0 1"),
        ("zlexcount", None, "zlexcount k1 - +"),
        ("zrank", None, "zrank k1 m"),
        ("zrevrank", None, "zrevrank k1 m"),
        ("zrandmember", None, "zrandmember k1"),
        ("zscan", None, "zscan k1 0"),
        ("zunion", None, "zunion 2 k1 k2"),
        ("zinter", None, "zinter 2 k1 k2"),
        ("zdiff", None, "zdiff 2 k1 k2"),
        ("zintercard", None, "zintercard 2 k1 k2"),
        ("zadd", None, "zadd k1 1 m"),
        ("zrem", None, "zrem k1 m"),
        ("zincrby", None, "zincrby k1 1 m"),
        ("zpopmin", None, "zpopmin k1"),
        ("zpopmax", None, "zpopmax k1"),
        ("bzpopmin", None, "bzpopmin k1 k2 0"),
        ("bzpopmax", None, "bzpopmax k1 k2 0"),
        ("zmpop", None, "zmpop 2 k1 k2 MIN"),
        ("bzmpop", None, "bzmpop 0 2 k1 k2 MIN"),
        ("zremrangebyrank", None, "zremrangebyrank k1 0 1"),
        ("zremrangebyscore", None, "zremrangebyscore k1 0 1"),
        ("zremrangebylex", None, "zremrangebylex k1 - +"),
        ("zunionstore", None, "zunionstore k1 2 k2 k3"),
        ("zinterstore", None, "zinterstore k1 2 k2 k3"),
        ("zdiffstore", None, "zdiffstore k1 2 k2 k3"),
        ("zrangestore", None, "zrangestore k1 k2 0 1"),
        ("xrange", None, "xrange k1 - +"),
        ("xrevrange", None, "xrevrange k1 + -"),
        ("xlen", None, "xlen k1"),
        ("xread", None, "xread COUNT 1 STREAMS k1 k2 0 0"),
        ("xreadgroup", None, "xreadgroup GROUP g c STREAMS k1 >"),
        ("xadd", None, "xadd k1 * f v"),
        ("xdel", None, "xdel k1 0-1"),
        ("xtrim", None, "xtrim k1 MAXLEN 1"),
        ("xack", None, "xack k1 g 0-1"),
        ("xclaim", None, "xclaim k1 g c 0 0-1"),
        ("xautoclaim", None, "xautoclaim k1 g c 0 0"),
        ("xsetid", None, "xsetid k1 0-1"),
        ("pfcount", None, "pfcount k1 k2"),
        ("pfadd", None, "pfadd k1 a"),
        ("pfmerge", None, "pfmerge k1 k2"),
        ("geopos", None, "geopos k1 m"),
        ("geodist", None, "geodist k1 a b"),
        ("geohash", None, "geohash k1 m"),
        ("geosearch", None, "geosearch k1 FROMMEMBER m BYRADIUS 1 km"),
        ("georadius_ro", None, "georadius_ro k1 0 0 1 km"),
        (
            "georadiusbymember_ro",
            None,
            "georadiusbymember_ro k1 m 1 km",
        ),
        ("georadius", None, "georadius k1 0 0 1 km"),
        ("georadiusbymember", None, "georadiusbymember k1 m 1 km"),
        (
            "geosearchstore",
            None,
            "geosearchstore k1 k2 FROMMEMBER m BYRADIUS 1 km",
        ),
        ("geoadd", None, "geoadd k1 0 0 m"),
        ("object", Some("encoding"), "object encoding k1"),
        ("object", Some("freq"), "object freq k1"),
        ("object", Some("idletime"), "object idletime k1"),
        ("object", Some("refcount"), "object refcount k1"),
        ("memory", Some("usage"), "memory usage k1"),
        ("xinfo", Some("stream"), "xinfo stream k1"),
        ("xinfo", Some("groups"), "xinfo groups k1"),
        ("xinfo", Some("consumers"), "xinfo consumers k1 g"),
        ("xgroup", Some("*"), "xgroup create k1 g $"),
        ("xgroup", Some("*"), "xgroup destroy k1 g"),
        ("xgroup", Some("*"), "xgroup createconsumer k1 g c"),
        ("xgroup", Some("*"), "xgroup delconsumer k1 g c"),
        ("xgroup", Some("*"), "xgroup setid k1 g $"),
    ];
    // Every keyed row has an example.
    for (name, sub) in crate::audit::commands::keyed_rows() {
        assert!(
            EXAMPLES.iter().any(|(n, s, _)| *n == name && *s == sub),
            "no GETKEYS example for {name} {sub:?}"
        );
    }
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = target(name, engine, "databastion", "");
        let cmds: Vec<Vec<Vec<u8>>> = EXAMPLES
            .iter()
            .map(|(_, _, ex)| {
                let mut c: Vec<Vec<u8>> = vec![b"COMMAND".to_vec(), b"GETKEYS".to_vec()];
                c.extend(ex.split(' ').map(|a| a.as_bytes().to_vec()));
                c
            })
            .collect();
        let refs: Vec<Vec<&[u8]>> = cmds
            .iter()
            .map(|c| c.iter().map(Vec::as_slice).collect())
            .collect();
        let replies = admin(&t, &refs).await;
        let mut checked = 0;
        let mut differ = Vec::new();
        for ((_, _, ex), r) in EXAMPLES.iter().zip(&replies) {
            let Value::Array(keys) = r else {
                // A command this version does not have.
                continue;
            };
            let args: Vec<&[u8]> = ex.split(' ').map(str::as_bytes).collect();
            let mut server: Vec<usize> = keys
                .iter()
                .filter_map(Value::as_bytes)
                .filter_map(|k| args.iter().position(|a| *a == k))
                .collect();
            server.sort_unstable();
            server.dedup();
            let (spec, _) = crate::audit::commands::lookup(args[0], args.get(1).copied());
            let mut ours = crate::audit::commands::key_indices(spec.keys, &args, args.len())
                .unwrap_or_default();
            ours.sort_unstable();
            ours.dedup();
            if ours != server {
                differ.push(format!("{ex}: ours {ours:?}, server {server:?}"));
            }
            checked += 1;
        }
        assert!(checked > 150, "{name}: {checked} rows checked");
        assert!(differ.is_empty(), "{name}: {differ:#?}");
    }
}

/// Review H1: clients on the server's Unix socket all share one address,
/// so a socket entry is never attributed through `CLIENT LIST` nor taken
/// for the agent's: two socket clients (the dev `admin` and the agent's
/// own user, connected well before their commands) give events without a
/// recorded account and with the client address `local`. Needs
/// `DATABASTION_IT_REDIS_EXEC_VALKEY` (the dev socket is inside the
/// container).
#[tokio::test(flavor = "multi_thread")]
async fn socket_clients_are_never_attributed() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    let Ok(exec) = std::env::var("DATABASTION_IT_REDIS_EXEC_VALKEY") else {
        tracing::warn!("DATABASTION_IT_REDIS_EXEC_VALKEY unset: socket attribution not tested");
        return;
    };
    let t = target("valkey", TargetEngine::Valkey, "databastion", "");
    let connector = Arc::new(RedisConnector::new());
    // Learned patterns for the objects.
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let (fs, mut frx) = FindingSink::channel(4096);
    let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
    connector.discover(&job, &fs).await.unwrap();
    drop(fs);
    drain.await.unwrap();
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = databastion_core::AuditConfig::local(&t, 1, &limits);
    let (sink, mut rx) = databastion_core::EventSink::channel(8192);
    let c2 = Arc::clone(&connector);
    let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // The CLI reads its whole input, then runs it: the connection opens at
    // once and its commands run after the sleep. The `admin` client then
    // stays connected (`BLPOP` with a timeout) while the agent's user runs
    // its command from another socket connection.
    let socket_client = |user: &str, password: String, commands: &str| {
        let script = format!(
            "C=$(command -v valkey-cli || command -v redis-cli); \
             S=/tmp/databastion-dev.sock; \
             [ -z \"${{DATABASTION_DEV_REDIS_SOCKET_DIR:-}}\" ] || \
             S=\"$DATABASTION_DEV_REDIS_SOCKET_DIR/redis.sock\"; \
             read -r P; \
             (printf 'AUTH %s %s\\n' {user} \"$P\"; sleep 3; printf '{commands}') \
             | $C -s \"$S\" >/dev/null 2>&1"
        );
        let mut parts = exec.split_whitespace();
        let mut cmd = std::process::Command::new(parts.next().unwrap());
        cmd.args(parts)
            .args(["bash", "-c", &script])
            .stdin(std::process::Stdio::piped());
        // The password goes through the CLI's standard input only (read
        // by the shell's `read`, sent by its `printf` builtin), never on a
        // command line of the host or the container (security review L4).
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut child = cmd.spawn()?;
            let mut stdin = child.stdin.take().expect("piped stdin");
            stdin.write_all(password.as_bytes())?;
            stdin.write_all(b"\n")?;
            drop(stdin);
            child.wait().map(|s| s.success())
        })
    };
    let a = socket_client(
        "admin",
        admin_password(),
        "HGETALL session:sockettest\\nGETRANGE session:sockettest 0 4095\\nBLPOP session:none 6\\n",
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let b = socket_client(
        "databastion",
        t.secret.read().unwrap().to_string(),
        "GETRANGE session:sockettest 0 4095\\n",
    );
    assert!(b.await.unwrap().unwrap(), "socket client (agent's user)");
    assert!(a.await.unwrap().unwrap(), "socket client (admin)");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    stream.abort();
    let _ = stream.await;
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    let json = events_json(&events);
    let local: Vec<&serde_json::Value> = json
        .iter()
        .filter(|e| e["principal"]["client_addr"] == "local")
        .collect();
    // Both clients' reads (the agent's user from another connection is
    // never the agent's): at least the 3 `HGETALL` / `GETRANGE`.
    assert!(local.len() >= 3, "{json:#?}");
    for e in local {
        assert_eq!(e["principal"]["account_not_recorded"], true, "{e}");
        assert!(e["principal"].get("db_user").is_none(), "{e}");
        assert_eq!(e["source"], "redis_slowlog", "{e}");
    }
}

/// A Unix-socket target of the dev server (`dev/redis/compose.socket.yml`,
/// published to the host): `tls: disable` and the declared server uid
/// (ADR-0052 decision 3).
fn socket_target(engine: &str, path: &str, server_uid: u32, extra: &str) -> TargetConfig {
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{{id: it-socket, \
         engine: {engine}, socket: \"{path}\", account: databastion, \
         secret: {{env: DATABASTION_DB_PASSWORD}}, \
         redis: {{tls: disable, server_uid: {server_uid}{extra}}}}}]}}",
    );
    databastion_core::AgentConfig::parse(&yaml).unwrap().targets[0].clone()
}

/// The newest slow-log id (as `admin`, over TCP: its own entries are never
/// socket entries).
async fn newest_slowlog_id(tcp: &TargetConfig) -> i64 {
    let r = admin(tcp, &[vec![b"SLOWLOG", b"GET", b"1"]]).await;
    let Value::Array(items) = &r[0] else {
        panic!("SLOWLOG GET reply")
    };
    items
        .first()
        .and_then(|e| match e {
            Value::Array(f) => match f.first() {
                Some(Value::Int(id)) => Some(*id),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or(-1)
}

/// #239 re-review N1 (ADR-0052 decision 8): on a Unix-socket target the
/// agent's own entries cannot be told apart from other local clients',
/// since every socket peer has the same address. The documented residual,
/// and the fail-closed side of it, against the dev servers' published
/// sockets with the Audit stream on the socket:
/// - the agent's own Discovery reads over the socket, another local client
///   (`admin`, connected well before its commands) and a client with the
///   agent's own user from another socket connection all give events with
///   `account_not_recorded` and client `local`, never an account;
/// - nothing is hidden: every socket slow-log entry that gives an event
///   (an independent read of the slow log, as `admin` over TCP) is
///   reported, no own-read budget is charged (no entry was taken for the
///   agent's), and no record is dropped;
/// - I2: no ground-truth value nor raw key name in the events;
/// - decision 3: with a server uid that is not the peer's, the password is
///   never sent (`authentication_failed`, no `ACL LOG` entry).
///
/// Needs the sockets on the host (`DATABASTION_IT_REDIS_SOCKET_VALKEY` /
/// `_REDIS`, set by `dev/agent-it.sh redis` when the override is up);
/// skipped without them unless `DATABASTION_IT_REDIS_REQUIRE_SOCKET=1` (CI).
#[tokio::test(flavor = "multi_thread")]
async fn a_socket_target_reports_the_agents_own_reads_unattributed() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    let required = std::env::var("DATABASTION_IT_REDIS_REQUIRE_SOCKET").as_deref() == Ok("1");
    let server_uid: u32 = std::env::var("DATABASTION_IT_REDIS_SERVER_UID")
        .ok()
        .and_then(|u| u.parse().ok())
        .unwrap_or(999);
    for (name, engine, var) in [
        (
            "valkey",
            TargetEngine::Valkey,
            "DATABASTION_IT_REDIS_SOCKET_VALKEY",
        ),
        (
            "redis",
            TargetEngine::Redis,
            "DATABASTION_IT_REDIS_SOCKET_REDIS",
        ),
    ] {
        let Ok(path) = std::env::var(var) else {
            assert!(!required, "{var} unset: the socket target is not tested");
            tracing::warn!("{var} unset: the socket target is not tested");
            continue;
        };
        let tcp = tgt(name, engine, "databastion", "").await;
        let extra = if legacy(engine).await {
            ", unevaluated_acl: accept"
        } else {
            ""
        };
        let t = socket_target(name, &path, server_uid, extra);
        let connector = Arc::new(RedisConnector::new());

        // Decision 3: a peer that is not the declared server user never
        // gets the password. A failed `AUTH` would leave an `ACL LOG`
        // entry, but a regression that authenticated before comparing the
        // peer's uid would succeed and leave none (security review M1): the
        // server's `AUTH` and `HELLO` call counts must not move either.
        // Each count is read on a new `admin` connection over TCP, which
        // runs its own handshake: that cost is measured first (two reads in
        // a row) and is the only change allowed across the check.
        let failures = acl_log_count(&tcp, "databastion").await;
        let calls0 = handshake_calls(&tcp).await;
        let calls1 = handshake_calls(&tcp).await;
        let wrong = socket_target(name, &path, server_uid + 1, extra);
        let h = connector.check(&wrong).await;
        let calls2 = handshake_calls(&tcp).await;
        assert!(!h.reachable, "{name}: {h:?}");
        assert_eq!(
            h.failure,
            Some(FailureCode::AuthenticationFailed),
            "{name}: {h:?}"
        );
        let own = (calls1.0 - calls0.0, calls1.1 - calls0.1);
        assert_eq!(
            (calls2.0 - calls1.0 - own.0, calls2.1 - calls1.1 - own.1),
            (0, 0),
            "{name}: AUTH / HELLO calls during the wrong-uid check \
             ({calls0:?}, {calls1:?}, {calls2:?})"
        );
        assert_eq!(acl_log_count(&tcp, "databastion").await, failures, "{name}");
        let h = connector.check(&t).await;
        assert!(h.reachable, "{name}: {h:?}");
        assert_eq!(h.failure, None, "{name}: {:?}", codes(&h));

        // A slow log that holds the whole run, for the independent count
        // below (restored at the end).
        let old_len = match &admin(&tcp, &[vec![b"CONFIG", b"GET", b"slowlog-max-len"]]).await[0] {
            Value::Map(m) => m[0].1.as_bytes().unwrap().to_vec(),
            Value::Array(a) => a[1].as_bytes().unwrap().to_vec(),
            v => panic!("CONFIG GET reply: {v:?}"),
        };
        // Restored on a panic too (the guard's drop), not only at the end.
        let restore = RestoreSlowlogLen {
            tcp: tcp.clone(),
            len: old_len,
        };
        admin(
            &tcp,
            &[vec![b"CONFIG", b"SET", b"slowlog-max-len", b"16384"]],
        )
        .await;

        // The patterns the stream maps keys to, learned over the socket.
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (fs, mut frx) = FindingSink::channel(4096);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        connector.discover(&job, &fs).await.unwrap();
        drop(fs);
        drain.await.unwrap();

        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-socket-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let limits = Limits {
            min_audit_poll_interval_s: 1,
            ..Limits::default()
        };
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
        let (sink, mut rx) = databastion_core::EventSink::channel(65536);
        let c2 = Arc::clone(&connector);
        let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
        let _abort = AbortOnDrop(stream.abort_handle());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert!(!stream.is_finished(), "{name}: {:?}", stream.await);
        // Past the stream's first poll (its start position).
        let start = newest_slowlog_id(&tcp).await;

        // Another local client, connected well before its reads, and a
        // client with the agent's own user from another socket connection.
        let (ta, pw) = (t.clone(), admin_password());
        let other = tokio::spawn(async move {
            raw_held(
                &ta,
                "admin",
                &pw,
                std::time::Duration::from_secs(3),
                &[
                    vec![b"HGETALL", b"session:jdupont"],
                    vec![b"GET", b"customer:1000:email"],
                    vec![b"GETRANGE", b"customer:1000:email", b"0", b"4095"],
                ],
                std::time::Duration::from_secs(2),
            )
            .await
        });
        let (tb, pw) = (t.clone(), t.secret.read().unwrap().to_string());
        let own_user = tokio::spawn(async move {
            raw_held(
                &tb,
                "databastion",
                &pw,
                std::time::Duration::from_secs(2),
                &[vec![b"GETRANGE", b"customer:1000:email", b"0", b"4095"]],
                std::time::Duration::from_secs(2),
            )
            .await
        });
        // The agent's own Discovery over the socket while the stream polls
        // (paced, so it lasts several polls and no poll finds more new
        // entries than one log read returns: a ring read past is counted in
        // `audit.records_dropped`, asserted absent below).
        let paced = Limits {
            discovery_duty_cycle_percent: 5,
            ..Limits::default()
        };
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &paced, key());
        let (fs, mut frx) = FindingSink::channel(4096);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        connector.discover(&job, &fs).await.unwrap();
        drop(fs);
        drain.await.unwrap();
        assert_eq!(other.await.unwrap().len(), 3, "{name}");
        assert_eq!(own_user.await.unwrap().len(), 1, "{name}");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let end = newest_slowlog_id(&tcp).await;
        // Polls past `end`.
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let h = connector.check(&t).await;
        stream.abort();
        let _ = stream.await;
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        // The independent count: socket entries in (start, end] that give
        // an event, from the slow log as the server holds it.
        let log = admin(&tcp, &[vec![b"SLOWLOG", b"GET", b"16384"]]).await;
        drop(restore);
        let _ = std::fs::remove_dir_all(&dir);
        let Value::Array(entries) = &log[0] else {
            panic!("SLOWLOG GET reply")
        };
        let learned = databastion_classifiers::keys::LearnedPatterns::default();
        let ctx = crate::audit::entries::Context {
            learned: &learned,
            stores: None,
            dbs: &[],
        };
        let parsed: Vec<_> = entries
            .iter()
            .map(|v| crate::audit::entries::parse_log_entry(v, &ctx).unwrap())
            .filter(|e| e.id > start && e.id <= end)
            .collect();
        // The ring held the whole window (not vacuous).
        assert!(
            parsed.iter().any(|e| e.id == start + 1),
            "{name}: the slow log lost the window's first entries"
        );
        let socket_entries = parsed
            .iter()
            .filter(|e| {
                e.peer.is_some_and(|p| p.socket().is_none()) && e.action.event_action().is_some()
            })
            .count();

        let json = events_json(&events);
        let text = serde_json::to_string(&json).unwrap();
        // I2: no ground-truth value, no raw key name.
        for v in ground_truth_values(name) {
            assert!(
                !text.contains(&v),
                "{name}: a ground-truth value in an event"
            );
        }
        for raw in ["jdupont", "customer:1000"] {
            assert!(!text.contains(raw), "{name}: {raw} in an event");
        }
        // Every socket entry: no recorded account, client `local`.
        let local: Vec<&serde_json::Value> = json
            .iter()
            .filter(|e| e["principal"]["client_addr"] == "local")
            .collect();
        for e in &local {
            assert_eq!(e["principal"]["account_not_recorded"], true, "{name}: {e}");
            assert!(e["principal"].get("db_user").is_none(), "{name}: {e}");
            assert!(
                e["principal"].get("db_user_fingerprint").is_none(),
                "{name}: {e}"
            );
        }
        // Nothing hidden: at least every socket entry of the window (the
        // stream also reports the entries just outside it).
        let local_slow = local
            .iter()
            .filter(|e| e["source"] == "redis_slowlog")
            .count();
        assert!(
            local_slow >= socket_entries,
            "{name}: {local_slow} socket events for {socket_entries} socket entries in \
             ({start}, {end}]"
        );
        // The agent's own reads (its client name) are among them: the
        // documented residual (N1), not left out.
        let own = local
            .iter()
            .filter(|e| e["principal"]["application"] == crate::cmd::CLIENT_NAME)
            .count();
        assert!(own >= 20, "{name}: {own} own socket reads reported");
        // The other socket clients (no client name): `admin`'s 3 reads and
        // the agent's user from another connection.
        let unnamed = local
            .iter()
            .filter(|e| {
                e["principal"].get("application").is_none()
                    && e["action"] == "read"
                    && e["source"] == "redis_slowlog"
            })
            .count();
        assert!(unnamed >= 4, "{name}: {json:#?}");
        // No entry was taken for the agent's: no own-read budget charged.
        let budgets = connector
            .state
            .audit
            .own_usage(&t.id)
            .lock()
            .unwrap()
            .budgeted_objects();
        assert!(budgets.is_empty(), "{name}: {budgets:?}");
        // Nothing dropped, and Limited (every socket entry is another
        // client's to the stream).
        assert!(
            !codes(&h).contains(&NoteCode::AuditRecordsDropped),
            "{name}: {:?}",
            codes(&h)
        );
        assert_eq!(
            h.audit_level,
            databastion_core::AuditLevel::Limited,
            "{name}: {:?}",
            codes(&h)
        );
    }
}

/// The P9-D end-to-end finding: keys in two databases whose learned
/// patterns differ (the dev keyspace: `session:*` in `db1` only), a slow
/// log long enough to hold a whole scan, and a Discovery scan while the
/// stream polls. Slow-log entries carry no database, so their objects are
/// matched against the patterns learned in every database (`*` here);
/// the agent's own sampling reads must still be budgeted per pattern
/// (ADR-0052 decision 8) and left out, never reported as one read of `*`,
/// with `limits.max_sample_rows` 100 too (the scaled budget).
#[tokio::test(flavor = "multi_thread")]
async fn own_scan_reads_across_databases_stay_within_the_pattern_budgets() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    // `limits.max_sample_rows` 100 (the P9-D variant): one scan samples up
    // to 100 keys per pattern, within the scaled budget (`100 ×
    // PER_KEY_MAX` per pattern, ADR-0052 refinement of 2026-10-16).
    const MAX_ROWS: u32 = 100;
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        let len = admin(&t, &[vec![b"CONFIG", b"GET", b"slowlog-max-len"]]).await;
        let old_len = match &len[0] {
            Value::Map(kv) => kv
                .first()
                .and_then(|(_, v)| v.as_bytes().map(<[u8]>::to_vec)),
            Value::Array(a) => a.get(1).and_then(|v| v.as_bytes().map(<[u8]>::to_vec)),
            _ => None,
        }
        .expect("slowlog-max-len");
        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-own-budget-{}-{name}",
            std::process::id()
        ));
        admin(&t, &[vec![b"CONFIG", b"SET", b"slowlog-max-len", b"1024"]]).await;
        // The scans and the stream in a task of their own, so a failure
        // there still restores the slow log's length and removes the state
        // directory before it is raised (review L3).
        let (t2, dir2) = (t.clone(), dir.clone());
        let run = tokio::spawn(async move {
            let (t, dir) = (t2, dir2);
            let connector = Arc::new(RedisConnector::new());
            // The patterns the stream maps keys to, in both databases.
            let first = Limits {
                max_sample_rows: MAX_ROWS,
                ..unpaced()
            };
            let job = ScanJob::new(ScanParams::contract_defaults(), &t, &first, key());
            let (fs, mut frx) = FindingSink::channel(4096);
            let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
            connector.discover(&job, &fs).await.unwrap();
            drop(fs);
            drain.await.unwrap();

            std::fs::create_dir_all(&dir).unwrap();
            let limits = Limits {
                min_audit_poll_interval_s: 1,
                max_sample_rows: MAX_ROWS,
                ..Limits::default()
            };
            let cfg =
                databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
            let (sink, mut rx) = databastion_core::EventSink::channel(8192);
            let c2 = Arc::clone(&connector);
            let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
            // Stopped whatever happens below.
            let _stop = AbortOnDrop(stream.abort_handle());
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            assert!(!stream.is_finished(), "{name}: {:?}", stream.await);

            // The agent's own Discovery while the stream polls (paced, so
            // no poll finds more than the 512 entries it reads).
            let paced = Limits {
                discovery_duty_cycle_percent: 30,
                max_sample_rows: MAX_ROWS,
                ..Limits::default()
            };
            let job = ScanJob::new(ScanParams::contract_defaults(), &t, &paced, key());
            let (fs, mut frx) = FindingSink::channel(4096);
            let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
            connector.discover(&job, &fs).await.unwrap();
            drop(fs);
            drain.await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            stream.abort();
            let _ = stream.await;
            let mut events = Vec::new();
            while let Ok(e) = rx.try_recv() {
                events.push(e);
            }
            (connector, events)
        })
        .await;
        admin(
            &t,
            &[vec![
                b"CONFIG",
                b"SET",
                b"slowlog-max-len",
                old_len.as_slice(),
            ]],
        )
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        let (connector, events) = match run {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        };
        let json = events_json(&events);
        // Nobody else used the server: no event at all.
        assert!(json.is_empty(), "{name}: {json:#?}");
        // Not vacuous: the stream did charge the scan's reads, per
        // pattern and database (`session:*` is learned in `db1` only).
        let budgets = connector
            .state
            .audit
            .own_usage(&t.id)
            .lock()
            .unwrap()
            .budgeted_objects();
        assert!(
            budgets.iter().any(|k| k == "db1\u{0}\u{0}session:*"),
            "{name}: {budgets:?}"
        );
        assert!(
            budgets.iter().any(|k| k.starts_with("db0\u{0}")),
            "{name}: {budgets:?}"
        );
    }
}

/// #275 review L6: with merged `*:*` families (`phone:<n>` first, then
/// `addressbook:<n>`, so the late family is sampled only through the
/// round-robin), the scan's own reads under Audit are never reported.
#[tokio::test(flavor = "multi_thread")]
async fn own_reads_of_merged_families_are_not_reported() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    // Few sample keys per pattern, so the round-robin decides which keys
    // are read.
    const MAX_ROWS: u32 = 4;
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "databases: [7]").await;
        let mut seed: Vec<Vec<Vec<u8>>> = vec![vec![b"SELECT".to_vec(), b"7".to_vec()]];
        seed.push(vec![b"FLUSHDB".to_vec()]);
        for i in 1..=40 {
            seed.push(vec![
                b"SET".to_vec(),
                format!("phone:{i}").into_bytes(),
                b"v".to_vec(),
            ]);
        }
        for i in 1..=3 {
            seed.push(vec![
                b"SET".to_vec(),
                format!("addressbook:{i}").into_bytes(),
                b"v".to_vec(),
            ]);
        }
        let cmds: Vec<Vec<&[u8]>> = seed
            .iter()
            .map(|c| c.iter().map(Vec::as_slice).collect())
            .collect();
        admin(&t, &cmds).await;
        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-merged-{}-{name}",
            std::process::id()
        ));
        let (t2, dir2) = (t.clone(), dir.clone());
        let run = tokio::spawn(async move {
            let (t, dir) = (t2, dir2);
            let connector = Arc::new(RedisConnector::new());
            let limits = Limits {
                max_sample_rows: MAX_ROWS,
                ..unpaced()
            };
            // The patterns the stream maps keys to.
            let job = ScanJob::new(ScanParams::contract_defaults(), &t, &limits, key());
            let (fs, mut frx) = FindingSink::channel(4096);
            let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
            connector.discover(&job, &fs).await.unwrap();
            drop(fs);
            drain.await.unwrap();

            std::fs::create_dir_all(&dir).unwrap();
            let audit_limits = Limits {
                min_audit_poll_interval_s: 1,
                max_sample_rows: MAX_ROWS,
                ..Limits::default()
            };
            let cfg = databastion_core::AuditConfig::local(&t, 1, &audit_limits)
                .with_state_dir(dir.clone());
            let (sink, mut rx) = databastion_core::EventSink::channel(8192);
            let c2 = Arc::clone(&connector);
            let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
            let _stop = AbortOnDrop(stream.abort_handle());
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            assert!(!stream.is_finished(), "{:?}", stream.await);
            // The agent's own scan while the stream polls.
            let job = ScanJob::new(ScanParams::contract_defaults(), &t, &limits, key());
            let (fs, mut frx) = FindingSink::channel(4096);
            let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
            connector.discover(&job, &fs).await.unwrap();
            drop(fs);
            drain.await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            stream.abort();
            let _ = stream.await;
            let mut events = Vec::new();
            while let Ok(e) = rx.try_recv() {
                events.push(e);
            }
            (connector, events)
        })
        .await;
        admin(&t, &[vec![b"SELECT", b"7"], vec![b"FLUSHDB"]]).await;
        let _ = std::fs::remove_dir_all(&dir);
        let (connector, events) = match run {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        };
        let json = events_json(&events);
        assert!(json.is_empty(), "{name}: {json:#?}");
        // Not vacuous: the scan's reads were charged to the merged pattern.
        let budgets = connector
            .state
            .audit
            .own_usage(&t.id)
            .lock()
            .unwrap()
            .budgeted_objects();
        assert!(
            budgets.iter().any(|k| k == "db7\u{0}\u{0}*:*"),
            "{name}: {budgets:?}"
        );
    }
}

/// The server's `AUTH` and `HELLO` call counts (`INFO commandstats`, as
/// `admin` over TCP; 0 for a command never called), read on a connection
/// of their own, whose handshake they include.
async fn handshake_calls(tcp: &TargetConfig) -> (i64, i64) {
    let r = admin(tcp, &[vec![b"INFO", b"commandstats"]]).await;
    let text = r[0]
        .as_bytes()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .expect("INFO commandstats reply");
    let calls = |cmd: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("cmdstat_{cmd}:calls=")))
            .and_then(|rest| rest.split(',').next())
            .map_or(0, |n| n.trim().parse().expect("cmdstat calls"))
    };
    (calls("auth"), calls("hello"))
}

/// Restores the server's `slowlog-max-len` when dropped, a panic included
/// (security review, informational): a test that fails leaves the dev
/// server's slow log as it found it. Drop cannot await, so the restore
/// runs on a runtime of its own in another thread.
struct RestoreSlowlogLen {
    tcp: TargetConfig,
    len: Vec<u8>,
}

impl Drop for RestoreSlowlogLen {
    fn drop(&mut self) {
        let (tcp, len) = (self.tcp.clone(), std::mem::take(&mut self.len));
        let restored = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|rt| {
                    rt.block_on(admin(
                        &tcp,
                        &[vec![b"CONFIG", b"SET", b"slowlog-max-len", &len]],
                    ))
                })
                .is_ok()
        })
        .join();
        if !matches!(restored, Ok(true)) && !std::thread::panicking() {
            panic!("slowlog-max-len not restored");
        }
    }
}

/// Keys of the load run's shape (`load:s:<n>` strings, every tenth
/// `load:h:<n>` a hash; e2e/load/seed.py), written by `admin` into `db`
/// (the commands; `del` gives their deletion instead).
fn load_keys(db: &'static [u8], del: bool) -> Vec<Vec<Vec<u8>>> {
    let mut cmds: Vec<Vec<Vec<u8>>> = vec![vec![b"SELECT".to_vec(), db.to_vec()]];
    for n in 1..=LOAD_KEYS {
        let key = if n % 10 == 0 {
            format!("load:h:{n}")
        } else {
            format!("load:s:{n}")
        };
        cmds.push(match (del, n % 10 == 0) {
            (true, _) => vec![b"DEL".to_vec(), key.into_bytes()],
            (false, true) => vec![
                b"HSET".to_vec(),
                key.into_bytes(),
                b"status".to_vec(),
                b"active".to_vec(),
            ],
            (false, false) => vec![b"SET".to_vec(), key.into_bytes(), b"v".to_vec()],
        });
    }
    cmds
}

/// Keys of the load shape per database.
const LOAD_KEYS: u32 = 300;

async fn admin_owned(t: &TargetConfig, cmds: &[Vec<Vec<u8>>]) {
    let borrowed: Vec<Vec<&[u8]>> = cmds
        .iter()
        .map(|c| c.iter().map(Vec::as_slice).collect())
        .collect();
    admin(t, &borrowed).await;
}

/// The objects (object, database) of `admin`'s slow-log `GET`s.
fn admin_get_objects(json: &[serde_json::Value]) -> Vec<(String, String)> {
    json.iter()
        .filter(|e| {
            e["principal"]["db_user"] == "admin"
                && e["action"] == "read"
                && e["source"] == "redis_slowlog"
        })
        .flat_map(|e| e["objects"].as_array().cloned().unwrap_or_default())
        .map(|o| {
            (
                o["object"].as_str().unwrap_or_default().to_owned(),
                o["database"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// One Discovery scan, then an Audit stream during which `admin` reads
/// `load:s:7` (database 0) from a connection older than the read; the
/// learned patterns of `db0` and the events' JSON.
async fn scan_then_load_get(
    t: &TargetConfig,
    dir: &std::path::Path,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let connector = Arc::new(RedisConnector::new());
    let job = ScanJob::new(ScanParams::contract_defaults(), t, &unpaced(), key());
    let (fs, mut frx) = FindingSink::channel(4096);
    let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
    connector.discover(&job, &fs).await.unwrap();
    drop(fs);
    drain.await.unwrap();
    let db0: Vec<String> = connector
        .state
        .audit
        .learned(&t.id)
        .dbs
        .get(&0)
        .map(|s| s.patterns().to_vec())
        .unwrap_or_default();

    std::fs::create_dir_all(dir).unwrap();
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = databastion_core::AuditConfig::local(t, 1, &limits).with_state_dir(dir.to_path_buf());
    let (sink, mut rx) = databastion_core::EventSink::channel(8192);
    let c2 = Arc::clone(&connector);
    let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
    let _stop = AbortOnDrop(stream.abort_handle());
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(!stream.is_finished(), "{:?}", stream.await);
    let pw = admin_password();
    raw_held(
        t,
        "admin",
        &pw,
        std::time::Duration::from_secs(3),
        &[vec![b"GET", b"load:s:7"]],
        std::time::Duration::from_secs(4),
    )
    .await;
    stream.abort();
    let _ = stream.await;
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    let _ = std::fs::remove_dir_all(dir);
    (db0, events_json(&events))
}

/// ROADMAP phase 9 follow-up "why the Valkey load keys are not attributed
/// to learned patterns" (load run 39679876881): the load keys
/// (`load:s:<n>`, database 0) are learned in `db0` (`load:*:*` here), but a
/// slow-log entry carries no database, and with keys in `db0` and `db1`
/// (the dev and load keyspace) only patterns learned in **every**
/// database with keys apply (ADR-0052 decision 8): the `GET` is a read of
/// `*` in `*`. Once `db1` holds keys of the same shape too, the pattern is
/// learned in both and the same `GET` is a read of that pattern in `*`.
#[tokio::test(flavor = "multi_thread")]
async fn load_keys_are_attributed_only_when_learned_in_every_database() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-load-attr-{}-{name}",
            std::process::id()
        ));
        admin_owned(&t, &load_keys(b"0", false)).await;
        // The scans and streams in a task of their own, so the keys are
        // removed even when an assertion fails.
        let (t2, dir2) = (t.clone(), dir.clone());
        let run = tokio::spawn(async move {
            let (t, dir) = (t2, dir2);
            // Load keys in db0 only: learned there, not usable.
            let (db0, json) = scan_then_load_get(&t, &dir).await;
            // `load:*:*` on the dev keyspace (the `s` / `h` segment has
            // too few keys per value to stay literal next to the others).
            let learned =
                databastion_classifiers::keys::LearnedPatterns::new(db0.iter().map(String::as_str));
            let pattern = learned
                .pattern_of(b"load:s:7")
                .unwrap_or_else(|| panic!("{name}: load:s:7 matches none of {db0:?}"));
            assert!(pattern.as_str().starts_with("load:"), "{name}: {db0:?}");
            let only_db0 = admin_get_objects(&json);
            assert_eq!(
                only_db0,
                vec![("*".to_owned(), "*".to_owned())],
                "{name}: {json:#?}"
            );
            // Load keys in db1 too: `load:s:*` learned in both databases.
            admin_owned(&t, &load_keys(b"1", false)).await;
            let (_, json) = scan_then_load_get(&t, &dir).await;
            let both = admin_get_objects(&json);
            assert_eq!(
                both,
                vec![(pattern.as_str().to_owned(), "*".to_owned())],
                "{name}: {json:#?}"
            );
        })
        .await;
        admin_owned(&t, &load_keys(b"0", true)).await;
        admin_owned(&t, &load_keys(b"1", true)).await;
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(e) = run {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

/// Aborts a task when dropped (a test that fails leaves no stream polling).
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// ADR-0056 decision 2 item 5: a key with a fullwidth segment (`ｃｏｌｏｒ`,
/// U+FF43 …, which NFKC maps to `color`) is marked altered in Discovery
/// (the finding's `location.altered` names `object`) and in Audit (the
/// event object read through the fullwidth spelling, and through the plain
/// spelling mapped to the pattern learned from it, carry `object` in
/// `altered`); a plain key of another shape is never marked. The contract
/// JSON is the spooled form (before the send-time strip).
#[tokio::test(flavor = "multi_thread")]
async fn a_fullwidth_key_segment_is_marked_altered_in_discovery_and_audit() {
    if !enabled() {
        return;
    }
    let _serial = serial().await;
    const ALTERED: &str = "fwtest/\u{FF43}\u{FF4F}\u{FF4C}\u{FF4F}\u{FF52}|theme";
    const PLAIN_SPELLING: &[u8] = b"fwtest/color|theme";
    const PLAIN: &str = "fwplain.color|theme/main";
    // A hash whose field name holds a fullwidth `ｅ` and a U+200B
    // (security review M1): the finding's `field` is `email`, altered.
    const HASH: &str = "fwhash|profile/main.card";
    const HASH_FIELD: &str = "\u{FF45}ma\u{200B}il";
    const MARK: &str = "fwqzxk";
    for (name, engine) in [
        ("valkey", TargetEngine::Valkey),
        ("redis", TargetEngine::Redis),
    ] {
        let t = tgt(name, engine, "databastion", "").await;
        let value = format!("jane.{MARK}@example.com");
        // In both databases of the dev keyspace: a slow-log entry names no
        // database, so only patterns learned in every database with keys
        // apply (ADR-0052 decision 8).
        let mut set: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut del: Vec<Vec<Vec<u8>>> = Vec::new();
        for db in [b"0", b"1"] {
            set.push(vec![b"SELECT".to_vec(), db.to_vec()]);
            del.push(vec![b"SELECT".to_vec(), db.to_vec()]);
            for k in [ALTERED, PLAIN] {
                set.push(vec![
                    b"SET".to_vec(),
                    k.as_bytes().to_vec(),
                    value.clone().into_bytes(),
                ]);
                del.push(vec![b"DEL".to_vec(), k.as_bytes().to_vec()]);
            }
            set.push(vec![
                b"HSET".to_vec(),
                HASH.as_bytes().to_vec(),
                HASH_FIELD.as_bytes().to_vec(),
                value.clone().into_bytes(),
                b"city".to_vec(),
                b"Lyon".to_vec(),
            ]);
            del.push(vec![b"DEL".to_vec(), HASH.as_bytes().to_vec()]);
        }
        admin_owned(&t, &set).await;
        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-altered-{}-{name}",
            std::process::id()
        ));
        let (t2, dir2) = (t.clone(), dir.clone());
        let run = tokio::spawn(async move {
            let (t, dir) = (t2, dir2);
            let connector = Arc::new(RedisConnector::new());
            let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
            let (fs, mut frx) = FindingSink::channel(4096);
            let collect = tokio::spawn(async move {
                let mut out = Vec::new();
                while let Some(f) = frx.recv().await {
                    out.push(f);
                }
                out
            });
            connector.discover(&job, &fs).await.unwrap();
            drop(fs);
            let findings = collect.await.unwrap();
            let json = findings_json(&findings, engine);
            let at = |object: &str| -> Vec<serde_json::Value> {
                json.iter()
                    .filter(|f| f["location"]["object"] == object)
                    .cloned()
                    .collect()
            };
            let altered = at("fwtest/color|theme");
            assert!(!altered.is_empty(), "{name}: {json:#?}");
            for f in &altered {
                assert_eq!(
                    f["location"]["altered"],
                    serde_json::json!(["object"]),
                    "{name}: {f:#}"
                );
            }
            // The hash field: `email`, altered, on every finding there.
            let email: Vec<serde_json::Value> = at(HASH)
                .into_iter()
                .filter(|f| f["location"]["field"] == "email")
                .collect();
            assert!(!email.is_empty(), "{name}: {json:#?}");
            for f in &email {
                assert_eq!(
                    f["location"]["altered"],
                    serde_json::json!(["field"]),
                    "{name}: {f:#}"
                );
            }
            let plain = at(PLAIN);
            assert!(!plain.is_empty(), "{name}: {json:#?}");
            for f in &plain {
                assert!(f["location"].get("altered").is_none(), "{name}: {f:#}");
            }
            // The learned pattern keeps its marker for Audit.
            let learned = connector.state.audit.learned(&t.id);
            let db0: Vec<(String, bool)> = learned.dbs[&0]
                .marked()
                .map(|(p, a)| (p.to_owned(), a))
                .collect();
            assert!(
                db0.contains(&("fwtest/color|theme".to_owned(), true)),
                "{name}: {db0:?}"
            );
            assert!(db0.contains(&(PLAIN.to_owned(), false)), "{name}: {db0:?}");

            std::fs::create_dir_all(&dir).unwrap();
            let limits = Limits {
                min_audit_poll_interval_s: 1,
                ..Limits::default()
            };
            let cfg = databastion_core::AuditConfig::local(&t, 1, &limits)
                .with_state_dir(dir.to_path_buf());
            let (sink, mut rx) = databastion_core::EventSink::channel(8192);
            let c2 = Arc::clone(&connector);
            let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
            let _stop = AbortOnDrop(stream.abort_handle());
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            assert!(!stream.is_finished(), "{:?}", stream.await);
            let pw = admin_password();
            raw_held(
                &t,
                "admin",
                &pw,
                std::time::Duration::from_secs(3),
                &[
                    vec![b"GET", ALTERED.as_bytes()],
                    vec![b"GET", PLAIN_SPELLING],
                    vec![b"GET", PLAIN.as_bytes()],
                ],
                std::time::Duration::from_secs(4),
            )
            .await;
            stream.abort();
            let _ = stream.await;
            let mut events = Vec::new();
            while let Ok(e) = rx.try_recv() {
                events.push(e);
            }
            let json = events_json(&events);
            let reads: Vec<(String, Option<serde_json::Value>)> = json
                .iter()
                .filter(|e| {
                    e["principal"]["db_user"] == "admin"
                        && e["action"] == "read"
                        && e["source"] == "redis_slowlog"
                })
                .flat_map(|e| e["objects"].as_array().cloned().unwrap_or_default())
                .map(|o| {
                    (
                        o["object"].as_str().unwrap_or_default().to_owned(),
                        o.get("altered").cloned(),
                    )
                })
                .collect();
            let object = Some(serde_json::json!(["object"]));
            // The two `fwtest` reads (fullwidth and plain spelling) are one
            // object, aggregated or not; the plain key apart, unmarked.
            assert!(
                reads.contains(&("fwtest/color|theme".to_owned(), object.clone())),
                "{name}: {json:#?}"
            );
            assert!(
                !reads.contains(&("fwtest/color|theme".to_owned(), None)),
                "{name}: {json:#?}"
            );
            assert!(
                reads.contains(&(PLAIN.to_owned(), None)),
                "{name}: {json:#?}"
            );
            // No raw spelling and no value reaches the contract JSON (I2).
            for text in [format!("{json:?}"), format!("{findings:?}")] {
                assert!(!text.contains('\u{FF43}') && !text.contains(MARK), "{name}");
            }
        })
        .await;
        admin_owned(&t, &del).await;
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(e) = run {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}
