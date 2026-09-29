//! Integration tests against the dev `mongo` service (`make dev`: MongoDB
//! 8.0 Community, seeded `app` database, profiler level 1 with
//! `slowms` 0, the ADR-0026 account of `dev/mongo/initdb/10-seed.js`).
//!
//! - `DATABASTION_TEST_MONGO_URL`: the agent account
//!   (`mongodb://databastion:…@127.0.0.1:27017/app?authSource=admin`).
//!   Without it, every test here is skipped, with a message on stderr.
//! - `DATABASTION_TEST_MONGO_ADMIN_URL`: an administrator
//!   (`mongodb://root:…@127.0.0.1:27017/?authSource=admin`), for the probe
//!   fixtures (database `databastion_probe`, dropped and recreated; roles
//!   and accounts `databastion_it_*`). Without it, those tests are skipped.
//!
//! The dev server has no TLS: the tests connect with `tls: disable` on the
//! loopback address (the TLS and SCRAM exchanges are covered by the
//! scripted server of `fake.rs`).
//!
//! `DATABASTION_TEST_REQUIRE` (comma-separated: `mongo`, `mongo-admin`, or
//! `all`) turns the matching skips into failures: CI lists what each run
//! must exercise.
//!
//! The tests are serialized.

// Skip notices and the recall table (counts only, never a value).
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{
    AuditLevel, Connector, ConnectorError, FailureCode, FindingSink, NoteCode, ScanJob, ScanParams,
    TargetNote,
};

use crate::MongodbConnector;
use crate::bson::{Doc, DocBuf, Value};
use crate::conn::{Kind, Session, Timeouts};
use crate::error::Stage;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PROBE_DB: &str = "databastion_probe";
const MIN_USER: &str = "databastion_it_min";
const OVER_USER: &str = "databastion_it_over";
const SHA1_USER: &str = "databastion_it_sha1";
const MIN_ROLE: &str = "databastion_it_discovery";
const IT_PASSWORD: &str = "dev-only-it-account-FAKE";
/// Documents of the large probe collection: above 20 x 200 (the contract
/// default `sample_rows`), so it is read with `$sample`.
const PEOPLE: usize = 5000;

#[derive(Debug, Clone)]
struct Url {
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
    auth_source: String,
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `mongodb://user:password@host:port/db?authSource=x`.
fn parse_url(raw: &str) -> Option<Url> {
    let rest = raw.strip_prefix("mongodb://")?;
    let (auth, rest) = rest.rsplit_once('@')?;
    let (user, password) = auth.split_once(':')?;
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (hostport, db) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = hostport.rsplit_once(':').unwrap_or((hostport, "27017"));
    let auth_source = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("authSource="))
        .unwrap_or("admin");
    Some(Url {
        host: host.to_owned(),
        port: port.parse().ok()?,
        user: percent_decode(user)?,
        password: percent_decode(password)?,
        dbname: db.to_owned(),
        auth_source: auth_source.to_owned(),
    })
}

/// Reports a skipped check (a failure when listed in
/// `DATABASTION_TEST_REQUIRE`).
fn skip(prerequisite: &str, message: &str) {
    let required = std::env::var("DATABASTION_TEST_REQUIRE").unwrap_or_default();
    assert!(
        !required
            .split(',')
            .any(|r| r.trim() == prerequisite || r.trim() == "all"),
        "required test prerequisite `{prerequisite}` missing: {message}"
    );
    eprintln!("skipped: {message}");
}

fn server() -> Option<Url> {
    match std::env::var("DATABASTION_TEST_MONGO_URL") {
        Ok(u) => Some(parse_url(&u).expect("DATABASTION_TEST_MONGO_URL")),
        Err(_) => {
            skip("mongo", "DATABASTION_TEST_MONGO_URL is not set");
            None
        }
    }
}

fn admin() -> Option<Url> {
    match std::env::var("DATABASTION_TEST_MONGO_ADMIN_URL") {
        Ok(u) => Some(parse_url(&u).expect("DATABASTION_TEST_MONGO_ADMIN_URL")),
        Err(_) => {
            skip("mongo-admin", "DATABASTION_TEST_MONGO_ADMIN_URL is not set");
            None
        }
    }
}

/// A private temporary directory holding the target secret file.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "databastion-mongo-it-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A declared target for `url`'s server with `user` (password in a `0600`
/// file).
fn target(url: &Url, user: &str, password: &str, auth_source: &str) -> (TempDir, TargetConfig) {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TempDir::new();
    let file = dir.0.join("secret");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .unwrap();
    f.write_all(password.as_bytes()).unwrap();
    let yaml = format!(
        "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: mongo-it\n    \
         engine: mongodb\n    host: \"{}\"\n    port: {}\n    account: \"{user}\"\n    \
         secret: {{file: \"{}\"}}\n    mongodb: {{tls: disable, auth_source: {auth_source}}}\n",
        url.host,
        url.port,
        file.display()
    );
    let config = databastion_core::AgentConfig::parse(&yaml).unwrap();
    (dir, config.targets[0].clone())
}

fn agent_target(url: &Url) -> (TempDir, TargetConfig) {
    target(url, &url.user, &url.password, &url.auth_source)
}

async fn admin_session(a: &Url) -> Session {
    let (_dir, t) = target(a, &a.user, &a.password, &a.auth_source);
    Session::connect(&t, Timeouts::new(Duration::from_secs(120)))
        .await
        .unwrap()
}

/// Runs an administration command; `Err` carries the server code.
async fn run(s: &mut Session, db: &str, command: DocBuf) -> Result<Vec<u8>, Option<i32>> {
    s.command(Stage::Check, db, command, Kind::Setup)
        .await
        .map(|r| r.doc_bytes())
        .map_err(|e| e.server_code)
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[7u8; 32]).unwrap())
}

async fn scan(t: &TargetConfig) -> (Result<(), ConnectorError>, Vec<MaskedFinding>) {
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        t,
        &Limits::default(),
        key(),
    );
    let (sink, mut rx) = FindingSink::channel(100_000);
    let r = MongodbConnector::new().discover(&job, &sink).await;
    drop(sink);
    let mut out = Vec::new();
    while let Some(f) = rx.recv().await {
        out.push(f);
    }
    (r, out)
}

type Key = (String, String, String, String);

fn located(findings: &[MaskedFinding]) -> BTreeSet<Key> {
    findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            assert!(l.schema.is_none(), "MongoDB locations have no schema");
            (
                l.database.as_str().to_owned(),
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str().to_owned(),
            )
        })
        .collect()
}

/// Captures every log line of the current thread.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let logs = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || logs.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn codes(notes: &[TargetNote]) -> Vec<&'static str> {
    notes.iter().map(|n| n.code().as_str()).collect()
}

#[tokio::test]
async fn check_reports_reachable_with_audit_none_and_minimal_grants() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let (_dir, t) = agent_target(&url);
    let connector = MongodbConnector::new();
    let h = connector.check(&t).await;
    assert!(h.reachable, "{h:?}");
    assert_eq!(h.audit_level, AuditLevel::None);
    assert_eq!(h.failure, None);
    let got = codes(&h.notes);
    assert!(
        got.contains(&NoteCode::AuditStreamNotAvailable.as_str()),
        "{got:?}"
    );
    // The dev account holds the ADR-0026 grant only.
    assert!(
        got.iter().all(|c| !c.starts_with("privilege.")),
        "{got:?} ({:?})",
        h.detail
    );
    assert!(!connector.supports_audit());
    // A wrong password.
    let (_dir, t) = target(&url, &url.user, "wrong-password", &url.auth_source);
    let h = connector.check(&t).await;
    assert!(!h.reachable);
    assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
}

#[tokio::test]
async fn seed_recall_regression() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev/ground-truth.json");
    let gt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let expected: Vec<&serde_json::Value> = gt["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "mongodb" && l["database"] == url.dbname.as_str())
        .collect();
    assert!(!expected.is_empty(), "no ground truth for {}", url.dbname);
    let (_dir, t) = agent_target(&url);
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        scan(&t).await
    };
    r.unwrap();
    let found = located(&findings);
    let mut per: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut false_positives = 0;
    for l in &expected {
        let o = l["object"].as_str().unwrap().to_owned();
        let f = l["expected_normalized_name"]
            .as_str()
            .or_else(|| l["field"].as_str())
            .unwrap()
            .to_owned();
        for c in l["expected_classifiers"].as_array().unwrap() {
            let c = c.as_str().unwrap().to_owned();
            let e = per.entry(c.clone()).or_default();
            e.1 += 1;
            if found.contains(&(url.dbname.clone(), o.clone(), f.clone(), c)) {
                e.0 += 1;
            }
        }
        if l["negative_control"] == true {
            false_positives += found.iter().filter(|k| k.1 == o && k.2 == f).count();
        }
    }
    let (mut tp, mut total) = (0, 0);
    for (c, (hit, n)) in &per {
        eprintln!("mongodb recall {c:<24} {hit}/{n}");
        tp += hit;
        total += n;
    }
    eprintln!(
        "mongodb findings {}, negative-control hits {false_positives}",
        found.len()
    );
    assert_eq!(tp, total, "missed ground-truth locations: {per:?}");
    assert_eq!(false_positives, 0);
    // Value-bearing keys never reach a location nor the logs.
    let text = logs.text();
    for l in &expected {
        for v in l["name_values"].as_array().into_iter().flatten() {
            let v = v.as_str().unwrap();
            assert!(!text.contains(v), "a value-bearing key reached the logs");
            for k in &found {
                assert!(!k.2.contains(v), "{k:?}");
            }
        }
    }
    assert!(
        !text.contains("@example."),
        "a sampled value reached the logs"
    );
}

/// Recreates the probe database and the test accounts.
async fn probe_fixtures(a: &Url) {
    let mut s = admin_session(a).await;
    let _ = run(&mut s, PROBE_DB, DocBuf::new().i32("dropDatabase", 1)).await;
    for user in [MIN_USER, OVER_USER, SHA1_USER] {
        let _ = run(&mut s, "admin", DocBuf::new().str("dropUser", user)).await;
    }
    let _ = run(&mut s, "admin", DocBuf::new().str("dropRole", MIN_ROLE)).await;
    // A large collection (read with `$sample`), a small one with values
    // in nested arrays, a view, a time-series collection, a deep document.
    // Insert in batches of 1000.
    let mut batch = Vec::new();
    for i in 0..PEOPLE {
        batch.push(
            DocBuf::new()
                .str("email", &format!("person{i}@example.com"))
                .i32("n", i32::try_from(i).unwrap()),
        );
        if batch.len() == 1000 || i + 1 == PEOPLE {
            let documents = std::mem::take(&mut batch);
            run(
                &mut s,
                PROBE_DB,
                DocBuf::new()
                    .str("insert", "people")
                    .array("documents", documents),
            )
            .await
            .unwrap();
        }
    }
    let nested: Vec<DocBuf> = (0..20)
        .map(|i| {
            DocBuf::new().doc(
                "profile",
                DocBuf::new().array(
                    "contacts",
                    vec![DocBuf::new().str("mail", &format!("nested{i}@example.org"))],
                ),
            )
        })
        .collect();
    run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("insert", "nested")
            .array("documents", nested),
    )
    .await
    .unwrap();
    run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("create", "people_view")
            .str("viewOn", "people")
            .array("pipeline", Vec::new()),
    )
    .await
    .unwrap();
    run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("create", "metrics")
            .doc("timeseries", DocBuf::new().str("timeField", "ts")),
    )
    .await
    .unwrap();
    let metrics: Vec<DocBuf> = (0..10)
        .map(|i| {
            DocBuf::new()
                .raw(0x09, "ts", &(1_700_000_000_000i64 + i).to_le_bytes())
                .str("owner", &format!("metric{i}@example.net"))
        })
        .collect();
    run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("insert", "metrics")
            .array("documents", metrics),
    )
    .await
    .unwrap();
    let mut deep = DocBuf::new().str("mail", "deep@example.com");
    for _ in 0..40 {
        deep = DocBuf::new().doc("n", deep);
    }
    run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("insert", "deep")
            .array("documents", vec![deep]),
    )
    .await
    .unwrap();
    // The ADR-0026 role on the probe database, an over-privileged account
    // (the previous recommendation plus writes), a SCRAM-SHA-1-only one.
    run(
        &mut s,
        "admin",
        DocBuf::new()
            .str("createRole", MIN_ROLE)
            .array(
                "privileges",
                vec![
                    DocBuf::new()
                        .doc(
                            "resource",
                            DocBuf::new().str("db", PROBE_DB).str("collection", ""),
                        )
                        .array_str("actions", &["find", "listCollections"]),
                ],
            )
            .array("roles", Vec::new()),
    )
    .await
    .unwrap();
    for (user, roles, mechanism) in [
        (
            MIN_USER,
            vec![DocBuf::new().str("role", MIN_ROLE).str("db", "admin")],
            "SCRAM-SHA-256",
        ),
        (
            OVER_USER,
            vec![
                DocBuf::new().str("role", "readWrite").str("db", PROBE_DB),
                DocBuf::new()
                    .str("role", "clusterMonitor")
                    .str("db", "admin"),
            ],
            "SCRAM-SHA-256",
        ),
        (
            SHA1_USER,
            vec![DocBuf::new().str("role", MIN_ROLE).str("db", "admin")],
            "SCRAM-SHA-1",
        ),
    ] {
        run(
            &mut s,
            "admin",
            DocBuf::new()
                .str("createUser", user)
                .str("pwd", IT_PASSWORD)
                .array("roles", roles)
                .array_str("mechanisms", &[mechanism]),
        )
        .await
        .unwrap();
    }
    s.close().await;
}

/// The probe account's operations on the probe database, from its
/// profiler (`--profile 1 --slowms 0` in dev: every operation is
/// recorded).
async fn profiled(a: &Url) -> Vec<Vec<u8>> {
    let mut s = admin_session(a).await;
    let reply = run(
        &mut s,
        PROBE_DB,
        DocBuf::new()
            .str("find", "system.profile")
            // The agent account's operations (the fixture session has the
            // same application name).
            .doc(
                "filter",
                DocBuf::new().str("user", &format!("{MIN_USER}@admin")),
            )
            .i32("limit", 10_000)
            .i32("batchSize", 10_000)
            .bool("singleBatch", true),
    )
    .await
    .unwrap();
    s.close().await;
    let doc = Doc::new(&reply).unwrap();
    let batch = doc
        .doc("cursor")
        .unwrap()
        .unwrap()
        .array("firstBatch")
        .unwrap()
        .unwrap();
    batch
        .iter()
        .filter_map(|e| match e.unwrap().1 {
            Value::Doc(d) => Some(d.as_bytes().to_vec()),
            _ => None,
        })
        .collect()
}

/// Idle cursors on the probe database (only the agent reads it with
/// cursors; the fixture reads are single batches).
async fn open_agent_cursors(a: &Url) -> usize {
    let mut s = admin_session(a).await;
    let reply = run(
        &mut s,
        "admin",
        DocBuf::new()
            .i32("aggregate", 1)
            .array(
                "pipeline",
                vec![
                    DocBuf::new().doc(
                        "$currentOp",
                        DocBuf::new()
                            .bool("idleCursors", true)
                            .bool("allUsers", true),
                    ),
                    DocBuf::new().doc(
                        "$match",
                        DocBuf::new().str("type", "idleCursor").doc(
                            "ns",
                            DocBuf::new().str("$regex", &format!("^{PROBE_DB}\\.")),
                        ),
                    ),
                ],
            )
            .doc("cursor", DocBuf::new()),
    )
    .await
    .unwrap();
    s.close().await;
    let doc = Doc::new(&reply).unwrap();
    doc.doc("cursor")
        .unwrap()
        .unwrap()
        .array("firstBatch")
        .unwrap()
        .unwrap()
        .iter()
        .count()
}

#[tokio::test]
async fn probes() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let Some(a) = admin() else { return };
    probe_fixtures(&a).await;

    // Scan with the ADR-0026 role.
    let (_dir, t) = target(&url, MIN_USER, IT_PASSWORD, "admin");
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        scan(&t).await
    };
    r.unwrap();
    let found = located(&findings);
    let has = |o: &str, f: &str| {
        found
            .iter()
            .any(|k| k.0 == PROBE_DB && k.1 == o && k.2 == f && k.3 == "pii.email")
    };
    assert!(has("people", "email"), "{found:?}");
    assert!(has("nested", "profile.contacts[].mail"), "{found:?}");
    assert!(has("metrics", "owner"), "{found:?}");
    // The deep value is beyond the walk bound; the view is never read.
    assert!(!found.iter().any(|k| k.1 == "deep"), "{found:?}");
    assert!(!found.iter().any(|k| k.1 == "people_view"), "{found:?}");
    let people = findings
        .iter()
        .find(|f| f.location().unwrap().object.as_str() == "people")
        .unwrap();
    assert_eq!(people.estimated_rows(), Some(PEOPLE as u64));
    assert!(people.sampled() <= 200);
    let text = logs.text();
    assert!(text.contains("view (runs its pipeline)"), "{text}");
    assert!(
        !text.contains("@example."),
        "a sampled value reached the logs"
    );

    // No cursor left open.
    assert_eq!(open_agent_cursors(&a).await, 0);

    // Every agent read of the probe database carries maxTimeMS; `$sample`
    // on the large collection, `find` elsewhere; no write, no getMore.
    let ops = profiled(&a).await;
    assert!(!ops.is_empty(), "the profiler recorded nothing");
    let mut sampled_people = false;
    for bytes in &ops {
        let op = Doc::new(bytes).unwrap();
        let kind = op.str("op").unwrap().unwrap_or_default();
        // Reads only: no insert, update, remove nor getmore.
        assert!(
            ["query", "command", "killcursors"].contains(&kind),
            "agent operation of kind {kind}"
        );
        let Some(command) = op.doc("command").unwrap() else {
            continue;
        };
        let first = command
            .iter()
            .next()
            .map(|e| String::from_utf8(e.unwrap().0.to_vec()).unwrap())
            .unwrap_or_default();
        if ["find", "aggregate", "count", "listCollections"].contains(&first.as_str()) {
            assert!(
                command.int("maxTimeMS").unwrap().is_some_and(|t| t > 0),
                "{first} without maxTimeMS"
            );
        }
        if first == "aggregate" && command.str("aggregate").unwrap() == Some("people") {
            sampled_people = true;
            assert_eq!(command.flag("allowDiskUse").unwrap(), Some(false));
        }
        assert_ne!(first, "getMore");
    }
    assert!(
        sampled_people,
        "the large collection was not read with $sample"
    );

    // Over-privilege is reported.
    let (_dir, t) = target(&url, OVER_USER, IT_PASSWORD, "admin");
    let h = MongodbConnector::new().check(&t).await;
    assert!(h.reachable, "{h:?}");
    let got = codes(&h.notes);
    for code in [
        NoteCode::PrivilegeWriteActions,
        NoteCode::PrivilegeReadBeyondDiscovery,
        NoteCode::PrivilegeClusterActions,
        NoteCode::PrivilegeSystemCollections,
        NoteCode::CoverageViewsNotSampled,
    ] {
        assert!(
            got.contains(&code.as_str()),
            "{} missing: {got:?}",
            code.as_str()
        );
    }
    // The minimal role is not.
    let (_dir, t) = target(&url, MIN_USER, IT_PASSWORD, "admin");
    let h = MongodbConnector::new().check(&t).await;
    assert!(
        codes(&h.notes).iter().all(|c| !c.starts_with("privilege.")),
        "{:?}",
        h.notes
    );

    // An account without SCRAM-SHA-256 credentials cannot be used.
    let (_dir, t) = target(&url, SHA1_USER, IT_PASSWORD, "admin");
    let h = MongodbConnector::new().check(&t).await;
    assert!(!h.reachable);
    assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
}

#[test]
fn urls_are_parsed() {
    let u = parse_url("mongodb://databastion:p%40ss@127.0.0.1:27018/app?authSource=admin").unwrap();
    assert_eq!(
        (
            u.host.as_str(),
            u.port,
            u.user.as_str(),
            u.password.as_str()
        ),
        ("127.0.0.1", 27018, "databastion", "p@ss")
    );
    assert_eq!(
        (u.dbname.as_str(), u.auth_source.as_str()),
        ("app", "admin")
    );
    let u = parse_url("mongodb://root:pw@localhost/").unwrap();
    assert_eq!((u.port, u.auth_source.as_str()), (27017, "admin"));
}
