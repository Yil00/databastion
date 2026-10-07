//! Protocol tests against a scripted server over an in-memory stream (no
//! listening socket, I1): the handshake and SCRAM-SHA-256 (hostile server
//! answers no dev server produces on demand), the commands the connector
//! sends, cursor handling and a whole scan with its findings.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{ConnectorError, FailureCode, FindingSink, ScanJob, ScanParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::bson::{Doc, DocBuf, Value};
use crate::catalog::{CollKind, Collection};
use crate::conn::{Session, Timeouts};
use crate::discover::{self, Method};
use crate::error::{MgError, Stage};
use crate::scram::server::Server as ScramServer;
use crate::wire::{self, Wire};

const USER: &str = "databastion";
const PASSWORD: &str = "dev-only-fake-PASSWORD";

/// A collection of the scripted server.
#[derive(Clone)]
pub(crate) struct FakeColl {
    pub(crate) name: String,
    pub(crate) kind: &'static str,
    pub(crate) docs: Vec<Vec<u8>>,
    /// `count` answer (default: the number of documents).
    pub(crate) count: Option<i64>,
    /// `count`, `find` and `aggregate` answer `Unauthorized`.
    pub(crate) unauthorized: bool,
}

impl FakeColl {
    pub(crate) fn new(name: &str, docs: Vec<Vec<u8>>) -> Self {
        Self {
            name: name.to_owned(),
            kind: "collection",
            docs,
            count: None,
            unauthorized: false,
        }
    }
}

/// What the scripted server does.
#[derive(Clone)]
pub(crate) struct Script {
    pub(crate) wire_version: i32,
    pub(crate) iterations: u32,
    /// The server signature is wrong.
    pub(crate) bad_signature: bool,
    /// `saslStart` answers `done: true`.
    pub(crate) done_early: bool,
    /// `saslContinue` answers `done: false` (no `skipEmptyExchange`).
    pub(crate) empty_exchange: bool,
    /// The password the server knows.
    pub(crate) password: String,
    pub(crate) databases: Vec<(String, Vec<FakeColl>)>,
    /// Cursor id of `find` / `aggregate` / `listCollections` replies.
    pub(crate) cursor_id: i64,
    /// Privileges returned by `connectionStatus`.
    pub(crate) privileges: Vec<Vec<u8>>,
    /// The header of every `find` / `aggregate` reply claims more than the
    /// limit.
    pub(crate) oversized_find: bool,
    /// Commands answered `Unauthorized`.
    pub(crate) failing: Vec<&'static str>,
    /// `find` / `aggregate` replies carry a malformed element in their
    /// batch (with the scripted cursor id).
    pub(crate) malformed_batch: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            wire_version: 25,
            iterations: 4096,
            bad_signature: false,
            done_early: false,
            empty_exchange: false,
            password: PASSWORD.to_owned(),
            databases: Vec::new(),
            cursor_id: 0,
            privileges: vec![
                DocBuf::new()
                    .doc(
                        "resource",
                        DocBuf::new().str("db", "app").str("collection", ""),
                    )
                    .array_str("actions", &["find", "listCollections"])
                    .finish(),
            ],
            oversized_find: false,
            failing: Vec::new(),
            malformed_batch: false,
        }
    }
}

/// A command the server received.
#[derive(Debug, Clone)]
pub(crate) struct Received {
    pub(crate) name: String,
    pub(crate) db: String,
    pub(crate) collection: Option<String>,
    pub(crate) max_time_ms: Option<i64>,
    pub(crate) read_preference: Option<String>,
    pub(crate) keys: Vec<String>,
    /// `$sample` size for an aggregate, `limit` for a find.
    pub(crate) size: Option<i64>,
}

pub(crate) type Log = Arc<Mutex<Vec<Received>>>;

fn array_of(docs: &[Vec<u8>]) -> Vec<u8> {
    let mut a = DocBuf::new();
    for (i, d) in docs.iter().enumerate() {
        a = a.raw(0x03, &i.to_string(), d);
    }
    a.finish()
}

fn cursor_reply(db: &str, coll: &str, docs: &[Vec<u8>], id: i64) -> Vec<u8> {
    DocBuf::new()
        .doc(
            "cursor",
            DocBuf::new()
                .i64("id", id)
                .str("ns", &format!("{db}.{coll}"))
                .raw(0x04, "firstBatch", &array_of(docs)),
        )
        .i32("ok", 1)
        .finish()
}

fn error_reply(code: i32) -> Vec<u8> {
    DocBuf::new()
        .i32("ok", 0)
        .str("errmsg", "hostile text jane.doe@example.com")
        .i32("code", code)
        .str("codeName", "Whatever")
        .finish()
}

fn frame(response_to: i32, body: &[u8]) -> Vec<u8> {
    let mut payload = 0u32.to_le_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(body);
    let mut out = Vec::new();
    out.extend_from_slice(&i32::try_from(16 + payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&7i32.to_le_bytes());
    out.extend_from_slice(&response_to.to_le_bytes());
    out.extend_from_slice(&wire::OP_MSG.to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Whether an aggregate's first stage is a `$group`.
fn group_stage(body: &Doc<'_>) -> bool {
    body.array("pipeline")
        .unwrap()
        .and_then(|p| match p.iter().next() {
            Some(Ok((_, Value::Doc(stage)))) => stage.doc("$group").unwrap(),
            _ => None,
        })
        .is_some()
}

/// The CAS store guard's key probe: `$sample` then a `$project` of `k`.
fn key_probe(body: &Doc<'_>) -> bool {
    body.array("pipeline")
        .unwrap()
        .and_then(|p| match p.iter().nth(1) {
            Some(Ok((_, Value::Doc(stage)))) => stage.doc("$project").unwrap(),
            _ => None,
        })
        .is_some_and(|proj| proj.doc("k").unwrap().is_some())
}

fn keys_have(body: &Doc<'_>, key: &str) -> bool {
    body.get(key).unwrap().is_some()
}

fn payload_of(body: &Doc<'_>) -> Vec<u8> {
    match body.get("payload").unwrap() {
        Some(Value::Binary(_, p)) => p.to_vec(),
        _ => panic!("no payload"),
    }
}

/// Serves one connection until the client closes it.
#[allow(clippy::too_many_lines)]
pub(crate) async fn serve(mut stream: DuplexStream, script: Script, log: Log) {
    let scram = ScramServer {
        salt: b"fake-salt-16byte".to_vec(),
        iterations: script.iterations,
        server_nonce: "SRVNONCE".to_owned(),
        password: script.password.clone(),
    };
    let mut exchange: Option<(String, String)> = None;
    loop {
        let mut header = [0u8; 16];
        if stream.read_exact(&mut header).await.is_err() {
            return;
        }
        let len = usize::try_from(i32::from_le_bytes(header[..4].try_into().unwrap())).unwrap();
        let id = i32::from_le_bytes(header[4..8].try_into().unwrap());
        let mut rest = vec![0u8; len - 16];
        if stream.read_exact(&mut rest).await.is_err() {
            return;
        }
        let (start, end) = wire::parse(&rest).unwrap();
        let body = Doc::new(&rest[start..end]).unwrap();
        let mut keys = Vec::new();
        for e in body.iter() {
            keys.push(String::from_utf8(e.unwrap().0.to_vec()).unwrap());
        }
        let name = keys[0].clone();
        let db = body.str("$db").unwrap().unwrap_or_default().to_owned();
        let collection = body.str(&name).unwrap().map(str::to_owned);
        let size = match name.as_str() {
            "find" => body.int("limit").unwrap(),
            "aggregate" => body
                .array("pipeline")
                .unwrap()
                .and_then(|p| match p.iter().next() {
                    Some(Ok((_, Value::Doc(stage)))) => stage.doc("$sample").unwrap(),
                    _ => None,
                })
                .and_then(|s| s.int("size").unwrap()),
            _ => None,
        };
        log.lock().unwrap().push(Received {
            name: name.clone(),
            db: db.clone(),
            collection: collection.clone(),
            max_time_ms: body.int("maxTimeMS").unwrap(),
            read_preference: body
                .doc("$readPreference")
                .unwrap()
                .and_then(|d| d.str("mode").unwrap().map(str::to_owned)),
            keys,
            size,
        });
        let find_coll = |db: &str| -> Option<FakeColl> {
            script
                .databases
                .iter()
                .find(|(d, _)| d == db)
                .and_then(|(_, cs)| cs.iter().find(|c| Some(&c.name) == collection.as_ref()))
                .cloned()
        };
        let reply: Vec<u8> = match name.as_str() {
            n if script.failing.contains(&n) => error_reply(13),
            "hello" => DocBuf::new()
                .bool("isWritablePrimary", true)
                .i32("maxWireVersion", script.wire_version)
                .i32("minWireVersion", 0)
                // Never read by the connector (I5).
                .array_str("hosts", &["evil.example:27017"])
                .i32("ok", 1)
                .finish(),
            "saslStart" => {
                assert_eq!(body.str("mechanism").unwrap(), Some("SCRAM-SHA-256"));
                let (bare, first) = scram.first(&payload_of(&body));
                exchange = Some((bare, first.clone()));
                DocBuf::new()
                    .i32("conversationId", 1)
                    .bool("done", script.done_early)
                    .binary("payload", first.as_bytes())
                    .i32("ok", 1)
                    .finish()
            }
            "saslContinue" => {
                let payload = payload_of(&body);
                if payload.is_empty() {
                    DocBuf::new()
                        .i32("conversationId", 1)
                        .bool("done", true)
                        .binary("payload", b"")
                        .i32("ok", 1)
                        .finish()
                } else {
                    let (bare, first) = exchange.take().unwrap();
                    match scram.last(&bare, &first, &payload) {
                        Some(mut v) => {
                            if script.bad_signature {
                                v = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
                            }
                            DocBuf::new()
                                .i32("conversationId", 1)
                                .bool("done", !script.empty_exchange)
                                .binary("payload", v.as_bytes())
                                .i32("ok", 1)
                                .finish()
                        }
                        None => error_reply(18),
                    }
                }
            }
            "buildInfo" => DocBuf::new()
                .str("version", "8.0.32")
                .array_str("modules", &[])
                .i32("ok", 1)
                .finish(),
            "connectionStatus" => {
                let mut privileges = DocBuf::new();
                for (i, p) in script.privileges.iter().enumerate() {
                    privileges = privileges.raw(0x03, &i.to_string(), p);
                }
                DocBuf::new()
                    .doc(
                        "authInfo",
                        DocBuf::new().raw(
                            0x04,
                            "authenticatedUserPrivileges",
                            &privileges.finish(),
                        ),
                    )
                    .i32("ok", 1)
                    .finish()
            }
            "listDatabases" => {
                let dbs: Vec<Vec<u8>> = ["admin", "local", "config"]
                    .iter()
                    .map(|d| (*d).to_owned())
                    .chain(script.databases.iter().map(|(d, _)| d.clone()))
                    .map(|d| DocBuf::new().str("name", &d).finish())
                    .collect();
                DocBuf::new()
                    .raw(0x04, "databases", &array_of(&dbs))
                    .i32("ok", 1)
                    .finish()
            }
            "listCollections" => {
                let colls: Vec<Vec<u8>> = script
                    .databases
                    .iter()
                    .find(|(d, _)| *d == db)
                    .map(|(_, cs)| {
                        cs.iter()
                            .map(|c| {
                                DocBuf::new()
                                    .str("name", &c.name)
                                    .str("type", c.kind)
                                    .finish()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                cursor_reply(&db, "$cmd.listCollections", &colls, script.cursor_id)
            }
            "count" => match find_coll(&db) {
                Some(c) if c.unauthorized => error_reply(13),
                Some(c) => DocBuf::new()
                    .i64("n", c.count.unwrap_or(i64::try_from(c.docs.len()).unwrap()))
                    .i32("ok", 1)
                    .finish(),
                None => error_reply(26),
            },
            "find" | "aggregate" => {
                // The key probe is answered normally: the oversized reply
                // is the documents' read.
                if script.oversized_find && !key_probe(&body) {
                    let mut h = Vec::new();
                    h.extend_from_slice(&i32::MAX.to_le_bytes());
                    h.extend_from_slice(&7i32.to_le_bytes());
                    h.extend_from_slice(&id.to_le_bytes());
                    h.extend_from_slice(&wire::OP_MSG.to_le_bytes());
                    let _ = stream.write_all(&h).await;
                    continue;
                }
                match find_coll(&db) {
                    Some(c) if c.unauthorized => error_reply(13),
                    // Like the server: a `find` on a view (time-series) is
                    // converted to an aggregation, which refuses
                    // `singleBatch`.
                    Some(c) if c.kind == "timeseries" && keys_have(&body, "singleBatch") => {
                        error_reply(168)
                    }
                    // A batch holding a string where a document belongs.
                    Some(c) if script.malformed_batch => DocBuf::new()
                        .doc(
                            "cursor",
                            DocBuf::new()
                                .i64("id", script.cursor_id)
                                .str("ns", &format!("{db}.{}", c.name))
                                .raw(0x04, "firstBatch", &DocBuf::new().str("0", "x").finish()),
                        )
                        .i32("ok", 1)
                        .finish(),
                    // The key probe: the first document's top-level keys.
                    Some(c) if name == "aggregate" && key_probe(&body) => {
                        let docs: Vec<Vec<u8>> = c
                            .docs
                            .first()
                            .map(|d| {
                                let keys: Vec<String> = Doc::new(d)
                                    .unwrap()
                                    .iter()
                                    .map(|e| String::from_utf8(e.unwrap().0.to_vec()).unwrap())
                                    .collect();
                                let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
                                DocBuf::new().array_str("k", &keys).finish()
                            })
                            .into_iter()
                            .collect();
                        cursor_reply(&db, &c.name, &docs, 0)
                    }
                    // The CAS store guard's `$group` on `type`.
                    Some(c) if name == "aggregate" && group_stage(&body) => {
                        let mut groups: Vec<(String, i64)> = Vec::new();
                        for d in &c.docs {
                            let t = Doc::new(d)
                                .unwrap()
                                .str("type")
                                .unwrap()
                                .unwrap_or("")
                                .to_owned();
                            match groups.iter_mut().find(|(k, _)| *k == t) {
                                Some((_, n)) => *n += 1,
                                None => groups.push((t, 1)),
                            }
                        }
                        let docs: Vec<Vec<u8>> = groups
                            .iter()
                            .map(|(t, n)| DocBuf::new().str("_id", t).i64("n", *n).finish())
                            .collect();
                        cursor_reply(&db, &c.name, &docs, 0)
                    }
                    Some(c) => {
                        let n = usize::try_from(size.unwrap_or(0)).unwrap();
                        let docs: Vec<Vec<u8>> = c.docs.iter().take(n).cloned().collect();
                        cursor_reply(&db, &c.name, &docs, script.cursor_id)
                    }
                    None => error_reply(26),
                }
            }
            "killCursors" => DocBuf::new().i32("ok", 1).finish(),
            "whatsmyuri" => DocBuf::new()
                .str("you", "10.0.0.15:40000")
                .i32("ok", 1)
                .finish(),
            _ => error_reply(59),
        };
        if stream.write_all(&frame(id, &reply)).await.is_err() {
            return;
        }
    }
}

/// A session to a scripted server.
pub(crate) async fn session(
    script: Script,
    password: &str,
) -> (Result<Session<DuplexStream>, MgError>, Log) {
    let log: Log = Arc::default();
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server, script, Arc::clone(&log)));
    let s = Session::establish(
        Wire::new(client),
        Timeouts::new(Duration::from_secs(5)),
        USER,
        password,
        "admin",
    )
    .await;
    (s, log)
}

fn names(log: &Log) -> Vec<String> {
    log.lock().unwrap().iter().map(|r| r.name.clone()).collect()
}

#[tokio::test]
async fn handshake_then_scram_sha_256() {
    let (s, log) = session(Script::default(), PASSWORD).await;
    let s = s.unwrap();
    assert_eq!(s.info.max_wire_version, 25);
    assert!(!s.info.mongos);
    assert_eq!(names(&log), ["hello", "saslStart", "saslContinue"]);
    let hello = log.lock().unwrap()[0].clone();
    assert!(hello.keys.contains(&"client".to_owned()));
    assert_eq!(hello.db, "admin");
    // Setup commands carry no maxTimeMS nor read preference.
    assert!(log.lock().unwrap().iter().all(|r| r.max_time_ms.is_none()));
}

#[tokio::test]
async fn an_empty_exchange_follows_a_verified_signature() {
    let script = Script {
        empty_exchange: true,
        ..Script::default()
    };
    let (s, log) = session(script, PASSWORD).await;
    s.unwrap();
    assert_eq!(
        names(&log),
        ["hello", "saslStart", "saslContinue", "saslContinue"]
    );
}

#[tokio::test]
async fn hostile_or_failed_authentication_is_refused() {
    for (script, password) in [
        // Wrong password: the server refuses the proof.
        (Script::default(), "wrong"),
        // An iteration count below 4096 (a relayed proof cheap to attack).
        (
            Script {
                iterations: 1,
                ..Script::default()
            },
            PASSWORD,
        ),
        // A server that cannot prove it knows the password.
        (
            Script {
                bad_signature: true,
                ..Script::default()
            },
            PASSWORD,
        ),
        // `done` before the client proved anything.
        (
            Script {
                done_early: true,
                ..Script::default()
            },
            PASSWORD,
        ),
    ] {
        let (s, log) = session(script, password).await;
        let e = s.unwrap_err();
        assert_eq!(e.code, FailureCode::AuthenticationFailed, "{e:?}");
        assert_eq!(e.stage, Stage::Auth);
        assert!(e.fatal);
        // Nothing but the handshake and SASL was sent.
        assert!(
            names(&log)
                .iter()
                .all(|n| ["hello", "saslStart", "saslContinue"].contains(&n.as_str())),
            "{:?}",
            names(&log)
        );
    }
}

#[tokio::test]
async fn servers_older_than_5_0_are_unsupported() {
    let script = Script {
        wire_version: 9,
        ..Script::default()
    };
    let (s, log) = session(script, PASSWORD).await;
    let e = s.unwrap_err();
    assert_eq!(e.code, FailureCode::Unsupported);
    // No credential exchange with an unsupported server.
    assert_eq!(names(&log), ["hello"]);
}

fn user_doc(i: usize) -> Vec<u8> {
    let first = ["Jean", "Camille", "Hugo", "Emma", "Louis"][i % 5];
    DocBuf::new()
        .str("_id", &format!("u{i:04}"))
        .str(
            "email",
            &format!("{}.martin{i}@example.com", first.to_lowercase()),
        )
        .doc(
            "name",
            DocBuf::new().str("first", first).str("last", "Martin"),
        )
        .doc(
            "contacts",
            DocBuf::new().doc(
                &format!("contact{i}@example.org"),
                DocBuf::new().str(
                    "phone",
                    &format!("06 12 34 {:02} {:02}", i % 100, (i * 7) % 100),
                ),
            ),
        )
        .bool("email_verified", true)
        .finish()
}

fn target() -> TargetConfig {
    databastion_core::AgentConfig::parse(
        "{console: {url: \"https://c.example\"}, state_dir: /s, targets: \
         [{id: mongo-fake, engine: mongodb, host: 127.0.0.1, account: databastion, \
         secret: {env: PW}, mongodb: {tls: disable}}]}",
    )
    .unwrap()
    .targets[0]
        .clone()
}

async fn run_scan(script: Script) -> (Result<u64, ConnectorError>, Vec<MaskedFinding>, Log) {
    let (r, findings, log, _) = run_scan_job(script).await;
    (r.map(|o| o.timeseries_refused), findings, log)
}

async fn run_scan_job(
    script: Script,
) -> (
    Result<discover::ScanOutcome, ConnectorError>,
    Vec<MaskedFinding>,
    Log,
    ScanJob,
) {
    let t = target();
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &t,
        &Limits::default(),
        Arc::new(HmacKey::new(&[7u8; 32]).unwrap()),
    );
    let (sink, mut rx) = FindingSink::channel(10_000);
    let log: Log = Arc::default();
    let timeouts = Timeouts::new(job.statement_timeout());
    let r = discover::scan(&job, &sink, &t, || {
        let log = Arc::clone(&log);
        let script = script.clone();
        async move {
            let (client, server) = tokio::io::duplex(1 << 20);
            tokio::spawn(serve(server, script, log));
            Session::establish(Wire::new(client), timeouts, USER, PASSWORD, "admin").await
        }
    })
    .await;
    drop(sink);
    let mut out = Vec::new();
    while let Some(f) = rx.recv().await {
        out.push(f);
    }
    (r, out, log, job)
}

#[tokio::test]
async fn a_whole_scan_over_the_wire() {
    let users: Vec<Vec<u8>> = (0..30).map(user_doc).collect();
    let big: Vec<Vec<u8>> = (0..50).map(user_doc).collect();
    let script = Script {
        databases: vec![(
            "app".to_owned(),
            vec![
                FakeColl::new("users", users),
                FakeColl {
                    // Estimated far above 20 x sample_rows: `$sample`.
                    count: Some(1_000_000),
                    ..FakeColl::new("events", big)
                },
                FakeColl {
                    kind: "view",
                    ..FakeColl::new("users_view", Vec::new())
                },
                FakeColl {
                    kind: "timeseries",
                    ..FakeColl::new("metrics", vec![DocBuf::new().str("ts", "x").finish()])
                },
                FakeColl {
                    unauthorized: true,
                    ..FakeColl::new("secret_stuff", Vec::new())
                },
                FakeColl::new("export_jane.doe@example.com", vec![user_doc(1)]),
            ],
        )],
        ..Script::default()
    };
    let (r, findings, log) = run_scan(script).await;
    r.unwrap();
    let received = log.lock().unwrap().clone();
    // Never a system database, never a view.
    let data = ["listCollections", "count", "find", "aggregate"];
    assert!(
        received
            .iter()
            .filter(|c| data.contains(&c.name.as_str()))
            .all(|c| c.db == "app" && c.collection.as_deref() != Some("users_view")),
        "{received:?}"
    );
    // Every read carries maxTimeMS and the read preference.
    for c in received.iter().filter(|c| {
        [
            "listDatabases",
            "listCollections",
            "count",
            "find",
            "aggregate",
        ]
        .contains(&c.name.as_str())
    }) {
        assert!(c.max_time_ms.is_some_and(|t| t > 0), "{c:?}");
        assert_eq!(
            c.read_preference.as_deref(),
            Some("secondaryPreferred"),
            "{c:?}"
        );
    }
    // `$sample` for the large collection, `find` for the others; no count
    // on the time-series collection; never getMore.
    let reads: Vec<(String, String)> = received
        .iter()
        .filter(|c| ["find", "aggregate", "count"].contains(&c.name.as_str()))
        .map(|c| (c.name.clone(), c.collection.clone().unwrap_or_default()))
        .collect();
    assert!(reads.contains(&("aggregate".to_owned(), "events".to_owned())));
    assert!(reads.contains(&("find".to_owned(), "users".to_owned())));
    assert!(reads.contains(&("find".to_owned(), "metrics".to_owned())));
    assert!(!reads.contains(&("count".to_owned(), "metrics".to_owned())));
    assert!(received.iter().all(|c| c.name != "getMore"));
    // Findings: normalized paths, masked values.
    let located: Vec<(String, String, String)> = findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            assert!(l.schema.is_none());
            (
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str().to_owned(),
            )
        })
        .collect();
    for expected in [
        ("users", "email", "pii.email"),
        ("users", "contacts.*.phone", "pii.phone"),
        ("events", "email", "pii.email"),
    ] {
        let expected = (
            expected.0.to_owned(),
            expected.1.to_owned(),
            expected.2.to_owned(),
        );
        assert!(located.contains(&expected), "{expected:?} in {located:?}");
    }
    for f in &findings {
        let l = f.location().unwrap();
        for name in [l.database.as_str(), l.object.as_str(), l.field.as_str()] {
            assert!(!name.contains('@') && !name.contains("example"), "{name}");
        }
        for s in f.masked_samples() {
            assert!(!s.as_str().contains("martin"), "{}", s.as_str());
        }
    }
    // The value-bearing collection name is masked.
    assert!(located.iter().any(|(o, _, _)| o == "*"), "{located:?}");
    // The estimate comes from `count`.
    let users = findings
        .iter()
        .find(|f| f.location().unwrap().object.as_str() == "users")
        .unwrap();
    assert_eq!(users.estimated_rows(), Some(30));
}

#[tokio::test]
async fn open_cursors_are_killed_and_never_read_further() {
    let script = Script {
        cursor_id: 42,
        databases: vec![(
            "app".to_owned(),
            vec![FakeColl::new("users", (0..5).map(user_doc).collect())],
        )],
        ..Script::default()
    };
    let (r, _, log) = run_scan(script).await;
    r.unwrap();
    let received = log.lock().unwrap().clone();
    let kills: Vec<&Received> = received
        .iter()
        .filter(|c| c.name == "killCursors")
        .collect();
    // One for the listing, one for the read.
    assert_eq!(kills.len(), 2, "{received:?}");
    assert!(
        kills
            .iter()
            .any(|k| k.collection.as_deref() == Some("$cmd.listCollections"))
    );
    assert!(
        kills
            .iter()
            .any(|k| k.collection.as_deref() == Some("users"))
    );
    assert!(received.iter().all(|c| c.name != "getMore"));
}

#[tokio::test]
async fn an_oversized_reply_skips_the_collection_and_reconnects() {
    let script = Script {
        oversized_find: true,
        databases: vec![(
            "app".to_owned(),
            vec![
                FakeColl::new("a", vec![user_doc(1)]),
                FakeColl::new("b", vec![user_doc(2)]),
            ],
        )],
        ..Script::default()
    };
    let (r, findings, log) = run_scan(script).await;
    r.unwrap();
    assert!(findings.is_empty());
    // A new connection (hello) for the next collection after the broken
    // one; both collections were tried.
    let hellos = names(&log).iter().filter(|n| *n == "hello").count();
    assert_eq!(hellos, 2, "{:?}", names(&log));
    assert_eq!(
        names(&log).iter().filter(|n| *n == "find").count(),
        2,
        "{:?}",
        names(&log)
    );
}

#[tokio::test]
async fn sample_collection_uses_the_bounded_read() {
    let script = Script {
        databases: vec![(
            "app".to_owned(),
            vec![FakeColl::new("users", (0..10).map(user_doc).collect())],
        )],
        ..Script::default()
    };
    let (s, log) = session(script, PASSWORD).await;
    let mut s = s.unwrap();
    let coll = Collection {
        name: "users".to_owned(),
        kind: CollKind::Collection,
    };
    let sampled = discover::sample_collection(&mut s, "app", &coll, 3)
        .await
        .unwrap();
    assert_eq!(sampled.method, Method::Natural);
    assert_eq!(sampled.estimated_rows, Some(10));
    assert_eq!(sampled.collector.stats.documents, 3);
    let find = log
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.name == "find")
        .cloned()
        .unwrap();
    assert_eq!(find.size, Some(3));
    assert!(find.keys.contains(&"singleBatch".to_owned()));
    // A collection gone since the listing: a non-fatal error.
    let e = discover::sample_collection(
        &mut s,
        "app",
        &Collection {
            name: "missing".to_owned(),
            kind: CollKind::Collection,
        },
        3,
    )
    .await
    .unwrap_err();
    assert!(!e.fatal);
    assert_eq!(e.server_code, Some(26));
    assert!(!s.is_broken());
}

#[tokio::test]
async fn check_reports_privileges_and_views() {
    let script = Script {
        databases: vec![(
            "app".to_owned(),
            vec![
                FakeColl::new("users", Vec::new()),
                FakeColl {
                    kind: "view",
                    ..FakeColl::new("v", Vec::new())
                },
            ],
        )],
        privileges: vec![
            DocBuf::new()
                .doc(
                    "resource",
                    DocBuf::new().str("db", "app").str("collection", ""),
                )
                .array_str(
                    "actions",
                    &["find", "listCollections", "insert", "changeStream"],
                )
                .finish(),
            DocBuf::new()
                .doc("resource", DocBuf::new().bool("cluster", true))
                .array_str("actions", &["inprog"])
                .finish(),
        ],
        ..Script::default()
    };
    let (s, _log) = session(script, PASSWORD).await;
    let mut s = s.unwrap();
    let build = crate::check::build_info(&mut s).await.unwrap();
    assert_eq!(build.version, "8.0.32");
    assert_eq!(build.edition, "community");
    let r = crate::check::report(&mut s).await;
    assert!(r.privileges_known);
    assert_eq!(r.databases, 1);
    assert_eq!(r.views, 1);
    let codes: Vec<(&str, Option<u64>)> = r
        .notes(false)
        .iter()
        .map(|n| (n.code().as_str(), n.count()))
        .collect();
    assert_eq!(
        codes,
        [
            ("privilege.write_actions", Some(1)),
            ("privilege.read_beyond_discovery", Some(1)),
            ("privilege.cluster_actions", Some(1)),
            ("coverage.views_not_sampled", Some(1)),
        ]
    );
}

#[tokio::test]
async fn server_error_text_is_never_kept() {
    let script = Script {
        databases: vec![("app".to_owned(), vec![])],
        ..Script::default()
    };
    let (s, _) = session(script, PASSWORD).await;
    let mut s = s.unwrap();
    let e = discover::sample_collection(
        &mut s,
        "app",
        &Collection {
            name: "nope".to_owned(),
            kind: CollKind::Collection,
        },
        3,
    )
    .await
    .unwrap_err();
    let text = format!("{e:?} {}", e.into_connector_error());
    assert!(
        !text.contains("jane") && !text.contains("hostile"),
        "{text}"
    );
}

// ------------------------------------------------------------ seed recall

/// Appends a JSON value as BSON, the way `mongosh` stores the seed
/// (`JSON.parse` then `insertMany`): integers as int32 when they fit, other
/// numbers as doubles.
fn append(doc: DocBuf, key: &str, value: &serde_json::Value) -> DocBuf {
    use serde_json::Value as J;
    match value {
        J::Null => doc.raw(0x0A, key, &[]),
        J::Bool(b) => doc.bool(key, *b),
        J::Number(n) => match n.as_i64().and_then(|i| i32::try_from(i).ok()) {
            Some(i) => doc.i32(key, i),
            None => doc.raw(0x01, key, &n.as_f64().unwrap().to_le_bytes()),
        },
        J::String(s) => doc.str(key, s),
        J::Array(items) => {
            let mut array = DocBuf::new();
            for (i, item) in items.iter().enumerate() {
                array = append(array, &i.to_string(), item);
            }
            doc.raw(0x04, key, &array.finish())
        }
        J::Object(map) => {
            let mut inner = DocBuf::new();
            for (k, v) in map {
                inner = append(inner, k, v);
            }
            doc.raw(0x03, key, &inner.finish())
        }
    }
}

fn seed_collections() -> Vec<FakeColl> {
    let seed: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/seed/out/mongo.json")).unwrap();
    seed["collections"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, docs)| {
            let docs = docs
                .as_array()
                .unwrap()
                .iter()
                .map(|d| {
                    let mut doc = DocBuf::new();
                    for (k, v) in d.as_object().unwrap() {
                        doc = append(doc, k, v);
                    }
                    doc.finish()
                })
                .collect();
            FakeColl::new(name, docs)
        })
        .collect()
}

/// The dev seed, served over the wire by the scripted server, gives every
/// ground-truth location of the `app` database and nothing on the
/// negative controls; value-bearing keys never reach a location, and no
/// ground-truth value is in clear in the serialized findings (interim I2).
#[tokio::test]
async fn seed_recall_over_the_wire() {
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    let script = Script {
        databases: vec![("app".to_owned(), seed_collections())],
        ..Script::default()
    };
    let (r, findings, _) = run_scan(script).await;
    r.unwrap();
    let found: std::collections::BTreeSet<(String, String, String)> = findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            assert_eq!(l.database.as_str(), "app");
            (
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str().to_owned(),
            )
        })
        .collect();
    let mut missed = Vec::new();
    let mut false_positives = Vec::new();
    for l in gt["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "mongodb" && l["database"] == "app")
    {
        let object = l["object"].as_str().unwrap();
        let field = l["expected_normalized_name"]
            .as_str()
            .or_else(|| l["field"].as_str())
            .unwrap();
        for c in l["expected_classifiers"].as_array().unwrap() {
            let key = (
                object.to_owned(),
                field.to_owned(),
                c.as_str().unwrap().to_owned(),
            );
            if !found.contains(&key) {
                missed.push(key);
            }
        }
        if l["negative_control"] == true {
            false_positives.extend(
                found
                    .iter()
                    .filter(|(o, f, _)| o == object && f == field)
                    .cloned(),
            );
        }
        for v in l["name_values"].as_array().into_iter().flatten() {
            let v = v.as_str().unwrap();
            for (o, f, _) in &found {
                assert!(!o.contains(v) && !f.contains(v), "{v} in {o}.{f}");
            }
        }
    }
    assert!(missed.is_empty(), "missed: {missed:?}\nfound: {found:?}");
    assert!(false_positives.is_empty(), "{false_positives:?}");
    // No finding outside the ground truth ("a location not listed is
    // expected to produce no finding").
    let listed: std::collections::BTreeSet<(String, String, String)> = gt["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "mongodb" && l["database"] == "app")
        .flat_map(|l| {
            let object = l["object"].as_str().unwrap().to_owned();
            let field = l["expected_normalized_name"]
                .as_str()
                .or_else(|| l["field"].as_str())
                .unwrap()
                .to_owned();
            l["expected_classifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |c| {
                    (
                        object.clone(),
                        field.clone(),
                        c.as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let extra: Vec<_> = found.difference(&listed).collect();
    assert!(
        extra.is_empty(),
        "findings outside the ground truth: {extra:?}"
    );
    // Interim I2 check (end-of-phase-5 review M1): no ground-truth value
    // (length >= 4) in clear in the serialized masked findings.
    assert!(crate::i2::assert_no_value(&gt, "app", &findings) > 0);
}

/// Time-series collections are read through their view (no
/// `singleBatch`); one the server refuses is counted for `check()`.
#[tokio::test]
async fn time_series_collections_are_read_or_their_refusal_counted() {
    let metrics: Vec<Vec<u8>> = (0..10)
        .map(|i| {
            DocBuf::new()
                .str("owner", &format!("metric{i}@example.net"))
                .finish()
        })
        .collect();
    let timeseries = |unauthorized| FakeColl {
        kind: "timeseries",
        unauthorized,
        ..FakeColl::new("metrics", metrics.clone())
    };
    let script = Script {
        databases: vec![("app".to_owned(), vec![timeseries(false)])],
        ..Script::default()
    };
    let (r, findings, _) = run_scan(script).await;
    assert_eq!(r.unwrap(), 0);
    assert!(findings.iter().any(|f| {
        let l = f.location().unwrap();
        l.object.as_str() == "metrics" && l.field.as_str() == "owner"
    }));
    let script = Script {
        databases: vec![("app".to_owned(), vec![timeseries(true)])],
        ..Script::default()
    };
    let (r, findings, _) = run_scan(script).await;
    assert_eq!(r.unwrap(), 1);
    assert!(findings.is_empty());
}

/// Privileges that cannot be read are reported as not evaluated (never as
/// least privilege), and a coverage listing that fails keeps the privilege
/// evaluation (security review M1).
#[tokio::test]
async fn privileges_not_evaluated_and_coverage_failures() {
    let over = DocBuf::new()
        .doc("resource", DocBuf::new().bool("cluster", true))
        .array_str("actions", &["inprog"])
        .finish();
    let codes = |r: &crate::check::Report| -> Vec<&'static str> {
        r.notes(false).iter().map(|n| n.code().as_str()).collect()
    };
    // connectionStatus refused.
    let script = Script {
        failing: vec!["connectionStatus"],
        ..Script::default()
    };
    let (s, _) = session(script, PASSWORD).await;
    let r = crate::check::report(&mut s.unwrap()).await;
    assert!(!r.privileges_known);
    assert_eq!(codes(&r), ["privilege.not_evaluated"]);
    // listDatabases refused after connectionStatus answered.
    let script = Script {
        failing: vec!["listDatabases"],
        privileges: vec![over],
        ..Script::default()
    };
    let (s, _) = session(script, PASSWORD).await;
    let r = crate::check::report(&mut s.unwrap()).await;
    assert!(r.privileges_known && !r.coverage_known);
    assert_eq!(codes(&r), ["privilege.cluster_actions"]);
}

/// A malformed batch with an open cursor: the collection is skipped and
/// the cursor is still killed (security review N1), on the `find` path and
/// on the `$sample` path.
#[tokio::test]
async fn an_open_cursor_is_killed_when_the_batch_is_malformed() {
    for count in [None, Some(1_000_000)] {
        let script = Script {
            cursor_id: 77,
            malformed_batch: true,
            databases: vec![(
                "app".to_owned(),
                vec![FakeColl {
                    count,
                    ..FakeColl::new("users", vec![user_doc(1)])
                }],
            )],
            ..Script::default()
        };
        let (s, log) = session(script, PASSWORD).await;
        let mut s = s.unwrap();
        let e = discover::sample_collection(
            &mut s,
            "app",
            &Collection {
                name: "users".to_owned(),
                kind: CollKind::Collection,
            },
            5,
        )
        .await
        .unwrap_err();
        assert!(!e.fatal);
        let received = log.lock().unwrap().clone();
        let read = if count.is_some() { "aggregate" } else { "find" };
        assert!(received.iter().any(|c| c.name == read), "{received:?}");
        assert!(
            received
                .iter()
                .any(|c| c.name == "killCursors" && c.collection.as_deref() == Some("users")),
            "{received:?}"
        );
    }
}

/// End-of-phase-5 review I1: a truncated command has an unknown shape
/// (no whole-read signal from a filter the server cut off), and an entry
/// that does not parse is skipped and counted without failing the poll.
#[tokio::test]
async fn profiler_truncated_and_odd_entries() {
    use crate::audit::profiler::{self, DbCursor};
    let truncated = DocBuf::new()
        .raw(0x09, "ts", &1_000i64.to_le_bytes())
        .str("op", "query")
        .str("ns", "app.users")
        .i32("nreturned", 20_000)
        .str("appName", "mongosh")
        .str("client", "10.0.0.9")
        .str("user", "alice@admin")
        .str("cmd", "$truncated")
        .bool("tr", true)
        .i32("fk", 0)
        .finish();
    // A time, then a string whose length runs past the document.
    let mut broken = DocBuf::new()
        .raw(0x09, "ts", &1_500i64.to_le_bytes())
        .str("op", "query")
        .finish();
    // The string length before "query\0" and the terminating NUL.
    let at = broken.len() - 1 - 6 - 4;
    broken[at..at + 4].copy_from_slice(&1000i32.to_le_bytes());
    let entries = vec![
        truncated,
        broken,
        profile_entry(2_000, "bob@admin", "mongodump", 0),
    ];
    let script = Script {
        databases: vec![(
            "app".to_owned(),
            vec![FakeColl::new("system.profile", entries)],
        )],
        ..Script::default()
    };
    let (s, log) = session(script, PASSWORD).await;
    let mut s = s.unwrap();
    let mut cursor = DbCursor::after(0);
    let polled = profiler::poll(&mut s, "app", &mut cursor).await.unwrap();
    assert_eq!(polled.records.len(), 2);
    assert_eq!(polled.dropped, 1);
    // The projection sent flags truncated commands.
    let sent = log.lock().unwrap().last().cloned().unwrap();
    assert!(sent.keys.contains(&"projection".to_owned()));
    let mut b = crate::audit::events::EventBuilder::new(
        databastion_core::audit::own::OwnAccount::new(
            "databastion@admin",
            Some("databastion-agent"),
            None,
            200,
            databastion_core::audit::own::SharedOwnUsage::default(),
        ),
        "databastion@admin".to_owned(),
        200,
    );
    let events = b.convert(
        polled.records,
        databastion_classifiers::masking::EventSource::MongodbProfiler,
        std::time::SystemTime::now(),
    );
    let signals: Vec<Vec<&str>> = events
        .iter()
        .map(|e| e.signals().iter().map(|s| s.as_str()).collect())
        .collect();
    assert_eq!(
        signals,
        [
            vec!["volume.large_result"],
            vec![
                "shape.full_table_read",
                "volume.large_result",
                "signature.mongodump"
            ],
        ]
    );
    s.close().await;
}

/// A projected profiler entry (what the server returns for the fixed
/// projection).
fn profile_entry(ts: i64, user: &str, app: &str, filter_keys: i32) -> Vec<u8> {
    DocBuf::new()
        .raw(0x09, "ts", &ts.to_le_bytes())
        .str("op", "query")
        .str("ns", "app.users")
        .i32("nreturned", 20_000)
        .str("appName", app)
        .str("client", "10.0.0.9")
        .str("user", user)
        .str("cmd", "find")
        .i32("fk", filter_keys)
        .finish()
}

/// The profiler source: the poll command (fixed projection, bounded,
/// single batch, `maxTimeMS`), the read position, and the events.
#[tokio::test]
async fn profiler_polls_are_bounded_and_resume_after_what_was_read() {
    use crate::audit::profiler::{self, DbCursor};
    let entries = vec![
        profile_entry(1_000, "alice@admin", "mongodump", 0),
        profile_entry(2_000, "bob@admin", "mongosh", 1),
        profile_entry(2_000, "carol@admin", "mongosh", 2),
    ];
    let script = Script {
        databases: vec![(
            "app".to_owned(),
            vec![FakeColl::new("system.profile", entries)],
        )],
        ..Script::default()
    };
    let (s, log) = session(script, PASSWORD).await;
    let mut s = s.unwrap();
    assert_eq!(
        crate::audit::whoami(&mut s).await,
        databastion_classifiers::masking::ClientAddr::parse("10.0.0.15")
    );
    let mut cursor = DbCursor::after(0);
    let polled = profiler::poll(&mut s, "app", &mut cursor).await.unwrap();
    assert_eq!(polled.records.len(), 3);
    assert!(!polled.more);
    let sent = log.lock().unwrap().last().cloned().unwrap();
    assert_eq!(sent.name, "find");
    assert_eq!(sent.collection.as_deref(), Some("system.profile"));
    assert_eq!(sent.db, "app");
    assert_eq!(sent.size, Some(profiler::BATCH));
    assert_eq!(sent.read_preference.as_deref(), Some("secondaryPreferred"));
    assert!(sent.max_time_ms.is_some_and(|t| t > 0));
    for key in ["filter", "projection", "sort", "singleBatch"] {
        assert!(sent.keys.contains(&key.to_owned()), "{key}");
    }
    assert!(!sent.keys.contains(&"batchSize".to_owned()));
    // The scripted server ignores the filter: what was read is not read
    // again.
    let polled = profiler::poll(&mut s, "app", &mut cursor).await.unwrap();
    assert!(polled.records.is_empty(), "{:?}", polled.records);
    // Phase 7: nor after an agent restart (the position saved and
    // restored: time and hashes of the entries read at that millisecond).
    let saved = profiler::encode_cursors(&[("app".to_owned(), cursor.clone())].into()).unwrap();
    let mut restored = profiler::decode_cursors(&saved, 10_000)
        .remove("app")
        .unwrap();
    assert_eq!(restored, cursor);
    let polled = profiler::poll(&mut s, "app", &mut restored).await.unwrap();
    assert!(polled.records.is_empty(), "{:?}", polled.records);
    // Events: the tool's whole read with its volume; the filtered reads
    // without signatures.
    let mut b = crate::audit::events::EventBuilder::new(
        databastion_core::audit::own::OwnAccount::new(
            "databastion@admin",
            Some("databastion-agent"),
            None,
            200,
            databastion_core::audit::own::SharedOwnUsage::default(),
        ),
        "databastion@admin".to_owned(),
        200,
    );
    let mut cursor = DbCursor::after(0);
    let polled = profiler::poll(&mut s, "app", &mut cursor).await.unwrap();
    let events = b.convert(
        polled.records,
        databastion_classifiers::masking::EventSource::MongodbProfiler,
        std::time::SystemTime::now(),
    );
    let signals: Vec<Vec<&str>> = events
        .iter()
        .map(|e| e.signals().iter().map(|s| s.as_str()).collect())
        .collect();
    assert_eq!(
        signals,
        [
            vec![
                "shape.full_table_read",
                "volume.large_result",
                "signature.mongodump"
            ],
            vec!["volume.large_result"],
            vec!["volume.large_result"],
        ]
    );
    // An unauthorized database: a non-fatal error.
    let e = profiler::poll(&mut s, "other", &mut DbCursor::after(0))
        .await
        .unwrap_err();
    assert!(!e.fatal);
    s.close().await;
}

// ------------------------------------------------------- CAS store guard

/// Fake ticket ids (never valid anywhere).
const TICKETS: [&str; 3] = [
    "TGT-1-FakeTgtValueAaaaaaaaaaaaaaaa-cas01",
    "ST-2-FakeStValueBbbbbbbbbbbbbbbbb-cas01",
    "ST-3-FakeStValueCcccccccccccccccc-cas01",
];
const PRINCIPAL: &str = "ticket.owner@example.org";

fn ticket_doc(id: &str, kind: &str) -> Vec<u8> {
    DocBuf::new()
        .str("_id", id)
        .str("type", kind)
        .str(
            "json",
            &format!("{{\"id\":\"{id}\",\"principal\":\"{PRINCIPAL}\"}}"),
        )
        .str("principal", PRINCIPAL)
        .date("expireAt", 1_800_000_000_000)
        .finish()
}

/// ADR-0041 decisions 5 and 14 over the wire: a ticket collection under a
/// built-in name (never read, its `type` counts only), one renamed
/// (recognized by its document shape, dropped unclassified), a plain
/// collection with ticket-id-shaped values (the tripwire), an audit trail
/// (ticket ids excluded by projection, principals without masked samples)
/// and a service registry (no masked samples, no `secret.*` fingerprints).
#[tokio::test]
async fn cas_store_guard_over_the_wire() {
    let tgt = "org.apereo.cas.ticket.TicketGrantingTicketImpl";
    let st = "org.apereo.cas.ticket.ServiceTicketImpl";
    let enc = "org.apereo.cas.ticket.registry.EncodedTicket";
    let refs: Vec<Vec<u8>> = (0..30)
        .map(|i| {
            DocBuf::new()
                .str("_id", &format!("r{i}"))
                .str("ref", if i % 7 == 0 { TICKETS[2] } else { "ref-x" })
                .str("email", &format!("guard.user{i}@example.com"))
                .finish()
        })
        .collect();
    let audit: Vec<Vec<u8>> = (0..20)
        .map(|i| {
            DocBuf::new()
                .str("principal", &format!("audit.user{i}@example.net"))
                .str("actionPerformed", "SERVICE_TICKET_CREATED")
                .str("clientIpAddress", &format!("192.0.2.{i}"))
                .finish()
        })
        .collect();
    let services: Vec<Vec<u8>> = (0..20)
        .map(|i| {
            DocBuf::new()
                .str("@class", "org.apereo.cas.services.OidcRegisteredService")
                .str("serviceId", &format!("https://app{i}.example.com/.*"))
                .str("clientSecret", &format!("AKIA{i:0>16}"))
                .str("description", &format!("owner{i}@example.com"))
                .finish()
        })
        .collect();
    let script = Script {
        databases: vec![(
            "cas".to_owned(),
            vec![
                FakeColl::new(
                    "serviceTicketsCollection",
                    vec![ticket_doc(TICKETS[1], st), ticket_doc("x-1", enc)],
                ),
                FakeColl::new(
                    "sso_sessions_v2",
                    vec![ticket_doc(TICKETS[0], tgt), ticket_doc(TICKETS[1], st)],
                ),
                FakeColl::new("app_sessions", refs),
                FakeColl::new("MongoDbCasAuditRepository", audit),
                FakeColl::new("cas-service-registry", services),
            ],
        )],
        ..Script::default()
    };
    let (r, findings, log, job) = run_scan_job(script).await;
    let outcome = r.unwrap();
    let received = log.lock().unwrap().clone();
    let reads = |coll: &str| -> Vec<Received> {
        received
            .iter()
            .filter(|c| c.collection.as_deref() == Some(coll))
            .cloned()
            .collect()
    };
    // Built-in name: the key probe (field names only, to find the type
    // field), then one `$group` aggregate; no `find` nor `count`.
    let built_in = reads("serviceTicketsCollection");
    assert_eq!(built_in.len(), 2, "{built_in:?}");
    assert!(built_in.iter().all(|c| c.name == "aggregate"));
    assert_eq!(built_in[0].size, Some(1));
    assert_eq!(built_in[1].size, None);
    // Renamed (PR #141 review L4): recognized by the key probe before any
    // document is read; then its `$group`, and no `find` nor `count`.
    let renamed = reads("sso_sessions_v2");
    assert_eq!(renamed.len(), 2, "{renamed:?}");
    assert!(renamed.iter().all(|c| c.name == "aggregate"));
    assert_eq!(renamed[1].size, None);
    // The audit trail is read without its ticket ids and headers.
    let audit_find = reads("MongoDbCasAuditRepository");
    assert!(
        audit_find
            .iter()
            .any(|c| c.name == "find" && c.keys.iter().any(|k| k == "projection")),
        "{audit_find:?}"
    );
    assert_eq!(job.cas_guard().registries(), 2);
    assert_eq!(job.cas_guard().unencrypted(), 3);
    assert_eq!(job.cas_guard().tripped(), 1);
    let at = |object: &str, field: &str| {
        findings
            .iter()
            .filter(|f| {
                let l = f.location().unwrap();
                l.object.as_str() == object && l.field.as_str() == field
            })
            .collect::<Vec<_>>()
    };
    for f in &findings {
        let o = f.location().unwrap().object.as_str();
        assert!(
            o != "sso_sessions_v2" && o != "serviceTicketsCollection",
            "{f:?}"
        );
    }
    assert!(at("app_sessions", "ref").is_empty());
    assert_eq!(at("app_sessions", "email").len(), 1, "{findings:?}");
    let principal = at("MongoDbCasAuditRepository", "principal");
    assert_eq!(principal.len(), 1, "{findings:?}");
    assert!(principal[0].masked_samples().is_empty());
    let registry: Vec<_> = findings
        .iter()
        .filter(|f| f.location().unwrap().object.as_str() == "cas-service-registry")
        .collect();
    assert!(!registry.is_empty(), "{findings:?}");
    for f in &registry {
        assert!(f.masked_samples().is_empty(), "{f:?}");
        if f.classifier().is_secret() {
            assert!(f.fingerprints().is_empty(), "{f:?}");
        }
    }
    let text = format!("{findings:?}");
    for v in TICKETS.iter().chain([&PRINCIPAL]) {
        assert!(!text.contains(v), "{v} leaked");
    }
    // Recorded for check(): both ticket registries and the audit trail.
    let mut recorded: Vec<&str> = outcome
        .cas_stores
        .iter()
        .map(|(_, c, _)| c.as_str())
        .collect();
    recorded.sort_unstable();
    assert_eq!(
        recorded,
        [
            "MongoDbCasAuditRepository",
            "serviceTicketsCollection",
            "sso_sessions_v2"
        ]
    );
}

#[test]
fn find_scopes_of_connection_status() {
    use crate::privileges::{FindScope, find_scopes};
    let p = |res: DocBuf, actions: &[&str]| {
        DocBuf::new()
            .doc("resource", res)
            .array_str("actions", actions)
            .finish()
    };
    let privileges = [
        p(
            DocBuf::new()
                .str("db", "cas")
                .str("collection", "cas_tickets"),
            &["find"],
        ),
        p(
            DocBuf::new().str("db", "app").str("collection", ""),
            &["find", "listCollections"],
        ),
        p(
            DocBuf::new().str("db", "x").str("collection", "y"),
            &["insert"],
        ),
        p(DocBuf::new().bool("cluster", true), &["find"]),
        p(DocBuf::new().bool("anyResource", true), &["anyAction"]),
        p(DocBuf::new().str("db", "").str("collection", ""), &["find"]),
    ];
    let reply = DocBuf::new()
        .doc(
            "authInfo",
            DocBuf::new().raw(0x04, "authenticatedUserPrivileges", &array_of(&privileges)),
        )
        .finish();
    assert_eq!(
        find_scopes(Doc::new(&reply).unwrap()).unwrap(),
        [
            FindScope::Collection("cas".into(), "cas_tickets".into()),
            FindScope::Database("app".into()),
            FindScope::Any,
            FindScope::Any,
        ]
    );
}

/// PR #141 review L5: the ticket type field is found whatever its ASCII
/// case; L4: the key probe projects field names only.
#[test]
fn ticket_type_field_and_key_probe() {
    let k = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(discover::ticket_type_field(&k(&["_id", "Type"])), "Type");
    assert_eq!(discover::ticket_type_field(&k(&["TYPE", "type"])), "type");
    assert_eq!(discover::ticket_type_field(&k(&["_type", "kind"])), "type");
    let group = discover::ticket_types_command("t", "TYPE").finish();
    let group = Doc::new(&group).unwrap();
    let stage = group.array("pipeline").unwrap().unwrap();
    let Some(Ok((_, Value::Doc(first)))) = stage.iter().next() else {
        panic!("no $group");
    };
    assert_eq!(
        first.doc("$group").unwrap().unwrap().str("_id").unwrap(),
        Some("$TYPE")
    );
    let probe = discover::key_probe_command("t").finish();
    let probe = Doc::new(&probe).unwrap();
    assert!(key_probe(&probe));
    let stages: Vec<_> = probe
        .array("pipeline")
        .unwrap()
        .unwrap()
        .iter()
        .map(|e| match e.unwrap().1 {
            Value::Doc(d) => d,
            _ => panic!("stage"),
        })
        .collect();
    assert_eq!(stages.len(), 2);
    let sample = stages[0].doc("$sample").unwrap().unwrap();
    assert_eq!(sample.int("size").unwrap(), Some(1));
    // `_id` excluded, only `k` (the keys) projected.
    let project = stages[1].doc("$project").unwrap().unwrap();
    let projected: Vec<String> = project
        .iter()
        .map(|e| String::from_utf8(e.unwrap().0.to_vec()).unwrap())
        .collect();
    assert_eq!(projected, ["_id", "k"]);
    assert_eq!(project.int("_id").unwrap(), Some(0));
}
