//! Audit integration tests against the dev `mongo` service (P5-B, P5-C,
//! ADR-0027): MongoDB 8.0 Community, profiler level 1 with `slowms` 0, the
//! structured JSON log in `dev/.state/logs/mongodb/mongod.log`.
//!
//! - `DATABASTION_TEST_MONGO_LOG`: the server log as the agent host sees
//!   it (bind mount). Without it, the server-log test is skipped
//!   (prerequisite `mongo-log`).
//! - `DATABASTION_TEST_MONGO_DUMP_CMD` / `DATABASTION_TEST_MONGO_EXPORT_CMD`:
//!   shell commands running the real `mongodump` / `mongoexport` against
//!   the dev server (in CI, inside the container). Without them, only the
//!   simulated runs (a session declaring the tool's application name) are
//!   checked (prerequisite `mongodump`).
//!
//! - `DATABASTION_TEST_PSMDB_URL`, `DATABASTION_TEST_PSMDB_ADMIN_URL` and
//!   `DATABASTION_TEST_PSMDB_AUDIT_LOG` (phase 7): the opt-in dev `psmdb`
//!   service (Percona Server for MongoDB, `auditLog` JSON file with
//!   `auditAuthorizationSuccess`), its administrator and its `auditLog` as
//!   the agent host sees it. Without them, the `auditLog` test is skipped
//!   (prerequisite `psmdb-audit`); the parser is also covered by the
//!   fixtures of `audit::records`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{AuditLevel, Connector, ConnectorError, EventSink, NoteCode};

use super::{
    IT_PASSWORD, Logs, SERIAL, TempDir, Url, admin, admin_session, codes, run, scan, server, skip,
    target, target_with,
};
use crate::MongodbConnector;
use crate::bson::DocBuf;
use crate::conn::{Session, Timeouts};

const PROFILER_USER: &str = "databastion_it_profiler";
const PROFILER_ROLE: &str = "databastion_it_profiler";
/// A literal of a filter: never in an event nor in the logs.
const MARKER: &str = "needle-7Qz-FAKE";
/// A collection of the seeded `app` database.
const COLLECTION: &str = "users";

fn env_path(var: &str, key: &str) -> Option<PathBuf> {
    // A dev log may belong to the test's own user (the tailer refuses it
    // in production).
    databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
    match std::env::var(var) {
        Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => {
            skip(key, &format!("{var} is not set"));
            None
        }
    }
}

/// Runs a real tool command (`DATABASTION_TEST_MONGO_<label>_CMD`).
fn real_tool(label: &str) -> bool {
    let var = format!("DATABASTION_TEST_MONGO_{label}_CMD");
    let Ok(cmd) = std::env::var(&var) else {
        skip("mongodump", &format!("{var} is not set (real tool run)"));
        return false;
    };
    let out = std::process::Command::new("sh")
        .args(["-c", &cmd])
        .stdout(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => panic!(
            "{var} failed: {:?} {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("{var} failed to start: {e}"),
    }
}

fn describe(e: &MaskedEvent) -> String {
    format!("{e:?}")
}

fn has(events: &[MaskedEvent], object: &str, signal: &str) -> bool {
    events.iter().any(|e| {
        e.objects().iter().any(|o| o.object().as_str() == object)
            && e.signals().iter().any(|s| s.as_str() == signal)
    })
}

async fn collect_until(
    rx: &mut tokio::sync::mpsc::Receiver<MaskedEvent>,
    out: &mut Vec<MaskedEvent>,
    timeout: Duration,
    done: impl Fn(&[MaskedEvent]) -> bool,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !done(out) {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(e)) => out.push(e),
            _ => break,
        }
    }
}

/// What a driver does when it closes a pooled connection still in its
/// handshake: `hello` carrying a speculative `saslStart` for `user`, then
/// the connection closes before the proof. mongod logs "Failed to
/// authenticate" (`AuthenticationAbandoned`, 337): not a failed login.
async fn abandon_handshake(url: &Url, user: &str) {
    let endpoint = crate::net::Endpoint::Tcp {
        host: url.host.clone(),
        port: url.port,
    };
    let mut wire = crate::wire::Wire::new(endpoint.open(None).await.unwrap());
    let (_exchange, first) = crate::scram::Scram::start(user).unwrap();
    let hello = DocBuf::new()
        .i32("hello", 1)
        .doc(
            "speculativeAuthenticate",
            DocBuf::new()
                .i32("saslStart", 1)
                .str("mechanism", crate::scram::MECHANISM)
                .binary("payload", &first)
                .str("db", "admin"),
        )
        .str("$db", "admin")
        .finish();
    let reply = wire.round_trip(&hello).await.unwrap();
    assert!(
        reply
            .doc()
            .doc("speculativeAuthenticate")
            .unwrap()
            .is_some(),
        "the server did not start the speculative conversation"
    );
    wire.shutdown().await;
}

/// "Failed to authenticate" lines (id 5286307) of the server log after
/// byte `from`, as `(user, result)` (test accounts only).
fn auth_failed_lines(log: &Path, from: u64) -> Vec<(String, i64)> {
    let bytes = std::fs::read(log).unwrap();
    let start = usize::try_from(from).unwrap().min(bytes.len());
    bytes[start..]
        .split(|b| *b == b'\n')
        .filter_map(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
        .filter(|v| v["id"] == 5_286_307)
        .map(|v| {
            (
                v["attr"]["user"].as_str().unwrap_or_default().to_owned(),
                v["attr"]["result"].as_i64().unwrap_or_default(),
            )
        })
        .collect()
}

/// Waits (10 s at most) until the server log holds, after byte `from`, a
/// "Failed to authenticate" line with `result` for each of `users`.
async fn wait_auth_failed(log: &Path, from: u64, result: i64, users: &[&str]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let got = auth_failed_lines(log, from);
        if users
            .iter()
            .all(|u| got.iter().any(|(gu, gr)| gu == u && *gr == result))
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "mongod did not log result {result} for {users:?}: {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Runs `audit_stream` in a task (poll interval 1 s, cursors in `state`).
fn start_audit(
    connector: Arc<MongodbConnector>,
    t: &TargetConfig,
    state: &Path,
) -> (
    tokio::task::JoinHandle<Result<(), ConnectorError>>,
    tokio::sync::mpsc::Receiver<MaskedEvent>,
) {
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = databastion_core::AuditConfig::local(t, 1, &limits).with_state_dir(state.to_owned());
    let (sink, rx) = EventSink::channel(10_000);
    let task = tokio::spawn(async move { connector.audit_stream(&cfg, &sink).await });
    (task, rx)
}

/// An administrator session declaring `app`.
async fn admin_as(a: &Url, app: &str) -> Session {
    let (_dir, t) = target(a, &a.user, &a.password, &a.auth_source);
    Session::connect_as(&t, Timeouts::new(Duration::from_secs(60)), app)
        .await
        .unwrap()
}

/// A whole-collection read and a filtered one (with [`MARKER`]).
async fn reads(a: &Url, app: &str) {
    let mut s = admin_as(a, app).await;
    run(
        &mut s,
        "app",
        DocBuf::new()
            .str("find", COLLECTION)
            .doc("filter", DocBuf::new())
            .bool("singleBatch", true),
    )
    .await
    .unwrap();
    run(
        &mut s,
        "app",
        DocBuf::new()
            .str("find", COLLECTION)
            .doc("filter", DocBuf::new().str("email", MARKER))
            .bool("singleBatch", true),
    )
    .await
    .unwrap();
    s.close().await;
}

/// Nothing of the marker in the events or the logs.
fn assert_no_marker(events: &[MaskedEvent], logs: &Logs) {
    let all: String = events.iter().map(describe).collect::<Vec<_>>().join("\n");
    assert!(!all.contains("7Qz"), "marker in events");
    assert!(!logs.text().contains("7Qz"), "marker in the logs");
}

/// The agent's own Discovery reads are left out.
fn assert_no_own_reads(events: &[MaskedEvent], own: &str) {
    for e in events {
        let p = e.principal();
        assert!(
            !(p.account_name() == own
                && p.application() == Some("databastion-agent")
                && matches!(e.action(), EventAction::Read)),
            "the agent's own read was reported: {e:?}"
        );
    }
}

#[tokio::test]
async fn audit_from_the_server_log() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let Some(a) = admin() else { return };
    let Some(log) = env_path("DATABASTION_TEST_MONGO_LOG", "mongo-log") else {
        return;
    };
    let extra = format!(
        ", audit_log: {{path: \"{}\", format: server_log}}",
        log.display()
    );
    let (_dir, t) = target_with(&url, &url.user, &url.password, &url.auth_source, &extra);
    let connector = Arc::new(MongodbConnector::new());
    let h = connector.check(&t).await;
    assert!(h.reachable, "{h:?}");
    // Nothing read from the log yet: None until the stream parses a record.
    assert_eq!(h.audit_level, AuditLevel::None, "{:?}", h.detail);
    assert_eq!(connector.audit_source(&t), Some(EventSource::MongodbLog));
    assert!(
        codes(&h.notes).contains(&NoteCode::AuditLimitedPendingFirstRecord.as_str()),
        "{:?}",
        h.notes
    );
    let got = codes(&h.notes);
    assert!(
        got.contains(&NoteCode::AuditSlowOperationsOnly.as_str()),
        "{got:?}"
    );
    assert!(got.iter().all(|c| !c.starts_with("privilege.")), "{got:?}");

    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    // The stream opens the log at its end: let it start first.
    tokio::time::sleep(Duration::from_secs(3)).await;
    reads(&a, "mongodump").await;
    reads(&a, "mongosh 2.3.0").await;
    // Handshakes abandoned by a client (existing accounts, the agent's own
    // included): no auth_failure (e2e flake of #98: mongodump). mongod
    // must have logged them (AuthenticationAbandoned, 337) before the
    // failures below: the stream reads the log in order, so the failures
    // it reports prove it read, and dropped, these lines first.
    let from = std::fs::metadata(&log).unwrap().len();
    abandon_handshake(&url, &a.user).await;
    abandon_handshake(&url, &url.user).await;
    wait_auth_failed(&log, from, 337, &[&a.user, &url.user]).await;
    // Two failed authentications: an unknown account (UserNotFound, 11)
    // and a wrong password on an existing one (AuthenticationFailed, 18).
    let (_d, nobody) = target(&url, "databastion_it_nobody", "wrong-password", "admin");
    assert!(
        Session::connect(&nobody, Timeouts::new(Duration::from_secs(10)))
            .await
            .is_err()
    );
    let (_d, wrong) = target(&url, &a.user, "wrong-password", &a.auth_source);
    assert!(
        Session::connect(&wrong, Timeouts::new(Duration::from_secs(10)))
            .await
            .is_err()
    );
    wait_auth_failed(&log, from, 11, &["databastion_it_nobody"]).await;
    wait_auth_failed(&log, from, 18, &[&a.user]).await;
    // Nothing else failed meanwhile: exactly these four lines.
    let mut logged: Vec<i64> = auth_failed_lines(&log, from)
        .into_iter()
        .map(|(_, r)| r)
        .collect();
    logged.sort_unstable();
    assert_eq!(logged, [11, 18, 337, 337]);
    // The agent's own Discovery.
    let (r, _findings) = scan(&t).await;
    r.unwrap();
    let mut events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(60), |ev| {
        has(ev, COLLECTION, "signature.mongodump")
            && ev
                .iter()
                .filter(|e| e.action() == EventAction::AuthFailure)
                .count()
                >= 2
            && ev.iter().any(|e| {
                e.principal()
                    .application()
                    .is_some_and(|a| a.starts_with("mongosh"))
                    && e.objects()
                        .iter()
                        .any(|o| o.object().as_str() == COLLECTION)
            })
    })
    .await;
    // A little longer for the agent's own reads (they must not come).
    collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
    // Records were read: Limited now.
    let h = connector.check(&t).await;
    assert_eq!(h.audit_level, AuditLevel::Limited, "{:?}", h.detail);
    task.abort();
    let text: Vec<String> = events.iter().map(describe).collect();
    // Interim I2 check (end-of-phase-5 review M1): no ground-truth value in
    // the events as the core would send them, nor in the logs.
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    crate::i2::assert_clean(
        "serialized events",
        &gt,
        "app",
        &crate::i2::serialize_events(&events),
    );
    crate::i2::assert_clean("logs", &gt, "app", &logs.text());
    assert!(has(&events, COLLECTION, "signature.mongodump"), "{text:#?}");
    assert!(
        has(&events, COLLECTION, "shape.full_table_read"),
        "{text:#?}"
    );
    let dump = events
        .iter()
        .find(|e| {
            e.signals()
                .iter()
                .any(|s| s.as_str() == "signature.mongodump")
        })
        .unwrap();
    assert_eq!(dump.principal().account_name(), format!("{}@admin", a.user));
    assert!(dump.rows().is_some_and(|n| n > 0), "{dump:?}");
    assert_eq!(dump.source(), EventSource::MongodbLog);
    // The filtered read by another client: no signature, no shape.
    assert!(events.iter().any(|e| {
        e.principal()
            .application()
            .is_some_and(|a| a.starts_with("mongosh"))
            && e.action() == EventAction::Read
    }));
    assert!(
        events
            .iter()
            .filter(|e| e
                .principal()
                .application()
                .is_some_and(|a| a.starts_with("mongosh")))
            .all(|e| e
                .signals()
                .iter()
                .all(|s| !s.as_str().starts_with("signature.")))
    );
    let failures: Vec<_> = events
        .iter()
        .filter(|e| e.action() == EventAction::AuthFailure)
        .collect();
    // The unknown account and the wrong password (both read after the
    // abandoned handshakes): those are not failures.
    assert_eq!(failures.len(), 2, "{text:#?}");
    assert!(failures.iter().all(|e| !e.principal().send_name()));
    // Exactly the two refused accounts (raw names are held in memory
    // only; the core sends fingerprints), never the abandoned ones alone.
    let mut names: Vec<&str> = failures
        .iter()
        .map(|e| e.principal().account_name())
        .collect();
    names.sort_unstable();
    let mut expected = vec![
        "databastion_it_nobody@admin".to_owned(),
        format!("{}@{}", a.user, a.auth_source),
    ];
    expected.sort_unstable();
    assert_eq!(names, expected);
    assert_no_own_reads(&events, &format!("{}@{}", url.user, url.auth_source));
    assert_no_marker(&events, &logs);
    // The real tool, from inside the container (its own application name).
    let fresh = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &fresh.0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    if real_tool("DUMP") {
        let mut more = Vec::new();
        collect_until(&mut rx, &mut more, Duration::from_secs(60), |ev| {
            ev.iter().any(|e| {
                e.signals()
                    .iter()
                    .any(|s| s.as_str() == "signature.mongodump")
            })
        })
        .await;
        task.abort();
        assert!(
            more.iter().any(|e| e
                .signals()
                .iter()
                .any(|s| s.as_str() == "signature.mongodump")),
            "the real mongodump run was not flagged"
        );
    } else {
        task.abort();
    }
}

/// Recreates the profiler role and account: the ADR-0026 role on `app`
/// plus `find` on `app.system.profile` (ADR-0027 decision 5).
async fn profiler_account(a: &Url) {
    let mut s = admin_session(a).await;
    let _ = run(
        &mut s,
        "admin",
        DocBuf::new().str("dropUser", PROFILER_USER),
    )
    .await;
    let _ = run(
        &mut s,
        "admin",
        DocBuf::new().str("dropRole", PROFILER_ROLE),
    )
    .await;
    run(
        &mut s,
        "admin",
        DocBuf::new()
            .str("createRole", PROFILER_ROLE)
            .array(
                "privileges",
                vec![
                    DocBuf::new()
                        .doc(
                            "resource",
                            DocBuf::new().str("db", "app").str("collection", ""),
                        )
                        .array_str("actions", &["find", "listCollections"]),
                    DocBuf::new()
                        .doc(
                            "resource",
                            DocBuf::new()
                                .str("db", "app")
                                .str("collection", "system.profile"),
                        )
                        .array_str("actions", &["find"]),
                ],
            )
            .array("roles", Vec::new()),
    )
    .await
    .unwrap();
    run(
        &mut s,
        "admin",
        DocBuf::new()
            .str("createUser", PROFILER_USER)
            .str("pwd", IT_PASSWORD)
            .array_str("mechanisms", &["SCRAM-SHA-256"])
            .array(
                "roles",
                vec![DocBuf::new().str("role", PROFILER_ROLE).str("db", "admin")],
            ),
    )
    .await
    .unwrap();
    s.close().await;
}

#[tokio::test]
async fn audit_from_the_profiler() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let Some(a) = admin() else { return };
    profiler_account(&a).await;
    let (_dir, t) = target(&url, PROFILER_USER, IT_PASSWORD, "admin");
    let connector = Arc::new(MongodbConnector::new());
    let h = connector.check(&t).await;
    assert!(h.reachable, "{h:?}");
    assert_eq!(h.audit_level, AuditLevel::None, "{:?}", h.detail);
    assert!(
        codes(&h.notes).contains(&NoteCode::AuditLimitedPendingFirstRecord.as_str()),
        "{:?}",
        h.notes
    );
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbProfiler)
    );
    let got = codes(&h.notes);
    assert!(
        got.contains(&NoteCode::AuditSlowOperationsOnly.as_str()),
        "{got:?}"
    );
    // No stream reads the profiler yet: its grant is over-privilege.
    assert!(
        got.contains(&NoteCode::PrivilegeSystemCollections.as_str()),
        "{got:?}"
    );

    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    // While the stream reads the profiler, the grant is the Audit grant.
    let h = connector.check(&t).await;
    let got = codes(&h.notes);
    assert!(
        !got.contains(&NoteCode::PrivilegeSystemCollections.as_str()),
        "{got:?} ({:?})",
        h.detail
    );
    reads(&a, "mongoexport").await;
    let (r, _findings) = scan(&t).await;
    r.unwrap();
    let mut events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(60), |ev| {
        has(ev, COLLECTION, "signature.mongoexport")
    })
    .await;
    collect_until(&mut rx, &mut events, Duration::from_secs(4), |_| false).await;
    // Entries were read: Limited now.
    let h = connector.check(&t).await;
    assert_eq!(h.audit_level, AuditLevel::Limited, "{:?}", h.detail);
    task.abort();
    let text: Vec<String> = events.iter().map(describe).collect();
    // Interim I2 check (end-of-phase-5 review M1): no ground-truth value in
    // the events as the core would send them, nor in the logs.
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    crate::i2::assert_clean(
        "serialized events",
        &gt,
        "app",
        &crate::i2::serialize_events(&events),
    );
    crate::i2::assert_clean("logs", &gt, "app", &logs.text());
    let export = events
        .iter()
        .find(|e| {
            e.signals()
                .iter()
                .any(|s| s.as_str() == "signature.mongoexport")
        })
        .unwrap_or_else(|| panic!("{text:#?}"));
    assert_eq!(export.source(), EventSource::MongodbProfiler);
    assert_eq!(
        export.principal().account_name(),
        format!("{}@admin", a.user)
    );
    assert!(export.rows().is_some_and(|n| n > 0), "{export:?}");
    assert!(
        has(&events, COLLECTION, "shape.full_table_read"),
        "{text:#?}"
    );
    // The agent's own reads (Discovery, and its polls of system.profile)
    // are left out.
    assert_no_own_reads(&events, &format!("{PROFILER_USER}@admin"));
    assert!(
        events.iter().all(|e| e
            .objects()
            .iter()
            .all(|o| o.object().as_str() != "system.profile")),
        "{text:#?}"
    );
    assert_no_marker(&events, &logs);
    // Phase 7: the profiler position is persisted. A read while the agent
    // is stopped is reported after its restart (a new connector, the same
    // state directory).
    let saved = std::fs::read(state.0.join(format!("{}.mongodb_profiler.cursor", t.id)))
        .expect("profiler cursor saved");
    assert!(
        String::from_utf8_lossy(&saved).contains("\"app\""),
        "{}",
        String::from_utf8_lossy(&saved)
    );
    reads(&a, "mongoexport").await;
    let restarted = Arc::new(MongodbConnector::new());
    let (task, mut rx) = start_audit(Arc::clone(&restarted), &t, &state.0);
    let mut after = Vec::new();
    collect_until(&mut rx, &mut after, Duration::from_secs(60), |ev| {
        has(ev, COLLECTION, "signature.mongoexport")
    })
    .await;
    task.abort();
    let text: Vec<String> = after.iter().map(describe).collect();
    assert!(
        has(&after, COLLECTION, "signature.mongoexport"),
        "a read while the agent was stopped: {text:#?}"
    );
    assert_no_marker(&after, &logs);
    // The real tool, from inside the container.
    let fresh = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &fresh.0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    if real_tool("EXPORT") {
        let mut more = Vec::new();
        collect_until(&mut rx, &mut more, Duration::from_secs(60), |ev| {
            ev.iter().any(|e| {
                e.signals()
                    .iter()
                    .any(|s| s.as_str() == "signature.mongoexport")
            })
        })
        .await;
        assert!(
            more.iter().any(|e| e
                .signals()
                .iter()
                .any(|s| s.as_str() == "signature.mongoexport")),
            "the real mongoexport run was not flagged"
        );
    }
    task.abort();
    let mut s = admin_session(&a).await;
    let _ = run(
        &mut s,
        "admin",
        DocBuf::new().str("dropUser", PROFILER_USER),
    )
    .await;
    let _ = run(
        &mut s,
        "admin",
        DocBuf::new().str("dropRole", PROFILER_ROLE),
    )
    .await;
    s.close().await;
}

/// A `mongodb://` URL from `var` (prerequisite `key`).
fn env_url(var: &str, key: &str) -> Option<Url> {
    match std::env::var(var) {
        Ok(u) if !u.is_empty() => Some(super::parse_url(&u).expect(var)),
        _ => {
            skip(key, &format!("{var} is not set"));
            None
        }
    }
}

/// Phase 7 (P5-B follow-up): the `auditLog` source against a real Percona
/// Server for MongoDB (dev `psmdb` service: JSON file,
/// `auditAuthorizationSuccess`), not only recorded samples.
#[tokio::test]
async fn audit_from_the_percona_audit_log() {
    let _serial = SERIAL.lock().await;
    let Some(url) = env_url("DATABASTION_TEST_PSMDB_URL", "psmdb-audit") else {
        return;
    };
    let Some(a) = env_url("DATABASTION_TEST_PSMDB_ADMIN_URL", "psmdb-audit") else {
        return;
    };
    let Some(log) = env_path("DATABASTION_TEST_PSMDB_AUDIT_LOG", "psmdb-audit") else {
        return;
    };
    let extra = format!(
        ", audit_log: {{path: \"{}\", format: audit_log}}",
        log.display()
    );
    let (_dir, t) = target_with(&url, &url.user, &url.password, &url.auth_source, &extra);
    let connector = Arc::new(MongodbConnector::new());
    let h = connector.check(&t).await;
    assert!(h.reachable, "{h:?}");
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbAuditLog),
        "{:?}",
        h.detail
    );
    let got = codes(&h.notes);
    assert!(got.iter().all(|c| !c.starts_with("privilege.")), "{got:?}");

    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    // The stream opens the log at its end: let it start first.
    tokio::time::sleep(Duration::from_secs(3)).await;
    reads(&a, "mongodump").await;
    reads(&a, "mongosh 2.3.0").await;
    // A failed authentication.
    let (_d, wrong) = target(&url, "databastion_it_nobody", "wrong-password", "admin");
    assert!(
        Session::connect(&wrong, Timeouts::new(Duration::from_secs(10)))
            .await
            .is_err()
    );
    // The agent's own Discovery.
    let (r, _findings) = scan(&t).await;
    r.unwrap();
    let admin_name = format!("{}@admin", a.user);
    let mut events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(60), |ev| {
        ev.iter().any(|e| e.action() == EventAction::AuthFailure)
            && ev.iter().any(|e| {
                e.action() == EventAction::Read
                    && e.principal().account_name() == admin_name
                    && e.objects()
                        .iter()
                        .any(|o| o.object().as_str() == COLLECTION)
            })
    })
    .await;
    // A little longer for the agent's own reads (they must not come).
    collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
    // A successful authCheck was read: Partial (never Full, ADR-0027).
    let h = connector.check(&t).await;
    assert_eq!(h.audit_level, AuditLevel::Partial, "{:?}", h.detail);
    task.abort();
    let text: Vec<String> = events.iter().map(describe).collect();
    assert!(
        events
            .iter()
            .all(|e| e.source() == EventSource::MongodbAuditLog),
        "{text:#?}"
    );
    assert!(
        events.iter().any(|e| e.action() == EventAction::Read
            && e.principal().account_name() == admin_name
            && e.objects()
                .iter()
                .any(|o| o.object().as_str() == COLLECTION)),
        "{text:#?}"
    );
    let failure = events
        .iter()
        .find(|e| e.action() == EventAction::AuthFailure)
        .unwrap_or_else(|| panic!("no failed authentication: {text:#?}"));
    assert!(!failure.principal().send_name());
    // Whether the server records the client metadata (the tool's
    // application name) in its auditLog: reported, not required.
    if !has(&events, COLLECTION, "signature.mongodump") {
        eprintln!(
            "note: no signature.mongodump from this server's auditLog (client metadata not audited?)"
        );
    }
    // I2: no ground-truth value in the events as the core would send them,
    // nor in the logs.
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    crate::i2::assert_clean(
        "serialized events",
        &gt,
        "app",
        &crate::i2::serialize_events(&events),
    );
    crate::i2::assert_clean("logs", &gt, "app", &logs.text());
    assert_no_own_reads(&events, &format!("{}@{}", url.user, url.auth_source));
    assert_no_marker(&events, &logs);
}
