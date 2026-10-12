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

/// Failed authentication lines of the server log after byte `from`, as
/// `(user, result)` (test accounts only): "Failed to authenticate"
/// (5286307, MongoDB 7.0+, numeric `result`) and "Authentication failed"
/// (20249, MongoDB 5.0 and 6.0, a status string in `error`, mapped to its
/// code here).
fn auth_failed_lines(log: &Path, from: u64) -> Vec<(String, i64)> {
    let bytes = std::fs::read(log).unwrap();
    let start = usize::try_from(from).unwrap().min(bytes.len());
    bytes[start..]
        .split(|b| *b == b'\n')
        .filter_map(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
        .filter_map(|v| {
            let attr = &v["attr"];
            if v["id"] == 5_286_307 {
                Some((
                    attr["user"].as_str().unwrap_or_default().to_owned(),
                    attr["result"].as_i64().unwrap_or_default(),
                ))
            } else if v["id"] == 20_249 {
                let error = attr["error"].as_str().unwrap_or_default();
                let code = [
                    ("UserNotFound:", 11),
                    ("AuthenticationFailed:", 18),
                    ("AuthenticationAbandoned:", 337),
                ]
                .iter()
                .find(|(name, _)| error.starts_with(name))
                .map_or(-1, |(_, code)| *code);
                Some((
                    attr["principalName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    code,
                ))
            } else {
                None
            }
        })
        .collect()
}

/// The server's major version (`buildInfo`).
async fn server_major(a: &Url) -> u32 {
    let mut s = admin_session(a).await;
    let build = crate::check::build_info(&mut s).await.unwrap();
    s.close().await;
    build
        .version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or_else(|| panic!("unexpected server version {:?}", build.version))
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
    // included): no auth_failure (e2e flake of #98: mongodump). MongoDB
    // 7.0+ logs them ("Failed to authenticate", AuthenticationAbandoned,
    // 337) and must have done so before the failures below: the stream
    // reads the log in order, so the failures it reports prove it read,
    // and dropped, these lines first. MongoDB 5.0 and 6.0 log them at
    // debug level 3 only: nothing at the default verbosity (checked below,
    // once the later failures are logged).
    let logs_abandoned = server_major(&a).await >= 7;
    let from = std::fs::metadata(&log).unwrap().len();
    abandon_handshake(&url, &a.user).await;
    abandon_handshake(&url, &url.user).await;
    if logs_abandoned {
        wait_auth_failed(&log, from, 337, &[&a.user, &url.user]).await;
    }
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
    // Nothing else failed meanwhile: exactly these four lines (7.0+), or
    // only the two refused credentials (5.0, 6.0: no abandoned line).
    let mut logged: Vec<i64> = auth_failed_lines(&log, from)
        .into_iter()
        .map(|(_, r)| r)
        .collect();
    logged.sort_unstable();
    if logs_abandoned {
        assert_eq!(logged, [11, 18, 337, 337]);
    } else {
        assert_eq!(logged, [11, 18]);
    }
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

/// A read whose error text shows a value read: `$toInt` of an e-mail
/// address fails with `ConversionFailure` (241), "Failed to parse number
/// '<the address>' in $convert", and returns no document.
fn telling_read() -> DocBuf {
    DocBuf::new().str("find", COLLECTION).doc(
        "filter",
        DocBuf::new().doc(
            "$expr",
            DocBuf::new().array(
                "$eq",
                vec![DocBuf::new().str("$toInt", "$email"), DocBuf::new()],
            ),
        ),
    )
}

/// A read stopped by its `maxTimeMS` (`MaxTimeMSExpired`, 50): no value
/// in its text, and no JavaScript (a `$where` would always be reported,
/// ADR-0027 refinement of 2026-10-12): a long expression per document.
fn quiet_read() -> DocBuf {
    let sum = DocBuf::new().doc(
        "$reduce",
        DocBuf::new()
            .doc(
                "input",
                DocBuf::new().list("$range", DocBuf::new().i32("0", 0).i32("1", 200_000)),
            )
            .i32("initialValue", 0)
            .doc(
                "in",
                DocBuf::new().list("$add", DocBuf::new().str("0", "$$value").i32("1", 1)),
            ),
    );
    DocBuf::new()
        .str("find", COLLECTION)
        .doc(
            "filter",
            DocBuf::new().doc(
                "$expr",
                DocBuf::new().list("$gt", DocBuf::new().doc("0", sum).i32("1", 0)),
            ),
        )
        .i32("maxTimeMS", 5)
}

/// Runs `command` on `app`, which must fail with `code`.
async fn fails_with(s: &mut Session, command: DocBuf, code: i32) {
    let r = run(s, "app", command).await;
    assert_eq!(r.err(), Some(Some(code)), "unexpected outcome");
}

/// Phase 8 follow-ups (security review of #197, L1): failed reads that
/// return no document, against a running stream of `t` (whose account is
/// `own`): a failure whose text shows the value read is always reported,
/// from another account and from the agent's own identity; a quiet one
/// (its `maxTimeMS`) of the agent's is left out; another account's quiet
/// one is an ordinary event. No value of the error texts in the events or
/// the logs.
async fn failed_reads_flow(
    connector: &Arc<MongodbConnector>,
    t: &TargetConfig,
    a: &Url,
    own: &str,
    source: EventSource,
) {
    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(connector), t, &state.0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut agent = Session::connect(t, Timeouts::new(Duration::from_secs(60)))
        .await
        .unwrap();
    // The agent's identity: a quiet failure first (left out), then one
    // that shows a value (reported).
    fails_with(&mut agent, quiet_read(), 50).await;
    fails_with(&mut agent, telling_read(), 241).await;
    agent.close().await;
    let mut other = admin_as(a, "mongosh 2.3.0").await;
    fails_with(&mut other, quiet_read(), 50).await;
    fails_with(&mut other, telling_read(), 241).await;
    other.close().await;
    let admin_name = format!("{}@{}", a.user, a.auth_source);
    let from = |name: &str, ev: &MaskedEvent| {
        ev.principal().account_name() == name
            && ev.action() == EventAction::Read
            && ev
                .objects()
                .iter()
                .any(|o| o.object().as_str() == COLLECTION)
    };
    let mut events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(60), |ev| {
        ev.iter().any(|e| from(&admin_name, e) && e.always_report())
            && ev.iter().any(|e| from(own, e) && e.always_report())
    })
    .await;
    collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
    task.abort();
    let text: Vec<String> = events.iter().map(describe).collect();
    assert!(events.iter().all(|e| e.source() == source), "{text:#?}");
    // Another account: both failures are events; the one that may show
    // values is always reported, the quiet one is not.
    let theirs: Vec<&MaskedEvent> = events.iter().filter(|e| from(&admin_name, e)).collect();
    assert_eq!(theirs.len(), 2, "{text:#?}");
    assert_eq!(
        theirs.iter().filter(|e| e.always_report()).count(),
        1,
        "{text:#?}"
    );
    assert!(theirs.iter().all(|e| e.rows() == Some(0)), "{text:#?}");
    // The agent's identity: only the failure that may show values.
    let ours: Vec<&MaskedEvent> = events.iter().filter(|e| from(own, e)).collect();
    assert_eq!(ours.len(), 1, "{text:#?}");
    assert!(ours[0].always_report());
    assert_eq!(ours[0].principal().application(), Some("databastion-agent"));
    assert_eq!(ours[0].rows(), Some(0));
    // I2: the error texts quote seeded addresses; none in the events as
    // the core would send them, nor in the logs.
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    crate::i2::assert_clean(
        "serialized events",
        &gt,
        "app",
        &crate::i2::serialize_events(&events),
    );
    crate::i2::assert_clean("logs", &gt, "app", &logs.text());
    assert!(
        !text.iter().any(|t| t.contains("@example.")),
        "an address in the events"
    );
    assert!(!logs.text().contains("@example."), "an address in the logs");
}

#[tokio::test]
async fn failed_reads_without_documents_from_the_server_log() {
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
    assert!(connector.check(&t).await.reachable);
    let from = std::fs::metadata(&log).unwrap().len();
    failed_reads_flow(
        &connector,
        &t,
        &a,
        &format!("{}@{}", url.user, url.auth_source),
        EventSource::MongodbLog,
    )
    .await;
    // The premise: the server logged the value in the failure's text
    // (never printed here).
    let bytes = std::fs::read(&log).unwrap();
    let start = usize::try_from(from).unwrap().min(bytes.len());
    let shown = bytes[start..]
        .split(|b| *b == b'\n')
        .filter_map(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
        .filter(|v| v["attr"]["errCode"] == 241)
        .any(|v| {
            v["attr"]["errMsg"]
                .as_str()
                .is_some_and(|m| m.contains("@example."))
        });
    assert!(shown, "the server log shows no value in the error text");
}

#[tokio::test]
async fn failed_reads_without_documents_from_the_profiler() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let Some(a) = admin() else { return };
    profiler_account(&a).await;
    let (_dir, t) = target(&url, PROFILER_USER, IT_PASSWORD, "admin");
    let connector = Arc::new(MongodbConnector::new());
    assert!(connector.check(&t).await.reachable);
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbProfiler)
    );
    failed_reads_flow(
        &connector,
        &t,
        &a,
        &format!("{PROFILER_USER}@admin"),
        EventSource::MongodbProfiler,
    )
    .await;
    drop_profiler_account(&a).await;
}

/// The same on Percona Server for MongoDB (dev `psmdb`), through its
/// profiler (turned on for `app` here: the service runs with the
/// `auditLog` only).
#[tokio::test]
async fn failed_reads_without_documents_on_percona_server_for_mongodb() {
    let _serial = SERIAL.lock().await;
    let Some(url) = env_url("DATABASTION_TEST_PSMDB_URL", "psmdb-audit") else {
        return;
    };
    let Some(a) = env_url("DATABASTION_TEST_PSMDB_ADMIN_URL", "psmdb-audit") else {
        return;
    };
    profiler_account(&a).await;
    let mut s = admin_session(&a).await;
    run(
        &mut s,
        "app",
        DocBuf::new().i32("profile", 1).i32("slowms", 0),
    )
    .await
    .unwrap();
    s.close().await;
    let (_dir, t) = target(&url, PROFILER_USER, IT_PASSWORD, "admin");
    let connector = Arc::new(MongodbConnector::new());
    assert!(connector.check(&t).await.reachable);
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbProfiler)
    );
    failed_reads_flow(
        &connector,
        &t,
        &a,
        &format!("{PROFILER_USER}@admin"),
        EventSource::MongodbProfiler,
    )
    .await;
    let mut s = admin_session(&a).await;
    run(&mut s, "app", DocBuf::new().i32("profile", 0))
        .await
        .unwrap();
    s.close().await;
    drop_profiler_account(&a).await;
}

async fn drop_profiler_account(a: &Url) {
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
    s.close().await;
}

// ---- Server-side JavaScript (security review of #207, M3). ----

/// A `$function` operator whose code holds [`MARKER`] (never copied).
fn js_function(body: &str, args: &[&str]) -> DocBuf {
    DocBuf::new().doc(
        "$function",
        DocBuf::new()
            .str("body", body)
            .array_str("args", args)
            .str("lang", "js"),
    )
}

/// A `$where` that sleeps past its `maxTimeMS` (`MaxTimeMSExpired`, 50):
/// the "slow" outcome of a one-bit oracle.
fn js_where_timeout() -> DocBuf {
    DocBuf::new()
        .str("find", COLLECTION)
        .doc(
            "filter",
            DocBuf::new().str("$where", "sleep(100) || 'needle-7Qz-FAKE'"),
        )
        .i32("maxTimeMS", 50)
}

/// A `$function` match that returns no document: the "fast" outcome.
fn js_function_match() -> DocBuf {
    DocBuf::new()
        .str("aggregate", COLLECTION)
        .array(
            "pipeline",
            vec![DocBuf::new().doc(
                "$match",
                DocBuf::new().doc(
                    "$expr",
                    js_function(
                        "function(e) { return e === 'needle-7Qz-FAKE'; }",
                        &["$email"],
                    ),
                ),
            )],
        )
        .doc("cursor", DocBuf::new())
}

/// `$function` in a `$lookup` sub-pipeline (one document returned).
fn js_lookup() -> DocBuf {
    let sub = DocBuf::new().doc(
        "$match",
        DocBuf::new().doc("$expr", js_function("function() { return false; }", &[])),
    );
    DocBuf::new()
        .str("aggregate", COLLECTION)
        .array(
            "pipeline",
            vec![
                DocBuf::new().i32("$limit", 1),
                DocBuf::new().doc(
                    "$lookup",
                    DocBuf::new()
                        .str("from", COLLECTION)
                        .array("pipeline", vec![sub])
                        .str("as", "x"),
                ),
            ],
        )
        .doc("cursor", DocBuf::new())
}

/// No JavaScript, but nested past the detection bound (`$and` of `$and`
/// …): fails closed. No document.
fn too_deep() -> DocBuf {
    let mut e = DocBuf::new().list("$eq", DocBuf::new().i32("0", 1).i32("1", 0));
    for _ in 0..40 {
        e = DocBuf::new().list("$and", DocBuf::new().doc("0", e));
    }
    DocBuf::new()
        .str("find", COLLECTION)
        .doc("filter", DocBuf::new().doc("$expr", e))
}

/// Runs the operations (their outcomes checked); `through_view`: also a
/// read through [`JS_VIEW`].
async fn javascript_ops(s: &mut Session, through_view: bool) {
    fails_with(s, js_where_timeout(), 50).await;
    for command in [
        js_function_match(),
        js_lookup(),
        too_deep(),
        js_internal_emit(),
    ] {
        run(s, "app", command).await.unwrap();
    }
    if through_view {
        run(s, "app", js_union_with_view()).await.unwrap();
    }
}

/// A view of the collection whose pipeline runs JavaScript (no document).
const JS_VIEW: &str = "databastion_it_js_view";

async fn create_js_view(a: &Url) {
    let mut s = admin_session(a).await;
    let _ = run(&mut s, "app", DocBuf::new().str("drop", JS_VIEW)).await;
    run(
        &mut s,
        "app",
        DocBuf::new()
            .str("create", JS_VIEW)
            .str("viewOn", COLLECTION)
            .array(
                "pipeline",
                vec![DocBuf::new().doc(
                    "$match",
                    DocBuf::new().doc("$expr", js_function("function() { return false; }", &[])),
                )],
            ),
    )
    .await
    .unwrap();
    s.close().await;
}

async fn drop_js_view(a: &Url) {
    let mut s = admin_session(a).await;
    let _ = run(&mut s, "app", DocBuf::new().str("drop", JS_VIEW)).await;
    s.close().await;
}

/// `$_internalJsEmit`, what `mapReduce` compiles to, written by a client
/// (accepted by MongoDB 8.0; security review of #216, H1). One document.
fn js_internal_emit() -> DocBuf {
    DocBuf::new()
        .str("aggregate", COLLECTION)
        .array(
            "pipeline",
            vec![
                DocBuf::new().i32("$limit", 1),
                DocBuf::new().doc(
                    "$project",
                    DocBuf::new().doc(
                        "x",
                        DocBuf::new().doc(
                            "$_internalJsEmit",
                            DocBuf::new()
                                .str("eval", "function() { emit(this._id, 'needle-7Qz-FAKE'); }")
                                .str("this", "$$ROOT"),
                        ),
                    ),
                ),
            ],
        )
        .doc("cursor", DocBuf::new())
}

/// A `$unionWith` into [`JS_VIEW`]: the command names only the view; the
/// server shows its pipeline in `resolvedViews`. One document.
fn js_union_with_view() -> DocBuf {
    DocBuf::new()
        .str("aggregate", COLLECTION)
        .array(
            "pipeline",
            vec![
                DocBuf::new().i32("$limit", 1),
                DocBuf::new().doc("$unionWith", DocBuf::new().str("coll", JS_VIEW)),
            ],
        )
        .doc("cursor", DocBuf::new())
}

/// The operations of [`javascript_ops`] from the agent's identity and
/// from another account, against a running stream of `t` (account
/// `own`): each is a read of the collection, always reported (none is left
/// out as the agent's own), with 0 documents (1 for the `$lookup`, the
/// `$_internalJsEmit` and the view read) when the source counts them. No
/// JavaScript code (it holds the marker) in the events or the logs.
async fn javascript_flow(
    connector: &Arc<MongodbConnector>,
    t: &TargetConfig,
    a: &Url,
    own: &str,
    source: EventSource,
) {
    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    // The `auditLog` shows a view's name only (a documented residual).
    let through_view = source != EventSource::MongodbAuditLog;
    let n = if through_view { 6 } else { 5 };
    create_js_view(a).await;
    let (task, mut rx) = start_audit(Arc::clone(connector), t, &state.0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut agent = Session::connect(t, Timeouts::new(Duration::from_secs(60)))
        .await
        .unwrap();
    javascript_ops(&mut agent, through_view).await;
    agent.close().await;
    let mut other = admin_as(a, "mongosh 2.3.0").await;
    javascript_ops(&mut other, through_view).await;
    other.close().await;
    drop_js_view(a).await;
    let admin_name = format!("{}@{}", a.user, a.auth_source);
    let from = |name: &str, ev: &MaskedEvent| {
        ev.principal().account_name() == name
            && ev
                .objects()
                .iter()
                .any(|o| o.object().as_str() == COLLECTION)
    };
    let mut events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(60), |ev| {
        ev.iter().filter(|e| from(&admin_name, e)).count() >= n
            && ev.iter().filter(|e| from(own, e)).count() >= n
    })
    .await;
    collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
    task.abort();
    let text: Vec<String> = events.iter().map(describe).collect();
    assert!(events.iter().all(|e| e.source() == source), "{text:#?}");
    for name in [admin_name.as_str(), own] {
        let theirs: Vec<&MaskedEvent> = events.iter().filter(|e| from(name, e)).collect();
        assert_eq!(theirs.len(), n, "{name}: {text:#?}");
        assert!(
            theirs
                .iter()
                .all(|e| e.always_report() && e.action() == EventAction::Read),
            "{name}: {text:#?}"
        );
        if source == EventSource::MongodbAuditLog {
            // No count on this source.
            assert!(theirs.iter().all(|e| e.rows().is_none()), "{text:#?}");
        } else {
            let mut rows: Vec<Option<u64>> = theirs.iter().map(|e| e.rows()).collect();
            rows.sort_unstable();
            assert_eq!(
                rows,
                [Some(0), Some(0), Some(0), Some(1), Some(1), Some(1)],
                "{name}: {text:#?}"
            );
        }
    }
    // The `auditLog` names the application only when the server audits the
    // client metadata (`audit_from_the_percona_audit_log`).
    if source != EventSource::MongodbAuditLog {
        let ours = events.iter().find(|e| from(own, e)).unwrap();
        assert_eq!(ours.principal().application(), Some("databastion-agent"));
    }
    // I2: no ground-truth value and no JavaScript code in the events as the
    // core would send them, nor in the logs.
    let gt: serde_json::Value =
        serde_json::from_str(include_str!("../../../../dev/ground-truth.json")).unwrap();
    crate::i2::assert_clean(
        "serialized events",
        &gt,
        "app",
        &crate::i2::serialize_events(&events),
    );
    crate::i2::assert_clean("logs", &gt, "app", &logs.text());
    assert_no_marker(&events, &logs);
    for code in ["sleep(", "function(", "$where", "$function"] {
        assert!(
            !text.iter().any(|t| t.contains(code)),
            "{code} in the events"
        );
        assert!(!logs.text().contains(code), "{code} in the logs");
    }
}

#[tokio::test]
async fn javascript_from_the_server_log() {
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
    assert!(connector.check(&t).await.reachable);
    javascript_flow(
        &connector,
        &t,
        &a,
        &format!("{}@{}", url.user, url.auth_source),
        EventSource::MongodbLog,
    )
    .await;
}

#[tokio::test]
async fn javascript_from_the_profiler() {
    let _serial = SERIAL.lock().await;
    let Some(url) = server() else { return };
    let Some(a) = admin() else { return };
    profiler_account(&a).await;
    let (_dir, t) = target(&url, PROFILER_USER, IT_PASSWORD, "admin");
    let connector = Arc::new(MongodbConnector::new());
    assert!(connector.check(&t).await.reachable);
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbProfiler)
    );
    javascript_flow(
        &connector,
        &t,
        &a,
        &format!("{PROFILER_USER}@admin"),
        EventSource::MongodbProfiler,
    )
    .await;
    drop_profiler_account(&a).await;
}

/// The server computes the `js` flag of the projection: the forms of the
/// ADR-0027 refinement of 2026-10-12, the depth bound, truncated
/// commands (cut, or whole with the name in their text, `{ insert: `
/// excepted), a cut that splits a UTF-8 character (byte operators only),
/// and the agent's own poll. Checked against what the dev server
/// recorded, by reading the flag the projection computes for entries
/// marked by a `comment`.
#[tokio::test]
async fn the_profiler_projection_flags_javascript() {
    let _serial = SERIAL.lock().await;
    let Some(a) = admin() else { return };
    let mut s = admin_session(&a).await;
    let f = || js_function("function() { return false; }", &[]);
    let nest = |n: usize, inner: DocBuf| {
        let mut e = inner;
        for _ in 0..n {
            e = DocBuf::new().list("$and", DocBuf::new().doc("0", e));
        }
        e
    };
    let big = |n: usize, item: &str| {
        let mut l = DocBuf::new();
        for i in 0..n {
            l = l.str(&i.to_string(), item);
        }
        l
    };
    let ints = |n: usize| {
        let mut l = DocBuf::new();
        for i in 0..n {
            l = l.i32(&i.to_string(), i32::try_from(i % 10).unwrap());
        }
        l
    };
    let find = |filter: DocBuf| DocBuf::new().str("find", COLLECTION).doc("filter", filter);
    let euros = |pad: &str| {
        find(DocBuf::new().str("pad", pad).doc(
            "email",
            DocBuf::new().list(
                "$nin",
                big(6000, "\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}"),
            ),
        ))
    };
    let agg = |stages: Vec<DocBuf>| {
        DocBuf::new()
            .str("aggregate", COLLECTION)
            .array("pipeline", stages)
            .doc("cursor", DocBuf::new())
    };
    // (comment, command, expected flag)
    let cases: Vec<(&str, DocBuf, bool)> = vec![
        ("plain", find(DocBuf::new().str("email", "$where")), false),
        ("where", find(DocBuf::new().str("$where", "false")), true),
        ("function", find(DocBuf::new().doc("$expr", f())), true),
        (
            "accumulator",
            agg(vec![
                DocBuf::new().doc(
                    "$group",
                    DocBuf::new().null("_id").doc(
                        "n",
                        DocBuf::new().doc(
                            "$accumulator",
                            DocBuf::new()
                                .str("init", "function() { return 0; }")
                                .str("accumulate", "function(s) { return s; }")
                                .array("accumulateArgs", Vec::new())
                                .str("merge", "function(a, b) { return a; }")
                                .str("lang", "js"),
                        ),
                    ),
                ),
            ]),
            true,
        ),
        (
            "facet",
            agg(vec![DocBuf::new().doc(
                "$facet",
                DocBuf::new().array(
                    "a",
                    vec![DocBuf::new().doc("$match", DocBuf::new().doc("$expr", f()))],
                ),
            )]),
            true,
        ),
        (
            "projection",
            DocBuf::new()
                .str("find", COLLECTION)
                .doc("filter", DocBuf::new())
                .doc("projection", DocBuf::new().doc("e", f()))
                .i32("limit", 1),
            true,
        ),
        (
            "mapreduce-explain",
            DocBuf::new()
                .doc(
                    "explain",
                    DocBuf::new()
                        .str("mapReduce", COLLECTION)
                        .str("map", "function() { emit(1, 1); }")
                        .str("reduce", "function(k, v) { return 1; }")
                        .doc("out", DocBuf::new().i32("inline", 1)),
                )
                .str("verbosity", "queryPlanner"),
            true,
        ),
        // At the bound: keys at depth 63 examined; a container at 64 not.
        (
            "deep-ok",
            find(DocBuf::new().doc(
                "$expr",
                nest(
                    29,
                    DocBuf::new().list("$eq", DocBuf::new().i32("0", 1).i32("1", 0)),
                ),
            )),
            false,
        ),
        (
            "deep-js",
            find(DocBuf::new().doc("$expr", nest(29, f()))),
            true,
        ),
        (
            "deep-over",
            find(DocBuf::new().doc(
                "$expr",
                nest(
                    31,
                    DocBuf::new().list("$eq", DocBuf::new().i32("0", 1).i32("1", 0)),
                ),
            )),
            true,
        ),
        // Truncated by the profiler (over 50 KiB): cut, the name lost.
        (
            "cut",
            find(
                DocBuf::new()
                    .doc("email", DocBuf::new().list("$nin", big(6000, "x-padding")))
                    .str("$where", "false"),
            ),
            true,
        ),
        // Truncated, cut inside a 3-byte UTF-8 character (one of the
        // three pads splits one).
        ("cut-utf8-0", euros(""), true),
        ("cut-utf8-1", euros("x"), true),
        ("cut-utf8-2", euros("xx"), true),
        // Truncated but whole (its text is shorter than its BSON): the
        // name is in the text, or not.
        (
            "whole-js",
            find(
                DocBuf::new()
                    .str("$where", "false")
                    .doc("n", DocBuf::new().list("$nin", ints(6000))),
            ),
            true,
        ),
        (
            "whole-plain",
            find(DocBuf::new().doc("n", DocBuf::new().list("$nin", ints(6000)))),
            false,
        ),
        // `$_internalJs*` (security review of #216, H1): accepted by the
        // server from a client.
        ("internal-emit", js_internal_emit(), true),
        (
            "internal-reduce",
            agg(vec![
                DocBuf::new().doc(
                    "$group",
                    DocBuf::new().null("_id").doc(
                        "x",
                        DocBuf::new().doc(
                            "$_internalJsReduce",
                            DocBuf::new()
                                .doc("data", DocBuf::new().i32("k", 1).i32("v", 1))
                                .str("eval", "function(k, v) { return 1; }"),
                        ),
                    ),
                ),
            ]),
            true,
        ),
        // Views: their pipeline is in `resolvedViews`, through a view of a
        // view too (`$lookup`, `$unionWith`).
        (
            "view-plain",
            DocBuf::new()
                .str("find", PLAIN_VIEW)
                .doc("filter", DocBuf::new()),
            false,
        ),
        (
            "view-js-lookup",
            agg(vec![
                DocBuf::new().i32("$limit", 1),
                DocBuf::new().doc(
                    "$lookup",
                    DocBuf::new()
                        .str("from", JS_VIEW)
                        .str("localField", "_id")
                        .str("foreignField", "_id")
                        .str("as", "x"),
                ),
            ]),
            true,
        ),
        ("view-js-union", js_union_with_view(), true),
        (
            "view-js-of-view",
            DocBuf::new()
                .str("find", VIEW_OF_JS_VIEW)
                .doc("filter", DocBuf::new()),
            true,
        ),
        // Walked fields over 64 KiB together (a large view pipeline): not
        // walked, JavaScript (M1).
        (
            "view-big",
            DocBuf::new()
                .str("find", BIG_VIEW)
                .doc("filter", DocBuf::new()),
            true,
        ),
        // A cursor opened without JavaScript.
        (
            "getmore-open",
            find(DocBuf::new()).i32("batchSize", 1),
            false,
        ),
    ];
    // Views (dropped at the end).
    for v in [VIEW_OF_JS_VIEW, JS_VIEW, PLAIN_VIEW, BIG_VIEW] {
        let _ = run(&mut s, "app", DocBuf::new().str("drop", v)).await;
    }
    let view = |name: &str, on: &str, stages: Vec<DocBuf>| {
        DocBuf::new()
            .str("create", name)
            .str("viewOn", on)
            .array("pipeline", stages)
    };
    for v in [
        view(
            JS_VIEW,
            COLLECTION,
            vec![DocBuf::new().doc("$match", DocBuf::new().doc("$expr", f()))],
        ),
        view(
            VIEW_OF_JS_VIEW,
            JS_VIEW,
            vec![DocBuf::new().i32("$limit", 1)],
        ),
        view(PLAIN_VIEW, COLLECTION, vec![DocBuf::new().i32("$limit", 1)]),
        view(
            BIG_VIEW,
            COLLECTION,
            vec![DocBuf::new().doc(
                "$match",
                DocBuf::new().doc("email", DocBuf::new().list("$nin", big(8000, "x-padding"))),
            )],
        ),
    ] {
        run(&mut s, "app", v).await.unwrap();
    }
    // The dev server's level (1, `slowms` 0) is restored at the end.
    let before = run(&mut s, "app", DocBuf::new().i32("profile", -1))
        .await
        .unwrap();
    let before = crate::bson::Doc::new(&before).unwrap();
    let was = i32::try_from(before.int("was").unwrap().unwrap()).unwrap();
    let slowms = i32::try_from(before.int("slowms").unwrap().unwrap()).unwrap();
    run(&mut s, "app", DocBuf::new().i32("profile", 2))
        .await
        .unwrap();
    let expected: Vec<(&str, bool)> = cases.iter().map(|(c, _, js)| (*c, *js)).collect();
    let names: Vec<String> = expected.iter().map(|(c, _)| format!("js-it-{c}")).collect();
    let names: Vec<String> = names
        .into_iter()
        .chain(
            ["js-it-getmore-plain", "js-it-near-a", "js-it-near-b"]
                .iter()
                .map(|c| (*c).to_owned()),
        )
        .collect();
    let comments: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut expected = expected;
    let mut cursor = None;
    for (comment, command, _) in cases {
        // Failures (the `$where` ones) are recorded too.
        let reply = run(
            &mut s,
            "app",
            command.str("comment", &format!("js-it-{comment}")),
        )
        .await;
        if comment == "getmore-open" {
            let reply = reply.unwrap();
            let d = crate::bson::Doc::new(&reply).unwrap();
            cursor = d.doc("cursor").unwrap().unwrap().int("id").unwrap();
        }
    }
    // A getMore of a cursor opened without JavaScript: its opening command
    // is in `originatingCommand`, so it does not count (L1).
    let id = cursor.filter(|id| *id != 0).expect("an open cursor");
    run(
        &mut s,
        "app",
        DocBuf::new()
            .i64("getMore", id)
            .str("collection", COLLECTION)
            .i32("batchSize", 1)
            .str("comment", "js-it-getmore-plain"),
    )
    .await
    .unwrap();
    let _ = run(
        &mut s,
        "app",
        DocBuf::new()
            .str("killCursors", COLLECTION)
            .array_i64("cursors", &[id]),
    )
    .await;
    expected.push(("getmore-plain", false));
    // A whole truncated text within 16 bytes of the cut length (L2): the
    // probe's text length, then the same command padded to 51 190 bytes.
    // The text abbreviates long strings: the length is tuned with
    // integers (three bytes each) and a short string.
    let padded = |k: usize, r: usize, comment: &str| {
        let mut ones = DocBuf::new();
        for i in 0..k {
            ones = ones.i32(&i.to_string(), 1);
        }
        find(
            DocBuf::new()
                .str("pad", &"p".repeat(r))
                .doc("n", DocBuf::new().list("$nin", ints(6000)))
                .doc("m", DocBuf::new().list("$nin", ones)),
        )
        .str("comment", comment)
    };
    let length = |comment: &str| {
        DocBuf::new()
            .str("find", "system.profile")
            .doc("filter", DocBuf::new().str("command.comment", comment))
            .doc("projection", DocBuf::new().doc("l", truncated_len()))
            .doc("sort", DocBuf::new().i32("$natural", -1))
            .i64("limit", 1)
            .bool("singleBatch", true)
    };
    let len_of = |reply: &[u8]| {
        let d = crate::bson::Doc::new(reply).unwrap();
        let batch = d
            .doc("cursor")
            .unwrap()
            .unwrap()
            .array("firstBatch")
            .unwrap()
            .unwrap();
        let (_, v) = batch.iter().next().unwrap().unwrap();
        let crate::bson::Value::Doc(e) = v else {
            panic!("no entry")
        };
        usize::try_from(e.int("l").unwrap().unwrap()).unwrap()
    };
    let _ = run(&mut s, "app", padded(0, 0, "js-it-near-a")).await;
    let len0 = len_of(&run(&mut s, "app", length("js-it-near-a")).await.unwrap());
    assert!(len0 < 51_000, "{len0}");
    let k = (51_190 - len0) / 3 - 4;
    let _ = run(&mut s, "app", padded(k, 0, "js-it-near-c")).await;
    let len1 = len_of(&run(&mut s, "app", length("js-it-near-c")).await.unwrap());
    assert!(len1 <= 51_190 && 51_190 - len1 < 40, "{len1}");
    let _ = run(&mut s, "app", padded(k, 51_190 - len1, "js-it-near-b")).await;
    let near = run(&mut s, "app", length("js-it-near-b")).await.unwrap();
    // Not cut (no `...`): only the backstop flags it.
    assert_eq!(len_of(&near), 51_190);
    expected.push(("near-a", false));
    expected.push(("near-b", true));
    // The agent's own poll, profiled as it is sent.
    let _ = run(
        &mut s,
        "app",
        crate::audit::profiler::poll_command(&crate::audit::profiler::DbCursor::after(0)),
    )
    .await;
    run(
        &mut s,
        "app",
        DocBuf::new().i32("profile", was).i32("slowms", slowms),
    )
    .await
    .unwrap();
    let reply = run(
        &mut s,
        "app",
        DocBuf::new()
            .str("find", "system.profile")
            .doc(
                "filter",
                DocBuf::new().array(
                    "$or",
                    vec![
                        DocBuf::new()
                            .doc("command.comment", DocBuf::new().array_str("$in", &comments)),
                        DocBuf::new()
                            .doc("command.projection.js", DocBuf::new().bool("$exists", true)),
                    ],
                ),
            )
            .doc(
                "projection",
                crate::audit::profiler::projection()
                    .str("c", "$command.comment")
                    .str("pr", "$command.projection.js")
                    .doc(
                        "rv",
                        DocBuf::new().list(
                            "$gt",
                            DocBuf::new()
                                .doc(
                                    "0",
                                    DocBuf::new().doc(
                                        "$size",
                                        DocBuf::new().list(
                                            "$ifNull",
                                            DocBuf::new().str("0", "$resolvedViews").doc(
                                                "1",
                                                DocBuf::new().list("$literal", DocBuf::new()),
                                            ),
                                        ),
                                    ),
                                )
                                .i32("1", 0),
                        ),
                    ),
            )
            .i64("limit", 1000)
            .bool("singleBatch", true),
    )
    .await
    .unwrap();
    let reply = crate::bson::Doc::new(&reply).unwrap();
    let batch = reply
        .doc("cursor")
        .unwrap()
        .unwrap()
        .array("firstBatch")
        .unwrap()
        .unwrap();
    let mut flags: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut views: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut own_polls = 0;
    for e in batch.iter() {
        let (_, v) = e.unwrap();
        let crate::bson::Value::Doc(d) = v else {
            continue;
        };
        let js = d.flag("js").unwrap();
        if let Some(c) = d.str("c").unwrap() {
            flags.insert(c.to_owned(), js.unwrap());
            views.insert(c.to_owned(), d.flag("rv").unwrap().unwrap_or(false));
        } else if d.get("pr").unwrap().is_some() {
            own_polls += 1;
            assert_eq!(js, Some(false), "the agent's own poll is flagged");
        }
    }
    assert!(own_polls >= 1, "the poll was not profiled");
    for (comment, js) in expected {
        assert_eq!(
            flags.get(&format!("js-it-{comment}")),
            Some(&js),
            "{comment}: {flags:?}"
        );
    }
    // The views' pipelines are in `resolvedViews`, through a `$lookup`, a
    // `$unionWith` and a view of a view.
    for c in [
        "view-plain",
        "view-js-lookup",
        "view-js-union",
        "view-js-of-view",
        "view-big",
    ] {
        assert_eq!(
            views.get(&format!("js-it-{c}")),
            Some(&true),
            "{c}: {views:?}"
        );
    }
    for v in [VIEW_OF_JS_VIEW, JS_VIEW, PLAIN_VIEW, BIG_VIEW] {
        let _ = run(&mut s, "app", DocBuf::new().str("drop", v)).await;
    }
    s.close().await;
}

const PLAIN_VIEW: &str = "databastion_it_plain_view";
const BIG_VIEW: &str = "databastion_it_big_view";
const VIEW_OF_JS_VIEW: &str = "databastion_it_view_of_js_view";

/// The byte length of a profiled command's `$truncated` text.
fn truncated_len() -> DocBuf {
    DocBuf::new().doc(
        "$strLenBytes",
        DocBuf::new().doc(
            "$getField",
            DocBuf::new()
                .doc("field", DocBuf::new().str("$literal", "$truncated"))
                .str("input", "$command"),
        ),
    )
}

#[tokio::test]
async fn javascript_on_percona_server_for_mongodb() {
    let _serial = SERIAL.lock().await;
    let Some(url) = env_url("DATABASTION_TEST_PSMDB_URL", "psmdb-audit") else {
        return;
    };
    let Some(a) = env_url("DATABASTION_TEST_PSMDB_ADMIN_URL", "psmdb-audit") else {
        return;
    };
    profiler_account(&a).await;
    let mut s = admin_session(&a).await;
    run(
        &mut s,
        "app",
        DocBuf::new().i32("profile", 1).i32("slowms", 0),
    )
    .await
    .unwrap();
    s.close().await;
    let (_dir, t) = target(&url, PROFILER_USER, IT_PASSWORD, "admin");
    let connector = Arc::new(MongodbConnector::new());
    assert!(connector.check(&t).await.reachable);
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::MongodbProfiler)
    );
    javascript_flow(
        &connector,
        &t,
        &a,
        &format!("{PROFILER_USER}@admin"),
        EventSource::MongodbProfiler,
    )
    .await;
    let mut s = admin_session(&a).await;
    run(&mut s, "app", DocBuf::new().i32("profile", 0))
        .await
        .unwrap();
    s.close().await;
    drop_profiler_account(&a).await;
}

/// The `auditLog` carries the whole command (`param.args`) of every
/// authorized operation, JavaScript included, but no count and not how it
/// ended.
#[tokio::test]
async fn javascript_on_the_percona_audit_log() {
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
    assert!(connector.check(&t).await.reachable);
    javascript_flow(
        &connector,
        &t,
        &a,
        &format!("{}@{}", url.user, url.auth_source),
        EventSource::MongodbAuditLog,
    )
    .await;
}
