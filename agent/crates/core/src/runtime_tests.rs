//! HTTP tests against a wiremock server bound to 127.0.0.1 (test code
//! only; the agent itself never listens, I1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex as StdMutex};

use wiremock::matchers::{body_partial_json, header, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;
use crate::fsutil::test_dir::TempDir;
use crate::session::RotateOutcome;

const S0: &str = "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE0";
const TOKEN: &str = "dbe_TOKENTOKENTOKENTOKENTOKENTOKENTOKENTOKEN012";
const AGENT_ID: &str = "0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
const STATUS_PATH: &str = r"^/api/agent/v1/jobs/[0-9a-f-]{36}/status$";

struct Env {
    _dir: TempDir,
    config_path: PathBuf,
    config: AgentConfig,
    state: StateDir,
}

fn env(server: &MockServer) -> Env {
    let dir = TempDir::new();
    let state_dir = dir.path().join("state");
    let text = format!(
        "console:\n  url: {}\n  insecure_dev_http: true\n  long_poll_wait_s: 0\n\
         state_dir: {}\ntargets:\n  - id: pg-main\n    engine: postgres\n    host: 127.0.0.1\n    \
         port: 5432\n    account: databastion\n    secret:\n      env: DATABASTION_PG\n",
        server.uri(),
        state_dir.display()
    );
    let config_path = dir.path().join("agent.yaml");
    std::fs::write(&config_path, &text).unwrap();
    let config = AgentConfig::parse(&text).unwrap();
    Env {
        state: StateDir::new(&state_dir),
        _dir: dir,
        config_path,
        config,
    }
}

fn write_token(env: &Env) -> PathBuf {
    let path = env.config_path.with_file_name("token");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{TOKEN}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn enroll_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(
        include_str!("../../../../shared/protocol/fixtures/valid/EnrollResponse.default.json"),
        "application/json",
    )
}

fn heartbeat_response(interval: i64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "console_min_protocol": 1,
        "heartbeat_interval_s": interval,
        "server_time": "2026-09-28T14:02:00Z"
    }))
}

fn rotate_response(duplicate: bool) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "grace_expires_at": "2026-09-28T14:07:11Z",
        "duplicate": duplicate
    }))
}

fn error_body(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(serde_json::json!({"code": code, "message": "Generic message."}))
}

fn bearer(secret: &str) -> String {
    format!("Bearer {secret}")
}

async fn enrolled(server: &MockServer) -> Env {
    let env = env(server);
    let _guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .respond_with(enroll_response())
        .mount_as_scoped(server)
        .await;
    enroll(
        &env.config,
        &write_token(&env),
        EnrollOptions::default(),
        &[Engine::Postgres],
    )
    .await
    .unwrap();
    env
}

fn session(env: &Env) -> Session {
    Session::new(
        Uplink::new(&env.config).unwrap(),
        env.state.clone(),
        env.state.load_identity().unwrap(),
    )
}

fn runtime(env: &Env) -> Runtime {
    Runtime::new(&env.config_path, env.config.clone(), Vec::new()).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ------------------------------------------------------------- enrollment

#[tokio::test]
async fn enroll_stores_identity_and_local_hmac_key() {
    let server = MockServer::start().await;
    let env = env(&server);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .and(header("x-databastion-protocol", "1"))
        .and(header("user-agent", uplink::user_agent().as_str()))
        .and(body_partial_json(serde_json::json!({
            "token": TOKEN, "connectors": ["postgres"], "os": "linux"
        })))
        .respond_with(enroll_response())
        .expect(3)
        .mount(&server)
        .await;
    let token = write_token(&env);
    let id = enroll(
        &env.config,
        &token,
        EnrollOptions::default(),
        &[Engine::Postgres],
    )
    .await
    .unwrap();
    assert_eq!(id, AGENT_ID);
    for req in server.received_requests().await.unwrap() {
        assert!(req.headers.get("authorization").is_none());
        assert!(req.headers.get("x-databastion-agent-id").is_none());
    }
    let identity = env.state.load_identity().unwrap();
    assert_eq!(identity.secret.expose(), S0);
    assert_eq!(identity.heartbeat_interval_s, 30);
    assert_eq!(mode(&env.state.identity_path()), 0o600);
    assert_eq!(mode(&env.state.hmac_key_path()), 0o600);
    let key = env.state.load_hmac_key().unwrap();
    assert_eq!(key.len(), 32);
    // The HMAC key never appears in a request.
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    for req in server.received_requests().await.unwrap() {
        assert!(!String::from_utf8_lossy(&req.body).contains(&hex));
    }

    let err = enroll(
        &env.config,
        &token,
        EnrollOptions::default(),
        &[Engine::Postgres],
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        AgentError::Identity(IdentityError::AlreadyEnrolled(_))
    ));
    let force = EnrollOptions {
        force: true,
        new_hmac_key: false,
    };
    enroll(&env.config, &token, force, &[Engine::Postgres])
        .await
        .unwrap();
    // --force keeps the existing HMAC key unless --new-hmac-key.
    assert_eq!(*env.state.load_hmac_key().unwrap(), *key);
    let renew = EnrollOptions {
        force: true,
        new_hmac_key: true,
    };
    enroll(&env.config, &token, renew, &[Engine::Postgres])
        .await
        .unwrap();
    assert_ne!(*env.state.load_hmac_key().unwrap(), *key);
}

#[tokio::test]
async fn world_readable_token_file_is_refused() {
    let server = MockServer::start().await;
    let env = env(&server);
    let token = write_token(&env);
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = enroll(&env.config, &token, EnrollOptions::default(), &[])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("readable by others"), "{err}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn enroll_401_is_not_retried() {
    let server = MockServer::start().await;
    let env = env(&server);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .respond_with(error_body(401, "unauthorized"))
        .expect(1)
        .mount(&server)
        .await;
    let err = enroll(
        &env.config,
        &write_token(&env),
        EnrollOptions::default(),
        &[],
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not retried"), "{err}");
    assert!(!err.to_string().contains(TOKEN));
    assert!(!env.state.has_identity());
}

#[tokio::test]
async fn enroll_honors_retry_after_on_503() {
    let server = MockServer::start().await;
    let env = env(&server);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .respond_with(error_body(503, "unavailable").insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .respond_with(enroll_response())
        .mount(&server)
        .await;
    let start = Instant::now();
    enroll(
        &env.config,
        &write_token(&env),
        EnrollOptions::default(),
        &[],
    )
    .await
    .unwrap();
    assert!(start.elapsed() >= Duration::from_secs(1));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn invalid_token_file_is_rejected_without_echo() {
    let server = MockServer::start().await;
    let env = env(&server);
    let path = env.config_path.with_file_name("token");
    std::fs::write(&path, "dbe_short-SECRETISH").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = enroll(&env.config, &path, EnrollOptions::default(), &[])
        .await
        .unwrap_err();
    assert!(!err.to_string().contains("SECRETISH"), "{err}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

// -------------------------------------------------------------- heartbeat

#[tokio::test]
async fn heartbeat_sends_contract_headers_and_clamps_interval() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .and(header("x-databastion-agent-id", AGENT_ID))
        .and(header("x-databastion-protocol", "1"))
        .respond_with(heartbeat_response(1))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(heartbeat_response(0))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let interval = rt.heartbeat_once().await.unwrap();
    assert_eq!(interval, Some(10));
    rt.session.set_heartbeat_interval(10);
    assert_eq!(env.state.load_identity().unwrap().heartbeat_interval_s, 10);
    // `0` is rejected: the previous interval is kept.
    assert_eq!(rt.heartbeat_once().await.unwrap(), None);

    let requests = server.received_requests().await.unwrap();
    let last = requests.last().unwrap();
    let hb: serde_json::Value = serde_json::from_slice(&last.body).unwrap();
    // Conforms to the generated (closed) type.
    serde_json::from_value::<HeartbeatRequest>(hb.clone()).unwrap();
    assert_eq!(hb["targets"][0]["target_id"], "pg-main");
    assert_eq!(hb["targets"][0]["reachable"], false);
    assert_eq!(hb["targets"][0]["last_error"], "unsupported");
    assert!(hb["metrics"]["heartbeats_sent_total"].is_number());
    // No target address nor account in the heartbeat (I3).
    let text = String::from_utf8_lossy(&last.body).to_string();
    assert!(!text.contains("127.0.0.1") && !text.contains("\"databastion\""));
}

#[tokio::test]
async fn unauthorized_with_current_secret_suspends_with_slow_retry() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(error_body(401, "unauthorized"))
        .expect(1)
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let err = rt.heartbeat_once().await.unwrap_err();
    assert!(matches!(err, CallError::Unauthorized));
    // First slow retry after 60-90 s, then every 15 min.
    let first = rt
        .on_call_error("heartbeat", &err, 1, Duration::from_secs(30))
        .unwrap();
    assert!(first >= Duration::from_secs(60) && first <= Duration::from_secs(90));
    assert_eq!(*rt.state.borrow(), RunState::Suspended);
    for _ in 0..2 {
        let delay = rt
            .on_call_error("heartbeat", &err, 1, Duration::from_secs(30))
            .unwrap();
        assert!(delay >= Duration::from_secs(900));
    }
    // A 401 seen by another loop does not consume the quick retry.
    let rt = runtime(&env);
    let other = rt
        .on_call_error("jobs", &err, 1, Duration::from_secs(30))
        .unwrap();
    assert!(other >= Duration::from_secs(900));
    let hb = rt
        .on_call_error("heartbeat", &err, 1, Duration::from_secs(30))
        .unwrap();
    assert!(hb <= Duration::from_secs(90));
}

#[tokio::test]
async fn upgrade_required_keeps_running() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(426).set_body_json(serde_json::json!({
            "code": "protocol_unsupported", "message": "Upgrade required.", "min_protocol": 2
        })))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let err = rt.heartbeat_once().await.unwrap_err();
    let delay = rt
        .on_call_error("heartbeat", &err, 1, Duration::from_secs(30))
        .unwrap();
    assert_eq!(delay, Duration::from_secs(300));
    assert_eq!(*rt.state.borrow(), RunState::Active);
}

#[tokio::test]
async fn run_stops_on_shutdown() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent/v1/jobs"))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(200)))
        .mount(&server)
        .await;
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn({
        let path = env.config_path.clone();
        async move { run(&path, Vec::new(), rx).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .any(|r| r.url.path().ends_with("/heartbeat"))
    );
    assert!(
        requests
            .iter()
            .any(|r| r.url.path().ends_with("/jobs") && r.url.query() == Some("wait=0"))
    );
}

// ------------------------------------------------------------------- jobs

fn job(id: &str, kind: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "job_id": id, "type": kind, "created_at": "2026-09-28T14:00:00Z", "params": params
    })
}

async fn statuses(server: &MockServer) -> Vec<(String, serde_json::Value)> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/status"))
        .map(|r: Request| {
            let id = r.url.path().split('/').rev().nth(1).unwrap().to_owned();
            (id, serde_json::from_slice(&r.body).unwrap())
        })
        .collect()
}

#[tokio::test]
async fn jobs_are_parsed_individually_and_reported() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let reload = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f71";
    let unknown = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f72";
    let audit = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f73";
    let mut audit_job: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../shared/protocol/fixtures/valid/JobList.audit-configure.json"
    ))
    .unwrap();
    let mut audit_job = audit_job["jobs"][0].take();
    audit_job["job_id"] = audit.into();
    audit_job.as_object_mut().unwrap().remove("expires_at");
    let body = serde_json::json!({ "jobs": [
        job(reload, "agent.config.reload", serde_json::json!({})),
        job(unknown, "agent.self_destruct", serde_json::json!({})),
        {"type": "agent.config.reload"},
        audit_job,
    ]});
    let rt = runtime(&env);
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    let got = statuses(&server).await;
    let find = |id: &str| got.iter().find(|(i, _)| i == id).unwrap().1.clone();
    assert_eq!(find(reload)["status"], "succeeded");
    assert_eq!(find(unknown)["status"], "failed");
    assert_eq!(find(unknown)["error"]["code"], "unsupported");
    assert_eq!(find(audit)["status"], "failed");
    assert_eq!(find(audit)["error"]["code"], "unsupported");
    assert_eq!(got.len(), 3);
    for (_, update) in &got {
        serde_json::from_value::<JobStatusUpdate>(update.clone()).unwrap();
    }
    assert_eq!(rt.counters.jobs_unparseable.load(Ordering::Relaxed), 2);

    // Redelivery: parsed jobs are deduplicated; the unknown one (never
    // parsed, so not in the ledger) is reported again.
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    assert_eq!(statuses(&server).await.len(), 4);
}

#[tokio::test]
async fn expired_job_is_failed_as_expired() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut j = job(
        "01920f5f-0c30-7e6f-a043-2b3c4d5e6f74",
        "agent.config.reload",
        serde_json::json!({}),
    );
    j["expires_at"] = "2020-01-01T00:00:00Z".into();
    let rt = runtime(&env);
    rt.handle_job_list(&serde_json::to_vec(&serde_json::json!({"jobs": [j]})).unwrap())
        .await
        .unwrap();
    let got = statuses(&server).await;
    assert_eq!(got[0].1["error"]["code"], "expired");
}

// --------------------------------------------------------------- rotation

fn rotate_bodies(requests: &[Request]) -> Vec<serde_json::Value> {
    requests
        .iter()
        .filter(|r| r.url.path().ends_with("/rotate"))
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

#[tokio::test]
async fn rotation_persists_pending_first_reuses_it_and_promotes() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let job_id = Uuid::try_from("01920f5f-1d40-7f70-b154-3c4d5e6f7081").unwrap();
    let first = session(&env);

    // 1. /rotate fails: the pending secret is already on disk.
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(error_body(400, "invalid_request"))
        .mount_as_scoped(&server)
        .await;
    assert!(first.rotate(Some(job_id)).await.is_err());
    let on_disk = env.state.load_identity().unwrap();
    let s1 = on_disk.pending.clone().unwrap().expose().to_owned();
    assert_eq!(on_disk.secret.expose(), S0);
    assert_eq!(mode(&env.state.identity_path()), 0o600);
    drop(guard);

    // 2. Redelivery after a restart (fresh session): the same S1 is resent.
    let session = session(&env);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(rotate_response(true))
        .mount(&server)
        .await;
    assert_eq!(
        session.rotate(Some(job_id)).await.unwrap(),
        RotateOutcome::Registered { duplicate: true }
    );
    let bodies = rotate_bodies(&server.received_requests().await.unwrap());
    assert_eq!(bodies.len(), 2);
    for body in &bodies {
        assert_eq!(body["new_secret"], s1.as_str());
        assert_eq!(body["job_id"], job_id.to_string());
    }

    // 3. First success with S1 promotes it.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(&s1).as_str()))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    session
        .call(
            Method::POST,
            "/heartbeat",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    let on_disk = env.state.load_identity().unwrap();
    assert_eq!(on_disk.secret.expose(), s1);
    assert!(on_disk.pending.is_none());
    assert_eq!(session.snapshot().secret.expose(), s1);

    // 4. The same job redelivered after promotion: no new secret.
    assert_eq!(
        session.rotate(Some(job_id)).await.unwrap(),
        RotateOutcome::AlreadyDone
    );
    assert_eq!(
        rotate_bodies(&server.received_requests().await.unwrap()).len(),
        2
    );
}

#[tokio::test]
async fn unregistered_pending_secret_falls_back_to_current() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    // Crash between persisting S1 and POST /rotate.
    let mut identity = env.state.load_identity().unwrap();
    let s1 = crate::identity::generate_secret().unwrap();
    identity.pending = Some(s1.clone());
    env.state.save_identity(&identity).unwrap();

    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(s1.expose()).as_str()))
        .respond_with(error_body(401, "unauthorized"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    let session = session(&env);
    session
        .call(
            Method::POST,
            "/heartbeat",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    let auths: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/heartbeat"))
        .map(|r| r.headers["authorization"].to_str().unwrap().to_owned())
        .collect();
    assert_eq!(auths, [bearer(s1.expose()), bearer(S0)]);
    assert!(session.needs_rotation_retry());
    let on_disk = env.state.load_identity().unwrap();
    assert_eq!(on_disk.secret.expose(), S0);
    assert_eq!(on_disk.pending.unwrap().expose(), s1.expose());
}

#[tokio::test]
async fn rotation_conflict_is_fatal() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(error_body(409, "rotation_conflict"))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let err = rt
        .rotate_for_job(Uuid::try_from("01920f5f-1d40-7f70-b154-3c4d5e6f7082").unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::RotationConflict));
}

// ---------------------------------------------------------- secrets / logs

#[derive(Clone, Default)]
struct Capture(Arc<StdMutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn secrets_never_appear_in_logs_or_debug() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(error_body(401, "unauthorized"))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    rt.rotate_for_job(Uuid::try_from("01920f5f-1d40-7f70-b154-3c4d5e6f7083").unwrap())
        .await
        .unwrap();
    let err = rt.heartbeat_once().await.unwrap_err();
    rt.on_call_error("heartbeat", &err, 1, Duration::from_secs(30))
        .unwrap();

    let identity = env.state.load_identity().unwrap();
    let s1 = identity.pending.clone().unwrap().expose().to_owned();
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // Everything is captured, including third-party trace output (hyper).
    assert!(!logs.is_empty());
    let debug = format!("{identity:?} {err:?} {:?}", env.config);
    for secret in [S0, s1.as_str(), TOKEN] {
        assert!(!logs.contains(secret), "secret in logs");
        assert!(!debug.contains(secret), "secret in Debug");
    }
}

// ------------------------------------------------------ review follow-ups

#[tokio::test]
async fn lost_rotate_response_never_falls_back_to_s0() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    // Unknown outcome: the console registered S1 but the response was lost.
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(ResponseTemplate::new(502))
        .mount_as_scoped(&server)
        .await;
    assert!(session.rotate(None).await.is_err());
    drop(guard);
    let s1 = env
        .state
        .load_identity()
        .unwrap()
        .pending
        .unwrap()
        .expose()
        .to_owned();
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(&s1).as_str()))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(error_body(409, "rotation_conflict"))
        .mount(&server)
        .await;
    for _ in 0..3 {
        session
            .call(
                Method::POST,
                "/heartbeat",
                &[],
                Some(b"{}"),
                uplink::REQUEST_TIMEOUT,
            )
            .await
            .unwrap();
    }
    let with_s0 = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/heartbeat"))
        .filter(|r| r.headers["authorization"].to_str().unwrap() == bearer(S0))
        .count();
    assert_eq!(with_s0, 0);
    assert_eq!(env.state.load_identity().unwrap().secret.expose(), s1);
}

#[tokio::test]
async fn rotation_conflict_on_any_request_stops_the_agent() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(error_body(409, "rotation_conflict"))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let err = rt.heartbeat_once().await.unwrap_err();
    assert!(matches!(err, CallError::RotationConflict));
    assert!(matches!(
        rt.on_call_error("heartbeat", &err, 1, Duration::from_secs(30)),
        Err(AgentError::RotationConflict)
    ));
}

#[tokio::test]
async fn s1_401_after_the_latest_rotate_attempt_puts_s0_first() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(ResponseTemplate::new(503))
        .mount_as_scoped(&server)
        .await;
    assert!(session.rotate(None).await.is_err());
    drop(guard);
    assert!(!session.needs_rotation_retry());
    let s1 = session.snapshot().pending.unwrap();
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(s1.expose()).as_str()))
        .respond_with(error_body(401, "unauthorized"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    session
        .call(
            Method::POST,
            "/heartbeat",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    assert!(session.needs_rotation_retry());
}

#[tokio::test]
async fn invalid_secret_fails_the_job_and_clears_rotation_jobs() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let job = Uuid::try_from("01920f5f-1d40-7f70-b154-3c4d5e6f7090").unwrap();
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(error_body(400, "invalid_secret"))
        .mount_as_scoped(&server)
        .await;
    let rt = runtime(&env);
    assert_eq!(
        rt.rotate_for_job(job).await.unwrap(),
        Some(Outcome::failed(FailureCode::Internal))
    );
    let on_disk = env.state.load_identity().unwrap();
    assert!(on_disk.pending.is_none());
    assert!(on_disk.rotation_jobs.is_empty());
    drop(guard);
    // Redelivery of the same job: a new secret is generated and registered.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount(&server)
        .await;
    assert_eq!(
        rt.rotate_for_job(job).await.unwrap(),
        Some(Outcome::SUCCEEDED)
    );
    let bodies = rotate_bodies(&server.received_requests().await.unwrap());
    assert_eq!(bodies.len(), 2);
    assert_ne!(bodies[0]["new_secret"], bodies[1]["new_secret"]);
}

#[tokio::test]
async fn every_job_satisfied_by_the_secret_is_acknowledged_and_new_rotation_deferred() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let jobs: Vec<Uuid> = (0..3)
        .map(|i| {
            Uuid::try_from(format!("01920f5f-1d40-7f70-b154-3c4d5e6f70a{i}").as_str()).unwrap()
        })
        .collect();
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount(&server)
        .await;
    let session = session(&env);
    for job in &jobs {
        assert!(matches!(
            session.rotate(Some(*job)).await.unwrap(),
            RotateOutcome::Registered { .. }
        ));
    }
    let bodies = rotate_bodies(&server.received_requests().await.unwrap());
    assert!(
        bodies
            .iter()
            .all(|b| b["new_secret"] == bodies[0]["new_secret"])
    );
    assert_eq!(env.state.load_identity().unwrap().rotation_jobs, jobs);
    // Promotion.
    let s1 = session.snapshot().pending.unwrap();
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(s1.expose()).as_str()))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    session
        .call(
            Method::POST,
            "/heartbeat",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    // Any of them redelivered after promotion (even after a restart):
    // acknowledged without a new rotation.
    let restarted = self::session(&env);
    for job in &jobs {
        assert_eq!(
            restarted.rotate(Some(*job)).await.unwrap(),
            RotateOutcome::AlreadyDone
        );
    }
    // A new rotate job within 60 s of the promotion is deferred.
    let new_job = Uuid::try_from("01920f5f-1d40-7f70-b154-3c4d5e6f70b0").unwrap();
    assert_eq!(
        session.rotate(Some(new_job)).await.unwrap(),
        RotateOutcome::Deferred
    );
    assert_eq!(
        rotate_bodies(&server.received_requests().await.unwrap()).len(),
        3
    );
}

#[tokio::test]
async fn reload_refuses_console_or_state_dir_changes() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let rt = runtime(&env);
    let text = std::fs::read_to_string(&env.config_path).unwrap();
    std::fs::write(
        &env.config_path,
        text.replace(&server.uri(), "http://127.0.0.1:1"),
    )
    .unwrap();
    assert_eq!(
        rt.reload_config(),
        Outcome::failed(FailureCode::InvalidParams)
    );
    assert_eq!(rt.config().console.url, server.uri());
    std::fs::write(&env.config_path, text.replace("port: 5432", "port: 5433")).unwrap();
    assert_eq!(rt.reload_config(), Outcome::SUCCEEDED);
}

#[test]
fn poll_gap_prevents_hot_loop() {
    let mut streak = 0;
    let fast = Duration::from_millis(5);
    let first = poll_gap(fast, false, &mut streak, 0.0);
    assert_eq!(first, Duration::from_secs(1));
    for _ in 0..20 {
        assert!(poll_gap(fast, false, &mut streak, 0.5) >= Duration::from_secs(1));
    }
    assert!(poll_gap(fast, false, &mut streak, 1.0) <= Duration::from_secs(300));
    assert_eq!(poll_gap(fast, true, &mut streak, 0.5), Duration::ZERO);
    assert_eq!(streak, 0);
    assert_eq!(
        poll_gap(Duration::from_secs(25), false, &mut streak, 0.5),
        Duration::ZERO
    );
}

#[tokio::test]
async fn immediate_204_does_not_hot_loop() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(heartbeat_response(30))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent/v1/jobs"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn({
        let path = env.config_path.clone();
        async move { run(&path, Vec::new(), rx).await }
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let polls = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/jobs"))
        .count();
    assert!((1..=3).contains(&polls), "{polls} polls in 1.5 s");
}

// ---------------------------------------------------------------- spool

/// Scripted `/findings` responses, in order; then plain acks.
enum Step {
    Ack(bool),
    Items(&'static [&'static str]),
    TooLarge,
    Conflict,
}

struct Script(std::sync::Mutex<std::collections::VecDeque<Step>>);

impl wiremock::Respond for Script {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let ack = |dup: bool| {
            ResponseTemplate::new(202)
                .set_body_json(serde_json::json!({"batch_id": body["batch_id"], "duplicate": dup}))
        };
        match self.0.lock().unwrap().pop_front() {
            None | Some(Step::Ack(false)) => ack(false),
            Some(Step::Ack(true)) => ack(true),
            Some(Step::Items(pointers)) => {
                let details: Vec<_> = pointers
                    .iter()
                    .map(|p| serde_json::json!({"pointer": p, "keyword": "maximum"}))
                    .collect();
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "code": "invalid_request", "message": "Invalid.", "details": details
                }))
            }
            Some(Step::TooLarge) => error_body(413, "payload_too_large"),
            Some(Step::Conflict) => error_body(409, "batch_conflict"),
        }
    }
}

async fn spooled_runtime(server: &MockServer, steps: Vec<Step>, findings: usize) -> (Env, Runtime) {
    let env = enrolled(server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(Script(std::sync::Mutex::new(steps.into())))
        .mount(server)
        .await;
    let rt = runtime(&env);
    let found = crate::spool::tests::masked(findings, "email");
    rt.spool_findings(
        Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        &TargetId::try_from("pg-main").unwrap(),
        databastion_protocol::Engine::Postgres,
        &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
        &found,
    )
    .unwrap();
    (env, rt)
}

async fn sent_batches(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/findings"))
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

async fn drain(rt: &Runtime) {
    for _ in 0..20 {
        if rt.flush_once(1).await.unwrap() == Flush::Idle {
            return;
        }
    }
    panic!("spool not drained");
}

#[tokio::test]
async fn items_rejected_by_pointer_are_dropped_and_rest_resent_under_new_id() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(
        &server,
        vec![Step::Items(&["/findings/1/confidence", "/findings/3"])],
        10,
    )
    .await;
    drain(&rt).await;
    let sent = sent_batches(&server).await;
    assert_eq!(sent.len(), 2);
    assert_ne!(sent[0]["batch_id"], sent[1]["batch_id"]);
    assert_eq!(sent[1]["findings"].as_array().unwrap().len(), 8);
    let status = rt.lock_spool().status();
    assert_eq!(status.dropped_items.unwrap().0, 2);
    assert_eq!(status.dropped_batches.unwrap().0, 0);
    assert_eq!(status.batches.0, 0);
}

#[tokio::test]
async fn out_of_range_item_pointer_drops_the_batch() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(&server, vec![Step::Items(&["/findings/7"])], 3).await;
    drain(&rt).await;
    assert_eq!(sent_batches(&server).await.len(), 1);
    assert_eq!(rt.lock_spool().status().dropped_batches.unwrap().0, 1);
}

#[tokio::test]
async fn envelope_pointer_drops_the_whole_batch() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(&server, vec![Step::Items(&["/job_id"])], 4).await;
    drain(&rt).await;
    assert_eq!(sent_batches(&server).await.len(), 1);
    let status = rt.lock_spool().status();
    assert_eq!(status.dropped_batches.unwrap().0, 1);
    assert_eq!(status.dropped_items.unwrap().0, 4);
}

#[tokio::test]
async fn payload_too_large_splits_in_halves_with_new_ids() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(&server, vec![Step::TooLarge, Step::Ack(true)], 9).await;
    drain(&rt).await;
    let sent = sent_batches(&server).await;
    let sizes: Vec<_> = sent
        .iter()
        .map(|b| b["findings"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [9, 4, 5]);
    let ids: std::collections::HashSet<_> =
        sent.iter().map(|b| b["batch_id"].to_string()).collect();
    assert_eq!(ids.len(), 3);
    let m = rt.metrics().0;
    let get = |k: &str| m[&MetricsMapKey::try_from(k).unwrap()];
    assert!((get("batches_duplicate_total") - 1.0).abs() < f64::EPSILON);
    assert!((get("batches_sent_total") - 2.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn batch_conflict_is_dropped_never_resent() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(&server, vec![Step::Conflict], 3).await;
    drain(&rt).await;
    assert_eq!(sent_batches(&server).await.len(), 1);
    let m = rt.metrics().0;
    assert!(
        (m[&MetricsMapKey::try_from("batch_conflicts_total").unwrap()] - 1.0).abs() < f64::EPSILON
    );
    assert_eq!(rt.lock_spool().status().dropped_batches.unwrap().0, 1);
}

#[tokio::test]
async fn server_errors_keep_the_batch_for_retry() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let found = crate::spool::tests::masked(2, "email");
    rt.spool_findings(
        Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        &TargetId::try_from("pg-main").unwrap(),
        databastion_protocol::Engine::Postgres,
        &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
        &found,
    )
    .unwrap();
    assert!(matches!(rt.flush_once(1).await.unwrap(), Flush::Retry(_)));
    let hb = rt.build_heartbeat().await.unwrap();
    assert_eq!(hb.spool.batches.0, 1);
    assert!(hb.spool.bytes.0 > 0);
    assert!(hb.spool.max_bytes.0 > 0);
}

#[test]
fn spool_backoff_grows_and_is_capped() {
    let top = |f| spool_backoff(f, 0.999_999);
    assert!(top(1) <= Duration::from_secs(1));
    assert!(top(2) > top(1));
    assert!(top(6) > Duration::from_secs(30));
    assert_eq!(top(40), Duration::from_secs(300).mul_f64(0.999_999));
}

async fn spool_answered_with(template: ResponseTemplate) -> Runtime {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(template)
        .mount(&server)
        .await;
    let rt = runtime(&env);
    let found = crate::spool::tests::masked(2, "email");
    rt.spool_findings(
        Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        &TargetId::try_from("pg-main").unwrap(),
        databastion_protocol::Engine::Postgres,
        &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
        &found,
    )
    .unwrap();
    for failures in 1..=3 {
        assert!(matches!(
            rt.flush_once(failures).await.unwrap(),
            Flush::Retry(_)
        ));
    }
    drop(server);
    rt
}

#[tokio::test]
async fn non_contract_answers_never_empty_the_spool() {
    let html = ResponseTemplate::new(200).set_body_string("<html>proxy login</html>");
    let bare_404 = ResponseTemplate::new(404);
    let bare_409 = ResponseTemplate::new(409).set_body_string("conflict");
    let wrong_ack = ResponseTemplate::new(202).set_body_json(serde_json::json!({
        "batch_id": "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f", "duplicate": false
    }));
    for template in [html, bare_404, bare_409, wrong_ack] {
        let rt = spool_answered_with(template).await;
        let status = rt.lock_spool().status();
        assert_eq!(status.batches.0, 1);
        assert_eq!(status.dropped_batches.unwrap().0, 0);
        let m = rt.metrics().0;
        let unexpected = m[&MetricsMapKey::try_from("batches_unexpected_response_total").unwrap()];
        assert!((unexpected - 3.0).abs() < f64::EPSILON);
        assert!(m.contains_key(&MetricsMapKey::try_from("spool_quarantined_total").unwrap()));
    }
}

#[tokio::test]
async fn unknown_rotation_outcome_is_probed_with_s1_before_resending_rotate() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(ResponseTemplate::new(502))
        .mount_as_scoped(&server)
        .await;
    assert!(session.rotate(None).await.is_err());
    drop(guard);
    let s1 = env
        .state
        .load_identity()
        .unwrap()
        .pending
        .unwrap()
        .expose()
        .to_owned();
    // The console registered and promoted S1 meanwhile; S0 is past grace.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(&s1).as_str()))
        .respond_with(heartbeat_response(30))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(error_body(409, "rotation_conflict"))
        .expect(0)
        .mount(&server)
        .await;
    let outcome = session.rotate_probed(None, Some(b"{}")).await.unwrap();
    assert_eq!(outcome, RotateOutcome::AlreadyDone);
    let stored = env.state.load_identity().unwrap();
    assert!(stored.pending.is_none());
    assert_eq!(stored.secret.expose(), s1);
}

#[tokio::test]
async fn probe_refused_falls_back_to_rotate_with_s0() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(ResponseTemplate::new(502))
        .mount_as_scoped(&server)
        .await;
    assert!(session.rotate(None).await.is_err());
    drop(guard);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(error_body(401, "unauthorized"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(true))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        session.rotate_probed(None, Some(b"{}")).await.unwrap(),
        RotateOutcome::Registered { duplicate: true }
    );
    assert!(env.state.load_identity().unwrap().pending.is_some());
}

#[tokio::test]
async fn probe_success_with_unparseable_body_does_not_promote() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(ResponseTemplate::new(502))
        .mount_as_scoped(&server)
        .await;
    assert!(session.rotate(None).await.is_err());
    drop(guard);
    let before = env.state.load_identity().unwrap();
    let s1 = before.pending.as_ref().unwrap().expose().to_owned();
    // A 2xx that is not a HeartbeatResponse (e.g. a proxy page) proves
    // nothing about S1.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(&s1).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>proxy login</html>"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(true))
        .expect(0)
        .mount(&server)
        .await;
    let err = session.rotate_probed(None, Some(b"{}")).await.unwrap_err();
    assert!(
        matches!(
            err,
            CallError::Uplink(UplinkError::UnexpectedResponse { status: 200 })
        ),
        "{err:?}"
    );
    let stored = env.state.load_identity().unwrap();
    assert_eq!(stored.secret.expose(), S0);
    assert_eq!(stored.pending.unwrap().expose(), s1);
    assert_eq!(session.snapshot().secret.expose(), S0);
}

