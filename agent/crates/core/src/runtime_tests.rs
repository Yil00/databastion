//! HTTP tests against a wiremock server bound to 127.0.0.1 (test code
//! only; the agent itself never listens, I1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex as StdMutex};

use wiremock::matchers::{body_partial_json, header, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;
use crate::engine::TargetHealth;
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
    assert_eq!(
        hb["classifiers_version"],
        databastion_classifiers::id::CLASSIFIERS_VERSION
    );
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
            uplink::accept::heartbeat,
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
            uplink::accept::heartbeat,
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
                uplink::accept::heartbeat,
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
            uplink::accept::heartbeat,
        )
        .await
        .unwrap();
    assert!(session.needs_rotation_retry());
}

async fn heartbeat_call(session: &Session) -> Result<HeartbeatResponse, CallError> {
    session
        .call(
            Method::POST,
            "/heartbeat",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
            uplink::accept::heartbeat,
        )
        .await
}

/// L1 (a): a `401` on S1 for a request sent while `/rotate` was in flight
/// (S1 not registered yet), but handled after the `/rotate` `200`, is stale:
/// it must not put S0 first again (a later S0 past the 60 s window would
/// lock the agent).
#[tokio::test]
async fn stale_s1_401_handled_after_rotate_success_keeps_s1_first() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false).set_delay(Duration::from_millis(300)))
        .mount(&server)
        .await;
    // S0 answers slowly, so the heartbeat's S0 success is handled after the
    // `/rotate` 200; S1 (anything but S0) is refused at once.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(heartbeat_response(30).set_delay(Duration::from_millis(900)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(error_body(401, "unauthorized"))
        .mount(&server)
        .await;
    let (rotated, called) = tokio::join!(session.rotate(None), async {
        // Starts after the attempt began (S1 pending, epoch bumped).
        tokio::time::sleep(Duration::from_millis(100)).await;
        heartbeat_call(&session).await
    });
    assert_eq!(
        rotated.unwrap(),
        RotateOutcome::Registered { duplicate: false }
    );
    called.unwrap();
    let s1 = session.snapshot().pending.unwrap();
    let auths: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/heartbeat"))
        .map(|r| r.headers["authorization"].to_str().unwrap().to_owned())
        .collect();
    assert_eq!(auths, [bearer(s1.expose()), bearer(S0)]);
    // The stale 401 was ignored: S1 stays first, no /rotate retry needed.
    assert!(!session.needs_rotation_retry());
}

/// L1 (b), decision: a `429` / `503` on the pending S1 is **not** retried
/// with S0. The console answers it before recognizing the secret, so S1 may
/// already be promoted and S0 past the 60 s window, where any use of S0
/// locks the agent (ADR-0010, ADR-0011). The throttled error is returned
/// (retryable, honoring `Retry-After`) and S1 stays first.
#[tokio::test]
async fn throttled_pending_s1_is_retried_later_never_with_s0() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let session = session(&env);
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount_as_scoped(&server)
        .await;
    session.rotate(None).await.unwrap();
    drop(guard);
    let s1 = session.snapshot().pending.unwrap();
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(s1.expose()).as_str()))
        .respond_with(error_body(503, "unavailable").insert_header("retry-after", "7"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .and(header("authorization", bearer(S0).as_str()))
        .respond_with(error_body(409, "rotation_conflict"))
        .expect(0)
        .mount(&server)
        .await;
    for _ in 0..2 {
        let err = heartbeat_call(&session).await.unwrap_err();
        assert!(
            matches!(
                &err,
                CallError::Uplink(UplinkError::Throttled {
                    status: 503,
                    retry_after: Some(d)
                }) if *d == Duration::from_secs(7)
            ),
            "{err:?}"
        );
    }
    assert!(!session.needs_rotation_retry());
    assert_eq!(session.snapshot().pending.unwrap().expose(), s1.expose());
}

/// `/rotate` success is checked like every other endpoint: a non-contract
/// `200` registers nothing and leaves S1 pending with an unknown outcome.
#[tokio::test]
async fn non_contract_rotate_reply_is_unexpected() {
    for template in [
        ResponseTemplate::new(200).set_body_raw("<html>proxy</html>", "text/html"),
        ResponseTemplate::new(200).set_body_raw(
            r#"{"grace_expires_at":"2026-09-28T14:07:11Z","duplicate":false}"#,
            "text/plain",
        ),
        heartbeat_response(30),
    ] {
        let server = MockServer::start().await;
        let env = enrolled(&server).await;
        let session = session(&env);
        Mock::given(method("POST"))
            .and(path("/api/agent/v1/rotate"))
            .respond_with(template)
            .mount(&server)
            .await;
        assert_unexpected(session.rotate(None).await);
        let stored = env.state.load_identity().unwrap();
        assert_eq!(stored.secret.expose(), S0);
        assert!(stored.pending.is_some());
        assert!(!session.needs_rotation_retry());
    }
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
            uplink::accept::heartbeat,
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

/// Resets the batch serialization fault injection on drop.
struct FailSerialization;

impl FailSerialization {
    fn on() -> Self {
        uplink::FAIL_BATCH_SERIALIZATION.with(|f| f.set(true));
        Self
    }
}

impl Drop for FailSerialization {
    fn drop(&mut self) {
        uplink::FAIL_BATCH_SERIALIZATION.with(|f| f.set(false));
    }
}

fn serialization_failures(rt: &Runtime) -> f64 {
    rt.metrics().0[&MetricsMapKey::try_from("batches_serialization_failed_total").unwrap()]
}

#[tokio::test]
async fn unserializable_batches_are_counted_when_spooling() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let rt = runtime(&env);
    assert!(serialization_failures(&rt).abs() < f64::EPSILON);
    let found = crate::spool::tests::masked(3, "email");
    {
        let _fail = FailSerialization::on();
        rt.spool_findings(
            Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
            &TargetId::try_from("pg-main").unwrap(),
            databastion_protocol::Engine::Postgres,
            &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
            &found,
        )
        .unwrap();
    }
    assert!((serialization_failures(&rt) - 1.0).abs() < f64::EPSILON);
    let status = rt.lock_spool().status();
    assert_eq!(status.batches.0, 0);
    assert_eq!(status.dropped_items.unwrap().0, 3);
    // Reported in the heartbeat metrics.
    let hb = serde_json::to_value(rt.build_heartbeat().await.unwrap()).unwrap();
    assert_eq!(hb["metrics"]["batches_serialization_failed_total"], 1.0);
}

#[tokio::test]
async fn unserializable_halves_are_counted_and_dropped() {
    let server = MockServer::start().await;
    let (_env, rt) = spooled_runtime(&server, vec![Step::TooLarge], 4).await;
    let _fail = FailSerialization::on();
    drain(&rt).await;
    assert_eq!(sent_batches(&server).await.len(), 1);
    assert!((serialization_failures(&rt) - 1.0).abs() < f64::EPSILON);
    let status = rt.lock_spool().status();
    assert_eq!(status.batches.0, 0);
    assert_eq!(status.dropped_batches.unwrap().0, 1);
}

/// A runtime whose session holds a registered pending S1 (tried first),
/// with every endpoint answering `200 text/html` (e.g. a TLS-inspection
/// proxy's page).
async fn s1_pending_behind_html_proxy(server: &MockServer) -> (Env, Runtime, String) {
    let env = enrolled(server).await;
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount_as_scoped(server)
        .await;
    assert_eq!(
        session(&env).rotate(None).await.unwrap(),
        RotateOutcome::Registered { duplicate: false }
    );
    drop(guard);
    let s1 = env
        .state
        .load_identity()
        .unwrap()
        .pending
        .unwrap()
        .expose()
        .to_owned();
    Mock::given(path_regex(r"^/api/agent/v1/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html>proxy</html>", "text/html"))
        .mount(server)
        .await;
    let rt = runtime(&env);
    (env, rt, s1)
}

fn assert_not_promoted(env: &Env, rt: &Runtime, s1: &str) {
    let stored = env.state.load_identity().unwrap();
    assert_eq!(stored.secret.expose(), S0);
    assert_eq!(stored.pending.unwrap().expose(), s1);
    let memory = rt.session.snapshot();
    assert_eq!(memory.secret.expose(), S0);
    assert_eq!(memory.pending.unwrap().expose(), s1);
}

fn assert_unexpected<T: std::fmt::Debug>(result: Result<T, CallError>) {
    assert!(
        matches!(
            result,
            Err(CallError::Uplink(UplinkError::UnexpectedResponse {
                status: 200
            }))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn html_200_to_s1_heartbeat_does_not_promote() {
    let server = MockServer::start().await;
    let (env, rt, s1) = s1_pending_behind_html_proxy(&server).await;
    assert_unexpected(rt.heartbeat_once().await);
    assert_not_promoted(&env, &rt, &s1);
    let auth = server.received_requests().await.unwrap();
    let last = auth.last().unwrap();
    assert!(last.url.path().ends_with("/heartbeat"));
    assert_eq!(last.headers["authorization"], bearer(&s1).as_str());
}

#[tokio::test]
async fn html_200_to_s1_batch_upload_does_not_promote() {
    let server = MockServer::start().await;
    let (env, rt, s1) = s1_pending_behind_html_proxy(&server).await;
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
    assert_not_promoted(&env, &rt, &s1);
    assert_eq!(rt.lock_spool().status().batches.0, 1);
    let m = rt.metrics().0;
    let unexpected = m[&MetricsMapKey::try_from("batches_unexpected_response_total").unwrap()];
    assert!((unexpected - 1.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn html_200_to_s1_job_poll_does_not_promote() {
    let server = MockServer::start().await;
    let (env, rt, s1) = s1_pending_behind_html_proxy(&server).await;
    let result = rt
        .session
        .call(
            Method::GET,
            "/jobs",
            &[("wait", "0".to_owned())],
            None,
            uplink::REQUEST_TIMEOUT,
            uplink::accept::job_list,
        )
        .await;
    assert_unexpected(result.map(|l| l.is_some()));
    assert_not_promoted(&env, &rt, &s1);
}

#[tokio::test]
async fn html_200_to_s1_job_status_does_not_promote() {
    let server = MockServer::start().await;
    let (env, rt, s1) = s1_pending_behind_html_proxy(&server).await;
    let result = rt
        .session
        .call(
            Method::POST,
            "/jobs/01920f5f-0c30-7e6f-a043-2b3c4d5e6f71/status",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
            uplink::accept::no_content,
        )
        .await;
    assert_unexpected(result);
    assert_not_promoted(&env, &rt, &s1);
}

#[tokio::test]
async fn contract_answer_to_s1_promotes() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let guard = Mock::given(method("POST"))
        .and(path("/api/agent/v1/rotate"))
        .respond_with(rotate_response(false))
        .mount_as_scoped(&server)
        .await;
    session(&env).rotate(None).await.unwrap();
    drop(guard);
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    rt.session
        .call(
            Method::POST,
            "/jobs/01920f5f-0c30-7e6f-a043-2b3c4d5e6f71/status",
            &[],
            Some(b"{}"),
            uplink::REQUEST_TIMEOUT,
            uplink::accept::no_content,
        )
        .await
        .unwrap();
    let stored = env.state.load_identity().unwrap();
    assert!(stored.pending.is_none());
    assert_ne!(stored.secret.expose(), S0);
}

// ---------------------------------------------------------- target health

struct Health(TargetHealth);

#[async_trait::async_trait]
impl Connector for Health {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    async fn check(&self) -> TargetHealth {
        self.0.clone()
    }

    async fn discover(
        &self,
        _: &crate::ScanJob,
        _: &crate::FindingSink,
    ) -> Result<(), crate::ConnectorError> {
        Ok(())
    }

    async fn audit_stream(
        &self,
        _: &crate::AuditConfig,
        _: &crate::EventSink,
    ) -> Result<(), crate::ConnectorError> {
        Ok(())
    }
}

#[tokio::test]
async fn connector_failure_code_is_reported_as_last_error() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    let unreachable = TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(FailureCode::TargetUnreachable),
        detail: None,
    };
    let healthy = TargetHealth {
        reachable: true,
        audit_level: AuditLevel::Limited,
        failure: None,
        detail: None,
    };
    for (health, expected) in [
        (
            TargetHealth::not_implemented(Engine::Postgres),
            Some(FailureCode::Unsupported),
        ),
        (unreachable, Some(FailureCode::TargetUnreachable)),
        (healthy, None),
    ] {
        let rt = Runtime::new(
            &env.config_path,
            env.config.clone(),
            vec![Box::new(Health(health.clone()))],
        )
        .unwrap();
        let statuses = rt.target_statuses(&env.config).await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].last_error, expected);
        assert_eq!(statuses[0].reachable, health.reachable);
    }
}

// ------------------------------------------------------- discovery scans

/// Records the bounds it receives and submits one e-mail finding built
/// through `ScanJob::classify`.
/// What a connector saw: sample rows, statement timeout, classifiers.
type SeenBounds = (
    u32,
    u32,
    Option<Vec<databastion_classifiers::id::ClassifierId>>,
);

struct Scanner(StdMutex<Vec<SeenBounds>>);

#[async_trait::async_trait]
impl Connector for Scanner {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    async fn check(&self) -> TargetHealth {
        TargetHealth::not_implemented(Engine::Postgres)
    }

    async fn discover(
        &self,
        job: &crate::ScanJob,
        sink: &crate::FindingSink,
    ) -> Result<(), crate::ConnectorError> {
        use databastion_classifiers::masking::{FindingLocation, RawSample};
        use databastion_classifiers::names::normalize_path;
        self.0.lock().unwrap().push((
            job.sample_rows(),
            job.statement_timeout_ms(),
            job.classifiers().map(<[_]>::to_vec),
        ));
        let raw = ["jane.doe@example.com", "john.smith@example.org"];
        let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
        for f in job.classify("email", &values) {
            let location = FindingLocation {
                database: normalize_path("shop"),
                schema: Some(normalize_path("crm")),
                object: normalize_path("customers"),
                field: normalize_path("email"),
            };
            sink.submit(f.into_finding(location)).await?;
        }
        Ok(())
    }

    async fn audit_stream(
        &self,
        _: &crate::AuditConfig,
        _: &crate::EventSink,
    ) -> Result<(), crate::ConnectorError> {
        Ok(())
    }
}

#[tokio::test]
async fn discovery_scans_go_through_the_gate_and_spool_fingerprinted_findings() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(Script(std::sync::Mutex::new(Vec::new().into())))
        .mount(&server)
        .await;
    let scanner = Arc::new(Scanner(StdMutex::new(Vec::new())));
    struct Shared(Arc<Scanner>);
    #[async_trait::async_trait]
    impl Connector for Shared {
        fn engine(&self) -> Engine {
            self.0.engine()
        }
        async fn check(&self) -> TargetHealth {
            self.0.check().await
        }
        async fn discover(
            &self,
            job: &crate::ScanJob,
            sink: &crate::FindingSink,
        ) -> Result<(), crate::ConnectorError> {
            self.0.discover(job, sink).await
        }
        async fn audit_stream(
            &self,
            cfg: &crate::AuditConfig,
            sink: &crate::EventSink,
        ) -> Result<(), crate::ConnectorError> {
            self.0.audit_stream(cfg, sink).await
        }
    }
    let rt = Runtime::new(
        &env.config_path,
        env.config.clone(),
        vec![Box::new(Shared(Arc::clone(&scanner)))],
    )
    .unwrap();
    let ok = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f81";
    let empty = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f82";
    let unknown_id = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f83";
    let bad_timeout = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f84";
    let unknown_target = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f85";
    let scan = |id: &str, target: &str, params: serde_json::Value| {
        serde_json::json!({
            "job_id": id, "type": "discovery.scan", "created_at": "2026-09-28T14:00:00Z",
            "target_id": target, "classifiers_version": "2026.09.1", "params": params
        })
    };
    let body = serde_json::json!({ "jobs": [
        // 10000 rows requested, local cap 1000; timeout 0 -> local cap.
        scan(ok, "pg-main", serde_json::json!({
            "sample_rows": 10000, "max_duration_s": 900, "statement_timeout_ms": 0,
            "classifiers": ["pii.email"]})),
        scan(empty, "pg-main", serde_json::json!({
            "sample_rows": 200, "max_duration_s": 900, "databases": []})),
        scan(unknown_id, "pg-main", serde_json::json!({
            "sample_rows": 200, "max_duration_s": 900, "classifiers": ["pii.unknown"]})),
        scan(bad_timeout, "pg-main", serde_json::json!({
            "sample_rows": 200, "max_duration_s": 900, "statement_timeout_ms": 50})),
        scan(unknown_target, "pg-other", serde_json::json!({
            "sample_rows": 200, "max_duration_s": 900})),
    ]});
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    // Refused jobs are reported at once; the valid one waits for the worker,
    // and a redelivery does not queue it twice.
    assert!(statuses(&server).await.iter().all(|(i, _)| i != ok));
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    assert_eq!(rt.lock_scans().queued.len(), 1);
    run_queued_scans(&rt).await;
    let got = statuses(&server).await;
    let find = |id: &str| got.iter().find(|(i, _)| i == id).unwrap().1.clone();
    assert_eq!(find(ok)["status"], "succeeded");
    for id in [empty, bad_timeout] {
        assert_eq!(find(id)["error"]["code"], "invalid_params", "{id}");
    }
    // An id outside the compiled classifier set is a capability mismatch.
    assert_eq!(find(unknown_id)["error"]["code"], "unsupported");
    assert_eq!(find(unknown_target)["error"]["code"], "unknown_target");
    assert_eq!(rt.counters.jobs_invalid_params.load(Ordering::Relaxed), 2);
    assert_eq!(
        rt.counters
            .jobs_unsupported_classifiers
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(rt.counters.findings_received.load(Ordering::Relaxed), 1);

    // Only the gated job reached the connector, clamped.
    let seen = scanner.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(
            1000,
            30_000,
            Some(vec![databastion_classifiers::id::ClassifierId::Email])
        )]
    );

    drain(&rt).await;
    let batches = sent_batches(&server).await;
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    serde_json::from_value::<databastion_protocol::FindingsBatch>(batch.clone()).unwrap();
    assert_eq!(
        batch["classifiers_version"],
        databastion_classifiers::id::CLASSIFIERS_VERSION
    );
    let item = &batch["findings"][0];
    assert_eq!(item["job_id"], serde_json::Value::Null);
    assert_eq!(batch["job_id"], ok);
    assert_eq!(item["masked_samples"].as_array().unwrap().len(), 2);
    let fps = item["fingerprints"].as_array().unwrap();
    assert_eq!(fps.len(), 2);
    // Fingerprints use the enrolled agent key.
    let key = databastion_classifiers::masking::HmacKey::new(&env.state.load_hmac_key().unwrap())
        .unwrap();
    let jane = key
        .fingerprint(
            databastion_classifiers::id::ClassifierId::Email,
            &databastion_classifiers::masking::RawSample::new("jane.doe@example.com"),
        )
        .unwrap();
    assert!(fps.iter().any(|f| f == jane.as_str()));
    let text = batch.to_string();
    assert!(!text.contains("jane") && !text.contains("smith"), "{text}");
}

/// Runs every queued scan (the scan worker, without its loop).
async fn run_queued_scans(rt: &Runtime) {
    loop {
        let next = rt.lock_scans().queued.pop_front();
        let Some(prepared) = next else {
            return;
        };
        rt.run_prepared_scan(prepared, std::future::pending()).await;
    }
}

/// Submits one finding, then never returns (a stuck scan).
struct Stuck;

#[async_trait::async_trait]
impl Connector for Stuck {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    async fn check(&self) -> TargetHealth {
        TargetHealth::not_implemented(Engine::Postgres)
    }

    async fn discover(
        &self,
        job: &crate::ScanJob,
        sink: &crate::FindingSink,
    ) -> Result<(), crate::ConnectorError> {
        use databastion_classifiers::masking::{FindingLocation, RawSample};
        use databastion_classifiers::names::normalize_path;
        let values = [RawSample::new("jane.doe@example.com")];
        for f in job.classify("email", &values) {
            let location = FindingLocation {
                database: normalize_path("shop"),
                schema: None,
                object: normalize_path("customers"),
                field: normalize_path("email"),
            };
            sink.submit(f.into_finding(location)).await?;
        }
        std::future::pending::<()>().await;
        Ok(())
    }

    async fn audit_stream(
        &self,
        _: &crate::AuditConfig,
        _: &crate::EventSink,
    ) -> Result<(), crate::ConnectorError> {
        Ok(())
    }
}

#[tokio::test]
async fn suspension_cancels_a_running_scan_and_flushes_its_findings() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let rt = Runtime::new(&env.config_path, env.config.clone(), vec![Box::new(Stuck)]).unwrap();
    let id = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f91";
    let reload = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f92";
    let body = serde_json::json!({ "jobs": [{
        "job_id": id, "type": "discovery.scan", "created_at": "2026-09-28T14:00:00Z",
        "target_id": "pg-main", "classifiers_version": "2026.09.1",
        "params": {"sample_rows": 200, "max_duration_s": 900}
    }]});
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    let (shutdown_tx, shutdown) = watch::channel(false);
    let worker = rt.scan_loop(shutdown);
    let driver = async {
        // The jobs path is free while the scan runs.
        for _ in 0..50 {
            if rt.counters.findings_received.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        rt.handle_job_list(
            &serde_json::to_vec(&serde_json::json!({"jobs": [
                job(reload, "agent.config.reload", serde_json::json!({}))
            ]}))
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(statuses(&server).await.iter().any(|(i, _)| i == reload));
        // Revocation: a fatal 401 suspends the agent.
        rt.set_state(RunState::Suspended);
        for _ in 0..50 {
            if statuses(&server).await.iter().any(|(i, _)| i == id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        shutdown_tx.send(true).unwrap();
    };
    let (r, ()) = tokio::join!(worker, driver);
    r.unwrap();
    let got = statuses(&server).await;
    let update = &got.iter().find(|(i, _)| i == id).unwrap().1;
    assert_eq!(update["error"]["code"], "cancelled");
    // The finding handed over before the cancellation was spooled.
    assert_eq!(rt.lock_spool().status().batches.0, 1);
    assert_eq!(rt.counters.findings_lost.load(Ordering::Relaxed), 0);
    assert!(rt.lock_scans().in_flight.is_empty());
}

// ------------------------------------------------ 501, classifier set, cap

const JOB: &str = "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a";

fn not_implemented(retry_after: Option<&str>) -> ResponseTemplate {
    let t = error_body(501, "unavailable");
    match retry_after {
        Some(v) => t.insert_header("Retry-After", v),
        None => t,
    }
}

fn metric(rt: &Runtime, name: &str) -> f64 {
    rt.metrics().0[&MetricsMapKey::try_from(name).unwrap()]
}

#[tokio::test]
async fn not_implemented_events_park_only_that_endpoint() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/events"))
        .respond_with(not_implemented(Some("3600")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/events"))
        .respond_with(Script(std::sync::Mutex::new(Vec::new().into())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(Script(std::sync::Mutex::new(Vec::new().into())))
        .mount(&server)
        .await;
    let rt = runtime(&env);
    // Queue: events first, then findings.
    rt.lock_spool()
        .push(&crate::spool::tests::events_batch())
        .unwrap();
    rt.spool_findings(
        Uuid::try_from(JOB).unwrap(),
        &TargetId::try_from("pg-main").unwrap(),
        databastion_protocol::Engine::Postgres,
        &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
        &crate::spool::tests::masked(3, "email"),
    )
    .unwrap();
    // 501 on /events: parked for Retry-After, the batch kept.
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Progress);
    {
        let mut parked = rt.lock_parked();
        let now = Instant::now();
        assert!(parked.is_parked(false, now));
        assert!(!parked.is_parked(true, now));
        let until = parked.events.until.unwrap();
        assert!(until >= now + Duration::from_secs(3590));
        assert!(until <= now + Duration::from_secs(3600 + 31));
    }
    assert!(rt.endpoint_parked(false));
    assert!(!rt.endpoint_parked(true));
    // /findings is not blocked behind the parked /events batch.
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Progress);
    assert_eq!(sent_batches(&server).await.len(), 1);
    // Only the parked batch is left, never dropped.
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Idle);
    let status = rt.lock_spool().status();
    assert_eq!(status.batches.0, 1);
    assert_eq!(status.dropped_batches.unwrap().0, 0);
    assert!((metric(&rt, "batches_parked_total") - 1.0).abs() < f64::EPSILON);
    // Once the park has elapsed, the same batch is sent again.
    rt.lock_parked().events.until = Some(Instant::now());
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Progress);
    assert_eq!(rt.lock_spool().status().batches.0, 0);
    assert!(!rt.endpoint_parked(false));
    assert_eq!(rt.lock_parked().events.strikes, 0);
    let events: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/events"))
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["batch_id"].clone())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], events[1], "the parked batch keeps its batch_id");
}

#[tokio::test]
async fn not_implemented_findings_do_not_block_events_and_pause_scans() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(not_implemented(None))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/events"))
        .respond_with(Script(std::sync::Mutex::new(Vec::new().into())))
        .mount(&server)
        .await;
    let rt = Runtime::new(
        &env.config_path,
        env.config.clone(),
        vec![Box::new(Flood(None))],
    )
    .unwrap();
    rt.spool_findings(
        Uuid::try_from(JOB).unwrap(),
        &TargetId::try_from("pg-main").unwrap(),
        databastion_protocol::Engine::Postgres,
        &databastion_protocol::ClassifiersVersion::try_from("2026.09.1").unwrap(),
        &crate::spool::tests::masked(2, "email"),
    )
    .unwrap();
    rt.lock_spool()
        .push(&crate::spool::tests::events_batch())
        .unwrap();
    // 501 without Retry-After: parked for the spool backoff.
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Progress);
    assert!(rt.endpoint_parked(true));
    let until = rt.lock_parked().findings.until.unwrap();
    assert!(until <= Instant::now() + Duration::from_secs(1));
    rt.lock_parked().findings.until = Some(Instant::now() + Duration::from_secs(60));
    // The events batch behind it is sent.
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Progress);
    assert_eq!(rt.flush_once(1).await.unwrap(), Flush::Idle);
    assert_eq!(rt.lock_spool().status().batches.0, 1);
    // No new findings are produced while /findings is parked.
    let body = serde_json::json!({ "jobs": [scan_job(
        "01920f5f-0c30-7e6f-a043-2b3c4d5e6fa1", "2026.09.1", serde_json::json!({}))] });
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    let (stop, shutdown) = watch::channel(false);
    let worker = rt.scan_loop(shutdown);
    let driver = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send(true).unwrap();
    };
    let (r, ()) = tokio::join!(worker, driver);
    r.unwrap();
    assert_eq!(rt.lock_scans().queued.len(), 1);
    assert_eq!(rt.counters.findings_received.load(Ordering::Relaxed), 0);
    // A second 501 grows the backoff; a contract answer ends the streak.
    assert_eq!(rt.lock_parked().findings.strikes, 1);
    let mut parked = Parked::default();
    let now = Instant::now();
    let d1 = parked.park(true, None, now, 0.999_999);
    let d2 = parked.park(true, None, now, 0.999_999);
    assert!(d2 > d1);
    parked.answered(true);
    assert!(!parked.is_parked(true, now));
    assert_eq!(parked.findings.strikes, 0);
    assert_eq!(
        parked.park(false, Some(Duration::from_secs(10)), now, 0.0),
        Duration::from_secs(10)
    );
}

fn scan_job(id: &str, version: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut params = serde_json::json!({"sample_rows": 200, "max_duration_s": 900});
    if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    serde_json::json!({
        "job_id": id, "type": "discovery.scan", "created_at": "2026-09-28T14:00:00Z",
        "target_id": "pg-main", "classifiers_version": version, "params": params
    })
}

/// Submits `Some(n)` findings then returns, or floods forever (`None`).
struct Flood(Option<usize>);

#[async_trait::async_trait]
impl Connector for Flood {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    async fn check(&self) -> TargetHealth {
        TargetHealth::not_implemented(Engine::Postgres)
    }

    async fn discover(
        &self,
        job: &crate::ScanJob,
        sink: &crate::FindingSink,
    ) -> Result<(), crate::ConnectorError> {
        use databastion_classifiers::masking::{FindingLocation, RawSample};
        use databastion_classifiers::names::normalize_path;
        let values = [RawSample::new("jane.doe@example.com")];
        let mut n = 0;
        while self.0.is_none_or(|max| n < max) {
            for f in job.classify("email", &values) {
                let location = FindingLocation {
                    database: normalize_path("shop"),
                    schema: None,
                    object: normalize_path("customers"),
                    field: normalize_path("email"),
                };
                sink.submit(f.into_finding(location)).await?;
            }
            n += 1;
        }
        Ok(())
    }

    async fn audit_stream(
        &self,
        _: &crate::AuditConfig,
        _: &crate::EventSink,
    ) -> Result<(), crate::ConnectorError> {
        Ok(())
    }
}

#[tokio::test]
async fn scans_with_an_unsupported_classifier_set_are_refused_before_the_target() {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    struct Untouchable;
    #[async_trait::async_trait]
    impl Connector for Untouchable {
        fn engine(&self) -> Engine {
            Engine::Postgres
        }
        async fn check(&self) -> TargetHealth {
            panic!("the target must not be touched");
        }
        async fn discover(
            &self,
            _: &crate::ScanJob,
            _: &crate::FindingSink,
        ) -> Result<(), crate::ConnectorError> {
            panic!("the target must not be touched");
        }
        async fn audit_stream(
            &self,
            _: &crate::AuditConfig,
            _: &crate::EventSink,
        ) -> Result<(), crate::ConnectorError> {
            panic!("the target must not be touched");
        }
    }
    let rt = Runtime::new(
        &env.config_path,
        env.config.clone(),
        vec![Box::new(Untouchable)],
    )
    .unwrap();
    let other_version = "01920f5f-0c30-7e6f-a043-2b3c4d5e6fb1";
    let unknown_id = "01920f5f-0c30-7e6f-a043-2b3c4d5e6fb2";
    // Even with otherwise invalid parameters, the capability check wins.
    let both = "01920f5f-0c30-7e6f-a043-2b3c4d5e6fb3";
    let body = serde_json::json!({ "jobs": [
        scan_job(other_version, "2026.10.1", serde_json::json!({})),
        scan_job(unknown_id, CLASSIFIERS_VERSION,
            serde_json::json!({"classifiers": ["pii.email", "pii.passport"]})),
        scan_job(both, "2099.01.1", serde_json::json!({"databases": []})),
    ]});
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    assert!(rt.lock_scans().queued.is_empty());
    assert!(rt.lock_scans().in_flight.is_empty());
    let got = statuses(&server).await;
    for id in [other_version, unknown_id, both] {
        let update = &got.iter().find(|(i, _)| i == id).unwrap().1;
        assert_eq!(update["status"], "failed", "{id}");
        assert_eq!(update["error"]["code"], "unsupported", "{id}");
    }
    assert_eq!(rt.counters.jobs_invalid_params.load(Ordering::Relaxed), 0);
    assert!((metric(&rt, "jobs_unsupported_classifiers_total") - 3.0).abs() < f64::EPSILON);
}

#[test]
fn per_job_findings_cap_matches_the_contract() {
    assert_eq!(MAX_FINDINGS_PER_JOB, 50_000);
}

async fn capped_scan(findings: Option<usize>, cap: usize) -> (MockServer, Runtime) {
    let server = MockServer::start().await;
    let env = enrolled(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(STATUS_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/findings"))
        .respond_with(Script(std::sync::Mutex::new(Vec::new().into())))
        .mount(&server)
        .await;
    let mut rt = Runtime::new(
        &env.config_path,
        env.config.clone(),
        vec![Box::new(Flood(findings))],
    )
    .unwrap();
    rt.findings_cap = cap;
    let body =
        serde_json::json!({ "jobs": [scan_job(JOB, CLASSIFIERS_VERSION, serde_json::json!({}))] });
    rt.handle_job_list(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    run_queued_scans(&rt).await;
    drain(&rt).await;
    (server, rt)
}

fn sent_findings(batches: &[serde_json::Value]) -> usize {
    batches
        .iter()
        .map(|b| b["findings"].as_array().unwrap().len())
        .sum()
}

#[tokio::test]
async fn scan_stops_at_the_per_job_findings_cap() {
    // A connector that never ends: stopped at the cap, not at its deadline.
    let (server, rt) = capped_scan(None, 450).await;
    let got = statuses(&server).await;
    let update = &got.iter().find(|(i, _)| i == JOB).unwrap().1;
    assert_eq!(update["status"], "failed");
    assert_eq!(update["error"]["code"], "resource_limit");
    // Exactly the cap was emitted (in several batches), none beyond.
    let batches = sent_batches(&server).await;
    assert!(batches.len() >= 3);
    assert_eq!(sent_findings(&batches), 450);
    assert!((metric(&rt, "scans_findings_capped_total") - 1.0).abs() < f64::EPSILON);
    assert_eq!(rt.counters.findings_lost.load(Ordering::Relaxed), 0);
    assert!(rt.lock_scans().in_flight.is_empty());
}

#[tokio::test]
async fn scan_reaching_exactly_the_cap_succeeds() {
    let (server, rt) = capped_scan(Some(7), 7).await;
    let got = statuses(&server).await;
    let update = &got.iter().find(|(i, _)| i == JOB).unwrap().1;
    assert_eq!(update["status"], "succeeded");
    assert_eq!(sent_findings(&sent_batches(&server).await), 7);
    assert!(metric(&rt, "scans_findings_capped_total").abs() < f64::EPSILON);
    // One more finding than the cap fails the job.
    let (server, _rt) = capped_scan(Some(8), 7).await;
    let got = statuses(&server).await;
    let update = &got.iter().find(|(i, _)| i == JOB).unwrap().1;
    assert_eq!(update["error"]["code"], "resource_limit");
    assert_eq!(sent_findings(&sent_batches(&server).await), 7);
}
