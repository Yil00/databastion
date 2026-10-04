//! The CAS connector wired into the agent runtime, against a mock console
//! (wiremock, bound to 127.0.0.1 by the test only; the agent itself never
//! listens, I1): a `cas` target, its findings and its access events reach
//! the console only once a heartbeat response lists `engine.cas`
//! (ADR-0039 decision 8, ADR-0042), and nothing raw leaves (I2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use databastion_core::{AgentConfig, EnrollOptions};
use tokio::sync::watch;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "dbe_TOKENTOKENTOKENTOKENTOKENTOKENTOKENTOKEN012";
const SCAN_ID: &str = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f91";
const AUDIT_ID: &str = "01920f5f-0c30-7e6f-a043-2b3c4d5e6f92";
/// Raw values of the fixtures: none may reach the console.
const RAW: [&str; 7] = [
    "jane.doe@example.org",
    "john.roe@example.org",
    "max.moe@example.org",
    "fake-clear-secret-0000",
    "alice.user",
    "ST-1-FAKEfakeFAKE",
    "192.0.2.77",
];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p =
            std::env::temp_dir().join(format!("databastion-cas-runtime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `202` with the batch's own id (`BatchAck`).
struct Ack;

impl Respond for Ack {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        ResponseTemplate::new(202)
            .set_body_json(serde_json::json!({"batch_id": body["batch_id"], "duplicate": false}))
    }
}

fn heartbeat_response(accepts: &[&str]) -> ResponseTemplate {
    let mut body = serde_json::json!({
        "console_min_protocol": 1,
        "heartbeat_interval_s": 10,
        "server_time": "2026-10-04T09:00:00Z"
    });
    if !accepts.is_empty() {
        body["accepts"] = serde_json::json!(accepts);
    }
    ResponseTemplate::new(200).set_body_json(body)
}

fn service(dir: &Path, id: u32, name: &str, email: &str) {
    std::fs::write(
        dir.join(format!("{name}-{id}.json")),
        format!(
            r#"{{"@class": "org.apereo.cas.services.OidcRegisteredService", "id": {id},
                "name": "{name}", "serviceId": "^https://{host}\\.example\\.org/.*",
                "clientId": "c{id}", "clientSecret": "fake-clear-secret-0000",
                "contacts": [{{"name": "Contact", "email": "{email}"}}]}}"#,
            host = name.to_ascii_lowercase()
        ),
    )
    .unwrap();
}

fn append(log: &Path, text: &str) {
    let mut f = std::fs::OpenOptions::new().append(true).open(log).unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

/// Requests received so far, as (path, JSON body).
async fn received(server: &MockServer) -> Vec<(String, serde_json::Value)> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            let body = serde_json::from_slice(&r.body).unwrap_or(serde_json::Value::Null);
            (r.url.path().to_owned(), body)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cas_results_wait_for_the_engine_capability() {
    // Every file of this test is the test's own (possibly root's).
    databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
    databastion_connector_cas::allow_agent_owned_files_for_tests();

    let server = MockServer::start().await;
    let dir = TempDir::new();
    let services = dir.0.join("services");
    std::fs::create_dir(&services).unwrap();
    service(&services, 1, "Hr", "jane.doe@example.org");
    service(&services, 2, "Wiki", "john.roe@example.org");
    service(&services, 3, "Mail", "max.moe@example.org");
    let log = dir.0.join("cas_audit.log");
    std::fs::write(&log, "").unwrap();
    let state_dir = dir.0.join("state");
    let text = format!(
        "console:\n  url: {}\n  insecure_dev_http: true\n  long_poll_wait_s: 0\n\
         state_dir: {}\nlimits:\n  min_audit_poll_interval_s: 1\n  \
         discovery_duty_cycle_percent: 100\ntargets:\n  - id: cas-prod\n    engine: cas\n    \
         cas:\n      service_registry:\n        json_dir: {}\n      audit_log:\n        \
         path: {}\n",
        server.uri(),
        state_dir.display(),
        services.display(),
        log.display()
    );
    let config_path = dir.0.join("agent.yaml");
    std::fs::write(&config_path, &text).unwrap();
    let config = AgentConfig::parse(&text).unwrap();

    // Enrollment: only the connectors of protocol 0.1.0 are listed.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/enroll"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("../../../../shared/protocol/fixtures/valid/EnrollResponse.default.json"),
            "application/json",
        ))
        .mount(&server)
        .await;
    let token = dir.0.join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    databastion_core::enroll(
        &config,
        &token,
        EnrollOptions::default(),
        &[databastion_core::Engine::Cas],
    )
    .await
    .unwrap();

    // The first heartbeat response lists no capability (an older console),
    // the next ones list `engine.cas`.
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(heartbeat_response(&[]))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent/v1/heartbeat"))
        .respond_with(heartbeat_response(&[
            "engine.cas",
            "job_progress.coverage",
            "target_status.notes",
        ]))
        .with_priority(2)
        .mount(&server)
        .await;
    let jobs = serde_json::json!({"jobs": [
        {
            "job_id": SCAN_ID, "type": "discovery.scan", "created_at": "2026-10-04T09:00:00Z",
            "target_id": "cas-prod", "classifiers_version": "2026.09.1",
            "params": {"sample_rows": 100, "max_duration_s": 600}
        },
        {
            "job_id": AUDIT_ID, "type": "audit.configure", "created_at": "2026-10-04T09:00:00Z",
            "target_id": "cas-prod",
            "params": {"enabled": true, "aggregation_window_s": 1, "poll_interval_s": 1}
        }
    ]});
    Mock::given(method("GET"))
        .and(path("/api/agent/v1/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jobs))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent/v1/jobs"))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/api/agent/v1/jobs/[0-9a-f-]{36}/status$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    for endpoint in ["findings", "events"] {
        Mock::given(method("POST"))
            .and(path(format!("/api/agent/v1/{endpoint}")))
            .respond_with(Ack)
            .mount(&server)
            .await;
    }

    let (stop, shutdown) = watch::channel(false);
    let agent = tokio::spawn(async move {
        databastion_core::run(
            &config_path,
            vec![Box::new(databastion_connector_cas::CasConnector::new())],
            shutdown,
        )
        .await
    });

    // Audit records keep coming while the stream runs (it starts at the end
    // of the file): successful logins and a service ticket.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut done = false;
    while Instant::now() < deadline {
        let when = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        append(
            &log,
            &format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"alice.user\", \"when\": {when}, \
                 \"clientIpAddress\": \"192.0.2.77\", \"userAgent\": \"curl/8.5.0 (x86_64)\"}}\n\
                 {{\"action\": \"SERVICE_TICKET_CREATED\", \"who\": \"alice.user\", \"when\": {when}, \
                 \"what\": \"ST-1-FAKEfakeFAKE-cas01 for https://hr.example.org/x?ticket=ST-1\", \
                 \"clientIpAddress\": \"192.0.2.77\"}}\n"
            ),
        );
        let reqs = received(&server).await;
        let heartbeats: Vec<&serde_json::Value> = reqs
            .iter()
            .filter(|(p, _)| p.ends_with("/heartbeat"))
            .map(|(_, b)| b)
            .collect();
        let reported = heartbeats.iter().any(|b| {
            b["targets"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t["engine"] == "cas"))
        });
        let findings = reqs.iter().any(|(p, _)| p.ends_with("/findings"));
        let events = reqs.iter().any(|(p, _)| p.ends_with("/events"));
        if reported && findings && events {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent).await;
    let reqs = received(&server).await;
    assert!(
        done,
        "requests: {:?}",
        reqs.iter().map(|r| &r.0).collect::<Vec<_>>()
    );

    // Before any heartbeat response listed `engine.cas`: no cas target, no
    // findings, no events.
    let enroll = reqs.iter().find(|(p, _)| p.ends_with("/enroll")).unwrap();
    assert!(!enroll.1["connectors"].to_string().contains("cas"));
    let heartbeats: Vec<usize> = reqs
        .iter()
        .enumerate()
        .filter(|(_, (p, _))| p.ends_with("/heartbeat"))
        .map(|(i, _)| i)
        .collect();
    let first = &reqs[heartbeats[0]].1;
    assert!(!first.to_string().contains("\"cas\""), "{first}");
    // The response to the second heartbeat is the first to list the token.
    let granted = heartbeats[1];
    for (i, (p, _)) in reqs.iter().enumerate() {
        if p.ends_with("/findings") || p.ends_with("/events") {
            assert!(i > granted, "{p} sent before engine.cas was listed");
        }
    }

    // Once listed: the target, its findings and its events.
    let status = reqs
        .iter()
        .filter(|(p, _)| p.ends_with("/heartbeat"))
        .flat_map(|(_, b)| b["targets"].as_array().cloned().unwrap_or_default())
        .find(|t| t["engine"] == "cas")
        .unwrap();
    assert_eq!(status["target_id"], "cas-prod");
    assert_eq!(status["reachable"], true);
    let findings: Vec<&serde_json::Value> = reqs
        .iter()
        .filter(|(p, _)| p.ends_with("/findings"))
        .flat_map(|(_, b)| b["findings"].as_array().unwrap().iter())
        .collect();
    assert!(
        findings.iter().any(|f| f["location"]["engine"] == "cas"
            && f["location"]["database"] == "service_registry"
            && f["location"]["field"] == "contacts[].email"
            && f["classifier"] == "pii.email"),
        "{findings:?}"
    );
    let events: Vec<&serde_json::Value> = reqs
        .iter()
        .filter(|(p, _)| p.ends_with("/events"))
        .flat_map(|(_, b)| b["events"].as_array().unwrap().iter())
        .collect();
    assert!(events.iter().all(|e| e["source"] == "cas_audit_log"));
    let connect = events.iter().find(|e| e["action"] == "connect").unwrap();
    assert!(connect["principal"]["db_user_fingerprint"].is_string());
    assert_eq!(connect["principal"]["client_addr"], "192.0.2.0");
    assert_eq!(connect["principal"]["application"], "curl/8.5.0");
    let read = events.iter().find(|e| e["action"] == "read").unwrap();
    assert_eq!(read["objects"][0]["database"], "service_registry");
    assert_eq!(read["objects"][0]["object"], "Hr");

    // I2: no raw value in anything the console received.
    let all = reqs
        .iter()
        .map(|(_, b)| b.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    for raw in RAW {
        assert!(!all.contains(raw), "{raw} reached the console");
    }
}
