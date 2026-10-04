//! Integration tests against the dev `openldap` service (`make dev`:
//! Debian slapd, seeded `dc=example,dc=org`, `slapo-accesslog` in
//! `cn=accesslog` with `reads writes session`, the service DN
//! `cn=databastion,ou=services,dc=example,dc=org` reading the tree except
//! `userPassword`, and `cn=accesslog`).
//!
//! - `DATABASTION_TEST_LDAP_URL`: `ldap://127.0.0.1:1389` (the tests use
//!   `tls: disable` on the loopback address). Without it, every test here
//!   is skipped, with a message on stderr.
//! - `DATABASTION_TEST_LDAP_PASSWORD`: the service DN's password
//!   (`DATABASTION_DB_PASSWORD` of `dev/.env`); the DN can be changed with
//!   `DATABASTION_TEST_LDAP_BIND_DN`.
//! - `DATABASTION_TEST_LDAP_ADMIN_PASSWORD`: the password of
//!   `cn=admin,dc=example,dc=org` (the root DN of the data database), for
//!   the over-privilege and bulk-export tests. Without it, those are
//!   skipped.
//! - `DATABASTION_TEST_LDAP_EXPORT_CMD`: a shell command running a real
//!   paged `ldapsearch` export of the tree as the administrator (CI:
//!   inside the container). Without it, the export is played by the
//!   connector's own client.
//! - `DATABASTION_TEST_LDAPS_URL` and `DATABASTION_TEST_LDAP_CA_FILE`: the
//!   dev server's LDAPS port (`ldaps://localhost:1636`) and the CA that
//!   signed its certificate, for the TLS tests (`verify_full`,
//!   `start_tls`). Without them, those are skipped.
//!
//! - `DATABASTION_TEST_LDAPI_PATH` and `DATABASTION_TEST_LDAPI_DN`: an
//!   `ldapi://` socket reachable from the test process and the DN slapd
//!   maps the test's Unix uid to, for SASL `EXTERNAL` (CI: the dev
//!   server's socket directory published to the runner by
//!   `dev/openldap/compose.ldapi.yml`, the runner's uid mapped to the
//!   service DN).
//!
//! `DATABASTION_TEST_REQUIRE` (comma-separated: `ldap`, `ldap-admin`,
//! `ldap-export`, `ldap-tls`, `ldapi`, or `all`) turns the matching skips
//! into failures.
//!
//! The tests are serialized.

// Skip notices and the recall table (counts only, never a value).
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::masking::{
    EventAction, EventSource, HmacKey, MaskedEvent, MaskedFinding, Signal,
};
use databastion_classifiers::names::normalize_ldap_dn;
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{
    AuditConfig, AuditLevel, Connector, ConnectorError, EventSink, FailureCode, FindingSink,
    NoteCode, ScanJob, ScanParams, TargetNote,
};

use crate::OpenldapConnector;
use crate::conn::{Auth, Session, Timeouts};
use crate::error::Stage;
use crate::proto::{Entry, Filter, Scope, Search};

mod cas_guard_it;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SERVICE_DN: &str = "cn=databastion,ou=services,dc=example,dc=org";
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const SUFFIX: &str = "dc=example,dc=org";

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

#[derive(Debug, Clone)]
struct Server {
    host: String,
    port: u16,
}

fn parse_url(url: &str, scheme: &str, default_port: &str) -> Server {
    let rest = url
        .strip_prefix(scheme)
        .unwrap_or_else(|| panic!("{scheme} URL expected"))
        .trim_end_matches('/');
    let (host, port) = rest.rsplit_once(':').unwrap_or((rest, default_port));
    Server {
        host: host.to_owned(),
        port: port.parse().expect("port"),
    }
}

fn server() -> Option<Server> {
    match std::env::var("DATABASTION_TEST_LDAP_URL") {
        Ok(url) => Some(parse_url(&url, "ldap://", "389")),
        Err(_) => {
            skip("ldap", "DATABASTION_TEST_LDAP_URL is not set");
            None
        }
    }
}

fn password() -> String {
    std::env::var("DATABASTION_TEST_LDAP_PASSWORD").expect("DATABASTION_TEST_LDAP_PASSWORD")
}

fn service_dn() -> String {
    std::env::var("DATABASTION_TEST_LDAP_BIND_DN").unwrap_or_else(|_| SERVICE_DN.to_owned())
}

fn admin_password() -> Option<String> {
    match std::env::var("DATABASTION_TEST_LDAP_ADMIN_PASSWORD") {
        Ok(p) => Some(p),
        Err(_) => {
            skip(
                "ldap-admin",
                "DATABASTION_TEST_LDAP_ADMIN_PASSWORD is not set",
            );
            None
        }
    }
}

/// A private temporary directory (secret file, audit state).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "databastion-ldap-it-{}-{}",
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

/// A declared target binding as `dn` (password in a `0600` file), with
/// more `openldap` settings in `settings` (default `{tls: disable}`).
fn target_with(s: &Server, dn: &str, password: &str, settings: &str) -> (TempDir, TargetConfig) {
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
        "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: ldap-it\n    \
         engine: openldap\n    host: \"{}\"\n    port: {}\n    account: \"{dn}\"\n    \
         secret: {{file: \"{}\"}}\n    openldap: {settings}\n",
        s.host,
        s.port,
        file.display()
    );
    let config = databastion_core::AgentConfig::parse(&yaml).unwrap();
    (dir, config.targets[0].clone())
}

fn target(s: &Server, dn: &str, password: &str) -> (TempDir, TargetConfig) {
    target_with(s, dn, password, "{tls: disable}")
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[7u8; 32]).unwrap())
}

/// Local limits of the scans here: Discovery pacing off (these tests are
/// about sampling; pacing is covered by `databastion_core::pacing`, the
/// core's runtime tests and the load harness of #92).
fn unpaced() -> Limits {
    Limits {
        discovery_duty_cycle_percent: 100,
        ..Limits::default()
    }
}

async fn scan(t: &TargetConfig) -> (Result<(), ConnectorError>, Vec<MaskedFinding>) {
    let connector = OpenldapConnector::new();
    let job = ScanJob::new(ScanParams::contract_defaults(), t, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(4096);
    let r = connector.discover(&job, &sink).await;
    drop(sink);
    let mut out = Vec::new();
    while let Some(f) = rx.recv().await {
        out.push(f);
    }
    (r, out)
}

/// (database, schema, object, field, classifier).
type Key = (String, Option<String>, String, String, String);

fn located(findings: &[MaskedFinding]) -> BTreeSet<Key> {
    findings
        .iter()
        .filter_map(|f| {
            let l = f.location()?;
            Some((
                l.database.as_str().to_owned(),
                l.schema.as_ref().map(|s| s.as_str().to_owned()),
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str().to_owned(),
            ))
        })
        .collect()
}

use crate::i2::Logs;

fn codes(notes: &[TargetNote]) -> Vec<&'static str> {
    notes.iter().map(|n| n.code().as_str()).collect()
}

#[tokio::test]
async fn check_proves_full_audit_and_minimal_privileges() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    let (_dir, t) = target(&s, &service_dn(), &password());
    let connector = OpenldapConnector::new();
    let health = connector.check(&t).await;
    assert!(health.reachable, "{:?}", health.detail);
    // The dev server logs reads: the check's own base search proves it.
    assert_eq!(health.audit_level, AuditLevel::Full, "{:?}", health.detail);
    let c = codes(&health.notes);
    assert!(
        c.contains(&NoteCode::PrivilegeWriteNotEvaluated.as_str()),
        "{c:?}"
    );
    assert!(
        c.contains(&NoteCode::PrivilegeAccesslogWithoutAudit.as_str()),
        "{c:?}"
    );
    assert!(
        !c.contains(&NoteCode::PrivilegePasswordAttributesReadable.as_str()),
        "{c:?}"
    );
    assert!(
        !c.contains(&NoteCode::PrivilegeConfigReadable.as_str()),
        "{c:?}"
    );
    assert!(
        !c.contains(&NoteCode::AuditReadsNotLogged.as_str()),
        "{c:?}"
    );
    assert_eq!(
        connector.audit_source(&t),
        Some(EventSource::OpenldapAccesslog)
    );
    // A wrong password: authentication_failed at the auth stage.
    let (_dir2, bad) = target(&s, &service_dn(), "not-the-password");
    let health = OpenldapConnector::new().check(&bad).await;
    assert!(!health.reachable);
    assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
    // An unknown log base: no Audit source.
    let (_dir3, nolog) = target_with(
        &s,
        &service_dn(),
        &password(),
        "{tls: disable, accesslog_base: \"cn=nosuchlog\"}",
    );
    let health = OpenldapConnector::new().check(&nolog).await;
    assert!(health.reachable);
    assert_eq!(health.audit_level, AuditLevel::None);
    assert!(codes(&health.notes).contains(&NoteCode::AuditAccesslogNotReadable.as_str()));
}

#[tokio::test]
async fn check_flags_a_dn_that_can_read_password_hashes() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    let Some(admin) = admin_password() else {
        return;
    };
    let (_dir, t) = target(&s, ADMIN_DN, &admin);
    let health = OpenldapConnector::new().check(&t).await;
    assert!(health.reachable, "{:?}", health.detail);
    let c = codes(&health.notes);
    assert!(
        c.contains(&NoteCode::PrivilegePasswordAttributesReadable.as_str()),
        "{c:?}"
    );
}

#[tokio::test]
async fn seed_recall_regression() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev/ground-truth.json");
    let gt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let expected: Vec<&serde_json::Value> = gt["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "openldap")
        .collect();
    assert!(!expected.is_empty());
    let (_dir, t) = target(&s, &service_dn(), &password());
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        scan(&t).await
    };
    r.unwrap();
    let found = located(&findings);
    if std::env::var("LDAP_IT_DEBUG").is_ok() {
        for f in &found {
            eprintln!("{f:?}");
        }
    }
    let mut per: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut false_positives = Vec::new();
    for l in &expected {
        // The ground truth's `container` is the location `schema`, its
        // `object` the structural object class.
        let container = l["expected_normalized_name"].as_str().map_or_else(
            || {
                normalize_ldap_dn(l["container"].as_str().unwrap())
                    .as_str()
                    .to_owned()
            },
            str::to_owned,
        );
        let object = l["object"].as_str().unwrap();
        let field = l["field"].as_str().unwrap();
        for c in l["expected_classifiers"].as_array().unwrap() {
            let c = c.as_str().unwrap();
            let e = per.entry(c.to_owned()).or_default();
            e.1 += 1;
            if found.contains(&(
                l["database"].as_str().unwrap().to_owned(),
                Some(container.clone()),
                object.to_owned(),
                field.to_owned(),
                c.to_owned(),
            )) {
                e.0 += 1;
            }
        }
        if l["negative_control"] == true {
            false_positives.extend(
                found
                    .iter()
                    .filter(|f| {
                        f.1.as_deref() == Some(container.as_str()) && f.2 == object && f.3 == field
                    })
                    .map(|f| f.4.clone()),
            );
        }
    }
    let (mut tp, mut total) = (0, 0);
    for (c, (hit, n)) in &per {
        eprintln!("openldap recall {c:<24} {hit}/{n}");
        tp += hit;
        total += n;
    }
    eprintln!(
        "openldap findings {}, negative-control hits {}",
        found.len(),
        false_positives.len()
    );
    assert_eq!(tp, total, "missed ground-truth locations: {per:?}");
    assert!(false_positives.is_empty(), "{false_positives:?}");
    // userPassword is never read: no finding on it anywhere; no DN-valued
    // attribute (`member`) either.
    assert!(
        !found
            .iter()
            .any(|f| f.3 == "userpassword" || f.3 == "member")
    );
    // Values and value-bearing names never reach a location nor the logs.
    let text = logs.text();
    for l in &expected {
        for v in l["name_values"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(l["values"].as_array().into_iter().flatten())
        {
            let v = v.as_str().unwrap();
            assert!(!text.contains(v), "a seeded value reached the logs");
            assert!(
                !found
                    .iter()
                    .any(|f| f.1.as_deref().is_some_and(|c| c.contains(v))),
                "a seeded value reached a location"
            );
        }
    }
    assert!(!text.contains("uid="), "an entry DN reached the logs");
    // Interim I2 check (end-of-phase-6 review L2): no ground-truth value
    // and no entry DN in the serialized findings nor in the logs.
    let values = crate::i2::ground_truth_values(&gt);
    assert!(!values.is_empty());
    let agent = service_dn();
    crate::i2::assert_clean(
        "serialized findings",
        &crate::i2::findings_text(&findings),
        &values,
        &[],
    );
    crate::i2::assert_clean("scan logs", &text, &values, &[&agent]);
}

/// A bulk export of the tree as the administrator: the real `ldapsearch`
/// of `DATABASTION_TEST_LDAP_EXPORT_CMD`, or the connector's client.
async fn export(s: &Server, password: &str) {
    if let Ok(cmd) = std::env::var("DATABASTION_TEST_LDAP_EXPORT_CMD") {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "export command failed");
        return;
    }
    skip(
        "ldap-export",
        "DATABASTION_TEST_LDAP_EXPORT_CMD is not set: exporting with the connector's client",
    );
    let stream = tokio::net::TcpStream::connect((s.host.as_str(), s.port))
        .await
        .unwrap();
    let mut session = Session::establish(
        crate::net::Transport::Tcp(stream),
        Timeouts::new(Duration::from_secs(10)),
        Auth::Simple {
            dn: ADMIN_DN,
            password,
        },
    )
    .await
    .unwrap();
    let search = Search {
        base: SUFFIX,
        scope: Scope::Sub,
        size_limit: 10_000,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present("objectClass"),
        attributes: &["*"],
    };
    let o = session
        .search(Stage::Sample, &search, &mut |_: Entry| {})
        .await
        .unwrap();
    assert!(o.entries > 80);
    session.close().await;
}

#[tokio::test]
async fn audit_reports_a_bulk_export_and_leaves_the_agent_out() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    let Some(admin) = admin_password() else {
        return;
    };
    let (dir, t) = target(&s, &service_dn(), &password());
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = AuditConfig::local(&t, 1, &limits).with_state_dir(dir.0.clone());
    let connector = Arc::new(OpenldapConnector::new());
    let (sink, mut rx) = EventSink::channel(4096);
    let stream_logs = Logs::default();
    let stream = {
        use tracing::instrument::WithSubscriber as _;
        let connector = Arc::clone(&connector);
        let cfg = cfg.clone();
        tokio::spawn(
            async move { connector.audit_stream(&cfg, &sink).await }
                .with_subscriber(stream_logs.dispatch()),
        )
    };
    // Let the stream start. On a first start it also reads the last minute
    // of the log (earlier tests): only what happens from here on counts.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let since = std::time::SystemTime::now() - Duration::from_secs(1);
    let logs = Logs::default();
    {
        let _guard = logs.capture();
        let (r, _) = scan(&t).await;
        r.unwrap();
    }
    export(&s, &admin).await;
    let mut events: Vec<MaskedEvent> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(e)) => events.push(e),
            Ok(None) => break,
            Err(_) => {
                if events
                    .iter()
                    .any(|e| e.signals().contains(&Signal::BulkSearch))
                {
                    break;
                }
            }
        }
    }
    stream.abort();
    events.retain(|e| e.ts() >= since);
    let agent = crate::dn::canon(&service_dn()).unwrap();
    let bulk: Vec<&MaskedEvent> = events
        .iter()
        .filter(|e| e.signals().contains(&Signal::BulkSearch))
        .collect();
    assert!(!bulk.is_empty(), "no bulk search reported: {events:?}");
    assert!(
        bulk.iter()
            .all(|e| e.principal().account_name() == ADMIN_DN),
        "{bulk:?}"
    );
    assert!(bulk.iter().map(|e| e.rows().unwrap_or(0)).sum::<u64>() > 80);
    // The administrator is not in openldap.clear_principals: its DN leaves
    // as a fingerprint.
    assert!(bulk.iter().all(|e| !e.principal().send_name()));
    // The agent's own scan and connections are routine.
    let own: Vec<&MaskedEvent> = events
        .iter()
        .filter(|e| e.principal().account_name() == agent)
        .collect();
    assert!(
        own.is_empty(),
        "the agent's own activity was reported: {own:?}"
    );
    // The administrator's bind is a connection.
    assert!(events.iter().any(
        |e| e.action() == EventAction::Connect && e.principal().account_name() == ADMIN_DN
    ));
    // The cursor was persisted.
    assert!(std::fs::read_dir(&dir.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".cursor")
    }));
    assert!(!logs.text().contains("uid="));
    // Interim I2 check (end-of-phase-6 review L2): no ground-truth value
    // and no entry DN in the serialized events (the administrator leaves
    // as a fingerprint), nor in the logs of the scan and of the stream.
    let values = crate::i2::ground_truth_values(&crate::i2::ground_truth());
    let agent = service_dn();
    crate::i2::assert_clean(
        "serialized events",
        &crate::i2::events_text(&events),
        &values,
        &[&agent],
    );
    crate::i2::assert_clean("scan logs", &logs.text(), &values, &[&agent]);
    crate::i2::assert_clean("stream logs", &stream_logs.text(), &values, &[&agent]);
}

#[tokio::test]
async fn tls_verify_full_and_start_tls() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    let (Ok(ldaps), Ok(ca)) = (
        std::env::var("DATABASTION_TEST_LDAPS_URL"),
        std::env::var("DATABASTION_TEST_LDAP_CA_FILE"),
    ) else {
        skip(
            "ldap-tls",
            "DATABASTION_TEST_LDAPS_URL / DATABASTION_TEST_LDAP_CA_FILE are not set",
        );
        return;
    };
    let tls = parse_url(&ldaps, "ldaps://", "636");
    let (_d1, t) = target_with(
        &tls,
        &service_dn(),
        &password(),
        &format!("{{tls: verify_full, ca_file: \"{ca}\"}}"),
    );
    let h = OpenldapConnector::new().check(&t).await;
    assert!(h.reachable, "{:?}", h.detail);
    // StartTLS on the cleartext port, to the certificate's host name.
    let plain = Server {
        host: tls.host.clone(),
        port: s.port,
    };
    let (_d2, t) = target_with(
        &plain,
        &service_dn(),
        &password(),
        &format!("{{tls: start_tls, ca_file: \"{ca}\"}}"),
    );
    let h = OpenldapConnector::new().check(&t).await;
    assert!(h.reachable, "{:?}", h.detail);
    // The system store does not trust the dev CA: refused at the TLS
    // stage, before any password is sent.
    let (_d3, t) = target_with(&tls, &service_dn(), &password(), "{tls: verify_full}");
    let h = OpenldapConnector::new().check(&t).await;
    assert!(!h.reachable);
    assert_eq!(h.notes[0].labels()[0].as_str(), "stage_tls");
}

/// SASL `EXTERNAL` over an `ldapi://` socket reachable from the test
/// process (`DATABASTION_TEST_LDAPI_PATH`), authenticating the test's Unix
/// uid as `DATABASTION_TEST_LDAPI_DN` (the DN slapd maps it to, e.g.
/// `gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`). In CI
/// (phase 7), the dev server's socket directory is published to the runner
/// (`dev/openldap/compose.ldapi.yml`) and `olcAuthzRegexp` maps the
/// runner's uid to the service DN, as recommended in `docs/05-security.md`;
/// a Discovery scan then reads the tree with that identity.
#[tokio::test]
async fn sasl_external_over_ldapi() {
    let _serial = SERIAL.lock().await;
    let (Ok(path), Ok(dn)) = (
        std::env::var("DATABASTION_TEST_LDAPI_PATH"),
        std::env::var("DATABASTION_TEST_LDAPI_DN"),
    ) else {
        skip(
            "ldapi",
            "DATABASTION_TEST_LDAPI_PATH / DATABASTION_TEST_LDAPI_DN are not set",
        );
        return;
    };
    let yaml = |account: &str| {
        format!(
            "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: ldapi-it\n    \
             engine: openldap\n    socket: \"{path}\"\n    account: \"{account}\"\n    \
             openldap: {{tls: disable, bind: sasl_external}}\n"
        )
    };
    let t = databastion_core::AgentConfig::parse(&yaml(&dn))
        .unwrap()
        .targets[0]
        .clone();
    let h = OpenldapConnector::new().check(&t).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(h.failure, None, "{:?}", h.detail);
    if dn.eq_ignore_ascii_case(SERVICE_DN) {
        // Mapped to the service DN: its read access applies.
        let (r, findings) = scan(&t).await;
        r.unwrap();
        assert!(!findings.is_empty(), "no finding read over ldapi://");
    }
    // Another expected identity: refused after the bind.
    let t = databastion_core::AgentConfig::parse(&yaml(
        "cn=not-the-agent,ou=services,dc=example,dc=org",
    ))
    .unwrap()
    .targets[0]
        .clone();
    let h = OpenldapConnector::new().check(&t).await;
    assert!(!h.reachable);
    assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
}
