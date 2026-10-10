//! Integration tests against MySQL and MariaDB servers: the dev environment
//! (`make dev`: MySQL 8.4 and MariaDB 11.4, seeded, with the dev-only TLS
//! material of `dev/mysql/initdb/30-tls.sh` and `dev/mariadb/tls-entrypoint.sh`).
//!
//! Per server (`MYSQL` or `MARIADB`):
//! - `DATABASTION_TEST_<S>_URL`: the agent account on the seeded database
//!   (`mysql://databastion:…@127.0.0.1:3306/hr`). Without it, every test
//!   here is skipped for that server, with a message on stderr.
//! - `DATABASTION_TEST_<S>_ADMIN_URL`: an administrator (`root`), for the
//!   probe fixtures (databases `databastion_probe` and
//!   `databastion_probe_sink`, dropped and recreated, and test accounts
//!   `databastion_it_*`). Without it, those tests are skipped.
//! - `DATABASTION_TEST_<S>_CA_FILE`: the dev CA; the tests then connect
//!   with `tls: verify_full`, otherwise with `tls: disable` (loopback).
//!   MySQL accounts use `caching_sha2_password`, whose full authentication
//!   the connector only performs over TLS: the MySQL fixture tests need it.
//!
//! `DATABASTION_TEST_MARIADB_NETWORK_HOST`: a non-loopback address of the
//! MariaDB server, port 3306 (e.g. the container address), for the
//! `mysql_native_password` refusal on a network without TLS.
//!
//! `DATABASTION_TEST_REQUIRE` (comma-separated: `mysql`, `mariadb`,
//! `mysql-admin`, `mariadb-admin`, `mysql-tls`, `mariadb-tls`, `federated`,
//! `pam`, `network`, the Audit keys of [`audit_it`] (`mariadb-audit`,
//! `percona`, `percona-audit`, `mysqldump`), or `all`) turns the matching
//! skips into failures: CI lists what each run must exercise.
//!
//! The tests are serialized. They live in the crate (not `tests/`) to reach
//! the session layer for the kill and transaction probes.

// Skip notices and the recall table (counts only, never a value).
#![allow(clippy::print_stderr)]

mod audit_it;
mod builtins_it;
mod cas_guard_it;
mod explain_it;
mod stmt_text_it;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{
    AuditLevel, Connector, ConnectorError, FailureCode, FindingSink, NoteCode, ScanJob, ScanParams,
    TargetNote,
};

use crate::MysqlConnector;
use crate::conn::{Flavor, Session, Timeouts};
use crate::discover::normalize;
use crate::error::Stage;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PROBE_DB: &str = "databastion_probe";
const SINK_DB: &str = "databastion_probe_sink";
const RW_USER: &str = "databastion_it_rw";
const MIN_USER: &str = "databastion_it_min";
const SINK_USER: &str = "databastion_it_sink";
const PAM_USER: &str = "databastion_it_pam";
const AUTH_USER: &str = "databastion_it_auth";
const EXT_USER: &str = "databastion_it_ext";
/// SELECT on the probe database only (the dev agent account reads the
/// seeded database only, ADR-0018 minimal variant).
const SCAN_USER: &str = "databastion_it_scan";
const IT_PASSWORD: &str = "dev-only-it-account-FAKE";
/// An account holding its privileges through roles (P4-D).
const ROLE_USER: &str = "databastion_it_roles";
/// Its roles: SELECT, then DELETE, on the seeded database (default role);
/// INSERT and UPDATE there, granted but not enabled; SELECT on `mysql`,
/// through the previous role; DROP, as a MySQL mandatory role.
const ROLE_READ: &str = "databastion_it_r_read";
const ROLE_WRITE: &str = "databastion_it_r_write";
const ROLE_SYS: &str = "databastion_it_r_sys";
const ROLE_MANDATORY: &str = "databastion_it_r_mand";

#[derive(Debug, Clone)]
struct Url {
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
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

/// `mysql://user:password@host:port/db`.
fn parse_url(raw: &str) -> Option<Url> {
    let rest = raw
        .strip_prefix("mysql://")
        .or_else(|| raw.strip_prefix("mariadb://"))?;
    let (auth, rest) = rest.rsplit_once('@')?;
    let (user, password) = auth.split_once(':')?;
    let (hostport, db) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = hostport.rsplit_once(':').unwrap_or((hostport, "3306"));
    Some(Url {
        host: host.to_owned(),
        port: port.parse().ok()?,
        user: percent_decode(user)?,
        password: percent_decode(password)?,
        dbname: db.to_owned(),
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

#[derive(Debug, Clone)]
struct Server {
    /// `mysql` or `mariadb` (also the target engine).
    name: &'static str,
    url: Url,
    admin: Option<Url>,
    ca: Option<String>,
}

impl Server {
    fn flavor(&self) -> Flavor {
        if self.name == "mariadb" {
            Flavor::Mariadb
        } else {
            Flavor::Mysql
        }
    }

    /// TLS settings of the targets built for this server.
    fn tls(&self) -> String {
        match &self.ca {
            Some(ca) => format!("tls: verify_full, ca_file: \"{ca}\""),
            None => "tls: disable".to_owned(),
        }
    }

    /// The admin URL, or a skip. MySQL fixtures also need TLS (full
    /// authentication of the test accounts).
    fn admin(&self) -> Option<Url> {
        let Some(a) = self.admin.clone() else {
            skip(
                &format!("{}-admin", self.name),
                &format!(
                    "DATABASTION_TEST_{}_ADMIN_URL is not set (probe fixtures)",
                    self.name.to_uppercase()
                ),
            );
            return None;
        };
        if self.name == "mysql" && self.ca.is_none() {
            skip(
                "mysql-tls",
                "DATABASTION_TEST_MYSQL_CA_FILE is not set (MySQL test accounts need TLS)",
            );
            return None;
        }
        Some(a)
    }
}

/// The configured servers; a skip message for each missing one.
fn servers() -> Vec<Server> {
    let mut out = Vec::new();
    for name in ["mysql", "mariadb"] {
        let upper = name.to_uppercase();
        let var = |suffix: &str| std::env::var(format!("DATABASTION_TEST_{upper}_{suffix}")).ok();
        let Some(url) = var("URL").as_deref().and_then(parse_url) else {
            skip(
                name,
                &format!("DATABASTION_TEST_{upper}_URL is not set (start `make dev`)"),
            );
            continue;
        };
        // The dev agent account requires TLS (ADR-0018): without the CA,
        // the server is not tested.
        let ca = var("CA_FILE");
        if ca.is_none() {
            skip(
                &format!("{name}-tls"),
                &format!(
                    "DATABASTION_TEST_{upper}_CA_FILE is not set (the dev account requires TLS)"
                ),
            );
            continue;
        }
        out.push(Server {
            name,
            url,
            admin: var("ADMIN_URL").as_deref().and_then(parse_url),
            ca,
        });
    }
    out
}

/// A private temporary directory holding the target secret file.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "databastion-my-it-{}-{}",
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

/// A declared target for `server` with `user` (password in a `0600`
/// file) and the given TLS settings.
fn target_tls(server: &Server, user: &str, password: &str, tls: &str) -> (TempDir, TargetConfig) {
    target_at(
        server,
        &server.url.host,
        server.url.port,
        user,
        password,
        tls,
    )
}

/// Same, at another address.
fn target_at(
    server: &Server,
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    tls: &str,
) -> (TempDir, TargetConfig) {
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
        "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: my-it\n    \
         engine: {}\n    host: \"{}\"\n    port: {}\n    account: \"{user}\"\n    \
         secret: {{file: \"{}\"}}\n    mysql: {{{tls}}}\n",
        server.name,
        host,
        port,
        file.display()
    );
    let config = databastion_core::AgentConfig::parse(&yaml).unwrap();
    (dir, config.targets[0].clone())
}

fn target(server: &Server, user: &str, password: &str) -> (TempDir, TargetConfig) {
    target_tls(server, user, password, &server.tls())
}

fn agent_target(server: &Server) -> (TempDir, TargetConfig) {
    target(server, &server.url.user, &server.url.password)
}

/// An administrator session (no read-only default). The connector's
/// session setup pins `wait_timeout` to 60 s; test fixtures keep their
/// admin session open across long steps (a probe scan under a loaded CI
/// runner takes longer), so the idle timeout is raised on this session
/// only: otherwise the server closes it and the next query fails.
async fn admin_session(server: &Server, admin: &Url) -> Session {
    let (_dir, t) = target(server, &admin.user, &admin.password);
    let mut s = Session::connect_admin(&t, Timeouts::new(Duration::from_secs(120)))
        .await
        .unwrap();
    exec(&mut s, "SET SESSION wait_timeout = 3600").await;
    s
}

async fn exec(s: &mut Session, statement: &str) {
    if let Err(e) = s.exec(Stage::Check, statement).await {
        panic!("{e:?}: {statement}");
    }
}

async fn scalar(s: &mut Session, statement: &str) -> Option<String> {
    s.query(Stage::Check, statement)
        .await
        .unwrap_or_else(|e| panic!("{e:?}: {statement}"))
        .into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .flatten()
}

async fn count(s: &mut Session, statement: &str) -> i64 {
    scalar(s, statement)
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
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

async fn scan(target: &TargetConfig) -> (Result<(), ConnectorError>, Vec<MaskedFinding>) {
    let job = ScanJob::new(ScanParams::contract_defaults(), target, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(100_000);
    let r = MysqlConnector::new().discover(&job, &sink).await;
    drop(sink);
    let mut out = Vec::new();
    while let Some(f) = rx.recv().await {
        out.push(f);
    }
    (r, out)
}

type Key = (String, String, String, &'static str);

fn located(findings: &[MaskedFinding]) -> BTreeSet<Key> {
    findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            assert!(l.schema.is_none(), "MySQL locations have no schema");
            (
                l.database.as_str().to_owned(),
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str(),
            )
        })
        .collect()
}

fn key_of(db: &str, object: &str, field: &str, classifier: &'static str) -> Key {
    (
        db.to_owned(),
        object.to_owned(),
        field.to_owned(),
        classifier,
    )
}

fn sampled(findings: &[MaskedFinding], db: &str, object: &str, field: &str) -> Option<u32> {
    findings
        .iter()
        .find(|f| {
            let l = f.location().unwrap();
            l.database.as_str() == db && l.object.as_str() == object && l.field.as_str() == field
        })
        .map(MaskedFinding::sampled)
}

/// Captures every log line of the current thread (current-thread runtime:
/// the connector's spawned tasks run here too).
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

/// Connection ids of the agent's sessions (connection attribute
/// `program_name = databastion-agent`), seen by an administrator.
async fn agent_connections(admin: &mut Session) -> Vec<String> {
    admin
        .query(
            Stage::Check,
            "SELECT a.PROCESSLIST_ID FROM performance_schema.session_connect_attrs a \
             WHERE a.ATTR_NAME = 'program_name' AND a.ATTR_VALUE = 'databastion-agent' \
               AND a.PROCESSLIST_ID <> CONNECTION_ID()",
        )
        .await
        .unwrap()
        .into_iter()
        .filter_map(|r| r.into_iter().next().flatten())
        .collect()
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn admin_sessions_outlive_the_connector_idle_timeout() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        assert_eq!(
            scalar(&mut a, "SELECT @@session.wait_timeout")
                .await
                .as_deref(),
            Some("3600"),
            "{}",
            server.name
        );
    }
}

#[tokio::test]
async fn check_reports_reachable_with_an_honest_audit_level() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let (_dir, t) = agent_target(&server);
        let health = MysqlConnector::new().check(&t).await;
        assert!(health.reachable, "{}: {health:?}", server.name);
        assert_eq!(health.failure, None);
        let detail = health.detail.unwrap();
        eprintln!("{} check: {detail}", server.name);
        // ADR-0018 minimal variant: no performance_schema grant (the Audit
        // tests use their own account) and no audit log on this target:
        // no source the account can read.
        assert_eq!(health.audit_level, AuditLevel::None, "{detail}");
        assert!(
            detail.contains("performance_schema not readable by the account"),
            "{detail}"
        );
        assert!(detail.contains("no audit source"), "{detail}");
        // The dev account is not over-privileged.
        assert!(!detail.contains("over-privileged"), "{detail}");
        // The same as closed notes, every one registered for the engine.
        assert_registered_notes(server.flavor(), &health.notes);
        note(&health.notes, NoteCode::AuditPerformanceSchemaNotReadable);
        assert!(
            !health
                .notes
                .iter()
                .any(|n| n.code().as_str().starts_with("privilege.")),
            "{}: {:?}",
            server.name,
            health.notes
        );
        if server.name == "mariadb" {
            assert!(
                detail.contains("server_audit active (logging ON, file output)"),
                "{detail}"
            );
            assert!(
                detail.contains("reading its log needs mysql.audit_log"),
                "{detail}"
            );
            let n = note(&health.notes, NoteCode::AuditServerAuditNotRead);
            let labels: Vec<String> = n.labels().iter().map(|l| l.as_str()).collect();
            assert_eq!(labels, ["logging_on", "file_output"]);
        }

        // Wrong password: authentication_failed, no server text.
        let (_dir, bad) = target(&server, &server.url.user, "wrong-password-FAKE");
        let health = MysqlConnector::new().check(&bad).await;
        assert!(!health.reachable);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(health.notes.len(), 1, "{:?}", health.notes);
        assert_eq!(health.notes[0].code(), NoteCode::CheckStageFailed);
        assert!(!health.notes[0].labels()[0].is_other());
        let detail = health.detail.unwrap();
        assert!(
            !detail.contains("denied") && !detail.contains("databastion"),
            "{detail}"
        );
    }
}

/// Every note is registered in the contract registry for the server's
/// engine (`check.server_is_*` for the declared one).
fn assert_registered_notes(flavor: Flavor, notes: &[TargetNote]) {
    let registry: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../shared/protocol/target-notes.json"
    ))
    .unwrap();
    let engine = match flavor {
        Flavor::Mysql => "mysql",
        Flavor::Mariadb => "mariadb",
    };
    for n in notes {
        let engines = registry[n.code().as_str()]["engines"].as_array();
        assert!(
            engines.is_some_and(|e| e.iter().any(|x| x == engine)),
            "{} not registered for {engine}",
            n.code().as_str()
        );
    }
}

fn note(notes: &[TargetNote], code: NoteCode) -> &TargetNote {
    notes
        .iter()
        .find(|n| n.code() == code)
        .unwrap_or_else(|| panic!("no {} note: {notes:?}", code.as_str()))
}

#[tokio::test]
async fn sessions_are_read_only_with_timeouts() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let (_dir, t) = agent_target(&server);
        let mut session = Session::connect(&t, Timeouts::new(Duration::from_millis(1500)))
            .await
            .unwrap();
        // MariaDB names `transaction_isolation` so only from 11.1 on; `tx_isolation` exists on every
        // supported release (10.11 included).
        let (timeout, ro, isolation) = match server.flavor() {
            Flavor::Mysql => (
                "@@session.max_execution_time",
                "@@session.transaction_read_only",
                "@@session.transaction_isolation",
            ),
            Flavor::Mariadb => (
                "@@session.max_statement_time",
                "@@session.tx_read_only",
                "@@session.tx_isolation",
            ),
        };
        let mut tx = session.begin().await.unwrap();
        let row = tx
            .query(
                Stage::Check,
                &format!(
                    "SELECT {timeout}, {ro}, @@session.sql_mode, @@session.wait_timeout, \
                     @@session.net_read_timeout, @@session.net_write_timeout, \
                     @@session.lock_wait_timeout, @@session.character_set_results, \
                     {isolation}"
                ),
            )
            .await
            .unwrap()
            .remove(0);
        let got: Vec<String> = row.into_iter().map(Option::unwrap_or_default).collect();
        let expected_timeout = match server.flavor() {
            Flavor::Mysql => "1500",
            Flavor::Mariadb => "1.500000",
        };
        assert_eq!(got[0], expected_timeout, "{}", server.name);
        assert_eq!(got[1], "1");
        assert!(got[2].contains("NO_BACKSLASH_ESCAPES") && got[2].contains("STRICT_ALL_TABLES"));
        assert_eq!(
            &got[3..9],
            ["60", "30", "30", "2", "utf8mb4", "READ-COMMITTED"]
        );
        tx.commit().await.unwrap();

        // The statement timeout applies on the server.
        let mut session = Session::connect(&t, Timeouts::new(Duration::from_millis(300)))
            .await
            .unwrap();
        let mut tx = session.begin().await.unwrap();
        let started = Instant::now();
        let r = tx.query(Stage::Sample, "SELECT SLEEP(3)").await;
        assert!(started.elapsed() < Duration::from_secs(2), "{r:?}");
        match r {
            // MySQL interrupts SLEEP() and returns 1.
            Ok(rows) => assert_eq!(rows[0][0].as_deref(), Some("1")),
            // MariaDB: ER_STATEMENT_TIMEOUT.
            Err(e) => {
                assert_eq!(e.code, FailureCode::Timeout, "{e:?}");
                assert!(!e.fatal);
            }
        }
        tx.rollback().await;
    }
}

#[tokio::test]
async fn dropped_statement_is_killed_on_the_server() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let (_dir, t) = agent_target(&server);
        let mut observer = admin_session(&server, &admin).await;
        let running = |marker: &'static str| {
            format!(
                "SELECT COUNT(*) FROM information_schema.PROCESSLIST \
                 WHERE COMMAND = 'Query' AND ID <> CONNECTION_ID() \
                   AND INFO LIKE '%{marker}%'"
            )
        };
        let timeouts = Timeouts::new(Duration::from_secs(60));

        // Control: a statement whose future is dropped without the guard
        // keeps running on the server (administrator account: the agent
        // account is limited to 4 sessions).
        {
            let (_dir, admin_t) = target(&server, &admin.user, &admin.password);
            let mut plain = Session::connect_unguarded(&admin_t, timeouts)
                .await
                .unwrap();
            let fut = plain.query(Stage::Sample, "SELECT SLEEP(4) /* it-control */");
            assert!(
                tokio::time::timeout(Duration::from_millis(300), fut)
                    .await
                    .is_err()
            );
            drop(plain);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                count(&mut observer, &running("it-control")).await,
                1,
                "{}: control still running after drop",
                server.name
            );
        }

        // The connector: the whole unit of work (session, transaction,
        // statement) is dropped at a deadline, as the core does at
        // `max_duration_s`; the statement is killed on the server.
        let work = async {
            let mut session = Session::connect(&t, timeouts).await.unwrap();
            let mut tx = session.begin().await.unwrap();
            let _ = tx
                .query(Stage::Sample, "SELECT SLEEP(30) /* it-kill */")
                .await;
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), work)
                .await
                .is_err()
        );
        let mut remaining = -1;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            remaining = count(&mut observer, &running("it-kill")).await;
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(
            remaining, 0,
            "{}: the dropped statement still runs on the server",
            server.name
        );
    }
}

#[tokio::test]
async fn no_transaction_is_held_across_submit() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        // An account that sees one table (`people`, two findings): the scan
        // blocks on its second submit, after sampling on its session.
        probe_fixtures(&server, &admin).await;
        let (_dir, t) = target(&server, MIN_USER, IT_PASSWORD);
        let mut observer = admin_session(&server, &admin).await;
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        // Capacity 1 and no consumer: the scan blocks in `submit().await`.
        let (sink, mut rx) = FindingSink::channel(1);
        let connector = MysqlConnector::new();
        let scan = connector.discover(&job, &sink);
        tokio::pin!(scan);
        assert!(
            tokio::time::timeout(Duration::from_secs(3), &mut scan)
                .await
                .is_err()
        );
        let ids = agent_connections(&mut observer).await;
        assert_eq!(ids.len(), 1, "{}: one agent session", server.name);
        let id = &ids[0];
        let trx = count(
            &mut observer,
            &format!(
                "SELECT COUNT(*) FROM information_schema.INNODB_TRX \
                 WHERE trx_mysql_thread_id = {id}"
            ),
        )
        .await;
        let command = scalar(
            &mut observer,
            &format!("SELECT COMMAND FROM information_schema.PROCESSLIST WHERE ID = {id}"),
        )
        .await;
        let locks = count(
            &mut observer,
            &format!(
                "SELECT COUNT(*) FROM performance_schema.metadata_locks l \
                 JOIN performance_schema.threads th ON th.THREAD_ID = l.OWNER_THREAD_ID \
                 WHERE th.PROCESSLIST_ID = {id}"
            ),
        )
        .await;
        assert_eq!(
            (trx, command.as_deref(), locks),
            (0, Some("Sleep"), 0),
            "{}: blocked in submit with the session idle, no transaction, no lock",
            server.name
        );
        let mut n = 0;
        loop {
            tokio::select! {
                r = &mut scan => {
                    r.unwrap();
                    break;
                }
                f = rx.recv() => n += usize::from(f.is_some()),
            }
        }
        while rx.try_recv().is_ok() {
            n += 1;
        }
        assert!(n > 1);
    }
}

#[tokio::test]
async fn seed_recall_regression() {
    let _serial = SERIAL.lock().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev/ground-truth.json");
    let gt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for server in servers() {
        let expected: Vec<&serde_json::Value> = gt["locations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|l| l["engine"] == server.name && l["database"] == server.url.dbname.as_str())
            .collect();
        if expected.is_empty() {
            skip(server.name, "no ground-truth location for this database");
            continue;
        }
        let (_dir, t) = agent_target(&server);
        let logs = Logs::default();
        let (r, findings) = {
            let _guard = logs.capture();
            scan(&t).await
        };
        r.unwrap();
        let found = located(&findings);
        let db = normalize(&server.url.dbname).as_str().to_owned();
        let names = |l: &serde_json::Value| {
            let s = |k: &str| normalize(l[k].as_str().unwrap_or("")).as_str().to_owned();
            (s("object"), s("field"))
        };
        let mut per: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
        let mut false_positives = 0;
        for l in &expected {
            let (o, f) = names(l);
            for c in l["expected_classifiers"].as_array().unwrap() {
                let id = ClassifierId::parse(c.as_str().unwrap()).unwrap().as_str();
                let e = per.entry(id).or_default();
                e.1 += 1;
                if found.contains(&key_of(&db, &o, &f, id)) {
                    e.0 += 1;
                }
            }
            if l["negative_control"] == true {
                false_positives += found
                    .iter()
                    .filter(|k| k.0 == db && k.1 == o && k.2 == f)
                    .count();
            }
        }
        let (mut tp, mut total) = (0, 0);
        for (c, (hit, n)) in &per {
            eprintln!("{} recall {c:<24} {hit}/{n}", server.name);
            tp += hit;
            total += n;
        }
        eprintln!(
            "{} findings {}, negative-control hits {false_positives}",
            server.name,
            found.len()
        );
        assert_eq!(
            tp, total,
            "{}: missed ground-truth locations: {per:?}",
            server.name
        );
        assert_eq!(false_positives, 0);
        // Value-bearing table names never reach a finding or a log in
        // clear.
        let text = logs.text();
        for k in &found {
            assert!(!k.1.contains('@') && !k.1.contains("richard"), "{k:?}");
        }
        assert!(
            !text.contains("jean.richard"),
            "a value-bearing name reached the logs"
        );
        assert!(
            !text.contains("@example."),
            "a sampled value reached the logs"
        );
    }
}

// ------------------------------------------------------------ probes

/// Recreates the probe database, the sink database and the test accounts.
/// Returns whether a FEDERATED table could be created.
async fn probe_fixtures(server: &Server, admin: &Url) -> bool {
    let mut a = admin_session(server, admin).await;
    let port = scalar(&mut a, "SELECT @@port").await.unwrap_or_default();
    for statement in [
        format!("DROP DATABASE IF EXISTS {PROBE_DB}"),
        format!("DROP DATABASE IF EXISTS {SINK_DB}"),
        format!("CREATE DATABASE {PROBE_DB} CHARACTER SET utf8mb4"),
        format!("CREATE DATABASE {SINK_DB} CHARACTER SET utf8mb4"),
    ] {
        exec(&mut a, &statement).await;
    }
    for user in [RW_USER, MIN_USER, SINK_USER, SCAN_USER] {
        exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        let plugin = match server.flavor() {
            Flavor::Mysql => "IDENTIFIED WITH caching_sha2_password BY",
            Flavor::Mariadb => "IDENTIFIED BY",
        };
        exec(
            &mut a,
            &format!("CREATE USER '{user}'@'%' {plugin} '{IT_PASSWORD}'"),
        )
        .await;
    }
    let p = PROBE_DB;
    for statement in [
        // Base table with a virtual generated column (computed on read)
        // and a stored one (read as stored).
        format!(
            "CREATE TABLE {p}.people (id INT PRIMARY KEY, email VARCHAR(120), \
             g VARCHAR(130) AS (CONCAT(email, '')) VIRTUAL, \
             s VARCHAR(130) AS (CONCAT(email, '')) STORED) ENGINE=InnoDB"
        ),
        format!(
            "INSERT INTO {p}.people (id, email) \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40) \
             SELECT i, CONCAT('probe.user', i, '@example.com') FROM n"
        ),
        // A definer function that writes, and a view calling it.
        format!("CREATE TABLE {p}.touched (at INT) ENGINE=InnoDB"),
        format!(
            "CREATE FUNCTION {p}.touch() RETURNS INT DETERMINISTIC MODIFIES SQL DATA \
             SQL SECURITY DEFINER \
             BEGIN INSERT INTO {p}.touched VALUES (1); RETURN 1; END"
        ),
        format!(
            "CREATE SQL SECURITY DEFINER VIEW {p}.v_touch AS \
             SELECT {p}.touch() AS t, email FROM {p}.people"
        ),
        // A table of an engine outside the allow-list.
        format!("CREATE TABLE {p}.csv_t (email VARCHAR(120) NOT NULL) ENGINE=CSV"),
        format!("INSERT INTO {p}.csv_t VALUES ('csv.user@example.com')"),
        // Rows of about 1 MiB each (64 text values of 4096 4-byte
        // characters): the 32 MiB per-table budget stops the sample.
        format!(
            "CREATE TABLE {p}.a_wide (email VARCHAR(120), {}) ENGINE=InnoDB ROW_FORMAT=DYNAMIC",
            (0..64)
                .map(|i| format!("c{i} MEDIUMTEXT"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!(
            "INSERT INTO {p}.a_wide \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40) \
             SELECT CONCAT('wide.user', i, '@example.com'), {} FROM n",
            (0..64)
                .map(|_| "REPEAT('\u{1F600}', 4096)".to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // M2: 2600 text columns of 4096 4-byte characters in one row
        // (about 42 MB, over the largest packet the connector accepts):
        // sampled in column batches, so the row never has to fit in one
        // packet and the scan goes on.
        format!(
            "CREATE TABLE {p}.a_many (email VARCHAR(120), {}) ENGINE=MyISAM",
            (0..2600)
                .map(|i| format!("m{i} MEDIUMTEXT"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!(
            "INSERT INTO {p}.a_many SELECT 'many.user@example.com', {}",
            (0..2600)
                .map(|_| "REPEAT('\u{1F600}', 4096)".to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // The sink of the FEDERATED table.
        format!("CREATE TABLE {SINK_DB}.src (email VARCHAR(120)) ENGINE=InnoDB"),
        format!("INSERT INTO {SINK_DB}.src VALUES ('sink.user@example.com')"),
        format!("GRANT SELECT ON {SINK_DB}.src TO '{SINK_USER}'@'%'"),
        // Test accounts: one with write privileges (read-only probe,
        // over-privilege), one with SELECT on one table only.
        format!("GRANT SELECT, INSERT, EXECUTE ON {p}.* TO '{RW_USER}'@'%'"),
        format!("GRANT SELECT ON {p}.people TO '{MIN_USER}'@'%'"),
        format!("GRANT SELECT ON {p}.* TO '{SCAN_USER}'@'%'"),
        format!("GRANT SELECT ON performance_schema.* TO '{MIN_USER}'@'%'"),
    ] {
        exec(&mut a, &statement).await;
    }
    // FEDERATED (MariaDB: the FederatedX plugin, installed on demand).
    if server.flavor() == Flavor::Mariadb {
        let installed = count(
            &mut a,
            "SELECT COUNT(*) FROM information_schema.ENGINES \
             WHERE ENGINE = 'FEDERATED' AND SUPPORT IN ('YES', 'DEFAULT')",
        )
        .await;
        if installed == 0 {
            let _ = a.exec(Stage::Check, "INSTALL SONAME 'ha_federatedx'").await;
        }
    }
    a.exec(
        Stage::Check,
        &format!(
            "CREATE TABLE {p}.fed (email VARCHAR(120)) ENGINE=FEDERATED \
             CONNECTION='mysql://{SINK_USER}:{IT_PASSWORD}@127.0.0.1:{port}/{SINK_DB}/src'"
        ),
    )
    .await
    .is_ok()
        && count(
            &mut a,
            &format!(
                "SELECT COUNT(*) FROM information_schema.TABLES \
                 WHERE TABLE_SCHEMA = '{p}' AND TABLE_NAME = 'fed' AND ENGINE = 'FEDERATED'"
            ),
        )
        .await
            == 1
}

/// Connections opened by the FEDERATED sink account so far.
async fn sink_connections(a: &mut Session) -> i64 {
    count(
        a,
        &format!(
            "SELECT COALESCE(SUM(TOTAL_CONNECTIONS), 0) FROM performance_schema.accounts \
             WHERE USER = '{SINK_USER}'"
        ),
    )
    .await
}

#[tokio::test]
async fn probes() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let federated = probe_fixtures(&server, &admin).await;
        let mut a = admin_session(&server, &admin).await;
        let (_dir, t) = target(&server, SCAN_USER, IT_PASSWORD);
        let db = normalize(PROBE_DB).as_str().to_owned();

        // Control for the FEDERATED probe: a read through the table
        // connects to the sink account.
        let before = if federated {
            let before = sink_connections(&mut a).await;
            let _ = a
                .query(
                    Stage::Check,
                    &format!("SELECT COUNT(*) FROM {PROBE_DB}.fed"),
                )
                .await;
            let after = sink_connections(&mut a).await;
            assert!(after > before, "{}: control: FEDERATED read", server.name);
            Some(after)
        } else {
            skip(
                "federated",
                &format!("{}: FEDERATED engine not available", server.name),
            );
            None
        };

        let logs = Logs::default();
        let (r, findings) = {
            let _guard = logs.capture();
            scan(&t).await
        };
        r.unwrap();
        let text = logs.text();
        let found = located(&findings);
        let objects: BTreeSet<&str> = found
            .iter()
            .filter(|k| k.0 == db)
            .map(|k| k.1.as_str())
            .collect();
        // Base table sampled; the stored generated column is read, the
        // virtual one never selected.
        assert!(
            found.contains(&key_of(&db, "people", "email", "pii.email")),
            "{}: {found:?}",
            server.name
        );
        assert!(found.contains(&key_of(&db, "people", "s", "pii.email")));
        assert!(
            !found.iter().any(|k| k.1 == "people" && k.2 == "g"),
            "{}: virtual generated column sampled",
            server.name
        );
        assert!(text.contains("virtual generated columns not sampled"));
        // The view calling a definer function is not sampled, and the
        // function never ran.
        assert!(!objects.contains("v_touch"));
        assert!(text.contains("view (runs its definition with the definer's rights)"));
        assert_eq!(
            count(&mut a, &format!("SELECT COUNT(*) FROM {PROBE_DB}.touched")).await,
            0
        );
        // Engines outside the allow-list are not read.
        assert!(!objects.contains("csv_t") && !objects.contains("fed"));
        assert!(
            text.lines().any(|l| l.contains("object not covered")
                && l.contains("object=\"csv_t\"")
                && l.contains("engine not in the local-data allow-list")),
            "{text}"
        );
        if let Some(after_control) = before {
            assert!(text.lines().any(|l| l.contains("object not covered")
                && l.contains("object=\"fed\"")
                && l.contains("remote-access engine")));
            // The scan did not make the server connect to the sink.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                sink_connections(&mut a).await,
                after_control,
                "{}: the scan read the FEDERATED table",
                server.name
            );
        }
        // Byte budget: rows of ~1 MiB, 32 MiB per table, the statement
        // killed, the next tables sampled on a new session. The columns
        // are sampled in batches whose statements stay under the audit
        // logs' limits (`sql::sample_statements`), each within its share
        // of the budget (security review of 914c9d2, N2): the first batch
        // (`email` and about half the text columns) stops on its share,
        // the second runs on a new session.
        assert!(text.contains("sample byte budget reached"), "{text}");
        let email = sampled(&findings, &db, "a_wide", "email");
        assert!(email.is_some_and(|n| (10..40).contains(&n)), "{email:?}");
        assert!(
            text.matches("sample stopped: statement killed").count() >= 2,
            "{text}"
        );
        let mut lingering = -1;
        for _ in 0..50 {
            lingering = count(
                &mut a,
                "SELECT COUNT(*) FROM information_schema.PROCESSLIST \
                 WHERE COMMAND = 'Query' AND ID <> CONNECTION_ID() AND INFO LIKE '%a_wide%'",
            )
            .await;
            if lingering == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            lingering, 0,
            "{}: the stopped sample still runs",
            server.name
        );
        // M2: the very wide row is sampled in batches (its first batch
        // holds the e-mail column), the second batch stops at the byte
        // budget; no row was refused as oversized, and the scan went on.
        assert_eq!(sampled(&findings, &db, "a_many", "email"), Some(1));
        assert!(
            !text.contains("a row larger than the connector accepts"),
            "{text}"
        );
        // No system schema is ever sampled.
        for k in &found {
            assert!(
                !["mysql", "sys", "information_schema", "performance_schema"]
                    .contains(&k.0.as_str()),
                "{k:?}"
            );
        }

        // Read-only: an account with INSERT and EXECUTE cannot write in the
        // connector's transactions, directly or through a definer function.
        let (_dir, rw) = target(&server, RW_USER, IT_PASSWORD);
        let mut session = Session::connect(&rw, Timeouts::new(Duration::from_secs(5)))
            .await
            .unwrap();
        for statement in [
            format!("INSERT INTO {PROBE_DB}.touched VALUES (2)"),
            format!("SELECT {PROBE_DB}.touch()"),
        ] {
            let mut tx = session.begin().await.unwrap();
            let e = match tx.query(Stage::Check, &statement).await {
                Err(e) => e,
                Ok(_) => panic!("{}: {statement} succeeded", server.name),
            };
            // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
            assert_eq!(e.errno, Some(1792), "{}: {statement}", server.name);
            tx.rollback().await;
        }
        // Autocommit statements follow the session default (read only).
        let e = session
            .exec(
                Stage::Check,
                &format!("INSERT INTO {PROBE_DB}.touched VALUES (3)"),
            )
            .await
            .unwrap_err();
        assert_eq!(e.errno, Some(1792));
        drop(session);
        assert_eq!(
            count(&mut a, &format!("SELECT COUNT(*) FROM {PROBE_DB}.touched")).await,
            0
        );

        // Over-privilege: write privileges reported; a SELECT-only account
        // is not.
        let health = MysqlConnector::new().check(&rw).await;
        let detail = health.detail.unwrap();
        assert!(
            detail.contains(
                "privileges beyond SELECT on databases / tables / columns: EXECUTE, INSERT"
            ),
            "{}: {detail}",
            server.name
        );
        assert_registered_notes(server.flavor(), &health.notes);
        let labels: Vec<String> = note(&health.notes, NoteCode::PrivilegeBeyondSelect)
            .labels()
            .iter()
            .map(|l| l.as_str())
            .collect();
        assert_eq!(labels, ["execute", "insert"], "{}", server.name);
        let (_dir, min) = target(&server, MIN_USER, IT_PASSWORD);
        let health = MysqlConnector::new().check(&min).await;
        assert!(health.reachable);
        assert_eq!(health.audit_level, AuditLevel::Partial);
        let detail = health.detail.unwrap();
        // Its only over-privilege: performance_schema without Audit.
        assert!(
            detail.contains(
                "over-privileged: SELECT on performance_schema without Audit enabled \
                 (statement text of every session readable);"
            ) || detail.ends_with(
                "over-privileged: SELECT on performance_schema without Audit enabled \
                 (statement text of every session readable)"
            ),
            "{}: {detail}",
            server.name
        );
        note(
            &health.notes,
            NoteCode::PrivilegePerformanceSchemaWithoutAudit,
        );
        // It only sees (and samples) its table.
        let (r, findings) = scan(&min).await;
        r.unwrap();
        let objects: BTreeSet<String> = located(&findings).into_iter().map(|k| k.1).collect();
        assert_eq!(
            objects,
            BTreeSet::from(["people".to_owned()]),
            "{}",
            server.name
        );
    }
}

#[tokio::test]
async fn authentication_refusals() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let refused = |tls: &str, user: &str, password: &str| {
            let (dir, t) = target_tls(&server, user, password, tls);
            async move {
                let logs = Logs::default();
                let health = {
                    let _guard = logs.capture();
                    MysqlConnector::new().check(&t).await
                };
                drop(dir);
                (health, logs.text())
            }
        };
        match server.flavor() {
            Flavor::Mysql => {
                // A new account has no entry in the authentication cache:
                // caching_sha2_password asks for full authentication,
                // refused without TLS (no RSA key retrieval, no cleartext
                // password on TCP).
                exec(&mut a, &format!("DROP USER IF EXISTS '{AUTH_USER}'@'%'")).await;
                exec(
                    &mut a,
                    &format!(
                        "CREATE USER '{AUTH_USER}'@'%' IDENTIFIED WITH caching_sha2_password \
                         BY '{IT_PASSWORD}'"
                    ),
                )
                .await;
                let (health, logs) = refused("tls: disable", AUTH_USER, IT_PASSWORD).await;
                assert!(!health.reachable);
                assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
                assert!(logs.contains("full authentication without TLS"), "{logs}");
                // Over TLS it succeeds (and fills the cache); then the fast
                // path works without TLS on loopback.
                let (health, _) = refused(&server.tls(), AUTH_USER, IT_PASSWORD).await;
                assert!(health.reachable, "{health:?}");
                let (health, _) = refused("tls: disable", AUTH_USER, IT_PASSWORD).await;
                assert!(health.reachable, "{health:?}");
                exec(&mut a, &format!("DROP USER '{AUTH_USER}'@'%'")).await;
            }
            Flavor::Mariadb => {
                // mysql_native_password on a network without TLS
                // (`disable_insecure` to a non-loopback address: the
                // container's address, port 3306).
                match std::env::var("DATABASTION_TEST_MARIADB_NETWORK_HOST") {
                    Ok(host) => {
                        let (_dir, t) = target_at(
                            &server,
                            &host,
                            3306,
                            &server.url.user,
                            &server.url.password,
                            "tls: disable_insecure",
                        );
                        let logs = Logs::default();
                        let health = {
                            let _guard = logs.capture();
                            MysqlConnector::new().check(&t).await
                        };
                        let logs = logs.text();
                        assert!(!health.reachable, "{health:?}");
                        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
                        assert!(
                            logs.contains("mysql_native_password on a network"),
                            "{logs}"
                        );
                        assert!(logs.contains("tls: disable_insecure"));
                    }
                    Err(_) => skip(
                        "network",
                        "DATABASTION_TEST_MARIADB_NETWORK_HOST is not set (native password \
                         refusal on a network)",
                    ),
                }
                // PAM (the `dialog` plugin sends the password in clear).
                let _ = a.exec(Stage::Check, "INSTALL SONAME 'auth_pam'").await;
                let _ = a
                    .exec(
                        Stage::Check,
                        &format!("DROP USER IF EXISTS '{PAM_USER}'@'%'"),
                    )
                    .await;
                if a.exec(
                    Stage::Check,
                    &format!("CREATE USER '{PAM_USER}'@'%' IDENTIFIED VIA pam"),
                )
                .await
                .is_ok()
                {
                    let (health, logs) = refused(&server.tls(), PAM_USER, IT_PASSWORD).await;
                    assert!(!health.reachable);
                    assert!(
                        logs.contains("dialog (PAM, cleartext password) is never used")
                            || logs.contains("mysql_clear_password"),
                        "{logs}"
                    );
                } else {
                    skip("pam", "mariadb: auth_pam not available");
                }
            }
        }
    }
}

#[tokio::test]
async fn extended_variant_is_an_expected_warning_and_reads_no_system_table() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{EXT_USER}'@'%'")).await;
        exec(
            &mut a,
            &format!("CREATE USER '{EXT_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        exec(&mut a, &format!("GRANT SELECT ON *.* TO '{EXT_USER}'@'%'")).await;
        // Secrets in system tables the extended account can read (the
        // connector must never output them): a server definition password
        // (`mysql.servers`) and the textual password hashes.
        exec(&mut a, "DROP SERVER IF EXISTS databastion_it_srv").await;
        exec(
            &mut a,
            "CREATE SERVER databastion_it_srv FOREIGN DATA WRAPPER mysql \
             OPTIONS (USER 'u', PASSWORD 'ServerPwMarker-FAKE', HOST '192.0.2.1')",
        )
        .await;
        let mut hashes: Vec<String> = a
            .query(
                Stage::Check,
                "SELECT authentication_string FROM mysql.user \
                 WHERE CHAR_LENGTH(authentication_string) > 0",
            )
            .await
            .unwrap()
            .into_iter()
            .filter_map(|r| r.into_iter().next().flatten())
            .collect();
        hashes.push("ServerPwMarker-FAKE".to_owned());
        let with_flag = format!("{}, extended_grants: true", server.tls());
        let (_dir, t) = target_tls(&server, EXT_USER, IT_PASSWORD, &with_flag);
        let logs = Logs::default();
        let (r, findings, health) = {
            let _guard = logs.capture();
            let (r, findings) = scan(&t).await;
            let health = MysqlConnector::new().check(&t).await;
            (r, findings, health)
        };
        r.unwrap();
        let detail = health.detail.clone().unwrap();
        assert!(
            detail.contains("extended variant: global SELECT"),
            "{}: {detail}",
            server.name
        );
        assert!(!detail.contains("over-privileged"), "{detail}");
        // Every database readable, never a system one.
        let found = located(&findings);
        assert!(found.iter().any(|k| k.0 == server.url.dbname));
        for k in &found {
            assert!(
                !["mysql", "sys", "information_schema", "performance_schema"]
                    .contains(&k.0.as_str()),
                "{k:?}"
            );
        }
        let output = format!("{findings:?}\n{health:?}\n{}", logs.text());
        for hash in &hashes {
            assert!(
                !output.contains(hash.as_str()),
                "a password hash in agent output"
            );
        }
        // Same account without the flag: over-privileged.
        let (_dir, t) = target(&server, EXT_USER, IT_PASSWORD);
        let detail = MysqlConnector::new().check(&t).await.detail.unwrap();
        assert!(
            detail.contains("over-privileged: global SELECT"),
            "{}: {detail}",
            server.name
        );
        exec(&mut a, &format!("DROP USER '{EXT_USER}'@'%'")).await;
        exec(&mut a, "DROP SERVER databastion_it_srv").await;
    }
}

/// The `privilege.*` notes of a fresh `check()` (no cached report), with
/// the detail and the logs it wrote.
async fn privilege_check(t: &TargetConfig) -> (Vec<TargetNote>, String) {
    let logs = Logs::default();
    let health = {
        let _guard = logs.capture();
        MysqlConnector::new().check(t).await
    };
    assert!(health.reachable, "{health:?}");
    let notes = health
        .notes
        .into_iter()
        .filter(|n| n.code().as_str().starts_with("privilege."))
        .collect();
    (
        notes,
        format!("{}\n{}", health.detail.unwrap_or_default(), logs.text()),
    )
}

/// The labels of a note, sorted by name.
fn labels(n: &TargetNote) -> Vec<String> {
    let mut v: Vec<String> = n.labels().iter().map(|l| l.as_str()).collect();
    v.sort();
    v
}

async fn drop_role_fixtures(a: &mut Session) {
    exec(a, &format!("DROP USER IF EXISTS '{ROLE_USER}'@'%'")).await;
    for role in [ROLE_READ, ROLE_WRITE, ROLE_SYS, ROLE_MANDATORY] {
        exec(a, &format!("DROP ROLE IF EXISTS `{role}`")).await;
    }
}

/// The note `code` of `server`'s check; the panic names the server.
fn server_note<'a>(server: &str, notes: &'a [TargetNote], code: NoteCode) -> &'a TargetNote {
    notes
        .iter()
        .find(|n| n.code() == code)
        .unwrap_or_else(|| panic!("{server}: no {} note: {notes:?}", code.as_str()))
}

fn assert_no_note(server: &str, notes: &[TargetNote], code: NoteCode, output: &str) {
    assert!(
        !notes.iter().any(|n| n.code() == code),
        "{server}: unexpected {} note: {notes:?}\n{output}",
        code.as_str()
    );
}

/// P4-D: privileges held through roles.
///
/// MySQL: every applicable role is evaluated (`SHOW GRANTS FOR
/// CURRENT_USER() USING …`): the default role, a granted role that is not
/// enabled, a role granted through a role, and a mandatory role.
///
/// MariaDB shows a role's grants to a least-privilege account only for the
/// session's current role (the default role): its privileges are
/// evaluated, every other applicable role is reported as not evaluated,
/// never assumed harmless.
///
/// Both: `WITH ADMIN OPTION` is a grant option, and no role or account name
/// leaves the check.
#[tokio::test]
async fn role_privileges_are_evaluated() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let name = server.name;
        let mysql = server.flavor() == Flavor::Mysql;
        let db = server.url.dbname.clone();
        let mut a = admin_session(&server, &admin).await;
        drop_role_fixtures(&mut a).await;
        exec(
            &mut a,
            &format!("CREATE USER '{ROLE_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        for role in [ROLE_READ, ROLE_WRITE, ROLE_SYS] {
            exec(&mut a, &format!("CREATE ROLE `{role}`")).await;
        }
        exec(
            &mut a,
            &format!("GRANT SELECT ON `{db}`.* TO `{ROLE_READ}`"),
        )
        .await;
        exec(&mut a, &format!("GRANT `{ROLE_READ}` TO '{ROLE_USER}'@'%'")).await;
        let default_role = if mysql {
            format!("SET DEFAULT ROLE `{ROLE_READ}` TO '{ROLE_USER}'@'%'")
        } else {
            format!("SET DEFAULT ROLE `{ROLE_READ}` FOR '{ROLE_USER}'@'%'")
        };
        exec(&mut a, &default_role).await;
        let (_dir, t) = target(&server, ROLE_USER, IT_PASSWORD);

        // SELECT on the application database through the default role:
        // the minimal variant, nothing to report (MariaDB 10.11+: the
        // grants to PUBLIC were read, and hold nothing).
        let (notes, output) = privilege_check(&t).await;
        assert!(notes.is_empty(), "{name}: {notes:?}\n{output}");

        // MariaDB 10.11+ (ADR-0025 residual, phase 7): a privilege granted
        // to PUBLIC is held by every account, and is evaluated.
        if !mysql && a.version() >= (10, 11, 0) {
            exec(&mut a, &format!("GRANT INSERT ON `{db}`.* TO PUBLIC")).await;
            let (notes, output) = privilege_check(&t).await;
            exec(&mut a, &format!("REVOKE INSERT ON `{db}`.* FROM PUBLIC")).await;
            let beyond = server_note(name, &notes, NoteCode::PrivilegeBeyondSelect);
            assert_eq!(labels(beyond), ["insert"], "{name}: {output}");
            assert_no_note(name, &notes, NoteCode::PrivilegeRolesNotEvaluated, &output);
            let (notes, output) = privilege_check(&t).await;
            assert!(notes.is_empty(), "{name}: {notes:?}\n{output}");
        }

        // A role granted but not enabled, holding write privileges and,
        // through another role, SELECT on the mysql database.
        exec(
            &mut a,
            &format!("GRANT INSERT, UPDATE ON `{db}`.* TO `{ROLE_WRITE}`"),
        )
        .await;
        exec(
            &mut a,
            &format!("GRANT SELECT ON `mysql`.* TO `{ROLE_SYS}`"),
        )
        .await;
        exec(&mut a, &format!("GRANT `{ROLE_SYS}` TO `{ROLE_WRITE}`")).await;
        exec(
            &mut a,
            &format!("GRANT `{ROLE_WRITE}` TO '{ROLE_USER}'@'%'"),
        )
        .await;
        let (notes, output) = privilege_check(&t).await;
        assert_registered_notes(server.flavor(), &notes);
        if mysql {
            let beyond = server_note(name, &notes, NoteCode::PrivilegeBeyondSelect);
            assert_eq!(labels(beyond), ["insert", "update"], "{name}: {output}");
            assert_eq!(beyond.count(), Some(2), "{name}");
            server_note(name, &notes, NoteCode::PrivilegeSystemDatabaseSelect);
            assert_no_note(name, &notes, NoteCode::PrivilegeRolesNotEvaluated, &output);
        } else {
            // The two roles that are not the current role cannot be read:
            // reported as such, and nothing is inferred from them.
            let unevaluated = server_note(name, &notes, NoteCode::PrivilegeRolesNotEvaluated);
            assert_eq!(unevaluated.count(), Some(2), "{name}: {output}");
            assert_no_note(name, &notes, NoteCode::PrivilegeBeyondSelect, &output);
        }
        assert_no_note(name, &notes, NoteCode::PrivilegeGrantOption, &output);

        // A write privilege on the default role: evaluated on both engines.
        exec(
            &mut a,
            &format!("GRANT DELETE ON `{db}`.* TO `{ROLE_READ}`"),
        )
        .await;
        let (notes, output) = privilege_check(&t).await;
        let beyond = server_note(name, &notes, NoteCode::PrivilegeBeyondSelect);
        if mysql {
            assert_eq!(
                labels(beyond),
                ["delete", "insert", "update"],
                "{name}: {output}"
            );
            assert_no_note(name, &notes, NoteCode::PrivilegeRolesNotEvaluated, &output);
        } else {
            assert_eq!(labels(beyond), ["delete"], "{name}: {output}");
            let unevaluated = server_note(name, &notes, NoteCode::PrivilegeRolesNotEvaluated);
            assert_eq!(unevaluated.count(), Some(2), "{name}: {output}");
        }

        // WITH ADMIN OPTION: the account can grant the role to others.
        exec(
            &mut a,
            &format!("GRANT `{ROLE_READ}` TO '{ROLE_USER}'@'%' WITH ADMIN OPTION"),
        )
        .await;
        let (notes, _) = privilege_check(&t).await;
        server_note(name, &notes, NoteCode::PrivilegeGrantOption);

        // MySQL mandatory roles apply to every account.
        if mysql {
            exec(&mut a, &format!("CREATE ROLE `{ROLE_MANDATORY}`")).await;
            exec(
                &mut a,
                &format!("GRANT DROP ON `{db}`.* TO `{ROLE_MANDATORY}`"),
            )
            .await;
            let previous = scalar(&mut a, "SELECT @@GLOBAL.mandatory_roles")
                .await
                .unwrap_or_default();
            exec(
                &mut a,
                &format!("SET GLOBAL mandatory_roles = '`{ROLE_MANDATORY}`@`%`'"),
            )
            .await;
            let (notes, output) = privilege_check(&t).await;
            let restore = format!(
                "SET GLOBAL mandatory_roles = '{}'",
                previous.replace('\'', "''")
            );
            exec(&mut a, &restore).await;
            let beyond = server_note(name, &notes, NoteCode::PrivilegeBeyondSelect);
            assert_eq!(
                labels(beyond),
                ["delete", "drop", "insert", "update"],
                "{name}: {output}"
            );
        }

        // Role and account names stay on the agent host: they are neither
        // in the notes nor in the logs or the detail.
        let (notes, output) = privilege_check(&t).await;
        let text = format!("{notes:?}\n{output}");
        for n in [ROLE_READ, ROLE_WRITE, ROLE_SYS, ROLE_MANDATORY, ROLE_USER] {
            assert!(!text.contains(n), "{name}: {n} in {text}");
        }

        drop_role_fixtures(&mut a).await;
    }
}

#[tokio::test]
async fn verify_full_tls_with_a_pinned_ca() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        if server.ca.is_none() {
            continue;
        }
        let (_dir, t) = agent_target(&server);
        let health = MysqlConnector::new().check(&t).await;
        assert!(health.reachable, "{health:?}");
        let (r, findings) = scan(&t).await;
        r.unwrap();
        assert!(!findings.is_empty());
        // System roots only: the throwaway CA is not trusted.
        let (_dir, t) = target_tls(
            &server,
            &server.url.user,
            &server.url.password,
            "tls: verify_full",
        );
        let logs = Logs::default();
        let health = {
            let _guard = logs.capture();
            MysqlConnector::new().check(&t).await
        };
        assert!(!health.reachable);
        assert_eq!(health.failure, Some(FailureCode::TargetUnreachable));
        assert!(logs.text().contains("TLS handshake failed"));
    }
}

/// The dev servers' data directories hold databases only: a foreign
/// directory there (the MariaDB TLS material used to live in
/// `/var/lib/mysql/databastion-tls`) is listed as a schema
/// `#mysql50#…` that Discovery would try to scan.
#[tokio::test]
async fn data_directory_holds_no_foreign_schema() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let foreign = scalar(
            &mut a,
            "SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA \
             WHERE SCHEMA_NAME LIKE '#mysql50#%' OR SCHEMA_NAME LIKE '%databastion-tls%'",
        )
        .await;
        assert_eq!(foreign, None, "{}", server.name);
    }
}

#[test]
fn urls_are_parsed() {
    let u = parse_url("mysql://databastion:p%40ss@127.0.0.1:3307/support").unwrap();
    assert_eq!(
        (
            u.host.as_str(),
            u.port,
            u.user.as_str(),
            u.password.as_str(),
            u.dbname.as_str()
        ),
        ("127.0.0.1", 3307, "databastion", "p@ss", "support")
    );
    assert!(parse_url("postgresql://a:b@h/d").is_none());
}
