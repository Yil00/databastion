//! Integration tests against a PostgreSQL server: the dev environment
//! (`make dev`, PostgreSQL 17 + pgaudit) or `dev/postgres/local-cluster.sh`
//! (host binaries, no Docker).
//!
//! - `DATABASTION_TEST_PG_URL`: the agent role on the seeded database
//!   (`postgresql://databastion:…@127.0.0.1:5432/shop`). Without it, every
//!   test here is skipped with a message on stderr.
//! - `DATABASTION_TEST_PG_ADMIN_URL`: a superuser, for the ADR-0012 probe
//!   fixtures (database `databastion_probe`, dropped and recreated) and the
//!   extended-variant role. Without it, those tests are skipped.
//!
//! The tests are serialized (the agent role has `CONNECTION LIMIT 4`).
//! They live in the crate (not `tests/`) to reach the session layer for
//! the cancellation and transaction probes.

// Skip notices and the recall table (counts only, never a value).
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use databastion_classifiers::id::ClassifierId;
use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{
    AuditLevel, Connector, ConnectorError, FailureCode, FindingSink, ScanJob, ScanParams,
};
use tokio_postgres::NoTls;

use crate::PostgresConnector;
use crate::conn::{Session, Timeouts};
use crate::discover::normalize;
use crate::error::Stage;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PROBE_DB: &str = "databastion_probe";
const EXT_ROLE: &str = "databastion_it_ext";
const EXT_PASSWORD: &str = "dev-only-it-extended-FAKE";
/// Catalog secrets planted for the extended-variant probe.
const MARKERS: [&str; 6] = [
    "MappingPw-FAKE",
    "SrvOptionMarker-FAKE",
    "SetconfigMarker-FAKE",
    "LargeObjectMarker-FAKE",
    "StatsMarker-FAKE",
    "SCRAM-SHA-256$",
];

#[derive(Debug, Clone)]
struct Url {
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
}

fn url(var: &str) -> Option<Url> {
    let raw = std::env::var(var).ok()?;
    let config: tokio_postgres::Config = raw.parse().ok()?;
    let host = match config.get_hosts().first()? {
        tokio_postgres::config::Host::Tcp(h) => h.clone(),
        tokio_postgres::config::Host::Unix(_) => return None,
    };
    Some(Url {
        host,
        port: config.get_ports().first().copied().unwrap_or(5432),
        user: config.get_user()?.to_owned(),
        password: String::from_utf8(config.get_password()?.to_vec()).ok()?,
        dbname: config.get_dbname().unwrap_or("postgres").to_owned(),
    })
}

/// Reports a skipped check. When its prerequisite is listed in
/// `DATABASTION_TEST_REQUIRE` (comma-separated: `pg`, `admin`, `pss`,
/// `pgaudit`, `weak-auth`, `tls`, or `all`), the skip is a failure: CI
/// lists what each run must exercise.
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

fn agent_url() -> Option<Url> {
    let u = url("DATABASTION_TEST_PG_URL");
    if u.is_none() {
        skip(
            "pg",
            "DATABASTION_TEST_PG_URL is not set (start `make dev` or \
             dev/postgres/local-cluster.sh)",
        );
    }
    u
}

fn admin_url() -> Option<Url> {
    let u = url("DATABASTION_TEST_PG_ADMIN_URL");
    if u.is_none() {
        skip(
            "admin",
            "DATABASTION_TEST_PG_ADMIN_URL is not set (ADR-0012 fixture probes)",
        );
    }
    u
}

/// A private temporary directory holding the target secret file.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "databastion-pg-it-{}-{}",
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

thread_local! {
    /// TLS settings of the targets built by [`target`] on this thread.
    static TLS: std::cell::RefCell<String> = std::cell::RefCell::new("tls: disable".to_owned());
}

/// A declared target for `u` (password in a `0600` file), TLS disabled
/// (loopback test server) unless [`TLS`] says otherwise.
fn target(
    u: &Url,
    user: &str,
    password: &str,
    db: &str,
    extended: bool,
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
    let tls = TLS.with(|t| t.borrow().clone());
    let yaml = format!(
        "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: pg-it\n    \
         engine: postgres\n    host: \"{}\"\n    port: {}\n    account: \"{user}\"\n    \
         secret: {{file: \"{}\"}}\n    postgres: {{databases: [\"{db}\"], {tls}, \
         extended_grants: {extended}}}\n",
        u.host,
        u.port,
        file.display()
    );
    let config = databastion_core::AgentConfig::parse(&yaml).unwrap();
    (dir, config.targets[0].clone())
}

async fn raw_client(u: &Url, user: &str, password: &str, db: &str) -> tokio_postgres::Client {
    let mut c = tokio_postgres::Config::new();
    c.host(&u.host)
        .port(u.port)
        .user(user)
        .password(password)
        .dbname(db)
        .application_name("databastion-it");
    let (client, conn) = c.connect(NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

async fn admin(u: &Url, db: &str) -> tokio_postgres::Client {
    raw_client(u, &u.user, &u.password, db).await
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[7u8; 32]).unwrap())
}

async fn scan(
    target: &TargetConfig,
    params: ScanParams,
) -> (Result<(), ConnectorError>, Vec<MaskedFinding>) {
    let job = ScanJob::new(params, target, &Limits::default(), key());
    let (sink, mut rx) = FindingSink::channel(10_000);
    let r = PostgresConnector::new().discover(&job, &sink).await;
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
            (
                l.schema.as_ref().unwrap().as_str().to_owned(),
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
                f.classifier().as_str(),
            )
        })
        .collect()
}

fn key_of(schema: &str, object: &str, field: &str, classifier: &'static str) -> Key {
    (
        schema.to_owned(),
        object.to_owned(),
        field.to_owned(),
        classifier,
    )
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

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn check_reports_reachable_with_an_honest_audit_level() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let health = PostgresConnector::new().check(&t).await;
    assert!(health.reachable, "{health:?}");
    assert_eq!(health.failure, None);
    // Minimal variant with pg_read_all_stats and pg_stat_statements loaded:
    // Limited. Never Full before the audit log path can be checked (P4-A).
    assert!(health.audit_level <= AuditLevel::Limited, "{health:?}");
    let detail = health.detail.unwrap();
    assert!(!detail.contains("over-privileged"), "{detail}");
    eprintln!("check: {:?}; {detail}", health.audit_level);

    // Wrong password: authentication_failed, no server text.
    let (_dir, bad) = target(&u, &u.user, "wrong-password-FAKE", &u.dbname, false);
    let health = PostgresConnector::new().check(&bad).await;
    assert!(!health.reachable);
    assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
    assert!(!health.detail.unwrap().contains("password"));
}

#[tokio::test]
async fn transactions_are_read_only_with_local_timeouts() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let timeouts = Timeouts::new(Duration::from_millis(1500));
    let session = Session::connect(&t, &u.dbname, timeouts).await.unwrap();
    let tx = session.begin(timeouts).await.unwrap();
    let rows = tx
        .query(
            Stage::Check,
            "SELECT pg_catalog.current_setting('statement_timeout'), \
                    pg_catalog.current_setting('lock_timeout'), \
                    pg_catalog.current_setting('idle_in_transaction_session_timeout'), \
                    pg_catalog.current_setting('transaction_read_only'), \
                    pg_catalog.current_setting('search_path'), \
                    pg_catalog.current_setting('application_name')",
            &[],
        )
        .await
        .unwrap();
    let got: Vec<String> = (0..6).map(|i| rows[0].get(i)).collect();
    assert_eq!(
        got,
        ["1500ms", "2s", "10s", "on", "", "databastion-agent"],
        "SET LOCAL timeouts, read-only transaction, empty search_path"
    );
    tx.commit().await.unwrap();

    // The statement timeout applies (cancelled on the server, 57014).
    let tx = session
        .begin(Timeouts::new(Duration::from_millis(300)))
        .await
        .unwrap();
    let e = tx
        .query(Stage::Sample, "SELECT pg_catalog.pg_sleep(3)", &[])
        .await
        .unwrap_err();
    assert_eq!(e.code, FailureCode::Timeout);
    assert_eq!(e.sqlstate(), Some("57014"));
    assert!(!e.fatal);
    tx.rollback().await;

    // Writes fail in the connector's transactions, whatever the grants.
    let tx = session.begin(timeouts).await.unwrap();
    let e = tx
        .query(
            Stage::Sample,
            "CREATE TEMP TABLE databastion_it_tmp (x int)",
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(e.sqlstate(), Some("25006"), "read_only_sql_transaction");
    tx.rollback().await;
}

#[tokio::test]
async fn dropped_statement_is_cancelled_on_the_server() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let observer = raw_client(&u, &u.user, &u.password, &u.dbname).await;
    let active = |marker: &'static str| {
        let observer = &observer;
        async move {
            let row = observer
                .query_one(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity \
                     WHERE state = 'active' AND pid <> pg_catalog.pg_backend_pid() \
                       AND query LIKE '%' || $1::text || '%'",
                    &[&marker],
                )
                .await
                .unwrap();
            row.get::<_, i64>(0)
        }
    };

    // Control: a statement whose future is dropped without a cancel request
    // keeps running on the server.
    {
        let plain = raw_client(&u, &u.user, &u.password, &u.dbname).await;
        let fut = plain.execute("SELECT pg_catalog.pg_sleep(4) /* it-control */", &[]);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), fut)
                .await
                .is_err()
        );
        drop(plain);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            active("it-control").await,
            1,
            "control: still running after drop"
        );
    }

    // The connector: the whole unit of work (session, transaction,
    // statement) is dropped at a deadline, as the core does at
    // `max_duration_s`; the statement is cancelled on the server.
    let timeouts = Timeouts::new(Duration::from_secs(60));
    let work = async {
        let session = Session::connect(&t, &u.dbname, timeouts).await.unwrap();
        let tx = session.begin(timeouts).await.unwrap();
        let _ = tx
            .query(
                Stage::Sample,
                "SELECT pg_catalog.pg_sleep(30) /* it-cancel */",
                &[],
            )
            .await;
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), work)
            .await
            .is_err()
    );
    let mut remaining = -1;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining = active("it-cancel").await;
        if remaining == 0 {
            break;
        }
    }
    assert_eq!(
        remaining, 0,
        "the dropped statement still runs on the server"
    );
}

#[tokio::test]
async fn no_transaction_is_held_across_submit() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let observer = raw_client(&u, &u.user, &u.password, &u.dbname).await;
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &t,
        &Limits::default(),
        key(),
    );
    // Capacity 1 and no consumer: the scan blocks in `submit().await`.
    let (sink, mut rx) = FindingSink::channel(1);
    let connector = PostgresConnector::new();
    let scan = connector.discover(&job, &sink);
    tokio::pin!(scan);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut scan)
            .await
            .is_err()
    );
    let states: Vec<String> = observer
        .query(
            "SELECT state FROM pg_catalog.pg_stat_activity \
             WHERE application_name = 'databastion-agent' \
               AND pid <> pg_catalog.pg_backend_pid()",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(states, ["idle"], "blocked in submit with the session idle");
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

#[tokio::test]
async fn seed_recall_regression() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev/ground-truth.json");
    let gt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let pg: Vec<&serde_json::Value> = gt["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "postgresql" && l["database"] == u.dbname.as_str())
        .collect();
    if pg.is_empty() {
        skip("pg", "no ground-truth location for this database");
        return;
    }
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        scan(&t, ScanParams::contract_defaults()).await
    };
    r.unwrap();
    let found = located(&findings);
    let names = |l: &serde_json::Value| {
        let s = |k: &str| normalize(l[k].as_str().unwrap_or("")).as_str().to_owned();
        (s("container"), s("object"), s("field"))
    };
    let mut per: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let mut false_positives = 0;
    for l in &pg {
        let (s, o, f) = names(l);
        for c in l["expected_classifiers"].as_array().unwrap() {
            let id = ClassifierId::parse(c.as_str().unwrap()).unwrap().as_str();
            let e = per.entry(id).or_default();
            e.1 += 1;
            if found.contains(&key_of(&s, &o, &f, id)) {
                e.0 += 1;
            }
        }
        if l["negative_control"] == true {
            false_positives += found
                .iter()
                .filter(|k| k.0 == s && k.1 == o && k.2 == f)
                .count();
        }
    }
    let (mut tp, mut total) = (0, 0);
    for (c, (hit, n)) in &per {
        eprintln!("recall {c:<24} {hit}/{n}");
        tp += hit;
        total += n;
    }
    eprintln!(
        "findings {}, negative-control hits {false_positives}",
        found.len()
    );
    // Regression bound: every seeded location is found (the offline
    // ground-truth test of the classifiers crate holds the per-classifier
    // criterion); negative controls stay silent.
    assert_eq!(tp, total, "missed ground-truth locations: {per:?}");
    assert_eq!(false_positives, 0);
    // Value-bearing table names never reach a finding or a log in clear.
    assert!(
        !found
            .iter()
            .any(|k| k.1.contains("0639988384") || k.1.contains("lucas"))
    );
    let text = logs.text();
    assert!(
        !text.contains("0639988384") && !text.contains("lucas_martin"),
        "{text}"
    );
    assert!(
        !text.contains("@example."),
        "a sampled value reached the logs"
    );
}

// ------------------------------------------------------------ ADR-0012

const PROBE_FIXTURES: &str = r#"
CREATE EXTENSION postgres_fdw;
CREATE SCHEMA probe;
CREATE SCHEMA probe_hidden;
CREATE TABLE probe_hidden.hidden (email text);
INSERT INTO probe_hidden.hidden SELECT 'hidden.user' || i || '@example.com' FROM generate_series(1, 20) i;
CREATE SERVER remote FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'databastion-probe.invalid', dbname 'x', connect_timeout '2',
           application_name 'SrvOptionMarker-FAKE');
CREATE USER MAPPING FOR PUBLIC SERVER remote OPTIONS (user 'u', password 'MappingPw-FAKE');
GRANT USAGE ON FOREIGN SERVER remote TO PUBLIC;

-- Partitioned root with a local leaf and a foreign leaf on an unresolvable host.
CREATE TABLE probe.p (id int, email text) PARTITION BY RANGE (id);
CREATE TABLE probe.p_local PARTITION OF probe.p FOR VALUES FROM (0) TO (1000);
CREATE FOREIGN TABLE probe.p_remote PARTITION OF probe.p FOR VALUES FROM (1000) TO (2000) SERVER remote;
INSERT INTO probe.p_local SELECT i, 'part.user' || i || '@example.com' FROM generate_series(1, 40) i;

-- Inheritance parent with a foreign child.
CREATE TABLE probe.parent (id int, email text);
CREATE FOREIGN TABLE probe.parent_remote () INHERITS (probe.parent) SERVER remote;
INSERT INTO probe.parent SELECT i, 'inh.user' || i || '@example.com' FROM generate_series(1, 40) i;

-- A user function that fails when called: any call from the connector breaks the sample.
CREATE FUNCTION probe.pol(text) RETURNS boolean LANGUAGE plpgsql
  AS $$ BEGIN RAISE EXCEPTION 'user function called'; END $$;

-- RLS policy calling a user function.
CREATE TABLE probe.rls_func (owner text, email text);
INSERT INTO probe.rls_func SELECT 'o', 'func.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_func ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_func USING (probe.pol(owner));

-- RLS policy with a subquery on a view calling a user function.
CREATE VIEW probe.v AS SELECT probe.pol('x') AS ok;
CREATE TABLE probe.rls_view (owner text, email text);
INSERT INTO probe.rls_view SELECT 'o', 'view.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_view ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_view USING (EXISTS (SELECT 1 FROM probe.v WHERE ok));

-- RLS policy on built-ins only: sampled (positive control).
CREATE TABLE probe.rls_builtin (owner text, email text);
INSERT INTO probe.rls_builtin SELECT 'o', 'builtin.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_builtin ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_builtin USING (length(owner) > 0);

-- Partitioned root with RLS hiding every row, leaf without RLS.
CREATE TABLE probe.rls_root (id int, email text) PARTITION BY RANGE (id);
CREATE TABLE probe.rls_root_leaf PARTITION OF probe.rls_root FOR VALUES FROM (0) TO (1000);
INSERT INTO probe.rls_root_leaf SELECT i, 'root.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_root ENABLE ROW LEVEL SECURITY;
CREATE POLICY none ON probe.rls_root USING (false);

-- No SELECT grant.
CREATE TABLE probe.no_grant (email text);
INSERT INTO probe.no_grant VALUES ('nogrant.user@example.com');

-- SECURITY DEFINER function that writes.
CREATE TABLE probe.touched (at timestamptz);
CREATE FUNCTION probe.touch() RETURNS void LANGUAGE sql SECURITY DEFINER
  AS 'INSERT INTO probe.touched VALUES (now())';

-- Catalog markers for the extended variant.
SELECT lo_from_bytea(0, 'LargeObjectMarker-FAKE'::bytea);
CREATE TABLE probe.stats (code text);
INSERT INTO probe.stats SELECT 'StatsMarker-FAKE' FROM generate_series(1, 100);
ANALYZE probe.stats;

-- Large relation (TABLESAMPLE) and one with stale statistics (short sample: LIMIT fallback).
CREATE TABLE probe.big (id int, email text);
INSERT INTO probe.big SELECT i, 'big.user' || i || '@example.com' FROM generate_series(1, 20000) i;
ANALYZE probe.big;
CREATE TABLE probe.stale (id int, email text) WITH (autovacuum_enabled = false);
INSERT INTO probe.stale SELECT i, 'stale.user' || i || '@example.com' FROM generate_series(1, 20000) i;
ANALYZE probe.stale;
DELETE FROM probe.stale WHERE id > 30;

-- H1: policies calling pinned built-ins that run SQL text or resolve names at run time
-- (no pg_depend row): skipped. A policy on allowed built-ins only (current_setting): sampled.
CREATE TABLE probe.rls_qxml (owner text, email text);
INSERT INTO probe.rls_qxml SELECT 'o', 'qxml.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_qxml ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_qxml
  USING (pg_catalog.query_to_xml('select probe.pol(''x'')', true, false, '') IS NOT NULL);
CREATE TABLE probe.rls_toreg (owner text, email text);
INSERT INTO probe.rls_toreg SELECT 'o', 'toreg.user' || i || '@example.com' FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_toreg ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_toreg USING (pg_catalog.to_regclass(owner) IS NULL);
CREATE TABLE probe.rls_setting (owner text, email text);
INSERT INTO probe.rls_setting SELECT 'databastion-agent', 'setting.user' || i || '@example.com'
  FROM generate_series(1, 40) i;
ALTER TABLE probe.rls_setting ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON probe.rls_setting
  USING (owner = pg_catalog.current_setting('application_name') AND length(email) > 0);

-- M1: rows of 12 MiB each; the 32 MiB per-relation budget stops the sample after two.
CREATE TABLE probe.a_wide (email text, blob text);
INSERT INTO probe.a_wide SELECT 'wide.user' || i || '@example.com', repeat('x', 12 * 1024 * 1024)
  FROM generate_series(1, 10) i;

GRANT USAGE ON SCHEMA probe TO databastion;
GRANT SELECT ON ALL TABLES IN SCHEMA probe TO databastion;
REVOKE SELECT ON probe.no_grant FROM databastion;
"#;

/// Recreates `databastion_probe` and the extended-variant role.
async fn probe_fixtures(admin_url: &Url, agent_user: &str) {
    let a = admin(admin_url, "postgres").await;
    for statement in [
        format!("DROP DATABASE IF EXISTS {PROBE_DB} WITH (FORCE)"),
        format!("CREATE DATABASE {PROBE_DB}"),
    ] {
        a.batch_execute(&statement).await.unwrap();
    }
    let exists = a
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&EXT_ROLE])
        .await
        .unwrap()
        .is_some();
    if !exists {
        a.batch_execute(&format!(
            "SET log_min_error_statement = panic; \
             CREATE ROLE {EXT_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION \
               NOBYPASSRLS CONNECTION LIMIT 4 PASSWORD '{EXT_PASSWORD}'; \
             GRANT pg_read_all_data, pg_read_all_settings, pg_read_all_stats TO {EXT_ROLE};"
        ))
        .await
        .unwrap();
    }
    a.batch_execute(&format!(
        "GRANT CONNECT ON DATABASE {PROBE_DB} TO \"{agent_user}\", {EXT_ROLE}; \
         ALTER ROLE {EXT_ROLE} IN DATABASE {PROBE_DB} \
           SET application_name = 'SetconfigMarker-FAKE';"
    ))
    .await
    .unwrap();
    let p = admin(admin_url, PROBE_DB).await;
    p.batch_execute(PROBE_FIXTURES).await.unwrap();

    // L5: foreign leaf / child on a server that is reachable (this cluster,
    // database databastion_fdw_sink): any connection would be counted in
    // pg_stat_database.sessions of the sink.
    for statement in [
        format!("DROP DATABASE IF EXISTS {SINK_DB} WITH (FORCE)"),
        format!("CREATE DATABASE {SINK_DB}"),
    ] {
        a.batch_execute(&statement).await.unwrap();
    }
    let sink_user_exists = a
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&SINK_ROLE])
        .await
        .unwrap()
        .is_some();
    if !sink_user_exists {
        a.batch_execute(&format!(
            "SET log_min_error_statement = panic; \
             CREATE ROLE {SINK_ROLE} LOGIN PASSWORD '{SINK_PASSWORD}';"
        ))
        .await
        .unwrap();
    }
    a.batch_execute(&format!(
        "GRANT CONNECT ON DATABASE {SINK_DB} TO {SINK_ROLE}"
    ))
    .await
    .unwrap();
    let port: String = p
        .query_one("SELECT current_setting('port')", &[])
        .await
        .unwrap()
        .get(0);
    p.batch_execute(&format!(
        "CREATE SERVER local_sink FOREIGN DATA WRAPPER postgres_fdw \
           OPTIONS (host '127.0.0.1', port '{port}', dbname '{SINK_DB}'); \
         CREATE USER MAPPING FOR PUBLIC SERVER local_sink \
           OPTIONS (user '{SINK_ROLE}', password '{SINK_PASSWORD}'); \
         GRANT USAGE ON FOREIGN SERVER local_sink TO PUBLIC; \
         CREATE TABLE probe.q (id int, email text) PARTITION BY RANGE (id); \
         CREATE TABLE probe.q_local PARTITION OF probe.q FOR VALUES FROM (0) TO (1000); \
         CREATE FOREIGN TABLE probe.q_remote PARTITION OF probe.q \
           FOR VALUES FROM (1000) TO (2000) SERVER local_sink; \
         INSERT INTO probe.q_local SELECT i, 'q.user' || i || '@example.com' \
           FROM generate_series(1, 40) i; \
         CREATE TABLE probe.qparent (id int, email text); \
         CREATE FOREIGN TABLE probe.qparent_remote () INHERITS (probe.qparent) SERVER local_sink; \
         INSERT INTO probe.qparent SELECT i, 'qp.user' || i || '@example.com' \
           FROM generate_series(1, 40) i; \
         GRANT SELECT ON ALL TABLES IN SCHEMA probe TO databastion; \
         REVOKE SELECT ON probe.no_grant FROM databastion;"
    ))
    .await
    .unwrap();
}

const SINK_DB: &str = "databastion_fdw_sink";
const SINK_ROLE: &str = "databastion_it_sink";
const SINK_PASSWORD: &str = "dev-only-it-sink-FAKE";

/// Sessions opened so far on the sink database (after the stats of ended
/// sessions are flushed).
async fn sink_sessions(admin: &tokio_postgres::Client) -> i64 {
    admin
        .query_one(
            "SELECT sessions FROM pg_stat_database WHERE datname = $1",
            &[&SINK_DB],
        )
        .await
        .unwrap()
        .get(0)
}

/// Waits until the sink session count differs from `from` (max 5 s).
async fn sink_sessions_change(admin: &tokio_postgres::Client, from: i64) -> i64 {
    for _ in 0..50 {
        let now = sink_sessions(admin).await;
        if now != from {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    from
}

#[tokio::test]
async fn adr_0012_probes() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    probe_fixtures(&adm, &u.user).await;
    let (_dir, t) = target(&u, &u.user, &u.password, PROBE_DB, false);

    // Minimal-variant negative probes, in the connector's own session.
    let timeouts = Timeouts::new(Duration::from_secs(5));
    let session = Session::connect(&t, PROBE_DB, timeouts).await.unwrap();
    for (statement, sqlstate) in [
        ("SELECT rolpassword FROM pg_catalog.pg_authid", "42501"),
        ("SELECT umoptions FROM pg_catalog.pg_user_mapping", "42501"),
        // A SECURITY DEFINER function owned by another role cannot write in
        // the connector's read-only transactions.
        ("SELECT probe.touch()", "25006"),
    ] {
        let tx = session.begin(timeouts).await.unwrap();
        let e = tx.query(Stage::Check, statement, &[]).await.unwrap_err();
        assert_eq!(e.sqlstate(), Some(sqlstate), "{statement}");
        tx.rollback().await;
    }
    drop(session);
    let a = admin(&adm, PROBE_DB).await;
    let touched: i64 = a
        .query_one("SELECT count(*) FROM probe.touched", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(touched, 0);

    // Control for the foreign leaf proof: reading the root (not `ONLY`)
    // connects to the sink, which the session counter shows.
    let before = sink_sessions(&a).await;
    {
        let c = admin(&adm, PROBE_DB).await;
        let _ = c.query("SELECT count(*) FROM probe.q", &[]).await;
    }
    let after_control = sink_sessions_change(&a, before).await;
    assert!(
        after_control > before,
        "control: a read through the root must reach the sink"
    );

    // Scan of the probe database.
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        scan(&t, ScanParams::contract_defaults()).await
    };
    r.unwrap();
    let text = logs.text();
    let found = located(&findings);
    let objects: BTreeSet<&str> = found.iter().map(|k| k.1.as_str()).collect();
    // Partitioned root reported (not its leaf); inheritance parent read
    // `FROM ONLY`; no foreign leaf / child read: the scan reached no remote
    // host (a connection attempt fails with 08001 and skips the object).
    assert!(
        found.contains(&key_of("probe", "p", "email", "pii.email")),
        "{found:?}"
    );
    assert!(found.contains(&key_of("probe", "parent", "email", "pii.email")));
    assert!(!objects.contains("p_local") && !objects.contains("p_remote"));
    assert!(!objects.contains("parent_remote"));
    assert!(
        !text.contains("object skipped") && !text.contains("partition skipped"),
        "{text}"
    );
    assert!(!text.contains("08001"), "{text}");
    assert!(found.contains(&key_of("probe", "q", "email", "pii.email")));
    assert!(found.contains(&key_of("probe", "qparent", "email", "pii.email")));
    // M1: the wide relation stopped at its byte budget (two 12 MiB rows),
    // the statement cancelled, the next objects sampled on a new session.
    assert!(text.contains("sample byte budget reached"), "{text}");
    let wide = findings
        .iter()
        .find(|f| f.location().unwrap().object.as_str() == "a_wide")
        .map(MaskedFinding::sampled);
    assert_eq!(wide, Some(2));
    // Bounded sampling: TABLESAMPLE on the large relation, LIMIT fallback
    // when the sample comes back short (stale statistics).
    let sampled = |object: &str| {
        findings
            .iter()
            .find(|f| f.location().unwrap().object.as_str() == object)
            .map(MaskedFinding::sampled)
    };
    let big = sampled("big").unwrap();
    assert!(big > 0 && big <= 200, "{big}");
    assert_eq!(sampled("stale"), Some(30));
    let pss = admin(&adm, &u.dbname).await;
    if let Ok(row) = pss
        .query_one(
            "SELECT count(*) FILTER (WHERE query LIKE '%\"big\" TABLESAMPLE SYSTEM%'), \
                    count(*) FILTER (WHERE query LIKE '%\"stale\" TABLESAMPLE SYSTEM%'), \
                    count(*) FILTER (WHERE query LIKE '%FROM ONLY \"probe\".\"stale\" LIMIT%') \
             FROM pg_stat_statements \
             WHERE dbid = (SELECT oid FROM pg_database WHERE datname = $1) \
               AND userid = (SELECT oid FROM pg_roles WHERE rolname = $2)",
            &[&PROBE_DB, &u.user],
        )
        .await
    {
        let counts: (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
        assert_eq!(
            counts,
            (1, 1, 1),
            "TABLESAMPLE statements seen by pg_stat_statements"
        );
    } else {
        skip(
            "pss",
            "pg_stat_statements not queryable (TABLESAMPLE statement check)",
        );
    }

    // No connection reached the sink during the scan (L5).
    assert_eq!(
        sink_sessions_change(&a, after_control).await,
        after_control,
        "the scan connected to the foreign server"
    );

    // RLS: built-in policy sampled (and logged as possibly incomplete);
    // user function / view-subquery policies and the leaf of an RLS root
    // are skipped and reported as not covered.
    assert!(objects.contains("rls_builtin"));
    assert!(text.contains("the sample may be incomplete"));
    assert!(objects.contains("rls_setting"));
    assert!(
        !text
            .lines()
            .any(|l| l.contains("object not covered") && l.contains("rls_setting")),
        "current_setting policy must be sampled"
    );
    for skipped in [
        "rls_qxml",
        "rls_toreg",
        "rls_func",
        "rls_view",
        "rls_root",
        "rls_root_leaf",
        "no_grant",
        "hidden",
    ] {
        assert!(!objects.contains(skipped), "{skipped} sampled");
    }
    assert!(!text.contains("user function called"));
    for (name, reason) in [
        (
            "rls_func",
            "row-level security policy with user code or another relation",
        ),
        (
            "rls_view",
            "row-level security policy with user code or another relation",
        ),
        ("rls_root_leaf", "row-level security on an ancestor"),
        ("no_grant", "no SELECT privilege"),
        (
            "rls_qxml",
            "row-level security policy with user code or another relation",
        ),
        (
            "rls_toreg",
            "row-level security policy with user code or another relation",
        ),
    ] {
        assert!(
            text.lines().any(|l| l.contains("object not covered")
                && l.contains(&format!("object=\"{name}\""))
                && l.contains(reason)),
            "{name} not reported: {text}"
        );
    }

    // check(): schemas without USAGE and skipped relations are listed.
    let health = {
        let _guard = logs.capture();
        PostgresConnector::new().check(&t).await
    };
    assert!(health.reachable);
    let detail = health.detail.unwrap();
    assert!(
        detail.contains("1 schema(s) without USAGE")
            && detail.contains("1 relation(s) without SELECT")
            && detail.contains("5 relation(s) skipped for row-level security"),
        "{detail}"
    );
    assert!(logs.text().contains("probe_hidden"));

    // pgaudit (dev image): is `pgaudit.log` readable without
    // pg_read_all_settings?
    let pgaudit_loaded = a
        .query_one("SELECT current_setting('shared_preload_libraries')", &[])
        .await
        .unwrap()
        .get::<_, String>(0)
        .contains("pgaudit");
    let session = Session::connect(&t, PROBE_DB, timeouts).await.unwrap();
    let probe = crate::check::audit_probe(&session, timeouts).await.unwrap();
    if pgaudit_loaded {
        assert_eq!(
            probe.pgaudit_loaded,
            Some(true),
            "pgaudit.log not readable: {probe:?}"
        );
        eprintln!("pgaudit loaded; pgaudit.log readable without pg_read_all_settings");
    } else {
        assert_eq!(probe.pgaudit_loaded, Some(false));
        skip(
            "pgaudit",
            "pgaudit is not loaded on this server (pgaudit.log probe)",
        );
    }
}

#[tokio::test]
async fn extended_variant_leaks_no_catalog_marker() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    probe_fixtures(&adm, &u.user).await;
    let (_dir, t) = target(&u, EXT_ROLE, EXT_PASSWORD, PROBE_DB, true);
    let logs = Logs::default();
    let (r, findings, health) = {
        let _guard = logs.capture();
        let (r, findings) = scan(&t, ScanParams::contract_defaults()).await;
        let health = PostgresConnector::new().check(&t).await;
        (r, findings, health)
    };
    r.unwrap();
    assert!(health.reachable);
    let detail = health.detail.clone().unwrap();
    assert!(detail.contains("extended variant"), "{detail}");
    assert!(!detail.contains("over-privileged"), "{detail}");
    // pg_read_all_data reads every schema, never a system one.
    let found = located(&findings);
    assert!(found.iter().any(|k| k.0 == "probe_hidden"));
    for k in &found {
        assert!(
            !["pg_catalog", "information_schema", "pg_toast"].contains(&k.0.as_str()),
            "{k:?}"
        );
    }
    let output = format!("{findings:?}\n{health:?}\n{}", logs.text());
    for marker in MARKERS {
        assert!(!output.contains(marker), "{marker} in agent output");
    }
    // Same role without the flag: reported as over-privileged.
    let (_dir, t) = target(&u, EXT_ROLE, EXT_PASSWORD, PROBE_DB, false);
    let health = PostgresConnector::new().check(&t).await;
    let detail = health.detail.unwrap();
    assert!(
        detail.contains("over-privileged") && detail.contains("pg_read_all_data"),
        "{detail}"
    );
}

#[tokio::test]
async fn idle_in_transaction_timeout_ends_the_session() {
    let Some(u) = agent_url() else { return };
    let _serial = SERIAL.lock().await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let timeouts = Timeouts::new(Duration::from_secs(5)).with_idle(Duration::from_millis(500));
    let session = Session::connect(&t, &u.dbname, timeouts).await.unwrap();
    let tx = session.begin(timeouts).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let e = tx.query(Stage::Sample, "SELECT 1", &[]).await.unwrap_err();
    // The server ended the session (FATAL 25P03, then the connection
    // closes): fatal, never retried on this session.
    assert!(e.fatal, "{e:?}");
    assert!(
        matches!(e.sqlstate(), Some("25P03") | None),
        "{:?}",
        e.sqlstate()
    );
}

#[tokio::test]
async fn cleartext_and_md5_passwords_are_refused_without_tls() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, "postgres").await;
    // Needs pg_hba lines for these roles (dev/postgres/local-cluster.sh).
    let methods: Vec<(String, String)> = a
        .query(
            "SELECT u, auth_method FROM pg_hba_file_rules, unnest(user_name) AS u \
             WHERE u IN ('databastion_it_md5', 'databastion_it_clear')",
            &[],
        )
        .await
        .map(|rows| rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        .unwrap_or_default();
    if methods.len() < 2 {
        skip(
            "weak-auth",
            "no md5 / password pg_hba lines for the test roles",
        );
        return;
    }
    for (role, encryption) in [
        ("databastion_it_md5", "md5"),
        ("databastion_it_clear", "scram-sha-256"),
    ] {
        a.batch_execute(&format!(
            "SET log_min_error_statement = panic; SET password_encryption = '{encryption}'; \
             DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                 CREATE ROLE {role} LOGIN; \
               END IF; \
             END $$; \
             ALTER ROLE {role} PASSWORD 'dev-only-it-weak-FAKE'; \
             GRANT CONNECT ON DATABASE \"{}\" TO {role};",
            u.dbname
        ))
        .await
        .unwrap();
        let (_dir, t) = target(&u, role, "dev-only-it-weak-FAKE", &u.dbname, false);
        let logs = Logs::default();
        let health = {
            let _guard = logs.capture();
            PostgresConnector::new().check(&t).await
        };
        assert!(!health.reachable, "{role}");
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
        assert!(
            logs.text().contains("cleartext or MD5 password"),
            "{role}: {}",
            logs.text()
        );
    }
}

#[tokio::test]
async fn verify_full_tls_with_a_pinned_ca() {
    let Some(u) = agent_url() else { return };
    let Ok(ca) = std::env::var("DATABASTION_TEST_PG_CA_FILE") else {
        skip("tls", "DATABASTION_TEST_PG_CA_FILE is not set (TLS test)");
        return;
    };
    let _serial = SERIAL.lock().await;
    TLS.with(|t| *t.borrow_mut() = format!("tls: verify_full, ca_file: \"{ca}\""));
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let health = PostgresConnector::new().check(&t).await;
    assert!(health.reachable, "{health:?}");
    let (r, findings) = scan(&t, ScanParams::contract_defaults()).await;
    r.unwrap();
    assert!(!findings.is_empty());
    // System roots only: the throwaway CA is not trusted.
    TLS.with(|t| *t.borrow_mut() = "tls: verify_full".to_owned());
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let health = PostgresConnector::new().check(&t).await;
    TLS.with(|t| *t.borrow_mut() = "tls: disable".to_owned());
    assert!(!health.reachable);
    assert_eq!(health.failure, Some(FailureCode::TargetUnreachable));
}

#[tokio::test]
async fn poisoned_session_is_closed_before_submit() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    probe_fixtures(&adm, &u.user).await;
    let (_dir, t) = target(&u, &u.user, &u.password, PROBE_DB, false);
    let observer = admin(&adm, PROBE_DB).await;
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &t,
        &Limits::default(),
        key(),
    );
    // Capacity 1, already full: the first submit blocks. `probe.a_wide`
    // is the first object: its sample stops at the byte budget, then the
    // scan blocks in submit.
    let (sink, mut rx) = FindingSink::channel(1);
    sink.submit(MaskedFinding::new(
        databastion_classifiers::masking::ClassifierId::PII_EMAIL,
        Vec::new(),
    ))
    .await
    .unwrap();
    let logs = Logs::default();
    let _guard = logs.capture();
    let connector = PostgresConnector::new();
    let scan = connector.discover(&job, &sink);
    tokio::pin!(scan);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), &mut scan)
            .await
            .is_err()
    );
    assert!(logs.text().contains("sample byte budget reached"));
    // No agent backend left in a transaction, no lock on the relation.
    let mut held: (i64, i64) = (-1, -1);
    for _ in 0..30 {
        let row = observer
            .query_one(
                "SELECT (SELECT count(*) FROM pg_stat_activity \
                         WHERE application_name = 'databastion-agent' \
                           AND state LIKE 'idle in transaction%'), \
                        (SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) \
                         WHERE a.application_name = 'databastion-agent' \
                           AND l.relation = 'probe.a_wide'::regclass)",
                &[],
            )
            .await
            .unwrap();
        held = (row.get(0), row.get(1));
        if held == (0, 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(held, (0, 0), "transaction or lock held across submit");
    // Drain: the scan completes on a new session.
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
    assert!(n > 1);
}
