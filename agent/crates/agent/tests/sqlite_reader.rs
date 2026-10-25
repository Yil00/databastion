//! The SQLite connector with its real reader process (ADR-0059 decisions
//! 2 to 7): the agent binary built by Cargo in its hidden `sqlite-reader`
//! mode, under the strict file policy, on a read-only bind mount, with the
//! application's writer in another process (this test's).
//!
//! These tests need root, to play the three accounts of a deployment
//! (the application owning the files, the agent's account reading them
//! through its group, and the read-only mount): they create the files as
//! root, give them to uid 10001 / gid 10002 (mode 0640, directory 2750),
//! bind-mount the directory read-only, and run the reader as uid 10003
//! with gid 10002. Without root they are skipped with that reason, unless
//! `DATABASTION_IT_SQLITE_REQUIRE=1` (the CI job `agent-sqlite`), which
//! fails them instead. Landlock is required too (the reader refuses to
//! open anything without it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use databastion_connector_sqlite::SqliteConnector;
use databastion_connector_sqlite::ipc::{
    Request, Response, RowidAlias, SampleRange, SampleRequest,
};
use databastion_connector_sqlite::process::{Death, ReaderProcess};
use databastion_connector_sqlite::testing::{Writer, build_from_sql, seed};
use databastion_core::config::TargetConfig;
use databastion_core::config::sqlite::{RollbackMode, SqliteSettings};
use databastion_core::notes::NoteCode;
use databastion_core::{AuditLevel, Connector, FailureCode, FindingSink, ScanJob, ScanParams};

const APP_UID: u32 = 10_001;
const SHARED_GID: u32 = 10_002;
const AGENT_UID: u32 = 10_003;

fn euid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse().ok())
        .unwrap()
}

fn landlock() -> bool {
    databastion_connector_sqlite::sandbox::landlock_available()
}

/// The deployment of one test: `rw` (the application's directory) and
/// `ro`, the same directory mounted read-only, where the agent reads.
struct Env {
    base: PathBuf,
    rw: PathBuf,
    ro: PathBuf,
}

/// The reader executable: one copy of the agent binary, which any account
/// can run, for the whole test binary.
fn reader_executable() -> PathBuf {
    static EXE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    EXE.get_or_init(|| {
        let dir = PathBuf::from(format!(
            "/tmp/databastion-sqlite-reader-exe-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("databastion-agent");
        std::fs::copy(env!("CARGO_BIN_EXE_databastion-agent"), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        exe
    })
    .clone()
}

fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap();
    assert!(status.success(), "{cmd:?}");
}

impl Env {
    fn new(name: &str) -> Option<Self> {
        let required = std::env::var("DATABASTION_IT_SQLITE_REQUIRE").as_deref() == Ok("1");
        let skip = |why: &str| {
            assert!(!required, "sqlite reader tests required but: {why}");
            eprintln!("skipped: {why}");
            None
        };
        if euid() != 0 {
            return skip(
                "needs root to create files owned by another account, run the reader as a third \
                 one, and bind-mount read-only (run as root, e.g. the CI job agent-sqlite)",
            );
        }
        if !landlock() {
            return skip("Landlock is not available on this kernel");
        }
        let base = PathBuf::from(format!(
            "/tmp/databastion-sqlite-reader-{}-{name}",
            std::process::id()
        ));
        let _ = Command::new("umount")
            .arg(base.join("ro"))
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rw = base.join("rw");
        let ro = base.join("ro");
        std::fs::create_dir(&rw).unwrap();
        std::fs::create_dir(&ro).unwrap();
        databastion_connector_sqlite::set_reader_executable_for_tests(reader_executable());
        databastion_connector_sqlite::set_reader_credentials_for_tests(AGENT_UID, SHARED_GID);
        Some(Self { base, rw, ro })
    }

    /// Mounts `rw` read-only on `ro`, after giving every file to the
    /// application.
    fn mount(&self) {
        give(&self.rw, 0o2750);
        for e in std::fs::read_dir(&self.rw).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                give(&p, 0o2750);
            } else {
                give(&p, 0o640);
            }
        }
        run(Command::new("mount")
            .arg("--bind")
            .arg(&self.rw)
            .arg(&self.ro));
        run(Command::new("mount")
            .args(["-o", "remount,bind,ro"])
            .arg(&self.ro));
    }

    /// Mounts `dir` (files another writer created, with their owners and
    /// modes) read-only on `ro`.
    fn mount_dir(&self, dir: &Path) {
        run(Command::new("mount").arg("--bind").arg(dir).arg(&self.ro));
        run(Command::new("mount")
            .args(["-o", "remount,bind,ro"])
            .arg(&self.ro));
    }

    fn target(&self, file: &str, mode: RollbackMode) -> TargetConfig {
        target_at(&self.ro.join(file), mode)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.ro).status();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn give(p: &Path, mode: u32) {
    std::os::unix::fs::chown(p, Some(APP_UID), Some(SHARED_GID)).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn target_at(path: &Path, mode: RollbackMode) -> TargetConfig {
    TargetConfig::sqlite_for_tests(
        "crm-app",
        SqliteSettings::for_tests(path.to_owned(), 500, mode),
    )
}

fn job(t: &TargetConfig) -> ScanJob {
    let limits = databastion_core::config::Limits {
        discovery_duty_cycle_percent: 100,
        ..databastion_core::config::Limits::default()
    };
    let key = Arc::new(databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap());
    ScanJob::new(ScanParams::contract_defaults(), t, &limits, key).with_rotation(42)
}

/// The findings of a scan: (object, field, classifier) and the coverage.
async fn scan(
    c: &SqliteConnector,
    t: &TargetConfig,
) -> (
    Vec<(String, String, String)>,
    databastion_core::ScanCoverage,
) {
    let (found, cov, _) = scan_masked(c, t).await;
    (found, cov)
}

/// The masked findings of a scan.
type Masked = Vec<databastion_classifiers::masking::MaskedFinding>;

/// [`scan`], with the masked findings themselves.
async fn scan_masked(
    c: &SqliteConnector,
    t: &TargetConfig,
) -> (
    Vec<(String, String, String)>,
    databastion_core::ScanCoverage,
    Masked,
) {
    let job = job(t);
    let (sink, mut rx) = FindingSink::channel(4096);
    c.discover(&job, &sink).await.unwrap();
    let cov = sink.coverage_for_tests().unwrap_or_default();
    drop(sink);
    let mut out = Vec::new();
    let mut masked = Vec::new();
    while let Some(f) = rx.recv().await {
        let l = f.location().unwrap();
        assert_eq!(l.database.as_str(), "main");
        assert!(l.schema.is_none());
        out.push((
            l.object.as_str().to_owned(),
            l.field.as_str().to_owned(),
            f.classifier().as_str().to_owned(),
        ));
        masked.push(f);
    }
    (out, cov, masked)
}

/// The `then` properties of the `allOf` entry of `$defs/<def>` whose `if`
/// is `engine: const sqlite` (review L9; no full JSON Schema validator is
/// in the dependencies: the generated types check the rest).
fn sqlite_branch(def: &str) -> serde_json::Map<String, serde_json::Value> {
    let path = databastion_protocol_codegen::default_openapi_path();
    let yaml = std::fs::read_to_string(path).unwrap();
    let doc = databastion_protocol_codegen::json_schema_from_openapi(&yaml).unwrap();
    doc["$defs"][def]["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["if"]["properties"]["engine"]["const"] == "sqlite")
        .unwrap()["then"]["properties"]
        .as_object()
        .unwrap()
        .clone()
}

/// Only `const` and `false` are understood; anything else fails the test.
fn conforms(rules: &serde_json::Map<String, serde_json::Value>, item: &serde_json::Value) {
    for (key, rule) in rules {
        match rule {
            serde_json::Value::Bool(false) => assert!(item.get(key).is_none(), "{key}: {item}"),
            serde_json::Value::Object(o) => {
                assert_eq!(o.keys().collect::<Vec<_>>(), ["const"], "{key}");
                assert_eq!(item.get(key), Some(&o["const"]), "{key}: {item}");
            }
            other => panic!("unsupported rule {other} under {key}"),
        }
    }
}

/// A log writer for the I2 check: every line the connector logs.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_rollback_file_is_scanned_by_the_sandboxed_reader() {
    let Some(env) = Env::new("rollback") else {
        return;
    };
    seed(&env.rw.join("crm.db"), false);
    env.mount();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let c = SqliteConnector::new();
    let t = env.target("crm.db", RollbackMode::Read);
    let h = c.check(&t).await;
    assert!(h.reachable, "{h:?}");
    assert_eq!(h.audit_level, AuditLevel::None);
    assert!(h.failure.is_none());
    let (found, cov) = scan(&c, &t).await;
    let has = |o: &str, f: &str, cl: &str| found.iter().any(|x| x.0 == o && x.1 == f && x.2 == cl);
    assert!(has("clients", "email", "pii.email"), "{found:?}");
    assert!(has("clients", "domain", "pii.email") || !found.is_empty());
    assert!(has("contacts", "email", "pii.email"), "{found:?}");
    assert!(has("contacts", "iban", "pii.iban"), "{found:?}");
    assert!(has("strict_t", "mail", "pii.email"), "{found:?}");
    assert!(has("odd", "mail", "pii.email"), "{found:?}");
    // Never the view, the VIRTUAL generated column, BLOB or REAL columns.
    assert!(
        !found
            .iter()
            .any(|x| x.0 == "v_clients" || x.1 == "initial" || x.1 == "note" || x.1 == "score")
    );
    assert!(cov.sampled >= 5, "{cov:?}");
    // Review L9: what the connector produced, through the core's one
    // conversion: none dropped, every batch a valid FindingsBatch, every
    // location conforming to the contract's sqlite branch.
    let (_, _, masked) = scan_masked(&c, &t).await;
    let bodies = databastion_core::test_support::contract_findings_json(
        &masked,
        databastion_core::config::TargetEngine::Sqlite,
    );
    let location = sqlite_branch("Location");
    let mut sent = 0;
    for body in bodies.lines() {
        let batch: databastion_protocol::FindingsBatch = serde_json::from_str(body).unwrap();
        let v = serde_json::to_value(&batch).unwrap();
        for f in v["findings"].as_array().unwrap() {
            conforms(&location, &f["location"]);
            sent += 1;
        }
    }
    assert!(sent > 0);
    assert_eq!(sent, masked.len(), "findings dropped by the core");
    // And the target status the heartbeat would send for the connector's
    // health, even if a connector reported a server version.
    let status = databastion_core::test_support::contract_target_status_json(
        &h,
        databastion_core::config::TargetEngine::Sqlite,
        Some("3.53.2"),
    );
    let parsed: databastion_protocol::TargetStatus = serde_json::from_str(&status).unwrap();
    conforms(
        &sqlite_branch("TargetStatus"),
        &serde_json::to_value(&parsed).unwrap(),
    );
    // I2 and decision 2: no sampled value and no path in the logs.
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!text.is_empty());
    for needle in [
        "@example.",
        "FR7630006",
        "33612345",
        "/tmp/databastion-sqlite-reader",
        "crm.db",
    ] {
        assert!(!text.contains(needle), "{needle} logged: {text}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_wal_file_is_read_while_another_process_writes_and_nothing_changes() {
    let Some(env) = Env::new("wal") else { return };
    let rw = env.rw.join("app.db");
    seed(&rw, true);
    env.mount();
    // The application: this process, holding the database open.
    let writer = Writer::open(&rw);
    writer.insert_email("late.writer@example.com");
    let c = SqliteConnector::new();
    let t = env.target("app.db", RollbackMode::Skip);
    let h = c.check(&t).await;
    assert!(h.reachable, "{h:?}");
    let snapshot = || {
        let mut v: Vec<(String, Vec<u8>, std::time::SystemTime)> = std::fs::read_dir(&env.rw)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                    m.modified().unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let before = snapshot();
    assert!(
        before.iter().any(|(n, _, _)| n == "app.db-wal")
            && before.iter().any(|(n, _, _)| n == "app.db-shm")
    );
    let (found, _) = scan(&c, &t).await;
    assert!(
        found.iter().any(|x| x.0 == "clients" && x.1 == "email"),
        "{found:?}"
    );
    // The directory, the -wal and the -shm: byte for byte and mtime.
    assert!(before == snapshot(), "the reader changed a file");
    // No reader was killed (review L3: the idle locks of a WAL reader are
    // those of an idle connection).
    let h = c.check(&t).await;
    assert!(
        !h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageReaderProcessFailed),
        "{h:?}"
    );
    // A write after the scan is seen by the next one.
    writer.insert_email("later@example.com");
    let (again, _) = scan(&c, &t).await;
    assert!(!again.is_empty());
    drop(writer);
    // The application closed cleanly: no -wal / -shm, not readable.
    let h = c.check(&t).await;
    assert!(!h.reachable);
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageWalFilesNotReadable),
        "{h:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn refusals_are_reported_with_their_notes() {
    let Some(env) = Env::new("refusals") else {
        return;
    };
    seed(&env.rw.join("rollback.db"), false);
    seed(&env.rw.join("agent-owned.db"), false);
    env.mount();
    let c = SqliteConnector::new();
    // A rollback file under the default `skip`: reachable, not read.
    let t = env.target("rollback.db", RollbackMode::Skip);
    let h = c.check(&t).await;
    assert!(h.reachable);
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageRollbackModeNotRead),
        "{h:?}"
    );
    let (found, cov) = scan(&c, &t).await;
    assert!(found.is_empty());
    assert_eq!(cov.unsupported, 1);
    // The file system is not read-only: the same file through `rw`.
    let t = target_at(&env.rw.join("rollback.db"), RollbackMode::Read);
    let h = c.check(&t).await;
    assert_eq!(h.failure, Some(FailureCode::Unsupported));
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageFilesystemNotReadOnly),
        "{h:?}"
    );
    // A file the agent's account owns (it could write it).
    run(Command::new("umount").arg(&env.ro));
    std::os::unix::fs::chown(env.rw.join("agent-owned.db"), Some(AGENT_UID), None).unwrap();
    run(Command::new("mount")
        .arg("--bind")
        .arg(&env.rw)
        .arg(&env.ro));
    run(Command::new("mount")
        .args(["-o", "remount,bind,ro"])
        .arg(&env.ro));
    let t = env.target("agent-owned.db", RollbackMode::Read);
    let h = c.check(&t).await;
    assert_eq!(h.failure, Some(FailureCode::Unsupported));
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::PrivilegeDatabaseFileWritable),
        "{h:?}"
    );
    // A symlink in the path.
    let link = env.base.join("link");
    std::os::unix::fs::symlink(&env.ro, &link).unwrap();
    let t = target_at(&link.join("rollback.db"), RollbackMode::Read);
    let h = c.check(&t).await;
    assert!(
        h.notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageFilePathRefused),
        "{h:?}"
    );
    // Not readable by the agent's account.
    let t = env.target("missing.db", RollbackMode::Read);
    assert_eq!(
        c.check(&t).await.failure,
        Some(FailureCode::TargetUnreachable)
    );
}

fn status_field(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().to_owned()))
        .unwrap()
}

/// Decision 4: the reader runs with no new privileges, a seccomp filter,
/// its limits and an empty environment; a `-shm` truncated under it kills
/// the reader with `SIGBUS`, never the agent.
#[tokio::test(flavor = "current_thread")]
async fn the_reader_is_sandboxed_and_its_crashes_stay_its_own() {
    let Some(env) = Env::new("sandbox") else {
        return;
    };
    let rw = env.rw.join("app.db");
    seed(&rw, true);
    env.mount();
    // The application in its own process: a truncated -shm raises SIGBUS
    // in every process that maps it.
    let mut writer = writer_process(&rw);
    let ro = env.ro.join("app.db");
    let mut r = ReaderProcess::spawn().unwrap();
    let open = Request::Open(databastion_connector_sqlite::ipc::OpenRequest {
        path: zeroize::Zeroizing::new(ro.as_os_str().as_encoded_bytes().to_vec()),
        max_statement_ms: 500,
        rollback_read: false,
    });
    let resp = r.call(&open, Duration::from_secs(5)).await.unwrap();
    assert!(matches!(resp, Response::Opened(o) if o.wal), "{resp:?}");
    let pid = r.pid_for_tests().unwrap();
    assert_eq!(status_field(pid, "NoNewPrivs:"), "1");
    assert_eq!(status_field(pid, "Seccomp:"), "2");
    assert_eq!(
        status_field(pid, "Uid:").split_whitespace().next(),
        Some("10003")
    );
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    for (name, value) in [
        ("Max file size", "0"),
        ("Max open files", "16"),
        ("Max core file size", "0"),
    ] {
        let line = limits.lines().find(|l| l.starts_with(name)).unwrap();
        assert_eq!(
            line.split_whitespace().nth(name.split(' ').count()),
            Some(value),
            "{line}"
        );
    }
    assert!(
        std::fs::read(format!("/proc/{pid}/environ"))
            .unwrap()
            .is_empty(),
        "the environment was passed"
    );
    let resp = r
        .call(&Request::Catalog, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(resp, Response::Catalog(..)), "{resp:?}");
    let sample = Request::Sample(SampleRequest {
        table: zeroize::Zeroizing::new(b"clients".to_vec()),
        alias: Some(RowidAlias::Rowid),
        columns: vec![zeroize::Zeroizing::new(b"email".to_vec())],
        range: SampleRange::From(1),
        limit: 10,
    });
    let resp = r.call(&sample, Duration::from_secs(5)).await.unwrap();
    assert!(
        matches!(resp, Response::Sample(ref s) if s.rows == 10),
        "{resp:?}"
    );
    // Review N1: between units the reader is stopped, its locks read while
    // it cannot change them (those of an idle WAL connection, by the
    // agent's own view of the file), and it answers again once continued.
    assert!(r.pause().await, "the reader did not stop");
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    assert!(
        state.rsplit_once(") ").unwrap().1.starts_with('T'),
        "{state}"
    );
    let view = databastion_connector_sqlite::check::agent_view(&ro).unwrap();
    assert!(view.wal && view.shm_ino != 0);
    assert_eq!(
        databastion_connector_sqlite::locks::idle_ok_now(pid, view.id, view.shm_ino, view.wal),
        Some(true)
    );
    let resp = r.call(&sample, Duration::from_secs(5)).await.unwrap();
    assert!(
        matches!(resp, Response::Sample(ref s) if s.rows == 10),
        "{resp:?}"
    );
    // The application's account truncates the -shm under the reader.
    std::fs::OpenOptions::new()
        .write(true)
        .open(databastion_connector_sqlite::files::side_path(&rw, "-shm"))
        .unwrap()
        .set_len(0)
        .unwrap();
    let after = r.call(&sample, Duration::from_secs(5)).await;
    // SIGBUS in the reader (measured: always `Died`).
    assert_eq!(after.err(), Some(Death::Died));
    // This process (the agent) is still here.
    let _ = writer.kill();
    let _ = writer.wait();
}

/// Starts the writer helper (this test binary, `writer_helper_process`)
/// holding `path` open, and waits until it wrote.
fn writer_process(path: &Path) -> std::process::Child {
    use std::io::BufRead;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "writer_helper_process",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("DATABASTION_IT_SQLITE_WRITER", path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    for line in std::io::BufReader::new(out).lines() {
        if line.unwrap().contains("writer-ready") {
            return child;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the writer helper did not start");
}

/// The writer helper process (started by `writer_process`, never on its
/// own): holds the database open and writes, until its stdin closes.
#[test]
#[ignore = "helper process of the reader tests, started by them"]
fn writer_helper_process() {
    let Some(path) = std::env::var_os("DATABASTION_IT_SQLITE_WRITER") else {
        return;
    };
    let w = Writer::open(Path::new(&path));
    w.insert_email("w@example.com");
    let mut stdout = std::io::stdout();
    writeln!(stdout, "writer-ready").unwrap();
    stdout.flush().unwrap();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// The dev directory (the seed manifest, its SQL scripts, the ground truth).
fn dev_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev")
}

/// One file of the seeded matrix: its name, the manifest file it was
/// written from, its journal mode and the optional modules its writer had.
struct Variant {
    file: String,
    base: String,
    journal_mode: String,
    modules: Vec<String>,
}

const JOURNAL_MODES: [&str; 4] = ["delete", "truncate", "persist", "wal"];
const PAGE_SIZES: [u32; 3] = [512, 4096, 65_536];
const AUTO_VACUUM: [&str; 2] = ["none", "full"];

/// The script without its `-- databastion:requires fts5` blocks (the
/// bundled library compiles FTS5 out).
fn without_fts5(sql: &str) -> String {
    let mut out = String::new();
    let mut skip = false;
    for line in sql.split_inclusive('\n') {
        match line.trim() {
            "-- databastion:requires fts5" => skip = true,
            "-- databastion:end" => skip = false,
            _ if !skip => out.push_str(line),
            _ => {}
        }
    }
    out
}

/// Writes the matrix of `dev/sqlite/build.py matrix` into `dir` with the
/// bundled library, without the FTS5 blocks.
fn build_matrix(dir: &Path) -> Vec<Variant> {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dev_dir().join("seed/out/sqlite.json")).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    for e in manifest["files"].as_array().unwrap() {
        let base = e["file"].as_str().unwrap();
        let sql = without_fts5(
            &std::fs::read_to_string(dev_dir().join("seed/out").join(e["sql"].as_str().unwrap()))
                .unwrap(),
        );
        let encoding = e["encoding"].as_str().unwrap();
        for jm in JOURNAL_MODES {
            for ps in PAGE_SIZES {
                for (i, av) in AUTO_VACUUM.iter().enumerate() {
                    let file = format!("{}-{jm}-p{ps}-av{i}.db", base.trim_end_matches(".db"));
                    build_from_sql(&dir.join(&file), &sql, jm, encoding, ps, av);
                    out.push(Variant {
                        file,
                        base: base.to_owned(),
                        journal_mode: jm.to_owned(),
                        modules: Vec::new(),
                    });
                }
            }
        }
    }
    out
}

/// The variants another writer recorded in `dir/variants.json`.
fn read_variants(dir: &Path) -> (String, Vec<Variant>) {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("variants.json")).unwrap()).unwrap();
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_owned();
    let variants = doc["variants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Variant {
            file: s(&v["file"]),
            base: s(&v["base"]),
            journal_mode: s(&v["journal_mode"]),
            modules: v["modules"].as_array().unwrap().iter().map(s).collect(),
        })
        .collect();
    (s(&doc["sqlite_version"]), variants)
}

/// A ground-truth location as a finding stores it: the part of a name
/// that carries a value replaced by its expected normalized name.
fn location_key(loc: &serde_json::Value) -> (String, String) {
    let s = |k: &str| loc[k].as_str().unwrap_or_default().to_owned();
    let (mut object, mut field) = (s("object"), s("field"));
    if let Some(norm) = loc["expected_normalized_name"].as_str() {
        let in_name = |n: &str| {
            loc["name_values"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|v| n.contains(v.as_str().unwrap()))
        };
        if in_name(&object) {
            norm.clone_into(&mut object);
        } else if in_name(&field) {
            norm.clone_into(&mut field);
        }
    }
    (object, field)
}

/// ADR-0059 decision 10 (P10-D): the dev seed's files (dev/seed/out/sqlite.json),
/// in every journal mode (DELETE, TRUNCATE, PERSIST, WAL), page size (512,
/// 4 096, 65 536) and `auto_vacuum` setting, read by the sandboxed reader
/// and compared with dev/ground-truth.json: every location with an
/// expected classifier found, no finding anywhere else, no value in the
/// logs. The writer is the bundled library (this process, holding the WAL
/// files open), or, with `DATABASTION_IT_SQLITE_SEEDED=<dir>`, another
/// SQLite: the engine matrix's writers, which wrote `<dir>` with
/// `dev/sqlite/build.py matrix --hold` as the application's account and
/// hold its WAL files open.
#[tokio::test(flavor = "current_thread")]
async fn seeded_dev_files_match_the_ground_truth() {
    let Some(env) = Env::new("seeded") else {
        return;
    };
    let mut writers = Vec::new();
    let (writer, variants) = if let Some(dir) = std::env::var_os("DATABASTION_IT_SQLITE_SEEDED") {
        let dir = PathBuf::from(dir);
        let (version, variants) = read_variants(&dir);
        env.mount_dir(&dir);
        (format!("SQLite {version} (another process)"), variants)
    } else {
        let variants = build_matrix(&env.rw);
        for v in variants.iter().filter(|v| v.journal_mode == "wal") {
            writers.push(Writer::hold(&env.rw.join(&v.file)));
        }
        env.mount();
        ("the bundled library (this process)".to_owned(), variants)
    };
    assert_eq!(
        variants.len(),
        72,
        "3 files x 4 journal modes x 3 page sizes x 2"
    );
    let truth: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dev_dir().join("ground-truth.json")).unwrap(),
    )
    .unwrap();
    let locations: Vec<&serde_json::Value> = truth["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "sqlite")
        .collect();
    assert!(!locations.is_empty());
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let c = SqliteConnector::new();
    let mut errors = Vec::new();
    for v in &variants {
        let id = v.file.trim_end_matches(".db").to_owned();
        let t = TargetConfig::sqlite_for_tests(
            &id,
            SqliteSettings::for_tests(env.ro.join(&v.file), 500, RollbackMode::Read),
        );
        let h = c.check(&t).await;
        if !h.reachable || h.failure.is_some() || h.audit_level != AuditLevel::None {
            errors.push(format!("{id}: check {h:?}"));
            continue;
        }
        let (found, cov) = scan(&c, &t).await;
        let mut expected = 0;
        let mut missing = Vec::new();
        let mut want: Vec<((String, String), Vec<&str>)> = Vec::new();
        for loc in locations.iter().filter(|l| l["file"] == v.base.as_str()) {
            if let Some(m) = loc["requires"].as_str()
                && !v.modules.iter().any(|x| x == m)
            {
                continue;
            }
            let key = location_key(loc);
            let classifiers: Vec<&str> = loc["expected_classifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect();
            if !classifiers.is_empty() {
                expected += 1;
                if !found.iter().any(|f| {
                    (&f.0, &f.1) == (&key.0, &key.1) && classifiers.contains(&f.2.as_str())
                }) {
                    // Location names without the value-bearing part (the
                    // normalized key) are safe to print.
                    missing.push(format!("{}.{} {classifiers:?}", key.0, key.1));
                }
            }
            want.push((key, classifiers));
        }
        let unexpected: Vec<String> = found
            .iter()
            .filter(|f| {
                !want
                    .iter()
                    .any(|(k, cl)| (&k.0, &k.1) == (&f.0, &f.1) && cl.contains(&f.2.as_str()))
            })
            .map(|f| {
                // A finding's names are normalized: no value.
                format!("{}.{} {}", f.0, f.1, f.2)
            })
            .collect();
        eprintln!(
            "[it] sqlite seeded ({writer}): {id}: {} finding(s), {}/{expected} expected location(s), \
             sampled {}, unsupported {}, limit {}",
            found.len(),
            expected - missing.len(),
            cov.sampled,
            cov.unsupported,
            cov.limit,
        );
        if !missing.is_empty() {
            errors.push(format!("{id}: not found: {missing:?}"));
        }
        if !unexpected.is_empty() {
            errors.push(format!("{id}: unexpected: {unexpected:?}"));
        }
    }
    drop(writers);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    // I2 and decision 2: no ground-truth value (long enough not to match a
    // word of a log line by chance) and no path in the logs.
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!text.is_empty());
    let mut leaked = 0;
    for loc in &locations {
        for v in loc["values"]
            .as_array()
            .into_iter()
            .chain(loc["name_values"].as_array())
            .flatten()
        {
            let v = v.as_str().unwrap();
            if v.chars().count() >= 8 && text.contains(v) {
                leaked += 1;
            }
        }
    }
    assert_eq!(leaked, 0, "ground-truth value(s) in the logs");
    for needle in ["/tmp/databastion-sqlite-reader", ".db\""] {
        assert!(!text.contains(needle), "{needle} logged");
    }
}

/// ADR-0059 decision 4 and the end-to-end scenario of decision 10: a
/// `-shm` truncated by the application while a paced scan (the default
/// 1 % duty cycle) runs kills the reader at its next unit with `SIGBUS`:
/// one reader lost, its unit counted `skipped_error`; the scan goes on
/// and succeeds (until the application rebuilds its WAL index the next
/// readers find the file not readable, `wal_files_not_readable`, and
/// count their tables `skipped_error` too, without dying); once the
/// application opened the file again a new scan loses nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_shm_truncated_during_a_paced_scan_costs_a_unit_never_the_agent() {
    let Some(env) = Env::new("paced-shm") else {
        return;
    };
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let rw = env.rw.join("app.db");
    seed(&rw, true);
    env.mount();
    let mut writer = writer_process(&rw);
    let c = SqliteConnector::new();
    let t = env.target("app.db", RollbackMode::Skip);
    assert!(c.check(&t).await.reachable);
    let key = Arc::new(databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap());
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &t,
        &databastion_core::config::Limits::default(),
        key,
    )
    .with_rotation(42);
    let (sink, mut rx) = FindingSink::channel(4096);
    let shm = databastion_connector_sqlite::files::side_path(&rw, "-shm");
    let truncate = async {
        // A few paced units in: the reader has mapped the -shm.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&shm)
            .unwrap()
            .set_len(0)
            .unwrap();
        std::time::Instant::now()
    };
    let started = std::time::Instant::now();
    let (outcome, truncated_at) = tokio::join!(c.discover(&job, &sink), truncate);
    outcome.unwrap();
    let cov = sink.coverage_for_tests().unwrap_or_default();
    drop(sink);
    let mut found = 0;
    while rx.recv().await.is_some() {
        found += 1;
    }
    eprintln!(
        "[it] sqlite paced scan with a truncated -shm: truncated after {:?}, scan {:?}, {found} finding(s), {cov:?}",
        truncated_at - started,
        started.elapsed()
    );
    assert!(
        started.elapsed() > truncated_at - started,
        "the scan ended before the truncation"
    );
    assert!(cov.error >= 1, "no unit lost: {cov:?}");
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text.matches("sqlite reader process lost").count(),
        1,
        "one reader death"
    );
    // The application crashed or not, it opens the file again.
    let _ = writer.kill();
    let _ = writer.wait();
    let mut writer = writer_process(&rw);
    let h = c.check(&t).await;
    assert!(h.reachable, "{h:?}");
    let (found, cov) = scan(&c, &t).await;
    assert_eq!(cov.error, 0, "{cov:?}");
    assert!(!found.is_empty());
    let _ = writer.kill();
    let _ = writer.wait();
}
