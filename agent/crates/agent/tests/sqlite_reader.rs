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
use databastion_connector_sqlite::testing::{Writer, seed};
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
    let job = job(t);
    let (sink, mut rx) = FindingSink::channel(4096);
    c.discover(&job, &sink).await.unwrap();
    let cov = sink.coverage_for_tests().unwrap_or_default();
    drop(sink);
    let mut out = Vec::new();
    while let Some(f) = rx.recv().await {
        let l = f.location().unwrap();
        assert_eq!(l.database.as_str(), "main");
        assert!(l.schema.is_none());
        out.push((
            l.object.as_str().to_owned(),
            l.field.as_str().to_owned(),
            f.classifier().as_str().to_owned(),
        ));
    }
    (out, cov)
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
