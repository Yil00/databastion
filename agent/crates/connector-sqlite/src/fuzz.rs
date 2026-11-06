//! Entry points of the fuzz targets (`agent/fuzz`, feature `fuzzing`, never
//! the agent binary; ADR-0059 decision 5, security review L6).
//!
//! - [`header`]: the Rust header pre-check alone.
//! - [`ipc`]: both IPC decoders and the frame assembler.
//! - [`file`]: a main file and optional `-wal`, `-shm` and `-journal` files,
//!   written to a private directory and run through the reader's real
//!   pipeline (the path and file checks, the header pre-check, the
//!   connection setup, the catalog, `table_xinfo` and sampling statements)
//!   with the production limits and a small statement deadline. The
//!   self-check of decision 1 runs first and fails the run when the build
//!   did not get the production `LIBSQLITE3_FLAGS`. A WAL file set runs
//!   twice: first with nobody holding the `-shm` `DMS` lock (SQLite builds
//!   its private heap copy of the WAL index from the `-wal`), then with a
//!   [`ShmHelper`] process holding it, as an application's writer does, so
//!   that SQLite maps the fuzzed `-shm` read-only and trusts its WAL index
//!   (the reliable `-shm` path).
//!
//! Every entry point must never panic nor hang, whatever the input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::files::Policy;
use crate::ipc::{
    FrameBuffer, MAX_RESPONSE, OpenRequest, Request, Response, RowidAlias, SampleRange,
    SampleRequest,
};
use crate::reader::Session;

/// The header pre-check on arbitrary bytes.
pub fn header(data: &[u8]) {
    let len = u64::try_from(data.len()).unwrap_or(0);
    let _ = crate::header::check(data, len.saturating_mul(4096));
    let _ = crate::header::check(data, len);
}

/// Both IPC decoders and the frame assembler.
pub fn ipc(data: &[u8]) {
    let _ = Request::decode(data);
    let _ = Response::decode(data);
    let mut fb = FrameBuffer::new(MAX_RESPONSE);
    for chunk in data.chunks(7) {
        if fb.push(chunk).is_err() {
            break;
        }
        if let Ok(Some(body)) = fb.take() {
            let _ = Response::decode(&body);
        }
    }
}

/// The private directory of this fuzz process (mode 0700).
fn dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        // The self-check first: a build without the production flags fails
        // the run here.
        crate::db::self_check().expect("SQLite self-check (production LIBSQLITE3_FLAGS)");
        let d = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("databastion-fuzz-sqlite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    })
}

/// Splits the input into length-prefixed parts (a 3-byte length each):
/// the main file, then the `-wal`, `-shm` and `-journal` files (absent when
/// the input ends first).
fn split(mut data: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    while parts.len() < 4 {
        let Some((len, rest)) = data.split_first_chunk::<3>() else {
            break;
        };
        let n = usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]);
        let (part, rest) = rest.split_at(n.min(rest.len()));
        parts.push(part);
        data = rest;
    }
    parts
}

/// The `-shm` of the fuzzed file set (the [`ShmHelper`] locks this path).
#[must_use]
pub fn shm_path() -> PathBuf {
    crate::files::side_path(&dir().join("f.db"), "-shm")
}

/// The size of one `-shm` region: a writer's `-shm` is always a multiple of
/// it, and SQLite maps nothing of a shorter one.
const SHM_REGION: usize = 32 * 1024;

/// A hostile file set through the reader's pipeline. With `helper`, a WAL
/// set (a `-wal` and a `-shm` part) runs a second time with the helper
/// holding the `-shm` `DMS` lock, its `-shm` part padded with zeros to a
/// whole number of regions.
pub fn file(data: &[u8], helper: Option<&mut ShmHelper>) {
    let _ = file_counted(data, helper);
}

/// [`file`], returning the rows each pass sampled (tests).
fn file_counted(data: &[u8], helper: Option<&mut ShmHelper>) -> (u64, Option<u64>) {
    let d = dir();
    let main = d.join("f.db");
    let sides = ["-wal", "-shm", "-journal"];
    for s in sides {
        let _ = std::fs::remove_file(crate::files::side_path(&main, s));
    }
    let parts = split(data);
    let Some(first) = parts.first() else {
        return (0, None);
    };
    std::fs::write(&main, first).unwrap();
    for (s, part) in sides.iter().zip(parts.iter().skip(1)) {
        std::fs::write(crate::files::side_path(&main, s), part).unwrap();
    }
    let unlocked = run(&main);
    let (Some(helper), Some(shm)) = (helper, parts.get(2)) else {
        return (unlocked, None);
    };
    // The reliable -shm path: the same files, the -shm padded as a writer's
    // always is, and another process holding its DMS lock.
    let mut padded = shm.to_vec();
    padded.resize(padded.len().div_ceil(SHM_REGION).max(1) * SHM_REGION, 0);
    let shm_file = crate::files::side_path(&main, "-shm");
    let _ = std::fs::remove_file(&shm_file);
    std::fs::write(&shm_file, &padded).unwrap();
    helper.lock();
    let locked = run(&main);
    helper.unlock();
    (unlocked, Some(locked))
}

/// One pass of the reader's pipeline on the written files; the rows
/// sampled.
fn run(main: &Path) -> u64 {
    let req = OpenRequest {
        path: zeroize::Zeroizing::new(crate::files::path_bytes(main)),
        max_statement_ms: 50,
        rollback_read: true,
    };
    // The fuzzer's own files: the writability and read-only mount rules
    // cannot hold here; every other check and every SQLite setting is the
    // production one.
    let policy = Policy {
        refuse_agent_writable: false,
        require_read_only_fs: false,
        exact_descriptor_set: false,
        open_no_links: true,
    };
    let Ok((mut s, _)) = Session::open(&req, policy, None) else {
        return 0;
    };
    let mut sampled = 0u64;
    let Response::Catalog(rows, _) = s.handle(&Request::Catalog) else {
        return 0;
    };
    for row in rows.iter().filter(|r| !r.view && r.rootpage > 0).take(8) {
        let Response::Columns(cols) = s.handle(&Request::Columns(row.name.clone())) else {
            continue;
        };
        let columns: Vec<_> = cols
            .iter()
            .filter(|c| c.hidden != 2 && crate::sql::quote(&c.name).is_some())
            .take(crate::ipc::MAX_COLUMNS)
            .map(|c| c.name.clone())
            .collect();
        if columns.is_empty() {
            continue;
        }
        let range = match s.handle(&Request::Bounds(row.name.clone(), RowidAlias::Rowid)) {
            Response::Bounds(Some((lo, _))) => SampleRange::From(lo),
            Response::Bounds(None) => continue,
            _ => SampleRange::Plain { reverse: false },
        };
        let alias = match range {
            SampleRange::Plain { .. } => None,
            _ => Some(RowidAlias::Rowid),
        };
        if let Response::Sample(r) = s.handle(&Request::Sample(SampleRequest {
            table: row.name.clone(),
            alias,
            columns,
            range,
            limit: 100,
        })) {
            sampled += u64::from(r.rows);
        }
    }
    let _ = s.handle(&Request::Stats);
    let _ = s.handle(&Request::Pragmas);
    let _ = s.handle(&Request::Close);
    sampled
}

/// The environment variable that makes a process the [`ShmHelper`]: the
/// path of the `-shm` to lock.
pub const SHM_HELPER_ENV: &str = "DATABASTION_FUZZ_SHM_HELPER";

/// The tag of the helper's answers on its standard output (any other text,
/// such as a test harness's, is ignored).
const ANSWER: &str = "databastion-fuzz-shm-helper: ";

/// How long the helper may take to start (an instrumented binary) and to
/// answer one request.
const START_TIMEOUT: Duration = Duration::from_secs(30);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// The helper process's side: when [`SHM_HELPER_ENV`] is set, this process
/// is the helper, and this function never returns. It answers `ready`,
/// then, per line on its standard input, `L` (open the `-shm` read-only and
/// take a shared POSIX lock on its `DMS` byte alone, as an idle
/// application's connection holds it: `locked` or `failed`) and `U`
/// (close it, which drops the lock: `unlocked`); it exits at the end of
/// its input, so it never outlives the process that started it, whatever
/// ends that one. Call it first in the fuzz target's `init`.
pub fn shm_helper_if_requested() {
    let Some(path) = std::env::var_os(SHM_HELPER_ENV) else {
        return;
    };
    let path = PathBuf::from(path);
    let mut out = std::io::stdout().lock();
    let answer = |out: &mut std::io::StdoutLock<'_>, what: &str| {
        let ok = writeln!(out, "{ANSWER}{what}").and_then(|()| out.flush());
        if ok.is_err() {
            std::process::exit(0);
        }
    };
    answer(&mut out, "ready");
    let mut held: Option<rustix::fd::OwnedFd> = None;
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        match line.as_str() {
            "L" => {
                held = None;
                let fd = rustix::fs::open(
                    &path,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .ok()
                .filter(lock_dms);
                match fd {
                    Some(fd) => {
                        held = Some(fd);
                        answer(&mut out, "locked");
                    }
                    None => answer(&mut out, "failed"),
                }
            }
            "U" => {
                held = None;
                answer(&mut out, "unlocked");
            }
            _ => break,
        }
    }
    drop(held);
    std::process::exit(0);
}

/// The `DMS` byte of the `-shm` (`UNIX_SHM_BASE + SQLITE_SHM_NLOCK`, as in
/// `locks.rs`).
const SHM_DMS: u8 = 128;

/// A shared POSIX lock on the `DMS` byte alone, as an idle writer's
/// connection holds it (`F_SETLK`, not waiting).
fn lock_dms(fd: &rustix::fd::OwnedFd) -> bool {
    let lock = libc::flock {
        l_type: libc::F_RDLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: libc::off_t::from(SHM_DMS),
        l_len: 1,
        l_pid: 0,
    };
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETLK(&lock)).is_ok()
}

/// A helper process that holds the fuzzed `-shm`'s `DMS` lock while the
/// reader's pipeline runs (ADR-0059 decision 5, fuzzing): POSIX locks are
/// per process, so SQLite in this process sees the lock only when another
/// process holds it. The process is started from the command its caller
/// builds (the fuzz target's own binary, whose `init` calls
/// [`shm_helper_if_requested`]), and ends when this value is dropped or
/// this process ends (the end of its standard input).
pub struct ShmHelper {
    child: Child,
    stdin: Option<ChildStdin>,
    answers: Receiver<String>,
}

impl std::fmt::Debug for ShmHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShmHelper")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl ShmHelper {
    /// Starts the helper from `command` (its program and arguments; the
    /// environment variable and the standard streams are set here) and
    /// waits for it to be ready.
    ///
    /// # Panics
    /// When the helper cannot be started or does not answer: the harness
    /// itself is broken, which must fail the run.
    #[must_use]
    pub fn start(mut command: std::process::Command) -> Self {
        let mut child = command
            .env(SHM_HELPER_ENV, shm_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sqlite_file harness: start the -shm helper");
        let stdout = child.stdout.take().expect("helper stdout");
        let stdin = child.stdin.take();
        let (tx, answers) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some((_, a)) = line.split_once(ANSWER)
                    && tx.send(a.to_owned()).is_err()
                {
                    break;
                }
            }
        });
        let mut h = Self {
            child,
            stdin,
            answers,
        };
        h.expect("ready", START_TIMEOUT);
        h
    }

    /// Waits for `want`; panics on another answer, the end of the helper
    /// or the timeout.
    fn expect(&mut self, want: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let got = self
            .answers
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match got {
            Ok(a) if a == want => {}
            Ok(a) => panic!("sqlite_file harness: the -shm helper answered {a}, not {want}"),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("sqlite_file harness: the -shm helper did not answer {want}");
            }
        }
    }

    fn send(&mut self, line: &str) {
        let sent = self
            .stdin
            .as_mut()
            .map(|s| writeln!(s, "{line}").and_then(|()| s.flush()));
        assert!(
            matches!(sent, Some(Ok(()))),
            "sqlite_file harness: the -shm helper is gone"
        );
    }

    /// The helper takes the `DMS` lock on [`shm_path`].
    ///
    /// # Panics
    /// When it cannot (see [`ShmHelper::start`]).
    pub fn lock(&mut self) {
        self.send("L");
        self.expect("locked", ANSWER_TIMEOUT);
    }

    /// The helper drops the lock.
    ///
    /// # Panics
    /// When it does not answer (see [`ShmHelper::start`]).
    pub fn unlock(&mut self) {
        self.send("U");
        self.expect("unlocked", ANSWER_TIMEOUT);
    }

    /// The helper's process id (tests).
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for ShmHelper {
    /// Ends the helper's input, waits up to one second for it to exit,
    /// then kills it: no process outlives the value.
    fn drop(&mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![
            u8::try_from(bytes.len() >> 16).unwrap(),
            u8::try_from((bytes.len() >> 8) & 0xff).unwrap(),
            u8::try_from(bytes.len() & 0xff).unwrap(),
        ];
        out.extend_from_slice(bytes);
        out
    }

    /// This test binary as the helper (`shm_helper_process` below).
    fn helper() -> ShmHelper {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "fuzz::tests::shm_helper_process",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ]);
        ShmHelper::start(c)
    }

    /// The fuzz tests share this process's one fuzz directory.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    #[ignore = "helper process of the fuzz tests, started by them"]
    fn shm_helper_process() {
        shm_helper_if_requested();
    }

    #[test]
    fn entry_points_take_any_input() {
        let _g = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut h = helper();
        for input in [&b""[..], b"\x00\x00\x05hello", &[0xff; 300]] {
            header(input);
            ipc(input);
            file(input, None);
            file(input, Some(&mut h));
        }
        // A real file through the pipeline.
        let d = crate::it::Dir::new("fuzz-seed");
        let p = d.path("seed.db");
        crate::testing::seed(&p, false);
        file(&part(&std::fs::read(&p).unwrap()), Some(&mut h));
    }

    /// The second pass takes the reliable -shm path: with the helper
    /// holding the DMS lock, SQLite trusts the fuzzed WAL index, which here
    /// is a writer's -shm saved before its last commit, so that commit's
    /// frames (still in the -wal) are not read; without the lock, the heap
    /// copy of the WAL index is built from the whole -wal and reads them.
    #[test]
    fn a_wal_set_runs_the_heap_and_the_reliable_shm_paths() {
        let _g = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let d = crate::it::Dir::new("fuzz-wal");
        let p = d.path("w.db");
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('a@example.com');",
        )
        .unwrap();
        let _: i64 = c
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        let shm = std::fs::read(crate::files::side_path(&p, "-shm")).unwrap();
        c.execute("INSERT INTO t VALUES ('b@example.com')", [])
            .unwrap();
        let main = std::fs::read(&p).unwrap();
        let wal = std::fs::read(crate::files::side_path(&p, "-wal")).unwrap();
        drop(c);
        assert_eq!(shm.len() % SHM_REGION, 0);
        let mut input = part(&main);
        input.extend(part(&wal));
        input.extend(part(&shm));
        let mut h = helper();
        let (unlocked, locked) = file_counted(&input, Some(&mut h));
        assert_eq!((unlocked, locked), (2, Some(1)));
        // Without a helper, one pass only.
        assert_eq!(file_counted(&input, None), (2, None));
        // The helper ends with its value.
        let pid = h.pid();
        drop(h);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
