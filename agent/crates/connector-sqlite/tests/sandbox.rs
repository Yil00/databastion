//! The reader's sandbox, applied for real (review L2, ADR-0059 decision 4):
//! this binary re-executes itself in a child mode, applies
//! `sandbox::early` and `sandbox::restrict` as the reader does, and checks
//! that what a compromised reader would try is refused. The child inherits
//! a descriptor without `O_CLOEXEC` (as cargo's jobserver pipes, PR #356),
//! which `sandbox::early` must close. Needs Landlock; skipped without it
//! unless `DATABASTION_IT_SQLITE_REQUIRE=1`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use databastion_connector_sqlite::sandbox;
use rustix::fs::{FlockOperation, Mode, OFlags};

const CHILD: &str = "--sandbox-child";

fn refused<T: std::fmt::Debug>(
    what: &str,
    r: Result<T, rustix::io::Errno>,
    errno: rustix::io::Errno,
) {
    match r {
        Err(e) if e == errno => {}
        other => panic!("{what}: expected {errno:?}, got {other:?}"),
    }
}

/// The child: the sandbox of a reader opening `db`, then every refusal.
/// `leaked` is the descriptor number it inherited.
fn child(db: &Path, leaked: i32) {
    let ppid = rustix::process::getppid().expect("a parent");
    let fd_path = PathBuf::from(format!("/proc/self/fd/{leaked}"));
    assert!(
        fd_path.symlink_metadata().is_ok(),
        "fd {leaked} not inherited"
    );
    if let Err((step, f)) = sandbox::early_step() {
        panic!("sandbox::early failed at step {step}: {f:?}");
    }
    // Every inherited descriptor is closed.
    assert!(
        fd_path.symlink_metadata().is_err(),
        "fd {leaked} still open after early"
    );
    let fds: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(fds.len() <= 4, "descriptors after early: {fds:?}");
    if let Err(f) = sandbox::restrict(db) {
        panic!("sandbox::restrict failed: {f:?}");
    }
    // Reading the declared file works.
    let fd = rustix::fs::open(db, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .expect("read the file");
    let mut b = [0u8; 4];
    assert_eq!(rustix::io::pread(&fd, &mut b, 0).unwrap(), 4);
    // No socket (std reports the seccomp EPERM as PermissionDenied).
    let s = std::net::TcpStream::connect("127.0.0.1:9");
    assert_eq!(
        s.as_ref().map_err(std::io::Error::raw_os_error).err(),
        Some(Some(libc::EPERM)),
        "socket: {s:?}"
    );
    // No signal to the agent, no limit change on it.
    refused(
        "kill(ppid, 0)",
        rustix::process::test_kill_process(ppid),
        rustix::io::Errno::PERM,
    );
    refused(
        "prlimit64(ppid)",
        rustix::process::prlimit(
            Some(ppid),
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(1),
                maximum: Some(1),
            },
        ),
        rustix::io::Errno::PERM,
    );
    // No write open of the declared file.
    refused(
        "open(O_RDWR)",
        rustix::fs::open(db, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()),
        rustix::io::Errno::PERM,
    );
    // No read outside the grant (Landlock).
    refused(
        "open outside the directory",
        rustix::fs::open(
            "/etc/hostname",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ),
        rustix::io::Errno::ACCESS,
    );
    let other = db.with_file_name("other.db");
    refused(
        "open of another file of the directory",
        rustix::fs::open(&other, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()),
        rustix::io::Errno::ACCESS,
    );
    // No process, no exec.
    assert!(
        Command::new("/bin/true")
            .stdin(Stdio::null())
            .status()
            .is_err(),
        "execve"
    );
    // No flock.
    refused(
        "flock",
        rustix::fs::flock(&fd, FlockOperation::LockShared),
        rustix::io::Errno::PERM,
    );
    println!("sandbox-child-ok");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(CHILD) {
        child(Path::new(&args[2]), args[3].parse().unwrap());
        return ExitCode::SUCCESS;
    }
    let required = std::env::var("DATABASTION_IT_SQLITE_REQUIRE").as_deref() == Ok("1");
    if !sandbox::landlock_available() {
        assert!(!required, "Landlock is required");
        eprintln!("skipped: Landlock is not available on this kernel");
        return ExitCode::SUCCESS;
    }
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("databastion-sqlite-sandbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db: PathBuf = dir.join("app.db");
    std::fs::write(&db, b"SQLite format 3\0").unwrap();
    std::fs::write(dir.join("other.db"), b"x").unwrap();
    // A descriptor the child inherits (no O_CLOEXEC).
    let leaked = rustix::fs::open(&db, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .arg(CHILD)
        .arg(&db)
        .arg(format!("{}", leaked.as_raw_fd()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    drop(leaked);
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() && stdout.contains("sandbox-child-ok") {
        println!("test sandbox_refusals ... ok");
        ExitCode::SUCCESS
    } else {
        eprintln!("test sandbox_refusals ... FAILED\n{stdout}\n{stderr}");
        ExitCode::FAILURE
    }
}
