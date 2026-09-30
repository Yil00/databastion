//! End-of-phase-4 review L4: the core tailer refuses an audit log owned by
//! the agent's own user, symlinks followed. Its own test binary: the other
//! tests allow such files (every file a test creates is its own).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::PathBuf;

use databastion_core::audit::tail::{Framing, TailError, Tailer, readable};

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "databastion-tail-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_log_owned_by_the_agents_user_is_refused() {
    let d = dir();
    let path = d.join("audit.log");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{{\"a\":1}}").unwrap();
    drop(f);
    // Created by this process: owned by the agent's own user.
    assert!(!readable(&path));
    let mut t = Tailer::new(path.clone(), Framing::Lines, None);
    assert!(matches!(
        t.poll(),
        Err(TailError::Unreadable(std::io::ErrorKind::PermissionDenied))
    ));
    // The same through a symlink: the target's owner counts.
    let link = d.join("link.log");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(!readable(&link));
    let mut t = Tailer::new(link, Framing::Lines, None);
    assert!(t.poll().is_err());
    std::fs::remove_dir_all(&d).unwrap();
}
