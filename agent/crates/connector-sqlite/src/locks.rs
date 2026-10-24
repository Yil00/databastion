//! The reader's locks while it is idle (review L3, ADR-0059 decision 3):
//! after each response the agent reads `/proc/locks` and kills a reader
//! that holds more than an idle SQLite connection does, so a compromised
//! reader cannot hold the application's commits or checkpoints between
//! units.
//!
//! What an idle read-only connection holds (SQLite's unix VFS):
//! - rollback-journal mode: nothing (autocommit statements only);
//! - WAL mode: a `SHARED` read lock on the database file (kept while the
//!   connection is open; it does not block WAL writers) and the `DMS` read
//!   lock on the `-shm` (byte 128); never a read mark (bytes 123 to 127,
//!   which would pin checkpoints) nor a write lock (a read-only descriptor
//!   cannot take one anyway).
//!
//! Chosen over closing the reader at every pacing pause: at the default 1 %
//! duty cycle that would start a reader (exec, self-check, open procedure,
//! and on a WAL file without a writer the heap index rebuilt from the whole
//! `-wal`) for nearly every unit.
//!
//! `flock` is refused by the reader's seccomp filter.

use crate::files::Identity;

/// The `DMS` byte of the `-shm` (`UNIX_SHM_BASE + SQLITE_SHM_NLOCK`).
const SHM_DMS: u64 = 128;

/// One `/proc/locks` line: (pid, major, minor, inode, write, start, end).
type Line = (u32, u64, u64, u64, bool, u64, Option<u64>);

fn parse(line: &str) -> Option<Line> {
    if line.contains("->") {
        return None;
    }
    let f: Vec<&str> = line.split_whitespace().collect();
    let write = match *f.get(3)? {
        "READ" => false,
        "WRITE" => true,
        _ => return None,
    };
    let pid = f.get(4)?.parse().ok()?;
    let mut dev = f.get(5)?.split(':');
    let major = u64::from_str_radix(dev.next()?, 16).ok()?;
    let minor = u64::from_str_radix(dev.next()?, 16).ok()?;
    let ino = dev.next()?.parse().ok()?;
    let start = f.get(6)?.parse().ok()?;
    let end = match *f.get(7)? {
        "EOF" => None,
        e => Some(e.parse().ok()?),
    };
    Some((pid, major, minor, ino, write, start, end))
}

/// Whether the locks of process `pid` in `text` (`/proc/locks`) are those
/// of an idle connection to the database `db` (`shm_ino` 0: no `-shm`).
#[must_use]
pub fn idle_ok(text: &str, pid: u32, db: Identity, shm_ino: u64, wal: bool) -> bool {
    let (major, minor) = (rustix::fs::major(db.dev), rustix::fs::minor(db.dev));
    for line in text.lines() {
        let Some((p, maj, min, ino, write, start, end)) = parse(line) else {
            continue;
        };
        if p != pid {
            continue;
        }
        let same_dev = (u64::from(major), u64::from(minor)) == (maj, min);
        let allowed = same_dev
            && !write
            && if ino == db.ino {
                wal
            } else {
                shm_ino != 0 && ino == shm_ino && start == SHM_DMS && end == Some(SHM_DMS)
            };
        if !allowed {
            return false;
        }
    }
    true
}

/// [`idle_ok`] on this host's `/proc/locks`; `None` when it cannot be read.
#[must_use]
pub fn idle_ok_now(pid: u32, db: Identity, shm_ino: u64, wal: bool) -> Option<bool> {
    let text = std::fs::read_to_string("/proc/locks").ok()?;
    Some(idle_ok(&text, pid, db, shm_ino, wal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Identity {
        // major 8, minor 1.
        Identity {
            dev: rustix::fs::makedev(8, 1),
            ino: 5678,
        }
    }

    #[test]
    fn idle_locks_are_those_of_an_idle_connection() {
        let wal = "1: POSIX  ADVISORY  READ 42 08:01:5678 1073741826 1073742335\n\
                   2: POSIX  ADVISORY  READ 42 08:01:9999 128 128\n\
                   3: POSIX  ADVISORY  WRITE 7 08:01:5678 0 EOF\n";
        assert!(idle_ok(wal, 42, db(), 9999, true));
        // Rollback mode: no lock at all while idle.
        assert!(!idle_ok(wal, 42, db(), 9999, false));
        // A read mark on the -shm pins checkpoints.
        let mark = "1: POSIX  ADVISORY  READ 42 08:01:9999 123 123\n";
        assert!(!idle_ok(mark, 42, db(), 9999, true));
        // A lock on another file, another device, or a write lock.
        assert!(!idle_ok(
            "1: POSIX  ADVISORY  READ 42 08:01:1 0 EOF\n",
            42,
            db(),
            9999,
            true
        ));
        assert!(!idle_ok(
            "1: POSIX  ADVISORY  READ 42 08:02:5678 0 EOF\n",
            42,
            db(),
            9999,
            true
        ));
        assert!(!idle_ok(
            "1: POSIX  ADVISORY  WRITE 42 08:01:5678 0 EOF\n",
            42,
            db(),
            9999,
            true
        ));
        // Another process's locks and blocked waiters are not the reader's.
        assert!(idle_ok(
            "1: -> POSIX  ADVISORY  READ 42 08:01:5678 0 EOF\n",
            42,
            db(),
            0,
            false
        ));
        assert!(idle_ok(wal, 43, db(), 0, false));
    }
}
