//! Incremental, bounded reading of the server log file with a persisted
//! cursor.
//!
//! - The cursor is `(device, inode, offset)` of the end of the last
//!   complete record whose events were submitted; it is saved through the
//!   core's `CursorStore` (`0600`, atomic).
//! - First start (no cursor): reading starts at the **end** of the file;
//!   history is not replayed.
//! - Restart with a cursor on the same file: reading resumes at the saved
//!   offset. A different inode at the path means the file was rotated
//!   while the agent was stopped: the new file is read from its start (the
//!   tail of the old one is lost; a warning is logged).
//! - Rotation while running (rename + new file): the open handle is read
//!   to its end first, then the new file from its start. Truncation (the
//!   file got shorter than the offset, `copytruncate` or
//!   `log_truncate_on_rotation`): reading restarts at 0.
//! - Each poll reads at most [`MAX_POLL_BYTES`]; records are bounded by the
//!   splitter. The path must be a regular file (checked before and after
//!   opening, so a FIFO or a device is never read).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use databastion_core::audit::CursorStore;
use zeroize::Zeroizing;

use super::records::{Format, Splitter};

/// Most bytes read per poll.
pub(crate) const MAX_POLL_BYTES: u64 = 8 * 1024 * 1024;
/// Read chunk.
const CHUNK: usize = 256 * 1024;
/// Bytes before the offset compared at each poll (in-place rewrite).
const TAIL_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Cursor {
    v: u32,
    dev: u64,
    ino: u64,
    offset: u64,
}

/// Why the log could not be read (kind only; never a path or content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TailError {
    /// Missing, not a regular file, or not readable by the agent.
    Unreadable(std::io::ErrorKind),
}

/// Result of one poll.
pub(crate) struct Polled {
    pub(crate) records: Vec<Zeroizing<Vec<u8>>>,
    /// More data is waiting (the poll stopped at its byte bound).
    pub(crate) more: bool,
}

pub(crate) struct Tailer {
    path: PathBuf,
    file: Option<(File, u64, u64)>,
    /// Offset read up to in the open file.
    offset: u64,
    /// The last bytes read before `offset` (in memory only): a file
    /// rewritten in place to at least the same size is detected when they
    /// change.
    tail: Zeroizing<Vec<u8>>,
    splitter: Splitter,
    store: Option<CursorStore>,
    /// Oversized records seen (skipped).
    pub(crate) oversized: u64,
    /// Rotations or truncations seen.
    pub(crate) rotations: u64,
}

fn open_regular(path: &std::path::Path) -> Result<(File, u64, u64, u64), TailError> {
    let err = |e: std::io::Error| TailError::Unreadable(e.kind());
    let meta = std::fs::metadata(path).map_err(err)?;
    if !meta.file_type().is_file() {
        return Err(TailError::Unreadable(std::io::ErrorKind::InvalidInput));
    }
    let file = File::open(path).map_err(err)?;
    let meta = file.metadata().map_err(err)?;
    if !meta.file_type().is_file() {
        return Err(TailError::Unreadable(std::io::ErrorKind::InvalidInput));
    }
    Ok((file, meta.dev(), meta.ino(), meta.len()))
}

/// Whether the configured log file can be opened and read (for `check()`).
pub(crate) fn readable(path: &std::path::Path) -> bool {
    open_regular(path).is_ok_and(|(mut f, _, _, _)| {
        let mut b = [0u8; 1];
        f.read(&mut b).is_ok()
    })
}

impl Tailer {
    pub(crate) fn new(path: PathBuf, format: Format, store: Option<CursorStore>) -> Self {
        Self {
            path,
            file: None,
            offset: 0,
            tail: Zeroizing::new(Vec::new()),
            splitter: Splitter::new(format),
            store,
            oversized: 0,
            rotations: 0,
        }
    }

    fn load_cursor(&self) -> Option<Cursor> {
        let store = self.store.as_ref()?;
        match store.load() {
            Ok(Some(bytes)) => serde_json::from_slice::<Cursor>(&bytes)
                .ok()
                .filter(|c| c.v == 1),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "audit cursor unreadable; starting at the end of the log");
                None
            }
        }
    }

    /// Opens the file on first use, positioned from the saved cursor.
    fn ensure_open(&mut self) -> Result<(), TailError> {
        if self.file.is_some() {
            return Ok(());
        }
        let (mut file, dev, ino, len) = open_regular(&self.path)?;
        let start = match self.load_cursor() {
            Some(c) if c.dev == dev && c.ino == ino && c.offset <= len => c.offset,
            Some(c) if c.dev == dev && c.ino == ino => {
                self.rotations += 1;
                tracing::warn!(
                    "audit log truncated while the agent was stopped; reading from its start"
                );
                0
            }
            Some(_) => {
                self.rotations += 1;
                tracing::warn!(
                    "audit log rotated while the agent was stopped; reading the new file from its \
                     start (the end of the previous file is not read)"
                );
                0
            }
            None => len,
        };
        file.seek(SeekFrom::Start(start))
            .map_err(|e| TailError::Unreadable(e.kind()))?;
        self.file = Some((file, dev, ino));
        self.offset = start;
        self.splitter.reset();
        Ok(())
    }

    /// Reads what was appended since the last poll (bounded).
    pub(crate) fn poll(&mut self) -> Result<Polled, TailError> {
        self.ensure_open()?;
        let mut records = Vec::new();
        let mut read_total: u64 = 0;
        let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
        loop {
            let Some((file, dev, ino)) = self.file.as_mut() else {
                break;
            };
            let (dev, ino) = (*dev, *ino);
            // Truncated (or rewritten) in place?
            let rewritten = {
                use std::os::unix::fs::FileExt as _;
                let n = self.tail.len() as u64;
                let mut now = Zeroizing::new(vec![0u8; self.tail.len()]);
                n > 0
                    && self.offset >= n
                    && (file.read_exact_at(&mut now, self.offset - n).is_err()
                        || *now != *self.tail)
            };
            if let Ok(meta) = file.metadata() {
                if meta.len() < self.offset || rewritten {
                    self.rotations += 1;
                    tracing::warn!("audit log truncated; reading from its start");
                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| TailError::Unreadable(e.kind()))?;
                    self.offset = 0;
                    self.tail.clear();
                    self.splitter.reset();
                }
            }
            let mut eof = false;
            while read_total < MAX_POLL_BYTES {
                let n = file
                    .read(&mut buf[..])
                    .map_err(|e| TailError::Unreadable(e.kind()))?;
                if n == 0 {
                    eof = true;
                    break;
                }
                self.offset += n as u64;
                read_total += n as u64;
                self.splitter.feed(&buf[..n], &mut records);
                let keep = TAIL_BYTES.min(n);
                self.tail.clear();
                self.tail.extend_from_slice(&buf[n - keep..n]);
            }
            self.oversized = self.splitter.oversized;
            if !eof {
                return Ok(Polled {
                    records,
                    more: true,
                });
            }
            // At the end of the open file: has the path moved to a new file?
            match std::fs::metadata(&self.path) {
                Ok(meta)
                    if meta.file_type().is_file() && (meta.dev(), meta.ino()) != (dev, ino) =>
                {
                    self.rotations += 1;
                    tracing::info!("audit log rotated; following the new file");
                    self.file = None;
                    match open_regular(&self.path) {
                        Ok((file, dev, ino, _)) => {
                            self.file = Some((file, dev, ino));
                            self.offset = 0;
                            self.tail.clear();
                            self.splitter.reset();
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ => break,
            }
        }
        Ok(Polled {
            records,
            more: false,
        })
    }

    /// Saves the position of the end of the last complete record read.
    pub(crate) fn commit(&self) {
        let (Some(store), Some((_, dev, ino))) = (self.store.as_ref(), self.file.as_ref()) else {
            return;
        };
        let cursor = Cursor {
            v: 1,
            dev: *dev,
            ino: *ino,
            offset: self.offset.saturating_sub(self.splitter.pending()),
        };
        match serde_json::to_vec(&cursor) {
            Ok(bytes) => {
                if let Err(e) = store.save(&bytes) {
                    tracing::warn!(error = %e, "audit cursor not saved");
                }
            }
            Err(_) => tracing::warn!("audit cursor not saved"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "databastion-tail-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn append(path: &std::path::Path, s: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    fn lines(p: Polled) -> Vec<String> {
        p.records
            .iter()
            .map(|r| String::from_utf8(r.to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn follows_appends_rotation_and_truncation() {
        let d = Dir::new("rot");
        let log = d.0.join("postgresql.json");
        append(&log, "old history\n");
        let mut t = Tailer::new(log.clone(), Format::Jsonlog, None);
        // First start: history is not replayed.
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, "a\nb\npart");
        assert_eq!(lines(t.poll().unwrap()), ["a", "b"]);
        append(&log, "ial\n");
        assert_eq!(lines(t.poll().unwrap()), ["partial"]);
        // Rotation by rename: the old file is drained, then the new one.
        append(&log, "c\n");
        std::fs::rename(&log, d.0.join("postgresql.json.1")).unwrap();
        append(&d.0.join("postgresql.json.1"), "d\n");
        append(&log, "e\n");
        assert_eq!(lines(t.poll().unwrap()), ["c", "d", "e"]);
        assert_eq!(t.rotations, 1);
        // Truncation in place.
        std::fs::write(&log, "f\n").unwrap();
        assert_eq!(lines(t.poll().unwrap()), ["f"]);
        assert_eq!(t.rotations, 2);
    }

    #[test]
    fn polls_are_bounded() {
        let d = Dir::new("bound");
        let log = d.0.join("pg.json");
        append(&log, "");
        let mut t = Tailer::new(log.clone(), Format::Jsonlog, None);
        t.poll().unwrap();
        let line = format!("{}\n", "x".repeat(1023));
        let big: String = line.repeat(9 * 1024);
        append(&log, &big);
        let p = t.poll().unwrap();
        assert!(p.more);
        assert!(p.records.len() <= 8 * 1024);
        let p2 = t.poll().unwrap();
        assert!(!p2.more);
        assert_eq!(p.records.len() + p2.records.len(), 9 * 1024);
    }

    #[test]
    fn rejects_non_regular_files() {
        let d = Dir::new("fifo");
        let mut t = Tailer::new(d.0.clone(), Format::Csvlog, None);
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert!(!readable(&d.0));
        assert!(!readable(&d.0.join("missing")));
    }
}
