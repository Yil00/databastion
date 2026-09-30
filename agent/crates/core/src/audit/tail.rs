//! Incremental, bounded reading of an audit log file with a persisted
//! cursor (engine-agnostic: the PostgreSQL server log, the MariaDB
//! `server_audit` log, the `audit_log` JSON file).
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
//! - The cursor also keeps a keyed fingerprint of the [`FP_BYTES`] bytes
//!   of the file just before its offset, and before the end of what was
//!   read when it holds a replay: HMAC-SHA256 with a sub-key of the agent
//!   key ([`TAG_KEY_PURPOSE`]), over the position and those bytes; never
//!   the bytes themselves (I2). At a restart on the same inode, the
//!   fingerprints are recomputed: a mismatch, or a file shorter than a
//!   saved position, means the file was truncated (`copytruncate`) or
//!   rewritten while the agent was stopped, even if it grew back past the
//!   offset. The cursor is then discarded: reading restarts at the start of
//!   the file, the replay is dropped, a warning is logged and the reset is
//!   counted (heartbeat metric `audit_cursor_reset_total`), rather than
//!   resuming in the middle of new content and treating new records as
//!   already reported (end-of-phase-7 review L1). A cursor saved without
//!   fingerprints (an older agent) is used as before; a new agent key
//!   (`enroll --new-hmac-key`) makes every saved fingerprint mismatch, so
//!   the current files are read again from their start once.
//! - Rotation while running (rename + new file): the open handle is read
//!   to its end first, then the new file from its start. Truncation (the
//!   file got shorter than the offset, `copytruncate` or
//!   `log_truncate_on_rotation`): reading restarts at 0.
//! - Records come with their position ([`RecordPos`]). A source that
//!   holds records back (the MySQL / MariaDB grouping of a statement's
//!   records) commits with [`Tailer::commit_from`]: the cursor is then the
//!   start of the oldest record held in the open file, with the end of what
//!   was read and the keys to replay ([`Replay`]); a restart re-reads from
//!   there and the source replays only the records of those keys
//!   ([`Tailer::take_replay`]).
//! - Each poll reads at most [`MAX_POLL_BYTES`]; records are bounded by the
//!   splitter. The path must be a regular file (checked before and after
//!   opening, so a FIFO or a device is never read).
//! - The file must **not be writable by the agent's own account**: not
//!   owned by its effective uid, not world-writable, not group-writable
//!   for one of its groups; checked on the opened handle, so after
//!   following symlinks (end-of-phase-4 review L4). An audit log is
//!   written by the database server; one the agent's account could write
//!   would not be evidence of what the server did. Such a file is refused
//!   like an unreadable one (`PermissionDenied`: `audit.log_not_readable`
//!   in `check()`).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use databastion_classifiers::masking::LocalTagKey;
use zeroize::Zeroizing;

use super::CursorStore;

/// Most bytes read per poll.
pub const MAX_POLL_BYTES: u64 = 8 * 1024 * 1024;
/// Read chunk.
const CHUNK: usize = 256 * 1024;
/// Bytes before the offset compared at each poll (in-place rewrite).
const TAIL_BYTES: usize = 32;
/// Bytes before a saved position covered by its fingerprint.
pub const FP_BYTES: u64 = 256;
/// Purpose of the sub-key of the agent key used for the cursor
/// fingerprints (`LocalTagKey`).
pub const TAG_KEY_PURPOSE: &str = "audit-tail-cursor";
/// Domain of the cursor fingerprints, under their sub-key.
const FP_DOMAIN: &[u8] = b"databastion/tail-cursor/v1\0";

/// Longest record kept, in bytes: a longer record is skipped to its end
/// and counted, never buffered.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// How records are delimited in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// One record per line (`jsonlog`, `server_audit`, `audit_log` JSON
    /// lines).
    Lines,
    /// CSV records: a newline inside a quoted field does not end the
    /// record (`csvlog`).
    Csv,
    /// Top-level JSON objects, one per line or pretty-printed over several
    /// lines, possibly inside an array (`audit_log_filter` / MySQL
    /// Enterprise JSON): a record is a balanced `{…}` (braces inside
    /// strings ignored); bytes between objects (`[`, `,`, `]`, blanks) are
    /// skipped. A line whose first non-blank byte is `{` always starts a
    /// new record, so a damaged record (unbalanced, or a string cut by a
    /// newline, which valid JSON cannot hold) is dropped instead of
    /// swallowing the records after it.
    JsonObjects,
}

/// Splits a byte stream into records (a newline ends a record; with
/// [`Framing::Csv`], only outside a quoted field). Bounded: see
/// [`MAX_RECORD_BYTES`].
pub struct Splitter {
    framing: Framing,
    csv: bool,
    buf: Zeroizing<Vec<u8>>,
    in_quotes: bool,
    skipping: bool,
    /// Bytes consumed since the end of the last complete record.
    pending: u64,
    /// Records completed by the last `feed`: (index after their last byte
    /// in the data fed, bytes since the previous record boundary).
    ends: Vec<(usize, u64)>,
    /// Records skipped for their size.
    pub oversized: u64,
    /// Records dropped as damaged ([`Framing::JsonObjects`]).
    pub malformed: u64,
    max: usize,
    /// [`Framing::JsonObjects`]: nesting depth, inside a string, after a
    /// backslash in a string, at the start of a line.
    depth: usize,
    in_string: bool,
    escaped: bool,
    line_start: bool,
}

impl Splitter {
    /// A splitter with the default record bound.
    #[must_use]
    pub fn new(framing: Framing) -> Self {
        Self::with_max(framing, MAX_RECORD_BYTES)
    }

    /// A splitter keeping records of at most `max` bytes.
    #[must_use]
    pub fn with_max(framing: Framing, max: usize) -> Self {
        Self {
            framing,
            csv: framing == Framing::Csv,
            buf: Zeroizing::new(Vec::new()),
            in_quotes: false,
            skipping: false,
            pending: 0,
            ends: Vec::new(),
            oversized: 0,
            malformed: 0,
            max,
            depth: 0,
            in_string: false,
            escaped: false,
            line_start: true,
        }
    }

    /// Bytes of an incomplete record at the end of what was fed.
    #[must_use]
    pub fn pending(&self) -> u64 {
        self.pending
    }

    /// Forgets any incomplete record (file rotated or truncated).
    pub fn reset(&mut self) {
        self.buf.clear();
        self.in_quotes = false;
        self.skipping = false;
        self.pending = 0;
        self.depth = 0;
        self.in_string = false;
        self.escaped = false;
        self.line_start = true;
    }

    /// Where the records of the last [`Self::feed`] end: (index after their
    /// last byte in the data fed, bytes since the previous record boundary,
    /// which may lie in earlier data).
    #[must_use]
    pub fn last_ends(&self) -> &[(usize, u64)] {
        &self.ends
    }

    /// Feeds bytes; complete records are appended to `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Zeroizing<Vec<u8>>>) {
        self.ends.clear();
        if self.framing == Framing::JsonObjects {
            self.feed_json(data, out);
            return;
        }
        for (i, &b) in data.iter().enumerate() {
            self.pending += 1;
            if self.csv && b == b'"' {
                self.in_quotes = !self.in_quotes;
            }
            if b == b'\n' && !self.in_quotes {
                if self.skipping {
                    self.skipping = false;
                    self.oversized += 1;
                } else if !self.buf.is_empty() {
                    let mut record = Zeroizing::new(Vec::with_capacity(self.buf.len()));
                    record.extend_from_slice(&self.buf);
                    if record.last() == Some(&b'\r') {
                        record.pop();
                    }
                    out.push(record);
                    self.ends.push((i + 1, self.pending));
                }
                self.buf.clear();
                self.pending = 0;
                continue;
            }
            if self.skipping {
                continue;
            }
            if self.buf.len() >= self.max {
                self.skipping = true;
                self.buf.clear();
                continue;
            }
            self.buf.push(b);
        }
    }
}

impl Splitter {
    fn feed_json(&mut self, data: &[u8], out: &mut Vec<Zeroizing<Vec<u8>>>) {
        for (i, &b) in data.iter().enumerate() {
            self.pending += 1;
            if b == b'\n' {
                if self.in_string {
                    // Valid JSON has no raw newline in a string.
                    self.in_string = false;
                    self.escaped = false;
                }
                self.line_start = true;
                self.keep(b);
                continue;
            }
            let blank = matches!(b, b' ' | b'\t' | b'\r');
            if self.line_start && !blank {
                self.line_start = false;
                if b == b'{' && self.depth > 0 {
                    // A new record starts: the open one is damaged.
                    self.malformed += 1;
                    self.depth = 0;
                    self.buf.clear();
                    self.skipping = false;
                }
            }
            if self.depth == 0 {
                if b == b'{' {
                    self.depth = 1;
                    self.in_string = false;
                    self.escaped = false;
                    self.skipping = false;
                    self.buf.clear();
                    self.keep(b);
                }
                continue;
            }
            self.keep(b);
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if b == b'\\' {
                    self.escaped = true;
                } else if b == b'"' {
                    self.in_string = false;
                }
                continue;
            }
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        if self.skipping {
                            self.skipping = false;
                            self.oversized += 1;
                        } else {
                            let mut record = Zeroizing::new(Vec::with_capacity(self.buf.len()));
                            record.extend_from_slice(&self.buf);
                            out.push(record);
                            self.ends.push((i + 1, self.pending));
                        }
                        self.buf.clear();
                        self.pending = 0;
                    }
                }
                _ => {}
            }
        }
    }

    /// Keeps a byte of the current JSON record, within the bound.
    fn keep(&mut self, b: u8) {
        if self.depth == 0 || self.skipping {
            return;
        }
        if self.buf.len() >= self.max {
            self.skipping = true;
            self.buf.clear();
            return;
        }
        self.buf.push(b);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Cursor {
    v: u32,
    dev: u64,
    ino: u64,
    offset: u64,
    /// Set when `offset` was moved back to records the source held
    /// ([`Tailer::commit_from`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay: Option<Replay>,
    /// Keyed fingerprint (hex) of the bytes before `offset` (see the
    /// module documentation); absent in a cursor of an older agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
    /// Keyed fingerprint (hex) of the bytes before `replay.end`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end_fp: Option<String>,
}

/// Keyed fingerprint of the (at most [`FP_BYTES`]) bytes of `file` before
/// `pos`, bound to `pos`. `None` when they cannot be read (the file is
/// shorter). Reads at most [`FP_BYTES`]; the bytes are zeroized.
fn fingerprint_at(file: &File, key: &LocalTagKey, pos: u64) -> Option<[u8; 32]> {
    use std::os::unix::fs::FileExt as _;
    let n = pos.min(FP_BYTES);
    let mut window = Zeroizing::new(vec![0u8; usize::try_from(n).ok()?]);
    file.read_exact_at(&mut window, pos - n).ok()?;
    Some(key.tag(&[FP_DOMAIN, &pos.to_be_bytes(), &window]))
}

/// [`fingerprint_at`] in hex, as saved in the cursor; empty (never
/// matching) when the bytes cannot be read.
fn fingerprint_hex(file: &File, key: &LocalTagKey, pos: u64) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    fingerprint_at(file, key, pos).map_or_else(String::new, |tag| {
        tag.iter()
            .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0x0f)]])
            .map(char::from)
            .collect()
    })
}

/// Parses a saved fingerprint; `None` unless exactly 64 hex digits.
fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let digits = s.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *o = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// What to replay after a restart from a cursor moved back
/// ([`Tailer::commit_from`]): the records up to `end` (the end of what had
/// been read) were handed over already, except those of the `keep` keys
/// at or after their offset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Replay {
    /// End of what had been read (offset in the file).
    pub end: u64,
    /// (key, start offset): the records of `key` from that offset were
    /// held by the source, not handed over.
    pub keep: Vec<(u64, u64)>,
}

/// Position of a record in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordPos {
    /// Device and inode of the file it was read from.
    pub file: (u64, u64),
    /// Offset of the end of the previous record (a boundary reading can
    /// resume from).
    pub start: u64,
    /// Offset just after the record.
    pub end: u64,
}

/// The records to replay after a restart, in the file the tailer opened
/// (see [`Replay`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFrom {
    /// Device and inode of the file.
    pub file: (u64, u64),
    /// What to replay.
    pub replay: Replay,
}

/// Why the log could not be read (kind only; never a path or content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailError {
    /// Missing, not a regular file, or not readable by the agent.
    Unreadable(std::io::ErrorKind),
}

/// Result of one poll.
pub struct Polled {
    /// Complete records read (zeroized on drop).
    pub records: Vec<Zeroizing<Vec<u8>>>,
    /// Position of each record (same order as `records`).
    pub positions: Vec<RecordPos>,
    /// More data is waiting (the poll stopped at its byte bound).
    pub more: bool,
}

/// Follows one log file (see the module documentation).
pub struct Tailer {
    path: PathBuf,
    framing: Framing,
    file: Option<(File, u64, u64)>,
    /// Offset read up to in the open file.
    offset: u64,
    /// The last bytes read before `offset` (in memory only; loaded from the
    /// file at open): a file rewritten in place to at least the same size
    /// is detected when they change.
    tail: Zeroizing<Vec<u8>>,
    splitter: Splitter,
    store: Option<CursorStore>,
    /// Replay found in the cursor at open, until taken.
    replay: Option<ReplayFrom>,
    /// Oversized records seen (skipped).
    pub oversized: u64,
    /// Rotations or truncations seen.
    pub rotations: u64,
}

/// Test support only: accept log files the agent's user could write
/// (every file a test creates is its own). Compiled only for tests and the
/// `test-support` feature (enabled from the connectors'
/// `[dev-dependencies]`), never set by the agent binary (checked by the
/// architecture tests).
#[cfg(any(test, feature = "test-support"))]
static ALLOW_OWN_FILES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test support only (see [`ALLOW_OWN_FILES`]): lets the tests of this
/// crate and of the connectors tail files they created themselves.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn allow_agent_owned_logs_for_tests() {
    ALLOW_OWN_FILES.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(any(test, feature = "test-support"))]
fn own_files_allowed() -> bool {
    ALLOW_OWN_FILES.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(any(test, feature = "test-support")))]
fn own_files_allowed() -> bool {
    false
}

/// Whether a log file is refused because the agent's own account could
/// have written it: owned by the agent's effective user, writable by
/// anyone (`S_IWOTH`), or writable by its group when that group is one of
/// the agent's (effective or supplementary).
fn writable_by_agent(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    if own_files_allowed() {
        return false;
    }
    let mode = meta.permissions().mode();
    if meta.uid() == rustix::process::geteuid().as_raw() || mode & 0o002 != 0 {
        return true;
    }
    mode & 0o020 != 0 && {
        let gid = meta.gid();
        gid == rustix::process::getegid().as_raw()
            || rustix::process::getgroups()
                .map_or(true, |groups| groups.iter().any(|g| g.as_raw() == gid))
    }
}

/// Opens the log without blocking (a FIFO or device planted at the path
/// cannot block the open: `O_NONBLOCK`, `O_NOCTTY`), then checks the
/// **handle** is a regular file (no stat-then-open race) not owned by the
/// agent's own user. Blocking I/O: call from a blocking thread.
fn open_regular(path: &std::path::Path) -> Result<(File, u64, u64, u64), TailError> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| TailError::Unreadable(std::io::Error::from(e).kind()))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| TailError::Unreadable(e.kind()))?;
    if !meta.file_type().is_file() {
        return Err(TailError::Unreadable(std::io::ErrorKind::InvalidInput));
    }
    if writable_by_agent(&meta) {
        tracing::warn!(
            "audit log refused: the agent's own user owns it or can write it (owner, a group of \
             the agent's with write access, or world-writable); it must be written and owned by \
             the database server (see the agent README, audit log files)"
        );
        return Err(TailError::Unreadable(std::io::ErrorKind::PermissionDenied));
    }
    Ok((file, meta.dev(), meta.ino(), meta.len()))
}

/// Whether the configured log file can be opened and read (for `check()`
/// and the source choice). Blocking I/O: call from a blocking thread.
#[must_use]
pub fn readable(path: &std::path::Path) -> bool {
    open_regular(path).is_ok_and(|(mut f, _, _, _)| {
        let mut b = [0u8; 1];
        f.read(&mut b).is_ok()
    })
}

impl Tailer {
    /// A tailer of the file at `path`, with the cursor kept in `store`
    /// (none: always start at the end of the file).
    #[must_use]
    pub fn new(path: PathBuf, framing: Framing, store: Option<CursorStore>) -> Self {
        Self {
            path,
            framing,
            file: None,
            offset: 0,
            tail: Zeroizing::new(Vec::new()),
            splitter: Splitter::new(framing),
            store,
            replay: None,
            oversized: 0,
            rotations: 0,
        }
    }

    /// Damaged records dropped by the splitter
    /// ([`Framing::JsonObjects`]).
    #[must_use]
    pub fn malformed(&self) -> u64 {
        self.splitter.malformed
    }

    /// Framing of the log records.
    #[must_use]
    pub fn framing(&self) -> Framing {
        self.framing
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
            Some(mut c) if c.dev == dev && c.ino == ino => {
                // A replay whose end lies before the offset is not one the
                // tailer saves: ignored, as before.
                c.replay = c.replay.filter(|r| r.end >= c.offset);
                if self.cursor_intact(&file, len, &c) {
                    self.replay = c.replay.map(|replay| ReplayFrom {
                        file: (dev, ino),
                        replay,
                    });
                    c.offset
                } else {
                    self.rotations += 1;
                    super::count_cursor_reset();
                    tracing::warn!(
                        "audit log truncated or rewritten while the agent was stopped; the saved \
                         position is discarded and the file is read from its start"
                    );
                    0
                }
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
        // The bytes before the start, for the in-place rewrite check of the
        // next polls (in memory only).
        self.tail.clear();
        if start > 0 {
            use std::os::unix::fs::FileExt as _;
            let n = start.min(TAIL_BYTES as u64);
            self.tail.resize(usize::try_from(n).unwrap_or(0), 0);
            if file.read_exact_at(&mut self.tail, start - n).is_err() {
                self.tail.clear();
            }
        }
        self.file = Some((file, dev, ino));
        self.offset = start;
        self.splitter.reset();
        Ok(())
    }

    /// Whether the saved cursor `c` of the open file (same inode, length
    /// `len`) still points at what was read: its positions are within the
    /// file and, when the cursor has fingerprints and the agent key is
    /// available, the bytes before them match. A cursor without
    /// fingerprints (older agent) or without a key (tests) is checked on
    /// its positions only. Reads at most `2 * FP_BYTES`.
    fn cursor_intact(&self, file: &File, len: u64, c: &Cursor) -> bool {
        let end = c.replay.as_ref().map(|r| r.end);
        if c.offset > len || end.is_some_and(|e| e > len) {
            return false;
        }
        let Some(key) = self.store.as_ref().and_then(CursorStore::tag_key) else {
            return true;
        };
        if c.fp.is_none() && c.end_fp.is_none() {
            return true;
        }
        let matches = |pos: u64, saved: Option<&String>| {
            saved
                .and_then(|s| parse_fingerprint(s))
                .zip(fingerprint_at(file, key, pos))
                .is_some_and(|(saved, now)| saved == now)
        };
        matches(c.offset, c.fp.as_ref()) && end.is_none_or(|e| matches(e, c.end_fp.as_ref()))
    }

    /// Reads what was appended since the last poll (bounded). Blocking
    /// I/O: call from a blocking thread.
    ///
    /// # Errors
    /// [`TailError`] when the file is missing, not a regular file or not
    /// readable.
    pub fn poll(&mut self) -> Result<Polled, TailError> {
        self.ensure_open()?;
        let mut records = Vec::new();
        let mut positions = Vec::new();
        let mut read_total: u64 = 0;
        let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
        while let Some((file, dev, ino)) = self.file.as_mut() {
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
                let base = self.offset;
                self.offset += n as u64;
                read_total += n as u64;
                self.splitter.feed(&buf[..n], &mut records);
                for &(i, len) in self.splitter.last_ends() {
                    let end = base + i as u64;
                    positions.push(RecordPos {
                        file: (dev, ino),
                        start: end.saturating_sub(len),
                        end,
                    });
                }
                let keep = TAIL_BYTES.min(n);
                self.tail.clear();
                self.tail.extend_from_slice(&buf[n - keep..n]);
            }
            self.oversized = self.splitter.oversized;
            if !eof {
                return Ok(Polled {
                    records,
                    positions,
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
            positions,
            more: false,
        })
    }

    /// The replay found in the saved cursor when the file was opened
    /// (once).
    pub fn take_replay(&mut self) -> Option<ReplayFrom> {
        self.replay.take()
    }

    /// Saves a cursor that holds nothing back: [`Self::commit`] when the
    /// file is open, otherwise the saved cursor without its replay (moved
    /// to the end read before). For a source that reported what it held
    /// (its stream ends) so that a later stream does not replay it.
    pub fn settle(&self) {
        if self.file.is_some() {
            self.commit();
            return;
        }
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if let Some(mut c) = self.load_cursor() {
            if let Some(r) = c.replay.take() {
                c.offset = r.end;
                // The fingerprint of the end becomes that of the offset
                // (an empty one, never matching, if it was missing).
                let end_fp = c.end_fp.take();
                if c.fp.is_some() || end_fp.is_some() {
                    c.fp = Some(end_fp.unwrap_or_default());
                }
                match serde_json::to_vec(&c) {
                    Ok(bytes) => {
                        if let Err(e) = store.save(&bytes) {
                            tracing::warn!(error = %e, "audit cursor not saved");
                        }
                    }
                    Err(_) => tracing::warn!("audit cursor not saved"),
                }
            }
        }
    }

    /// Saves the position of the end of the last complete record read.
    pub fn commit(&self) {
        self.commit_from(&[]);
    }

    /// Saves the position like [`Self::commit`], moved back to the start of
    /// the oldest record the source still holds in the open file: `held`
    /// lists (key, position of the first held record of that key). Held
    /// records of an earlier (rotated) file cannot be re-read after a
    /// restart and are left out. A restart then resumes at that start and
    /// [`Self::take_replay`] tells which records up to the end read so far
    /// are to be replayed.
    pub fn commit_from(&self, held: &[(u64, RecordPos)]) {
        let (Some(store), Some((file, dev, ino))) = (self.store.as_ref(), self.file.as_ref())
        else {
            return;
        };
        let end = self.offset.saturating_sub(self.splitter.pending());
        let here: Vec<(u64, u64)> = held
            .iter()
            .filter(|(_, p)| p.file == (*dev, *ino) && p.start < end)
            .map(|(k, p)| (*k, p.start))
            .collect();
        let from = here.iter().map(|(_, s)| *s).min();
        let offset = from.unwrap_or(end);
        let key = store.tag_key();
        let cursor = Cursor {
            v: 1,
            dev: *dev,
            ino: *ino,
            offset,
            replay: from.map(|_| Replay { end, keep: here }),
            fp: key.map(|k| fingerprint_hex(file, k, offset)),
            end_fp: key
                .filter(|_| from.is_some())
                .map(|k| fingerprint_hex(file, k, end)),
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::io::Write as _;

    use super::*;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            // The files of these tests are the test's own.
            allow_agent_owned_logs_for_tests();
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

    fn lines_of(p: &Polled) -> Vec<String> {
        p.records
            .iter()
            .map(|r| String::from_utf8(r.to_vec()).unwrap())
            .collect()
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
        let mut t = Tailer::new(log.clone(), Framing::Lines, None);
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
    fn positions_and_a_cursor_moved_back_to_held_records() {
        let d = Dir::new("held");
        let log = d.0.join("server_audit.log");
        append(&log, "");
        let store = || CursorStore::new(&d.0, "t", "server_audit");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        t.commit();
        append(&log, "a1\nb1\na2\n");
        let p = t.poll().unwrap();
        assert_eq!(lines_of(&p), ["a1", "b1", "a2"]);
        let pos = p.positions.clone();
        assert_eq!(
            pos.iter().map(|p| (p.start, p.end)).collect::<Vec<_>>(),
            [(0, 3), (3, 6), (6, 9)]
        );
        // The source still holds `a1` (key 7); `b1` was handed over.
        t.commit_from(&[(7, pos[0])]);
        drop(t);
        // Restart: reading resumes at `a1`, with the replay to apply.
        append(&log, "a3\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        let p = t.poll().unwrap();
        assert_eq!(lines_of(&p), ["a1", "b1", "a2", "a3"]);
        let r = t.take_replay().unwrap();
        assert_eq!(
            r.replay,
            Replay {
                end: 9,
                keep: vec![(7, 0)]
            }
        );
        assert_eq!(r.file, pos[0].file);
        assert!(t.take_replay().is_none());
        // Held again, then settled without the file open: the replay is
        // dropped, the cursor at the end read.
        t.commit_from(&[(7, p.positions[0])]);
        drop(t);
        let t = Tailer::new(log.clone(), Framing::Lines, store());
        t.settle();
        drop(t);
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        assert!(t.take_replay().is_none());
        // Nothing held: a plain cursor.
        t.commit_from(&[]);
        drop(t);
        let mut t = Tailer::new(log, Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        assert!(t.take_replay().is_none());
    }

    fn tag_key(seed: u8) -> std::sync::Arc<LocalTagKey> {
        let key = databastion_classifiers::masking::HmacKey::new(&[seed; 32]).unwrap();
        std::sync::Arc::new(key.local_tag_key(TAG_KEY_PURPOSE).unwrap())
    }

    /// `copytruncate`: the same inode, emptied in place, then written.
    fn copytruncate(path: &std::path::Path, s: &str) {
        let ino = std::fs::metadata(path).unwrap().ino();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
        drop(f);
        assert_eq!(std::fs::metadata(path).unwrap().ino(), ino);
    }

    fn saved(store: &CursorStore) -> Cursor {
        serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap()
    }

    #[test]
    fn copytruncate_and_regrowth_while_stopped_resets_the_cursor() {
        let d = Dir::new("fp-trunc");
        let log = d.0.join("server_audit.log");
        append(&log, "history\n");
        let key = tag_key(1);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        append(&log, "a1\nb1\nc1\n");
        let p = t.poll().unwrap();
        assert_eq!(lines_of(&p), ["a1", "b1", "c1"]);
        // `a1` is held: the cursor goes back to it, with a replay up to
        // the end read; both positions are fingerprinted.
        t.commit_from(&[(7, p.positions[0])]);
        let c = saved(&store().unwrap());
        assert_eq!(c.offset, 8);
        assert_eq!(c.replay.as_ref().map(|r| r.end), Some(17));
        assert_eq!(c.fp.as_deref().map(str::len), Some(64));
        assert_eq!(c.end_fp.as_deref().map(str::len), Some(64));
        // The raw bytes are not in the cursor.
        let raw = String::from_utf8(store().unwrap().load().unwrap().unwrap()).unwrap();
        assert!(!raw.contains("a1") && !raw.contains("history"));
        drop(t);
        // Stopped: the log is copytruncated and grows back past both
        // saved positions.
        copytruncate(&log, "n1 xxxxxxxx\nn2 xxxxxxxx\nn3\n");
        let resets = crate::audit::cursor_resets();
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        let p = t.poll().unwrap();
        // Nothing is skipped: the whole new content, and no replay.
        assert_eq!(lines_of(&p), ["n1 xxxxxxxx", "n2 xxxxxxxx", "n3"]);
        assert!(t.take_replay().is_none());
        assert_eq!(t.rotations, 1);
        assert!(crate::audit::cursor_resets() > resets);
        // Without a replay: a plain cursor at the end, then the same.
        t.commit();
        let c = saved(&store().unwrap());
        assert!(c.replay.is_none() && c.end_fp.is_none() && c.fp.is_some());
        drop(t);
        copytruncate(&log, "m1 yyyyyyyyyyyyyyyyyyyyyy\nm2\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(
            lines(t.poll().unwrap()),
            ["m1 yyyyyyyyyyyyyyyyyyyyyy", "m2"]
        );
        assert_eq!(t.rotations, 1);
        // A file shorter than the end read (the offset still within it)
        // is a truncation too.
        t.commit_from(&[]);
        append(&log, "q1\nq2\n");
        let p = t.poll().unwrap();
        t.commit_from(&[(1, p.positions[0])]);
        drop(t);
        copytruncate(&log, "r1 zzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n");
        let mut t = Tailer::new(log, Framing::Lines, store());
        assert_eq!(
            lines(t.poll().unwrap()),
            ["r1 zzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]
        );
        assert!(t.take_replay().is_none());
    }

    #[test]
    fn a_fingerprinted_cursor_is_kept_across_a_normal_restart() {
        let d = Dir::new("fp-keep");
        let log = d.0.join("server_audit.log");
        append(&log, &"h".repeat(1000));
        append(&log, "\n");
        let key = tag_key(2);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        append(&log, "a1\nb1\n");
        let p = t.poll().unwrap();
        t.commit_from(&[(7, p.positions[0])]);
        drop(t);
        append(&log, "c1\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["a1", "b1", "c1"]);
        let r = t.take_replay().unwrap();
        assert_eq!(r.replay.end, 1007);
        assert_eq!(t.rotations, 0);
        // Settled without the file open: the end's fingerprint becomes
        // the offset's, and the restart keeps it.
        t.commit_from(&[(7, p.positions[0])]);
        drop(t);
        let t = Tailer::new(log.clone(), Framing::Lines, store());
        t.settle();
        drop(t);
        let c = saved(&store().unwrap());
        assert!(c.replay.is_none() && c.end_fp.is_none());
        assert_eq!(c.offset, 1010);
        append(&log, "d1\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["d1"]);
        assert_eq!(t.rotations, 0);
        // At the end, nothing new: the rewrite check of the poll works
        // from the first poll after a restart.
        t.commit();
        drop(t);
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        copytruncate(&log, &format!("{}\ne1\n", "k".repeat(1020)));
        assert_eq!(
            lines(t.poll().unwrap()),
            ["k".repeat(1020), "e1".to_owned()]
        );
        assert_eq!(t.rotations, 1);
    }

    #[test]
    fn a_cursor_without_fingerprints_keeps_the_previous_behaviour() {
        let d = Dir::new("fp-old");
        let log = d.0.join("server_audit.log");
        append(&log, "a1\nb1\n");
        let meta = std::fs::metadata(&log).unwrap();
        let key = tag_key(3);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        // A cursor saved by an older agent (no `fp`, `end_fp`).
        let old = format!(
            "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":3,\"replay\":{{\"end\":6,\"keep\":[[7,0]]}}}}",
            meta.dev(),
            meta.ino()
        );
        store().unwrap().save(old.as_bytes()).unwrap();
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["b1"]);
        assert_eq!(t.take_replay().unwrap().replay.end, 6);
        assert_eq!(t.rotations, 0);
        // Its next save has fingerprints.
        t.commit();
        assert!(saved(&store().unwrap()).fp.is_some());
        drop(t);
        // Without the key (no fingerprint check possible), a fingerprinted
        // cursor is checked on its positions only.
        let mut t = Tailer::new(
            log.clone(),
            Framing::Lines,
            CursorStore::new(&d.0, "t", "server_audit"),
        );
        assert!(t.poll().unwrap().records.is_empty());
        assert_eq!(t.rotations, 0);
    }

    #[test]
    fn a_tampered_or_crafted_cursor_resets_without_panicking() {
        let d = Dir::new("fp-tamper");
        let log = d.0.join("server_audit.log");
        append(&log, "a1\nb1\n");
        let meta = std::fs::metadata(&log).unwrap();
        let key = tag_key(4);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        t.commit();
        drop(t);
        let good = saved(&store().unwrap());
        let fp = good.fp.clone().unwrap();
        let flipped = format!(
            "{}{}",
            if fp.starts_with('0') { '1' } else { '0' },
            &fp[1..]
        );
        let bad_fps = [
            Some(flipped),
            Some("zz".repeat(32)),
            Some(String::new()),
            Some("é".repeat(40)),
            Some("0".repeat(64 * 1000)),
        ];
        for bad in bad_fps {
            let mut c = good.clone();
            c.fp = bad;
            store()
                .unwrap()
                .save(&serde_json::to_vec(&c).unwrap())
                .unwrap();
            let mut t = Tailer::new(log.clone(), Framing::Lines, store());
            assert_eq!(lines(t.poll().unwrap()), ["a1", "b1"]);
            assert_eq!(t.rotations, 1);
        }
        // Another agent key: every fingerprint mismatches.
        let mut c = good.clone();
        c.fp = good.fp.clone();
        store()
            .unwrap()
            .save(&serde_json::to_vec(&c).unwrap())
            .unwrap();
        let other = tag_key(5);
        let mut t = Tailer::new(
            log.clone(),
            Framing::Lines,
            CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(other)),
        );
        assert_eq!(lines(t.poll().unwrap()), ["a1", "b1"]);
        // A replay without its end fingerprint, and crafted positions.
        let crafted = [
            format!(
                "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":6,\"fp\":\"{fp}\",\"replay\":{{\"end\":6,\"keep\":[]}}}}",
                meta.dev(),
                meta.ino()
            ),
            format!(
                "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":{},\"fp\":\"{fp}\",\"replay\":{{\"end\":{},\"keep\":[[1,{}]]}},\"end_fp\":\"{fp}\"}}",
                meta.dev(),
                meta.ino(),
                u64::MAX,
                u64::MAX,
                u64::MAX
            ),
            format!(
                "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":0,\"fp\":\"{fp}\",\"replay\":{{\"end\":{},\"keep\":[]}},\"end_fp\":\"{fp}\"}}",
                meta.dev(),
                meta.ino(),
                u64::MAX
            ),
        ];
        for c in crafted {
            store().unwrap().save(c.as_bytes()).unwrap();
            let mut t = Tailer::new(log.clone(), Framing::Lines, store());
            assert_eq!(lines(t.poll().unwrap()), ["a1", "b1"]);
            assert!(t.take_replay().is_none());
            assert_eq!(t.rotations, 1);
        }
    }

    #[test]
    fn fingerprints_parse_strictly() {
        assert!(parse_fingerprint(&"0".repeat(63)).is_none());
        assert!(parse_fingerprint(&"A".repeat(64)).is_none());
        assert!(parse_fingerprint(&"g".repeat(64)).is_none());
        assert_eq!(parse_fingerprint(&"f".repeat(64)), Some([0xff; 32]));
        // Fingerprints are bound to their position.
        let d = Dir::new("fp-pos");
        let log = d.0.join("x.log");
        append(&log, "aaaa");
        let f = File::open(&log).unwrap();
        let k = tag_key(6);
        assert_ne!(fingerprint_at(&f, &k, 2), fingerprint_at(&f, &k, 3));
        assert!(fingerprint_at(&f, &k, 5).is_none());
        assert_eq!(fingerprint_hex(&f, &k, 5), "");
        assert!(parse_fingerprint(&fingerprint_hex(&f, &k, 4)).is_some());
    }

    #[test]
    fn json_positions_span_chunks() {
        let mut s = Splitter::new(Framing::JsonObjects);
        let mut out = Vec::new();
        s.feed(b"[{\"a\":", &mut out);
        assert!(s.last_ends().is_empty());
        s.feed(b"1},\n{\"b\":2}", &mut out);
        assert_eq!(out.len(), 2);
        // Ends in the second feed; the first record's bytes began 6 bytes
        // before it (a boundary: the start of the data).
        assert_eq!(s.last_ends(), [(2, 8), (11, 9)]);
    }

    #[test]
    fn polls_are_bounded() {
        let d = Dir::new("bound");
        let log = d.0.join("pg.json");
        append(&log, "");
        let mut t = Tailer::new(log.clone(), Framing::Lines, None);
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
    fn a_fifo_never_blocks() {
        let d = Dir::new("fifo2");
        let fifo = d.0.join("pg.json");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !status.is_ok_and(|s| s.success()) {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send((
                readable(&path),
                Tailer::new(path, Framing::Lines, None).poll().is_err(),
            ));
        });
        let (ok, err) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("opening a FIFO blocked");
        assert!(!ok && err);
    }

    #[test]
    fn rejects_non_regular_files() {
        let d = Dir::new("fifo");
        let mut t = Tailer::new(d.0.clone(), Framing::Csv, None);
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert!(!readable(&d.0));
        assert!(!readable(&d.0.join("missing")));
    }

    #[test]
    fn csv_records_span_quoted_newlines() {
        let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
        let mut out = Vec::new();
        s.feed(b"a,\"b\nc\"\nd\npartial,\"open", &mut out);
        let got: Vec<Vec<u8>> = out.iter().map(|r| r.to_vec()).collect();
        assert_eq!(got, [b"a,\"b\nc\"".to_vec(), b"d".to_vec()]);
        assert_eq!(s.pending(), "partial,\"open".len() as u64);
    }

    #[test]
    fn huge_records_are_skipped_not_buffered() {
        let mut data = vec![b'x'; 5000];
        data.push(b'\n');
        data.extend_from_slice(b"{\"ok\":1}\n");
        let mut s = Splitter::with_max(Framing::Lines, 4096);
        let mut out = Vec::new();
        s.feed(&data, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(s.oversized, 1);
        assert_eq!(s.pending(), 0);
        // A huge unterminated record keeps at most `max` bytes.
        let mut s = Splitter::with_max(Framing::Lines, 16);
        let mut out = Vec::new();
        s.feed(&[b'y'; 100_000], &mut out);
        assert!(out.is_empty());
        assert!(s.buf.len() <= 16);
        assert_eq!(s.pending(), 100_000);
    }

    #[test]
    fn json_objects_are_framed_in_both_layouts() {
        let lines = b"{\"audit_record\":{\"name\":\"Query\",\"sqltext\":\"select '}' \\\" {\"}}\n{\"a\":1}\n{\"par";
        let mut s = Splitter::new(Framing::JsonObjects);
        let mut out = Vec::new();
        s.feed(lines, &mut out);
        assert_eq!(out.len(), 2);
        let first: serde_json::Value = serde_json::from_slice(&out[0]).unwrap();
        assert_eq!(first["audit_record"]["sqltext"], "select '}' \" {");
        assert_eq!(s.pending(), 6);
        // Pretty-printed array, cut in the middle of the second record.
        let pretty = b"[\n  {\n    \"id\": 1,\n    \"account\": { \"user\": \"root\" }\n  },\n  {\n    \"id\": 2,";
        let mut s = Splitter::new(Framing::JsonObjects);
        let mut out = Vec::new();
        s.feed(pretty, &mut out);
        assert_eq!(out.len(), 1);
        let v: serde_json::Value = serde_json::from_slice(&out[0]).unwrap();
        assert_eq!(v["account"]["user"], "root");
        s.feed(b"\n    \"x\": \"}\"\n  }\n]", &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(s.pending(), 2);
        // A damaged record (unterminated string, then a new record line)
        // is dropped; the next one is kept.
        let mut s = Splitter::new(Framing::JsonObjects);
        let mut out = Vec::new();
        s.feed(b"{\"a\": \"cut\n{\"b\": 2}\n", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(s.malformed, 1);
        assert_eq!(&out[0][..], b"{\"b\": 2}");
        // Oversized records are skipped whole.
        let mut s = Splitter::with_max(Framing::JsonObjects, 8);
        let mut out = Vec::new();
        s.feed(b"{\"long\": \"0123456789\"}{\"k\":1}", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(s.oversized, 1);
    }
}
