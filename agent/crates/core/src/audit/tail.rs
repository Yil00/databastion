//! Incremental, bounded reading of an audit log file with a persisted
//! cursor (engine-agnostic: the PostgreSQL server log, the MariaDB
//! `server_audit` log, the `audit_log` JSON file).
//!
//! - The cursor is `(device, inode, offset)` of the end of the last
//!   complete record whose events were submitted; it is saved through the
//!   core's `CursorStore` (`0600`, atomic).
//! - First start (no cursor): reading starts at the **end** of the file;
//!   history is not replayed. That end may lie inside a record the server
//!   is still writing (PostgreSQL writes a csvlog record of more than
//!   4 KiB in several `write`s): a record begun before it is dropped, and
//!   with CSV framing the quote state is unknown until a quote settles it
//!   ([`Splitter::reset_unaligned`]); a start inside a quoted field taken
//!   as "outside" would leave the state inverted for good, with no record
//!   ever complete again. A cursor saved before a record ends where the
//!   state is known ([`Splitter::aligned`]) says so (`unaligned`): a
//!   restart resumes at its position unaligned, as at the first start
//!   (#267 review L1, security review of #278 L1).
//! - CSV quote state: every quote is checked against the CSV quoting
//!   rules under the current and the inverted state; a state that only the
//!   inverted one explains is corrected and the record in progress dropped
//!   (counted in [`Tailer::malformed`] when the state was known before: a
//!   damaged record). When the quote that tells it is the first one after
//!   the last newline taken as quoted, that newline ended the damaged
//!   record: only the damaged record is dropped, and the record after it
//!   is kept (#267 review L2).
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
//!   fingerprints (an older agent) is used as before (positions checked
//!   only).
//! - The cursor names the sub-key its fingerprints were made with (`kid`:
//!   a tag of a fixed label, which reveals nothing about the key). After a
//!   new agent key (`enroll --new-hmac-key`), a cursor of another (or no)
//!   `kid` cannot be checked: it gets the positions-only check of an older
//!   agent's cursor, and is fingerprinted again at the next save, instead
//!   of re-reading every log from its start (duplicate events, false volume
//!   incidents). Only a mismatch under the same `kid` resets it.
//! - Fingerprints are computed when the cursor is saved, possibly long
//!   after the read (the events are handed over first, under
//!   backpressure). The last bytes read (in memory) are compared with the
//!   file first; when they differ (the file was truncated or rewritten
//!   since the read), the fingerprints are saved empty, which never match:
//!   the next start reads the file from its start rather than trusting a
//!   fingerprint of new content (security review of #97, L-a).
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
//!   for one of its groups; checked on the opened handle (end-of-phase-4
//!   review L4). An audit log is written by the database server; one the
//!   agent's account could write would not be evidence of what the server
//!   did. Such a file is refused like an unreadable one
//!   (`PermissionDenied`: `audit.log_not_readable` in `check()`).
//! - The file must have **one hard link** (`st_nlink` = 1, on the handle,
//!   at every open and reopen): a hard link put at the path could be any
//!   other file the agent can read (security review of #140 L1).
//! - The path is opened with `O_NOFOLLOW` (security review of #138 L2): a
//!   symlink as its last component is refused (directories above it are
//!   still resolved), at the first open and at every reopen after a
//!   rotation, so a symlink swapped in at rotation time cannot redirect the
//!   tailer to another file. A source can add its own checks of every
//!   opened file ([`Tailer::with_open_check`]), run on the opened handle
//!   after each (re)open; a file they refuse is not read.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use databastion_classifiers::masking::LocalTagKey;
use zeroize::Zeroizing;

use super::CursorStore;

/// Oracles of the CSV splitter for the property test and the fuzz target
/// (`agent/fuzz`); `fuzzing` feature (and tests) only.
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz;

/// Whether `seg` is the start of a csvlog record up to its first quote: a
/// log time (`YYYY-MM-DD HH:MM:SS[.f…] ZONE`), one comma, the quote
/// (security review of #278, M1). Bytes only, nothing logged.
fn csv_record_start(seg: &[u8]) -> bool {
    let Some(time) = seg.strip_suffix(b",\"") else {
        return false;
    };
    // Date and time of day: fixed positions.
    if time.len() < 21 {
        return false;
    }
    let (fixed, rest) = time.split_at(19);
    let shape_ok = fixed.iter().enumerate().all(|(i, &b)| match i {
        4 | 7 => b == b'-',
        10 => b == b' ',
        13 | 16 => b == b':',
        _ => b.is_ascii_digit(),
    });
    if !shape_ok {
        return false;
    }
    // Optional fraction, then one space and the zone.
    let rest = match rest.strip_prefix(b".") {
        Some(r) => {
            let n = r.iter().take_while(|b| b.is_ascii_digit()).count();
            if !(1..=9).contains(&n) {
                return false;
            }
            &r[n..]
        }
        None => rest,
    };
    let Some(zone) = rest.strip_prefix(b" ") else {
        return false;
    };
    (1..=16).contains(&zone.len())
        && zone
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b':'))
}

/// Most bytes read per poll.
pub const MAX_POLL_BYTES: u64 = 8 * 1024 * 1024;
/// With [`Framing::LinesKeepingEmpty`], a poll also stops after the chunk
/// that brings it to this many records: an empty line is a record there,
/// so [`MAX_POLL_BYTES`] alone would let a poll hold millions of them.
pub const MAX_POLL_RECORDS_KEEPING_EMPTY: usize = 64 * 1024;
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
    /// lines). An empty line gives no record.
    Lines,
    /// One record per line, as [`Framing::Lines`] (same bound, same `\r`
    /// handling, same positions and alignment), except that an empty line
    /// is a record too (an empty one): the Firebird trace log, whose
    /// records end with empty lines that its grammar requires.
    LinesKeepingEmpty,
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
    /// Records dropped as damaged ([`Framing::JsonObjects`]; with
    /// [`Framing::Csv`], a record whose quotes were found inconsistent).
    pub malformed: u64,
    max: usize,
    /// [`Framing::JsonObjects`]: nesting depth, inside a string, after a
    /// backslash in a string, at the start of a line.
    depth: usize,
    in_string: bool,
    escaped: bool,
    line_start: bool,
    /// [`Framing::Csv`]: whether `in_quotes` is known to be right. False
    /// after [`Self::reset_unaligned`] (reading starts at an offset that
    /// may lie inside a quoted field) until a quote settles it.
    parity_known: bool,
    /// [`Framing::Csv`]: the byte before the current one (`None`: start of
    /// the data, or unknown).
    prev: Option<u8>,
    /// [`Framing::Csv`]: the last byte was a quote whose check needs the
    /// next byte: (it opened a field under `in_quotes`, the byte before it
    /// allows an opening quote).
    quote: Option<(bool, bool)>,
    /// [`Framing::Csv`]: the length of `buf` after its last newline, taken
    /// as inside a quoted field. If the state turns out inverted, that
    /// newline ended a record and the record in progress starts after it:
    /// while the state is not settled (a start inside a record), and when
    /// a known state is found inverted (a damaged record before that
    /// newline) provided the quote that tells it is the first one after
    /// the newline ([`Self::cut_quotes`]).
    cut: Option<usize>,
    /// [`Framing::Csv`]: quotes met since [`Self::cut`] was set.
    cut_quotes: u32,
    /// Whether the last record boundary taken (the offset
    /// [`Self::pending`] bytes back) is known to be a real one.
    /// False after [`Self::reset_unaligned`] until a record ends where the
    /// quote state is settled (CSV) or the first newline ([`Framing::Lines`]
    /// not after a newline): a cursor saved there would lose the unaligned
    /// state at a restart (#267 review L1), so [`Tailer::commit_from`] saves
    /// it with the cursor.
    aligned: bool,
    /// The record in progress is dropped at its end (see [`Discard`]).
    discard: Discard,
    /// [`Framing::Csv`]: times the quote state was found inverted and
    /// corrected.
    pub realigned: u64,
}

/// Why the record in progress is dropped at its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discard {
    /// Kept.
    No,
    /// It started before the offset reading started from: dropped
    /// silently (history is not replayed).
    Unaligned,
    /// Its quotes were inconsistent (a damaged record): dropped and
    /// counted in [`Splitter::malformed`].
    Damaged,
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
            parity_known: true,
            prev: None,
            quote: None,
            cut: None,
            cut_quotes: 0,
            aligned: true,
            discard: Discard::No,
            realigned: 0,
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
        self.parity_known = true;
        self.prev = None;
        self.quote = None;
        self.cut = None;
        self.cut_quotes = 0;
        self.aligned = true;
        self.discard = Discard::No;
    }

    /// Whether the start of the record in progress (the offset
    /// [`Self::pending`] bytes before the end of what was fed) is known to
    /// be a record boundary: false from [`Self::reset_unaligned`] until the
    /// first record ends where it is known (see [`Self::aligned`]).
    #[must_use]
    pub fn aligned(&self) -> bool {
        self.aligned
    }

    /// Forgets any incomplete record before reading from an offset that
    /// is not known to be a record boundary (first start at the end of a
    /// file the server is writing: a record can be half written, a
    /// PostgreSQL csvlog record of more than 4 KiB is written in several
    /// `write`s). `after_newline`: the byte before the offset is a
    /// newline.
    ///
    /// - [`Framing::Lines`] and [`Framing::LinesKeepingEmpty`]: the first
    ///   record is dropped unless the offset follows a newline.
    /// - [`Framing::Csv`]: the offset may lie inside a quoted field, where
    ///   a newline does not end a record; a quote state taken as "outside"
    ///   there would stay inverted for every later record (each record has
    ///   an even number of quotes): no record would ever be complete
    ///   again. Records are dropped until a quote settles the state (see
    ///   [`Self::feed`]); the first one also unless the offset follows a
    ///   newline.
    /// - [`Framing::JsonObjects`]: records start at a `{` outside any
    ///   object; nothing more is needed.
    pub fn reset_unaligned(&mut self, after_newline: bool) {
        self.reset();
        match self.framing {
            Framing::Lines | Framing::LinesKeepingEmpty | Framing::Csv => {
                self.parity_known = !self.csv;
                self.aligned = after_newline && !self.csv;
                if !after_newline {
                    self.discard = Discard::Unaligned;
                }
            }
            Framing::JsonObjects => {}
        }
    }

    /// [`Framing::Csv`]: checks the quote before `b` and notes a quote at
    /// `b`. In a well-formed CSV record, an opening quote follows a comma,
    /// a newline (record start) or a quote (`""` inside a field), and a
    /// closing quote is followed by a comma, a newline, a carriage return
    /// or a quote (`""`). Each quote is checked under the current state
    /// and under the inverted one: when only the inverted state is
    /// consistent, the state is inverted and the record in progress
    /// (begun at a false boundary) dropped; when only the current one is,
    /// it is known to be right. PostgreSQL quotes every non-empty text
    /// field (the message is never empty), so the state is settled within
    /// a record.
    fn csv_byte(&mut self, b: u8) {
        if let Some((opened, prev_ok)) = self.quote.take() {
            let next_ok = matches!(b, b'"' | b',' | b'\n' | b'\r');
            let (ours, inverted) = if opened {
                (prev_ok, next_ok)
            } else {
                (next_ok, prev_ok)
            };
            if !ours && inverted {
                self.in_quotes = !self.in_quotes;
                self.realigned += 1;
                let cut = self.cut.take();
                self.discard = if self.parity_known {
                    // A known state found inverted: the record in progress
                    // is damaged (cut short inside a quoted field). That
                    // newline ended the damaged record (#267 review L2)
                    // only if what follows it up to the quote that tells
                    // the inversion is the start of a csvlog record: a log
                    // time, one comma, that quote. Then the damaged record
                    // is dropped and counted now, and the record after it
                    // kept. Otherwise (a quoted newline of the statement,
                    // the write cut later: security review of #278, M1)
                    // the whole record in progress is dropped at its end.
                    let starts_record = |k: &usize| {
                        self.cut_quotes == 1 && self.buf.get(*k..).is_some_and(csv_record_start)
                    };
                    match cut.filter(starts_record) {
                        Some(k) => {
                            self.drop_before(k);
                            if self.discard != Discard::Unaligned {
                                self.malformed += 1;
                            }
                            Discard::No
                        }
                        None if self.discard == Discard::Unaligned => Discard::Unaligned,
                        None => Discard::Damaged,
                    }
                } else if let Some(k) = cut {
                    // The last newline taken as quoted ended a record: the
                    // record in progress starts after it, at a boundary
                    // now known.
                    self.drop_before(k);
                    self.aligned = true;
                    Discard::No
                } else {
                    Discard::Unaligned
                };
                self.parity_known = true;
                self.cut = None;
            } else if ours && !inverted {
                self.parity_known = true;
                self.cut = None;
            }
        }
        if b == b'"' {
            self.cut_quotes = self.cut_quotes.saturating_add(1);
            let prev_ok = self.prev.is_none_or(|p| matches!(p, b',' | b'\n' | b'"'));
            self.quote = Some((!self.in_quotes, prev_ok));
            self.in_quotes = !self.in_quotes;
        }
        self.prev = Some(b);
    }

    /// Drops the first `k` bytes of the record in progress, which then
    /// starts after them (the byte being fed is counted in `pending`, not
    /// yet in `buf`).
    fn drop_before(&mut self, k: usize) {
        self.buf.drain(..k);
        self.pending = self.buf.len() as u64 + 1;
        // A record being skipped for its size ended at that newline.
        self.skipping = false;
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
            if self.csv {
                self.csv_byte(b);
            }
            if b == b'\n' && !self.in_quotes {
                // A record that started before a false boundary, or before
                // the quote state is settled, is dropped.
                let drop = std::mem::replace(&mut self.discard, Discard::No);
                if drop == Discard::Damaged {
                    self.malformed += 1;
                }
                self.cut = None;
                // A boundary the quote state is settled at (always, with
                // `Lines`) is a record boundary a cursor can be saved at.
                self.aligned = self.parity_known;
                if drop != Discard::No || !self.parity_known {
                    self.skipping = false;
                } else if self.skipping {
                    self.skipping = false;
                    self.oversized += 1;
                } else if !self.buf.is_empty() || self.framing == Framing::LinesKeepingEmpty {
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
            if !self.skipping && self.buf.len() >= self.max {
                self.skipping = true;
                // CSV: the bytes after the last newline taken as quoted
                // are kept (within the bound): if that newline turns out
                // to have ended a record, the record after it is kept.
                match self.cut.take() {
                    Some(k) if self.csv => {
                        self.buf.drain(..k);
                        self.cut = Some(0);
                    }
                    _ => self.buf.clear(),
                }
            }
            if self.skipping {
                if self.csv && b == b'\n' {
                    self.buf.clear();
                    self.cut = Some(0);
                    self.cut_quotes = 0;
                } else if self.cut.is_some() {
                    if self.buf.len() >= self.max {
                        self.buf.clear();
                        self.cut = None;
                    } else {
                        self.buf.push(b);
                    }
                }
                continue;
            }
            self.buf.push(b);
            if self.csv && b == b'\n' {
                // Kept in the record: taken as inside a quoted field.
                self.cut = Some(self.buf.len());
                self.cut_quotes = 0;
            }
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
    /// Identifier (hex) of the sub-key the fingerprints were made with
    /// ([`key_id`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// Saved before the first record boundary of a first start was known
    /// ([`Splitter::aligned`]): a restart resumes at `offset` unaligned,
    /// as at that first start (security review of #278, L1). Absent (an
    /// older agent, or a known boundary): aligned.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unaligned: bool,
}

/// Label of the key identifier (see [`key_id`]).
const KID_LABEL: &[u8] = b"databastion/tail-cursor/kid/v1";

/// Identifier of the fingerprint sub-key: its tag of a fixed label (hex).
/// Tells two keys apart without revealing anything about them.
fn key_id(key: &LocalTagKey) -> String {
    hex32(&key.tag(&[KID_LABEL]))
}

/// Lowercase hex of a tag.
fn hex32(tag: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    tag.iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0x0f)]])
        .map(char::from)
        .collect()
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
    fingerprint_at(file, key, pos).map_or_else(String::new, |tag| hex32(&tag))
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
    // 64 digits: 32 pairs, no remainder.
    let (pairs, _) = digits.as_chunks::<2>();
    for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
        *o = (nibble(*hi)? << 4) | nibble(*lo)?;
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
    /// The source's checks of every opened file.
    open_check: Option<OpenCheck>,
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

/// A file the tailer has just opened, handed to a source's
/// [`OpenCheck`]: its configured path, the opened handle and the handle's
/// metadata (`fstat`).
pub struct OpenedFile<'a> {
    /// The configured path (its last component is not a symlink).
    pub path: &'a std::path::Path,
    /// The opened handle (read-only).
    pub file: &'a File,
    /// Metadata of the handle.
    pub meta: &'a std::fs::Metadata,
}

/// A source's own checks of every file the tailer opens (first open and
/// every reopen after a rotation), run after the tailer's: an error refuses
/// the file (`TailError::Unreadable` with that kind), which is then not
/// read. It must decide on the handle (`fstat`), or bind any check made on
/// the path to the handle's `(st_dev, st_ino)`.
pub type OpenCheck =
    std::sync::Arc<dyn Fn(&OpenedFile<'_>) -> Result<(), std::io::ErrorKind> + Send + Sync>;

/// Opens the log without blocking (a FIFO or device planted at the path
/// cannot block the open: `O_NONBLOCK`, `O_NOCTTY`) and without following
/// a symlink as its last component (`O_NOFOLLOW`), then checks the
/// **handle** is a regular file (no stat-then-open race) not owned by the
/// agent's own user, then runs the source's `check`. Blocking I/O: call
/// from a blocking thread.
fn open_regular(
    path: &std::path::Path,
    check: Option<&OpenCheck>,
) -> Result<(File, u64, u64, u64), TailError> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
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
    // A hard link put at the path (whoever can write the log directory,
    // with `fs.protected_hardlinks=0`) could be any other file the agent
    // can read: refused like a final symlink (security review of #140 L1).
    if meta.nlink() != 1 {
        tracing::warn!(
            "audit log refused: the file has several hard links; it must be the log the \
             server writes, with one link"
        );
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
    if let Some(check) = check {
        check(&OpenedFile {
            path,
            file: &file,
            meta: &meta,
        })
        .map_err(TailError::Unreadable)?;
    }
    Ok((file, meta.dev(), meta.ino(), meta.len()))
}

/// Whether the configured log file can be opened and read (for `check()`
/// and the source choice). Blocking I/O: call from a blocking thread.
#[must_use]
pub fn readable(path: &std::path::Path) -> bool {
    open_regular(path, None).is_ok_and(|(mut f, _, _, _)| {
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
            open_check: None,
        }
    }

    /// Adds the source's own checks of every file this tailer opens (see
    /// [`OpenCheck`]).
    #[must_use]
    pub fn with_open_check(mut self, check: OpenCheck) -> Self {
        self.open_check = Some(check);
        self
    }

    /// Damaged records dropped by the splitter ([`Framing::JsonObjects`],
    /// and [`Framing::Csv`] records with inconsistent quotes).
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
        let (mut file, dev, ino, len) = open_regular(&self.path, self.open_check.as_ref())?;
        let cursor = self.load_cursor();
        // First start: the end of a file being written need not be a record
        // boundary (see `Splitter::reset_unaligned`); nor the position of a
        // cursor saved before one was known.
        let mut unaligned = cursor.is_none() && len > 0;
        let start = match cursor {
            Some(mut c) if c.dev == dev && c.ino == ino => {
                // A replay whose end lies before the offset is not one the
                // tailer saves: ignored, as before.
                c.replay = c.replay.filter(|r| r.end >= c.offset);
                if self.cursor_intact(&file, len, &c) {
                    self.replay = c.replay.map(|replay| ReplayFrom {
                        file: (dev, ino),
                        replay,
                    });
                    unaligned = c.unaligned && c.offset > 0;
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
        if unaligned {
            let after_newline = self.tail.last() == Some(&b'\n');
            self.splitter.reset_unaligned(after_newline);
        } else {
            self.splitter.reset();
        }
        self.file = Some((file, dev, ino));
        self.offset = start;
        Ok(())
    }

    /// Whether the saved cursor `c` of the open file (same inode, length
    /// `len`) still points at what was read: its positions are within the
    /// file and, when the cursor has fingerprints and the agent key is
    /// available, the bytes before them match. A cursor without
    /// fingerprints (older agent), made with another key (`kid`: after a
    /// new agent key) or without a key (tests) is checked on its positions
    /// only. Reads at most `2 * FP_BYTES`.
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
        if c.kid.as_deref() != Some(key_id(key).as_str()) {
            tracing::info!(
                "audit cursor fingerprinted with another agent key: checked on its positions \
                 only, fingerprinted again at the next save"
            );
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
            if let Ok(meta) = file.metadata()
                && (meta.len() < self.offset || rewritten)
            {
                self.rotations += 1;
                tracing::warn!("audit log truncated; reading from its start");
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| TailError::Unreadable(e.kind()))?;
                self.offset = 0;
                self.tail.clear();
                self.splitter.reset();
            }
            let mut eof = false;
            while read_total < MAX_POLL_BYTES
                && (self.framing != Framing::LinesKeepingEmpty
                    || records.len() < MAX_POLL_RECORDS_KEEPING_EMPTY)
            {
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
            // `lstat`: a symlink put in its place is a change too, and the
            // reopen refuses it (`O_NOFOLLOW`).
            match std::fs::symlink_metadata(&self.path) {
                Ok(meta)
                    if (meta.file_type().is_file() || meta.file_type().is_symlink())
                        && (meta.dev(), meta.ino()) != (dev, ino) =>
                {
                    self.rotations += 1;
                    tracing::info!("audit log rotated; following the new file");
                    self.file = None;
                    match open_regular(&self.path, self.open_check.as_ref()) {
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
        if let Some(mut c) = self.load_cursor()
            && let Some(r) = c.replay.take()
        {
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

    /// Whether the last bytes read before `offset` (kept in memory) are
    /// still those of the file. Reads at most [`TAIL_BYTES`].
    fn read_bytes_unchanged(&self, file: &File) -> bool {
        use std::os::unix::fs::FileExt as _;
        if self.offset == 0 {
            return true;
        }
        let n = self.tail.len() as u64;
        if n == 0 || n > self.offset {
            return false;
        }
        let mut now = Zeroizing::new(vec![0u8; self.tail.len()]);
        file.read_exact_at(&mut now, self.offset - n).is_ok() && *now == *self.tail
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
        // First start, before the first record boundary is known: the
        // position is saved with that state, so that a restart resumes
        // there unaligned instead of as aligned (#267 review L1), and reads
        // what was written while the agent was stopped (security review of
        // #278, L1). Nothing is held then (no record was read).
        let unaligned = !self.splitter.aligned();
        let end = self.offset.saturating_sub(self.splitter.pending());
        let here: Vec<(u64, u64)> = held
            .iter()
            .filter(|(_, p)| p.file == (*dev, *ino) && p.start < end)
            .map(|(k, p)| (*k, p.start))
            .collect();
        let from = here.iter().map(|(_, s)| *s).min();
        let offset = from.unwrap_or(end);
        let key = store.tag_key();
        // The file may have changed since it was read (the events were
        // handed over first): fingerprints of new content would let a
        // restart resume in its middle. Empty ones never match.
        let unchanged = key.is_none() || self.read_bytes_unchanged(file);
        if !unchanged {
            tracing::warn!(
                "audit log changed since it was read; the saved position will not be trusted \
                 at the next start"
            );
        }
        let fingerprint = |k: &LocalTagKey, pos: u64| {
            if unchanged {
                fingerprint_hex(file, k, pos)
            } else {
                String::new()
            }
        };
        let cursor = Cursor {
            v: 1,
            dev: *dev,
            ino: *ino,
            offset,
            replay: from.map(|_| Replay { end, keep: here }),
            fp: key.map(|k| fingerprint(k, offset)),
            end_fp: key.filter(|_| from.is_some()).map(|k| fingerprint(k, end)),
            kid: key.map(key_id),
            unaligned,
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
        // The same key identifier is required for the check to apply.
        let kid = good.kid.clone().unwrap();
        assert_eq!(kid.len(), 64);
        // A replay without its end fingerprint, and crafted positions.
        let crafted = [
            format!(
                "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":6,\"fp\":\"{fp}\",\"kid\":\"{kid}\",\"replay\":{{\"end\":6,\"keep\":[]}}}}",
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
    fn a_new_agent_key_keeps_the_position_and_refingerprints_it() {
        let d = Dir::new("fp-kid");
        let log = d.0.join("server_audit.log");
        append(&log, "");
        let (old_key, new_key) = (tag_key(8), tag_key(9));
        let store = |k: &std::sync::Arc<LocalTagKey>| {
            CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(k.clone()))
        };
        let mut t = Tailer::new(log.clone(), Framing::Lines, store(&old_key));
        assert!(t.poll().unwrap().records.is_empty());
        append(&log, "a1\nb1\n");
        let p = t.poll().unwrap();
        t.commit_from(&[(7, p.positions[0])]);
        drop(t);
        let before = saved(&store(&old_key).unwrap());
        append(&log, "c1\n");
        // `enroll --new-hmac-key`: the fingerprints cannot be checked; the
        // position and the replay are kept (positions checked only), not
        // reset to the start of the log.
        let mut t = Tailer::new(log.clone(), Framing::Lines, store(&new_key));
        assert_eq!(lines(t.poll().unwrap()), ["a1", "b1", "c1"]);
        assert_eq!(t.take_replay().unwrap().replay.end, 6);
        assert_eq!(t.rotations, 0);
        // Fingerprinted again, under the new key, at the next save.
        t.commit();
        drop(t);
        let after = saved(&store(&new_key).unwrap());
        assert!(after.kid.is_some() && after.kid != before.kid);
        assert!(after.fp.is_some() && after.fp != before.fp);
        // A cursor with fingerprints but no key identifier is treated the
        // same way.
        let mut c = after.clone();
        c.kid = None;
        c.fp = Some("0".repeat(64));
        store(&new_key)
            .unwrap()
            .save(&serde_json::to_vec(&c).unwrap())
            .unwrap();
        let mut t = Tailer::new(log.clone(), Framing::Lines, store(&new_key));
        assert!(t.poll().unwrap().records.is_empty());
        assert_eq!(t.rotations, 0);
        t.commit();
        drop(t);
        // Under the same key, a truncation while stopped still resets.
        copytruncate(&log, "n1 xxxxxxxx\nn2\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store(&new_key));
        assert_eq!(lines(t.poll().unwrap()), ["n1 xxxxxxxx", "n2"]);
        assert_eq!(t.rotations, 1);
        // And a mismatch under the same key identifier (tampered
        // fingerprint) resets too.
        t.commit();
        drop(t);
        let mut c = saved(&store(&new_key).unwrap());
        c.fp = Some("0".repeat(64));
        store(&new_key)
            .unwrap()
            .save(&serde_json::to_vec(&c).unwrap())
            .unwrap();
        let mut t = Tailer::new(log, Framing::Lines, store(&new_key));
        assert_eq!(lines(t.poll().unwrap()), ["n1 xxxxxxxx", "n2"]);
        assert_eq!(t.rotations, 1);
    }

    #[test]
    fn a_truncation_between_the_read_and_the_save_is_not_trusted() {
        let d = Dir::new("fp-late");
        let log = d.0.join("server_audit.log");
        append(&log, "");
        let key = tag_key(10);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(t.poll().unwrap().records.is_empty());
        append(&log, "a1\nb1\nc1\n");
        let p = t.poll().unwrap();
        // While the events are handed over (backpressure), the log is
        // copytruncated and grows back past the offset and the end read.
        copytruncate(&log, "n1 xxxxxxxx\nn2 xxxxxxxx\nn3\n");
        t.commit_from(&[(7, p.positions[0])]);
        let c = saved(&store().unwrap());
        assert_eq!(c.fp.as_deref(), Some(""));
        assert_eq!(c.end_fp.as_deref(), Some(""));
        drop(t);
        // The next start does not resume in the middle of the new content.
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(
            lines(t.poll().unwrap()),
            ["n1 xxxxxxxx", "n2 xxxxxxxx", "n3"]
        );
        assert!(t.take_replay().is_none());
        assert_eq!(t.rotations, 1);
        // Unchanged file: the fingerprints are saved.
        t.commit();
        assert_eq!(saved(&store().unwrap()).fp.map(|f| f.len()), Some(64));
    }

    #[test]
    fn an_old_cursor_whose_replay_ends_past_the_file_resets() {
        let d = Dir::new("fp-old-end");
        let log = d.0.join("server_audit.log");
        append(&log, "a1\nb1\n");
        let meta = std::fs::metadata(&log).unwrap();
        let key = tag_key(11);
        let store =
            || CursorStore::new(&d.0, "t", "server_audit").map(|s| s.with_tag_key(key.clone()));
        // An older agent's cursor (no fingerprint): the offset is within
        // the file but the end read is past it, so the file was truncated.
        // Previously the offset was kept and the replay dropped; now the
        // file is read from its start.
        let old = format!(
            "{{\"v\":1,\"dev\":{},\"ino\":{},\"offset\":3,\"replay\":{{\"end\":60,\"keep\":[[7,3]]}}}}",
            meta.dev(),
            meta.ino()
        );
        store().unwrap().save(old.as_bytes()).unwrap();
        let resets = crate::audit::cursor_resets();
        let mut t = Tailer::new(log, Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["a1", "b1"]);
        assert!(t.take_replay().is_none());
        assert_eq!(t.rotations, 1);
        assert!(crate::audit::cursor_resets() > resets);
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

    /// Empty lines: no record with [`Framing::Lines`] (unchanged), an
    /// empty record with [`Framing::LinesKeepingEmpty`], with the same
    /// positions, `\r` handling, bound and unaligned start otherwise.
    #[test]
    fn empty_lines_are_kept_only_when_asked() {
        let data = b"a\n\nb \r\n\r\n\n";
        let mut s = Splitter::new(Framing::Lines);
        let mut out = Vec::new();
        s.feed(data, &mut out);
        let got: Vec<&[u8]> = out.iter().map(|r| r.as_slice()).collect();
        // `\r\n` alone was already an empty record; a bare `\n` none.
        assert_eq!(got, [&b"a"[..], b"b ", b""]);
        assert_eq!(s.last_ends(), [(2, 2), (7, 4), (9, 2)]);
        let mut k = Splitter::new(Framing::LinesKeepingEmpty);
        let mut out = Vec::new();
        k.feed(data, &mut out);
        let got: Vec<&[u8]> = out.iter().map(|r| r.as_slice()).collect();
        assert_eq!(got, [&b"a"[..], b"", b"b ", b"", b""]);
        assert_eq!(k.last_ends(), [(2, 2), (3, 1), (7, 4), (9, 2), (10, 1)]);
        assert_eq!(k.pending(), 0);
        // The bound: a longer line is skipped and counted, the empty line
        // after it kept.
        let mut k = Splitter::with_max(Framing::LinesKeepingEmpty, 4);
        let mut out = Vec::new();
        k.feed(b"abcdefgh\n\nab\n", &mut out);
        let got: Vec<&[u8]> = out.iter().map(|r| r.as_slice()).collect();
        assert_eq!(got, [&b""[..], b"ab"]);
        assert_eq!(k.oversized, 1);
        // An unaligned start drops the first (partial) line only.
        let mut k = Splitter::new(Framing::LinesKeepingEmpty);
        k.reset_unaligned(false);
        assert!(!k.aligned());
        let mut out = Vec::new();
        k.feed(b"tail\n\nx\n", &mut out);
        let got: Vec<&[u8]> = out.iter().map(|r| r.as_slice()).collect();
        assert_eq!(got, [&b""[..], b"x"]);
        assert!(k.aligned());
        let mut k = Splitter::new(Framing::LinesKeepingEmpty);
        k.reset_unaligned(true);
        assert!(k.aligned());
        let mut out = Vec::new();
        k.feed(b"\nx\n", &mut out);
        assert_eq!(out.len(), 2);
    }

    /// The tailer with [`Framing::LinesKeepingEmpty`]: empty lines and
    /// their positions, rotation as with [`Framing::Lines`], and a poll
    /// of empty lines bounded in records.
    #[test]
    fn a_tailer_keeping_empty_lines() {
        let d = Dir::new("keep-empty");
        let log = d.0.join("audit.log");
        append(&log, "");
        let mut t = Tailer::new(log.clone(), Framing::LinesKeepingEmpty, None);
        assert_eq!(t.framing(), Framing::LinesKeepingEmpty);
        assert!(t.poll().unwrap().records.is_empty());
        append(&log, "h1\n\nh2\nbody\n\n");
        let p = t.poll().unwrap();
        assert_eq!(lines_of(&p), ["h1", "", "h2", "body", ""]);
        let spans: Vec<(u64, u64)> = p.positions.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(spans, [(0, 3), (3, 4), (4, 7), (7, 12), (12, 13)]);
        // Rotation: the old file is finished, the new one read.
        append(&log, "old\n\n");
        std::fs::rename(&log, d.0.join("audit.2026-10-31T10-00-00.0000.log")).unwrap();
        append(&log, "\nnew\n");
        let p = t.poll().unwrap();
        assert_eq!(lines_of(&p), ["old", "", "", "new"]);
        assert_eq!(t.rotations, 1);
        // Bounded in records: 600 000 empty lines (well under the byte
        // bound) take several polls, each under the record bound plus one
        // chunk.
        append(&log, &"\n".repeat(600_000));
        let (mut total, mut polls) = (0, 0);
        loop {
            let p = t.poll().unwrap();
            polls += 1;
            assert!(p.records.len() <= MAX_POLL_RECORDS_KEEPING_EMPTY + CHUNK);
            assert_eq!(p.records.len(), p.positions.len());
            total += p.records.len();
            if !p.more {
                break;
            }
        }
        assert_eq!(total, 600_000);
        assert!(polls >= 3, "{polls}");
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
    fn a_symlinked_log_is_refused_at_open_and_at_rotation() {
        let d = Dir::new("symlink");
        let elsewhere = d.0.join("other.log");
        append(&elsewhere, "secret history\n");
        // A symlink as the configured path: never opened.
        let link = d.0.join("linked.log");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let mut t = Tailer::new(link.clone(), Framing::Lines, None);
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert!(!readable(&link));

        // A symlink swapped in at rotation time is refused, and nothing of
        // its target is read.
        let log = d.0.join("audit.log");
        append(&log, "old\n");
        let opened = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let seen = std::sync::Arc::clone(&opened);
        let check: OpenCheck = std::sync::Arc::new(move |f: &OpenedFile<'_>| {
            assert!(f.meta.file_type().is_file());
            seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        });
        let mut t = Tailer::new(log.clone(), Framing::Lines, None).with_open_check(check);
        assert!(lines(t.poll().unwrap()).is_empty());
        assert_eq!(opened.load(std::sync::atomic::Ordering::Relaxed), 1);
        std::fs::rename(&log, d.0.join("audit.log.1")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert_eq!(opened.load(std::sync::atomic::Ordering::Relaxed), 1);
        // A regular file again: opened, and the source's check runs again.
        std::fs::remove_file(&log).unwrap();
        append(&log, "");
        assert!(lines(t.poll().unwrap()).is_empty());
        assert_eq!(opened.load(std::sync::atomic::Ordering::Relaxed), 2);
        append(&log, "b\n");
        let got = lines(t.poll().unwrap());
        assert_eq!(got, ["b"]);
    }

    #[test]
    fn a_hard_linked_log_is_refused_at_open_and_at_rotation() {
        let d = Dir::new("hardlink");
        let other = d.0.join("other.log");
        append(&other, "secret history\n");
        let linked = d.0.join("linked.log");
        std::fs::hard_link(&other, &linked).unwrap();
        let mut t = Tailer::new(linked.clone(), Framing::Lines, None);
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        assert!(!readable(&linked));
        // Swapped in at rotation.
        let log = d.0.join("audit.log");
        append(&log, "");
        let mut t = Tailer::new(log.clone(), Framing::Lines, None);
        assert!(lines(t.poll().unwrap()).is_empty());
        std::fs::rename(&log, d.0.join("audit.log.1")).unwrap();
        std::fs::remove_file(&linked).unwrap();
        std::fs::hard_link(&other, &log).unwrap();
        assert!(matches!(t.poll(), Err(TailError::Unreadable(_))));
        // A regular single-link file again: followed.
        std::fs::remove_file(&log).unwrap();
        append(&log, "");
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, "b\n");
        assert_eq!(lines(t.poll().unwrap()), ["b"]);
    }

    #[test]
    fn a_refusing_open_check_keeps_the_file_unread() {
        let d = Dir::new("check");
        let log = d.0.join("audit.log");
        append(&log, "x\n");
        let check: OpenCheck =
            std::sync::Arc::new(|_: &OpenedFile<'_>| Err(std::io::ErrorKind::PermissionDenied));
        let mut t = Tailer::new(log, Framing::Lines, None).with_open_check(check);
        assert_eq!(
            t.poll().err(),
            Some(TailError::Unreadable(std::io::ErrorKind::PermissionDenied))
        );
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

    /// A PostgreSQL csvlog record whose statement spans lines and holds
    /// quotes and commas (as pgaudit writes it inside the message).
    fn csvlog_record(n: u32) -> String {
        format!(
            "2026-10-17 12:34:28.{n:03} UTC,\"databastion\",\"shop\",4242,\"127.0.0.1:5555\",\
             6710f0a4.4d2,{n},\"SELECT\",2026-10-17 12:34:27 UTC,3/45,0,LOG,00000,\
             \"AUDIT: SESSION,{n},1,READ,SELECT,,,\"\"SELECT id, \"\"e,mail\"\" /* a, \"\"b\"\" */\n\
             FROM crm.t_{n}\nWHERE x = ',\"\"'\"\",<not logged>\",,,,,,,,,\"databastion-it\",\
             \"client backend\",,0\n"
        )
    }

    fn strings(out: &[Zeroizing<Vec<u8>>]) -> Vec<String> {
        out.iter()
            .map(|r| String::from_utf8(r.to_vec()).unwrap())
            .collect()
    }

    /// The first start of a csvlog stream at an end of file that lies
    /// anywhere inside a record the server is still writing (PostgreSQL
    /// writes a record of more than 4 KiB in several `write`s, such as the
    /// agent's own probes): the records after it are all read. A start
    /// inside a quoted field taken as "outside" left the quote state
    /// inverted, and no record was ever complete again (CI job
    /// 117395163577, `failed_reads_and_what_is_reported`: no csvlog event
    /// in 30 s).
    #[test]
    fn a_csv_start_inside_a_record_realigns() {
        let cut = csvlog_record(1);
        let next = [csvlog_record(2), csvlog_record(3)];
        let want: Vec<String> = next
            .iter()
            .map(|r| r.trim_end_matches('\n').to_owned())
            .collect();
        // Every offset of the record, inside and outside its quoted fields.
        for at in 0..=cut.len() {
            let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
            let after_newline = at == 0 || cut.as_bytes()[at - 1] == b'\n';
            s.reset_unaligned(after_newline);
            let mut out = Vec::new();
            let mut rest = cut.as_bytes()[at..].to_vec();
            for r in &next {
                rest.extend_from_slice(r.as_bytes());
            }
            // Fed in two chunks: the quote checks span `feed` calls.
            let (a, b) = rest.split_at(rest.len() / 3);
            s.feed(a, &mut out);
            s.feed(b, &mut out);
            let got = strings(&out);
            if at == 0 {
                assert_eq!(got.len(), 3, "start at the record's start");
                assert_eq!(got[1..], want[..]);
            } else {
                assert_eq!(got, want, "start at byte {at} of the record");
            }
            assert_eq!(s.pending(), 0);
            assert_eq!(s.malformed, 0, "start at byte {at}");
        }
        // Through the tailer: no cursor, the file ends inside a quoted field
        // of the record being written.
        let d = Dir::new("csvcut");
        let log = d.0.join("postgresql.csv");
        let split = cut.find("FROM crm").unwrap() + 4;
        append(&log, &csvlog_record(0));
        append(&log, &cut[..split]);
        let mut t = Tailer::new(log.clone(), Framing::Csv, None);
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, &cut[split..]);
        append(&log, &next[0]);
        append(&log, &next[1]);
        assert_eq!(lines(t.poll().unwrap()), want);
        append(&log, &csvlog_record(4));
        assert_eq!(lines(t.poll().unwrap()).len(), 1);
        assert_eq!(t.malformed(), 0);
    }

    /// A csvlog record cut short (an odd number of quotes, e.g. a server
    /// stopped while writing it) no longer swallows every later record:
    /// the quote state is corrected at the next record's first quoted
    /// field, only the damaged record is dropped (counted), and the next
    /// one is kept with the following ones (#267 review L2).
    #[test]
    fn a_damaged_csv_record_is_dropped_and_the_state_corrected() {
        let full = csvlog_record(1);
        let damaged = &full[..full.find("WHERE").unwrap()];
        let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
        let mut out = Vec::new();
        let data = format!(
            "{}{damaged}\n{}{}{}",
            csvlog_record(0),
            csvlog_record(2),
            csvlog_record(3),
            csvlog_record(4)
        );
        s.feed(data.as_bytes(), &mut out);
        let got = strings(&out);
        let want: Vec<String> = [0, 2, 3, 4]
            .map(|n| csvlog_record(n).trim_end_matches('\n').to_owned())
            .to_vec();
        assert_eq!(got, want);
        assert_eq!(s.malformed, 1);
        assert_eq!(s.realigned, 1);
        assert_eq!(s.pending(), 0);
        // Through the tailer: the positions of the kept record start after
        // the damaged one.
        let d = Dir::new("csvdamaged");
        let log = d.0.join("postgresql.csv");
        append(&log, "");
        let mut t = Tailer::new(log.clone(), Framing::Csv, None);
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, &data);
        let p = t.poll().unwrap();
        let ends: Vec<u64> = p.positions.iter().map(|p| p.end).collect();
        let starts: Vec<u64> = p.positions.iter().map(|p| p.start).collect();
        let r0 = csvlog_record(0).len() as u64;
        let cut = r0 + damaged.len() as u64 + 1;
        let r = |n| csvlog_record(n).len() as u64;
        assert_eq!(starts, [0, cut, cut + r(2), cut + r(2) + r(3)]);
        assert_eq!(ends[1], cut + r(2));
        assert_eq!(lines(p), want);
        assert_eq!(t.malformed(), 1);
        // Security review of #278, M1: a statement whose text, after a
        // quoted newline, looks like the unquoted fields of a record, cut
        // later with the next record written right after it. That newline
        // is not a record boundary (what follows it up to the inverting
        // quote is not a log time and one comma): the hybrid is dropped,
        // never read as a record of another user.
        let forged = "SELECT x\n2026-10-18 09:00:00.000 UTC,mallory,shop,1,,s,1,,\
                      2026-10-18 09:00:00 UTC,3/1,0,ERROR,57014,,,,,,,,,,psql,client backend,,";
        let victim = csvlog_record(1).replace("AUDIT: SESSION", &format!("statement: {forged}"));
        let cut_at = victim.find("ERROR,57014,").unwrap() + "ERROR,57014,".len();
        for sep in ["", "\n"] {
            let data = format!(
                "{}{}{sep}{}{}",
                csvlog_record(0),
                &victim[..cut_at],
                csvlog_record(2),
                csvlog_record(3)
            );
            let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
            let mut out = Vec::new();
            s.feed(data.as_bytes(), &mut out);
            let got = strings(&out);
            assert!(got.iter().all(|r| !r.contains("mallory")), "{sep:?}");
            let mut want = vec![csvlog_record(0)];
            if !sep.is_empty() {
                // The cut ends at a record boundary: the next record is kept.
                want.push(csvlog_record(2));
            }
            want.push(csvlog_record(3));
            let want: Vec<String> = want
                .iter()
                .map(|r| r.trim_end_matches('\n').to_owned())
                .collect();
            assert_eq!(got, want, "{sep:?}");
            assert_eq!(s.malformed, 1);
        }
        // Record starts.
        assert!(csv_record_start(b"2026-10-18 09:00:00.123 UTC,\""));
        assert!(csv_record_start(b"2026-10-18 09:00:00 +02,\""));
        for no in [
            &b"2026-10-18 09:00:00.123 UTC,mallory,\""[..],
            b"x2026-10-18 09:00:00.123 UTC,\"",
            b"2026-10-18 09:00:00.123 UTC\"",
            b"2026-10-18 09:00:00. UTC,\"",
            b"2026-10-18T09:00:00 UTC,\"",
            b",\"",
        ] {
            assert!(!csv_record_start(no));
        }
        // When another quote comes between the newline and the quote that
        // tells the state is inverted, the newline is not trusted as a
        // boundary: the record in progress is dropped whole (one count).
        let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
        let mut out = Vec::new();
        s.feed(b"a,\"cut\n\"\",x,\"y\"\nc,\"z\"\n", &mut out);
        assert_eq!(strings(&out), ["c,\"z\""]);
        assert_eq!(s.malformed, 1);
        // Well-formed records never trip the checks.
        let mut s = Splitter::with_max(Framing::Csv, MAX_RECORD_BYTES);
        let mut out = Vec::new();
        let many: String = (0..50).map(csvlog_record).collect();
        for chunk in many.as_bytes().chunks(7) {
            s.feed(chunk, &mut out);
        }
        assert_eq!(out.len(), 50);
        assert_eq!((s.malformed, s.realigned), (0, 0));
    }

    /// A restart while the CSV quote state is still unknown at the first
    /// start: the cursor is saved with that state and the restart resumes
    /// there unaligned; nothing is counted as damaged, and the records
    /// written while the agent was stopped are read (#267 review L1,
    /// security review of #278 L1).
    #[test]
    fn a_restart_while_the_csv_state_is_unknown() {
        let d = Dir::new("csvrestart");
        let log = d.0.join("postgresql.csv");
        let store = || CursorStore::new(&d.0, "t", "pgaudit");
        // A statement over several lines, and no quote in its last lines:
        // the start lies in a quoted field and the quote state stays
        // unknown over the newlines read.
        let rec = csvlog_record(1).replace("FROM crm.t_1", "FROM crm.t_1\nJOIN a\nJOIN b");
        let at = rec.find("JOIN a").unwrap();
        append(&log, &csvlog_record(0));
        append(&log, &rec[..at]);
        let mut t = Tailer::new(log.clone(), Framing::Csv, store());
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, "JOIN a\nJOIN b\n");
        assert!(lines(t.poll().unwrap()).is_empty());
        assert!(!t.splitter.aligned());
        t.commit();
        // Saved with the unaligned state (security review of #278, L1).
        let c = saved(&store().unwrap());
        assert!(c.unaligned);
        assert_eq!(c.offset, std::fs::metadata(&log).unwrap().len());
        drop(t);
        // While the agent is stopped: the rest of the record, then two
        // records. The restart resumes at the saved position, unaligned:
        // both records are read, nothing is counted as damaged.
        append(&log, &rec[at + "JOIN a\nJOIN b\n".len()..]);
        append(&log, &csvlog_record(2));
        append(&log, &csvlog_record(3));
        let mut t = Tailer::new(log.clone(), Framing::Csv, store());
        let want: Vec<String> = [2, 3]
            .map(|n| csvlog_record(n).trim_end_matches('\n').to_owned())
            .to_vec();
        assert_eq!(lines(t.poll().unwrap()), want);
        assert_eq!(t.malformed(), 0);
        assert!(t.splitter.aligned());
        t.commit();
        let c = saved(&store().unwrap());
        assert!(!c.unaligned);
        assert_eq!(c.offset, std::fs::metadata(&log).unwrap().len());
        // An aligned cursor does not carry the field (older agents read
        // it unchanged).
        let raw = String::from_utf8(store().unwrap().load().unwrap().unwrap()).unwrap();
        assert!(!raw.contains("unaligned"));
        drop(t);
        append(&log, &csvlog_record(4));
        let mut t = Tailer::new(log.clone(), Framing::Csv, store());
        assert_eq!(lines(t.poll().unwrap()).len(), 1);
        // The old behaviour: a cursor saved inside the quoted field, read
        // as aligned at the restart, counted one false damaged record.
        let mut s = Splitter::new(Framing::Csv);
        let mut out = Vec::new();
        s.feed(&rec.as_bytes()[at + "JOIN a\nJOIN b\n".len()..], &mut out);
        s.feed(csvlog_record(2).as_bytes(), &mut out);
        assert_eq!(s.malformed, 1);
    }

    /// The first start inside a record longer than the bound, while the
    /// quote state is unknown: the record is dropped (never buffered past
    /// the bound, not counted as damaged) and the next one kept, whether
    /// the start lies in a quoted field or not.
    #[test]
    fn an_oversized_record_while_the_csv_state_is_unknown() {
        let long = csvlog_record(1).replace(
            "FROM crm.t_1",
            &format!("FROM crm.t_1\n{}", "JOIN x\n".repeat(200)),
        );
        let next = [csvlog_record(2), csvlog_record(3)];
        let want: Vec<String> = next
            .iter()
            .map(|r| r.trim_end_matches('\n').to_owned())
            .collect();
        for at in [
            1,
            long.find("databastion").unwrap(),
            long.find("FROM crm").unwrap(),
            long.find("JOIN x").unwrap() + 3,
            long.rfind("JOIN x").unwrap(),
            long.len() - 3,
        ] {
            let mut s = Splitter::with_max(Framing::Csv, 512);
            s.reset_unaligned(long.as_bytes()[at - 1] == b'\n');
            let mut out = Vec::new();
            for chunk in long.as_bytes()[at..].chunks(97) {
                s.feed(chunk, &mut out);
                assert!(s.buf.len() <= 512);
            }
            for r in &next {
                s.feed(r.as_bytes(), &mut out);
            }
            assert_eq!(strings(&out), want, "start at byte {at}");
            assert_eq!(s.malformed, 0, "start at byte {at}");
            assert!(s.oversized <= 1);
            assert!(s.aligned());
        }
        // A start inside a long line of a quoted field whose closing quote
        // does not tell the state (it follows a newline): the end of the
        // record is taken as quoted while it is skipped, and the next
        // record is kept from the bytes after it.
        let tricky = format!(
            "2026-10-18 09:00:00.001 UTC,\"databastion\",\"shop\",4242,,6710f0a4.4d2,1,,\
             2026-10-18 08:59:00 UTC,3/45,0,LOG,00000,\"statement: SELECT\n{}\n\",,0\n",
            "x ".repeat(400)
        );
        for at in [tricky.find("x x").unwrap() + 1, tricky.len() - 400] {
            let mut s = Splitter::with_max(Framing::Csv, 512);
            s.reset_unaligned(false);
            let mut out = Vec::new();
            s.feed(&tricky.as_bytes()[at..], &mut out);
            for r in &next {
                s.feed(r.as_bytes(), &mut out);
            }
            assert_eq!(strings(&out), want, "start at byte {at}");
            assert_eq!(s.malformed, 0);
            assert!(s.aligned());
        }
        // Generic CSV where a quote that does not tell the state (`,"` then
        // `,`) leaves it inverted past the end of a long record: the end
        // of the record is taken as quoted while the record is skipped (or
        // just before it is), and the record after it is kept from the
        // bytes after that newline.
        for ys in [600, 500] {
            let data = format!("h,\"aaa,\",{}\nzzzzzzzzzz,\"q\"\nk,\"v\"\n", "y".repeat(ys));
            let mut s = Splitter::with_max(Framing::Csv, 512);
            s.reset_unaligned(false);
            let mut out = Vec::new();
            s.feed(&data.as_bytes()[4..], &mut out);
            assert_eq!(strings(&out), ["zzzzzzzzzz,\"q\"", "k,\"v\""], "{ys}");
            assert_eq!((s.malformed, s.realigned), (0, 1));
            assert!(s.buf.len() <= 512);
        }
        // The same record read from its start is skipped and counted.
        let mut s = Splitter::with_max(Framing::Csv, 512);
        let mut out = Vec::new();
        s.feed(long.as_bytes(), &mut out);
        s.feed(next[0].as_bytes(), &mut out);
        assert_eq!(strings(&out), want[..1]);
        assert_eq!((s.oversized, s.malformed, s.realigned), (1, 0, 0));
    }

    /// A line-framed log cut inside a line at the first start, with a
    /// commit before the line ends: the cursor is saved unaligned, so a
    /// restart does not read the end of the cut line as a record (#267
    /// review L1) and reads the lines written while the agent was stopped
    /// (security review of #278, L1); once a line ended, the cursor is
    /// aligned again.
    #[test]
    fn lines_after_a_restart() {
        let d = Dir::new("linerestart");
        let log = d.0.join("postgresql.json");
        let store = || CursorStore::new(&d.0, "t", "jsonlog");
        append(&log, "{\"a\":1}\n{\"half");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(lines(t.poll().unwrap()).is_empty());
        t.commit();
        assert!(saved(&store().unwrap()).unaligned);
        drop(t);
        // Written while the agent is stopped: the end of the cut line is
        // not read as a record, the next line is.
        append(&log, "\":2}\n{\"b\":3}\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["{\"b\":3}"]);
        t.commit();
        drop(t);
        append(&log, "{\"c\":4}\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert_eq!(lines(t.poll().unwrap()), ["{\"c\":4}"]);
        // A first start after a newline is aligned at once.
        let d = Dir::new("linerestart2");
        let log = d.0.join("postgresql.json");
        let store = || CursorStore::new(&d.0, "t", "jsonlog");
        append(&log, "{\"a\":1}\n");
        let mut t = Tailer::new(log.clone(), Framing::Lines, store());
        assert!(lines(t.poll().unwrap()).is_empty());
        t.commit();
        assert_eq!(saved(&store().unwrap()).offset, 8);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        /// The CSV splitter's oracles (`fuzz::check`) over statement
        /// texts quoted as PostgreSQL does (#267 review L3).
        #[test]
        fn csv_splitter_oracles(
            statements in proptest::collection::vec(
                "[a-zA-Z0-9 _.*=<>()'\"\\,;\n\r\t-]{0,80}|[\"\n,]{0,12}|\\PC{0,24}",
                0..6,
            ),
            chunk in 0usize..64,
            at in 0usize..4096,
            damage in 0usize..65536,
            max in 64usize..1100,
        ) {
            let statements: Vec<&[u8]> = statements.iter().map(String::as_bytes).collect();
            fuzz::check(&statements, chunk, at, damage, max);
        }

        /// [`Framing::LinesKeepingEmpty`] at any chunking: exactly the
        /// complete lines (one `\r` before the newline dropped, as with
        /// [`Framing::Lines`]), and [`Framing::Lines`] gives the same
        /// records and positions less the empty lines.
        #[test]
        fn lines_keeping_empty_are_lines_plus_the_empty_ones(
            data in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::strategy::Just(b'\n'),
                    proptest::strategy::Just(b'\r'),
                    proptest::strategy::Just(b' '),
                    proptest::strategy::Just(b'a'),
                ],
                0..200,
            ),
            chunk in 1usize..32,
        ) {
            let run = |framing| {
                let mut s = Splitter::new(framing);
                let (mut out, mut ends) = (Vec::new(), Vec::new());
                let mut base = 0;
                for c in data.chunks(chunk) {
                    s.feed(c, &mut out);
                    ends.extend(s.last_ends().iter().map(|&(i, n)| (base + i, n)));
                    base += c.len();
                }
                let out: Vec<Vec<u8>> = out.iter().map(|r| r.to_vec()).collect();
                (out, ends)
            };
            let (kept, kept_ends) = run(Framing::LinesKeepingEmpty);
            let mut expect: Vec<Vec<u8>> = data.split(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
            expect.pop();
            for l in &mut expect {
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
            }
            proptest::prop_assert_eq!(&kept, &expect);
            let (lines, line_ends) = run(Framing::Lines);
            // `Lines` drops a line that is a bare newline (one byte); an
            // empty line written `\r\n` stays a record there.
            let (want, want_ends): (Vec<_>, Vec<_>) = kept
                .iter()
                .zip(&kept_ends)
                .filter(|(_, (_, n))| *n > 1)
                .map(|(r, e)| (r.clone(), *e))
                .unzip();
            proptest::prop_assert_eq!(lines, want);
            proptest::prop_assert_eq!(line_ends, want_ends);
        }
    }

    /// A line-framed log whose end is not after a newline at the first
    /// start: the cut line is dropped, the next ones read.
    #[test]
    fn a_line_start_inside_a_record_drops_it() {
        let d = Dir::new("linecut");
        let log = d.0.join("postgresql.json");
        append(&log, "{\"a\":1}\n{\"half");
        let mut t = Tailer::new(log.clone(), Framing::Lines, None);
        assert!(lines(t.poll().unwrap()).is_empty());
        append(&log, "\":2}\n{\"b\":3}\n");
        assert_eq!(lines(t.poll().unwrap()), ["{\"b\":3}"]);
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
