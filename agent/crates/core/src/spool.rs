//! Bounded disk spool of result batches. Crate-private.
//!
//! - `<state_dir>/spool/` (`0700`); one file per batch (`0600`), written
//!   with `fsutil::write_private_atomic` (temporary file, `fsync`, `rename`,
//!   directory `fsync`). A stale temporary file from a crash is removed at
//!   startup.
//! - A file holds exactly the body sent to the console: a `FindingsBatch` or
//!   `EventsBatch` built by `uplink::to_batches` (masked types only, I2),
//!   with its UUIDv7 `batch_id`.
//! - File names give the FIFO order: `<seq>[.<n>]*-<f|e>.json`. A batch
//!   replaced after a `400` / `404` / `413` gets child keys (`<seq>.0`,
//!   `<seq>.1`) so it keeps its place at the head of the queue.
//! - Bounded by `spool.max_bytes` and `spool.max_batches`: when full, a
//!   batch is dropped and counted (`dropped_batches`, `dropped_items`),
//!   by priority (phase 7, failed-login flood): findings and events each
//!   keep up to 3/4 of the bounds against the other, so a flood of events
//!   cannot evict the findings (nor findings the events); within the
//!   events, the batches holding a `signature.*` signal are dropped last,
//!   and a new batch without one is dropped rather than evict them. Within
//!   a class, the oldest batch goes first.
//! - A file that cannot be read or parsed is moved to `spool/quarantine/`
//!   (at most [`MAX_QUARANTINED`] files kept) and counted; it never crashes
//!   the agent. Its content is never logged.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use databastion_protocol::SpoolStatus;

use crate::config::SpoolConfig;
use crate::fsutil;
use crate::uplink::{MAX_BATCH_BYTES, ResultBatch};

/// Quarantined files kept for inspection.
pub(crate) const MAX_QUARANTINED: usize = 32;
/// Deepest replacement key (bounded splits).
const MAX_KEY_DEPTH: usize = 16;
/// Largest child key part (4 digits in file names).
const MAX_CHILD: u64 = 9999;
/// Largest spool file read.
const MAX_FILE_BYTES: u64 = (MAX_BATCH_BYTES as u64) * 4;

/// Position of a batch in the queue.
pub(crate) type Key = Vec<u64>;

#[derive(Debug, Clone)]
struct Entry {
    key: Key,
    findings: bool,
    /// An events batch holding a `signature.*` signal.
    signature: bool,
    bytes: u64,
    items: u64,
    created: SystemTime,
}

/// What a batch is, for the eviction priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Findings,
    /// Events without a `signature.*` signal: dropped first.
    Events,
    /// Events with a `signature.*` signal: dropped last.
    Signature,
}

impl Class {
    fn of(findings: bool, signature: bool) -> Self {
        match (findings, signature) {
            (true, _) => Self::Findings,
            (false, false) => Self::Events,
            (false, true) => Self::Signature,
        }
    }
}

impl Entry {
    fn class(&self) -> Class {
        Class::of(self.findings, self.signature)
    }
}

/// Share of the bounds (bytes, batches) findings or events keep against
/// the other when the spool is full: `SHARE_NUM / SHARE_DEN`.
const SHARE_NUM: u64 = 3;
const SHARE_DEN: u64 = 4;

/// Why a spooled file could not be read.
#[derive(Debug)]
enum ReadError {
    /// Missing (removed meanwhile): forget the entry.
    Gone,
    /// Unparseable, or refused by the file checks: quarantine.
    Corrupt,
    /// Resource error (EMFILE, ENOMEM…): retry later.
    Transient(io::Error),
}

/// Counters exported in the heartbeat.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpoolCounters {
    pub(crate) dropped_batches: u64,
    /// New batches dropped themselves when the spool was full (also in
    /// `dropped_batches`), apart from the evicted ones.
    pub(crate) rejected_batches: u64,
    pub(crate) dropped_items: u64,
    pub(crate) quarantined: u64,
}

/// The spool.
#[derive(Debug)]
pub(crate) struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    max_batches: usize,
    entries: VecDeque<Entry>,
    total: u64,
    next_seq: u64,
    pub(crate) counters: SpoolCounters,
}

fn file_name(key: &[u64], findings: bool) -> String {
    let mut name = format!("{:020}", key.first().copied().unwrap_or(0));
    for part in key.iter().skip(1) {
        name.push('.');
        name.push_str(&part.to_string());
    }
    name.push_str(if findings { "-f.json" } else { "-e.json" });
    name
}

fn parse_name(name: &str) -> Option<(Key, bool)> {
    let (stem, findings) = if let Some(s) = name.strip_suffix("-f.json") {
        (s, true)
    } else {
        (name.strip_suffix("-e.json")?, false)
    };
    let mut key = Vec::new();
    for (i, part) in stem.split('.').enumerate() {
        let ok = if i == 0 {
            part.len() == 20
        } else {
            (1..=4).contains(&part.len())
        };
        if !ok || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        key.push(part.parse().ok()?);
    }
    (key.len() <= MAX_KEY_DEPTH).then_some((key, findings))
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl Spool {
    /// Opens (creates) `<state_dir>/spool`, loads the queue, removes stale
    /// temporary files and quarantines unreadable ones.
    pub(crate) fn open(state_dir: &Path, config: &SpoolConfig) -> io::Result<Self> {
        let dir = state_dir.join("spool");
        fsutil::ensure_private_dir(&dir)?;
        fsutil::ensure_private_dir(&dir.join("quarantine"))?;
        let mut spool = Self {
            dir,
            max_bytes: config.max_bytes,
            max_batches: usize::try_from(config.max_batches).unwrap_or(usize::MAX),
            entries: VecDeque::new(),
            total: 0,
            next_seq: 0,
            counters: SpoolCounters::default(),
        };
        let mut found = Vec::new();
        for entry in fs::read_dir(&spool.dir)? {
            let entry = entry?;
            let os_name = entry.file_name();
            let Some(name) = os_name.to_str() else {
                spool.quarantine(&os_name);
                continue;
            };
            if name == "quarantine" {
                continue;
            }
            if name.starts_with('.') && name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            let Some((key, findings)) = parse_name(name) else {
                spool.quarantine(&os_name);
                continue;
            };
            match spool.read(&key, findings) {
                Ok(batch) => {
                    let created = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or_else(|_| SystemTime::now());
                    found.push(Entry {
                        key,
                        findings,
                        signature: batch.has_signature(),
                        bytes: to_u64(batch.bytes().len()),
                        items: to_u64(batch.len()),
                        created,
                    });
                }
                Err(ReadError::Corrupt) => spool.quarantine(&os_name),
                Err(ReadError::Gone) => {}
                // Transient (EMFILE, ENOMEM…): the agent cannot start
                // consistently; the caller reports the error.
                Err(ReadError::Transient(e)) => return Err(e),
            }
        }
        found.sort_by(|a, b| a.key.cmp(&b.key));
        spool.next_seq = found
            .iter()
            .filter_map(|e| e.key.first())
            .max()
            .map_or(0, |m| m.saturating_add(1));
        spool.total = found.iter().map(|e| e.bytes).sum();
        spool.entries = found.into();
        spool.make_room(0, None);
        Ok(spool)
    }

    fn path(&self, key: &[u64], findings: bool) -> PathBuf {
        self.dir.join(file_name(key, findings))
    }

    /// Reads and parses a spooled batch.
    fn read(&self, key: &[u64], findings: bool) -> Result<ResultBatch, ReadError> {
        let classify = |e: io::Error| match e.kind() {
            io::ErrorKind::NotFound => ReadError::Gone,
            // Symlink, wrong owner / mode, not a regular file.
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData => ReadError::Corrupt,
            _ => ReadError::Transient(e),
        };
        let file = fsutil::open_private(&self.path(key, findings)).map_err(classify)?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(classify)?;
        if to_u64(bytes.len()) > MAX_FILE_BYTES {
            return Err(ReadError::Corrupt);
        }
        ResultBatch::parse(findings, bytes).ok_or(ReadError::Corrupt)
    }

    /// Moves a file to `quarantine/` (by its raw OS name, so non-UTF-8 names
    /// are handled) and keeps at most [`MAX_QUARANTINED`] files there.
    fn quarantine(&mut self, name: &OsStr) {
        self.counters.quarantined += 1;
        tracing::warn!("unreadable spool file moved to quarantine");
        let qdir = self.dir.join("quarantine");
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let safe: String = name
            .to_string_lossy()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();
        let source = self.dir.join(name);
        if fs::rename(&source, qdir.join(format!("{stamp:039}-{safe}"))).is_err() {
            let _ = fs::remove_file(&source);
        }
        if let Ok(read) = fs::read_dir(&qdir) {
            let mut names: Vec<PathBuf> = read.filter_map(|e| e.ok().map(|e| e.path())).collect();
            names.sort();
            let excess = names.len().saturating_sub(MAX_QUARANTINED);
            for old in names.into_iter().take(excess) {
                let _ = fs::remove_file(old);
            }
        }
    }

    fn remove_entry(&mut self, index: usize) -> Option<Entry> {
        let entry = self.entries.remove(index)?;
        self.total = self.total.saturating_sub(entry.bytes);
        let _ = fs::remove_file(self.path(&entry.key, entry.findings));
        Some(entry)
    }

    /// Drops batches until `incoming` more bytes and one more batch of
    /// `class` fit (`None`: only enforce the bounds), by priority (see the
    /// module documentation). `false` when the new batch must be dropped
    /// instead (an events batch without a signature, when only batches
    /// that rank above it could make room).
    fn make_room(&mut self, incoming: u64, class: Option<Class>) -> bool {
        let extra = usize::from(class.is_some());
        while !self.entries.is_empty()
            && (self.entries.len() + extra > self.max_batches
                || self.total.saturating_add(incoming) > self.max_bytes)
        {
            let Some(i) = self.victim(incoming, class) else {
                return false;
            };
            if let Some(e) = self.remove_entry(i) {
                self.counters.dropped_batches += 1;
                self.counters.dropped_items += e.items;
                match e.class() {
                    Class::Findings => tracing::warn!("spool full: oldest findings batch dropped"),
                    Class::Events => tracing::warn!("spool full: oldest events batch dropped"),
                    Class::Signature => tracing::warn!(
                        "spool full: oldest events batch with a signature signal dropped"
                    ),
                }
            }
        }
        true
    }

    fn oldest(&self, class: Class) -> Option<usize> {
        self.entries.iter().position(|e| e.class() == class)
    }

    /// The batch to drop to make room for `incoming` bytes of `class`.
    fn victim(&self, incoming: u64, class: Option<Class>) -> Option<usize> {
        let events_first = || {
            self.oldest(Class::Events)
                .or_else(|| self.oldest(Class::Findings))
                .or_else(|| self.oldest(Class::Signature))
        };
        let Some(class) = class else {
            // Bounds only (a smaller configuration at startup).
            return events_first();
        };
        let own_events = class != Class::Findings;
        let (bytes, count) = self
            .entries
            .iter()
            .filter(|e| e.findings != own_events)
            .fold((0u64, 0u64), |(b, n), e| (b.saturating_add(e.bytes), n + 1));
        let share =
            |bound: u64| bound / SHARE_DEN * SHARE_NUM + bound % SHARE_DEN * SHARE_NUM / SHARE_DEN;
        let own_over = bytes.saturating_add(incoming) > share(self.max_bytes)
            || count + 1 > share(to_u64(self.max_batches));
        let own = if own_events {
            // A batch without a signature never evicts one with.
            self.oldest(Class::Events).or_else(|| {
                (class == Class::Signature)
                    .then(|| self.oldest(Class::Signature))
                    .flatten()
            })
        } else {
            self.oldest(Class::Findings)
        };
        let other = if own_events {
            self.oldest(Class::Findings)
        } else {
            self.oldest(Class::Events)
                .or_else(|| self.oldest(Class::Signature))
        };
        match (class, own_over) {
            // A plain events batch over the events' share evicts plain
            // events only; else it is dropped itself (never a signature
            // batch, never findings within their share).
            (Class::Events, true) => own,
            // Findings and signature batches over their share evict their
            // own class first, then the other (small bounds: a share of 0
            // with `max_batches` 1 must not drop every incoming batch).
            (_, true) => own.or(other),
            (_, false) => other.or(own),
        }
    }

    /// Writes a batch file (after making room). `Ok(None)`: the batch can
    /// never fit and was dropped (counted).
    fn write(&mut self, key: Key, batch: &ResultBatch) -> io::Result<Option<Entry>> {
        let items = to_u64(batch.len());
        let bytes = batch.bytes();
        let len = to_u64(bytes.len());
        if len > self.max_bytes
            || len > to_u64(MAX_BATCH_BYTES)
            || key.len() > MAX_KEY_DEPTH
            || key.iter().skip(1).any(|p| *p > MAX_CHILD)
        {
            self.counters.dropped_batches += 1;
            self.counters.dropped_items += items;
            return Ok(None);
        }
        let class = Class::of(batch.is_findings(), batch.has_signature());
        if !self.make_room(len, Some(class)) {
            self.counters.dropped_batches += 1;
            self.counters.rejected_batches += 1;
            self.counters.dropped_items += items;
            match class {
                Class::Events => tracing::warn!(
                    "spool full: new events batch dropped (the spool holds findings and events \
                     batches with a signature signal)"
                ),
                Class::Findings => tracing::warn!("spool full: new findings batch dropped"),
                Class::Signature => {
                    tracing::warn!("spool full: new events batch with a signature signal dropped")
                }
            }
            return Ok(None);
        }
        fsutil::write_private_atomic(&self.path(&key, batch.is_findings()), bytes)?;
        self.total += len;
        Ok(Some(Entry {
            key,
            findings: batch.is_findings(),
            signature: batch.has_signature(),
            bytes: len,
            items,
            created: SystemTime::now(),
        }))
    }

    /// Inserts an entry at its key position (entries stay sorted by key).
    fn insert_sorted(&mut self, entry: Entry) {
        let at = self.entries.partition_point(|e| e.key < entry.key);
        self.entries.insert(at, entry);
    }

    /// Appends a batch at the tail.
    pub(crate) fn push(&mut self, batch: &ResultBatch) -> io::Result<()> {
        let key = vec![self.next_seq];
        self.next_seq = self.next_seq.saturating_add(1);
        if let Some(entry) = self.write(key, batch)? {
            self.entries.push_back(entry);
        }
        Ok(())
    }

    /// The batch at the head of the queue. Corrupt files are quarantined
    /// and skipped; a transient read error (EMFILE, ENOMEM…) leaves the
    /// queue untouched and returns `None` (retried later).
    #[cfg(test)]
    pub(crate) fn front(&mut self) -> Option<(Key, ResultBatch)> {
        self.front_where(|_| true)
    }

    /// The oldest batch whose endpoint is accepted by `endpoint` (called
    /// with `true` for `/findings`, `false` for `/events`). A parked
    /// endpoint (`501`) is skipped without reordering: each endpoint stays
    /// FIFO. Corrupt files are quarantined and skipped; a transient read
    /// error (EMFILE, ENOMEM…) leaves the queue untouched and returns `None`
    /// (retried later).
    #[cfg(test)]
    pub(crate) fn front_where(
        &mut self,
        endpoint: impl FnMut(bool) -> bool,
    ) -> Option<(Key, ResultBatch)> {
        self.front_sendable(endpoint, |_| true)
    }

    /// As [`front_where`](Self::front_where), also skipping (and keeping)
    /// the batches `sendable` refuses: those carrying a value of an engine
    /// the console has not accepted (ADR-0039 decision 8) are held until it
    /// does. Holding needs the batch read; it only happens to batches of
    /// such engines, which are rare (the console only gives jobs for the
    /// targets it was told about).
    pub(crate) fn front_sendable(
        &mut self,
        mut endpoint: impl FnMut(bool) -> bool,
        mut sendable: impl FnMut(&ResultBatch) -> bool,
    ) -> Option<(Key, ResultBatch)> {
        let mut index = 0;
        loop {
            let entry = self.entries.get(index)?.clone();
            if !endpoint(entry.findings) {
                index += 1;
                continue;
            }
            match self.read(&entry.key, entry.findings) {
                Ok(batch) if !sendable(&batch) => index += 1,
                Ok(batch) => return Some((entry.key, batch)),
                Err(ReadError::Transient(e)) => {
                    tracing::warn!(kind = %e.kind(), "spool read failed; will retry");
                    return None;
                }
                Err(err) => {
                    self.entries.remove(index);
                    self.total = self.total.saturating_sub(entry.bytes);
                    if matches!(err, ReadError::Corrupt) {
                        self.quarantine(OsStr::new(&file_name(&entry.key, entry.findings)));
                    }
                }
            }
        }
    }

    fn position(&self, key: &[u64]) -> Option<usize> {
        self.entries.iter().position(|e| e.key == key)
    }

    /// Removes a batch after it was accepted (it may already have been
    /// evicted by `make_room`).
    pub(crate) fn remove(&mut self, key: &[u64]) {
        if let Some(i) = self.position(key) {
            self.remove_entry(i);
        }
    }

    /// Drops a rejected batch and counts it.
    pub(crate) fn drop_batch(&mut self, key: &[u64]) {
        if let Some(e) = self.position(key).and_then(|i| self.remove_entry(i)) {
            self.counters.dropped_batches += 1;
            self.counters.dropped_items += e.items;
        }
    }

    /// Replaces a batch by `replacements` (new `batch_id`s) at the same
    /// place in the queue; `dropped_items` counts the items left out, only
    /// once every replacement is written. Child keys never reuse a key
    /// already in the queue (e.g. left by a crash during an earlier
    /// replacement). The old file is removed last: a crash in between may
    /// resend the old `batch_id` (idempotent on the console).
    pub(crate) fn replace(
        &mut self,
        key: &[u64],
        replacements: &[ResultBatch],
        dropped_items: u64,
    ) -> io::Result<()> {
        let Some(index) = self.position(key) else {
            return Ok(()); // evicted meanwhile
        };
        // Out of the index first, so `make_room` cannot evict it while its
        // replacements are written; its file stays until the end.
        let Some(old) = self.entries.remove(index) else {
            return Ok(());
        };
        self.total = self.total.saturating_sub(old.bytes);
        let first_free = self
            .entries
            .iter()
            .filter(|e| e.key.len() == key.len() + 1 && e.key.starts_with(key))
            .filter_map(|e| e.key.last().copied())
            .max()
            .map_or(0, |m| m + 1);
        let mut written = Vec::new();
        for (n, batch) in replacements.iter().enumerate() {
            let mut child = key.to_vec();
            child.push(first_free + to_u64(n));
            match self.write(child, batch) {
                Ok(Some(e)) => written.push(e),
                Ok(None) => {}
                Err(e) => {
                    // Roll back: remove the new files, restore the old entry.
                    for w in written {
                        let _ = fs::remove_file(self.path(&w.key, w.findings));
                        self.total = self.total.saturating_sub(w.bytes);
                    }
                    self.total += old.bytes;
                    self.insert_sorted(old);
                    return Err(e);
                }
            }
        }
        self.counters.dropped_items += dropped_items;
        for e in written {
            self.insert_sorted(e);
        }
        let _ = fs::remove_file(self.path(&old.key, old.findings));
        Ok(())
    }

    /// Heartbeat `spool` section.
    pub(crate) fn status(&self) -> SpoolStatus {
        let count = crate::sanitize::clamped_count;
        let oldest = self.entries.iter().map(|e| e.created).min().map(|t| {
            SystemTime::now()
                .duration_since(t)
                .map_or(0, |d| d.as_secs())
        });
        SpoolStatus {
            batches: count(to_u64(self.entries.len())),
            bytes: count(self.total),
            dropped_batches: Some(count(self.counters.dropped_batches)),
            dropped_items: Some(count(self.counters.dropped_items)),
            max_bytes: count(self.max_bytes),
            oldest_age_s: oldest.map(count),
        }
    }

    /// Sequence number the next [`push`](Self::push) gets. Batches pushed
    /// between two readings of it have their first key part in that range;
    /// their replacements (splits, resends) keep it.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Findings batches still spooled whose first key part is in `seqs`
    /// (see [`next_seq`](Self::next_seq)).
    pub(crate) fn findings_pending(&self, seqs: &std::ops::Range<u64>) -> usize {
        self.entries
            .iter()
            .filter(|e| e.findings && e.key.first().is_some_and(|s| seqs.contains(s)))
            .count()
    }

    /// Number of spooled batches.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[path = "spool_tests.rs"]
pub(crate) mod tests;
