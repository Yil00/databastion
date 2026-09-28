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
//! - Bounded by `spool.max_bytes` and `spool.max_batches`: when full, the
//!   oldest batches are dropped first and counted (`dropped_batches`,
//!   `dropped_items`).
//! - A file that cannot be read or parsed is moved to `spool/quarantine/`
//!   (at most [`MAX_QUARANTINED`] files kept) and counted; it never crashes
//!   the agent. Its content is never logged.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use databastion_protocol::{Count, SpoolStatus};

use crate::config::SpoolConfig;
use crate::fsutil;
use crate::uplink::{MAX_BATCH_BYTES, ResultBatch};

/// Quarantined files kept for inspection.
pub(crate) const MAX_QUARANTINED: usize = 32;
/// Deepest replacement key (bounded splits).
const MAX_KEY_DEPTH: usize = 16;
/// Largest spool file read.
const MAX_FILE_BYTES: u64 = (MAX_BATCH_BYTES as u64) * 4;

/// Position of a batch in the queue.
pub(crate) type Key = Vec<u64>;

#[derive(Debug, Clone)]
struct Entry {
    key: Key,
    findings: bool,
    bytes: u64,
    items: u64,
    created: SystemTime,
}

/// Counters exported in the heartbeat.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpoolCounters {
    pub(crate) dropped_batches: u64,
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
            part.len() == 1
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
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                spool.quarantine(&entry.file_name().to_string_lossy());
                continue;
            };
            if name == "quarantine" {
                continue;
            }
            if name.starts_with('.') && name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            match parse_name(&name) {
                Some((key, findings)) => match spool.read(&key, findings) {
                    Some((batch, bytes)) => {
                        let created = entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or_else(|_| SystemTime::now());
                        found.push(Entry {
                            key,
                            findings,
                            bytes: to_u64(bytes),
                            items: to_u64(batch.len()),
                            created,
                        });
                    }
                    None => spool.quarantine(&name),
                },
                None => spool.quarantine(&name),
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
        spool.make_room(0);
        Ok(spool)
    }

    fn path(&self, key: &[u64], findings: bool) -> PathBuf {
        self.dir.join(file_name(key, findings))
    }

    /// Reads and parses a spooled batch; `None` if unreadable or invalid.
    fn read(&self, key: &[u64], findings: bool) -> Option<(ResultBatch, usize)> {
        let file = fsutil::open_private(&self.path(key, findings)).ok()?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
        if to_u64(bytes.len()) > MAX_FILE_BYTES {
            return None;
        }
        let batch = ResultBatch::parse(findings, &bytes)?;
        (batch.len() > 0).then_some((batch, bytes.len()))
    }

    fn quarantine(&mut self, name: &str) {
        self.counters.quarantined += 1;
        tracing::warn!("unreadable spool file moved to quarantine");
        let qdir = self.dir.join("quarantine");
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let safe: String = name
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
        if fs::rename(self.dir.join(name), qdir.join(format!("{stamp}-{safe}"))).is_err() {
            let _ = fs::remove_file(self.dir.join(name));
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

    /// Drops the oldest batches until `incoming` more bytes and one more
    /// batch fit (`incoming == 0`: only enforce the bounds).
    fn make_room(&mut self, incoming: u64) {
        let extra = usize::from(incoming > 0);
        while !self.entries.is_empty()
            && (self.entries.len() + extra > self.max_batches
                || self.total.saturating_add(incoming) > self.max_bytes)
        {
            if let Some(e) = self.remove_entry(0) {
                self.counters.dropped_batches += 1;
                self.counters.dropped_items += e.items;
                tracing::warn!("spool full: oldest batch dropped");
            }
        }
    }

    fn write(&mut self, key: Key, batch: &ResultBatch) -> io::Result<Option<Entry>> {
        let items = to_u64(batch.len());
        let bytes = batch
            .to_bytes()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "batch serialization"))?;
        let len = to_u64(bytes.len());
        if len > self.max_bytes || len > to_u64(MAX_BATCH_BYTES) || key.len() > MAX_KEY_DEPTH {
            self.counters.dropped_batches += 1;
            self.counters.dropped_items += items;
            return Ok(None);
        }
        self.make_room(len);
        fsutil::write_private_atomic(&self.path(&key, batch.is_findings()), &bytes)?;
        self.total += len;
        Ok(Some(Entry {
            key,
            findings: batch.is_findings(),
            bytes: len,
            items,
            created: SystemTime::now(),
        }))
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

    /// The batch at the head of the queue. Unreadable files are quarantined
    /// and skipped.
    pub(crate) fn front(&mut self) -> Option<(Key, ResultBatch)> {
        loop {
            let entry = self.entries.front()?.clone();
            if let Some((batch, _)) = self.read(&entry.key, entry.findings) {
                return Some((entry.key, batch));
            }
            self.entries.pop_front();
            self.total = self.total.saturating_sub(entry.bytes);
            self.quarantine(&file_name(&entry.key, entry.findings));
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
    /// place in the queue; `dropped_items` counts the items left out. The
    /// new files are written before the old one is removed.
    pub(crate) fn replace(
        &mut self,
        key: &[u64],
        replacements: &[ResultBatch],
        dropped_items: u64,
    ) -> io::Result<()> {
        let Some(index) = self.position(key) else {
            return Ok(()); // evicted meanwhile
        };
        self.counters.dropped_items += dropped_items;
        let mut new_entries = Vec::new();
        for (n, batch) in replacements.iter().enumerate() {
            let mut child = key.to_vec();
            child.push(to_u64(n));
            if let Some(e) = self.write(child, batch)? {
                new_entries.push(e);
            }
        }
        // `write` may have evicted entries: find the old one again.
        if let Some(i) = self.position(key) {
            if let Some(old) = self.entries.remove(i) {
                self.total = self.total.saturating_sub(old.bytes);
                let _ = fs::remove_file(self.path(&old.key, old.findings));
            }
        }
        let at = index.min(self.entries.len());
        for (offset, e) in new_entries.into_iter().enumerate() {
            let at = (at + offset).min(self.entries.len());
            self.entries.insert(at, e);
        }
        Ok(())
    }

    /// Heartbeat `spool` section.
    pub(crate) fn status(&self) -> SpoolStatus {
        let count = |n: u64| Count(i64::try_from(n).unwrap_or(i64::MAX));
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

    /// Number of spooled batches.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[path = "spool_tests.rs"]
pub(crate) mod tests;
