//! Audit state shared by `check()`, Discovery and the Audit stream of a
//! target (ADR-0052 decision 8): the patterns learned by the last walk of
//! each database (with the scan generation, persisted by the stream
//! through the core's counters file so a restart keeps them), the proof
//! that a slow-log or command-log entry was read in the last 24 h (the
//! Limited level), entries lost to ring-buffer overruns
//! (`audit.records_dropped`), the agent's own denials, and whether a
//! stream runs.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use databastion_classifiers::keys::LearnedPatterns;
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::SharedOwnUsage;

/// The Limited proof and the dropped count last this long.
pub(crate) const FRESHNESS: Duration = Duration::from_secs(24 * 3600);
/// Largest learned-patterns file (the core's counters bound).
const MAX_FILE: usize = 2 * 1024 * 1024 - 4096;

/// The learned patterns of a target.
#[derive(Debug, Default, Clone)]
pub(crate) struct Learned {
    /// Scan generation: bumped by every walk that changes a set.
    pub(crate) generation: u64,
    pub(crate) dbs: BTreeMap<u16, Arc<LearnedPatterns>>,
}

impl Learned {
    /// The persisted form: `v1`, `gen <n>`, then per database `db <index>`
    /// followed by its patterns, one per line (contract `KeyPattern`s: no
    /// line break, no key-name text). Cut at the file bound.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = format!("v1\ngen {}\n", self.generation).into_bytes();
        for (db, set) in &self.dbs {
            let head = format!("db {db}\n");
            if out.len() + head.len() > MAX_FILE {
                break;
            }
            out.extend_from_slice(head.as_bytes());
            for p in set.patterns() {
                if out.len() + p.len() + 1 > MAX_FILE {
                    break;
                }
                out.extend_from_slice(p.as_bytes());
                out.push(b'\n');
            }
        }
        out
    }

    /// Reads [`Self::encode`]'s form; every pattern goes through the
    /// contract gate again (`LearnedPatterns::new`). `None` when not
    /// understood.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        if lines.next()? != "v1" {
            return None;
        }
        let generation = lines.next()?.strip_prefix("gen ")?.parse().ok()?;
        let mut dbs: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
        let mut current: Option<u16> = None;
        for l in lines {
            if let Some(db) = l.strip_prefix("db ") {
                let db = db.parse().ok()?;
                dbs.entry(db).or_default();
                current = Some(db);
            } else if let Some(db) = current {
                dbs.entry(db).or_default().push(l);
            }
        }
        Some(Self {
            generation,
            dbs: dbs
                .into_iter()
                .map(|(db, p)| (db, Arc::new(LearnedPatterns::new(p))))
                .collect(),
        })
    }
}

/// Per-target Audit facts.
#[derive(Default)]
pub(crate) struct Shared {
    learned: Mutex<HashMap<String, Learned>>,
    slow_record: Mutex<HashMap<String, Instant>>,
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
    own_denials: Mutex<HashMap<String, (u64, Instant)>>,
    running: Mutex<HashMap<String, usize>>,
    own_usage: Mutex<HashMap<String, SharedOwnUsage>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bump(m: &Mutex<HashMap<String, (u64, Instant)>>, target_id: &str, n: u64) {
    let mut map = lock(m);
    let e = map
        .entry(target_id.to_owned())
        .or_insert((0, Instant::now()));
    if e.1.elapsed() >= FRESHNESS {
        *e = (0, Instant::now());
    }
    e.0 = e.0.saturating_add(n);
}

fn fresh(m: &Mutex<HashMap<String, (u64, Instant)>>, target_id: &str) -> u64 {
    lock(m)
        .get(target_id)
        .filter(|(_, at)| at.elapsed() < FRESHNESS)
        .map_or(0, |(n, _)| *n)
}

/// A running stream; unregistered on drop.
pub(crate) struct Running<'a> {
    shared: &'a Shared,
    target: String,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut map = lock(&self.shared.running);
        if let Some(n) = map.get_mut(&self.target) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.target);
            }
        }
    }
}

impl Shared {
    /// Records the patterns of one database walk (Discovery). A complete
    /// walk replaces the database's set; a walk stopped early only fills
    /// a database without one (its patterns are still gated, but fewer).
    pub(crate) fn learn(&self, target_id: &str, db: u16, patterns: &[String], complete: bool) {
        let mut map = lock(&self.learned);
        let l = map.entry(target_id.to_owned()).or_default();
        if !complete && l.dbs.contains_key(&db) {
            return;
        }
        l.dbs.insert(
            db,
            Arc::new(LearnedPatterns::new(patterns.iter().map(String::as_str))),
        );
        l.generation = l.generation.saturating_add(1);
    }

    /// The learned patterns of a target.
    pub(crate) fn learned(&self, target_id: &str) -> Learned {
        lock(&self.learned)
            .get(target_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Loads the persisted patterns when memory holds an older generation
    /// (an agent restart), else saves memory's when newer than the file.
    pub(crate) fn sync_learned(
        &self,
        target_id: &str,
        store: Option<&CursorStore>,
        saved: &mut u64,
    ) {
        let Some(store) = store else { return };
        let mut map = lock(&self.learned);
        let mem = map.entry(target_id.to_owned()).or_default();
        if *saved == 0 && mem.generation == 0 {
            match store.load() {
                Ok(Some(bytes)) => {
                    if let Some(l) = Learned::decode(&bytes) {
                        *saved = l.generation;
                        *mem = l;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Redis / Valkey: learned patterns not readable")
                }
            }
            return;
        }
        if mem.generation > *saved {
            let bytes = mem.encode();
            let generation = mem.generation;
            drop(map);
            match store.save(&bytes) {
                Ok(()) => *saved = generation,
                Err(e) => tracing::warn!(error = %e, "Redis / Valkey: learned patterns not saved"),
            }
        }
    }

    pub(crate) fn note_slow_record(&self, target_id: &str) {
        lock(&self.slow_record).insert(target_id.to_owned(), Instant::now());
    }

    /// A slow-log or command-log entry was read in the last 24 h.
    pub(crate) fn recent_slow_record(&self, target_id: &str) -> bool {
        lock(&self.slow_record)
            .get(target_id)
            .is_some_and(|t| t.elapsed() < FRESHNESS)
    }

    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        if n > 0 {
            bump(&self.dropped, target_id, n);
        }
    }

    pub(crate) fn dropped(&self, target_id: &str) -> u64 {
        fresh(&self.dropped, target_id)
    }

    /// An `ACL LOG` denial of the agent's user from one of its own
    /// connections: a declaration that does not match the ACL (reported
    /// by `check()`, never as an event; H3).
    pub(crate) fn note_own_denial(&self, target_id: &str, n: u64) {
        bump(&self.own_denials, target_id, n);
    }

    pub(crate) fn own_denials(&self, target_id: &str) -> u64 {
        fresh(&self.own_denials, target_id)
    }

    pub(crate) fn started(&self, target_id: &str) -> Running<'_> {
        *lock(&self.running).entry(target_id.to_owned()).or_default() += 1;
        Running {
            shared: self,
            target: target_id.to_owned(),
        }
    }

    pub(crate) fn is_running(&self, target_id: &str) -> bool {
        lock(&self.running).contains_key(target_id)
    }

    /// The agent's own-read counters of a target (outlive streams).
    pub(crate) fn own_usage(&self, target_id: &str) -> SharedOwnUsage {
        Arc::clone(
            lock(&self.own_usage)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learned_patterns_round_trip_through_the_gate() {
        let s = Shared::default();
        s.learn(
            "t",
            0,
            &["session:*".to_owned(), "user:*:email".to_owned()],
            true,
        );
        s.learn(
            "t",
            3,
            &["cart:*".to_owned(), "user:123456789".to_owned()],
            false,
        );
        // A partial walk does not replace a complete one.
        s.learn("t", 0, &["other:*".to_owned()], false);
        let l = s.learned("t");
        assert_eq!(l.generation, 2);
        let back = Learned::decode(&l.encode()).unwrap();
        assert_eq!(back.generation, 2);
        assert_eq!(back.dbs[&0].patterns(), ["session:*", "user:*:email"]);
        // A pattern that is not a contract `KeyPattern` never comes back.
        assert_eq!(back.dbs[&3].patterns(), ["cart:*"]);
        assert!(Learned::decode(b"v2\ngen 1\n").is_none());
        let tampered = b"v1\ngen 1\ndb 0\nuser:jane.doe@example.com\n";
        assert!(Learned::decode(tampered).unwrap().dbs[&0].is_empty());
    }
}
