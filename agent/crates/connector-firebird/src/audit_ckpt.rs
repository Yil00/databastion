//! The Firebird Audit stream's parser checkpoint on disk (ADR-0060 R25
//! items 7 and 9, R39 (a)): where it is written, what it is bound to, and
//! the deduplication of the events already sent.
//!
//! **Files** (both under `<state_dir>/audit/`, `0600`, written atomically
//! through the core's `CursorStore`, refused unless private regular files
//! of the agent user, never followed through a symlink):
//! - `<target>.firebird_audit_trace.checkpoint` (at most 14 MiB): the log
//!   file identity and offset it is bound to, the parser state as it was
//!   at that offset ([`crate::stream`]'s `export`), and the deduplication
//!   positions;
//! - `<target>.firebird_ledger.counters` (at most 2 MiB): the agent's own
//!   attachments and execution credits ([`crate::own`]), written at every
//!   checkpoint and at the end of every own session.
//!
//! Together they stay within R25 item 9's one 16 MiB cap. Both are sealed
//! with a keyed tag under the agent key's audit sub-key; a file that does
//! not verify is not used.
//!
//! **The order of writes** at each commit: the ledger, then the
//! checkpoint, then the tailer's cursor at the checkpoint's offset. A
//! restart uses the checkpoint only when the tailer resumed from exactly
//! its file and offset with fingerprints verified under the current key
//! (`Tailer::take_resumed`); a crash between two writes, a rotation or
//! rewrite while stopped, a reset cursor: the checkpoint is not used, and
//! the stream starts with no state as before (fail closed).
//!
//! **Deduplication by position** (R25 item 7, L11). Each event carries
//! the position it is attributed to. A position is recorded as sent only
//! once every event attributed to it is durably handled by the core
//! (`EventSink::durable`: spooled, or dropped by the reporting filter),
//! none of them still held, so all the events of a position are marked
//! sent or none is. A checkpoint lists the positions recorded since the
//! state it holds; a restored stream emits nothing for them. Past the cap,
//! the oldest positions are dropped first (their events are sent again: an
//! accepted over-reporting, never a loss).
//!
//! **What is trusted** from the files: nothing that does not verify and
//! decode within every bound, and is not bound to the current server run,
//! the current declared databases and account, and the exact resumed
//! position. The files are the agent's own state, like its spool and
//! cursors: whoever can write them can also read the agent key.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::LocalTagKey;
use databastion_core::audit::CursorStore;
use databastion_core::audit::tail::Resumed;

use crate::ckpt::{Bad, Reader, Refused, Writer};
use crate::own::{Ledger, Saved};
use crate::stream::{DKey, Machine};

/// The checkpoint file's name (with the target id and `.checkpoint`).
pub(crate) const CHECKPOINT: &str = "firebird_audit_trace";
/// The persisted ledger's name (with the target id and `.counters`).
pub(crate) const LEDGER: &str = "firebird_ledger";
/// The checkpoint's magic.
pub(crate) const MAGIC: &[u8; 4] = b"FBCK";
/// Deduplication positions kept at most.
const MAX_DEDUP: usize = 262_144;
/// One position, encoded.
const DKEY_BYTES: usize = 8 + 8 + 8 + 1;
/// Checkpoints written at most this often (between two writes, the cursor
/// stays at the last one's offset).
const WRITE_EVERY: Duration = Duration::from_secs(1);
/// The envelope's own bytes.
const ENVELOPE: usize = 4 + 2 + 4 + 32;

/// A checkpoint body, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Body {
    pub(crate) file: (u64, u64),
    pub(crate) pos: u64,
    pub(crate) machine: Vec<u8>,
    pub(crate) dedup: Vec<DKey>,
}

impl Body {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.file.0);
        w.u64(self.file.1);
        w.u64(self.pos);
        w.len(self.machine.len());
        w.buf.extend_from_slice(&self.machine);
        w.len(self.dedup.len());
        for k in &self.dedup {
            w.u64(k.file.0);
            w.u64(k.file.1);
            w.u64(k.off);
            w.bool(k.group);
        }
        w.buf
    }

    /// Strict, bounded (the fuzz target `firebird_checkpoint`).
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Bad> {
        let mut r = Reader::new(body);
        let file = (r.u64()?, r.u64()?);
        let pos = r.u64()?;
        let n = r.len(databastion_core::audit::MAX_CHECKPOINT_BYTES, 1)?;
        let machine = r.bytes(n)?.to_vec();
        let n = r.len(MAX_DEDUP, DKEY_BYTES)?;
        let mut dedup = Vec::with_capacity(n);
        let mut seen = HashSet::with_capacity(n);
        for _ in 0..n {
            let k = DKey {
                file: (r.u64()?, r.u64()?),
                off: r.u64()?,
                group: r.bool()?,
            };
            if !seen.insert(k) {
                return Err(Bad);
            }
            dedup.push(k);
        }
        r.done()?;
        Ok(Self {
            file,
            pos,
            machine,
            dedup,
        })
    }

    fn size(machine: usize, dedup: usize) -> usize {
        ENVELOPE + 24 + 4 + machine + 4 + dedup * DKEY_BYTES
    }
}

/// What was loaded at the stream's start, waiting for the position the
/// tailer resumes from.
struct Loaded {
    body: Body,
    ledger: Option<Saved>,
}

/// The last checkpoint written.
struct Written {
    file: (u64, u64),
    pos: u64,
    step: u64,
    at: Instant,
}

/// A checkpoint taken, written once the core has every event emitted
/// before it durably.
struct Pending {
    file: (u64, u64),
    pos: u64,
    machine: Vec<u8>,
    step: u64,
    /// The sink's count when it was taken.
    ticket: u64,
    /// The pending groups' first positions then.
    firsts: HashSet<u64>,
}

/// Counters of the checkpoint, for the tests and the local detail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CkptCounts {
    /// Checkpoints restored at a start.
    pub(crate) restored: u64,
    /// Checkpoints found and not used (refused or not bound to the resumed
    /// position).
    pub(crate) refused: u64,
    /// Checkpoints written.
    pub(crate) written: u64,
    /// Commits with no checkpoint possible (no state to write, nor an
    /// earlier one in the open file): the position held back as without a
    /// checkpoint.
    pub(crate) fallback: u64,
    /// Deduplication positions dropped for the cap (their events would be
    /// sent again after a restart).
    pub(crate) dedup_dropped: u64,
    /// Pending groups ended for the cap (R25 item 9).
    pub(crate) shed: u64,
}

/// Where the cursor is committed after a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    /// At this file and offset: the checkpoint written there.
    At((u64, u64), u64),
    /// No checkpoint: the position is held back as without one, and not
    /// past this offset of the open file (the first event the core does not
    /// have durably yet, or the checkpoint taken and not yet written), so a
    /// restart re-reads and sends it again rather than losing it.
    Fallback(Option<u64>),
}

/// The stream's checkpoint.
pub(crate) struct Checkpointer {
    store: CursorStore,
    key: Arc<LocalTagKey>,
    ledger: Arc<Ledger>,
    loaded: Option<Loaded>,
    /// Restored positions, until the stream passes them.
    restored: HashSet<DKey>,
    /// Positions emitted, waiting until the core has them durably: the
    /// ticket (`EventSink::submitted` after their last event) and step.
    waiting: HashMap<DKey, (u64, u64)>,
    /// Positions durably sent, with their step.
    durable: HashMap<DKey, u64>,
    dirty: bool,
    last: Option<Written>,
    pending: Option<Pending>,
    /// After pending groups were ended for the cap: no checkpoint without
    /// them until their outputs are durable (L11).
    shed_until: Option<u64>,
    /// The groups' state budget asked for by the last commit.
    shed_target: Option<usize>,
    pub(crate) counts: CkptCounts,
    /// [`WRITE_EVERY`] (tests: shorter).
    every: Duration,
    /// The core's checkpoint file bound (tests: smaller).
    cap: usize,
}

impl Checkpointer {
    /// The stream's checkpoint, loaded (and the ledger's store attached):
    /// `None` without a state directory or the agent key's sub-key (the
    /// stream then holds its position back and re-sends, as before).
    pub(crate) fn open(
        store: Option<CursorStore>,
        ledger_store: Option<CursorStore>,
        ledger: &Arc<Ledger>,
    ) -> Option<Self> {
        let store = store?;
        let key = store.local_tag_key()?;
        let mut counts = CkptCounts::default();
        let loaded = match store.load() {
            Ok(Some(bytes)) => match crate::ckpt::open(&key, MAGIC, &bytes)
                .and_then(|b| Body::decode(b).map_err(|_| Refused::Body))
            {
                Ok(body) => Some(body),
                Err(r) => {
                    counts.refused += 1;
                    tracing::warn!(
                        reason = r.as_str(),
                        "Firebird parser checkpoint not used; the stream starts with no state"
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                counts.refused += 1;
                tracing::warn!(
                    error = %e,
                    "Firebird parser checkpoint not readable; the stream starts with no state"
                );
                None
            }
        };
        let saved = ledger_store.as_ref().and_then(|s| match s.load() {
            Ok(Some(bytes)) => crate::ckpt::open(&key, crate::own::MAGIC, &bytes)
                .ok()
                .and_then(|b| Saved::decode(b).ok()),
            _ => None,
        });
        if let Some(s) = ledger_store {
            ledger.attach_store(s, Arc::clone(&key));
        }
        Some(Self {
            store,
            key,
            ledger: Arc::clone(ledger),
            loaded: loaded.map(|body| Loaded {
                body,
                ledger: saved,
            }),
            restored: HashSet::new(),
            waiting: HashMap::new(),
            durable: HashMap::new(),
            dirty: false,
            last: None,
            pending: None,
            shed_until: None,
            shed_target: None,
            counts,
            every: WRITE_EVERY,
            cap: databastion_core::audit::MAX_CHECKPOINT_BYTES,
        })
    }

    /// Test support: the write interval and the size cap.
    #[cfg(test)]
    pub(crate) fn tune_for_tests(&mut self, every: Duration, cap: usize) {
        self.every = every;
        self.cap = cap;
    }

    /// The agent key's sub-key (for [`Machine::enable_checkpoint`]).
    pub(crate) fn key(&self) -> Arc<LocalTagKey> {
        Arc::clone(&self.key)
    }

    /// The tailer opened its file (`resumed`: the saved position it resumed
    /// from, `Tailer::take_resumed`): the loaded checkpoint is restored into
    /// `m` when it is bound to exactly that position, verified; otherwise it
    /// is not used. Once, before the first record is handed.
    pub(crate) fn on_open(&mut self, resumed: Option<Resumed>, m: &mut Machine, now: Instant) {
        let Some(l) = self.loaded.take() else {
            return;
        };
        let bound =
            resumed.is_some_and(|r| r.verified && r.file == l.body.file && r.offset == l.body.pos);
        let result = if bound {
            m.import(&l.body.machine, now)
        } else {
            Err(Refused::Position)
        };
        match result {
            Ok(()) => {
                m.clear_invalidations();
                let attaches = m.attaches();
                let credits = l.ledger.map_or(0, |s| {
                    self.ledger.restore(s, &attaches, (l.body.file, l.body.pos))
                });
                self.restored = l.body.dedup.iter().copied().collect();
                m.set_suppress(self.restored.clone());
                self.counts.restored += 1;
                // The restored state is the last checkpoint until a new one.
                self.last = Some(Written {
                    file: l.body.file,
                    pos: l.body.pos,
                    step: 0,
                    // The first commit after a restore is not throttled.
                    at: now.checked_sub(self.every).unwrap_or(now),
                });
                tracing::info!(
                    credits,
                    positions = self.restored.len(),
                    "Firebird parser checkpoint restored"
                );
            }
            Err(r) => {
                self.counts.refused += 1;
                tracing::warn!(
                    reason = r.as_str(),
                    "Firebird parser checkpoint not used; the stream starts with no state"
                );
            }
        }
    }

    /// The events of a delivery, handed to the core: `sent` gives, per
    /// event, its position, the sink's count after it and its step. A
    /// position some of whose events are still held (`held`) is not
    /// recorded; one emitted again is durable again only with its new
    /// events. `suppressed`: positions not emitted again (still sent).
    pub(crate) fn sent(
        &mut self,
        sent: &[(Option<DKey>, u64, u64)],
        held: &HashSet<DKey>,
        suppressed: Vec<(DKey, u64)>,
    ) {
        let mut last: HashMap<DKey, (u64, u64)> = HashMap::new();
        for (k, ticket, step) in sent {
            if let Some(k) = k {
                let e = last.entry(*k).or_insert((*ticket, *step));
                e.0 = e.0.max(*ticket);
                e.1 = e.1.max(*step);
            }
        }
        for (k, v) in last {
            self.durable.remove(&k);
            self.restored.remove(&k);
            if held.contains(&k) {
                self.waiting.remove(&k);
            } else {
                self.waiting.insert(k, v);
            }
        }
        for (k, step) in suppressed {
            self.durable.insert(k, step);
            self.dirty = true;
        }
    }

    /// Records the positions whose events the core now has durably
    /// (`durable`: `EventSink::durable`; `None` after a failed flush:
    /// nothing is recorded).
    pub(crate) fn settle(&mut self, durable: Option<u64>) {
        let Some(d) = durable else {
            return;
        };
        let done: Vec<DKey> = self
            .waiting
            .iter()
            .filter(|(_, (t, _))| *t <= d)
            .map(|(k, _)| *k)
            .collect();
        for k in done {
            if let Some((_, step)) = self.waiting.remove(&k) {
                self.durable.insert(k, step);
                self.dirty = true;
            }
        }
        if self.shed_until.is_some_and(|t| t <= d) {
            self.shed_until = None;
        }
    }

    /// Pending groups were ended for the cap: their outputs are the sink's
    /// events up to `ticket`.
    pub(crate) fn shed(&mut self, ticket: u64, n: usize) {
        self.counts.shed += u64::try_from(n).unwrap_or(u64::MAX);
        self.shed_until = Some(self.shed_until.unwrap_or(0).max(ticket));
    }

    /// The groups' state budget the last commit asked for (R25 item 9,
    /// first step), once.
    pub(crate) fn take_shed_target(&mut self) -> Option<usize> {
        self.shed_target.take()
    }

    /// Takes a checkpoint of the state of `m` at `live` (the read position,
    /// when the state is that of it: the record in progress or the end
    /// read), or the snapshot of the current hold, and writes it once every
    /// event emitted before it is durably handled by the core (`submitted`
    /// and `durable`: the sink's counts): the checkpoint's position never
    /// passes an event the core could still lose, so a crash re-reads it.
    /// Returns where the cursor goes: the last checkpoint written in the
    /// open file (`open`), or, with none, the held-back position.
    pub(crate) fn commit(
        &mut self,
        m: &Machine,
        live: Option<((u64, u64), u64)>,
        open: Option<(u64, u64)>,
        sink: (u64, Option<u64>),
        now: Instant,
    ) -> Commit {
        if self.loaded.is_some() {
            // Not yet bound to the position the tailer resumes from: the
            // loaded file is kept, nothing written.
            return Commit::Fallback(None);
        }
        let (submitted, durable) = sink;
        if self.pending.as_ref().is_some_and(|p| Some(p.file) != open) {
            self.pending = None;
        }
        let throttled = self
            .last
            .as_ref()
            .is_some_and(|l| now.duration_since(l.at) < self.every);
        if self.pending.is_none() && self.shed_until.is_none() && !throttled {
            self.pending = self.candidate(m, live, open, submitted, now);
        }
        let ready = self
            .pending
            .as_ref()
            .is_some_and(|p| durable.is_some_and(|d| d >= p.ticket));
        if ready && let Some(p) = self.pending.take() {
            let unchanged = self
                .last
                .as_ref()
                .is_some_and(|l| l.file == p.file && l.pos == p.pos && l.step == p.step);
            if !(unchanged && !self.dirty) {
                self.write(p, now);
            }
        }
        match self.last.as_ref().filter(|l| Some(l.file) == open) {
            Some(l) => Commit::At(l.file, l.pos),
            None => self.fallback(open),
        }
    }

    /// A checkpoint of the state now, if one can be taken.
    fn candidate(
        &mut self,
        m: &Machine,
        live: Option<((u64, u64), u64)>,
        open: Option<(u64, u64)>,
        submitted: u64,
        now: Instant,
    ) -> Option<Pending> {
        let (file, pos, machine, step) = if m.checkpointable() {
            let (f, p) = live.filter(|(f, _)| Some(*f) == open)?;
            (f, p, m.export(now)?, m.step())
        } else if m.blockless_pending() {
            // A snapshot older than the last checkpoint would move it back.
            let s = m.snapshot().filter(|s| {
                Some(s.file) == open && self.last.as_ref().is_none_or(|l| s.step >= l.step)
            })?;
            (s.file, s.pos, s.body.clone(), s.step)
        } else {
            return None;
        };
        let cap = self.cap;
        let size = Body::size(machine.len(), 0);
        if size > cap {
            // R25 item 9: the oldest pending groups end first (at the next
            // poll); never a truncated checkpoint.
            self.shed_target = Some(m.group_bytes().saturating_sub(size - cap + (64 << 10)));
            return None;
        }
        Some(Pending {
            file,
            pos,
            machine,
            step,
            ticket: submitted,
            firsts: m.group_firsts(),
        })
    }

    /// Writes `p` with the positions recorded as sent that can come again
    /// from its state: emitted after it (by step), and restored ones it has
    /// not passed.
    fn write(&mut self, p: Pending, now: Instant) {
        self.durable.retain(|_, s| *s >= p.step);
        self.restored.retain(|k| {
            k.file == p.file && (k.off >= p.pos || (k.group && p.firsts.contains(&k.off)))
        });
        let mut dedup: Vec<(u64, DKey)> = self
            .restored
            .iter()
            .map(|k| (0, *k))
            .chain(self.durable.iter().map(|(k, s)| (*s, *k)))
            .collect();
        dedup.sort();
        dedup.dedup_by_key(|(_, k)| *k);
        let cap = self.cap;
        let room = (cap.saturating_sub(Body::size(p.machine.len(), 0)) / DKEY_BYTES).min(MAX_DEDUP);
        if dedup.len() > room {
            // The oldest first (their events are sent again after a restart).
            let drop = dedup.len() - room;
            self.counts.dedup_dropped += u64::try_from(drop).unwrap_or(u64::MAX);
            for (_, k) in dedup.drain(..drop) {
                self.durable.remove(&k);
                self.restored.remove(&k);
            }
        }
        let body = Body {
            file: p.file,
            pos: p.pos,
            machine: p.machine,
            dedup: dedup.into_iter().map(|(_, k)| k).collect(),
        };
        // The ledger first: a checkpoint never goes with an older ledger
        // than the credits its re-read needs.
        self.ledger.persist();
        let Some(bytes) = crate::ckpt::seal(&self.key, MAGIC, &body.encode()) else {
            return;
        };
        if let Err(e) = self.store.save(&bytes) {
            // The last checkpoint written stays (and the cursor with it).
            tracing::warn!(error = %e, "Firebird parser checkpoint not saved");
            return;
        }
        self.counts.written += 1;
        self.dirty = false;
        self.last = Some(Written {
            file: body.file,
            pos: body.pos,
            step: p.step,
            at: now,
        });
    }

    /// No checkpoint for the open file: the file is removed (a restart must
    /// not restore a state the cursor no longer goes with) and the position
    /// is held back as without a checkpoint.
    fn fallback(&mut self, open: Option<(u64, u64)>) -> Commit {
        self.counts.fallback += 1;
        if (self.last.take().is_some() || self.counts.fallback == 1)
            && let Err(e) = self.store.remove()
        {
            tracing::warn!(error = %e, "Firebird parser checkpoint not removed");
        }
        let hold = open.and_then(|o| {
            self.pending
                .iter()
                .filter(|p| p.file == o)
                .map(|p| p.pos)
                .chain(self.waiting.keys().filter(|k| k.file == o).map(|k| k.off))
                .min()
        });
        Commit::Fallback(hold)
    }
}
