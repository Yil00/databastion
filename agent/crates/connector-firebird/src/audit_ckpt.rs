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
//!   checkpoint and, on a blocking thread, soon after an own session ends.
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
const DKEY_BYTES: usize = 8 + 8 + 8 + 1 + 8 + 8;
/// Checkpoints written at most this often (between two writes, the cursor
/// stays at the last one's offset).
const WRITE_EVERY: Duration = Duration::from_secs(1);
/// The envelope's own bytes.
const ENVELOPE: usize = 4 + 2 + 4 + 32;
/// Declared databases of one target at most, in a checkpoint.
const MAX_DATABASES: usize = 4096;
/// Digests kept per database between two checkpoints; past it, one that
/// never matches (the database is invalidated at a restart, fail closed).
const MAX_DIGESTS: usize = 16;
/// The digest kept past [`MAX_DIGESTS`].
const NEVER: [u8; 32] = [0; 32];
/// Commits in a row whose checkpoint does not fit the cap before the last
/// one is dropped and the position held back as without one (review L3).
const MAX_TOO_LARGE: u32 = 3;
/// The host's boot id (`/proc/sys/kernel/random/boot_id`).
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// A checkpoint body, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Body {
    /// A keyed tag of the host's boot id (security review L1): a
    /// checkpoint of another boot is not used.
    pub(crate) boot: [u8; 32],
    pub(crate) file: (u64, u64),
    pub(crate) pos: u64,
    /// The end of what the writing process had read in `file` (the re-read
    /// region's end; `u64::MAX` when it read past `file`).
    pub(crate) read_end: u64,
    /// Per declared database, the keyed digests of what the checks gave the
    /// stream ([`crate::audit::Classes::digest`]: the decision of
    /// 2026-11-01 on L10), every one in force since the state's position
    /// (security review M2 of round 2): a restart whose check differs from
    /// any of them invalidates the database.
    pub(crate) digests: Vec<Vec<[u8; 32]>>,
    /// Re-read invalidations still running when it was written:
    /// `(database, end in file)`.
    pub(crate) invalid: Vec<(u32, u64)>,
    pub(crate) machine: Vec<u8>,
    pub(crate) dedup: Vec<DKey>,
}

impl Body {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes32(&self.boot);
        w.u64(self.file.0);
        w.u64(self.file.1);
        w.u64(self.pos);
        w.u64(self.read_end);
        w.len(self.digests.len());
        for set in &self.digests {
            w.len(set.len());
            for d in set {
                w.bytes32(d);
            }
        }
        w.len(self.invalid.len());
        for (db, end) in &self.invalid {
            w.u32(*db);
            w.u64(*end);
        }
        w.len(self.machine.len());
        w.buf.extend_from_slice(&self.machine);
        w.len(self.dedup.len());
        for k in &self.dedup {
            w.u64(k.file.0);
            w.u64(k.file.1);
            w.u64(k.off);
            w.bool(k.group);
            w.u64(k.members);
            w.u64(k.last);
        }
        w.buf
    }

    /// Strict, bounded (the fuzz target `firebird_checkpoint`).
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Bad> {
        let mut r = Reader::new(body);
        let boot = r.bytes32()?;
        let file = (r.u64()?, r.u64()?);
        let pos = r.u64()?;
        let read_end = r.u64()?;
        if read_end < pos {
            return Err(Bad);
        }
        let n = r.len(MAX_DATABASES, 4)?;
        let mut digests = Vec::with_capacity(n);
        for _ in 0..n {
            let m = r.len(MAX_DIGESTS, 32)?;
            let mut set = Vec::with_capacity(m);
            for _ in 0..m {
                set.push(r.bytes32()?);
            }
            digests.push(set);
        }
        let n = r.len(MAX_DATABASES, 12)?;
        let mut invalid = Vec::with_capacity(n);
        for _ in 0..n {
            let db = r.u32()?;
            let end = r.u64()?;
            if usize::try_from(db).map_or(true, |d| d >= digests.len()) || end <= pos {
                return Err(Bad);
            }
            invalid.push((db, end));
        }
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
                members: r.u64()?,
                last: r.u64()?,
            };
            if !k.group && (k.members != 0 || k.last != 0) {
                return Err(Bad);
            }
            if !seen.insert(k) {
                return Err(Bad);
            }
            dedup.push(k);
        }
        r.done()?;
        Ok(Self {
            boot,
            file,
            pos,
            read_end,
            digests,
            invalid,
            machine,
            dedup,
        })
    }

    pub(crate) fn size(machine: usize, dedup: usize, dbs: usize) -> usize {
        ENVELOPE + 32 + 32 + 4 + dbs * (32 + 12) + 4 + 4 + machine + 4 + dedup * DKEY_BYTES
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

/// What a checkpoint is written with: the digests of the current check
/// per declared database, and the read end (file and offset).
pub(crate) type Facts<'a> = (&'a [[u8; 32]], Option<((u64, u64), u64)>);

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
    /// The digests in force since it was taken.
    since: Vec<Vec<[u8; 32]>>,
}

/// Adds `current` to the digests in force per database.
fn merge(sets: &mut Vec<Vec<[u8; 32]>>, current: &[[u8; 32]]) {
    if sets.len() < current.len() {
        sets.resize(current.len(), Vec::new());
    }
    for (set, d) in sets.iter_mut().zip(current) {
        if set.contains(d) {
            continue;
        }
        if set.len() + 1 >= MAX_DIGESTS {
            if !set.contains(&NEVER) {
                set.push(NEVER);
            }
        } else {
            set.push(*d);
        }
    }
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
    /// Checkpoints that did not fit the cap (review L3).
    pub(crate) too_large: u64,
    /// Log resets (truncation, rotation) that dropped every position.
    pub(crate) resets: u64,
    /// Declared databases invalidated for a re-read after a restore (their
    /// check results changed while the agent was stopped).
    pub(crate) invalidated: u64,
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
    /// The tag of this boot's id.
    boot: [u8; 32],
    /// Commits in a row whose checkpoint did not fit.
    too_large: u32,
    /// Per declared database, the digests in force since the state of the
    /// last checkpoint written (or restored) was taken.
    hist: Vec<Vec<[u8; 32]>>,
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
        let boot = boot_tag(&key, std::fs::read(BOOT_ID).ok()?.as_slice())?;
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
            boot,
            too_large: 0,
            hist: Vec::new(),
        })
    }

    /// Test support: another boot id.
    #[cfg(test)]
    pub(crate) fn set_boot_for_tests(&mut self, id: &[u8]) {
        if let Some(b) = boot_tag(&self.key, id) {
            self.boot = b;
        }
    }

    /// A log reset (truncation, rotation): positions read before it may
    /// name other content. Every position recorded, waiting or restored is
    /// dropped, the checkpoint taken or written for this file is dropped
    /// and its file removed: the position is held back as without one
    /// until a checkpoint of the new content is written.
    pub(crate) fn reset(&mut self) {
        self.counts.resets += 1;
        self.restored.clear();
        self.durable.clear();
        self.waiting.clear();
        self.pending = None;
        self.dirty = false;
        if self.last.take().is_some()
            && let Err(e) = self.store.remove()
        {
            tracing::warn!(error = %e, "Firebird parser checkpoint not removed");
        }
    }

    /// The machine dropped its suppressed positions (a run change): the
    /// restored ones are dropped too.
    pub(crate) fn forget_restored(&mut self) {
        self.restored.clear();
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
    pub(crate) fn on_open(
        &mut self,
        resumed: Option<Resumed>,
        m: &mut Machine,
        digests: &[[u8; 32]],
        len: Option<u64>,
        now: Instant,
    ) {
        let Some(l) = self.loaded.take() else {
            return;
        };
        let bound =
            resumed.is_some_and(|r| r.verified && r.file == l.body.file && r.offset == l.body.pos);
        let result = if l.body.boot != self.boot {
            // Another boot: another server run whatever its pid and start.
            Err(Refused::State)
        } else if bound {
            m.import(&l.body.machine, now)
        } else {
            Err(Refused::Position)
        };
        match result {
            Ok(()) => {
                m.clear_invalidations();
                // L10 (decision of 2026-11-01): a database whose check
                // results differ from any in force since the state's
                // position is invalidated for every record of the file read
                // up to its length now (security review M2 of round 2: the
                // records written while the agent was stopped too); the
                // invalidations still running then go on.
                let mut inv: Vec<(usize, u64)> = l
                    .body
                    .invalid
                    .iter()
                    .filter_map(|(d, e)| usize::try_from(*d).ok().map(|d| (d, *e)))
                    .collect();
                let end = len.unwrap_or(u64::MAX);
                for (i, d) in digests.iter().enumerate() {
                    let differs = l
                        .body
                        .digests
                        .get(i)
                        .is_none_or(|set| set.is_empty() || set.iter().any(|x| x != d));
                    if differs && end > l.body.pos {
                        inv.push((i, end));
                        self.counts.invalidated += 1;
                    }
                }
                // The digests in force since the restored state: its own
                // and the current check's.
                self.hist = l.body.digests.clone();
                merge(&mut self.hist, digests);
                m.set_reread_invalid(l.body.file, &inv);
                // The next checkpoint carries the invalidation and the new
                // digests, even with no other change.
                self.dirty |= !inv.is_empty();
                let attaches = m.attaches();
                let credits = l.ledger.map_or(0, |s| {
                    self.ledger.restore(s, &attaches, (l.body.file, l.body.pos))
                });
                // R1 rule 5 (L3): a database restored while the agent was
                // stopped (the persisted ledger, now restored, shows the
                // check's attachment to be of a new life) starts its
                // attachments again.
                m.apply_restores();
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
        facts: Facts<'_>,
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
        // Every check result in force since the last state written, and
        // since the one taken (security review M2 of round 2).
        merge(&mut self.hist, facts.0);
        if let Some(p) = self.pending.as_mut() {
            merge(&mut p.since, facts.0);
        }
        let throttled = self
            .last
            .as_ref()
            .is_some_and(|l| now.duration_since(l.at) < self.every);
        if self.pending.is_none() && self.shed_until.is_none() && !throttled {
            self.pending = self.candidate(m, live, open, submitted, now);
            if let Some(p) = self.pending.as_mut() {
                merge(&mut p.since, facts.0);
            }
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
                self.write(p, m, facts, now);
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
        let size = Body::size(machine.len(), 0, m.attaches().len());
        if size > cap {
            // R25 item 9: the oldest pending groups end first (at the next
            // poll); never a truncated checkpoint. Review L3: counted and
            // logged; after a few in a row, the last checkpoint is dropped.
            self.counts.too_large += 1;
            self.too_large += 1;
            tracing::warn!(
                bytes = size,
                "Firebird parser checkpoint larger than its cap; not written"
            );
            if self.too_large >= MAX_TOO_LARGE {
                self.drop_last();
            }
            self.shed_target = Some(m.group_bytes().saturating_sub(size - cap + (64 << 10)));
            return None;
        }
        self.too_large = 0;
        Some(Pending {
            file,
            pos,
            machine,
            step,
            ticket: submitted,
            firsts: m.group_firsts(),
            since: Vec::new(),
        })
    }

    /// Writes `p` with the positions recorded as sent that can come again
    /// from its state: emitted after it (by step), and restored ones it has
    /// not passed.
    fn write(&mut self, p: Pending, m: &Machine, facts: Facts<'_>, now: Instant) {
        let (digests, read) = facts;
        let since = p.since.clone();
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
        let room = (cap.saturating_sub(Body::size(p.machine.len(), 0, digests.len())) / DKEY_BYTES)
            .min(MAX_DEDUP);
        if dedup.len() > room {
            // The oldest first (their events are sent again after a restart).
            let drop = dedup.len() - room;
            self.counts.dedup_dropped += u64::try_from(drop).unwrap_or(u64::MAX);
            for (_, k) in dedup.drain(..drop) {
                self.durable.remove(&k);
                self.restored.remove(&k);
            }
        }
        let read_end = match read {
            Some((f, e)) if f == p.file => e.max(p.pos),
            _ => u64::MAX,
        };
        let body = Body {
            boot: self.boot,
            file: p.file,
            pos: p.pos,
            read_end,
            // Every digest in force since the last state written: a superset
            // of those since this one's (taken after it, or a snapshot of a
            // hold newer than it).
            digests: {
                let mut d = self.hist.clone();
                merge(&mut d, digests);
                d
            },
            invalid: m
                .reread_invalid(p.file)
                .into_iter()
                .filter(|(_, e)| *e > p.pos)
                .filter_map(|(d, e)| u32::try_from(d).ok().map(|d| (d, e)))
                .collect(),
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
        // From now on, the digests in force since this state was taken.
        self.hist = since;
        self.last = Some(Written {
            file: body.file,
            pos: body.pos,
            step: p.step,
            at: now,
        });
    }

    /// Review L3: no checkpoint fits: the last one is dropped (its file
    /// removed), so the position is held back as without one rather than
    /// staying at an ever older checkpoint.
    fn drop_last(&mut self) {
        self.too_large = 0;
        if self.last.take().is_some()
            && let Err(e) = self.store.remove()
        {
            tracing::warn!(error = %e, "Firebird parser checkpoint not removed");
        }
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

/// The keyed tag of a boot id (`None` when it is not one: empty or too
/// long).
fn boot_tag(key: &LocalTagKey, id: &[u8]) -> Option<[u8; 32]> {
    let id = id.trim_ascii();
    (!id.is_empty() && id.len() <= 64)
        .then(|| crate::ckpt::tag(key, b"databastion.firebird.checkpoint.boot.v1", &[id]))
}
