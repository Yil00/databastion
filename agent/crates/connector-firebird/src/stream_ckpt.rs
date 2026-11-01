//! The parser state of [`super::Machine`] as persisted in the checkpoint
//! (ADR-0060 R25 items 7 and 9, R1 rule 11's persisted list, R41 item 7,
//! R42 item 4), and its strict restore.
//!
//! **What is written** (every item bounded as the live state is):
//! - an identity: a keyed tag of the declared databases (labels, `attach`
//!   names, resolved paths and aliases, exclusions), the agent's account
//!   and the server mode, and the run (pid and process start time);
//! - the run state: the unconfirmed mark, the remembered failed pids;
//! - every binding (database identity, attachment id, header token,
//!   anchored / poisoned / tainted / own marks, kind, open transactions,
//!   trigger and sweep sequence state), the live and ended tokens, the
//!   service sessions, the highest ids, the seen ids and their floors, the
//!   eviction order, the learned floors, the watermarks, the Garbage
//!   Collector's binding and linger;
//! - the open split window (its remaining reading time);
//! - the block-ful pending fold groups (binding, transaction, counts,
//!   relation and routine names, row counts, signals, the always-reported
//!   and `*` marks, which carry R41 item 7's "dependent seen" bit, their
//!   age in reading time and first position);
//! - the clock offset (confirmed, pending, its bindings) and the probe
//!   records per binding;
//! - the invalidation state of R28 item 4 and R41 item 8 (invalidated
//!   databases, open DDL transactions, waits, the run-long marks, times).
//!
//! Undeclared databases are their keyed hash (R1 rule 11), never a name.
//! Relation and routine names are in clear (as in events: a name can embed
//! a value its owner put in it).
//! **Not written**: any statement text or parameter; the names a
//! DDL text named in the interval (R41 item 8): a database that had such
//! names is restored with every relation dependent instead (fail closed);
//! held records (the checkpoint is only taken where none is held: they lie
//! after its position and the re-read regenerates them, R25 item 7 and
//! third-pass N6); counters.
//!
//! **Restore** refuses the whole body (the stream then starts with no
//! state, as before the checkpoint existed) on any decoding error, on
//! another identity or run (a checkpoint of another server run, or of
//! other declared databases, is never used), and on any bound or
//! consistency rule the live state keeps (caps per database and in all,
//! tokens bound to their bindings, indices of declared databases, offsets
//! on the R42 grid, no block-less group).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::{LocalTagKey, Signal};

use super::{
    Binding, DbId, Group, Key, Kind, MAX_BINDINGS_DECLARED, MAX_BINDINGS_UNDECLARED, MAX_DDL_OPEN,
    MAX_GROUP_NAMES, MAX_GROUPS, MAX_GROUPS_PER_BINDING, MAX_SERVICES, MAX_STATE_BYTES,
    MAX_STREAM_BYTES, MAX_TOKENS_ENDED, MAX_UNDECLARED, Machine, Part, Pend, Run, SeenIds,
    TriggerWait, WINDOW,
};
use crate::ckpt::{Bad, Reader, Refused, Writer};

/// The longest age kept for a reading-time instant (the bounds that read
/// them are seconds; older is as good as this).
const MAX_AGE: Duration = Duration::from_secs(3600);
/// Remembered failed pids (R1 rule 2).
const MAX_FAILED_PIDS: usize = 64;
/// Open transactions per binding (as the live state keeps them).
const MAX_OPEN_TRAS: usize = MAX_GROUPS_PER_BINDING * 4;
/// Every binding of every identity at its cap.
const MAX_ALL_BINDINGS: usize = MAX_BINDINGS_DECLARED * 64 + MAX_BINDINGS_UNDECLARED * 16;

fn age(now: Instant, t: Instant) -> u64 {
    let d = now.saturating_duration_since(t).min(MAX_AGE);
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn back(now: Instant, ms: u64) -> Instant {
    let d = Duration::from_millis(ms).min(MAX_AGE);
    now.checked_sub(d).unwrap_or(now)
}

fn wall_ms(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn wall(ms: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(ms)
}

/// A map's entries in key order (the checkpoint is deterministic).
fn sorted<K: Ord, V>(m: &HashMap<K, V>) -> Vec<(&K, &V)> {
    let mut v: Vec<(&K, &V)> = m.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v
}

fn w_db(w: &mut Writer, d: DbId) {
    match d {
        DbId::Declared(i) => {
            w.u8(0);
            w.u32(u32::try_from(i).unwrap_or(u32::MAX));
        }
        DbId::Undeclared(h) => {
            w.u8(1);
            w.u64(h);
        }
    }
}

fn w_key(w: &mut Writer, k: Key) {
    w_db(w, k.0);
    w.u64(k.1);
}

fn w_token(w: &mut Writer, t: (u32, u64)) {
    w.u32(t.0);
    w.u64(t.1);
}

fn w_part(w: &mut Writer, p: &Part) {
    w.u64(p.count);
    w.len(p.names.len());
    for n in &p.names {
        w.str(n);
    }
    w.len(p.rels.len());
    for n in &p.rels {
        w.str(n);
    }
    w.bool(p.overflow);
    w.opt_u64(p.rows);
    w.len(p.signals.len());
    for s in &p.signals {
        w.str(s.as_str());
    }
    w.bool(p.always);
    w.bool(p.star);
    w.bool(p.write);
}

/// Decoding with the stream's facts (the number of declared databases).
struct Dec<'a, 'b> {
    r: &'b mut Reader<'a>,
    ndb: usize,
}

impl Dec<'_, '_> {
    fn db(&mut self) -> Result<DbId, Bad> {
        match self.r.u8()? {
            0 => {
                let i = usize::try_from(self.r.u32()?).map_err(|_| Bad)?;
                if i >= self.ndb {
                    return Err(Bad);
                }
                Ok(DbId::Declared(i))
            }
            1 => Ok(DbId::Undeclared(self.r.u64()?)),
            _ => Err(Bad),
        }
    }
    fn declared(&mut self) -> Result<usize, Bad> {
        let i = usize::try_from(self.r.u32()?).map_err(|_| Bad)?;
        if i >= self.ndb {
            return Err(Bad);
        }
        Ok(i)
    }
    fn key(&mut self) -> Result<Key, Bad> {
        Ok((self.db()?, self.r.u64()?))
    }
    fn token(&mut self) -> Result<(u32, u64), Bad> {
        Ok((self.r.u32()?, self.r.u64()?))
    }
    fn part(&mut self) -> Result<Part, Bad> {
        let mut p = Part {
            count: self.r.u64()?,
            ..Part::default()
        };
        for v in [&mut p.names, &mut p.rels] {
            let n = self.r.len(MAX_GROUP_NAMES, 4)?;
            for _ in 0..n {
                let s = self.r.str()?;
                if v.contains(&s) {
                    return Err(Bad);
                }
                p.bytes += s.len() + 24;
                v.push(s);
            }
        }
        p.overflow = self.r.bool()?;
        p.rows = self.r.opt_u64()?;
        let n = self.r.len(Signal::ALL.len(), 4)?;
        for _ in 0..n {
            let s = self.r.str()?;
            let sig = Signal::ALL
                .iter()
                .copied()
                .find(|x| x.as_str() == s)
                .ok_or(Bad)?;
            if p.signals.contains(&sig) {
                return Err(Bad);
            }
            p.signals.push(sig);
        }
        p.always = self.r.bool()?;
        p.star = self.r.bool()?;
        p.write = self.r.bool()?;
        Ok(p)
    }
}

impl Machine {
    /// The tag of what the checkpoint was taken for: the declared databases
    /// as the stream resolves them, the agent's account and the server mode.
    fn identity(&self, key: &LocalTagKey) -> [u8; 32] {
        let mut w = Writer::default();
        w.len(self.s.databases.len());
        for d in &self.s.databases {
            w.str(&d.label);
            w.str(&d.attach);
            w.str(d.resolved.as_deref().unwrap_or(""));
            w.bool(d.resolved.is_some());
            w.str(d.alias.as_deref().unwrap_or(""));
            w.bool(d.alias.is_some());
            w.bool(d.excluded);
        }
        w.str(&self.s.account);
        w.bool(self.s.superserver);
        crate::ckpt::tag(
            key,
            b"databastion.firebird.checkpoint.identity.v1",
            &[&w.buf],
        )
    }

    /// Fuzzing support: what a body of this stream starts with (its
    /// identity tag and run), so the fuzz target reaches the state decoder.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn body_prefix(&self) -> Option<Vec<u8>> {
        let key = self.tag_key.as_deref()?;
        let run = self.run?;
        let mut w = Writer::default();
        w.bytes32(&self.identity(key));
        w.u32(run.pid);
        w.u64(run.start?);
        Some(w.buf)
    }

    /// Whether the state can be written as a checkpoint at the current read
    /// position: nothing held, no block-less group pending (R25 item 7: the
    /// position would be held back to it), no group ended but not yet
    /// emitted, a confirmed run with its start time, and a key.
    pub(crate) fn checkpointable(&self) -> bool {
        self.tag_key.is_some()
            && self.run.is_some_and(|r| r.start.is_some())
            && !self.unconfirmed
            && self.held.is_empty()
            && self.hold_since.is_none()
            && self.pending_end.is_empty()
            && !self.groups.iter().any(Group::blockless)
    }

    /// The parser state as a checkpoint body, `None` when it cannot be
    /// written now ([`Self::checkpointable`]).
    pub(crate) fn export(&self, now: Instant) -> Option<Vec<u8>> {
        if !self.checkpointable() {
            return None;
        }
        let key = self.tag_key.as_deref()?;
        let run = self.run?;
        let mut w = Writer::default();
        w.bytes32(&self.identity(key));
        w.u32(run.pid);
        w.u64(run.start?);
        w.len(self.failed_pids.len());
        for p in &self.failed_pids {
            w.u32(*p);
        }
        // Bindings, in insertion order (deterministic).
        let mut bindings: Vec<(&Key, &Binding)> = self.bindings.iter().collect();
        bindings.sort_by_key(|(_, b)| b.seq);
        w.len(bindings.len());
        for (k, b) in bindings {
            w_key(&mut w, *k);
            w.u64(b.seq);
            w_token(&mut w, b.token);
            w.bool(b.anchored);
            w.bool(b.poisoned);
            w.bool(b.tainted);
            w.u8(match b.kind {
                Kind::User => 0,
                Kind::Internal => 1,
                Kind::Sweep => 2,
            });
            w.opt_u64(b.first_tra);
            w.len(b.open_tras.len());
            for t in &b.open_tras {
                w.u64(*t);
            }
            w.u8(b.sweep_step);
            w.bool(b.own);
            match b.trigger_wait {
                None => w.u8(0),
                Some(TriggerWait::Disconnect(t)) => {
                    w.u8(1);
                    w.u64(t);
                }
                Some(TriggerWait::Reset) => w.u8(2),
                Some(TriggerWait::TraEnd(t)) => {
                    w.u8(3);
                    w.u64(t);
                }
            }
        }
        w.u64(self.next_seq);
        let mut live: Vec<(&(u32, u64), &Key)> = self.token_live.iter().collect();
        live.sort_by_key(|(t, _)| **t);
        w.len(live.len());
        for (t, k) in live {
            w_token(&mut w, *t);
            w_key(&mut w, *k);
        }
        // Each ended token once, at its latest place in the order.
        let mut once = HashSet::new();
        let mut ended: Vec<&(u32, u64)> = self
            .token_ended_order
            .iter()
            .rev()
            .filter(|t| self.token_ended.contains_key(t) && once.insert(**t))
            .collect();
        ended.reverse();
        w.len(ended.len());
        for t in ended {
            w_token(&mut w, *t);
        }
        let mut services: Vec<(&(u32, u64), &bool)> = self.services.iter().collect();
        services.sort();
        w.len(services.len());
        for (t, v) in services {
            w_token(&mut w, *t);
            w.bool(*v);
        }
        w.len(self.highest.len());
        for (d, (id, at)) in sorted(&self.highest) {
            w_db(&mut w, *d);
            w.u64(*id);
            w.u64(age(now, *at));
        }
        w.len(self.seen_ids.len());
        for (d, s) in sorted(&self.seen_ids) {
            w_db(&mut w, *d);
            w.opt_u64(s.floor);
            let kept: Vec<u64> = s
                .order
                .iter()
                .copied()
                .filter(|i| s.set.contains(i))
                .collect();
            w.len(kept.len());
            for i in kept {
                w.u64(i);
            }
        }
        let evictable: Vec<&(u64, Key)> = self
            .evictable
            .iter()
            .filter(|(seq, k)| {
                self.bindings.get(k).is_some_and(|b| {
                    b.seq == *seq && (!b.anchored || matches!(k.0, DbId::Undeclared(_)))
                })
            })
            .collect();
        w.len(evictable.len());
        for (seq, k) in evictable {
            w.u64(*seq);
            w_key(&mut w, *k);
        }
        w.len(self.learned_floor.len());
        for (d, f) in sorted(&self.learned_floor) {
            w_db(&mut w, *d);
            w.u64(*f);
        }
        w.len(self.watermark.len());
        for (i, m) in sorted(&self.watermark) {
            w.u32(u32::try_from(*i).unwrap_or(u32::MAX));
            w.u64(*m);
        }
        w.len(self.internal.len());
        for (d, k) in sorted(&self.internal) {
            w_db(&mut w, *d);
            w_key(&mut w, *k);
        }
        w.len(self.gc_alone_since.len());
        for (d, at) in sorted(&self.gc_alone_since) {
            w_db(&mut w, *d);
            w.u64(age(now, *at));
        }
        let window = self.window_until.map(|u| {
            u64::try_from(u.saturating_duration_since(now).min(WINDOW).as_millis())
                .unwrap_or(u64::MAX)
        });
        w.opt_u64(window);
        // N1: only the groups of live bindings of declared databases (the
        // others end with nothing to send).
        let groups: Vec<&Group> = self
            .groups
            .iter()
            .filter(|g| matches!(g.key.0, DbId::Declared(_)) && self.bindings.contains_key(&g.key))
            .collect();
        w.len(groups.len());
        for g in groups {
            w_key(&mut w, g.key);
            w.u64(g.tra);
            w_part(&mut w, &g.full);
            w.u64(age(now, g.started));
            w.u64(g.first);
            w.u64(g.last);
        }
        match self.last_declared {
            Some(i) => {
                w.u8(1);
                w.u32(u32::try_from(i).unwrap_or(u32::MAX));
            }
            None => w.u8(0),
        }
        w.opt_i64(self.offset);
        match self.offset_pending {
            Some((o, k, probe)) => {
                w.u8(1);
                w.i64(o);
                w_key(&mut w, k);
                w.bool(probe);
            }
            None => w.u8(0),
        }
        w.len(self.probe_records.len());
        for (k, n) in sorted(&self.probe_records) {
            w_key(&mut w, *k);
            w.u32(*n);
        }
        match self.offset_from {
            Some((a, b, prev)) => {
                w.u8(1);
                w_key(&mut w, a);
                w_key(&mut w, b);
                w.opt_i64(prev);
            }
            None => w.u8(0),
        }
        let dbs = |w: &mut Writer, set: &mut dyn Iterator<Item = usize>| {
            let mut v: Vec<usize> = set.collect();
            v.sort_unstable();
            v.dedup();
            w.len(v.len());
            for i in v {
                w.u32(u32::try_from(i).unwrap_or(u32::MAX));
            }
        };
        dbs(&mut w, &mut self.views_invalid.iter().copied());
        w.len(self.ddl_open.len());
        for ((k, t), db) in sorted(&self.ddl_open) {
            w_key(&mut w, *k);
            w.u64(*t);
            w.u32(u32::try_from(*db).unwrap_or(u32::MAX));
        }
        w.len(self.ddl_wait.len());
        for (db, pends) in sorted(&self.ddl_wait) {
            w.u32(u32::try_from(*db).unwrap_or(u32::MAX));
            w.len(pends.len());
            let mut pends: Vec<&Pend> = pends.iter().collect();
            pends.sort();
            for p in pends {
                match p {
                    Pend::Tra(k, t) => {
                        w.u8(0);
                        w_key(&mut w, *k);
                        w.u64(*t);
                    }
                    Pend::Binding(k) => {
                        w.u8(1);
                        w_key(&mut w, *k);
                    }
                }
            }
        }
        dbs(&mut w, &mut self.run_sticky.iter().copied());
        w.len(self.invalid_after.len());
        for (db, t) in sorted(&self.invalid_after) {
            w.u32(u32::try_from(*db).unwrap_or(u32::MAX));
            w.u64(wall_ms(*t));
        }
        // R41 item 8: the names DDL texts named are not written; their
        // databases count every relation as dependent instead.
        dbs(
            &mut w,
            &mut self
                .all_relations
                .iter()
                .copied()
                .chain(self.ddl_named.keys().copied())
                .chain(self.ddl_named_lent.iter().copied()),
        );
        Some(w.buf)
    }

    /// Restores the parser state from a checkpoint body: the whole body or
    /// nothing. The stream's settings and counters are kept.
    pub(crate) fn import(&mut self, body: &[u8], now: Instant) -> Result<(), Refused> {
        let key = self.tag_key.clone().ok_or(Refused::State)?;
        let mut r = Reader::new(body);
        let ndb = self.s.databases.len();
        let mut d = Dec { r: &mut r, ndb };
        let identity = d.r.bytes32().map_err(|_| Refused::Body)?;
        if identity != self.identity(&key) {
            return Err(Refused::State);
        }
        let run = Run {
            pid: d.r.u32().map_err(|_| Refused::Body)?,
            start: Some(d.r.u64().map_err(|_| Refused::Body)?),
        };
        // A checkpoint of another server run (or with the run not known
        // with its start time now) is never used (R39 (a), fail closed).
        if self.run != Some(run) || self.unconfirmed {
            return Err(Refused::State);
        }
        let st = decode(&mut d, now).map_err(|_| Refused::Body)?;
        r.done().map_err(|_| Refused::Body)?;
        let mut m = Restored::default();
        m.fill(st).map_err(|()| Refused::State)?;
        // Every rule of the live state, then the global cap.
        self.failed_pids = m.failed_pids;
        self.bindings = m.bindings;
        self.next_seq = m.next_seq;
        self.token_live = m.token_live;
        self.token_ended = m.token_ended.iter().map(|t| (*t, ())).collect();
        self.token_ended_order = m.token_ended;
        self.services = m.services;
        self.highest = m.highest;
        self.seen_total = m.seen_ids.values().map(|s| s.set.len()).sum();
        self.seen_ids = m.seen_ids;
        self.binding_count = HashMap::new();
        for k in self.bindings.keys() {
            *self.binding_count.entry(k.0).or_insert(0) += 1;
        }
        self.evictable = m.evictable;
        self.learned_floor = m.learned_floor;
        self.watermark = m.watermark;
        self.internal = m.internal;
        self.gc_alone_since = m.gc_alone_since;
        self.window_until = m.window_until;
        self.groups = m.groups;
        self.held = Vec::new();
        self.held_bytes = 0;
        self.hold_since = None;
        self.pending_end = Vec::new();
        self.last_declared = m.last_declared;
        self.offset = m.offset;
        self.offset_pending = m.offset_pending;
        self.probe_records = m.probe_records;
        self.offset_from = m.offset_from;
        self.views_invalid = m.views_invalid;
        self.ddl_open = m.ddl_open;
        self.ddl_wait = m.ddl_wait;
        self.run_sticky = m.run_sticky;
        self.invalid_after = m.invalid_after;
        self.ddl_named = HashMap::new();
        self.ddl_named_lent = Vec::new();
        self.all_relations = m.all_relations;
        let caps = self.binding_count.iter().all(|(d, n)| match d {
            DbId::Declared(_) => *n <= MAX_BINDINGS_DECLARED,
            DbId::Undeclared(_) => *n <= MAX_BINDINGS_UNDECLARED,
        }) && self
            .seen_ids
            .keys()
            .chain(self.binding_count.keys())
            .filter(|d| matches!(d, DbId::Undeclared(_)))
            .collect::<HashSet<_>>()
            .len()
            <= MAX_UNDECLARED;
        let groups_ok = self.groups.iter().map(Group::bytes).sum::<usize>() <= MAX_STATE_BYTES;
        if !caps || !groups_ok || self.state_bytes() > MAX_STREAM_BYTES {
            // Nothing of a refused body is kept.
            self.reset_parser_state();
            return Err(Refused::State);
        }
        Ok(())
    }

    /// The parser state of a stream with no checkpoint (what [`Self::import`]
    /// sets), the run and the settings kept.
    fn reset_parser_state(&mut self) {
        self.failed_pids.clear();
        self.bindings.clear();
        self.next_seq = 0;
        self.token_live.clear();
        self.token_ended.clear();
        self.token_ended_order.clear();
        self.services.clear();
        self.highest.clear();
        self.seen_ids.clear();
        self.seen_total = 0;
        self.binding_count.clear();
        self.evictable.clear();
        self.learned_floor.clear();
        self.watermark.clear();
        self.internal.clear();
        self.gc_alone_since.clear();
        self.window_until = None;
        self.groups.clear();
        self.held.clear();
        self.held_bytes = 0;
        self.hold_since = None;
        self.pending_end.clear();
        self.last_declared = None;
        self.offset = None;
        self.offset_pending = None;
        self.probe_records.clear();
        self.offset_from = None;
        self.views_invalid.clear();
        self.ddl_open.clear();
        self.ddl_wait.clear();
        self.run_sticky.clear();
        self.invalid_after.clear();
        self.ddl_named.clear();
        self.ddl_named_lent.clear();
        self.all_relations.clear();
    }
}

/// The decoded body, before its consistency rules.
#[derive(Default)]
struct Decoded {
    failed_pids: Vec<u32>,
    bindings: Vec<(Key, Binding)>,
    next_seq: u64,
    token_live: Vec<((u32, u64), Key)>,
    token_ended: Vec<(u32, u64)>,
    services: Vec<((u32, u64), bool)>,
    highest: Vec<(DbId, u64, Instant)>,
    seen: Vec<(DbId, Option<u64>, Vec<u64>)>,
    evictable: Vec<(u64, Key)>,
    learned_floor: Vec<(DbId, u64)>,
    watermark: Vec<(usize, u64)>,
    internal: Vec<(DbId, Key)>,
    gc_alone_since: Vec<(DbId, Instant)>,
    window_until: Option<Instant>,
    groups: Vec<Group>,
    last_declared: Option<usize>,
    offset: Option<i64>,
    offset_pending: Option<(i64, Key, bool)>,
    probe_records: Vec<(Key, u32)>,
    offset_from: Option<(Key, Key, Option<i64>)>,
    views_invalid: Vec<usize>,
    ddl_open: Vec<((Key, u64), usize)>,
    ddl_wait: Vec<(usize, Vec<Pend>)>,
    run_sticky: Vec<usize>,
    invalid_after: Vec<(usize, SystemTime)>,
    all_relations: Vec<usize>,
}

#[allow(clippy::too_many_lines)]
fn decode(d: &mut Dec<'_, '_>, now: Instant) -> Result<Decoded, Bad> {
    let mut st = Decoded::default();
    let n = d.r.len(MAX_FAILED_PIDS, 4)?;
    for _ in 0..n {
        st.failed_pids.push(d.r.u32()?);
    }
    let n = d.r.len(MAX_ALL_BINDINGS, 9 + 8 + 8 + 12)?;
    for _ in 0..n {
        let k = d.key()?;
        let seq = d.r.u64()?;
        let token = d.token()?;
        let anchored = d.r.bool()?;
        let poisoned = d.r.bool()?;
        let tainted = d.r.bool()?;
        let kind = match d.r.u8()? {
            0 => Kind::User,
            1 => Kind::Internal,
            2 => Kind::Sweep,
            _ => return Err(Bad),
        };
        let first_tra = d.r.opt_u64()?;
        let t = d.r.len(MAX_OPEN_TRAS, 8)?;
        let mut open_tras = Vec::with_capacity(t);
        for _ in 0..t {
            open_tras.push(d.r.u64()?);
        }
        let sweep_step = d.r.u8()?;
        let own = d.r.bool()?;
        let trigger_wait = match d.r.u8()? {
            0 => None,
            1 => Some(TriggerWait::Disconnect(d.r.u64()?)),
            2 => Some(TriggerWait::Reset),
            3 => Some(TriggerWait::TraEnd(d.r.u64()?)),
            _ => return Err(Bad),
        };
        st.bindings.push((
            k,
            Binding {
                seq,
                token,
                anchored,
                poisoned,
                tainted,
                kind,
                first_tra,
                open_tras,
                sweep_step,
                own,
                trigger_wait,
            },
        ));
    }
    st.next_seq = d.r.u64()?;
    let n = d.r.len(MAX_ALL_BINDINGS, 12 + 9 + 8)?;
    for _ in 0..n {
        st.token_live.push((d.token()?, d.key()?));
    }
    let n = d.r.len(MAX_TOKENS_ENDED, 12)?;
    for _ in 0..n {
        st.token_ended.push(d.token()?);
    }
    let n = d.r.len(MAX_SERVICES, 13)?;
    for _ in 0..n {
        st.services.push((d.token()?, d.r.bool()?));
    }
    let n = d.r.len(MAX_UNDECLARED + 64, 5 + 16)?;
    for _ in 0..n {
        let db = d.db()?;
        let id = d.r.u64()?;
        st.highest.push((db, id, back(now, d.r.u64()?)));
    }
    let n = d.r.len(MAX_UNDECLARED + 64, 5 + 1 + 4)?;
    for _ in 0..n {
        let db = d.db()?;
        let floor = d.r.opt_u64()?;
        let m = d.r.len(MAX_STREAM_BYTES / 16, 8)?;
        let mut ids = Vec::with_capacity(m);
        for _ in 0..m {
            ids.push(d.r.u64()?);
        }
        st.seen.push((db, floor, ids));
    }
    let n = d.r.len(MAX_ALL_BINDINGS, 8 + 9 + 8)?;
    for _ in 0..n {
        st.evictable.push((d.r.u64()?, d.key()?));
    }
    let n = d.r.len(MAX_UNDECLARED + 64, 5 + 8)?;
    for _ in 0..n {
        st.learned_floor.push((d.db()?, d.r.u64()?));
    }
    let n = d.r.len(64, 12)?;
    for _ in 0..n {
        st.watermark.push((d.declared()?, d.r.u64()?));
    }
    let n = d.r.len(MAX_UNDECLARED + 64, 5 + 9 + 8)?;
    for _ in 0..n {
        st.internal.push((d.db()?, d.key()?));
    }
    let n = d.r.len(MAX_UNDECLARED + 64, 5 + 8)?;
    for _ in 0..n {
        let db = d.db()?;
        st.gc_alone_since.push((db, back(now, d.r.u64()?)));
    }
    st.window_until =
        d.r.opt_u64()?
            .map(|ms| now + Duration::from_millis(ms).min(WINDOW));
    let n = d.r.len(MAX_GROUPS, 9 + 8 + 8 + 16)?;
    for _ in 0..n {
        let key = d.key()?;
        let tra = d.r.u64()?;
        let full = d.part()?;
        let started = back(now, d.r.u64()?);
        let first = d.r.u64()?;
        let last = d.r.u64()?;
        if last < first {
            return Err(Bad);
        }
        st.groups.push(Group {
            key,
            tra,
            full,
            bare: Part::default(),
            started,
            first,
            first_bare: None,
            last,
        });
    }
    st.last_declared = match d.r.u8()? {
        0 => None,
        1 => Some(d.declared()?),
        _ => return Err(Bad),
    };
    st.offset = d.r.opt_i64()?;
    st.offset_pending = match d.r.u8()? {
        0 => None,
        1 => Some((d.r.i64()?, d.key()?, d.r.bool()?)),
        _ => return Err(Bad),
    };
    let n = d.r.len(MAX_ALL_BINDINGS, 9 + 8 + 4)?;
    for _ in 0..n {
        st.probe_records.push((d.key()?, d.r.u32()?));
    }
    st.offset_from = match d.r.u8()? {
        0 => None,
        1 => Some((d.key()?, d.key()?, d.r.opt_i64()?)),
        _ => return Err(Bad),
    };
    let dbs = |d: &mut Dec<'_, '_>| -> Result<Vec<usize>, Bad> {
        let n = d.r.len(d.ndb, 4)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(d.declared()?);
        }
        Ok(v)
    };
    st.views_invalid = dbs(d)?;
    let n = d.r.len(MAX_DDL_OPEN, 9 + 8 + 8 + 4)?;
    for _ in 0..n {
        let k = d.key()?;
        let t = d.r.u64()?;
        st.ddl_open.push(((k, t), d.declared()?));
    }
    let n = d.r.len(d.ndb, 8)?;
    for _ in 0..n {
        let db = d.declared()?;
        let m = d.r.len(MAX_DDL_OPEN, 1 + 9 + 8)?;
        let mut v = Vec::with_capacity(m);
        for _ in 0..m {
            v.push(match d.r.u8()? {
                0 => Pend::Tra(d.key()?, d.r.u64()?),
                1 => Pend::Binding(d.key()?),
                _ => return Err(Bad),
            });
        }
        st.ddl_wait.push((db, v));
    }
    st.run_sticky = dbs(d)?;
    let n = d.r.len(d.ndb, 12)?;
    for _ in 0..n {
        let db = d.declared()?;
        st.invalid_after.push((db, wall(d.r.u64()?)));
    }
    st.all_relations = dbs(d)?;
    Ok(st)
}

/// The restored state, with every consistency rule checked.
#[derive(Default)]
struct Restored {
    failed_pids: Vec<u32>,
    bindings: HashMap<Key, Binding>,
    next_seq: u64,
    token_live: HashMap<(u32, u64), Key>,
    token_ended: VecDeque<(u32, u64)>,
    services: HashMap<(u32, u64), bool>,
    highest: HashMap<DbId, (u64, Instant)>,
    seen_ids: HashMap<DbId, SeenIds>,
    evictable: VecDeque<(u64, Key)>,
    learned_floor: HashMap<DbId, u64>,
    watermark: HashMap<usize, u64>,
    internal: HashMap<DbId, Key>,
    gc_alone_since: HashMap<DbId, Instant>,
    window_until: Option<Instant>,
    groups: VecDeque<Group>,
    last_declared: Option<usize>,
    offset: Option<i64>,
    offset_pending: Option<(i64, Key, bool)>,
    probe_records: HashMap<Key, u32>,
    offset_from: Option<(Key, Key, Option<i64>)>,
    views_invalid: HashSet<usize>,
    ddl_open: HashMap<(Key, u64), usize>,
    ddl_wait: HashMap<usize, HashSet<Pend>>,
    run_sticky: HashSet<usize>,
    invalid_after: HashMap<usize, SystemTime>,
    all_relations: HashSet<usize>,
}

/// Inserts every item, refusing a duplicate key.
fn unique<K: std::hash::Hash + Eq, V>(
    items: impl IntoIterator<Item = (K, V)>,
) -> Result<HashMap<K, V>, ()> {
    let mut m = HashMap::new();
    for (k, v) in items {
        if m.insert(k, v).is_some() {
            return Err(());
        }
    }
    Ok(m)
}

fn unique_set<T: std::hash::Hash + Eq>(
    items: impl IntoIterator<Item = T>,
) -> Result<HashSet<T>, ()> {
    let mut s = HashSet::new();
    for t in items {
        if !s.insert(t) {
            return Err(());
        }
    }
    Ok(s)
}

impl Restored {
    #[allow(clippy::too_many_lines)]
    fn fill(&mut self, st: Decoded) -> Result<(), ()> {
        self.failed_pids = st.failed_pids;
        if unique_set(self.failed_pids.iter().copied())?.len() != self.failed_pids.len() {
            return Err(());
        }
        self.next_seq = st.next_seq;
        self.bindings = unique(st.bindings)?;
        let seqs = unique_set(self.bindings.values().map(|b| b.seq))?;
        if seqs.iter().any(|s| *s >= self.next_seq) {
            return Err(());
        }
        // Every live token is its binding's (R1 rule 4: one live binding
        // per token).
        self.token_live = unique(st.token_live)?;
        if self
            .token_live
            .iter()
            .any(|(t, k)| self.bindings.get(k).is_none_or(|b| b.token != *t))
        {
            return Err(());
        }
        let ended = unique_set(st.token_ended.iter().copied())?;
        if ended.len() != st.token_ended.len() {
            return Err(());
        }
        self.token_ended = st.token_ended.into();
        self.services = unique(st.services)?;
        self.highest = unique(st.highest.into_iter().map(|(d, id, at)| (d, (id, at))))?;
        let mut total = 0usize;
        for (db, floor, ids) in st.seen {
            let cap = match db {
                DbId::Declared(_) => MAX_BINDINGS_DECLARED,
                DbId::Undeclared(_) => MAX_BINDINGS_UNDECLARED,
            };
            if ids.len() > cap {
                return Err(());
            }
            let set = unique_set(ids.iter().copied())?;
            total += set.len();
            let s = SeenIds {
                set,
                order: ids.into(),
                floor,
            };
            if self.seen_ids.insert(db, s).is_some() {
                return Err(());
            }
        }
        if total.saturating_mul(16) > MAX_STREAM_BYTES {
            return Err(());
        }
        // The eviction order names live, evictable bindings only, each once.
        let ev = unique_set(st.evictable.iter().copied())?;
        if ev.len() != st.evictable.len()
            || st.evictable.iter().any(|(seq, k)| {
                self.bindings.get(k).is_none_or(|b| {
                    b.seq != *seq || (b.anchored && matches!(k.0, DbId::Declared(_)))
                })
            })
        {
            return Err(());
        }
        self.evictable = st.evictable.into();
        self.learned_floor = unique(st.learned_floor)?;
        self.watermark = unique(st.watermark)?;
        self.internal = unique(st.internal)?;
        self.gc_alone_since = unique(st.gc_alone_since)?;
        self.window_until = st.window_until;
        let mut per: HashMap<Key, usize> = HashMap::new();
        let mut seen_groups = HashSet::new();
        for g in st.groups {
            let n = per.entry(g.key).or_insert(0);
            *n += 1;
            if *n > MAX_GROUPS_PER_BINDING
                || !seen_groups.insert((g.key, g.tra))
                || g.full.count == 0
                || !matches!(g.key.0, DbId::Declared(_))
                || !self.bindings.contains_key(&g.key)
            {
                return Err(());
            }
            self.groups.push_back(g);
        }
        self.last_declared = st.last_declared;
        // R42 item 1: a confirmed offset is on the grid.
        if st.offset.is_some_and(|o| super::grid_offset(o) != Some(o))
            || st
                .offset_pending
                .is_some_and(|(o, _, _)| super::grid_offset(o) != Some(o))
            || st
                .offset_from
                .is_some_and(|(_, _, p)| p.is_some_and(|o| super::grid_offset(o) != Some(o)))
        {
            return Err(());
        }
        self.offset = st.offset;
        self.offset_pending = st.offset_pending;
        self.probe_records = unique(st.probe_records)?;
        self.offset_from = st.offset_from;
        self.views_invalid = unique_set(st.views_invalid)?;
        self.ddl_open = unique(st.ddl_open)?;
        let mut wait = HashMap::new();
        for (db, v) in st.ddl_wait {
            let set = unique_set(v)?;
            if set.is_empty() || wait.insert(db, set).is_some() {
                return Err(());
            }
        }
        self.ddl_wait = wait;
        self.run_sticky = unique_set(st.run_sticky)?;
        self.invalid_after = unique(st.invalid_after)?;
        self.all_relations = unique_set(st.all_relations)?;
        // The databases with an invalidation in progress are invalidated.
        let waiting = self
            .ddl_open
            .values()
            .chain(self.ddl_wait.keys())
            .chain(&self.run_sticky)
            .chain(&self.all_relations);
        for db in waiting {
            self.views_invalid.insert(*db);
        }
        Ok(())
    }
}
