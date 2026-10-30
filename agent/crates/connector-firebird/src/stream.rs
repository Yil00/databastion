//! The multi-record rules of the Firebird system audit trace (ADR-0060
//! decision 6 and its refinements R1 to R36): what the single-record
//! rules of [`crate::trace_events`] cannot decide alone.
//!
//! [`Machine`] is a pure state machine (no I/O): the runner
//! ([`crate::audit`]) feeds it assembled records with their log positions,
//! the reading time, and the facts `check()` and `/proc` give (the run,
//! the catalog classes, the agent's own attachments and execution
//! credits); it hands back masked events per declared database.
//!
//! Implemented, fail closed:
//! - **Runs** (R1 rules 1 and 2, R5): the run is the pid and start time
//!   `check()` and `/proc` confirm; a record of another pid is ambiguous
//!   (the stream is not stopped: such records are loud until a check
//!   confirms a new run, which ends every binding of the old one); a start
//!   time change of the same pid makes the records read until the next
//!   confirmation ambiguous (R5 item 4).
//! - **Bindings** (R1 rules 3 to 6, R7): per database identity and
//!   attachment id, anchored at `ATTACH_DATABASE` (or learned from the
//!   first record after a gap); every record of an attachment carries its
//!   binding's token; one live binding per token; a duplicate attach
//!   poisons both; ids out of order within R7's bounds (256 ids, 10 s of
//!   reading time); ids above the agent's latest own id plus 4 096
//!   ambiguous; the watermark; learned bindings never the agent's own;
//!   service sessions bound from `ATTACH_SERVICE` to `DETACH_SERVICE`;
//!   the bounds of R1 rule 11.
//! - **`TRACE_INIT` / `TRACE_FINI`** (R5 item 2).
//! - **The Garbage Collector** (R6, R16, R30): one internal binding per
//!   database identity, one transaction, its end only with no other live
//!   binding; the sweep binding of R17 with its record sequence.
//! - **Database names** (R2): the resolved path, the declared alias and
//!   the aliases of the evaluated map; same file name as a declared
//!   database ambiguous (M4); undeclared databases ambiguous under proof
//!   11, dropped and counted otherwise (R1 rule 8).
//! - **Split windows** (H1 fix 2, R1 rule 7): 60 s of reading time,
//!   ended by a record of the agent's own anchored binding; bindings
//!   attached inside a window tainted until they detach.
//! - **Folding** (R4, R25): a routine finish record pends in its binding's
//!   transaction group and folds, by maximum, into the next statement
//!   finish of that binding and transaction; database triggers never fold
//!   (R15) and are checked against their sequence (`ON CONNECT` in the
//!   binding's first transaction, `ON DISCONNECT` followed by the detach,
//!   the reset pair of R34); a group whose transaction ends unfolded
//!   becomes the block-ful part's events and the block-less part's
//!   ambiguous records; the stream budget (4 096 groups, 16 transactions
//!   per binding) ends the oldest first. While a block-less nested record
//!   pends, the events of every other record are held (65 536 records,
//!   10 s) and released, or made ambiguous, with the decision (R8 item 2).
//! - **The agent's own records** (decision 6, R8 item 4, R13, R22, R35):
//!   only on an anchored, unpoisoned, untainted binding whose attachment
//!   id and local port are an own attachment of the ledger, with the
//!   agent's account, role `NONE`, a text of the closed set or a sampling
//!   text that consumes an execution credit, `records fetched` within the
//!   credit's bounds, a block within the text's relations and the
//!   metadata-loading set, no signal.
//!
//! Not implemented here (each fail closed or left to the stream's caller,
//! listed in the lot 3 report): the stop of R1 rule 2 (records of an
//! unconfirmed pid are ambiguous instead), R1 rule 9, the checkpoint of
//! parser state (R25 items 7 and 9: positions are held back instead and
//! the records re-read for state), local external data sources (R29:
//! their `<internal>` attachments are ambiguous, as R18 item 3 accepted).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::MaskedEvent;
use databastion_classifiers::query::firebird::{FirebirdKind, analyze_firebird};

use crate::own::{Ledger, Verdict};
use crate::trace_conf::AliasMap;
use crate::trace_events::{Catalog, Converted, Draft, convert, to_event};
use crate::trace_log::{
    Body, Event, LogTime, Outcome, ParseOptions, Protocol, Record, RoutineKind, ServiceName,
    TriggerKind, parse,
};

/// R1 rule 7: a split window lasts this much reading time.
const WINDOW: Duration = Duration::from_secs(60);
/// R7: ids accepted out of order.
const ORDER_IDS: u64 = 256;
/// R7: reading time within which an out-of-order id is accepted.
const ORDER_TIME: Duration = Duration::from_secs(10);
/// R1 rule 5: the margin above the agent's latest own id.
const ID_MARGIN: u64 = 4096;
/// R1 rule 11.
const MAX_BINDINGS_DECLARED: usize = 16_384;
const MAX_BINDINGS_UNDECLARED: usize = 4096;
const MAX_UNDECLARED: usize = 256;
const MAX_SERVICES: usize = 1024;
/// R1 rule 11: the global cap on the stream's state (bindings, seen ids,
/// ended tokens, groups, held records).
pub(crate) const MAX_STREAM_BYTES: usize = 16 << 20;
/// The estimated state of one binding (its key, token, transactions).
const BINDING_BYTES: usize = 256;
/// Ended tokens remembered (R5 item 2), oldest dropped first.
const MAX_TOKENS_ENDED: usize = 65_536;
/// DDL transactions tracked at most (R41 item 8); past it, invalidated
/// until the run ends.
const MAX_DDL_OPEN: usize = 4096;
/// R25: the stream budget.
const MAX_GROUPS: usize = 4096;
const MAX_GROUPS_PER_BINDING: usize = 16;
/// R25 item 5: block-ful-only groups end after this much reading time.
const GROUP_TIME: Duration = Duration::from_secs(10);
/// R8 item 2, R25 item 6: the hold bound.
const MAX_HELD: usize = 65_536;
const HOLD_TIME: Duration = Duration::from_secs(10);
/// The largest change of a confirmed clock offset a credited record other
/// than the read-back probe may make (one hour: a daylight-saving change).
const OFFSET_STEP: i64 = 3600;
/// R30 item 3: the Garbage Collector's expected end.
const GC_END: Duration = Duration::from_secs(10);

/// The names one declared database can be printed under (R2 rule 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredNames {
    /// The operator's label (sent as `Location.database`).
    pub(crate) label: String,
    /// `MON$DATABASE_NAME` from the agent's own attachment.
    pub(crate) resolved: Option<String>,
    /// The declared `attach` when it is an alias.
    pub(crate) alias: Option<String>,
    /// Excluded by R9: handled as an undeclared database.
    pub(crate) excluded: bool,
    /// The declared `attach` (the ledger's key; never sent).
    pub(crate) attach: String,
    /// When the last check's catalog read of it started (R41 item 8).
    pub(crate) read_at: Option<SystemTime>,
}

/// Database identity (R1 rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DbId {
    Declared(usize),
    /// A keyed hash of the printed name (never kept in clear).
    Undeclared(u64),
}

/// What resolving a printed name gave.
enum Resolved {
    Db(DbId),
    /// Same file name as a declared database, an alias not in the map, a
    /// case variant: ambiguous (R2 rules 2 and 3, M4).
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    /// The Garbage Collector (R6, R16).
    Internal,
    /// The automatic sweep (R17).
    Sweep,
}

#[derive(Debug, Clone)]
struct Binding {
    /// Insertion order (R1 rule 11's eviction).
    seq: u64,
    token: (u32, u64),
    anchored: bool,
    poisoned: bool,
    tainted: bool,
    kind: Kind,
    /// Transactions started on it (R15: `ON CONNECT` in the first).
    first_tra: Option<u64>,
    open_tras: Vec<u64>,
    /// R17's sequence position.
    sweep_step: u8,
    /// The own attachment of the ledger it matched, when it did.
    own: bool,
    /// A database trigger waiting for its sequence (R15 item 2, R34).
    trigger_wait: Option<TriggerWait>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerWait {
    /// `ON DISCONNECT` in this transaction: after the transaction's end
    /// record, its `DETACH_DATABASE` (R15 item 2), or `ON CONNECT` (R34).
    Disconnect(u64),
    /// The reset pair: `ALTER SESSION RESET` next (R34 item 2).
    Reset,
    /// `ON TRANSACTION_COMMIT` / `_ROLLBACK`: the next record of the
    /// binding in this transaction is its end record (R15 item 2).
    TraEnd(u64),
}

type Key = (DbId, u64);

/// The ids seen for one database identity (R16 item 2, R30 review L7):
/// kept up to a bound, oldest dropped first; ids at or below the floor
/// count as seen.
#[derive(Debug, Default)]
struct SeenIds {
    set: std::collections::HashSet<u64>,
    order: VecDeque<u64>,
    floor: Option<u64>,
}

/// A pending fold group (R4, R25 item 1): one binding and transaction,
/// its records merged as they come (never kept): the block-ful part and
/// the block-less part.
#[derive(Debug, Clone)]
struct Group {
    key: Key,
    tra: u64,
    /// Block-ful records merged.
    full: Part,
    /// Block-less records merged (H1 fix 2 if not folded).
    bare: Part,
    started: Instant,
    /// The position of its first record (the persisted position is held
    /// back to it).
    first: u64,
    /// The position of its first block-less record (R25 item 1).
    first_bare: Option<u64>,
}

impl Group {
    fn blockless(&self) -> bool {
        self.bare.count > 0
    }

    /// The group's state in bytes (R25 item 4's budget).
    fn bytes(&self) -> usize {
        128 + self.full.bytes + self.bare.bytes
    }
}

/// Merged records of one part of a group (R25 item 1): their count, at
/// most [`MAX_GROUP_NAMES`] routine names and [`MAX_GROUP_NAMES`]
/// relations (past either, `*` and the always-reported mark, never
/// ambiguous), the largest row count, the signals.
#[derive(Debug, Clone, Default)]
struct Part {
    count: u64,
    names: Vec<String>,
    rels: Vec<String>,
    overflow: bool,
    rows: Option<u64>,
    signals: Vec<databastion_classifiers::masking::Signal>,
    always: bool,
    /// `*` from a member (a view over an always-reported relation).
    star: bool,
    write: bool,
    bytes: usize,
}

/// R25 item 2: names and relations kept per group part.
const MAX_GROUP_NAMES: usize = 256;
/// R25 items 4 and 6: group state and held state, each per stream.
const MAX_STATE_BYTES: usize = 16 << 20;

impl Part {
    fn add(&mut self, m: Member) {
        self.count += 1;
        let keep = |v: &mut Vec<String>, o: String, overflow: &mut bool, bytes: &mut usize| {
            if v.contains(&o) {
                return;
            }
            if v.len() >= MAX_GROUP_NAMES {
                *overflow = true;
                return;
            }
            *bytes += o.len() + 24;
            v.push(o);
        };
        keep(&mut self.names, m.name, &mut self.overflow, &mut self.bytes);
        for o in m.draft.objects {
            keep(&mut self.rels, o, &mut self.overflow, &mut self.bytes);
        }
        self.rows = match (self.rows, m.draft.rows) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        for sg in m.draft.signals {
            if !self.signals.contains(&sg) {
                self.signals.push(sg);
            }
        }
        self.always |= m.draft.always;
        self.star |= m.draft.star;
        self.write |= m.draft.action == Some(databastion_classifiers::masking::EventAction::Write);
    }

    fn draft(&self) -> Draft {
        use databastion_classifiers::masking::EventAction;
        let mut objects = self.rels.clone();
        for n in &self.names {
            if !objects.contains(n) {
                objects.push(n.clone());
            }
        }
        Draft {
            action: Some(if self.write {
                EventAction::Write
            } else {
                EventAction::Read
            }),
            objects,
            star: self.overflow || self.star,
            always: self.always || self.overflow,
            rows: self.rows,
            signals: self.signals.clone(),
        }
    }
}

/// One routine record for its group.
#[derive(Debug, Clone)]
struct Member {
    /// The routine's name (R4's folded object name).
    name: String,
    /// Its block's relations, rows and signals.
    draft: Draft,
    block_less: bool,
}

/// One output waiting for the hold to end (R8 item 2).
#[derive(Debug)]
struct Held {
    db: Vec<usize>,
    event: MaskedEvent,
}

/// The held state of one event, in bytes (R25 item 6's budget).
fn held_bytes(ev: &MaskedEvent) -> usize {
    256 + ev.objects().len() * 160
}

/// Facts of the run (R1 rule 1, R5 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Run {
    pub(crate) pid: u32,
    /// `/proc/<pid>/stat` field 22, `None` when not visible.
    pub(crate) start: Option<u64>,
}

/// Counters for notes and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) records: u64,
    pub(crate) ambiguous: u64,
    pub(crate) undeclared_dropped: u64,
    pub(crate) own: u64,
    pub(crate) panics: u64,
    pub(crate) oversized: u64,
    /// Records of each declared database parsed (proof 9), by index.
    pub(crate) parsed_declared: u64,
    /// Records read again after a restart, and emitted again (R39 (a)).
    pub(crate) reread: u64,
    /// Bindings evicted under R1 rule 11's global cap.
    pub(crate) evicted: u64,
    /// Statement records of the agent's own anchored attachments whose
    /// block or count matched no credit's own-statement table row (the
    /// engine-matrix test of R20 expects none).
    pub(crate) own_not_matched: u64,
}

/// The stream's settings.
pub(crate) struct Settings {
    pub(crate) databases: Vec<DeclaredNames>,
    pub(crate) aliases: Option<AliasMap>,
    /// Proof 11 holds (R1 rule 8).
    pub(crate) proof11: bool,
    /// The agent's account (upper-cased, as the server stores it).
    pub(crate) account: String,
    pub(crate) parse: ParseOptions,
    /// SuperServer proven (R6, R16): the internal shape applies.
    pub(crate) superserver: bool,
}

/// The state machine.
pub(crate) struct Machine {
    s: Settings,
    run: Option<Run>,
    /// Records are ambiguous until the next confirmation (R5 item 4).
    unconfirmed: bool,
    failed_pids: Vec<u32>,
    bindings: HashMap<Key, Binding>,
    token_live: HashMap<(u32, u64), Key>,
    /// Tokens whose binding ended at the last record that carried them
    /// (R5 item 2: the `TRACE_FINI` after it).
    token_ended: HashMap<(u32, u64), ()>,
    /// Their order, for the bound (stale entries skipped).
    token_ended_order: VecDeque<(u32, u64)>,
    services: HashMap<(u32, u64), bool>,
    highest: HashMap<DbId, (u64, Instant)>,
    seen_ids: HashMap<DbId, SeenIds>,
    /// Ids kept in `seen_ids`, every identity (the global cap).
    seen_total: usize,
    /// Bindings per database identity (the per-database caps).
    binding_count: HashMap<DbId, usize>,
    /// Evictable bindings (learned, or of an undeclared database), oldest
    /// first, with their sequence number (R1 rule 11).
    evictable: VecDeque<(u64, Key)>,
    next_seq: u64,
    /// R1 rule 11's learned floor per database identity.
    learned_floor: HashMap<DbId, u64>,
    watermark: HashMap<usize, u64>,
    internal: HashMap<DbId, Key>,
    gc_alone_since: HashMap<DbId, Instant>,
    window_until: Option<Instant>,
    groups: VecDeque<Group>,
    held: Vec<Held>,
    /// The held state in bytes (R25 item 6).
    held_bytes: usize,
    hold_since: Option<Instant>,
    /// The declared database of the last well-formed record (fix 3).
    last_declared: Option<usize>,
    /// Local time offset: agent time minus the server's printed time,
    /// confirmed by a credited own record (review M3).
    offset: Option<i64>,
    /// An offset learned from an own attach, not confirmed yet.
    /// `(offset, binding, needs the probe)`: a change of more than an hour
    /// from the confirmed offset is applied only on the probe (R42 item 3).
    offset_pending: Option<(i64, Key, bool)>,
    /// Read-back probe records seen per own binding (R42 item 2: a probe
    /// that confirms must be unique on its binding).
    probe_records: HashMap<Key, u32>,
    /// The binding whose credited record confirmed the offset, and the
    /// offset before it (restored if that binding is poisoned).
    offset_from: Option<(Key, Option<i64>)>,
    /// Declared databases whose dependent and block-blind sets are
    /// invalidated (R28 item 4, R41 item 8).
    views_invalid: std::collections::HashSet<usize>,
    /// DDL transactions seen without their end record: binding and
    /// transaction, and the database (R41 item 8).
    ddl_open: HashMap<(Key, u64), usize>,
    /// Per database: after an ambiguous DDL record whose transaction could
    /// not be kept in `ddl_open`, the transactions known open on that
    /// database at the record; invalidated until each has ended (re-review
    /// M-1).
    ddl_wait: HashMap<usize, std::collections::HashSet<(Key, u64)>>,
    /// Databases invalidated until the run ends (an ambiguous DDL record
    /// with nothing to wait on).
    run_sticky: std::collections::HashSet<usize>,
    /// Per database: a check's catalog read must start after this to
    /// clear the invalidation (the latest invalidating record or DDL
    /// transaction end, agent clock).
    invalid_after: HashMap<usize, SystemTime>,
    /// Per database: relations named by DDL texts in the interval.
    ddl_named: HashMap<usize, std::collections::HashSet<String>>,
    /// Databases where an unparsable or ambiguous DDL record makes every
    /// relation dependent.
    all_relations: std::collections::HashSet<usize>,
    /// The `(st_dev, st_ino)` of the log file being read (the ledger keys
    /// consumed credits by record position).
    file: (u64, u64),
    ledger: std::sync::Arc<Ledger>,
    hash_key: std::collections::hash_map::RandomState,
    /// Groups ended by the record being judged, emitted in `apply`.
    pending_end: Vec<Group>,
    pub(crate) counts: Counts,
    /// A view DDL record asks for an early check (R28 item 4).
    pub(crate) check_requested: bool,
    /// The record being judged is of the agent's own anchored binding
    /// inside a split window: it ends the window only if it is the agent's
    /// own (R1 rule 7, re-review L-C).
    window_ender: bool,
    /// The read-back probe's own record was read (proof 7).
    pub(crate) probe_seen: Option<SystemTime>,
    /// Ambiguous records by the rule (source line) that judged them, for
    /// the tests and the local detail.
    pub(crate) why: std::collections::BTreeMap<u32, u64>,
}

/// What the machine emits: an event and the declared databases it goes to.
pub(crate) type Emitted = (usize, MaskedEvent);

impl Machine {
    pub(crate) fn new(s: Settings, ledger: std::sync::Arc<Ledger>) -> Self {
        Self {
            s,
            run: None,
            unconfirmed: false,
            failed_pids: Vec::new(),
            bindings: HashMap::new(),
            token_live: HashMap::new(),
            token_ended: HashMap::new(),
            token_ended_order: VecDeque::new(),
            services: HashMap::new(),
            highest: HashMap::new(),
            seen_ids: HashMap::new(),
            seen_total: 0,
            binding_count: HashMap::new(),
            evictable: VecDeque::new(),
            next_seq: 0,
            learned_floor: HashMap::new(),
            watermark: HashMap::new(),
            internal: HashMap::new(),
            gc_alone_since: HashMap::new(),
            window_until: None,
            groups: VecDeque::new(),
            held: Vec::new(),
            held_bytes: 0,
            hold_since: None,
            last_declared: None,
            offset: None,
            offset_pending: None,
            probe_records: HashMap::new(),
            offset_from: None,
            file: (0, 0),
            views_invalid: std::collections::HashSet::new(),
            ddl_open: HashMap::new(),
            ddl_wait: HashMap::new(),
            run_sticky: std::collections::HashSet::new(),
            invalid_after: HashMap::new(),
            ddl_named: HashMap::new(),
            all_relations: std::collections::HashSet::new(),
            ledger,
            hash_key: std::collections::hash_map::RandomState::new(),
            pending_end: Vec::new(),
            counts: Counts::default(),
            check_requested: false,
            window_ender: false,
            probe_seen: None,
            why: std::collections::BTreeMap::new(),
        }
    }

    /// Test support: the confirmed clock offset.
    #[cfg(test)]
    pub(crate) fn offset_for_tests(&self) -> Option<i64> {
        self.offset
    }

    /// Test support: fills `ddl_open` with another binding's DDL
    /// transactions on database `db`.
    #[cfg(test)]
    pub(crate) fn fill_ddl_open_for_tests(&mut self, db: usize) {
        for t in 0..MAX_DDL_OPEN as u64 {
            self.ddl_open.insert(((DbId::Declared(db), 50), t), db);
        }
    }

    /// Test support: the DDL transactions tracked.
    #[cfg(test)]
    pub(crate) fn ddl_open_len_for_tests(&self) -> usize {
        self.ddl_open.len()
    }

    /// The log file the next records come from.
    pub(crate) fn set_file(&mut self, file: (u64, u64)) {
        self.file = file;
    }

    /// New settings from a re-evaluation (names, map, proof 11).
    pub(crate) fn reconfigure(&mut self, s: Settings) {
        self.s = s;
        // R41 item 8: a database's sets are valid again only when this
        // check's catalog read started after every DDL transaction seen
        // since ended (none still open) and after the latest invalidating
        // record.
        let open: std::collections::HashSet<usize> = self
            .ddl_open
            .values()
            .copied()
            .chain(self.ddl_wait.keys().copied())
            .chain(self.run_sticky.iter().copied())
            .collect();
        let clear: Vec<usize> = self
            .views_invalid
            .iter()
            .copied()
            .filter(|db| {
                !open.contains(db)
                    && self
                        .s
                        .databases
                        .get(*db)
                        .and_then(|d| d.read_at)
                        .is_some_and(|r| self.invalid_after.get(db).is_none_or(|a| r > *a))
            })
            .collect();
        for db in clear {
            self.views_invalid.remove(&db);
            self.invalid_after.remove(&db);
            self.ddl_named.remove(&db);
            self.all_relations.remove(&db);
        }
    }

    /// R41 item 8: the database's sets are invalidated from now.
    fn invalidate(&mut self, db: usize, wall: SystemTime) {
        self.views_invalid.insert(db);
        let a = self.invalid_after.entry(db).or_insert(wall);
        *a = (*a).max(wall);
        self.check_requested = true;
    }

    /// A run confirmed by `check()` or a `/proc` sample (R1 rule 1, R5
    /// item 4). A different pid or start time ends every binding of the
    /// old run.
    pub(crate) fn confirm_run(&mut self, run: Run) {
        // Review N1: a provisional run (no start time, the first pid seen)
        // is compared by its pid only.
        let other = self.run.is_some_and(|r| match r.start {
            None => r.pid != run.pid,
            Some(_) => r != run,
        });
        if other {
            self.end_run();
        }
        self.run = Some(run);
        self.unconfirmed = false;
    }

    /// A `/proc` sample that shows another start time than the current
    /// run's: records are ambiguous until `check()` confirms (R5 item 4).
    pub(crate) fn start_time_changed(&mut self) {
        self.unconfirmed = true;
    }

    fn end_run(&mut self) {
        // Re-review L-5: the run's DDL transactions end with it.
        let wall = SystemTime::now();
        let dbs: Vec<usize> = self
            .ddl_open
            .values()
            .copied()
            .chain(self.ddl_wait.keys().copied())
            .chain(self.run_sticky.iter().copied())
            .collect();
        self.ddl_open.clear();
        self.ddl_wait.clear();
        self.run_sticky.clear();
        for db in dbs {
            self.invalidate(db, wall);
        }
        self.probe_records.clear();
        // Review L-B: the run's pending groups end as R25 item 3 says (at the
        // next record or reading-time bound), never dropped silently.
        let groups: Vec<Group> = self.groups.drain(..).collect();
        self.pending_end.extend(groups);
        self.bindings.clear();
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
        self.failed_pids.clear();
    }

    /// The stream's state in bytes, estimated (R1 rule 11's global cap).
    pub(crate) fn state_bytes(&self) -> usize {
        self.bindings.len() * BINDING_BYTES
            + self.seen_total * 16
            + self.token_ended.len() * 48
            + self.token_ended_order.len() * 16
            + (self.highest.len() + self.seen_ids.len() + self.binding_count.len()) * 64
            + self.services.len() * 48
            + self.evictable.len() * 32
            + self.groups.iter().map(Group::bytes).sum::<usize>()
            + self.held_bytes
    }

    /// Whether `id` was seen for the database identity: kept, or at or
    /// below the seen-id floor (R30 review L7).
    fn is_seen(&self, db: DbId, id: u64) -> bool {
        self.seen_ids
            .get(&db)
            .is_some_and(|s| s.set.contains(&id) || s.floor.is_some_and(|f| id <= f))
    }

    /// Room for the database identity: declared, already known, or fewer
    /// than 256 undeclared identities known (R1 rule 11).
    fn identity_room(&self, db: DbId) -> bool {
        match db {
            DbId::Declared(_) => true,
            DbId::Undeclared(_) => {
                self.seen_ids.contains_key(&db)
                    || self.binding_count.contains_key(&db)
                    || self
                        .seen_ids
                        .keys()
                        .filter(|d| matches!(d, DbId::Undeclared(_)))
                        .count()
                        < MAX_UNDECLARED
            }
        }
    }

    /// Whether a new binding of `db` may be kept (R1 rule 11): its
    /// identity has room, its database is under its cap, and the global
    /// cap holds, after evicting the oldest evictable bindings if needed.
    /// `false`: the binding is not kept and its record is ambiguous.
    fn admit(&mut self, db: DbId) -> bool {
        if !self.identity_room(db) {
            return false;
        }
        let cap = match db {
            DbId::Declared(_) => MAX_BINDINGS_DECLARED,
            DbId::Undeclared(_) => MAX_BINDINGS_UNDECLARED,
        };
        if self.binding_count.get(&db).copied().unwrap_or(0) >= cap {
            return false;
        }
        // The binding and what comes with it (its seen id, its token, the
        // highest id): a margin.
        while self.state_bytes() + BINDING_BYTES + 1024 > MAX_STREAM_BYTES {
            if !self.evict_one() {
                return false;
            }
        }
        true
    }

    /// Evicts the oldest evictable binding (learned, or of an undeclared
    /// database; never an anchored binding of a declared database). Its
    /// records become ambiguous (its id stays seen), its pending groups
    /// end, and a learned eviction raises the learned floor.
    fn evict_one(&mut self) -> bool {
        while let Some((seq, key)) = self.evictable.pop_front() {
            if !self.bindings.get(&key).is_some_and(|b| b.seq == seq) {
                continue;
            }
            let Some(b) = self.remove_binding(key) else {
                continue;
            };
            self.token_live.remove(&b.token);
            let groups: Vec<Group> = self
                .groups
                .iter()
                .filter(|g| g.key == key)
                .cloned()
                .collect();
            self.groups.retain(|g| g.key != key);
            self.pending_end.extend(groups);
            if !b.anchored {
                let f = self.learned_floor.entry(key.0).or_insert(0);
                *f = (*f).max(key.1);
            }
            // Re-review L-5: its DDL transactions end with it.
            let wall = SystemTime::now();
            let ended: Vec<(Key, u64)> = self
                .ddl_open
                .keys()
                .filter(|(k, _)| *k == key)
                .copied()
                .collect();
            for e in ended {
                if let Some(db) = self.ddl_open.remove(&e) {
                    self.invalidate(db, wall);
                }
            }
            for w in self.ddl_wait.values_mut() {
                w.retain(|(k, _)| *k != key);
            }
            let done: Vec<usize> = self
                .ddl_wait
                .iter()
                .filter(|(_, w)| w.is_empty())
                .map(|(db, _)| *db)
                .collect();
            for db in done {
                self.ddl_wait.remove(&db);
                self.invalidate(db, wall);
            }
            self.counts.evicted += 1;
            return true;
        }
        false
    }

    fn insert_binding(&mut self, key: Key, mut b: Binding) {
        b.seq = self.next_seq;
        self.next_seq += 1;
        if !b.anchored || matches!(key.0, DbId::Undeclared(_)) {
            self.evictable.push_back((b.seq, key));
        }
        *self.binding_count.entry(key.0).or_insert(0) += 1;
        if let Some(old) = self.bindings.insert(key, b) {
            // Replaced (not expected): the count stays one.
            let _ = old;
            if let Some(n) = self.binding_count.get_mut(&key.0) {
                *n = n.saturating_sub(1);
            }
        }
    }

    fn remove_binding(&mut self, key: Key) -> Option<Binding> {
        let b = self.bindings.remove(&key)?;
        if let Some(n) = self.binding_count.get_mut(&key.0) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.binding_count.remove(&key.0);
            }
        }
        Some(b)
    }

    /// A token whose binding ended (R5 item 2), bounded, oldest first.
    fn end_token(&mut self, token: (u32, u64)) {
        if self.token_ended.insert(token, ()).is_none() {
            self.token_ended_order.push_back(token);
        }
        // Bounded, and under the global cap (a dropped token's `TRACE_FINI`
        // is ambiguous: fail closed).
        while self.token_ended_order.len() > MAX_TOKENS_ENDED
            || (self.state_bytes() > MAX_STREAM_BYTES && !self.token_ended_order.is_empty())
        {
            if let Some(t) = self.token_ended_order.pop_front() {
                self.token_ended.remove(&t);
            }
        }
    }

    /// The position the persisted cursor may advance to: the first record
    /// of the oldest pending group (R25 item 7), `None` when nothing pends.
    pub(crate) fn held_from(&self) -> Option<u64> {
        self.groups.iter().map(|g| g.first).min()
    }

    /// R28 item 4, R41 item 8: what invalidates the dependent and
    /// block-blind sets, and what ends a DDL transaction.
    /// - any DDL statement record of a declared database (its relations
    ///   join the interval's named set; a text that does not parse makes
    ///   every relation dependent), opening a DDL transaction until its end
    ///   record (or its binding's end);
    /// - an ambiguous DDL record: every declared database, every relation;
    /// - `DROP_DATABASE`, `CREATE_DATABASE` and a services restore of a
    ///   declared database.
    ///
    /// Each asks for an early check, and so does the end of a DDL
    /// transaction (R11 8d's merging).
    /// A DDL record whose transaction cannot be kept in `ddl_open` (not
    /// resolved, or no room): each database waits for every transaction
    /// known open on it at the record; when the record's own transaction is
    /// not among them, or they are too many, until the run ends (re-review
    /// M-1, never fail open).
    fn hold_ddl(&mut self, dbs: &[usize], key: Option<Key>, tra: Option<u64>) {
        for &db in dbs {
            let open: std::collections::HashSet<(Key, u64)> = self
                .bindings
                .iter()
                .filter(|(k, _)| k.0 == DbId::Declared(db))
                .flat_map(|(k, b)| b.open_tras.iter().map(move |t| (*k, *t)))
                .collect();
            let own_known = key.is_some_and(|k| tra.is_some_and(|t| open.contains(&(k, t))));
            if !own_known || open.len() > MAX_DDL_OPEN {
                self.run_sticky.insert(db);
            } else {
                self.ddl_wait.entry(db).or_default().extend(open);
            }
        }
    }

    fn note_ddl(&mut self, rec: &Record<'_>, decision: &Decision, wall: SystemTime) {
        let key = rec.att.and_then(|att| match self.resolve(att.database) {
            Resolved::Db(d) => Some((d, att.id)),
            Resolved::Ambiguous => None,
        });
        // The end of a DDL transaction, or of its binding.
        let tra = rec.tra.map(|t| t.id);
        let ended: Vec<(Key, u64)> = match rec.header.event {
            Event::CommitTransaction | Event::RollbackTransaction => self
                .ddl_open
                .keys()
                .filter(|(k, t)| Some(*k) == key && Some(*t) == tra)
                .copied()
                .collect(),
            Event::DetachDatabase | Event::DropDatabase => self
                .ddl_open
                .keys()
                .filter(|(k, _)| Some(*k) == key)
                .copied()
                .collect(),
            _ => Vec::new(),
        };
        for e in ended {
            if let Some(db) = self.ddl_open.remove(&e) {
                self.invalidate(db, wall);
            }
        }
        // The transactions an ambiguous DDL record waits on (M-1).
        let ends = |(k, t): &(Key, u64)| match rec.header.event {
            Event::CommitTransaction | Event::RollbackTransaction => {
                Some(*k) == key && Some(*t) == tra
            }
            Event::DetachDatabase | Event::DropDatabase => Some(*k) == key,
            _ => false,
        };
        let mut done = Vec::new();
        for (db, w) in &mut self.ddl_wait {
            w.retain(|e| !ends(e));
            if w.is_empty() {
                done.push(*db);
            }
        }
        for db in done {
            self.ddl_wait.remove(&db);
            self.invalidate(db, wall);
        }
        match (&rec.body, rec.header.event, decision) {
            (Body::Statement { text, .. }, _, _) => {
                let a = analyze_firebird(text);
                if a.kind != FirebirdKind::Ddl {
                    return;
                }
                match decision {
                    Decision::Ambiguous { .. } => {
                        // Re-review M-1: the DDL transaction is kept open
                        // under its resolved binding and transaction, so a
                        // check before its end does not clear the sets.
                        let dbs: Vec<usize> = match key {
                            Some((DbId::Declared(i), _)) => vec![i],
                            _ => (0..self.s.databases.len()).collect(),
                        };
                        for db in &dbs {
                            self.invalidate(*db, wall);
                            self.all_relations.insert(*db);
                        }
                        match (key, tra) {
                            (Some(k @ (DbId::Declared(i), _)), Some(t))
                                if self.ddl_open.len() < MAX_DDL_OPEN =>
                            {
                                self.ddl_open.insert((k, t), i);
                            }
                            _ => self.hold_ddl(&dbs, key, tra),
                        }
                    }
                    Decision::Normal { db, key } => {
                        let db = *db;
                        self.invalidate(db, wall);
                        if a.parses() {
                            let named = self.ddl_named.entry(db).or_default();
                            for r in a.relations.iter().chain(&a.procedures) {
                                if named.len() < 4096 {
                                    named.insert(r.trim_end_matches(' ').to_owned());
                                }
                            }
                        } else {
                            self.all_relations.insert(db);
                        }
                        match (key, tra) {
                            (Some(k), Some(t)) if self.ddl_open.len() < MAX_DDL_OPEN => {
                                self.ddl_open.insert((*k, t), db);
                            }
                            // No room, or no transaction: held as an
                            // unresolved record is (never fail open).
                            _ => self.hold_ddl(&[db], *key, tra),
                        }
                    }
                    _ => {}
                }
            }
            (_, Event::DropDatabase | Event::CreateDatabase, Decision::Normal { db, .. }) => {
                self.invalidate(*db, wall);
            }
            (
                Body::Service {
                    name:
                        Some(ServiceName::RestoreDatabase | ServiceName::IncrementalRestoreDatabase),
                    ..
                },
                _,
                Decision::Normal { db, .. },
            ) => self.invalidate(*db, wall),
            _ => {}
        }
    }

    /// R41 items 3 and 6: whether a record names an object of the dependent
    /// set: any identifier token of its text (both dialect readings,
    /// packaged names by their package), its text's relations and routines
    /// and its block's relations at object positions (where a name unknown
    /// to the catalog read counts too), a routine record's name line, and a
    /// non-ASCII quoted identifier from an attachment whose character set
    /// is not `UTF8`.
    fn dependent_hit(&self, rec: &Record<'_>, cat: &dyn Catalog) -> bool {
        if let Some(b) = &rec.trailer.block
            && b.iter().any(|(n, _)| cat.always_view(n))
        {
            return true;
        }
        match &rec.body {
            Body::Statement { text, .. } => {
                // Re-review L-2: the connector's own constant texts are
                // matched at object positions only (their other tokens are
                // its column names, aliases and built-in calls).
                let ids = if crate::sql::checked(text) {
                    crate::idents::Idents::default()
                } else {
                    crate::idents::idents(text)
                };
                if ids.cut
                    || ids.names.iter().any(|n| cat.dependent_token(n))
                    || ids.packaged.iter().any(|(p, _)| cat.dependent_token(p))
                {
                    return true;
                }
                if ids.non_ascii_quoted && rec.att.is_none_or(|a| a.charset != "UTF8") {
                    return true;
                }
                let a = analyze_firebird(text);
                a.relations
                    .iter()
                    .chain(&a.procedures)
                    .any(|n| cat.always_view(n))
            }
            Body::Routine { name, .. } => cat.always_view(name.name),
            _ => false,
        }
    }

    /// R42 item 2: a provisional offset is confirmed only by a record
    /// whose own measured offset (`measured`: the connector's time of the
    /// statement against the record's printed time) is within 5 s of it:
    /// a credited own record of the binding that learned it, or the
    /// read-back probe (`by_probe`, on any own binding: the probe alone
    /// confirms a change of more than an hour, item 3).
    fn confirm_offset(&mut self, key: Key, by_probe: bool, measured: Option<i64>) {
        if let Some((o, k, needs_probe)) = self.offset_pending
            && measured.is_some_and(|m| (m - o).abs() <= 5)
            && (by_probe || (k == key && !needs_probe))
        {
            self.offset_from = Some((k, self.offset));
            self.offset = Some(o);
            self.offset_pending = None;
        }
    }

    /// A record's time: the printed time with `offset`, bounded by the
    /// observation (not later than now plus 5 s, R42 item 5).
    fn record_time(&self, t: LogTime, offset: Option<i64>) -> SystemTime {
        let naive = naive_seconds(t) + offset.unwrap_or(0);
        let printed = u64::try_from(naive)
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        printed.min(SystemTime::now() + crate::own::LIFETIME_SLACK)
    }

    /// The offset's binding poisoned (or the pending one): reverted.
    fn check_offset_binding(&mut self) {
        let poisoned = |m: &Self, k: &Key| m.bindings.get(k).is_some_and(|b| b.poisoned);
        if let Some((_, k, _)) = self.offset_pending
            && poisoned(self, &k)
        {
            self.offset_pending = None;
        }
        if let Some((k, prev)) = self.offset_from
            && poisoned(self, &k)
        {
            self.offset = prev;
            self.offset_from = None;
        }
    }

    fn hash(&self, name: &str) -> u64 {
        use std::hash::BuildHasher;
        self.hash_key.hash_one(name)
    }

    fn resolve(&self, printed: &str) -> Resolved {
        if printed.len() > 4096 {
            return Resolved::Ambiguous;
        }
        for (i, d) in self.s.databases.iter().enumerate() {
            let mine =
                d.resolved.as_deref() == Some(printed) || d.alias.as_deref() == Some(printed);
            if mine {
                return if d.excluded {
                    Resolved::Db(DbId::Undeclared(self.hash(printed)))
                } else {
                    Resolved::Db(DbId::Declared(i))
                };
            }
        }
        let path = if printed.starts_with('/') {
            Some(printed.to_owned())
        } else {
            match self.s.aliases.as_ref().map(|m| m.get(printed)) {
                Some(Some(a)) => match &a.path {
                    Some(p) => Some(p.clone()),
                    None => return Resolved::Ambiguous,
                },
                // Not in the map, or no map (R2 rule 2).
                _ => return Resolved::Ambiguous,
            }
        };
        let Some(path) = path else {
            return Resolved::Ambiguous;
        };
        for (i, d) in self.s.databases.iter().enumerate() {
            if d.resolved.as_deref() == Some(path.as_str()) {
                return if d.excluded {
                    Resolved::Db(DbId::Undeclared(self.hash(&path)))
                } else {
                    Resolved::Db(DbId::Declared(i))
                };
            }
        }
        let file = |p: &str| p.rsplit('/').next().map(str::to_owned);
        if self.s.databases.iter().any(|d| {
            d.resolved
                .as_deref()
                .is_some_and(|r| file(r) == file(&path))
                || d.alias
                    .as_deref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(printed))
        }) {
            return Resolved::Ambiguous;
        }
        Resolved::Db(DbId::Undeclared(self.hash(&path)))
    }

    /// Converts a header time with the learned offset (decision 6: the
    /// server's local time).
    fn time(&self, t: LogTime) -> SystemTime {
        let naive = naive_seconds(t);
        let secs = naive + self.offset.unwrap_or(0);
        let base = SystemTime::UNIX_EPOCH;
        let frac = Duration::from_micros(u64::from(t.frac) * 100);
        match u64::try_from(secs) {
            Ok(s) => base + Duration::from_secs(s) + frac,
            Err(_) => base,
        }
    }

    /// One assembled record at log offset `pos` (its first byte), read at
    /// reading time `now`. Events go to `out`. A record re-read after a
    /// restart is judged and emitted as on its first reading (R39 (a):
    /// without a state checkpoint it may be judged differently, so nothing
    /// is suppressed; duplicates are the accepted over-reporting).
    pub(crate) fn push(
        &mut self,
        raw: &[u8],
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
        self.counts.records += 1;
        // Review L3: the whole record (parse, judgement, view sets, event)
        // under the panic isolation; a record that panics, or whose header
        // does not parse, is ambiguous (loud), never dropped.
        let done = databastion_core::isolate(|| self.record(raw, pos, now, cat, out));
        match done {
            Some(true) => {}
            Some(false) => self.loud(now, cat, out),
            None => {
                self.counts.panics += 1;
                self.loud(now, cat, out);
            }
        }
    }

    /// One record; `false` when it does not parse.
    fn record(
        &mut self,
        raw: &[u8],
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) -> bool {
        // R28 item 4: after a view DDL record, until the next check, every
        // view (and every name the catalog read does not know) counts as
        // dependent.
        let named = std::mem::take(&mut self.ddl_named);
        let all = self.all_relations.clone();
        let invalid = self.views_invalid.clone();
        let wrapped: Vec<Invalidated<'_>> = cat
            .iter()
            .enumerate()
            .map(|(i, c)| Invalidated {
                inner: *c,
                invalid: invalid.contains(&i),
                named: named.get(&i),
                all: all.contains(&i),
            })
            .collect();
        let cats: Vec<&dyn Catalog> = wrapped.iter().map(|w| w as &dyn Catalog).collect();
        let done = self.record_in(raw, pos, now, &cats, out);
        drop(cats);
        drop(wrapped);
        // The names of the interval, with those this record added.
        for (db, n) in named {
            self.ddl_named.entry(db).or_default().extend(n);
        }
        done
    }

    fn record_in(
        &mut self,
        raw: &[u8],
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) -> bool {
        self.expire(now, cat, out);
        let Some(rec) = parse(raw, self.s.parse) else {
            return false;
        };
        self.window_ender = false;
        // Test support: a record that makes the rules panic (L3's test).
        #[cfg(test)]
        if raw.ends_with(b"\nPANIC-FOR-TESTS") {
            panic!("a test panic");
        }
        let decision = self.judge(&rec, pos, now, cat);
        self.check_offset_binding();
        self.note_ddl(&rec, &decision, SystemTime::now());
        self.apply(decision, &rec, pos, now, cat, out);
        true
    }

    /// A record that could not be read (review H1): longer than the
    /// assembler's bound (`Oversized`), or lines before any header
    /// (`Orphan`). Nothing of it is known, so it is ambiguous: an event
    /// naming `*`, always reported, attributed by fix 3 (the preceding
    /// well-formed record's database, or every declared database), counted
    /// as ambiguous (proof 8), and it opens a split window (it may hide a
    /// split, H1 fix 2).
    pub(crate) fn unreadable(
        &mut self,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
        self.counts.records += 1;
        self.counts.oversized += 1;
        self.loud(now, cat, out);
    }

    /// A record of which nothing is known (unreadable, unparsable, or its
    /// rules panicked): `*`, always reported, fix 3, a window.
    fn loud(&mut self, now: Instant, cat: &[&dyn Catalog], out: &mut Vec<Emitted>) {
        self.counts.ambiguous += 1;
        *self.why.entry(line!()).or_default() += 1;
        let wrapped: Vec<Invalidated<'_>> = cat
            .iter()
            .map(|c| Invalidated {
                inner: *c,
                invalid: false,
                named: None,
                all: false,
            })
            .collect();
        let cats: Vec<&dyn Catalog> = wrapped.iter().map(|w| w as &dyn Catalog).collect();
        self.expire(now, &cats, out);
        self.window_until = Some(now + WINDOW);
        let d = Draft {
            action: Some(databastion_classifiers::masking::EventAction::Read),
            star: true,
            always: true,
            ..Draft::default()
        };
        let dbs: Vec<usize> = match self.last_declared {
            Some(i) => vec![i],
            None => (0..self.s.databases.len())
                .filter(|i| !self.s.databases[*i].excluded)
                .collect(),
        };
        for db in dbs {
            let ev = self.draft_event(&d, None, db);
            self.emit(db, ev, out);
        }
    }

    /// Ends every pending group and releases the held records (a log
    /// rotation, review M3): as R25 item 3 says, the block-ful part of a
    /// group becomes its event and its block-less part is ambiguous.
    pub(crate) fn end_all(&mut self, now: Instant, cat: &[&dyn Catalog], out: &mut Vec<Emitted>) {
        while let Some(g) = self.groups.pop_front() {
            self.end_group(g, now, cat, out);
        }
        if self.hold_since.is_some() {
            self.release(false, out);
        }
    }

    /// The bounds that run on reading time: windows, groups, holds, the
    /// Garbage Collector's expected end.
    pub(crate) fn expire(&mut self, now: Instant, cat: &[&dyn Catalog], out: &mut Vec<Emitted>) {
        if self.window_until.is_some_and(|u| now >= u) {
            self.window_until = None;
        }
        // Groups ended outside a record (a run's end, an eviction).
        for g in std::mem::take(&mut self.pending_end) {
            self.end_group(g, now, cat, out);
        }
        while let Some(g) = self.groups.front() {
            let blockless = g.blockless();
            let bound = if blockless { HOLD_TIME } else { GROUP_TIME };
            if now.duration_since(g.started) < bound {
                break;
            }
            let Some(g) = self.groups.pop_front() else {
                break;
            };
            self.end_group(g, now, cat, out);
        }
        if self.hold_since.is_some() && !self.groups.iter().any(Group::blockless) {
            self.release(false, out);
        }
        let gone: Vec<DbId> = self
            .gc_alone_since
            .iter()
            .filter(|(_, t)| now.duration_since(**t) > GC_END)
            .map(|(d, _)| *d)
            .collect();
        for d in gone {
            self.gc_alone_since.remove(&d);
            if let Some(k) = self.internal.remove(&d)
                && let Some(b) = self.remove_binding(k)
            {
                self.token_live.remove(&b.token);
            }
        }
    }

    fn release(&mut self, ambiguous: bool, out: &mut Vec<Emitted>) {
        self.hold_since = None;
        self.held_bytes = 0;
        for h in std::mem::take(&mut self.held) {
            let ev = if ambiguous {
                self.counts.ambiguous += 1;
                h.event.with_always_report()
            } else {
                h.event
            };
            for d in h.db {
                out.push((d, ev.clone()));
            }
        }
    }

    fn live_others(&self, db: DbId, except: Key) -> bool {
        self.bindings
            .iter()
            .any(|(k, b)| k.0 == db && *k != except && b.kind != Kind::Internal)
    }
}

/// A database's catalog while its sets are invalidated (R28 item 4, R41
/// item 8): every view, routine, package, trigger and unknown name, every
/// table with a computed column at the last read, every name a DDL text of
/// the interval named, and every relation after an unparsable or
/// ambiguous DDL record count as dependent.
struct Invalidated<'a> {
    inner: &'a dyn Catalog,
    invalid: bool,
    named: Option<&'a std::collections::HashSet<String>>,
    all: bool,
}

impl Catalog for Invalidated<'_> {
    fn class(&self, relation: &str) -> crate::trace_events::RelClass {
        self.inner.class(relation)
    }

    fn always_view(&self, relation: &str) -> bool {
        use crate::trace_events::RelClass;
        if self.inner.always_view(relation) {
            return true;
        }
        if !self.invalid {
            return false;
        }
        let r = relation.trim_end_matches(' ');
        let class = self.inner.class(r);
        matches!(class, RelClass::View | RelClass::Unknown)
            || self.inner.computed(r)
            || self.named.is_some_and(|n| n.contains(r))
            || (self.all && !matches!(class, RelClass::System | RelClass::Virtual))
    }

    fn dependent_token(&self, name: &str) -> bool {
        self.inner.dependent_token(name)
            || (self.invalid
                && self
                    .named
                    .is_some_and(|n| n.contains(name.trim_end_matches(' '))))
    }

    fn computed(&self, relation: &str) -> bool {
        self.inner.computed(relation)
    }
}

/// The verdict on one record before its event is built.
enum Decision {
    /// No event (well formed, nothing read, or the agent's own).
    Nothing,
    /// A dropped record of an undeclared database (R1 rule 8).
    Dropped,
    /// An event (or a fold) for a declared database.
    Normal { db: usize, key: Option<Key> },
    /// A well-formed database-trigger record (R15 item 4): the block's
    /// relations under the filters, no rows; block-less, no event.
    Trigger { db: usize },
    /// Ambiguous (fix 3); `window`: it opens one.
    Ambiguous { window: bool, at: u32 },
    /// A permission refusal of another client (review L2).
    Denied { db: usize },
}

impl Machine {
    #[allow(clippy::too_many_lines)]
    fn judge(
        &mut self,
        rec: &Record<'_>,
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
    ) -> Decision {
        let h = &rec.header;
        let token = h.token();
        // Runs (R1 rules 1 and 2, R5).
        let pid_ok = match self.run {
            Some(r) => r.pid == h.pid && !self.unconfirmed,
            // Before the first confirmation, a history walk: the first pid
            // is taken; the first check confirms it or ends it.
            None => {
                self.run = Some(Run {
                    pid: h.pid,
                    start: None,
                });
                true
            }
        };
        if !pid_ok {
            if !self.failed_pids.contains(&h.pid) && self.failed_pids.len() < 64 {
                self.failed_pids.push(h.pid);
            }
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        if rec.defect.is_some() {
            let window = matches!(
                convert(rec, cat[0]),
                Converted::Ambiguous { window: true, .. }
            );
            return Decision::Ambiguous {
                window,
                at: line!(),
            };
        }
        let in_window = self.window_until.is_some_and(|u| now < u);
        match h.event {
            Event::TraceInit => {
                self.token_ended.remove(&token);
                return if self.token_live.contains_key(&token) {
                    Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    }
                } else {
                    Decision::Nothing
                };
            }
            Event::TraceFini => {
                if self.token_ended.remove(&token).is_some() {
                    return Decision::Nothing;
                }
                if let Some(k) = self.token_live.get(&token).copied()
                    && self
                        .bindings
                        .get(&k)
                        .is_some_and(|b| b.kind == Kind::Internal)
                {
                    if self.live_others(k.0, k) {
                        return Decision::Ambiguous {
                            window: false,
                            at: line!(),
                        };
                    }
                    self.end_binding(k);
                    return Decision::Nothing;
                }
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
            Event::AttachService => {
                if self.token_live.contains_key(&token) || self.services.len() >= MAX_SERVICES {
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                self.services.insert(token, true);
                return Decision::Nothing;
            }
            Event::DetachService => {
                if self.services.remove(&token).is_none() {
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                self.end_token(token);
                return Decision::Nothing;
            }
            Event::StartService | Event::QueryService => {
                if !self.services.contains_key(&token) {
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                // R27 item 1 (a): the backup's database argument.
                if let Body::Service {
                    database: Some(d), ..
                } = &rec.body
                {
                    return match self.resolve(d) {
                        Resolved::Db(DbId::Declared(i)) => Decision::Normal { db: i, key: None },
                        Resolved::Db(DbId::Undeclared(_)) => Decision::Dropped,
                        Resolved::Ambiguous => Decision::Ambiguous {
                            window: false,
                            at: line!(),
                        },
                    };
                }
                return match self.s.databases.iter().position(|d| !d.excluded) {
                    // Attributed to every declared database (fix 3).
                    Some(_) if matches!(&rec.body, Body::Service { name: Some(_), .. }) => {
                        Decision::Ambiguous {
                            window: false,
                            at: line!(),
                        }
                    }
                    _ => Decision::Nothing,
                };
            }
            Event::Error => {
                // Their codes are kept, nothing else; follow-ups carry no
                // object (R22 item 7). A permission refusal on a binding
                // that is not the agent's own is an attempt to read
                // (review L2): `*`, always reported, the code only.
                let denied = matches!(&rec.body, Body::Error { codes, .. }
                    if codes.contains(&crate::error::gds::NO_PRIV));
                if denied
                    && let Some(att) = rec.att
                    && let Resolved::Db(DbId::Declared(i)) = self.resolve(att.database)
                    && !self
                        .bindings
                        .get(&(DbId::Declared(i), att.id))
                        .is_some_and(|b| b.own && b.anchored)
                {
                    return Decision::Denied { db: i };
                }
                return Decision::Nothing;
            }
            Event::Warning => return Decision::Nothing,
            _ => {}
        }
        let Some(att) = rec.att else {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        };
        let db = match self.resolve(att.database) {
            Resolved::Db(d) => d,
            Resolved::Ambiguous => {
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
        };
        if let DbId::Declared(i) = db {
            self.counts.parsed_declared += 1;
            let _ = i;
        }
        let key = (db, att.id);
        let internal_line = att.protocol == Protocol::Internal;
        // The Garbage Collector (R6, R16, R30).
        if internal_line && att.user == "Garbage Collector" && att.role.is_none() {
            return self.internal_record(rec, key, token, now);
        }
        if internal_line
            && !(att.user == "SWEEPER" && att.role == Some("NONE") && att.charset == "NONE")
        {
            // R6 item 5, R29: other internal attachments.
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        match h.event {
            Event::AttachDatabase | Event::CreateDatabase if h.outcome == Outcome::Ok => {
                self.attach(rec, key, token, now, in_window, internal_line)
            }
            Event::AttachDatabase => {
                // FAILED / UNAUTHORIZED (R10): one live token is a breach.
                if self.token_live.contains_key(&token) {
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                self.end_token(token);
                self.normal(db, None)
            }
            _ => self.attached_record(rec, key, token, pos, now, in_window, cat),
        }
    }

    /// A binding past the caps of R1 rule 11: its record is ambiguous,
    /// except for an undeclared database without proof 11, whose records
    /// are dropped and counted (R1 rule 8, re-review L-3).
    fn refused(&self, db: DbId, at: u32) -> Decision {
        match db {
            DbId::Undeclared(_) if !self.s.proof11 => Decision::Dropped,
            _ => Decision::Ambiguous { window: false, at },
        }
    }

    fn normal(&mut self, db: DbId, key: Option<Key>) -> Decision {
        match db {
            DbId::Declared(i) => {
                self.last_declared = Some(i);
                Decision::Normal { db: i, key }
            }
            DbId::Undeclared(_) if self.s.proof11 => Decision::Ambiguous {
                window: false,
                at: line!(),
            },
            DbId::Undeclared(_) => Decision::Dropped,
        }
    }

    fn internal_record(
        &mut self,
        rec: &Record<'_>,
        key: Key,
        token: (u32, u64),
        now: Instant,
    ) -> Decision {
        if !self.s.superserver {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        let db = key.0;
        let shape = rec.client.is_none()
            && rec.tra.is_some_and(|t| t.internal_flags)
            && rec.att.is_some_and(|a| a.charset == "NONE");
        match rec.header.event {
            Event::StartTransaction if shape && rec.trailer.block.is_none() => {
                let seen = self.is_seen(db, key.1) || self.bindings.contains_key(&key);
                if seen || self.token_live.contains_key(&token) {
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                if !self.admit(db) {
                    return self.refused(db, line!());
                }
                if let Some(old) = self.internal.get(&db).copied() {
                    // The replacement rule (R16 item 2).
                    if self.live_others(db, old) {
                        return Decision::Ambiguous {
                            window: false,
                            at: line!(),
                        };
                    }
                    self.end_binding(old);
                }
                self.see(db, key.1);
                self.internal.insert(db, key);
                self.token_live.insert(token, key);
                self.insert_binding(
                    key,
                    Binding {
                        seq: 0,
                        token,
                        anchored: true,
                        poisoned: false,
                        tainted: false,
                        kind: Kind::Internal,
                        first_tra: rec.tra.map(|t| t.id),
                        open_tras: rec.tra.map(|t| t.id).into_iter().collect(),
                        sweep_step: 0,
                        own: false,
                        trigger_wait: None,
                    },
                );
                if !self.live_others(db, key) {
                    self.gc_alone_since.insert(db, now);
                }
                Decision::Nothing
            }
            Event::CommitTransaction if shape && rec.trailer.block.is_none() => {
                let ok =
                    self.bindings.get(&key).is_some_and(|b| {
                        b.token == token && b.kind == Kind::Internal && !b.poisoned
                    }) && !self.live_others(db, key);
                if ok {
                    Decision::Nothing
                } else {
                    if let Some(b) = self.bindings.get_mut(&key) {
                        b.poisoned = true;
                    }
                    Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    }
                }
            }
            _ => {
                if let Some(b) = self.bindings.get_mut(&key) {
                    b.poisoned = true;
                }
                Decision::Ambiguous {
                    window: false,
                    at: line!(),
                }
            }
        }
    }

    /// Marks `id` seen for the database identity, within the per-identity
    /// bound (16 384 declared, 4 096 undeclared): past it the oldest id
    /// goes and the seen-id floor rises to it (R30 review L7). Called only
    /// after the caps passed.
    fn see(&mut self, db: DbId, id: u64) {
        let cap = match db {
            DbId::Declared(_) => MAX_BINDINGS_DECLARED,
            DbId::Undeclared(_) => MAX_BINDINGS_UNDECLARED,
        };
        let v = self.seen_ids.entry(db).or_default();
        if !v.set.insert(id) {
            return;
        }
        v.order.push_back(id);
        self.seen_total += 1;
        while v.order.len() > cap {
            if let Some(old) = v.order.pop_front() {
                v.set.remove(&old);
                v.floor = Some(v.floor.map_or(old, |f| f.max(old)));
                self.seen_total -= 1;
            }
        }
    }

    fn attach(
        &mut self,
        rec: &Record<'_>,
        key: Key,
        token: (u32, u64),
        now: Instant,
        in_window: bool,
        internal_line: bool,
    ) -> Decision {
        let (db, id) = key;
        let sweep = internal_line;
        if sweep && rec.client.is_some() {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        // R1 rule 3: a duplicate poisons both.
        if self.bindings.contains_key(&key) || self.is_seen(db, id) {
            if let Some(b) = self.bindings.get_mut(&key) {
                b.poisoned = true;
                b.own = false;
            }
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        // R1 rule 4: one live binding per token.
        if self.token_live.contains_key(&token) || self.services.contains_key(&token) {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        // R1 rule 5 and R7: order and the run bound.
        let bound = match db {
            DbId::Declared(i) => self
                .ledger
                .latest_id(&self.s.databases[i].attach)
                .map(|l| l.saturating_add(ID_MARGIN)),
            DbId::Undeclared(_) => None,
        };
        let mut ambiguous = false;
        let mut raise = false;
        if bound.is_some_and(|b| id > b) {
            ambiguous = true;
        } else {
            match self.highest.get(&db).copied() {
                Some((hi, at)) if id < hi => {
                    if hi - id > ORDER_IDS || now.duration_since(at) > ORDER_TIME {
                        ambiguous = true;
                    }
                }
                _ => raise = true,
            }
        }
        // R1 rule 11: caps before anything is kept (review H-A).
        if !self.admit(db) {
            return self.refused(db, line!());
        }
        if raise {
            self.highest.insert(db, (id, now));
        }
        // The agent's own attachment (decision 6, R1 rule 5).
        let own = match (db, rec.att) {
            (DbId::Declared(i), Some(att)) => {
                let port = match att.protocol {
                    Protocol::Tcp(ip, p) if ip.is_loopback() => Some(p),
                    _ => None,
                };
                let label = self.s.databases[i].attach.clone();
                // R42 item 1: this attach's measured offset, on the grid.
                let measured = self
                    .ledger
                    .opened(&label, id)
                    .and_then(|o| o.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .and_then(|d| i64::try_from(d.as_secs()).ok())
                    .and_then(|agent| grid_offset(agent - naive_seconds(rec.header.time)));
                // R42 item 5: the attachment's lifetime holds the record's
                // time (this attach's offset, else the confirmed one).
                let t = self.record_time(rec.header.time, measured.or(self.offset));
                let mine = port.is_some_and(|p| self.ledger.is_own_attach(&label, id, p, Some(t)))
                    && att.user.eq_ignore_ascii_case(&self.s.account)
                    && att.role.is_none_or(|r| r == "NONE");
                if mine {
                    self.watermark.entry(i).or_insert(id);
                    // The clock offset (R40 item 2, R42): only from an own
                    // attach outside a window and not ambiguous, rounded to
                    // the grid, provisional until confirmed. A pending
                    // change that needs the probe is not overwritten by a
                    // later attach (R42 item 3).
                    if !in_window
                        && !ambiguous
                        && let Some(o) = measured
                        && !self.offset_pending.is_some_and(|p| p.2)
                    {
                        let needs_probe =
                            self.offset.is_some_and(|cur| (o - cur).abs() > OFFSET_STEP);
                        if needs_probe {
                            // R42 item 3: the probe re-confirms it.
                            self.check_requested = true;
                        }
                        if self.offset != Some(o) {
                            self.offset_pending = Some((o, key, needs_probe));
                        }
                    }
                }
                mine
            }
            _ => false,
        };
        self.see(db, id);
        self.token_ended.remove(&token);
        self.token_live.insert(token, key);
        self.gc_alone_since.remove(&db);
        self.insert_binding(
            key,
            Binding {
                seq: 0,
                token,
                anchored: true,
                poisoned: false,
                tainted: in_window || ambiguous,
                kind: if sweep { Kind::Sweep } else { Kind::User },
                first_tra: None,
                open_tras: Vec::new(),
                sweep_step: 0,
                own: own && !in_window && !ambiguous,
                trigger_wait: None,
            },
        );
        if ambiguous {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        self.normal(db, Some(key))
    }

    fn end_binding(&mut self, key: Key) {
        self.probe_records.remove(&key);
        if let Some(b) = self.remove_binding(key) {
            self.token_live.remove(&b.token);
            self.end_token(b.token);
            if self.internal.get(&key.0) == Some(&key) {
                self.internal.remove(&key.0);
            }
            // Its pending groups end, never dropped silently.
            let groups: Vec<Group> = self
                .groups
                .iter()
                .filter(|g| g.key == key)
                .cloned()
                .collect();
            self.groups.retain(|g| g.key != key);
            self.pending_end.extend(groups);
            if !self.live_others(key.0, key) && self.internal.contains_key(&key.0) {
                self.gc_alone_since.insert(key.0, Instant::now());
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn attached_record(
        &mut self,
        rec: &Record<'_>,
        key: Key,
        token: (u32, u64),
        pos: u64,
        now: Instant,
        in_window: bool,
        cat: &[&dyn Catalog],
    ) -> Decision {
        let (db, id) = key;
        let h = &rec.header;
        // Learned bindings (R1 rule 5).
        if !self.bindings.contains_key(&key) {
            let above_watermark = match db {
                DbId::Declared(i) => self.watermark.get(&i).is_some_and(|w| id > *w),
                DbId::Undeclared(_) => false,
            };
            let seen = self.is_seen(db, id);
            let below_floor = self.learned_floor.get(&db).is_some_and(|f| id <= *f);
            // R1 rule 11 (review H-A): the caps on the learned path too,
            // checked before anything is kept.
            if above_watermark || seen || below_floor || self.token_live.contains_key(&token) {
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
            if !self.admit(db) {
                return self.refused(db, line!());
            }
            self.see(db, id);
            self.token_live.insert(token, key);
            self.insert_binding(
                key,
                Binding {
                    seq: 0,
                    token,
                    anchored: false,
                    poisoned: false,
                    tainted: in_window,
                    kind: Kind::User,
                    first_tra: None,
                    open_tras: Vec::new(),
                    sweep_step: 0,
                    own: false,
                    trigger_wait: None,
                },
            );
        }
        let Some(b) = self.bindings.get(&key).cloned() else {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        };
        if b.token != token || b.poisoned {
            if let Some(b) = self.bindings.get_mut(&key) {
                b.poisoned |= !b.anchored;
            }
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        if b.tainted {
            if matches!(h.event, Event::DetachDatabase | Event::DropDatabase) {
                self.end_binding(key);
            }
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        // The own binding ends a window (R1 rule 7), only if the record is
        // the agent's own (re-review L-C): decided in `apply`.
        if b.own && b.anchored {
            self.window_ender = in_window;
        } else if in_window {
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        // A database trigger waiting for its sequence (R15, R34).
        if let Some(wait) = b.trigger_wait {
            let this_tra = rec.tra.map(|t| t.id);
            let is_end = matches!(
                h.event,
                Event::CommitTransaction | Event::RollbackTransaction
            );
            let (next_ok, keep) = match (wait, h.event, &rec.body) {
                (TriggerWait::Disconnect(t), _, _) if is_end && this_tra == Some(t) => (true, true),
                (TriggerWait::Disconnect(_), Event::DetachDatabase, _) => (true, false),
                (
                    TriggerWait::Disconnect(_),
                    Event::ExecuteTriggerFinish,
                    Body::Routine { name, .. },
                ) if name.trigger == Some(TriggerKind::OnConnect) => {
                    if let Some(b) = self.bindings.get_mut(&key) {
                        b.trigger_wait = Some(TriggerWait::Reset);
                    }
                    return Decision::Trigger { db: db_index(db) };
                }
                (TriggerWait::Reset, _, _) if is_end || h.event == Event::StartTransaction => {
                    (true, true)
                }
                (
                    TriggerWait::Reset,
                    Event::ExecuteStatementFinish,
                    Body::Statement { text, .. },
                ) => (
                    analyze_firebird(text).kind == FirebirdKind::SessionReset,
                    false,
                ),
                (TriggerWait::TraEnd(t), _, _) if this_tra != Some(t) => (true, true),
                (TriggerWait::TraEnd(_), _, _) => (is_end, false),
                _ => (false, false),
            };
            if !keep && let Some(b) = self.bindings.get_mut(&key) {
                b.trigger_wait = None;
            }
            if !next_ok {
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
        }
        if b.kind == Kind::Sweep {
            return self.sweep_record(rec, key);
        }
        let tra = rec.tra.map(|t| t.id);
        match h.event {
            Event::DetachDatabase | Event::DropDatabase => {
                if self.groups.iter().any(|g| g.key == key) {
                    // The pending groups end with the attachment (R4).
                    let gs: Vec<Group> = self
                        .groups
                        .iter()
                        .filter(|g| g.key == key)
                        .cloned()
                        .collect();
                    self.groups.retain(|g| g.key != key);
                    for g in gs {
                        self.pending_end.push(g);
                    }
                }
                self.end_binding(key);
                if b.own
                    && let DbId::Declared(i) = db
                {
                    self.ledger.note_detach(&self.s.databases[i].attach, id);
                }
                return self.normal(db, Some(key));
            }
            Event::StartTransaction => {
                if let (Some(t), Some(bm)) = (tra, self.bindings.get_mut(&key)) {
                    bm.first_tra.get_or_insert(t);
                    if bm.open_tras.len() < MAX_GROUPS_PER_BINDING * 4 {
                        bm.open_tras.push(t);
                    }
                }
                return self.normal(db, Some(key));
            }
            Event::CommitTransaction | Event::RollbackTransaction => {
                if let Some(t) = tra {
                    if let Some(bm) = self.bindings.get_mut(&key) {
                        bm.open_tras.retain(|x| *x != t);
                    }
                    let gs: Vec<Group> = self
                        .groups
                        .iter()
                        .filter(|g| g.key == key && g.tra == t)
                        .cloned()
                        .collect();
                    self.groups.retain(|g| !(g.key == key && g.tra == t));
                    self.pending_end.extend(gs);
                }
                return self.normal(db, Some(key));
            }
            _ => {}
        }
        // Routine finish records (R4, R14, R15, R25).
        if let Body::Routine { name, kind, .. } = &rec.body {
            if let Some(trig) = name.trigger.filter(|t| t.is_database_trigger()) {
                // R15 item 2: a live binding, its transaction started on it
                // and not ended, and the kind's condition.
                let open = tra.is_some_and(|t| b.open_tras.contains(&t));
                let ok = open
                    && match trig {
                        TriggerKind::OnConnect => b.first_tra == tra,
                        TriggerKind::OnDisconnect => {
                            if let (Some(bm), Some(t)) = (self.bindings.get_mut(&key), tra) {
                                bm.trigger_wait = Some(TriggerWait::Disconnect(t));
                            }
                            true
                        }
                        TriggerKind::OnTransactionCommit | TriggerKind::OnTransactionRollback => {
                            if let (Some(bm), Some(t)) = (self.bindings.get_mut(&key), tra) {
                                bm.trigger_wait = Some(TriggerWait::TraEnd(t));
                            }
                            true
                        }
                        _ => true,
                    };
                return if ok {
                    self.normal(db, Some(key));
                    Decision::Trigger { db: db_index(db) }
                } else {
                    // R15 item 5: a block-less one opens a window.
                    Decision::Ambiguous {
                        window: rec.trailer.block.is_none(),
                        at: line!(),
                    }
                };
            }
            // Foldable: an anchored binding whose transaction start was
            // read (R4).
            let foldable = b.anchored && tra.is_some_and(|t| b.open_tras.contains(&t));
            if foldable && let Some(t) = tra {
                let mut draft = routine_draft(rec, *kind, cat[db_index(db)]);
                // R41 item 7: the match is decided per nested record; the
                // mark is sticky in the group (its parts keep `*`).
                if self.dependent_hit(rec, cat[db_index(db)]) {
                    draft.star = true;
                    draft.always = true;
                }
                let block_less = rec.trailer.block.is_none();
                let m = Member {
                    name: name.name.to_owned(),
                    draft,
                    block_less,
                };
                if !self.add_to_group(key, t, m, now, pos) {
                    return Decision::Ambiguous {
                        window: block_less,
                        at: line!(),
                    };
                }
                return Decision::Nothing;
            }
            // Not foldable: its own event (R4), or ambiguous block-less.
            return self.normal(db, Some(key));
        }
        self.normal(db, Some(key))
    }

    fn sweep_record(&mut self, rec: &Record<'_>, key: Key) -> Decision {
        let step = self.bindings.get(&key).map_or(0, |b| b.sweep_step);
        let (ok, next) = match (step, rec.header.event) {
            (0, Event::SweepStart) => (true, 1),
            (1, Event::StartTransaction) => (rec.tra.is_some_and(|t| t.internal_flags), 2),
            (2, Event::SweepProgress) => (true, 2),
            (2, Event::SweepFinish) => (true, 3),
            (3, Event::CommitTransaction) => (true, 4),
            (4, Event::DetachDatabase) => {
                self.end_binding(key);
                return self.normal(key.0, None);
            }
            _ => (false, step),
        };
        if !ok {
            if let Some(b) = self.bindings.get_mut(&key) {
                b.poisoned = true;
            }
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        if let Some(b) = self.bindings.get_mut(&key) {
            b.sweep_step = next;
        }
        self.normal(key.0, Some(key))
    }

    fn add_to_group(&mut self, key: Key, tra: u64, m: Member, now: Instant, pos: u64) -> bool {
        if m.block_less && self.hold_since.is_none() {
            self.hold_since = Some(now);
        }
        // R25 item 4: the group state budget, oldest groups ended first.
        while self.groups.iter().map(Group::bytes).sum::<usize>() > MAX_STATE_BYTES {
            let Some(old) = self.groups.pop_front() else {
                break;
            };
            self.pending_end.push(old);
        }
        if let Some(g) = self
            .groups
            .iter_mut()
            .find(|g| g.key == key && g.tra == tra)
        {
            if m.block_less {
                g.first_bare.get_or_insert(pos);
                g.bare.add(m);
            } else {
                g.full.add(m);
            }
            return true;
        }
        let per = self.groups.iter().filter(|g| g.key == key).count();
        if per >= MAX_GROUPS_PER_BINDING || self.groups.len() >= MAX_GROUPS {
            // Ended oldest first, fail closed (R25 item 4).
            if let Some(i) = self
                .groups
                .iter()
                .position(|g| per < MAX_GROUPS_PER_BINDING || g.key == key)
                && let Some(old) = self.groups.remove(i)
            {
                self.pending_end.push(old);
            }
        }
        let mut g = Group {
            key,
            tra,
            full: Part::default(),
            bare: Part::default(),
            started: now,
            first: pos,
            first_bare: None,
        };
        if m.block_less {
            g.first_bare = Some(pos);
            g.bare.add(m);
        } else {
            g.full.add(m);
        }
        self.groups.push_back(g);
        true
    }

    /// A group ended without folding (R25 item 3): its block-ful part is
    /// one event; its block-less part is ambiguous (H1 fix 2: `*`, always
    /// reported, a window), and the held records with it.
    fn end_group(
        &mut self,
        g: Group,
        _now: Instant,
        _cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
        let DbId::Declared(db) = g.key.0 else {
            return;
        };
        if g.full.count > 0
            && let Some(d) = finish(g.full.draft())
        {
            out.push((db, self.draft_event(&d, None, db)));
        }
        if g.blockless() {
            *self.why.entry(1).or_default() += g.bare.count;
            self.counts.ambiguous += g.bare.count;
            self.window_until = Some(Instant::now() + WINDOW);
            let mut d = g.bare.draft();
            d.star = true;
            d.always = true;
            if let Some(d) = finish(d) {
                out.push((db, self.draft_event(&d, None, db)));
            }
            if self.hold_since.is_some() {
                self.release(true, out);
            }
        }
    }

    fn draft_event(&self, d: &Draft, rec: Option<&Record<'_>>, db: usize) -> MaskedEvent {
        let label = &self.s.databases[db].label;
        match rec {
            Some(r) => to_event(d, r, label, self.time(r.header.time)),
            None => {
                let principal = databastion_classifiers::masking::EventPrincipal::unidentified();
                let mut ev = MaskedEvent::new(
                    databastion_classifiers::masking::EventSource::FirebirdAuditTrace,
                    d.action
                        .unwrap_or(databastion_classifiers::masking::EventAction::Read),
                    principal,
                    SystemTime::now(),
                );
                let dbn = crate::discover::normalize(label);
                if d.star {
                    ev = ev.with_object(databastion_classifiers::masking::EventObject::new(
                        dbn.clone(),
                        None,
                        databastion_classifiers::names::NormalizedName::wildcard(),
                    ));
                }
                for o in &d.objects {
                    ev = ev.with_object(databastion_classifiers::masking::EventObject::new(
                        dbn.clone(),
                        None,
                        crate::discover::normalize(o),
                    ));
                }
                ev = ev.with_rows(d.rows);
                for s in &d.signals {
                    ev = ev.with_signal(*s);
                }
                if d.always {
                    ev = ev.with_always_report();
                }
                ev
            }
        }
    }
}

fn db_index(db: DbId) -> usize {
    match db {
        DbId::Declared(i) => i,
        DbId::Undeclared(_) => 0,
    }
}

/// A routine record's draft for folding (R4): its counters' relations,
/// rows and the routine's name.
fn routine_draft(rec: &Record<'_>, _kind: RoutineKind, cat: &dyn Catalog) -> Draft {
    let mut d = match convert(rec, cat) {
        // A block-ful record: its marks stay (always-reported relations,
        // views over them: re-review L-A).
        Converted::Event(d) => d,
        // A block-less one: only the ambiguous form's `*` and mark go (the
        // group decides its ambiguity, R25 item 3).
        Converted::Ambiguous { mut draft, .. } => {
            draft.star = false;
            draft.always = false;
            draft
        }
        Converted::Nothing => Draft::default(),
    };
    d.rows = rec.trailer.fetched;
    d
}

/// The R36 rule on a merged draft (no object and no signal: no event).
fn finish(mut d: Draft) -> Option<Draft> {
    if d.signals
        .contains(&databastion_classifiers::masking::Signal::BackupDatabase)
    {
        d.star = true;
        d.always = true;
    }
    if d.objects.is_empty() && !d.star {
        if d.signals.is_empty() {
            return None;
        }
        d.star = true;
        d.always = true;
    }
    Some(d)
}

/// Unites a fold group into a statement's draft (R4: objects united, rows
/// by maximum; R33 item 6: the "no event" rules after the union).
fn fold(mut stmt: Draft, g: &Group) -> Draft {
    for m in [&g.full, &g.bare]
        .into_iter()
        .filter(|p| p.count > 0)
        .map(Part::draft)
    {
        stmt.star |= m.star;
        for o in m.objects {
            if !stmt.objects.contains(&o) {
                stmt.objects.push(o);
            }
        }
        stmt.rows = match (stmt.rows, m.rows) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        for s in m.signals {
            if !stmt.signals.contains(&s) {
                stmt.signals.push(s);
            }
        }
        stmt.always |= m.always;
        if m.action == Some(databastion_classifiers::masking::EventAction::Write) {
            stmt.action = Some(databastion_classifiers::masking::EventAction::Write);
        }
        if stmt
            .rows
            .is_some_and(|n| n > crate::trace_events::LARGE_RESULT)
            && !stmt
                .signals
                .contains(&databastion_classifiers::masking::Signal::LargeResult)
        {
            stmt.signals
                .push(databastion_classifiers::masking::Signal::LargeResult);
        }
    }
    stmt
}

impl Machine {
    #[allow(clippy::too_many_lines)]
    fn apply(
        &mut self,
        decision: Decision,
        rec: &Record<'_>,
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
        // Groups ended by this record (a transaction end, a detach).
        for g in std::mem::take(&mut self.pending_end) {
            self.end_group(g, now, cat, out);
        }
        match decision {
            Decision::Nothing => {}
            Decision::Trigger { db } => {
                let c = cat[db.min(cat.len() - 1)];
                // R41 item 5: a database-trigger record of the dependent set
                // (or naming a trigger unknown to the catalog read) gives an
                // always-reported `*` event, block-less ones too, never own.
                let dependent = self.dependent_hit(rec, c);
                if rec.trailer.block.is_none() && !dependent {
                    return;
                }
                let mut d = match convert(rec, c) {
                    Converted::Event(d) | Converted::Ambiguous { draft: d, .. } => d,
                    Converted::Nothing => Draft {
                        action: Some(databastion_classifiers::masking::EventAction::Read),
                        ..Draft::default()
                    },
                };
                if dependent {
                    d.star = true;
                    d.always = true;
                }
                d.rows = None;
                if let Some(d) = finish(d) {
                    let ev = self.draft_event(&d, Some(rec), db);
                    self.emit(db, ev, out);
                }
            }
            Decision::Dropped => self.counts.undeclared_dropped += 1,
            Decision::Denied { db } => {
                let d = Draft {
                    action: Some(databastion_classifiers::masking::EventAction::Read),
                    star: true,
                    always: true,
                    ..Draft::default()
                };
                let ev = self.draft_event(&d, Some(rec), db);
                self.emit(db, ev, out);
            }
            Decision::Ambiguous { window, at } => {
                self.counts.ambiguous += 1;
                *self.why.entry(at).or_default() += 1;
                #[cfg(test)]
                if std::env::var_os("FB_STREAM_DEBUG").is_some() {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!(
                            "ambiguous at {at}: {:?} {:?} {:?}",
                            rec.header.event,
                            rec.header.token(),
                            rec.att.map(|a| a.id)
                        );
                    }
                }
                if window {
                    self.window_until = Some(now + WINDOW);
                }
                // Fix 3: the preceding well-formed record's database, or
                // every declared database; the relations classed with that
                // database's catalog (review L6).
                let dbs: Vec<usize> = match self.last_declared {
                    Some(i) => vec![i],
                    None => (0..self.s.databases.len())
                        .filter(|i| !self.s.databases[*i].excluded)
                        .collect(),
                };
                for db in dbs {
                    let mut d = match convert(rec, cat[db.min(cat.len() - 1)]) {
                        Converted::Event(d) | Converted::Ambiguous { draft: d, .. } => d,
                        Converted::Nothing => Draft::default(),
                    };
                    d.star = true;
                    d.always = true;
                    if d.action == Some(databastion_classifiers::masking::EventAction::AuthFailure)
                    {
                        d.action = Some(databastion_classifiers::masking::EventAction::Read);
                    }
                    let ev = self.draft_event(&d, Some(rec), db);
                    self.emit(db, ev, out);
                }
            }
            Decision::Normal { db, key } => {
                let c = convert(rec, cat[db.min(cat.len() - 1)]);
                let ambiguous = matches!(c, Converted::Ambiguous { .. });
                let mut folded = false;
                let (mut draft, window) = match c {
                    Converted::Nothing => (None, false),
                    Converted::Event(d) => (Some(d), false),
                    Converted::Ambiguous { draft, window } => {
                        self.counts.ambiguous += 1;
                        *self.why.entry(0).or_default() += 1;
                        #[cfg(test)]
                        if std::env::var_os("FB_STREAM_DEBUG").is_some() {
                            #[allow(clippy::print_stderr)]
                            {
                                eprintln!(
                                    "record rule ambiguous: {:?} {:?}",
                                    rec.header.event, rec.body
                                );
                            }
                        }
                        (Some(draft), window)
                    }
                };
                // Folding into a statement finish (R4).
                if rec.header.event == Event::ExecuteStatementFinish
                    && let (Some(k), Some(t)) = (key, rec.tra.map(|t| t.id))
                    && let Some(i) = self.groups.iter().position(|g| g.key == k && g.tra == t)
                {
                    let Some(g) = self.groups.remove(i) else {
                        return;
                    };
                    let base = draft.take().unwrap_or_default();
                    draft = finish(fold(base, &g));
                    folded = true;
                    if self.hold_since.is_some() && !self.groups.iter().any(Group::blockless) {
                        self.release(false, out);
                    }
                }
                if window {
                    self.window_until = Some(now + WINDOW);
                }
                // R41 item 4: a record naming an object of the dependent set
                // gets `*` and the always-reported mark in every shape
                // (failed records included), unless it is one of the
                // agent's own texts (re-review L-1: an exact sampling text
                // or a closed-set constant text, credited first).
                let dependent = self.dependent_hit(rec, cat[db.min(cat.len() - 1)]);
                // The agent's own record (decision 6, R8 item 4).
                // Also for a record with no event of its own (its objects all
                // noise): its credit is consumed, and the read-back probe
                // (proof 7) and the clock offset are confirmed by it.
                // Never for an ambiguous record (review L4), nor for a
                // statement that folded a routine group (review M1: the
                // agent's texts call no routine, and crediting it would drop
                // the group's relations).
                if let Some(k) = key
                    && !window
                    && !ambiguous
                    && !folded
                {
                    let d = draft.clone().unwrap_or_default();
                    match self.own_record(rec, k, &d, pos) {
                        Some(true) => {
                            self.counts.own += 1;
                            if std::mem::take(&mut self.window_ender) {
                                self.window_until = None;
                            }
                            return;
                        }
                        // A text of the closed set on the agent's
                        // attachment with no credit left (R8 item 4):
                        // ambiguous, `*` and always reported.
                        None => {
                            let d = draft.get_or_insert_with(|| Draft {
                                action: Some(databastion_classifiers::masking::EventAction::Read),
                                rows: rec.trailer.fetched,
                                ..Draft::default()
                            });
                            d.star = true;
                            d.always = true;
                        }
                        Some(false) => {}
                    }
                }
                if dependent {
                    let d = draft.get_or_insert_with(|| Draft {
                        action: Some(databastion_classifiers::masking::EventAction::Read),
                        rows: rec.trailer.fetched,
                        ..Draft::default()
                    });
                    d.star = true;
                    d.always = true;
                }
                // A record of the agent's binding inside a window that is
                // not its own: ambiguous (fix 3), the window stays.
                if std::mem::take(&mut self.window_ender) {
                    self.counts.ambiguous += 1;
                    *self.why.entry(line!()).or_default() += 1;
                    let d = draft.get_or_insert_with(|| Draft {
                        action: Some(databastion_classifiers::masking::EventAction::Read),
                        rows: rec.trailer.fetched,
                        ..Draft::default()
                    });
                    d.star = true;
                    d.always = true;
                }
                let Some(d) = draft else {
                    return;
                };
                let ev = self.draft_event(&d, Some(rec), db);
                self.emit(db, ev, out);
            }
        }
    }

    fn emit(&mut self, db: usize, ev: MaskedEvent, out: &mut Vec<Emitted>) {
        if self.hold_since.is_some() {
            let b = held_bytes(&ev);
            if self.held.len() >= MAX_HELD || self.held_bytes + b > MAX_STATE_BYTES {
                // Past the hold bound: the held records become ambiguous.
                self.release(true, out);
            } else {
                self.held_bytes += b;
                self.held.push(Held {
                    db: vec![db],
                    event: ev,
                });
                return;
            }
        }
        out.push((db, ev));
    }

    /// The own-record rule (decision 6, R8 item 4, R13, R22, R35).
    /// `Some(true)`: the agent's own (a credit consumed); `Some(false)`:
    /// not; `None`: a closed-set text with no credit left (loud).
    fn own_record(&mut self, rec: &Record<'_>, key: Key, d: &Draft, pos: u64) -> Option<bool> {
        let Some(b) = self.bindings.get(&key) else {
            return Some(false);
        };
        let DbId::Declared(i) = key.0 else {
            return Some(false);
        };
        // A signal refuses the record, except `shape.full_table_read` on a
        // constant text of the closed set (measured on 5.0.4: IDENTITY and
        // the `SEC$` / `RDB$CONFIG` probes name an always-reported relation
        // in a `FROM RDB$DATABASE` select, so the text alone raises it at
        // every execution; the block and the count are checked as for any
        // own text).
        let text_signal_only = match &rec.body {
            Body::Statement { text, .. } => {
                crate::sql::checked(text)
                    && d.signals
                        .iter()
                        .all(|s| *s == databastion_classifiers::masking::Signal::FullTableRead)
            }
            _ => false,
        };
        if !(b.own && b.anchored)
            || b.poisoned
            || b.tainted
            || (!d.signals.is_empty() && !text_signal_only)
        {
            return Some(false);
        }
        let Some(att) = rec.att else {
            return Some(false);
        };
        if !att.user.eq_ignore_ascii_case(&self.s.account) || att.role.is_some_and(|r| r != "NONE")
        {
            return Some(false);
        }
        let label = self.s.databases[i].attach.clone();
        let text = match &rec.body {
            Body::Statement {
                text,
                params: false,
                ..
            } => *text,
            // Transaction records of an own attachment: the agent's only
            // when no relation is left after the filters (review M1: an
            // R24 block naming a user relation is reported).
            Body::Context => return Some(d.objects.is_empty() && !d.star && !d.always),
            _ => return Some(false),
        };
        let block: Vec<&str> = rec
            .trailer
            .block
            .as_ref()
            .map(|b| b.iter().map(|(n, _)| *n).collect())
            .unwrap_or_default();
        let fetched = rec.trailer.fetched.unwrap_or(0);
        let failed = rec.header.outcome == Outcome::Failed;
        // R42 item 2: a second read-back probe record on a binding poisons
        // it (the probe that confirms must be unique).
        let probe = text == crate::sql::READ_BACK_PROBE;
        if probe {
            let n = self.probe_records.entry(key).or_insert(0);
            *n += 1;
            if *n > 1 {
                if let Some(b) = self.bindings.get_mut(&key) {
                    b.poisoned = true;
                    b.own = false;
                }
                self.check_offset_binding();
                return Some(false);
            }
        }
        // The record's time under the binding's offset (confirmed, or the
        // one it learned), bounded by the observation (R42 item 5).
        let effective = match self.offset_pending {
            Some((o, k, _)) if k == key => Some(o),
            _ => self.offset,
        };
        let t = self.record_time(rec.header.time, effective);
        let measured_base = naive_seconds(rec.header.time);
        // The own-statement table's row (R13, R20, R23), the credit's
        // R22 / R35 bounds and its life on both sides (R42 item 5),
        // checked before the credit is consumed.
        let accept = |a: &crate::conn::FetchAccount, table: Option<&str>, at: SystemTime| {
            crate::own_table::matches(text, table, &block, fetched, a)
                && crate::own::within(a, fetched, failed)
                && t <= at + crate::own::LIFETIME_SLACK
                && t + crate::own::CREDIT_LIFE >= at
        };
        match self
            .ledger
            .consume(&label, key.1, text, (self.file, pos), accept)
        {
            Verdict::Own => {
                // Proof 7: the probe's exact text, one record fetched, a
                // block naming `RDB$DATABASE`.
                if text == crate::sql::READ_BACK_PROBE
                    && fetched == 1
                    && block.contains(&"RDB$DATABASE")
                {
                    self.probe_seen = Some(SystemTime::now());
                }
                let measured = self
                    .ledger
                    .consumed_time((self.file, pos))
                    .and_then(|c| c.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .and_then(|d| i64::try_from(d.as_secs()).ok())
                    .map(|c| c - measured_base);
                self.confirm_offset(key, probe, measured);
                Some(true)
            }
            Verdict::NotOwn => {
                self.counts.own_not_matched += 1;
                Some(false)
            }
            // A text of the set with no credit left: loud (R8 item 4).
            Verdict::NoCredit => {
                self.counts.ambiguous += 1;
                *self.why.entry(line!()).or_default() += 1;
                None
            }
        }
    }
}

/// R42 item 1: a measured offset (agent UTC minus the server's printed
/// local time) within 5 s of a whole quarter hour, for a UTC offset of the
/// server's zone from −12 h to +14 h (so an offset from −14 h to +12 h),
/// rounded to the grid; `None` otherwise (a forged attach time or a
/// skewed clock is not taken).
pub(crate) fn grid_offset(offset: i64) -> Option<i64> {
    const QUARTER: i64 = 15 * 60;
    let r = offset.rem_euclid(QUARTER);
    let (dist, nearest) = if r <= QUARTER / 2 {
        (r, offset - r)
    } else {
        (QUARTER - r, offset - r + QUARTER)
    };
    // The zone's UTC offset is the opposite of this one.
    let zone = -nearest;
    (dist <= 5 && (-12 * 3600..=14 * 3600).contains(&zone)).then_some(nearest)
}

/// Whether a measured offset is accepted (R42 item 1).
pub(crate) fn plausible_offset(offset: i64) -> bool {
    grid_offset(offset).is_some()
}

/// Seconds since the epoch of a printed time, read as UTC.
pub(crate) fn naive_seconds(t: LogTime) -> i64 {
    let (y, m, d) = (i64::from(t.year), i64::from(t.month), i64::from(t.day));
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second)
}
