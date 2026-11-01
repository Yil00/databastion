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
//!   `check()` and `/proc` confirm. A record of a new pid stops the
//!   stream before it ([`Machine::stop_wanted`], the stop itself is the
//!   runner's, `crate::audit`) until a check started after the stop
//!   confirms that pid, and the run changes at that record, or the
//!   confirmation fails (another pid read, or 60 s): the pid is remembered
//!   and its records are ambiguous, a 10-minute cooldown starts. A run a
//!   check read before the stream reaches its records is pending until the
//!   first record of its pid. A start-time change of the same pid makes the
//!   records read until the next confirmation ambiguous, and asks for an
//!   immediate check (R5 item 4).
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
//! - **The parser checkpoint** (R25 items 7 and 9, R39 (a)): the state is
//!   exported where nothing is held ([`Machine::export`], module
//!   `stream_ckpt`), or, while a block-less group pends, as it was before
//!   the record that started the hold (a snapshot); every event carries
//!   the position it is attributed to (its record, or a group's first
//!   record), and a restored stream emits nothing for a position whose
//!   events were durably spooled before the restart (deduplication by
//!   position).
//!
//! - **Local external data sources** (R29, with the maintainer's decision
//!   of 2026-11-01 on the review of #402): an `<internal>` attach with a
//!   user and a role, no client line, on the run's pid, anchors an
//!   external-source binding (never own, never internal) whose events are
//!   held across its transactions and released, as judged, at a
//!   transaction end once a caller was seen (a user binding's finish
//!   record of code in a transaction that started before the external
//!   binding's open transaction); the caller test then starts again (a
//!   pooled connection serves several callers). With none, they stay held
//!   and are ambiguous at its detach or at a bound (10 minutes of reading
//!   time, 16 384 events and 4 MiB per stream with each hold charged, not
//!   persisted: the position is held back at the first held record). A
//!   failed hold ends its pending fold groups ambiguous too.
//! - **The remote 4-tuple** (R1 rule 9, with security review L11 of
//!   2026-10-26): a new TCP binding whose client address and port another
//!   live binding holds is ambiguous (tainted until it detaches); so is
//!   one whose `ATTACH_DATABASE` was written within 10 s of being read (past
//!   an end of file the runner saw less than 10 s earlier), still live
//!   when the runner read the server's connections after that read (no
//!   `DETACH_DATABASE` of its token later in the read), with no connection
//!   of the server's port that has its client end ([`TcpView`]). Not
//!   evaluated when the agent lags or the table was not read whole.

#[path = "stream_ckpt.rs"]
mod stream_ckpt;

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
/// R1 rule 2 (security review L-b): pids remembered as failed per run.
pub(crate) const MAX_FAILED_PIDS: usize = 64;
/// R1 rule 2: a stop lasts at most this long (agent time).
pub(crate) const STOP_LIMIT: Duration = Duration::from_secs(60);
/// R1 rule 2 (security review M-3): the cooldown after a failed
/// confirmation.
pub(crate) const STOP_COOLDOWN: Duration = Duration::from_secs(600);
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
/// R30 item 3: the Garbage Collector's expected end after the last other
/// binding of its database ends, past the database's linger when the last
/// check read one above 0 (with no linger, or the linger not known, this
/// alone: a later record of the Garbage Collector is ambiguous, loud).
const GC_END: Duration = Duration::from_secs(10);

/// The longest linger taken as known (24 h, review N2); a longer one is
/// not known (the 10 s bound, fail closed).
pub(crate) const MAX_LINGER: u32 = 24 * 3600;

/// R30 item 3: the Garbage Collector's expected end for a database whose
/// last check read the linger `linger` (seconds).
pub(crate) fn gc_end(linger: Option<u32>) -> Duration {
    match linger {
        Some(l) if l > 0 && l <= MAX_LINGER => GC_END + Duration::from_secs(u64::from(l)),
        _ => GC_END,
    }
}

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

/// What the last `check()` gives the stream for R1 rule 5, per declared
/// database (the order of [`Settings::databases`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RestoreFacts {
    /// Restores the checks of this process confirmed from a changed
    /// `DB_GUID` or `MON$CREATION_DATE` (a count).
    pub(crate) confirmed: u64,
    /// The check attachment's `CURRENT_CONNECTION`.
    pub(crate) own_id: Option<u64>,
}

/// Database identity (R1 rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// A local external data source's attachment (R29): an `<internal>`
    /// line with a user and a role.
    External,
}

/// R29 item 2 (with the maintainer's decision of 2026-11-01 on the
/// review of #402): the events of an external-source binding, held across
/// its transactions until one of them ends after a caller was seen. O(1)
/// per binding (review H1): no candidate set is kept; a caller is a
/// binding whose code finish record's transaction started before the
/// external binding's open transaction (positions, `Machine::tra_pos`).
#[derive(Debug)]
struct ExtHold {
    /// Reading time of the first event held since the last release (the
    /// 10-minute bound).
    started: Option<Instant>,
    /// Its position (the persisted position is held back to it).
    first_pos: Option<u64>,
    events: Vec<ExtHeld>,
    bytes: usize,
    /// The position of the `START_TRANSACTION` of the external binding's
    /// open transaction (candidates are taken there, review L4).
    tx_start: Option<u64>,
    /// A caller was seen since the last release (reset at each release:
    /// a pooled external connection serves several callers).
    caller: bool,
}

/// The bytes one external-source hold is charged, held events apart.
const EXT_HOLD_BYTES: usize = 256;

/// One record of an external-source binding: its event as judged, if
/// any, and its ambiguous form (`*`, always reported).
#[derive(Debug)]
struct ExtHeld {
    db: usize,
    normal: Option<MaskedEvent>,
    loud: MaskedEvent,
    key: Option<DKey>,
}

/// R29 item 2: a binding's events are held at most this long.
const EXT_TIME: Duration = Duration::from_secs(600);
/// R29 item 2 (security review L9): held events per stream.
const EXT_EVENTS: usize = 16_384;
const EXT_BYTES: usize = 4 << 20;

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
    /// R1 rule 9: a keyed hash of its TCP line's client address and port.
    addr: Option<u64>,
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

/// What a held DDL record's database waits on (re-review M-1, round 4
/// M-1b): a transaction's end record (or its binding's end), or a
/// binding's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Pend {
    Tra(Key, u64),
    Binding(Key),
}

impl Pend {
    fn key(self) -> Key {
        match self {
            Self::Tra(k, _) | Self::Binding(k) => k,
        }
    }
}

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
    /// The position of its last record (its events' key).
    last: u64,
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
    /// The position it is attributed to.
    key: Option<DKey>,
}

/// The position an event is attributed to (R25 item 7's deduplication by
/// position): its record's, or for the events of a group that ended
/// without folding, the group's members: its first record's position, its
/// number of records and its last record's position (`group`). A re-read
/// that groups the records otherwise (a group ended by reading time, a cap
/// or shedding on the first reading, not on the re-read) gives another
/// key, so its events are sent, never suppressed for another group's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct DKey {
    /// The log file's `(st_dev, st_ino)`.
    pub(crate) file: (u64, u64),
    /// The record's first byte (a group: its first record's).
    pub(crate) off: u64,
    pub(crate) group: bool,
    /// A group's records (0 for a record).
    pub(crate) members: u64,
    /// A group's last record's first byte (0 for a record).
    pub(crate) last: u64,
}

/// The state as it was before the record that started a block-less hold
/// (the checkpoint while the hold lasts, R25 item 7).
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub(crate) file: (u64, u64),
    pub(crate) pos: u64,
    pub(crate) body: Vec<u8>,
    /// [`Machine::step`] when it was taken.
    pub(crate) step: u64,
    /// Reading time when it was taken.
    taken: Instant,
}

/// Snapshots are taken at most this often (each copies the state): a
/// hold that starts sooner after the last one keeps the older snapshot, a
/// valid state at an earlier position (a longer re-read, never a loss).
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// The largest state a snapshot is taken of (each block-less hold copies
/// it); past it, no snapshot, so no new checkpoint while the hold lasts
/// (the last one stays: a longer re-read, fail closed).
const MAX_SNAPSHOT_STATE: usize = 4 << 20;

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
    /// Events not emitted again after a restart: their position's events
    /// had been durably spooled (R25 item 7).
    pub(crate) deduped: u64,
    /// Statement records of the agent's own anchored attachments whose
    /// block or count matched no credit's own-statement table row (the
    /// engine-matrix test of R20 expects none).
    pub(crate) own_not_matched: u64,
    /// Restores confirmed by `check()` and applied (R1 rule 5).
    pub(crate) restores: u64,
    /// R1 rule 9: new TCP bindings ambiguous for a client address and port
    /// another live binding holds, for no matching socket, and attaches
    /// read within 10 s whose socket condition could not be evaluated (the
    /// table not read whole).
    pub(crate) tcp_reused: u64,
    pub(crate) tcp_no_socket: u64,
    pub(crate) tcp_not_evaluated: u64,
    /// R1 rule 9: fresh TCP attaches whose socket was found.
    pub(crate) tcp_corroborated: u64,
    /// R29: external-source bindings emitted with a caller, and those whose
    /// records were made ambiguous.
    pub(crate) ext_released: u64,
    pub(crate) ext_failed: u64,
    /// Error follow-ups of the agent's own records consumed (R22, R35).
    pub(crate) follow_ups: u64,
    /// `ERROR` records of the agent's own anchored bindings that were no
    /// expected follow-up (handled as any client's: no event).
    pub(crate) own_errors_not_followed: u64,
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
    /// The run was taken from the first pid seen, before any check (R40
    /// item 4): records of another pid are ambiguous, with no stop.
    provisional: bool,
    /// Pids that failed a confirmation (R1 rule 2): ambiguous at once,
    /// with no stop; at most [`MAX_FAILED_PIDS`].
    failed_pids: Vec<u32>,
    /// A run a check read that differs by its pid from the current run
    /// (R1 rule 2): the run changes at the first record that carries its
    /// pid, never before (the stream may still be reading the old run).
    pending_run: Option<Run>,
    /// R1 rule 2 (security review M-3): after a failed confirmation,
    /// records of any new pid are ambiguous without a stop until then
    /// (reading time).
    cooldown_until: Option<Instant>,
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
    /// The binding that learned the offset, the one whose credited record
    /// confirmed it (the same, or a probe's), and the offset before it
    /// (restored if either binding is poisoned).
    offset_from: Option<(Key, Key, Option<i64>)>,
    /// Declared databases whose dependent and block-blind sets are
    /// invalidated (R28 item 4, R41 item 8).
    views_invalid: std::collections::HashSet<usize>,
    /// DDL transactions seen without their end record: binding and
    /// transaction, and the database (R41 item 8).
    ddl_open: HashMap<(Key, u64), usize>,
    /// Per database: after an ambiguous DDL record whose transaction could
    /// not be kept in `ddl_open`, the transactions known open on that
    /// database at the record, or the bindings live at it; invalidated
    /// until each has ended (re-review M-1, round 4 M-1b and L-7).
    ddl_wait: HashMap<usize, std::collections::HashSet<Pend>>,
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
    /// The databases whose `ddl_named` set is lent to the record being
    /// read; on a panic of that record the sets are lost, and these
    /// databases fall back to `all_relations` (never fail open).
    ddl_named_lent: Vec<usize>,
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
    /// A start-time change asks for an immediate check (R5 item 4), not
    /// merged with the early checks of R11 8d.
    pub(crate) run_check_requested: bool,
    /// The record being judged is of the agent's own anchored binding
    /// inside a split window: it ends the window only if it is the agent's
    /// own (R1 rule 7, re-review L-C).
    window_ender: bool,
    /// The read-back probe's own record was read (proof 7).
    pub(crate) probe_seen: Option<SystemTime>,
    /// Ambiguous records by the rule (source line) that judged them, for
    /// the tests and the local detail.
    pub(crate) why: std::collections::BTreeMap<u32, u64>,
    /// The agent key's sub-key: undeclared databases' hashes stable across
    /// restarts, and the checkpoint's identity tag (`None`: no checkpoint).
    tag_key: Option<std::sync::Arc<databastion_classifiers::masking::LocalTagKey>>,
    /// The position of each event pushed to the caller's output, and the
    /// step it was emitted at (taken with [`Self::take_keys`]).
    keys: Vec<(Option<DKey>, u64)>,
    /// The position the record being read attributes its events to.
    cur: Option<DKey>,
    /// Positions whose events were durably spooled before a restart: not
    /// emitted again (R25 item 7).
    suppress: std::collections::HashSet<DKey>,
    /// The positions suppressed, with their step (still sent: kept for the
    /// next checkpoint).
    suppressed: Vec<(DKey, u64)>,
    /// Events emitted so far (held ones at their release).
    step: u64,
    /// Snapshots are taken (the stream checkpoints).
    snapshots: bool,
    snapshot: Option<Snapshot>,
    /// Events are pushed with no position (a poll across a log reset: a
    /// position there may name other content).
    pub(crate) unkeyed: bool,
    /// The suppressed positions were dropped (a run change, a log reset):
    /// the checkpoint drops its restored ones too.
    pub(crate) suppress_cleared: bool,
    /// After a restore, the declared databases whose check results differ
    /// from the previous process's (the decision of 2026-11-01 on L10):
    /// every relation counts as dependent for the records re-read before
    /// that process's read end, `(database, file, end)`.
    reread_invalid: Vec<(usize, (u64, u64), u64)>,
    /// R1 rule 5: the last check's restore facts, and per declared
    /// `attach` the confirmed-restore count already applied.
    restore_facts: Vec<RestoreFacts>,
    restores_seen: HashMap<String, u64>,
    /// R22 items 5 to 8, R35: the error follow-up per own binding, not
    /// persisted (a restart loses an expected follow-up, so its record is
    /// handled as any client's error record: no event, nothing hidden; and
    /// a consumed one, so a forged second copy right after a restart is not
    /// loud, which hides nothing either).
    follow_ups: HashMap<Key, FollowUp>,
    /// R1 rule 9: the runner's observation of the current read.
    tcp: Option<TcpView>,
    /// R1 rule 9: the live bindings by their client end's hash.
    /// Per hash: the live bindings not yet poisoned for it, and how many
    /// live bindings hold it (a reuse poisons the first ones once; the
    /// count keeps the end held while any of them lives).
    by_addr: HashMap<u64, (Vec<Key>, usize)>,
    /// R29: the external-source bindings (each holds its events until a
    /// transaction of it ends after a caller was seen).
    ext: HashMap<Key, ExtHold>,
    /// R29 (review H1 and L4 of #402): the position of the
    /// `START_TRANSACTION` of each open transaction of a user binding, for
    /// the caller test; bounded with the bindings' open transactions.
    tra_pos: HashMap<Key, Vec<(u64, u64)>>,
    /// The positions kept in `tra_pos` (the state's size).
    tra_pos_entries: usize,
    /// Their held events and bytes (the stream's bounds).
    ext_events: usize,
    ext_bytes: usize,
    /// Holds that ended with no verdict (the binding gone, a bound): their
    /// records are ambiguous, emitted at the next record or expiry.
    ext_fail: Vec<ExtHold>,
}

/// What the machine emits: an event and the declared databases it goes to.
pub(crate) type Emitted = (usize, MaskedEvent);

impl Machine {
    pub(crate) fn new(s: Settings, ledger: std::sync::Arc<Ledger>) -> Self {
        Self {
            s,
            run: None,
            unconfirmed: false,
            provisional: false,
            failed_pids: Vec::new(),
            pending_run: None,
            cooldown_until: None,
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
            ddl_named_lent: Vec::new(),
            ledger,
            hash_key: std::collections::hash_map::RandomState::new(),
            pending_end: Vec::new(),
            counts: Counts::default(),
            check_requested: false,
            run_check_requested: false,
            window_ender: false,
            probe_seen: None,
            why: std::collections::BTreeMap::new(),
            tag_key: None,
            keys: Vec::new(),
            cur: None,
            suppress: std::collections::HashSet::new(),
            suppressed: Vec::new(),
            step: 0,
            snapshots: false,
            snapshot: None,
            unkeyed: false,
            suppress_cleared: false,
            reread_invalid: Vec::new(),
            restore_facts: Vec::new(),
            restores_seen: HashMap::new(),
            follow_ups: HashMap::new(),
            tcp: None,
            by_addr: HashMap::new(),
            ext: HashMap::new(),
            tra_pos: HashMap::new(),
            tra_pos_entries: 0,
            ext_events: 0,
            ext_bytes: 0,
            ext_fail: Vec::new(),
        }
    }

    /// R1 rule 5, at the stream's start: the restores the checks confirmed
    /// before it are not applied again (the stream starts with no state, or
    /// with a checkpoint's, which the watermark rule covers).
    pub(crate) fn restore_baseline(&mut self, facts: &[RestoreFacts]) {
        self.restores_seen = self
            .s
            .databases
            .iter()
            .zip(facts)
            .map(|(d, f)| (d.attach.clone(), f.confirmed))
            .collect();
        self.restore_facts = facts.to_vec();
    }

    /// R1 rule 5: a new check's restore facts, applied at once.
    pub(crate) fn set_restore_facts(&mut self, facts: Vec<RestoreFacts>) {
        self.restore_facts = facts;
        self.apply_restores();
    }

    /// R1 rule 5: restores are recognised from `check()` only, never from
    /// a log record. A declared database is restored when a check of this
    /// process read another `DB_GUID` or `MON$CREATION_DATE` than the one
    /// before, or when the agent's persisted ledger shows the check's
    /// attachment to be of a new database life (an own attachment with a
    /// higher id registered well before it, [`Ledger::new_life`]: the
    /// maintainer's decision of 2026-11-01 on L3, instead of the trace's
    /// watermark; it holds across stream and agent restarts, and the
    /// evidence is forgotten once applied). Then the database's bindings
    /// end, its own-attachment set, watermark, highest and seen ids and
    /// learned floor are cleared, its DDL waits end, and its dependent sets
    /// are invalidated until the next check. Returns the databases restored.
    pub(crate) fn apply_restores(&mut self) -> usize {
        let mut n = 0;
        for i in 0..self.s.databases.len().min(self.restore_facts.len()) {
            let f = self.restore_facts[i];
            let d = &self.s.databases[i];
            if d.excluded {
                continue;
            }
            let seen = self.restores_seen.get(&d.attach).copied().unwrap_or(0);
            let by_state = f.confirmed > seen;
            let by_id = f
                .own_id
                .is_some_and(|own| self.ledger.new_life(&d.attach, own));
            self.restores_seen.insert(d.attach.clone(), f.confirmed);
            if by_state || by_id {
                self.restore_db(i, f.own_id);
                n += 1;
            }
        }
        n
    }

    /// R1 rule 5: a confirmed restore of declared database `i`.
    fn restore_db(&mut self, i: usize, own_id: Option<u64>) {
        let db = DbId::Declared(i);
        let keys: Vec<Key> = self
            .bindings
            .keys()
            .filter(|k| k.0 == db)
            .copied()
            .collect();
        for k in keys {
            self.end_binding(k);
        }
        // Its DDL transactions and waits end with its bindings (as at a
        // run's end and an eviction, re-review L-5; review L1).
        self.ddl_open.retain(|(k, _), _| k.0 != db);
        for w in self.ddl_wait.values_mut() {
            w.retain(|p| p.key().0 != db);
        }
        self.ddl_wait.retain(|_, w| !w.is_empty());
        // Review L2: the records between the read position and the real
        // restore point are of the earlier life, judged with this check's
        // sets: invalidated until the next check, whatever was open.
        self.invalidate(i, SystemTime::now());
        self.watermark.remove(&i);
        self.highest.remove(&db);
        if let Some(seen) = self.seen_ids.remove(&db) {
            self.seen_total = self.seen_total.saturating_sub(seen.order.len());
        }
        self.learned_floor.remove(&db);
        self.gc_alone_since.remove(&db);
        if let Some(id) = own_id {
            self.ledger
                .forget_earlier_life(&self.s.databases[i].attach, id);
        }
        self.counts.restores += 1;
        tracing::info!(
            database = i,
            "Firebird declared database restored (R1 rule 5): its attachments start again"
        );
    }

    /// The suppressed positions the read has passed are dropped: those
    /// before `pos` in `file` (a group's while a pending group starts
    /// there), and every one of another file.
    pub(crate) fn prune_suppress(&mut self, file: (u64, u64), pos: u64) {
        if self.suppress.is_empty() {
            return;
        }
        let firsts = self.group_firsts();
        self.suppress
            .retain(|k| k.file == file && (k.off >= pos || (k.group && firsts.contains(&k.off))));
        self.reread_invalid
            .retain(|(_, f, end)| *f == file && *end > pos);
    }

    /// A log reset (a truncation, a rotation): positions read before it may
    /// name other content now. Nothing is suppressed any more, the snapshot
    /// is dropped, and the re-read invalidation ends.
    pub(crate) fn reset_positions(&mut self) {
        self.suppress.clear();
        self.suppress_cleared = true;
        self.snapshot = None;
        self.reread_invalid.clear();
    }

    /// After a restore: the databases invalidated for the records re-read
    /// before `end` of `file` (the decision of 2026-11-01 on L10).
    pub(crate) fn set_reread_invalid(&mut self, file: (u64, u64), dbs: &[(usize, u64)]) {
        self.reread_invalid = dbs
            .iter()
            .filter(|(d, _)| *d < self.s.databases.len())
            .map(|(d, e)| (*d, file, *e))
            .collect();
    }

    /// The re-read invalidations still to apply, `(database, end)` in
    /// `file` (written with the next checkpoint).
    pub(crate) fn reread_invalid(&self, file: (u64, u64)) -> Vec<(usize, u64)> {
        self.reread_invalid
            .iter()
            .filter(|(_, f, _)| *f == file)
            .map(|(d, _, e)| (*d, *e))
            .collect()
    }

    fn reread_dirty(&self, db: usize, pos: u64) -> bool {
        self.reread_invalid
            .iter()
            .any(|(d, f, e)| *d == db && *f == self.file && pos < *e)
    }

    /// Enables the checkpoint: the agent key's sub-key (stable hashes of
    /// undeclared databases, the identity tag) and the snapshots of R25
    /// item 7. Before any record.
    pub(crate) fn enable_checkpoint(
        &mut self,
        key: std::sync::Arc<databastion_classifiers::masking::LocalTagKey>,
    ) {
        self.tag_key = Some(key);
        self.snapshots = true;
    }

    /// The positions not to emit again (restored with a checkpoint).
    pub(crate) fn set_suppress(&mut self, keys: std::collections::HashSet<DKey>) {
        self.suppress = keys;
    }

    /// The positions of the events pushed since the last call, in order,
    /// with their step.
    pub(crate) fn take_keys(&mut self) -> Vec<(Option<DKey>, u64)> {
        std::mem::take(&mut self.keys)
    }

    /// The positions suppressed since the last call.
    pub(crate) fn take_suppressed(&mut self) -> Vec<(DKey, u64)> {
        std::mem::take(&mut self.suppressed)
    }

    /// The positions some of whose events are still held.
    pub(crate) fn held_keys(&self) -> std::collections::HashSet<DKey> {
        self.held.iter().filter_map(|h| h.key).collect()
    }

    /// Events emitted so far.
    pub(crate) fn step(&self) -> u64 {
        self.step
    }

    /// A block-less group pends: the position is held back to it.
    pub(crate) fn blockless_pending(&self) -> bool {
        self.groups.iter().any(Group::blockless)
    }

    /// The first positions of the pending groups (their keys may come
    /// again).
    pub(crate) fn group_firsts(&self) -> std::collections::HashSet<u64> {
        self.groups.iter().map(|g| g.first).collect()
    }

    /// The pending groups' state in bytes (R25 item 4).
    pub(crate) fn group_bytes(&self) -> usize {
        self.groups.iter().map(Group::bytes).sum()
    }

    /// R25 item 9, first step: the oldest pending groups end, as item 3
    /// says (their outputs to `out`), until the groups' state is at most
    /// `budget` bytes. The number ended.
    pub(crate) fn shed_groups(
        &mut self,
        budget: usize,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) -> usize {
        let mut n = 0;
        while self.group_bytes() > budget {
            let Some(g) = self.groups.pop_front() else {
                break;
            };
            self.end_group(g, now, cat, out);
            n += 1;
        }
        if n > 0 && self.hold_since.is_some() && !self.blockless_pending() {
            self.release(false, out);
        }
        n
    }

    /// The declared `attach` names (the ledger's keys).
    pub(crate) fn attaches(&self) -> Vec<String> {
        self.s.databases.iter().map(|d| d.attach.clone()).collect()
    }

    /// The snapshot of the current hold, if one was taken.
    pub(crate) fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Pushes one event to the caller's output, attributed to `key`; not
    /// emitted again when its position was durably spooled before a
    /// restart.
    fn put(&mut self, out: &mut Vec<Emitted>, db: usize, ev: MaskedEvent, key: Option<DKey>) {
        self.step += 1;
        let key = key.filter(|_| !self.unkeyed);
        if let Some(k) = key
            && self.suppress.contains(&k)
        {
            self.counts.deduped += 1;
            self.suppressed.push((k, self.step));
            return;
        }
        out.push((db, ev));
        self.keys.push((key, self.step));
    }

    /// The key of a group's events.
    fn group_key(&self, g: &Group) -> DKey {
        DKey {
            file: self.file,
            off: g.first,
            group: true,
            members: g.full.count + g.bare.count,
            last: g.last,
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

    /// Test support: whether every relation of `db` counts as dependent
    /// until the next check.
    #[cfg(test)]
    pub(crate) fn all_relations_for_tests(&self, db: usize) -> bool {
        self.all_relations.contains(&db)
    }

    /// Test support: a DDL wait on database `db` for a binding of it.
    #[cfg(test)]
    pub(crate) fn fill_ddl_wait_for_tests(&mut self, db: usize) {
        self.ddl_wait
            .entry(db)
            .or_default()
            .insert(Pend::Binding((DbId::Declared(db), 50)));
    }

    /// Test support: the databases with a DDL wait.
    #[cfg(test)]
    pub(crate) fn ddl_wait_len_for_tests(&self) -> usize {
        self.ddl_wait.len()
    }

    /// Test support: whether `db`'s dependent sets are invalidated.
    #[cfg(test)]
    pub(crate) fn views_invalid_for_tests(&self, db: usize) -> bool {
        self.views_invalid.contains(&db)
    }

    /// Test support: the DDL transactions tracked.
    #[cfg(test)]
    pub(crate) fn ddl_open_len_for_tests(&self) -> usize {
        self.ddl_open.len()
    }

    /// The log file the next records come from.
    pub(crate) fn set_file(&mut self, file: (u64, u64)) {
        if file != self.file {
            // Transactions started in an earlier file started before
            // anything of this one (R29's caller test compares positions).
            for v in self.tra_pos.values_mut() {
                for (_, p) in v.iter_mut() {
                    *p = 0;
                }
            }
            // An external transaction opened in an earlier file: its start
            // position means nothing here, so no caller is taken for it
            // (review L5 of #402: held until a later transaction).
            for h in self.ext.values_mut() {
                h.tx_start = None;
            }
        }
        self.file = file;
    }

    /// New settings from a re-evaluation (names, map, proof 11).
    pub(crate) fn reconfigure(&mut self, s: Settings) {
        self.s = s;
        self.clear_invalidations();
    }

    /// The invalidations a check's catalog read clears (after a new check,
    /// and after a restore under the current check's settings).
    pub(crate) fn clear_invalidations(&mut self) {
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
        let old = self.run;
        let other = old.is_some_and(|r| match r.start {
            None => r.pid != run.pid,
            Some(_) => r != run,
        });
        if other {
            self.end_run();
            // R1 rule 2: the own-attachment lifetimes of the old run close
            // (a new pid; a restart with the same pid is closed by the
            // connector's lost-connection rule, decision 3).
            if let Some(o) = old
                && o.pid != run.pid
            {
                self.ledger.end_run(o.pid);
            }
        }
        self.run = Some(run);
        self.unconfirmed = false;
        self.provisional = false;
        if self.pending_run.is_some_and(|p| p.pid == run.pid) {
            self.pending_run = None;
        }
    }

    /// The run a new check read (R1 rules 1 and 2). The same run, or a run
    /// of the same pid with a new start time (R5 item 4: placed by the
    /// start-time samples), or any run while the current one is
    /// provisional (R40 item 4), is confirmed at once. A run of another pid
    /// is kept pending: the run changes at the first record that carries
    /// that pid (the stream may still be reading records of the old run,
    /// which stay judged as the old run's).
    pub(crate) fn check_run(&mut self, run: Run) {
        match self.run {
            Some(r) if r.pid != run.pid && !self.provisional => {
                self.pending_run = Some(run);
            }
            _ => self.confirm_run(run),
        }
    }

    /// A `/proc` sample that shows another start time than the current
    /// run's: records are ambiguous until `check()` confirms (R5 item 4).
    /// The stream asks for an immediate check (`run_check_requested`).
    pub(crate) fn start_time_changed(&mut self) {
        if !self.unconfirmed {
            self.run_check_requested = true;
        }
        self.unconfirmed = true;
    }

    /// R1 rule 2: whether the record whose header is `h` stops the stream
    /// before it: a pid other than the current run's, of a confirmed run
    /// (never before the first check, R40 item 4), that no check has shown
    /// to be the server's (a pending run), that did not fail a
    /// confirmation, outside the cooldown, with fewer than
    /// [`MAX_FAILED_PIDS`] pids remembered. `TRACE_INIT` / `TRACE_FINI`
    /// carry no run boundary (R5 item 1): only the pid decides.
    pub(crate) fn stop_wanted(&self, h: &crate::trace_log::Header, now: Instant) -> bool {
        let Some(r) = self.run else {
            return false;
        };
        !self.provisional
            && h.pid != r.pid
            && !self.pending_run.is_some_and(|p| p.pid == h.pid)
            && !self.failed_pids.contains(&h.pid)
            && self.failed_pids.len() < MAX_FAILED_PIDS
            && self.cooldown_until.is_none_or(|u| now >= u)
    }

    /// R1 rule 2: the confirmation of a stop on `pid` failed (the check read
    /// another run, or none answered within [`STOP_LIMIT`]): the pid is
    /// remembered for the run, and the cooldown starts. Its records are
    /// ambiguous (they carry a pid other than the run's).
    pub(crate) fn confirmation_failed(&mut self, pid: u32, now: Instant) {
        if !self.failed_pids.contains(&pid) && self.failed_pids.len() < MAX_FAILED_PIDS {
            self.failed_pids.push(pid);
        }
        self.cooldown_until = Some(now + STOP_COOLDOWN);
    }

    /// R1 rule 7 and R25: time while the stream is stopped (R1 rule 2) is
    /// not reading time: every reading-time instant moves by `d` (split
    /// windows, fold groups, holds, the order rule's times, the Garbage
    /// Collector's expected end, the cooldown is agent time and stays).
    pub(crate) fn pause(&mut self, d: Duration) {
        if let Some(u) = self.window_until.as_mut() {
            *u += d;
        }
        for g in &mut self.groups {
            g.started += d;
        }
        if let Some(h) = self.hold_since.as_mut() {
            *h += d;
        }
        for (_, t) in self.highest.values_mut() {
            *t += d;
        }
        for t in self.gc_alone_since.values_mut() {
            *t += d;
        }
        for h in self.ext.values_mut() {
            if let Some(t) = h.started.as_mut() {
                *t += d;
            }
        }
    }

    /// Test support: the pids remembered as failed.
    #[cfg(test)]
    pub(crate) fn failed_pids_for_tests(&self) -> &[u32] {
        &self.failed_pids
    }

    /// Test support: the split window's end, if one is open at `now`.
    #[cfg(test)]
    pub(crate) fn window_for_tests(&self, now: Instant) -> Option<Instant> {
        self.window_until.filter(|u| now < *u)
    }

    /// Test support: a split window opened at `now`.
    #[cfg(test)]
    pub(crate) fn open_window_for_tests(&mut self, now: Instant) {
        self.window_until = Some(now + WINDOW);
    }

    /// Test support: the current run.
    #[cfg(test)]
    pub(crate) fn run_for_tests(&self) -> Option<Run> {
        self.run
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
        // The positions restored for the old run are not suppressed in the
        // new one (fail closed: sent again).
        if !self.suppress.is_empty() {
            self.suppress.clear();
            self.suppress_cleared = true;
        }
        // Review L-B: the run's pending groups end as R25 item 3 says (at the
        // next record or reading-time bound), never dropped silently.
        let groups: Vec<Group> = self.groups.drain(..).collect();
        self.pending_end.extend(groups);
        self.bindings.clear();
        self.tra_pos.clear();
        self.tra_pos_entries = 0;
        self.by_addr.clear();
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
        self.cooldown_until = None;
        self.follow_ups.clear();
        // R29: the run's external-source holds end with no verdict.
        let keys: Vec<Key> = self.ext.keys().copied().collect();
        for k in keys {
            self.fail_ext(k);
        }
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
            + self.tra_pos.len() * 48
            + self.tra_pos_entries * 24
            + self.by_addr.len() * 48
            + self.ext_bytes
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
                w.retain(|p| p.key() != key);
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
        if let Some(a) = b.addr {
            let e = self.by_addr.entry(a).or_default();
            if !b.poisoned {
                e.0.push(key);
            }
            e.1 += 1;
        }
        if let Some(old) = self.bindings.insert(key, b) {
            // Replaced (not expected): the count stays one.
            let _ = old;
            if let Some(n) = self.binding_count.get_mut(&key.0) {
                *n = n.saturating_sub(1);
            }
        }
    }

    fn remove_binding(&mut self, key: Key) -> Option<Binding> {
        if let Some(v) = self.tra_pos.remove(&key) {
            self.tra_pos_entries = self.tra_pos_entries.saturating_sub(v.len());
        }
        let b = self.bindings.remove(&key)?;
        if let Some(a) = b.addr
            && let Some(v) = self.by_addr.get_mut(&a)
        {
            v.0.retain(|k| *k != key);
            v.1 = v.1.saturating_sub(1);
            if v.1 == 0 {
                self.by_addr.remove(&a);
            }
        }
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
    /// of the oldest pending group (R25 item 7), or the first held record
    /// of an external-source binding (R29 item 2), `None` when nothing
    /// pends.
    pub(crate) fn held_from(&self) -> Option<u64> {
        self.groups
            .iter()
            .map(|g| g.first)
            .chain(self.ext.values().filter_map(|h| h.first_pos))
            .min()
    }

    /// A hold the checkpoint cannot be taken in (a block-less group, or an
    /// external-source binding's held events): the snapshot of its start
    /// is used.
    pub(crate) fn holds_pending(&self) -> bool {
        self.blockless_pending()
            || self.ext.values().any(|h| !h.events.is_empty())
            || !self.ext_fail.is_empty()
    }

    /// R29: a new external-source binding's hold, charged to the stream's
    /// bounds; `false` past them (its records are then ambiguous).
    fn new_ext_hold(&mut self, key: Key) -> bool {
        if self.ext_bytes + EXT_HOLD_BYTES > EXT_BYTES {
            return false;
        }
        self.ext_bytes += EXT_HOLD_BYTES;
        self.ext.insert(
            key,
            ExtHold {
                started: None,
                first_pos: None,
                events: Vec::new(),
                bytes: 0,
                tx_start: None,
                caller: false,
            },
        );
        true
    }

    /// R29: the hold of `key` ends. Its held events, and its fold groups
    /// still pending (review M2 of #402: never a quiet event), become
    /// ambiguous; the binding, if live, is poisoned (`poison`: a failure;
    /// otherwise its end with nothing held).
    fn fail_ext(&mut self, key: Key) {
        let Some(mut h) = self.ext.remove(&key) else {
            return;
        };
        self.ext_events = self.ext_events.saturating_sub(h.events.len());
        self.ext_bytes = self.ext_bytes.saturating_sub(h.bytes + EXT_HOLD_BYTES);
        // Its pending groups end loud, wherever they wait.
        let mut gs: Vec<Group> = self
            .groups
            .iter()
            .filter(|g| g.key == key)
            .cloned()
            .collect();
        self.groups.retain(|g| g.key != key);
        gs.extend(self.pending_end.iter().filter(|g| g.key == key).cloned());
        self.pending_end.retain(|g| g.key != key);
        for g in gs {
            let DbId::Declared(db) = g.key.0 else {
                continue;
            };
            let mut d = g.full.draft();
            for o in g.bare.draft().objects {
                if !d.objects.contains(&o) {
                    d.objects.push(o);
                }
            }
            d.star = true;
            d.always = true;
            let loud = self.draft_event(&d, None, db);
            h.events.push(ExtHeld {
                db,
                normal: None,
                loud,
                key: Some(self.group_key(&g)),
            });
        }
        if h.events.is_empty() {
            return;
        }
        self.counts.ext_failed += 1;
        if let Some(b) = self.bindings.get_mut(&key)
            && b.kind == Kind::External
        {
            b.poisoned = true;
        }
        self.ext_fail.push(h);
    }

    /// Emits the records of the holds that ended with no caller, each
    /// ambiguous (R29 item 2, as R18 item 3: always reported, `*`).
    fn flush_ext_fail(&mut self, out: &mut Vec<Emitted>) {
        for h in std::mem::take(&mut self.ext_fail) {
            for e in h.events {
                self.counts.ambiguous += 1;
                *self.why.entry(2).or_default() += 1;
                self.emit_keyed(e.db, e.loud, e.key, out);
            }
        }
    }

    /// R29 item 2 (decision of 2026-11-01): a transaction of the
    /// external-source binding `key` ended. Once a caller was seen, its
    /// held events are emitted as judged and the caller test starts again;
    /// with none, they stay held (the binding's detach or a bound decides).
    fn ext_tx_end(&mut self, key: Key, out: &mut Vec<Emitted>) {
        let Some(h) = self.ext.get_mut(&key) else {
            return;
        };
        h.tx_start = None;
        if !h.caller {
            return;
        }
        h.caller = false;
        h.started = None;
        h.first_pos = None;
        let events = std::mem::take(&mut h.events);
        let bytes = std::mem::take(&mut h.bytes);
        self.counts.ext_released += 1;
        self.ext_events = self.ext_events.saturating_sub(events.len());
        self.ext_bytes = self.ext_bytes.saturating_sub(bytes);
        for e in events {
            if let Some(ev) = e.normal {
                self.emit_keyed(e.db, ev, e.key, out);
            }
        }
    }

    /// R29 item 2: one record's outputs of the external-source binding
    /// `key`, held; past a bound, the hold fails.
    fn hold_ext(&mut self, key: Key, db: usize, normal: Option<MaskedEvent>, loud: MaskedEvent) {
        let b = held_bytes(&loud) + normal.as_ref().map_or(0, held_bytes);
        let now = Instant::now();
        let pos = self.cur.map(|k| k.off);
        let Some(h) = self.ext.get_mut(&key) else {
            return;
        };
        h.started.get_or_insert(now);
        if h.first_pos.is_none() {
            h.first_pos = pos;
        }
        h.events.push(ExtHeld {
            db,
            normal,
            loud,
            key: self.cur,
        });
        h.bytes += b;
        self.ext_events += 1;
        self.ext_bytes += b;
        if self.ext_events > EXT_EVENTS || self.ext_bytes > EXT_BYTES {
            self.fail_ext(key);
        }
    }

    /// R29 item 2: a finish record of code of the user binding `key` in
    /// transaction `tra` is the caller of every external-source binding
    /// whose open transaction started after `tra` did (so `tra` was open
    /// at it, and is still open: it writes this record).
    fn note_caller(&mut self, key: Key, tra: Option<u64>) {
        let Some(p) = tra.and_then(|t| {
            self.tra_pos
                .get(&key)
                .and_then(|v| v.iter().find(|(x, _)| *x == t).map(|(_, p)| *p))
        }) else {
            return;
        };
        for h in self.ext.values_mut() {
            if h.tx_start.is_some_and(|s| p < s) {
                h.caller = true;
            }
        }
    }

    /// The key of the external-source binding a record belongs to, when its
    /// events are held.
    fn ext_key(&self, rec: &Record<'_>) -> Option<Key> {
        if self.ext.is_empty() {
            return None;
        }
        let att = rec.att?;
        let Resolved::Db(d) = self.resolve(att.database) else {
            return None;
        };
        let k = (d, att.id);
        self.ext.contains_key(&k).then_some(k)
    }

    /// R1 rule 9: the runner's observation for the records handed next.
    pub(crate) fn set_tcp_view(&mut self, v: Option<TcpView>) {
        self.tcp = v;
    }

    /// R1 rule 9 for a new TCP binding at `pos` with `token`: ambiguous
    /// when another live binding holds the same client address and port,
    /// or, for a record written within 10 s and a binding still live when
    /// the table was read, when no server connection has that client end.
    fn tcp_breach(
        &mut self,
        addr: u64,
        ep: std::net::SocketAddr,
        token: (u32, u64),
        pos: u64,
        att: (&str, u64),
    ) -> bool {
        // Review L2 of #402: a reused client end poisons every binding that
        // holds it, as a duplicate id does (R1 rule 3).
        let mut reused = false;
        if let Some(e) = self.by_addr.get_mut(&addr) {
            reused = e.1 > 0;
            for k in std::mem::take(&mut e.0) {
                if let Some(b) = self.bindings.get_mut(&k) {
                    b.poisoned = true;
                    b.own = false;
                }
            }
        }
        if reused {
            self.counts.tcp_reused += 1;
            self.check_offset_binding();
            return true;
        }
        let Some(v) = self.tcp.as_ref() else {
            return false;
        };
        let fresh = v.file == self.file && v.fresh_from.is_some_and(|f| pos >= f);
        // Review M1 of #402: only a later `DETACH_DATABASE` of this same
        // binding (its token, its database name and its attachment id).
        let db = db_hash(att.0);
        let detached = v.detached.get(&token).is_some_and(|ps| {
            ps.iter()
                .any(|(p, id, d)| *p > pos && *id == att.1 && *d == db)
        });
        if !fresh || detached {
            return false;
        }
        match &v.clients {
            None => {
                self.counts.tcp_not_evaluated += 1;
                false
            }
            Some(c) if c.contains(&ep) => {
                self.counts.tcp_corroborated += 1;
                false
            }
            Some(_) => {
                self.counts.tcp_no_socket += 1;
                true
            }
        }
    }

    /// Test support: external-source holds pending.
    #[cfg(test)]
    pub(crate) fn ext_holds_for_tests(&self) -> usize {
        self.ext.len()
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
    ///
    /// Round 4 M-1b and L-7: a record whose transaction is not known waits
    /// for the end of its binding when that binding is live; a record of
    /// which no binding is known (`key` `None`: its database does not
    /// resolve, or nothing of it was read) waits for the end of every
    /// binding live on the database at the record (the agent's own and the
    /// Garbage Collector's excepted: neither writes DDL), not for the run's
    /// end, so one forged record does not invalidate a run.
    fn hold_ddl(&mut self, dbs: &[usize], key: Option<Key>, tra: Option<u64>) {
        for &db in dbs {
            let Some(k) = key.filter(|k| k.0 == DbId::Declared(db)) else {
                let live: std::collections::HashSet<Pend> = self
                    .bindings
                    .iter()
                    .filter(|(k, b)| {
                        k.0 == DbId::Declared(db) && !b.own && b.kind != Kind::Internal
                    })
                    .map(|(k, _)| Pend::Binding(*k))
                    .collect();
                if live.len() > MAX_DDL_OPEN {
                    self.run_sticky.insert(db);
                } else if !live.is_empty() {
                    self.ddl_wait.entry(db).or_default().extend(live);
                }
                continue;
            };
            let open: std::collections::HashSet<Pend> = self
                .bindings
                .iter()
                .filter(|(k, _)| k.0 == DbId::Declared(db))
                .flat_map(|(k, b)| b.open_tras.iter().map(move |t| Pend::Tra(*k, *t)))
                .collect();
            let own_known = tra.is_some_and(|t| open.contains(&Pend::Tra(k, t)));
            if own_known && open.len() <= MAX_DDL_OPEN {
                self.ddl_wait.entry(db).or_default().extend(open);
            } else if self.bindings.contains_key(&k) {
                self.ddl_wait
                    .entry(db)
                    .or_default()
                    .insert(Pend::Binding(k));
            } else {
                self.run_sticky.insert(db);
            }
        }
    }

    /// A record that may be DDL whose text was not read whole (an
    /// ambiguous DDL statement, a defective statement finish, an
    /// unreadable record): every relation of its database counts as
    /// dependent until a check after its transaction's end (round 4 M-1b).
    /// A database that resolves as undeclared invalidates nothing (L-7).
    fn possible_ddl(&mut self, key: Option<Key>, tra: Option<u64>, wall: SystemTime) {
        let dbs: Vec<usize> = match key {
            Some((DbId::Declared(i), _)) => vec![i],
            Some((DbId::Undeclared(_), _)) => return,
            None => (0..self.s.databases.len()).collect(),
        };
        for db in &dbs {
            self.invalidate(*db, wall);
            self.all_relations.insert(*db);
        }
        match (key, tra) {
            (Some(k @ (DbId::Declared(i), _)), Some(t)) if self.ddl_open.len() < MAX_DDL_OPEN => {
                self.ddl_open.insert((k, t), i);
            }
            _ => self.hold_ddl(&dbs, key, tra),
        }
    }

    fn note_ddl(&mut self, rec: &Record<'_>, decision: &Decision, wall: SystemTime) {
        let key = rec.att.and_then(|att| match self.resolve(att.database) {
            Resolved::Db(d) => Some((d, att.id)),
            Resolved::Ambiguous => None,
        });
        // The end of a DDL transaction, or of its binding: only a well-formed
        // record ends one (a defective record may be forged; never fail
        // open).
        let tra = rec.tra.map(|t| t.id);
        let well_formed = rec.defect.is_none();
        let ended: Vec<(Key, u64)> = match rec.header.event {
            _ if !well_formed => Vec::new(),
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
        // What a held DDL record waits on (M-1, M-1b): a binding's wait
        // also ends when the binding is gone by any other path.
        let ends = |p: &Pend| {
            well_formed
                && match (p, rec.header.event) {
                    (Pend::Tra(k, t), Event::CommitTransaction | Event::RollbackTransaction) => {
                        Some(*k) == key && Some(*t) == tra
                    }
                    (_, Event::DetachDatabase | Event::DropDatabase) => Some(p.key()) == key,
                    _ => false,
                }
        };
        let bindings = &self.bindings;
        let mut done = Vec::new();
        for (db, w) in &mut self.ddl_wait {
            w.retain(|p| !ends(p) && !matches!(p, Pend::Binding(k) if !bindings.contains_key(k)));
            if w.is_empty() {
                done.push(*db);
            }
        }
        for db in done {
            self.ddl_wait.remove(&db);
            self.invalidate(db, wall);
        }
        // Round 4 M-1b: a statement finish whose text was not read (a
        // missing trailer, a text that is not UTF-8, an injected or
        // misshapen body) may be DDL.
        if rec.header.event == Event::ExecuteStatementFinish
            && rec.defect.is_some()
            && !matches!(rec.body, Body::Statement { .. })
        {
            self.possible_ddl(key, tra, wall);
            return;
        }
        match (&rec.body, rec.header.event, decision) {
            (Body::Statement { text, .. }, _, _) => {
                let a = analyze_firebird(text);
                if a.kind != FirebirdKind::Ddl {
                    return;
                }
                match decision {
                    // Re-review M-1: the DDL transaction is kept open under
                    // its resolved binding and transaction, so a check before
                    // its end does not clear the sets.
                    Decision::Ambiguous { .. } => self.possible_ddl(key, tra, wall),
                    Decision::Normal { db, key } => {
                        let db = *db;
                        self.invalidate(db, wall);
                        // Every identifier token of the DDL text is named
                        // (the analysis takes no relation from a DDL text,
                        // so `ALTER TABLE T ADD C COMPUTED BY (…)` names
                        // `T` this way); past the bound, or a text that does
                        // not lex whole, every relation.
                        let ids = crate::idents::idents(text);
                        let tokens = ids.names.len() + ids.packaged.len();
                        let named = self.ddl_named.entry(db).or_default();
                        if a.parses() && !ids.cut && named.len() + tokens <= 4096 {
                            named.extend(ids.names);
                            named.extend(ids.packaged.into_iter().map(|(p, _)| p));
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
            self.offset_from = Some((k, key, self.offset));
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
        if let Some((k, by, prev)) = self.offset_from
            && (poisoned(self, &k) || poisoned(self, &by))
        {
            self.offset = prev;
            self.offset_from = None;
        }
    }

    fn hash(&self, name: &str) -> u64 {
        use std::hash::BuildHasher;
        // R1 rule 11: a keyed hash under the agent's key, stable across
        // restarts (the checkpoint keeps undeclared identities by it).
        match &self.tag_key {
            Some(k) => {
                let t = crate::ckpt::tag(
                    k,
                    b"databastion.firebird.undeclared_database.v1",
                    &[name.as_bytes()],
                );
                let mut b = [0u8; 8];
                b.copy_from_slice(&t[..8]);
                u64::from_be_bytes(b)
            }
            None => self.hash_key.hash_one(name),
        }
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
        self.cur = Some(DKey {
            file: self.file,
            off: pos,
            group: false,
            members: 0,
            last: 0,
        });
        // Review L3: the whole record (parse, judgement, view sets, event)
        // under the panic isolation; a record that panics, or whose header
        // does not parse, is ambiguous (loud), never dropped.
        let done = databastion_core::isolate(|| self.record(raw, pos, now, cat, out));
        match done {
            Some(true) => {}
            Some(false) => self.loud(now, cat, out),
            None => {
                self.counts.panics += 1;
                // The DDL names lent to the record are lost with it: every
                // relation of those databases counts until the next check.
                for db in std::mem::take(&mut self.ddl_named_lent) {
                    self.all_relations.insert(db);
                }
                self.loud(now, cat, out);
            }
        }
        self.cur = None;
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
        self.ddl_named_lent = named.keys().copied().collect();
        let mut all = self.all_relations.clone();
        let mut invalid = self.views_invalid.clone();
        // L10 (decision of 2026-11-01): a database whose check results
        // changed while the agent was stopped, in the re-read region.
        for db in 0..self.s.databases.len() {
            if self.reread_dirty(db, pos) {
                all.insert(db);
                invalid.insert(db);
            }
        }
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
        self.ddl_named_lent.clear();
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
        // R25 item 7: a block-less routine record may start a hold, and
        // the position is then held back to it: the state before it is the
        // checkpoint while the hold lasts.
        // R29 item 2: so may an external-source attach (its events are held
        // until its transaction's end).
        let ext_attach = (rec.header.event == Event::AttachDatabase
            && rec.att.is_some_and(|a| a.protocol == Protocol::Internal))
            || self
                .ext_key(&rec)
                .is_some_and(|k| self.ext.get(&k).is_some_and(|h| h.events.is_empty()));
        if self.snapshots
            && ((matches!(rec.body, Body::Routine { .. }) && rec.trailer.block.is_none())
                || ext_attach)
            && !self.holds_pending()
            && self.snapshot.as_ref().is_none_or(|s| {
                s.file != self.file || now.duration_since(s.taken) >= SNAPSHOT_EVERY
            })
        {
            self.snapshot = (self.state_bytes() <= MAX_SNAPSHOT_STATE)
                .then(|| self.export(now))
                .flatten()
                .map(|body| Snapshot {
                    file: self.file,
                    pos,
                    body,
                    step: self.step,
                    taken: now,
                });
        }
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

    /// [`Self::unreadable`] for the record at `pos` (its events attributed
    /// to that position).
    pub(crate) fn unreadable_at(
        &mut self,
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
        self.cur = Some(DKey {
            file: self.file,
            off: pos,
            group: false,
            members: 0,
            last: 0,
        });
        self.unreadable(now, cat, out);
        self.cur = None;
    }

    /// A record of which nothing is known (unreadable, unparsable, or its
    /// rules panicked): `*`, always reported, fix 3, a window.
    fn loud(&mut self, now: Instant, cat: &[&dyn Catalog], out: &mut Vec<Emitted>) {
        self.counts.ambiguous += 1;
        *self.why.entry(line!()).or_default() += 1;
        // Round 4 M-1b: it may be a DDL record (R41 item 8): every declared
        // database, every relation, until the bindings live at it end.
        self.possible_ddl(None, None, SystemTime::now());
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
        // R29: held external-source bindings shed, ambiguous; a hold with
        // nothing held stays (review L5 of #402: its binding's next records
        // are held again, never emitted with no caller).
        let keys: Vec<Key> = self
            .ext
            .iter()
            .filter(|(_, h)| !h.events.is_empty())
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            self.fail_ext(k);
        }
        self.flush_ext_fail(out);
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
        // R29 item 2: 10 minutes of reading time per external-source hold.
        let old: Vec<Key> = self
            .ext
            .iter()
            .filter(|(_, h)| h.started.is_some_and(|t| now.duration_since(t) >= EXT_TIME))
            .map(|(k, _)| *k)
            .collect();
        for k in old {
            self.fail_ext(k);
        }
        self.flush_ext_fail(out);
        let linger = |d: &DbId| match d {
            DbId::Declared(i) => cat.get(*i).and_then(|c| c.linger()),
            DbId::Undeclared(_) => None,
        };
        let gone: Vec<DbId> = self
            .gc_alone_since
            .iter()
            .filter(|(d, t)| now.duration_since(**t) > gc_end(linger(d)))
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
                self.put(out, d, ev.clone(), h.key);
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

    fn linger(&self) -> Option<u32> {
        self.inner.linger()
    }
}

/// The error follow-up a credited own record leaves on its binding (R22
/// items 5 to 8, R35): the exact `ERROR` record the server writes next on
/// that binding after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FollowKind {
    /// The server's statement timeout (`FAILED` finish of a credit ended
    /// `failed`): `335544794` and `335545129` at `JResultSet::fetchNext`.
    Timeout,
    /// The connector's answered cancel (`FAILED` finish of a credit ended
    /// `cancelled`): `335544794` alone, at `JStatement::openCursor` or
    /// `JResultSet::fetchNext`.
    Cancel,
    /// A stale cancel met by the `DSQL_drop` (R22 item 3): `335544794`
    /// alone (its location was not measured: the two of the cancel).
    StaleCancel,
    /// The row-limit cut whose last request reached the end of the result
    /// (R35): `335544364` alone at `JResultSet::fetchNext`.
    ReqSync,
}

impl FollowKind {
    fn of(a: &crate::conn::FetchAccount) -> Option<Self> {
        use crate::conn::FetchEnd;
        match a.end {
            FetchEnd::Failed => Some(Self::Timeout),
            FetchEnd::Cancelled => Some(Self::Cancel),
            _ if a.stale_cancel_follow_up => Some(Self::StaleCancel),
            FetchEnd::End | FetchEnd::Early if a.cut => Some(Self::ReqSync),
            _ => None,
        }
    }

    /// Whether an `ERROR` record's location and codes are this follow-up's
    /// (the codes exactly, in any order, each once).
    fn matches(self, at: Option<crate::trace_log::ErrorAt>, codes: &[u32]) -> bool {
        use crate::error::gds;
        use crate::trace_log::ErrorAt;
        let mut c = codes.to_vec();
        c.sort_unstable();
        match self {
            Self::Timeout => {
                at == Some(ErrorAt::FetchNext) && c == [gds::CANCELLED, gds::REQ_STMT_TIMEOUT]
            }
            Self::Cancel | Self::StaleCancel => {
                matches!(at, Some(ErrorAt::FetchNext | ErrorAt::OpenCursor))
                    && c == [gds::CANCELLED]
            }
            Self::ReqSync => at == Some(ErrorAt::FetchNext) && c == [gds::REQ_SYNC],
        }
    }

    const ALL: [Self; 4] = [
        Self::Timeout,
        Self::Cancel,
        Self::StaleCancel,
        Self::ReqSync,
    ];
}

/// One binding's follow-up: expected, or consumed (a second record of the
/// follow-up shape is then ambiguous, R22 item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FollowUp {
    kind: FollowKind,
    consumed: bool,
}

/// R22 item 7: an `ERROR` record of the exact follow-up shape (the
/// header, the attachment line, the client line, the transaction line
/// where present, the location line, one line per code, no trailer) whose
/// location and codes are one of the follow-ups'.
fn follow_up_shape<'r>(rec: &'r Record<'_>) -> Option<&'r [u32]> {
    let Body::Error { codes, other_lines } = &rec.body else {
        return None;
    };
    (rec.att.is_some()
        && rec.client.is_some()
        && *other_lines == 0
        // A trailer under an `ERROR` record is a defect (ambiguous) at
        // parse, before this.
        && FollowKind::ALL
            .iter()
            .any(|k| k.matches(rec.header.at, codes)))
    .then_some(codes.as_slice())
}

/// R1 rule 9: what the runner observed for the records of one read, for
/// the remote 4-tuple corroboration.
#[derive(Debug, Clone, Default)]
pub(crate) struct TcpView {
    /// The log file the read was of.
    pub(crate) file: (u64, u64),
    /// Records at or after this offset were written within the last 10 s
    /// of agent time (past an end-of-file offset the tailer recorded less
    /// than 10 s before the read, security review L11): `None` when no
    /// such observation exists (the agent lags, or just started), and the
    /// socket condition is then not evaluated.
    pub(crate) fresh_from: Option<u64>,
    /// The client endpoints of the server's connections, read after the
    /// read (`None`: not read, a bound reached, or no table).
    pub(crate) clients: Option<std::collections::HashSet<std::net::SocketAddr>>,
    /// Tokens with a `DETACH_DATABASE` in the read: its offset, its
    /// attachment id and its printed database name's [`db_hash`]. Such a
    /// binding was no longer live when the table was read.
    pub(crate) detached: Detaches,
}

/// [`TcpView::detached`]: per token, `(offset, attachment id, db_hash)`.
pub(crate) type Detaches = HashMap<(u32, u64), Vec<(u64, u64, u64)>>;

/// An in-memory hash of a printed database name (R1 rule 9's detach
/// match; never persisted or sent).
pub(crate) fn db_hash(name: &str) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
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
        // Runs (R1 rules 1 and 2, R5). A run a check read, of this record's
        // pid, starts here (R1 rule 2: the first record that carries the
        // new pid is the run boundary).
        if let (Some(r), Some(p)) = (self.run, self.pending_run)
            && r.pid != h.pid
            && p.pid == h.pid
        {
            self.confirm_run(p);
        }
        let pid_ok = match self.run {
            Some(r) => r.pid == h.pid && !self.unconfirmed,
            // Before the first confirmation, a history walk: the first pid
            // is taken; the first check confirms it or ends it.
            None => {
                self.run = Some(Run {
                    pid: h.pid,
                    start: None,
                });
                self.provisional = true;
                true
            }
        };
        if !pid_ok {
            // Ambiguous: a pid that failed its confirmation (remembered by
            // `confirmation_failed`), one met in the cooldown or past the
            // remembered pids, a provisional run's other pid, or records
            // after a start-time change until the next confirmation.
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
                // R22 items 5 to 8, R35: the error follow-up of the credited
                // own record before it on its binding, of the exact shape,
                // consumed with no event; a second record of a follow-up
                // shape once it is consumed is ambiguous (a forged copy is
                // loud); any other error record of the binding is handled
                // as any client's, never as the agent's own.
                if let Some(att) = rec.att
                    && let Resolved::Db(d) = self.resolve(att.database)
                {
                    let key = (d, att.id);
                    let live_own = self.bindings.get(&key).is_some_and(|b| {
                        b.own && b.anchored && !b.poisoned && !b.tainted && b.token == token
                    });
                    let shape = follow_up_shape(rec);
                    match self.follow_ups.get(&key).copied() {
                        Some(f)
                            if !f.consumed
                                && live_own
                                && shape.is_some_and(|c| f.kind.matches(h.at, c)) =>
                        {
                            self.follow_ups.insert(
                                key,
                                FollowUp {
                                    consumed: true,
                                    ..f
                                },
                            );
                            self.counts.follow_ups += 1;
                            return Decision::Nothing;
                        }
                        Some(f) if f.consumed && shape.is_some() => {
                            return Decision::Ambiguous {
                                window: false,
                                at: line!(),
                            };
                        }
                        Some(f) if !f.consumed => {
                            // Not its follow-up: the next record was another.
                            self.follow_ups.remove(&key);
                        }
                        _ => {}
                    }
                    if live_own {
                        self.counts.own_errors_not_followed += 1;
                    }
                }
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
        // R22: a follow-up is the next record of its binding, an `ERROR`
        // record; any other record ends it.
        self.follow_ups.remove(&key);
        let internal_line = att.protocol == Protocol::Internal;
        // The Garbage Collector (R6, R16, R30).
        if internal_line && att.user == "Garbage Collector" && att.role.is_none() {
            return self.internal_record(rec, key, token, now);
        }
        let sweeper = att.user == "SWEEPER" && att.role == Some("NONE") && att.charset == "NONE";
        // R29 item 1: a local external data source's attach, exactly
        // `<name> (ATT_<n>, <user>:<role>, NONE, <internal>)` with no client
        // line, on the current run's pid (checked above).
        let ext_attach = internal_line
            && !sweeper
            && h.event == Event::AttachDatabase
            && h.outcome == Outcome::Ok
            && att.role.is_some()
            && att.charset == "NONE"
            && rec.client.is_none();
        let ext_record = internal_line
            && self
                .bindings
                .get(&key)
                .is_some_and(|b| b.kind == Kind::External);
        if internal_line && !sweeper && !ext_attach && !ext_record {
            // R6 item 5: other internal attachments.
            return Decision::Ambiguous {
                window: false,
                at: line!(),
            };
        }
        let kind = if ext_attach {
            Kind::External
        } else if internal_line {
            Kind::Sweep
        } else {
            Kind::User
        };
        match h.event {
            Event::AttachDatabase | Event::CreateDatabase if h.outcome == Outcome::Ok => {
                let d = self.attach(rec, key, token, now, in_window, kind, pos);
                // R29 item 2: its events are held across its transactions
                // until one ends after a caller was seen; past the stream's
                // bound for holds, it is ambiguous at once.
                if kind == Kind::External
                    && matches!(d, Decision::Normal { .. })
                    && !self.new_ext_hold(key)
                {
                    if let Some(b) = self.bindings.get_mut(&key) {
                        b.poisoned = true;
                    }
                    return Decision::Ambiguous {
                        window: false,
                        at: line!(),
                    };
                }
                d
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
                        addr: None,
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

    #[allow(clippy::too_many_arguments)]
    fn attach(
        &mut self,
        rec: &Record<'_>,
        key: Key,
        token: (u32, u64),
        now: Instant,
        in_window: bool,
        kind: Kind,
        pos: u64,
    ) -> Decision {
        let (db, id) = key;
        if kind != Kind::User && rec.client.is_some() {
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
        // R1 rule 9: the remote 4-tuple of a TCP line (not the server's
        // internal attachments, which have none).
        let mut addr = None;
        let mut poison_new = false;
        if kind == Kind::User
            && let Some(att) = rec.att
            && let Protocol::Tcp(ip, port) = att.protocol
        {
            let ep = crate::peer::canonical_endpoint(ip, port);
            let tag = self.hash(&ep.to_string());
            let before = self.counts.tcp_reused;
            if self.tcp_breach(tag, ep, token, pos, (att.database, att.id)) {
                ambiguous = true;
                poison_new = self.counts.tcp_reused > before;
            }
            addr = Some(tag);
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
                poisoned: poison_new,
                tainted: in_window || ambiguous,
                kind,
                first_tra: None,
                open_tras: Vec::new(),
                sweep_step: 0,
                own: own && !in_window && !ambiguous,
                trigger_wait: None,
                addr,
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
        self.follow_ups.remove(&key);
        // R29: a binding gone before its transaction's end has no caller.
        self.fail_ext(key);
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
                    addr: None,
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
            // A poisoned binding (a failed external-source binding, R29; a
            // reused client end, review L2 of #402) ends at its own detach,
            // which is ambiguous too; its id stays seen, so a later record
            // of it is ambiguous as well.
            if b.token == token
                && b.poisoned
                && matches!(h.event, Event::DetachDatabase | Event::DropDatabase)
            {
                self.end_binding(key);
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
        // R29 item 2: an external-source binding detached with events still
        // held saw no caller for them: they, and the detach, are ambiguous.
        if b.kind == Kind::External {
            // Review L5 of #402: an external-source binding with no hold
            // (dropped by any path) is never emitted as judged: ambiguous.
            if !self.ext.contains_key(&key) {
                if matches!(h.event, Event::DetachDatabase | Event::DropDatabase) {
                    self.end_binding(key);
                }
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
            let held = self.ext.get(&key).is_some_and(|h| !h.events.is_empty());
            if matches!(h.event, Event::DetachDatabase | Event::DropDatabase) && held {
                self.fail_ext(key);
                self.end_binding(key);
                return Decision::Ambiguous {
                    window: false,
                    at: line!(),
                };
            }
            if h.event == Event::StartTransaction
                && let Some(x) = self.ext.get_mut(&key)
            {
                x.tx_start = Some(pos);
            }
        }
        // R29 item 2: a finish record of code on a user binding.
        if b.kind == Kind::User && !self.ext.is_empty() {
            let code = match &rec.body {
                Body::Routine { .. } => true,
                Body::Statement { text, .. } => analyze_firebird(text).calls_code(),
                _ => false,
            };
            if code {
                self.note_caller(key, rec.tra.map(|t| t.id));
            }
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
                        // R29: where it started (the caller test).
                        if bm.kind == Kind::User {
                            let v = self.tra_pos.entry(key).or_default();
                            if !v.iter().any(|(x, _)| *x == t) {
                                v.push((t, pos));
                                self.tra_pos_entries += 1;
                            }
                        }
                    }
                }
                return self.normal(db, Some(key));
            }
            Event::CommitTransaction | Event::RollbackTransaction => {
                if let Some(t) = tra {
                    if let Some(bm) = self.bindings.get_mut(&key) {
                        bm.open_tras.retain(|x| *x != t);
                    }
                    if let Some(v) = self.tra_pos.get_mut(&key) {
                        let n = v.len();
                        v.retain(|(x, _)| *x != t);
                        self.tra_pos_entries -= n - v.len();
                        if v.is_empty() {
                            self.tra_pos.remove(&key);
                        }
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
            g.last = g.last.max(pos);
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
            last: pos,
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
        let key = Some(self.group_key(&g));
        // R29 item 2: a group of a held external-source binding is held
        // with it.
        if self.ext.contains_key(&g.key) {
            let mut d = g.full.draft();
            if g.blockless() {
                for o in g.bare.draft().objects {
                    if !d.objects.contains(&o) {
                        d.objects.push(o);
                    }
                }
                d.star = true;
                d.always = true;
            }
            let normal = finish(d.clone()).map(|d| self.draft_event(&d, None, db));
            let mut l = d;
            l.star = true;
            l.always = true;
            let loud = self.draft_event(&l, None, db);
            let cur = std::mem::replace(&mut self.cur, key);
            self.hold_ext(g.key, db, normal, loud);
            self.cur = cur;
            if g.blockless() {
                // R25 item 3: its block-less part is ambiguous, with a window
                // and the records held behind it.
                *self.why.entry(1).or_default() += g.bare.count;
                self.counts.ambiguous += g.bare.count;
                self.window_until = Some(Instant::now() + WINDOW);
                if self.hold_since.is_some() {
                    self.release(true, out);
                }
            }
            return;
        }
        if g.full.count > 0
            && let Some(d) = finish(g.full.draft())
        {
            let ev = self.draft_event(&d, None, db);
            self.put(out, db, ev, key);
        }
        if g.blockless() {
            *self.why.entry(1).or_default() += g.bare.count;
            self.counts.ambiguous += g.bare.count;
            self.window_until = Some(Instant::now() + WINDOW);
            let mut d = g.bare.draft();
            d.star = true;
            d.always = true;
            if let Some(d) = finish(d) {
                let ev = self.draft_event(&d, None, db);
                self.put(out, db, ev, key);
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
        self.flush_ext_fail(out);
        // R29 item 2: a record of an external-source binding whose events
        // are held.
        let ext = self.ext_key(rec);
        let tra_end = matches!(
            rec.header.event,
            Event::CommitTransaction | Event::RollbackTransaction
        );
        self.apply_in(decision, ext, rec, pos, now, cat, out);
        if let Some(k) = ext
            && tra_end
        {
            self.ext_tx_end(k, out);
        }
        self.flush_ext_fail(out);
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    fn apply_in(
        &mut self,
        decision: Decision,
        ext: Option<Key>,
        rec: &Record<'_>,
        pos: u64,
        now: Instant,
        cat: &[&dyn Catalog],
        out: &mut Vec<Emitted>,
    ) {
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
                let normal = finish(d.clone()).map(|d| self.draft_event(&d, Some(rec), db));
                if let Some(k) = ext {
                    let loud = self.loud_form(Some(d), rec, db);
                    self.hold_ext(k, db, normal, loud);
                } else if let Some(ev) = normal {
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
                if let Some(k) = ext {
                    let normal = draft.as_ref().map(|d| self.draft_event(d, Some(rec), db));
                    let loud = self.loud_form(draft, rec, db);
                    self.hold_ext(k, db, normal, loud);
                    return;
                }
                let Some(d) = draft else {
                    return;
                };
                let ev = self.draft_event(&d, Some(rec), db);
                self.emit(db, ev, out);
            }
        }
    }

    /// A record's ambiguous form (H1 fix 3): its draft, or a read, with `*`
    /// and the always-reported mark.
    fn loud_form(&self, d: Option<Draft>, rec: &Record<'_>, db: usize) -> MaskedEvent {
        let mut d = d.unwrap_or_else(|| Draft {
            action: Some(databastion_classifiers::masking::EventAction::Read),
            rows: rec.trailer.fetched,
            ..Draft::default()
        });
        d.star = true;
        d.always = true;
        self.draft_event(&d, Some(rec), db)
    }

    /// [`Self::emit`] for an event attributed to `key` (a held one).
    fn emit_keyed(
        &mut self,
        db: usize,
        ev: MaskedEvent,
        key: Option<DKey>,
        out: &mut Vec<Emitted>,
    ) {
        let cur = std::mem::replace(&mut self.cur, key);
        self.emit(db, ev, out);
        self.cur = cur;
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
                    key: self.cur,
                });
                return;
            }
        }
        let key = self.cur;
        self.put(out, db, ev, key);
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
        let tag_key = self.tag_key.as_deref();
        let accept = |a: &crate::conn::FetchAccount, table: Option<&str>, at: SystemTime| {
            // A restored credit's table is a tag: the block's relation it is.
            let table = crate::own::credit_table(table, &block, tag_key);
            crate::own_table::matches(text, table.as_deref(), &block, fetched, a)
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
                // R22 items 5 and 6, R35: the credit's error follow-up, for
                // the next record of this binding.
                match self
                    .ledger
                    .consumed_account((self.file, pos))
                    .as_ref()
                    .and_then(FollowKind::of)
                {
                    Some(kind) => {
                        self.follow_ups.insert(
                            key,
                            FollowUp {
                                kind,
                                consumed: false,
                            },
                        );
                    }
                    None => {
                        self.follow_ups.remove(&key);
                    }
                }
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
