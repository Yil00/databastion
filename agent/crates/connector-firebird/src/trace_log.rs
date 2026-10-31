//! The Firebird system audit trace log: the record assembler and the
//! closed record grammars (ADR-0060 decision 6, "Parsing a hostile text
//! log", and its refinements R1 to R36).
//!
//! Every client that can send SQL writes into this file: statement texts,
//! parameter values, process names, user and role names, user exception
//! messages and the values routines return are written verbatim (8f), so
//! any of them can hold a line of the format. This module is built for
//! that:
//!
//! - **Splitting** ([`Assembler`]): a record starts at a line matching the
//!   closed header grammar ([`header`]) and ends before the next one. The
//!   assembler cannot tell a forged header from a real one; the grammars
//!   below make every split it causes visible ([`Defect`]). A record is
//!   bounded at [`MAX_RECORD`]; a longer one is skipped to its end (its
//!   bytes zeroized) and reported as [`Assembled::Oversized`]. The last
//!   record is held until a following header arrives or the caller sees a
//!   stable end of file ([`Assembler::flush`]).
//! - **Trailer first** (H1 fix 1): each record is read from its end for
//!   its trailer (the per-table block, the performance line of R31,
//!   `<n> records fetched`), which the server writes after everything a
//!   client controls. A trailer shape that does not fit the event, or two
//!   trailers, is [`Defect::Shape`]; a finish record without its trailer
//!   is [`Defect::MissingTrailer`] (H1 fix 2, which opens a split window
//!   under R1 rule 7).
//! - **Kept (I2)**: the header, the attachment, client-hint, transaction
//!   and service facts, the relation names and counters of the per-table
//!   block, `records fetched`, the performance line's numbers, GDS codes,
//!   the routine kind and, borrowed from the record buffer for the
//!   statement-text analysis only, the statement text. **Dropped at
//!   parse**: parameter values (`param<i>` lines, the values routines
//!   return), the plan, BLR and DYN dumps, the client process line (only
//!   whether it names `gbak` is kept), error and warning message texts,
//!   service arguments (only the database argument of a backup, borrowed,
//!   for its resolution), the `Transaction counters:` values. Nothing here
//!   copies a value out of the record buffer, which the caller zeroizes
//!   after handling the record (R4, review L-5); errors carry kinds only.
//!
//! The rules that need more than one record (bindings, runs, windows,
//! folding, credits) are the stream's, not this module's.

use zeroize::Zeroizing;

/// Longest record parsed, in bytes (decision 6): a longer one is not
/// parsed, and is reported loud.
pub(crate) const MAX_RECORD: usize = 1 << 20;
/// Lines of the per-table block kept per record: the relations a statement
/// touched (16 384 is far above any catalog; more is a forged block).
const MAX_BLOCK_ROWS: usize = 16_384;
/// GDS codes kept per `ERROR` / `WARNING` record.
const MAX_CODES: usize = 16;
/// The separator line above a statement text (79 dashes).
const DASHES: &str =
    "-------------------------------------------------------------------------------";
/// The separator line above a plan (`print_plan`, 79 carets).
const CARETS: &str =
    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
/// The right end of the per-table header line: eight 10-character columns.
const BLOCK_COLUMNS: &str =
    "   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge";
/// The two session lines of `TRACE_INIT` / `TRACE_FINI` (R20, 8h: both
/// versions and modes).
const SESSION_LINES: [&str; 2] = ["\tSESSION_1 Firebird Audit", "\t"];

/// A header's event (the closed list of decision 6, with the events the
/// measurements added: `CREATE_DATABASE`, `DROP_DATABASE`, the sweep
/// events, `PRIVILEGES_CHANGE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Event {
    AttachDatabase,
    DetachDatabase,
    CreateDatabase,
    DropDatabase,
    StartTransaction,
    CommitTransaction,
    RollbackTransaction,
    CommitRetaining,
    RollbackRetaining,
    PrepareStatement,
    ExecuteStatementStart,
    ExecuteStatementFinish,
    ExecuteStatementRestart,
    FreeStatement,
    CloseCursor,
    ExecuteProcedureStart,
    ExecuteProcedureFinish,
    ExecuteFunctionStart,
    ExecuteFunctionFinish,
    ExecuteTriggerStart,
    ExecuteTriggerFinish,
    CompileBlr,
    ExecuteBlr,
    ExecuteDyn,
    SetContext,
    AttachService,
    DetachService,
    StartService,
    QueryService,
    TraceInit,
    TraceFini,
    SweepStart,
    SweepProgress,
    SweepFinish,
    SweepFailed,
    PrivilegesChange,
    /// `ERROR AT <location>`.
    Error,
    /// `WARNING AT <location>`.
    Warning,
}

const EVENTS: &[(&str, Event)] = &[
    ("ATTACH_DATABASE", Event::AttachDatabase),
    ("DETACH_DATABASE", Event::DetachDatabase),
    ("CREATE_DATABASE", Event::CreateDatabase),
    ("DROP_DATABASE", Event::DropDatabase),
    ("START_TRANSACTION", Event::StartTransaction),
    ("COMMIT_TRANSACTION", Event::CommitTransaction),
    ("ROLLBACK_TRANSACTION", Event::RollbackTransaction),
    ("COMMIT_RETAINING", Event::CommitRetaining),
    ("ROLLBACK_RETAINING", Event::RollbackRetaining),
    ("PREPARE_STATEMENT", Event::PrepareStatement),
    ("EXECUTE_STATEMENT_START", Event::ExecuteStatementStart),
    ("EXECUTE_STATEMENT_FINISH", Event::ExecuteStatementFinish),
    ("EXECUTE_STATEMENT_RESTART", Event::ExecuteStatementRestart),
    ("FREE_STATEMENT", Event::FreeStatement),
    ("CLOSE_CURSOR", Event::CloseCursor),
    ("EXECUTE_PROCEDURE_START", Event::ExecuteProcedureStart),
    ("EXECUTE_PROCEDURE_FINISH", Event::ExecuteProcedureFinish),
    ("EXECUTE_FUNCTION_START", Event::ExecuteFunctionStart),
    ("EXECUTE_FUNCTION_FINISH", Event::ExecuteFunctionFinish),
    ("EXECUTE_TRIGGER_START", Event::ExecuteTriggerStart),
    ("EXECUTE_TRIGGER_FINISH", Event::ExecuteTriggerFinish),
    ("COMPILE_BLR", Event::CompileBlr),
    ("EXECUTE_BLR", Event::ExecuteBlr),
    ("EXECUTE_DYN", Event::ExecuteDyn),
    ("SET_CONTEXT", Event::SetContext),
    ("ATTACH_SERVICE", Event::AttachService),
    ("DETACH_SERVICE", Event::DetachService),
    ("START_SERVICE", Event::StartService),
    ("QUERY_SERVICE", Event::QueryService),
    ("TRACE_INIT", Event::TraceInit),
    ("TRACE_FINI", Event::TraceFini),
    ("SWEEP_START", Event::SweepStart),
    ("SWEEP_PROGRESS", Event::SweepProgress),
    ("SWEEP_FINISH", Event::SweepFinish),
    ("SWEEP_FAILED", Event::SweepFailed),
    ("PRIVILEGES_CHANGE", Event::PrivilegesChange),
];

impl Event {
    /// The record families, for the grammars.
    fn family(self) -> Family {
        use Event as E;
        match self {
            E::TraceInit | E::TraceFini => Family::Session,
            E::AttachDatabase | E::DetachDatabase | E::CreateDatabase | E::DropDatabase => {
                Family::Attachment
            }
            E::StartTransaction
            | E::CommitTransaction
            | E::RollbackTransaction
            | E::CommitRetaining
            | E::RollbackRetaining => Family::Transaction,
            E::ExecuteStatementFinish => Family::StatementFinish,
            E::PrepareStatement
            | E::ExecuteStatementStart
            | E::ExecuteStatementRestart
            | E::FreeStatement
            | E::CloseCursor
            | E::ExecuteDyn
            | E::SetContext
            | E::PrivilegesChange => Family::NoTrailer,
            E::ExecuteProcedureStart | E::ExecuteFunctionStart | E::ExecuteTriggerStart => {
                Family::NoTrailer
            }
            E::ExecuteProcedureFinish => Family::Routine(RoutineKind::Procedure),
            E::ExecuteFunctionFinish => Family::Routine(RoutineKind::Function),
            E::ExecuteTriggerFinish => Family::Routine(RoutineKind::Trigger),
            E::CompileBlr | E::ExecuteBlr => Family::Blr,
            E::AttachService | E::DetachService | E::StartService | E::QueryService => {
                Family::Service
            }
            E::SweepStart | E::SweepProgress | E::SweepFinish | E::SweepFailed => Family::Sweep,
            E::Error | E::Warning => Family::Error,
        }
    }

    /// A finish event whose trailer the server always writes (H1 fix 2).
    pub(crate) fn is_finish(self) -> bool {
        matches!(
            self.family(),
            Family::StatementFinish | Family::Routine(_) | Family::Blr
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Session,
    Attachment,
    Transaction,
    StatementFinish,
    NoTrailer,
    Routine(RoutineKind),
    Blr,
    Service,
    Sweep,
    Error,
}

/// `FAILED` / `UNAUTHORIZED` forms of a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Outcome {
    Ok,
    Failed,
    Unauthorized,
}

/// Where an `ERROR` / `WARNING` record says the error was raised: a closed
/// list (R22 item 7, R35), anything else [`ErrorAt::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorAt {
    FetchNext,
    OpenCursor,
    StatementExecute,
    AttachDatabase,
    Other,
}

/// The server's local time of a header (decision 6: converted with the
/// offset learned from the read-back probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LogTime {
    pub(crate) year: u16,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) minute: u8,
    pub(crate) second: u8,
    /// Tenths of a millisecond (four digits).
    pub(crate) frac: u16,
}

/// A record header: `<time> (<pid>:0x<address>) <event>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) time: LogTime,
    pub(crate) pid: u32,
    /// The token's address part (a heap address, R1: not a secret).
    pub(crate) address: u64,
    pub(crate) event: Event,
    pub(crate) outcome: Outcome,
    /// `ERROR AT` / `WARNING AT` only.
    pub(crate) at: Option<ErrorAt>,
}

impl Header {
    /// The token `(pid, address)` of R1.
    // Used by the stream (bindings, folding), the next part of lot 3.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn token(&self) -> (u32, u64) {
        (self.pid, self.address)
    }
}

fn digits<const N: usize>(s: &[u8]) -> Option<u32> {
    if s.len() != N || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.iter().try_fold(0u32, |a, d| {
        a.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

/// Parses a header line (the closed grammar of decision 6), or `None`.
pub(crate) fn header(line: &[u8]) -> Option<Header> {
    // 2026-10-30T15:22:38.3650 (24:0x7fdc1dd7adc0) EVENT
    if line.len() < 26 || line.len() > 256 {
        return None;
    }
    let (t, rest) = line.split_at(24);
    let sep = |i: usize, c: u8| t.get(i) == Some(&c);
    if !(sep(4, b'-') && sep(7, b'-') && sep(10, b'T') && sep(13, b':') && sep(16, b':'))
        || !sep(19, b'.')
    {
        return None;
    }
    let time = LogTime {
        year: u16::try_from(digits::<4>(&t[0..4])?).ok()?,
        month: u8::try_from(digits::<2>(&t[5..7])?).ok()?,
        day: u8::try_from(digits::<2>(&t[8..10])?).ok()?,
        hour: u8::try_from(digits::<2>(&t[11..13])?).ok()?,
        minute: u8::try_from(digits::<2>(&t[14..16])?).ok()?,
        second: u8::try_from(digits::<2>(&t[17..19])?).ok()?,
        frac: u16::try_from(digits::<4>(&t[20..24])?).ok()?,
    };
    if !(1..=12).contains(&time.month)
        || !(1..=31).contains(&time.day)
        || time.hour > 23
        || time.minute > 59
        || time.second > 60
    {
        return None;
    }
    let rest = rest.strip_prefix(b" (")?;
    let close = rest.iter().position(|b| *b == b')')?;
    let (token, rest) = rest.split_at(close);
    let colon = token.iter().position(|b| *b == b':')?;
    let (pid, addr) = token.split_at(colon);
    if pid.is_empty() || pid.len() > 10 || !pid.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let pid: u32 = std::str::from_utf8(pid).ok()?.parse().ok()?;
    let addr = addr.strip_prefix(b":0x")?;
    if addr.is_empty()
        || addr.len() > 16
        || !addr
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let address = u64::from_str_radix(std::str::from_utf8(addr).ok()?, 16).ok()?;
    let ev = std::str::from_utf8(rest.strip_prefix(b") ")?).ok()?;
    let (event, outcome, at) = event(ev)?;
    Some(Header {
        time,
        pid,
        address,
        event,
        outcome,
        at,
    })
}

fn event(s: &str) -> Option<(Event, Outcome, Option<ErrorAt>)> {
    for (prefix, e) in [("ERROR AT ", Event::Error), ("WARNING AT ", Event::Warning)] {
        if let Some(loc) = s.strip_prefix(prefix) {
            let ok = !loc.is_empty()
                && loc.len() <= 64
                && loc
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':');
            if !ok {
                return None;
            }
            let at = match loc {
                "JResultSet::fetchNext" => ErrorAt::FetchNext,
                "JStatement::openCursor" => ErrorAt::OpenCursor,
                "JStatement::execute" => ErrorAt::StatementExecute,
                "JProvider::attachDatabase" => ErrorAt::AttachDatabase,
                _ => ErrorAt::Other,
            };
            return Some((e, Outcome::Ok, Some(at)));
        }
    }
    let (outcome, name) = if let Some(n) = s.strip_prefix("FAILED ") {
        (Outcome::Failed, n)
    } else if let Some(n) = s.strip_prefix("UNAUTHORIZED ") {
        (Outcome::Unauthorized, n)
    } else {
        (Outcome::Ok, s)
    };
    EVENTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, e)| (*e, outcome, None))
}

/// Whether a line has the header grammar (an injection marker inside a
/// record's client-controlled parts).
pub(crate) fn is_header(line: &[u8]) -> bool {
    header(line).is_some()
}

// ---------------------------------------------------------------------------
// The assembler.

/// What the assembler hands over.
pub(crate) enum Assembled {
    /// One record: its header line first, then its body lines. Zeroized
    /// when dropped.
    Record(Zeroizing<Vec<u8>>),
    /// A record longer than [`MAX_RECORD`]: skipped, its bytes zeroized,
    /// reported loud (decision 6). Its header, when it parsed.
    Oversized(Option<Header>),
    /// Bytes before the first header of the read (a start inside a record,
    /// or garbage): dropped, counted by the caller.
    Orphan,
}

/// Groups lines into records at header lines (decision 6, L5).
pub(crate) struct Assembler {
    /// The record in progress, reserved once at the bound so that no
    /// reallocation leaves an unzeroized copy (R4, review L-5).
    buf: Zeroizing<Vec<u8>>,
    /// The header of the record in progress, when one started it.
    head: Option<Header>,
    /// The record in progress passed the bound.
    oversized: bool,
    /// Lines before the first header were seen.
    orphan: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub(crate) fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(MAX_RECORD)),
            head: None,
            oversized: false,
            orphan: false,
        }
    }

    /// Whether a record is held (the caller holds it at end of file until
    /// a stable end, decision 6, review L5).
    pub(crate) fn holding(&self) -> bool {
        self.head.is_some() || self.orphan
    }

    /// One line, without its newline. A header line ends the record in
    /// progress, which is returned.
    pub(crate) fn push_line(&mut self, line: &[u8]) -> Option<Assembled> {
        if let Some(h) = header(line) {
            let done = self.take();
            self.head = Some(h);
            self.append(line);
            return done;
        }
        if self.head.is_none() {
            self.orphan = true;
            return None;
        }
        self.append(b"\n");
        self.append(line);
        None
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.oversized {
            return;
        }
        if self.buf.len() + bytes.len() > MAX_RECORD {
            self.oversized = true;
            // Only the written bytes (the bytes past them were zeroized
            // when last cleared): `Vec::zeroize` would clear the whole
            // 1 MiB reservation at every record.
            zeroize::Zeroize::zeroize(self.buf.as_mut_slice());
            self.buf.clear();
            return;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The record in progress, ended at a stable end of file (or by the
    /// next header).
    pub(crate) fn flush(&mut self) -> Option<Assembled> {
        self.take()
    }

    fn take(&mut self) -> Option<Assembled> {
        if std::mem::take(&mut self.orphan) && self.head.is_none() {
            return Some(Assembled::Orphan);
        }
        let head = self.head.take()?;
        if std::mem::take(&mut self.oversized) {
            return Some(Assembled::Oversized(Some(head)));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(self.buf.len()));
        out.extend_from_slice(&self.buf);
        zeroize::Zeroize::zeroize(self.buf.as_mut_slice());
        self.buf.clear();
        Some(Assembled::Record(out))
    }
}

// ---------------------------------------------------------------------------
// Lines of a record.

/// The attachment line's protocol field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// `TCPv4:<address>/<port>` or `TCPv6:<address>/<port>`.
    Tcp(std::net::IpAddr, u16),
    /// `<internal>`.
    Internal,
}

/// `\t<database> (ATT_<n>, <user>[:<role>], <charset>, <protocol>)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttLine<'a> {
    /// The printed database name (a path or an alias, R2): mapped to a
    /// declared database, then discarded.
    pub(crate) database: &'a str,
    pub(crate) id: u64,
    pub(crate) user: &'a str,
    /// `None` when the line has no `:role` part (the Garbage Collector).
    pub(crate) role: Option<&'a str>,
    pub(crate) charset: &'a str,
    pub(crate) protocol: Protocol,
}

/// The client process line: only whether it names `gbak` is kept (R27
/// item 1 (b)), and that one was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientLine {
    pub(crate) gbak: bool,
}

/// `\t\t(TRA_<n>, <flags>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraLine {
    pub(crate) id: u64,
    pub(crate) read_only: bool,
    /// The exact flags of the Garbage Collector's and the sweeper's
    /// transactions: `READ_COMMITTED | REC_VERSION | WAIT | READ_ONLY`
    /// (R16, R17).
    pub(crate) internal_flags: bool,
}

/// The per-table counters of one relation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) natural: u64,
    pub(crate) index: u64,
    pub(crate) update: u64,
    pub(crate) insert: u64,
    pub(crate) delete: u64,
    pub(crate) backout: u64,
    pub(crate) purge: u64,
    pub(crate) expunge: u64,
}

impl Counters {
    /// The counter-wise maximum (R4, R25: folding by maximum).
    // Used by the stream (bindings, folding), the next part of lot 3.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn max(self, o: Self) -> Self {
        Self {
            natural: self.natural.max(o.natural),
            index: self.index.max(o.index),
            update: self.update.max(o.update),
            insert: self.insert.max(o.insert),
            delete: self.delete.max(o.delete),
            backout: self.backout.max(o.backout),
            purge: self.purge.max(o.purge),
            expunge: self.expunge.max(o.expunge),
        }
    }

    /// Whether the relation was written (an update, insert or delete).
    pub(crate) fn wrote(&self) -> bool {
        self.update > 0 || self.insert > 0 || self.delete > 0
    }
}

/// The performance line (R31): `<ms> ms` and the closed counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Perf {
    pub(crate) ms: u64,
    pub(crate) reads: Option<u64>,
    pub(crate) writes: Option<u64>,
    pub(crate) fetches: Option<u64>,
    pub(crate) marks: Option<u64>,
}

/// The trailer read from a record's end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Trailer<'a> {
    pub(crate) fetched: Option<u64>,
    pub(crate) perf: Option<Perf>,
    /// The relations of the per-table block, in the order written.
    pub(crate) block: Option<Vec<(&'a str, Counters)>>,
}

impl Trailer<'_> {
    fn is_empty(&self) -> bool {
        self.fetched.is_none() && self.perf.is_none() && self.block.is_none()
    }
}

/// The routine kinds of finish records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutineKind {
    Procedure,
    Function,
    Trigger,
}

/// A trigger name line's kind (R14 item 2, R15, R26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TriggerKind {
    /// A row trigger (`BEFORE INSERT` and the like) on a relation.
    Row,
    /// `ON CONNECT`.
    OnConnect,
    /// `ON DISCONNECT`.
    OnDisconnect,
    /// `ON TRANSACTION_START`.
    OnTransactionStart,
    /// `ON TRANSACTION_COMMIT`.
    OnTransactionCommit,
    /// `ON TRANSACTION_ROLLBACK`.
    OnTransactionRollback,
    /// `BEFORE DDL` / `AFTER DDL` (R26).
    Ddl,
}

impl TriggerKind {
    /// A database trigger of R15 (never folded).
    // Used by the stream (bindings, folding), the next part of lot 3.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn is_database_trigger(self) -> bool {
        !matches!(self, Self::Row | Self::Ddl)
    }
}

/// The closed list of trigger kinds in name lines.
fn trigger_kind(s: &str) -> Option<TriggerKind> {
    use TriggerKind as K;
    Some(match s {
        "ON CONNECT" => K::OnConnect,
        "ON DISCONNECT" => K::OnDisconnect,
        "ON TRANSACTION_START" => K::OnTransactionStart,
        "ON TRANSACTION_COMMIT" => K::OnTransactionCommit,
        "ON TRANSACTION_ROLLBACK" => K::OnTransactionRollback,
        "BEFORE DDL" | "AFTER DDL" => K::Ddl,
        _ => {
            let (when, what) = s.split_once(' ')?;
            if !matches!(when, "BEFORE" | "AFTER") {
                return None;
            }
            // Multi-action triggers: `INSERT OR UPDATE OR DELETE`.
            if what
                .split(" OR ")
                .all(|w| matches!(w, "INSERT" | "UPDATE" | "DELETE"))
            {
                K::Row
            } else {
                return None;
            }
        }
    })
}

/// Which grammar of a name line (R14 item 2): the major series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Series {
    /// 4.0.x from 4.0.7: trigger lines are a tab, `<name> [FOR <rel>]
    /// (<kind>)` and a trailing space.
    V4,
    /// 5.0.x from 5.0.4: `Trigger <name> [FOR <rel>] (<kind>):`.
    #[default]
    V5,
}

/// A parsed routine name line: the routine name only as R4's folded object
/// name, never an object of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoutineName<'a> {
    pub(crate) name: &'a str,
    pub(crate) trigger: Option<TriggerKind>,
}

fn routine_name(line: &str, kind: RoutineKind, series: Series) -> Option<RoutineName<'_>> {
    match kind {
        RoutineKind::Procedure | RoutineKind::Function => {
            let prefix = if kind == RoutineKind::Procedure {
                "Procedure "
            } else {
                "Function "
            };
            let name = line.strip_prefix(prefix)?.strip_suffix(':')?;
            (!name.is_empty()).then_some(RoutineName {
                name,
                trigger: None,
            })
        }
        RoutineKind::Trigger => {
            // Right-anchored (review N4): the end, the kind, an optional
            // ` FOR <relation>`, the name what remains.
            let body = match series {
                Series::V5 => line.strip_prefix("Trigger ")?.strip_suffix(':')?,
                Series::V4 => line.strip_prefix('\t')?.strip_suffix(' ')?,
            };
            let body = body.strip_suffix(')')?;
            let open = body.rfind(" (")?;
            let kind = trigger_kind(&body[open + 2..])?;
            let head = &body[..open];
            let name = match head.rfind(" FOR ") {
                Some(i) if matches!(kind, TriggerKind::Row | TriggerKind::Ddl) => &head[..i],
                _ if kind == TriggerKind::Row => return None,
                _ => head,
            };
            (!name.is_empty()).then_some(RoutineName {
                name,
                trigger: Some(kind),
            })
        }
    }
}

fn att_line(line: &str) -> Option<AttLine<'_>> {
    let line = line.strip_prefix('\t')?;
    if line.starts_with('\t') {
        return None;
    }
    let inner = line.strip_suffix(')')?;
    let open = inner.rfind(" (ATT_")?;
    let database = &inner[..open];
    let fields = &inner[open + 6..];
    let mut parts = fields.rsplitn(3, ", ");
    let protocol = parts.next()?;
    let charset = parts.next()?;
    let rest = parts.next()?;
    let (id, userrole) = rest.split_once(", ")?;
    if database.is_empty() || database.len() > 4096 {
        return None;
    }
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id: u64 = id.parse().ok()?;
    if userrole.contains([',', '(', ')']) || userrole.is_empty() {
        return None;
    }
    let (user, role) = match userrole.split_once(':') {
        Some((u, r)) if !r.contains(':') && !u.is_empty() && !r.is_empty() => (u, Some(r)),
        Some(_) => return None,
        None => (userrole, None),
    };
    if charset.is_empty()
        || !charset
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some(AttLine {
        database,
        id,
        user,
        role,
        charset,
        protocol: protocol_field(protocol)?,
    })
}

fn protocol_field(s: &str) -> Option<Protocol> {
    if s == "<internal>" {
        return Some(Protocol::Internal);
    }
    let rest = s
        .strip_prefix("TCPv4:")
        .or_else(|| s.strip_prefix("TCPv6:"))?;
    let (addr, port) = rest.rsplit_once('/')?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ip: std::net::IpAddr = addr.parse().ok()?;
    if s.starts_with("TCPv4:") != ip.is_ipv4() {
        return None;
    }
    Some(Protocol::Tcp(ip, port.parse().ok()?))
}

/// A client line: one tab, then `<process>:<pid>` (client-set, R27 item 1
/// (b)); only whether the last path component is `gbak` is kept.
fn client_line(line: &str) -> Option<ClientLine> {
    let rest = line.strip_prefix('\t')?;
    if rest.is_empty() || rest.starts_with('\t') {
        return None;
    }
    let (process, pid) = rest.rsplit_once(':')?;
    if pid.is_empty() || pid.len() > 10 || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let last = process.rsplit(['/', '\\']).next().unwrap_or(process);
    Some(ClientLine {
        gbak: last == "gbak" || last == "gbak.exe",
    })
}

const TRA_FLAGS: &[&str] = &[
    "CONCURRENCY",
    "CONSISTENCY",
    "READ_COMMITTED",
    "REC_VERSION",
    "NO_REC_VERSION",
    "READ_CONSISTENCY",
    "WAIT",
    "NOWAIT",
    "READ_ONLY",
    "READ_WRITE",
];

fn tra_line(line: &str) -> Option<TraLine> {
    let inner = line.strip_prefix("\t\t(TRA_")?.strip_suffix(')')?;
    let (id, flags) = inner.split_once(", ")?;
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut read_only = false;
    for f in flags.split(" | ") {
        let known = TRA_FLAGS.contains(&f)
            || f.strip_prefix("LOCK_TIMEOUT ").is_some_and(|n| {
                !n.is_empty() && n.len() <= 10 && n.bytes().all(|b| b.is_ascii_digit())
            });
        if !known {
            return None;
        }
        read_only |= f == "READ_ONLY";
    }
    Some(TraLine {
        id: id.parse().ok()?,
        read_only,
        internal_flags: flags == "READ_COMMITTED | REC_VERSION | WAIT | READ_ONLY",
    })
}

fn decimal(s: &str, max: usize) -> Option<u64> {
    if s.is_empty() || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The performance line of R31: the time right-aligned in seven columns,
/// ` ms`, then `read(s)`, `write(s)`, `fetch(es)`, `mark(s)`, each at most
/// once and in that order.
pub(crate) fn perf_line(line: &str) -> Option<Perf> {
    let (time, rest) = line.split_once(" ms")?;
    let n = time.trim_start_matches(' ');
    let spaces = time.len() - n.len();
    if (n.len() < 7 && spaces + n.len() != 7) || (n.len() >= 7 && spaces != 0) {
        return None;
    }
    let mut p = Perf {
        ms: decimal(n, 20)?,
        ..Perf::default()
    };
    let mut rest = rest;
    let mut slot = 0usize;
    while !rest.is_empty() {
        let item = rest.strip_prefix(", ")?;
        let end = item.find(", ").unwrap_or(item.len());
        let (field, tail) = item.split_at(end);
        let (num, name) = field.split_once(' ')?;
        let v = decimal(num, 20)?;
        let at = ["read(s)", "write(s)", "fetch(es)", "mark(s)"]
            .iter()
            .position(|n| *n == name)?;
        if at < slot {
            return None;
        }
        slot = at + 1;
        match at {
            0 => p.reads = Some(v),
            1 => p.writes = Some(v),
            2 => p.fetches = Some(v),
            _ => p.marks = Some(v),
        }
        rest = tail;
    }
    Some(p)
}

/// `<n> records fetched`.
pub(crate) fn fetched_line(line: &str) -> Option<u64> {
    decimal(line.strip_suffix(" records fetched")?, 20)
}

fn block_header(line: &str) -> Option<usize> {
    let name = line.strip_suffix(BLOCK_COLUMNS)?;
    let pad = name.strip_prefix("Table")?;
    (pad.bytes().all(|b| b == b' ')).then_some(line.len())
}

fn block_row(line: &str, width: usize) -> Option<(&str, Counters)> {
    if line.len() != width || width < 81 || !line.is_char_boundary(width - 80) {
        return None;
    }
    let (name, cols) = line.split_at(width - 80);
    // The counters are ASCII digits and spaces (review of part 1, M1).
    if !cols.is_ascii() {
        return None;
    }
    let name = name.trim_end_matches(' ');
    if name.is_empty() {
        return None;
    }
    let mut v = [0u64; 8];
    for (i, slot) in v.iter_mut().enumerate() {
        let f = &cols[i * 10..i * 10 + 10];
        let n = f.trim_start_matches(' ');
        *slot = if n.is_empty() { 0 } else { decimal(n, 10)? };
    }
    Some((
        name,
        Counters {
            natural: v[0],
            index: v[1],
            update: v[2],
            insert: v[3],
            delete: v[4],
            backout: v[5],
            purge: v[6],
            expunge: v[7],
        },
    ))
}

/// Whether a line has the shape of a trailer line or of a separator the
/// format writes (H1, "Other ambiguity"): inside a client-controlled area
/// it marks a split or a second trailer.
fn trailer_shaped(line: &str) -> bool {
    perf_line(line).is_some()
        || fetched_line(line).is_some()
        || block_header(line).is_some()
        || (!line.is_empty() && line.bytes().all(|b| b == b'*'))
        || line == DASHES
        || line == CARETS
        || is_header(line.as_bytes())
}

/// Reads the trailer from the end of `lines` (blank lines at the end
/// removed by the caller); returns it and the lines above it.
fn trailer<'a, 'b>(mut lines: &'b [&'a str]) -> (Trailer<'a>, &'b [&'a str]) {
    let mut t = Trailer::default();
    // The per-table block: its rows from the bottom, then the asterisk
    // line and the header, then one blank line above it.
    let mut rows = 0usize;
    while rows < lines.len() && rows <= MAX_BLOCK_ROWS {
        let l = lines[lines.len() - 1 - rows];
        if l.bytes().all(|b| b == b'*') && !l.is_empty() {
            break;
        }
        rows += 1;
    }
    if (1..=MAX_BLOCK_ROWS).contains(&rows) && lines.len() >= rows + 2 {
        let stars = lines[lines.len() - 1 - rows];
        let head = lines[lines.len() - 2 - rows];
        if let Some(width) = block_header(head)
            && stars.len() == width
        {
            let mut out = Vec::with_capacity(rows);
            let body = &lines[lines.len() - rows..];
            let parsed: Option<()> = body.iter().try_for_each(|l| {
                out.push(block_row(l, width)?);
                Some(())
            });
            if parsed.is_some() {
                t.block = Some(out);
                lines = &lines[..lines.len() - rows - 2];
                if lines.last() == Some(&"") {
                    lines = &lines[..lines.len() - 1];
                }
            }
        }
    }
    if let Some(p) = lines.last().and_then(|l| perf_line(l)) {
        t.perf = Some(p);
        lines = &lines[..lines.len() - 1];
        if let Some(n) = lines.last().and_then(|l| fetched_line(l)) {
            t.fetched = Some(n);
            lines = &lines[..lines.len() - 1];
        }
    }
    (t, lines)
}

// ---------------------------------------------------------------------------
// Records.

/// Why a record is not well formed on its own (the stream adds the
/// multi-record reasons of R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defect {
    /// A finish record with no trailer (H1 fix 2): a split window opens
    /// at it (R1 rule 7).
    MissingTrailer,
    /// A trailer that does not fit the event, two trailers, or a body line
    /// outside the event's grammar (H1 fix 1, "Other ambiguity").
    Shape,
    /// The attachment, transaction or service line does not parse.
    ContextLine,
    /// A header-shaped or trailer-shaped line in a client-controlled area
    /// (H1 fix 6).
    Injected,
    /// The statement text was cut at `max_sql_length` (decision 6).
    CutText,
    /// A body that is not valid UTF-8 (the server writes text).
    Encoding,
}

/// A parsed record. Borrows the record buffer: nothing outlives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record<'a> {
    pub(crate) header: Header,
    pub(crate) att: Option<AttLine<'a>>,
    pub(crate) client: Option<ClientLine>,
    pub(crate) tra: Option<TraLine>,
    pub(crate) body: Body<'a>,
    pub(crate) trailer: Trailer<'a>,
    pub(crate) defect: Option<Defect>,
}

/// The event-specific part of a record.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Body<'a> {
    /// `TRACE_INIT` / `TRACE_FINI` with the fixed session lines.
    Session,
    /// Attachment and transaction events: nothing beyond the context
    /// lines and the trailer.
    Context,
    /// A statement finish.
    Statement {
        /// `Statement <n>:` (absent for the session-management form,
        /// R20).
        id: Option<u64>,
        /// The text, borrowed for the analysis only (I2: never kept).
        text: &'a str,
        /// `param<i>` lines (or a plan) followed the text: dropped.
        params: bool,
    },
    /// A routine finish (R14).
    Routine {
        name: RoutineName<'a>,
        kind: RoutineKind,
        /// A function's `returns:` line was found.
        returns: bool,
    },
    /// `COMPILE_BLR` / `EXECUTE_BLR`: the BLR area dropped (R33 item 5).
    Blr,
    /// An error or warning: the GDS codes only (decision 6).
    Error {
        codes: Vec<u32>,
        /// Lines other than the GDS code lines (message continuations).
        other_lines: usize,
    },
    /// A service record.
    Service {
        user: &'a str,
        protocol: Protocol,
        /// `START_SERVICE`: the service name from the closed list.
        name: Option<ServiceName>,
        /// The database argument of a backup (`-b <database>`), borrowed
        /// for its resolution under R2 (R27 item 1 (a)), then discarded.
        database: Option<&'a str>,
    },
    /// A sweep record (R17): the `Transaction counters:` list checked.
    Sweep { counters: bool },
    /// An event this module has no grammar for (start and prepare events):
    /// no trailer expected, no object.
    Other,
}

/// The closed list of service names kept (decision 6: "only the service
/// name from a closed list").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceName {
    BackupDatabase,
    IncrementalBackupDatabase,
    RestoreDatabase,
    IncrementalRestoreDatabase,
    StartTraceSession,
    ListTraceSessions,
    UserManagement,
    Other,
}

fn service_name(s: &str) -> ServiceName {
    use ServiceName as S;
    match s {
        "Backup Database" => S::BackupDatabase,
        "Incremental Backup Database" => S::IncrementalBackupDatabase,
        "Restore Database" => S::RestoreDatabase,
        "Incremental Restore Database" => S::IncrementalRestoreDatabase,
        "Start Trace Session" => S::StartTraceSession,
        "List Trace Sessions" => S::ListTraceSessions,
        "Add User"
        | "Modify User"
        | "Delete User"
        | "Display User"
        | "Display User Adm"
        | "Set Domain Admins Mapping"
        | "Drop Domain Admins Mapping" => S::UserManagement,
        _ => S::Other,
    }
}

/// `\tservice_mgr, (Service 0x<hex>, <user>, <protocol>, <client>)`.
fn service_line(line: &str) -> Option<(&str, Protocol)> {
    let inner = line
        .strip_prefix("\tservice_mgr, (Service 0x")?
        .strip_suffix(')')?;
    let (handle, rest) = inner.split_once(", ")?;
    if handle.is_empty() || handle.len() > 16 || !handle.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (user, rest) = rest.split_once(", ")?;
    if user.is_empty() || user.contains(['(', ')', ':']) {
        return None;
    }
    let (protocol, _client) = rest.split_once(", ")?;
    Some((user, protocol_field(protocol)?))
}

/// Parse options from the trace configuration.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ParseOptions {
    /// The effective `max_sql_length` (a text at it ending in `...` is
    /// cut).
    pub(crate) max_sql_length: Option<usize>,
    /// The name-line grammar.
    pub(crate) series: Series,
}

/// Parses one assembled record. `raw` is the record's bytes as the
/// assembler returned them (header line first).
pub(crate) fn parse(raw: &[u8], opts: ParseOptions) -> Option<Record<'_>> {
    let (first, body) = match raw.iter().position(|b| *b == b'\n') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (raw, &raw[raw.len()..]),
    };
    let header = header(first)?;
    let mut rec = Record {
        header,
        att: None,
        client: None,
        tra: None,
        body: Body::Other,
        trailer: Trailer::default(),
        defect: None,
    };
    // Trailer first, from the raw bytes (H1 fix 1; review of part 1, H1):
    // the server writes the trailer after everything a client controls,
    // so it is read before any line a client could have spoiled (a text
    // that is not UTF-8, an attachment or client line that does not
    // parse). Each trailer line is decoded on its own; the defects found
    // later keep it, so an ambiguous record keeps its real counters and
    // row count.
    rec.trailer = raw_trailer(body);
    let Ok(body) = std::str::from_utf8(body) else {
        rec.defect = Some(Defect::Encoding);
        // Round 4 M-1b: the server writes the attachment and transaction
        // lines before any client text; each is decoded on its own, so the
        // record's binding and transaction are known (its DDL transaction
        // tracked under them) even when a later line is not UTF-8.
        raw_context(&mut rec, body);
        return Some(rec);
    };
    // The record ends with blank lines before the next header.
    let all: Vec<&str> = if body.is_empty() {
        Vec::new()
    } else {
        body.split('\n').collect()
    };
    let mut end = all.len();
    while end > 0 && all[end - 1].is_empty() {
        end -= 1;
    }
    let lines = &all[..end];
    let defect = body_of(&mut rec, body, lines, opts).err();
    rec.defect = defect;
    Some(rec)
}

/// The trailer of a record body read from its end, line by line (each
/// line decoded on its own; the first line from the end that is not
/// UTF-8 ends the trailer area).
fn raw_trailer(body: &[u8]) -> Trailer<'_> {
    let mut lines: Vec<&str> = Vec::new();
    let mut parts: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    while parts.last().is_some_and(|l| l.is_empty()) {
        parts.pop();
    }
    // Enough lines for the largest block, the performance line and
    // `records fetched`.
    for l in parts.iter().rev().take(MAX_BLOCK_ROWS + 8) {
        match std::str::from_utf8(l) {
            Ok(l) => lines.push(l),
            Err(_) => break,
        }
    }
    lines.reverse();
    trailer(&lines).0
}

/// The context lines of a record whose body is not UTF-8 (round 4 M-1b):
/// the attachment line, an optional client line (skipped unread) and an
/// optional transaction line, each decoded on its own. Session and service
/// records have none.
fn raw_context<'a>(rec: &mut Record<'a>, body: &'a [u8]) {
    if matches!(rec.header.event.family(), Family::Session | Family::Service) {
        return;
    }
    let mut lines = body.split(|b| *b == b'\n');
    let Some(att) = lines
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(att_line)
    else {
        return;
    };
    rec.att = Some(att);
    let mut next = lines.next();
    if let Some(l) = next
        && l.starts_with(b"\t")
        && !l.starts_with(b"\t\t")
    {
        next = lines.next();
    }
    if let Some(l) = next
        && l.starts_with(b"\t\t")
    {
        rec.tra = std::str::from_utf8(l).ok().and_then(tra_line);
    }
}

type Parsed<T> = Result<T, Defect>;

fn body_of<'a>(
    rec: &mut Record<'a>,
    parent: &'a str,
    lines: &[&'a str],
    opts: ParseOptions,
) -> Parsed<()> {
    let family = rec.header.event.family();
    if family == Family::Session {
        return if lines == SESSION_LINES {
            rec.body = Body::Session;
            Ok(())
        } else {
            Err(Defect::Shape)
        };
    }
    if family == Family::Service {
        return service_body(rec, lines);
    }
    // Context lines: the attachment line, an optional client line, an
    // optional transaction line.
    let mut i = 0usize;
    let first = lines.first().ok_or(Defect::Shape)?;
    rec.att = Some(att_line(first).ok_or(Defect::ContextLine)?);
    i += 1;
    if let Some(l) = lines.get(i)
        && l.starts_with('\t')
        && !l.starts_with("\t\t")
    {
        rec.client = Some(client_line(l).ok_or(Defect::Injected)?);
        i += 1;
    }
    if let Some(l) = lines.get(i)
        && l.starts_with("\t\t")
    {
        rec.tra = Some(tra_line(l).ok_or(Defect::ContextLine)?);
        i += 1;
    }
    let rest = &lines[i..];
    let (t, above) = trailer(rest);
    rec.trailer = t;
    match family {
        Family::Attachment => {
            no_trailer(&rec.trailer)?;
            only_blank(above)?;
            rec.body = Body::Context;
            Ok(())
        }
        Family::Transaction => {
            // R20 and R24 item 1: a performance line, then a block or none,
            // on transaction-end records; nothing on a start.
            let end = !matches!(rec.header.event, Event::StartTransaction);
            if rec.trailer.fetched.is_some() {
                return Err(Defect::Shape);
            }
            if end && rec.trailer.perf.is_none() {
                return Err(Defect::Shape);
            }
            if !end && !rec.trailer.is_empty() {
                return Err(Defect::Shape);
            }
            if rec.tra.is_none() {
                return Err(Defect::ContextLine);
            }
            only_blank(above)?;
            rec.body = Body::Context;
            Ok(())
        }
        Family::NoTrailer => {
            no_trailer(&rec.trailer)?;
            if above.iter().any(|l| trailer_shaped(l)) {
                return Err(Defect::Injected);
            }
            rec.body = Body::Other;
            Ok(())
        }
        Family::StatementFinish => statement_body(rec, parent, above, opts),
        Family::Routine(kind) => routine_body(rec, above, kind, opts.series),
        Family::Blr => {
            if rec.trailer.fetched.is_some() {
                return Err(Defect::Shape);
            }
            if rec.trailer.perf.is_none() {
                return Err(Defect::MissingTrailer);
            }
            if rec.header.event == Event::CompileBlr && rec.trailer.block.is_some() {
                return Err(Defect::Shape);
            }
            // `Statement <n>:` and the separator, as on statement
            // records; then the BLR area (and a `print_blr` dump), dropped
            // unread (R33 item 5), which may not hold a trailer or a
            // header.
            let mut area = above;
            if area.first() == Some(&"") {
                area = &area[1..];
            }
            if area.first().is_some_and(|l| {
                l.strip_prefix("Statement ")
                    .and_then(|r| r.strip_suffix(':'))
                    .is_some_and(|n| decimal(n, 20).is_some())
            }) {
                area = &area[1..];
            }
            if area.first() == Some(&DASHES) {
                area = &area[1..];
            }
            if area.iter().any(|l| trailer_shaped(l)) {
                return Err(Defect::Injected);
            }
            rec.body = Body::Blr;
            Ok(())
        }
        Family::Error => {
            no_trailer(&rec.trailer)?;
            let mut codes = Vec::new();
            let mut other = 0usize;
            for l in above {
                if trailer_shaped(l) {
                    return Err(Defect::Injected);
                }
                match l.split_once(" : ").and_then(|(c, _)| decimal(c, 9)) {
                    Some(c) if l.as_bytes().get(9) == Some(&b' ') && codes.len() < MAX_CODES => {
                        codes.push(u32::try_from(c).map_err(|_| Defect::Shape)?);
                    }
                    _ => other += 1,
                }
            }
            rec.body = Body::Error {
                codes,
                other_lines: other,
            };
            Ok(())
        }
        Family::Sweep => {
            let finish = matches!(rec.header.event, Event::SweepProgress | Event::SweepFinish);
            if rec.trailer.fetched.is_some() {
                return Err(Defect::Shape);
            }
            if finish && rec.trailer.perf.is_none() {
                return Err(Defect::MissingTrailer);
            }
            if !finish && !rec.trailer.is_empty() {
                return Err(Defect::Shape);
            }
            rec.body = Body::Sweep {
                counters: sweep_counters(above),
            };
            Ok(())
        }
        Family::Session | Family::Service => Err(Defect::Shape),
    }
}

fn no_trailer(t: &Trailer<'_>) -> Parsed<()> {
    if t.is_empty() {
        Ok(())
    } else {
        Err(Defect::Shape)
    }
}

fn only_blank(lines: &[&str]) -> Parsed<()> {
    if lines.iter().all(|l| l.is_empty()) {
        Ok(())
    } else {
        Err(Defect::Shape)
    }
}

/// `Transaction counters:` and its four named numeric lines (R17 item 1).
fn sweep_counters(lines: &[&str]) -> bool {
    let lines: Vec<&str> = lines.iter().copied().filter(|l| !l.is_empty()).collect();
    let names = [
        "Oldest interesting",
        "Oldest active",
        "Oldest snapshot",
        "Next transaction",
    ];
    lines.len() == 5
        && lines[0] == "Transaction counters:"
        && lines[1..].iter().zip(names).all(|(l, n)| {
            l.strip_prefix('\t')
                .and_then(|r| r.strip_prefix(n))
                .is_some_and(|v| {
                    let d = v.trim_start_matches(' ');
                    d.len() < v.len() && decimal(d, 20).is_some()
                })
        })
}

fn statement_body<'a>(
    rec: &mut Record<'a>,
    parent: &'a str,
    above: &[&'a str],
    opts: ParseOptions,
) -> Parsed<()> {
    let t = &rec.trailer;
    if t.fetched.is_none() || t.perf.is_none() {
        // A statement finish always ends with `records fetched` and a
        // performance line (H1 fix 2).
        return Err(Defect::MissingTrailer);
    }
    // A blank line, an optional `Statement <n>:`, the dashes, the text.
    let mut i = 0usize;
    if above.first() == Some(&"") {
        i += 1;
    } else {
        return Err(Defect::Shape);
    }
    let mut id = None;
    if let Some(n) = above
        .get(i)
        .and_then(|l| l.strip_prefix("Statement "))
        .and_then(|l| l.strip_suffix(':'))
    {
        id = Some(decimal(n, 20).ok_or(Defect::Shape)?);
        i += 1;
    }
    if above.get(i) != Some(&DASHES) {
        return Err(Defect::Shape);
    }
    i += 1;
    let area = &above[i..];
    // The text ends at the first plan separator or parameter line; what
    // follows is dropped unread except for trailer-shaped lines.
    let cut = area
        .iter()
        .position(|l| *l == CARETS || param_line(l))
        .unwrap_or(area.len());
    // A parameter line only after a blank line that follows the text
    // (review of part 1, H2): a `param<i> = ` line inside the text is
    // client text.
    if area.get(cut).is_some_and(|l| param_line(l)) && (cut == 0 || !area[cut - 1].is_empty()) {
        return Err(Defect::Injected);
    }
    let (mut text_lines, after) = area.split_at(cut);
    // A blank line separates the text from its parameters.
    while text_lines.len() > 1 && text_lines.last() == Some(&"") {
        text_lines = &text_lines[..text_lines.len() - 1];
    }
    if text_lines.is_empty() || text_lines == [""] {
        return Err(Defect::Shape);
    }
    if text_lines
        .iter()
        .chain(after)
        .any(|l| trailer_shaped(l) && *l != CARETS)
    {
        return Err(Defect::Injected);
    }
    // The text as one borrowed slice of the record buffer.
    let text = join_borrowed(parent, text_lines).ok_or(Defect::Shape)?;
    // As many parameter lines as the text has `?` placeholders outside
    // literals and comments (review of part 1, H2).
    let params = after.iter().filter(|l| param_line(l)).count();
    let placeholders =
        databastion_classifiers::query::firebird::analyze_firebird(text).placeholders;
    if params != placeholders {
        return Err(Defect::Injected);
    }
    // The server cuts a longer text to `max_sql_length` bytes, `...`
    // included. The tailer drops one `\r` before each newline (as for the
    // other line-based logs), so a text written with CRLF line breaks
    // reaches here shorter than the server wrote it, by at most one byte
    // per line break: counted as if each had been there (fail closed).
    let breaks = text_lines.len() - 1;
    if let Some(limit) = opts.max_sql_length
        && text.len().saturating_add(breaks) >= limit
        && text.ends_with("...")
    {
        rec.body = Body::Statement {
            id,
            text,
            params: !after.is_empty(),
        };
        return Err(Defect::CutText);
    }
    rec.body = Body::Statement {
        id,
        text,
        params: !after.is_empty(),
    };
    Ok(())
}

/// `param<i> = …`.
fn param_line(l: &str) -> bool {
    l.strip_prefix("param")
        .and_then(|r| r.split_once(" = "))
        .is_some_and(|(n, _)| decimal(n, 5).is_some())
}

/// The lines as one slice of `parent`, the text they were split from
/// (consecutive lines, separated by one `\n`): offsets from the slices'
/// addresses, no copy of the text.
fn join_borrowed<'a>(parent: &'a str, lines: &[&'a str]) -> Option<&'a str> {
    let base = parent.as_ptr() as usize;
    let first = lines.first()?;
    let last = lines.last()?;
    let start = (first.as_ptr() as usize).checked_sub(base)?;
    let end = (last.as_ptr() as usize + last.len()).checked_sub(base)?;
    let mut expect = start;
    for l in lines {
        if (l.as_ptr() as usize).checked_sub(base)? != expect {
            return None;
        }
        expect += l.len() + 1;
    }
    parent.get(start..end)
}

fn routine_body<'a>(
    rec: &mut Record<'a>,
    above: &[&'a str],
    kind: RoutineKind,
    series: Series,
) -> Parsed<()> {
    let t = &rec.trailer;
    if t.perf.is_none() {
        return Err(Defect::MissingTrailer);
    }
    // R14 item 1: `records fetched` only on a selectable procedure.
    if t.fetched.is_some() && kind != RoutineKind::Procedure {
        return Err(Defect::Shape);
    }
    let mut i = 0usize;
    if above.first() == Some(&"") {
        i += 1;
    }
    let line = above.get(i).ok_or(Defect::Shape)?;
    let name = routine_name(line, kind, series).ok_or(Defect::Shape)?;
    let area = &above[i + 1..];
    if area.iter().any(|l| trailer_shaped(l)) {
        return Err(Defect::Injected);
    }
    let returns = area.contains(&"returns:");
    if kind == RoutineKind::Function && !returns {
        return Err(Defect::Shape);
    }
    rec.body = Body::Routine {
        name,
        kind,
        returns,
    };
    Ok(())
}

fn service_body<'a>(rec: &mut Record<'a>, lines: &[&'a str]) -> Parsed<()> {
    let first = lines.first().ok_or(Defect::Shape)?;
    let (user, protocol) = service_line(first).ok_or(Defect::ContextLine)?;
    let rest = &lines[1..];
    if rest.iter().any(|l| trailer_shaped(l)) {
        return Err(Defect::Injected);
    }
    let mut name = None;
    let mut database = None;
    if rec.header.event == Event::StartService {
        let n = rest
            .first()
            .and_then(|l| l.strip_prefix("\t\""))
            .and_then(|l| l.strip_suffix('"'))
            .ok_or(Defect::Shape)?;
        // One service name line, and no line after it shaped like the
        // service line's client part (review of part 1, M5).
        let named = rest
            .iter()
            .filter(|l| l.starts_with("\t\"") && l.ends_with('"'))
            .count();
        let client_shaped = rest.iter().skip(1).any(|l| {
            l.strip_suffix(')')
                .and_then(|l| l.rsplit_once(':'))
                .is_some_and(|(_, d)| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        });
        if named != 1 || client_shaped {
            return Err(Defect::Injected);
        }
        let n = service_name(n);
        if matches!(
            n,
            ServiceName::BackupDatabase | ServiceName::IncrementalBackupDatabase
        ) {
            // Exactly `-b <database> <file>`; any other form (a path with
            // a space included) does not resolve: attributed to every
            // declared database (R27 item 1 (a)).
            database = rest
                .get(1)
                .and_then(|l| l.strip_prefix("\t-b "))
                .and_then(|a| {
                    let parts: Vec<&str> = a.split(' ').collect();
                    (parts.len() == 2 && parts.iter().all(|p| !p.is_empty())).then(|| parts[0])
                });
        }
        name = Some(n);
    } else if !rest.iter().all(|l| l.is_empty()) {
        return Err(Defect::Shape);
    }
    rec.body = Body::Service {
        user,
        protocol,
        name,
        database,
    };
    Ok(())
}

// Redacting `Debug` (review of part 1, N1): record bytes, statement
// texts, printed database names, user, role and service names never reach
// a debug string (a panic payload, a test message, a log).

impl std::fmt::Debug for Assembled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(r) => write!(f, "Record({} bytes)", r.len()),
            Self::Oversized(h) => f.debug_tuple("Oversized").field(h).finish(),
            Self::Orphan => f.write_str("Orphan"),
        }
    }
}

impl std::fmt::Debug for AttLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttLine")
            .field("id", &self.id)
            .field("role", &self.role.is_some())
            .field("charset", &self.charset)
            .field(
                "protocol",
                &match self.protocol {
                    Protocol::Tcp(..) => "tcp",
                    Protocol::Internal => "internal",
                },
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => f.write_str("Session"),
            Self::Context => f.write_str("Context"),
            Self::Statement { id, text, params } => f
                .debug_struct("Statement")
                .field("id", id)
                .field("text_bytes", &text.len())
                .field("params", params)
                .finish(),
            Self::Routine { kind, returns, .. } => f
                .debug_struct("Routine")
                .field("kind", kind)
                .field("returns", returns)
                .finish_non_exhaustive(),
            Self::Blr => f.write_str("Blr"),
            Self::Error { codes, other_lines } => f
                .debug_struct("Error")
                .field("codes", codes)
                .field("other_lines", other_lines)
                .finish(),
            Self::Service { name, database, .. } => f
                .debug_struct("Service")
                .field("name", name)
                .field("database", &database.is_some())
                .finish_non_exhaustive(),
            Self::Sweep { counters } => {
                f.debug_struct("Sweep").field("counters", counters).finish()
            }
            Self::Other => f.write_str("Other"),
        }
    }
}
