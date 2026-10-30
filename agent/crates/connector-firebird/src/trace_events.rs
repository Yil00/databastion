//! What one trace record becomes (ADR-0060 decision 6, "Objects", the
//! always-reported rules and "Signals"; refinements R4, R8, R10, R12, R14,
//! R15, R24, R27, R28, R33, R34 and R36).
//!
//! [`convert`] applies the single-record rules to a parsed
//! [`Record`](crate::trace_log::Record): the trailer shape the record
//! has (block-ful, block-less, the no-record shape), the statement text's
//! analysis (the Firebird mode of the normalizer), the relation classes
//! the agent's catalog read gives ([`Catalog`]) and the closed
//! always-reported lists. The result is a [`Draft`] (relation names,
//! `*`, the always-reported mark, rows and signals, no text), or no event,
//! or an ambiguous record (H1 fix 3: the counters' objects, `*`, always
//! reported), with whether it opens a split window (H1 fix 2, R1 rule 7).
//!
//! The rules that need more than one record (bindings and runs, split
//! windows, folding of routine records into their statement and the
//! pending groups, the agent's own statements and their credits, the
//! external-source bindings, the Garbage Collector and sweep sequences)
//! are the stream's: [`convert`] gives a routine record's own event (the
//! not-folded case of R4) and the stream decides whether it is folded.
//!
//! I2: the statement text is read through the analysis only; a draft holds
//! relation names (identifiers), never a literal, a parameter, a BLR text
//! or a returned value, which the record parser already left unread.

use std::time::SystemTime;

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::firebird::{FirebirdAnalysis, FirebirdKind, analyze_firebird};

use crate::discover::normalize;
use crate::trace_log::{Body, Counters, Defect, Event, Outcome, Protocol, Record, ServiceName};

/// More rows than this in one statement: `volume.large_result` (decision
/// 6, "Signals").
pub(crate) const LARGE_RESULT: u64 = 10_000;

/// Statement-text objects, always reported (decision 6, the counterpart of
/// ADR-0045 part (a) and ADR-0049; drift-tested per image).
pub(crate) const STATEMENT_TEXT_RELATIONS: &[&str] = &[
    "MON$STATEMENTS",
    "MON$COMPILED_STATEMENTS",
    "MON$CONTEXT_VARIABLES",
    "MON$CALL_STACK",
];

/// Credential-bearing objects, always reported (decision 6, the
/// counterpart of ADR-0050).
pub(crate) const CREDENTIAL_RELATIONS: &[&str] = &[
    "SEC$USERS",
    "SEC$USER_ATTRIBUTES",
    "SEC$GLOBAL_AUTH_MAPPING",
    "RDB$AUTH_MAPPING",
    "PLG$SRP",
    "PLG$SRP_VIEW",
    "PLG$USERS",
    "PLG$VIEW_USERS",
    "RDB$DB_CREATORS",
    "RDB$CONFIG",
];

/// Whether a relation is on an always-reported list. The profiler's
/// `PLG$PROF_*` tables and views (5.0) are matched by prefix: adding
/// to an always-reported list only reports more.
pub(crate) fn always_listed(name: &str) -> bool {
    STATEMENT_TEXT_RELATIONS.contains(&name)
        || CREDENTIAL_RELATIONS.contains(&name)
        || name.starts_with("PLG$PROF_")
}

/// A relation's class, from the agent's catalog read of its database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelClass {
    /// A persistent user table (relation type 0, no view BLR, no external
    /// file).
    Table,
    /// A view.
    View,
    /// An external-file table (block-blind, R28).
    External,
    /// A global temporary table.
    Gtt,
    /// A virtual relation (relation type 3: `MON$`, `RDB$CONFIG`, the
    /// virtual `SEC$` relations), on the per-version list.
    Virtual,
    /// A system relation (on the decision 5 list, or a non-zero system
    /// flag): noise in reads unless always reported.
    System,
    /// Not in the last catalog read: an ordinary object.
    Unknown,
}

/// The catalog facts the rules need, per declared database (from
/// `check()`; never the name prefix alone, security review M5).
pub(crate) trait Catalog {
    /// The class of a relation, by its stored name.
    fn class(&self, relation: &str) -> RelClass;
    /// A view that depends on an always-reported relation (R12 item 5).
    fn always_view(&self, relation: &str) -> bool;
}

/// An event before its principal and database are attached.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Draft {
    pub(crate) action: Option<EventAction>,
    /// Relation (or routine) names, in the order found, no duplicates.
    pub(crate) objects: Vec<String>,
    /// `*` of the database.
    pub(crate) star: bool,
    pub(crate) always: bool,
    pub(crate) rows: Option<u64>,
    pub(crate) signals: Vec<Signal>,
}

impl Draft {
    fn object(&mut self, name: &str) {
        if !self.objects.iter().any(|o| o == name) {
            self.objects.push(name.to_owned());
        }
    }

    fn signal(&mut self, s: Signal) {
        if !self.signals.contains(&s) {
            self.signals.push(s);
        }
    }

    /// R36 item 1: a record that raises a signal always gives an event;
    /// with no object left it names `*`; `signature.backup_database`
    /// always names `*` and is always reported.
    fn finish(mut self) -> Option<Self> {
        if self.signals.contains(&Signal::BackupDatabase) {
            self.star = true;
            self.always = true;
        }
        if self.objects.is_empty() && !self.star {
            if self.signals.is_empty() {
                return None;
            }
            self.star = true;
            self.always = true;
        }
        Some(self)
    }
}

/// What a record becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Converted {
    /// No event (a record that reads nothing, or the stream's business).
    Nothing,
    /// A well-formed record's event.
    Event(Draft),
    /// An ambiguous record (H1 fix 3): always reported, `*`, never the
    /// agent's own, never dropped as an undeclared database's. `window`:
    /// it opens a split window (H1 fix 2, R1 rule 7).
    Ambiguous { draft: Draft, window: bool },
}

/// Applies the noise filter to one relation: `None` when it is left out
/// (a system or virtual relation outside the always-reported lists); the
/// always-reported mark otherwise.
fn keep(name: &str, cat: &dyn Catalog) -> Option<bool> {
    let always = always_listed(name) || cat.always_view(name);
    if always {
        return Some(true);
    }
    match cat.class(name) {
        RelClass::System | RelClass::Virtual => None,
        _ => Some(false),
    }
}

fn block_objects(d: &mut Draft, block: &[(&str, Counters)], cat: &dyn Catalog) -> bool {
    let mut wrote = false;
    for (name, c) in block {
        if let Some(always) = keep(name, cat) {
            d.object(name);
            d.always |= always;
            wrote |= c.wrote();
        }
    }
    wrote
}

fn text_objects(d: &mut Draft, a: &FirebirdAnalysis, cat: &dyn Catalog) {
    for name in &a.relations {
        if let Some(always) = keep(name, cat) {
            d.object(name);
            d.always |= always;
        }
        // Block-blind relations (R28): reads of external-file tables are
        // remote data and always reported; a view the block cannot show
        // through stays named from the text.
        if cat.class(name) == RelClass::External {
            d.signal(Signal::RemoteDataAccess);
            d.star = true;
            d.always = true;
        }
    }
    for p in &a.procedures {
        d.object(p);
    }
}

/// The ambiguous form of a record (H1 fix 3).
fn ambiguous(rec: &Record<'_>, cat: &dyn Catalog, window: bool) -> Converted {
    let mut d = Draft {
        action: Some(EventAction::Read),
        star: true,
        always: true,
        rows: rec.trailer.fetched,
        ..Draft::default()
    };
    if let Some(block) = &rec.trailer.block
        && block_objects(&mut d, block, cat)
    {
        d.action = Some(EventAction::Write);
    }
    Converted::Ambiguous { draft: d, window }
}

/// Text-derived signals of a statement (decision 6, R36).
fn text_signals(d: &mut Draft, a: &FirebirdAnalysis) {
    if a.backup {
        d.signal(Signal::BackupDatabase);
    }
    if a.remote_access {
        d.signal(Signal::RemoteDataAccess);
        d.star = true;
        d.always = true;
    }
    if a.psql || a.unknown_call || a.execute_statement {
        // Code that runs out of sight (decision 6).
        d.star = true;
        d.always = true;
    }
}

fn action_of(kind: FirebirdKind) -> EventAction {
    match kind {
        FirebirdKind::Write => EventAction::Write,
        FirebirdKind::Ddl => EventAction::Ddl,
        FirebirdKind::Dcl => EventAction::Dcl,
        _ => EventAction::Read,
    }
}

/// Converts one parsed record (single-record rules only; see the module
/// documentation).
pub(crate) fn convert(rec: &Record<'_>, cat: &dyn Catalog) -> Converted {
    if let Some(defect) = rec.defect {
        let window = defect == Defect::MissingTrailer && rec.header.event.is_finish();
        return ambiguous(rec, cat, window);
    }
    match (&rec.body, rec.header.event) {
        (Body::Statement { text, params, .. }, Event::ExecuteStatementFinish) => {
            statement(rec, text, *params, cat)
        }
        (Body::Routine { .. }, _) => routine(rec, cat),
        (Body::Blr, Event::CompileBlr) => match rec.header.outcome {
            Outcome::Ok => Converted::Nothing,
            // Pending 3n (R33 items 1 and 3).
            _ => ambiguous(rec, cat, false),
        },
        (Body::Blr, Event::ExecuteBlr) => {
            if rec.header.outcome != Outcome::Ok {
                return ambiguous(rec, cat, false);
            }
            // R33 item 2: the block's relations, `*`, always reported, no
            // rows.
            let mut d = Draft {
                action: Some(EventAction::Read),
                star: true,
                always: true,
                ..Draft::default()
            };
            if let Some(b) = &rec.trailer.block {
                block_objects(&mut d, b, cat);
            }
            Converted::Event(d)
        }
        (Body::Context, Event::CommitTransaction | Event::RollbackTransaction) => {
            // R24 items 1 and 2: a block on a transaction-end record.
            let Some(b) = &rec.trailer.block else {
                return Converted::Nothing;
            };
            let mut d = Draft {
                action: Some(EventAction::Read),
                ..Draft::default()
            };
            block_objects(&mut d, b, cat);
            d.finish().map_or(Converted::Nothing, Converted::Event)
        }
        (Body::Context, Event::AttachDatabase) => match rec.header.outcome {
            // R10 item 3: authenticated failures, user fingerprinted.
            Outcome::Failed | Outcome::Unauthorized => Converted::Event(Draft {
                action: Some(EventAction::AuthFailure),
                ..Draft::default()
            }),
            // R27 item 1 (b): a `gbak` client line, a client-set hint.
            Outcome::Ok if rec.client.is_some_and(|c| c.gbak) => Converted::Event(Draft {
                action: Some(EventAction::Read),
                star: true,
                always: true,
                signals: vec![Signal::BackupDatabase],
                ..Draft::default()
            }),
            Outcome::Ok => Converted::Nothing,
        },
        (Body::Service { name, .. }, Event::StartService) => service(*name),
        _ => Converted::Nothing,
    }
}

/// A services `START_SERVICE` (R27 item 1 (a), decision 6): backups raise
/// `signature.backup_database`; trace sessions are statement-text reads;
/// user management keeps its kind only.
fn service(name: Option<ServiceName>) -> Converted {
    let mut d = Draft {
        star: true,
        always: true,
        ..Draft::default()
    };
    match name {
        Some(ServiceName::BackupDatabase | ServiceName::IncrementalBackupDatabase) => {
            d.action = Some(EventAction::Read);
            d.signal(Signal::BackupDatabase);
        }
        Some(ServiceName::StartTraceSession | ServiceName::ListTraceSessions) => {
            d.action = Some(EventAction::Read);
        }
        Some(ServiceName::UserManagement) => d.action = Some(EventAction::Dcl),
        _ => return Converted::Nothing,
    }
    Converted::Event(d)
}

/// A routine finish record's own event (R4: the not-folded case; R14,
/// R15 item 4): the routine's counters and row count, under the filters.
/// A block-less routine record that is not folded is ambiguous (R8 item
/// 2), and the stream decides the folding before calling this.
fn routine(rec: &Record<'_>, cat: &dyn Catalog) -> Converted {
    let Some(b) = &rec.trailer.block else {
        return ambiguous(rec, cat, true);
    };
    let mut d = Draft {
        action: Some(EventAction::Read),
        rows: rec.trailer.fetched,
        ..Draft::default()
    };
    if block_objects(&mut d, b, cat) {
        d.action = Some(EventAction::Write);
    }
    if !d.objects.is_empty() && d.rows.is_some_and(|n| n > LARGE_RESULT) {
        d.signal(Signal::LargeResult);
    }
    d.finish().map_or(Converted::Nothing, Converted::Event)
}

fn statement(rec: &Record<'_>, text: &str, params: bool, cat: &dyn Catalog) -> Converted {
    let a = analyze_firebird(text);
    let fetched = rec.trailer.fetched.unwrap_or(0);
    // A text that ends inside an unterminated construct (and is not cut:
    // the parser reports cut texts as defects) is evidence of a split
    // (R12 item 3).
    if a.unterminated {
        return ambiguous(rec, cat, true);
    }
    let mut d = Draft {
        action: Some(action_of(a.kind)),
        rows: Some(fetched),
        ..Draft::default()
    };
    match &rec.trailer.block {
        Some(block) => {
            if a.kind.cannot_read() {
                // R24 item 3 and R34 item 1: transaction statements and
                // `ALTER SESSION RESET` may carry a block, with exactly
                // `0 records fetched` and no parameter line; the other
                // kinds of R8 case (b) may not.
                if !matches!(
                    a.kind,
                    FirebirdKind::Transaction | FirebirdKind::SessionReset
                ) || fetched != 0
                    || params
                {
                    return ambiguous(rec, cat, false);
                }
                d.rows = None;
                d.action = Some(EventAction::Read);
                block_objects(&mut d, block, cat);
                return d.finish().map_or(Converted::Nothing, Converted::Event);
            }
            if block_objects(&mut d, block, cat) && d.action == Some(EventAction::Read) {
                d.action = Some(EventAction::Write);
            }
        }
        None => {
            // R8 item 1 and R12: the block-less shapes.
            if a.kind.cannot_read() {
                return if fetched == 0 && !params {
                    Converted::Nothing
                } else {
                    ambiguous(rec, cat, true)
                };
            }
            let all_virtual = a
                .relations
                .iter()
                .all(|r| cat.class(r) == RelClass::Virtual);
            let case_a = a.parses() && all_virtual && !a.calls_code();
            let case_c = a.parses() && all_virtual && a.calls_code();
            let no_record = fetched == 0
                // R12 item 3: a text whose dialect readings differ keeps
                // the shape, and names `*` below (no window).
                || (fetched == 1
                    && !a.unterminated
                    && a.aggregate_only
                    // R28: global temporary tables join persistent
                    // tables in R12's aggregate branch.
                    && a
                        .relations
                        .iter()
                        .all(|r| matches!(cat.class(r), RelClass::Table | RelClass::Gtt)));
            if a.credential || matches!(a.kind, FirebirdKind::Ddl | FirebirdKind::Dcl) {
                // DDL and DCL keep their kind (decision 6): a block-less
                // DDL record read no record.
                if fetched != 0 {
                    return ambiguous(rec, cat, true);
                }
            } else if case_c {
                d.star = true;
                d.always = true;
            } else if !case_a && !no_record {
                return ambiguous(rec, cat, true);
            } else if a.dialects_differ {
                // R12 item 3: the readings differ, `*`, no window.
                d.star = true;
                d.always = true;
            }
        }
    }
    if a.credential || matches!(a.kind, FirebirdKind::Ddl | FirebirdKind::Dcl) {
        // DDL and DCL keep their kind, never text (decision 6), and the
        // credential forms their kind only (the #82 rule): `*`, always
        // reported, with the block's objects under the filters and the
        // text's server-side copy and remote-access flags.
        d.star = true;
        d.always = true;
        if !a.credential {
            text_signals(&mut d, &a);
        }
        return d.finish().map_or(Converted::Nothing, Converted::Event);
    }
    text_objects(&mut d, &a, cat);
    text_signals(&mut d, &a);
    // The volume and shape signals are about the objects read: a read
    // of noise relations only raises none.
    if !d.objects.is_empty() {
        if a.kind == FirebirdKind::Select && a.unrestricted_select && fetched > 0 {
            d.signal(Signal::FullTableRead);
        }
        if fetched > LARGE_RESULT {
            d.signal(Signal::LargeResult);
        }
    }
    d.finish().map_or(Converted::Nothing, Converted::Event)
}

/// The event of a draft, under the record's principal and the declared
/// database `db` (the operator's label, never a path). `failed`: the
/// user name is fingerprinted (R10 item 3; decision 6, "Principals").
pub(crate) fn to_event(draft: &Draft, rec: &Record<'_>, db: &str, ts: SystemTime) -> MaskedEvent {
    let (user, client) = match (&rec.att, &rec.body) {
        (Some(att), _) => (Some(att.user), Some(att.protocol)),
        (None, Body::Service { user, protocol, .. }) => (Some(*user), Some(*protocol)),
        _ => (None, None),
    };
    let client = client.and_then(|p| match p {
        Protocol::Tcp(ip, _) => Some(ClientAddr::Ip(ip)),
        Protocol::Internal => None,
    });
    let action = draft.action.unwrap_or(EventAction::Read);
    let principal = match (action, user) {
        (EventAction::AuthFailure, Some(u)) => EventPrincipal::failed_account(u),
        (_, Some(u)) => EventPrincipal::account(u),
        (_, None) => EventPrincipal::unidentified(),
    }
    .with_client(client);
    let mut ev = MaskedEvent::new(EventSource::FirebirdAuditTrace, action, principal, ts);
    if action == EventAction::AuthFailure {
        return ev;
    }
    let dbn = normalize(db);
    if draft.star {
        // `*` first, so that it always fits.
        ev = ev.with_object(EventObject::new(
            dbn.clone(),
            None,
            NormalizedName::wildcard(),
        ));
    }
    for o in &draft.objects {
        ev = ev.with_object(EventObject::new(dbn.clone(), None, normalize(o)));
    }
    ev = ev.with_rows(draft.rows);
    for s in &draft.signals {
        ev = ev.with_signal(*s);
    }
    if draft.always {
        ev = ev.with_always_report();
    }
    ev
}
