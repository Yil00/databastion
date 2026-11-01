//! Audit from the Firebird system audit trace (ADR-0060 decision 6 and
//! its refinements): what `check()` gathers for the stream and the level,
//! and the stream itself ([`stream`]).
//!
//! - **`check()`** ([`evaluate`]): the declared databases' resolved paths
//!   and security-database kinds (R2 rule 1, R9), their catalog classes,
//!   the configuration files under the file rules (proofs 1 to 6 and 11),
//!   the binding to the running server (proof 2: `AuditTraceConfigFile`,
//!   `ServerMode`, the files not changed since the server process started,
//!   the process visible), the readers check (R4), the read-back probe
//!   (proof 7), the stream's freshness and ambiguity (proofs 8 and 9). The
//!   level is Partial when every proof holds, Limited with a record of a
//!   declared database parsed in the last 24 h, None otherwise; Full is
//!   never reported.
//! - **The stream**: the core tailer (`O_NOFOLLOW`, one hard link,
//!   rotation, keyed truncation fingerprints, persisted positions) with
//!   this module's open check on its handle; lines assembled into records
//!   ([`crate::trace_log`]), the last one held until a following header or
//!   a stable end of file (2 s); [`crate::stream::Machine`] applies the
//!   rules; the persisted position is held back to the first record of a
//!   pending fold group or of the record in progress.
//! - **The parser checkpoint** ([`crate::audit_ckpt`], R25 items 7 and 9,
//!   R39 (a)): with a state directory, each commit writes the ledger, then
//!   the parser state as it was at the position the cursor is saved at
//!   (the record in progress, or the first block-less record of a hold),
//!   then the cursor. A restart that resumes from exactly that position
//!   restores the state and the agent's credits, re-reads from there, and
//!   emits nothing again for a position whose events were durably spooled;
//!   other events of the re-read region are sent again (over-reporting,
//!   never a loss). Without a usable checkpoint (none written, refused,
//!   another server run, another position), the stream starts with no
//!   state and the records re-read are judged and emitted as on their
//!   first reading, as before.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use databastion_core::audit::tail::{Framing, OpenCheck, OpenedFile, TailError, Tailer};
use databastion_core::config::firebird::FirebirdAuditConfig;
use databastion_core::{
    AuditConfig, AuditLevel, ConnectorError, EventSink, FailureCode, NoteCode, NoteLabel, Notes,
    TargetNote,
};

use crate::audit_ckpt::{Checkpointer, Commit};
use crate::catalog;
use crate::stream::{DeclaredNames, Machine, Run, Settings};
use crate::trace_conf::{self, AliasMap, DeclaredDb, ServerMode};
use crate::trace_events::{Catalog, RelClass};
use crate::trace_log::{Assembled, Assembler, ParseOptions, Series, header};

/// Proof 7: the read-back probe's record must be found within this.
const PROBE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Proofs 8 and 9.
const DAY: Duration = Duration::from_secs(24 * 3600);
/// A record at end of file is held until the file has not grown for this
/// long (decision 6, review L5).
const STABLE_EOF: Duration = Duration::from_secs(2);
/// The tailer's cursor name.
const CURSOR: &str = "firebird_audit_trace";

/// One declared database, as `check()` read it.
#[derive(Clone, Default)]
pub(crate) struct DbFacts {
    pub(crate) attach: String,
    pub(crate) label: String,
    pub(crate) resolved: Option<String>,
    pub(crate) catalog: Classes,
    /// Excluded by R9 (`check()` decided it before any probe): not read by
    /// Discovery, an undeclared database for the stream.
    pub(crate) excluded: bool,
    /// When the attachment's catalog read started (R41 item 8: only a
    /// read started after every DDL transaction's end clears the
    /// invalidation).
    pub(crate) read_at: Option<SystemTime>,
    /// The linger, the restore state and the check attachment's id (R30
    /// item 3, R1 rule 5).
    pub(crate) state: crate::check::DbState,
    /// Restores the checks of this process confirmed for this database from
    /// a changed `DB_GUID` or `MON$CREATION_DATE` (R1 rule 5), counted by
    /// [`evaluate`].
    pub(crate) restores: u64,
    /// The last restore state read (kept across a check whose read
    /// failed, so the next one is compared with it).
    pub(crate) restore_seen: Option<crate::check::RestoreState>,
}

/// The relation classes of one database's catalog read (decision 5's
/// user relations; everything else is a system or virtual relation only
/// when the read was complete).
#[derive(Clone, Default)]
pub(crate) struct Classes {
    user: HashMap<String, RelClass>,
    complete: bool,
    /// The views that depend on an always-reported relation (R12 item 5).
    deps: crate::views::ViewDeps,
    /// The database's linger in seconds (R30 item 3), `None` when not read.
    linger: Option<u32>,
    /// The restore state of R1 rule 5, `None` when not read.
    restore: Option<crate::check::RestoreState>,
}

impl Classes {
    pub(crate) fn from_catalog(c: &catalog::Catalog, deps: crate::views::ViewDeps) -> Self {
        let Some(rels) = &c.relations else {
            return Self {
                deps,
                ..Self::default()
            };
        };
        let user = rels
            .iter()
            .map(|r| {
                let class = match r.kind {
                    catalog::Kind::Table => RelClass::Table,
                    catalog::Kind::View => RelClass::View,
                    catalog::Kind::External => RelClass::External,
                    catalog::Kind::Temporary => RelClass::Gtt,
                    catalog::Kind::Other => RelClass::Unknown,
                };
                (catalog::trimmed(&r.name).to_owned(), class)
            })
            .collect();
        Self {
            user,
            complete: !c.relations_cut && c.relations_dropped == 0,
            deps,
            linger: None,
            restore: None,
        }
    }

    /// With the restore state the check read (R1 rule 5).
    #[must_use]
    pub(crate) fn with_restore(mut self, restore: Option<crate::check::RestoreState>) -> Self {
        self.restore = restore;
        self
    }

    /// With the linger the check read (R30 item 3).
    #[must_use]
    pub(crate) fn with_linger(mut self, linger: Option<u32>) -> Self {
        self.linger = linger;
        self
    }
}

impl Classes {
    /// The keyed digest of what this check gives the stream for its
    /// database (the decision of 2026-11-01 on L10: a restored checkpoint
    /// re-reads a database whose digest changed with every relation
    /// dependent): whether the catalog read was complete; the user
    /// relations classed as external-file tables (the block-blind set of
    /// R28) and as views; the dependent set of R41 (dependent objects,
    /// tables with a computed column and whether the columns were read,
    /// routine names, whether those reads were complete); the linger of R30
    /// item 3 and the restore state of R1 rule 5 (`DB_GUID` and
    /// `MON$CREATION_DATE`: ADR-0060 R60, so that a database restored while
    /// the agent was stopped, from a backup with the same schema, is
    /// invalidated at the restore). Names are sorted;
    /// only the tag is kept. Any relation class or check result the stream
    /// comes to use beyond these must join the digest.
    pub(crate) fn digest(&self, key: &databastion_classifiers::masking::LocalTagKey) -> [u8; 32] {
        let mut w = crate::ckpt::Writer::default();
        let set = |w: &mut crate::ckpt::Writer, names: &mut dyn Iterator<Item = &String>| {
            let mut v: Vec<&String> = names.collect();
            v.sort();
            w.len(v.len());
            for n in v {
                w.str(n);
            }
        };
        w.bool(self.complete);
        let of = |c: RelClass| {
            self.user
                .iter()
                .filter(move |(_, k)| **k == c)
                .map(|(n, _)| n)
        };
        set(&mut w, &mut of(RelClass::External));
        set(&mut w, &mut of(RelClass::View));
        set(&mut w, &mut self.deps.dependent.iter());
        set(&mut w, &mut self.deps.computed.iter());
        w.bool(self.deps.computed_known);
        set(&mut w, &mut self.deps.routines.iter());
        w.bool(self.deps.complete);
        w.opt_u64(self.linger.map(u64::from));
        w.bool(self.restore.is_some());
        if let Some(r) = &self.restore {
            w.str(&r.guid);
            w.str(&r.created);
        }
        crate::ckpt::tag(
            key,
            b"databastion.firebird.checkpoint.check_digest.v1",
            &[&w.buf],
        )
    }
}

impl Catalog for Classes {
    fn class(&self, r: &str) -> RelClass {
        if let Some(c) = self.user.get(r) {
            return *c;
        }
        // Not a user relation (system flag 0) of a complete read: a
        // system relation only when it is on the explicit list of the
        // tested images (decision 5, drift-tested), the virtual ones among
        // them by kind (R8 item 1). Any other name, whatever its prefix
        // (a table `RDB$LOOT` created since the read), is an object
        // (review M2 of the refinement of 2026-10-30).
        if !self.complete || !catalog::NEVER_SAMPLED.contains(&r) {
            return RelClass::Unknown;
        }
        if VIRTUAL.contains(&r) {
            RelClass::Virtual
        } else {
            RelClass::System
        }
    }

    /// R41: a name at an object position (a relation or routine of the
    /// text, a block name, a routine name line) that is in the dependent
    /// set, or that the last complete catalog read does not know (item 3);
    /// with an incomplete read (failed, cut, past its bounds: item 2),
    /// every view, routine, package, trigger and unknown name, and every
    /// table with a computed column (every table when the columns were not
    /// read).
    fn always_view(&self, relation: &str) -> bool {
        let r = relation.trim_end_matches(' ');
        if !self.complete || !self.deps.complete {
            return match self.class(r) {
                RelClass::View | RelClass::Unknown => true,
                RelClass::Table | RelClass::Gtt => {
                    !self.deps.computed_known || self.deps.computed.contains(r)
                }
                RelClass::External | RelClass::System | RelClass::Virtual => false,
            };
        }
        self.deps.dependent.contains(r)
            || (self.class(r) == RelClass::Unknown && !self.deps.routines.contains(r))
    }

    fn computed(&self, relation: &str) -> bool {
        let r = relation.trim_end_matches(' ');
        matches!(self.class(r), RelClass::Table | RelClass::Gtt)
            && (!self.deps.computed_known || self.deps.computed.contains(r))
    }

    /// R41 item 6: any identifier token equal to a dependent object's name.
    fn dependent_token(&self, name: &str) -> bool {
        self.deps.dependent.contains(name.trim_end_matches(' '))
    }

    fn linger(&self) -> Option<u32> {
        self.linger
    }
}

/// The virtual relations (relation type 3) of the tested images, 4.0.7
/// and 5.0.4 (R8 item 1's per-version list; the engine-matrix drift test
/// checks it against each server in both directions). A name of this list
/// that a version lacks is never in its log.
const VIRTUAL: &[&str] = &[
    "MON$ATTACHMENTS",
    "MON$CALL_STACK",
    "MON$COMPILED_STATEMENTS",
    "MON$CONTEXT_VARIABLES",
    "MON$DATABASE",
    "MON$IO_STATS",
    "MON$MEMORY_USAGE",
    "MON$RECORD_STATS",
    "MON$STATEMENTS",
    "MON$TABLE_STATS",
    "MON$TRANSACTIONS",
    "RDB$CONFIG",
    "RDB$KEYWORDS",
    "RDB$TIME_ZONES",
    "SEC$DB_CREATORS",
    "SEC$GLOBAL_AUTH_MAPPING",
    "SEC$USERS",
    "SEC$USER_ATTRIBUTES",
];

/// What the stream reports back to `check()`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StreamFacts {
    pub(crate) last_record: Option<SystemTime>,
    pub(crate) last_ambiguous: Option<SystemTime>,
    pub(crate) ambiguous: u64,
    pub(crate) gap: Option<SystemTime>,
    pub(crate) probe_seen: Option<SystemTime>,
    /// Gap events counted (review M4): rotations or truncations, records
    /// the tailer dropped, record-rule panics, cursor resets.
    pub(crate) gaps: u64,
    /// Where the last stream of this process saved its cursor: the file
    /// and the offset the next stream must resume at (review M4).
    pub(crate) saved: Option<((u64, u64), u64)>,
    /// R1 rule 2: the time the stream stopped for run confirmations, summed
    /// over stops each ending within an hour of the previous one, and when
    /// the last one ended (`run_confirmation_stalled` past 60 s within the
    /// hour; a chain of stops is summed whole, so the label errs on the
    /// side of being shown).
    pub(crate) stopped: Duration,
    pub(crate) last_stop: Option<SystemTime>,
}

/// R1 rule 2: the label `run_confirmation_stalled` past this much stopped
/// time within one hour.
const STALLED: Duration = Duration::from_secs(60);

impl StreamFacts {
    /// One stop of `d` ended at `at` (R1 rule 2).
    pub(crate) fn note_stop(&mut self, d: Duration, at: SystemTime) {
        let fresh = self
            .last_stop
            .is_some_and(|l| at.duration_since(l).unwrap_or_default() < Duration::from_secs(3600));
        self.stopped = if fresh { self.stopped + d } else { d };
        self.last_stop = Some(at);
    }

    /// Whether the stream stopped more than 60 s within the last hour.
    pub(crate) fn stalled(&self, now: SystemTime) -> bool {
        self.stopped > STALLED
            && self.last_stop.is_some_and(|l| {
                now.duration_since(l).unwrap_or_default() < Duration::from_secs(3600)
            })
    }
}

/// Per target: what the last `check()` evaluated, and the stream's facts.
#[derive(Default)]
pub(crate) struct AuditState {
    inner: Mutex<HashMap<String, Target>>,
}

// Review N3: no path, alias, label or catalog name in a `Debug` output
// (these structures must never reach a log in clear).
impl std::fmt::Debug for DbFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbFacts")
            .field("resolved", &self.resolved.is_some())
            .field("excluded", &self.excluded)
            .field("catalog", &self.catalog)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Classes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Classes")
            .field("user_relations", &self.user.len())
            .field("complete", &self.complete)
            .field("dependent_views", &self.deps.dependent.len())
            .field("dependencies_complete", &self.deps.complete)
            .field("linger", &self.linger)
            .field("restore", &self.restore.is_some())
            .finish()
    }
}

impl std::fmt::Debug for AuditState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditState").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("dbs", &self.dbs)
            .field("aliases", &self.aliases.is_some())
            .field("proof11", &self.proof11)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Default, Clone)]
struct Target {
    dbs: Vec<DbFacts>,
    aliases: Option<AliasMap>,
    proof11: bool,
    superserver: bool,
    max_sql_length: u64,
    run: Option<Run>,
    /// When the check that read `run` started (R1 rule 2: only a check
    /// started after a stop confirms it).
    run_read_at: Option<SystemTime>,
    stream: StreamFacts,
    probe_sent: Option<SystemTime>,
    generation: u64,
    /// The identity files the last readers check used (R44 item 6).
    identity_source: Option<crate::host_identity::Source>,
}

impl AuditState {
    fn with<R>(&self, id: &str, f: impl FnOnce(&mut Target) -> R) -> R {
        let mut m = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(m.entry(id.to_owned()).or_default())
    }

    /// The declared `attach` of every database the last evaluation
    /// excluded (R9), for Discovery.
    pub(crate) fn excluded_attach(&self, id: &str) -> Vec<String> {
        self.with(id, |t| {
            t.dbs
                .iter()
                .filter(|d| d.excluded)
                .map(|d| d.attach.clone())
                .collect()
        })
    }

    pub(crate) fn note_stream(&self, id: &str, f: impl FnOnce(&mut StreamFacts)) {
        self.with(id, |t| f(&mut t.stream));
    }
}

/// The inputs `check()` read from the server for the Audit evaluation.
pub(crate) struct CheckInputs {
    pub(crate) dbs: Vec<DbFacts>,
    /// `MON$SERVER_PID` on the agent's own attachment.
    pub(crate) server_pid: Option<u32>,
    pub(crate) peer_uid: Option<u32>,
    /// When the check started (before its first attachment, so the pid is
    /// read after it).
    pub(crate) started: SystemTime,
}

/// R9 rule 3: the evaluated `databases.conf` (read under the file rules
/// and parsed), `None` when not configured, unreadable or not parsed.
/// Blocking: reads a local file.
pub(crate) fn alias_map(cfg: &FirebirdAuditConfig) -> Option<AliasMap> {
    let root = cfg.root.to_string_lossy().into_owned();
    let p = cfg.databases_conf.as_ref()?;
    let (bytes, _) = crate::fsread::read_checked(p, trace_conf::MAX_CONF_BYTES).ok()?;
    trace_conf::parse_databases_conf(&bytes, &root).ok()
}

/// R44 item 6 (security review N7): one local `info` line naming the
/// target and the source when its readers check switches between the
/// host's files and declared files (never a path or content).
fn note_identity_source(
    state: &AuditState,
    target_id: &str,
    source: Option<crate::host_identity::Source>,
) {
    let previous = state.with(target_id, |t| {
        std::mem::replace(&mut t.identity_source, source)
    });
    if let Some(now) = crate::host_identity::switched(previous, source) {
        tracing::info!(
            target_id = %target_id,
            source = now.as_str(),
            "Firebird readers check: identity files source"
        );
    }
}

/// The proofs, the level and the notes (decision 6; refinements).
/// Blocking: reads local files.
#[allow(clippy::too_many_lines)]
pub(crate) fn evaluate(
    state: &AuditState,
    target_id: &str,
    cfg: &FirebirdAuditConfig,
    input: CheckInputs,
    notes: &mut Notes,
    detail: &mut Vec<String>,
) -> AuditLevel {
    let mut proven = true;
    let mut not_eval: Vec<&'static str> = Vec::new();
    let root = cfg.root.to_string_lossy().into_owned();
    // R10: failed logins are not in the trace of the target database.
    notes.add(TargetNote::new(NoteCode::AuditFailedLoginsNotAudited));
    let run = input
        .server_pid
        .map(|pid| (pid, crate::fsread::process_start(pid)));
    let started = run.and_then(|(_, s)| s.and_then(|(_, t)| t));
    if started.is_none() {
        // Proof 2: another pid namespace, or `hidepid`; or a computed start
        // later than now (R60: virtualised clocks), which proves nothing.
        not_eval.push("server_process_not_visible");
        if run.is_some_and(|(_, s)| s.is_some()) {
            detail.push(
                "the Firebird server process has no wall-clock start (unreadable or later than \
                 now): not bound to the running server"
                    .to_owned(),
            );
        }
    }
    let changed = |t: SystemTime| started.is_none_or(|s| t > s);
    // firebird.conf (M3).
    let fb = crate::fsread::read_checked(&cfg.firebird_conf, trace_conf::MAX_CONF_BYTES);
    let mut mode = ServerMode::Super;
    match fb {
        Ok((bytes, mtime)) => match trace_conf::parse_firebird_conf(&bytes) {
            Ok(conf) => {
                mode = conf.server_mode;
                if !trace_conf::binds_trace_config(
                    &conf,
                    &root,
                    &cfg.trace_config.to_string_lossy(),
                ) {
                    not_eval.push("trace_config_file_mismatch");
                }
                if changed(mtime) {
                    not_eval.push("config_changed_since_start");
                }
            }
            Err(_) => not_eval.push("firebird_conf_unreadable"),
        },
        Err(_) => not_eval.push("firebird_conf_unreadable"),
    }
    // databases.conf (R2 rule 2, rule 5).
    let aliases = cfg.databases_conf.as_ref().and_then(|p| {
        match crate::fsread::read_checked(p, trace_conf::MAX_CONF_BYTES) {
            Ok((bytes, mtime)) => {
                if changed(mtime) {
                    not_eval.push("databases_conf");
                    return None;
                }
                trace_conf::parse_databases_conf(&bytes, &root).ok()
            }
            Err(_) => None,
        }
    });
    // R9: `check()` excluded the databases that are their own security
    // database (or not shown not to be one) before any probe, and reported
    // the note; the map read here may also exclude one (rule 3, fail
    // closed: a map changed since the check).
    let mut names = Vec::new();
    let mut dbs = input.dbs.clone();
    for (d, kept) in input.dbs.iter().zip(dbs.iter_mut()) {
        let alias = (!d.attach.starts_with('/')).then_some(d.attach.as_str());
        let decl = DeclaredDb {
            label: &d.label,
            resolved: d.resolved.as_deref(),
            alias,
        };
        let map_self = trace_conf::own_security_database(aliases.as_ref(), &decl, &root);
        let excl = d.excluded || map_self != Some(false);
        // Re-review L-E: kept with the target's facts, for the stream and
        // for Discovery (`excluded_attach`).
        kept.excluded = excl;
        if excl && !d.excluded {
            detail.push(format!(
                "{}: excluded from Audit (databases.conf, rule 3 of R9)",
                d.label
            ));
        }
        // Proof 11: the declared database file has a single link.
        if let Some(p) = &d.resolved
            && crate::fsread::identity(std::path::Path::new(p)).is_some_and(|(_, n)| n != 1)
        {
            not_eval.push("database_path_not_unique");
        }
        names.push(DeclaredNames {
            label: d.label.clone(),
            resolved: d.resolved.clone(),
            alias: alias.map(str::to_owned),
            excluded: excl,
            attach: d.attach.clone(),
            read_at: None,
        });
    }
    // The trace configuration (proofs 3 to 6 and 11).
    let mut proof11 = false;
    let mut max_sql = 300;
    match crate::fsread::read_checked(&cfg.trace_config, trace_conf::MAX_CONF_BYTES) {
        Ok((bytes, mtime)) => {
            if changed(mtime) {
                not_eval.push("config_changed_since_start");
            }
            match trace_conf::parse_trace_conf(&bytes) {
                Ok(t) => {
                    let decls: Vec<DeclaredDb<'_>> = names
                        .iter()
                        .filter(|n| !n.excluded)
                        .map(|n| DeclaredDb {
                            label: &n.label,
                            resolved: n.resolved.as_deref(),
                            alias: n.alias.as_deref(),
                        })
                        .collect();
                    let v = trace_conf::evaluate(&trace_conf::Inputs {
                        trace: &t,
                        aliases: aliases.as_ref(),
                        databases: &decls,
                        log: &cfg.log.to_string_lossy(),
                        root: &root,
                        longest_own_text: crate::own_table::longest_text(),
                    });
                    proven &= v.partial;
                    proof11 = !v.notes.iter().any(|n| {
                        n.labels()
                            .iter()
                            .any(|l| l.as_str() == "foreign_databases_logged")
                    });
                    max_sql = v.max_sql_length;
                    detail.extend(v.detail);
                    for n in v.notes {
                        notes.add(n);
                    }
                }
                Err(_) => not_eval.push("trace_config_unreadable"),
            }
        }
        Err(_) => not_eval.push("trace_config_unreadable"),
    }
    // Proof 1 and R4: the log and who can read it.
    // Opened and checked on its handle, never read here (review H3).
    let log_ok = crate::fsread::check_file(&cfg.log).is_ok();
    if !log_ok {
        notes.add(TargetNote::new(NoteCode::AuditLogNotReadable));
        proven = false;
    }
    // R4 (R39 (i)): the server's uid from the server process proof 2
    // finds, or the declared `peer_uid`, never a default.
    // R44 item 3: container detection at every check.
    let in_container = databastion_core::config::firebird::agent_in_container();
    let source = crate::host_identity::Source::of(in_container, cfg.host_identity.is_some());
    note_identity_source(state, target_id, source);
    let server = input.server_pid.and_then(crate::fsread::server_ids);
    let place = crate::fsread::Place {
        in_container,
        host_identity: cfg.host_identity.as_ref(),
    };
    if let Err(why) = crate::fsread::readers_check(&cfg.log, server, input.peer_uid, place) {
        notes.add(TargetNote::new(NoteCode::AuditLogReadableByOthers));
        detail.push(format!("readers check: {why}"));
        proven = false;
    }
    // Review L4: the declared root is the server's layout (its binary in
    // `<root>/bin`); otherwise the macros may not resolve to
    // the root and proof 2 is not proven.
    if started.is_some() {
        let dir = input.server_pid.and_then(crate::fsread::server_binary_dir);
        let root_path = std::path::Path::new(&root);
        // Re-review note: `<root>/bin` only (the images' and the tarball's).
        if !dir.is_some_and(|d| d == root_path.join("bin")) {
            not_eval.push("server_layout_not_the_root");
        }
    }
    // Proof 10 and R1 rule 10: Classic is Limited.
    if mode == ServerMode::Classic {
        detail.push("ServerMode Classic: Audit is Limited at best (R1 rule 10)".to_owned());
        proven = false;
    }
    if !not_eval.is_empty() {
        not_eval.sort_unstable();
        not_eval.dedup();
        notes.add(
            TargetNote::new(NoteCode::AuditTraceConfigNotEvaluated)
                .with_labels(not_eval.iter().map(|l| NoteLabel::firebird(l))),
        );
        proven = false;
    }
    let now = SystemTime::now();
    let recent = |t: Option<SystemTime>, d: Duration| {
        t.is_some_and(|t| now.duration_since(t).unwrap_or_default() < d)
    };
    state.with(target_id, |t| {
        let probe_ok = recent(t.stream.probe_seen, PROBE_WINDOW);
        if t.stream
            .last_ambiguous
            .is_some_and(|a| recent(Some(a), DAY))
        {
            let mut n =
                TargetNote::new(NoteCode::AuditLogRecordsAmbiguous).with_count(t.stream.ambiguous);
            // R1 rule 2: stopped more than 60 s within one hour.
            if t.stream.stalled(now) {
                n = n.with_labels([NoteLabel::firebird("run_confirmation_stalled")]);
            }
            notes.add(n);
            proven = false;
        }
        if recent(t.stream.gap, DAY) {
            notes.add(TargetNote::new(NoteCode::AuditRecordsDropped));
            proven = false;
        }
        let fresh = recent(t.stream.last_record, DAY);
        if !fresh {
            notes.add(TargetNote::new(NoteCode::AuditPartialPendingFirstRecord));
        }
        count_restores(&t.dbs, &mut dbs);
        t.dbs = dbs;
        t.aliases = aliases.clone();
        t.proof11 = proof11;
        t.superserver = mode == ServerMode::Super;
        t.max_sql_length = max_sql;
        if let Some((pid, start)) = run {
            t.run = Some(Run {
                pid,
                start: start.map(|(ticks, _)| ticks),
            });
            t.run_read_at = Some(input.started);
        }
        t.probe_sent = Some(now);
        t.generation += 1;
        if proven && probe_ok && fresh {
            AuditLevel::Partial
        } else if fresh {
            AuditLevel::Limited
        } else {
            AuditLevel::None
        }
    })
}

/// R1 rule 5: a restore is confirmed when a database's `DB_GUID` or
/// `MON$CREATION_DATE` differs from the last one a check of this process
/// read for it (both read). The count goes on from the previous check's
/// facts, and the last state read is kept across a check whose read
/// failed.
fn count_restores(previous: &[DbFacts], dbs: &mut [DbFacts]) {
    for d in dbs.iter_mut() {
        let prev = previous.iter().find(|p| p.attach == d.attach);
        let seen = prev.and_then(|p| p.restore_seen.clone());
        d.restores = prev.map_or(0, |p| p.restores);
        match (&seen, &d.state.restore) {
            (Some(a), Some(b)) if a != b => d.restores += 1,
            _ => {}
        }
        d.restore_seen = d.state.restore.clone().or(seen);
    }
}

/// What the stream needs of the last check for R1 rule 5, per declared
/// database (the order of [`settings`]'s).
pub(crate) fn restore_facts(state: &AuditState, id: &str) -> Vec<crate::stream::RestoreFacts> {
    state.with(id, |t| {
        t.dbs
            .iter()
            .map(|d| crate::stream::RestoreFacts {
                confirmed: d.restores,
                own_id: d.state.own_id,
            })
            .collect()
    })
}

/// The tailer's open check (ADR-0043 decision 5): on its own handle.
pub(crate) fn open_check(path: PathBuf) -> OpenCheck {
    Arc::new(move |f: &OpenedFile<'_>| {
        if f.path != path.as_path() {
            return Err(std::io::ErrorKind::InvalidInput);
        }
        crate::fsread::check_opened(f.path, f.meta).map_err(|r| match r {
            crate::fsread::Refusal::Writable => std::io::ErrorKind::PermissionDenied,
            _ => std::io::ErrorKind::InvalidInput,
        })
    })
}

/// What the last `check()` gives the stream: its settings, the classes of
/// each declared database, the run it read, its generation, and when it
/// started (the run's read time, R1 rule 2).
type CheckResult = (Settings, Vec<Classes>, Option<Run>, u64, Option<SystemTime>);

/// The stream's settings from the last `check()`.
fn settings(state: &AuditState, id: &str, account: &str, series: Series) -> CheckResult {
    state.with(id, |t| {
        let databases = t
            .dbs
            .iter()
            .map(|d| DeclaredNames {
                label: d.label.clone(),
                resolved: d.resolved.clone(),
                alias: (!d.attach.starts_with('/')).then(|| d.attach.clone()),
                excluded: d.excluded,
                attach: d.attach.clone(),
                read_at: d.read_at,
            })
            .collect();
        (
            Settings {
                databases,
                aliases: t.aliases.clone(),
                proof11: t.proof11,
                account: account.to_ascii_uppercase(),
                parse: ParseOptions {
                    max_sql_length: usize::try_from(t.max_sql_length).ok(),
                    series,
                },
                superserver: t.superserver,
            },
            t.dbs.iter().map(|d| d.catalog.clone()).collect(),
            t.run,
            t.generation,
            t.run_read_at,
        )
    })
}

/// How the trace log is split into lines: every line, empty ones
/// included. A record of the trace log ends with empty lines its grammar
/// requires (between the context lines and the statement, before the
/// per-table block, at its end): dropping them makes every statement
/// finish a [`crate::trace_log::Defect::Shape`] (found by the e2e job).
pub(crate) const FRAMING: Framing = Framing::LinesKeepingEmpty;

/// Starts an early `check()` of the stream's target; `false` when one is
/// running (R11 8d, R28 item 4).
pub(crate) type EarlyCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// At most one early check per target in this time (R11 8d).
const EARLY_CHECK_EVERY: Duration = Duration::from_secs(30);

/// The Audit stream of one target. Runs until the core drops it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn stream(
    state: Arc<AuditState>,
    ledger: Arc<crate::own::Ledger>,
    early: EarlyCheck,
    cfg: &AuditConfig,
    audit: &FirebirdAuditConfig,
    account: &str,
    series: Series,
    sink: &EventSink,
) -> Result<(), ConnectorError> {
    let id = cfg.target_id().to_owned();
    let (s, mut cats, run, mut generation, _) = settings(&state, &id, account, series);
    if s.databases.is_empty() {
        // No check has read the databases yet.
        return Err(ConnectorError::Target {
            engine: databastion_core::Engine::Firebird,
            code: FailureCode::Unsupported,
            engine_code: None,
        });
    }
    let ckpt = Checkpointer::open(
        cfg.checkpoint(crate::audit_ckpt::CHECKPOINT),
        cfg.counters(crate::audit_ckpt::LEDGER),
        &ledger,
    );
    let mut machine = Machine::new(s, ledger);
    machine.restore_baseline(&restore_facts(&state, &id));
    if let Some(c) = &ckpt {
        machine.enable_checkpoint(c.key());
    }
    let mut requests = EarlyRequests::default();
    let mut seen = Seen::default();
    if let Some(r) = run {
        machine.confirm_run(r);
    }
    let mut runner = Runner {
        log: audit.log.clone(),
        digests: ckpt
            .as_ref()
            .map(|c| cats.iter().map(|x| x.digest(&c.key())).collect())
            .unwrap_or_default(),
        ckpt,
        shed: 0,
        tailer: Tailer::new(audit.log.clone(), FRAMING, cfg.cursor(CURSOR))
            .with_open_check(open_check(audit.log.clone())),
        asm: Assembler::new(),
        record_start: None,
        file: None,
        last_growth: Instant::now(),
        reread_end: None,
        expect: state.with(&id, |t| t.stream.saved),
        reset: false,
        last_end: None,
        lost_in: None,
        ended: None,
        backlog: std::collections::VecDeque::new(),
        batch: None,
        stop: None,
        sample: None,
    };
    loop {
        // A new check: new names, classes, run.
        let (s, c, run, g, read_at) = settings(&state, &id, account, series);
        let mut verdict = None;
        if g != generation {
            generation = g;
            machine.reconfigure(s);
            // R1 rule 5: restores the check confirmed.
            machine.set_restore_facts(restore_facts(&state, &id));
            cats = c;
            if let Some(ck) = &runner.ckpt {
                let key = ck.key();
                runner.digests = cats.iter().map(|x| x.digest(&key)).collect();
            }
            if let Some(r) = run {
                machine.check_run(r);
            }
            // R1 rule 2: a check started after the stop confirms it (the
            // record's pid is the server's) or fails it.
            if let (Some(st), Some(r), Some(at)) = (runner.stop.as_ref(), run, read_at)
                && at >= st.wall
            {
                verdict = Some(r.pid == st.pid);
            }
        }
        if let Some(st) = runner.stop.as_mut() {
            let waited = st.since.elapsed();
            if verdict.is_none() && waited < crate::stream::STOP_LIMIT {
                // R1 rule 2: an immediate check, not merged with the early
                // checks; again until one starts (a check running since
                // before the stop does not confirm it).
                if !st.requested {
                    st.requested = early();
                }
                tokio::time::sleep(STOP_POLL).await;
                continue;
            }
            let pid = st.pid;
            let confirmed = verdict == Some(true);
            runner.stop = None;
            end_stop(&state, &id, &mut machine, pid, waited, confirmed);
        }
        // R5 item 4: the run's start time before each read cycle (and after
        // the read, `Runner::poll`); a pid that is gone or no longer a
        // Firebird server is a change too.
        runner.sample = run.filter(|r| r.start.is_some());
        if let Some(r) = runner.sample
            && let Some(start) = r.start
            && crate::fsread::process_start(r.pid).is_none_or(|(t, _)| t != start)
        {
            machine.start_time_changed();
        }
        let polled;
        (runner, machine, cats, polled) = poll_and_deliver(runner, machine, cats, sink).await?;
        // R1 rule 2: a stop asks for an immediate check at once; so does a
        // start-time change (R5 item 4).
        if let Some(st) = runner.stop.as_mut()
            && !st.requested
        {
            st.requested = early();
        }
        if std::mem::take(&mut machine.run_check_requested) && runner.stop.is_none() && !early() {
            machine.check_requested = true;
        }
        // R1 rule 5 (L3, L4): the ledger's evidence of a new database life
        // is used once the first poll has restored a checkpoint (or found
        // none), so a restore confirmed before this stream started is
        // applied now, not to the state this stream builds later.
        machine.apply_restores();
        let now = SystemTime::now();
        // Proofs 8 and 9 from this stream's deltas (review L2: a restarted
        // stream's counters start again at 0), and the gaps of proof 8
        // (review M4, L3).
        let c = machine.counts;
        let gaps = runner.tailer.rotations
            + runner.tailer.oversized
            + runner.tailer.malformed()
            + c.panics
            + u64::from(runner.reset);
        let probe = machine.probe_seen.take();
        report(&state, &id, &mut seen, &c, gaps, probe, now);
        // R28 item 4: view DDL asks for an early check, merged.
        if std::mem::take(&mut machine.check_requested) {
            requests.request(generation);
        }
        requests.serve(generation, Instant::now(), &*early);
        let more = match polled {
            Ok(more) => more,
            Err(_) => {
                state.note_stream(&id, |f| f.gap = Some(now));
                tokio::time::sleep(cfg.poll_interval()).await;
                continue;
            }
        };
        if let Some(c) = runner.ckpt.as_mut() {
            c.settle(sink.durable());
        }
        let held;
        let counts = (sink.submitted(), sink.durable());
        (runner, machine, held) = tokio::task::spawn_blocking(move || {
            let held = runner.commit(&machine, counts);
            runner.tailer.commit_from(&held);
            (runner, machine, held)
        })
        .await
        .map_err(|e| {
            // A panic of the blocking task is resumed (re-review L-D).
            let _ = databastion_core::resume_panic(e);
            ConnectorError::Target {
                engine: databastion_core::Engine::Firebird,
                code: FailureCode::Internal,
                engine_code: None,
            }
        })?;
        // Where the next stream must resume (review M4).
        let resume = held
            .first()
            .map(|(_, p)| (p.file, p.start))
            .or(runner.last_end);
        if resume.is_some() {
            state.note_stream(&id, |f| f.saved = resume);
        }
        if !more {
            tokio::time::sleep(cfg.poll_interval()).await;
        }
    }
}

/// One read cycle of the stream: the runner's poll on a blocking thread,
/// then every event it produced handed to the sink, and only then the
/// poll's result. The events go first also when the poll failed: a
/// rotation whose new file cannot be opened ends what the old file held
/// (its last record, pending fold groups) into the events, then fails
/// (security review H1 of #392); a caller that met the error first would
/// drop them.
async fn poll_and_deliver(
    runner: Runner,
    machine: Machine,
    cats: Vec<Classes>,
    sink: &EventSink,
) -> Result<(Runner, Machine, Vec<Classes>, Result<bool, TailError>), ConnectorError> {
    let (mut r, mut m, cats, out, keys, polled) = tokio::task::spawn_blocking(move || {
        let mut m = machine;
        let mut r = runner;
        let mut out = Vec::new();
        let cats_ref: Vec<&dyn Catalog> = cats.iter().map(|c| c as &dyn Catalog).collect();
        let polled = r.poll(&mut m, &cats_ref, &mut out);
        let keys = m.take_keys();
        (r, m, cats, out, keys, polled)
    })
    .await
    .map_err(|e| {
        // A panic of the blocking task is resumed (re-review L-D).
        let _ = databastion_core::resume_panic(e);
        ConnectorError::Target {
            engine: databastion_core::Engine::Firebird,
            code: FailureCode::Internal,
            engine_code: None,
        }
    })?;
    // Each event's position and the sink's count after it (R25 item 7:
    // a position is recorded as sent once the core has all its events
    // durably). Keys out of step with the events: none recorded.
    let aligned = keys.len() == out.len();
    let mut sent = Vec::with_capacity(out.len());
    for (i, (_db, ev)) in out.into_iter().enumerate() {
        sink.submit(ev).await?;
        let (k, step) = if aligned { keys[i] } else { (None, 0) };
        sent.push((k, sink.submitted(), step));
    }
    if let Some(c) = r.ckpt.as_mut() {
        c.sent(&sent, &m.held_keys(), m.take_suppressed());
        let shed = std::mem::take(&mut r.shed);
        if shed > 0 {
            c.shed(sink.submitted(), shed);
        }
    } else {
        let _ = m.take_suppressed();
    }
    Ok((r, m, cats, polled))
}

/// R1 rule 2: how often a stopped stream looks for its confirmation.
const STOP_POLL: Duration = Duration::from_millis(200);

/// R1 rule 2: a stop ended after `waited`, confirmed (the record's pid is
/// the server's: the run changes at that record) or not (the pid is
/// remembered and the cooldown starts). The stopped time is not reading
/// time; the metrics and the stream's facts count it.
fn end_stop(
    state: &AuditState,
    id: &str,
    machine: &mut Machine,
    pid: u32,
    waited: Duration,
    confirmed: bool,
) {
    machine.pause(waited);
    databastion_core::connector::count_firebird_stream_stopped(waited);
    if !confirmed {
        machine.confirmation_failed(pid, Instant::now());
        databastion_core::connector::count_firebird_run_confirmation_failed();
    }
    state.note_stream(id, |f| f.note_stop(waited, SystemTime::now()));
    tracing::info!(
        target_id = %id,
        confirmed,
        stopped_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
        "Firebird Audit stream: a record of a new server pid, run confirmation ended (R1 rule 2)"
    );
}

/// The merged early-check requests of one stream (R11 8d): a request is
/// served by an early check at most once per [`EARLY_CHECK_EVERY`], never
/// while a check runs, or by any newer check result (a new generation).
#[derive(Debug, Default)]
struct EarlyRequests {
    /// The check generation the pending request was made under.
    pending: Option<u64>,
    last: Option<Instant>,
}

impl EarlyRequests {
    fn request(&mut self, generation: u64) {
        self.pending.get_or_insert(generation);
    }

    fn serve(&mut self, generation: u64, now: Instant, start: &dyn Fn() -> bool) {
        let Some(g) = self.pending else {
            return;
        };
        if generation != g {
            // A newer check result serves it.
            self.pending = None;
            return;
        }
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < EARLY_CHECK_EVERY)
        {
            return;
        }
        if start() {
            self.last = Some(now);
            self.pending = None;
        }
    }
}

/// Reports this stream's progress for proofs 8 and 9: by delta from the
/// last report, so that a restarted stream (its counters at 0) still marks
/// new ambiguous records, new records and new gaps (review L2, M4).
fn report(
    state: &AuditState,
    id: &str,
    seen: &mut Seen,
    c: &crate::stream::Counts,
    gaps: u64,
    probe: Option<SystemTime>,
    now: SystemTime,
) {
    state.note_stream(id, |f| {
        if c.parsed_declared > seen.parsed {
            f.last_record = Some(now);
        }
        if c.ambiguous > seen.ambiguous {
            f.last_ambiguous = Some(now);
            f.ambiguous += c.ambiguous - seen.ambiguous;
        }
        if gaps > seen.gaps {
            f.gap = Some(now);
            f.gaps += gaps - seen.gaps;
        }
        if let Some(p) = probe {
            f.probe_seen = Some(p);
        }
    });
    *seen = Seen {
        parsed: c.parsed_declared,
        ambiguous: c.ambiguous,
        gaps,
    };
}

/// This stream's counters at the last report (review L2).
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    parsed: u64,
    ambiguous: u64,
    gaps: u64,
}

struct Runner {
    /// The log's path (its length at a restore).
    log: PathBuf,
    /// The parser checkpoint (`None` without a state directory or key).
    ckpt: Option<Checkpointer>,
    /// Per declared database, the digest of the current check's results
    /// ([`Classes::digest`]).
    digests: Vec<[u8; 32]>,
    /// Pending groups ended for the checkpoint's cap in this poll.
    shed: usize,
    tailer: Tailer,
    asm: Assembler,
    /// The log offset of the record in progress (held back).
    record_start: Option<u64>,
    /// The `(st_dev, st_ino)` of the file read last.
    file: Option<(u64, u64)>,
    last_growth: Instant,
    /// After a restart: the file and the end of what the previous reading
    /// had read. Records before it are emitted again (R39 (a)) and counted.
    reread_end: Option<((u64, u64), u64)>,
    /// Where the previous stream of this process saved its cursor: the
    /// first record read must start there, otherwise the cursor was reset
    /// (a gap, review M4).
    expect: Option<((u64, u64), u64)>,
    reset: bool,
    /// The file and end of the last line read.
    last_end: Option<((u64, u64), u64)>,
    /// A line the tailer skipped for its size at the end of a poll, in a
    /// file not read yet: the first record of that file lost a line.
    lost_in: Option<(u64, u64)>,
    /// The last file whose held records were ended ([`Self::end_file`]).
    ended: Option<(u64, u64)>,
    /// The lines of the last poll not yet handed (R1 rule 2: the stream
    /// stopped before one of them). Never more than one poll.
    backlog: std::collections::VecDeque<Line>,
    /// What the poll of the backlog's lines needs at its end.
    batch: Option<Batch>,
    /// R1 rule 2: the stream is stopped before the record at the head of
    /// the backlog (`record_start`), not persisted: a restart reads that
    /// record again and stops again if it must.
    stop: Option<Stop>,
    /// R5 item 4: the run whose start time is sampled after each read.
    sample: Option<Run>,
}

/// One line of a poll, with the files of the lines the tailer skipped
/// for their size just before it.
struct Line {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    pos: databastion_core::audit::tail::RecordPos,
    skipped: Vec<(u64, u64)>,
}

/// The end of a poll, once its lines are all handed.
#[derive(Debug, Clone)]
struct Batch {
    /// Lines skipped after the last line.
    trailing: Vec<(u64, u64)>,
    more: bool,
    /// Its events carry no position (a log reset in that poll).
    unkeyed: bool,
}

/// R1 rule 2: a stop before a record of a new pid.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stop {
    pub(crate) pid: u32,
    /// When it started (agent time, and wall time for the checks).
    since: Instant,
    wall: SystemTime,
    /// An immediate check was started.
    requested: bool,
}

impl Runner {
    fn poll(
        &mut self,
        m: &mut Machine,
        cats: &[&dyn Catalog],
        out: &mut Vec<crate::stream::Emitted>,
    ) -> Result<bool, TailError> {
        if cats.is_empty() {
            return Ok(false);
        }
        // R1 rule 2: stopped, nothing is read or judged until the run is
        // confirmed or the confirmation fails.
        if self.stop.is_some() {
            return Ok(false);
        }
        if self.backlog.is_empty() {
            self.read(m, out, cats)?;
        }
        let now = Instant::now();
        let Some(batch) = self.batch.clone() else {
            return Ok(false);
        };
        m.unkeyed = batch.unkeyed;
        if self.hand_lines(m, now, cats, out) {
            // Stopped before a record (R1 rule 2): the rest waits.
            m.unkeyed = false;
            return Ok(false);
        }
        self.batch = None;
        for f in batch.trailing {
            if Some(f) == self.file {
                self.asm.lose_line();
            } else {
                self.lost_in = Some(f);
            }
        }
        // The file being read was ended by a rotation whose new file has
        // given no line yet (or cannot be opened): what it holds ends now
        // (security review M1 of #392).
        if let Some(f) = self.tailer.take_ended() {
            self.end_file(f, m, now, cats, out);
        }
        // A stable end of file: the record in progress is complete.
        if !batch.more && now.duration_since(self.last_growth) >= STABLE_EOF {
            let done = self.asm.flush();
            let rs = self.record_start.unwrap_or(0);
            self.hand(m, done, rs, now, cats, out);
            self.record_start = None;
        }
        // R25 item 9: the checkpoint would pass its cap: the oldest pending
        // groups end (their outputs sent before a checkpoint without them).
        if let Some(budget) = self.ckpt.as_mut().and_then(Checkpointer::take_shed_target) {
            self.shed += m.shed_groups(budget, now, cats, out);
        }
        m.expire(now, cats, out);
        m.unkeyed = false;
        // The suppressed positions the read has passed (review M1).
        if let Some(f) = self.file {
            let at = self
                .record_start
                .or(self.last_end.filter(|(lf, _)| *lf == f).map(|(_, e)| e));
            if let Some(at) = at {
                m.prune_suppress(f, at);
            }
        }
        if std::mem::take(&mut m.suppress_cleared)
            && let Some(c) = self.ckpt.as_mut()
        {
            c.forget_restored();
        }
        Ok(batch.more)
    }

    /// One read of the tailer: its lines become the backlog.
    fn read(
        &mut self,
        m: &mut Machine,
        out: &mut Vec<crate::stream::Emitted>,
        cats: &[&dyn Catalog],
    ) -> Result<(), TailError> {
        let rotations = self.tailer.rotations;
        let polled = match self.tailer.poll() {
            Ok(p) => p,
            Err(e) => {
                // A rotation whose new file cannot be opened still ended
                // the old one (security review M1 of #392).
                let now = Instant::now();
                if let Some(f) = self.tailer.take_ended() {
                    self.end_file(f, m, now, cats, out);
                }
                return Err(e);
            }
        };
        // R5 item 4: the start time after the read too. A restart during
        // the read puts every record of this poll in the interval:
        // ambiguous until the next confirmation.
        if let Some(r) = self.sample
            && let Some(start) = r.start
            && crate::fsread::process_start(r.pid).is_none_or(|(t, _)| t != start)
        {
            m.start_time_changed();
        }
        // R39 (a): the re-read region (known once the file is open); its end
        // is kept for the count.
        if let Some(r) = self.tailer.take_replay() {
            self.reread_end = Some((r.file, r.replay.end));
        }
        let now = Instant::now();
        // The checkpoint, restored only when bound to exactly the position
        // the tailer resumed from (before any record is handed).
        if let Some(c) = self.ckpt.as_mut() {
            let resumed = self.tailer.take_resumed();
            // The log's length now (the re-read invalidation's end: the
            // records written while the agent was stopped included).
            let len = resumed.and_then(|r| {
                use std::os::unix::fs::MetadataExt as _;
                std::fs::symlink_metadata(&self.log)
                    .ok()
                    .filter(|md| (md.dev(), md.ino()) == r.file)
                    .map(|md| md.len())
            });
            c.on_open(resumed, m, &self.digests, len, now);
        }
        // A log reset in this poll (a truncation, a rotation; review M1): no
        // position read before it is trusted any more, and this poll's
        // events carry none (an inode can be reused, an offset can name new
        // content).
        let reset = self.tailer.rotations != rotations;
        if reset && let Some(c) = self.ckpt.as_mut() {
            m.reset_positions();
            c.reset();
        }
        if !polled.records.is_empty() {
            self.last_growth = now;
        }
        // Lines the tailer skipped for their size (longer than 1 MiB): the
        // record they belong to is made ambiguous, never parsed without
        // them.
        let skipped_at = |k: usize| {
            polled
                .skipped
                .iter()
                .filter(move |(i, _)| *i == k)
                .map(|(_, f)| *f)
                .collect::<Vec<_>>()
        };
        let n = polled.records.len();
        let trailing = skipped_at(n);
        let skips: Vec<Vec<(u64, u64)>> = (0..n).map(skipped_at).collect();
        for ((bytes, pos), skipped) in polled.records.into_iter().zip(polled.positions).zip(skips) {
            self.backlog.push_back(Line {
                bytes,
                pos,
                skipped,
            });
        }
        self.batch = Some(Batch {
            trailing,
            more: polled.more,
            unkeyed: reset,
        });
        Ok(())
    }

    /// Hands the backlog's lines to the assembler and the machine; `true`
    /// when the stream stopped before a record (R1 rule 2: a new pid), the
    /// record in progress before it handed, its line kept at the backlog's
    /// head and the position held back to it.
    fn hand_lines(
        &mut self,
        m: &mut Machine,
        now: Instant,
        cats: &[&dyn Catalog],
        out: &mut Vec<crate::stream::Emitted>,
    ) -> bool {
        while let Some(mut l) = self.backlog.pop_front() {
            let line = l.bytes.strip_suffix(b"\n").unwrap_or(&l.bytes);
            let pos = l.pos;
            let start = pos.start;
            let before = self.file;
            let skipped = std::mem::take(&mut l.skipped);
            if skipped.iter().any(|f| Some(*f) == before) {
                self.asm.lose_line();
            }
            if let Some(e) = self.expect.take()
                && e != (pos.file, pos.start)
            {
                self.reset = true;
            }
            let last_end = self.last_end;
            self.last_end = Some((pos.file, pos.end));
            if self.file != Some(pos.file) {
                if let Some(old) = self.file {
                    // A rotation (review M3): the old file ended.
                    self.end_file(old, m, now, cats, out);
                }
                self.file = Some(pos.file);
                m.set_file(pos.file);
                match self.lost_in.take() {
                    Some(f) if f == pos.file => self.asm.lose_line(),
                    // A line skipped in a file of which no line was read
                    // (security review L2 of #392): a record lost whole.
                    Some(_) => m.unreadable(now, cats, out),
                    None => {}
                }
            }
            if skipped.iter().any(|f| Some(*f) != before) {
                self.asm.lose_line();
            }
            if let Some(h) = header(line) {
                // R1 rule 2: a record of a new pid stops the stream before
                // it. The record in progress is complete (this header ends
                // it).
                if m.stop_wanted(&h, now) {
                    let done = self.asm.flush();
                    let rs = self.record_start.unwrap_or(start);
                    self.hand(m, done, rs, now, cats, out);
                    self.record_start = Some(start);
                    self.last_end = last_end;
                    self.backlog.push_front(l);
                    self.stop = Some(Stop {
                        pid: h.pid,
                        since: Instant::now(),
                        wall: SystemTime::now(),
                        requested: false,
                    });
                    tracing::info!(
                        "Firebird Audit stream stopped before a record of a new server pid; \
                         confirming the run (R1 rule 2)"
                    );
                    return true;
                }
                // The record in progress ends here.
                let done = self.asm.push_line(line);
                let rs = self.record_start.unwrap_or(start);
                self.hand(m, done, rs, now, cats, out);
                self.record_start = Some(start);
                m.set_file(pos.file);
            } else {
                // Only a header ends a record (`push_line` returns
                // nothing for a body line).
                let done = self.asm.push_line(line);
                self.hand(m, done, start, now, cats, out);
            }
        }
        false
    }

    /// R1 rule 2: the stop in force, if any.
    #[cfg(test)]
    pub(crate) fn stop_for_tests(&self) -> Option<Stop> {
        self.stop
    }

    /// Writes the checkpoint (when the stream has one) and gives the
    /// position the cursor is saved at: the checkpoint's, or without one
    /// the held-back position ([`Self::held`]).
    fn commit(
        &mut self,
        m: &Machine,
        sink: (u64, Option<u64>),
    ) -> Vec<(u64, databastion_core::audit::tail::RecordPos)> {
        let open = self.tailer.open_file();
        // The state is that of the read position: the record in progress,
        // or the end of the last line read; after a rotation that ended the
        // old file, the start of the new one (nothing of it read yet).
        let live = match (self.file, self.record_start) {
            (Some(f), _) if open != Some(f) && self.ended == Some(f) => open.map(|o| (o, 0)),
            (Some(f), Some(start)) => Some((f, start)),
            (Some(f), None) => self.last_end.filter(|(lf, _)| *lf == f),
            (None, _) => None,
        };
        let Some(c) = self.ckpt.as_mut() else {
            return self.held(m);
        };
        let read = self.last_end;
        match c.commit(m, live, open, sink, (&self.digests, read), Instant::now()) {
            Commit::At(file, start) => vec![(
                0,
                databastion_core::audit::tail::RecordPos {
                    file,
                    start,
                    end: start,
                },
            )],
            Commit::Fallback(hold) => {
                let mut held = self.held(m);
                if let (Some(start), Some(file)) = (hold, open) {
                    held.push((
                        0,
                        databastion_core::audit::tail::RecordPos {
                            file,
                            start,
                            end: start,
                        },
                    ));
                }
                held
            }
        }
    }

    /// The file `f` ended (rotated away, read to its end): if it is the
    /// file being read, its last record is complete and what it still
    /// holds (pending fold groups, held records) ends now, as R25 item 3
    /// says, since a held position in a rotated file cannot be re-read
    /// after a restart. Once per file: the next file's first line finds
    /// nothing left.
    fn end_file(
        &mut self,
        f: (u64, u64),
        m: &mut Machine,
        now: Instant,
        cats: &[&dyn Catalog],
        out: &mut Vec<crate::stream::Emitted>,
    ) {
        if self.file != Some(f) || self.ended == Some(f) {
            return;
        }
        let done = self.asm.flush();
        let rs = self.record_start.unwrap_or(0);
        self.hand(m, done, rs, now, cats, out);
        self.record_start = None;
        m.end_all(now, cats, out);
        self.ended = Some(f);
    }

    /// The position the cursor may be saved at: the first record of the
    /// oldest pending group or the record in progress (R25 item 7).
    fn held(&self, m: &Machine) -> Vec<(u64, databastion_core::audit::tail::RecordPos)> {
        let held = m.held_from().into_iter().chain(self.record_start).min();
        match (held, self.file) {
            (Some(start), Some(file)) => vec![(
                0,
                databastion_core::audit::tail::RecordPos {
                    file,
                    start,
                    end: start,
                },
            )],
            _ => Vec::new(),
        }
    }

    /// Hands an assembled record to the machine: a record is judged; an
    /// oversized record or orphan lines are ambiguous (review H1).
    fn hand(
        &self,
        m: &mut Machine,
        done: Option<Assembled>,
        start: u64,
        now: Instant,
        cats: &[&dyn Catalog],
        out: &mut Vec<crate::stream::Emitted>,
    ) {
        match done {
            Some(Assembled::Record(raw)) => {
                self.count_reread(m, start);
                m.push(&raw, start, now, cats, out);
            }
            Some(Assembled::Oversized(_) | Assembled::Orphan) => {
                self.count_reread(m, start);
                m.unreadable_at(start, now, cats, out);
            }
            None => {}
        }
    }

    fn count_reread(&self, m: &mut Machine, start: u64) {
        if self
            .reread_end
            .is_some_and(|(f, e)| self.file == Some(f) && start < e)
        {
            m.counts.reread += 1;
        }
    }
}

#[cfg(test)]
#[path = "audit_ckpt_tests.rs"]
mod ckpt_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn test_settings() -> Settings {
        Settings {
            databases: vec![DeclaredNames {
                label: "app".to_owned(),
                resolved: Some("/var/lib/firebird/data/app.fdb".to_owned()),
                alias: None,
                excluded: false,
                attach: "/var/lib/firebird/data/app.fdb".to_owned(),
                read_at: None,
            }],
            aliases: Some(AliasMap::default()),
            proof11: true,
            account: "DATABASTION_AGENT".to_owned(),
            parse: ParseOptions {
                max_sql_length: Some(65_000),
                series: Series::V5,
            },
            superserver: true,
        }
    }

    fn runner(
        log: &std::path::Path,
        store: Option<databastion_core::audit::CursorStore>,
    ) -> Runner {
        Runner {
            log: log.to_path_buf(),
            ckpt: None,
            digests: Vec::new(),
            shed: 0,
            tailer: Tailer::new(log.to_path_buf(), FRAMING, store)
                .with_open_check(open_check(log.to_path_buf())),
            asm: Assembler::new(),
            record_start: None,
            file: None,
            last_growth: Instant::now(),
            reread_end: None,
            expect: None,
            reset: false,
            last_end: None,
            lost_in: None,
            ended: None,
            backlog: std::collections::VecDeque::new(),
            batch: None,
            stop: None,
            sample: None,
        }
    }

    fn append(log: &std::path::Path, text: &str) {
        let mut f = std::fs::OpenOptions::new().append(true).open(log).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn objects(out: &[crate::stream::Emitted]) -> Vec<String> {
        out.iter()
            .flat_map(|(_, e)| e.objects().iter().map(|o| o.object().as_str().to_owned()))
            .collect()
    }

    /// One reading session: polls (no stable end of file), then saves the
    /// cursor as the stream does; the process then stops.
    fn session(log: &std::path::Path, dir: &std::path::Path) -> (Vec<crate::stream::Emitted>, u64) {
        let store = databastion_core::audit::CursorStore::new(dir, "t", "fb");
        let mut r = runner(log, store);
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        r.tailer.commit_from(&r.held(&m));
        (out, m.counts.reread)
    }

    fn temp(name: &str) -> std::path::PathBuf {
        databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
        crate::fsread::allow_own_files_for_tests();
        let dir = std::env::temp_dir().join(format!("fb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// R1 rule 2: a stream of a confirmed run of pid 24 that has read an
    /// attachment and a read, then meets a record of pid 99: the polls up
    /// to it, with what they emitted.
    fn stopped_at_a_new_pid(
        name: &str,
    ) -> (
        std::path::PathBuf,
        Runner,
        Machine,
        Classes,
        Vec<crate::stream::Emitted>,
        u64,
    ) {
        use crate::stream_tests::{APP, attach, select};
        let dir = temp(name);
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let mut r = runner(&log, None);
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        m.confirm_run(Run {
            pid: 24,
            start: Some(1000),
        });
        let classes = Classes::default();
        let mut out = Vec::new();
        {
            let cats: Vec<&dyn Catalog> = vec![&classes];
            while r.poll(&mut m, &cats, &mut out).unwrap() {}
        }
        let old = format!(
            "{}{}",
            attach("24:0x7f0000000100", 3, APP),
            select("24:0x7f0000000100", 3, 5, APP, "CUSTOMERS", 2)
        );
        let new_run = format!(
            "{}{}",
            attach("99:0x7f0000000900", 9, APP),
            select("99:0x7f0000000900", 9, 11, APP, "PAYROLL", 3)
        );
        // A last record, so the new run's read is complete.
        let tail = attach("99:0x7f0000000990", 10, APP);
        append(&log, &format!("{old}{new_run}{tail}"));
        {
            let cats: Vec<&dyn Catalog> = vec![&classes];
            while r.poll(&mut m, &cats, &mut out).unwrap() {}
        }
        (dir, r, m, classes, out, old.len() as u64)
    }

    fn poll_all(r: &mut Runner, m: &mut Machine, classes: &Classes) -> Vec<crate::stream::Emitted> {
        let cats: Vec<&dyn Catalog> = vec![classes];
        let mut out = Vec::new();
        while r.poll(m, &cats, &mut out).unwrap() {}
        out
    }

    /// R1 rule 2, the stop: the record of a new pid stops the stream
    /// before it, without advancing its position (the cursor is held at
    /// its start) and nothing of the new pid is judged; the records before
    /// it are. While stopped, nothing more is read.
    #[test]
    fn a_new_pid_stops_the_stream_before_its_record() {
        let (dir, mut r, mut m, classes, out, old_len) = stopped_at_a_new_pid("stop");
        assert!(objects(&out).contains(&"CUSTOMERS".to_owned()));
        assert!(!objects(&out).contains(&"PAYROLL".to_owned()));
        assert_eq!(m.counts.ambiguous, 0, "{:?}", m.why);
        let st = r.stop_for_tests().expect("stopped");
        assert_eq!(st.pid, 99);
        // The position is held at the new pid's first record (its
        // `TRACE_INIT`), the end of the old run's records.
        let held = r.held(&m);
        assert_eq!(held.first().map(|(_, p)| p.start), Some(old_len));
        append(
            &r.log.clone(),
            &crate::stream_tests::select(
                "24:0x7f0000000100",
                3,
                6,
                crate::stream_tests::APP,
                "LEDGER",
                1,
            ),
        );
        assert!(
            poll_all(&mut r, &mut m, &classes).is_empty(),
            "nothing read while stopped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R1 rule 2, a confirmed change: a check started after the stop reads
    /// pid 99; the run changes at that record, the old run's bindings end,
    /// and the new run's records are judged normally (no ambiguous
    /// record). Before the stop existed they were all ambiguous.
    #[test]
    fn a_confirmed_new_pid_starts_a_run_at_its_record() {
        let (dir, mut r, mut m, classes, _, _) = stopped_at_a_new_pid("confirmed");
        let state = AuditState::default();
        m.check_run(Run {
            pid: 99,
            start: Some(2000),
        });
        r.stop = None;
        end_stop(&state, "t", &mut m, 99, Duration::from_millis(300), true);
        let out = poll_all(&mut r, &mut m, &classes);
        assert!(
            objects(&out).contains(&"PAYROLL".to_owned()),
            "{:?}",
            objects(&out)
        );
        assert_eq!(m.counts.ambiguous, 0, "{:?}", m.why);
        assert_eq!(m.run_for_tests().map(|x| x.pid), Some(99));
        assert!(m.failed_pids_for_tests().is_empty());
        // A record of the ended run is a new pid like any other: a stop.
        append(
            &r.log.clone(),
            &crate::stream_tests::select(
                "24:0x7f0000000100",
                3,
                6,
                crate::stream_tests::APP,
                "LEDGER",
                1,
            ),
        );
        let _ = poll_all(&mut r, &mut m, &classes);
        assert_eq!(r.stop_for_tests().map(|s| s.pid), Some(24));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R1 rule 2, a failed confirmation (the check read the old run, or
    /// none answered within 60 s): the new pid's records are ambiguous
    /// (always reported, `*`), the pid is remembered and its next records
    /// are ambiguous with no stop; in the 10-minute cooldown any other new
    /// pid is ambiguous with no stop too.
    #[test]
    fn a_failed_confirmation_makes_the_pid_ambiguous_and_starts_the_cooldown() {
        use crate::stream_tests::{APP, select};
        let (dir, mut r, mut m, classes, _, _) = stopped_at_a_new_pid("failed");
        let state = AuditState::default();
        r.stop = None;
        end_stop(&state, "t", &mut m, 99, Duration::from_secs(60), false);
        let out = poll_all(&mut r, &mut m, &classes);
        assert!(m.counts.ambiguous >= 2, "{:?}", m.why);
        let payroll: Vec<_> = out
            .iter()
            .filter(|(_, e)| e.objects().iter().any(|o| o.object().as_str() == "PAYROLL"))
            .collect();
        assert!(!payroll.is_empty() && payroll.iter().all(|(_, e)| e.always_report()));
        assert_eq!(m.failed_pids_for_tests(), &[99]);
        assert_eq!(m.run_for_tests().map(|x| x.pid), Some(24));
        append(
            &r.log.clone(),
            &format!(
                "{}{}",
                select("99:0x7f0000000900", 9, 12, APP, "PAYROLL", 1),
                select("98:0x7f0000000980", 8, 13, APP, "LEDGER", 1)
            ),
        );
        let before = m.counts.ambiguous;
        let _ = poll_all(&mut r, &mut m, &classes);
        assert!(
            r.stop_for_tests().is_none(),
            "no stop: remembered, then cooldown"
        );
        assert!(m.counts.ambiguous >= before + 2);
        // The stalled label's facts: 60 s within the hour is not past it.
        state.with("t", |t| assert!(!t.stream.stalled(SystemTime::now())));
        end_stop(&state, "t", &mut m, 97, Duration::from_secs(5), false);
        state.with("t", |t| assert!(t.stream.stalled(SystemTime::now())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R1 rule 2: a run a check read before the stream reaches its records
    /// is pending; the old run's remaining records are judged as the old
    /// run's, and the run changes at the first record of the new pid with
    /// no stop. Before the first check (a provisional run, R40 item 4) a
    /// new pid never stops the stream.
    #[test]
    fn a_pending_run_changes_at_its_first_record_without_a_stop() {
        use crate::stream_tests::{APP, attach, select};
        let dir = temp("pending");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let mut r = runner(&log, None);
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        m.confirm_run(Run {
            pid: 24,
            start: Some(1000),
        });
        let classes = Classes::default();
        let _ = poll_all(&mut r, &mut m, &classes);
        m.check_run(Run {
            pid: 99,
            start: Some(2000),
        });
        append(
            &log,
            &format!(
                "{}{}{}{}{}",
                attach("24:0x7f0000000100", 3, APP),
                select("24:0x7f0000000100", 3, 5, APP, "CUSTOMERS", 2),
                attach("99:0x7f0000000900", 9, APP),
                select("99:0x7f0000000900", 9, 11, APP, "PAYROLL", 3),
                attach("99:0x7f0000000990", 10, APP)
            ),
        );
        let out = poll_all(&mut r, &mut m, &classes);
        assert!(r.stop_for_tests().is_none());
        assert_eq!(m.counts.ambiguous, 0, "{:?}", m.why);
        assert!(objects(&out).contains(&"CUSTOMERS".to_owned()));
        assert!(objects(&out).contains(&"PAYROLL".to_owned()));
        assert_eq!(m.run_for_tests().map(|x| x.pid), Some(99));
        // Provisional: never a stop.
        let mut p = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let mut r2 = runner(&log, None);
        let _ = poll_all(&mut r2, &mut p, &classes);
        append(
            &log,
            &format!(
                "{}{}",
                attach("24:0x7f0000000110", 4, APP),
                attach("77:0x7f0000000770", 5, APP)
            ),
        );
        let _ = poll_all(&mut r2, &mut p, &classes);
        assert!(r2.stop_for_tests().is_none());
        assert!(p.counts.ambiguous >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R1 rule 2 (security review L-b): past 64 remembered pids, every new
    /// pid is ambiguous with no stop for the rest of the run; stopped time
    /// is not reading time (a split window outlives the stop).
    #[test]
    fn remembered_pids_are_bounded_and_stops_are_not_reading_time() {
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        m.confirm_run(Run {
            pid: 24,
            start: Some(1000),
        });
        let h = |pid: u32| crate::trace_log::Header {
            time: crate::trace_log::LogTime {
                year: 2026,
                month: 10,
                day: 30,
                hour: 15,
                minute: 22,
                second: 38,
                frac: 0,
            },
            pid,
            address: 1,
            event: crate::trace_log::Event::AttachDatabase,
            outcome: crate::trace_log::Outcome::Ok,
            at: None,
        };
        let t0 = Instant::now();
        let later = t0 + crate::stream::STOP_COOLDOWN + Duration::from_secs(1);
        assert!(!m.stop_wanted(&h(24), t0));
        assert!(m.stop_wanted(&h(100), t0));
        for pid in 100..164 {
            m.confirmation_failed(pid, t0);
        }
        assert!(!m.stop_wanted(&h(100), later), "remembered");
        assert!(!m.stop_wanted(&h(500), later), "past 64 remembered pids");
        let mut q = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        q.confirm_run(Run {
            pid: 24,
            start: Some(1000),
        });
        q.confirmation_failed(100, t0);
        assert!(
            !q.stop_wanted(&h(101), t0 + Duration::from_secs(10)),
            "cooldown"
        );
        assert!(q.stop_wanted(&h(101), later), "after the cooldown");
        assert!(q.window_for_tests(t0).is_none());
        q.open_window_for_tests(t0);
        q.pause(Duration::from_secs(50));
        assert!(
            q.window_for_tests(t0 + Duration::from_secs(100)).is_some(),
            "paused"
        );
        assert!(q.window_for_tests(t0 + Duration::from_secs(111)).is_none());
    }

    /// R1 rule 2 against a real server (`dev/firebird/it.sh`): the main
    /// server restarted under another pid, then an isql workload. The log
    /// written from just before the restart (`FIREBIRD_IT_RUN_CHANGE_LOG`)
    /// is read by a stream confirmed on the old pid
    /// (`FIREBIRD_IT_RUN_OLD_PID`): it stops at the first record of the
    /// new pid; the server pid the agent's own attachment reads (as
    /// `check()` does) is that record's; with it the run changes there and
    /// no record of the new run is ambiguous. Without the confirmation
    /// (the failed path), they are.
    #[tokio::test]
    #[allow(clippy::print_stderr)]
    async fn it_run_change() {
        let (Ok(tail), Ok(old)) = (
            std::env::var("FIREBIRD_IT_RUN_CHANGE_LOG"),
            std::env::var("FIREBIRD_IT_RUN_OLD_PID"),
        ) else {
            return;
        };
        let old: u32 = old.trim().parse().unwrap();
        let bytes = std::fs::read(&tail).unwrap();
        let names = |label: &str, path: &str| DeclaredNames {
            label: label.to_owned(),
            resolved: Some(path.to_owned()),
            alias: None,
            excluded: false,
            attach: path.to_owned(),
            read_at: None,
        };
        let settings = || Settings {
            databases: vec![
                names("app", "/var/lib/firebird/data/app.fdb"),
                names("crm", "/var/lib/firebird/data/crm.fdb"),
            ],
            aliases: Some(AliasMap::default()),
            proof11: true,
            account: "DATABASTION_AGENT".to_owned(),
            parse: ParseOptions {
                max_sql_length: Some(65_000),
                series: if std::env::var("FIREBIRD_IT_MAJOR").as_deref() == Ok("4") {
                    Series::V4
                } else {
                    Series::V5
                },
            },
            superserver: true,
        };
        // The pid the server gives the agent's own attachment.
        let t = databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /tmp, targets: [{{id: fb-it, \
             engine: firebird, host: 127.0.0.1, port: {}, account: DATABASTION_AGENT, \
             secret: {{file: \"{}\"}}, firebird: {{peer_uid: 84, \
             databases: [{{name: app, attach: \"/var/lib/firebird/data/app.fdb\"}}]}}}}]}}",
            std::env::var("FIREBIRD_PORT").unwrap(),
            std::env::var("FIREBIRD_IT_AGENT_PASSWORD_FILE").unwrap(),
        ))
        .unwrap()
        .targets
        .remove(0);
        let endpoint = crate::conn::Endpoint::of(&t).unwrap();
        let password = t.secret.read().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut s = crate::conn::connect(
            &endpoint,
            password.as_bytes(),
            "/var/lib/firebird/data/app.fdb",
            deadline,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        crate::check::prepare(&mut s, false, deadline)
            .await
            .unwrap();
        s.close().await;
        let server_pid = crate::own::ledger_for(endpoint.addr).server_pid().unwrap();
        eprintln!("[measure] run change: old pid {old}, server pid now {server_pid}");
        assert_ne!(server_pid, old, "the restart gave the server another pid");
        for confirm in [true, false] {
            let dir = temp(if confirm {
                "it-run-ok"
            } else {
                "it-run-failed"
            });
            let log = dir.join("audit.log");
            std::fs::write(&log, b"").unwrap();
            let mut r = runner(&log, None);
            let mut m = Machine::new(settings(), Arc::new(crate::own::Ledger::default()));
            m.confirm_run(Run {
                pid: old,
                start: Some(1),
            });
            let classes = Classes::default();
            let _ = poll_all(&mut r, &mut m, &classes);
            append(&log, &String::from_utf8_lossy(&bytes));
            let mut out = poll_all(&mut r, &mut m, &classes);
            let st = r.stop_for_tests().expect("stopped at the new pid");
            assert_eq!(st.pid, server_pid, "the record's pid is the server's");
            let before = m.counts.ambiguous;
            let state = AuditState::default();
            if confirm {
                m.check_run(Run {
                    pid: server_pid,
                    start: Some(2),
                });
            }
            r.stop = None;
            end_stop(
                &state,
                "t",
                &mut m,
                st.pid,
                Duration::from_millis(10),
                confirm,
            );
            out.extend(poll_all(&mut r, &mut m, &classes));
            std::thread::sleep(STABLE_EOF + Duration::from_millis(200));
            out.extend(poll_all(&mut r, &mut m, &classes));
            let after = m.counts.ambiguous - before;
            eprintln!(
                "[measure] run change (confirmed {confirm}): old-run records ambiguous {before}, \
                 new-run records ambiguous {after}, events {}, run {:?}",
                out.len(),
                m.run_for_tests().map(|x| x.pid)
            );
            assert!(
                objects(&out).contains(&"CUSTOMERS".to_owned()),
                "{:?}",
                objects(&out)
            );
            if confirm {
                assert_eq!(after, 0, "{:?}", m.why);
                assert_eq!(m.run_for_tests().map(|x| x.pid), Some(server_pid));
                assert_eq!(m.counts.own_not_matched, 0);
            } else {
                assert!(after > 0);
                assert_eq!(m.failed_pids_for_tests(), &[server_pid]);
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// R39 (a) test 1, review M1 (1): the record in progress when the agent stops
    /// (the cursor saved before it) is read again after the restart and
    /// its event sent; before, it lay inside the re-read region and was
    /// dropped as a replay: one lost read per restart.
    #[test]
    fn a_restart_mid_record_sends_the_record_in_progress() {
        use crate::stream_tests::{attach, select};
        let dir = temp("mid");
        let log = dir.join("audit.log");
        let a = "24:0x7f0000000100";
        let b = "24:0x7f0000000200";
        let full = select(b, 4, 7, crate::stream_tests::APP, "PAYROLL", 3);
        // The second attachment's read is being written when the agent
        // stops: its header and part of its body are in the file.
        let cut = full.len() / 2;
        // A first start reads from the end: the stream starts on an
        // empty log.
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        append(
            &log,
            &format!(
                "{}{}{}{}",
                attach(a, 3, crate::stream_tests::APP),
                select(a, 3, 5, crate::stream_tests::APP, "CUSTOMERS", 2),
                attach(b, 4, crate::stream_tests::APP),
                &full[..cut]
            ),
        );
        let (first, _) = session(&log, &dir);
        assert!(objects(&first).contains(&"CUSTOMERS".to_owned()));
        assert!(!objects(&first).contains(&"PAYROLL".to_owned()));
        // The server finishes the record; a new record follows.
        append(&log, &full[cut..]);
        append(
            &log,
            &attach("24:0x7f0000000300", 5, crate::stream_tests::APP),
        );
        let (second, reread) = session(&log, &dir);
        assert!(reread > 0, "the re-read region was read again");
        assert!(
            objects(&second).contains(&"PAYROLL".to_owned()),
            "{:?}",
            objects(&second)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `a`'s transaction 5 starts, then a procedure record of it pends
    /// (block-less, or with a block naming `SECRETS`).
    fn pending_routine(block: bool) -> String {
        use crate::stream_tests::{APP, HEAD};
        let a = "24:0x7f0000000100";
        let ctx = format!(
            "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
        );
        let blk = if block {
            format!(
                "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n",
                "Table",
                "*".repeat(115),
                "SECRETS",
                5,
                ""
            )
        } else {
            String::new()
        };
        format!(
            "{HEAD} ({a}) START_TRANSACTION\n{ctx}\n{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n{ctx}\nProcedure P1:\n      0 ms, 3 fetch(es)\n{blk}\n"
        )
    }

    /// Writes `records` after a first start on an empty log, reads them
    /// in one session, then restarts on the unchanged log: both sessions'
    /// events.
    fn restart_over(
        name: &str,
        records: &str,
    ) -> (
        Vec<crate::stream::Emitted>,
        Vec<crate::stream::Emitted>,
        u64,
    ) {
        let dir = temp(name);
        let log = dir.join("audit.log");
        // A first start reads from the end: the stream starts on an
        // empty log.
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        append(&log, records);
        let (first, _) = session(&log, &dir);
        let (second, reread) = session(&log, &dir);
        let _ = std::fs::remove_dir_all(&dir);
        (first, second, reread)
    }

    /// R39 (a) test 2 (review M1 (2)): a restart during a block-less hold,
    /// with another binding's read held behind it: the held read is sent
    /// after the restart.
    #[test]
    fn a_restart_during_a_block_less_hold_sends_the_held_records() {
        use crate::stream_tests::{APP, attach, select};
        let b = "24:0x7f0000000200";
        let (first, second, reread) = restart_over(
            "hold",
            &format!(
                "{}{}{}{}{}",
                attach("24:0x7f0000000100", 3, APP),
                attach(b, 4, APP),
                pending_routine(false),
                select(b, 4, 7, APP, "PAYROLL", 3),
                attach("24:0x7f0000000300", 5, APP),
            ),
        );
        assert!(!objects(&first).contains(&"PAYROLL".to_owned()), "held");
        assert!(reread > 0);
        assert!(
            objects(&second).contains(&"PAYROLL".to_owned()),
            "{:?}",
            objects(&second)
        );
    }

    /// R39 (a) test 3: a restart with a pending fold group (block-ful)
    /// inside the re-read region: its relations are sent after the
    /// restart.
    #[test]
    fn a_restart_with_a_pending_group_sends_its_relations() {
        use crate::stream_tests::{APP, attach};
        let (first, second, reread) = restart_over(
            "group",
            &format!(
                "{}{}{}",
                attach("24:0x7f0000000100", 3, APP),
                pending_routine(true),
                attach("24:0x7f0000000300", 5, APP),
            ),
        );
        assert!(!objects(&first).contains(&"SECRETS".to_owned()), "pending");
        assert!(reread > 0);
        assert!(
            objects(&second).contains(&"SECRETS".to_owned()),
            "{:?}",
            objects(&second)
        );
    }

    /// R39 (a) test 4: a restart with an ambiguous record (another pid)
    /// inside the re-read region (held back by a pending group before it):
    /// it is sent again after the restart, `*` and always reported.
    #[test]
    fn a_restart_with_an_ambiguous_record_sends_it_again() {
        use crate::stream_tests::{APP, attach, select};
        let (_, second, reread) = restart_over(
            "ambiguous",
            &format!(
                "{}{}{}{}",
                attach("24:0x7f0000000100", 3, APP),
                pending_routine(true),
                select("99:0x7f0000000900", 9, 9, APP, "LEDGER", 1),
                attach("24:0x7f0000000300", 5, APP),
            ),
        );
        assert!(reread > 0);
        let ledger: Vec<_> = second
            .iter()
            .filter(|(_, e)| e.objects().iter().any(|x| x.object().as_str() == "LEDGER"))
            .collect();
        assert!(!ledger.is_empty(), "{:?}", objects(&second));
        assert!(ledger.iter().all(|(_, e)| e.always_report()));
        assert!(objects(&second).contains(&"*".to_owned()));
    }

    /// Review H1: a record above the assembler's bound (a block of 10 000
    /// relations, more than 1 MiB) is not dropped: it gives an ambiguous
    /// `*` event, always reported, counted as ambiguous.
    #[test]
    fn an_oversized_record_is_ambiguous_never_dropped() {
        use crate::stream_tests::{APP, HEAD, attach};
        let dir = temp("over");
        let log = dir.join("audit.log");
        let a = "24:0x7f0000000100";
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        let att = format!(
            "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
        );
        let mut big = format!(
            "{HEAD} ({a}) START_TRANSACTION\n{att}\n{HEAD} ({a}) EXECUTE_STATEMENT_FINISH\n{att}\nStatement 1:\n{}\nSELECT * FROM PAYROLL WHERE ID > 0\n50 records fetched\n      0 ms, 7 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n",
            "-".repeat(79),
            "Table",
            "*".repeat(115)
        );
        big.push_str(&format!("{:<35}{:>10}{:>70}\n", "PAYROLL", 50, ""));
        for i in 0..10_000 {
            big.push_str(&format!("{:<35}{:>10}{:>70}\n", format!("T{i}"), 1, ""));
        }
        big.push('\n');
        assert!(big.len() > crate::trace_log::MAX_RECORD);
        append(
            &log,
            &format!(
                "{}{}{}",
                attach(a, 3, APP),
                big,
                attach("24:0x7f0000000300", 5, APP)
            ),
        );
        let (out, _) = session(&log, &dir);
        assert!(
            out.iter().any(|(_, e)| e.always_report()
                && e.objects().iter().any(|o| o.object().as_str() == "*")),
            "{:?}",
            objects(&out)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Security review M1 of #392: a rotation whose new file cannot be
    /// opened ends the old file all the same: the record held at its end
    /// is handed on and nothing of it stays held (lost at a restart
    /// otherwise), whether the poll that met the rotation read lines of
    /// the old file (handed on) or nothing (the poll fails).
    #[test]
    fn a_rotation_to_an_unopenable_file_ends_what_the_old_file_holds() {
        use crate::stream_tests::{APP, attach, select};
        for read_in_the_rotating_poll in [true, false] {
            let dir = temp(&format!("rotfail-{read_in_the_rotating_poll}"));
            let log = dir.join("audit.log");
            std::fs::write(&log, b"").unwrap();
            let store = databastion_core::audit::CursorStore::new(&dir, "t", "fb");
            let mut r = runner(&log, store);
            let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
            let classes = Classes::default();
            let cats: Vec<&dyn Catalog> = vec![&classes];
            let mut out = Vec::new();
            assert!(!r.poll(&mut m, &cats, &mut out).unwrap());
            let a = "24:0x7f0000000100";
            append(
                &log,
                &format!(
                    "{}{}",
                    attach(a, 3, APP),
                    select(a, 3, 5, APP, "CUSTOMERS", 2)
                ),
            );
            if !read_in_the_rotating_poll {
                while r.poll(&mut m, &cats, &mut out).unwrap() {}
                // The select is the record in progress: held.
                assert!(r.record_start.is_some());
                assert!(!objects(&out).contains(&"CUSTOMERS".to_owned()));
            }
            std::fs::rename(&log, dir.join("audit.1.log")).unwrap();
            let elsewhere = dir.join("other");
            std::fs::write(&elsewhere, b"").unwrap();
            std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
            for _ in 0..3 {
                let _ = r.poll(&mut m, &cats, &mut out);
            }
            assert!(
                objects(&out).contains(&"CUSTOMERS".to_owned()),
                "{read_in_the_rotating_poll}: {:?}",
                objects(&out)
            );
            assert!(r.record_start.is_none());
            assert!(r.held(&m).is_empty());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Security review H1 of #392, the live case: the last record is
    /// held, the server rotates into a file the agent cannot open, and
    /// the poll that meets the rotation reads nothing and fails. The held
    /// record, ended into the poll's events, reaches the sink before the
    /// stream handles the error.
    #[tokio::test]
    async fn the_held_record_reaches_the_sink_when_the_rotating_poll_fails() {
        use crate::stream_tests::{APP, attach, select};
        let dir = temp("deliver");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let store = databastion_core::audit::CursorStore::new(&dir, "t", "fb");
        let runner = runner(&log, store);
        let machine = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let cats = vec![Classes::default()];
        let (sink, mut rx) = EventSink::channel(64);
        let (runner, machine, cats, polled) = poll_and_deliver(runner, machine, cats, &sink)
            .await
            .unwrap();
        assert!(!polled.unwrap());
        let a = "24:0x7f0000000100";
        append(
            &log,
            &format!(
                "{}{}",
                attach(a, 3, APP),
                select(a, 3, 5, APP, "PAYROLL", 2)
            ),
        );
        let (runner, machine, cats, polled) = poll_and_deliver(runner, machine, cats, &sink)
            .await
            .unwrap();
        polled.unwrap();
        assert!(runner.record_start.is_some(), "the select is held");
        assert!(rx.try_recv().is_err());
        std::fs::rename(&log, dir.join("audit.1.log")).unwrap();
        let elsewhere = dir.join("other");
        std::fs::write(&elsewhere, b"").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
        let (_, _, _, polled) = poll_and_deliver(runner, machine, cats, &sink)
            .await
            .unwrap();
        assert!(polled.is_err(), "the rotating poll fails");
        let mut objects = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            objects.extend(ev.objects().iter().map(|o| o.object().as_str().to_owned()));
        }
        assert!(objects.contains(&"PAYROLL".to_owned()), "{objects:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Security review L2 of #392: a line skipped in a file of which no
    /// line was read (it rotated away first) is a record lost whole:
    /// ambiguous, counted oversized.
    #[test]
    fn a_line_skipped_in_a_file_never_read_is_ambiguous() {
        use crate::stream_tests::{APP, attach};
        let dir = temp("lostfile");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let mut r = runner(&log, None);
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        assert!(!r.poll(&mut m, &cats, &mut out).unwrap());
        append(&log, &attach("24:0x7f0000000100", 3, APP));
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        // B: one line past the bound only, read in the poll that opens it.
        std::fs::rename(&log, dir.join("audit.1.log")).unwrap();
        std::fs::write(&log, format!("{}\n", "x".repeat(1_100_000))).unwrap();
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert_eq!(r.tailer.oversized, 1);
        // C before any line of B.
        std::fs::rename(&log, dir.join("audit.2.log")).unwrap();
        std::fs::write(&log, attach("24:0x7f0000000300", 5, APP)).unwrap();
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert_eq!(m.counts.oversized, 1, "{:?}", m.counts);
        assert!(out.iter().any(|(_, e)| e.always_report()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A statement text line longer than the tailer's line bound (only
    /// possible with `max_sql_length` above 1 MiB, which `check()` no
    /// longer proves Partial) is skipped by the tailer; the record it
    /// belonged to is made ambiguous (`*`, always reported, counted
    /// oversized), never parsed without it, and the next record is read.
    #[test]
    fn a_record_that_lost_a_skipped_line_is_ambiguous() {
        use crate::stream_tests::{APP, HEAD, attach};
        let dir = temp("lostline");
        let log = dir.join("audit.log");
        let a = "24:0x7f0000000100";
        std::fs::write(&log, b"").unwrap();
        let mut r = runner(&log, None);
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        assert!(!r.poll(&mut m, &cats, &mut out).unwrap());
        let att = format!(
            "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
        );
        let record = |text: &str, rel: &str| {
            format!(
                "{HEAD} ({a}) EXECUTE_STATEMENT_FINISH\n{att}\nStatement 1:\n{}\n{text}\n1 records fetched\n      0 ms, 7 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{rel:<35}{:>10}{:>70}\n\n",
                "-".repeat(79),
                "Table",
                "*".repeat(115),
                1,
                ""
            )
        };
        let long = format!(
            "SELECT A FROM T1\nUNION ALL SELECT B FROM T1 /* {} */",
            "x".repeat(1_100_000)
        );
        append(
            &log,
            &format!(
                "{}{HEAD} ({a}) START_TRANSACTION\n{att}\n{}{}{}",
                attach(a, 3, APP),
                record(&long, "T1"),
                record("SELECT C FROM T2", "T2"),
                attach("24:0x7f0000000300", 5, APP)
            ),
        );
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert_eq!(r.tailer.oversized, 1);
        assert_eq!(m.counts.oversized, 1, "{:?}", m.counts);
        assert!(
            out.iter().any(|(_, e)| e.always_report()
                && e.objects().iter().any(|o| o.object().as_str() == "*")),
            "{:?}",
            objects(&out)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review L2: a restarted stream's first ambiguous record and first
    /// record are reported although its counters are below the previous
    /// stream's; review M4: a gap is reported.
    #[test]
    fn proofs_8_and_9_by_delta_across_stream_restarts() {
        let state = AuditState::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut seen = Seen::default();
        let mut c = crate::stream::Counts {
            parsed_declared: 100,
            ambiguous: 5,
            ..Default::default()
        };
        report(&state, "t", &mut seen, &c, 0, None, t0);
        // No progress: nothing new.
        report(
            &state,
            "t",
            &mut seen,
            &c,
            0,
            None,
            t0 + Duration::from_secs(10),
        );
        let f = state.with("t", |t| t.stream);
        assert_eq!(f.last_record, Some(t0));
        assert_eq!(f.ambiguous, 5);
        assert!(f.gap.is_none());
        // A new stream: its counters start at 0.
        let mut seen = Seen::default();
        c = crate::stream::Counts {
            parsed_declared: 1,
            ambiguous: 1,
            ..Default::default()
        };
        let t1 = t0 + Duration::from_secs(60);
        report(&state, "t", &mut seen, &c, 1, None, t1);
        let f = state.with("t", |t| t.stream);
        assert_eq!(f.last_record, Some(t1));
        assert_eq!(f.last_ambiguous, Some(t1));
        assert_eq!(f.ambiguous, 6);
        assert_eq!(f.gap, Some(t1));
    }

    /// Review M4: a stream that does not resume where the previous one of
    /// this process saved its cursor (a reset) counts a gap.
    #[test]
    fn a_cursor_reset_is_a_gap() {
        use crate::stream_tests::{APP, attach};
        let dir = temp("reset");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        append(
            &log,
            &format!(
                "{}{}",
                attach("24:0x7f0000000100", 3, APP),
                attach("24:0x7f0000000300", 5, APP)
            ),
        );
        let mut r = runner(
            &log,
            databastion_core::audit::CursorStore::new(&dir, "t", "fb"),
        );
        r.expect = Some(((0, 0), 12_345));
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert!(r.reset);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review M3: a rotation while a fold group pends in the old file ends
    /// the group there (its relations sent), so that nothing held lies in
    /// the rotated file when the cursor is saved; a restart then loses
    /// nothing.
    #[test]
    fn a_rotation_ends_what_the_old_file_holds() {
        use crate::stream_tests::{APP, attach};
        let dir = temp("rotate");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        let store = || databastion_core::audit::CursorStore::new(&dir, "t", "fb");
        let mut r = runner(&log, store());
        let mut m = Machine::new(test_settings(), Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        append(
            &log,
            &format!(
                "{}{}{}",
                attach("24:0x7f0000000100", 3, APP),
                pending_routine(true),
                attach("24:0x7f0000000300", 5, APP)
            ),
        );
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert!(!objects(&out).contains(&"SECRETS".to_owned()), "pending");
        // The server rotates the log.
        std::fs::rename(&log, dir.join("audit.log.1")).unwrap();
        std::fs::write(&log, attach("24:0x7f0000000400", 6, APP)).unwrap();
        append(&log, &attach("24:0x7f0000000500", 7, APP));
        for _ in 0..3 {
            while r.poll(&mut m, &cats, &mut out).unwrap() {}
        }
        assert!(
            objects(&out).contains(&"SECRETS".to_owned()),
            "{:?}",
            objects(&out)
        );
        let held = r.held(&m);
        assert!(held.iter().all(|(_, p)| Some(p.file) == r.file));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review H1: lines before any header (a read that starts inside a
    /// record) are ambiguous too, never dropped silently.
    #[test]
    fn orphan_lines_are_ambiguous() {
        use crate::stream_tests::{APP, attach};
        let dir = temp("orphan");
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let _ = session(&log, &dir);
        append(
            &log,
            &format!(
                "PAYROLL                                    50\n\n{}{}",
                attach("24:0x7f0000000100", 3, APP),
                attach("24:0x7f0000000300", 5, APP)
            ),
        );
        let (out, _) = session(&log, &dir);
        assert!(
            out.iter().any(|(_, e)| e.always_report()),
            "{:?}",
            objects(&out)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The runner over a real file: records assembled from the tailer's
    /// lines, the last one held at end of file, events out.
    #[test]
    fn the_runner_reads_a_log() {
        databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
        crate::fsread::allow_own_files_for_tests();
        let dir = std::env::temp_dir().join(format!("fb-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, b"").unwrap();
        let settings = Settings {
            databases: vec![DeclaredNames {
                label: "app".to_owned(),
                resolved: Some("/var/lib/firebird/data/app.fdb".to_owned()),
                alias: None,
                excluded: false,
                attach: "/var/lib/firebird/data/app.fdb".to_owned(),
                read_at: None,
            }],
            aliases: Some(AliasMap::default()),
            proof11: true,
            account: "DATABASTION_AGENT".to_owned(),
            parse: ParseOptions {
                max_sql_length: Some(65_000),
                series: Series::V5,
            },
            superserver: true,
        };
        let mut m = Machine::new(settings, Arc::new(crate::own::Ledger::default()));
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut r = Runner {
            log: log.clone(),
            ckpt: None,
            digests: Vec::new(),
            shed: 0,
            tailer: Tailer::new(log.clone(), FRAMING, None)
                .with_open_check(open_check(log.clone())),
            asm: Assembler::new(),
            record_start: None,
            file: None,
            last_growth: Instant::now(),
            reread_end: None,
            expect: None,
            reset: false,
            last_end: None,
            lost_in: None,
            ended: None,
            backlog: std::collections::VecDeque::new(),
            batch: None,
            stop: None,
            sample: None,
        };
        let mut out = Vec::new();
        assert!(r.poll(&mut m, &cats, &mut out).is_ok());
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(include_bytes!("../testdata/trace-5.0.4-triggers-sweep.log"))
            .unwrap();
        drop(f);
        while r.poll(&mut m, &cats, &mut out).unwrap() {}
        assert!(m.counts.records > 50, "{:?}", m.counts);
        assert!(!out.is_empty());
        // The record in progress is held back.
        assert!(r.record_start.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What one path made of a recorded log: records, ambiguous records
    /// (by rule), events, and the records whose parse found a defect.
    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        records: u64,
        ambiguous: u64,
        why: std::collections::BTreeMap<u32, u64>,
        events: usize,
        defects: Vec<(crate::trace_log::Event, crate::trace_log::Defect)>,
    }

    fn settings_for(series: Series) -> Settings {
        let mut s = test_settings();
        s.parse.series = series;
        s
    }

    fn defects_of(
        recs: &[Assembled],
        series: Series,
    ) -> Vec<(crate::trace_log::Event, crate::trace_log::Defect)> {
        let opts = settings_for(series).parse;
        recs.iter()
            .filter_map(|r| match r {
                Assembled::Record(raw) => crate::trace_log::parse(raw, opts)
                    .and_then(|p| p.defect.map(|d| (p.header.event, d))),
                _ => None,
            })
            .collect()
    }

    /// The parser's path of the connector's other tests: the log split on
    /// `\n` in memory and assembled, no tailer.
    fn direct(log: &[u8], series: Series) -> Outcome {
        let mut m = Machine::new(
            settings_for(series),
            Arc::new(crate::own::Ledger::default()),
        );
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut asm = Assembler::new();
        let mut recs = Vec::new();
        for line in log.split(|b| *b == b'\n') {
            recs.extend(asm.push_line(line));
        }
        recs.extend(asm.flush());
        let now = Instant::now();
        let mut out = Vec::new();
        let mut pos = 0;
        for r in &recs {
            if let Assembled::Record(raw) = r {
                m.push(raw, pos, now, &cats, &mut out);
                pos += raw.len() as u64 + 1;
            }
        }
        m.expire(now + Duration::from_secs(120), &cats, &mut out);
        Outcome {
            records: m.counts.records,
            ambiguous: m.counts.ambiguous,
            why: m.why.clone(),
            events: out.len(),
            defects: defects_of(&recs, series),
        }
    }

    /// The live path: the log appended to a real file after a first start,
    /// read by the core tailer with `framing` and the stream's runner (its
    /// record held at end of file, then flushed as at a stable end); the
    /// defects from the same tailer lines through the same assembler.
    fn through_the_tailer(name: &str, log: &[u8], series: Series, framing: Framing) -> Outcome {
        let dir = temp(name);
        let path = dir.join("audit.log");
        std::fs::write(&path, b"").unwrap();
        let mut r = runner(&path, None);
        r.tailer =
            Tailer::new(path.clone(), framing, None).with_open_check(open_check(path.clone()));
        let mut m = Machine::new(
            settings_for(series),
            Arc::new(crate::own::Ledger::default()),
        );
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        assert!(!r.poll(&mut m, &cats, &mut out).unwrap());
        // Written in pieces that cut records and lines, as a server does.
        for piece in log.chunks(4093) {
            append(&path, std::str::from_utf8(piece).unwrap());
            while r.poll(&mut m, &cats, &mut out).unwrap() {}
        }
        let now = Instant::now();
        let done = r.asm.flush();
        let rs = r.record_start.unwrap_or(0);
        r.hand(&mut m, done, rs, now, &cats, &mut out);
        m.expire(now + Duration::from_secs(120), &cats, &mut out);
        // The same log read by a fresh tailer (a first start reads from
        // the end: an empty copy first), its lines assembled.
        let copy = dir.join("copy.log");
        std::fs::write(&copy, b"").unwrap();
        let mut asm = Assembler::new();
        let mut recs = Vec::new();
        let mut t =
            Tailer::new(copy.clone(), framing, None).with_open_check(open_check(copy.clone()));
        assert!(t.poll().unwrap().records.is_empty());
        append(&copy, std::str::from_utf8(log).unwrap());
        loop {
            let p = t.poll().unwrap();
            for line in &p.records {
                recs.extend(asm.push_line(line));
            }
            if !p.more {
                break;
            }
        }
        recs.extend(asm.flush());
        let _ = std::fs::remove_dir_all(&dir);
        Outcome {
            records: m.counts.records,
            ambiguous: m.counts.ambiguous,
            why: m.why.clone(),
            events: out.len(),
            defects: defects_of(&recs, series),
        }
    }

    /// The e2e-firebird defect: the trace log's records need their empty
    /// lines. The recorded logs of both images, read by the real tailer and
    /// the stream's runner, give exactly what the parser's own tests see
    /// (no statement finish judged a `Shape` defect, no ambiguous record
    /// beyond the recorded logs' known ones); with empty lines dropped
    /// (the framing of the other line-based sources), every statement
    /// finish was a `Shape` defect and ambiguous.
    #[test]
    fn the_recorded_logs_read_through_the_tailer_are_parsed_as_recorded() {
        use crate::trace_log::{Defect, Event};
        let logs: [(&str, &[u8], Series); 3] = [
            (
                "rec5t",
                include_bytes!("../testdata/trace-5.0.4-triggers-sweep.log"),
                Series::V5,
            ),
            (
                "rec4t",
                include_bytes!("../testdata/trace-4.0.7-triggers-sweep.log"),
                Series::V4,
            ),
            (
                "rec5i",
                include_bytes!("../testdata/trace-5.0.4-isql-gbak.log"),
                Series::V5,
            ),
        ];
        for (name, log, series) in logs {
            let want = direct(log, series);
            let got = through_the_tailer(name, log, series, FRAMING);
            assert_eq!(got, want, "{name}");
            let finishes = log
                .split(|b| *b == b'\n')
                .filter(|l| l.ends_with(b") EXECUTE_STATEMENT_FINISH"))
                .count();
            assert!(finishes > 10, "{name}: {finishes}");
            if name != "rec5i" {
                // The trigger logs: no defect at all.
                assert!(got.defects.is_empty(), "{name}: {:?}", got.defects);
            } else {
                // The isql log's only defects are its forged split (a
                // header in a comment, 8f), never a statement finish's
                // shape.
                assert!(!got.defects.is_empty());
                assert!(
                    !got.defects
                        .contains(&(Event::ExecuteStatementFinish, Defect::Shape)),
                    "{:?}",
                    got.defects
                );
            }
            // What the old framing did (this test would have caught it).
            let old = through_the_tailer(&format!("{name}-old"), log, series, Framing::Lines);
            let shaped = old
                .defects
                .iter()
                .filter(|d| **d == (Event::ExecuteStatementFinish, Defect::Shape))
                .count();
            assert!(
                shaped * 10 >= finishes * 9,
                "{name}: {shaped} of {finishes}"
            );
            assert!(old.ambiguous > want.ambiguous, "{name}");
        }
    }

    /// A statement text written with CRLF line breaks and cut by the
    /// server at `max_sql_length` (its last bytes `...`): the tailer drops
    /// the `\r` before each newline, so the text is shorter than the limit
    /// when parsed; it is still judged cut (`CutText`, ambiguous), and a
    /// shorter text ending `...` is not.
    #[test]
    fn a_cut_text_with_crlf_line_breaks_is_still_cut() {
        use crate::stream_tests::{APP, HEAD};
        use crate::trace_log::{Defect, parse};
        let limit = 4096;
        let record = |text: &str| {
            format!(
                "{HEAD} (24:0x7f0000000100) EXECUTE_STATEMENT_FINISH\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nStatement 1:\n{}\n{text}\n1 records fetched\n      0 ms, 7 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n\n",
                "-".repeat(79),
                "Table",
                "*".repeat(115),
                "T1",
                1,
                ""
            )
        };
        // `max_sql_length` bytes as the server writes a cut text: the
        // first `limit - 3` bytes of the text, then `...`.
        let mut text = String::new();
        while text.len() < limit - 3 {
            text.push_str("SELECT A, B, C FROM T1 UNION ALL\r\n");
        }
        text.truncate(limit - 3);
        let text = text.trim_end_matches(['\r', '\n']).to_owned();
        let pad = limit - 3 - text.len();
        let cut = format!("{text}{}...", " ".repeat(pad));
        assert_eq!(cut.len(), limit);
        let short = format!("{}...", cut[..limit / 2].trim_end_matches(['\r', '\n']));
        let dir = temp("crlf");
        let path = dir.join("audit.log");
        std::fs::write(&path, b"").unwrap();
        let mut t =
            Tailer::new(path.clone(), FRAMING, None).with_open_check(open_check(path.clone()));
        assert!(t.poll().unwrap().records.is_empty());
        append(&path, &format!("{}{}", record(&cut), record(&short)));
        let mut asm = Assembler::new();
        let mut recs = Vec::new();
        for line in &t.poll().unwrap().records {
            recs.extend(asm.push_line(line));
        }
        recs.extend(asm.flush());
        let opts = ParseOptions {
            max_sql_length: Some(limit),
            series: Series::V5,
        };
        let defects: Vec<Option<Defect>> = recs
            .iter()
            .map(|r| match r {
                Assembled::Record(raw) => parse(raw, opts).unwrap().defect,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(defects, [Some(Defect::CutText), None]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R28 item 4 under R11 8d: requests are merged, at most one early
    /// check per 30 s, never while one runs, and a newer check serves them.
    #[test]
    fn early_checks_are_merged() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        let started = AtomicU32::new(0);
        let busy = AtomicBool::new(false);
        let start = || {
            if busy.load(Ordering::Relaxed) {
                return false;
            }
            started.fetch_add(1, Ordering::Relaxed);
            true
        };
        let t0 = Instant::now();
        let mut r = EarlyRequests::default();
        r.serve(1, t0, &start);
        assert_eq!(started.load(Ordering::Relaxed), 0);
        r.request(1);
        r.request(1);
        r.serve(1, t0, &start);
        assert_eq!(started.load(Ordering::Relaxed), 1);
        // Within 30 s: held, not started.
        r.request(1);
        r.serve(1, t0 + Duration::from_secs(10), &start);
        assert_eq!(started.load(Ordering::Relaxed), 1);
        // Past 30 s, but a check runs: held.
        busy.store(true, Ordering::Relaxed);
        r.serve(1, t0 + Duration::from_secs(31), &start);
        assert_eq!(started.load(Ordering::Relaxed), 1);
        busy.store(false, Ordering::Relaxed);
        r.serve(1, t0 + Duration::from_secs(32), &start);
        assert_eq!(started.load(Ordering::Relaxed), 2);
        // A newer check result serves a pending request.
        r.request(2);
        r.serve(3, t0 + Duration::from_secs(100), &start);
        r.serve(3, t0 + Duration::from_secs(200), &start);
        assert_eq!(started.load(Ordering::Relaxed), 2);
    }

    /// R44 item 6 (review N8): the line is written where the check
    /// switches, once per switch, and names no path.
    #[test]
    fn the_identity_source_line_is_written_on_a_switch() {
        use crate::host_identity::Source;
        #[derive(Clone, Default)]
        struct Logs(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Logs {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs = Logs::default();
        let w = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || w.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let state = AuditState::default();
        let lines = || {
            String::from_utf8_lossy(&logs.0.lock().unwrap())
                .lines()
                .filter(|l| l.contains("identity files source"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        note_identity_source(&state, "fb-1", Some(Source::HostFiles));
        note_identity_source(&state, "fb-1", Some(Source::HostFiles));
        assert_eq!(lines().len(), 1);
        note_identity_source(&state, "fb-1", Some(Source::DeclaredFiles));
        note_identity_source(&state, "fb-1", None);
        note_identity_source(&state, "fb-2", Some(Source::DeclaredFiles));
        let l = lines();
        assert_eq!(l.len(), 3, "{l:?}");
        assert!(l[0].contains("host_files") && l[0].contains("fb-1"));
        assert!(l[1].contains("declared_files") && l[1].contains("fb-1"));
        assert!(l[2].contains("fb-2"));
        assert!(l.iter().all(|x| !x.contains('/')), "{l:?}");
        assert!(l.iter().all(|x| x.contains("INFO")));
    }

    /// Re-review L-E: the `databases.conf` rule of R9, decided by the
    /// evaluation (here a map that cannot be read: fail closed), reaches
    /// the stream's settings and Discovery's exclusions.
    #[test]
    fn the_databases_conf_exclusion_reaches_the_stream_and_discovery() {
        let state = AuditState::default();
        let cfg = FirebirdAuditConfig {
            log: "/nonexistent/fb/audit.log".into(),
            trace_config: "/nonexistent/fb/fbtrace.conf".into(),
            firebird_conf: "/nonexistent/fb/firebird.conf".into(),
            root: "/nonexistent/fb".into(),
            databases_conf: Some("/nonexistent/fb/databases.conf".into()),
            host_identity: None,
        };
        let db = DbFacts {
            attach: "/data/app.fdb".to_owned(),
            label: "app".to_owned(),
            resolved: Some("/data/app.fdb".to_owned()),
            catalog: Classes::default(),
            excluded: false,
            read_at: None,
            state: crate::check::DbState::default(),
            restores: 0,
            restore_seen: None,
        };
        let (mut notes, mut detail) = (Notes::default(), Vec::new());
        let _ = evaluate(
            &state,
            "t",
            &cfg,
            CheckInputs {
                dbs: vec![db],
                server_pid: None,
                peer_uid: None,
                started: SystemTime::now(),
            },
            &mut notes,
            &mut detail,
        );
        assert_eq!(state.excluded_attach("t"), ["/data/app.fdb"]);
        let (s, _, _, _, _) = settings(&state, "t", "AGENT", Series::V5);
        assert!(s.databases.iter().all(|d| d.excluded));
    }

    /// R1 rule 5: a changed `DB_GUID` or creation date between two checks
    /// of this process is a restore, counted per database; the same state,
    /// or a read that failed, is not; the last state read is kept across a
    /// failed read, so a change across it is still counted.
    #[test]
    fn restores_are_counted_from_the_checks_restore_state() {
        let st = |g: &str| crate::check::RestoreState {
            guid: g.to_owned(),
            created: "2026-11-01 14:16:12.3840 UTC".to_owned(),
        };
        let db = |attach: &str, r: Option<crate::check::RestoreState>| DbFacts {
            attach: attach.to_owned(),
            state: crate::check::DbState {
                restore: r,
                ..crate::check::DbState::default()
            },
            ..DbFacts::default()
        };
        let mut prev: Vec<DbFacts> = Vec::new();
        let mut step = |dbs: Vec<DbFacts>| {
            let mut dbs = dbs;
            count_restores(&prev, &mut dbs);
            let n: Vec<u64> = dbs.iter().map(|d| d.restores).collect();
            prev = dbs;
            n
        };
        assert_eq!(step(vec![db("a", Some(st("1"))), db("b", None)]), [0, 0]);
        assert_eq!(
            step(vec![db("a", Some(st("1"))), db("b", Some(st("x")))]),
            [0, 0]
        );
        assert_eq!(
            step(vec![db("a", Some(st("2"))), db("b", Some(st("x")))]),
            [1, 0]
        );
        // A failed read: no restore, the last state kept.
        assert_eq!(step(vec![db("a", None), db("b", Some(st("x")))]), [1, 0]);
        assert_eq!(
            step(vec![db("a", Some(st("3"))), db("b", Some(st("y")))]),
            [2, 1]
        );
        // Another creation date alone is a restore too.
        let mut later = st("3");
        later.created = "2026-11-02 00:00:00.0000 UTC".to_owned();
        assert_eq!(
            step(vec![db("a", Some(later)), db("b", Some(st("y")))]),
            [3, 1]
        );
    }

    /// Review N3: the audit facts' `Debug` shows no path, label or name.
    #[test]
    fn audit_facts_debug_is_redacted() {
        let d = DbFacts {
            attach: "/secret/app.fdb".to_owned(),
            label: "secretlabel".to_owned(),
            resolved: Some("/secret/app.fdb".to_owned()),
            catalog: Classes {
                user: HashMap::from([("SECRET_TABLE".to_owned(), RelClass::Table)]),
                complete: true,
                deps: crate::views::ViewDeps::default(),
                linger: None,
                restore: None,
            },
            excluded: false,
            read_at: None,
            state: crate::check::DbState::default(),
            restores: 0,
            restore_seen: None,
        };
        let state = AuditState::default();
        state.with("t", |t| t.dbs = vec![d.clone()]);
        let all = format!("{d:?} {state:?} {:?}", state.with("t", |t| t.clone()));
        for s in ["/secret", "secretlabel", "SECRET_TABLE"] {
            assert!(!all.contains(s), "{all}");
        }
    }

    #[test]
    fn classes_from_the_catalog() {
        let c = Classes {
            user: HashMap::from([
                ("RDB$CUSTOMER_ARCHIVE".to_owned(), RelClass::Table),
                ("V_MIX".to_owned(), RelClass::View),
                ("V_PLAIN".to_owned(), RelClass::View),
            ]),
            complete: true,
            deps: crate::views::ViewDeps {
                dependent: ["V_MIX".to_owned(), "P_MON".to_owned()]
                    .into_iter()
                    .collect(),
                computed: ["T_COMP".to_owned()].into_iter().collect(),
                computed_known: true,
                routines: ["P_MON".to_owned(), "P_OK".to_owned()]
                    .into_iter()
                    .collect(),
                complete: true,
            },
            linger: None,
            restore: None,
        };
        assert_eq!(c.class("RDB$CUSTOMER_ARCHIVE"), RelClass::Table);
        assert_eq!(c.class("RDB$RELATIONS"), RelClass::System);
        assert_eq!(c.class("MON$STATEMENTS"), RelClass::Virtual);
        assert_eq!(c.class("CUSTOMERS"), RelClass::Unknown);
        // Review M2: a name off the explicit list is an object, whatever
        // its prefix.
        assert_eq!(c.class("RDB$LOOT"), RelClass::Unknown);
        assert_eq!(c.class("MON$LOOT"), RelClass::Unknown);
        assert_eq!(c.class("PLG$LOOT"), RelClass::Unknown);
        let cut = Classes::default();
        assert_eq!(cut.class("RDB$RELATIONS"), RelClass::Unknown);
        // R12 item 5, R41.
        assert!(c.always_view("V_MIX"));
        assert!(c.always_view("P_MON"));
        assert!(!c.always_view("V_PLAIN"));
        assert!(!c.always_view("P_OK"));
        assert!(!c.always_view("RDB$CUSTOMER_ARCHIVE"));
        // R41 item 3: unknown to the catalog read: dependent.
        assert!(c.always_view("CUSTOMERS"));
        assert!(c.always_view("P_NEW"));
        // Tokens: the set only (no unknown-name rule).
        assert!(c.dependent_token("P_MON  "));
        assert!(!c.dependent_token("SELECT"));
        // An incomplete dependency read: every view, routine and unknown
        // name, and every table when the columns are not known.
        let open = Classes {
            deps: crate::views::ViewDeps::default(),
            ..c.clone()
        };
        assert!(open.always_view("V_PLAIN"));
        assert!(open.always_view("V_NEW"));
        assert!(open.always_view("P_OK"));
        assert!(open.always_view("RDB$CUSTOMER_ARCHIVE"));
        assert!(!open.always_view("RDB$RELATIONS"));
        let open = Classes {
            deps: crate::views::ViewDeps {
                computed_known: true,
                computed: ["T_COMP".to_owned()].into_iter().collect(),
                ..crate::views::ViewDeps::default()
            },
            ..c.clone()
        };
        assert!(!open.always_view("RDB$CUSTOMER_ARCHIVE"));
    }
}
