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
//!   pending fold group or of the record in progress. The records read
//!   again after a restart (from that held-back position) are judged and
//!   emitted as on their first reading (R39 (a)): with no checkpoint of
//!   the parser's state, a re-read record can be judged differently, so
//!   none is suppressed; the events of the re-read region the previous
//!   reading had handed over are sent twice (accepted over-reporting,
//!   never a loss).

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
        }
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
    let started = run.and_then(|(_, s)| s.map(|(_, t)| t));
    if started.is_none() {
        // Proof 2: another pid namespace, or `hidepid`.
        not_eval.push("server_process_not_visible");
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
            notes.add(
                TargetNote::new(NoteCode::AuditLogRecordsAmbiguous).with_count(t.stream.ambiguous),
            );
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

/// The stream's settings from the last `check()`.
fn settings(
    state: &AuditState,
    id: &str,
    account: &str,
    series: Series,
) -> (Settings, Vec<Classes>, Option<Run>, u64) {
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
    let (s, mut cats, run, mut generation) = settings(&state, &id, account, series);
    if s.databases.is_empty() {
        // No check has read the databases yet.
        return Err(ConnectorError::Target {
            engine: databastion_core::Engine::Firebird,
            code: FailureCode::Unsupported,
            engine_code: None,
        });
    }
    let mut machine = Machine::new(s, ledger);
    let mut requests = EarlyRequests::default();
    let mut seen = Seen::default();
    if let Some(r) = run {
        machine.confirm_run(r);
    }
    let mut runner = Runner {
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
    };
    loop {
        // A new check: new names, classes, run.
        let (s, c, run, g) = settings(&state, &id, account, series);
        if g != generation {
            generation = g;
            machine.reconfigure(s);
            cats = c;
            if let Some(r) = run {
                machine.confirm_run(r);
            }
        }
        // R5 item 4: the run's start time before each read cycle; a pid
        // that is gone or no longer a Firebird server is a change too.
        if let Some(r) = run
            && let Some(start) = r.start
            && crate::fsread::process_start(r.pid).is_none_or(|(t, _)| t != start)
        {
            machine.start_time_changed();
        }
        let (r, m, out, polled) = tokio::task::spawn_blocking(move || {
            let mut m = machine;
            let mut r = runner;
            let mut out = Vec::new();
            let cats_ref: Vec<&dyn Catalog> = cats.iter().map(|c| c as &dyn Catalog).collect();
            let polled = r.poll(&mut m, &cats_ref, &mut out);
            (r, (m, cats), out, polled)
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
        runner = r;
        (machine, cats) = m;
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
        for (_db, ev) in out {
            sink.submit(ev).await?;
        }
        let held = runner.held(&machine);
        // Where the next stream must resume (review M4).
        let resume = held
            .first()
            .map(|(_, p)| (p.file, p.start))
            .or(runner.last_end);
        if resume.is_some() {
            state.note_stream(&id, |f| f.saved = resume);
        }
        runner = tokio::task::spawn_blocking(move || {
            runner.tailer.commit_from(&held);
            runner
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
        if !more {
            tokio::time::sleep(cfg.poll_interval()).await;
        }
    }
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
        let polled = self.tailer.poll()?;
        // R39 (a): the re-read region (known once the file is open) is
        // emitted again, not suppressed; its end is kept for the count.
        if let Some(r) = self.tailer.take_replay() {
            self.reread_end = Some((r.file, r.replay.end));
        }
        let now = Instant::now();
        if !polled.records.is_empty() {
            self.last_growth = now;
        }
        for (line, pos) in polled.records.iter().zip(&polled.positions) {
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let start = pos.start;
            if let Some(e) = self.expect.take()
                && e != (pos.file, pos.start)
            {
                self.reset = true;
            }
            self.last_end = Some((pos.file, pos.end));
            if self.file != Some(pos.file) {
                if self.file.is_some() {
                    // A rotation (review M3): the old file ended. Its last
                    // record is complete; what it still holds (pending fold
                    // groups, held records) ends now, as R25 item 3 says,
                    // since a held position in a rotated file cannot be
                    // re-read after a restart.
                    let done = self.asm.flush();
                    let rs = self.record_start.unwrap_or(0);
                    self.hand(m, done, rs, now, cats, out);
                    self.record_start = None;
                    m.end_all(now, cats, out);
                }
                self.file = Some(pos.file);
                m.set_file(pos.file);
            }
            if header(line).is_some() {
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
        // A stable end of file: the record in progress is complete.
        if !polled.more && now.duration_since(self.last_growth) >= STABLE_EOF {
            let done = self.asm.flush();
            let rs = self.record_start.unwrap_or(0);
            self.hand(m, done, rs, now, cats, out);
            self.record_start = None;
        }
        m.expire(now, cats, out);
        Ok(polled.more)
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
                m.unreadable(now, cats, out);
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
            },
            &mut notes,
            &mut detail,
        );
        assert_eq!(state.excluded_attach("t"), ["/data/app.fdb"]);
        let (s, _, _, _) = settings(&state, "t", "AGENT", Series::V5);
        assert!(s.databases.iter().all(|d| d.excluded));
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
            },
            excluded: false,
            read_at: None,
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
