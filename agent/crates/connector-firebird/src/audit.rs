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
#[derive(Debug, Clone, Default)]
pub(crate) struct DbFacts {
    pub(crate) attach: String,
    pub(crate) label: String,
    pub(crate) resolved: Option<String>,
    pub(crate) catalog: Classes,
    /// Excluded by R9 (`check()` decided it before any probe): not read by
    /// Discovery, an undeclared database for the stream.
    pub(crate) excluded: bool,
}

/// The relation classes of one database's catalog read (decision 5's
/// user relations; everything else is a system or virtual relation only
/// when the read was complete).
#[derive(Debug, Clone, Default)]
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
        if r.starts_with("MON$") || r.starts_with("SEC$") || r == "RDB$CONFIG" {
            RelClass::Virtual
        } else {
            RelClass::System
        }
    }

    /// R12 item 5: a view of the dependency set; with an incomplete
    /// dependency read (failed, cut, past its bounds), every view and
    /// every name the catalog read does not know.
    fn always_view(&self, relation: &str) -> bool {
        if self.deps.complete {
            return self.deps.dependent.contains(relation);
        }
        matches!(self.class(relation), RelClass::View | RelClass::Unknown)
    }
}

/// What the stream reports back to `check()`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StreamFacts {
    pub(crate) last_record: Option<SystemTime>,
    pub(crate) last_ambiguous: Option<SystemTime>,
    pub(crate) ambiguous: u64,
    pub(crate) gap: Option<SystemTime>,
    pub(crate) probe_seen: Option<SystemTime>,
}

/// Per target: what the last `check()` evaluated, and the stream's facts.
#[derive(Debug, Default)]
pub(crate) struct AuditState {
    inner: Mutex<HashMap<String, Target>>,
}

#[derive(Debug, Default, Clone)]
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
}

impl AuditState {
    fn with<R>(&self, id: &str, f: impl FnOnce(&mut Target) -> R) -> R {
        let mut m = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(m.entry(id.to_owned()).or_default())
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
    for d in &input.dbs {
        let alias = (!d.attach.starts_with('/')).then_some(d.attach.as_str());
        let decl = DeclaredDb {
            label: &d.label,
            resolved: d.resolved.as_deref(),
            alias,
        };
        let map_self = trace_conf::own_security_database(aliases.as_ref(), &decl, &root);
        let excl = d.excluded || map_self != Some(false);
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
    let log_ok = crate::fsread::read_checked(&cfg.log, usize::MAX).is_ok()
        || std::fs::symlink_metadata(&cfg.log).is_ok_and(|m| m.is_file());
    if !log_ok {
        notes.add(TargetNote::new(NoteCode::AuditLogNotReadable));
        proven = false;
    }
    // R4 (R39 (i)): the server's uid from the server process proof 2
    // finds, or the declared `peer_uid`, never a default.
    let in_container = databastion_core::config::firebird::agent_in_container();
    let server = input.server_pid.and_then(crate::fsread::server_ids);
    if let Err(why) = crate::fsread::readers_check(&cfg.log, server, input.peer_uid, in_container) {
        notes.add(TargetNote::new(NoteCode::AuditLogReadableByOthers));
        detail.push(format!("readers check: {why}"));
        proven = false;
    }
    // Review L4: the declared root is the server's layout (its binary in
    // `<root>/bin` or `<root>`); otherwise the macros may not resolve to
    // the root and proof 2 is not proven.
    if started.is_some() {
        let dir = input.server_pid.and_then(crate::fsread::server_binary_dir);
        let root_path = std::path::Path::new(&root);
        if !dir.is_some_and(|d| d == root_path.join("bin") || d == root_path) {
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
        t.dbs = input.dbs.clone();
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
        let _ = names;
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
fn open_check(path: PathBuf) -> OpenCheck {
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
    if let Some(r) = run {
        machine.confirm_run(r);
    }
    let mut runner = Runner {
        tailer: Tailer::new(audit.log.clone(), Framing::Lines, cfg.cursor(CURSOR))
            .with_open_check(open_check(audit.log.clone())),
        asm: Assembler::new(),
        record_start: None,
        file: None,
        last_growth: Instant::now(),
        reread_end: None,
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
        // R5 item 4: the run's start time before each read cycle.
        if let Some(r) = run
            && let Some(start) = r.start
            && crate::fsread::process_start(r.pid).is_some_and(|(t, _)| t != start)
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
        .map_err(|_| ConnectorError::Target {
            engine: databastion_core::Engine::Firebird,
            code: FailureCode::Internal,
            engine_code: None,
        })?;
        runner = r;
        (machine, cats) = m;
        let now = SystemTime::now();
        state.note_stream(&id, |f| {
            if machine.counts.parsed_declared > 0 {
                f.last_record = Some(now);
            }
            if machine.counts.ambiguous > f.ambiguous {
                f.last_ambiguous = Some(now);
                f.ambiguous = machine.counts.ambiguous;
            }
            if let Some(p) = machine.probe_seen.take() {
                f.probe_seen = Some(p);
            }
        });
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
        runner = tokio::task::spawn_blocking(move || {
            runner.tailer.commit_from(&held);
            runner
        })
        .await
        .map_err(|_| ConnectorError::Target {
            engine: databastion_core::Engine::Firebird,
            code: FailureCode::Internal,
            engine_code: None,
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
            if self.file != Some(pos.file) {
                // A rotation: the record in progress belongs to the old file.
                self.file = Some(pos.file);
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
            tailer: Tailer::new(log.to_path_buf(), Framing::Lines, store)
                .with_open_check(open_check(log.to_path_buf())),
            asm: Assembler::new(),
            record_start: None,
            file: None,
            last_growth: Instant::now(),
            reread_end: None,
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
            tailer: Tailer::new(log.clone(), Framing::Lines, None)
                .with_open_check(open_check(log.clone())),
            asm: Assembler::new(),
            record_start: None,
            file: None,
            last_growth: Instant::now(),
            reread_end: None,
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
                dependent: ["V_MIX".to_owned()].into_iter().collect(),
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
        // R12 item 5.
        assert!(c.always_view("V_MIX"));
        assert!(!c.always_view("V_PLAIN"));
        assert!(!c.always_view("CUSTOMERS"));
        // An incomplete dependency read: every view, and unknown names.
        let open = Classes {
            deps: crate::views::ViewDeps::default(),
            ..c.clone()
        };
        assert!(open.always_view("V_PLAIN"));
        assert!(open.always_view("V_NEW"));
        assert!(!open.always_view("RDB$CUSTOMER_ARCHIVE"));
        assert!(!open.always_view("RDB$RELATIONS"));
    }
}
