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
//!   pending fold group or of the record in progress, and the records read
//!   again after a restart are replayed for state only.

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
    /// `MON$SEC_DATABASE` (R9 rule 1): `Default`, `Self`, `Other`.
    pub(crate) sec_database: Option<String>,
    pub(crate) catalog: Classes,
}

/// The relation classes of one database's catalog read (decision 5's
/// user relations; everything else is a system or virtual relation only
/// when the read was complete).
#[derive(Debug, Clone, Default)]
pub(crate) struct Classes {
    user: HashMap<String, RelClass>,
    complete: bool,
}

impl Classes {
    pub(crate) fn from_catalog(c: &catalog::Catalog) -> Self {
        let Some(rels) = &c.relations else {
            return Self::default();
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
        }
    }
}

impl Catalog for Classes {
    fn class(&self, r: &str) -> RelClass {
        if let Some(c) = self.user.get(r) {
            return *c;
        }
        // Not a user relation (system flag 0) of a complete read: a
        // system relation; the virtual ones by their names (R8 item 1).
        if !self.complete {
            return RelClass::Unknown;
        }
        if r.starts_with("MON$") || r.starts_with("SEC$") || r == "RDB$CONFIG" {
            RelClass::Virtual
        } else if r.starts_with("RDB$") || r.starts_with("PLG$") {
            RelClass::System
        } else {
            RelClass::Unknown
        }
    }

    fn always_view(&self, _relation: &str) -> bool {
        // R12 item 5's view-dependency read is not implemented yet: no
        // view is known to depend on an always-reported relation.
        false
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
    // R9: databases that are their own security database are excluded.
    let mut excluded = 0u64;
    let mut names = Vec::new();
    for d in &input.dbs {
        let alias = (!d.attach.starts_with('/')).then_some(d.attach.as_str());
        let decl = DeclaredDb {
            label: &d.label,
            resolved: d.resolved.as_deref(),
            alias,
        };
        let shape = d.catalog.user.contains_key("PLG$SRP")
            || d.catalog.user.contains_key("PLG$USERS")
            || d.catalog.user.contains_key("PLG$VIEW_USERS");
        let sec_ok = matches!(d.sec_database.as_deref(), Some("Default" | "Other"));
        let map_self = trace_conf::own_security_database(aliases.as_ref(), &decl, &root);
        let excl = !sec_ok || shape || map_self != Some(false);
        if excl {
            excluded += 1;
            detail.push(format!(
                "{}: excluded from Audit (its own security database, or not shown not to be one)",
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
    if excluded > 0 {
        notes.add(TargetNote::new(NoteCode::CoverageSecurityDatabaseExcluded).with_count(excluded));
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
                        longest_own_text: crate::sql::STATEMENTS
                            .iter()
                            .map(|s| s.text.len())
                            .max()
                            .unwrap_or(0),
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
    let in_container = databastion_core::config::firebird::agent_in_container();
    if crate::fsread::readable_by_others(&cfg.log, input.peer_uid.unwrap_or(84), in_container) {
        notes.add(TargetNote::new(NoteCode::AuditLogReadableByOthers));
        proven = false;
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
                excluded: !matches!(d.sec_database.as_deref(), Some("Default" | "Other")),
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

/// The Audit stream of one target. Runs until the core drops it.
pub(crate) async fn stream(
    state: Arc<AuditState>,
    ledger: Arc<crate::own::Ledger>,
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
        replay_end: None,
    };
    if let Some(r) = runner.tailer.take_replay() {
        runner.replay_end = Some(r.replay.end);
    }
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
        let held = machine
            .held_from()
            .into_iter()
            .chain(runner.record_start)
            .min();
        let held: Vec<(u64, databastion_core::audit::tail::RecordPos)> = match (held, runner.file) {
            (Some(start), Some(file)) => vec![(
                0,
                databastion_core::audit::tail::RecordPos {
                    file,
                    start,
                    end: start,
                },
            )],
            _ => Vec::new(),
        };
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

struct Runner {
    tailer: Tailer,
    asm: Assembler,
    /// The log offset of the record in progress (held back).
    record_start: Option<u64>,
    /// The `(st_dev, st_ino)` of the file read last.
    file: Option<(u64, u64)>,
    last_growth: Instant,
    /// After a restart: records ending before this were handed over
    /// already, and are replayed for state only.
    replay_end: Option<u64>,
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
                if let Some(Assembled::Record(raw)) = self.asm.push_line(line) {
                    let rs = self.record_start.unwrap_or(start);
                    let replay = self.replay_end.is_some_and(|e| rs < e);
                    m.push(&raw, rs, now, cats, replay, out);
                }
                self.record_start = Some(start);
            } else {
                if let Some(Assembled::Oversized(_)) = self.asm.push_line(line) {
                    m.counts.oversized += 1;
                }
            }
        }
        // A stable end of file: the record in progress is complete.
        if !polled.more && now.duration_since(self.last_growth) >= STABLE_EOF {
            if let Some(Assembled::Record(raw)) = self.asm.flush() {
                let rs = self.record_start.unwrap_or(0);
                let replay = self.replay_end.is_some_and(|e| rs < e);
                m.push(&raw, rs, now, cats, replay, out);
            }
            self.record_start = None;
        }
        m.expire(now, cats, false, out);
        Ok(polled.more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

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
            replay_end: None,
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

    #[test]
    fn classes_from_the_catalog() {
        let c = Classes {
            user: HashMap::from([("RDB$CUSTOMER_ARCHIVE".to_owned(), RelClass::Table)]),
            complete: true,
        };
        assert_eq!(c.class("RDB$CUSTOMER_ARCHIVE"), RelClass::Table);
        assert_eq!(c.class("RDB$RELATIONS"), RelClass::System);
        assert_eq!(c.class("MON$STATEMENTS"), RelClass::Virtual);
        assert_eq!(c.class("CUSTOMERS"), RelClass::Unknown);
        let cut = Classes::default();
        assert_eq!(cut.class("RDB$RELATIONS"), RelClass::Unknown);
    }
}
