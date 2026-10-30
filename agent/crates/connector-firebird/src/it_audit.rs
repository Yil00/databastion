//! Integration tests of the Audit parsers against the pinned servers'
//! own files (ADR-0060 decision 6, lot 3): `dev/firebird/it.sh` turns the
//! system audit trace on for the main server (`AuditTraceConfigFile`, a
//! trace configuration meeting the proofs, the log on a volume), runs an
//! `isql` workload over loopback TCP and a `gbak` backup through the
//! services manager, then copies the server's `firebird.conf`,
//! `databases.conf`, the trace configuration and the log for these tests.
//! The workload holds fake markers only (a literal and a password), which
//! must never reach an event.

use std::collections::BTreeMap;
use std::time::SystemTime;

use databastion_classifiers::masking::Signal;

use crate::trace_conf::{
    DeclaredDb, Inputs, ServerMode, binds_trace_config, evaluate, parse_databases_conf,
    parse_firebird_conf, parse_trace_conf,
};
use crate::trace_events::{Catalog, Converted, RelClass, convert, to_event};
use crate::trace_log::{Assembled, Assembler, ParseOptions, Series, parse};

const ROOT: &str = "/opt/firebird";
const APP: &str = "/var/lib/firebird/data/app.fdb";
const CRM: &str = "/var/lib/firebird/data/crm.fdb";
const LOG: &str = "/var/lib/firebird/audit/audit.log";
/// The workload's markers (fake values, `dev/firebird/it.sh`): a statement
/// literal, a password, a routine's returned value, `EXECUTE STATEMENT`'s
/// inner text, a client process name (also on a database-trigger record).
const MARKERS: [&str; 5] = [
    "it-marker-lit-7",
    "it-marker-pw-7",
    "it-marker-ret-7",
    "it-marker-es-7",
    "it-marker-proc-7",
];

fn file(var: &str) -> Option<Vec<u8>> {
    if !super::enabled() {
        return None;
    }
    let path = std::env::var(var).ok()?;
    Some(std::fs::read(path).expect("readable"))
}

fn series() -> Series {
    if std::env::var("FIREBIRD_IT_MAJOR").as_deref() == Ok("4") {
        Series::V4
    } else {
        Series::V5
    }
}

fn longest_own_text() -> usize {
    crate::own_table::longest_text()
}

/// The image's `firebird.conf` (with the image entrypoint's settings and
/// `AuditTraceConfigFile`) parses with the closed key set, binds the trace
/// configuration, and the trace configuration meets every proof for both
/// declared databases under the image's `databases.conf`.
#[test]
fn the_server_configuration_proves_partial() {
    let (Some(conf), Some(trace), Some(dbconf)) = (
        file("FIREBIRD_IT_FIREBIRD_CONF"),
        file("FIREBIRD_IT_TRACE_CONF"),
        file("FIREBIRD_IT_DATABASES_CONF"),
    ) else {
        return;
    };
    let conf = parse_firebird_conf(&conf).expect("the image's firebird.conf parses");
    assert_eq!(conf.server_mode, ServerMode::Super);
    assert!(binds_trace_config(&conf, ROOT, "/databastion/fbtrace.conf"));
    let map = parse_databases_conf(&dbconf, ROOT).expect("the image's databases.conf parses");
    let trace = parse_trace_conf(&trace).expect("the trace configuration parses");
    let dbs = [
        DeclaredDb {
            label: "app",
            resolved: Some(APP),
            alias: None,
        },
        DeclaredDb {
            label: "crm",
            resolved: Some(CRM),
            alias: None,
        },
    ];
    let v = evaluate(&Inputs {
        trace: &trace,
        aliases: Some(&map),
        databases: &dbs,
        log: LOG,
        root: ROOT,
        longest_own_text: longest_own_text(),
    });
    assert!(v.partial, "{:?} {:?}", v.notes, v.detail);
}

/// The test databases' catalog classes (in production: `check()`'s read).
struct Cat;

impl Catalog for Cat {
    fn class(&self, r: &str) -> RelClass {
        match r {
            "CUSTOMERS" | "NOGRANT" => RelClass::Table,
            "RDB$CONFIG" => RelClass::Virtual,
            _ if r.starts_with("RDB$") => RelClass::System,
            _ if r.starts_with("MON$") || r.starts_with("SEC$") => RelClass::Virtual,
            _ => RelClass::Unknown,
        }
    }
    fn always_view(&self, _: &str) -> bool {
        false
    }
}

/// Every record the server wrote for the workload parses well formed
/// (no defect: nothing in the workload forges a record), and the
/// workload's reads and backups become the events of the rules.
#[test]
fn the_server_trace_log_parses_and_gives_the_events() {
    let Some(log) = file("FIREBIRD_IT_AUDIT_LOG") else {
        return;
    };
    let opts = ParseOptions {
        max_sql_length: Some(65_000),
        series: series(),
    };
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split(|b| *b == b'\n') {
        recs.extend(a.push_line(line));
    }
    recs.extend(a.flush());
    assert!(recs.len() > 20, "{} records", recs.len());
    let mut defects = BTreeMap::new();
    let mut events = Vec::new();
    for r in &recs {
        let Assembled::Record(raw) = r else {
            panic!("not a record: {r:?}");
        };
        let rec = parse(raw, opts).expect("every header parses");
        if let Some(d) = rec.defect {
            *defects
                .entry(format!("{:?} {:?}", rec.header.event, d))
                .or_insert(0) += 1;
        }
        if let Converted::Event(d) | Converted::Ambiguous { draft: d, .. } = convert(&rec, &Cat) {
            events.push((
                format!("{d:?}"),
                to_event(&d, &rec, "app", SystemTime::UNIX_EPOCH),
            ));
        }
    }
    assert!(defects.is_empty(), "{defects:?}");
    for (text, ev) in &events {
        let all = format!("{text} {ev:?}");
        for m in MARKERS {
            assert!(!all.contains(m), "a marker reached an event: {all}");
        }
    }
    let customers = |e: &&(String, databastion_classifiers::masking::MaskedEvent)| {
        e.1.objects()
            .iter()
            .any(|o| o.object().as_str().eq_ignore_ascii_case("customers"))
    };
    assert!(
        events
            .iter()
            .filter(customers)
            .any(|e| e.1.signals().contains(&Signal::FullTableRead)),
        "no full read of CUSTOMERS"
    );
    let backups = events
        .iter()
        .filter(|e| e.1.signals().contains(&Signal::BackupDatabase))
        .count();
    // ALTER DATABASE BEGIN BACKUP and the services backup.
    assert!(backups >= 2, "{backups} backup events");
    assert!(
        events
            .iter()
            .filter(|e| e.1.signals().contains(&Signal::BackupDatabase))
            .all(|e| e.1.always_report())
    );
}

/// The stream rules on the server's own log: bindings, tokens, the
/// Garbage Collector, triggers and services hold; the only ambiguous
/// records are the statement finishes isql writes without a
/// `Statement <n>:` line for DDL and DCL (R20, reported for a refinement).
#[test]
fn the_server_trace_log_through_the_stream() {
    let Some(log) = file("FIREBIRD_IT_AUDIT_LOG") else {
        return;
    };
    let names = |label: &str, path: &str| crate::stream::DeclaredNames {
        label: label.to_owned(),
        resolved: Some(path.to_owned()),
        alias: None,
        excluded: false,
        attach: path.to_owned(),
        read_at: None,
    };
    let settings = crate::stream::Settings {
        databases: vec![names("app", APP), names("crm", CRM)],
        aliases: Some(Default::default()),
        proof11: true,
        account: "DATABASTION_AGENT".to_owned(),
        parse: ParseOptions {
            max_sql_length: Some(65_000),
            series: series(),
        },
        superserver: true,
    };
    let mut m =
        crate::stream::Machine::new(settings, std::sync::Arc::new(crate::own::Ledger::default()));
    let cats: [&dyn Catalog; 2] = [&Cat, &Cat];
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split(|b| *b == b'\n') {
        recs.extend(a.push_line(line));
    }
    recs.extend(a.flush());
    let mut out = Vec::new();
    let now = std::time::Instant::now();
    let mut bare = 0u64;
    for (i, r) in recs.iter().enumerate() {
        let Assembled::Record(raw) = r else { continue };
        if let Some(rec) = parse(
            raw,
            ParseOptions {
                max_sql_length: Some(65_000),
                series: series(),
            },
        ) && let crate::trace_log::Body::Statement { id: None, text, .. } = rec.body
            && !databastion_classifiers::query::firebird::analyze_firebird(text)
                .kind
                .cannot_read()
        {
            bare += 1;
        }
        m.push(raw, i as u64, now, &cats, &mut out);
    }
    assert_eq!(m.counts.panics, 0);
    assert_eq!(m.counts.ambiguous, bare, "{:?}", m.why);
    assert!(!out.is_empty());
    // #82: no marker of the workload reaches an event through the stream.
    for (_, ev) in &out {
        let all = format!("{ev:?}");
        for mk in MARKERS {
            assert!(!all.contains(mk), "a marker reached an event: {all}");
        }
    }
    // The markers are in the log (the cases were written).
    let text = String::from_utf8_lossy(&log);
    for mk in MARKERS {
        // The server may mask a password; the other cases must be there.
        if mk == "it-marker-pw-7" {
            eprintln!(
                "[measure] password marker in the trace: {}",
                text.contains(mk)
            );
            continue;
        }
        assert!(text.contains(mk), "{mk} not in the server's log");
    }
}

/// The engine-matrix own-statement test of R20, phase 2: the server's log
/// (written while phase 1, `it::own_reads_for_the_matrix`, ran the agent's
/// `check()`, a Discovery scan, the view-dependency read and the read-back
/// probe) through the stream with phase 1's ledger. Every statement
/// record of the agent's own attachments matches its text's row of the
/// own-statement table and its credit (none rejected, none without a
/// credit), the read-back probe is found (proof 7), and every credit of a
/// statement that ran is consumed.
#[test]
fn the_agent_records_match_the_own_statement_table() {
    let (Some(log), Some(dump)) = (
        file("FIREBIRD_IT_AUDIT_LOG"),
        file("FIREBIRD_IT_MATRIX_FILE"),
    ) else {
        return;
    };
    let ledger = std::sync::Arc::new(crate::own::Ledger::load(
        std::str::from_utf8(&dump).unwrap(),
    ));
    let names = |label: &str, path: &str| crate::stream::DeclaredNames {
        label: label.to_owned(),
        resolved: Some(path.to_owned()),
        alias: None,
        excluded: false,
        attach: path.to_owned(),
        read_at: None,
    };
    let settings = crate::stream::Settings {
        databases: vec![names("app", APP), names("crm", CRM)],
        aliases: Some(Default::default()),
        proof11: true,
        account: "DATABASTION_AGENT".to_owned(),
        parse: ParseOptions {
            max_sql_length: Some(65_000),
            series: series(),
        },
        superserver: true,
    };
    let mut m = crate::stream::Machine::new(settings, std::sync::Arc::clone(&ledger));
    let cats: [&dyn Catalog; 2] = [&Cat, &Cat];
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split(|b| *b == b'\n') {
        recs.extend(a.push_line(line));
    }
    recs.extend(a.flush());
    let mut out = Vec::new();
    let now = std::time::Instant::now();
    let mut pos = 0u64;
    for r in &recs {
        let Assembled::Record(raw) = r else { continue };
        // The closed set's trailers, for the table (constant texts only:
        // no value).
        if let Some(rec) = parse(
            raw,
            ParseOptions {
                max_sql_length: Some(65_000),
                series: series(),
            },
        ) && let crate::trace_log::Body::Statement {
            text, id, params, ..
        } = rec.body
            && crate::sql::checked(text)
        {
            let verdict = match convert(&rec, &Cat) {
                Converted::Nothing => "nothing".to_owned(),
                Converted::Event(d) => format!("event {:?} {:?}", d.signals, d.always),
                Converted::Ambiguous { window, .. } => format!("ambiguous window {window}"),
            };
            eprintln!("[measure] own text id {id:?} params {params}: {verdict}");
            let name = crate::sql::STATEMENTS
                .iter()
                .find(|s| s.text == text)
                .map_or_else(
                    || format!("probe of {} bytes", text.len()),
                    |s| s.name.to_owned(),
                );
            let block: Vec<&str> = rec
                .trailer
                .block
                .as_ref()
                .map(|b| b.iter().map(|(n, _)| *n).collect())
                .unwrap_or_default();
            eprintln!(
                "[measure] own text {name}: {:?} fetched {:?} block {block:?} defect {:?}",
                rec.header.outcome, rec.trailer.fetched, rec.defect
            );
        }
        m.push(raw, pos, now, &cats, &mut out);
        pos += raw.len() as u64 + 1;
    }
    eprintln!(
        "[it] own records {} not matched {} why {:?}",
        m.counts.own, m.counts.own_not_matched, m.why
    );
    assert!(m.counts.own > 50, "{:?}", m.counts);
    assert_eq!(m.counts.own_not_matched, 0, "{:?}", m.counts);
    assert!(m.probe_seen.is_some(), "the read-back probe (proof 7)");
    // R42 item 6: the offset the agent learned against the server's
    // header times (it.sh can run the server with another process TZ and
    // DefaultTimeZone; FIREBIRD_IT_TZ_OFFSET is the offset if headers
    // follow the process TZ: agent UTC minus printed time).
    let want: i64 = std::env::var("FIREBIRD_IT_TZ_OFFSET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    eprintln!(
        "[measure] learned clock offset {:?} (process TZ gives {want})",
        m.offset_for_tests()
    );
    assert_eq!(
        m.offset_for_tests(),
        Some(want),
        "header times follow the process TZ"
    );
    // Credits left only for executions the server did not finish.
    let left: Vec<_> = ledger
        .credits_left()
        .into_iter()
        .filter(|(_, end)| !matches!(end, crate::conn::FetchEnd::Error))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// Security review N5 of 2026-10-30: each boolean spelling the agent's
/// trace-configuration parser accepts means what the server applies
/// (`dev/firebird/it.sh` starts a user trace session with
/// `log_connections = <spelling>` and records whether an attachment was
/// traced, not traced, or the configuration refused). A spelling the agent
/// accepts as true is applied as true, as false as false; a spelling the
/// server refuses is refused by the agent.
#[test]
fn boolean_spellings_mean_what_the_server_applies() {
    let Some(results) = file("FIREBIRD_IT_BOOLEANS_FILE") else {
        return;
    };
    let results = String::from_utf8(results).unwrap();
    let mut n = 0;
    for line in results.lines() {
        let Some((spelling, server)) = line.split_once(' ') else {
            continue;
        };
        let conf = format!("database\n{{\n\tenabled = true\n\tlog_connections = {spelling}\n}}\n");
        let agent = parse_trace_conf(conf.as_bytes()).ok().and_then(|t| {
            t.sections.first().and_then(|s| {
                s.settings
                    .0
                    .iter()
                    .find(|(k, _)| *k == "log_connections")
                    .map(|(_, v)| v.clone())
            })
        });
        match agent {
            Some(crate::trace_conf::Value::Bool(true)) => assert_eq!(server, "true", "{spelling}"),
            Some(crate::trace_conf::Value::Bool(false)) => {
                assert_eq!(server, "false", "{spelling}")
            }
            _ => {}
        }
        if server == "refused" {
            assert!(
                agent.is_none(),
                "{spelling}: refused by the server, accepted by the agent"
            );
        }
        eprintln!("[measure] trace boolean {spelling:?}: server {server}, agent {agent:?}");
        n += 1;
    }
    assert!(n >= 8, "{n} spellings");
}

/// Drift test per series (item 5): every performance line the server
/// wrote (an indented `<n> ms` line) parses under the series' grammar.
#[test]
fn every_performance_line_of_the_server_parses() {
    let Some(log) = file("FIREBIRD_IT_AUDIT_LOG") else {
        return;
    };
    let text = String::from_utf8_lossy(&log);
    let mut n = 0;
    for line in text.lines() {
        let t = line.trim_start();
        if line.starts_with(' ')
            && t.split_once(" ms")
                .is_some_and(|(d, _)| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        {
            assert!(crate::trace_log::perf_line(line).is_some(), "{line:?}");
            n += 1;
        }
    }
    eprintln!("[measure] performance lines {n}");
    assert!(n > 20, "{n}");
}

/// The machine over the server's log for R41 item 9's commit-after-check
/// case: `CREATE PROCEDURE <name>` in a transaction committed after a
/// `check()` placed between the DDL record and its commit (a check whose
/// catalog read started there). `ambiguous`: the DDL record is made
/// ambiguous without forging, by an unconfirmed run (as after a server
/// restart) confirmed right after it. The call of the procedure after the
/// commit, before any later check, must still be marked.
fn late_commit_case(log: &[u8], name: &str, ambiguous: bool) {
    let names = |label: &str, path: &str| crate::stream::DeclaredNames {
        label: label.to_owned(),
        resolved: Some(path.to_owned()),
        alias: None,
        excluded: false,
        attach: path.to_owned(),
        read_at: None,
    };
    let settings = |at: Option<SystemTime>| crate::stream::Settings {
        databases: vec![
            crate::stream::DeclaredNames {
                read_at: at,
                ..names("app", APP)
            },
            crate::stream::DeclaredNames {
                read_at: at,
                ..names("crm", CRM)
            },
        ],
        aliases: Some(Default::default()),
        proof11: true,
        account: "DATABASTION_AGENT".to_owned(),
        parse: ParseOptions {
            max_sql_length: Some(65_000),
            series: series(),
        },
        superserver: true,
    };
    let mut m = crate::stream::Machine::new(
        settings(None),
        std::sync::Arc::new(crate::own::Ledger::default()),
    );
    let cats: [&dyn Catalog; 2] = [&Cat, &Cat];
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split(|b| *b == b'\n') {
        recs.extend(a.push_line(line));
    }
    recs.extend(a.flush());
    let now = std::time::Instant::now();
    let create = format!("CREATE PROCEDURE {name} ");
    let call = format!("SELECT * FROM {name}");
    let (mut seen_create, mut seen_call) = (false, false);
    for (i, r) in recs.iter().enumerate() {
        let Assembled::Record(raw) = r else { continue };
        let opts = ParseOptions {
            max_sql_length: Some(65_000),
            series: series(),
        };
        let text = parse(raw, opts).and_then(|rec| match rec.body {
            crate::trace_log::Body::Statement { text, .. } => Some(text.to_owned()),
            _ => None,
        });
        let is_create = text.as_deref().is_some_and(|t| t.starts_with(&create));
        let is_call = text.as_deref() == Some(call.as_str());
        if is_create && ambiguous {
            m.start_time_changed();
        }
        let pid = parse(raw, opts).map(|rec| rec.header.pid);
        let mut out = Vec::new();
        m.push(raw, i as u64, now, &cats, &mut out);
        if is_create {
            seen_create = true;
            if ambiguous && let Some(pid) = pid {
                m.confirm_run(crate::stream::Run { pid, start: None });
            }
            // The intervening check: its catalog read starts after the
            // DDL record, before the commit.
            std::thread::sleep(std::time::Duration::from_millis(5));
            m.reconfigure(settings(Some(SystemTime::now())));
        }
        if is_call {
            seen_call = true;
            assert!(
                !out.is_empty() && out.iter().all(|(_, e)| e.always_report()),
                "{name} (ambiguous {ambiguous}): the call after the commit is marked"
            );
        }
    }
    assert!(seen_create && seen_call, "{name}: the case is in the log");
}

/// R41 item 9 (re-review M-1): a `CREATE PROCEDURE` committed after an
/// intervening `check()`, on the normal path and on the ambiguous path.
#[test]
fn a_procedure_committed_after_an_intervening_check_stays_dependent() {
    let Some(log) = file("FIREBIRD_IT_AUDIT_LOG") else {
        return;
    };
    late_commit_case(&log, "P_LATE_A", false);
    late_commit_case(&log, "P_LATE_B", true);
}

/// R42 item 6: header times follow the server process's time zone, not a
/// session's `SET TIME ZONE` (here `+09:00`): the marker statement of that
/// session is printed within a minute of the record before it.
#[test]
fn header_times_ignore_the_session_time_zone() {
    let Some(log) = file("FIREBIRD_IT_AUDIT_LOG") else {
        return;
    };
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split(|b| *b == b'\n') {
        recs.extend(a.push_line(line));
    }
    recs.extend(a.flush());
    let opts = ParseOptions {
        max_sql_length: Some(65_000),
        series: series(),
    };
    let mut prev: Option<i64> = None;
    let mut found = false;
    for r in &recs {
        let Assembled::Record(raw) = r else { continue };
        let Some(rec) = parse(raw, opts) else {
            continue;
        };
        let t = crate::stream::naive_seconds(rec.header.time);
        if let crate::trace_log::Body::Statement { text, .. } = rec.body
            && text.contains("'it-tz-session'")
        {
            let p = prev.expect("a record before the marker");
            eprintln!(
                "[measure] session SET TIME ZONE '+09:00': header {} s from the record before",
                t - p
            );
            assert!((t - p).abs() < 60, "{}", t - p);
            found = true;
        }
        prev = Some(t);
    }
    assert!(found, "the session marker is in the log");
}
