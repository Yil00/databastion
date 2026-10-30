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
/// The workload's markers (fake values, `dev/firebird/it.sh`).
const MARKERS: [&str; 2] = ["it-marker-lit-7", "it-marker-pw-7"];

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
    crate::sql::STATEMENTS
        .iter()
        .map(|s| s.text.len())
        .max()
        .unwrap_or(0)
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
