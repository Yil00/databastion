//! Tests of the single-record rules (ADR-0060 decision 6 and its
//! refinements): the R36 parser cases of the four server-side copy forms,
//! the #82 I2 marker cases of R4, R33 item 5 and the lot 3 obligations,
//! and the recorded logs of the pinned images.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::time::SystemTime;

use databastion_classifiers::masking::{EventAction, Signal};

use super::trace_events::*;
use super::trace_log::*;

/// The catalog of the recorded and synthesized databases.
struct Cat(HashMap<&'static str, RelClass>);

impl Catalog for Cat {
    fn class(&self, relation: &str) -> RelClass {
        if let Some(c) = self.0.get(relation) {
            return *c;
        }
        // The test databases' system relations (in production: the
        // catalog's system flag and the decision 5 list, never a prefix).
        if relation.starts_with("RDB$") {
            RelClass::System
        } else if relation.starts_with("MON$") || relation.starts_with("SEC$") {
            RelClass::Virtual
        } else {
            RelClass::Unknown
        }
    }

    fn always_view(&self, relation: &str) -> bool {
        relation == "V_STATEMENTS"
    }
}

fn cat() -> Cat {
    Cat(HashMap::from([
        ("T1", RelClass::Table),
        ("T_EMPTY", RelClass::Table),
        ("GTT1", RelClass::Gtt),
        ("CUSTOMERS", RelClass::Table),
        ("V1", RelClass::View),
        ("EXT_EXPORT", RelClass::External),
        ("RDB$CONFIG", RelClass::Virtual),
        ("RDB$CUSTOMER_ARCHIVE", RelClass::Table),
    ]))
}

const HEAD: &str = "2026-10-30T15:22:38.4210 (24:0x7fdc1dd7adc0)";
const ATT: &str = "\t/data/app.fdb (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/41410)";
const TRA: &str = "\t\t(TRA_15, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)";
const DASHES: &str =
    "-------------------------------------------------------------------------------";

/// A per-table block, as the server writes it.
fn block(rows: &[(&str, u64, u64)]) -> String {
    let mut s = format!(
        "{:<35}{}\n{}\n",
        "Table",
        "   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge",
        "*".repeat(115)
    );
    for (name, natural, insert) in rows {
        let n = |v: u64| {
            if v == 0 {
                format!("{:>10}", "")
            } else {
                format!("{v:>10}")
            }
        };
        s.push_str(&format!(
            "{name:<35}{}{}{}{}{}{}{}{}\n",
            n(*natural),
            n(0),
            n(0),
            n(*insert),
            n(0),
            n(0),
            n(0),
            n(0)
        ));
    }
    s
}

fn statement(text: &str, extra: &str, fetched: u64, blk: Option<&str>) -> String {
    let mut s = format!(
        "{HEAD} EXECUTE_STATEMENT_FINISH\n{ATT}\n\t/usr/bin/app:28\n{TRA}\n\nStatement 7:\n{DASHES}\n{text}\n{extra}{fetched} records fetched\n      0 ms, 7 fetch(es)\n"
    );
    if let Some(b) = blk {
        s.push('\n');
        s.push_str(b);
    }
    s
}

fn one(record: &str) -> Converted {
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for l in record.split('\n') {
        recs.extend(a.push_line(l.as_bytes()));
    }
    recs.extend(a.flush());
    assert_eq!(recs.len(), 1, "{record}");
    let Assembled::Record(raw) = &recs[0] else {
        panic!("not a record")
    };
    let rec = parse(raw, ParseOptions::default()).expect("header");
    convert(&rec, &cat())
}

/// The event of one record, as the uplink would see it (debug form).
fn event_text(record: &str) -> String {
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for l in record.split('\n') {
        recs.extend(a.push_line(l.as_bytes()));
    }
    recs.extend(a.flush());
    let mut out = String::new();
    for r in &recs {
        let Assembled::Record(raw) = r else { continue };
        let rec = parse(raw, ParseOptions::default()).unwrap();
        let draft = match convert(&rec, &cat()) {
            Converted::Event(d) | Converted::Ambiguous { draft: d, .. } => d,
            Converted::Nothing => continue,
        };
        let ev = to_event(&draft, &rec, "app", SystemTime::UNIX_EPOCH);
        out.push_str(&format!("{draft:?} {ev:?}\n"));
    }
    out
}

/// The events of a log text.
fn events(log: &str) -> Vec<databastion_classifiers::masking::MaskedEvent> {
    let mut a = Assembler::new();
    let mut recs = Vec::new();
    for l in log.split('\n') {
        recs.extend(a.push_line(l.as_bytes()));
    }
    recs.extend(a.flush());
    recs.iter()
        .filter_map(|r| {
            let Assembled::Record(raw) = r else {
                return None;
            };
            let rec = parse(raw, ParseOptions::default()).unwrap();
            match convert(&rec, &cat()) {
                Converted::Event(d) | Converted::Ambiguous { draft: d, .. } => {
                    Some(to_event(&d, &rec, "app", SystemTime::UNIX_EPOCH))
                }
                Converted::Nothing => None,
            }
        })
        .collect()
}

fn event(c: Converted) -> Draft {
    match c {
        Converted::Event(d) => d,
        other => panic!("not an event: {other:?}"),
    }
}

/// R36 item 1: `ALTER DATABASE BEGIN BACKUP`, `CREATE SHADOW`, `ADD FILE`
/// and `ADD DIFFERENCE FILE`, block-ful (system relations only) and
/// block-less: exactly one event with `signature.backup_database`, `*`,
/// the always-reported mark and the record's principal.
#[test]
fn server_side_copies_always_give_one_event() {
    let files = block(&[("RDB$FILES", 0, 1)]);
    for text in [
        "ALTER DATABASE BEGIN BACKUP",
        "CREATE SHADOW 1 '/tmp/app.shd'",
        "ALTER DATABASE ADD FILE '/tmp/app2.fdb'",
        "ALTER DATABASE ADD DIFFERENCE FILE '/tmp/app.delta'",
    ] {
        for blk in [Some(files.as_str()), None] {
            let rec = statement(text, "", 0, blk).replace("Statement 7:\n", "");
            let d = event(one(&rec));
            assert_eq!(d.signals, [Signal::BackupDatabase], "{text}");
            assert!(d.star && d.always, "{text}");
            assert!(d.objects.is_empty(), "{text}: {:?}", d.objects);
            assert_eq!(d.action, Some(EventAction::Ddl), "{text}");
            let ev_text = event_text(&rec);
            assert_eq!(ev_text.lines().count(), 1, "{text}");
            assert!(!ev_text.contains("/tmp/"), "{ev_text}");
            let evs = events(&rec);
            assert_eq!(evs.len(), 1, "{text}");
            assert_eq!(evs[0].principal().account_name(), "APP", "{text}");
            assert!(evs[0].always_report() && evs[0].signals() == [Signal::BackupDatabase]);
        }
    }
    // The end of a backup and dropping a copy are DDL events (kind kept,
    // `*`, always reported) without the signal.
    for text in ["ALTER DATABASE END BACKUP", "DROP SHADOW 1"] {
        let rec = statement(text, "", 0, Some(&files)).replace("Statement 7:\n", "");
        let d = event(one(&rec));
        assert_eq!(d.action, Some(EventAction::Ddl), "{text}");
        assert!(d.signals.is_empty() && d.star && d.always, "{text}");
    }
}

/// The recorded 5.0.4 log: the backup forms there give their event, the
/// services backup and the direct `gbak` attachment their signal (R27
/// item 1), and no record of the log panics or carries a literal.
#[test]
fn the_recorded_log_gives_the_backup_events() {
    let log = include_str!("../testdata/trace-5.0.4-isql-gbak.log");
    let out = event_text(log);
    let backups = out.lines().filter(|l| l.contains("BackupDatabase")).count();
    // BEGIN BACKUP, ADD DIFFERENCE FILE, CREATE SHADOW, the services
    // backup, and the gbak client's attachments.
    assert!(backups >= 4, "{backups}\n{out}");
    for literal in ["/tmp/app.delta", "/tmp/app.shd", "/tmp/app.fbk"] {
        assert!(!out.contains(literal), "{literal}");
    }
}

#[test]
fn statement_rules() {
    // A block-ful read: counters and text united, rows, no signal under
    // the limit.
    let d = event(one(&statement(
        "SELECT * FROM T1 WHERE ID = 1",
        "",
        1,
        Some(&block(&[("T1", 1, 0), ("RDB$DATABASE", 1, 0)])),
    )));
    assert_eq!(d.objects, ["T1"]);
    assert_eq!(d.rows, Some(1));
    assert!(d.signals.is_empty() && !d.star && !d.always);
    // A full read and a large result.
    let d = event(one(&statement(
        "SELECT * FROM T1",
        "",
        20_000,
        Some(&block(&[("T1", 20_000, 0)])),
    )));
    assert_eq!(d.signals, [Signal::FullTableRead, Signal::LargeResult]);
    // A write.
    let d = event(one(&statement(
        "INSERT INTO T1 (ID) VALUES (3)",
        "",
        0,
        Some(&block(&[("T1", 0, 1)])),
    )));
    assert_eq!(d.action, Some(EventAction::Write));
    // Always-reported relations keep their name and mark; views over them
    // too (R12 item 5).
    let d = event(one(&statement("SELECT * FROM MON$STATEMENTS", "", 0, None)));
    assert_eq!(d.objects, ["MON$STATEMENTS"]);
    assert!(d.always);
    let d = event(one(&statement(
        "SELECT * FROM V_STATEMENTS",
        "",
        2,
        Some(&block(&[("RDB$DATABASE", 1, 0)])),
    )));
    assert!(d.always && d.objects == ["V_STATEMENTS"]);
    // A user table named like a system relation is an ordinary object.
    let d = event(one(&statement(
        "SELECT * FROM \"RDB$CUSTOMER_ARCHIVE\" WHERE 1 = 1",
        "",
        1,
        Some(&block(&[("RDB$CUSTOMER_ARCHIVE", 1, 0)])),
    )));
    assert_eq!(d.objects, ["RDB$CUSTOMER_ARCHIVE"]);
    // Noise: a read of virtual relations only, outside the lists.
    assert_eq!(
        one(&statement(
            "SELECT MON$SERVER_PID FROM MON$ATTACHMENTS",
            "",
            1,
            None
        )),
        Converted::Nothing
    );
    // Code: `*`, always reported (R8 case (c)).
    let d = event(one(&statement("EXECUTE BLOCK AS BEGIN END", "", 0, None)));
    assert!(d.star && d.always);
    // External-file tables: remote data, `*`.
    let d = event(one(&statement(
        "SELECT * FROM EXT_EXPORT WHERE 1 = 1",
        "",
        0,
        None,
    )));
    assert!(d.signals.contains(&Signal::RemoteDataAccess) && d.star);
}

/// R8 item 1, R12: the block-less shapes.
#[test]
fn block_less_statements() {
    // The no-record shape: 0 rows, or one aggregate row over tables.
    let d = event(one(&statement(
        "SELECT * FROM T1 WHERE ID = 9",
        "",
        0,
        None,
    )));
    assert_eq!(d.objects, ["T1"]);
    assert_eq!(d.rows, Some(0));
    let d = event(one(&statement("SELECT COUNT(*) FROM T_EMPTY", "", 1, None)));
    assert_eq!(d.objects, ["T_EMPTY"]);
    let d = event(one(&statement("SELECT COUNT(*) FROM GTT1", "", 1, None)));
    assert_eq!(d.objects, ["GTT1"]);
    // One aggregate row over a view: a block was expected (R12 item 1).
    assert!(matches!(
        one(&statement("SELECT COUNT(*) FROM V1", "", 1, None)),
        Converted::Ambiguous { window: true, .. }
    ));
    // Rows from a table without a block: ambiguous, a window.
    assert!(matches!(
        one(&statement("SELECT * FROM T1", "", 3, None)),
        Converted::Ambiguous { window: true, .. }
    ));
    // Session statements read nothing (R8 case (b)).
    for t in [
        "COMMIT",
        "SET TRANSACTION",
        "SAVEPOINT S1",
        "ALTER SESSION RESET",
    ] {
        assert_eq!(one(&statement(t, "", 0, None)), Converted::Nothing, "{t}");
    }
    // R24 item 3 and R34 item 1: transaction statements and resets may
    // carry a block; other session statements may not.
    let trig = block(&[("T1", 2, 0)]);
    for t in ["COMMIT", "SET TRANSACTION", "ALTER SESSION RESET"] {
        let d = event(one(&statement(t, "", 0, Some(&trig))));
        assert_eq!(d.objects, ["T1"], "{t}");
        assert_eq!(d.rows, None, "{t}");
    }
    assert!(matches!(
        one(&statement("SAVEPOINT S1", "", 0, Some(&trig))),
        Converted::Ambiguous { .. }
    ));
    // R12 item 3: a text ending inside an unterminated construct.
    assert!(matches!(
        one(&statement("SELECT * FROM T1 /* x", "", 0, None)),
        Converted::Ambiguous { window: true, .. }
    ));
    // Differing dialect readings: `*`, always reported, no window.
    let d = event(one(&statement(
        "SELECT * FROM \"T1\" WHERE A = 1",
        "",
        0,
        None,
    )));
    assert!(d.star && d.always);
}

/// R33: BLR records.
#[test]
fn blr_records() {
    let compile = format!(
        "{HEAD} COMPILE_BLR\n{ATT}\n\t/usr/bin/blrclient:9\n\nStatement 12:\n{DASHES}\n      0 ms\n"
    );
    assert_eq!(one(&compile), Converted::Nothing);
    let execute = format!(
        "{HEAD} EXECUTE_BLR\n{ATT}\n\t/usr/bin/blrclient:9\n{TRA}\n\nStatement 12:\n{DASHES}\n      0 ms, 2 fetch(es)\n\n{}",
        block(&[("CUSTOMERS", 1, 0)])
    );
    let d = event(one(&execute));
    assert_eq!(d.objects, ["CUSTOMERS"]);
    assert!(d.star && d.always && d.rows.is_none());
    let refused = compile.replace("COMPILE_BLR", "UNAUTHORIZED COMPILE_BLR");
    assert!(matches!(one(&refused), Converted::Ambiguous { .. }));
}

/// R24 items 1 and 2, R10 item 3, R27 item 1.
#[test]
fn transaction_attachment_and_service_records() {
    let commit = format!(
        "{HEAD} COMMIT_TRANSACTION\n{ATT}\n\t/usr/bin/app:28\n{TRA}\n     48 ms, 105 read(s), 5 write(s), 278 fetch(es), 4 mark(s)\n\n{}",
        block(&[("RDB$FILES", 3, 2)])
    );
    assert_eq!(one(&commit), Converted::Nothing);
    let commit = commit.replace("RDB$FILES", "SEC$USERS");
    let d = event(one(&commit));
    assert!(d.always && d.objects == ["SEC$USERS"]);
    let failed = format!("{HEAD} FAILED ATTACH_DATABASE\n{ATT}\n\t/usr/bin/app:28\n");
    let d = event(one(&failed));
    assert_eq!(d.action, Some(EventAction::AuthFailure));
    let gbak = format!("{HEAD} ATTACH_DATABASE\n{ATT}\n\t/opt/firebird/bin/gbak:40\n");
    let d = event(one(&gbak));
    assert_eq!(d.signals, [Signal::BackupDatabase]);
    let plain = format!("{HEAD} ATTACH_DATABASE\n{ATT}\n\t/usr/bin/app:28\n");
    assert_eq!(one(&plain), Converted::Nothing);
    let service = format!(
        "{HEAD} START_SERVICE\n\tservice_mgr, (Service 0x7fdc1e6754c0, SYSDBA, TCPv4:127.0.0.1/41416, /opt/firebird/bin/gbak:40)\n\t\"Backup Database\"\n\t-b /data/app.fdb /tmp/app.fbk\n"
    );
    let d = event(one(&service));
    assert_eq!(d.signals, [Signal::BackupDatabase]);
    assert!(d.star && d.always);
    let users = service.replace("Backup Database", "Add User").replace(
        "\t-b /data/app.fdb /tmp/app.fbk\n",
        "\t-user_name X -user_password Y\n",
    );
    let d = event(one(&users));
    assert_eq!(d.action, Some(EventAction::Dcl));
}

/// The #82 I2 marker cases of R4 and R33 item 5 and the lot 3
/// obligations, at the parser and event level: no marker reaches a draft
/// or an event (the end-to-end test asserts the same for the uplink, the
/// logs and the metrics).
#[test]
fn markers_never_reach_an_event() {
    const M: &str = "DBMARKER42";
    let routine = |kind: &str, line: &str, returns: &str| {
        format!(
            "{HEAD} EXECUTE_{kind}_FINISH\n{ATT}\n\t/usr/bin/{M}proc:28\n{TRA}\n\n{line}\n\nparam0 = varchar(32), \"{M}\"\n{returns}\n      0 ms, 3 fetch(es)\n\n{}",
            block(&[("T1", 1, 0)])
        )
    };
    let cases = [
        // A statement literal.
        statement(
            &format!("SELECT * FROM T1 WHERE A = '{M}'"),
            "",
            0,
            Some(&block(&[("T1", 1, 0)])),
        ),
        // A parameter.
        statement(
            "SELECT * FROM T1 WHERE A = ?",
            &format!("\nparam0 = varchar(32), \"{M}\"\n\n"),
            0,
            Some(&block(&[("T1", 1, 0)])),
        ),
        // The client process name.
        statement(
            "SELECT * FROM T1 WHERE ID = 1",
            "",
            1,
            Some(&block(&[("T1", 1, 0)])),
        )
        .replace("/usr/bin/app:28", &format!("/usr/bin/{M}:28")),
        // A password (the #82 rule).
        statement(&format!("CREATE USER U PASSWORD '{M}'"), "", 0, None),
        // A cut literal (decision 6: the rest after the quote dropped).
        statement(&format!("SELECT * FROM T1 WHERE A = '{M}"), "", 0, None),
        // EXECUTE STATEMENT's inner text, written as a statement record.
        statement(
            &format!("EXECUTE BLOCK AS BEGIN EXECUTE STATEMENT 'SELECT ''{M}'' FROM T1'; END"),
            "",
            0,
            None,
        ),
        statement(
            &format!("SELECT '{M}' FROM T1 WHERE 1 = 1"),
            "",
            0,
            Some(&block(&[("T1", 1, 0)])),
        ),
        // A BLR literal under print_blr, and a BLR client's process name.
        format!(
            "{HEAD} EXECUTE_BLR\n{ATT}\n\t/usr/bin/{M}:9\n{TRA}\n\nStatement 12:\n{DASHES}\n   0 blr_version5,\n   1 blr_begin,\n   2    blr_literal, blr_text2, 0,0, 10,0, '{M}',\n      0 ms, 2 fetch(es)\n\n{}",
            block(&[("CUSTOMERS", 1, 0)])
        ),
        // A routine's returned value and argument.
        routine(
            "FUNCTION",
            "Function F0:",
            &format!("\nreturns:\nparam0 = varchar(32), \"{M}\"\n"),
        ),
        routine("PROCEDURE", "Procedure P0:", ""),
        // A database trigger record's process name.
        routine("TRIGGER", "Trigger TR_CONN (ON CONNECT):", ""),
        // A failed attach's user name (fingerprinted, never in clear).
        format!(
            "{HEAD} FAILED ATTACH_DATABASE\n\t/data/app.fdb (ATT_0, {M}:NONE, UTF8, TCPv4:127.0.0.1/41410)\n\t/usr/bin/app:28\n"
        ),
    ];
    for (i, rec) in cases.iter().enumerate() {
        let out = event_text(rec);
        assert!(!out.contains(M), "case {i}: {out}");
        assert!(!out.contains(&M.to_lowercase()), "case {i}: {out}");
    }
}
