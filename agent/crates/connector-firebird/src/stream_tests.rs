//! Tests of the multi-record rules ([`super::stream`]) on the recorded
//! logs of the pinned images and on synthesized forgeries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::own::Ledger;
use super::stream::*;
use super::trace_events::{Catalog, RelClass};
use super::trace_log::{Assembled, Assembler, ParseOptions, Series};

pub(crate) const APP: &str = "/var/lib/firebird/data/app.fdb";

struct Cat;
impl Catalog for Cat {
    fn class(&self, r: &str) -> RelClass {
        if r.starts_with("RDB$") {
            RelClass::System
        } else if r.starts_with("MON$") || r.starts_with("SEC$") {
            RelClass::Virtual
        } else {
            RelClass::Table
        }
    }
    fn always_view(&self, _: &str) -> bool {
        false
    }
}

fn settings(proof11: bool, series: Series) -> Settings {
    Settings {
        databases: vec![DeclaredNames {
            label: "app".to_owned(),
            resolved: Some(APP.to_owned()),
            alias: None,
            excluded: false,
            attach: APP.to_owned(),
        }],
        aliases: Some(Default::default()),
        proof11,
        account: "DATABASTION_AGENT".to_owned(),
        parse: ParseOptions {
            max_sql_length: Some(65_000),
            series,
        },
        superserver: true,
    }
}

/// Feeds a log through a fresh machine; returns it and the events.
fn run(log: &str, proof11: bool, series: Series) -> (Machine, Vec<Emitted>) {
    let mut m = Machine::new(settings(proof11, series), Arc::new(Ledger::default()));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let mut a = Assembler::new();
    let mut out = Vec::new();
    let now = Instant::now();
    let mut pos = 0u64;
    let mut recs = Vec::new();
    for line in log.split('\n') {
        recs.extend(a.push_line(line.as_bytes()));
    }
    recs.extend(a.flush());
    for r in &recs {
        if let Assembled::Record(raw) = r {
            m.push(raw, pos, now, &cats, &mut out);
            pos += raw.len() as u64 + 1;
        }
    }
    m.expire(now + Duration::from_secs(120), &cats, &mut out);
    (m, out)
}

/// Statement finishes without a `Statement <n>:` line whose text is not a
/// transaction statement (isql's DDL and DCL).
fn bare_ddl(log: &str) -> u64 {
    let lines: Vec<&str> = log.lines().collect();
    let mut n = 0;
    for (i, l) in lines.iter().enumerate() {
        if !l.ends_with(") EXECUTE_STATEMENT_FINISH") {
            continue;
        }
        let mut j = i + 1;
        while j < lines.len() && !lines[j].starts_with("---") && !lines[j].starts_with("Statement ")
        {
            j += 1;
        }
        if lines.get(j).is_some_and(|x| x.starts_with("---"))
            && let Some(t) = lines.get(j + 1)
            && !t.starts_with("SET TRANSACTION")
            && !t.starts_with("COMMIT")
            && !t.starts_with("ROLLBACK")
        {
            n += 1;
        }
    }
    n
}

fn names(out: &[Emitted]) -> Vec<String> {
    out.iter()
        .flat_map(|(_, e)| e.objects().iter().map(|o| o.object().as_str().to_owned()))
        .collect()
}

/// The recorded logs: every attachment is bound, the Garbage Collector's
/// records are internal, the triggers fold or follow their sequence; the
/// only ambiguous records are the forged split of the 5.0.4 log (a header
/// in a comment, 8f) and what its window covers.
#[test]
fn recorded_logs() {
    let (m, out) = run(
        include_str!("../testdata/trace-5.0.4-triggers-sweep.log"),
        false,
        Series::V5,
    );
    assert_eq!(m.counts.panics, 0);
    assert!(!out.is_empty());
    assert!(names(&out).iter().any(|n| n.eq_ignore_ascii_case("t1")));
    let (m4, _) = run(
        include_str!("../testdata/trace-4.0.7-triggers-sweep.log"),
        false,
        Series::V4,
    );
    assert_eq!(m4.counts.panics, 0);
    // No forgery in the trigger logs: the only ambiguous records are the
    // statement finishes `isql` writes without a `Statement <n>:` line for
    // DDL and DCL, which R20 makes ambiguous outside R8 case (b) (a fact
    // that contradicts R20, reported for a refinement).
    let t5 = include_str!("../testdata/trace-5.0.4-triggers-sweep.log");
    let t4 = include_str!("../testdata/trace-4.0.7-triggers-sweep.log");
    assert_eq!(m.counts.ambiguous, bare_ddl(t5), "5.0.4 {:?}", m.why);
    assert_eq!(m4.counts.ambiguous, bare_ddl(t4), "4.0.7 {:?}", m4.why);
    assert!(bare_ddl(t5) > 0);
    let (m5, _) = run(
        include_str!("../testdata/trace-5.0.4-isql-gbak.log"),
        false,
        Series::V5,
    );
    assert!(m5.counts.ambiguous > 0, "the forged split is loud");
}

pub(crate) const HEAD: &str = "2026-10-30T15:22:38.4210";

pub(crate) fn attach(token: &str, id: u64, db: &str) -> String {
    format!(
        "{HEAD} ({token}) TRACE_INIT\n\tSESSION_1 Firebird Audit\n\t\n\n{HEAD} ({token}) ATTACH_DATABASE\n\t{db} (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\n"
    )
}

pub(crate) fn select(token: &str, id: u64, tra: u64, db: &str, rel: &str, rows: u64) -> String {
    format!(
        "{HEAD} ({token}) START_TRANSACTION\n\t{db} (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\t\t(TRA_{tra}, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\n\
         {HEAD} ({token}) EXECUTE_STATEMENT_FINISH\n\t{db} (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\t\t(TRA_{tra}, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nStatement 1:\n{}\nSELECT * FROM {rel} WHERE ID > 0\n{rows} records fetched\n      0 ms, 7 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{rel:<35}{rows:>10}{:>70}\n\n",
        "-".repeat(79),
        "Table",
        "*".repeat(115),
        ""
    )
}

#[test]
fn bindings_tokens_and_poisoning() {
    let a = "24:0x7f0000000100";
    let b = "24:0x7f0000000200";
    // A well-formed attachment and read.
    let ok = format!(
        "{}{}",
        attach(a, 3, APP),
        select(a, 3, 5, APP, "CUSTOMERS", 2)
    );
    let (m, out) = run(&ok, true, Series::V5);
    assert_eq!(m.counts.ambiguous, 0);
    assert_eq!(names(&out), ["CUSTOMERS"]);
    // A record of the attachment under another token: ambiguous.
    let wrong = format!(
        "{}{}",
        attach(a, 3, APP),
        select(b, 3, 5, APP, "CUSTOMERS", 2)
    );
    let (m, out) = run(&wrong, true, Series::V5);
    assert!(m.counts.ambiguous > 0);
    assert!(out.iter().all(|(_, e)| e.always_report()));
    // A duplicate attach poisons both (R1 rule 3).
    let dup = format!(
        "{}{}{}",
        attach(a, 3, APP),
        attach(b, 3, APP),
        select(a, 3, 5, APP, "CUSTOMERS", 2)
    );
    let (m, _) = run(&dup, true, Series::V5);
    assert!(m.counts.ambiguous >= 2);
    // Another pid: ambiguous (R1 rule 2), never dropped.
    let other = format!(
        "{}{}",
        attach(a, 3, APP),
        select("99:0x7f0000000100", 3, 5, APP, "T", 1)
    );
    let (m, _) = run(&other, true, Series::V5);
    assert!(m.counts.ambiguous > 0);
}

/// R1 rule 8 and R2: undeclared databases ambiguous under proof 11,
/// dropped without it; a same-file-name path is ambiguous (M4).
#[test]
fn undeclared_databases() {
    let a = "24:0x7f0000000100";
    let other = "/data/other.fdb";
    let log = format!("{}{}", attach(a, 3, other), select(a, 3, 5, other, "T", 1));
    let (m, out) = run(&log, true, Series::V5);
    assert!(m.counts.ambiguous > 0 && !out.is_empty());
    let (m, out) = run(&log, false, Series::V5);
    assert_eq!(m.counts.ambiguous, 0);
    assert!(m.counts.undeclared_dropped > 0 && out.is_empty());
    let same = "/elsewhere/app.fdb";
    let log = format!("{}{}", attach(a, 3, same), select(a, 3, 5, same, "T", 1));
    let (m, _) = run(&log, false, Series::V5);
    assert!(m.counts.ambiguous > 0);
    // An alias not in the map.
    let log = format!(
        "{}{}",
        attach(a, 3, "appalias"),
        select(a, 3, 5, "appalias", "T", 1)
    );
    let (m, _) = run(&log, false, Series::V5);
    assert!(m.counts.ambiguous > 0);
}

/// R1 rule 7: a statement finish without its trailer opens a window; the
/// records inside it are ambiguous.
#[test]
fn split_windows() {
    let a = "24:0x7f0000000100";
    let cut = format!(
        "{HEAD} ({a}) EXECUTE_STATEMENT_FINISH\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nStatement 1:\n{}\nSELECT 1 FROM RDB$DATABASE\n\n",
        "-".repeat(79)
    );
    let log = format!("{}{cut}{}", attach(a, 3, APP), select(a, 3, 6, APP, "T", 1));
    let (m, out) = run(&log, true, Series::V5);
    assert!(m.counts.ambiguous >= 2, "{:?}", m.counts);
    assert!(out.iter().all(|(_, e)| e.always_report()));
}

/// R4: a procedure record folds into its statement (objects united, rows
/// by maximum).
#[test]
fn routine_records_fold() {
    let a = "24:0x7f0000000100";
    let proc_rec = format!(
        "{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nProcedure P1:\n      0 ms, 3 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n\n",
        "Table",
        "*".repeat(115),
        "SECRETS",
        5,
        ""
    );
    let sel = select(a, 3, 5, APP, "CUSTOMERS", 2);
    let at = sel
        .find(&format!("{HEAD} ({a}) EXECUTE_STATEMENT_FINISH"))
        .unwrap();
    let (start, finish) = sel.split_at(at);
    let log = format!("{}{start}{proc_rec}{finish}", attach(a, 3, APP));
    let (m, out) = run(&log, true, Series::V5);
    assert_eq!(m.counts.ambiguous, 0, "{:?}", m.counts);
    assert_eq!(out.len(), 1);
    let n = names(&out);
    assert!(
        n.contains(&"CUSTOMERS".to_owned())
            && n.contains(&"SECRETS".to_owned())
            && n.contains(&"P1".to_owned()),
        "{n:?}"
    );
}

/// R1 rule 1 and R5 item 4: a confirmed run change ends every binding;
/// a start-time change makes records ambiguous until a confirmation; a
/// pending fold group holds the persisted position back.
#[test]
fn runs_and_held_positions() {
    let a = "24:0x7f0000000100";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    m.reconfigure(settings(true, Series::V5));
    m.confirm_run(Run {
        pid: 24,
        start: Some(1),
    });
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let now = Instant::now();
    let mut out = Vec::new();
    let feed = |m: &mut Machine, log: &str, out: &mut Vec<Emitted>| {
        let mut asm = Assembler::new();
        let mut recs = Vec::new();
        for line in log.split('\n') {
            recs.extend(asm.push_line(line.as_bytes()));
        }
        recs.extend(asm.flush());
        for (i, r) in recs.iter().enumerate() {
            if let Assembled::Record(raw) = r {
                m.push(raw, i as u64 * 100, now, &cats, out);
            }
        }
    };
    feed(&mut m, &attach(a, 3, APP), &mut out);
    assert_eq!(m.counts.ambiguous, 0);
    assert_eq!(m.held_from(), None);
    // The same pid, another start time: ambiguous until confirmed.
    m.start_time_changed();
    feed(&mut m, &select(a, 3, 5, APP, "T", 1), &mut out);
    assert!(m.counts.ambiguous > 0);
    // Confirmed: the old run's binding is gone, the record is learned.
    m.confirm_run(Run {
        pid: 24,
        start: Some(2),
    });
    let before = m.counts.ambiguous;
    feed(&mut m, &select(a, 3, 6, APP, "T", 1), &mut out);
    assert_eq!(m.counts.ambiguous, before);
}

/// A statement finish of `user` on attachment `id` (port `40000 + id`).
#[allow(clippy::too_many_arguments)]
fn stmt(
    token: &str,
    id: u64,
    tra: u64,
    user: &str,
    text: &str,
    fetched: u64,
    block: &[(&str, u64)],
) -> String {
    let mut out = format!(
        "{HEAD} ({token}) EXECUTE_STATEMENT_FINISH\n\t{APP} (ATT_{id}, {user}:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\t\t(TRA_{tra}, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nStatement 1:\n{}\n{text}\n{fetched} records fetched\n      0 ms, 7 fetch(es)\n",
        "-".repeat(79)
    );
    if !block.is_empty() {
        out.push_str(&format!(
            "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n",
            "Table",
            "*".repeat(115)
        ));
        for (r, n) in block {
            out.push_str(&format!("{r:<35}{n:>10}{:>70}\n", ""));
        }
    }
    out.push('\n');
    out
}

fn attach_as(token: &str, id: u64, user: &str) -> String {
    format!(
        "{HEAD} ({token}) ATTACH_DATABASE\n\t{APP} (ATT_{id}, {user}:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\n"
    )
}

fn feed(m: &mut Machine, cats: &[&dyn Catalog], log: &str, base: u64) -> Vec<Emitted> {
    let mut asm = Assembler::new();
    let mut recs = Vec::new();
    for line in log.split('\n') {
        recs.extend(asm.push_line(line.as_bytes()));
    }
    recs.extend(asm.flush());
    let mut out = Vec::new();
    let now = Instant::now();
    for (i, r) in recs.iter().enumerate() {
        if let Assembled::Record(raw) = r {
            m.push(raw, base + i as u64 * 1000, now, cats, &mut out);
        }
    }
    out
}

/// Review L2: a permission refusal of another client is an attempt to
/// read: `*`, always reported, no text; other error codes give nothing.
#[test]
fn permission_refusals_of_other_clients_are_reported() {
    let a = "24:0x7f0000000100";
    let err = |code: &str| {
        format!(
            "{HEAD} ({a}) ERROR AT JStatement::prepare\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n{code} : no permission for SELECT access to TABLE PAYROLL\n\n"
        )
    };
    let (m, out) = run(
        &format!("{}{}", attach(a, 3, APP), err("335544352")),
        true,
        Series::V5,
    );
    assert_eq!(m.counts.ambiguous, 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].1.always_report());
    assert_eq!(names(&out), ["*"]);
    let (_, out) = run(
        &format!("{}{}", attach(a, 3, APP), err("335544334")),
        true,
        Series::V5,
    );
    assert!(out.is_empty());
}

struct ViewCat;
impl Catalog for ViewCat {
    fn class(&self, r: &str) -> RelClass {
        match r {
            "V_X" => RelClass::View,
            _ => Cat.class(r),
        }
    }
    fn always_view(&self, r: &str) -> bool {
        r == "V_DEP"
    }
}

/// R12 item 5: a view of the dependency set gives `*` and the mark; R28
/// item 4: view DDL invalidates the sets until the next check.
#[test]
fn views_over_always_reported_relations_and_view_ddl() {
    let a = "24:0x7f0000000100";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let cat = ViewCat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let read = |rel: &str, tra: u64| {
        stmt(
            a,
            3,
            tra,
            "APP",
            &format!("SELECT * FROM {rel} WHERE ID > 0"),
            2,
            &[("CUSTOMERS", 2)],
        )
    };
    let out = feed(
        &mut m,
        &cats,
        &format!("{}{}", attach(a, 3, APP), read("V_DEP", 5)),
        0,
    );
    assert!(
        out.iter().any(|(_, e)| e.always_report()),
        "{:?}",
        names(&out)
    );
    assert!(names(&out).contains(&"*".to_owned()));
    let out = feed(&mut m, &cats, &read("V_X", 6), 10_000);
    assert!(!out.is_empty() && out.iter().all(|(_, e)| !e.always_report()));
    // A view DDL record: every view counts as dependent until a check.
    let ddl = stmt(
        a,
        3,
        7,
        "APP",
        "CREATE VIEW V_NEW AS SELECT ID FROM CUSTOMERS",
        0,
        &[],
    );
    feed(&mut m, &cats, &ddl, 20_000);
    let out = feed(&mut m, &cats, &read("V_X", 8), 30_000);
    assert!(
        out.iter().all(|(_, e)| e.always_report()),
        "{:?}",
        names(&out)
    );
    m.reconfigure(settings(true, Series::V5));
    let out = feed(&mut m, &cats, &read("V_X", 9), 40_000);
    assert!(out.iter().all(|(_, e)| !e.always_report()));
}

/// R39 (g) through the stream: an own record is the agent's only with its
/// text's row (here `RDB$DATABASE` must be read, nothing outside the
/// may-read set); a copy with a user table in its block is not, and a
/// closed-set text with no credit left is `*`, always reported. Review
/// M3: the clock offset learned from the own attach is confirmed only by
/// the credited record, and reverted when its binding is poisoned.
#[test]
fn own_records_follow_the_table_and_confirm_the_offset() {
    use crate::conn::{FetchAccount, FetchEnd};
    let a = "24:0x7f0000000100";
    let ledger = Arc::new(Ledger::default());
    // Opened one hour after the printed time: a whole-hour offset.
    let printed = super::stream::naive_seconds(super::trace_log::LogTime {
        year: 2026,
        month: 10,
        day: 30,
        hour: 15,
        minute: 22,
        second: 38,
        frac: 4210,
    });
    let opened = std::time::SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(printed + 3600).unwrap());
    ledger.register_at(APP, 3, 40003, 24, opened);
    let account = |counted| FetchAccount {
        counted,
        requested: 64,
        last: 64,
        largest: 64,
        end: FetchEnd::End,
        ..FetchAccount::default()
    };
    let mut m = Machine::new(settings(true, Series::V5), Arc::clone(&ledger));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let agent = "DATABASTION_AGENT";
    feed(&mut m, &cats, &attach_as(a, 3, agent), 0);
    assert_eq!(m.offset_for_tests(), None, "provisional until credited");
    let before = m.counts.own;
    let v = crate::sql::VERSION;
    ledger.credit(APP, 3, v, None, account(1));
    let out = feed(
        &mut m,
        &cats,
        &stmt(a, 3, 5, agent, v, 1, &[("RDB$DATABASE", 1)]),
        1000,
    );
    assert!(out.is_empty());
    assert_eq!(m.counts.own, before + 1);
    assert_eq!(m.offset_for_tests(), Some(3600));
    // A copy carrying a user table: not the agent's own, reported.
    ledger.credit(APP, 3, v, None, account(1));
    let out = feed(
        &mut m,
        &cats,
        &stmt(a, 3, 6, agent, v, 1, &[("RDB$DATABASE", 1), ("PAYROLL", 1)]),
        2000,
    );
    assert!(names(&out).contains(&"PAYROLL".to_owned()));
    // The credit is still there for the agent's real record.
    let out = feed(
        &mut m,
        &cats,
        &stmt(a, 3, 7, agent, v, 1, &[("RDB$DATABASE", 1)]),
        3000,
    );
    assert!(out.is_empty());
    // No credit left: loud.
    let out = feed(
        &mut m,
        &cats,
        &stmt(a, 3, 8, agent, v, 1, &[("RDB$DATABASE", 1)]),
        4000,
    );
    assert!(!out.is_empty() && out.iter().all(|(_, e)| e.always_report()));
    assert!(names(&out).contains(&"*".to_owned()));
    // A duplicate attach poisons the binding: the offset reverts.
    feed(
        &mut m,
        &cats,
        &attach_as("24:0x7f0000000200", 3, agent),
        5000,
    );
    assert_eq!(m.offset_for_tests(), None);
}

#[test]
fn plausible_offsets() {
    for o in [0, 3600, -3600, 19_800, 20_700, -12_600, 3603, 3597] {
        assert!(super::stream::plausible_offset(o), "{o}");
    }
    for o in [7, 3610, 900 * 4 + 450, 15 * 3600, -15 * 3600] {
        assert!(!super::stream::plausible_offset(o), "{o}");
    }
}
