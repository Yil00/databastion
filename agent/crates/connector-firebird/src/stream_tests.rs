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
            read_at: None,
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
    assert!(m.check_requested, "view DDL asks for an early check");
    let out = feed(&mut m, &cats, &read("V_X", 8), 30_000);
    assert!(
        out.iter().all(|(_, e)| e.always_report()),
        "{:?}",
        names(&out)
    );
    // R41 item 8 (review M2): a check whose catalog read started before
    // the DDL transaction's end does not clear the invalidation.
    let early = std::time::SystemTime::now();
    let at = |t: std::time::SystemTime| {
        let mut s = settings(true, Series::V5);
        s.databases[0].read_at = Some(t);
        s
    };
    m.reconfigure(at(early));
    let out = feed(&mut m, &cats, &read("V_X", 9), 40_000);
    assert!(
        out.iter().all(|(_, e)| e.always_report()),
        "the DDL is still open"
    );
    // The DDL transaction ends; a check read started before the end does
    // not clear it either, one started after does.
    let commit = format!(
        "{HEAD} ({a}) COMMIT_TRANSACTION\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_7, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n      0 ms, 1 fetch(es)\n\n"
    );
    m.check_requested = false;
    feed(&mut m, &cats, &commit, 45_000);
    assert!(
        m.check_requested,
        "a DDL transaction's end asks for an early check"
    );
    m.reconfigure(at(early));
    let out = feed(&mut m, &cats, &read("V_X", 10), 50_000);
    assert!(out.iter().all(|(_, e)| e.always_report()));
    std::thread::sleep(Duration::from_millis(5));
    m.reconfigure(at(std::time::SystemTime::now()));
    let out = feed(&mut m, &cats, &read("V_X", 11), 60_000);
    assert!(
        out.iter().all(|(_, e)| !e.always_report()),
        "{:?}",
        names(&out)
    );
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
    let (head, opened) = now_head(3600);
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
    feed_h(&head, &mut m, &cats, &attach_as(a, 3, agent), 0);
    assert_eq!(m.offset_for_tests(), None, "provisional until credited");
    let before = m.counts.own;
    let v = crate::sql::VERSION;
    ledger.credit_at(APP, 3, v, account(1), opened);
    let out = feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(a, 3, 5, agent, v, 1, &[("RDB$DATABASE", 1)]),
        1000,
    );
    assert!(out.is_empty());
    assert_eq!(m.counts.own, before + 1);
    assert_eq!(m.offset_for_tests(), Some(3600));
    // A copy carrying a user table: not the agent's own, reported.
    ledger.credit_at(APP, 3, v, account(1), opened);
    let out = feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(a, 3, 6, agent, v, 1, &[("RDB$DATABASE", 1), ("PAYROLL", 1)]),
        2000,
    );
    assert!(names(&out).contains(&"PAYROLL".to_owned()));
    // The credit is still there for the agent's real record.
    let out = feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(a, 3, 7, agent, v, 1, &[("RDB$DATABASE", 1)]),
        3000,
    );
    assert!(out.is_empty());
    // No credit left: loud.
    let out = feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(a, 3, 8, agent, v, 1, &[("RDB$DATABASE", 1)]),
        4000,
    );
    assert!(!out.is_empty() && out.iter().all(|(_, e)| e.always_report()));
    assert!(names(&out).contains(&"*".to_owned()));
    // A duplicate attach poisons the binding: the offset reverts.
    feed_h(
        &head,
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

/// Review H2 (I2): an ambiguous failed attach (here of a pid other than
/// the run's) never sends the attempted user name in clear: its principal
/// is fingerprinted, as for a well-formed failed attach (#82 marker case).
#[test]
fn an_ambiguous_failed_attach_never_sends_the_user_name() {
    const M: &str = "hunter2marker";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    m.confirm_run(Run {
        pid: 24,
        start: None,
    });
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    for (token, outcome) in [
        ("99:0x7f0000000900", "FAILED"),
        ("99:0x7f0000000901", "UNAUTHORIZED"),
        ("24:0x7f0000000902", "FAILED"),
    ] {
        let rec = format!(
            "{HEAD} ({token}) {outcome} ATTACH_DATABASE\n\t{APP} (ATT_0, {M}:NONE, UTF8, TCPv4:127.0.0.1/45555)\n\t/usr/bin/app:28\n\n"
        );
        let out = feed(&mut m, &cats, &rec, 0);
        assert!(!out.is_empty(), "{token}");
        for (_, e) in &out {
            assert!(!e.principal().send_name(), "{token}");
            assert!(!format!("{e:?}").contains(M), "{token}: {e:?}");
        }
    }
    assert!(m.counts.ambiguous >= 2);
}

/// Review M1: a transaction-end record of the agent's own attachment whose
/// block names a user relation is reported, not credited; a statement of
/// the agent's attachment that folded a routine group is not credited and
/// keeps the group's relations.
#[test]
fn own_transaction_records_and_folds_keep_their_relations() {
    let l = Arc::new(Ledger::default());
    l.register(APP, 3, 40003, 24);
    let mut m = Machine::new(settings(true, Series::V5), Arc::clone(&l));
    m.confirm_run(Run {
        pid: 24,
        start: None,
    });
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let tok = "24:0x7f0000000100";
    let att = format!(
        "\t{APP} (ATT_3, DATABASTION_AGENT:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/agent:28\n"
    );
    let tra = "\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_ONLY)\n";
    let blk = |rel: &str| {
        format!(
            "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{rel:<35}{:>10}{:>70}\n",
            "Table",
            "*".repeat(115),
            50,
            ""
        )
    };
    let log = format!(
        "{HEAD} ({tok}) ATTACH_DATABASE\n{att}\n{HEAD} ({tok}) START_TRANSACTION\n{att}{tra}\n{HEAD} ({tok}) COMMIT_TRANSACTION\n{att}{tra}      0 ms, 7 fetch(es)\n{}\n",
        blk("PAYROLL")
    );
    let out = feed(&mut m, &cats, &log, 0);
    assert!(
        names(&out).contains(&"PAYROLL".to_owned()),
        "{:?}",
        names(&out)
    );
    // A routine group folded into an own-text statement.
    let v = crate::sql::VERSION;
    l.credit(
        APP,
        3,
        v,
        None,
        crate::conn::FetchAccount {
            counted: 1,
            requested: 64,
            last: 64,
            largest: 64,
            end: crate::conn::FetchEnd::End,
            ..crate::conn::FetchAccount::default()
        },
    );
    let log = format!(
        "{HEAD} ({tok}) START_TRANSACTION\n{att}\t\t(TRA_6, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_ONLY)\n\n\
         {HEAD} ({tok}) EXECUTE_PROCEDURE_FINISH\n{att}\t\t(TRA_6, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_ONLY)\n\nProcedure P1:\n      0 ms, 3 fetch(es)\n{}\n{}",
        blk("SECRETS"),
        stmt(tok, 3, 6, "DATABASTION_AGENT", v, 1, &[("RDB$DATABASE", 1)])
    );
    let out = feed(&mut m, &cats, &log, 10_000);
    assert!(
        names(&out).contains(&"SECRETS".to_owned()),
        "{:?}",
        names(&out)
    );
}

/// Review L3: a record whose header does not parse is ambiguous (loud),
/// never dropped silently.
#[test]
fn an_unparsable_record_is_loud() {
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let mut out = Vec::new();
    m.push(
        b"not a trace record\nPAYROLL 50",
        0,
        Instant::now(),
        &cats,
        &mut out,
    );
    assert_eq!(m.counts.ambiguous, 1);
    assert!(!out.is_empty() && out.iter().all(|(_, e)| e.always_report()));
}

/// Review L5: DDL of code a view can depend on (a procedure) invalidates
/// the view sets as view DDL does.
#[test]
fn procedure_ddl_invalidates_the_view_sets() {
    let a = "24:0x7f0000000100";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let cat = ViewCat;
    let cats: [&dyn Catalog; 1] = [&cat];
    feed(&mut m, &cats, &attach(a, 3, APP), 0);
    let ddl = stmt(a, 3, 7, "APP", "ALTER PROCEDURE P1 AS BEGIN END", 0, &[]);
    feed(&mut m, &cats, &ddl, 1000);
    assert!(m.check_requested);
    let out = feed(
        &mut m,
        &cats,
        &stmt(
            a,
            3,
            8,
            "APP",
            "SELECT * FROM V_X WHERE ID > 0",
            2,
            &[("CUSTOMERS", 2)],
        ),
        2000,
    );
    assert!(
        out.iter().all(|(_, e)| e.always_report()),
        "{:?}",
        names(&out)
    );
}

struct LootCat;
impl Catalog for LootCat {
    fn class(&self, r: &str) -> RelClass {
        if r == "RDB$LOOT" {
            RelClass::Table
        } else {
            Cat.class(r)
        }
    }
    fn always_view(&self, _: &str) -> bool {
        false
    }
}

/// Review L6: an ambiguous record attributed to a database (fix 3) is
/// classed with that database's catalog, not the first one's.
#[test]
fn ambiguous_records_use_the_attributed_databases_catalog() {
    const CRM: &str = "/var/lib/firebird/data/crm.fdb";
    let mut s = settings(true, Series::V5);
    s.databases.push(DeclaredNames {
        label: "crm".to_owned(),
        resolved: Some(CRM.to_owned()),
        alias: None,
        excluded: false,
        attach: CRM.to_owned(),
        read_at: None,
    });
    let mut m = Machine::new(s, Arc::new(Ledger::default()));
    let (c0, c1) = (Cat, LootCat);
    let cats: [&dyn Catalog; 2] = [&c0, &c1];
    let a = "24:0x7f0000000100";
    // A well-formed record of crm, then an ambiguous one (another token
    // on crm's attachment) whose block names RDB$LOOT, a user table of
    // crm only.
    let log = format!(
        "{}{}",
        attach(a, 3, CRM),
        select("24:0x7f0000000999", 3, 5, CRM, "RDB$LOOT", 2)
    );
    let out = feed(&mut m, &cats, &log, 0);
    assert!(m.counts.ambiguous > 0);
    assert!(
        names(&out).contains(&"RDB$LOOT".to_owned()),
        "{:?}",
        names(&out)
    );
}

/// Review M5, R25: a per-row routine run 10 000 times before its
/// statement finish (block-ful, then block-less) folds into one event,
/// with no ambiguous record; past 256 distinct relations the folded event
/// names `*` and is always reported, never ambiguous.
#[test]
fn ten_thousand_per_row_routine_records_fold() {
    let a = "24:0x7f0000000100";
    let ctx = format!(
        "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
    );
    let blk = |rel: &str| {
        format!(
            "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{rel:<35}{:>10}{:>70}\n",
            "Table",
            "*".repeat(115),
            3,
            ""
        )
    };
    for (block, distinct) in [(true, false), (false, false), (true, true)] {
        let mut log = format!(
            "{}{HEAD} ({a}) START_TRANSACTION\n{ctx}\n",
            attach(a, 3, APP)
        );
        for i in 0..10_000 {
            let b = match (block, distinct) {
                (true, false) => blk("CUSTOMERS"),
                (true, true) => blk(&format!("T{i}")),
                _ => String::new(),
            };
            log.push_str(&format!(
                "{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n{ctx}\nProcedure P1:\n      0 ms, 3 fetch(es)\n{b}\n"
            ));
        }
        log.push_str(&stmt(
            a,
            3,
            5,
            "APP",
            "SELECT P1_X FROM ORDERS WHERE ID > 0",
            10_000,
            &[("ORDERS", 10_000)],
        ));
        let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
        let cat = Cat;
        let cats: [&dyn Catalog; 1] = [&cat];
        let t = std::time::Instant::now();
        let out = feed(&mut m, &cats, &log, 0);
        // The assembler clears only what it wrote (it cleared its whole
        // 1 MiB reservation per record before: about 100 s here).
        assert!(t.elapsed() < Duration::from_secs(30), "{:?}", t.elapsed());
        assert_eq!(
            m.counts.ambiguous, 0,
            "block {block} distinct {distinct}: {:?}",
            m.why
        );
        assert_eq!(out.len(), 1, "{:?}", names(&out));
        let n = names(&out);
        if distinct {
            // Past 256 relations: `*`, always reported (the core keeps 15
            // named objects).
            assert!(n.contains(&"*".to_owned()), "{n:?}");
            assert!(out[0].1.always_report());
        } else {
            assert!(
                n.contains(&"ORDERS".to_owned()) && n.contains(&"P1".to_owned()),
                "{n:?}"
            );
            assert!(!out[0].1.always_report());
        }
        if block && !distinct {
            assert!(n.contains(&"CUSTOMERS".to_owned()));
        }
    }
}

/// The clock offset's change limit (coordinator's note on R40 item 2): a
/// confirmed offset moves by at most one hour on an ordinary credited own
/// record; a larger move needs the read-back probe (proof 7).
#[test]
fn a_confirmed_offset_moves_by_more_than_an_hour_only_on_the_probe() {
    use crate::conn::{FetchAccount, FetchEnd};
    let account = FetchAccount {
        counted: 1,
        requested: 64,
        last: 64,
        largest: 64,
        end: FetchEnd::End,
        ..FetchAccount::default()
    };
    // Attachment 3 sees the server one hour behind, attachment 4 four.
    let (h1, now) = now_head(3600);
    let (h4, _) = now_head(4 * 3600);
    let ledger = Arc::new(Ledger::default());
    ledger.register_at(APP, 3, 40003, 24, now);
    ledger.register_at(APP, 4, 40004, 24, now);
    let mut m = Machine::new(settings(true, Series::V5), Arc::clone(&ledger));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let agent = "DATABASTION_AGENT";
    let v = crate::sql::VERSION;
    let p = crate::sql::READ_BACK_PROBE;
    let (t3, t4) = ("24:0x7f0000000100", "24:0x7f0000000200");
    feed_h(&h1, &mut m, &cats, &attach_as(t3, 3, agent), 0);
    ledger.credit_at(APP, 3, v, account, now);
    feed_h(
        &h1,
        &mut m,
        &cats,
        &stmt(t3, 3, 5, agent, v, 1, &[("RDB$DATABASE", 1)]),
        1000,
    );
    assert_eq!(m.offset_for_tests(), Some(3600));
    // Three hours away: an ordinary credited record does not move it, and
    // an early check is asked for (R42 item 3).
    m.check_requested = false;
    feed_h(&h4, &mut m, &cats, &attach_as(t4, 4, agent), 2000);
    assert!(m.check_requested);
    ledger.credit_at(APP, 4, v, account, now);
    feed_h(
        &h4,
        &mut m,
        &cats,
        &stmt(t4, 4, 6, agent, v, 1, &[("RDB$DATABASE", 1)]),
        3000,
    );
    assert_eq!(m.offset_for_tests(), Some(3600));
    // A later attach does not overwrite the pending change.
    feed_h(
        &h1,
        &mut m,
        &cats,
        &attach_as("24:0x7f0000000300", 5, agent),
        3500,
    );
    // The read-back probe on that attachment confirms it.
    ledger.credit_at(APP, 4, p, account, now);
    feed_h(
        &h4,
        &mut m,
        &cats,
        &stmt(t4, 4, 7, agent, p, 1, &[("RDB$DATABASE", 1)]),
        4000,
    );
    assert_eq!(m.offset_for_tests(), Some(4 * 3600));
    // A second probe record on that binding poisons it (R42 item 2).
    ledger.credit_at(APP, 4, p, account, now);
    feed_h(
        &h4,
        &mut m,
        &cats,
        &stmt(t4, 4, 8, agent, p, 1, &[("RDB$DATABASE", 1)]),
        5000,
    );
    assert_eq!(
        m.offset_for_tests(),
        Some(3600),
        "reverted with the poisoned binding"
    );
}

/// Review H-A, R1 rule 11: a million forged records (fresh attachment ids
/// on a declared database, learned records with fresh ids, attaches to a
/// thousand undeclared databases, failed attaches with fresh tokens)
/// leave the stream's state under its 16 MiB cap; past the caps, records
/// are ambiguous, never kept.
#[test]
fn a_million_forged_records_stay_under_the_cap() {
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let now = Instant::now();
    let mut out = Vec::new();
    let mut max = 0usize;
    for i in 0u64..1_000_000 {
        let token = format!("24:0x{:x}", 0x1000_0000 + i);
        let id = 100_000 + i;
        let rec = match i % 4 {
            0 => format!(
                "{HEAD} ({token}) ATTACH_DATABASE\n\t{APP} (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/41000)\n\t/usr/bin/app:28\n"
            ),
            1 => format!(
                "{HEAD} ({token}) START_TRANSACTION\n\t{APP} (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/41000)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
            ),
            2 => format!(
                "{HEAD} ({token}) ATTACH_DATABASE\n\t/x/db{}.fdb (ATT_{id}, APP:NONE, UTF8, TCPv4:127.0.0.1/41000)\n\t/usr/bin/app:28\n",
                i % 1000
            ),
            _ => format!(
                "{HEAD} ({token}) FAILED ATTACH_DATABASE\n\t{APP} (ATT_0, APP:NONE, UTF8, TCPv4:127.0.0.1/41000)\n\t/usr/bin/app:28\n"
            ),
        };
        m.push(rec.as_bytes(), i * 300, now, &cats, &mut out);
        out.clear();
        if i % 10_000 == 0 {
            max = max.max(m.state_bytes());
        }
    }
    max = max.max(m.state_bytes());
    assert!(max <= super::stream::MAX_STREAM_BYTES, "{max}");
    assert!(m.counts.ambiguous > 0);
    assert_eq!(m.counts.panics, 0);
}

/// Re-review M-A (I2), #82: an `ERROR AT JProvider::attachDatabase`
/// record (ambiguous from another pid, or a permission refusal of the run)
/// never sends the attempted user name in clear.
#[test]
fn attach_error_records_never_send_the_user_name() {
    const M: &str = "pw-marker-ma";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    m.confirm_run(Run {
        pid: 24,
        start: None,
    });
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let mut seen = 0;
    for (token, code) in [
        ("99:0x7f0000000900", "335544472"),
        ("24:0x7f0000000901", "335544352"),
    ] {
        let rec = format!(
            "{HEAD} ({token}) ERROR AT JProvider::attachDatabase\n\t{APP} (ATT_0, {M}:NONE, UTF8, TCPv4:127.0.0.1/45555)\n\t/usr/bin/app:28\n{code} : Your user name and password are not defined\n\n"
        );
        for (_, e) in feed(&mut m, &cats, &rec, 0) {
            seen += 1;
            assert!(!e.principal().send_name(), "{token}");
            assert!(!format!("{e:?}").contains(M), "{token}: {e:?}");
        }
    }
    assert!(seen >= 2, "{seen}");
}

/// Re-review L-A: a routine record whose block names an always-reported
/// relation keeps the mark in its group; a group ended unfolded (its
/// transaction ends) gives an always-reported event.
#[test]
fn an_unfolded_group_keeps_the_always_reported_mark() {
    let a = "24:0x7f0000000100";
    let ctx = format!(
        "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
    );
    let log = format!(
        "{}{HEAD} ({a}) START_TRANSACTION\n{ctx}\n{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n{ctx}\nProcedure P1:\n      0 ms, 3 fetch(es)\n\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n\n{HEAD} ({a}) COMMIT_TRANSACTION\n{ctx}      0 ms, 1 fetch(es)\n\n",
        attach(a, 3, APP),
        "Table",
        "*".repeat(115),
        "MON$STATEMENTS",
        4,
        ""
    );
    let (m, out) = run(&log, true, Series::V5);
    assert_eq!(m.counts.ambiguous, 0, "{:?}", m.why);
    let ev: Vec<_> = out
        .iter()
        .filter(|(_, e)| {
            e.objects()
                .iter()
                .any(|o| o.object().as_str() == "MON$STATEMENTS")
        })
        .collect();
    assert!(!ev.is_empty(), "{:?}", names(&out));
    assert!(ev.iter().all(|(_, e)| e.always_report()));
}

/// Re-review L-C, R1 rule 7: a record of the agent's anchored binding
/// inside a split window ends it only when it is the agent's own; a
/// record of that binding that is not (no credit) is ambiguous and the
/// window stays.
#[test]
fn only_an_own_record_ends_a_split_window() {
    use crate::conn::{FetchAccount, FetchEnd};
    let ledger = Arc::new(Ledger::default());
    let (head, printed) = now_head(0);
    ledger.register_at(APP, 3, 40003, 24, printed);
    let mut m = Machine::new(settings(true, Series::V5), Arc::clone(&ledger));
    m.confirm_run(Run {
        pid: 24,
        start: None,
    });
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let agent = "DATABASTION_AGENT";
    let own = "24:0x7f0000000100";
    let other = "24:0x7f0000000200";
    feed_h(&head, &mut m, &cats, &attach_as(own, 3, agent), 0);
    feed_h(&head, &mut m, &cats, &attach(other, 4, APP), 1000);
    // A cut statement of the other client opens a window.
    let cut = format!(
        "{HEAD} ({other}) EXECUTE_STATEMENT_FINISH\n\t{APP} (ATT_4, APP:NONE, UTF8, TCPv4:127.0.0.1/40004)\n\t/usr/bin/app:28\n\t\t(TRA_9, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\nStatement 1:\n{}\nSELECT 1 FROM RDB$DATABASE\n\n",
        "-".repeat(79)
    );
    feed_h(&head, &mut m, &cats, &cut, 2000);
    let v = crate::sql::VERSION;
    // The agent's binding, a text with no credit: ambiguous, window stays.
    let before = m.counts.ambiguous;
    let out = feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(
            own,
            3,
            5,
            agent,
            "SELECT A FROM T WHERE ID = 1",
            1,
            &[("T", 1)],
        ),
        3000,
    );
    assert!(m.counts.ambiguous > before);
    assert!(out.iter().all(|(_, e)| e.always_report()));
    let before = m.counts.ambiguous;
    feed_h(
        &head,
        &mut m,
        &cats,
        &select(other, 4, 10, APP, "CUSTOMERS", 2),
        4000,
    );
    assert!(m.counts.ambiguous > before, "the window is still open");
    // A credited own record ends it.
    ledger.credit_at(
        APP,
        3,
        v,
        FetchAccount {
            counted: 1,
            requested: 64,
            last: 64,
            largest: 64,
            end: FetchEnd::End,
            ..FetchAccount::default()
        },
        printed,
    );
    feed_h(
        &head,
        &mut m,
        &cats,
        &stmt(own, 3, 6, agent, v, 1, &[("RDB$DATABASE", 1)]),
        5000,
    );
    let before = m.counts.ambiguous;
    feed_h(
        &head,
        &mut m,
        &cats,
        &select(other, 4, 11, APP, "CUSTOMERS", 2),
        6000,
    );
    assert_eq!(m.counts.ambiguous, before, "{:?}", m.why);
}

/// Review L3 (re-review note): a record whose rules actually panic is
/// isolated: counted, ambiguous (`*`, always reported), and the next
/// record is judged as usual.
#[test]
fn a_panicking_record_is_isolated_and_loud() {
    let a = "24:0x7f0000000100";
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    feed(&mut m, &cats, &attach(a, 3, APP), 0);
    let mut out = Vec::new();
    let rec = format!(
        "{HEAD} ({a}) START_TRANSACTION\n\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\nPANIC-FOR-TESTS"
    );
    m.push(rec.as_bytes(), 5000, Instant::now(), &cats, &mut out);
    assert_eq!(m.counts.panics, 1);
    assert!(!out.is_empty() && out.iter().all(|(_, e)| e.always_report()));
    let out = feed(&mut m, &cats, &select(a, 3, 6, APP, "CUSTOMERS", 2), 9000);
    assert!(names(&out).contains(&"CUSTOMERS".to_owned()));
}

/// Review L4 (dedicated): a record of the agent's attachment that the
/// conversion judges ambiguous (here the session text written without a
/// statement line but with a row) never consumes a credit, and is always
/// reported.
#[test]
fn an_ambiguous_own_text_never_consumes_a_credit() {
    use crate::conn::{FetchAccount, FetchEnd};
    let ledger = Arc::new(Ledger::default());
    ledger.register(APP, 3, 40003, 24);
    let mut m = Machine::new(settings(true, Series::V5), Arc::clone(&ledger));
    let cat = Cat;
    let cats: [&dyn Catalog; 1] = [&cat];
    let own = "24:0x7f0000000100";
    let agent = "DATABASTION_AGENT";
    feed(&mut m, &cats, &attach_as(own, 3, agent), 0);
    let t = crate::sql::IDLE_TIMEOUT;
    ledger.credit(
        APP,
        3,
        t,
        None,
        FetchAccount {
            end: FetchEnd::NotRun,
            ..FetchAccount::default()
        },
    );
    let rec = format!(
        "{HEAD} ({own}) EXECUTE_STATEMENT_FINISH\n\t{APP} (ATT_3, {agent}:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n\n{}\n{t}\n1 records fetched\n      0 ms, 1 fetch(es)\n\n",
        "-".repeat(79)
    );
    let out = feed(&mut m, &cats, &rec, 1000);
    assert!(!out.is_empty() && out.iter().all(|(_, e)| e.always_report()));
    assert_eq!(ledger.credits_left().len(), 1, "the credit stays");
}

/// A catalog with a given dependent set (R41).
struct DepCat(&'static [&'static str]);
impl Catalog for DepCat {
    fn class(&self, r: &str) -> RelClass {
        Cat.class(r)
    }
    fn always_view(&self, r: &str) -> bool {
        self.0.contains(&r)
    }
}

fn ctx(id: u64, tra: u64, charset: &str) -> String {
    format!(
        "\t{APP} (ATT_{id}, APP:NONE, {charset}, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\t\t(TRA_{tra}, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
    )
}

fn stmt_cs(token: &str, id: u64, tra: u64, charset: &str, text: &str, outcome: &str) -> String {
    format!(
        "{HEAD} ({token}) {outcome}EXECUTE_STATEMENT_FINISH\n{}\nStatement 1:\n{}\n{text}\n0 records fetched\n      0 ms, 7 fetch(es)\n\n",
        ctx(id, tra, charset),
        "-".repeat(79)
    )
}

/// R41 items 4 and 6: a statement naming an object of the dependent set
/// at any position (a procedure in `FROM`, a `MERGE … USING` source, a
/// packaged name by its package), a failed one too, and a non-ASCII
/// quoted identifier from a non-UTF8 attachment, gives `*` and the
/// always-reported mark; another statement does not.
#[test]
fn records_naming_dependent_objects_are_marked() {
    let a = "24:0x7f0000000100";
    let cat = DepCat(&["P_MON", "PKG"]);
    let cats: [&dyn Catalog; 1] = [&cat];
    for (text, outcome, charset, want) in [
        ("SELECT * FROM P_MON", "", "UTF8", true),
        (
            "MERGE INTO T USING P_MON ON 1 = 1 WHEN MATCHED THEN DELETE",
            "",
            "UTF8",
            true,
        ),
        ("SELECT PKG . F(1) FROM T WHERE ID = 1", "", "UTF8", true),
        ("SELECT * FROM P_MON", "FAILED ", "UTF8", true),
        (
            "SELECT * FROM \"Tabelle_ä\" WHERE ID = 1",
            "",
            "WIN1252",
            true,
        ),
        ("SELECT A FROM T WHERE ID = 1", "", "UTF8", false),
    ] {
        let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
        feed(&mut m, &cats, &attach(a, 3, APP), 0);
        let out = feed(
            &mut m,
            &cats,
            &stmt_cs(a, 3, 5, charset, text, outcome),
            1000,
        );
        let marked = out.iter().any(|(_, e)| {
            e.always_report() && e.objects().iter().any(|o| o.object().as_str() == "*")
        });
        assert_eq!(marked, want, "{text} {outcome}{charset}: {:?}", names(&out));
    }
}

/// R41 item 5 (review M1): a block-less database-trigger record of a
/// dependent trigger gives an always-reported `*` event; a block-less one
/// of another trigger gives none (R15 item 4).
#[test]
fn block_less_dependent_database_triggers_are_reported() {
    let a = "24:0x7f0000000100";
    let cat = DepCat(&["TR_MON"]);
    let cats: [&dyn Catalog; 1] = [&cat];
    for (trigger, want) in [("TR_MON", true), ("TR_OK", false)] {
        let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
        let log = format!(
            "{}{HEAD} ({a}) START_TRANSACTION\n{}\n{HEAD} ({a}) EXECUTE_TRIGGER_FINISH\n{}\nTrigger {trigger} (ON CONNECT):\n      0 ms, 2 fetch(es)\n\n",
            attach(a, 3, APP),
            ctx(3, 5, "UTF8"),
            ctx(3, 5, "UTF8")
        );
        let out = feed(&mut m, &cats, &log, 0);
        assert_eq!(m.counts.ambiguous, 0, "{trigger}: {:?}", m.why);
        assert_eq!(!out.is_empty(), want, "{trigger}: {:?}", names(&out));
        assert!(out.iter().all(|(_, e)| e.always_report()));
    }
}

/// R41 item 7 (review L5): a dependent routine record inside a per-row
/// group that ends early (its transaction ends unfolded) keeps the mark
/// on the group's event.
#[test]
fn a_dependent_routine_in_a_group_ended_early_keeps_the_mark() {
    let a = "24:0x7f0000000100";
    let cat = DepCat(&["P_MON"]);
    let cats: [&dyn Catalog; 1] = [&cat];
    let mut m = Machine::new(settings(true, Series::V5), Arc::new(Ledger::default()));
    let blk = format!(
        "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n",
        "Table",
        "*".repeat(115),
        "CUSTOMERS",
        3,
        ""
    );
    let mut log = format!(
        "{}{HEAD} ({a}) START_TRANSACTION\n{}\n",
        attach(a, 3, APP),
        ctx(3, 5, "UTF8")
    );
    for name in ["P_OK", "P_MON", "P_OK"] {
        log.push_str(&format!(
            "{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n{}\nProcedure {name}:\n      0 ms, 3 fetch(es)\n{blk}\n",
            ctx(3, 5, "UTF8")
        ));
    }
    log.push_str(&format!(
        "{HEAD} ({a}) COMMIT_TRANSACTION\n{}      0 ms, 1 fetch(es)\n\n",
        ctx(3, 5, "UTF8")
    ));
    let out = feed(&mut m, &cats, &log, 0);
    let ev: Vec<_> = out
        .iter()
        .filter(|(_, e)| {
            e.objects()
                .iter()
                .any(|o| o.object().as_str() == "CUSTOMERS")
        })
        .collect();
    assert!(!ev.is_empty(), "{:?}", names(&out));
    assert!(ev.iter().all(|(_, e)| e.always_report()));
}

/// A header time `offset` seconds before now (the server's printed local
/// time when the agent's clock minus it is `offset`), and the agent time
/// it stands for, whole seconds (R42 tests: credits live 15 minutes on the
/// agent's clock).
fn now_head(offset: i64) -> (String, std::time::SystemTime) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let agent = i64::try_from(now).unwrap();
    let printed = agent - offset;
    // Civil from days (Howard Hinnant).
    let days = printed.div_euclid(86_400);
    let secs = printed.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let head = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.0000",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    );
    let at = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(now);
    (head, at)
}

#[test]
fn now_head_round_trips() {
    let (head, at) = now_head(3600);
    let t = super::trace_log::LogTime {
        year: head[0..4].parse().unwrap(),
        month: head[5..7].parse().unwrap(),
        day: head[8..10].parse().unwrap(),
        hour: head[11..13].parse().unwrap(),
        minute: head[14..16].parse().unwrap(),
        second: head[17..19].parse().unwrap(),
        frac: 0,
    };
    let agent = i64::try_from(
        at.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert_eq!(agent - super::stream::naive_seconds(t), 3600);
}

/// `feed` with every header time replaced by `head` (R42 tests).
fn feed_h(
    head: &str,
    m: &mut Machine,
    cats: &[&dyn Catalog],
    log: &str,
    base: u64,
) -> Vec<Emitted> {
    feed(m, cats, &log.replace(HEAD, head), base)
}

/// R42 item 1 (TZ test): the measured offset is the agent's UTC minus the
/// server's printed local time, so a server zone of UTC+h gives −h. Every
/// zone in use, from UTC−12 to UTC+14 on the quarter-hour grid, is
/// accepted within 5 s and rounded to the grid; zones outside the range,
/// and offsets off the grid by more than 5 s, are refused.
#[test]
fn time_zones_on_the_grid() {
    use super::stream::grid_offset;
    let zone = |h: i64, m: i64| -(h * 3600 + h.signum() * m * 60);
    for (name, z) in [
        ("UTC", zone(0, 0)),
        ("Europe/Paris CET", zone(1, 0)),
        ("Europe/Paris CEST", zone(2, 0)),
        ("Asia/Kolkata", zone(5, 30)),
        ("Asia/Kathmandu", zone(5, 45)),
        ("Australia/Eucla", zone(8, 45)),
        ("Pacific/Kiritimati", zone(14, 0)),
        ("Pacific/Marquesas", zone(-9, 30)),
        ("Etc/GMT+12", zone(-12, 0)),
    ] {
        for drift in [-5, -1, 0, 3, 5] {
            assert_eq!(grid_offset(z + drift), Some(z), "{name} {drift}");
        }
        assert_eq!(grid_offset(z + 6), None, "{name} off the grid");
    }
    assert_eq!(
        grid_offset(zone(-13, 0)),
        None,
        "UTC-13 is outside the range"
    );
    assert_eq!(
        grid_offset(zone(15, 0)),
        None,
        "UTC+15 is outside the range"
    );
}
