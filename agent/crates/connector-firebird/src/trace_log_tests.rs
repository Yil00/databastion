//! Tests of the trace-log record grammars against logs recorded from the
//! pinned images (`testdata/`, `isql`, `gbak` and `gfix` workloads with
//! the dev trace configuration; fake data only) and synthesized records.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use super::trace_log::*;

const V5_ISQL: &str = include_str!("../testdata/trace-5.0.4-isql-gbak.log");
const V5_TRIGGERS: &str = include_str!("../testdata/trace-5.0.4-triggers-sweep.log");
const V4_TRIGGERS: &str = include_str!("../testdata/trace-4.0.7-triggers-sweep.log");

fn records(log: &str) -> Vec<Assembled> {
    let mut a = Assembler::new();
    let mut out = Vec::new();
    for line in log.split('\n') {
        out.extend(a.push_line(line.as_bytes()));
    }
    out.extend(a.flush());
    out
}

fn raw(a: &Assembled) -> &[u8] {
    match a {
        Assembled::Record(r) => r,
        other => panic!("not a record: {other:?}"),
    }
}

fn opts(series: Series) -> ParseOptions {
    ParseOptions {
        max_sql_length: Some(65_000),
        series,
    }
}

/// Every recorded record parses well formed, except the two halves of the
/// header forged inside a comment (8f): the real record loses its trailer
/// (H1 fix 2) and the forged one has no attachment line.
#[test]
fn recorded_logs_parse_well_formed_and_the_forged_split_is_loud() {
    for (log, series) in [
        (V5_ISQL, Series::V5),
        (V5_TRIGGERS, Series::V5),
        (V4_TRIGGERS, Series::V4),
    ] {
        let recs = records(log);
        assert!(recs.len() > 50);
        let mut defects = Vec::new();
        for a in &recs {
            let r = parse(raw(a), opts(series)).expect("header");
            if let Some(d) = r.defect {
                defects.push((r.header.event, d));
            }
        }
        if log == V5_ISQL {
            assert_eq!(
                defects,
                [
                    (Event::ExecuteStatementFinish, Defect::MissingTrailer),
                    (Event::AttachDatabase, Defect::ContextLine),
                ],
            );
        } else {
            assert!(defects.is_empty(), "{defects:?}");
        }
    }
}

fn find<'a>(
    recs: &'a [Assembled],
    pred: impl Fn(&Record<'_>) -> bool,
    series: Series,
) -> Record<'a> {
    recs.iter()
        .filter_map(|a| parse(raw(a), opts(series)))
        .find(|r| pred(r))
        .expect("no such record")
}

#[test]
fn statement_records_keep_text_counters_and_rows() {
    let recs = records(V5_ISQL);
    let r = find(
        &recs,
        |r| matches!(r.body, Body::Statement { text, .. } if text == "SELECT * FROM T1"),
        Series::V5,
    );
    assert_eq!(r.header.pid, 24);
    assert_eq!(r.trailer.fetched, Some(2));
    assert_eq!(r.trailer.perf.unwrap().fetches, Some(7));
    let block = r.trailer.block.as_ref().unwrap();
    assert_eq!(block.len(), 1);
    assert_eq!(block[0].0, "T1");
    assert_eq!(block[0].1.natural, 2);
    let att = r.att.unwrap();
    assert_eq!((att.id, att.user, att.role), (3, "SYSDBA", Some("NONE")));
    assert_eq!(att.database, "/var/lib/firebird/data/app.fdb");
    assert!(matches!(att.protocol, Protocol::Tcp(_, 41410)));
    assert!(!r.client.unwrap().gbak);
    assert!(matches!(
        r.body,
        Body::Statement {
            id: Some(295),
            params: false,
            ..
        }
    ));
    // A parameter line after the text: dropped, flagged.
    let r = find(
        &recs,
        |r| matches!(r.body, Body::Statement { text, .. } if text == "SELECT NAME FROM T1 WHERE ID = ?"),
        Series::V5,
    );
    assert!(matches!(r.body, Body::Statement { params: true, .. }));
    // A name with spaces of 63 characters, read from the right.
    let r = find(
        &recs,
        |r| {
            r.trailer
                .block
                .as_ref()
                .is_some_and(|b| b.iter().any(|(n, _)| n.starts_with("A Very Long")))
        },
        Series::V5,
    );
    let b = r.trailer.block.unwrap();
    assert_eq!(
        b[0].0,
        "A Very Long Table Name With Spaces Up To Sixty Three Characters"
    );
    // The session-management form, without `Statement <n>:` (R20).
    let r = find(
        &recs,
        |r| {
            matches!(
                r.body,
                Body::Statement {
                    text: "SET TRANSACTION",
                    ..
                }
            )
        },
        Series::V5,
    );
    assert!(matches!(r.body, Body::Statement { id: None, .. }));
    assert_eq!(r.trailer.fetched, Some(0));
    // The backup DDL with its block of system relations (R36).
    let r = find(
        &recs,
        |r| {
            matches!(
                r.body,
                Body::Statement {
                    text: "ALTER DATABASE BEGIN BACKUP",
                    ..
                }
            )
        },
        Series::V5,
    );
    assert_eq!(r.trailer.block.unwrap()[0].0, "RDB$FILES");
}

#[test]
fn routine_records_follow_r14() {
    let recs = records(V5_ISQL);
    let f = find(
        &recs,
        |r| r.header.event == Event::ExecuteFunctionFinish,
        Series::V5,
    );
    assert!(matches!(
        f.body,
        Body::Routine {
            kind: RoutineKind::Function,
            returns: true,
            name: RoutineName {
                name: "F1",
                trigger: None
            }
        }
    ));
    assert_eq!(f.trailer.fetched, None);
    let p = find(
        &recs,
        |r| r.header.event == Event::ExecuteProcedureFinish && r.trailer.fetched.is_some(),
        Series::V5,
    );
    assert!(matches!(
        p.body,
        Body::Routine {
            name: RoutineName { name: "P1", .. },
            ..
        }
    ));
    let p = find(
        &recs,
        |r| r.header.event == Event::ExecuteProcedureFinish && r.trailer.fetched.is_none(),
        Series::V5,
    );
    assert!(matches!(
        p.body,
        Body::Routine {
            name: RoutineName { name: "P2", .. },
            ..
        }
    ));
    let t = find(
        &recs,
        |r| r.header.event == Event::ExecuteTriggerFinish,
        Series::V5,
    );
    assert!(matches!(
        t.body,
        Body::Routine {
            name: RoutineName {
                name: "TRB",
                trigger: Some(TriggerKind::Row)
            },
            ..
        }
    ));
    assert!(t.trailer.block.is_none());
    for (log, series) in [(V5_TRIGGERS, Series::V5), (V4_TRIGGERS, Series::V4)] {
        let recs = records(log);
        let c = find(
            &recs,
            |r| {
                matches!(
                    r.body,
                    Body::Routine {
                        name: RoutineName {
                            trigger: Some(TriggerKind::OnConnect),
                            ..
                        },
                        ..
                    }
                )
            },
            series,
        );
        assert!(matches!(
            c.body,
            Body::Routine {
                name: RoutineName {
                    name: "TR_CONN",
                    ..
                },
                ..
            }
        ));
        assert_eq!(c.trailer.block.as_ref().unwrap()[0].0, "T1");
        let d = find(
            &recs,
            |r| {
                matches!(
                    r.body,
                    Body::Routine {
                        name: RoutineName {
                            trigger: Some(TriggerKind::Ddl),
                            ..
                        },
                        ..
                    }
                )
            },
            series,
        );
        assert!(matches!(
            d.body,
            Body::Routine {
                name: RoutineName {
                    name: "DDL_AFTER_CT",
                    ..
                },
                ..
            }
        ));
        find(
            &recs,
            |r| {
                matches!(
                    r.body,
                    Body::Routine {
                        name: RoutineName {
                            trigger: Some(TriggerKind::OnTransactionCommit),
                            ..
                        },
                        ..
                    }
                )
            },
            series,
        );
        // Each series' grammar only.
        let other = if series == Series::V4 {
            Series::V5
        } else {
            Series::V4
        };
        let bad = recs
            .iter()
            .filter_map(|a| parse(raw(a), opts(other)))
            .filter(|r| r.header.event == Event::ExecuteTriggerFinish)
            .all(|r| r.defect == Some(Defect::Shape));
        assert!(bad, "a trigger name line parsed under the other series");
    }
}

#[test]
fn service_sweep_session_and_internal_records() {
    let recs = records(V5_ISQL);
    let s = find(&recs, |r| r.header.event == Event::StartService, Series::V5);
    assert!(matches!(
        s.body,
        Body::Service {
            user: "SYSDBA",
            name: Some(ServiceName::BackupDatabase),
            database: Some("/var/lib/firebird/data/app.fdb"),
            ..
        }
    ));
    let g = find(
        &recs,
        |r| r.att.is_some_and(|a| a.user == "Garbage Collector"),
        Series::V5,
    );
    let att = g.att.unwrap();
    assert_eq!(
        (att.role, att.protocol, att.charset),
        (None, Protocol::Internal, "NONE")
    );
    assert!(g.client.is_none());
    assert!(g.tra.unwrap().internal_flags);
    // The services backup's own database attachment carries the client
    // line of the service's client (here `gbak -se`).
    let a = find(
        &recs,
        |r| r.header.event == Event::AttachDatabase && r.client.is_some_and(|c| c.gbak),
        Series::V5,
    );
    assert_eq!(a.att.unwrap().id, 4);
    let i = find(&recs, |r| r.header.event == Event::TraceInit, Series::V5);
    assert_eq!(i.body, Body::Session);
    let e = find(&recs, |r| r.header.event == Event::Error, Series::V5);
    assert_eq!(e.header.at, Some(ErrorAt::FetchNext));
    assert_eq!(
        e.body,
        Body::Error {
            codes: vec![335_544_334],
            other_lines: 0
        }
    );
    for (log, series) in [(V5_TRIGGERS, Series::V5), (V4_TRIGGERS, Series::V4)] {
        let recs = records(log);
        let s = find(&recs, |r| r.header.event == Event::SweepFinish, series);
        assert_eq!(s.body, Body::Sweep { counters: true });
        assert!(s.trailer.perf.is_some());
        let s = find(&recs, |r| r.header.event == Event::SweepStart, series);
        assert_eq!(s.body, Body::Sweep { counters: true });
    }
}

#[test]
fn the_performance_line_grammar_is_exact() {
    assert_eq!(perf_line("      0 ms").unwrap().ms, 0);
    let p = perf_line("     18 ms, 137 read(s), 59 write(s), 2469 fetch(es), 123 mark(s)").unwrap();
    assert_eq!(
        (p.ms, p.reads, p.writes, p.fetches, p.marks),
        (18, Some(137), Some(59), Some(2469), Some(123))
    );
    assert_eq!(perf_line("1234567 ms").unwrap().ms, 1_234_567);
    for bad in [
        "0 ms",
        "       0 ms",
        "      0 ms, 1 mark(s), 1 fetch(es)",
        "      0 ms, 1 fetch(es), 1 fetch(es)",
        "      0 ms, 1 page(s)",
        "      0 ms ",
        "      x ms",
    ] {
        assert!(perf_line(bad).is_none(), "{bad}");
    }
}

#[test]
fn headers_are_closed() {
    let h = header(b"2026-10-30T15:22:38.3650 (24:0x7fdc1dd7adc0) FAILED EXECUTE_STATEMENT_FINISH")
        .unwrap();
    assert_eq!(
        (h.event, h.outcome, h.pid),
        (Event::ExecuteStatementFinish, Outcome::Failed, 24)
    );
    assert_eq!(h.address, 0x7fdc_1dd7_adc0);
    for bad in [
        &b"2026-10-30T15:22:38.365 (24:0x7f) TRACE_INIT"[..],
        b"2026-10-30T15:22:38.3650 (24:0x7f) TRACE_INIT ",
        b"2026-10-30T15:22:38.3650 (24:7f) TRACE_INIT",
        b"2026-10-30T15:22:38.3650 (24:0x7F) TRACE_INIT",
        b"2026-10-30T15:22:38.3650 (24:0x7f) SOMETHING_ELSE",
        b"2026-13-30T15:22:38.3650 (24:0x7f) TRACE_INIT",
        b"2026-10-30T15:22:38.3650 (24:0x7f) ERROR AT a b",
    ] {
        assert!(header(bad).is_none(), "{}", String::from_utf8_lossy(bad));
    }
}

const STATEMENT: &str = "2026-10-30T15:22:38.4210 (24:0x7fdc1dd7adc0) EXECUTE_STATEMENT_FINISH
\t/data/app.fdb (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/41410)
\t/usr/bin/app:28
\t\t(TRA_15, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)

Statement 295:
-------------------------------------------------------------------------------
@TEXT@
3 records fetched
      0 ms, 7 fetch(es)

@BLOCK@
";

/// A per-table block of one relation, as the server writes it.
pub(crate) fn block(name: &str, natural: u64) -> String {
    let width = name.len().max(32);
    let head = format!(
        "{:<w$}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge",
        "Table",
        w = width
    );
    format!(
        "{head}\n{}\n{name:<width$}{natural:>10}{}",
        "*".repeat(width + 80),
        " ".repeat(70)
    )
}

fn with_text(text: &str) -> String {
    STATEMENT
        .replace("@TEXT@", text)
        .replace("@BLOCK@", &block("T1", 3))
}

#[test]
fn injected_lines_in_a_text_are_loud() {
    let ok = with_text("SELECT * FROM T1");
    let recs = records(&ok);
    assert_eq!(recs.len(), 1);
    assert_eq!(
        parse(raw(&recs[0]), ParseOptions::default())
            .unwrap()
            .defect,
        None
    );
    for inject in [
        "SELECT 1 FROM T1 /*\n3 records fetched\n*/",
        "SELECT 1 FROM T1 /*\n      0 ms\n*/",
        "SELECT 1 /*\n-------------------------------------------------------------------------------\n*/",
        "SELECT 1 /*\nTable                              Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n*/",
    ] {
        let t = with_text(inject);
        let recs = records(&t);
        let r = parse(raw(&recs[0]), ParseOptions::default()).unwrap();
        assert_eq!(r.defect, Some(Defect::Injected), "{inject}");
    }
    // A cut text (decision 6).
    let t = with_text("SELECT A, B, C FROM T...");
    let recs = records(&t);
    let r = parse(
        raw(&recs[0]),
        ParseOptions {
            max_sql_length: Some(10),
            series: Series::V5,
        },
    )
    .unwrap();
    assert_eq!(r.defect, Some(Defect::CutText));
    // A user name holding `,` or `(`: the attachment line does not parse.
    for user in ["A,B:NONE", "A(B:NONE", "A:B:C"] {
        let t = with_text("SELECT 1").replace("APP:NONE", user);
        let recs = records(&t);
        let r = parse(raw(&recs[0]), ParseOptions::default()).unwrap();
        assert_eq!(r.defect, Some(Defect::ContextLine), "{user}");
    }
}

#[test]
fn the_assembler_bounds_records() {
    let mut a = Assembler::new();
    assert!(a.push_line(b"not a header").is_none());
    let h = b"2026-10-30T15:22:38.4210 (24:0x7f) TRACE_INIT";
    assert!(matches!(a.push_line(h), Some(Assembled::Orphan)));
    let big = vec![b'x'; 4096];
    for _ in 0..300 {
        assert!(a.push_line(&big).is_none());
    }
    assert!(matches!(
        a.push_line(h),
        Some(Assembled::Oversized(Some(_)))
    ));
    assert!(a.holding());
    assert!(matches!(a.flush(), Some(Assembled::Record(_))));
    assert!(!a.holding());
    assert!(a.flush().is_none());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any bytes: the assembler and the parser never panic.
    #[test]
    fn arbitrary_logs_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut a = Assembler::new();
        for line in bytes.split(|b| *b == b'\n') {
            if let Some(Assembled::Record(r)) = a.push_line(line) {
                let _ = parse(&r, ParseOptions::default());
            }
        }
        if let Some(Assembled::Record(r)) = a.flush() {
            let _ = parse(&r, ParseOptions::default());
        }
    }

    /// H1: a text holding a header line splits the record, and the split
    /// is never silent: the real record loses its trailer, and the record
    /// the forged header starts has a defect unless it is a complete,
    /// well-formed record of its own (the forger's fake trailer, R1).
    #[test]
    fn a_forged_header_in_a_text_is_loud(pre in "[A-Z ]{0,20}", post in "[A-Z ]{0,20}") {
        let t = with_text(&format!(
            "SELECT 1 FROM T1 /* {pre}\n2026-01-01T00:00:00.0000 (1:0x1) ATTACH_DATABASE\n{post} */"
        ));
        let recs = records(&t);
        prop_assert_eq!(recs.len(), 2);
        let first = parse(raw(&recs[0]), ParseOptions::default()).unwrap();
        prop_assert_eq!(first.defect, Some(Defect::MissingTrailer));
        let second = parse(raw(&recs[1]), ParseOptions::default()).unwrap();
        prop_assert!(second.defect.is_some());
    }

    /// A text with no line of the format is kept whole, borrowed.
    #[test]
    fn plain_texts_are_kept_whole(text in "[A-Za-z0-9_ ,.*=()']{1,200}") {
        let t = with_text(&format!("SELECT {text}"));
        let recs = records(&t);
        let r = parse(raw(&recs[0]), ParseOptions::default()).unwrap();
        let expected = format!("SELECT {text}");
        let ok = matches!(r.body, Body::Statement { text: got, .. } if got == expected);
        prop_assert!(ok || r.defect.is_some());
        prop_assert!(r.defect.is_none() || perf_line(&expected).is_some() || fetched_line(&expected).is_some());
    }
}
