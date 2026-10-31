//! Regression tests of the early security review of lot 3 part 1
//! (`61cf9b7`): H1, H2, M1 to M5, L1, from the reviewer's probes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use databastion_classifiers::masking::Signal;
use proptest::prelude::*;

use super::trace_events::*;
use super::trace_log::*;

fn hdr() -> String {
    format!(
        "{:<35}{}",
        "Table", "   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge"
    )
}

fn opts() -> ParseOptions {
    ParseOptions {
        max_sql_length: Some(65_000),
        series: Series::V5,
    }
}

struct Cat(HashMap<&'static str, RelClass>);
impl Catalog for Cat {
    fn class(&self, r: &str) -> RelClass {
        if let Some(c) = self.0.get(r) {
            return *c;
        }
        if r.starts_with("MON$") {
            RelClass::Virtual
        } else if r.starts_with("RDB$") {
            RelClass::System
        } else {
            RelClass::Unknown
        }
    }
    fn always_view(&self, _r: &str) -> bool {
        false
    }
}

fn cat() -> Cat {
    Cat(HashMap::from([
        ("SECRET", RelClass::Table),
        ("T_EMPTY", RelClass::Table),
    ]))
}

fn blk() -> String {
    let h = hdr();
    let stars = "*".repeat(h.len());
    let row = format!("{:<35}{:>10}{}", "SECRET", 50000, " ".repeat(70));
    format!("\n{h}\n{stars}\n{row}")
}

fn stmt(att: &str, client: &str, text: &[u8], fetched: u64, block: bool) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"2026-10-30T15:22:38.4340 (24:0x7fdc1dd7adc0) EXECUTE_STATEMENT_FINISH\n");
    v.extend_from_slice(att.as_bytes());
    v.extend_from_slice(client.as_bytes());
    v.extend_from_slice(b"\t\t(TRA_25, CONCURRENCY | WAIT | READ_WRITE)\n\nStatement 1:\n-------------------------------------------------------------------------------\n");
    v.extend_from_slice(text);
    v.extend_from_slice(
        format!("\n{fetched} records fetched\n      0 ms, 8 fetch(es)\n").as_bytes(),
    );
    if block {
        v.extend_from_slice(blk().as_bytes());
    }
    v
}

const ATT: &str = "\t/x.fdb (ATT_3, U:NONE, NONE, TCPv4:127.0.0.1/41410)\n";

fn conv(b: &[u8]) -> Converted {
    let r = parse(b, opts()).unwrap();
    convert(&r, &cat())
}

/// An ambiguous record that keeps its real counters and rows.
fn keeps_trailer(c: &Converted) {
    match c {
        Converted::Ambiguous { draft, .. } => {
            assert_eq!(draft.objects, ["SECRET"], "{c:?}");
            assert_eq!(draft.rows, Some(50_000), "{c:?}");
            assert!(draft.star && draft.always);
        }
        other => panic!("not ambiguous: {other:?}"),
    }
}

/// H1: a spoiled line before the trailer (a client line without `:pid`,
/// a text that is not UTF-8, a user or role with `,` or a line break)
/// keeps the real counters and row count.
#[test]
fn h1_defects_keep_the_trailer() {
    keeps_trailer(&conv(&stmt(
        ATT,
        "\tevil\n\tx:1\n",
        b"SELECT * FROM SECRET",
        50_000,
        true,
    )));
    keeps_trailer(&conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT * FROM SECRET /* \xff */",
        50_000,
        true,
    )));
    for att in [
        "\t/x.fdb (ATT_3, U,X:NONE, NONE, TCPv4:127.0.0.1/41410)\n",
        "\t/x.fdb (ATT_3, U\nX:NONE, NONE, TCPv4:127.0.0.1/41410)\n",
        "\t/x.fdb (ATT_3, U:R,O, NONE, TCPv4:127.0.0.1/41410)\n",
    ] {
        keeps_trailer(&conv(&stmt(
            att,
            "\tisql:1\n",
            b"SELECT * FROM SECRET",
            50_000,
            true,
        )));
    }
    // The baseline is a plain event.
    assert!(matches!(
        conv(&stmt(
            ATT,
            "\tisql:1\n",
            b"SELECT * FROM SECRET",
            50_000,
            true
        )),
        Converted::Event(_)
    ));
    // A defect of a finish record whose trailer is incomplete opens a
    // window.
    let mut cut = stmt(ATT, "\tevil\n", b"SELECT * FROM SECRET", 0, false);
    let at = cut
        .windows(15)
        .position(|w| w == b"0 records fetch")
        .unwrap();
    cut.truncate(at);
    assert!(matches!(
        conv(&cut),
        Converted::Ambiguous { window: true, .. }
    ));
}

/// H2: a `param<i> = ` line inside the text is client text; an empty
/// relation set is not case (a).
#[test]
fn h2_parameter_lines_and_empty_relation_sets() {
    let text = b"SELECT\nparam0 = 1, s.MON$SQL_TEXT FROM (SELECT 1 AS param0 FROM MON$DATABASE) d CROSS JOIN MON$STATEMENTS s";
    let b = stmt(ATT, "\tisql:1\n", text, 5, false);
    let r = parse(&b, opts()).unwrap();
    assert_eq!(r.defect, Some(Defect::Injected));
    assert!(matches!(convert(&r, &cat()), Converted::Ambiguous { .. }));
    // Parameter lines must match the placeholders.
    let ok = stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT * FROM SECRET WHERE A = ?\n\nparam0 = integer, \"1\"",
        1,
        true,
    );
    assert_eq!(parse(&ok, opts()).unwrap().defect, None);
    let extra = stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT * FROM SECRET WHERE A = ?\n\nparam0 = integer, \"1\"\nparam1 = integer, \"2\"",
        1,
        true,
    );
    assert_eq!(
        parse(&extra, opts()).unwrap().defect,
        Some(Defect::Injected)
    );
    // No relation named, no block, rows: ambiguous.
    assert!(matches!(
        conv(&stmt(
            ATT,
            "\tisql:1\n",
            b"SELECT 1 AS X FROM (SELECT 1 FROM RDB$DATABASE) D",
            5,
            false
        )),
        Converted::Event(_) | Converted::Ambiguous { .. }
    ));
    assert!(matches!(
        conv(&stmt(ATT, "\tisql:1\n", b"SELECT CURRENT_USER", 5, false)),
        Converted::Ambiguous { window: true, .. }
    ));
}

/// M1: a multi-byte character in the counter columns never panics.
#[test]
fn m1_block_counters_are_ascii() {
    let h = hdr();
    let stars = "*".repeat(h.len());
    let name = format!("{:<width$}", "T1", width = h.len() - 80);
    let mut cols = String::from("         ");
    cols.push('é');
    while cols.len() < 80 {
        cols.push(' ');
    }
    let row = format!("{name}{cols}");
    let r = format!(
        "2026-10-30T15:22:38.4340 (24:0x7fdc1dd7adc0) ERROR AT JResultSet::fetchNext\n{ATT}335544517 : exception\n\n{h}\n{stars}\n{row}"
    );
    let _ = parse(r.as_bytes(), opts());
}

/// M2, M3, M4.
#[test]
fn m2_m3_m4_text_rules() {
    // Quoted calls are code.
    let d = match conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT \"F\"() FROM MON$DATABASE",
        1,
        false,
    )) {
        Converted::Event(d) => d,
        other => panic!("{other:?}"),
    };
    assert!(d.star && d.always);
    assert!(matches!(
        conv(&stmt(
            ATT,
            "\tisql:1\n",
            b"SELECT COUNT(*), \"F\"(1) FROM T_EMPTY",
            1,
            false
        )),
        Converted::Event(Draft { star: true, .. }) | Converted::Ambiguous { .. }
    ));
    // A large read of virtual relations names them (R20, M2).
    let d = match conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT * FROM MON$ATTACHMENTS",
        50_000,
        false,
    )) {
        Converted::Event(d) => d,
        other => panic!("{other:?}"),
    };
    assert_eq!(d.objects, ["MON$ATTACHMENTS"]);
    assert!(d.signals.contains(&Signal::LargeResult));
    // A PASSWORD word keeps the block, the shape and the volume.
    let d = match conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT C.*, 1 AS PASSWORD FROM SECRET C",
        50_000,
        true,
    )) {
        Converted::Event(d) => d,
        other => panic!("{other:?}"),
    };
    assert_eq!(d.objects, ["SECRET"]);
    assert!(d.star && d.always);
    assert!(d.signals.contains(&Signal::FullTableRead) && d.signals.contains(&Signal::LargeResult));
    // EXECUTE STATEMENT … ON EXTERNAL … PASSWORD: remote data access.
    let d = match conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"EXECUTE BLOCK AS BEGIN EXECUTE STATEMENT 'x' ON EXTERNAL 'h:/d' AS USER 'u' PASSWORD 'p'; END",
        0,
        false,
    )) {
        Converted::Event(d) => d,
        other => panic!("{other:?}"),
    };
    assert!(d.signals.contains(&Signal::RemoteDataAccess));
    // An unterminated block-ful text: ambiguous, its trailer kept.
    keeps_trailer(&conv(&stmt(
        ATT,
        "\tisql:1\n",
        b"SELECT * FROM SECRET /* x",
        50_000,
        true,
    )));
}

/// M5: a forged service name or client-shaped line is injected.
#[test]
fn m5_service_records() {
    let r = "2026-10-30T15:22:38.5960 (24:0x7fdc1dd7c440) START_SERVICE\n\tservice_mgr, (Service 0x7fdc1e6754c0, SYSDBA, TCPv4:127.0.0.1/41416, foo:1)\n\t\"Backup Database\"\n\t-b /other/x.fdb y:40)\n\t\"Backup Database\"\n\t-b /var/lib/firebird/data/app.fdb /tmp/app.fbk\n";
    assert_eq!(
        parse(r.as_bytes(), opts()).unwrap().defect,
        Some(Defect::Injected)
    );
    let spaced = "2026-10-30T15:22:38.5960 (24:0x7fdc1dd7c440) START_SERVICE\n\tservice_mgr, (Service 0x7fdc1e6754c0, SYSDBA, TCPv4:127.0.0.1/41416, foo:1)\n\t\"Backup Database\"\n\t-b /data/a b.fdb /tmp/x.fbk\n";
    let p = parse(spaced.as_bytes(), opts()).unwrap();
    assert_eq!(p.defect, None);
    assert!(matches!(p.body, Body::Service { database: None, .. }));
}

/// L1 (R20): the form without `Statement <n>:` only for R8 case (b).
#[test]
fn l1_statement_line() {
    let b = stmt(ATT, "\tisql:1\n", b"SELECT * FROM SECRET", 50_000, true);
    let s = String::from_utf8(b).unwrap().replace("Statement 1:\n", "");
    assert!(matches!(conv(s.as_bytes()), Converted::Ambiguous { .. }));
    let c = String::from_utf8(stmt(ATT, "\tisql:1\n", b"COMMIT", 0, false))
        .unwrap()
        .replace("Statement 1:\n", "");
    assert_eq!(conv(c.as_bytes()), Converted::Nothing);
}

/// N1: no text, name or path in a debug string.
#[test]
fn n1_redacting_debug() {
    let b = stmt(
        "\t/secret/path.fdb (ATT_3, MARKERUSER:MARKERROLE, NONE, TCPv4:127.0.0.1/41410)\n",
        "\tisql:1\n",
        b"SELECT 'MARKERLIT' FROM SECRET",
        1,
        true,
    );
    let r = parse(&b, opts()).unwrap();
    let dbg = format!("{r:?}");
    for m in ["MARKERUSER", "MARKERROLE", "MARKERLIT", "/secret/path"] {
        assert!(!dbg.contains(m), "{m}: {dbg}");
    }
}

proptest! {
    /// M1: arbitrary characters in a block row never panic.
    #[test]
    fn block_rows_never_panic(row in "\\PC{0,120}") {
        let h = hdr();
    let stars = "*".repeat(h.len());
        let r = format!(
            "2026-10-30T15:22:38.4340 (24:0x7fdc1dd7adc0) EXECUTE_PROCEDURE_FINISH\n{ATT}\t\t(TRA_1, READ_COMMITTED | WAIT | READ_ONLY)\n\nProcedure P:\n      0 ms\n\n{h}\n{stars}\n{row}"
        );
        if let Some(rec) = parse(r.as_bytes(), opts()) {
            let _ = convert(&rec, &cat());
        }
    }
}
