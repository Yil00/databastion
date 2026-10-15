//! Unit tests of the stream's position rules (security review of P9-A
//! lot 2, H1, L1, L8, L11).

use super::*;
use records::tests::rec;

const P1: &str = "N'/var/opt/mssql/audit/a_B5BEF79B-88AC-4A47-91AE-0081BBD71D51_*.sqlaudit'";

fn f(folder: &str, ts: i64) -> String {
    format!("{folder}a_B5BEF79B-88AC-4A47-91AE-0081BBD71D51_0_{ts:018}.sqlaudit")
}

fn at(file: &str, offset: i64) -> Record {
    let mut r = rec("SL", "U", "crm", "customers", "SELECT a FROM t WHERE b = 1");
    r.file = file.to_owned();
    r.offset = offset;
    r
}

fn pos(list: &[(&str, i64)]) -> Vec<(String, i64)> {
    list.iter().map(|(f, o)| ((*f).to_owned(), *o)).collect()
}

#[test]
fn cursor_round_trips() {
    let c = Cursor {
        file: Some("/var/opt/mssql/audit/a b_0_1.sqlaudit".to_owned()),
        offset: 53_248,
        skip: 3,
        pattern: Some(P1.to_owned()),
        after: Some(((134_365_416_940_740_000, 0), 4096)),
        history_us: Some(17),
    };
    assert_eq!(Cursor::decode(&c.encode()), Some(c));
    assert_eq!(
        Cursor::decode(&Cursor::default().encode()),
        Some(Cursor::default())
    );
    assert!(Cursor::decode(b"v2\n").is_none());
    assert!(Cursor::decode(b"v1\nfile zz\n").is_none());
    assert!(Cursor::decode(b"v1\nguid x\n").is_none());
    let big = Cursor::decode(b"v1\nskip 999999\n").unwrap();
    assert_eq!(big.skip, MAX_SKIP);
}

#[test]
fn file_keys_order_one_set() {
    assert_eq!(
        file_key(&f("/x/", 134_365_416_940_740_000)),
        Some((134_365_416_940_740_000, 0))
    );
    assert!(file_key("/x/a.sqlaudit").is_none());
    assert!(file_key("/x/a_0_12x.sqlaudit").is_none());
    assert!(file_key(&f("/z/", 1)) < file_key(&f("/a/", 2)));
    // Timestamp first, then partition.
    assert!(file_key("/x/a_9_1.sqlaudit") < file_key("/x/a_0_2.sqlaudit"));
}

#[test]
fn a_read_that_is_not_full_moves_to_its_last_buffer() {
    let c = Cursor::default();
    let n = advance(&c, &pos(&[("f1", 4096), ("f1", 8192), ("f2", 4096)]), 10);
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f2"), 4096, 0));
    assert_eq!(advance(&c, &[], 10), c);
}

#[test]
fn a_full_read_reads_its_last_buffer_again() {
    let c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        ..Cursor::default()
    };
    let n = advance(
        &c,
        &pos(&[("f1", 8192), ("f1", 8192), ("f1", 12288), ("f1", 12288)]),
        4,
    );
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f1"), 8192, 2));
    let c2 = Cursor {
        skip: 4,
        ..c.clone()
    };
    let n = advance(&c2, &pos(&[("f1", 8192); 8]), 8);
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f1"), 4096, 8));
}

/// Re-review N1: a buffer larger than a read is walked without losing or
/// repeating a record (skip 16, batch 16, a buffer of 40 records).
#[test]
fn a_large_buffer_is_walked_record_by_record() {
    let buffer: Vec<Record> = (0..40)
        .map(|i| {
            let mut r = at("f1", 8192);
            r.time_us = i;
            r
        })
        .collect();
    let mut c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        skip: 16,
        ..Cursor::default()
    };
    let mut seen: Vec<i64> = (0..16).collect();
    for _ in 0..10 {
        let top = 16 + c.skip as usize;
        let read: Vec<Record> = buffer.iter().take(top).cloned().collect();
        let returned = read.len();
        let b = batch(&c, read, returned, top);
        seen.extend(b.kept.iter().map(|r| r.time_us));
        c = b.next;
        if !b.full {
            break;
        }
    }
    assert_eq!(seen, (0..40).collect::<Vec<i64>>());
    assert_eq!((c.file.as_deref(), c.offset, c.skip), (Some("f1"), 8192, 0));
}

/// Review H1: another folder (either sort direction) or another GUID is
/// another file set: the position and any filter go, with a gap, and
/// every record of the new set is kept.
#[test]
fn a_new_file_set_is_read_whole() {
    for (old, new) in [("/var/z/", "/var/a/"), ("/var/a/", "/var/z/")] {
        let pat = |folder: &str| format!("N'{folder}a_GUID_*.sqlaudit'");
        let mut c = Cursor {
            file: Some(f(old, 900)),
            offset: 81_920,
            pattern: Some(pat(old)),
            after: Some(((900, 0), 81_920)),
            ..Cursor::default()
        };
        assert!(on_pattern(&mut c, &pat(new)), "a gap");
        assert_eq!(c.file, None);
        assert_eq!(c.after, None);
        let b = batch(&c, vec![at(&f(new, 1), 4096), at(&f(new, 1), 8192)], 2, 10);
        assert_eq!(
            b.kept.len(),
            2,
            "{old} -> {new}: records of the new set kept"
        );
        // The same pattern again: no gap.
        let mut same = b.next.clone();
        assert!(!on_pattern(&mut same, &pat(new)));
        assert_eq!(same.file.as_deref(), Some(f(new, 1).as_str()));
    }
    // A first pattern is no gap.
    let mut c = Cursor::default();
    assert!(!on_pattern(&mut c, P1));
}

/// Rollover (error 33225) in the same set: what was read is left out by
/// file key and offset, the rest kept, and the filter ends.
#[test]
fn a_refused_position_skips_what_was_read() {
    let folder = "/var/opt/mssql/audit/";
    let mut c = Cursor {
        file: Some(f(folder, 500)),
        offset: 8192,
        pattern: Some(P1.to_owned()),
        ..Cursor::default()
    };
    on_bad_position(&mut c);
    assert_eq!(c.file, None);
    assert_eq!(c.after, Some(((500, 0), 8192)));
    let recs = vec![
        at(&f(folder, 500), 4096),
        at(&f(folder, 500), 8192),
        at(&f(folder, 500), 12_288),
        at(&f(folder, 600), 4096),
    ];
    let b = batch(&c, recs, 4, 10);
    let kept: Vec<(i64, i64)> = b
        .kept
        .iter()
        .map(|r| (file_key(&r.file).unwrap().0, r.offset))
        .collect();
    assert_eq!(kept, [(500, 12_288), (600, 4096)]);
    assert_eq!(
        b.next.after, None,
        "the filter ends after a read that is not full"
    );
    // A full read that has not passed the position keeps the filter.
    let b = batch(&c, vec![at(&f(folder, 400), 4096)], 1, 1);
    assert!(b.kept.is_empty());
    assert_eq!(b.next.after, c.after);
}

/// Review L8: a buffer above the skip bound is a gap.
#[test]
fn an_oversized_buffer_is_a_gap() {
    let c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        skip: MAX_SKIP,
        ..Cursor::default()
    };
    let top = BATCH + MAX_SKIP as usize;
    let recs: Vec<Record> = (0..top).map(|_| at("f1", 8192)).collect();
    let b = batch(&c, recs, top, top);
    assert!(b.gap);
    assert_eq!(
        (b.next.file.as_deref(), b.next.offset, b.next.skip),
        (Some("f1"), 8192, 0)
    );
    assert_eq!(b.kept.len(), BATCH);
}

/// Review L11: the audit's start and stop records are gaps; changes of
/// the audit are always reported and probed again.
#[test]
fn ausc_records_are_gaps() {
    assert_eq!(records::map("AUSC", "A"), records::Mapped::Restart);
    assert_eq!(records::map("AUSF", "A"), records::Mapped::Restart);
    let s = records::group(vec![rec("AL", "A", "", "a", "ALTER SERVER AUDIT a")]);
    assert!(records::is_audit_change(&s[0]));
}
