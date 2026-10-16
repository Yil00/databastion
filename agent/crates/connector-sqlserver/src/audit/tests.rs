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
        session: Some(1_800_000_000_000_000),
        floor: Some(17),
        floor_set_ms: 1_800_000_000_000,
        buffer: Some(("/var/opt/mssql/xe/x_0_1.xel".to_owned(), 8192)),
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
    // A floor saved without its first start ends once caught up.
    let old = Cursor::decode(b"v1\nfloor 17\n").unwrap();
    assert_eq!((old.floor, old.floor_set_ms), (Some(17), 0));
}

/// The history phase lasts until a read that reached the end of the
/// source started once the delivery delay passed since the first start:
/// records of before the start that come late within it are history (not
/// counted as dropped, which would make every start Limited); then the
/// history phase and the floor end together.
#[test]
fn the_history_phase_covers_the_delivery_delay_then_ends_with_the_floor() {
    for skew in [0, xe::XE_CLOCK_SKEW_US] {
        let mut c = Cursor::default();
        c.first_start(Some(1_000_000), skew);
        let set = c.floor_set_ms;
        let prev = c.history_us;
        // A caught-up read within the delay: still history.
        let mut next = c.clone();
        next.history_us = None;
        next.settle(prev, set + 500, Duration::from_secs(1));
        assert_eq!(next.history_us, prev);
        assert_eq!(
            next.below(999_999, set, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert!(next.floor.is_some());
        // One started after it: both end.
        let mut next = next.clone();
        next.history_us = None;
        next.settle(prev, set + 1_000, Duration::from_secs(1));
        assert_eq!((next.history_us, next.floor), (None, None));
        assert_eq!(next.below(1, set, Duration::from_secs(1)), None);
        // The agent's clock went back past the first start: both end.
        let mut back = c.clone();
        back.history_us = None;
        back.settle(prev, set - 1, Duration::from_secs(1));
        assert_eq!((back.history_us, back.floor), (None, None));
        // Bounded at 5 minutes whatever the delay.
        let mut long = c.clone();
        long.history_us = None;
        long.settle(prev, set + 300_000, Duration::from_secs(86_400));
        assert_eq!((long.history_us, long.floor), (None, None));
    }
}

/// Final review L1: a first catch-up through a large backlog that goes on
/// past the delivery delay; what it reads below the start or the floor
/// after the delay is counted as dropped, not history.
#[test]
fn a_long_first_catch_up_counts_what_is_below_the_floor_after_the_delay() {
    for skew in [0, xe::XE_CLOCK_SKEW_US] {
        let mut c = Cursor::default();
        c.first_start(Some(1_000_000), skew);
        let c = c;
        let set = c.floor_set_ms;
        let delay = Duration::from_secs(1);
        let floor = 1_000_000 + skew;
        // Full reads of the backlog, one after the other: still in the
        // history phase (no read reached the end of the source, so the
        // cursor's history stays).
        let mut counted = 0;
        let mut history = 0;
        for (read, started) in [
            (0, set),
            (1, set + 400),
            (2, set + 999),
            (3, set + 1_000),
            (4, set + 5_000),
        ] {
            assert!(c.history_us.is_some(), "read {read}: catching up");
            for t in [1, 999_999, floor - 1] {
                match c.below(t, started, delay) {
                    Some(Below::History) => history += 1,
                    Some(Below::Dropped) => counted += 1,
                    None => panic!("below the floor"),
                }
            }
            assert_eq!(c.below(floor, started, delay), None);
        }
        assert_eq!((history, counted), (9, 6), "counted after the delay");
        // Bounded at 5 minutes whatever the delay.
        assert_eq!(
            c.below(1, set + 300_000, Duration::from_secs(86_400)),
            Some(Below::Dropped)
        );
        // The agent's clock went back past the first start: counted.
        assert_eq!(c.below(1, set - 1, delay), Some(Below::Dropped));
    }
}

/// Re-review N1, on both sources (SQL Server Audit: no skew; Extended
/// Events: the floor 20 ms past the first start).
#[test]
fn the_floor_is_counted_after_the_history_phase_and_ends() {
    for skew in [0, xe::XE_CLOCK_SKEW_US] {
        let mut c = Cursor::default();
        c.first_start(Some(1_000_000), skew);
        let set = c.floor_set_ms;
        let floor = 1_000_000 + skew;
        // History phase: below the start, or below the floor, not counted.
        assert_eq!(
            c.below(999_999, set, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert_eq!(
            c.below(floor - 1, set, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert_eq!(c.below(floor, set, Duration::from_secs(1)), None);
        // The floor stays during the history phase whatever the time.
        c.expire_floor(set + 3_600_000, Duration::from_secs(1));
        assert_eq!(c.floor, Some(floor));
        // After the first caught-up read: a record stamped below the floor
        // (late history, or the server's clock stepped back) is counted.
        c.history_us = None;
        assert_eq!(
            c.below(1, set, Duration::from_secs(1)),
            Some(Below::Dropped)
        );
        assert_eq!(
            c.below(floor - 1, set, Duration::from_secs(1)),
            Some(Below::Dropped)
        );
        assert_eq!(c.below(floor, set, Duration::from_secs(1)), None);
        // A read started before the delivery delay passed keeps it.
        c.expire_floor(set + 999, Duration::from_secs(1));
        assert_eq!(c.floor, Some(floor));
        // One started after it ends it: nothing below it is left out.
        c.expire_floor(set + 1_000, Duration::from_secs(1));
        assert_eq!(c.floor, None);
        assert_eq!(c.below(1, set, Duration::from_secs(1)), None);
        // Bounded at 5 minutes, whatever the delay (INFINITE latency).
        let mut c = Cursor::default();
        c.first_start(Some(1_000_000), skew);
        c.history_us = None;
        let set = c.floor_set_ms;
        c.expire_floor(set + 299_999, Duration::from_secs(86_400));
        assert!(c.floor.is_some());
        c.expire_floor(set + 300_000, Duration::from_secs(86_400));
        assert_eq!(c.floor, None);
        // The agent's clock went back past the first start: ended.
        let mut c = Cursor::default();
        c.first_start(Some(1_000_000), skew);
        c.history_us = None;
        let set = c.floor_set_ms;
        c.expire_floor(set - 1, Duration::from_secs(1));
        assert_eq!(c.floor, None);
    }
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
        let b = batch(&c, read, returned, top, file_key);
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
        let b = batch(
            &c,
            vec![at(&f(new, 1), 4096), at(&f(new, 1), 8192)],
            2,
            10,
            file_key,
        );
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
    on_bad_position(&mut c, file_key);
    assert_eq!(c.file, None);
    assert_eq!(c.after, Some(((500, 0), 8192)));
    let recs = vec![
        at(&f(folder, 500), 4096),
        at(&f(folder, 500), 8192),
        at(&f(folder, 500), 12_288),
        at(&f(folder, 600), 4096),
    ];
    let b = batch(&c, recs, 4, 10, file_key);
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
    let b = batch(&c, vec![at(&f(folder, 400), 4096)], 1, 1, file_key);
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
    let b = batch(&c, recs, top, top, file_key);
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

/// Extended Events positions: files ordered by their key (timestamp, then
/// `<n>`), never by path; a refused position in the same set reads from
/// the oldest file and leaves out what was read (lot 2 review H1).
#[test]
fn xe_positions_follow_the_file_key() {
    let f = |ts: i64| format!("/var/opt/mssql/xe/databastion_xe_0_{ts}.xel");
    let mut c = Cursor {
        file: Some(f(134_365_650_237_540_000)),
        offset: 8192,
        pattern: Some("N'/var/opt/mssql/xe/databastion_xe_0_*.xel'".to_owned()),
        session: Some(1),
        ..Cursor::default()
    };
    on_bad_position(&mut c, crate::sql::xe_file_key);
    assert_eq!(c.file, None);
    assert_eq!(c.after, Some(((134_365_650_237_540_000, 0), 8192)));
    let at = |file: &str, offset: i64| {
        let mut r = rec("SL", "U", "crm", "customers", "x");
        r.file = file.to_owned();
        r.offset = offset;
        r
    };
    let b = batch(
        &c,
        vec![
            at(&f(134_365_650_237_540_000), 4096),
            at(&f(134_365_650_237_540_000), 8192),
            at(&f(134_365_650_237_540_000), 12288),
            at(&f(134_365_660_000_000_000), 4096),
        ],
        4,
        10,
        crate::sql::xe_file_key,
    );
    let kept: Vec<(String, i64)> = b.kept.iter().map(|r| (r.file.clone(), r.offset)).collect();
    assert_eq!(
        kept,
        vec![
            (f(134_365_650_237_540_000), 12288),
            (f(134_365_660_000_000_000), 4096)
        ]
    );
    assert_eq!(b.next.after, None);
    assert_eq!(b.next.session, Some(1), "the session's start is kept");
}

/// Extended Events buffers hold hundreds of events (measured on 2025): a
/// buffer of any size is walked with reads of at most `asked` events, the
/// server skipping those handled; none is read twice, none lost.
#[test]
fn xe_large_buffers_are_walked_without_loss() {
    use crate::audit::xe::events::XeRecord;
    use crate::audit::xe::xe_batch;
    let ev = |file: &str, offset: i64, i: usize| XeRecord {
        file: file.to_owned(),
        offset,
        time_us: i64::try_from(i).unwrap(),
        name: "sql_statement_completed".to_owned(),
        event: None,
        procedure: None,
        skip: false,
        unreadable: false,
        index: 0,
    };
    // The file: buffer 4096 (3 events), 8192 (1 200 events), 12288 (5).
    let mut all = Vec::new();
    for (off, n) in [(4096, 3), (8192, 1200), (12288, 5)] {
        for _ in 0..n {
            all.push((off, all.len()));
        }
    }
    // The server: after the buffer at the position, skip, then `asked`.
    let read = |c: &Cursor, asked: usize| -> Vec<XeRecord> {
        let start = all
            .iter()
            .position(|(o, _)| c.file.is_none() || *o > c.offset)
            .unwrap_or(all.len());
        all.iter()
            .skip(start + c.skip as usize)
            .take(asked)
            .map(|(o, i)| ev("f", *o, *i))
            .collect()
    };
    let mut c = Cursor::default();
    let mut seen = Vec::new();
    for _ in 0..20 {
        let got = read(&c, 500);
        let n = got.len();
        let b = xe_batch(&c, got, n, 500);
        assert!(!b.gap);
        seen.extend(b.kept.iter().map(|r| r.time_us));
        c = b.next;
        if !b.full {
            break;
        }
    }
    let want: Vec<i64> = (0..all.len()).map(|i| i64::try_from(i).unwrap()).collect();
    assert_eq!(seen, want);
    assert_eq!((c.file.as_deref(), c.offset, c.skip), (Some("f"), 12288, 0));
    // A full read ending exactly at the end of the skipped buffer: the
    // next read starts with another buffer, and the position moves.
    let c = Cursor {
        file: Some("f".to_owned()),
        offset: 4096,
        skip: 1000,
        buffer: Some(("f".to_owned(), 8192)),
        ..Cursor::default()
    };
    let b = xe_batch(&c, vec![ev("f", 12288, 0), ev("f", 12288, 1)], 2, 2);
    assert_eq!(
        (b.next.file.as_deref(), b.next.offset, b.next.skip),
        (Some("f"), 8192, 2)
    );
    assert_eq!(b.next.buffer, Some(("f".to_owned(), 12288)));
    // Nothing new: the position and the skip stay.
    let b = xe_batch(&c, Vec::new(), 0, 500);
    assert_eq!((b.next.offset, b.next.skip), (4096, 1000));
}
