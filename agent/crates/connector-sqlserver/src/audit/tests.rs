//! Unit tests of the stream's position rules (security review of P9-A
//! lot 2, H1, L1, L8, L11).

use super::*;
use records::tests::rec;
use zeroize::Zeroizing;

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
        max_seen_us: Some(1_800_000_000_000_001),
    };
    assert_eq!(Cursor::decode(&c.encode()), Some(c));
    assert_eq!(
        Cursor::decode(&Cursor::default().encode()),
        Some(Cursor::default())
    );
    assert!(Cursor::decode(b"v2\n").is_none());
    assert!(Cursor::decode(b"v1\nfile zz\n").is_none());
    assert!(Cursor::decode(b"v1\nguid x\n").is_none());
    let big = Cursor::decode(b"v1\nskip 99999999\n").unwrap();
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
            next.below(999_999, None, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert!(next.floor.is_some());
        // One started after it: both end.
        let mut next = next.clone();
        next.history_us = None;
        next.settle(prev, set + 1_000, Duration::from_secs(1));
        assert_eq!((next.history_us, next.floor), (None, None));
        assert_eq!(next.below(1, None, Duration::from_secs(1)), None);
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

/// The history boundary by order (follow-up of the lot 3 final review,
/// L1): in the history phase, however long the first catch-up takes, a
/// record below the start or the floor is history unless it is stamped
/// more than the tolerance below the latest record handled (a step back of
/// the server's clock), counted then. A long backlog read in order gives
/// no drop.
#[test]
fn the_history_boundary_goes_by_order() {
    for skew in [0, xe::XE_CLOCK_SKEW_US] {
        let mut c = Cursor::default();
        c.first_start(Some(10_000_000_000), skew);
        let delay = Duration::from_secs(1);
        let floor = 10_000_000_000 + skew;
        // A long backlog with increasing times, read over many reads and
        // whatever time: all history, no drop.
        let mut seen = c.max_seen_us;
        let mut counted = 0;
        for t in (0..10_000).map(|i| 1_000_000 + i * 900_000) {
            match c.below(t, seen, delay) {
                Some(Below::History) => {}
                Some(Below::Dropped) => counted += 1,
                None => panic!("below the start"),
            }
            seen = Cursor::seen(seen, t);
        }
        assert_eq!(counted, 0, "a long backlog in order");
        // Disorder within the tolerance (5 s, the delay being shorter):
        // history.
        let m = seen.unwrap();
        assert_eq!(c.below(m - 5_000_000, seen, delay), Some(Below::History));
        // A step back beyond it, in the middle of the catch-up: counted.
        assert_eq!(c.below(m - 5_000_001, seen, delay), Some(Below::Dropped));
        // A longer delivery delay widens the tolerance, bounded by
        // FLOOR_MAX.
        assert_eq!(
            c.below(m - 30_000_000, seen, Duration::from_secs(60)),
            Some(Below::History)
        );
        assert_eq!(
            c.below(m - 300_000_001, seen, Duration::from_secs(86_400)),
            Some(Below::Dropped)
        );
        // At or above the start: not left out.
        assert_eq!(c.below(floor, seen, delay), None);
        // After the history phase: below the floor is counted.
        c.history_us = None;
        assert_eq!(c.below(floor - 1, seen, delay), Some(Below::Dropped));
    }
}

/// `max_seen_us` is kept across a restart (the cursor), and records a
/// refused position left out (`after`) do not move it.
#[test]
fn the_latest_record_seen_survives_a_restart() {
    let mut c = Cursor::default();
    c.first_start(Some(10_000_000_000), 0);
    c.max_seen_us = Some(9_000_000_000);
    let back = Cursor::decode(&c.encode()).unwrap();
    assert_eq!(back.max_seen_us, Some(9_000_000_000));
    assert_eq!(back.history_us, c.history_us);
    // After a refused position: the records at or before it are left out
    // by the batch, and only the kept ones move the latest time.
    let file = f("/x/", 134_365_416_940_740_000);
    let mut c = Cursor {
        after: Some(((134_365_416_940_740_000, 0), 8192)),
        ..Cursor::default()
    };
    c.first_start(Some(10_000_000_000), 0);
    let mut old = at(&file, 4096);
    old.time_us = 9_999_000_000;
    let mut new = at(&file, 12_288);
    new.time_us = 5_000_000;
    let b = batch(&c, vec![old, new], 2, 500, file_key);
    assert_eq!(
        b.kept.len(),
        1,
        "the record before the position is left out"
    );
    let seen = b
        .kept
        .iter()
        .fold(c.max_seen_us, |m, r| Cursor::seen(m, r.time_us));
    assert_eq!(seen, Some(5_000_000));
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
            c.below(999_999, None, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert_eq!(
            c.below(floor - 1, None, Duration::from_secs(1)),
            Some(Below::History)
        );
        assert_eq!(c.below(floor, None, Duration::from_secs(1)), None);
        // The floor stays during the history phase whatever the time.
        c.expire_floor(set + 3_600_000, Duration::from_secs(1));
        assert_eq!(c.floor, Some(floor));
        // After the first caught-up read: a record stamped below the floor
        // (late history, or the server's clock stepped back) is counted.
        c.history_us = None;
        assert_eq!(
            c.below(1, None, Duration::from_secs(1)),
            Some(Below::Dropped)
        );
        assert_eq!(
            c.below(floor - 1, None, Duration::from_secs(1)),
            Some(Below::Dropped)
        );
        assert_eq!(c.below(floor, None, Duration::from_secs(1)), None);
        // A read started before the delivery delay passed keeps it.
        c.expire_floor(set + 999, Duration::from_secs(1));
        assert_eq!(c.floor, Some(floor));
        // One started after it ends it: nothing below it is left out.
        c.expire_floor(set + 1_000, Duration::from_secs(1));
        assert_eq!(c.floor, None);
        assert_eq!(c.below(1, None, Duration::from_secs(1)), None);
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

fn next(c: &Cursor, positions: &[(String, i64)], full: bool) -> Cursor {
    let (n, gap) = next_position(c, positions, full, file_key);
    assert!(!gap);
    n
}

#[test]
fn a_read_that_is_not_full_moves_to_its_last_buffer() {
    let c = Cursor::default();
    let n = next(&c, &pos(&[("f1", 4096), ("f1", 8192), ("f2", 4096)]), false);
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f2"), 4096, 0));
    assert_eq!(n.buffer, None);
    assert_eq!(next(&c, &[], false), c);
}

#[test]
fn a_full_read_skips_its_last_buffer_on_the_server_next_time() {
    let c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        ..Cursor::default()
    };
    let n = next(
        &c,
        &pos(&[("f1", 8192), ("f1", 8192), ("f1", 12288), ("f1", 12288)]),
        true,
    );
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f1"), 8192, 2));
    assert_eq!(n.buffer, Some(("f1".to_owned(), 12288)));
    // Still that buffer: the count grows, the position stays.
    let n2 = next(&n, &pos(&[("f1", 12288); 8]), true);
    assert_eq!(
        (n2.file.as_deref(), n2.offset, n2.skip),
        (Some("f1"), 8192, 10)
    );
    // The skipped buffer had no more records: the position moves to it.
    let n3 = next(&n2, &pos(&[("f1", 16384); 3]), true);
    assert_eq!(
        (n3.file.as_deref(), n3.offset, n3.skip),
        (Some("f1"), 12288, 3)
    );
    assert_eq!(n3.buffer, Some(("f1".to_owned(), 16384)));
    // Nothing returned: everything stays.
    assert_eq!(next(&n3, &[], true), n3);
}

/// Re-review N1, with the skip on the server: a buffer larger than a read
/// is walked without losing or repeating a record (batch 16, a buffer of
/// 40 records).
#[test]
fn a_large_buffer_is_walked_record_by_record() {
    let files = AuditFiles::new(
        vec![("f1".to_owned(), 4096, 3), ("f1".to_owned(), 8192, 40)],
        2,
    );
    let mut c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        ..Cursor::default()
    };
    let mut seen: Vec<i64> = (0..3).collect();
    for _ in 0..10 {
        let (top, skip) = request(&c, 16);
        assert_eq!(top, 16, "a read asks for a batch whatever the skip");
        let read = files.read(&c, top, skip);
        let returned = read.len();
        let b = batch(&c, read, returned, top, file_key);
        seen.extend(b.kept.iter().map(|r| r.time_us));
        c = b.next;
        if !b.full {
            break;
        }
    }
    assert_eq!(seen, (0..43).collect::<Vec<i64>>());
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
        buffer: Some(("f1".to_owned(), 8192)),
        ..Cursor::default()
    };
    let (top, skip) = request(&c, BATCH);
    assert_eq!((top, skip), (BATCH, MAX_SKIP));
    let recs: Vec<Record> = (0..top).map(|_| at("f1", 8192)).collect();
    let b = batch(&c, recs, top, top, file_key);
    assert!(b.gap);
    assert_eq!(
        (
            b.next.file.as_deref(),
            b.next.offset,
            b.next.skip,
            b.next.buffer.as_ref()
        ),
        (Some("f1"), 8192, 0, None)
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

/// An audit file set as `sys.fn_get_audit_file` reads it (measured on
/// 2022): a read from (file, offset) starts at the buffer after that one,
/// in the next file when it was the file's last; the first `skip` rows
/// are skipped on the server, at most `top` returned, in file order. The
/// first `visible` buffers are written. Each record's `time_us` is its
/// index in the set.
struct AuditFiles {
    buffers: Vec<(String, i64, usize)>,
    visible: usize,
    all: Vec<Record>,
}

impl AuditFiles {
    fn new(buffers: Vec<(String, i64, usize)>, visible: usize) -> Self {
        let mut all = Vec::new();
        for (file, offset, n) in &buffers {
            for _ in 0..*n {
                let mut r = at(file, *offset);
                r.time_us = i64::try_from(all.len()).unwrap();
                all.push(r);
            }
        }
        Self {
            buffers,
            visible,
            all,
        }
    }

    fn read(&self, cursor: &Cursor, top: usize, skip: u32) -> Vec<Record> {
        let end: usize = self.buffers.iter().take(self.visible).map(|b| b.2).sum();
        let start: usize = match &cursor.file {
            None => 0,
            Some(f) => {
                let i = self
                    .buffers
                    .iter()
                    .position(|(bf, bo, _)| bf == f && *bo == cursor.offset)
                    .expect("a buffer of the set");
                self.buffers.iter().take(i + 1).map(|b| b.2).sum()
            }
        };
        let from = (start + skip as usize).min(end);
        self.all[from..end.min(from + top)].to_vec()
    }

    /// The stream's reads from the first start with reads of `batch`
    /// records, `per_poll` more buffers written each time a read is not
    /// full: the records handled, in order, and whether a gap was seen.
    fn walk(
        buffers: Vec<(String, i64, usize)>,
        batch_size: usize,
        per_poll: usize,
    ) -> (Vec<i64>, bool) {
        let mut files = Self::new(buffers, 0);
        let mut c = Cursor::default();
        let mut seen = Vec::new();
        let mut gap = false;
        loop {
            let (top, skip) = request(&c, batch_size);
            assert_eq!(top, batch_size, "a read asks for a batch whatever the skip");
            let read = files.read(&c, top, skip);
            let returned = read.len();
            let got = batch(&c, read, returned, top, file_key);
            assert!(!got.out_of_order, "the simulated server keeps file order");
            gap |= got.gap;
            seen.extend(got.kept.iter().map(|r| r.time_us));
            c = got.next;
            if !got.full {
                if files.visible == files.buffers.len() {
                    return (seen, gap);
                }
                // Caught up: the audit writes its next buffers.
                files.visible = (files.visible + per_poll).min(files.buffers.len());
            }
        }
    }
}

/// P9-D load run (300 statements/s): a rollover stalls the statements for
/// about 2.4 s, and the buffers written right after it hold up to about
/// 790 records (measured on 2022: 770 and 789, the buffer is about 500
/// KiB), more than a read. Such a buffer is walked by full reads whatever
/// its size, while the audit is written between reads: every record is
/// handled once, none lost, no gap. (Before the server-side skip, a read
/// asked for the batch plus the records already handled from the
/// buffer's start, and a buffer over 500 handled records was a gap that
/// lost its rest.)
#[test]
fn a_buffer_larger_than_a_read_loses_no_record() {
    let folder = "/var/opt/mssql/audit/";
    let (a, b) = (
        f(folder, 134_366_529_617_000_000),
        f(folder, 134_366_529_736_980_000),
    );
    let written: Vec<(String, i64, usize)> = vec![
        (a.clone(), 16_384, 245),
        (a.clone(), 176_128, 312),
        (a.clone(), 380_928, 290),
        (a.clone(), 1_753_088, 18),
        (b.clone(), 12_288, 770),
        (b.clone(), 512_000, 213),
        (b.clone(), 651_264, 789),
        (b.clone(), 1_163_264, 310),
        (b.clone(), 1_363_968, 2_400),
        (b.clone(), 4_000_000, 7),
    ];
    let total = i64::try_from(written.iter().map(|w| w.2).sum::<usize>()).unwrap();
    for per_poll in 1..=3 {
        let (seen, gap) = AuditFiles::walk(written.clone(), BATCH, per_poll);
        assert!(!gap, "no buffer is above the bound");
        assert_eq!(
            seen,
            (0..total).collect::<Vec<_>>(),
            "{per_poll} buffer(s) written per poll: every record once"
        );
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Any buffer sizes (up to several reads each), any read size, any
    /// number of buffers written between reads, across two files: every
    /// record is handled exactly once and in order.
    #[test]
    fn any_buffers_are_walked_without_loss_or_repeat(
        sizes in proptest::collection::vec(1usize..2_500, 1..10),
        split in 0usize..10,
        batch_size in 16usize..=BATCH,
        per_poll in 1usize..4,
    ) {
        let folder = "/var/opt/mssql/audit/";
        let (a, b) = (f(folder, 1), f(folder, 2));
        let buffers: Vec<(String, i64, usize)> = sizes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let file = if i < split { a.clone() } else { b.clone() };
                (file, 4096 * (i64::try_from(i).unwrap() + 1), *n)
            })
            .collect();
        let total = i64::try_from(sizes.iter().sum::<usize>()).unwrap();
        let (seen, gap) = AuditFiles::walk(buffers, batch_size, per_poll);
        proptest::prop_assert!(!gap);
        proptest::prop_assert_eq!(seen, (0..total).collect::<Vec<_>>());
    }
}

/// #255 review: the latest time handled ([`advance_seen`]) is shared by
/// both sources; records a read ends before (the deferral cut) are not
/// seen yet, and an earlier, higher time is kept.
#[test]
fn advance_seen_stops_at_the_cut() {
    let handled = [(0, 50), (1, 70), (2, 60), (3, 900), (4, 80)];
    assert_eq!(advance_seen(None, &handled, None), Some(900));
    assert_eq!(
        advance_seen(None, &handled, Some(3)),
        Some(70),
        "the build at 3 is read again"
    );
    assert_eq!(
        advance_seen(Some(40), &handled, Some(0)),
        Some(40),
        "a cut at the first record"
    );
    assert_eq!(advance_seen(None, &handled, Some(0)), None);
    assert_eq!(
        advance_seen(Some(1_000), &handled, None),
        Some(1_000),
        "never goes back"
    );
    assert_eq!(advance_seen(Some(5), &[], None), Some(5));
    // The next read, from the build, sees it and what follows.
    let next = [(0, 900), (1, 80)];
    assert_eq!(advance_seen(Some(70), &next, None), Some(900));
}

/// #255 review: with the deferral cut, through the history rule. A first
/// start's backlog holds a deferred build stamped far ahead of the
/// records after it (its statement completed late): had the cut read
/// counted the build, the records after it, read again by the next read,
/// would class below the latest time seen by more than the tolerance and
/// be counted as dropped. With the cut, they are history.
#[test]
fn the_deferral_cut_keeps_the_history_boundary() {
    let mut c = Cursor::default();
    c.first_start(Some(100_000_000_000), 0);
    let delay = Duration::from_secs(1);
    // Read 1: records 0, 1, then the build (2) the read ends before, then
    // 3 and 4 (cut away), all below the first start.
    let times = [
        10_000_000_000,
        10_000_100_000,
        20_000_000_000,
        10_000_200_000,
        10_000_300_000,
    ];
    let handled: Vec<(usize, i64)> = times.iter().copied().enumerate().collect();
    let mut seen = c.max_seen_us;
    for t in &times[..2] {
        assert_eq!(c.below(*t, seen, delay), Some(Below::History));
        seen = Cursor::seen(seen, *t);
    }
    c.max_seen_us = advance_seen(c.max_seen_us, &handled, Some(2));
    assert_eq!(c.max_seen_us, Some(10_000_100_000));
    // Read 2, from the build: the build (paired now) and the records after
    // it are classed in read order against the boundary of read 1.
    let mut seen = c.max_seen_us;
    let mut classes = Vec::new();
    for t in &times[2..] {
        classes.push(c.below(*t, seen, delay));
        seen = Cursor::seen(seen, *t);
    }
    assert_eq!(classes[0], Some(Below::History), "the build");
    // Inside one read, records stamped earlier than a build before them
    // are still classed by order (as they would be without any cut).
    assert_eq!(classes[1], Some(Below::Dropped));
    // Without the cut, read 1 would have seen the build: the records the
    // next read classes from the build on are compared to its time.
    let without = advance_seen(None, &handled, None);
    assert_eq!(without, Some(20_000_000_000));
    assert_eq!(
        c.below(times[3], without, delay),
        Some(Below::Dropped),
        "what the cut avoids for the records read again"
    );
}

/// #253 review L1: the order the server-side skip relies on is checked at
/// run time; any other order, or a name whose order cannot be read, is a
/// gap.
#[test]
fn reads_out_of_file_order_are_gaps() {
    let folder = "/var/opt/mssql/audit/";
    let (a, b) = (f(folder, 1), f(folder, 2));
    let c = Cursor::default();
    let ok = pos(&[(&a, 4096), (&a, 4096), (&a, 8192), (&b, 4096)]);
    assert!(in_file_order(&c, &ok, file_key));
    assert!(in_file_order(&c, &[], file_key));
    let back = pos(&[(&a, 8192), (&a, 4096)]);
    assert!(!in_file_order(&c, &back, file_key), "an offset going back");
    let files = pos(&[(&b, 4096), (&a, 8192)]);
    assert!(
        !in_file_order(&c, &files, file_key),
        "an older file after a newer"
    );
    let odd = pos(&[(&a, 4096), ("/var/opt/mssql/audit/other.sqlaudit", 8192)]);
    assert!(
        !in_file_order(&c, &odd, file_key),
        "a name without an order key"
    );
    // A read starts after the position's buffer.
    let at_pos = Cursor {
        file: Some(a.clone()),
        offset: 8192,
        ..Cursor::default()
    };
    assert!(in_file_order(&at_pos, &pos(&[(&a, 12_288)]), file_key));
    assert!(in_file_order(&at_pos, &pos(&[(&b, 4096)]), file_key));
    assert!(
        !in_file_order(&at_pos, &pos(&[(&a, 8192)]), file_key),
        "the position's buffer"
    );
    assert!(
        !in_file_order(&at_pos, &pos(&[(&a, 4096)]), file_key),
        "before the position"
    );
    // Not before the buffer whose first records the server skipped.
    let skipping = Cursor {
        file: Some(a.clone()),
        offset: 4096,
        skip: 3,
        buffer: Some((a.clone(), 12_288)),
        ..Cursor::default()
    };
    assert!(in_file_order(&skipping, &pos(&[(&a, 12_288)]), file_key));
    assert!(in_file_order(&skipping, &pos(&[(&b, 4096)]), file_key));
    assert!(
        !in_file_order(&skipping, &pos(&[(&a, 8192)]), file_key),
        "before the skipped buffer"
    );
    // Through `batch`: the flag, the records kept (read, reported: loud).
    let got = batch(&c, vec![at(&b, 4096), at(&a, 4096)], 2, 500, file_key);
    assert!(got.out_of_order);
    assert_eq!(got.kept.len(), 2);
    let got = batch(&c, vec![at(&a, 4096), at(&b, 4096)], 2, 500, file_key);
    assert!(!got.out_of_order);
    // The Extended Events file names.
    let (x, y) = ("/x/databastion_xe_0_133.xel", "/x/databastion_xe_0_134.xel");
    assert!(in_file_order(
        &c,
        &pos(&[(x, 4096), (y, 4096)]),
        sql::xe_file_key
    ));
    assert!(!in_file_order(
        &c,
        &pos(&[(y, 4096), (x, 4096)]),
        sql::xe_file_key
    ));
}

/// The reads of [`AuditFiles`] from the first start, with rows the reader
/// cannot parse (`malformed`, by index in the set: returned by the server,
/// dropped and counted by the reader): the records kept per read, the
/// malformed rows met, and whether a gap or a read out of order was seen.
fn walk_reads(
    mut files: AuditFiles,
    batch_size: usize,
    per_poll: usize,
    malformed: &[usize],
) -> (Vec<Vec<Record>>, usize, bool) {
    let mut c = Cursor::default();
    let mut reads = Vec::new();
    let mut met = 0;
    let mut gap = false;
    loop {
        let (top, skip) = request(&c, batch_size);
        let rows = files.read(&c, top, skip);
        let returned = rows.len();
        let parsed: Vec<Record> = rows
            .into_iter()
            .filter(|r| {
                let bad = malformed.contains(&usize::try_from(r.transaction).unwrap());
                met += usize::from(bad);
                !bad
            })
            .collect();
        let got = batch(&c, parsed, returned, top, file_key);
        assert!(!got.out_of_order, "the simulated server keeps file order");
        gap |= got.gap;
        reads.push(got.kept);
        c = got.next;
        if !got.full {
            if files.visible == files.buffers.len() {
                return (reads, met, gap);
            }
            files.visible = (files.visible + per_poll).min(files.buffers.len());
        }
    }
}

/// [`AuditFiles`] whose records carry their index as transaction id (each
/// its own statement).
fn indexed(buffers: Vec<(String, i64, usize)>) -> AuditFiles {
    let mut files = AuditFiles::new(buffers, 0);
    for (i, r) in files.all.iter_mut().enumerate() {
        r.transaction = i64::try_from(i).unwrap();
    }
    files
}

/// #253 review L2, unparsed rows: the skip counts the records read while
/// the server skips rows, so a row of a buffer still being walked that
/// cannot be parsed makes the next read start one row early: no record is
/// lost, and at most one per such row is read twice (each meeting of the
/// row is counted as dropped).
#[test]
fn unparsed_rows_lose_no_record() {
    let folder = "/var/opt/mssql/audit/";
    let a = f(folder, 134_366_529_617_000_000);
    let buffers = vec![(a.clone(), 4096, 700), (a.clone(), 512_000, 300)];
    let total: usize = 1000;
    for malformed in [vec![10], vec![499], vec![505, 650], vec![0, 1, 2, 703]] {
        for batch_size in [16, 250, BATCH] {
            let (reads, met, gap) = walk_reads(indexed(buffers.clone()), batch_size, 1, &malformed);
            assert!(!gap);
            let mut ids: Vec<i64> = reads.iter().flatten().map(|r| r.transaction).collect();
            let handled = ids.len();
            ids.sort_unstable();
            ids.dedup();
            let want: Vec<i64> = (0..total)
                .filter(|i| !malformed.contains(i))
                .map(|i| i64::try_from(i).unwrap())
                .collect();
            assert_eq!(ids, want, "{malformed:?}, {batch_size}: none lost");
            let twice = handled - want.len();
            let again = met - malformed.len();
            assert!(
                twice + again <= malformed.len(),
                "{malformed:?}, {batch_size}: bounded"
            );
            assert!(met >= malformed.len(), "every malformed row is counted");
        }
    }
}

/// #253 review L2, a statement split across a read boundary: the records
/// of one statement (one per object, one `event_time`) cut by a full
/// read give one event per read, each with its objects, none lost; a long
/// text whose first part was in the earlier read is cut (`*`, always
/// reported), never silently dropped.
#[test]
fn a_statement_split_across_reads_gives_two_events() {
    let folder = "/var/opt/mssql/audit/";
    let a = f(folder, 134_366_529_617_000_000);
    let mut files = indexed(vec![(a.clone(), 4096, 40), (a.clone(), 8192, 10)]);
    // Records 14 to 17: one statement reading four tables (a join).
    for (k, r) in files.all.iter_mut().enumerate().skip(14).take(4) {
        r.time_us = 14;
        r.transaction = 14;
        r.object = format!("t{k}");
        r.statement = Zeroizing::new("SELECT * FROM t14 JOIN t15 JOIN t16 JOIN t17".to_owned());
    }
    // Records 30 and 31: one long text in two parts.
    for (k, r) in files.all.iter_mut().enumerate().skip(30).take(2) {
        r.time_us = 30;
        r.transaction = 30;
        r.group = "0x1e".to_owned();
        r.sequence = i64::try_from(k - 29).unwrap();
        r.statement = Zeroizing::new(
            if k == 30 {
                "SELECT a FROM crm.customers "
            } else {
                "WHERE b = 1"
            }
            .to_owned(),
        );
    }
    let (reads, _, gap) = walk_reads(files, 16, 1, &[]);
    assert!(!gap);
    let statements: Vec<Vec<Statement>> = reads
        .into_iter()
        .map(|r| records::group(records::reassemble(r)))
        .collect();
    // Reads of 16: records 0..16, then 16..32: the join is split 2 + 2.
    let join: Vec<(usize, usize)> = statements
        .iter()
        .enumerate()
        .flat_map(|(i, ss)| {
            ss.iter()
                .filter(|s| s.head.transaction == 14)
                .map(move |s| (i, s.objects.len()))
        })
        .collect();
    // (The first read finds nothing written yet.)
    assert_eq!(
        join,
        [(1, 2), (2, 2)],
        "one event per read, every object kept"
    );
    // The two parts of the long text: in one read here (16..32), one event.
    let long: Vec<bool> = statements
        .iter()
        .flatten()
        .filter(|s| s.head.transaction == 30)
        .map(|s| s.head.cut)
        .collect();
    assert_eq!(long, [false]);

    // Cut between its two parts (reads of 31: 30 ends the first read),
    // the second part alone is a cut text: a read of `*`, always reported.
    let mut files = indexed(vec![(a.clone(), 4096, 40), (a, 8192, 10)]);
    for (k, r) in files.all.iter_mut().enumerate().skip(30).take(2) {
        r.time_us = 30;
        r.transaction = 30;
        r.group = "0x1e".to_owned();
        r.sequence = i64::try_from(k - 29).unwrap();
        r.statement = Zeroizing::new(
            if k == 30 {
                "SELECT a FROM crm.customers "
            } else {
                "WHERE b = 1"
            }
            .to_owned(),
        );
    }
    let (reads, _, _) = walk_reads(files, 31, 1, &[]);
    let parts: Vec<Statement> = reads
        .into_iter()
        .flat_map(|r| records::group(records::reassemble(r)))
        .filter(|s| s.head.transaction == 30)
        .collect();
    assert_eq!(parts.len(), 2, "one event per read");
    assert!(!parts[0].head.cut && parts[1].head.cut);
    let (ev, _) = records::convert(&parts[1]).unwrap();
    assert!(ev.always_report(), "the cut part is always reported");
}

/// End-of-phase-9 review L5: the 24 h gap memory survives an agent
/// restart (another `Shared`, as in the next process), so the target does
/// not show Partial again before the 24 h after a gap are over.
#[test]
fn the_gap_memory_survives_a_restart() {
    let t = "gap-test";
    let before = Shared::default();
    before.note_gap(t);
    before.note_dropped(t, 3);
    let bytes = before.encode_gap(t);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        text.starts_with("v1\ngap ") && text.contains("\ndropped 3 "),
        "{text}"
    );

    let after = Shared::default();
    assert!(!after.facts(t).gap);
    after.restore_gap(t, &bytes);
    let f = after.facts(t);
    assert!(f.gap, "the gap is remembered");
    assert_eq!(f.dropped, 3);
    // A stream restarted in the same process: not counted twice.
    after.restore_gap(t, &bytes);
    assert_eq!(after.facts(t).dropped, 3);
    after.note_dropped(t, 1);
    after.restore_gap(t, &bytes);
    assert_eq!(after.facts(t).dropped, 4);

    // Older than 24 h: forgotten.
    let old_ms = agent_now_ms() - i64::try_from(FRESHNESS.as_millis()).unwrap() - 1_000;
    let other = Shared::default();
    other.restore_gap(
        t,
        format!("v1\ngap {old_ms}\ndropped 5 {old_ms}\n").as_bytes(),
    );
    let f = other.facts(t);
    assert!(!f.gap && f.dropped == 0);
    // Ahead of the agent's clock (it went back): counted from now.
    let ahead = agent_now_ms() + 3_600_000;
    other.restore_gap(t, format!("v1\ngap {ahead}\n").as_bytes());
    assert!(other.facts(t).gap);
    // Nothing to remember: an empty memory.
    assert_eq!(Shared::default().encode_gap(t), b"v1\n");
    // A file not understood is a gap now (review of #276, L4).
    for bad in [
        "",
        "v2\n",
        "v1\ngap x\n",
        "v1\ngap 1 2\n",
        "v1\nother 1\n",
        "v1\ndropped 1\n",
    ] {
        let s = Shared::default();
        s.restore_gap(t, bad.as_bytes());
        let f = s.facts(t);
        assert!(f.gap && f.dropped == 1, "{bad:?}");
        assert!(decode_gap(bad.as_bytes()).is_none(), "{bad:?}");
    }
    // The level rule reads the restored gap: Limited, not Partial.
    let s = Shared::default();
    s.restore_gap(t, &bytes);
    assert!(s.facts(t).gap);
}

/// #276 review L6: the stream-level wiring of a read's faults, on both
/// sources: a read out of file order and a buffer over the bound are each
/// a gap with one dropped record; a clean read notes nothing.
#[test]
fn read_faults_are_gaps_on_both_sources() {
    for source in [Source::Audit, Source::Xevents] {
        let state = CheckState::default();
        let t = "faults-test";
        note_read_faults(&state, t, source, false, false);
        let facts = state.audit.facts(t);
        assert!(!facts.gap && facts.dropped == 0, "{source:?}");
        note_read_faults(&state, t, source, false, true);
        let facts = state.audit.facts(t);
        assert!(facts.gap && facts.dropped == 1, "{source:?}: out of order");
        assert_eq!(state.audit.out_of_order_reads(t), 1);
        note_read_faults(&state, t, source, true, true);
        assert_eq!(state.audit.facts(t).dropped, 3, "{source:?}: both");
        // From a batch out of order, through `batch`.
        let folder = "/var/opt/mssql/audit/";
        let got = batch(
            &Cursor::default(),
            vec![at(&f(folder, 2), 4096), at(&f(folder, 1), 4096)],
            2,
            500,
            file_key,
        );
        let state = CheckState::default();
        note_read_faults(&state, t, source, got.gap, got.out_of_order);
        assert!(state.audit.facts(t).gap, "{source:?}");
    }
}
