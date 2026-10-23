//! A simulated buffered event file read with the read size of [`super::size`]
//! (ADR-0051 refinement of 2026-10-22, test plan item 2): buffers of random
//! sizes written over time, the server-side `OFFSET` skip, responses
//! cancelled at the byte bound, the client's statement deadline, rule 2
//! cuts and deferrals, stream errors and agent restarts (the read size's
//! memory lost, the cursor persisted). Every event is handled exactly once
//! and in order, and the position never moves past an event not handled.
//!
//! Poisoned cancels (merge review L2 of the read-size change): a response
//! above the byte bound whose cancel the server did not acknowledge ends
//! the stream; the run calls `Shared::read_size` / `read_failed` /
//! `read_succeeded` and [`ReadSize::resume`] exactly as `read()` does, with
//! the connector's [`Shared`] kept across stream restarts and dropped at an
//! agent restart, so the size kept at a position drives the next stream's
//! reads there, down to `MIN_BATCH` under repeated poisoning.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use databastion_core::FailureCode;

use super::super::{BATCH, Cursor, MIN_BATCH, POLL_BYTES, Positioned, ReadAt, Shared, Source};
use super::size::{Path, ReadSize, Retry, XE_MAX_ROWS};
use super::xe_next;
use crate::error::{SsError, Stage};
use crate::sql;

#[derive(Debug, Clone)]
struct Ev {
    file: String,
    offset: i64,
    id: usize,
    bytes: usize,
}

impl Positioned for Ev {
    fn file(&self) -> &str {
        &self.file
    }
    fn offset(&self) -> i64 {
        self.offset
    }
}

/// The session's files: buffers `(file, offset)` of `events`, `visible`
/// of them written so far.
struct Files {
    buffers: Vec<(String, i64)>,
    events: Vec<Ev>,
    /// The first event of each buffer.
    starts: Vec<usize>,
    visible: usize,
}

impl Files {
    fn new(sizes: &[(usize, bool)], per_file: usize) -> Self {
        let (mut buffers, mut events, mut starts) = (Vec::new(), Vec::new(), Vec::new());
        for (i, (n, large)) in sizes.iter().enumerate() {
            let file = format!("/x/s_0_{}.xel", 1000 + i / per_file.max(1));
            let offset = i64::try_from((i % per_file.max(1)) * 4096).unwrap();
            buffers.push((file.clone(), offset));
            starts.push(events.len());
            for k in 0..*n {
                let id = events.len();
                // Small events of the load workload (about 3.6 KB on the
                // wire), and buffers of large ones (up to 123 KB).
                let bytes = if *large && k % 5 == 0 {
                    123_603
                } else {
                    3_512 + id % 100
                };
                events.push(Ev {
                    file: file.clone(),
                    offset,
                    id,
                    bytes,
                });
            }
        }
        Self {
            buffers,
            events,
            starts,
            visible: 0,
        }
    }

    fn end(&self) -> usize {
        self.starts
            .get(self.visible)
            .copied()
            .unwrap_or(self.events.len())
    }

    /// Where a read from `c` starts on the server, its skip included.
    fn start(&self, c: &Cursor) -> usize {
        let after = match &c.file {
            None => 0,
            Some(f) => {
                let i = self
                    .buffers
                    .iter()
                    .position(|(bf, bo)| bf == f && *bo == c.offset)
                    .expect("a buffer of the set");
                self.starts.get(i + 1).copied().unwrap_or(self.events.len())
            }
        };
        (after + c.skip as usize).min(self.end())
    }

    fn read(&self, c: &Cursor, top: usize) -> Result<Vec<Ev>, FailureCode> {
        let from = self.start(c);
        let rows = &self.events[from..self.end().min(from + top)];
        let bytes: usize = rows.iter().map(|e| e.bytes).sum();
        if bytes > POLL_BYTES {
            return Err(FailureCode::ResourceLimit);
        }
        Ok(rows.to_vec())
    }
}

/// What the scripted run met.
#[derive(Debug, Default)]
struct Met {
    cancels: u64,
    timeouts: u64,
    errors: u64,
    /// Reads above the byte bound whose cancel poisoned the session.
    poisoned: u64,
    largest_asked: usize,
    /// Every read asked: (events handled before it, rows asked, poisoned).
    asked: Vec<(usize, usize, bool)>,
}

/// The target of the simulated connector.
const T: &str = "t";

/// A fault of the script: 1 to 3 and 5.
fn is_fault(f: u8) -> bool {
    (1..=3).contains(&f) || f == 5
}

/// One run: `script` drives each step's fault (0 none, 1 a deadline, 2 a
/// stream error, 3 an agent restart, 4 a cut or deferral, 5 a response
/// above the byte bound whose cancel poisons the session, whatever the
/// simulated bytes); returns the ids handled, in order. Faults never
/// follow each other, except up to `poison_streak` poisoned reads in a
/// row (the same position read again by each restarted stream) and an
/// agent restart after a poisoned read.
fn run(
    files: &mut Files,
    script: &[u8],
    per_step: usize,
    poison_streak: usize,
) -> (Vec<usize>, Met) {
    let t0 = Instant::now();
    let mut now = t0;
    let mut cursor = Cursor::default();
    let mut size = ReadSize::default();
    // The connector's per-target facts: kept across stream restarts,
    // dropped at an agent restart.
    let mut shared = Shared::default();
    let mut handled: Vec<usize> = Vec::new();
    let mut met = Met::default();
    let mut step = 0usize;
    let mut idle = 0;
    let mut last = 0u8;
    let mut streak = 0usize;
    let mut faults = 0usize;
    let mut deferred_at: Option<usize> = None;
    // The size a poisoned read left at its position (the bound of the
    // next read there in this agent run, until a read succeeds).
    let mut poisoned_at: Option<(ReadAt, usize)> = None;
    while idle < 3 {
        let mut fault = script.get(step % script.len().max(1)).copied().unwrap_or(0);
        // No two faults in a row, and at most 40 in a run: a stream error
        // after every restart would read nothing (each restart forgets the
        // stream's halving: one more cancel, the residual of the
        // refinement's memory). Poisoned reads may follow each other up to
        // `poison_streak` times: the walk-down at one position.
        // An agent restart may follow a poisoned read too.
        let streaking = last == 5 && ((fault == 5 && streak < poison_streak) || fault == 3);
        if is_fault(fault) && (faults >= 40 || (is_fault(last) && !streaking)) {
            fault = 0;
        }
        streak = if fault == 5 { streak + 1 } else { 0 };
        last = fault;
        faults += usize::from(is_fault(fault));
        step += 1;
        assert!(step < 1_000_000, "the run ends");
        now += Duration::from_secs(7);
        if fault == 3 {
            // An agent restart: the size's memory and the connector's
            // facts are lost, the cursor kept.
            size = ReadSize::default();
            shared = Shared::default();
            poisoned_at = None;
            continue;
        }
        // What `read()` does first: the size kept at this very position
        // across a stream restart, taken into the stream's memory.
        let at = ReadAt::of(&cursor);
        let kept = shared.read_size(T, Source::Xevents, &at, usize::MAX);
        if kept < usize::MAX {
            size.resume(kept, now);
        }
        let top = size.rows();
        assert!((MIN_BATCH..=XE_MAX_ROWS).contains(&top), "{top}");
        met.largest_asked = met.largest_asked.max(top);
        met.asked.push((handled.len(), top, fault == 5));
        // The position never moves past an event not handled.
        assert_eq!(
            files.start(&cursor),
            handled.len(),
            "position at step {step}"
        );
        // A restarted stream never reads more than a poisoned read left at
        // the same position (fail closed: the walk-down goes on).
        if let Some((pa, n)) = &poisoned_at
            && *pa == at
        {
            assert!(top <= *n, "{top} after a poisoned read kept {n}");
        }
        // `read()` on a failed read: the connector keeps the halved size
        // (`Shared::read_failed`, every failure, as `read()`), then the
        // stream's own rule (`ReadSize::failed`).
        let fail = |size: &mut ReadSize, shared: &Shared, e: &SsError, poisoned: bool| {
            let _ = shared.read_failed(T, Source::Xevents, at.clone(), e, poisoned, top);
            size.failed(e, poisoned, now)
        };
        if fault == 5 {
            // A response above the bound, its cancel not acknowledged: the
            // stream ends; the next one (a new `ReadSize`, the same
            // `Shared`) reads from the same position.
            let e = SsError::new(FailureCode::ResourceLimit, Stage::Introspection);
            assert_eq!(fail(&mut size, &shared, &e, true), None);
            met.poisoned += 1;
            met.errors += 1;
            let left = shared.read_size(T, Source::Xevents, &at, usize::MAX);
            if left < usize::MAX {
                assert!(left <= (top / 2).max(MIN_BATCH), "{left} kept after {top}");
                poisoned_at = Some((at, left));
            } else {
                // Nothing is halved below the floor (`super::super::halved`).
                assert_eq!(top, MIN_BATCH, "nothing kept after {top}");
            }
            size = ReadSize::default();
            continue;
        }
        if fault == 1 {
            let e = SsError::new(FailureCode::Timeout, Stage::Introspection);
            match fail(&mut size, &shared, &e, false) {
                Some(r) => {
                    assert_eq!(r, Retry::Timeout);
                    met.timeouts += 1;
                }
                None => {
                    assert!(top <= BATCH);
                    met.errors += 1;
                    size = ReadSize::default();
                }
            }
            continue;
        }
        if fault == 2 {
            // A server error (1205): the stream fails and restarts.
            let e = SsError::server(1205, 13, Stage::Introspection);
            assert_eq!(fail(&mut size, &shared, &e, false), None);
            met.errors += 1;
            size = ReadSize::default();
            continue;
        }
        let rows = match files.read(&cursor, top) {
            Ok(rows) => {
                // The size kept across restarts ends with a successful read.
                shared.read_succeeded(T);
                poisoned_at = None;
                rows
            }
            Err(code) => {
                let e = SsError::new(code, Stage::Introspection);
                match fail(&mut size, &shared, &e, false) {
                    Some(r) => {
                        assert_eq!(r, Retry::Bytes);
                        met.cancels += 1;
                    }
                    None => {
                        assert_eq!(top, MIN_BATCH);
                        met.errors += 1;
                        size = ReadSize::default();
                    }
                }
                continue;
            }
        };
        let returned = rows.len();
        let largest = rows.iter().map(|e| e.bytes).max().unwrap_or(0);
        let positions: Vec<(String, i64)> =
            rows.iter().map(|e| (e.file.clone(), e.offset)).collect();
        let b = super::super::batch(&cursor, rows, returned, top, sql::xe_file_key);
        assert!(!b.gap && !b.out_of_order);
        let mut kept = b.kept;
        let mut next = b.next;
        let mut waits = false;
        if fault == 4 && returned > 0 {
            if b.full {
                // Rule 2: at or past the later of half the read and its
                // last 256 rows.
                let from = (returned / 2).max(returned.saturating_sub(256)).max(1);
                let at = from + step % (returned - from + 1);
                if at < returned {
                    assert!(returned - at <= 256.max(returned / 2));
                    kept.truncate(at);
                    (next, _) = xe_next(&cursor, &positions[..at], true);
                }
            } else if deferred_at != Some(handled.len()) {
                // A deferral: the read ends before an event, and waits;
                // once per position (the hold is bounded, MAX_DEFERRAL).
                let at = step % returned;
                deferred_at = Some(handled.len());
                kept.truncate(at);
                (next, _) = xe_next(&cursor, &positions[..at], true);
                waits = true;
            }
        }
        handled.extend(kept.iter().map(|e| e.id));
        cursor = next;
        let more = b.full && !waits;
        size.received(largest, if more { Path::Sized } else { Path::Base }, now);
        if !more {
            if files.visible < files.buffers.len() {
                files.visible = (files.visible + per_step).min(files.buffers.len());
                idle = 0;
            } else if !waits {
                idle += 1;
            }
        }
    }
    (handled, met)
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
    /// Test plan item 2: buffers of random sizes (some of large events),
    /// written a few at a time; deadlines, stream errors, poisoned cancels
    /// (in runs of up to `poison_streak` at one position), agent restarts,
    /// cuts and deferrals anywhere: every event handled exactly once and in
    /// order, the position never past an event not handled, and a stream
    /// restarted after a poisoned read never reads more there than the
    /// connector kept.
    #[test]
    fn a_buffered_file_is_read_whole_whatever_the_read_sizes(
        sizes in proptest::collection::vec((1usize..5_000, proptest::bool::weighted(0.15)), 1..24),
        per_file in 1usize..8,
        per_step in 1usize..4,
        poison_streak in 1usize..10,
        script in proptest::collection::vec(proptest::prop_oneof![
            6 => proptest::strategy::Just(0u8),
            1 => proptest::strategy::Just(1u8),
            1 => proptest::strategy::Just(2u8),
            1 => proptest::strategy::Just(3u8),
            2 => proptest::strategy::Just(4u8),
            2 => proptest::strategy::Just(5u8),
        ], 1..40),
    ) {
        let mut files = Files::new(&sizes, per_file);
        let total = files.events.len();
        let (handled, met) = run(&mut files, &script, per_step, poison_streak);
        proptest::prop_assert_eq!(handled.len(), total, "{:?}", met);
        proptest::prop_assert!(handled.iter().enumerate().all(|(i, id)| i == *id), "in order, once");
    }
}

/// A file of small events only, no fault: reads go to the sized bound
/// (N, or fewer by the wire bytes) and nothing is cancelled.
#[test]
fn small_events_are_read_at_the_sized_bound() {
    let mut files = Files::new(&[(4_593, false); 12], 4);
    let (handled, met) = run(&mut files, &[0], 12, 0);
    assert_eq!(handled.len(), 12 * 4_593);
    assert_eq!(met.cancels + met.timeouts + met.errors, 0, "{met:?}");
    assert_eq!(
        met.largest_asked,
        XE_MAX_ROWS.min(POLL_BYTES / 4 * 3 / 3_611)
    );
}

/// Buffers with large events (one in five, 123 KB each) among small ones:
/// the read of the sized bound that meets the first is cancelled, then
/// reads stay at most BATCH for 10 minutes and meet the second without a
/// cancel; none is lost or read twice.
#[test]
fn large_events_cost_one_cancel_per_ten_minutes() {
    let mut sizes = vec![(4_000, false); 6];
    sizes.extend([(300, true), (4_000, false), (300, true)]);
    sizes.extend(vec![(4_000, false); 6]);
    let total: usize = sizes.iter().map(|s| s.0).sum();
    let mut files = Files::new(&sizes, 3);
    let (handled, met) = run(&mut files, &[0], sizes.len(), 0);
    assert_eq!(handled.len(), total);
    // Steps of 7 s: the whole run takes less than 10 minutes.
    assert_eq!(met.cancels, 1, "{met:?}");
    assert_eq!(
        met.largest_asked,
        XE_MAX_ROWS.min(POLL_BYTES / 4 * 3 / 3_611)
    );
    assert_eq!(met.errors, 0, "{met:?}");
}

/// Merge review L2: poisoned cancels at one position, each ending the
/// stream. A first full read at `BATCH` sets the sized bound; the read of
/// N there poisons the session, and every restarted stream reads less
/// from the same position (the size the connector kept, taken in by
/// `ReadSize::resume`, capped at `BATCH`): 500, 250, 125, 62, 31, then 16
/// for as long as the poisoning recurs, never more; the first read that
/// succeeds there moves on, and nothing is lost or read twice. An agent
/// restart in between forgets the kept size (the connector's facts are in
/// memory): the next stream starts again at `BATCH`.
#[test]
fn repeated_poisoning_at_one_position_walks_down_to_the_floor() {
    let sized = XE_MAX_ROWS.min(POLL_BYTES / 4 * 3 / 3_611);
    // The reads at the position after the first read (`BATCH` events in).
    let at_second = |met: &Met| -> Vec<(usize, bool)> {
        met.asked
            .iter()
            .filter(|(pos, _, _)| *pos == BATCH)
            .map(|(_, top, poisoned)| (*top, *poisoned))
            .collect()
    };
    let total: usize = 4 * 4_000;
    let mut files = Files::new(&[(4_000, false); 4], 2);
    files.visible = 4;
    let mut script = vec![0u8];
    script.extend([5u8; 9]);
    script.extend([0u8; 200]);
    let (handled, met) = run(&mut files, &script, 4, 9);
    assert_eq!(handled.len(), total, "{met:?}");
    assert!(handled.iter().enumerate().all(|(i, id)| i == *id));
    assert_eq!(met.poisoned, 9, "{met:?}");
    assert_eq!(met.cancels + met.timeouts, 0, "{met:?}");
    assert_eq!(
        at_second(&met),
        [
            (sized, true),
            (500, true),
            (250, true),
            (125, true),
            (62, true),
            (31, true),
            (MIN_BATCH, true),
            (MIN_BATCH, true),
            (MIN_BATCH, true),
            // The first read that succeeds there: the position moves on.
            (MIN_BATCH, false),
        ],
    );

    // An agent restart after the third poisoned read: the kept size is
    // lost with the connector's facts, and the next stream reads `BATCH`.
    let mut files = Files::new(&[(4_000, false); 4], 2);
    files.visible = 4;
    let mut script = vec![0u8, 5, 5, 5, 3];
    script.extend([0u8; 200]);
    let (handled, met) = run(&mut files, &script, 4, 9);
    assert_eq!(handled.len(), total, "{met:?}");
    assert!(handled.iter().enumerate().all(|(i, id)| i == *id));
    assert_eq!(met.poisoned, 3, "{met:?}");
    assert_eq!(
        at_second(&met),
        [(sized, true), (500, true), (250, true), (BATCH, false)],
    );
}
