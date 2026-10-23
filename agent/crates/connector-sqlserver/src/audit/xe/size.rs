//! The size of the next Extended Events read: stream state set inside
//! `read()` (ADR-0051 refinement of 2026-10-22, option (b), security
//! review M1 and M2), never taken from the cycle's view of a read.
//!
//! - **After a read that succeeded, returned every row it asked, was
//!   handled, was not clamped and does not wait** (a full read cut by
//!   rule 2 included; `read()` then returns "more to read" from its normal
//!   end): the **sized bound**, the smaller of [`XE_MAX_ROWS`], the
//!   remembered cap and `0.75 × POLL_BYTES` divided by the largest row (in
//!   wire bytes) of that read, never below `BATCH`.
//! - **After a response above `POLL_BYTES`** (cancelled by the client,
//!   nothing of it handled): half the size, down to `MIN_BATCH`, kept for
//!   [`MEMORY`]; then the size grows back by doubling after each read that
//!   succeeds, to `BATCH`, then to the sized bound. A response above the
//!   bound at `MIN_BATCH`, or on a session left unusable by the cancel, is
//!   a stream error, as before.
//! - **Every other path** (a read that is not full, a deferral, a clamp
//!   before a file the session has not written, the restart after errors
//!   25722 / 25717, a re-probe that moved the cursor): `BATCH`.
//! - **Remembered for [`MEMORY`]**: a cancel above `POLL_BYTES`, or a
//!   retried timeout, of a read of more than `BATCH` rows caps the reads
//!   at `BATCH`. The memory lives in the stream (lost at a restart, which
//!   can cost one more cancel or timeout), with one exception:
//! - **Across a stream restart** (0.8.1, #321): a response above
//!   `POLL_BYTES` is also kept by the connector for the target, the source
//!   and the position (`Shared::read_failed`, the cancel acknowledged or
//!   not), until the next successful read there. When a poisoned session
//!   ended the stream, the next stream takes it in at its first read from
//!   that position ([`ReadSize::resume`]): as a halved size and a cap at
//!   `BATCH`, both for [`MEMORY`] from then, so a recurring poisoning still
//!   walks down to `MIN_BATCH` and the reads then grow back as after an
//!   in-stream cancel.
//! - **A timeout is retried at `BATCH`** only when the read asked more than
//!   `BATCH` rows, the timeout is the client's own statement deadline (no
//!   server error number: 1222, 1205, 601 and 605 map to a timeout too and
//!   stay stream errors) and the session is still usable after the cancel
//!   (the server acknowledged the `ATTENTION`). The position is unchanged.
//! - **Counted**: each cancel and timeout gives a `debug` line with the
//!   totals (read by the load harness), and an `info` line at most once
//!   per [`MEMORY`] per target with the counts since the last one.

use std::time::{Duration, Instant};

use databastion_core::FailureCode;

use super::super::{BATCH, MIN_BATCH, POLL_BYTES, halved};
use crate::error::SsError;

/// The Extended Events row bound (ADR-0051 refinement of 2026-10-22, N):
/// reads after a full read ask at most this many events, sized from the
/// wire bytes per row. Set from the read-cost measurement of 2026-10-22
/// on SQL Server 2022 (16.0.4305.5, docs/measurements/phase9-engine-facts.md):
/// a read costs about 37 ms plus 0.43 ms per event read and 0.06 ms per
/// event skipped; walking a buffer of 4 593 events gives about 1 250
/// events/s of reading time in reads of 500, 1 840 in reads of 2 000 and
/// 1 920 in reads of 3 000; a read of 4 000 of the load workload's events
/// (about 3.5 KiB each on the wire) is above `POLL_BYTES`. `BATCH` stays
/// SQL Server Audit's bound and this source's base size.
pub(crate) const XE_MAX_ROWS: usize = 2_000;
/// How long a response above `POLL_BYTES`, a cancel or a retried timeout
/// is remembered; also the period of the `info` line.
pub(crate) const MEMORY: Duration = Duration::from_secs(600);

/// How a read that received its response ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Path {
    /// Full, handled, not clamped, no wait (a rule 2 cut included).
    Sized,
    /// Any other end: not full, a deferral, a clamp, a re-probe that moved.
    Base,
}

/// How a read whose response was taken ended (security review L3 of the
/// read-size change: `read()`'s choice of "more to read" and of the next
/// size, in one pure function, [`ReadSize::ended`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadEnd {
    /// A position the server refused (errors 25722 / 25717): restarted at
    /// the oldest file, nothing read.
    Restarted,
    /// Its response came, and a re-probe moved the cursor (new file set or
    /// session start): not handled. `largest_row`: its largest row.
    ReprobeMoved { largest_row: usize },
    /// Handled: `full` it returned every row it asked, `waits` it ended
    /// before a deferred statistics build, `clamped` its position was kept
    /// before a file the session has not written yet.
    Handled {
        largest_row: usize,
        full: bool,
        waits: bool,
        clamped: bool,
    },
}

/// Why a read was retried rather than failing the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retry {
    /// A response above `POLL_BYTES`: cancelled, read again smaller.
    Bytes,
    /// The client's statement deadline on a read above `BATCH` rows.
    Timeout,
}

/// The read size of one stream.
#[derive(Debug)]
pub(crate) struct ReadSize {
    next: usize,
    /// The halved size after a response above `POLL_BYTES`, and when.
    halved: Option<(usize, Instant)>,
    /// Reads capped at `BATCH` since (a cancel or a retried timeout of a
    /// read above `BATCH` rows).
    capped: Option<Instant>,
    /// The largest row (wire bytes) of the last read that succeeded.
    largest_row: usize,
    /// Totals since the stream started.
    pub(crate) cancels: u64,
    pub(crate) timeouts: u64,
    /// The totals at the last `info` line, and when it was logged.
    logged: (u64, u64),
    logged_at: Option<Instant>,
    /// How long outcomes are remembered: [`MEMORY`], shorter only in the
    /// integration tests, per connector ([`ReadSize::with_memory`]).
    memory: Duration,
}

impl Default for ReadSize {
    fn default() -> Self {
        Self {
            next: BATCH,
            halved: None,
            capped: None,
            largest_row: 0,
            cancels: 0,
            timeouts: 0,
            logged: (0, 0),
            logged_at: None,
            memory: MEMORY,
        }
    }
}

fn active(at: Option<Instant>, now: Instant, memory: Duration) -> bool {
    at.is_some_and(|t| now.saturating_duration_since(t) < memory)
}

impl ReadSize {
    /// A stream's read size, its memory `memory` (`None`: [`MEMORY`]; set
    /// only by the integration tests, per connector instance).
    pub(crate) fn with_memory(memory: Option<Duration>) -> Self {
        Self {
            memory: memory.unwrap_or(MEMORY),
            ..Self::default()
        }
    }

    /// The rows of the next read.
    pub(crate) fn rows(&self) -> usize {
        self.next
    }

    /// The sized bound at `now` ([module documentation](self)).
    pub(crate) fn sized_bound(&self, now: Instant) -> usize {
        let by_bytes = (POLL_BYTES / 4 * 3)
            .checked_div(self.largest_row)
            .unwrap_or(XE_MAX_ROWS);
        let cap = if active(self.capped, now, self.memory) {
            BATCH
        } else {
            XE_MAX_ROWS
        };
        XE_MAX_ROWS.min(cap).min(by_bytes).max(BATCH)
    }

    /// Sets the next size after a read that ended as `end`; `true` when
    /// the next read follows at once (`read()`'s result).
    pub(crate) fn ended(&mut self, end: ReadEnd, now: Instant) -> bool {
        match end {
            ReadEnd::Restarted => {
                self.restarted(now);
                true
            }
            ReadEnd::ReprobeMoved { largest_row } => {
                self.received(largest_row, Path::Base, now);
                true
            }
            ReadEnd::Handled {
                largest_row,
                full,
                waits,
                clamped,
            } => {
                let more = full && !waits && !clamped;
                let path = if more { Path::Sized } else { Path::Base };
                self.received(largest_row, path, now);
                more
            }
        }
    }

    /// A read whose response was received, its largest row `largest_row`
    /// wire bytes, ended by `path`.
    pub(crate) fn received(&mut self, largest_row: usize, path: Path, now: Instant) {
        self.largest_row = largest_row;
        let base = match path {
            Path::Sized => self.sized_bound(now),
            Path::Base => BATCH,
        };
        self.settle(base, true, now);
    }

    /// A read the server refused (errors 25722 / 25717): the stream
    /// restarts at the oldest file, at `BATCH`.
    pub(crate) fn restarted(&mut self, now: Instant) {
        self.settle(BATCH, false, now);
    }

    fn settle(&mut self, base: usize, succeeded: bool, now: Instant) {
        let mut next = base;
        if let Some((size, at)) = self.halved {
            if active(Some(at), now, self.memory) || !succeeded {
                next = next.min(size);
            } else {
                // Grows back by doubling after each read that succeeds, to
                // `BATCH`, then to the sized bound.
                let grown = size.saturating_mul(2);
                if grown >= BATCH {
                    self.halved = None;
                    next = next.min(BATCH);
                } else {
                    self.halved = Some((grown, at));
                    next = next.min(grown);
                }
            }
        }
        if active(self.capped, now, self.memory) {
            next = next.min(BATCH);
        }
        self.next = next.max(MIN_BATCH);
    }

    /// Takes in `kept`, the size the connector kept at the position of the
    /// next read after an oversized read there that a poisoned session
    /// ended (`Shared::read_size`, 0.8.1): the next reads are at most
    /// `kept` (a halved size kept for [`MEMORY`] from `now`) and, unless
    /// this stream already remembers a cancel, capped at `BATCH` for
    /// [`MEMORY`], as a cancel in this stream would have left them. A size
    /// this stream already holds (its own cancel, also kept by the
    /// connector) changes nothing.
    pub(crate) fn resume(&mut self, kept: usize, now: Instant) {
        let fresh = self.halved.is_none() && !active(self.capped, now, self.memory);
        if kept < self.next {
            self.halved = Some((kept, now));
            self.next = kept.max(MIN_BATCH);
        }
        if fresh {
            self.capped = Some(now);
            self.next = self.next.min(BATCH);
        }
    }

    /// A read of `self.rows()` that failed with `e`, `poisoned` whether
    /// the session is unusable after it: `Some` when it is retried (the
    /// position unchanged), `None` when the stream fails, as before.
    pub(crate) fn failed(&mut self, e: &SsError, poisoned: bool, now: Instant) -> Option<Retry> {
        let asked = self.next;
        if poisoned {
            return None;
        }
        match e.code {
            // The released rule of both sources (`super::super::halved`):
            // the session in step, above `MIN_BATCH`.
            FailureCode::ResourceLimit => {
                let size = halved(e, false, asked)?;
                self.halved = Some((size, now));
                if asked > BATCH {
                    self.capped = Some(now);
                }
                self.cancels += 1;
                self.settle(size, false, now);
                Some(Retry::Bytes)
            }
            // The client's own deadline: no server error number (1222,
            // 1205, 601 and 605 carry theirs).
            FailureCode::Timeout if asked > BATCH && e.number.is_none() => {
                self.capped = Some(now);
                self.timeouts += 1;
                self.settle(BATCH, false, now);
                Some(Retry::Timeout)
            }
            _ => None,
        }
    }

    /// Logs a retry of a read of `asked` rows: a `debug` line each time,
    /// with the totals, and an `info` line at most once per [`MEMORY`];
    /// `true` when the `info` line was logged.
    pub(crate) fn log(
        &mut self,
        target_id: &str,
        retry: Retry,
        asked: usize,
        now: Instant,
    ) -> bool {
        let reason = match retry {
            Retry::Bytes => "response above 12 MiB",
            Retry::Timeout => "statement timeout",
        };
        tracing::debug!(
            target_id = %target_id,
            reason,
            asked,
            next = self.next,
            cancels_total = self.cancels,
            timeouts_total = self.timeouts,
            "Extended Events read cancelled: read again smaller"
        );
        if self
            .logged_at
            .is_some_and(|t| now.saturating_duration_since(t) < self.memory)
        {
            return false;
        }
        tracing::info!(
            target_id = %target_id,
            cancels = self.cancels - self.logged.0,
            timeouts = self.timeouts - self.logged.1,
            next = self.next,
            "Extended Events reads cancelled above 12 MiB or at the statement timeout since the last line: reads are smaller for 10 minutes"
        );
        self.logged = (self.cancels, self.timeouts);
        self.logged_at = Some(now);
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::error::Stage;

    fn bytes() -> SsError {
        SsError::new(FailureCode::ResourceLimit, Stage::Introspection)
    }
    fn deadline() -> SsError {
        SsError::new(FailureCode::Timeout, Stage::Introspection)
    }
    /// A small event of the load workload (measured: 3 512 to 3 603 wire
    /// bytes).
    const SMALL: usize = 3_603;

    /// Every path of `read()` (M1): a full read (and a rule 2 cut, the same
    /// path) goes on at the sized bound; a read that is not full, a
    /// deferral, a clamp and a re-probe that moved at `BATCH`; a refused
    /// position at `BATCH`.
    #[test]
    fn the_next_size_follows_the_path_of_the_read() {
        let t = Instant::now();
        let mut s = ReadSize::default();
        assert_eq!(s.rows(), BATCH, "a stream starts at BATCH");
        // Small rows: N.
        s.received(1_000, Path::Sized, t);
        assert_eq!(s.rows(), XE_MAX_ROWS);
        // Not full, a deferral, a clamp, a re-probe that moved: BATCH.
        s.received(1_000, Path::Base, t);
        assert_eq!(s.rows(), BATCH);
        s.received(1_000, Path::Sized, t);
        s.restarted(t);
        assert_eq!(s.rows(), BATCH, "errors 25722 / 25717");
        // The load workload's events: 0.75 × 12 MiB / 3 603 = 2 619 rows.
        s.received(SMALL, Path::Sized, t);
        assert_eq!(s.rows(), XE_MAX_ROWS.min(2_619));
        // Large rows: never below BATCH.
        s.received(123_603, Path::Sized, t);
        assert_eq!(s.rows(), BATCH);
        // No row (an empty read is never full; the bound alone).
        s.received(0, Path::Sized, t);
        assert_eq!(s.rows(), XE_MAX_ROWS);
    }

    /// Security review L3: every end of `read()` through the pure
    /// function it calls: "more to read" and the next size.
    #[test]
    fn every_end_of_a_read_sets_more_and_the_size() {
        let t = Instant::now();
        let handled = |full, waits, clamped| ReadEnd::Handled {
            largest_row: 1_000,
            full,
            waits,
            clamped,
        };
        for (end, more, rows) in [
            (handled(true, false, false), true, XE_MAX_ROWS),
            // A clamp before a file not written yet.
            (handled(true, false, true), false, BATCH),
            // A deferral.
            (handled(true, true, false), false, BATCH),
            (handled(false, true, false), false, BATCH),
            // Not full (caught up).
            (handled(false, false, false), false, BATCH),
            (ReadEnd::ReprobeMoved { largest_row: 1_000 }, true, BATCH),
            (ReadEnd::Restarted, true, BATCH),
        ] {
            let mut s = ReadSize::default();
            s.received(1_000, Path::Sized, t);
            assert_eq!(s.rows(), XE_MAX_ROWS);
            assert_eq!(s.ended(end, t), more, "{end:?}");
            assert_eq!(s.rows(), rows, "{end:?}");
        }
        // A full read's largest row sizes the next one.
        let mut s = ReadSize::default();
        assert!(s.ended(
            ReadEnd::Handled {
                largest_row: 6_000,
                full: true,
                waits: false,
                clamped: false
            },
            t
        ));
        assert_eq!(s.rows(), POLL_BYTES / 4 * 3 / 6_000);
    }

    /// The sized bound: the smaller of N, the cap and 0.75 × POLL_BYTES
    /// over the largest row of the last successful read, at least BATCH.
    #[test]
    fn the_sized_bound_comes_from_the_wire_bytes() {
        let t = Instant::now();
        let mut s = ReadSize::default();
        for (row, want) in [
            (1usize, XE_MAX_ROWS),
            (
                4_000,
                (POLL_BYTES / 4 * 3 / 4_000).clamp(BATCH, XE_MAX_ROWS),
            ),
            (POLL_BYTES / 4 * 3 / 600, 600.min(XE_MAX_ROWS)),
            (POLL_BYTES, BATCH),
        ] {
            s.received(row, Path::Base, t);
            assert_eq!(s.sized_bound(t), want, "row {row}");
            // A response of the sized bound's rows stays under 75 % of the
            // byte bound unless that is below BATCH.
            if want > BATCH {
                assert!(want * row <= POLL_BYTES / 4 * 3);
            }
        }
    }

    /// A response above 12 MiB: halved, down to MIN_BATCH, kept across
    /// cycles for 10 minutes, then doubling back to BATCH, then the sized
    /// bound; at MIN_BATCH a stream error.
    #[test]
    fn a_response_above_the_byte_bound_halves_for_ten_minutes() {
        let t = Instant::now();
        let at = |s: u64| t + Duration::from_secs(s);
        let mut s = ReadSize::default();
        s.received(1_000, Path::Sized, t);
        assert_eq!(s.rows(), XE_MAX_ROWS);
        // A read of N cancelled: half of it, and capped at BATCH.
        assert_eq!(s.failed(&bytes(), false, t), Some(Retry::Bytes));
        assert_eq!(s.rows(), BATCH);
        assert_eq!(s.cancels, 1);
        // BATCH cancelled again: 250, 125, 62, 31, 16, then a stream error.
        let mut want = BATCH;
        while want > MIN_BATCH {
            want = (want / 2).max(MIN_BATCH);
            assert_eq!(s.failed(&bytes(), false, at(1)), Some(Retry::Bytes));
            assert_eq!(s.rows(), want);
        }
        assert_eq!(s.failed(&bytes(), false, at(1)), None, "at MIN_BATCH");
        // Kept across cycles for 10 minutes, whatever the reads.
        for _ in 0..5 {
            s.received(1_000, Path::Sized, at(300));
            assert_eq!(s.rows(), MIN_BATCH);
        }
        s.restarted(at(400));
        assert_eq!(s.rows(), MIN_BATCH);
        // Then doubling after each successful read, to BATCH, then N.
        let mut sizes = Vec::new();
        for _ in 0..7 {
            s.received(1_000, Path::Sized, at(602));
            sizes.push(s.rows());
        }
        assert_eq!(sizes, [32, 64, 128, 256, BATCH, XE_MAX_ROWS, XE_MAX_ROWS]);
        // A refused position does not grow it.
        let mut s = ReadSize::default();
        assert_eq!(s.failed(&bytes(), false, t), Some(Retry::Bytes));
        assert_eq!(s.rows(), 250);
        s.restarted(at(700));
        assert_eq!(s.rows(), 250);
        s.received(1_000, Path::Base, at(700));
        assert_eq!(s.rows(), BATCH);
        // A cancel the server did not acknowledge: a stream error.
        let mut s = ReadSize::default();
        assert_eq!(s.failed(&bytes(), true, t), None);
    }

    /// The 10-minute cap of BATCH after a cancel or a retried timeout of
    /// a read above BATCH rows.
    #[test]
    fn a_cancel_or_a_timeout_above_batch_caps_the_reads() {
        let t = Instant::now();
        let at = |s: u64| t + Duration::from_secs(s);
        for e in [bytes(), deadline()] {
            let mut s = ReadSize::default();
            s.received(1_000, Path::Sized, t);
            assert!(s.failed(&e, false, t).is_some());
            assert_eq!(s.rows(), BATCH);
            for i in 1..60 {
                s.received(1_000, Path::Sized, at(i * 10));
                assert_eq!(s.rows(), BATCH, "{e:?} at {} s", i * 10);
            }
            s.received(1_000, Path::Sized, at(600));
            if e.code == FailureCode::ResourceLimit {
                // The halved size (1 000) grows back by doubling: to
                // BATCH first.
                assert_eq!(s.rows(), BATCH);
                s.received(1_000, Path::Sized, at(601));
            }
            assert_eq!(s.rows(), XE_MAX_ROWS, "{e:?} after 10 minutes");
        }
    }

    /// Security review M2: a timeout is retried at BATCH only on the
    /// client's deadline of a read above BATCH rows with the session still
    /// usable; server errors 1222, 1205, 601 and 605, a poisoned session
    /// and a timeout at BATCH rows or fewer stay stream errors.
    #[test]
    fn only_the_clients_deadline_above_batch_is_retried() {
        let t = Instant::now();
        let full = || {
            let mut s = ReadSize::default();
            s.received(1_000, Path::Sized, t);
            s
        };
        let mut s = full();
        assert_eq!(s.failed(&deadline(), false, t), Some(Retry::Timeout));
        assert_eq!((s.rows(), s.timeouts), (BATCH, 1));
        for n in [1222, 1205, 601, 605] {
            let e = SsError::server(n, 16, Stage::Introspection);
            assert_eq!(e.code, FailureCode::Timeout, "{n}");
            assert_eq!(full().failed(&e, false, t), None, "{n}");
        }
        assert_eq!(full().failed(&deadline(), true, t), None, "poisoned");
        // At BATCH rows or fewer.
        let mut s = ReadSize::default();
        assert_eq!(s.failed(&deadline(), false, t), None);
        assert_eq!(s.failed(&bytes(), false, t), Some(Retry::Bytes));
        assert_eq!(s.failed(&deadline(), false, t), None);
        // Other failures.
        for code in [FailureCode::Internal, FailureCode::PermissionDenied] {
            let e = SsError::new(code, Stage::Introspection);
            assert_eq!(full().failed(&e, false, t), None);
        }
    }

    /// The 0.8.1 guarantee (#321) with this stream state: a read above the
    /// byte bound that poisons the session ends the stream, and the
    /// restarted stream (a new `ReadSize`) takes in the halved size the
    /// connector kept at that very position (`Shared::read_failed` /
    /// `read_size`, as `read()` calls them), so a poisoning that recurs
    /// there walks down to `MIN_BATCH`; the reads are then capped at
    /// `BATCH` for 10 minutes; a successful read ends the connector's
    /// size, not this stream's memory; a size this stream already holds
    /// is not changed by it.
    #[tokio::test]
    async fn a_poisoned_read_keeps_its_halved_size_into_the_next_stream() {
        use crate::audit::{Cursor, ReadAt, Shared, Source};
        let t = Instant::now();
        let at_s = |s: u64| t + Duration::from_secs(s);
        let e = crate::audit::tests::poisoned_bound().await;
        let cursor = Cursor {
            file: Some("/var/opt/mssql/xe/x_0_1.xel".to_owned()),
            offset: 8192,
            skip: 3,
            pattern: Some("N'/var/opt/mssql/xe/x*.xel'".to_owned()),
            ..Cursor::default()
        };
        let at = ReadAt::of(&cursor);
        let shared = Shared::default();
        // What `read()` does before and after each read.
        let start = |s: &mut ReadSize, now| {
            let kept = shared.read_size("t", Source::Xevents, &at, usize::MAX);
            if kept < usize::MAX {
                s.resume(kept, now);
            }
            s.rows()
        };
        let fail = |s: &mut ReadSize, poisoned, now| {
            let asked = s.rows();
            let _ = shared.read_failed("t", Source::Xevents, at.clone(), &e, poisoned, asked);
            s.failed(&e, poisoned, now)
        };
        // A first stream at the sized bound: the read poisons the session.
        let mut s = ReadSize::default();
        s.received(1_000, Path::Sized, t);
        assert_eq!(start(&mut s, t), XE_MAX_ROWS);
        assert_eq!(fail(&mut s, true, t), None, "the stream ends");
        // Each restart reads less from the same position, down to the floor.
        let mut sizes = Vec::new();
        loop {
            let mut s = ReadSize::default();
            let n = start(&mut s, at_s(1));
            if sizes.last() == Some(&n) {
                break;
            }
            sizes.push(n);
            assert_eq!(fail(&mut s, true, at_s(1)), None);
        }
        assert_eq!(sizes, [500, 250, 125, 62, 31, 16]);
        // The next stream reads 16, then succeeds: the connector's size
        // ends, this stream keeps 16 for 10 minutes and its cap.
        let mut s = ReadSize::default();
        assert_eq!(start(&mut s, at_s(2)), MIN_BATCH);
        shared.read_succeeded("t");
        s.received(1_000, Path::Sized, at_s(3));
        assert_eq!(start(&mut s, at_s(3)), MIN_BATCH);
        s.received(1_000, Path::Sized, at_s(603));
        assert_eq!(s.rows(), 32, "then grows back by doubling");
        let mut fresh = ReadSize::default();
        assert_eq!(start(&mut fresh, at_s(3)), BATCH, "cleared for a restart");
        // A kept size above BATCH (a poisoned read of more than BATCH):
        // the restarted stream is capped at BATCH for 10 minutes.
        let mut s = ReadSize::default();
        s.received(1_000, Path::Sized, t);
        assert_eq!(fail(&mut s, true, t), None);
        let mut s = ReadSize::default();
        assert_eq!(start(&mut s, at_s(1)), BATCH);
        shared.read_succeeded("t");
        s.received(1_000, Path::Sized, at_s(2));
        assert_eq!(s.rows(), BATCH, "capped");
        s.received(1_000, Path::Sized, at_s(602));
        assert_eq!(s.rows(), XE_MAX_ROWS, "after 10 minutes");
        // A cancel in step: the stream halves on its own, and the size the
        // connector also keeps changes nothing in it.
        let mut s = ReadSize::default();
        s.received(1_000, Path::Sized, t);
        assert_eq!(fail(&mut s, false, t), Some(Retry::Bytes));
        assert_eq!(s.rows(), BATCH);
        assert_eq!(fail(&mut s, false, t), Some(Retry::Bytes));
        assert_eq!(start(&mut s, at_s(1)), 250);
        let capped = s.capped;
        assert_eq!(start(&mut s, at_s(2)), 250);
        assert_eq!(s.capped, capped);
    }

    /// The `info` line at most once per 10 minutes per stream, with the
    /// counts since the last one.
    #[test]
    fn the_cancel_line_is_rate_limited() {
        let t = Instant::now();
        let at = |s: u64| t + Duration::from_secs(s);
        let mut s = ReadSize::default();
        let mut infos = 0;
        for i in 0..30u64 {
            s.cancels += 1;
            infos += usize::from(s.log("t", Retry::Bytes, BATCH, at(i * 60)));
        }
        // 0 .. 1 740 s: lines at 0, 600 and 1 200 s.
        assert_eq!(infos, 3);
        assert_eq!(s.cancels, 30);
        assert_eq!(s.logged, (21, 0));
    }
}
