//! One cycle of an Audit stream's reads, shared by SQL Server Audit and
//! the Extended Events source ([`run`]), and the pause before the next one
//! ([`End::pause`]).
//!
//! A cycle reads full pages back to back (each read bounded: at most
//! `BATCH` rows on SQL Server Audit, at most `xe::size::XE_MAX_ROWS` on the
//! Extended Events source after a full read, `POLL_BYTES`, the statement
//! timeout) until a read is not
//! full (or must wait: a deferred statistics build, a position kept before
//! a file), or for [`CATCH_UP`] ([`HISTORY_CATCH_UP`] while the first
//! start's history is walked). Then:
//!
//! - **Caught up**: the poll interval, as always.
//! - **Behind** (the last read was full): a pause such that the reads take
//!   at most 80 % of the time (a quarter of the cycle's reading time), and
//!   that the next cycle starts at least a poll interval after this one
//!   started. So `limits.min_audit_poll_interval_s` (the poll interval's
//!   local floor) still bounds how often a cycle starts, and an operator
//!   who raised it lowers the catch-up load with it.
//! - **History** (the first start's history, records stamped before it):
//!   the same, with the reads at most two thirds of the time (a pause of
//!   half the reading time, at least 1 s).
//!
//! The reading time is the time spent in the poll statements only (review
//! R1 of 527eb08): a read that waits for the core's event queue (the
//! sink's back-pressure) or parses locally does not lengthen the pause.
//! The pause is also capped at the larger of the poll interval and
//! [`CATCH_UP`] / 4 plus the statement timeout (what the last statement of
//! a cycle can add), whatever a source reports.
//!
//! Before load run 39687119269, every cycle waited the poll interval: a
//! stream in its history phase (which only a read that is not full ends)
//! read at most 20 reads of 500 records per poll interval, under 1 000
//! records/s at the 10 s default (about 700 Extended Events events/s
//! measured against 1 500 written, never caught up), and any other stream
//! two thirds of its read rate.

use std::future::Future;
use std::time::{Duration, Instant};

use databastion_core::ConnectorError;

/// Reading time per cycle while behind the source.
pub(crate) const CATCH_UP: Duration = Duration::from_secs(20);
/// Reading time per cycle while the first start's history is walked
/// ([`super::Cursor::walking_history`]).
pub(crate) const HISTORY_CATCH_UP: Duration = Duration::from_secs(10);
/// Shortest pause after a cycle that ended behind.
pub(crate) const BEHIND_PAUSE: Duration = Duration::from_millis(100);
/// Shortest pause after a cycle of the history walk.
pub(crate) const HISTORY_PAUSE: Duration = Duration::from_secs(1);
/// The pause after a cycle behind is at least its reading time divided by
/// this: reads at most 80 % of the time.
const BEHIND_DIVISOR: u32 = 4;
/// The same for the history walk: reads at most two thirds of the time.
const HISTORY_DIVISOR: u32 = 2;
/// The longest pause after a cycle behind or of the history walk, the poll
/// interval aside: what [`CATCH_UP`] plus one statement at its timeout
/// asks.
const PAUSE_CAP: Duration =
    Duration::from_secs(CATCH_UP.as_secs() / BEHIND_DIVISOR as u64 + super::POLL_TIMEOUT.as_secs());
/// The "behind" log line, once per this per target at most.
const LOG_EVERY: Duration = Duration::from_secs(60);

/// Why a cycle ended, with its reading time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// A read reached the end of the source, or must wait.
    CaughtUp,
    /// [`CATCH_UP`] spent, the last read full.
    Behind(Duration),
    /// [`HISTORY_CATCH_UP`] spent walking the history, the last read full.
    History(Duration),
}

impl End {
    /// The wait before the next cycle, `poll` the poll interval: the poll
    /// interval when caught up; else at least the reads' share bound and
    /// the rest of the poll interval since the cycle started, at most
    /// [`PAUSE_CAP`] or the poll interval.
    pub(crate) fn pause(self, poll: Duration) -> Duration {
        let (busy, divisor, least) = match self {
            Self::CaughtUp => return poll,
            Self::Behind(b) => (b, BEHIND_DIVISOR, BEHIND_PAUSE),
            Self::History(b) => (b, HISTORY_DIVISOR, HISTORY_PAUSE),
        };
        (busy / divisor)
            .max(poll.saturating_sub(busy))
            .max(least)
            .min(poll.max(PAUSE_CAP))
    }
}

/// Whether a cycle ends after a read: `full` when the read asks for the
/// next one at once, `history` when it walked the history, `busy` the
/// cycle's reading time so far. `None`: the next read follows at once.
pub(crate) fn end(full: bool, history: bool, busy: Duration) -> Option<End> {
    if !full {
        Some(End::CaughtUp)
    } else if history && busy >= HISTORY_CATCH_UP {
        Some(End::History(busy))
    } else if busy >= CATCH_UP {
        Some(End::Behind(busy))
    } else {
        None
    }
}

/// One read's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Read {
    /// The read was full: the next one should follow at once.
    pub(crate) full: bool,
    /// The time spent in its poll statement (not in the sink's
    /// back-pressure, nor in local parsing).
    pub(crate) statements: Duration,
}

/// What a source gives a cycle.
pub(crate) trait Reads {
    fn target_id(&self) -> &str;
    fn source(&self) -> &'static str;
    /// Whether the next read walks the first start's history.
    fn walking_history(&self) -> bool;
    /// One read from the position (saved after it).
    fn read_once(&mut self) -> impl Future<Output = Result<Read, ConnectorError>> + Send;
    /// Between two reads of a cycle (the proofs, when a read asked).
    fn between(&mut self) -> impl Future<Output = Result<(), ConnectorError>> + Send;
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One cycle: reads until [`end`] says it ends, on the time spent in the
/// poll statements; the stream then waits [`End::pause`].
pub(crate) async fn run<R: Reads + Send>(
    r: &mut R,
    log: &mut BehindLog,
) -> Result<End, ConnectorError> {
    let mut busy = Duration::ZERO;
    let mut reads = 0usize;
    loop {
        let history = r.walking_history();
        let read = r.read_once().await?;
        reads += 1;
        busy = busy.saturating_add(read.statements);
        if let Some(e) = end(read.full, history, busy) {
            log.note(r.target_id(), r.source(), e, reads, r.now());
            return Ok(e);
        }
        r.between().await?;
    }
}

/// The log of a stream behind its source: an `info` line at most once per
/// [`LOG_EVERY`] with the cycles, reads and reading time since the last
/// one (the read rate, for the load runs), and one when it caught up;
/// history cycles at `debug`.
#[derive(Debug, Default)]
pub(crate) struct BehindLog {
    since: Option<Instant>,
    cycles: u32,
    reads: usize,
    busy: Duration,
}

impl BehindLog {
    /// Notes a cycle's end; `true` when a line was logged at `info`.
    pub(crate) fn note(
        &mut self,
        target_id: &str,
        source: &str,
        end: End,
        reads: usize,
        now: Instant,
    ) -> bool {
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        match end {
            End::History(busy) => {
                tracing::debug!(target_id = %target_id, source, reads, busy_ms = ms(busy), "Audit stream walking its first start's history");
                false
            }
            End::Behind(busy) => {
                let since = *self.since.get_or_insert(now);
                self.cycles += 1;
                self.reads += reads;
                self.busy += busy;
                if now.saturating_duration_since(since) < LOG_EVERY {
                    return false;
                }
                tracing::info!(target_id = %target_id, source, cycles = self.cycles, reads = self.reads, busy_ms = ms(self.busy), window_ms = ms(now.saturating_duration_since(since)), "Audit stream behind its source: reading on, the reads paced");
                *self = Self {
                    since: Some(now),
                    ..Self::default()
                };
                true
            }
            End::CaughtUp => {
                let logged = self.since.is_some();
                if logged {
                    tracing::info!(target_id = %target_id, source, cycles = self.cycles, reads = self.reads, busy_ms = ms(self.busy), "Audit stream caught up with its source");
                }
                *self = Self::default();
                logged
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::{BATCH, Cursor};
    use super::*;

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// A scripted source: each read takes `read_ms` on a simulated clock
    /// and returns the next of `fulls` (then `true`); `history` reads walk
    /// the history.
    struct Script {
        t0: Instant,
        t_ms: u64,
        read_ms: u64,
        /// Wall time a read waits beyond its statement (back-pressure).
        wait_ms: u64,
        fulls: Vec<bool>,
        history: usize,
        reads: usize,
        betweens: usize,
    }

    impl Script {
        fn new(read_ms: u64, fulls: &[bool], history: usize) -> Self {
            Self {
                t0: Instant::now(),
                t_ms: 0,
                read_ms,
                wait_ms: 0,
                fulls: fulls.to_vec(),
                history,
                reads: 0,
                betweens: 0,
            }
        }
    }

    impl Reads for Script {
        fn target_id(&self) -> &str {
            "t"
        }
        fn source(&self) -> &'static str {
            "test"
        }
        fn walking_history(&self) -> bool {
            self.reads < self.history
        }
        async fn read_once(&mut self) -> Result<Read, ConnectorError> {
            self.t_ms += self.read_ms + self.wait_ms;
            let full = self.fulls.get(self.reads).copied().unwrap_or(true);
            self.reads += 1;
            Ok(Read {
                full,
                statements: Duration::from_millis(self.read_ms),
            })
        }
        async fn between(&mut self) -> Result<(), ConnectorError> {
            self.betweens += 1;
            Ok(())
        }
        fn now(&self) -> Instant {
            self.t0 + Duration::from_millis(self.t_ms)
        }
    }

    /// Review M2: a read that is not full (a deferral or a clamped read
    /// returns `false` too) ends the cycle as caught up; full reads go on
    /// for the cycle's reading time, the history's while it is walked.
    #[test]
    fn the_cycle_ends_by_its_reads() {
        let mut log = BehindLog::default();
        // Caught up at the third read (or a deferral, a clamped read).
        let mut s = Script::new(100, &[true, true, false], 0);
        assert_eq!(block_on(run(&mut s, &mut log)).unwrap(), End::CaughtUp);
        assert_eq!((s.reads, s.betweens), (3, 2));
        // Behind: 20 s of 500 ms reads.
        let mut s = Script::new(500, &[], 0);
        let e = block_on(run(&mut s, &mut log)).unwrap();
        assert_eq!(e, End::Behind(Duration::from_secs(20)));
        assert_eq!(s.reads, 40);
        // History: 10 s while every read walks it.
        let mut s = Script::new(500, &[], usize::MAX);
        let e = block_on(run(&mut s, &mut log)).unwrap();
        assert_eq!(e, End::History(Duration::from_secs(10)));
        assert_eq!(s.reads, 20);
        // A cycle that leaves the history: behind, on the cycle's 20 s.
        let mut s = Script::new(500, &[], 5);
        let e = block_on(run(&mut s, &mut log)).unwrap();
        assert_eq!(e, End::Behind(Duration::from_secs(20)));
    }

    /// Review R1 of 527eb08: the sink's back-pressure (a read that waits
    /// a minute for the core's queue after a 500 ms statement) counts
    /// neither towards the cycle's reading time nor towards the pause.
    #[test]
    fn back_pressure_is_not_reading_time() {
        let mut log = BehindLog::default();
        let mut s = Script::new(500, &[], 0);
        s.wait_ms = 60_000;
        let e = block_on(run(&mut s, &mut log)).unwrap();
        assert_eq!(e, End::Behind(Duration::from_secs(20)));
        assert_eq!(s.reads, 40);
        assert_eq!(e.pause(Duration::from_secs(10)), Duration::from_secs(5));
        // Caught up after a wait: the poll interval, as always.
        let mut s = Script::new(100, &[false], 0);
        s.wait_ms = 3_600_000;
        let e = block_on(run(&mut s, &mut log)).unwrap();
        assert_eq!(e, End::CaughtUp);
        // Whatever a source reports, the pause is capped.
        let poll = Duration::from_secs(10);
        for e in [
            End::Behind(Duration::from_secs(3600)),
            End::History(Duration::from_secs(3600)),
        ] {
            assert_eq!(e.pause(poll), PAUSE_CAP);
            assert_eq!(e.pause(Duration::from_secs(600)), Duration::from_secs(600));
        }
        assert_eq!(PAUSE_CAP, CATCH_UP / 4 + super::super::POLL_TIMEOUT);
    }

    /// Review M1: the reads take at most 80 % of the time behind and two
    /// thirds in the history, and a cycle starts at most once per poll
    /// interval (its local floor included).
    #[test]
    fn pauses_bound_the_reads_share_and_keep_the_poll_floor() {
        let s = Duration::from_secs;
        let poll = s(10);
        assert_eq!(End::CaughtUp.pause(poll), poll);
        assert_eq!(End::Behind(s(20)).pause(poll), s(5));
        assert_eq!(End::History(s(10)).pause(poll), s(5));
        // A raised floor: the next cycle starts a poll interval after.
        assert_eq!(End::Behind(s(20)).pause(s(60)), s(40));
        assert_eq!(End::History(s(10)).pause(s(60)), s(50));
        // A short poll interval does not lift the share bound.
        assert_eq!(End::Behind(s(20)).pause(s(1)), s(5));
        assert_eq!(End::History(s(1)).pause(s(1)), HISTORY_PAUSE);
        assert_eq!(End::Behind(Duration::ZERO).pause(s(0)), BEHIND_PAUSE);
        for busy in [0, 1, 7, 20, 25] {
            for p in [1, 10, 60, 3600] {
                for e in [End::Behind(s(busy)), End::History(s(busy))] {
                    let pause = e.pause(s(p));
                    let share = busy as f64 / (busy as f64 + pause.as_secs_f64());
                    assert!(share <= 0.8 + 1e-9, "{e:?} {p}");
                    assert!(s(busy) + pause >= s(p), "a cycle per poll interval");
                    assert!(pause <= s(p).max(s(busy) / 2).max(HISTORY_PAUSE));
                }
            }
        }
    }

    /// Review L3: one `info` line per minute while behind, with the sums,
    /// and one when caught up; history cycles never at `info`.
    #[test]
    fn the_behind_line_is_rate_limited() {
        let mut log = BehindLog::default();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let b = End::Behind(CATCH_UP);
        let infos: usize = (0..10u64)
            .map(|i| usize::from(log.note("t", "x", b, 40, at(i * 25))))
            .sum();
        // 0..225 s: lines at 75, 150 and 225 s.
        assert_eq!(infos, 3);
        assert!(!log.note("t", "x", End::History(HISTORY_CATCH_UP), 20, at(300)));
        assert!(log.note("t", "x", End::CaughtUp, 1, at(301)));
        assert!(!log.note("t", "x", End::CaughtUp, 1, at(311)));
    }

    /// What [`model`] measured.
    #[derive(Debug)]
    struct Modelled {
        caught_up_ms: Option<u64>,
        /// Events written and not read yet at the end.
        behind: u64,
        /// The longest an event written after the catch-up waited (ms).
        max_lag_after_ms: u64,
        /// The reads' share of the time until the catch-up.
        busy_share: f64,
        /// The first read that was not full after the writes stopped.
        drained_ms: Option<u64>,
        /// The longest read (ms).
        longest_read_ms: u64,
        /// The longest pause between two cycles (ms).
        longest_pause_ms: u64,
    }

    /// A source writing `rate` events/s after a first start with `backlog`
    /// events of history, read by [`run`] in reads of at most [`BATCH`]
    /// taking `read_ms` each, with the session's counters `probe_ms` per
    /// cycle and [`End::pause`] between cycles, for `end_ms`.
    struct Model {
        rate: u64,
        backlog: u64,
        read_ms: u64,
        /// The cost model measured on 2026-10-22 instead of `read_ms`, in
        /// buffers of this many events (ADR-0051 refinement of 2026-10-22).
        buffer: Option<u64>,
        /// Reads sized by the Extended Events read size (else `BATCH`).
        size: Option<super::super::xe::size::ReadSize>,
        /// Nothing is written after this time.
        write_until_ms: u64,
        t0: Instant,
        t_ms: u64,
        pos: u64,
        cursor: Cursor,
        out: Modelled,
        busy_ms: u64,
    }

    impl Model {
        fn written_at(&self, i: u64) -> Option<u64> {
            i.checked_sub(self.backlog).map(|n| n * 1000 / self.rate)
        }
        fn stamp(&self, i: u64) -> i64 {
            self.written_at(i).map_or_else(
                || -1_000_000 - i64::try_from(self.backlog - i).unwrap(),
                |ms| i64::try_from(ms).unwrap() * 1000,
            )
        }
        fn available(&self, t: u64) -> u64 {
            self.backlog + t.min(self.write_until_ms) * self.rate / 1000
        }
    }

    impl Reads for Model {
        fn target_id(&self) -> &str {
            "model"
        }
        fn source(&self) -> &'static str {
            "model"
        }
        fn walking_history(&self) -> bool {
            self.cursor.walking_history()
        }
        async fn read_once(&mut self) -> Result<Read, ConnectorError> {
            let batch = self.size.as_ref().map_or(BATCH, |s| s.rows()) as u64;
            let n = self
                .available(self.t_ms)
                .saturating_sub(self.pos)
                .min(batch);
            let read_ms = match self.buffer {
                // Measured on 2022: about 37 ms, 0.43 ms per event read and
                // 0.06 ms per event of the buffer skipped.
                Some(buffer) => 37 + n * 43 / 100 + (self.pos % buffer) * 6 / 100,
                None => self.read_ms,
            };
            self.out.longest_read_ms = self.out.longest_read_ms.max(read_ms);
            self.t_ms += read_ms;
            if self.out.caught_up_ms.is_none() {
                self.busy_ms += read_ms;
            }
            for i in self.pos..self.pos + n {
                self.cursor.max_seen_us = Cursor::seen(self.cursor.max_seen_us, self.stamp(i));
                if let (Some(_), Some(w)) = (self.out.caught_up_ms, self.written_at(i)) {
                    self.out.max_lag_after_ms = self.out.max_lag_after_ms.max(self.t_ms - w);
                }
            }
            self.pos += n;
            let full = n == batch;
            let now = self.now();
            if let Some(size) = self.size.as_mut() {
                let path = if full {
                    super::super::xe::size::Path::Sized
                } else {
                    super::super::xe::size::Path::Base
                };
                // The load workload's events: 3.6 KB on the wire at most.
                size.received(3_603, path, now);
            }
            if !full && self.t_ms >= self.write_until_ms {
                self.out.drained_ms.get_or_insert(self.t_ms);
            }
            if !full {
                self.cursor.history_us = None;
                self.out.caught_up_ms.get_or_insert(self.t_ms);
            }
            Ok(Read {
                full,
                statements: Duration::from_millis(read_ms),
            })
        }
        async fn between(&mut self) -> Result<(), ConnectorError> {
            Ok(())
        }
        fn now(&self) -> Instant {
            self.t0 + Duration::from_millis(self.t_ms)
        }
    }

    fn model(rate: u64, backlog: u64, read_ms: u64, poll_ms: u64, end_ms: u64) -> Modelled {
        model_with(
            rate,
            backlog,
            read_ms,
            (None, false),
            u64::MAX,
            poll_ms,
            end_ms,
        )
    }

    fn model_with(
        rate: u64,
        backlog: u64,
        read_ms: u64,
        (buffer, sized): (Option<u64>, bool),
        write_until_ms: u64,
        poll_ms: u64,
        end_ms: u64,
    ) -> Modelled {
        let mut cursor = Cursor::default();
        cursor.first_start(Some(0), 0);
        let mut m = Model {
            rate,
            backlog,
            read_ms,
            buffer,
            size: sized.then(super::super::xe::size::ReadSize::default),
            write_until_ms,
            t0: Instant::now(),
            t_ms: 0,
            pos: 0,
            cursor,
            out: Modelled {
                caught_up_ms: None,
                behind: 0,
                max_lag_after_ms: 0,
                busy_share: 0.0,
                drained_ms: None,
                longest_read_ms: 0,
                longest_pause_ms: 0,
            },
            busy_ms: 0,
        };
        let mut log = BehindLog::default();
        while m.t_ms < end_ms {
            m.t_ms += 30; // the session's counters
            let e = block_on(run(&mut m, &mut log)).unwrap();
            let pause = u64::try_from(e.pause(Duration::from_millis(poll_ms)).as_millis()).unwrap();
            m.out.longest_pause_ms = m.out.longest_pause_ms.max(pause);
            m.t_ms += pause;
        }
        let until = m.out.caught_up_ms.unwrap_or(end_ms);
        m.out.busy_share = m.busy_ms as f64 / until as f64;
        m.out.behind = m.available(end_ms).saturating_sub(m.pos);
        m.out
    }

    /// Load run 39687119269 (Extended Events, 50 SELECTs/s of about 30
    /// events each, 10 s poll interval, a first start behind about 150 s
    /// of earlier workload): the stream stored about 700 events/s and
    /// never caught up. With [`run`] and [`End::pause`], at 190 ms a read
    /// of 500 events (the value that fits the measured rate under the old
    /// rule), it catches up within 8 minutes (434 s: the history at about
    /// 1 750 events/s, then the live backlog at about 2 100/s) with the
    /// reads at most 80 % of the time, then keeps up.
    #[test]
    fn a_stream_behind_its_source_catches_up() {
        let (rate, backlog, poll_ms) = (1_500, 225_000, 10_000);
        let m = model(rate, backlog, 190, poll_ms, 1_200_000);
        let caught = m.caught_up_ms.expect("caught up");
        assert!(caught <= 480_000, "{m:?}");
        assert!(m.busy_share <= 0.8, "{m:?}");
        assert!(m.max_lag_after_ms <= poll_ms + 2_000, "{m:?}");
        assert!(m.behind <= rate * (poll_ms + 2_000) / 1000, "{m:?}");
        // No history, 250 ms a read (2 000 events/s at most, 1 600 at
        // 80 %): still caught up.
        let m = model(rate, 0, 250, poll_ms, 1_200_000);
        assert!(m.behind <= rate * 12, "{m:?}");
    }

    /// ADR-0051 refinement of 2026-10-22, test plan item 2 (`cycle.rs`
    /// with mixed read sizes), on the cost model measured on 2022 (37 ms,
    /// plus 0.43 ms per event read and 0.06 ms per event skipped, in
    /// buffers of 4 593 events): a stream reading 1 500 events/s written
    /// for 600 s (the 50 SELECTs/s load run) falls behind with reads of
    /// 500 (it drains minutes after the writes stop) and keeps up with
    /// sized reads (`BATCH` after a read that is not full, the sized bound
    /// after a full one); either way the reads take at most 80 % of the
    /// time, each read at most a sixth of the statement timeout, and the
    /// pauses stay under their cap.
    #[test]
    fn sized_reads_drain_sooner_within_the_same_bounds() {
        let (rate, poll_ms, until) = (1_500, 10_000, 600_000);
        let run =
            |sized: bool| model_with(rate, 0, 0, (Some(4_593), sized), until, poll_ms, 1_800_000);
        let fixed = run(false);
        let sized = run(true);
        let (f, d) = (
            fixed.drained_ms.expect("drained with reads of 500"),
            sized.drained_ms.expect("drained with sized reads"),
        );
        assert!(f > until + 60_000, "reads of 500 fall behind: {fixed:?}");
        assert!(
            d < f,
            "sized reads drain sooner: {sized:?} against {fixed:?}"
        );
        for m in [&fixed, &sized] {
            assert!(m.busy_share <= 0.8 + 1e-9, "{m:?}");
            let timeout = u64::try_from(super::super::POLL_TIMEOUT.as_millis()).unwrap();
            assert!(m.longest_read_ms * 6 <= timeout, "{m:?}");
            assert!(
                m.longest_pause_ms <= u64::try_from(PAUSE_CAP.as_millis()).unwrap(),
                "{m:?}"
            );
        }
        assert!(d < until + 30_000, "sized reads keep up: {sized:?}");
    }
}
