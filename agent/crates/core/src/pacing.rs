//! Discovery pacing (ADR-0035, proposed): a bounded duty cycle of the
//! agent's work against a target during a scan, shared by every connector.
//!
//! MVP criterion (docs/04): the monitored database spends less than 2 % of
//! its CPU on Discovery. Sampling is bounded per object, but objects sampled
//! back to back keep one server core busy for the whole scan (load harness,
//! PR #92: 20 to 25 % of one core). So each unit of work (an object's
//! sampling, a catalog read) run through [`Pacer::paced`] leaves a **debt**
//! of `busy × (100 − d) / d`, `d` being `limits.discovery_duty_cycle_percent`,
//! paid (slept) **before the next unit**: the agent's wall-clock time in
//! queries is then at most `d` % of the scan's time, and there is no pause
//! after the last unit (a complete scan ends at once). That wall-clock time
//! bounds the server CPU the queries used on the scan's one connection (a
//! statement runs on one core; waits for I/O, locks and the network only
//! make the bound looser). A unit that failed or timed out is charged too.
//! Connectors release what a unit held (a poisoned session, the samples)
//! before the next paced call, so nothing is held during a pause.
//!
//! The bound is never relaxed. When the debt, plus the last unit's time and
//! a margin, would reach the scan's deadline, the next unit does not run:
//! [`Paced::OutOfTime`], and the connector reports the objects it did not
//! sample as skipped for a limit (`skipped_limit`), ending the scan without
//! a timeout (security review of #93, M3). So that a slow or hostile object
//! cannot hide the same tail at every scan, connectors rotate their object
//! order per scan ([`crate::ScanJob::rotate`]).
//!
//! Scans run one at a time per agent (the runtime's scan worker), so the
//! bound holds per agent and server, whatever the number of targets.
//!
//! A pause ends early when the scan is cancelled ([`ScanCancel`]: the
//! console cancels the job, the agent stops or is revoked, the scan's
//! window ends), and the paced call then reports
//! [`ConnectorError::Cancelled`] so the connector stops at once. The core
//! also drops the connector future in these cases; the token makes the
//! pause itself cancellable.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::connector::ConnectorError;

/// Default duty cycle, in percent of the scan's time.
pub const DEFAULT_DUTY_CYCLE_PERCENT: u8 = 1;
/// Accepted duty cycles, in percent (`100`: no pacing).
pub const DUTY_CYCLE_PERCENT_RANGE: (u8, u8) = (1, 100);

/// The pause after `busy` of work so that `busy / (busy + pause)` stays at
/// most `duty_percent` %. `100` (or more): no pause; `0` is read as `1`.
#[must_use]
pub fn pause_after(busy: Duration, duty_percent: u8) -> Duration {
    let d = u128::from(duty_percent.max(1));
    if d >= 100 {
        return Duration::ZERO;
    }
    // Rounded up, so the duty cycle is never exceeded by a rounding.
    let nanos = (busy.as_nanos() * (100 - d)).div_ceil(d);
    u64::try_from(nanos).map_or(Duration::MAX, Duration::from_nanos)
}

/// The scan was cancelled (the paced connector returns this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl From<Cancelled> for ConnectorError {
    fn from(_: Cancelled) -> Self {
        Self::Cancelled
    }
}

/// Cancellation of one scan, fired by the core ([`ScanCancel::channel`]).
/// Cancelled once `cancel` is called or its sender is dropped.
#[derive(Debug, Clone)]
pub struct ScanCancel(watch::Receiver<bool>);

/// The sending side of a [`ScanCancel`]: dropping it cancels too.
#[derive(Debug)]
pub struct ScanCancelHandle(watch::Sender<bool>);

impl ScanCancelHandle {
    /// Cancels the scan.
    pub fn cancel(&self) {
        let _ = self.0.send(true);
    }
}

impl ScanCancel {
    /// A new token and its handle.
    #[must_use]
    pub fn channel() -> (ScanCancelHandle, Self) {
        let (tx, rx) = watch::channel(false);
        (ScanCancelHandle(tx), Self(rx))
    }

    /// Whether the scan was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow() || self.0.has_changed().is_err()
    }

    /// Resolves once the scan is cancelled.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        // An error: the handle was dropped, which cancels too.
        let _ = rx.wait_for(|c| *c).await;
    }
}

/// Kept free before the scan's deadline when deciding whether the next
/// unit can run: the last unit's time plus this.
pub const DEADLINE_MARGIN: Duration = Duration::from_secs(2);

/// Outcome of a paced unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paced<T> {
    /// The unit ran.
    Done(T),
    /// Not run: paying the debt would reach the scan's deadline. Every later
    /// unit is refused too; the connector reports what it did not sample as
    /// skipped for a limit.
    OutOfTime,
}

#[derive(Debug, Default)]
struct State {
    /// Pause owed before the next unit.
    debt: Duration,
    /// Time of the last unit (the estimate of the next one).
    last: Duration,
    /// Out of time (sticky).
    out_of_time: bool,
    busy: Duration,
    paused: Duration,
}

/// Paces one scan (see the module documentation). Cheap to clone: clones
/// share the debt, the totals and the cancellation.
#[derive(Debug, Clone)]
pub struct Pacer {
    duty_percent: u8,
    cancel: Option<ScanCancel>,
    deadline: Option<Instant>,
    state: Arc<Mutex<State>>,
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new(DEFAULT_DUTY_CYCLE_PERCENT)
    }
}

impl Pacer {
    /// A pacer at `duty_percent` % (clamped to
    /// [`DUTY_CYCLE_PERCENT_RANGE`]), without cancellation or deadline.
    #[must_use]
    pub fn new(duty_percent: u8) -> Self {
        Self {
            duty_percent: duty_percent
                .max(DUTY_CYCLE_PERCENT_RANGE.0)
                .min(DUTY_CYCLE_PERCENT_RANGE.1),
            cancel: None,
            deadline: None,
            state: Arc::default(),
        }
    }

    /// The same pacer, ended early by `cancel`.
    #[must_use]
    pub fn with_cancel(mut self, cancel: ScanCancel) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// The same pacer, with the scan's deadline.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// The duty cycle, in percent.
    #[must_use]
    pub const fn duty_percent(&self) -> u8 {
        self.duty_percent
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(ScanCancel::is_cancelled)
    }

    /// Pays the debt before a unit, unless that would reach the deadline.
    async fn before_unit(&self) -> Result<bool, Cancelled> {
        if self.cancelled() {
            return Err(Cancelled);
        }
        let (debt, last) = {
            let st = self.lock();
            if st.out_of_time {
                return Ok(false);
            }
            (st.debt, st.last)
        };
        if let Some(deadline) = self.deadline {
            let needed = debt.saturating_add(last).saturating_add(DEADLINE_MARGIN);
            if Instant::now()
                .checked_add(needed)
                .is_none_or(|t| t >= deadline)
            {
                self.lock().out_of_time = true;
                return Ok(false);
            }
        }
        if !debt.is_zero() {
            let started = Instant::now();
            let r = match &self.cancel {
                Some(cancel) => tokio::select! {
                    () = tokio::time::sleep(debt) => Ok(()),
                    () = cancel.cancelled() => Err(Cancelled),
                },
                None => {
                    tokio::time::sleep(debt).await;
                    Ok(())
                }
            };
            let mut st = self.lock();
            st.paused = st.paused.saturating_add(started.elapsed());
            r?;
            st.debt = Duration::ZERO;
        }
        Ok(true)
    }

    /// Charges `busy` of work: the debt paid before the next unit.
    fn charge(&self, busy: Duration) {
        let mut st = self.lock();
        st.busy = st.busy.saturating_add(busy);
        st.last = busy;
        st.debt = st.debt.saturating_add(pause_after(busy, self.duty_percent));
    }

    /// Pays the debt of the previous units, runs `work` and charges the
    /// time it took (failed or not). No pause follows: the next paced call
    /// pays it, so the last unit of a scan is not followed by one.
    ///
    /// # Errors
    /// [`Cancelled`] when the scan is (or gets) cancelled: the pause ends
    /// at once and the connector must stop.
    pub async fn paced<F: Future>(&self, work: F) -> Result<Paced<F::Output>, Cancelled> {
        if !self.before_unit().await? {
            return Ok(Paced::OutOfTime);
        }
        let started = Instant::now();
        let out = work.await;
        self.charge(started.elapsed());
        Ok(Paced::Done(out))
    }

    /// Pays the debt now, before a unit whose setup must follow the pause
    /// (a session that may have gone stale meanwhile is checked or opened
    /// after it). The unit itself then goes through [`Self::paced`], which
    /// owes nothing more.
    ///
    /// # Errors
    /// [`Cancelled`], as [`Self::paced`].
    pub async fn turn(&self) -> Result<Paced<()>, Cancelled> {
        Ok(if self.before_unit().await? {
            Paced::Done(())
        } else {
            Paced::OutOfTime
        })
    }

    /// Pause owed before the next unit.
    #[must_use]
    pub fn debt(&self) -> Duration {
        self.lock().debt
    }

    /// Whether a unit was refused for the deadline.
    #[must_use]
    pub fn out_of_time(&self) -> bool {
        self.lock().out_of_time
    }

    /// Time spent in paced work and in pauses so far.
    #[must_use]
    pub fn totals(&self) -> (Duration, Duration) {
        let st = self.lock();
        (st.busy, st.paused)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn pause_arithmetic() {
        let ms = Duration::from_millis;
        // 1 %: 99 times the work.
        assert_eq!(pause_after(ms(10), 1), ms(990));
        assert_eq!(pause_after(ms(7), 1), ms(693));
        // 2 %: 49 times; 50 %: as long; 100 %: none.
        assert_eq!(pause_after(ms(10), 2), ms(490));
        assert_eq!(pause_after(ms(10), 50), ms(10));
        assert_eq!(pause_after(ms(10), 100), Duration::ZERO);
        assert_eq!(pause_after(ms(10), 200), Duration::ZERO);
        // 0 is read as 1 (never a division by zero).
        assert_eq!(pause_after(ms(10), 0), ms(990));
        // Rounded up: the duty cycle is never exceeded.
        assert_eq!(
            pause_after(Duration::from_nanos(1), 3),
            Duration::from_nanos(33)
        );
        for d in 1..=100u8 {
            for busy in [1u64, 7, 999, 1_500_000, 30_000_000_000] {
                let busy = Duration::from_nanos(busy);
                let pause = pause_after(busy, d);
                let total = (busy + pause).as_nanos();
                assert!(
                    busy.as_nanos() * 100 <= total * u128::from(d),
                    "{d} {busy:?} {pause:?}"
                );
            }
        }
        // No work: no pause; huge work: saturated, no panic.
        assert_eq!(pause_after(Duration::ZERO, 1), Duration::ZERO);
        assert_eq!(pause_after(Duration::MAX, 1), Duration::MAX);
    }

    #[test]
    fn duty_cycle_is_clamped() {
        assert_eq!(Pacer::new(0).duty_percent(), 1);
        assert_eq!(Pacer::new(250).duty_percent(), 100);
        assert_eq!(Pacer::default().duty_percent(), DEFAULT_DUTY_CYCLE_PERCENT);
    }

    async fn unit(pacer: &Pacer, ms: u64) -> Paced<()> {
        // Lazy: a `sleep` future's deadline is set when it is created.
        pacer
            .paced(async move { tokio::time::sleep(Duration::from_millis(ms)).await })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_debt_is_paid_before_the_next_unit_never_after_the_last() {
        let pacer = Pacer::new(50);
        // The first unit returns right after its work: no pause after it.
        let started = Instant::now();
        assert_eq!(unit(&pacer, 40).await, Paced::Done(()));
        assert!(
            started.elapsed() < Duration::from_millis(75),
            "{:?}",
            started.elapsed()
        );
        assert!(pacer.debt() >= Duration::from_millis(40));
        // The next one pays it first.
        let started = Instant::now();
        assert_eq!(unit(&pacer, 1).await, Paced::Done(()));
        assert!(started.elapsed() >= Duration::from_millis(38));
        let (busy, paused) = pacer.totals();
        assert!(busy >= Duration::from_millis(41), "{busy:?}");
        assert!(paused >= Duration::from_millis(38), "{paused:?}");
        // A unit that failed is charged too.
        let failed = pacer
            .paced(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Err::<(), ()>(())
            })
            .await
            .unwrap();
        assert_eq!(failed, Paced::Done(Err(())));
        assert!(pacer.debt() >= Duration::from_millis(20));
        // `turn` pays the debt ahead of a unit's setup.
        assert_eq!(unit(&pacer, 30).await, Paced::Done(()));
        let started = Instant::now();
        assert_eq!(pacer.turn().await, Ok(Paced::Done(())));
        // (Tokio timers have a millisecond granularity.)
        assert!(started.elapsed() >= Duration::from_millis(28));
        assert_eq!(pacer.debt(), Duration::ZERO);
        // 100 %: never any debt.
        let unpaced = Pacer::new(100);
        assert_eq!(unit(&unpaced, 5).await, Paced::Done(()));
        assert_eq!(unpaced.debt(), Duration::ZERO);
    }

    #[tokio::test]
    async fn units_stop_before_the_deadline_instead_of_passing_it() {
        // 1 %: 50 ms of work owe about 5 s; the deadline is 3 s away.
        let pacer = Pacer::new(1).with_deadline(Instant::now() + Duration::from_secs(3));
        assert_eq!(unit(&pacer, 50).await, Paced::Done(()));
        let started = Instant::now();
        let ran = std::sync::atomic::AtomicBool::new(false);
        let r = pacer
            .paced(async { ran.store(true, Ordering::Relaxed) })
            .await
            .unwrap();
        assert_eq!(r, Paced::OutOfTime);
        assert!(!ran.load(Ordering::Relaxed));
        // Refused at once, without sleeping; and for good.
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(pacer.out_of_time());
        assert_eq!(unit(&pacer, 0).await, Paced::OutOfTime);
        // Far enough from the deadline: the unit runs.
        let pacer = Pacer::new(1).with_deadline(Instant::now() + Duration::from_secs(60));
        assert_eq!(unit(&pacer, 5).await, Paced::Done(()));
        assert_eq!(unit(&pacer, 0).await, Paced::Done(()));
    }

    #[tokio::test]
    async fn a_long_debt_ends_at_cancellation() {
        let (handle, cancel) = ScanCancel::channel();
        let pacer = Pacer::new(1).with_cancel(cancel);
        // 100 ms of work: a debt of 9.9 s.
        assert_eq!(unit(&pacer, 100).await, Paced::Done(()));
        let task = {
            let pacer = pacer.clone();
            tokio::spawn(async move { pacer.paced(async {}).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        let started = Instant::now();
        handle.cancel();
        let r = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r, Err(Cancelled));
        assert!(started.elapsed() < Duration::from_secs(5));
        // Once cancelled, no more work runs.
        let ran = std::sync::atomic::AtomicBool::new(false);
        let r = pacer
            .paced(async { ran.store(true, Ordering::Relaxed) })
            .await;
        assert_eq!(r, Err(Cancelled));
        assert!(!ran.load(Ordering::Relaxed));
        assert!(matches!(
            ConnectorError::from(Cancelled),
            ConnectorError::Cancelled
        ));
    }

    #[tokio::test]
    async fn a_dropped_handle_cancels() {
        let (handle, cancel) = ScanCancel::channel();
        let pacer = Pacer::new(1).with_cancel(cancel);
        assert_eq!(unit(&pacer, 100).await, Paced::Done(()));
        let task = tokio::spawn(async move { pacer.paced(async {}).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(handle);
        let r = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r, Err(Cancelled));
    }
}
