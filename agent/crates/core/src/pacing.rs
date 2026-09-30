//! Discovery pacing (ADR-0035, proposed): a bounded duty cycle of the
//! agent's work against a target during a scan, shared by every connector.
//!
//! MVP criterion (docs/04): the monitored database spends less than 2 % of
//! its CPU on Discovery. Sampling is bounded per object, but objects sampled
//! back to back keep one server core busy for the whole scan (load harness,
//! PR #92: 20 to 25 % of one core). So after each unit of work (an object's
//! sampling, a catalog read), [`Pacer::pause`] waits
//! `busy × (100 − d) / d`, `d` being `limits.discovery_duty_cycle_percent`:
//! the agent's wall-clock time in queries is then at most `d` % of the
//! scan's time. That wall-clock time bounds the server CPU the queries
//! used on the scan's one connection (a statement runs on one core; waits
//! for I/O, locks and the network only make the bound looser).
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Time the paced work took and the pauses, for the scan's end log.
#[derive(Debug, Default)]
struct Totals {
    busy_ns: AtomicU64,
    paused_ns: AtomicU64,
}

/// Paces one scan (see the module documentation). Cheap to clone: clones
/// share the totals and the cancellation.
#[derive(Debug, Clone)]
pub struct Pacer {
    duty_percent: u8,
    cancel: Option<ScanCancel>,
    totals: Arc<Totals>,
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new(DEFAULT_DUTY_CYCLE_PERCENT)
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Pacer {
    /// A pacer at `duty_percent` % (clamped to
    /// [`DUTY_CYCLE_PERCENT_RANGE`]), without cancellation.
    #[must_use]
    pub fn new(duty_percent: u8) -> Self {
        Self {
            duty_percent: duty_percent
                .max(DUTY_CYCLE_PERCENT_RANGE.0)
                .min(DUTY_CYCLE_PERCENT_RANGE.1),
            cancel: None,
            totals: Arc::default(),
        }
    }

    /// The same pacer, ended early by `cancel`.
    #[must_use]
    pub fn with_cancel(mut self, cancel: ScanCancel) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// The duty cycle, in percent.
    #[must_use]
    pub const fn duty_percent(&self) -> u8 {
        self.duty_percent
    }

    /// Waits after `busy` of work (see [`pause_after`]).
    ///
    /// # Errors
    /// [`Cancelled`] when the scan is (or gets) cancelled: the pause ends
    /// at once and the connector must stop.
    pub async fn pause(&self, busy: Duration) -> Result<(), Cancelled> {
        self.totals
            .busy_ns
            .fetch_add(nanos(busy), Ordering::Relaxed);
        if self.cancel.as_ref().is_some_and(ScanCancel::is_cancelled) {
            return Err(Cancelled);
        }
        let pause = pause_after(busy, self.duty_percent);
        if pause.is_zero() {
            return Ok(());
        }
        let started = Instant::now();
        let r = match &self.cancel {
            Some(cancel) => tokio::select! {
                () = tokio::time::sleep(pause) => Ok(()),
                () = cancel.cancelled() => Err(Cancelled),
            },
            None => {
                tokio::time::sleep(pause).await;
                Ok(())
            }
        };
        self.totals
            .paused_ns
            .fetch_add(nanos(started.elapsed()), Ordering::Relaxed);
        r
    }

    /// Runs `work`, then pauses after the time it took.
    ///
    /// # Errors
    /// [`Cancelled`] (see [`Self::pause`]); `work`'s own result is inside.
    pub async fn paced<F: Future>(&self, work: F) -> Result<F::Output, Cancelled> {
        if self.cancel.as_ref().is_some_and(ScanCancel::is_cancelled) {
            return Err(Cancelled);
        }
        let started = Instant::now();
        let out = work.await;
        self.pause(started.elapsed()).await?;
        Ok(out)
    }

    /// Time spent in paced work and in pauses so far.
    #[must_use]
    pub fn totals(&self) -> (Duration, Duration) {
        (
            Duration::from_nanos(self.totals.busy_ns.load(Ordering::Relaxed)),
            Duration::from_nanos(self.totals.paused_ns.load(Ordering::Relaxed)),
        )
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn paced_work_waits_its_share() {
        let pacer = Pacer::new(50);
        let started = Instant::now();
        let out = pacer
            .paced(async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                7
            })
            .await;
        assert_eq!(out, Ok(7));
        assert!(started.elapsed() >= Duration::from_millis(60));
        let (busy, paused) = pacer.totals();
        assert!(busy >= Duration::from_millis(30), "{busy:?}");
        assert!(paused >= Duration::from_millis(30), "{paused:?}");
        // 100 %: no pause at all.
        let unpaced = Pacer::new(100);
        let started = Instant::now();
        unpaced.pause(Duration::from_secs(3600)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_long_pause_ends_at_cancellation() {
        let (handle, cancel) = ScanCancel::channel();
        let pacer = Pacer::new(1).with_cancel(cancel);
        let task = {
            let pacer = pacer.clone();
            // 10 s of work: a pause of 990 s.
            tokio::spawn(async move { pacer.pause(Duration::from_secs(10)).await })
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
        let task = tokio::spawn(async move { pacer.pause(Duration::from_secs(10)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(handle);
        let r = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r, Err(Cancelled));
    }
}
