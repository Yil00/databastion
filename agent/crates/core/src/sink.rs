//! Channels from connectors to the core.
//!
//! Sinks only accept types from `databastion_classifiers::masking`, whose
//! constructors guarantee the data has been masked. A connector therefore
//! cannot push an unmasked value towards the uplink (I2).

use std::sync::{Arc, Mutex};

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};
use tokio::sync::mpsc;

/// The receiving side of a sink was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("result sink closed")]
pub struct SinkClosed;

/// Discovery coverage of a scan: how many objects of the job's scope were
/// sampled, and how many were not, by reason (contract `JobProgress`
/// `objects_sampled` and `skipped_*`). Counts only, never a name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCoverage {
    /// Objects actually sampled.
    pub sampled: u64,
    /// Not sampled: the agent's account cannot read them.
    pub not_readable: u64,
    /// Not sampled because of row-level security.
    pub row_level_security: u64,
    /// Data held outside the target (foreign tables, remote engines).
    pub remote: u64,
    /// A kind of object the connector does not sample (views, sequences,
    /// engines outside its allow-list).
    pub unsupported: u64,
    /// Beyond a structural bound of the connector.
    pub limit: u64,
    /// Sampling failed, and the scan went on.
    pub error: u64,
}

impl ScanCoverage {
    /// Adds `other` to these counters (saturating).
    pub fn add(&mut self, other: Self) {
        self.sampled = self.sampled.saturating_add(other.sampled);
        self.not_readable = self.not_readable.saturating_add(other.not_readable);
        self.row_level_security = self
            .row_level_security
            .saturating_add(other.row_level_security);
        self.remote = self.remote.saturating_add(other.remote);
        self.unsupported = self.unsupported.saturating_add(other.unsupported);
        self.limit = self.limit.saturating_add(other.limit);
        self.error = self.error.saturating_add(other.error);
    }
}

/// The coverage a connector reported for a scan, read by the core once
/// the scan ends (`None`: the connector reported none).
pub(crate) type CoverageCell = Arc<Mutex<Option<ScanCoverage>>>;

/// Bounded channel of masked findings, from a connector to the core, and
/// the scan's coverage counters.
#[derive(Debug, Clone)]
pub struct FindingSink {
    tx: mpsc::Sender<MaskedFinding>,
    coverage: CoverageCell,
}

impl FindingSink {
    /// Creates a bounded sink and its receiving side (back-pressure when
    /// full).
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<MaskedFinding>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                coverage: CoverageCell::default(),
            },
            rx,
        )
    }

    /// Adds to the scan's coverage counters. Report as the scan goes
    /// (objects skipped once planned, each object once sampled or failed),
    /// so a scan stopped by its deadline still tells what it covered.
    pub fn add_coverage(&self, delta: ScanCoverage) {
        self.coverage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_default()
            .add(delta);
    }

    /// The coverage cell, readable after the sink itself is dropped.
    /// Test support: the coverage counters added so far.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn coverage_for_tests(&self) -> Option<ScanCoverage> {
        *self
            .coverage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn coverage_cell(&self) -> CoverageCell {
        Arc::clone(&self.coverage)
    }

    /// Submits a masked finding, waiting if the channel is full.
    ///
    /// # Errors
    /// [`SinkClosed`] if the core stopped consuming.
    pub async fn submit(&self, finding: MaskedFinding) -> Result<(), SinkClosed> {
        self.tx.send(finding).await.map_err(|_| SinkClosed)
    }
}

/// Bounded channel of masked access events, from a connector to the core.
///
/// It also tells the connector which of its events are **durably
/// handled** ([`Self::durable`]): spooled to disk, or dropped by the
/// `audit.configure` filter, by the core's flush after their aggregation
/// window. A source that must not record a position as sent before its
/// events are durably in the spool (the Firebird parser checkpoint,
/// ADR-0060 R25 item 7) compares the [`Self::submitted`] count after its
/// last event of a position with [`Self::durable`].
#[derive(Debug, Clone)]
pub struct EventSink {
    tx: mpsc::Sender<MaskedEvent>,
    durability: Arc<Durability>,
}

/// The counts behind [`EventSink::submitted`] and [`EventSink::durable`].
#[derive(Debug, Default)]
struct Durability {
    /// Events handed to the channel (each send that succeeded).
    submitted: std::sync::atomic::AtomicU64,
    /// The first this many events received are durably handled.
    durable: std::sync::atomic::AtomicU64,
    /// A flush failed to spool some events: nothing is durable from then
    /// on, for the life of this sink (fail closed).
    broken: std::sync::atomic::AtomicBool,
}

impl EventSink {
    /// Creates a bounded sink and its receiving side.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<MaskedEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                durability: Arc::default(),
            },
            rx,
        )
    }

    /// Submits a masked access event, waiting if the channel is full.
    ///
    /// # Errors
    /// [`SinkClosed`] if the core stopped consuming.
    pub async fn submit(&self, event: MaskedEvent) -> Result<(), SinkClosed> {
        self.tx.send(event).await.map_err(|_| SinkClosed)?;
        self.durability
            .submitted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Events submitted through this sink (and its clones) so far. The
    /// channel is FIFO, so for a source that submits from one task, the
    /// `n`-th event it submitted is durably handled once
    /// [`Self::durable`] is at least `n`.
    #[must_use]
    pub fn submitted(&self) -> u64 {
        self.durability
            .submitted
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many of the events submitted first are durably handled (spooled
    /// to disk, or dropped by the reporting filter); `None` once a flush
    /// failed to spool some of them (spool full, write error): nothing is
    /// durable then for the life of the sink, and a source re-sends after a
    /// restart rather than trusting a loss.
    #[must_use]
    pub fn durable(&self) -> Option<u64> {
        let d = &self.durability;
        (!d.broken.load(std::sync::atomic::Ordering::SeqCst))
            .then(|| d.durable.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// The core's flush handled the first `n` events received durably
    /// (`ok`), or failed to spool some of them (`!ok`, for good).
    pub(crate) fn mark_durable(&self, n: u64, ok: bool) {
        let d = &self.durability;
        if !ok {
            d.broken.store(true, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        d.durable.fetch_max(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test support: as the core's flush, the first `n` events received
    /// are durably handled.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn mark_durable_for_tests(&self, n: u64) {
        self.mark_durable(n, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_classifiers::masking::{ClassifierId, RawSample, mask};

    #[tokio::test]
    async fn finding_sink_delivers_masked_findings() {
        let (sink, mut rx) = FindingSink::channel(1);
        let finding = MaskedFinding::new(
            ClassifierId::PII_EMAIL,
            vec![mask(&RawSample::new("a@b.c"))],
        );
        sink.submit(finding.clone()).await.unwrap();
        assert_eq!(rx.recv().await, Some(finding));
    }

    #[test]
    fn coverage_is_added_up_and_outlives_the_sink() {
        let (sink, _rx) = FindingSink::channel(1);
        let cell = sink.coverage_cell();
        assert_eq!(*cell.lock().unwrap(), None);
        sink.add_coverage(ScanCoverage {
            sampled: 2,
            error: 1,
            ..ScanCoverage::default()
        });
        sink.clone().add_coverage(ScanCoverage {
            sampled: u64::MAX,
            remote: 3,
            ..ScanCoverage::default()
        });
        drop(sink);
        let c = cell.lock().unwrap().unwrap();
        assert_eq!((c.sampled, c.error, c.remote), (u64::MAX, 1, 3));
    }

    #[tokio::test]
    async fn finding_sink_reports_closed_receiver() {
        let (sink, rx) = FindingSink::channel(1);
        drop(rx);
        let finding = MaskedFinding::new(ClassifierId::PII_EMAIL, Vec::new());
        assert_eq!(sink.submit(finding).await, Err(SinkClosed));
    }

    /// The durable count follows the core's flushes, and a failed flush
    /// makes nothing durable from then on.
    #[tokio::test]
    async fn event_sink_tells_what_is_durable() {
        use databastion_classifiers::masking::{EventAction, EventPrincipal, EventSource};
        let (sink, mut rx) = EventSink::channel(4);
        let ev = || {
            MaskedEvent::new(
                EventSource::FirebirdAuditTrace,
                EventAction::Read,
                EventPrincipal::unidentified(),
                std::time::SystemTime::now(),
            )
        };
        sink.submit(ev()).await.unwrap();
        sink.submit(ev()).await.unwrap();
        assert_eq!(sink.submitted(), 2);
        assert_eq!(sink.durable(), Some(0));
        let _ = rx.recv().await;
        sink.mark_durable(1, true);
        assert_eq!(sink.durable(), Some(1));
        sink.mark_durable(0, true);
        assert_eq!(sink.durable(), Some(1), "never moves back");
        sink.mark_durable(2, false);
        assert_eq!(sink.durable(), None, "a failed flush, for good");
        sink.mark_durable(2, true);
        assert_eq!(sink.durable(), None);
    }
}
