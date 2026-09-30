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
#[derive(Debug, Clone)]
pub struct EventSink {
    tx: mpsc::Sender<MaskedEvent>,
}

impl EventSink {
    /// Creates a bounded sink and its receiving side.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<MaskedEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Submits a masked access event, waiting if the channel is full.
    ///
    /// # Errors
    /// [`SinkClosed`] if the core stopped consuming.
    pub async fn submit(&self, event: MaskedEvent) -> Result<(), SinkClosed> {
        self.tx.send(event).await.map_err(|_| SinkClosed)
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
}
