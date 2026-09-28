//! Channels from connectors to the core.
//!
//! Sinks only accept types from `databastion_classifiers::masking`, whose
//! constructors guarantee the data has been masked. A connector therefore
//! cannot push an unmasked value towards the uplink (I2).

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};
use tokio::sync::mpsc;

/// The receiving side of a sink was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("result sink closed")]
pub struct SinkClosed;

/// Bounded channel of masked findings, from a connector to the core.
#[derive(Debug, Clone)]
pub struct FindingSink {
    tx: mpsc::Sender<MaskedFinding>,
}

impl FindingSink {
    /// Creates a bounded sink and its receiving side (back-pressure when
    /// full).
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<MaskedFinding>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
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
    use databastion_classifiers::masking::{RawSample, mask};

    #[tokio::test]
    async fn finding_sink_delivers_masked_findings() {
        let (sink, mut rx) = FindingSink::channel(1);
        let finding = MaskedFinding::new("pii.email", vec![mask(&RawSample::new("a@b.c"))]);
        sink.submit(finding.clone()).await.unwrap();
        assert_eq!(rx.recv().await, Some(finding));
    }

    #[tokio::test]
    async fn finding_sink_reports_closed_receiver() {
        let (sink, rx) = FindingSink::channel(1);
        drop(rx);
        let finding = MaskedFinding::new("pii.email", Vec::new());
        assert_eq!(sink.submit(finding).await, Err(SinkClosed));
    }
}
