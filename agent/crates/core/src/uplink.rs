//! HTTPS uplink to the console (ADR-0001). Stub.
//!
//! The agent is always the client; nothing here listens (I1). Its API
//! only accepts masked types from `databastion_classifiers::masking`, which is
//! the type-level guarantee that no raw value is sent (I2, ADR-0003).
//! The whole module is crate-private: connectors (which depend on this crate)
//! cannot name or construct an [`Uplink`]; they only get sinks.
//!
//! Skeleton status (P0-D): no HTTP client yet. It will use reqwest with
//! rustls (no OpenSSL / native-tls). Request and response bodies are the
//! types generated from `shared/protocol/openapi.yaml` in
//! `databastion-protocol`; this module is their only user, and the request
//! bodies are only ever built from masked types.

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};
use databastion_protocol::BatchAck;

/// Uplink errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UplinkError {
    /// The uplink is not implemented yet.
    #[error("uplink is not implemented yet")]
    NotImplemented,
}

/// Client towards the console agent API.
#[derive(Debug)]
pub(crate) struct Uplink {}

impl Uplink {
    /// Creates the (stub) uplink.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {}
    }

    /// Sends a batch of masked findings.
    ///
    /// # Errors
    /// Always [`UplinkError::NotImplemented`] in the skeleton.
    pub(crate) async fn send_findings(
        &self,
        _batch: &[MaskedFinding],
    ) -> Result<BatchAck, UplinkError> {
        Err(UplinkError::NotImplemented)
    }

    /// Sends a batch of masked access events.
    ///
    /// # Errors
    /// Always [`UplinkError::NotImplemented`] in the skeleton.
    pub(crate) async fn send_events(
        &self,
        _batch: &[MaskedEvent],
    ) -> Result<BatchAck, UplinkError> {
        Err(UplinkError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_uplink_reports_not_implemented() {
        let uplink = Uplink::new();
        assert!(matches!(
            uplink.send_findings(&[]).await,
            Err(UplinkError::NotImplemented)
        ));
        assert!(matches!(
            uplink.send_events(&[]).await,
            Err(UplinkError::NotImplemented)
        ));
    }
}
