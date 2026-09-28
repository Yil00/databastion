//! HTTPS uplink to the console (ADR-0001). Stub.
//!
//! The agent is always the client; nothing here listens (I1). The public API
//! only accepts masked types from `databastion_classifiers::masking`, which is
//! the type-level guarantee that no raw value is sent (I2, ADR-0003).
//! Connectors never receive an [`Uplink`]; they only get sinks.
//!
//! Skeleton status (P0-D): no HTTP client yet. It will use reqwest with
//! rustls (no OpenSSL / native-tls) and the request/response types generated
//! from `shared/protocol/openapi.yaml`.

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};

/// Uplink errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UplinkError {
    /// The uplink is not implemented yet.
    #[error("uplink is not implemented yet")]
    NotImplemented,
}

/// Client towards the console agent API.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Uplink {}

impl Uplink {
    /// Creates the (stub) uplink.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Sends a batch of masked findings.
    ///
    /// # Errors
    /// Always [`UplinkError::NotImplemented`] in the skeleton.
    pub async fn send_findings(&self, _batch: &[MaskedFinding]) -> Result<(), UplinkError> {
        Err(UplinkError::NotImplemented)
    }

    /// Sends a batch of masked access events.
    ///
    /// # Errors
    /// Always [`UplinkError::NotImplemented`] in the skeleton.
    pub async fn send_events(&self, _batch: &[MaskedEvent]) -> Result<(), UplinkError> {
        Err(UplinkError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_uplink_reports_not_implemented() {
        let uplink = Uplink::new();
        assert_eq!(
            uplink.send_findings(&[]).await,
            Err(UplinkError::NotImplemented)
        );
        assert_eq!(
            uplink.send_events(&[]).await,
            Err(UplinkError::NotImplemented)
        );
    }
}
