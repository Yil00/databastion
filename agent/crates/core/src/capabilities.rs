//! Capability negotiation (ADR-0022).
//!
//! Every schema of the protocol is closed: a console built before an
//! optional request field was added answers `400` to a body carrying it (for
//! a heartbeat, the whole heartbeat is lost). The console therefore lists
//! the optional request fields it accepts in `HeartbeatResponse.accepts`,
//! and the agent sends such a field only when the latest heartbeat response
//! listed it: before the first response, when the list is absent, and after
//! a heartbeat rejected with `400` (e.g. a console rolled back), nothing is
//! accepted.

use std::collections::BTreeSet;
use std::sync::RwLock;

use databastion_protocol::CapabilityList;

/// Contract `CapabilityList.maxItems`: tokens past it are ignored (the
/// generated type does not enforce `maxItems`).
pub(crate) const MAX_CAPABILITIES: usize = 64;

/// Tokens of the optional request fields the agent may send (contract
/// `Capability`). No producer uses them yet.
#[allow(dead_code)]
pub(crate) mod token {
    /// `TargetStatus.notes`.
    pub(crate) const TARGET_STATUS_NOTES: &str = "target_status.notes";
    /// `AccessEvent.bytes`.
    pub(crate) const ACCESS_EVENT_BYTES: &str = "access_event.bytes";
    /// `JobProgress.objects_sampled` and `skipped_*`.
    pub(crate) const JOB_PROGRESS_COVERAGE: &str = "job_progress.coverage";
}

/// What the console accepts, from its latest heartbeat response.
#[derive(Debug, Default)]
pub(crate) struct ConsoleCapabilities {
    accepted: RwLock<BTreeSet<String>>,
}

impl ConsoleCapabilities {
    /// Replaces the set with the `accepts` of a heartbeat response (absent:
    /// nothing is accepted). Only the first [`MAX_CAPABILITIES`] tokens are
    /// kept, so a hostile or buggy console cannot grow the set.
    pub(crate) fn record(&self, accepts: Option<&CapabilityList>) {
        let set = accepts
            .map(|list| {
                list.iter()
                    .take(MAX_CAPABILITIES)
                    .map(|c| c.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        *self
            .accepted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = set;
    }

    /// Forgets every capability (heartbeat rejected with `400`).
    pub(crate) fn clear(&self) {
        self.record(None);
    }

    /// Whether the latest heartbeat response listed `token`.
    pub(crate) fn console_accepts(&self, token: &str) -> bool {
        self.accepted
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(token)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn list(tokens: &[&str]) -> CapabilityList {
        serde_json::from_value(serde_json::json!(tokens)).unwrap()
    }

    #[test]
    fn nothing_is_accepted_before_the_first_response() {
        let caps = ConsoleCapabilities::default();
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(!caps.console_accepts(token::ACCESS_EVENT_BYTES));
        assert!(!caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
    }

    #[test]
    fn the_latest_response_wins() {
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list(&[
            token::ACCESS_EVENT_BYTES,
            token::TARGET_STATUS_NOTES,
            "future.feature",
        ])));
        assert!(caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(caps.console_accepts(token::ACCESS_EVENT_BYTES));
        assert!(!caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
        caps.record(Some(&list(&[token::JOB_PROGRESS_COVERAGE])));
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        assert!(caps.console_accepts(token::JOB_PROGRESS_COVERAGE));
    }

    #[test]
    fn an_absent_list_or_a_rejected_heartbeat_accepts_nothing() {
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list(&[token::TARGET_STATUS_NOTES])));
        caps.record(None);
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
        caps.record(Some(&list(&[token::TARGET_STATUS_NOTES])));
        caps.clear();
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
    }

    #[test]
    fn tokens_past_the_contract_bound_are_ignored() {
        let mut tokens: Vec<String> = (0..MAX_CAPABILITIES)
            .map(|i| format!("filler.f{i}"))
            .collect();
        tokens.push(token::TARGET_STATUS_NOTES.to_owned());
        let list: CapabilityList = serde_json::from_value(serde_json::json!(tokens)).unwrap();
        let caps = ConsoleCapabilities::default();
        caps.record(Some(&list));
        assert!(caps.console_accepts("filler.f0"));
        assert!(caps.console_accepts(&format!("filler.f{}", MAX_CAPABILITIES - 1)));
        assert!(!caps.console_accepts(token::TARGET_STATUS_NOTES));
    }

    #[test]
    fn malformed_tokens_never_reach_the_agent() {
        // The generated `Capability` enforces the contract pattern: a
        // response with a malformed token fails to decode as a whole.
        assert!(
            serde_json::from_value::<CapabilityList>(serde_json::json!(["Target Notes"])).is_err()
        );
    }
}
