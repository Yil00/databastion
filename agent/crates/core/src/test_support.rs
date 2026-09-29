//! Test helpers for the connectors' tests (feature `test-support`, enabled
//! from their `[dev-dependencies]` only; never in the agent binary).
//!
//! The interim I2 checks (phase 7) serialize what would leave the agent
//! through the core's real conversion (`uplink::to_batches`, the single
//! masked -> contract conversion), so a connector test sees the exact
//! bodies the console would receive, as JSON text, without depending on
//! the generated protocol types.

// Test support: an invalid built-in identifier is a bug of this module.
#![allow(clippy::expect_used)]

use databastion_classifiers::masking::{HmacKey, MaskedEvent, MaskedFinding};

use crate::config::TargetEngine;
use crate::uplink;

fn join(built: &uplink::Built) -> String {
    built
        .batches
        .iter()
        .map(|b| String::from_utf8_lossy(b.bytes()).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The findings batches of `findings` for a target of `engine`, as sent
/// (JSON bodies, one per line).
///
/// # Panics
/// On an invalid built-in identifier (never).
#[must_use]
pub fn contract_findings_json(findings: &[MaskedFinding], engine: TargetEngine) -> String {
    let version = databastion_protocol::ClassifiersVersion::try_from(
        databastion_classifiers::id::CLASSIFIERS_VERSION,
    )
    .expect("classifier set version");
    let target = databastion_protocol::TargetId::try_from("test-target").expect("target id");
    join(&uplink::to_batches(uplink::MaskedResults::Findings {
        job_id: databastion_protocol::Uuid::try_from("01920f5f-0c30-7e6f-a043-2b3c4d5e6f00")
            .expect("job id"),
        classifiers_version: &version,
        target_id: &target,
        engine: crate::runtime::proto_engine(engine),
        findings,
    }))
}

/// The events batches of `events` (account names fingerprinted with
/// `key` as the agent does), as sent (JSON bodies, one per line).
///
/// # Panics
/// On an invalid built-in identifier (never).
#[must_use]
pub fn contract_events_json(events: &[MaskedEvent], key: &HmacKey) -> String {
    let target = databastion_protocol::TargetId::try_from("test-target").expect("target id");
    let fingerprints = crate::sanitize::HmacFingerprints(key);
    join(&uplink::to_batches(uplink::MaskedResults::Events {
        target_id: &target,
        events,
        fingerprints: &fingerprints,
        accept_bytes: true,
    }))
}
