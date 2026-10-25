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
    }))
}

/// The coverage a connector reported through `sink` so far (zero when
/// none).
#[must_use]
pub fn coverage_of(sink: &crate::FindingSink) -> crate::ScanCoverage {
    sink.coverage_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .unwrap_or_default()
}

/// The labels of `note` as the core sends them (negotiated, ranked by
/// severity, cut to the contract's 16, in enum order), for a console that
/// lists every label revision (`all_revisions`) or none.
#[must_use]
pub fn sent_labels(note: &crate::TargetNote, all_revisions: bool) -> Vec<String> {
    let revisions = crate::notes::LabelRevisions {
        r2026_10: all_revisions,
        r2026_10_b: all_revisions,
        r2026_10_c: all_revisions,
        r2026_10_d: all_revisions,
    };
    crate::notes::to_protocol(std::slice::from_ref(note), revisions)
        .first()
        .and_then(|n| n.labels.as_ref())
        .map(|l| l.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// The `TargetStatus` the heartbeat would send for `health` (a console
/// listing every note label revision), through the core's last step for
/// `sqlite` targets (`sanitize::enforce_sqlite_target_status`), as JSON.
/// `server_version` is what a connector would report.
///
/// # Panics
/// On an invalid built-in identifier (never).
#[must_use]
pub fn contract_target_status_json(
    health: &crate::TargetHealth,
    engine: TargetEngine,
    server_version: Option<&str>,
) -> String {
    let mut status = databastion_protocol::TargetStatus {
        audit_level: crate::runtime::proto_audit_level(health.audit_level),
        audit_source: None,
        edition: None,
        engine: crate::runtime::proto_engine(engine),
        last_error: health.failure,
        metrics: None,
        name_case: None,
        notes: crate::notes::to_protocol(
            &health.notes,
            crate::notes::LabelRevisions {
                r2026_10: true,
                r2026_10_b: true,
                r2026_10_c: true,
                r2026_10_d: true,
            },
        ),
        reachable: health.reachable,
        server_version: server_version
            .and_then(|v| databastion_protocol::TargetStatusServerVersion::try_from(v).ok()),
        target_id: databastion_protocol::TargetId::try_from("test-target").expect("target id"),
    };
    crate::sanitize::enforce_sqlite_target_status(&mut status);
    serde_json::to_string(&status).expect("a target status serializes")
}
