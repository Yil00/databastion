//! Interim I2 check of the MongoDB paths (end-of-phase-5 review M1, until
//! the end-to-end gate of `e2e/`): no ground-truth value of the scanned
//! database appears in clear in the findings and events as the core would
//! send them (its real conversion, `databastion_core::test_support`), nor
//! in the captured logs.

use databastion_classifiers::masking::{HmacKey, MaskedEvent, MaskedFinding};

/// Values shorter than this are too common to be a meaningful leak
/// (a masked sample keeps a few characters by design).
const MIN_LEN: usize = 4;

/// The findings as the core would send them (its real masked ->
/// contract conversion, JSON bodies).
pub(crate) fn serialize(findings: &[MaskedFinding]) -> String {
    databastion_core::test_support::contract_findings_json(
        findings,
        databastion_core::config::TargetEngine::Mongodb,
    )
}

/// The events as the core would send them (account names fingerprinted
/// with a test key when the core would).
pub(crate) fn serialize_events(events: &[MaskedEvent]) -> String {
    let key = HmacKey::new(&[7u8; 32]).expect("test key");
    databastion_core::test_support::contract_events_json(events, &key)
}

/// The ground-truth values (`values` and `name_values`) of the MongoDB
/// locations of `database`, of at least [`MIN_LEN`] characters.
pub(crate) fn ground_truth_values(gt: &serde_json::Value, database: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in gt["locations"]
        .as_array()
        .expect("locations")
        .iter()
        .filter(|l| l["engine"] == "mongodb" && l["database"] == database)
    {
        for key in ["values", "name_values"] {
            for v in l[key].as_array().into_iter().flatten() {
                let v = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                if v.chars().count() >= MIN_LEN {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Asserts that no ground-truth value of `database` is in `text` (a
/// serialized payload or captured logs); `what` names it. Returns how many
/// values were checked.
pub(crate) fn assert_clean(
    what: &str,
    gt: &serde_json::Value,
    database: &str,
    text: &str,
) -> usize {
    let values = ground_truth_values(gt, database);
    for v in &values {
        let escaped = serde_json::to_string(v).expect("string serializes");
        let escaped = &escaped[1..escaped.len() - 1];
        // The value itself is never printed (I2 hygiene in test output).
        assert!(
            !text.contains(v.as_str()) && !text.contains(escaped),
            "a MongoDB ground-truth value of {} characters is in clear in the {what}",
            v.chars().count()
        );
    }
    values.len()
}

/// Asserts that no ground-truth value of `database` is in `findings`.
/// Returns how many values were checked.
pub(crate) fn assert_no_value(
    gt: &serde_json::Value,
    database: &str,
    findings: &[MaskedFinding],
) -> usize {
    assert_clean("serialized findings", gt, database, &serialize(findings))
}
