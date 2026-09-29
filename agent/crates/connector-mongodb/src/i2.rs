//! Interim I2 check of the MongoDB Discovery path (end-of-phase-5 review
//! M1, until the end-to-end gate of `e2e/`): no ground-truth value of the
//! scanned database appears in clear in the serialized masked findings.

use databastion_classifiers::masking::MaskedFinding;

/// Values shorter than this are too common to be a meaningful leak
/// (a masked sample keeps a few characters by design).
const MIN_LEN: usize = 4;

/// Every text of the findings that would leave the agent: the location
/// names, the classifier, the masked samples and the fingerprints, one
/// JSON document per finding.
pub(crate) fn serialize(findings: &[MaskedFinding]) -> String {
    let items: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let l = f.location();
            serde_json::json!({
                "classifier": f.classifier().as_str(),
                "database": l.map(|l| l.database.as_str()),
                "schema": l.and_then(|l| l.schema.as_ref().map(|s| s.as_str())),
                "object": l.map(|l| l.object.as_str()),
                "field": l.map(|l| l.field.as_str()),
                "masked_samples": f.masked_samples().iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                "fingerprints": f.fingerprints().iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                "sampled": f.sampled(),
                "matched": f.matched(),
            })
        })
        .collect();
    serde_json::to_string(&items).expect("findings serialize")
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

/// Asserts that no ground-truth value of `database` is in `findings`.
/// Returns how many values were checked.
pub(crate) fn assert_no_value(
    gt: &serde_json::Value,
    database: &str,
    findings: &[MaskedFinding],
) -> usize {
    let text = serialize(findings);
    // Also compare with JSON escapes undone (non-ASCII is kept as is by
    // `serde_json`, but quotes and backslashes are escaped).
    let values = ground_truth_values(gt, database);
    for v in &values {
        let escaped = serde_json::to_string(v).expect("string serializes");
        let escaped = &escaped[1..escaped.len() - 1];
        // The value itself is never printed (I2 hygiene in test output).
        assert!(
            !text.contains(escaped),
            "a MongoDB ground-truth value of {} characters is in clear in the serialized findings",
            v.chars().count()
        );
    }
    values.len()
}
