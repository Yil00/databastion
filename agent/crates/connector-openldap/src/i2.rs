//! Interim I2 check of the OpenLDAP paths (end-of-phase-6 security review
//! L2, until the end-to-end gate of `e2e/`): no ground-truth value and no
//! entry DN (`uid=`, `cn=`) in clear in what would leave the agent (the
//! findings and access events as the core's real conversion serializes
//! them, `databastion_core::test_support`) nor in the logs.

use std::sync::{Arc, Mutex};

use databastion_classifiers::masking::{HmacKey, MaskedEvent, MaskedFinding};

/// Values shorter than this are too common to be a meaningful leak (a
/// masked sample keeps a few characters by design).
const MIN_LEN: usize = 4;

/// DNs (and naming attributes) that may appear in clear: the directory's
/// own configuration and schema entries. The agent's DN and the
/// `openldap.clear_principals` of a test are added by the caller.
const ALLOWED: [&str; 3] = ["cn=accesslog", "cn=subschema", "cn=config"];

/// The findings as the core would send them (its real masked ->
/// contract conversion, JSON bodies).
pub(crate) fn findings_text(findings: &[MaskedFinding]) -> String {
    databastion_core::test_support::contract_findings_json(
        findings,
        databastion_core::config::TargetEngine::Openldap,
    )
}

/// The events as the core would send them: principals in clear only when
/// the core sends them so, else their fingerprint (test key).
pub(crate) fn events_text(events: &[MaskedEvent]) -> String {
    let key = HmacKey::new(&[7u8; 32]).expect("test key");
    databastion_core::test_support::contract_events_json(events, &key)
}

/// The OpenLDAP ground-truth values (`values` and `name_values`) of at
/// least [`MIN_LEN`] characters.
pub(crate) fn ground_truth_values(gt: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for l in gt["locations"]
        .as_array()
        .expect("locations")
        .iter()
        .filter(|l| l["engine"] == "openldap")
    {
        for key in ["values", "name_values"] {
            for v in l[key].as_array().into_iter().flatten() {
                if let Some(v) = v.as_str().filter(|v| v.chars().count() >= MIN_LEN) {
                    out.push(v.to_owned());
                }
            }
        }
    }
    out
}

/// Asserts that `text` (serialized findings or events, or captured logs)
/// holds none of `values` and no `uid=` / `cn=` DN but the allowed ones
/// (`allowed`, compared without case). `what` names the text in the
/// failure message; the offending value is never printed.
pub(crate) fn assert_clean(what: &str, text: &str, values: &[String], allowed: &[&str]) {
    for v in values {
        let escaped = serde_json::to_string(v).expect("string serializes");
        let escaped = &escaped[1..escaped.len() - 1];
        assert!(
            !text.contains(v.as_str()) && !text.contains(escaped),
            "a ground-truth value of {} characters is in clear in the {what}",
            v.chars().count()
        );
    }
    let mut rest = text.to_ascii_lowercase();
    let mut allowed: Vec<String> = allowed
        .iter()
        .chain(ALLOWED.iter())
        .map(|a| a.to_ascii_lowercase())
        .collect();
    // Longest first: a DN is removed before its RDN.
    allowed.sort_by_key(|a| std::cmp::Reverse(a.len()));
    for a in &allowed {
        rest = rest.replace(a.as_str(), "");
    }
    assert!(
        !rest.contains("uid="),
        "an entry DN (uid=) is in the {what}"
    );
    assert!(!rest.contains("cn="), "an entry DN (cn=) is in the {what}");
}

/// The dev ground truth.
pub(crate) fn ground_truth() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../dev/ground-truth.json"))
        .expect("ground truth parses")
}

/// Captured log output of the connector.
#[derive(Clone, Default)]
pub(crate) struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    pub(crate) fn capture(&self) -> tracing::subscriber::DefaultGuard {
        tracing::dispatcher::set_default(&self.dispatch())
    }

    /// The capturing subscriber, for a future run on another task
    /// (`WithSubscriber`).
    pub(crate) fn dispatch(&self) -> tracing::Dispatch {
        let logs = self.clone();
        tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || logs.clone())
                .finish(),
        )
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}
