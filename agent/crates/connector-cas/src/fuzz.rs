//! Entry points of the fuzz targets (`agent/fuzz`, cargo-fuzz). Built only
//! with the `fuzzing` feature, never by the agent binary.
//!
//! Each function feeds arbitrary bytes to a parser of CAS data, which a
//! hostile service definition author or a hostile end user (`who`,
//! `userAgent`, the service URL in `what`) controls: the service
//! definition visitor (JSON, and YAML behind its pre-scan) with the field
//! naming and service index built on it, and the audit record visitor with the `what` reducer, the time
//! parser and the event builder. They must never panic nor hang; results
//! are dropped at once, nothing is logged.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use databastion_classifiers::masking::HmacKey;

use crate::audit::events::{Builder, TAG_PURPOSE};
use crate::config::{ClientAddrMode, UtcOffset};
use crate::parse::{definition, record, url, when};
use crate::registry::{ServiceIndex, field_name, object_name};

/// One service definition file: parsed, then every path named and the
/// service indexed and matched against a fixed host.
pub fn registry(data: &[u8]) {
    let Ok(d) = definition::parse_definition(data) else {
        return;
    };
    for s in &d.values {
        let _ = field_name(&s.path);
        let _ = url::strip_credentials(&s.value);
    }
    let _ = object_name(&d);
    let idx = ServiceIndex::new([&d]);
    if let Some(h) = url::service_of("https://app.example.org/") {
        let _ = idx.lookup(&h);
    }
}

/// One YAML service definition file: pre-scanned, parsed when accepted,
/// then named and indexed as [`registry`] does.
pub fn registry_yaml(data: &[u8]) {
    let _ = crate::parse::yaml::prescan(data);
    let Ok(d) = definition::parse_yaml_definition(data) else {
        return;
    };
    for s in &d.values {
        let _ = field_name(&s.path);
    }
    let _ = object_name(&d);
    let idx = ServiceIndex::new([&d]);
    if let Some(h) = url::service_of("https://app.example.org/") {
        let _ = idx.lookup(&h);
    }
}

/// One audit log line: parsed (in a fixed zone), its text also given to
/// the `what` reducer and the time parser, then converted to events.
pub fn audit_log(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = url::service_of(text);
        let _ = url::strip_credentials(text);
        let _ = when::parse_when(text, UtcOffset(3600));
    }
    let Ok(r) = record::parse_record(data, UtcOffset(0)) else {
        return;
    };
    let Some(key) = HmacKey::new(&[1u8; 32])
        .ok()
        .and_then(|k| k.local_tag_key(TAG_PURPOSE))
    else {
        return;
    };
    let mut b = Builder::new(
        key,
        &["svc".to_owned()],
        ClientAddrMode::Truncated,
        Some(Arc::new(ServiceIndex::default())),
    );
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut out = Vec::new();
    for _ in 0..3 {
        b.push(&r, now, &mut out);
    }
    b.flush(SystemTime::now(), true, &mut out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_points_accept_any_input() {
        for input in [
            &b""[..],
            b"{",
            b"\xff\xfe",
            br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "(", "name": "x"}"#,
            br#"{"action": "AUTHENTICATION_FAILED", "who": "a", "when": 1791115200000, "clientIpAddress": "::1"}"#,
            br#"{"action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z", "what": "https://[::1]:1/"}"#,
            br#"{"action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z", "what": {"service": "https://app.example.org/login", "ticketId": "ST-1-****-cas01"}}"#,
            br#"{"action": "SERVICE_TICKET_CREATED", "when": 1791115200000, "what": {"service": "https://a.example.org/", "service": "x"}}"#,
            b"--- !<org.apereo.cas.services.CasRegisteredService>\nserviceId: \"(\"\nname: x\n",
            b"--- !<org.apereo.cas.services.CasRegisteredService>\na: &a [*a]\n",
        ] {
            registry(input);
            registry_yaml(input);
            audit_log(input);
        }
    }
}
