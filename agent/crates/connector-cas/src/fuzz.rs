//! Entry points of the fuzz targets (`agent/fuzz`, cargo-fuzz). Built only
//! with the `fuzzing` feature, never by the agent binary.
//!
//! Each function feeds arbitrary bytes to a parser of CAS data, which a
//! hostile service definition author or a hostile end user (`who`,
//! `userAgent`, the service URL in `what`) controls: the service
//! definition visitor (JSON, and YAML behind its pre-scan) with the field
//! naming and service index built on it, and the audit record visitor with the `what` reducer, the time
//! parser and the event builder (with the token request / response
//! correlation state of ADR-0044, fed a short sequence of lines). They must
//! never panic nor hang; results are dropped at once, nothing is logged.

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

/// Most lines of one audit log input.
const MAX_AUDIT_LINES: usize = 64;

/// The fuzzing service index: OAuth / OIDC clients (one client id shared
/// by two entries) and a CAS service, client ids tagged with a fixed key.
fn fuzz_index() -> ServiceIndex {
    let mut idx = ServiceIndex::with_client_key(
        HmacKey::new(&[2u8; 32])
            .ok()
            .and_then(|k| k.local_tag_key(crate::registry::CLIENT_TAG_PURPOSE)),
    );
    for d in [
        &br#"{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "M2M", "serviceId": "^https://m2m\.example\.org/cb$", "clientId": "scratch-m2m"}"#[..],
        br#"{"@class": "org.apereo.cas.support.oauth.services.OAuthRegisteredService", "name": "Batch", "serviceId": "^https://batch\.example\.org/.*", "clientId": "batch"}"#,
        br#"{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "Dup", "serviceId": "^https://dup\.example\.org/.*", "clientId": "batch"}"#,
        br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "name": "App", "serviceId": "^https://app\.example\.org/.*"}"#,
    ] {
        if let Ok(d) = definition::parse_definition(d) {
            let _ = idx.add(&d);
        }
    }
    idx.finish();
    idx
}

/// An audit log excerpt: each line (at most [`MAX_AUDIT_LINES`]) parsed (in
/// a fixed zone), its text also given to the `what` reducer and the time
/// parser, then the records converted to events in order by one builder
/// (twice over, so the correlation state sees requests and responses
/// interleaved with its own leftovers).
pub fn audit_log(data: &[u8]) {
    let mut records = Vec::new();
    for line in data.split(|b| *b == b'\n').take(MAX_AUDIT_LINES) {
        if let Ok(text) = std::str::from_utf8(line) {
            let _ = url::service_of(text);
            let _ = url::strip_credentials(text);
            let _ = when::parse_when(text, UtcOffset(3600));
        }
        if let Ok(r) = record::parse_record(line, UtcOffset(0)) {
            records.push(r);
        }
    }
    if records.is_empty() {
        return;
    }
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
        Some(Arc::new(fuzz_index())),
    );
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut out = Vec::new();
    for _ in 0..2 {
        for r in &records {
            b.push(r, now, &mut out);
        }
    }
    if records.len() == 1
        && let Some(r) = records.first()
    {
        b.push(r, now, &mut out);
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
            br#"{"action": "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED", "when": 1791115200000, "what": {"code": "N/A", "grant_type": "client_credentials", "service": "scratch-m2m"}, "clientIpAddress": "192.0.2.1", "serverIpAddress": "198.51.100.3", "userAgent": "x"}
{"who": "scratch-m2m", "action": "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED", "when": 1791115200040, "what": {"access_token": "AT-1-FAKE"}, "clientIpAddress": "192.0.2.1", "serverIpAddress": "198.51.100.3", "userAgent": "x"}
{"who": "jdoe", "action": "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED", "when": 1791115200050}"#,
        ] {
            registry(input);
            registry_yaml(input);
            audit_log(input);
        }
        // The real CAS 8.0.2 OAuth / OIDC excerpt, as one input.
        audit_log(include_bytes!(
            "../fixtures/cas-8.0.2-oauth-oidc-audit.jsonl"
        ));
    }
}
