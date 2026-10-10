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
//!
//! [`registry_yaml_diff`] is differential (ADR-0046): on every file the
//! pre-scan accepts, the crate's YAML parser and an oracle deserializer of
//! the same pre-scanned text (`serde_yaml_ng` 0.10, the parser this crate
//! used before, linked by `agent/fuzz` and the tests only) must read the
//! same values and the same definition, or both fail.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use databastion_classifiers::masking::HmacKey;
use serde::de::{self, Deserialize, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

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

/// The oracle of [`registry_yaml_diff`]: a YAML deserializer of a
/// pre-scanned text.
pub trait YamlOracle {
    /// Its deserializer.
    type De<'a>: Deserializer<'a>;
    /// A deserializer of `text`.
    fn deserializer<'a>(&self, text: &'a [u8]) -> Self::De<'a>;
}

/// One YAML service definition file, read by the crate's parser and by
/// `oracle`: they must agree (see [`yaml_difference`]).
///
/// # Panics
/// When they disagree (the fuzz target's finding; no value is printed).
pub fn registry_yaml_diff<O: YamlOracle>(data: &[u8], oracle: &O) {
    let what = yaml_difference(data, oracle);
    assert!(what.is_none(), "the YAML parsers disagree on the {what:?}");
}

/// Where the crate's YAML parser and `oracle` disagree on a file, if
/// anywhere: on a file the pre-scan accepts, the tree of values the
/// pre-scanned text reads as (scalars resolved, keys read as strings), or
/// the failure to read it; then the service definition, or its error. A
/// file the pre-scan refuses is refused by both (the pre-scan is shared).
pub fn yaml_difference<O: YamlOracle>(data: &[u8], oracle: &O) -> Option<&'static str> {
    let pre = crate::parse::yaml::prescan(data).ok()?;
    let ours = crate::parse::yaml::Document::parse(&pre.text)
        .ok()
        .and_then(|d| Tree::deserialize(d).ok());
    let theirs = Tree::deserialize(oracle.deserializer(&pre.text)).ok();
    if ours != theirs {
        return Some("values");
    }
    let ours = summary(definition::parse_yaml_definition(data));
    let theirs = summary(definition::yaml_definition_with(
        oracle.deserializer(&pre.text),
        &pre,
    ));
    (ours != theirs).then_some("definition")
}

/// What a definition is compared on (every field, values in order).
type Summary = Result<
    (
        definition::ServiceType,
        Option<String>,
        Option<i64>,
        Option<i64>,
        String,
        definition::SecretForm,
        Option<String>,
        Vec<(Vec<definition::Seg>, String)>,
    ),
    definition::DefinitionError,
>;

fn summary(r: Result<definition::Definition, definition::DefinitionError>) -> Summary {
    r.map(|d| {
        (
            d.service_type,
            d.name.as_deref().cloned(),
            d.id,
            d.evaluation_order,
            d.service_id.to_string(),
            d.client_secret,
            d.client_id.as_deref().cloned(),
            d.values
                .iter()
                .map(|s| (s.path.clone(), s.value.to_string()))
                .collect(),
        )
    })
}

/// Every value of a document, as a deserializer hands it over.
#[derive(Debug, PartialEq)]
enum Tree {
    Unit,
    Bool(bool),
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    /// The bits of the float.
    F64(u64),
    Str(String),
    Seq(Vec<Tree>),
    Map(Vec<(String, Tree)>),
}

impl<'de> Deserialize<'de> for Tree {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(TreeVisitor)
    }
}

struct TreeVisitor;

impl<'de> Visitor<'de> for TreeVisitor {
    type Value = Tree;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Tree, E> {
        Ok(Tree::Unit)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Tree, E> {
        Ok(Tree::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Tree, E> {
        Ok(Tree::U64(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Tree, E> {
        Ok(Tree::I64(v))
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Tree, E> {
        Ok(Tree::U128(v))
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Tree, E> {
        Ok(Tree::I128(v))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Tree, E> {
        Ok(Tree::F64(v.to_bits()))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Tree, E> {
        Ok(Tree::Str(v.to_owned()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Tree, A::Error> {
        let mut items = Vec::new();
        while let Some(t) = seq.next_element::<Tree>()? {
            items.push(t);
        }
        Ok(Tree::Seq(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Tree, A::Error> {
        let mut entries = Vec::new();
        while let Some(k) = map.next_key_seed(KeyString)? {
            entries.push((k, map.next_value::<Tree>()?));
        }
        Ok(Tree::Map(entries))
    }
}

/// A key read as the visitor reads keys (`deserialize_str`).
struct KeyString;

impl<'de> DeserializeSeed<'de> for KeyString {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_str(self)
    }
}

impl Visitor<'_> for KeyString {
    type Value = String;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a key")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
        Ok(v.to_owned())
    }
}

/// Most lines of one audit log input.
const MAX_AUDIT_LINES: usize = 64;

/// [`fuzz_index`], built once (its patterns compile once per process).
static FUZZ_INDEX: std::sync::OnceLock<Arc<ServiceIndex>> = std::sync::OnceLock::new();

/// The fuzzing service index: OAuth / OIDC clients (one client id shared
/// by two entries) and a CAS service, client ids tagged with a fixed key.
fn fuzz_index() -> ServiceIndex {
    let mut idx = ServiceIndex::with_client_key(
        HmacKey::new(&[2u8; 32])
            .ok()
            .and_then(|k| k.local_tag_key(crate::registry::CLIENT_TAG_PURPOSE)),
    );
    for d in [
        &br#"{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "M2M", "serviceId": "^https://m2m\\.example\\.org/cb$", "clientId": "scratch-m2m"}"#[..],
        br#"{"@class": "org.apereo.cas.support.oauth.services.OAuthRegisteredService", "name": "Batch", "serviceId": "^https://batch\\.example\\.org/.*", "clientId": "batch"}"#,
        br#"{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "Dup", "serviceId": "^https://dup\\.example\\.org/.*", "clientId": "batch"}"#,
        br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "name": "App", "serviceId": "^https://app\\.example\\.org/.*"}"#,
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
    let mut lost = false;
    for line in data.split(|b| *b == b'\n').take(MAX_AUDIT_LINES) {
        if let Ok(text) = std::str::from_utf8(line) {
            let _ = url::service_of(text);
            let _ = url::strip_credentials(text);
            let _ = when::parse_when(text, UtcOffset(3600));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match record::parse_record(line, UtcOffset(0)) {
            Ok(r) => records.push(r),
            Err(_) => lost = true,
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
        Some(Arc::clone(
            FUZZ_INDEX.get_or_init(|| Arc::new(fuzz_index())),
        )),
    );
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut out = Vec::new();
    // As the stream does: a line that does not parse taints the
    // correlation over the read.
    if lost {
        let lo = records.iter().map(|r| r.when).min();
        let hi = records.iter().map(|r| r.when).max();
        b.note_loss(lo.zip(hi));
    }
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

/// `serde_yaml_ng` (a dev-dependency) as the oracle of the tests.
#[cfg(test)]
pub(crate) struct Ng;

#[cfg(test)]
impl YamlOracle for Ng {
    type De<'a> = serde_yaml_ng::Deserializer<'a>;
    fn deserializer<'a>(&self, text: &'a [u8]) -> Self::De<'a> {
        serde_yaml_ng::Deserializer::from_slice(text)
    }
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
            registry_yaml_diff(input, &Ng);
            audit_log(input);
        }
        for fixture in [
            &include_bytes!("../fixtures/registry/HR-Portal-10000003.yml")[..],
            include_bytes!("../fixtures/registry/Wiki-10000004.yaml"),
            include_bytes!("../fixtures/registry/SP-10000005.yml"),
        ] {
            registry_yaml_diff(fixture, &Ng);
            assert_eq!(yaml_difference(fixture, &Ng), None);
        }
        // The synthetic hostile files that seed the YAML fuzz targets.
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/registry-hostile");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(bytes.len() < 4096);
            registry_yaml(&bytes);
            registry_yaml_diff(&bytes, &Ng);
            seen += 1;
        }
        assert!(seen >= 10);
        // The fuzzing index holds its clients (review of #182 M2: the
        // named correlation path must be reachable by the fuzzer).
        let idx = fuzz_index();
        assert_eq!(idx.len(), 4);
        let entry = idx
            .client_tag("scratch-m2m")
            .and_then(|t| idx.client(t))
            .and_then(|r| idx.entry(r).map(|(_, n)| n.as_str().to_owned()));
        assert_eq!(entry.as_deref(), Some("M2M"));
        assert!(
            idx.client_tag("batch")
                .and_then(|t| idx.client(t))
                .is_none()
        );
        // The real CAS 8.0.2 OAuth / OIDC excerpt, as one input.
        audit_log(include_bytes!(
            "../fixtures/cas-8.0.2-oauth-oidc-audit.jsonl"
        ));
    }
}
