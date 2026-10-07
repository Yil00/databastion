//! CAS JSON audit records (ADR-0041 decision 7, security review L3).
//!
//! One record per line, written by the CAS `Slf4j` audit destination with
//! `cas.audit.engine.audit-format: JSON`. The parser is a closed serde
//! visitor on the keys `who`, `what`, `action`, `when`, `clientIpAddress`
//! and `userAgent`; every other key (`application`, `headers`,
//! `serverIpAddress`, `geoLocation`, `tenant`, unknown keys) is skipped
//! with `IgnoredAny`, never kept (only the presence of `headers` is
//! noted). **A record with a duplicate kept key is dropped.** A line that
//! is not one JSON object, or lacks a valid `action` or `when`, is dropped.
//!
//! `what` can hold a ticket id (a live SSO bearer credential). It is a
//! string (`ST-1-… for https://…`) or, as CAS 8.0 writes it, a JSON object
//! (`{"service": "https://…", "ticketId": "ST-1-…"}`). From the object only
//! the string value of the `service` key is read; every other key
//! (`ticketId`, `principal`, `credential`, unknown keys) and every nested
//! value is skipped with `IgnoredAny`, never copied, and a duplicate
//! `service` drops the record. Any other JSON type (`null`, a number, an
//! array) names no service. The text kept is held in a zeroizing buffer
//! only while the record is parsed, then reduced to the service URL's
//! scheme and host **for service-ticket issuance only**
//! ([`super::url::service_of`]) and dropped. Nothing else of it is kept.
//!
//! The `DEFAULT` (`WHO: … WHAT: …`) format is not supported (ADR-0041 open
//! question 6, confirmed: JSON is required).

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use super::bounded_owned;
use super::url::{ServiceHost, service_of};
use super::when::{from_epoch, parse_when};
use crate::config::UtcOffset;

/// Longest `who` kept, in bytes (cut on a character boundary).
pub const MAX_WHO_BYTES: usize = 1024;
/// Longest `what` (or object-form `service`) examined, in bytes (a longer
/// one is cut first).
const MAX_WHAT_BYTES: usize = 8192;
/// Longest `action` accepted, in bytes.
const MAX_ACTION_BYTES: usize = 128;
/// Longest application token kept, in characters.
const MAX_AGENT_CHARS: usize = 64;

/// Action suffixes chosen by CAS's action resolvers.
const SUFFIXES: [&str; 9] = [
    "_NOT_CREATED",
    "_NOT_TRIGGERED",
    "_SUCCESS",
    "_FAILED",
    "_FAILURE",
    "_CREATED",
    "_DESTROYED",
    "_TRIGGERED",
    "_ATTEMPTED",
];

/// The action of a record, from a closed list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `AUTHENTICATION_SUCCESS`.
    AuthSuccess,
    /// `AUTHENTICATION_FAILED`.
    AuthFailed,
    /// `SERVICE_TICKET_CREATED`.
    ServiceTicketCreated,
    /// `SAVE_SERVICE_SUCCESS`.
    SaveService,
    /// `DELETE_SERVICE_SUCCESS`.
    DeleteService,
    /// Any other action: no event, counted per base (the action without
    /// its resolver suffix; `[A-Z0-9_]` only).
    Other(String),
}

impl Action {
    fn from_name(name: &str) -> Option<Self> {
        if name.is_empty()
            || name.len() > MAX_ACTION_BYTES
            || !name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        Some(match name {
            "AUTHENTICATION_SUCCESS" => Self::AuthSuccess,
            "AUTHENTICATION_FAILED" => Self::AuthFailed,
            "SERVICE_TICKET_CREATED" => Self::ServiceTicketCreated,
            "SAVE_SERVICE_SUCCESS" => Self::SaveService,
            "DELETE_SERVICE_SUCCESS" => Self::DeleteService,
            other => {
                let base = SUFFIXES
                    .iter()
                    .find_map(|s| other.strip_suffix(s).filter(|b| !b.is_empty()))
                    .unwrap_or(other);
                Self::Other(base.to_owned())
            }
        })
    }

    /// Whether the record issues a ticket or token for a service (the
    /// OIDC / OAuth issuance actions are to verify against CAS 8.0 and are
    /// not listed yet).
    #[must_use]
    pub fn issues_for_service(&self) -> bool {
        matches!(self, Self::ServiceTicketCreated)
    }
}

/// One parsed audit record (closed facts only).
pub struct AuditRecord {
    /// Action.
    pub action: Action,
    /// `who` (bounded), when present.
    pub who: Option<Zeroizing<String>>,
    /// `when`.
    pub when: SystemTime,
    /// `clientIpAddress` when it is one IP literal.
    pub client: Option<IpAddr>,
    /// First product token of `userAgent` (e.g. `python-requests/2.32`),
    /// already reduced like the contract `Principal.application`: every
    /// character outside `[A-Za-z0-9._:/+-]` becomes `_`, at most 64
    /// characters (`EventPrincipal::with_application` applies the same rule
    /// again when the event is built).
    pub user_agent: Option<String>,
    /// Scheme and host of the service, for service-ticket issuance.
    pub service: Option<ServiceHost>,
    /// The record carries a `headers` key (cookies in the log).
    pub headers_logged: bool,
}

impl fmt::Debug for AuditRecord {
    // Principals and hosts are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("action", &self.action)
            .field("when", &self.when)
            .field("headers_logged", &self.headers_logged)
            .finish_non_exhaustive()
    }
}

/// Why a line was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Not one JSON object (another log format, a layout prefix).
    NotJson,
    /// A JSON object that is not a valid record: duplicate kept key,
    /// missing or invalid `action` or `when`.
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Who,
    What,
    Action,
    When,
    Client,
    Agent,
    Headers,
    Other,
}

struct KeySeed;

impl<'de> de::DeserializeSeed<'de> for KeySeed {
    type Value = K;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<K, D::Error> {
        d.deserialize_str(self)
    }
}

impl Visitor<'_> for KeySeed {
    type Value = K;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<K, E> {
        Ok(match v {
            "who" => K::Who,
            "what" => K::What,
            "action" => K::Action,
            "when" => K::When,
            "clientIpAddress" => K::Client,
            "userAgent" => K::Agent,
            "headers" => K::Headers,
            _ => K::Other,
        })
    }
}

/// A string (bounded, zeroized) or `None` for any other JSON type.
struct Text(Option<Zeroizing<String>>);

struct TextSeed(usize);

impl<'de> de::DeserializeSeed<'de> for TextSeed {
    type Value = Text;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Text, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for TextSeed {
    type Value = Text;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Text, E> {
        Ok(Text(Some(bounded_owned(v, self.0))))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Text, E> {
        Ok(Text(None))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Text, E> {
        Ok(Text(None))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Text, E> {
        Ok(Text(None))
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Text, E> {
        Ok(Text(None))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Text, E> {
        Ok(Text(None))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Text, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Text(None))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Text, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Text(None))
    }
}

/// The keys of an object-form `what`: only `service` is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WhatKey {
    Service,
    Other,
}

struct WhatKeySeed;

impl<'de> de::DeserializeSeed<'de> for WhatKeySeed {
    type Value = WhatKey;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<WhatKey, D::Error> {
        d.deserialize_str(self)
    }
}

impl Visitor<'_> for WhatKeySeed {
    type Value = WhatKey;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<WhatKey, E> {
        Ok(if v == "service" {
            WhatKey::Service
        } else {
            WhatKey::Other
        })
    }
}

/// `what`: the text to reduce (the string form, or the `service` string of
/// the object form; bounded, zeroized), and whether the object form had a
/// duplicate `service`.
struct What {
    text: Option<Zeroizing<String>>,
    duplicate: bool,
}

struct WhatSeed;

impl<'de> de::DeserializeSeed<'de> for WhatSeed {
    type Value = What;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<What, D::Error> {
        d.deserialize_any(self)
    }
}

impl WhatSeed {
    fn none() -> What {
        What {
            text: None,
            duplicate: false,
        }
    }
}

impl<'de> Visitor<'de> for WhatSeed {
    type Value = What;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or an object")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<What, E> {
        Ok(What {
            text: Some(bounded_owned(v, MAX_WHAT_BYTES)),
            duplicate: false,
        })
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<What, E> {
        Ok(Self::none())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<What, E> {
        Ok(Self::none())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<What, E> {
        Ok(Self::none())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<What, E> {
        Ok(Self::none())
    }
    fn visit_unit<E: de::Error>(self) -> Result<What, E> {
        Ok(Self::none())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<What, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Self::none())
    }
    // Only `service` is read (a string, or nothing for any other type);
    // every other key and value is skipped without being copied.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<What, A::Error> {
        let mut service: Option<Option<Zeroizing<String>>> = None;
        let mut duplicate = false;
        while let Some(k) = map.next_key_seed(WhatKeySeed)? {
            match k {
                WhatKey::Service => {
                    let v = map.next_value_seed(TextSeed(MAX_WHAT_BYTES))?.0;
                    if service.replace(v).is_some() {
                        duplicate = true;
                    }
                }
                WhatKey::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(What {
            text: service.flatten(),
            duplicate,
        })
    }
}

/// `when`: a string or an epoch number.
enum When {
    Text(Zeroizing<String>),
    Number(i64),
    Other,
}

struct WhenSeed;

impl<'de> de::DeserializeSeed<'de> for WhenSeed {
    type Value = When;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<When, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for WhenSeed {
    type Value = When;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a time")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<When, E> {
        Ok(When::Text(bounded_owned(v, 64)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<When, E> {
        Ok(When::Number(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<When, E> {
        Ok(i64::try_from(v).map_or(When::Other, When::Number))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<When, E> {
        Ok(When::Other)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<When, E> {
        Ok(When::Other)
    }
    fn visit_unit<E: de::Error>(self) -> Result<When, E> {
        Ok(When::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<When, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(When::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<When, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(When::Other)
    }
}

#[derive(Default)]
struct Raw {
    who: Option<Option<Zeroizing<String>>>,
    what: Option<What>,
    action: Option<Option<Zeroizing<String>>>,
    when: Option<When>,
    client: Option<Option<Zeroizing<String>>>,
    agent: Option<Option<Zeroizing<String>>>,
    headers: bool,
    duplicate: bool,
}

struct RecordVisitor;

impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Option<Raw>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an audit record")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<Raw>, A::Error> {
        let mut r = Raw::default();
        while let Some(k) = map.next_key_seed(KeySeed)? {
            let slot = match k {
                K::Who => &mut r.who,
                K::What => {
                    let w = map.next_value_seed(WhatSeed)?;
                    if w.duplicate || r.what.replace(w).is_some() {
                        r.duplicate = true;
                    }
                    continue;
                }
                K::Action => &mut r.action,
                K::Client => &mut r.client,
                K::Agent => &mut r.agent,
                K::When => {
                    let w = map.next_value_seed(WhenSeed)?;
                    if r.when.replace(w).is_some() {
                        r.duplicate = true;
                    }
                    continue;
                }
                K::Headers => {
                    r.headers = true;
                    map.next_value::<IgnoredAny>()?;
                    continue;
                }
                K::Other => {
                    map.next_value::<IgnoredAny>()?;
                    continue;
                }
            };
            let max = match k {
                K::Who => MAX_WHO_BYTES,
                K::Action => MAX_ACTION_BYTES + 1,
                _ => 256,
            };
            let v = map.next_value_seed(TextSeed(max))?.0;
            if slot.replace(v).is_some() {
                r.duplicate = true;
            }
        }
        Ok(Some(r))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Option<Raw>, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Option<Raw>, E> {
        Ok(None)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Option<Raw>, E> {
        Ok(None)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Option<Raw>, E> {
        Ok(None)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Option<Raw>, E> {
        Ok(None)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Option<Raw>, E> {
        Ok(None)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Option<Raw>, E> {
        Ok(None)
    }
}

/// The first product token of a user agent (up to the first blank), at
/// most 64 characters, reduced to the contract `Principal.application`
/// alphabet: any other character becomes `_` (a token of `_` only is
/// dropped).
fn first_token(ua: &str) -> Option<String> {
    let t: String = ua
        .split_whitespace()
        .next()?
        .chars()
        .take(MAX_AGENT_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    (!t.is_empty() && !t.bytes().all(|b| b == b'_')).then_some(t)
}

/// Parses one audit log line (see the module documentation).
///
/// # Errors
/// [`RecordError`].
pub fn parse_record(line: &[u8], zone: UtcOffset) -> Result<AuditRecord, RecordError> {
    let mut de = serde_json::Deserializer::from_slice(line);
    let raw = de
        .deserialize_any(RecordVisitor)
        .map_err(|_| RecordError::NotJson)?;
    de.end().map_err(|_| RecordError::NotJson)?;
    let raw = raw.ok_or(RecordError::NotJson)?;
    if raw.duplicate {
        return Err(RecordError::Invalid);
    }
    let action = raw
        .action
        .flatten()
        .and_then(|a| Action::from_name(&a))
        .ok_or(RecordError::Invalid)?;
    let when = match raw.when {
        Some(When::Text(t)) => parse_when(&t, zone),
        Some(When::Number(n)) => from_epoch(n),
        _ => None,
    }
    .ok_or(RecordError::Invalid)?;
    // `what` is read only for service-ticket issuance, then dropped
    // (zeroized) whatever the action.
    let what = raw.what.and_then(|w| w.text);
    let service = if action.issues_for_service() {
        what.as_deref().and_then(|w| service_of(w))
    } else {
        None
    };
    drop(what);
    let client = raw
        .client
        .flatten()
        .and_then(|c| c.trim().parse::<IpAddr>().ok())
        .map(crate::audit::events::canonical);
    let user_agent = raw.agent.flatten().and_then(|ua| first_token(&ua));
    Ok(AuditRecord {
        action,
        who: raw.who.flatten(),
        when,
        client,
        user_agent,
        service,
        headers_logged: raw.headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UTC: UtcOffset = UtcOffset(0);

    fn line(fields: &str) -> Vec<u8> {
        format!("{{{fields}}}").into_bytes()
    }

    #[test]
    fn a_service_ticket_record_is_reduced() {
        let r = parse_record(
            &line(
                r#""who": "jdoe", "what": "ST-1-FAKEfakeFAKE-cas01 for https://app.example.org/x?ticket=ST-2-FAKE",
                   "action": "SERVICE_TICKET_CREATED", "application": "CAS",
                   "when": "2026-10-04T12:00:00Z", "clientIpAddress": "192.0.2.10",
                   "serverIpAddress": "198.51.100.1", "userAgent": "Mozilla/5.0 (X11; Linux)",
                   "geoLocation": {"latitude": 1}, "tenant": "t""#,
            ),
            UTC,
        )
        .unwrap();
        assert_eq!(r.action, Action::ServiceTicketCreated);
        assert_eq!(r.who.as_deref().map(String::as_str), Some("jdoe"));
        assert_eq!(r.client, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(r.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(
            r.service.as_ref().map(ServiceHost::as_url).as_deref(),
            Some("https://app.example.org/")
        );
        assert!(!r.headers_logged);
        let dbg = format!("{r:?}");
        for leak in ["jdoe", "ST-", "example", "192.0"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
    }

    /// A CAS 8.0.2 `SERVICE_TICKET_CREATED` record: `what` is an object
    /// (ticket id masked by CAS here; `clear` puts it in clear).
    fn cas_802(ticket: &str) -> Vec<u8> {
        line(&format!(
            r#""who": "jdoe", "what": {{"service": "https://intranet.example.org/login?x=1",
                 "ticketId": "{ticket}"}},
               "action": "SERVICE_TICKET_CREATED", "application": "CAS",
               "when": "2026-10-04T12:00:00.123Z", "clientIpAddress": "192.0.2.10",
               "serverIpAddress": "198.51.100.1", "userAgent": "Mozilla/5.0 (X11; Linux)""#
        ))
    }

    #[test]
    fn an_object_what_names_its_service_only() {
        for ticket in [
            "ST-1-********************-cas01",
            "ST-1-FAKEclearTICKETvalue-cas01",
        ] {
            let r = parse_record(&cas_802(ticket), UTC).unwrap();
            assert_eq!(r.action, Action::ServiceTicketCreated);
            assert_eq!(
                r.service.as_ref().map(ServiceHost::as_url).as_deref(),
                Some("https://intranet.example.org/")
            );
            let dbg = format!("{r:?}");
            for leak in ["ST-", "FAKE", "cas01", "intranet", "jdoe"] {
                assert!(!dbg.contains(leak), "{leak}");
            }
        }
    }

    #[test]
    fn only_the_service_key_of_an_object_what_is_read() {
        let service = |what: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z", "what": {what}"#
                )),
                UTC,
            )
            .map(|r| r.service.as_ref().map(ServiceHost::as_url))
        };
        // Other keys (ticket ids, principals, credentials, nested values)
        // are skipped, wherever they are and whatever they hold.
        assert_eq!(
            service(
                r#"{"ticketId": "ST-1-FAKE for https://evil.example.net/",
                    "principal": {"id": "https://evil.example.net/", "attributes": {"mail": ["a@b.c"]}},
                    "credential": ["https://evil.example.net/"],
                    "service": "https://app.example.org/x", "extra": [[{"service": "https://evil.example.net/"}]]}"#
            ),
            Ok(Some("https://app.example.org/".to_owned()))
        );
        // No (string) service: no service, the record is kept.
        for what in [
            "null",
            "3",
            "true",
            r#"["https://app.example.org/"]"#,
            "{}",
            r#"{"ticketId": "ST-1-FAKE for https://app.example.org/"}"#,
            r#"{"service": null}"#,
            r#"{"service": {"id": "https://app.example.org/"}}"#,
            r#"{"Service": "https://app.example.org/"}"#,
        ] {
            assert_eq!(service(what), Ok(None), "{what}");
        }
        // A duplicate `service`, or `what` twice, drops the record.
        for what in [
            r#"{"service": "https://app.example.org/", "service": "https://evil.example.net/"}"#,
            r#"{"service": null, "service": "https://evil.example.net/"}"#,
            r#"{"service": "https://app.example.org/"}, "what": "https://evil.example.net/""#,
            r#""https://app.example.org/", "what": {"service": "https://evil.example.net/"}"#,
        ] {
            assert_eq!(service(what), Err(RecordError::Invalid), "{what}");
        }
        // Absent `what`.
        let r = parse_record(
            &line(r#""action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z""#),
            UTC,
        )
        .unwrap();
        assert!(r.service.is_none());
        // Skipped values are skipped without recursion (serde_json's
        // `IgnoredAny` path), so deep nesting (bounded by the tailer's line
        // cap) neither overflows the stack nor hides `service`.
        let nest = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
        for depth in [100, 100_000] {
            assert_eq!(
                service(&format!(
                    r#"{{"ticketId": {}, "service": "https://app.example.org/"}}"#,
                    nest(depth)
                )),
                Ok(Some("https://app.example.org/".to_owned()))
            );
        }
        // The `service` string is bounded like the string form.
        let long = format!("https://app.example.org/{}", "a".repeat(2 * MAX_WHAT_BYTES));
        assert_eq!(
            service(&format!(r#"{{"service": "{long}"}}"#)),
            Ok(Some("https://app.example.org/".to_owned()))
        );
    }

    #[test]
    fn an_object_what_is_ignored_for_other_actions() {
        let r = parse_record(
            &line(
                r#""who": "jdoe", "what": {"service": "https://app.example.org/", "ticketId": "TGT-1-FAKE"},
                   "action": "TICKET_GRANTING_TICKET_CREATED", "when": 1791115200000"#,
            ),
            UTC,
        )
        .unwrap();
        assert!(r.service.is_none());
    }

    #[test]
    fn what_is_ignored_for_other_actions() {
        let r = parse_record(
            &line(
                r#""who": "jdoe", "what": "https://app.example.org/ attrs={mail=jane@example.org}",
                   "action": "SERVICE_TICKET_VALIDATE_SUCCESS", "when": 1791115200000,
                   "headers": {"Cookie": "TGC=FAKE"}"#,
            ),
            UTC,
        )
        .unwrap();
        assert_eq!(
            r.action,
            Action::Other("SERVICE_TICKET_VALIDATE".to_owned())
        );
        assert!(r.service.is_none());
        assert!(r.headers_logged);
    }

    #[test]
    fn actions_are_closed() {
        let a = |n: &str| Action::from_name(n);
        assert_eq!(a("AUTHENTICATION_SUCCESS"), Some(Action::AuthSuccess));
        assert_eq!(a("AUTHENTICATION_FAILED"), Some(Action::AuthFailed));
        assert_eq!(a("SAVE_SERVICE_SUCCESS"), Some(Action::SaveService));
        assert_eq!(a("DELETE_SERVICE_SUCCESS"), Some(Action::DeleteService));
        assert_eq!(
            a("TICKET_GRANTING_TICKET_NOT_CREATED"),
            Some(Action::Other("TICKET_GRANTING_TICKET".to_owned()))
        );
        assert_eq!(a("_SUCCESS"), Some(Action::Other("_SUCCESS".to_owned())));
        for bad in [
            "",
            "authentication_success",
            "A B",
            "AUTH\u{0}",
            &"A".repeat(129),
        ] {
            assert_eq!(a(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn invalid_lines_are_dropped() {
        let ok = r#""action": "AUTHENTICATION_SUCCESS", "when": "2026-10-04T12:00:00Z""#;
        assert!(parse_record(&line(ok), UTC).is_ok());
        for (l, e) in [
            (
                line(&format!(r#"{ok}, "who": "a", "who": "admin""#)),
                RecordError::Invalid,
            ),
            (
                line(&format!(r#"{ok}, "action": "AUTHENTICATION_FAILED""#)),
                RecordError::Invalid,
            ),
            (line(&format!(r#"{ok}, "when": 1"#)), RecordError::Invalid),
            (
                line(r#""action": "AUTHENTICATION_SUCCESS""#),
                RecordError::Invalid,
            ),
            (
                line(r#""when": "2026-10-04T12:00:00Z""#),
                RecordError::Invalid,
            ),
            (
                line(r#""action": 3, "when": "2026-10-04T12:00:00Z""#),
                RecordError::Invalid,
            ),
            (
                line(r#""action": "AUTHENTICATION_SUCCESS", "when": "yesterday""#),
                RecordError::Invalid,
            ),
            (
                b"WHO: jdoe\nWHAT: TGT-1-FAKE".to_vec(),
                RecordError::NotJson,
            ),
            (
                b"2026-10-04 12:00:00 INFO {\"action\": \"X\"}".to_vec(),
                RecordError::NotJson,
            ),
            (format!("{{{ok}}} {{}}").into_bytes(), RecordError::NotJson),
            (b"[1, 2]".to_vec(), RecordError::NotJson),
            (b"".to_vec(), RecordError::NotJson),
        ] {
            assert_eq!(
                parse_record(&l, UTC).err(),
                Some(e),
                "{}",
                String::from_utf8_lossy(&l)
            );
        }
    }

    #[test]
    fn client_addresses_are_ip_literals_only() {
        let client = |c: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "AUTHENTICATION_SUCCESS", "when": "2026-10-04T12:00:00Z", "clientIpAddress": "{c}""#
                )),
                UTC,
            )
            .unwrap()
            .client
        };
        assert!(client("2001:db8::1").is_some());
        assert!(client(" 192.0.2.1 ").is_some());
        for bad in [
            "host.example.org",
            "192.0.2.1, 10.0.0.1",
            "192.0.2.1:443",
            "unknown",
            "",
        ] {
            assert_eq!(client(bad), None, "{bad}");
        }
    }

    #[test]
    fn user_agents_keep_a_sanitized_first_token() {
        let ua = |a: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "AUTHENTICATION_SUCCESS", "when": "2026-10-04T12:00:00Z", "userAgent": {a}"#
                )),
                UTC,
            )
            .unwrap()
            .user_agent
        };
        assert_eq!(
            ua(r#""python-requests/2.32.3 extra""#).as_deref(),
            Some("python-requests/2.32.3")
        );
        assert_eq!(
            ua(r#""curl/8.5.0;<script>\u0007é""#).as_deref(),
            Some("curl/8.5.0__script___")
        );
        assert_eq!(ua(r#""é€""#), None);
        assert_eq!(ua(r#""   ""#), None);
        assert_eq!(ua("3"), None);
        let long = ua(&format!("\"{}\"", "A".repeat(300))).unwrap();
        assert_eq!(long.len(), MAX_AGENT_CHARS);
    }

    #[test]
    fn who_is_bounded() {
        let who = "é".repeat(MAX_WHO_BYTES);
        let r = parse_record(
            &line(&format!(
                r#""action": "AUTHENTICATION_FAILED", "when": "2026-10-04T12:00:00Z", "who": "{who}""#
            )),
            UTC,
        )
        .unwrap();
        let w = r.who.unwrap();
        assert!(w.len() <= MAX_WHO_BYTES && w.chars().all(|c| c == 'é'));
    }
}
