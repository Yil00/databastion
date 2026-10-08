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
//! scheme and host **for service-ticket or token issuance only**
//! ([`super::url::service_of`]) and dropped. Nothing else of it is kept.
//!
//! OAuth 2.0 / OIDC (verified against CAS 8.0.2): the token endpoint's
//! issuance is `OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED`, whose `what` holds
//! the token values (`access_token`, `refresh_token`, `id_token`) and no
//! `service`: they are skipped like `ticketId`. The other OAuth / OIDC
//! actions (`OAUTH2_AUTHORIZATION_RESPONSE_CREATED`,
//! `OAUTH2_ACCESS_TOKEN_REQUEST_CREATED`, `OIDC_ID_TOKEN_CREATED`,
//! `OAUTH2_USER_PROFILE_CREATED`) are counted per base and give no event.
//!
//! **No unzeroized copy of a kept string** (ROADMAP phase 8 follow-up).
//! The caller holds the line in a zeroizing buffer. Kept keys and values
//! are taken as `serde_json` raw values, borrowed from the line, and
//! unescaped by [`super::jtext`] into zeroizing buffers allocated once:
//! `serde_json` never unescapes them into its private scratch buffer (which
//! is not wiped). A line whose first byte (after white space) is not `{` is
//! refused before parsing. Raw values are UTF-8 checked as a whole, so a
//! kept key whose value (even a skipped non-string one, such as an object
//! `what`) holds invalid UTF-8 drops the line (`NotJson`); CAS writes UTF-8.
//!
//! The `DEFAULT` (`WHO: … WHAT: …`) format is not supported (ADR-0041 open
//! question 6, confirmed: JSON is required).

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::jtext::{self, Invalid, Scalar};
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
    /// `OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED`: the OAuth 2.0 / OIDC token
    /// endpoint issued tokens (every grant type; verified against CAS
    /// 8.0.2: `who` is the user, or the client id for `client_credentials`,
    /// and `what` holds the token values and no service).
    TokenIssued,
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
            "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED" => Self::TokenIssued,
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

    /// Whether the record issues a ticket or token for a service
    /// (ADR-0041 decisions 7 and 10): a service ticket, or tokens from the
    /// OAuth 2.0 / OIDC token endpoint.
    #[must_use]
    pub fn issues_for_service(&self) -> bool {
        matches!(self, Self::ServiceTicketCreated | Self::TokenIssued)
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

/// Longest key compared, in bytes: a longer key is none of the kept ones.
const MAX_KEY_BYTES: usize = 32;

/// A deserialization error that carries none of the input.
fn refused<E: de::Error>(_: Invalid) -> E {
    E::custom("invalid JSON string")
}

/// The text of a key, unescaped by [`jtext`] (bounded, zeroized).
fn key_text<E: de::Error>(raw: &RawValue) -> Result<Zeroizing<String>, E> {
    jtext::unescape(raw.get(), MAX_KEY_BYTES + 1).map_err(refused)
}

fn record_key<E: de::Error>(raw: &RawValue) -> Result<K, E> {
    Ok(match key_text::<E>(raw)?.as_str() {
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

/// `what`: the text to reduce (the string form, or the `service` string of
/// the object form; bounded, zeroized), and whether the object form had a
/// duplicate `service`.
struct What {
    text: Option<Zeroizing<String>>,
    duplicate: bool,
}

/// Reads `what` from its raw text: a string is unescaped by [`jtext`]; an
/// object is parsed again from the same borrowed text by [`WhatVisitor`];
/// any other JSON type names no service.
fn what_of<E: de::Error>(raw: &RawValue) -> Result<What, E> {
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'"') => Ok(What {
            text: Some(jtext::unescape(text, MAX_WHAT_BYTES).map_err(refused)?),
            duplicate: false,
        }),
        Some(b'{') => serde_json::Deserializer::from_str(text)
            .deserialize_map(WhatVisitor)
            .map_err(|_| E::custom("invalid what")),
        _ => Ok(What {
            text: None,
            duplicate: false,
        }),
    }
}

/// The object form of `what`: only `service` is read (a string, or nothing
/// for any other type); every other key and value is skipped without being
/// copied.
struct WhatVisitor;

impl<'de> Visitor<'de> for WhatVisitor {
    type Value = What;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<What, A::Error> {
        let mut service: Option<Option<Zeroizing<String>>> = None;
        let mut duplicate = false;
        while let Some(k) = map.next_key::<&'de RawValue>()? {
            if key_text::<A::Error>(k)?.as_str() == "service" {
                let raw = map.next_value::<&'de RawValue>()?;
                let v = jtext::string(raw, MAX_WHAT_BYTES).map_err(refused)?;
                if service.replace(v).is_some() {
                    duplicate = true;
                }
            } else {
                map.next_value::<IgnoredAny>()?;
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

/// The record object. Kept keys and values are taken as [`RawValue`]s
/// (borrowed from the line, never unescaped by `serde_json`, see
/// [`jtext`]); skipped values go through `IgnoredAny`.
struct RecordVisitor;

impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Raw;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an audit record")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
        let mut r = Raw::default();
        while let Some(k) = map.next_key::<&'de RawValue>()? {
            let k = record_key::<A::Error>(k)?;
            let slot = match k {
                K::Who => &mut r.who,
                K::What => {
                    let w = what_of::<A::Error>(map.next_value::<&'de RawValue>()?)?;
                    if w.duplicate || r.what.replace(w).is_some() {
                        r.duplicate = true;
                    }
                    continue;
                }
                K::Action => &mut r.action,
                K::Client => &mut r.client,
                K::Agent => &mut r.agent,
                K::When => {
                    let raw = map.next_value::<&'de RawValue>()?;
                    let w = match jtext::scalar(raw, 64).map_err(refused)? {
                        Scalar::Str(s) => When::Text(s),
                        Scalar::Int(n) => When::Number(n),
                        Scalar::Other => When::Other,
                    };
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
            let raw = map.next_value::<&'de RawValue>()?;
            let v = jtext::string(raw, max).map_err(refused)?;
            if slot.replace(v).is_some() {
                r.duplicate = true;
            }
        }
        Ok(r)
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
    // Only an object is a record: anything else (a JSON string included,
    // whose escapes `serde_json` would unescape into its own buffer) is
    // refused before it is parsed.
    let first = line
        .iter()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    if first != Some(&b'{') {
        return Err(RecordError::NotJson);
    }
    let mut de = serde_json::Deserializer::from_slice(line);
    let raw = de
        .deserialize_map(RecordVisitor)
        .map_err(|_| RecordError::NotJson)?;
    de.end().map_err(|_| RecordError::NotJson)?;
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
    // `what` is read only for service-ticket or token issuance, then dropped
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

    /// Escaped strings (no unzeroized `serde_json` copy, [`super::jtext`])
    /// parse as before: in the object-form `service`, the string form, the
    /// kept keys and the other kept values.
    #[test]
    fn escaped_strings_parse_as_before() {
        let service = |what: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z", "what": {what}"#
                )),
                UTC,
            )
            .map(|r| r.service.as_ref().map(ServiceHost::as_url))
        };
        let app = Ok(Some("https://app.example.org/".to_owned()));
        for what in [
            r#"{"service": "https:\/\/app.example.org\/x?ticket=ST-1-FAKE"}"#,
            r#"{"service": "\u0068ttps://app.example.org/", "ticketId": "ST-1-\u0046AKE"}"#,
            r#"{"serv\u0069ce": "https://app.example.org/"}"#,
            r#""ST-1-FAKE for https:\/\/app.example.org\/x""#,
            r#""ST-1-FAKE for \u0068ttps://app.example.\u006frg/""#,
        ] {
            assert_eq!(service(what), app, "{what}");
        }
        // An escaped duplicate `service` is still a duplicate.
        assert_eq!(
            service(
                r#"{"service": "https://app.example.org/", "s\u0065rvice": "https://evil.example.net/"}"#
            ),
            Err(RecordError::Invalid)
        );
        // A lone surrogate in a kept string drops the line, as before.
        assert_eq!(
            service(r#"{"service": "https://app.example.org/\ud800"}"#),
            Err(RecordError::NotJson)
        );
        assert_eq!(
            service(r#""https://app.example.org/\udc00""#),
            Err(RecordError::NotJson)
        );
        // ... but not in a skipped one (serde_json only skips it).
        assert_eq!(
            service(r#"{"service": "https://app.example.org/", "ticketId": "\ud800"}"#),
            app
        );
        let r = parse_record(
            &line(
                r#""w\u0068o": "j\u00e9r\u00f4me", "\u0061ction": "AUTHENTICATION_\u0053UCCESS",
                   "when": "2026\u002d10-04T12:00:00Z", "clientIpAddress": "192.0.2.\u0031",
                   "userAgent": "curl\/8.5.0""#,
            ),
            UTC,
        )
        .unwrap();
        assert_eq!(r.action, Action::AuthSuccess);
        assert_eq!(r.who.as_deref().map(String::as_str), Some("jérôme"));
        assert_eq!(r.client, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(r.user_agent.as_deref(), Some("curl/8.5.0"));
        assert_eq!(
            parse_record(
                &line(
                    r#""who": "a", "w\u0068o": "b", "action": "AUTHENTICATION_SUCCESS", "when": 1"#
                ),
                UTC
            )
            .err(),
            Some(RecordError::Invalid)
        );
    }

    #[test]
    fn only_objects_are_records() {
        for l in [
            &br#""{\"action\": \"AUTHENTICATION_SUCCESS\", \"when\": 1}""#[..],
            b" \t\r\n[{}]",
            b"1",
            b"null",
            b"  ",
        ] {
            assert_eq!(
                parse_record(l, UTC).err(),
                Some(RecordError::NotJson),
                "{}",
                String::from_utf8_lossy(l)
            );
        }
        assert!(
            parse_record(
                b" \r\n\t{\"action\": \"AUTHENTICATION_SUCCESS\", \"when\": 1791115200000}",
                UTC
            )
            .is_ok()
        );
    }

    #[test]
    fn token_responses_are_issuance_without_token_values() {
        // CAS 8.0.2 `OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED` (token values
        // masked by CAS there; in clear here: never read either way).
        let r = parse_record(
            &line(
                r#""who": "jdoe", "what": {"access_token": "AT-1-FAKEclearTOKEN-cas01",
                   "refresh_token": "RT-1-FAKEclearTOKEN-cas01", "id_token": "eyJFAKE.eyJFAKE.FAKE",
                   "scope": "openid email", "token_type": "Bearer", "expires_in": "28800"},
                   "action": "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED",
                   "when": "2026-10-08T11:46:43.332813548", "clientIpAddress": "172.18.0.1",
                   "serverIpAddress": "172.18.0.3", "userAgent": "python-requests/2.33.1""#,
            ),
            UTC,
        )
        .unwrap();
        assert_eq!(r.action, Action::TokenIssued);
        assert!(r.action.issues_for_service());
        assert!(r.service.is_none());
        let dbg = format!("{r:?}");
        for leak in ["FAKE", "eyJ", "jdoe", "Bearer"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
        // The other OAuth / OIDC actions are not issuance: their `what`
        // (codes, refresh tokens, the token request's HTTP headers) is
        // never read.
        for (action, base) in [
            (
                "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED",
                "OAUTH2_ACCESS_TOKEN_REQUEST",
            ),
            ("OIDC_ID_TOKEN_CREATED", "OIDC_ID_TOKEN"),
            (
                "OAUTH2_AUTHORIZATION_RESPONSE_CREATED",
                "OAUTH2_AUTHORIZATION_RESPONSE",
            ),
            ("OAUTH2_USER_PROFILE_CREATED", "OAUTH2_USER_PROFILE"),
        ] {
            let r = parse_record(
                &line(&format!(
                    r#""who": "audit:unknown", "what": {{"service": "https://app.example.org/cb", "code": "OC-1-FAKE"}},
                       "action": "{action}", "when": 1791115200000"#
                )),
                UTC,
            )
            .unwrap();
            assert_eq!(r.action, Action::Other(base.to_owned()));
            assert!(r.service.is_none());
        }
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
            a("OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED"),
            Some(Action::TokenIssued)
        );
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
