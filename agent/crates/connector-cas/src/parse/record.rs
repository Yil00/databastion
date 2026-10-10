//! CAS JSON audit records (ADR-0041 decision 7, security review L3).
//!
//! One record per line, written by the CAS `Slf4j` audit destination with
//! `cas.audit.engine.audit-format: JSON`. The parser is a closed serde
//! visitor on the keys `who`, `what`, `action`, `when`, `clientIpAddress`,
//! `userAgent` and `serverIpAddress`; every other key (`application`,
//! `headers`, `geoLocation`, `tenant`, unknown keys) is skipped with
//! `IgnoredAny`, never kept (only the presence of `headers` is noted).
//! `serverIpAddress` is borrowed raw and decoded only for the token
//! request and response records, as an IP literal for their correlation
//! key (ADR-0044), never sent. **A record with a duplicate kept key is
//! dropped** (a duplicate `serverIpAddress` drops a token request or
//! response record only). A line that
//! is not one JSON object, or lacks a valid `action` or `when`, is dropped.
//!
//! `what` can hold a ticket id (a live SSO bearer credential). It is only
//! examined for an issuance action ([`Action::issues_for_service`]): for
//! any other action its raw text is borrowed from the line and never
//! decoded nor unescaped (a second `what` key still drops the record). It is a
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
//! `service`: they are skipped like `ticketId`. The token request
//! `OAUTH2_ACCESS_TOKEN_REQUEST_CREATED` (ADR-0044) gives no event either:
//! from its object-form `what` only the string values of `grant_type` and
//! `service` (the client id for the token-only grants) are read; `code`
//! (an authorization code or a refresh token id), `scope`,
//! `response_type`, unknown keys and nested values are skipped with
//! `IgnoredAny`, never copied; a duplicate `grant_type` or `service` drops
//! the record, and a string-form or non-object `what` gives no
//! [`TokenRequest`]. The other OAuth / OIDC actions
//! (`OAUTH2_AUTHORIZATION_RESPONSE_CREATED`, `OIDC_ID_TOKEN_CREATED`, whose
//! `what` holds the token request's headers, `OAUTH2_USER_PROFILE_CREATED`)
//! are counted per base and their `what` is never decoded.
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

use super::MAX_CLIENT_ID_BYTES;
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
    /// `OAUTH2_ACCESS_TOKEN_REQUEST_CREATED`: a token request (no event;
    /// ADR-0044: correlated with the next token response).
    TokenRequested,
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
            "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED" => Self::TokenRequested,
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

/// Longest `grant_type` compared, in bytes.
const MAX_GRANT_BYTES: usize = 32;

/// The `grant_type` of a token request (closed list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// `authorization_code`.
    AuthorizationCode,
    /// `refresh_token`.
    RefreshToken,
    /// `client_credentials`.
    ClientCredentials,
    /// `password`.
    Password,
    /// Any other value (the device grant included), or none.
    Other,
}

impl Grant {
    fn from_name(name: &str) -> Self {
        match name {
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            "client_credentials" => Self::ClientCredentials,
            "password" => Self::Password,
            _ => Self::Other,
        }
    }

    /// Whether the grant writes no service ticket: its token request's
    /// `service` is the client id (ADR-0044 decision 3).
    #[must_use]
    pub fn is_token_only(self) -> bool {
        matches!(
            self,
            Self::RefreshToken | Self::ClientCredentials | Self::Password
        )
    }
}

/// What is read from a token request's object-form `what` (ADR-0044
/// decision 1).
pub struct TokenRequest {
    /// `grant_type`.
    pub grant: Grant,
    /// `service` (the client id for the token-only grants), exact, at most
    /// [`MAX_CLIENT_ID_BYTES`] bytes (a longer one, or a value that is not
    /// a string, is `None`), zeroized. Reduced to a keyed tag by the
    /// event builder, then dropped with the record.
    pub client_id: Option<Zeroizing<String>>,
}

impl fmt::Debug for TokenRequest {
    // The client id is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

/// The correlation facts of a token request or response (ADR-0044): never
/// sent, reduced to a keyed tag by the event builder.
pub struct Correlation {
    /// `serverIpAddress` when it is one IP literal.
    pub server: Option<IpAddr>,
    /// The whole `userAgent` (bounded, zeroized).
    pub user_agent: Option<Zeroizing<String>>,
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
    /// For a token request with an object-form `what`: its grant and
    /// client id.
    pub token_request: Option<TokenRequest>,
    /// For a token request or response: the correlation facts.
    pub correlation: Option<Correlation>,
}

impl fmt::Debug for AuditRecord {
    // Principals, hosts, client ids and correlation facts are never
    // printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("action", &self.action)
            .field("when", &self.when)
            .field("headers_logged", &self.headers_logged)
            .field("token_request", &self.token_request)
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
    Server,
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
        "serverIpAddress" => K::Server,
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

/// The object form of a token request's `what` as read: `grant_type` and
/// `service` (each a string, or nothing for any other type), and whether
/// either came twice.
#[derive(Default)]
struct RequestWhat {
    grant: Option<Option<Zeroizing<String>>>,
    service: Option<Option<Zeroizing<String>>>,
    duplicate: bool,
}

/// Reads a token request's `what` from its raw text (ADR-0044 decision 1):
/// `Ok(None)` for a string-form or non-object `what`; `Err(Invalid)` for a
/// duplicate `grant_type` or `service`, `Err(NotJson)` for a kept value
/// that does not unescape.
fn token_request_of(raw: &RawValue) -> Result<Option<TokenRequest>, RecordError> {
    let text = raw.get();
    if text.as_bytes().first() != Some(&b'{') {
        return Ok(None);
    }
    let w = serde_json::Deserializer::from_str(text)
        .deserialize_map(RequestVisitor)
        .map_err(|_| RecordError::NotJson)?;
    if w.duplicate {
        return Err(RecordError::Invalid);
    }
    let grant = w
        .grant
        .flatten()
        .map_or(Grant::Other, |g| Grant::from_name(&g));
    let client_id = w
        .service
        .flatten()
        .filter(|c| !c.is_empty() && c.len() <= MAX_CLIENT_ID_BYTES);
    Ok(Some(TokenRequest { grant, client_id }))
}

/// The object form of a token request's `what`: only `grant_type` and
/// `service` are read; every other key (`code`, `scope`, `response_type`,
/// unknown keys) and value is skipped without being copied.
struct RequestVisitor;

impl<'de> Visitor<'de> for RequestVisitor {
    type Value = RequestWhat;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RequestWhat, A::Error> {
        let mut w = RequestWhat::default();
        while let Some(k) = map.next_key::<&'de RawValue>()? {
            let (slot, max) = match key_text::<A::Error>(k)?.as_str() {
                "grant_type" => (&mut w.grant, MAX_GRANT_BYTES + 1),
                // One byte more than compared: a longer client id is
                // recognized as such and selects nothing.
                "service" => (&mut w.service, MAX_CLIENT_ID_BYTES + 1),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    continue;
                }
            };
            let raw = map.next_value::<&'de RawValue>()?;
            let v = jtext::string(raw, max).map_err(refused)?;
            if slot.replace(v).is_some() {
                w.duplicate = true;
            }
        }
        Ok(w)
    }
}

/// `when`: a string or an epoch number.
enum When {
    Text(Zeroizing<String>),
    Number(i64),
    Other,
}

#[derive(Default)]
struct Raw<'de> {
    who: Option<Option<Zeroizing<String>>>,
    /// Kept raw (borrowed, not examined): reduced by [`what_of`] only for
    /// an issuance action, once the action is known.
    what: Option<&'de RawValue>,
    action: Option<Option<Zeroizing<String>>>,
    when: Option<When>,
    client: Option<Option<Zeroizing<String>>>,
    agent: Option<Option<Zeroizing<String>>>,
    /// Kept raw (borrowed, not examined): decoded only for a token request
    /// or response, once the action is known.
    server: Option<&'de RawValue>,
    /// `serverIpAddress` came twice: drops a token record only (the only
    /// ones it is read for; review of #182 L4).
    server_duplicate: bool,
    headers: bool,
    duplicate: bool,
}

/// The record object. Kept keys and values are taken as [`RawValue`]s
/// (borrowed from the line, never unescaped by `serde_json`, see
/// [`jtext`]); skipped values go through `IgnoredAny`.
struct RecordVisitor;

impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Raw<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an audit record")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw<'de>, A::Error> {
        let mut r = Raw::default();
        while let Some(k) = map.next_key::<&'de RawValue>()? {
            let k = record_key::<A::Error>(k)?;
            let slot = match k {
                K::Who => &mut r.who,
                K::What => {
                    let w = map.next_value::<&'de RawValue>()?;
                    if r.what.replace(w).is_some() {
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
                K::Server => {
                    let v = map.next_value::<&'de RawValue>()?;
                    if r.server.replace(v).is_some() {
                        r.server_duplicate = true;
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
    // `what` is read only for service-ticket or token issuance and for the
    // token request (for any other action its raw text is never examined),
    // then dropped (zeroized).
    let token_request = match raw.what {
        Some(w) if action == Action::TokenRequested => token_request_of(w)?,
        _ => None,
    };
    let service = match raw.what {
        Some(w) if action.issues_for_service() => {
            let w = what_of::<serde_json::Error>(w).map_err(|_| RecordError::NotJson)?;
            if w.duplicate {
                return Err(RecordError::Invalid);
            }
            w.text.as_deref().and_then(|t| service_of(t))
        }
        _ => None,
    };
    let client = raw
        .client
        .flatten()
        .and_then(|c| c.trim().parse::<IpAddr>().ok())
        .map(crate::audit::events::canonical);
    let agent = raw.agent.flatten();
    let user_agent = agent.as_deref().and_then(|ua| first_token(ua));
    // The correlation facts of the token request and response only
    // (ADR-0044): `serverIpAddress` is decoded here and nowhere else.
    let correlation = match action {
        Action::TokenRequested | Action::TokenIssued => {
            if raw.server_duplicate {
                return Err(RecordError::Invalid);
            }
            let server = match raw.server {
                Some(s) => jtext::string(s, 256)
                    .map_err(|_| RecordError::NotJson)?
                    .and_then(|s| s.trim().parse::<IpAddr>().ok())
                    .map(crate::audit::events::canonical),
                None => None,
            };
            Some(Correlation {
                server,
                user_agent: agent,
            })
        }
        _ => None,
    };
    Ok(AuditRecord {
        action,
        who: raw.who.flatten(),
        when,
        client,
        user_agent,
        service,
        headers_logged: raw.headers,
        token_request,
        correlation,
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
        assert!(r.token_request.is_none());
        let c = r.correlation.as_ref().unwrap();
        assert_eq!(c.server, Some("172.18.0.3".parse().unwrap()));
        assert_eq!(
            c.user_agent.as_deref().map(String::as_str),
            Some("python-requests/2.33.1")
        );
        let dbg = format!("{r:?}");
        for leak in ["FAKE", "eyJ", "jdoe", "Bearer", "172.18", "python"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
        // The other OAuth / OIDC actions are not issuance: their `what`
        // (codes, refresh tokens, the token request's HTTP headers) is
        // never read.
        for (action, base) in [
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
            assert!(r.token_request.is_none() && r.correlation.is_none());
        }
    }

    fn token_request(what: &str) -> Result<AuditRecord, RecordError> {
        parse_record(
            &line(&format!(
                r#""who": "audit:unknown", "what": {what},
                   "action": "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED", "when": 1791115200000,
                   "clientIpAddress": "192.0.2.1", "serverIpAddress": "198.51.100.3",
                   "userAgent": "python-requests/2.33.1 extra""#
            )),
            UTC,
        )
    }

    /// The token request (ADR-0044 decision 1): only `grant_type` and
    /// `service` are read from the object-form `what`.
    #[test]
    fn token_requests_read_grant_and_client_only() {
        let r = token_request(
            r#"{"code": "RT-1-FAKEclearREFRESH-cas01", "grant_type": "refresh_token",
                "service": "scratch-m2m", "scope": ["email", "openid"], "response_type": "none",
                "extra": {"service": "evil", "grant_type": "password"}}"#,
        )
        .unwrap();
        assert_eq!(r.action, Action::TokenRequested);
        assert!(!r.action.issues_for_service());
        assert!(r.service.is_none());
        let tr = r.token_request.as_ref().unwrap();
        assert_eq!(tr.grant, Grant::RefreshToken);
        assert_eq!(
            tr.client_id.as_deref().map(String::as_str),
            Some("scratch-m2m")
        );
        let c = r.correlation.as_ref().unwrap();
        assert_eq!(c.server, Some("198.51.100.3".parse().unwrap()));
        assert_eq!(
            c.user_agent.as_deref().map(String::as_str),
            Some("python-requests/2.33.1 extra")
        );
        let dbg = format!("{r:?}");
        for leak in ["FAKE", "RT-1", "scratch", "evil", "198.51", "openid"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
        let grant = |g: &str| {
            token_request(&format!(r#"{{"grant_type": {g}, "service": "c"}}"#))
                .unwrap()
                .token_request
                .unwrap()
                .grant
        };
        assert_eq!(grant(r#""client_credentials""#), Grant::ClientCredentials);
        assert_eq!(grant(r#""password""#), Grant::Password);
        assert_eq!(grant(r#""authorization_code""#), Grant::AuthorizationCode);
        assert_eq!(
            grant(r#""client\u005fcredentials""#),
            Grant::ClientCredentials
        );
        for other in [
            r#""urn:ietf:params:oauth:grant-type:device_code""#,
            r#""Password""#,
            r#""password ""#,
            "null",
            r#"["password"]"#,
        ] {
            assert_eq!(grant(other), Grant::Other, "{other}");
        }
        assert!(Grant::RefreshToken.is_token_only());
        assert!(Grant::ClientCredentials.is_token_only());
        assert!(Grant::Password.is_token_only());
        assert!(!Grant::AuthorizationCode.is_token_only());
        assert!(!Grant::Other.is_token_only());
        // A client id that is not a string, empty or too long: none.
        let client = |v: &str| {
            token_request(&format!(r#"{{"grant_type": "password", "service": {v}}}"#))
                .unwrap()
                .token_request
                .unwrap()
                .client_id
                .map(|c| c.len())
        };
        assert_eq!(client("3"), None);
        assert_eq!(client(r#""""#), None);
        assert_eq!(client(r#"{"id": "scratch-m2m"}"#), None);
        let max = "a".repeat(MAX_CLIENT_ID_BYTES);
        assert_eq!(client(&format!("\"{max}\"")), Some(MAX_CLIENT_ID_BYTES));
        assert_eq!(client(&format!("\"{max}a\"")), None);
        // A string-form or non-object `what` gives no token request.
        for what in [r#""N/A grant_type=password""#, "null", "[1]"] {
            assert!(
                token_request(what).unwrap().token_request.is_none(),
                "{what}"
            );
        }
        // A duplicate `grant_type` or `service` drops the record.
        for what in [
            r#"{"grant_type": "password", "grant_type": "refresh_token", "service": "c"}"#,
            r#"{"grant_type": "password", "service": "a", "s\u0065rvice": "b"}"#,
            r#"{"grant_type": "password", "service": null, "service": "b"}"#,
        ] {
            assert_eq!(
                token_request(what).err(),
                Some(RecordError::Invalid),
                "{what}"
            );
        }
        // A kept value that does not unescape drops the line; a skipped
        // one (`code`) is never decoded.
        assert_eq!(
            token_request(r#"{"grant_type": "password", "service": "\ud800"}"#).err(),
            Some(RecordError::NotJson)
        );
        assert!(
            token_request(r#"{"grant_type": "password", "code": "\ud800", "service": "c"}"#)
                .is_ok()
        );
    }

    /// `serverIpAddress` is decoded for the token request and response
    /// only; a second one drops those records only.
    #[test]
    fn server_addresses_are_read_for_token_records_only() {
        let rec = |action: &str, server: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "{action}", "when": 1791115200000, "serverIpAddress": {server}"#
                )),
                UTC,
            )
        };
        let server =
            |action: &str, v: &str| rec(action, v).unwrap().correlation.and_then(|c| c.server);
        for action in [
            "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED",
            "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED",
        ] {
            assert_eq!(
                server(action, r#""::ffff:198.51.100.3""#),
                Some("198.51.100.3".parse().unwrap())
            );
            for bad in [
                r#""cas01.example.org""#,
                r#""198.51.100.3:8443""#,
                "3",
                "null",
            ] {
                assert_eq!(server(action, bad), None, "{bad}");
            }
            assert_eq!(rec(action, r#""\udc00""#).err(), Some(RecordError::NotJson));
        }
        // Any other action: never decoded nor kept.
        let r = rec("SERVICE_TICKET_CREATED", r#""\udc00""#).unwrap();
        assert!(r.correlation.is_none());
        // A second `serverIpAddress` drops the token records only (review
        // of #182 L4).
        let twice = r#""198.51.100.3", "serverIpAddress": "198.51.100.4""#;
        for action in [
            "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED",
            "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED",
        ] {
            assert_eq!(
                rec(action, twice).err(),
                Some(RecordError::Invalid),
                "{action}"
            );
        }
        for action in [
            "AUTHENTICATION_SUCCESS",
            "SERVICE_TICKET_CREATED",
            "TICKET_GRANTING_TICKET_CREATED",
        ] {
            assert!(rec(action, twice).is_ok(), "{action}");
        }
    }

    /// For a non-issuance action `what` is never decoded: an escape that
    /// fails decoding (a lone surrogate) or a duplicate `service` inside it
    /// changes nothing, where an issuance action drops the line.
    #[test]
    fn what_is_not_decoded_for_other_actions() {
        let rec = |action: &str, what: &str| {
            parse_record(
                &line(&format!(
                    r#""action": "{action}", "when": 1791115200000, "what": {what}"#
                )),
                UTC,
            )
            .map(|r| r.service.is_some())
        };
        for what in [
            r#"{"service": "https:\/\/app.example.org\/\ud800"}"#,
            r#""https:\/\/app.example.org\/\udc00""#,
        ] {
            assert_eq!(
                rec("TICKET_GRANTING_TICKET_CREATED", what),
                Ok(false),
                "{what}"
            );
            assert_eq!(
                rec("SERVICE_TICKET_VALIDATE_SUCCESS", what),
                Ok(false),
                "{what}"
            );
            assert_eq!(
                rec("SERVICE_TICKET_CREATED", what),
                Err(RecordError::NotJson),
                "{what}"
            );
        }
        let dup =
            r#"{"service": "https://app.example.org/", "service": "https://evil.example.net/"}"#;
        assert_eq!(rec("AUTHENTICATION_SUCCESS", dup), Ok(false));
        assert_eq!(
            rec("SERVICE_TICKET_CREATED", dup),
            Err(RecordError::Invalid)
        );
        assert_eq!(
            rec("OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED", dup),
            Err(RecordError::Invalid)
        );
        // A second `what` key drops the record whatever the action.
        for action in ["AUTHENTICATION_SUCCESS", "SERVICE_TICKET_CREATED"] {
            assert_eq!(
                rec(
                    action,
                    r#""x", "what": {"service": "https://app.example.org/"}"#
                ),
                Err(RecordError::Invalid),
                "{action}"
            );
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
            a("OAUTH2_ACCESS_TOKEN_REQUEST_CREATED"),
            Some(Action::TokenRequested)
        );
        assert_eq!(
            a("OAUTH2_ACCESS_TOKEN_REQUEST_FAILED"),
            Some(Action::Other("OAUTH2_ACCESS_TOKEN_REQUEST".to_owned()))
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
