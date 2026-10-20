//! HTTPS uplink to the console (ADR-0001). Crate-private.
//!
//! - The agent is always the client; nothing here listens (I1).
//! - reqwest with rustls only (`rustls-tls-native-roots`, `ring` crypto
//!   provider), **TLS 1.3 minimum**, no redirects (the `Authorization`
//!   header is never replayed to another origin), bounded timeouts and a
//!   bounded response size. Plain `http://` is only possible for the
//!   loopback development exception validated by `config`.
//! - Headers per contract: `X-DataBastion-Protocol`, `User-Agent`, and,
//!   except for `/enroll`, `Authorization` (marked sensitive) and
//!   `X-DataBastion-Agent-Id`.
//! - Request and response bodies are never logged. Error bodies are parsed
//!   with the generated `Error` type and only their closed `code` and the
//!   `pointer` / `keyword` of `details` are logged.
//! - Findings and events are only accepted as masked types (I2, ADR-0003):
//!   [`to_batches`] is the single conversion from `MaskedFinding` /
//!   `MaskedEvent` to `FindingsBatch` / `EventsBatch`, with per-item
//!   sanitization (ADR-0009) and the 1 MiB / `maxItems` caps.

use std::time::Duration;

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};
use databastion_protocol::{
    AccessEvent, AgentSecret, ClassifierId as ProtoClassifierId, ClassifiersVersion, Count, Engine,
    ErrorCode, EventsBatch, Finding, FindingsBatch, Fingerprint as ProtoFingerprint, Identifier,
    Location, MaskedSample as ProtoMaskedSample, TargetId, Uuid, UuidV7, new_batch_id,
};
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};

use crate::backoff;
use crate::config::AgentConfig;
use crate::sanitize;

/// Protocol major version spoken by this agent.
pub(crate) const PROTOCOL_VERSION: &str = "1";
/// Default request timeout.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body read (bodies are small JSON documents).
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// `User-Agent`, as required by the contract.
pub(crate) fn user_agent() -> String {
    format!("databastion-agent/{}", env!("CARGO_PKG_VERSION"))
}

/// Uplink errors. They carry no request or response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UplinkError {
    /// Client construction failed (TLS / CA file).
    #[error("uplink setup failed: {0}")]
    Setup(&'static str),
    /// Network error or timeout; retryable.
    #[error("network error ({0})")]
    Transport(&'static str),
    /// `401`.
    #[error("unauthorized (401)")]
    Unauthorized,
    /// `426`: the console requires a newer protocol.
    #[error("protocol upgrade required (426), console minimum protocol {min_protocol:?}")]
    UpgradeRequired { min_protocol: Option<u64> },
    /// `429` / `503`, and `501` on `/findings` / `/events` (endpoint not
    /// implemented by this console, `code` `unavailable`); retryable,
    /// honoring `Retry-After` (parsed and clamped to `1..=3600` s). A `501`
    /// parks that endpoint only (docs/09, "Agent handling"); on any other
    /// path it is a [`UplinkError::Server`] error.
    #[error("console throttled the request ({status})")]
    Throttled {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Other `5xx`; retryable.
    #[error("console error ({status})")]
    Server { status: u16 },
    /// Non-retryable `4xx` (other than 401 / 426 / 429).
    /// `unknown_field`: a `details[].keyword` is `additionalProperties`,
    /// what a console built before an optional field answers to a body
    /// carrying it (docs/09, ADR-0022).
    #[error("request rejected ({status}, code {code:?})")]
    Rejected {
        status: u16,
        code: Option<ErrorCode>,
        unknown_field: bool,
    },
    /// `400` / `404` on `/findings` or `/events` whose `details` all point at
    /// items: the (deduplicated, sorted) indices of the rejected items, and
    /// among them those pointed at with the keyword `additionalProperties`
    /// (`unknown_field`, sorted) and with the keyword `enum`
    /// (`unknown_value`, sorted: what a console built before an engine
    /// value answers, ADR-0039 decision 8), and with the keyword `contains`
    /// on the item's `objects` or `if` on the item itself (`overflow_rule`,
    /// sorted: the contract rule that an event carrying
    /// `objects_overflowed` names a `*`, ADR-0053 decision 1 item 3).
    #[error("batch items rejected ({status}, {} items)", items.len())]
    ItemsRejected {
        status: u16,
        items: Vec<usize>,
        unknown_field: Vec<usize>,
        unknown_value: Vec<usize>,
        overflow_rule: Vec<usize>,
    },
    /// Unexpected status or undecodable body.
    #[error("unexpected response ({status})")]
    UnexpectedResponse { status: u16 },
}

impl UplinkError {
    /// Whether retrying the same request later may succeed.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport(_) | Self::Throttled { .. } | Self::Server { .. }
        )
    }

    /// Delay before retry `attempt` (0-based), honoring `Retry-After`.
    pub(crate) fn retry_delay(&self, attempt: u32) -> Duration {
        match self {
            Self::Throttled {
                retry_after: Some(ra),
                ..
            } => backoff::retry_after_delay(*ra, backoff::random_fraction()),
            _ => backoff::Backoff::CONSOLE.delay(attempt, backoff::random_fraction()),
        }
    }
}

/// How a request is authenticated.
#[derive(Clone, Copy)]
pub(crate) enum Auth<'a> {
    /// `POST /enroll` only.
    Anonymous,
    /// Agent secret and id.
    Agent {
        agent_id: &'a Uuid,
        secret: &'a AgentSecret,
    },
}

/// A successful response: status and body (never logged).
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
    /// Whether the `Content-Type` media type is `application/json`.
    pub(crate) json: bool,
}

/// Whether a `Content-Type` value has the `application/json` media type
/// (parameters such as `charset` are ignored).
fn is_json_media_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

/// Per-endpoint acceptance of a `2xx` reply (contract status, media type
/// and body). A reply is only acted upon, and a pending secret only
/// promoted, once its checker accepts it: a middlebox's `200` page proves
/// nothing (see `Session::call`).
pub(crate) mod accept {
    use databastion_protocol::{BatchAck, HeartbeatResponse, RotateResponse, UuidV7};
    use reqwest::StatusCode;

    use super::Reply;
    use crate::jobs::{self, PolledList};

    fn json<T: serde::de::DeserializeOwned>(reply: &Reply, status: StatusCode) -> Option<T> {
        if reply.status != status || !reply.json {
            return None;
        }
        serde_json::from_slice(&reply.body).ok()
    }

    /// `POST /heartbeat`: `200` + `HeartbeatResponse`.
    pub(crate) fn heartbeat(reply: &Reply) -> Option<HeartbeatResponse> {
        json(reply, StatusCode::OK)
    }

    /// `POST /rotate`: `200` + `RotateResponse`.
    pub(crate) fn rotate(reply: &Reply) -> Option<RotateResponse> {
        json(reply, StatusCode::OK)
    }

    /// `POST /findings`, `POST /events`: `202` + `BatchAck` for `batch_id`.
    pub(crate) fn batch_ack(batch_id: UuidV7) -> impl Fn(&Reply) -> Option<BatchAck> {
        move |reply| {
            json::<BatchAck>(reply, StatusCode::ACCEPTED).filter(|a| a.batch_id == batch_id)
        }
    }

    /// `GET /jobs`: `204` (no job, `None`) or `200` + a job list.
    pub(crate) fn job_list(reply: &Reply) -> Option<Option<PolledList>> {
        if reply.status == StatusCode::NO_CONTENT {
            return Some(None);
        }
        if reply.status != StatusCode::OK || !reply.json {
            return None;
        }
        jobs::parse_job_list(&reply.body).ok().map(Some)
    }

    /// `POST /jobs/{id}/status`: exactly `204`.
    pub(crate) fn no_content(reply: &Reply) -> Option<()> {
        (reply.status == StatusCode::NO_CONTENT).then_some(())
    }
}

/// Client towards the console agent API.
#[derive(Debug, Clone)]
pub(crate) struct Uplink {
    http: reqwest::Client,
    base: reqwest::Url,
}

impl Uplink {
    /// Builds the client from the validated configuration.
    pub(crate) fn new(config: &AgentConfig) -> Result<Self, UplinkError> {
        let base = config
            .console_url()
            .map_err(|_| UplinkError::Setup("invalid console.url"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-databastion-protocol",
            HeaderValue::from_static(PROTOCOL_VERSION),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .https_only(!config.console.insecure_dev_http)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(REQUEST_TIMEOUT)
            .user_agent(user_agent())
            .default_headers(headers);
        if config.console.insecure_dev_http {
            // Loopback development console: never through a proxy.
            builder = builder.no_proxy();
        }
        if let Some(ca_file) = &config.console.ca_file {
            let pem =
                std::fs::read(ca_file).map_err(|_| UplinkError::Setup("cannot read ca_file"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| UplinkError::Setup("ca_file is not a PEM certificate bundle"))?;
            if certs.is_empty() {
                return Err(UplinkError::Setup("ca_file contains no certificate"));
            }
            // Pinning: the configured CA bundle holds the only trusted roots.
            builder = builder.tls_built_in_root_certs(false);
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|_| UplinkError::Setup("cannot build the HTTPS client"))?;
        Ok(Self { http, base })
    }

    fn url(&self, path: &str) -> reqwest::Url {
        let mut url = self.base.clone();
        url.set_path(&format!("{}{path}", self.base.path()));
        url
    }

    /// Sends one request. Returns the reply on `2xx`; maps every other
    /// status to an [`UplinkError`]. No retry here.
    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        auth: Auth<'_>,
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Reply, UplinkError> {
        let mut request = self.http.request(method, self.url(path)).timeout(timeout);
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Auth::Agent { agent_id, secret } = auth {
            // The temporary string is zeroized and allocated once at its
            // final length (`format!` grows its buffer, leaving freed
            // copies); the header value itself is an immutable `Bytes`
            // that reqwest owns and drops after the request (not
            // zeroizable), as is the request body.
            let mut bearer = zeroize::Zeroizing::new(String::with_capacity(
                "Bearer ".len() + secret.expose().len(),
            ));
            bearer.push_str("Bearer ");
            bearer.push_str(secret.expose());
            let mut value = HeaderValue::from_str(&bearer)
                .map_err(|_| UplinkError::Setup("invalid secret header"))?;
            value.set_sensitive(true);
            let id = HeaderValue::from_str(&agent_id.to_string())
                .map_err(|_| UplinkError::Setup("invalid agent id header"))?;
            request = request
                .header(header::AUTHORIZATION, value)
                .header("x-databastion-agent-id", id);
        }
        if let Some(body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request.send().await.map_err(|e| transport(&e))?;
        let status = response.status();
        let json = is_json_media_type(response.headers().get(header::CONTENT_TYPE));
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(backoff::parse_retry_after);
        let body = read_limited(response).await?;
        if status.is_success() {
            return Ok(Reply { status, body, json });
        }
        Err(classify(path, status, retry_after, &body))
    }
}

fn transport(e: &reqwest::Error) -> UplinkError {
    // The error's Display can include the URL; only its kind is kept.
    UplinkError::Transport(if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_body() || e.is_decode() {
        "body"
    } else {
        "request"
    })
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, UplinkError> {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| transport(&e))? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(UplinkError::UnexpectedResponse { status });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The keyword a closed schema reports for a field it does not know: what
/// a console built before an optional field answers (docs/09).
const UNKNOWN_FIELD_KEYWORD: &str = "additionalProperties";

/// Whether a detail reports an unknown field.
fn is_unknown_field(d: &databastion_protocol::ErrorDetail) -> bool {
    d.keyword.as_str() == UNKNOWN_FIELD_KEYWORD
}

/// The keyword a closed enum reports for a value it does not know: what a
/// console built before an engine value answers (ADR-0039 decision 8).
const UNKNOWN_VALUE_KEYWORD: &str = "enum";

/// The field of an item that carries its engine value: `Location.engine`
/// of a finding, `AccessEvent.source` of an event (ADR-0042). An `enum`
/// detail counts as an unknown engine value only on exactly that field: the
/// console also answers `enum` for, e.g., an unregistered classifier
/// (`/findings/<i>/classifier`), which no later listing of a token cures.
fn engine_field(prefix: &str) -> &'static str {
    if prefix == "/findings/" {
        "location/engine"
    } else {
        "source"
    }
}

/// The keywords a console reports when an event carrying
/// `objects_overflowed` names no `*` (ADR-0053 decision 1 item 3): `contains`
/// on `/events/<i>/objects`, and `if` on `/events/<i>` (the `if` / `then`
/// rule that holds it).
const OVERFLOW_RULE_KEYWORDS: [(&str, &str); 2] = [("contains", "objects"), ("if", "")];

/// Item indices pointed at by `details`, and those of them pointed at with
/// the keywords `additionalProperties` and `enum`, and with the keywords of
/// the overflow rule (each sorted, deduplicated).
#[derive(Debug, Default, PartialEq, Eq)]
struct Pointed {
    items: Vec<usize>,
    unknown_field: Vec<usize>,
    unknown_value: Vec<usize>,
    overflow_rule: Vec<usize>,
}

/// Indices of the items designated by every `details[].pointer`, when all
/// of them point inside `/findings/<i>` or `/events/<i>` (docs/09), and
/// those of them pointed at with the keywords `additionalProperties` and
/// `enum`. `None` if any pointer targets the envelope, or if there is no
/// detail.
fn item_pointers(path: &str, error: &databastion_protocol::Error) -> Option<Pointed> {
    let prefix = match path {
        "/findings" => "/findings/",
        "/events" => "/events/",
        _ => return None,
    };
    if error.details.is_empty() {
        return None;
    }
    let mut p = Pointed {
        items: Vec::with_capacity(error.details.len()),
        ..Pointed::default()
    };
    for d in &error.details {
        let rest = d.pointer.as_str().strip_prefix(prefix)?;
        let (index, field) = rest.split_once('/').unwrap_or((rest, ""));
        let index = index.parse::<usize>().ok()?;
        p.items.push(index);
        if is_unknown_field(d) {
            p.unknown_field.push(index);
        }
        if d.keyword.as_str() == UNKNOWN_VALUE_KEYWORD && field == engine_field(prefix) {
            p.unknown_value.push(index);
        }
        if prefix == "/events/" && OVERFLOW_RULE_KEYWORDS.contains(&(d.keyword.as_str(), field)) {
            p.overflow_rule.push(index);
        }
    }
    for v in [
        &mut p.items,
        &mut p.unknown_field,
        &mut p.unknown_value,
        &mut p.overflow_rule,
    ] {
        v.sort_unstable();
        v.dedup();
    }
    Some(p)
}

/// The result endpoints, which a `501` parks.
fn is_result_path(path: &str) -> bool {
    matches!(path, "/findings" | "/events")
}

/// Maps a non-2xx response. Logs only the closed error code and the
/// `pointer` / `keyword` of the details, never the body.
fn classify(
    path: &str,
    status: StatusCode,
    retry_after: Option<Duration>,
    body: &[u8],
) -> UplinkError {
    let error = serde_json::from_slice::<databastion_protocol::Error>(body).ok();
    let code = error.as_ref().map(|e| e.code);
    let unknown_field = error
        .as_ref()
        .is_some_and(|e| e.details.iter().any(is_unknown_field));
    if let Some(error) = &error {
        let details: Vec<String> = error
            .details
            .iter()
            .take(8)
            .map(|d| format!("{}:{}", d.pointer.as_str(), d.keyword.as_str()))
            .collect();
        tracing::warn!(
            path,
            status = status.as_u16(),
            code = %error.code,
            ?details,
            "console rejected the request"
        );
    } else {
        tracing::warn!(
            path,
            status = status.as_u16(),
            "console returned an error without a valid error body"
        );
    }
    let status = status.as_u16();
    match status {
        401 => UplinkError::Unauthorized,
        426 => UplinkError::UpgradeRequired {
            min_protocol: error.and_then(|e| e.min_protocol).map(|p| p.0.get()),
        },
        429 | 503 => UplinkError::Throttled {
            status,
            retry_after,
        },
        // `501` parks a result endpoint (docs/09). Elsewhere it stays a
        // plain server error, retried within the caller's normal bound: a
        // long `Retry-After` must not silence heartbeats or job polls.
        501 if is_result_path(path) => UplinkError::Throttled {
            status,
            retry_after,
        },
        500..=599 => UplinkError::Server { status },
        400 | 404 => match error.as_ref().and_then(|e| item_pointers(path, e)) {
            Some(p) => UplinkError::ItemsRejected {
                status,
                items: p.items,
                unknown_field: p.unknown_field,
                unknown_value: p.unknown_value,
                overflow_rule: p.overflow_rule,
            },
            None => UplinkError::Rejected {
                status,
                code,
                unknown_field,
            },
        },
        400..=499 => UplinkError::Rejected {
            status,
            code,
            unknown_field,
        },
        _ => UplinkError::UnexpectedResponse { status },
    }
}

// ------------------------------------------------------------- result batches

/// Contract `x-databastion-max-bytes` of `FindingsBatch` / `EventsBatch`.
pub(crate) const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Contract `maxItems` of `FindingsBatch.findings`.
pub(crate) const MAX_FINDINGS_PER_BATCH: usize = 200;
/// Contract `maxItems` of `EventsBatch.events`.
pub(crate) const MAX_EVENTS_PER_BATCH: usize = 500;

/// A findings or events batch, as spooled and sent. Opaque: its only
/// constructors are [`to_batches`] (from masked types), [`ResultBatch::parse`]
/// (a spooled body, validated against the generated types and then kept
/// **verbatim**), and the splitting helpers [`ResultBatch::without`] /
/// [`ResultBatch::halves`].
#[derive(Debug, Clone)]
pub(crate) struct ResultBatch {
    findings: bool,
    batch_id: UuidV7,
    len: usize,
    bytes: Vec<u8>,
    /// An events batch holding a `signature.*` signal (kept first by the
    /// spool when it is full).
    signature: bool,
    /// Capability tokens of the engine values its items carry (ADR-0039
    /// decision 8; sorted, deduplicated, usually empty): the batch is held
    /// until the console lists every one.
    gates: Vec<&'static str>,
    /// Capability tokens of the gated fields its items carry (ADR-0022,
    /// ADR-0053 decision 2; sorted, deduplicated): the batch is spooled with
    /// them and they are stripped at send time unless the console lists
    /// them ([`for_console`](ResultBatch::for_console)).
    fields: Vec<&'static str>,
    /// Its gated-engine items were already kept once after a `400` `enum`
    /// (ADR-0042 decision 4): a second such rejection drops them. Kept in
    /// memory with the spool entry, not in the file.
    kept_once: bool,
    /// It was sent at least once (security review L2): it is sent again
    /// as it is, never stripped at send time under a new `batch_id` (the
    /// console may hold it already if an ack was lost; a refused field
    /// takes the `400` path). In memory with the spool entry only.
    attempted: bool,
}

/// Whether a batch carrying the engine tokens `gates` must wait: one of
/// them is not listed by the console (see [`ResultBatch::held_back`]).
pub(crate) fn held_back(
    gates: &[&'static str],
    caps: &crate::capabilities::ConsoleCapabilities,
) -> bool {
    !gates.iter().all(|t| caps.console_accepts(t))
}

/// The tokens gating a finding: those of its location's engine.
fn finding_gate(f: &Finding) -> &'static [&'static str] {
    crate::capabilities::engine_token(f.location.engine)
}

/// The tokens gating an event: those of its source (an event names no
/// engine; every source belongs to one engine, or to both Redis and
/// Valkey).
fn event_gate(e: &AccessEvent) -> &'static [&'static str] {
    crate::capabilities::audit_source_token(e.source)
}

/// Whether an event carries a `signature.*` signal.
fn has_signature(e: &AccessEvent) -> bool {
    e.signals
        .as_ref()
        .is_some_and(|s| s.iter().any(|x| x.starts_with("signature.")))
}

enum Parsed {
    Findings(FindingsBatch),
    Events(EventsBatch),
}

/// A batch could not be serialized, or (when splitting) its spooled bytes
/// could not be decoded for re-encoding. Its content is lost: both are
/// deterministic, so a retry would fail again.
/// Callers count it (`batches_serialization_failed_total`); nothing of its
/// content is kept or logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unserializable;

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: makes every batch serialization fail on
    /// this thread (`#[tokio::test]` runs on a single thread by default).
    pub(crate) static FAIL_BATCH_SERIALIZATION: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn serialize_batch<T: serde::Serialize>(batch: &T) -> Result<Vec<u8>, Unserializable> {
    #[cfg(test)]
    if FAIL_BATCH_SERIALIZATION.with(std::cell::Cell::get) {
        return Err(Unserializable);
    }
    serde_json::to_vec(batch).map_err(|_| Unserializable)
}

impl Parsed {
    fn into_batch(self) -> Result<ResultBatch, Unserializable> {
        let (findings, batch_id, len, bytes) = match &self {
            Self::Findings(b) => (true, b.batch_id, b.findings.len(), serialize_batch(b)),
            Self::Events(b) => (false, b.batch_id, b.events.len(), serialize_batch(b)),
        };
        Ok(ResultBatch {
            findings,
            batch_id,
            len,
            bytes: bytes?,
            signature: self.signature(),
            gates: self.gates(),
            fields: self.fields(),
            kept_once: false,
            attempted: false,
        })
    }

    fn fields(&self) -> Vec<&'static str> {
        let mut fields: Vec<&'static str> = match self {
            Self::Findings(_) => Vec::new(),
            Self::Events(b) => b.events.iter().flat_map(event_field_tokens).collect(),
        };
        fields.sort_unstable();
        fields.dedup();
        fields
    }

    fn gates(&self) -> Vec<&'static str> {
        let mut gates: Vec<&'static str> = match self {
            Self::Findings(b) => b
                .findings
                .iter()
                .flat_map(|f| finding_gate(f).iter().copied())
                .collect(),
            Self::Events(b) => b
                .events
                .iter()
                .flat_map(|e| event_gate(e).iter().copied())
                .collect(),
        };
        gates.sort_unstable();
        gates.dedup();
        gates
    }

    fn signature(&self) -> bool {
        match self {
            Self::Findings(_) => false,
            Self::Events(b) => b.events.iter().any(has_signature),
        }
    }
}

impl ResultBatch {
    /// Parses a spooled body of the given kind; the bytes are kept as they
    /// are (sent verbatim, so a resend is byte-identical for `batch_id`
    /// deduplication). `None` if invalid or empty.
    pub(crate) fn parse(findings: bool, bytes: Vec<u8>) -> Option<Self> {
        let parsed = Self::decode(findings, &bytes)?;
        let signature = parsed.signature();
        let gates = parsed.gates();
        let fields = parsed.fields();
        let (batch_id, len) = match parsed {
            Parsed::Findings(b) => (b.batch_id, b.findings.len()),
            Parsed::Events(b) => (b.batch_id, b.events.len()),
        };
        (len > 0).then_some(Self {
            findings,
            batch_id,
            len,
            bytes,
            signature,
            gates,
            fields,
            kept_once: false,
            attempted: false,
        })
    }

    /// Capability tokens of the engine values its items carry (sorted).
    pub(crate) fn gates(&self) -> &[&'static str] {
        &self.gates
    }

    /// Capability tokens of the gated fields its items carry (sorted).
    pub(crate) fn fields(&self) -> &[&'static str] {
        &self.fields
    }

    /// The batch to send to a console whose capabilities are `caps`
    /// (ADR-0053 decision 2): `Ok(None)` when it lists the token of every
    /// gated field the batch carries (sent as spooled); otherwise the same
    /// items under a **new** `batch_id`, with the fields whose tokens it
    /// does not list stripped, and only those (a console that lists
    /// `access_event.bytes` keeps `bytes`). `Err` if the bytes could not be
    /// decoded or the result serialized. Byte-for-byte what the conversion
    /// would have built without those fields, apart from `batch_id`.
    pub(crate) fn for_console(
        &self,
        caps: &crate::capabilities::Snapshot,
    ) -> Result<Option<Self>, Unserializable> {
        if self.fields.iter().all(|t| caps.accepts(t)) {
            return Ok(None);
        }
        let Some(Parsed::Events(b)) = Self::decode(self.findings, &self.bytes) else {
            return Err(Unserializable);
        };
        let bytes = caps.accepts(crate::capabilities::token::ACCESS_EVENT_BYTES);
        let overflowed = caps.accepts(crate::capabilities::token::ACCESS_EVENT_OBJECTS_OVERFLOWED);
        let events = b
            .events
            .into_iter()
            .map(|mut e| {
                if !bytes {
                    e.bytes = None;
                }
                if !overflowed {
                    e.objects_overflowed = None;
                }
                e
            })
            .collect();
        let mut out = Parsed::Events(EventsBatch {
            batch_id: new_batch_id(),
            events,
        })
        .into_batch()?;
        out.kept_once = self.kept_once;
        Ok(Some(out))
    }

    /// Whether an item at `items` (sorted) carries `objects_overflowed`.
    /// `false` if the bytes cannot be decoded.
    pub(crate) fn flagged_at(&self, items: &[usize]) -> bool {
        match Self::decode(self.findings, &self.bytes) {
            Some(Parsed::Events(b)) => b
                .events
                .iter()
                .enumerate()
                .any(|(i, e)| e.objects_overflowed.is_some() && items.binary_search(&i).is_ok()),
            Some(Parsed::Findings(_)) | None => false,
        }
    }

    /// Whether its gated-engine items were already kept once after a `400`
    /// `enum` (see [`stripped`](Self::stripped)).
    pub(crate) fn kept_once(&self) -> bool {
        self.kept_once
    }

    /// Whether it was sent at least once (see the field).
    pub(crate) fn attempted(&self) -> bool {
        self.attempted
    }

    /// The same batch, marked as sent at least once (restored from its
    /// spool entry).
    pub(crate) fn with_attempted(mut self, attempted: bool) -> Self {
        self.attempted = attempted;
        self
    }

    /// The same batch, marked as kept once (restored from its spool entry).
    pub(crate) fn with_kept_once(mut self, kept_once: bool) -> Self {
        self.kept_once = kept_once;
        self
    }

    /// Whether an item carries a value of an engine added after protocol
    /// 0.1.0 (ADR-0039 decision 8).
    pub(crate) fn carries_gated_engine(&self) -> bool {
        !self.gates.is_empty()
    }

    /// Whether the batch must wait: one of its items carries an engine
    /// value whose token the console's latest heartbeat response did not
    /// list (an older console would reject it with `400` `enum`). It stays
    /// spooled (the spool's bounds apply) and is sent once the token is
    /// listed.
    #[cfg(test)]
    pub(crate) fn held_back(&self, caps: &crate::capabilities::ConsoleCapabilities) -> bool {
        held_back(&self.gates, caps)
    }

    /// An events batch holding a `signature.*` signal.
    pub(crate) fn has_signature(&self) -> bool {
        self.signature
    }

    fn decode(findings: bool, bytes: &[u8]) -> Option<Parsed> {
        if findings {
            serde_json::from_slice(bytes).ok().map(Parsed::Findings)
        } else {
            serde_json::from_slice(bytes).ok().map(Parsed::Events)
        }
    }

    /// Whether this is a findings batch.
    pub(crate) fn is_findings(&self) -> bool {
        self.findings
    }

    /// API path.
    pub(crate) fn path(&self) -> &'static str {
        if self.findings {
            "/findings"
        } else {
            "/events"
        }
    }

    /// Idempotency key.
    pub(crate) fn batch_id(&self) -> UuidV7 {
        self.batch_id
    }

    /// Number of items.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Serialized body, exactly as spooled.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The same batch without the items at `drop` (sorted), under a **new**
    /// `batch_id`; `Ok(None)` if nothing is left, `Err` if this batch could
    /// not be decoded or the new batch could not be serialized.
    pub(crate) fn without(&self, drop: &[usize]) -> Result<Option<Self>, Unserializable> {
        fn keep<T: Clone>(items: &[T], drop: &[usize]) -> Vec<T> {
            items
                .iter()
                .enumerate()
                .filter(|(i, _)| drop.binary_search(i).is_err())
                .map(|(_, x)| x.clone())
                .collect()
        }
        // The bytes were validated when this batch was built or parsed: a
        // decode failure is an error, never "nothing left".
        let parsed = Self::decode(self.findings, &self.bytes).ok_or(Unserializable)?;
        let out = match parsed {
            Parsed::Findings(b) => Parsed::Findings(FindingsBatch {
                batch_id: new_batch_id(),
                findings: keep(&b.findings, drop),
                ..b
            }),
            Parsed::Events(b) => Parsed::Events(EventsBatch {
                batch_id: new_batch_id(),
                events: keep(&b.events, drop),
            }),
        }
        .into_batch()?
        // Splits and item drops keep the mark (ADR-0042 decision 4).
        .with_kept_once(self.kept_once);
        Ok((out.len > 0).then_some(out))
    }

    /// Whether an item carries a field gated by capability negotiation
    /// (ADR-0022): `AccessEvent.bytes`. Findings have none. `false` if the
    /// bytes cannot be decoded.
    pub(crate) fn carries_gated(&self) -> bool {
        match Self::decode(self.findings, &self.bytes) {
            Some(Parsed::Events(b)) => b.events.iter().any(event_carries_gated),
            Some(Parsed::Findings(_)) | None => false,
        }
    }

    /// The batch to send again after a `400` reporting an unknown field
    /// (`additionalProperties`) to a batch carrying gated fields, or an
    /// unknown enum value (`enum`) to a batch carrying gated engine values
    /// (ADR-0022 decision 9, ADR-0039 decision 8), under a **new**
    /// `batch_id`, with every gated field of every item stripped. Of the
    /// items at `rejected` (sorted), those pointed at with
    /// `additionalProperties` (`unknown`, sorted) that carried a gated
    /// field, and those pointed at with `enum` (`unknown_value`, sorted)
    /// that carry a gated engine value, are kept (an older console accepts
    /// the former without the field, and the latter once it lists the
    /// engine's token: until then [`held_back`](Self::held_back) holds
    /// them); the others were rejected for another reason and are left out.
    /// Returns the batch (`None` if nothing is left) and the number of
    /// items left out. The result carries no gated field, so it is stripped
    /// at most once. Gated-engine items are kept **once** (ADR-0042
    /// decision 4): a batch already [`kept_once`](Self::kept_once) was sent
    /// while the token was listed, so the same `enum` again means the
    /// console will not take them; they are left out (counted). The
    /// replacement of a batch that kept some is marked kept once. Items
    /// pointed at with the overflow rule (`overflow_rule`, sorted) that
    /// carried `objects_overflowed` are kept too, as in
    /// [`unflagged`](Self::unflagged).
    pub(crate) fn stripped(
        &self,
        rejected: &[usize],
        unknown: &[usize],
        unknown_value: &[usize],
        overflow_rule: &[usize],
    ) -> Result<(Option<Self>, usize), Unserializable> {
        self.rewrite(rejected, unknown, unknown_value, overflow_rule, true)
    }

    /// The batch to send again after a `400` reporting the overflow rule
    /// (`contains` / `if`, ADR-0053 decision 1 item 3) on items carrying
    /// `objects_overflowed`, under a **new** `batch_id`: those items are
    /// kept with the flag stripped (and only the flag), so the event is
    /// never lost; the other `rejected` items are left out, the other items
    /// kept as they are. Returns the batch (`None` if nothing is left) and
    /// the number of items left out. The kept items no longer carry the
    /// flag, so the same rule cannot keep them a second time.
    pub(crate) fn unflagged(
        &self,
        rejected: &[usize],
        overflow_rule: &[usize],
    ) -> Result<(Option<Self>, usize), Unserializable> {
        self.rewrite(rejected, &[], &[], overflow_rule, false)
    }

    /// [`stripped`](Self::stripped) (`strip_all`: every gated field of
    /// every item) or [`unflagged`](Self::unflagged).
    fn rewrite(
        &self,
        rejected: &[usize],
        unknown: &[usize],
        unknown_value: &[usize],
        overflow_rule: &[usize],
        strip_all: bool,
    ) -> Result<(Option<Self>, usize), Unserializable> {
        let parsed = Self::decode(self.findings, &self.bytes).ok_or(Unserializable)?;
        let mut left_out = 0usize;
        // Gated-engine items may be kept only once.
        let keep_values = !self.kept_once;
        let mut kept_values = false;
        let mut out = match parsed {
            // No gated finding field exists: only the rejected items go,
            // except those of a gated engine rejected as an unknown value.
            Parsed::Findings(b) => {
                let n = b.findings.len();
                let findings: Vec<Finding> = b
                    .findings
                    .into_iter()
                    .enumerate()
                    .filter(|(i, f)| {
                        if rejected.binary_search(i).is_err() {
                            return true;
                        }
                        let keep = keep_values
                            && unknown_value.binary_search(i).is_ok()
                            && !finding_gate(f).is_empty();
                        kept_values |= keep;
                        keep
                    })
                    .map(|(_, f)| f)
                    .collect();
                left_out = n - findings.len();
                Parsed::Findings(FindingsBatch {
                    batch_id: new_batch_id(),
                    findings,
                    ..b
                })
            }
            Parsed::Events(b) => {
                let mut events = Vec::with_capacity(b.events.len());
                for (i, mut e) in b.events.into_iter().enumerate() {
                    let field = unknown.binary_search(&i).is_ok() && event_carries_gated(&e);
                    let value = keep_values
                        && unknown_value.binary_search(&i).is_ok()
                        && !event_gate(&e).is_empty();
                    let overflow =
                        overflow_rule.binary_search(&i).is_ok() && e.objects_overflowed.is_some();
                    let is_rejected = rejected.binary_search(&i).is_ok();
                    if is_rejected {
                        if !field && !value && !overflow {
                            left_out += 1;
                            continue;
                        }
                        kept_values |= value;
                    }
                    if strip_all {
                        strip_gated_event(&mut e);
                    } else if is_rejected && overflow {
                        e.objects_overflowed = None;
                    }
                    events.push(e);
                }
                Parsed::Events(EventsBatch {
                    batch_id: new_batch_id(),
                    events,
                })
            }
        }
        .into_batch()?;
        out.kept_once = self.kept_once || kept_values;
        Ok(((out.len > 0).then_some(out), left_out))
    }

    /// Two halves, each under a new `batch_id` (`413`); `Ok(None)` for a
    /// single item, `Err` if a half could not be serialized or would be
    /// empty (`len` disagreeing with the decoded items).
    pub(crate) fn halves(&self) -> Result<Option<(Self, Self)>, Unserializable> {
        let n = self.len;
        if n < 2 {
            return Ok(None);
        }
        let first: Vec<usize> = (0..n / 2).collect();
        let second: Vec<usize> = (n / 2..n).collect();
        let (a, b) = (self.without(&second)?, self.without(&first)?);
        // An empty half means `len` disagrees with the decoded items: an
        // error, never a panic.
        match (a, b) {
            (Some(a), Some(b)) => Ok(Some((a, b))),
            _ => Err(Unserializable),
        }
    }
}

/// Whether an event carries a gated field (ADR-0022).
fn event_carries_gated(e: &AccessEvent) -> bool {
    e.bytes.is_some() || e.objects_overflowed.is_some()
}

/// The capability tokens of the gated fields an event carries.
fn event_field_tokens(e: &AccessEvent) -> impl Iterator<Item = &'static str> {
    use crate::capabilities::token;
    [
        e.bytes.is_some().then_some(token::ACCESS_EVENT_BYTES),
        e.objects_overflowed
            .is_some()
            .then_some(token::ACCESS_EVENT_OBJECTS_OVERFLOWED),
    ]
    .into_iter()
    .flatten()
}

/// Removes every gated field of an event (ADR-0022): `bytes` and
/// `objects_overflowed` (ADR-0053). A new gated `AccessEvent` field must be
/// added here, in [`event_carries_gated`], in [`event_field_tokens`] and in
/// [`ResultBatch::for_console`].
fn strip_gated_event(e: &mut AccessEvent) {
    e.bytes = None;
    e.objects_overflowed = None;
}

/// Batches built from masked results, and the items dropped on the way.
#[derive(Debug, Default)]
pub(crate) struct Built {
    pub(crate) batches: Vec<ResultBatch>,
    /// Items dropped (invalid, oversized, or in a batch that could not be
    /// serialized).
    pub(crate) dropped_items: u64,
    /// Batches lost because their serialization failed.
    pub(crate) unserializable_batches: u64,
}

impl Built {
    /// Adds a packed batch, or counts it (and its items) as lost.
    fn push(&mut self, parsed: Parsed) {
        let items = match &parsed {
            Parsed::Findings(b) => b.findings.len(),
            Parsed::Events(b) => b.events.len(),
        };
        match parsed.into_batch() {
            Ok(batch) => self.batches.push(batch),
            Err(Unserializable) => {
                self.unserializable_batches += 1;
                self.dropped_items += u64::try_from(items).unwrap_or(u64::MAX);
            }
        }
    }
}

/// Masked results handed to [`to_batches`].
pub(crate) enum MaskedResults<'a> {
    /// Findings of one `discovery.scan` job on one target.
    Findings {
        job_id: Uuid,
        classifiers_version: &'a ClassifiersVersion,
        target_id: &'a TargetId,
        engine: Engine,
        findings: &'a [MaskedFinding],
    },
    /// Access events of one target. Account names that do not conform
    /// (or come from a failed authentication) are fingerprinted with
    /// `fingerprints` (the agent HMAC key, `db_user` domain).
    Events {
        target_id: &'a TargetId,
        events: &'a [MaskedEvent],
        fingerprints: &'a dyn sanitize::Fingerprinter,
    },
}

/// **The** conversion from masked types to protocol batches (I2, I6,
/// ADR-0009): each item is converted, validated and sanitized
/// (`sanitize`), invalid items are dropped and counted, and the rest is
/// packed into batches of at most `maxItems` items and 1 MiB serialized,
/// each with a fresh UUIDv7 `batch_id`.
pub(crate) fn to_batches(results: MaskedResults<'_>) -> Built {
    match results {
        MaskedResults::Findings {
            job_id,
            classifiers_version,
            target_id,
            engine,
            findings,
        } => {
            let mut dropped = 0u64;
            let items: Vec<Finding> = findings
                .iter()
                .filter_map(|f| {
                    let item = finding_item(target_id, engine, f)
                        .and_then(|mut i| sanitize::check_finding(&mut i).then_some(i));
                    if item.is_none() {
                        dropped += 1;
                    }
                    item
                })
                .collect();
            let mut built = pack_findings(job_id, classifiers_version, items);
            built.dropped_items += dropped;
            built
        }
        MaskedResults::Events {
            target_id,
            events,
            fingerprints,
        } => {
            let mut dropped = 0u64;
            let now = std::time::SystemTime::now();
            let items: Vec<AccessEvent> = events
                .iter()
                .filter_map(|e| {
                    let item = event_item(target_id, e, fingerprints, now);
                    if item.is_none() {
                        dropped += 1;
                    }
                    item
                })
                .collect();
            let mut built = pack_events(items);
            built.dropped_items += dropped;
            built
        }
    }
}

fn timestamp(t: std::time::SystemTime) -> databastion_protocol::Timestamp {
    databastion_protocol::Timestamp(chrono::DateTime::<chrono::Utc>::from(t))
}

/// Converts a masked event (the protocol type is built here only, from
/// the closed enums and normalized names of `MaskedEvent`).
///
/// `ts` and `ts_last` come from the target's own clock (audit records)
/// and are clamped to the agent's clock `now`: a target clock running
/// ahead would otherwise make the console reject the whole batch as
/// future-dated (`formatMaximum`) and record an integrity event, losing
/// every event of that target, whatever the connector.
fn event_item(
    target_id: &TargetId,
    e: &MaskedEvent,
    fingerprints: &dyn sanitize::Fingerprinter,
    now: std::time::SystemTime,
) -> Option<AccessEvent> {
    use databastion_classifiers::masking::{ClientAddr, EventAction};
    use databastion_protocol::{AccessEventAction, AuditSource, ObjectRef, Signal};
    let id =
        |n: &databastion_classifiers::names::NormalizedName| Identifier::try_from(n.as_str()).ok();
    let p = e.principal();
    // `db_user` `*` means "several accounts" (contract `Principal`): only the
    // CAS failed-login aggregate carries it, on a `cas_audit_log`
    // `auth_failure` with `volume.failed_logins_many_accounts`. Any other
    // event built with that principal is dropped (counted), and an account
    // merely named `*` is sent as its fingerprint.
    if p.is_many_accounts()
        && !(e.source() == databastion_classifiers::masking::EventSource::CasAuditLog
            && e.action() == EventAction::AuthFailure
            && e.signals()
                .contains(&databastion_classifiers::masking::Signal::FailedLoginsManyAccounts))
    {
        return None;
    }
    // `account_not_recorded` (contract `Principal`): only on a Redis /
    // Valkey source and never on `auth_failure`; any other event built with
    // it is dropped (counted).
    if p.is_not_recorded() && (!e.source().is_redis() || e.action() == EventAction::AuthFailure) {
        return None;
    }
    let send_name = p.send_name()
        && (p.is_many_accounts()
            || p.account_name() != databastion_classifiers::masking::MANY_ACCOUNTS);
    let client = p.client().map(|c| match c {
        ClientAddr::Ip(ip) => ip.to_string(),
        ClientAddr::Local => "local".to_owned(),
    });
    let principal = if p.is_not_recorded() {
        sanitize::principal_not_recorded(client.as_deref(), p.application())
    } else {
        sanitize::principal(
            p.account_name(),
            send_name,
            client.as_deref(),
            p.application(),
            fingerprints,
        )?
    };
    let mut objects = Vec::with_capacity(e.objects().len());
    for o in e.objects() {
        objects.push(ObjectRef {
            database: id(o.database())?,
            // A Redis / Valkey source names its objects with a
            // `KeyPattern` (contract `ObjectRef`; checked with every `not`
            // rule by the sanitizer), every other source an `Identifier`.
            object: if e.source().is_redis() {
                o.object().as_str().parse().ok()?
            } else {
                id(o.object())?.into()
            },
            schema: match o.schema() {
                Some(s) => Some(id(s)?),
                None => None,
            },
        });
    }
    let signals: Vec<Signal> = e
        .signals()
        .iter()
        .filter_map(|s| Signal::try_from(s.as_str()).ok())
        .collect();
    let source =
        serde_json::from_value::<AuditSource>(serde_json::Value::from(e.source().as_str())).ok()?;
    Some(AccessEvent {
        action: match e.action() {
            EventAction::Connect => AccessEventAction::Connect,
            EventAction::AuthFailure => AccessEventAction::AuthFailure,
            EventAction::Read => AccessEventAction::Read,
            EventAction::Write => AccessEventAction::Write,
            EventAction::Ddl => AccessEventAction::Ddl,
            EventAction::Dcl => AccessEventAction::Dcl,
        },
        aggregated_count: std::num::NonZeroU64::new(e.aggregated_count())?,
        // The reply size where the source records it (Valkey's
        // `large-reply` command log). A gated field (ADR-0022): spooled,
        // and stripped at send time unless the console lists
        // `access_event.bytes` (`ResultBatch::for_console`).
        bytes: e.bytes().map(sanitize::clamped_count),
        objects,
        // ADR-0053 decision 2: always spooled when objects were left out,
        // stripped at send time unless the console lists
        // `access_event.objects_overflowed` (`ResultBatch::for_console`).
        // The sanitizer keeps a `*` in every flagged event.
        objects_overflowed: e.objects_overflowed().then_some(true),
        principal,
        rows: e.rows().map(sanitize::clamped_count),
        signals: (!signals.is_empty()).then_some(signals),
        source,
        target_id: target_id.clone(),
        ts: timestamp(e.ts().min(now)),
        ts_last: e
            .ts_last()
            .filter(|_| e.aggregated_count() > 1)
            .map(|t| timestamp(t.min(now))),
    })
}

fn finding_item(target_id: &TargetId, engine: Engine, f: &MaskedFinding) -> Option<Finding> {
    let loc = f.location()?;
    let id =
        |n: &databastion_classifiers::names::NormalizedName| Identifier::try_from(n.as_str()).ok();
    let masked_samples = f
        .masked_samples()
        .iter()
        .filter_map(|s| ProtoMaskedSample::try_from(s.as_str()).ok())
        .collect();
    Some(Finding {
        classifier: ProtoClassifierId::try_from(f.classifier().as_str()).ok()?,
        confidence: f.confidence(),
        estimated_rows: f
            .estimated_rows()
            .and_then(|r| i64::try_from(r).ok())
            .map(Count),
        fingerprints: {
            let fps: Vec<ProtoFingerprint> = f
                .fingerprints()
                .iter()
                .filter_map(|fp| ProtoFingerprint::try_from(fp.as_str()).ok())
                .collect();
            (!fps.is_empty()).then_some(fps)
        },
        location: Location {
            database: id(&loc.database)?,
            engine,
            field: id(&loc.field)?,
            // A Redis / Valkey key pattern (contract `KeyPattern`, checked
            // with its `not` rules by the sanitizer); an `Identifier` on
            // every other engine.
            object: if crate::sanitize::uses_key_patterns(engine) {
                loc.object.as_str().parse().ok()?
            } else {
                id(&loc.object)?.into()
            },
            schema: match &loc.schema {
                Some(s) => Some(id(s)?),
                None => None,
            },
        },
        masked_samples,
        matched: i64::from(f.matched()),
        sampled: std::num::NonZeroU64::new(u64::from(f.sampled()))?,
        target_id: target_id.clone(),
    })
}

/// Packs sanitized findings under the item and byte caps.
fn pack_findings(job_id: Uuid, version: &ClassifiersVersion, items: Vec<Finding>) -> Built {
    let make = |findings: Vec<Finding>| FindingsBatch {
        batch_id: new_batch_id(),
        classifiers_version: version.clone(),
        findings,
        job_id,
    };
    let mut built = Built::default();
    let envelope = serde_json::to_vec(&make(Vec::new())).map_or(MAX_BATCH_BYTES, |v| v.len());
    let mut current: Vec<Finding> = Vec::new();
    let mut size = envelope;
    for item in items {
        let Ok(len) = serde_json::to_vec(&item).map(|v| v.len() + 1) else {
            built.dropped_items += 1;
            continue;
        };
        if envelope + len > MAX_BATCH_BYTES {
            built.dropped_items += 1;
            continue;
        }
        if current.len() == MAX_FINDINGS_PER_BATCH || size + len > MAX_BATCH_BYTES {
            built.push(Parsed::Findings(make(std::mem::take(&mut current))));
            size = envelope;
        }
        size += len;
        current.push(item);
    }
    if !current.is_empty() {
        built.push(Parsed::Findings(make(current)));
    }
    built
}

/// Packs sanitized events under the item and byte caps. Gated fields are
/// kept: they are stripped at send time (ADR-0053 decision 2).
fn pack_events(items: Vec<AccessEvent>) -> Built {
    // Events with a `signature.*` signal go in batches of their own, first:
    // the spool keeps those batches when it is full (phase 7), and they are
    // sent ahead of the others of the same flush.
    let (signed, plain): (Vec<AccessEvent>, Vec<AccessEvent>) =
        items.into_iter().partition(has_signature);
    let mut built = pack_event_items(signed);
    let rest = pack_event_items(plain);
    built.batches.extend(rest.batches);
    built.dropped_items += rest.dropped_items;
    built.unserializable_batches += rest.unserializable_batches;
    built
}

fn pack_event_items(items: Vec<AccessEvent>) -> Built {
    let make = |events: Vec<AccessEvent>| EventsBatch {
        batch_id: new_batch_id(),
        events,
    };
    let mut built = Built::default();
    let envelope = serde_json::to_vec(&make(Vec::new())).map_or(MAX_BATCH_BYTES, |v| v.len());
    let mut current: Vec<AccessEvent> = Vec::new();
    let mut size = envelope;
    for mut item in items {
        if !sanitize::check_event(&mut item) {
            built.dropped_items += 1;
            continue;
        }
        let Ok(len) = serde_json::to_vec(&item).map(|v| v.len() + 1) else {
            built.dropped_items += 1;
            continue;
        };
        if envelope + len > MAX_BATCH_BYTES {
            built.dropped_items += 1;
            continue;
        }
        if current.len() == MAX_EVENTS_PER_BATCH || size + len > MAX_BATCH_BYTES {
            built.push(Parsed::Events(make(std::mem::take(&mut current))));
            size = envelope;
        }
        size += len;
        current.push(item);
    }
    if !current.is_empty() {
        built.push(Parsed::Events(make(current)));
    }
    built
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoFingerprints;
    impl sanitize::Fingerprinter for NoFingerprints {
        fn fingerprint(&self, _value: &str) -> Option<databastion_protocol::Fingerprint> {
            None
        }
    }

    #[test]
    fn event_timestamps_are_clamped_to_the_agent_clock() {
        use databastion_classifiers::masking::{
            EventAction, EventObject, EventPrincipal, EventSource,
        };
        use databastion_classifiers::names::normalize_path;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let target = TargetId::try_from("pg-main").unwrap();
        let event = |ts: SystemTime| {
            MaskedEvent::new(
                EventSource::Pgaudit,
                EventAction::Read,
                EventPrincipal::account("backup"),
                ts,
            )
            .with_object(EventObject::new(
                normalize_path("shop"),
                Some(normalize_path("crm")),
                normalize_path("customers"),
            ))
        };
        let item = |e: &MaskedEvent| event_item(&target, e, &NoFingerprints, now).unwrap();
        let at = |t: SystemTime| chrono::DateTime::<chrono::Utc>::from(t);

        // Target clock 10 min ahead: both timestamps become the agent's now.
        let ahead =
            event(now + Duration::from_secs(600)).with_aggregate(3, now + Duration::from_secs(900));
        let a = item(&ahead);
        assert_eq!(a.ts.0, at(now));
        assert_eq!(a.ts_last.map(|t| t.0), Some(at(now)));

        // Only the last record is ahead: `ts` kept, `ts_last` clamped, never
        // before `ts`.
        let past = now - Duration::from_secs(60);
        let partly = event(past).with_aggregate(3, now + Duration::from_secs(900));
        let p = item(&partly);
        assert_eq!(p.ts.0, at(past));
        assert_eq!(p.ts_last.map(|t| t.0), Some(at(now)));

        // Past timestamps are unchanged.
        let normal = event(past).with_aggregate(2, past + Duration::from_secs(30));
        let n = item(&normal);
        assert_eq!(n.ts.0, at(past));
        assert_eq!(
            n.ts_last.map(|t| t.0),
            Some(at(past + Duration::from_secs(30)))
        );
    }

    #[test]
    fn redis_events_carry_key_patterns_unrecorded_accounts_and_bytes() {
        use databastion_classifiers::keys::LearnedPatterns;
        use databastion_classifiers::masking::{
            EventAction, EventObject, EventPrincipal, EventSource, Signal as S,
        };
        use databastion_classifiers::names::normalize_path;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let target = TargetId::try_from("valkey-main").unwrap();
        struct Fp;
        impl sanitize::Fingerprinter for Fp {
            fn fingerprint(&self, _: &str) -> Option<databastion_protocol::Fingerprint> {
                databastion_protocol::Fingerprint::try_from(
                    format!("hmac-sha256:{}", "0".repeat(64)).as_str(),
                )
                .ok()
            }
        }
        let item = |e: &MaskedEvent| {
            event_item(&target, e, &Fp, now).map(|i| serde_json::to_value(i).unwrap())
        };
        let object = LearnedPatterns::new(["session:*"]).object(b"session:jdupont", false);
        let read = |source, principal| {
            MaskedEvent::new(source, EventAction::Read, principal, now).with_object(
                EventObject::new(normalize_path("db0"), None, object.clone()),
            )
        };
        let e = read(
            EventSource::RedisCommandlog,
            EventPrincipal::not_recorded().with_client(
                databastion_classifiers::masking::ClientAddr::parse("10.0.0.9"),
            ),
        )
        .with_signal(S::LargeReply)
        .with_bytes(Some(18_000));
        let j = item(&e).unwrap();
        assert_eq!(j["objects"][0]["object"], "session:*");
        assert_eq!(j["principal"]["account_not_recorded"], true);
        assert!(j["principal"].get("db_user").is_none());
        assert_eq!(j["principal"]["client_addr"], "10.0.0.9");
        assert_eq!(j["bytes"], 18_000);
        assert_eq!(j["source"], "redis_commandlog");
        // The same object on another source is an `Identifier` only: `:`
        // refuses it (the event is dropped, counted).
        assert!(item(&read(EventSource::Pgaudit, EventPrincipal::account("u"))).is_none());
        // `account_not_recorded` never on another source nor on a failed
        // authentication.
        assert!(
            item(&read(
                EventSource::MongodbProfiler,
                EventPrincipal::not_recorded()
            ))
            .is_none()
        );
        let auth = MaskedEvent::new(
            EventSource::RedisAclLog,
            EventAction::AuthFailure,
            EventPrincipal::not_recorded(),
            now,
        );
        assert!(item(&auth).is_none());
        let star = read(EventSource::RedisSlowlog, EventPrincipal::account("admin"));
        let j = item(&star).unwrap();
        assert_eq!(j["principal"]["db_user"], "admin");
    }

    #[test]
    fn only_the_cas_failed_login_aggregate_is_sent_as_star() {
        use databastion_classifiers::masking::{
            EventAction, EventPrincipal, EventSource, Signal as S,
        };
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let target = TargetId::try_from("cas-prod").unwrap();
        struct Fp;
        impl sanitize::Fingerprinter for Fp {
            fn fingerprint(&self, _: &str) -> Option<databastion_protocol::Fingerprint> {
                databastion_protocol::Fingerprint::try_from(
                    format!("hmac-sha256:{}", "0".repeat(64)).as_str(),
                )
                .ok()
            }
        }
        let item = |e: &MaskedEvent| {
            event_item(&target, e, &Fp, now).map(|i| serde_json::to_value(i).unwrap())
        };
        let agg = |source, action, signal: Option<S>| {
            let e = MaskedEvent::new(source, action, EventPrincipal::many_accounts(), now)
                .with_aggregate(40, now);
            match signal {
                Some(s) => e.with_signal(s),
                None => e,
            }
        };
        let ok = item(&agg(
            EventSource::CasAuditLog,
            EventAction::AuthFailure,
            Some(S::FailedLoginsManyAccounts),
        ))
        .unwrap();
        assert_eq!(ok["principal"]["db_user"], "*");
        // Anywhere else, the aggregate principal drops the event.
        for e in [
            agg(EventSource::CasAuditLog, EventAction::AuthFailure, None),
            agg(
                EventSource::CasAuditLog,
                EventAction::AuthFailure,
                Some(S::FailedLoginsOneAccount),
            ),
            agg(
                EventSource::CasAuditLog,
                EventAction::Connect,
                Some(S::FailedLoginsManyAccounts),
            ),
            agg(
                EventSource::Pgaudit,
                EventAction::AuthFailure,
                Some(S::FailedLoginsManyAccounts),
            ),
        ] {
            assert!(item(&e).is_none(), "{e:?}");
        }
        // An account named `*` is never sent as `*`.
        for source in [EventSource::Pgaudit, EventSource::CasAuditLog] {
            let named = MaskedEvent::new(
                source,
                EventAction::AuthFailure,
                EventPrincipal::account("*"),
                now,
            )
            .with_signal(S::FailedLoginsManyAccounts);
            let v = item(&named).unwrap();
            assert!(v["principal"].get("db_user").is_none(), "{v}");
            assert!(v["principal"]["db_user_fingerprint"].is_string(), "{v}");
        }
    }

    fn reply(status: u16, json: bool, body: &[u8]) -> Reply {
        Reply {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.to_vec(),
            json,
        }
    }

    #[test]
    fn json_media_type_ignores_parameters_and_case() {
        let check = |v: &str| is_json_media_type(Some(&HeaderValue::from_str(v).unwrap()));
        assert!(check("application/json"));
        assert!(check("Application/JSON; charset=utf-8"));
        assert!(!check("text/html"));
        assert!(!check("application/jsonp"));
        assert!(!is_json_media_type(None));
    }

    #[test]
    fn acceptance_follows_the_endpoint_contract() {
        let hb = br#"{"console_min_protocol":1,"heartbeat_interval_s":30,"server_time":"2026-09-28T14:02:00Z"}"#;
        assert!(accept::heartbeat(&reply(200, true, hb)).is_some());
        assert!(accept::heartbeat(&reply(200, false, hb)).is_none());
        assert!(accept::heartbeat(&reply(202, true, hb)).is_none());
        assert!(accept::heartbeat(&reply(200, true, b"<html>")).is_none());

        let id = new_batch_id();
        let ack =
            serde_json::to_vec(&serde_json::json!({"batch_id": id, "duplicate": false})).unwrap();
        assert!(accept::batch_ack(id)(&reply(202, true, &ack)).is_some());
        assert!(accept::batch_ack(id)(&reply(200, true, &ack)).is_none());
        assert!(accept::batch_ack(id)(&reply(202, false, &ack)).is_none());
        assert!(accept::batch_ack(new_batch_id())(&reply(202, true, &ack)).is_none());

        assert!(matches!(
            accept::job_list(&reply(204, false, b"")),
            Some(None)
        ));
        assert!(matches!(
            accept::job_list(&reply(200, true, br#"{"jobs":[]}"#)),
            Some(Some(_))
        ));
        assert!(accept::job_list(&reply(200, false, br#"{"jobs":[]}"#)).is_none());
        assert!(accept::job_list(&reply(200, true, b"[]")).is_none());

        let rotated = br#"{"grace_expires_at":"2026-09-28T14:07:11Z","duplicate":false}"#;
        assert!(accept::rotate(&reply(200, true, rotated)).is_some());
        assert!(accept::rotate(&reply(200, false, rotated)).is_none());
        assert!(accept::rotate(&reply(201, true, rotated)).is_none());
        assert!(accept::rotate(&reply(200, true, b"<html>")).is_none());
        assert!(accept::rotate(&reply(200, true, hb)).is_none());

        assert!(accept::no_content(&reply(204, false, b"")).is_some());
        assert!(accept::no_content(&reply(200, true, b"{}")).is_none());
        assert!(accept::no_content(&reply(202, false, b"")).is_none());
    }

    #[test]
    fn splitting_an_undecodable_batch_is_an_error() {
        let batch = ResultBatch {
            findings: true,
            batch_id: new_batch_id(),
            len: 4,
            bytes: b"not a batch".to_vec(),
            signature: false,
            gates: Vec::new(),
            fields: Vec::new(),
            kept_once: false,
            attempted: false,
        };
        assert_eq!(batch.without(&[0]).unwrap_err(), Unserializable);
        assert_eq!(batch.halves().unwrap_err(), Unserializable);
    }

    #[test]
    fn splitting_a_batch_whose_len_disagrees_with_its_items_is_an_error() {
        let built = pack_events(vec![crate::sanitize::tests::event("read", 16)]);
        let mut batch = built.batches.into_iter().next().unwrap();
        assert_eq!(batch.len(), 1);
        // Claims more items than it decodes to: one half ends up empty.
        batch.len = 4;
        assert_eq!(batch.halves().unwrap_err(), Unserializable);
    }

    #[test]
    fn classify_maps_statuses() {
        let body = br#"{"code":"rate_limited","message":"Too many requests."}"#;
        assert_eq!(
            classify(
                "/x",
                StatusCode::TOO_MANY_REQUESTS,
                Some(Duration::from_secs(3)),
                body
            ),
            UplinkError::Throttled {
                status: 429,
                retry_after: Some(Duration::from_secs(3))
            }
        );
        assert_eq!(
            classify("/x", StatusCode::UNAUTHORIZED, None, b"garbage"),
            UplinkError::Unauthorized
        );
        let body =
            br#"{"code":"protocol_unsupported","message":"Upgrade required.","min_protocol":2}"#;
        assert_eq!(
            classify("/x", StatusCode::UPGRADE_REQUIRED, None, body),
            UplinkError::UpgradeRequired {
                min_protocol: Some(2)
            }
        );
        let body = br#"{"code":"rotation_conflict","message":"Conflict."}"#;
        assert_eq!(
            classify("/rotate", StatusCode::CONFLICT, None, body),
            UplinkError::Rejected {
                status: 409,
                code: Some(ErrorCode::RotationConflict),
                unknown_field: false,
            }
        );
        assert!(classify("/x", StatusCode::BAD_GATEWAY, None, b"").is_retryable());
        assert!(!classify("/x", StatusCode::BAD_REQUEST, None, b"").is_retryable());
    }

    #[test]
    fn not_implemented_is_throttled_with_retry_after() {
        let body = br#"{"code":"unavailable","message":"Not implemented."}"#;
        // Same parsing and clamping as 429 / 503.
        for (value, expected) in [("3600", 3600), ("7200", 3600), ("0", 1), (" 42 ", 42)] {
            let ra = backoff::parse_retry_after(value);
            assert_eq!(
                classify("/events", StatusCode::NOT_IMPLEMENTED, ra, body),
                UplinkError::Throttled {
                    status: 501,
                    retry_after: Some(Duration::from_secs(expected))
                }
            );
        }
        // Without a valid header or body: still throttled, own backoff.
        let e = classify(
            "/events",
            StatusCode::NOT_IMPLEMENTED,
            backoff::parse_retry_after("soon"),
            b"",
        );
        assert_eq!(
            e,
            UplinkError::Throttled {
                status: 501,
                retry_after: None
            }
        );
        assert!(e.is_retryable());
        assert!(e.retry_delay(0) <= Duration::from_secs(1));
        // Outside the result endpoints: a bounded server error, whatever
        // `Retry-After` says.
        for path in [
            "/heartbeat",
            "/jobs",
            "/jobs/x/status",
            "/rotate",
            "/enroll",
        ] {
            let e = classify(
                path,
                StatusCode::NOT_IMPLEMENTED,
                Some(Duration::from_secs(3600)),
                body,
            );
            assert_eq!(e, UplinkError::Server { status: 501 }, "{path}");
            assert!(e.retry_delay(0) <= Duration::from_secs(1), "{path}");
        }
        assert!(matches!(
            classify(
                "/findings",
                StatusCode::NOT_IMPLEMENTED,
                Some(Duration::from_secs(3600)),
                body
            ),
            UplinkError::Throttled { status: 501, .. }
        ));
    }

    #[test]
    fn retry_delay_honors_retry_after() {
        let e = UplinkError::Throttled {
            status: 503,
            retry_after: Some(Duration::from_secs(20)),
        };
        let d = e.retry_delay(0);
        assert!(d >= Duration::from_secs(20) && d <= Duration::from_secs(24));
        let e = UplinkError::Throttled {
            status: 503,
            retry_after: None,
        };
        assert!(e.retry_delay(2) <= Duration::from_secs(4));
    }

    #[test]
    fn user_agent_matches_contract() {
        let ua = user_agent();
        let version = ua.strip_prefix("databastion-agent/").unwrap();
        assert_eq!(version.split('.').count(), 3);
    }

    #[test]
    fn event_packing_respects_the_byte_cap() {
        let event = crate::sanitize::tests::event("read", 16);
        let events: Vec<_> = (0..2000).map(|_| event.clone()).collect();
        let built = pack_events(events);
        assert!(built.batches.len() >= 4);
        for b in &built.batches {
            assert!(b.len() <= 500);
            assert!(b.bytes().len() <= MAX_BATCH_BYTES);
        }
        assert_eq!(built.dropped_items, 0);
        assert_eq!(
            pack_events(vec![crate::sanitize::tests::event("read", 0)]).dropped_items,
            1
        );
        let target = TargetId::try_from("pg-main").unwrap();
        let key = databastion_classifiers::masking::HmacKey::new(&[3u8; 32]).unwrap();
        let fps = sanitize::HmacFingerprints(&key);
        assert!(matches!(
            to_batches(MaskedResults::Events {
                target_id: &target,
                events: &[],
                fingerprints: &fps,
            })
            .batches
            .as_slice(),
            []
        ));
    }

    fn event_with_bytes(bytes: i64) -> AccessEvent {
        let mut e = crate::sanitize::tests::event("read", 1);
        e.bytes = Some(Count(bytes));
        e
    }

    fn events_of(batch: &ResultBatch) -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_slice(batch.bytes()).unwrap();
        v["events"].as_array().unwrap().clone()
    }

    fn caps(tokens: &[&str]) -> crate::capabilities::Snapshot {
        crate::capabilities::Snapshot::listing(tokens)
    }

    /// ADR-0053 decision 2, applied to `bytes` too: spooled in full, sent
    /// as spooled to a console that lists the token, stripped at send time
    /// otherwise.
    #[test]
    fn access_event_bytes_is_spooled_and_stripped_at_send_time() {
        use crate::capabilities::token;
        let built = pack_events(vec![event_with_bytes(42)]);
        let batch = &built.batches[0];
        assert_eq!(events_of(batch)[0]["bytes"], 42);
        assert!(batch.carries_gated());
        assert_eq!(batch.fields(), [token::ACCESS_EVENT_BYTES]);
        assert!(
            batch
                .for_console(&caps(&[token::ACCESS_EVENT_BYTES]))
                .unwrap()
                .is_none()
        );
        let sent = batch.for_console(&caps(&[])).unwrap().unwrap();
        assert_ne!(sent.batch_id(), batch.batch_id());
        assert!(events_of(&sent)[0].get("bytes").is_none());
        assert!(!sent.carries_gated() && sent.fields().is_empty());
        // Nothing left to strip: sent as is.
        assert!(sent.for_console(&caps(&[])).unwrap().is_none());
    }

    #[test]
    fn stripping_keeps_gated_items_and_drops_other_rejected_ones() {
        let plain = crate::sanitize::tests::event("read", 1);
        let built = pack_events(vec![
            event_with_bytes(1),
            plain.clone(),
            event_with_bytes(3),
            plain,
        ]);
        let batch = &built.batches[0];
        assert!(batch.carries_gated());
        // Items 0 (gated) and 1 (not gated) pointed at as unknown fields.
        let (again, left_out) = batch.stripped(&[0, 1], &[0, 1], &[], &[]).unwrap();
        let again = again.unwrap();
        assert_eq!(left_out, 1);
        assert_eq!(again.len(), 3);
        assert_ne!(again.batch_id(), batch.batch_id());
        assert!(!again.carries_gated(), "every gated field is stripped");
        assert!(events_of(&again).iter().all(|e| e.get("bytes").is_none()));
        // Item 2 (gated) pointed at for another keyword only (e.g.
        // `formatMinimum`): rejected for another reason, left out as well.
        let (again, left_out) = batch.stripped(&[0, 2], &[0], &[], &[]).unwrap();
        assert_eq!((again.unwrap().len(), left_out), (3, 1));
        // Envelope rejection: everything kept, stripped.
        let (all, left_out) = batch.stripped(&[], &[], &[], &[]).unwrap();
        assert_eq!((all.unwrap().len(), left_out), (4, 0));
        // Nothing left.
        let only = pack_events(vec![crate::sanitize::tests::event("read", 1)]);
        let (none, left_out) = only.batches[0].stripped(&[0], &[0], &[], &[]).unwrap();
        assert!(none.is_none());
        assert_eq!(left_out, 1);
    }

    /// ADR-0053: `objects_overflowed` is a gated field. A batch holding a
    /// flagged event that a console rejects as an unknown field
    /// (`additionalProperties` at `/events/<i>`) is resent with the field
    /// stripped, the event kept, never dropped.
    #[test]
    fn objects_overflowed_is_a_gated_field_stripped_and_resent() {
        let plain = crate::sanitize::tests::event("read", 1);
        let mut flagged: AccessEvent = serde_json::from_value(serde_json::json!({
            "target_id": "pg-main", "ts": "2026-09-28T14:02:11Z",
            "principal": {"db_user": "report"}, "action": "read",
            "objects": [{"database": "crm", "object": "orders"}, {"database": "crm", "object": "*"}],
            "source": "pgaudit", "aggregated_count": 1
        }))
        .unwrap();
        assert!(!event_carries_gated(&flagged));
        flagged.objects_overflowed = Some(true);
        assert!(event_carries_gated(&flagged));
        let built = pack_events(vec![plain, flagged]);
        assert_eq!(built.batches.len(), 1);
        let batch = &built.batches[0];
        assert!(batch.carries_gated());
        assert_eq!(events_of(batch)[1]["objects_overflowed"], true);
        // Item 1 (flagged) pointed at as an unknown field: kept, stripped.
        let (again, left_out) = batch.stripped(&[1], &[1], &[], &[]).unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (2, 0));
        assert_ne!(again.batch_id(), batch.batch_id());
        assert!(!again.carries_gated(), "the flag is stripped");
        let events = events_of(&again);
        assert!(events.iter().all(|e| e.get("objects_overflowed").is_none()));
        // The event itself is unchanged apart from the flag: still its `*`.
        assert_eq!(events[1]["objects"][1]["object"], "*");
    }

    #[test]
    fn findings_carry_no_gated_field() {
        let items = vec![crate::sanitize::tests::finding(); 3];
        let built = pack_findings(
            Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
            &ClassifiersVersion::try_from("2026.09.1").unwrap(),
            items,
        );
        let batch = &built.batches[0];
        assert!(!batch.carries_gated());
        let (again, left_out) = batch.stripped(&[1], &[1], &[], &[]).unwrap();
        assert_eq!((again.unwrap().len(), left_out), (2, 1));
    }

    /// The CAS fixtures' items, packed by the core as a connector's output
    /// would be.
    fn cas_findings_and_postgres() -> ResultBatch {
        let cas: FindingsBatch = serde_json::from_str(include_str!(
            "../../../../shared/protocol/fixtures/valid/FindingsBatch.cas.json"
        ))
        .unwrap();
        let mut items = vec![crate::sanitize::tests::finding()];
        items.extend(cas.findings);
        let built = pack_findings(cas.job_id, &cas.classifiers_version, items);
        assert_eq!(built.batches.len(), 1);
        built.batches.into_iter().next().unwrap()
    }

    fn cas_events_and_postgres() -> ResultBatch {
        let cas: EventsBatch = serde_json::from_str(include_str!(
            "../../../../shared/protocol/fixtures/valid/EventsBatch.cas.json"
        ))
        .unwrap();
        let mut items = vec![crate::sanitize::tests::event("read", 1)];
        items.extend(cas.events);
        let built = pack_events(items);
        assert_eq!(built.batches.len(), 1);
        built.batches.into_iter().next().unwrap()
    }

    #[test]
    fn batches_with_cas_items_are_held_until_the_console_lists_engine_cas() {
        use crate::capabilities::{ConsoleCapabilities, token};
        let caps = ConsoleCapabilities::default();
        for batch in [cas_findings_and_postgres(), cas_events_and_postgres()] {
            assert!(batch.carries_gated_engine());
            assert!(batch.held_back(&caps));
            // The spooled form gives the same answer (gates recomputed).
            let parsed = ResultBatch::parse(batch.is_findings(), batch.bytes().to_vec()).unwrap();
            assert!(parsed.held_back(&caps));
        }
        caps.record(Some(
            &serde_json::from_value(serde_json::json!([token::ENGINE_CAS])).unwrap(),
        ));
        assert!(!cas_findings_and_postgres().held_back(&caps));
        assert!(!cas_events_and_postgres().held_back(&caps));
        // Batches of the 0.1.0 engines are never held.
        let pg = pack_events(vec![crate::sanitize::tests::event("read", 1)]);
        assert!(!pg.batches[0].carries_gated_engine());
        assert!(!pg.batches[0].held_back(&ConsoleCapabilities::default()));
    }

    #[test]
    fn cas_items_rejected_as_unknown_values_are_kept_the_others_dropped() {
        // Findings: 0 postgres, 1..=3 cas. An older console points at the
        // engine of 1 and 3 (`enum`), at 0 and 2 for another keyword.
        let batch = cas_findings_and_postgres();
        let (again, left_out) = batch.stripped(&[0, 1, 2, 3], &[], &[1, 3], &[]).unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (2, 2));
        assert_ne!(again.batch_id(), batch.batch_id());
        assert!(again.carries_gated_engine(), "kept, so held again");
        // A postgres item pointed at with `enum` (e.g. an unregistered
        // classifier) is not an engine value: dropped.
        let (again, left_out) = batch.stripped(&[0], &[], &[0], &[]).unwrap();
        assert_eq!((again.unwrap().len(), left_out), (3, 1));

        // Events: 0 postgres, 1..=5 cas.
        let batch = cas_events_and_postgres();
        let (again, left_out) = batch
            .stripped(&[0, 1, 2, 3, 4, 5], &[], &[0, 1, 2, 3, 4, 5], &[])
            .unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (5, 1));
        assert!(
            events_of(&again)
                .iter()
                .all(|e| e["source"] == "cas_audit_log")
        );
    }

    #[test]
    fn cas_items_are_kept_once_then_dropped() {
        // ADR-0042 decision 4: the first `enum` keeps them (marked); the
        // same rejection of the marked batch, sent while the token was
        // listed, drops them.
        let batch = cas_findings_and_postgres();
        assert!(!batch.kept_once());
        let (again, left_out) = batch.stripped(&[1, 3], &[], &[1, 3], &[]).unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (4, 0));
        assert!(again.kept_once());
        // Item positions are unchanged (nothing was left out).
        let (last, left_out) = again.stripped(&[1, 3], &[], &[1, 3], &[]).unwrap();
        let last = last.unwrap();
        assert_eq!((last.len(), left_out), (2, 2));
        assert!(last.kept_once(), "the mark stays with the batch");
        // A split or an ordinary item drop keeps the mark.
        assert!(again.without(&[0]).unwrap().unwrap().kept_once());
        let (a, b) = again.halves().unwrap().unwrap();
        assert!(a.kept_once() && b.kept_once());
        // A batch kept for no gated-engine item is not marked.
        let (plain, _) = batch.stripped(&[0], &[], &[], &[]).unwrap();
        assert!(!plain.unwrap().kept_once());
    }

    #[test]
    fn classify_reports_unknown_field_details() {
        let body = |details: &str| {
            format!(r#"{{"code":"invalid_request","message":"Invalid.","details":[{details}]}}"#)
        };
        let d = |pointer: &str, keyword: &str| {
            format!(r#"{{"pointer":"{pointer}","keyword":"{keyword}"}}"#)
        };
        let items = body(
            &[
                d("/events/2", "additionalProperties"),
                d("/events/0", "formatMinimum"),
                d("/events/2/ts", "formatMinimum"),
            ]
            .join(","),
        );
        assert_eq!(
            classify("/events", StatusCode::BAD_REQUEST, None, items.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![0, 2],
                unknown_field: vec![2],
                unknown_value: vec![],
                overflow_rule: vec![],
            }
        );
        let other = body(&d("/events/1", "formatMinimum"));
        assert_eq!(
            classify("/events", StatusCode::BAD_REQUEST, None, other.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![1],
                unknown_field: vec![],
                unknown_value: vec![],
                overflow_rule: vec![],
            }
        );
        // An older console's answer to a `cas` value (ADR-0042): `enum`
        // counts as an unknown engine value on exactly the engine field,
        // never on another field (an unregistered classifier) nor on a
        // look-alike path.
        let value = body(
            &[
                d("/findings/3/location/engine", "enum"),
                d("/findings/1/classifier", "enum"),
                d("/findings/4/location/engine/x", "enum"),
                d("/findings/5/location", "enum"),
                d("/findings/0/sampled", "maximum"),
                d("/findings/2/location/engine", "maximum"),
            ]
            .join(","),
        );
        assert_eq!(
            classify("/findings", StatusCode::BAD_REQUEST, None, value.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![0, 1, 2, 3, 4, 5],
                unknown_field: vec![],
                unknown_value: vec![3],
                overflow_rule: vec![],
            }
        );
        let value = body(
            &[
                d("/events/2/source", "enum"),
                d("/events/1/action", "enum"),
                d("/events/0/principal/client_addr", "enum"),
            ]
            .join(","),
        );
        assert_eq!(
            classify("/events", StatusCode::BAD_REQUEST, None, value.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![0, 1, 2],
                unknown_field: vec![],
                unknown_value: vec![2],
                overflow_rule: vec![],
            }
        );
        let status = body(&d("/progress", "additionalProperties"));
        assert_eq!(
            classify(
                "/jobs/x/status",
                StatusCode::BAD_REQUEST,
                None,
                status.as_bytes()
            ),
            UplinkError::Rejected {
                status: 400,
                code: Some(ErrorCode::InvalidRequest),
                unknown_field: true,
            }
        );
        let status = body(&d("/ts", "formatMaximum"));
        assert_eq!(
            classify(
                "/jobs/x/status",
                StatusCode::BAD_REQUEST,
                None,
                status.as_bytes()
            ),
            UplinkError::Rejected {
                status: 400,
                code: Some(ErrorCode::InvalidRequest),
                unknown_field: false,
            }
        );
    }

    /// End to end: raw column values -> classifier with the agent key ->
    /// `MaskedFinding` -> protocol `Finding` -> serialized batch. The batch
    /// carries masked samples and domain-separated fingerprints, and neither
    /// a raw value nor the key.
    #[test]
    fn finding_items_carry_masked_samples_and_fingerprints() {
        use databastion_classifiers::column::ColumnClassifier;
        use databastion_classifiers::masking::{
            ClassifierId as C, FindingLocation, HmacKey, RawSample,
        };
        use databastion_classifiers::names::{NormalizedName, normalize_path};

        let key_bytes = [0x5au8; 32];
        let key = HmacKey::new(&key_bytes).unwrap();
        let raw = ["jane.doe@example.com", "john.smith@example.org", "x"];
        let values: Vec<RawSample<'_>> = raw.iter().map(|v| RawSample::new(v)).collect();
        let found = ColumnClassifier::new()
            .with_key(&key)
            .classify("email", &values);
        assert_eq!(found.len(), 1);
        let location = FindingLocation {
            database: normalize_path("shop"),
            schema: Some(normalize_path("crm")),
            object: normalize_path("customers"),
            field: normalize_path("email"),
        };
        let finding = found.into_iter().next().unwrap().into_finding(location);
        let _: &NormalizedName = &finding.location().unwrap().field;

        let target = TargetId::try_from("pg-main").unwrap();
        let version = ClassifiersVersion::try_from("2026.09.1").unwrap();
        let built = to_batches(MaskedResults::Findings {
            job_id: Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
            classifiers_version: &version,
            target_id: &target,
            engine: Engine::Postgres,
            findings: std::slice::from_ref(&finding),
        });
        assert_eq!(built.dropped_items, 0);
        let json = String::from_utf8(built.batches[0].bytes().to_vec()).unwrap();
        let batch: serde_json::Value = serde_json::from_str(&json).unwrap();
        let item = &batch["findings"][0];
        assert_eq!(item["classifier"], "pii.email");
        let samples: Vec<&str> = item["masked_samples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(samples.len(), 2);
        assert!(samples.contains(&"j***@e***.com"), "{samples:?}");
        let fps: Vec<&str> = item["fingerprints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let jane = key.fingerprint(C::Email, &RawSample::new(raw[0])).unwrap();
        let john = key.fingerprint(C::Email, &RawSample::new(raw[1])).unwrap();
        assert!(
            fps.contains(&jane.as_str()) && fps.contains(&john.as_str()),
            "{fps:?}"
        );
        // Domain separation: not the `db_user` fingerprint of the same bytes.
        let as_user = key.fingerprint_db_user(&RawSample::new(raw[0]));
        assert!(!fps.contains(&as_user.as_str()));
        // No raw value, no key material, in the batch or any Debug output.
        let key_hex: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let debug = format!("{finding:?} {key:?} {built:?}");
        for text in [&json, &debug] {
            for v in &raw[..2] {
                assert!(!text.contains(v), "raw value in {text}");
            }
            assert!(!text.contains("jane") && !text.contains("smith"));
            assert!(!text.contains(&key_hex));
            assert!(!text.contains("5a5a5a5a"));
        }
    }

    /// Masked events as a connector hands them to the core: one whose
    /// objects overflowed (a connector's own bound), one with `bytes`, one
    /// plain.
    fn overflowed_masked_events() -> Vec<MaskedEvent> {
        use databastion_classifiers::masking::{
            EventAction, EventObject, EventPrincipal, EventSource,
        };
        use databastion_classifiers::names::normalize_path;
        let now = std::time::SystemTime::now();
        let event = || {
            MaskedEvent::new(
                EventSource::Pgaudit,
                EventAction::Read,
                EventPrincipal::account("report"),
                now,
            )
            .with_object(EventObject::new(
                normalize_path("crm"),
                Some(normalize_path("public")),
                normalize_path("orders"),
            ))
        };
        vec![
            event()
                .with_unlisted_objects(normalize_path("crm"))
                .with_bytes(Some(7)),
            event().with_bytes(Some(9)),
            event(),
        ]
    }

    fn built_overflowed() -> ResultBatch {
        let target = TargetId::try_from("pg-main").unwrap();
        let key = databastion_classifiers::masking::HmacKey::new(&[3u8; 32]).unwrap();
        let fps = sanitize::HmacFingerprints(&key);
        let events = overflowed_masked_events();
        assert!(events[0].objects_overflowed());
        let built = to_batches(MaskedResults::Events {
            target_id: &target,
            events: &events,
            fingerprints: &fps,
        });
        assert_eq!((built.batches.len(), built.dropped_items), (1, 0));
        built.batches.into_iter().next().unwrap()
    }

    /// ADR-0053 decision 2 item 1: the conversion spools the flag (and
    /// `bytes`) whatever the capabilities hold (it does not even see them),
    /// with the `*` the contract requires; the spooled form gives the same
    /// field tokens.
    #[test]
    fn the_spooled_batch_carries_the_overflow_flag() {
        use crate::capabilities::token;
        let batch = built_overflowed();
        let events = events_of(&batch);
        assert_eq!(events[0]["objects_overflowed"], true);
        assert!(
            events[0]["objects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["object"] == "*" && o["database"] == "crm")
        );
        assert_eq!(events[0]["bytes"], 7);
        assert!(events[1].get("objects_overflowed").is_none());
        assert_eq!(events[1]["bytes"], 9);
        assert!(events[2].get("objects_overflowed").is_none() && events[2].get("bytes").is_none());
        let both = [
            token::ACCESS_EVENT_BYTES,
            token::ACCESS_EVENT_OBJECTS_OVERFLOWED,
        ];
        assert_eq!(batch.fields(), both);
        let parsed = ResultBatch::parse(false, batch.bytes().to_vec()).unwrap();
        assert_eq!(parsed.fields(), both);
        // A valid contract body.
        serde_json::from_slice::<EventsBatch>(batch.bytes()).unwrap();
    }

    /// ADR-0053 decision 2 item 2: stripped at send time per token.
    #[test]
    fn send_time_stripping_drops_only_the_unlisted_fields() {
        use crate::capabilities::token;
        let batch = built_overflowed();
        let has = |b: &ResultBatch, field: &str| -> Vec<bool> {
            events_of(b)
                .iter()
                .map(|e| e.get(field).is_some())
                .collect()
        };
        // Both listed: sent as spooled.
        let all = caps(&[
            token::ACCESS_EVENT_BYTES,
            token::ACCESS_EVENT_OBJECTS_OVERFLOWED,
        ]);
        assert!(batch.for_console(&all).unwrap().is_none());
        // Only `bytes` listed: the flag goes, `bytes` stays.
        let sent = batch
            .for_console(&caps(&[token::ACCESS_EVENT_BYTES]))
            .unwrap()
            .unwrap();
        assert_ne!(sent.batch_id(), batch.batch_id());
        assert_eq!(has(&sent, "objects_overflowed"), [false, false, false]);
        assert_eq!(has(&sent, "bytes"), [true, true, false]);
        assert_eq!(sent.fields(), [token::ACCESS_EVENT_BYTES]);
        // Only the flag listed: `bytes` goes.
        let sent = batch
            .for_console(&caps(&[token::ACCESS_EVENT_OBJECTS_OVERFLOWED]))
            .unwrap()
            .unwrap();
        assert_eq!(has(&sent, "objects_overflowed"), [true, false, false]);
        assert_eq!(has(&sent, "bytes"), [false, false, false]);
        // Neither (a 0.8.0 console): both go, every event kept, its `*` too.
        let sent = batch.for_console(&caps(&[])).unwrap().unwrap();
        assert_eq!(sent.len(), 3);
        assert!(!sent.carries_gated() && sent.fields().is_empty());
        assert_eq!(
            events_of(&sent)[0]["objects"],
            events_of(&batch)[0]["objects"]
        );
        // Never stripped twice: nothing is left to strip.
        assert!(sent.for_console(&caps(&[])).unwrap().is_none());
        // The kept-once mark (ADR-0042) survives the send-time strip.
        let marked = batch.clone().with_kept_once(true);
        assert!(marked.for_console(&caps(&[])).unwrap().unwrap().kept_once());
    }

    /// ADR-0053 decision 2 item 4 (3): a batch stripped at send time is
    /// byte-for-byte the batch the conversion would have built without the
    /// fields, apart from `batch_id`.
    #[test]
    fn a_batch_stripped_at_send_time_is_the_batch_built_without_the_fields() {
        let batch = built_overflowed();
        let sent = batch.for_console(&caps(&[])).unwrap().unwrap();
        let mut expected: EventsBatch = serde_json::from_slice(batch.bytes()).unwrap();
        expected.batch_id = sent.batch_id();
        for e in &mut expected.events {
            e.bytes = None;
            e.objects_overflowed = None;
        }
        // What `pack_events` builds from the same items without the fields.
        let rebuilt = pack_events(expected.events.clone());
        let mut rebuilt: EventsBatch = serde_json::from_slice(rebuilt.batches[0].bytes()).unwrap();
        rebuilt.batch_id = sent.batch_id();
        assert_eq!(sent.bytes(), serde_json::to_vec(&expected).unwrap());
        assert_eq!(sent.bytes(), serde_json::to_vec(&rebuilt).unwrap());
    }

    /// ADR-0022 decision 9 after the send-time strip: a `400` on a gated
    /// field still drops every gated field, even those the console listed,
    /// and the result is never stripped again.
    #[test]
    fn after_a_400_every_gated_field_is_stripped_once() {
        use crate::capabilities::token;
        let batch = built_overflowed();
        let sent = batch
            .for_console(&caps(&[token::ACCESS_EVENT_BYTES]))
            .unwrap()
            .unwrap();
        assert!(sent.carries_gated());
        let (again, left_out) = sent.stripped(&[0], &[0], &[], &[]).unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (3, 0));
        assert!(!again.carries_gated() && again.fields().is_empty());
        assert!(events_of(&again).iter().all(|e| e.get("bytes").is_none()));
        // Nothing gated left: neither the send-time path nor the `400` path
        // strips it again.
        let all = caps(&[
            token::ACCESS_EVENT_BYTES,
            token::ACCESS_EVENT_OBJECTS_OVERFLOWED,
        ]);
        assert!(again.for_console(&all).unwrap().is_none());
        assert!(again.for_console(&caps(&[])).unwrap().is_none());
    }

    /// Contract review M2: a flagged event refused for naming no `*`
    /// (`contains` / `if`) is kept without the flag, only the flag; the
    /// other rejected items are left out; a second refusal of the same
    /// item no longer keeps it.
    #[test]
    fn a_flagged_event_refused_by_the_overflow_rule_is_kept_once_without_the_flag() {
        let batch = built_overflowed();
        assert!(batch.flagged_at(&[0]));
        assert!(!batch.flagged_at(&[1, 2]));
        let (again, left_out) = batch.unflagged(&[0, 2], &[0, 2]).unwrap();
        let again = again.unwrap();
        assert_eq!((again.len(), left_out), (2, 1));
        assert_ne!(again.batch_id(), batch.batch_id());
        let events = events_of(&again);
        assert!(events[0].get("objects_overflowed").is_none());
        assert_eq!(events[0]["bytes"], 7, "only the flag is stripped");
        assert_eq!(events[1]["bytes"], 9, "not rejected: untouched");
        assert!(!again.flagged_at(&[0]));
        let (last, left_out) = again.unflagged(&[0], &[0]).unwrap();
        assert_eq!((last.unwrap().len(), left_out), (1, 1));
        // On the `400` gated-field path the refused flagged item is kept
        // too (stripped of every gated field).
        let (again, left_out) = batch.stripped(&[0, 2], &[], &[], &[0]).unwrap();
        assert_eq!((again.unwrap().len(), left_out), (2, 1));
    }

    #[test]
    fn classify_reports_the_overflow_rule_details() {
        let d = |pointer: &str, keyword: &str| serde_json::json!({"pointer": pointer, "keyword": keyword});
        let body = serde_json::json!({
            "code": "invalid_request", "message": "Invalid.",
            "details": [
                d("/events/1/objects", "contains"),
                d("/events/2", "if"),
                d("/events/3/objects", "if"),
                d("/events/4/objects/0", "contains"),
                d("/events/5", "contains"),
            ]
        })
        .to_string();
        assert_eq!(
            classify("/events", StatusCode::BAD_REQUEST, None, body.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![1, 2, 3, 4, 5],
                unknown_field: vec![],
                unknown_value: vec![],
                overflow_rule: vec![1, 2],
            }
        );
        // Findings carry no flag: never the overflow rule.
        let body = serde_json::json!({
            "code": "invalid_request", "message": "Invalid.",
            "details": [d("/findings/0", "if")]
        })
        .to_string();
        assert_eq!(
            classify("/findings", StatusCode::BAD_REQUEST, None, body.as_bytes()),
            UplinkError::ItemsRejected {
                status: 400,
                items: vec![0],
                unknown_field: vec![],
                unknown_value: vec![],
                overflow_rule: vec![],
            }
        );
    }
}
