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
    #[error("request rejected ({status}, code {code:?})")]
    Rejected {
        status: u16,
        code: Option<ErrorCode>,
    },
    /// `400` / `404` on `/findings` or `/events` whose `details` all point at
    /// items: the (deduplicated, sorted) indices of the rejected items.
    #[error("batch items rejected ({status}, {} items)", items.len())]
    ItemsRejected { status: u16, items: Vec<usize> },
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
            // The temporary string is zeroized; the header value itself is
            // an immutable `Bytes` that reqwest owns and drops after the
            // request (not zeroizable).
            let bearer = zeroize::Zeroizing::new(format!("Bearer {}", secret.expose()));
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

/// Indices of the items designated by every `details[].pointer`, when all
/// of them point inside `/findings/<i>` or `/events/<i>` (docs/09). `None`
/// if any pointer targets the envelope, or if there is no detail.
fn item_pointers(path: &str, error: &databastion_protocol::Error) -> Option<Vec<usize>> {
    let prefix = match path {
        "/findings" => "/findings/",
        "/events" => "/events/",
        _ => return None,
    };
    if error.details.is_empty() {
        return None;
    }
    let mut items = Vec::with_capacity(error.details.len());
    for d in &error.details {
        let rest = d.pointer.as_str().strip_prefix(prefix)?;
        let index = rest.split('/').next()?;
        items.push(index.parse::<usize>().ok()?);
    }
    items.sort_unstable();
    items.dedup();
    Some(items)
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
            Some(items) => UplinkError::ItemsRejected { status, items },
            None => UplinkError::Rejected { status, code },
        },
        400..=499 => UplinkError::Rejected { status, code },
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
        })
    }
}

impl ResultBatch {
    /// Parses a spooled body of the given kind; the bytes are kept as they
    /// are (sent verbatim, so a resend is byte-identical for `batch_id`
    /// deduplication). `None` if invalid or empty.
    pub(crate) fn parse(findings: bool, bytes: Vec<u8>) -> Option<Self> {
        let (batch_id, len) = match Self::decode(findings, &bytes)? {
            Parsed::Findings(b) => (b.batch_id, b.findings.len()),
            Parsed::Events(b) => (b.batch_id, b.events.len()),
        };
        (len > 0).then_some(Self {
            findings,
            batch_id,
            len,
            bytes,
        })
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
        .into_batch()?;
        Ok((out.len > 0).then_some(out))
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
    /// Access events (P4: `MaskedEvent` carries no content yet).
    #[cfg_attr(not(test), allow(dead_code, reason = "event producers land in P4"))]
    Events(&'a [MaskedEvent]),
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
        MaskedResults::Events(events) => {
            // P4: event masking produces no content yet; nothing to send.
            Built {
                batches: Vec::new(),
                dropped_items: u64::try_from(events.len()).unwrap_or(u64::MAX),
                unserializable_batches: 0,
            }
        }
    }
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
            object: id(&loc.object)?,
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

/// Packs sanitized events under the item and byte caps (used once event
/// masking produces content, P4; tested now).
#[cfg_attr(not(test), allow(dead_code, reason = "event masking lands in P4"))]
fn pack_events(items: Vec<AccessEvent>) -> Built {
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
                code: Some(ErrorCode::RotationConflict)
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
        assert!(matches!(
            to_batches(MaskedResults::Events(&[])).batches.as_slice(),
            []
        ));
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
}
