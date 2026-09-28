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
    ErrorCode, EventsBatch, Finding, FindingsBatch, Identifier, Location,
    MaskedSample as ProtoMaskedSample, TargetId, Uuid, UuidV7, new_batch_id,
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
    /// `429` / `503`; retryable, honoring `Retry-After`.
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
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(backoff::parse_retry_after);
        let body = read_limited(response).await?;
        if status.is_success() {
            return Ok(Reply { status, body });
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

/// A findings or events batch, as spooled and sent. Built only by
/// [`to_batches`] (from masked types) or by splitting such a batch.
#[derive(Debug, Clone)]
pub(crate) enum ResultBatch {
    /// `POST /findings`.
    Findings(FindingsBatch),
    /// `POST /events`.
    Events(EventsBatch),
}

impl ResultBatch {
    /// Parses a spooled body of the given kind.
    pub(crate) fn parse(findings: bool, bytes: &[u8]) -> Option<Self> {
        if findings {
            serde_json::from_slice(bytes).ok().map(Self::Findings)
        } else {
            serde_json::from_slice(bytes).ok().map(Self::Events)
        }
    }

    /// Whether this is a findings batch.
    pub(crate) fn is_findings(&self) -> bool {
        matches!(self, Self::Findings(_))
    }

    /// API path.
    pub(crate) fn path(&self) -> &'static str {
        if self.is_findings() {
            "/findings"
        } else {
            "/events"
        }
    }

    /// Idempotency key.
    pub(crate) fn batch_id(&self) -> UuidV7 {
        match self {
            Self::Findings(b) => b.batch_id,
            Self::Events(b) => b.batch_id,
        }
    }

    /// Number of items.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Findings(b) => b.findings.len(),
            Self::Events(b) => b.events.len(),
        }
    }

    /// Serialized body.
    pub(crate) fn to_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Findings(b) => serde_json::to_vec(b).ok(),
            Self::Events(b) => serde_json::to_vec(b).ok(),
        }
    }

    /// The same batch without the items at `drop`, under a **new**
    /// `batch_id`; `None` if nothing is left.
    pub(crate) fn without(&self, drop: &[usize]) -> Option<Self> {
        fn keep<T: Clone>(items: &[T], drop: &[usize]) -> Vec<T> {
            items
                .iter()
                .enumerate()
                .filter(|(i, _)| drop.binary_search(i).is_err())
                .map(|(_, x)| x.clone())
                .collect()
        }
        let out = match self {
            Self::Findings(b) => Self::Findings(FindingsBatch {
                batch_id: new_batch_id(),
                findings: keep(&b.findings, drop),
                ..b.clone()
            }),
            Self::Events(b) => Self::Events(EventsBatch {
                batch_id: new_batch_id(),
                events: keep(&b.events, drop),
            }),
        };
        (out.len() > 0).then_some(out)
    }

    /// Two halves, each under a new `batch_id` (`413`); `None` for a single
    /// item.
    pub(crate) fn halves(&self) -> Option<(Self, Self)> {
        let n = self.len();
        if n < 2 {
            return None;
        }
        let first: Vec<usize> = (0..n / 2).collect();
        let second: Vec<usize> = (n / 2..n).collect();
        Some((self.without(&second)?, self.without(&first)?))
    }
}

/// Batches built from masked results, and the items dropped on the way.
#[derive(Debug, Default)]
pub(crate) struct Built {
    pub(crate) batches: Vec<ResultBatch>,
    pub(crate) dropped_items: u64,
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
        fingerprints: None,
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
            built
                .batches
                .push(ResultBatch::Findings(make(std::mem::take(&mut current))));
            size = envelope;
        }
        size += len;
        current.push(item);
    }
    if !current.is_empty() {
        built.batches.push(ResultBatch::Findings(make(current)));
    }
    built
}

/// Packs sanitized events under the item and byte caps (used once event
/// masking produces content, P4; tested now).
#[cfg_attr(not(test), allow(dead_code, reason = "event masking lands in P4"))]
pub(crate) fn pack_events(items: Vec<AccessEvent>) -> Built {
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
            built
                .batches
                .push(ResultBatch::Events(make(std::mem::take(&mut current))));
            size = envelope;
        }
        size += len;
        current.push(item);
    }
    if !current.is_empty() {
        built.batches.push(ResultBatch::Events(make(current)));
    }
    built
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
