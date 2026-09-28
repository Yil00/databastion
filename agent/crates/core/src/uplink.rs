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
//! - Findings and events are only accepted as masked types (I2, ADR-0003);
//!   their batching lands with the spool (P2).

use std::time::Duration;

use databastion_classifiers::masking::{MaskedEvent, MaskedFinding};
use databastion_protocol::{AgentSecret, BatchAck, ErrorCode, Uuid};
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};

use crate::backoff;
use crate::config::AgentConfig;

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
    /// Not implemented yet (findings / events batches, P2).
    #[error("uplink operation is not implemented yet")]
    NotImplemented,
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
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|_| UplinkError::Setup("ca_file is not a PEM certificate"))?;
            // Pinning: the configured CA is the only trusted root.
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
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
            let mut value = HeaderValue::from_str(&format!("Bearer {}", secret.expose()))
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

    /// Sends a batch of masked findings (P2: spool and batching).
    pub(crate) async fn send_findings(
        &self,
        _batch: &[MaskedFinding],
    ) -> Result<BatchAck, UplinkError> {
        Err(UplinkError::NotImplemented)
    }

    /// Sends a batch of masked access events (P4: spool and batching).
    pub(crate) async fn send_events(
        &self,
        _batch: &[MaskedEvent],
    ) -> Result<BatchAck, UplinkError> {
        Err(UplinkError::NotImplemented)
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
        400..=499 => UplinkError::Rejected { status, code },
        _ => UplinkError::UnexpectedResponse { status },
    }
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
