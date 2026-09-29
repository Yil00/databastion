//! A session: one connection to the declared target (I5), optional
//! StartTLS, a bind, Who am I?, then the connector's searches (ADR-0029
//! decisions 1 to 3).
//!
//! - Only the configured host / socket is contacted; referrals are never
//!   followed.
//! - Every exchange has a client-side deadline (the search time limit plus
//!   a margin); a timed-out, broken or malformed exchange makes the session
//!   unusable (the caller reconnects).
//! - Messages are read with their length checked before the body
//!   ([`crate::ber::MAX_MESSAGE`]), into zeroized buffers.

use std::time::{Duration, Instant};

use databastion_core::FailureCode;
use databastion_core::config::{OpenldapBind, OpenldapTlsMode, TargetConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::ber::{self, Enc};
use crate::dn;
use crate::error::{LdError, Stage};
use crate::net::{self, Endpoint, Transport};
use crate::proto::{self, Entry, Message, ParseError, Response, Search};
use crate::tls;

/// A session idle for longer is replaced before its next operation.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60);
/// Client-side margin on top of the time limit.
const CLIENT_MARGIN: Duration = Duration::from_secs(2);
/// Continuation references accepted per search (counted, never followed).
const MAX_REFERENCES: u64 = 4096;
/// Default ports.
const LDAPS_PORT: u16 = 636;
const LDAP_PORT: u16 = 389;

/// Time bound of the operations of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    op: Duration,
}

impl Timeouts {
    /// At least 1 s (the search `timeLimit` is in seconds; `0` would mean
    /// no limit).
    pub(crate) fn new(op: Duration) -> Self {
        Self {
            op: op.max(Duration::from_secs(1)),
        }
    }

    /// The search `timeLimit`, in seconds (at least 1).
    pub(crate) fn time_limit(self) -> u32 {
        u32::try_from(self.op.as_millis().div_ceil(1000))
            .unwrap_or(u32::MAX)
            .clamp(1, 3600)
    }

    /// Client-side deadline of one exchange (a whole search included).
    fn exchange(self) -> Duration {
        Duration::from_secs(u64::from(self.time_limit())).saturating_add(CLIENT_MARGIN)
    }
}

/// How the session authenticates.
pub(crate) enum Auth<'a> {
    Simple {
        dn: &'a str,
        password: &'a str,
    },
    /// SASL `EXTERNAL`; the Who am I? identity must equal `expect`.
    External {
        expect: &'a str,
    },
}

/// What a search returned besides its entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Result code of `SearchResultDone`.
    pub(crate) code: u32,
    pub(crate) entries: u64,
    /// Continuation references (never followed).
    pub(crate) references: u64,
}

impl Outcome {
    /// Whether the server cut the result at a size limit (the entries read
    /// are complete and usable).
    pub(crate) fn cut(&self) -> bool {
        matches!(self.code, 4 | 11)
    }

    /// The error of a search that did not complete: any code but success
    /// and the size limits.
    pub(crate) fn error(&self, stage: Stage) -> Option<LdError> {
        (self.code != 0 && !self.cut()).then(|| LdError::result(self.code, stage))
    }
}

/// One connection.
pub(crate) struct Session<S = Transport> {
    io: BufReader<S>,
    next_id: i32,
    timeouts: Timeouts,
    last_used: Instant,
    broken: bool,
    /// The authorization DN the server reports for the session (Who am
    /// I?, without `dn:`), as the server normalizes it.
    pub(crate) identity: String,
}

impl<S> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

/// Where the target listens.
fn endpoint(target: &TargetConfig, tls: OpenldapTlsMode) -> Result<Endpoint, LdError> {
    match (&target.host, &target.socket) {
        (Some(host), None) => Ok(Endpoint::Tcp {
            host: host.clone(),
            port: target
                .port
                .unwrap_or(if tls == OpenldapTlsMode::VerifyFull {
                    LDAPS_PORT
                } else {
                    LDAP_PORT
                }),
        }),
        (None, Some(path)) => Ok(Endpoint::Unix { path: path.clone() }),
        _ => Err(LdError::new(FailureCode::Internal, Stage::Connect)),
    }
}

fn connect_error(e: &std::io::Error, with_tls: bool, stage: Stage) -> LdError {
    // rustls reports a refused certificate as `InvalidData`.
    let stage = if with_tls && e.kind() == std::io::ErrorKind::InvalidData {
        Stage::Tls
    } else {
        stage
    };
    tracing::debug!(kind = %e.kind(), stage = stage.as_str(), "connection failed");
    let code = if e.kind() == std::io::ErrorKind::TimedOut {
        FailureCode::Timeout
    } else {
        FailureCode::TargetUnreachable
    };
    LdError::new(code, stage)
}

impl Session<Transport> {
    /// Connects to `target` with its `agent.yaml` settings, then binds and
    /// checks the identity with Who am I?
    pub(crate) async fn connect(
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<Self, LdError> {
        let settings = target.openldap_settings();
        let password = match settings.bind {
            OpenldapBind::Simple => Some(target.secret.read().map_err(|e| {
                tracing::warn!(target_id = %target.id, error = %e, "target secret unavailable");
                LdError::new(FailureCode::AuthenticationFailed, Stage::Secret)
            })?),
            OpenldapBind::SaslExternal => None,
        };
        let endpoint = endpoint(target, settings.tls)?;
        let config = if settings.tls.verified() {
            Some(tls::verify_full(settings.ca_file.as_deref()).map_err(|e| {
                tracing::warn!(target_id = %target.id, error = %e, "TLS configuration failed");
                LdError::new(FailureCode::Internal, Stage::Tls)
            })?)
        } else {
            None
        };
        let transport = match (settings.tls, &endpoint, config) {
            (OpenldapTlsMode::VerifyFull, _, Some(config)) => endpoint
                .open(Some(config))
                .await
                .map_err(|e| connect_error(&e, true, Stage::Connect))?,
            (OpenldapTlsMode::StartTls, Endpoint::Tcp { host, .. }, Some(config)) => {
                let plain = endpoint
                    .open(None)
                    .await
                    .map_err(|e| connect_error(&e, false, Stage::Connect))?;
                let Transport::Tcp(stream) = start_tls(plain, timeouts).await? else {
                    return Err(LdError::new(FailureCode::Internal, Stage::Tls));
                };
                net::upgrade(stream, host, config)
                    .await
                    .map_err(|e| connect_error(&e, true, Stage::Tls))?
            }
            (OpenldapTlsMode::Disable, _, None) => endpoint
                .open(None)
                .await
                .map_err(|e| connect_error(&e, false, Stage::Connect))?,
            _ => return Err(LdError::new(FailureCode::Internal, Stage::Tls)),
        };
        let auth = match &password {
            Some(p) => Auth::Simple {
                dn: &target.account,
                password: p,
            },
            None => Auth::External {
                expect: &target.account,
            },
        };
        Session::establish(transport, timeouts, auth).await
    }
}

/// StartTLS on a cleartext connection: the extended request, a success
/// response, and **no byte after it** (a server, or an attacker on the
/// path, sending data before the handshake is refused). Returns the
/// transport, ready for the handshake.
pub(crate) async fn start_tls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    timeouts: Timeouts,
) -> Result<S, LdError> {
    let mut s = Session::new(stream, timeouts);
    let request = proto::extended(s.id(), proto::OID_START_TLS);
    let reply = s.single(Stage::Tls, &request).await?;
    match reply {
        Response::Extended { code: 0, .. } => {}
        Response::Extended { code, .. } => {
            tracing::warn!(result = code, "StartTLS refused by the server");
            return Err(LdError::result(code, Stage::Tls));
        }
        _ => return Err(LdError::new(FailureCode::Internal, Stage::Tls)),
    }
    if !s.io.buffer().is_empty() {
        tracing::warn!("bytes received after the StartTLS response: connection refused");
        return Err(LdError::new(FailureCode::Internal, Stage::Tls));
    }
    Ok(s.io.into_inner())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    fn new(stream: S, timeouts: Timeouts) -> Self {
        Self {
            io: BufReader::with_capacity(64 * 1024, stream),
            next_id: 1,
            timeouts,
            last_used: Instant::now(),
            broken: false,
            identity: String::new(),
        }
    }

    /// Binds and runs Who am I? on an open transport.
    pub(crate) async fn establish(
        stream: S,
        timeouts: Timeouts,
        auth: Auth<'_>,
    ) -> Result<Self, LdError> {
        let mut s = Self::new(stream, timeouts);
        let request = match &auth {
            Auth::Simple { dn, password } => {
                if password.is_empty() || dn.is_empty() {
                    // An unauthenticated bind (RFC 4513 5.1.2) could be
                    // accepted as anonymous: never sent.
                    return Err(LdError::new(FailureCode::AuthenticationFailed, Stage::Auth));
                }
                proto::bind_simple(s.id(), dn, password)
            }
            Auth::External { .. } => proto::bind_sasl_external(s.id()),
        };
        match s.single(Stage::Auth, &request).await? {
            Response::Bind { code: 0 } => {}
            Response::Bind { code } => {
                s.broken = true;
                return Err(LdError::result(code, Stage::Auth));
            }
            _ => {
                s.broken = true;
                return Err(LdError::new(FailureCode::Internal, Stage::Auth));
            }
        }
        let identity = s.whoami().await?;
        let refused = LdError::new(FailureCode::AuthenticationFailed, Stage::Auth);
        let Some(identity) = identity else {
            tracing::warn!("the server reports an anonymous identity after the bind");
            return Err(refused);
        };
        if let Auth::External { expect } = auth {
            if dn::canon(&identity) != dn::canon(expect) {
                tracing::warn!(
                    "the SASL EXTERNAL identity is not the configured account: check the \
                     olcAuthzRegexp mapping of the agent's uid"
                );
                return Err(refused);
            }
        }
        s.identity = identity;
        Ok(s)
    }

    /// Who am I? The authorization DN (lowercase canonical form of the
    /// server's answer), `None` for anonymous or a non-DN identity.
    async fn whoami(&mut self) -> Result<Option<String>, LdError> {
        let request = proto::extended(self.id(), proto::OID_WHOAMI);
        match self.single(Stage::SessionSetup, &request).await? {
            Response::Extended { code: 0, value, .. } => {
                let value = value.unwrap_or_default();
                let text = std::str::from_utf8(&value)
                    .map_err(|_| LdError::new(FailureCode::Internal, Stage::SessionSetup))?;
                Ok(text
                    .strip_prefix("dn:")
                    .filter(|d| !d.trim().is_empty())
                    .and_then(dn::canon))
            }
            Response::Extended { code, .. } => Err(LdError::result(code, Stage::SessionSetup)),
            _ => Err(LdError::new(FailureCode::Internal, Stage::SessionSetup)),
        }
    }

    fn id(&mut self) -> i32 {
        let id = self.next_id;
        self.next_id = if id == i32::MAX { 1 } else { id + 1 };
        id
    }

    async fn send(&mut self, request: &Enc) -> Result<(), LdError> {
        let io = self.io.get_mut();
        let r = async {
            io.write_all(request.as_bytes()).await?;
            io.flush().await
        }
        .await;
        r.map_err(|e| {
            self.broken = true;
            connect_error(&e, false, Stage::Connect)
        })
    }

    /// Reads one message: length checked before the body.
    async fn read_message(&mut self) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
        let mut head = [0u8; 6];
        self.io.read_exact(&mut head[..2]).await?;
        let mut have = 2;
        let total = loop {
            match ber::message_len(&head[..have]) {
                Ok(Some(total)) => break total,
                Ok(None) if have < head.len() => {
                    self.io.read_exact(&mut head[have..=have]).await?;
                    have += 1;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad message header",
                    ));
                }
            }
        };
        if total < have {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad message length",
            ));
        }
        let mut buf = Zeroizing::new(vec![0u8; total]);
        buf[..have].copy_from_slice(&head[..have]);
        self.io.read_exact(&mut buf[have..]).await?;
        Ok(buf)
    }

    /// Reads the next message of `id`; anything else ends the session.
    async fn next(&mut self, id: i32, stage: Stage) -> Result<Response, LdError> {
        let buf = match self.read_message().await {
            Ok(b) => b,
            Err(e) => {
                self.broken = true;
                return Err(if e.kind() == std::io::ErrorKind::InvalidData {
                    tracing::warn!(
                        stage = stage.as_str(),
                        "malformed or oversized LDAP message"
                    );
                    LdError::new(FailureCode::Internal, stage)
                } else {
                    connect_error(&e, false, stage)
                });
            }
        };
        match proto::parse(&buf) {
            Ok(Message { id: got, op }) if got == id => Ok(op),
            Ok(_) => {
                self.broken = true;
                tracing::warn!(stage = stage.as_str(), "LDAP response to another request");
                Err(LdError::new(FailureCode::Internal, stage))
            }
            Err(ParseError::Disconnected) => {
                self.broken = true;
                tracing::warn!(stage = stage.as_str(), "the server closed the connection");
                Err(LdError::new(FailureCode::TargetUnreachable, stage))
            }
            Err(ParseError::Malformed) => {
                self.broken = true;
                tracing::warn!(stage = stage.as_str(), "malformed LDAP response");
                Err(LdError::new(FailureCode::Internal, stage))
            }
        }
    }

    /// One request, one response, within the exchange deadline.
    async fn single(&mut self, stage: Stage, request: &Enc) -> Result<Response, LdError> {
        if self.broken {
            return Err(LdError::new(FailureCode::Internal, stage));
        }
        let id = request_id(request);
        let deadline = self.timeouts.exchange();
        let r = tokio::time::timeout(deadline, async {
            self.send(request).await?;
            loop {
                match self.next(id, stage).await? {
                    Response::Intermediate => {}
                    other => return Ok(other),
                }
            }
        })
        .await;
        self.last_used = Instant::now();
        match r {
            Ok(r) => r,
            Err(_) => {
                self.broken = true;
                Err(LdError::new(FailureCode::Timeout, stage))
            }
        }
    }

    /// Runs a search, handing each entry to `on_entry` as it arrives. The
    /// whole search is bounded by the exchange deadline; its result code is
    /// in the [`Outcome`] (see [`Outcome::error`]).
    pub(crate) async fn search(
        &mut self,
        stage: Stage,
        s: &Search<'_>,
        on_entry: &mut (dyn FnMut(Entry) + Send),
    ) -> Result<Outcome, LdError> {
        if self.broken {
            return Err(LdError::new(FailureCode::Internal, stage));
        }
        let search = Search {
            time_limit: self.timeouts.time_limit(),
            ..s.clone()
        };
        let id = self.id();
        let request = proto::search(id, &search);
        let deadline = self.timeouts.exchange();
        let r = tokio::time::timeout(deadline, async {
            self.send(&request).await?;
            let mut outcome = Outcome {
                code: 0,
                entries: 0,
                references: 0,
            };
            loop {
                match self.next(id, stage).await? {
                    Response::Entry(e) => {
                        outcome.entries += 1;
                        if outcome.entries > u64::from(search.size_limit.max(1)) {
                            // More entries than the size limit asked: the
                            // server ignores the bound, and memory would
                            // follow it.
                            self.broken = true;
                            tracing::warn!(
                                stage = stage.as_str(),
                                "the server returned more entries than the size limit"
                            );
                            return Err(LdError::new(FailureCode::ResourceLimit, stage));
                        }
                        on_entry(e);
                    }
                    Response::Reference => {
                        outcome.references += 1;
                        if outcome.references > MAX_REFERENCES {
                            self.broken = true;
                            return Err(LdError::new(FailureCode::ResourceLimit, stage));
                        }
                    }
                    Response::Intermediate => {}
                    Response::Done { code } => {
                        outcome.code = code;
                        return Ok(outcome);
                    }
                    _ => {
                        self.broken = true;
                        return Err(LdError::new(FailureCode::Internal, stage));
                    }
                }
            }
        })
        .await;
        self.last_used = Instant::now();
        match r {
            Ok(r) => r,
            Err(_) => {
                // The server may still be sending: the connection is
                // dropped (the server abandons an operation whose client
                // is gone; the time limit bounds it anyway).
                self.broken = true;
                Err(LdError::new(FailureCode::Timeout, stage))
            }
        }
    }

    /// Whether the session can no longer be used.
    pub(crate) fn is_broken(&self) -> bool {
        self.broken
    }

    /// Whether the session was idle for longer than [`STALE_AFTER`].
    pub(crate) fn is_stale(&self) -> bool {
        self.last_used.elapsed() > STALE_AFTER
    }

    /// Unbinds (best effort) and closes the connection.
    pub(crate) async fn close(mut self) {
        if !self.broken {
            let request = proto::unbind(self.id());
            let io = self.io.get_mut();
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                let _ = io.write_all(request.as_bytes()).await;
                let _ = io.shutdown().await;
            })
            .await;
        }
    }
}

/// The message id of an encoded request (always the first INTEGER).
fn request_id(request: &Enc) -> i32 {
    let mut r = ber::Reader::new(request.as_bytes());
    r.nested(ber::SEQUENCE)
        .and_then(|mut m| m.int(ber::INTEGER))
        .ok()
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_are_whole_seconds_never_zero() {
        assert_eq!(Timeouts::new(Duration::ZERO).time_limit(), 1);
        assert_eq!(Timeouts::new(Duration::from_millis(1500)).time_limit(), 2);
        assert_eq!(Timeouts::new(Duration::from_secs(30)).time_limit(), 30);
        assert_eq!(
            Timeouts::new(Duration::from_secs(30)).exchange(),
            Duration::from_secs(32)
        );
    }

    fn target(yaml: &str) -> TargetConfig {
        databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
        ))
        .unwrap()
        .targets[0]
            .clone()
    }

    #[test]
    fn endpoints_and_default_ports() {
        let t =
            target("{id: t, engine: openldap, host: ldap.internal, account: a, secret: {env: PW}}");
        assert!(matches!(
            endpoint(&t, OpenldapTlsMode::VerifyFull).unwrap(),
            Endpoint::Tcp { port: 636, .. }
        ));
        assert!(matches!(
            endpoint(&t, OpenldapTlsMode::StartTls).unwrap(),
            Endpoint::Tcp { port: 389, .. }
        ));
        let t = target(
            "{id: t, engine: openldap, socket: /run/slapd/ldapi, account: a, \
             secret: {env: PW}, openldap: {tls: disable}}",
        );
        assert!(matches!(
            endpoint(&t, OpenldapTlsMode::Disable).unwrap(),
            Endpoint::Unix { .. }
        ));
    }

    #[tokio::test]
    async fn an_unreadable_secret_fails_before_connecting() {
        let t = target(
            "{id: t, engine: openldap, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_LDAP_SECRET}, openldap: {tls: disable}}",
        );
        let e = Session::connect(&t, Timeouts::new(Duration::from_secs(1)))
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
        assert_eq!(e.stage, Stage::Secret);
    }
}
