//! A session: one connection to the declared target (I5), `hello`,
//! SCRAM-SHA-256, then the connector's commands (ADR-0026 decisions 1 to
//! 4, 6).
//!
//! - Only the configured host / socket is contacted: the `hosts`, `me` or
//!   `primary` fields of `hello` are never read.
//! - Every exchange has a client-side deadline (`maxTimeMS` plus a
//!   margin); a timed-out, broken or malformed exchange makes the session
//!   unusable (the caller reconnects).
//! - [`Kind::Read`] commands carry `maxTimeMS` and
//!   `$readPreference: secondaryPreferred`; setup commands (`hello`,
//!   `saslStart`, `saslContinue`, `buildInfo`) and `killCursors` are
//!   bounded client-side only.
//! - No logical session id is sent: no server session, no transaction.

use std::time::{Duration, Instant};

use databastion_core::FailureCode;
use databastion_core::config::{MongodbTlsMode, TargetConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::bson::{DocBuf, Value};
use crate::error::{MgError, Stage};
use crate::net::{Endpoint, Transport};
use crate::scram::{self, Scram};
use crate::tls;
use crate::wire::{Reply, Wire};

/// Oldest server accepted: wire version 13 is MongoDB 5.0.
pub(crate) const MIN_WIRE_VERSION: i64 = 13;
/// A session idle for longer is replaced before its next command.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60);
/// Client-side margin on top of `maxTimeMS`.
const CLIENT_MARGIN: Duration = Duration::from_secs(2);
/// Application name in the `hello` handshake (server logs, profiler).
pub(crate) const APP_NAME: &str = "databastion-agent";
/// Default MongoDB port.
const DEFAULT_PORT: u16 = 27017;

/// Statement timeout of a session: `maxTimeMS` of every read command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    statement: Duration,
}

impl Timeouts {
    /// At least 100 ms: never `0` (no limit in MongoDB).
    pub(crate) fn new(statement: Duration) -> Self {
        Self {
            statement: statement.max(Duration::from_millis(100)),
        }
    }

    /// `maxTimeMS` (never `0`).
    pub(crate) fn max_time_ms(self) -> i64 {
        i64::try_from(self.statement.as_millis())
            .unwrap_or(i64::MAX)
            .max(100)
    }

    /// Client-side deadline of one exchange.
    fn exchange(self) -> Duration {
        self.statement.saturating_add(CLIENT_MARGIN)
    }
}

/// How a command is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Bounded client-side only (`hello`, SASL, `buildInfo`,
    /// `killCursors`).
    Setup,
    /// `maxTimeMS` and `$readPreference: secondaryPreferred`.
    Read,
}

/// What `hello` told about the server (kinds only: never a host).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ServerInfo {
    pub(crate) max_wire_version: i64,
    /// A `mongos` router.
    pub(crate) mongos: bool,
}

/// One connection.
pub(crate) struct Session<S = Transport> {
    wire: Wire<S>,
    timeouts: Timeouts,
    last_used: Instant,
    broken: bool,
    pub(crate) info: ServerInfo,
}

impl<S> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("broken", &self.broken)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Where the target listens.
fn endpoint(target: &TargetConfig) -> Result<Endpoint, MgError> {
    match (&target.host, &target.socket) {
        (Some(host), None) => Ok(Endpoint::Tcp {
            host: host.clone(),
            port: target.port.unwrap_or(DEFAULT_PORT),
        }),
        (None, Some(path)) => Ok(Endpoint::Unix { path: path.clone() }),
        _ => Err(MgError::new(FailureCode::Internal, Stage::Connect)),
    }
}

fn client_metadata(app: &str) -> DocBuf {
    DocBuf::new()
        .doc("application", DocBuf::new().str("name", app))
        .doc(
            "driver",
            DocBuf::new()
                .str("name", APP_NAME)
                .str("version", env!("CARGO_PKG_VERSION")),
        )
        .doc("os", DocBuf::new().str("type", std::env::consts::OS))
}

impl Session<Transport> {
    /// Connects to `target` with its `agent.yaml` settings, then runs
    /// `hello` and authenticates.
    pub(crate) async fn connect(
        target: &TargetConfig,
        timeouts: Timeouts,
    ) -> Result<Self, MgError> {
        Self::connect_with_app(target, timeouts, APP_NAME).await
    }

    /// [`Self::connect`] declaring another application name (the
    /// integration tests play dump tools with it).
    #[cfg(test)]
    pub(crate) async fn connect_as(
        target: &TargetConfig,
        timeouts: Timeouts,
        app: &str,
    ) -> Result<Self, MgError> {
        Self::connect_with_app(target, timeouts, app).await
    }

    async fn connect_with_app(
        target: &TargetConfig,
        timeouts: Timeouts,
        app: &str,
    ) -> Result<Self, MgError> {
        let settings = target.mongodb_settings();
        let password = target.secret.read().map_err(|e| {
            tracing::warn!(target_id = %target.id, error = %e, "target secret unavailable");
            MgError::new(FailureCode::AuthenticationFailed, Stage::Secret)
        })?;
        let endpoint = endpoint(target)?;
        let tls = match settings.tls {
            MongodbTlsMode::VerifyFull => {
                Some(tls::verify_full(settings.ca_file.as_deref()).map_err(|e| {
                    tracing::warn!(target_id = %target.id, error = %e, "TLS configuration failed");
                    MgError::new(FailureCode::Internal, Stage::Tls)
                })?)
            }
            MongodbTlsMode::Disable => None,
            MongodbTlsMode::DisableInsecure => {
                tracing::warn!(
                    target_id = %target.id,
                    "INSECURE: TLS disabled on a network connection (tls: disable_insecure): \
                     samples and commands travel in clear, and an attacker on the path can relay \
                     the authentication: read-only is not guaranteed"
                );
                None
            }
        };
        let with_tls = tls.is_some();
        let transport = endpoint.open(tls).await.map_err(|e| {
            // rustls reports a refused certificate as `InvalidData`.
            let stage = if with_tls && e.kind() == std::io::ErrorKind::InvalidData {
                Stage::Tls
            } else {
                Stage::Connect
            };
            tracing::debug!(kind = %e.kind(), stage = stage.as_str(), "connection failed");
            let code = if e.kind() == std::io::ErrorKind::TimedOut {
                FailureCode::Timeout
            } else {
                FailureCode::TargetUnreachable
            };
            MgError::new(code, stage)
        })?;
        Self::establish_as(
            Wire::new(transport),
            timeouts,
            (&target.account, &password, &settings.auth_source),
            app,
        )
        .await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// `hello` (minimum wire version checked), then SCRAM-SHA-256.
    #[cfg(test)]
    pub(crate) async fn establish(
        wire: Wire<S>,
        timeouts: Timeouts,
        user: &str,
        password: &str,
        auth_source: &str,
    ) -> Result<Self, MgError> {
        Self::establish_as(wire, timeouts, (user, password, auth_source), APP_NAME).await
    }

    /// `hello` declaring `app`, then SCRAM-SHA-256 as `(user, password,
    /// auth_source)`.
    async fn establish_as(
        wire: Wire<S>,
        timeouts: Timeouts,
        (user, password, auth_source): (&str, &str, &str),
        app: &str,
    ) -> Result<Self, MgError> {
        let mut s = Self {
            wire,
            timeouts,
            last_used: Instant::now(),
            broken: false,
            info: ServerInfo::default(),
        };
        let hello = DocBuf::new()
            .i32("hello", 1)
            .bool("helloOk", true)
            .doc("client", client_metadata(app))
            .str("$db", "admin")
            .finish();
        let reply = s.exchange(Stage::SessionSetup, &hello).await?;
        let doc = reply.doc();
        let bad = |_| MgError::new(FailureCode::Internal, Stage::SessionSetup);
        let max_wire_version = doc.int("maxWireVersion").map_err(bad)?.unwrap_or(0);
        if max_wire_version < MIN_WIRE_VERSION {
            tracing::warn!(
                max_wire_version,
                "server older than MongoDB 5.0: not supported"
            );
            return Err(MgError::new(FailureCode::Unsupported, Stage::SessionSetup));
        }
        s.info = ServerInfo {
            max_wire_version,
            mongos: doc.str("msg").map_err(bad)? == Some("isdbgrid"),
        };
        s.authenticate(user, password, auth_source).await?;
        Ok(s)
    }

    /// SCRAM-SHA-256 with mutual authentication: the server signature is
    /// verified before `done` is trusted.
    async fn authenticate(
        &mut self,
        user: &str,
        password: &str,
        auth_source: &str,
    ) -> Result<(), MgError> {
        let refused = || MgError::new(FailureCode::AuthenticationFailed, Stage::Auth);
        let (exchange, first) =
            Scram::start(user).map_err(|_| MgError::new(FailureCode::Internal, Stage::Auth))?;
        let start = DocBuf::new()
            .i32("saslStart", 1)
            .str("mechanism", scram::MECHANISM)
            .binary("payload", &first)
            .i32("autoAuthorize", 1)
            .doc("options", DocBuf::new().bool("skipEmptyExchange", true))
            .str("$db", auth_source)
            .finish();
        let reply = self.exchange(Stage::Auth, &start).await?;
        let (conversation, done, server_first) = sasl_reply(&reply).ok_or_else(refused)?;
        if done {
            // Done before the client proved anything, and without a
            // server signature: no mutual authentication.
            self.broken = true;
            return Err(refused());
        }
        // PBKDF2 (up to `scram::MAX_ITERATIONS` rounds) runs on the
        // blocking pool, not on the async runtime, and within the exchange
        // deadline.
        let owned_password = Zeroizing::new(password.to_owned());
        let derivation = tokio::task::spawn_blocking(move || {
            exchange.client_final(&server_first, &owned_password)
        });
        let (last, expected) =
            match tokio::time::timeout(self.timeouts.exchange(), derivation).await {
                Ok(Ok(Ok(v))) => v,
                Ok(Ok(Err(e))) => {
                    self.broken = true;
                    return Err(MgError::from_scram(e));
                }
                Ok(Err(_)) => {
                    self.broken = true;
                    return Err(MgError::new(FailureCode::Internal, Stage::Auth));
                }
                Err(_) => {
                    self.broken = true;
                    return Err(MgError::new(FailureCode::Timeout, Stage::Auth));
                }
            };
        // Sized for every element (keys, lengths, types, terminators):
        // built without reallocating (no stray copy of the proof).
        let capacity = 128 + last.len() + auth_source.len();
        let body = Zeroizing::new(
            DocBuf::with_capacity(capacity)
                .i32("saslContinue", 1)
                .i32("conversationId", conversation)
                .binary("payload", &last)
                .str("$db", auth_source)
                .finish(),
        );
        debug_assert!(body.len() <= capacity, "the saslContinue body grew");
        let reply = self.exchange(Stage::Auth, &body).await?;
        let (_, done, server_final) = sasl_reply(&reply).ok_or_else(refused)?;
        expected.verify(&server_final).map_err(|e| {
            self.broken = true;
            MgError::from_scram(e)
        })?;
        if !done {
            // Servers that do not honour `skipEmptyExchange`: one empty
            // step, after the signature was verified.
            let body = DocBuf::new()
                .i32("saslContinue", 1)
                .i32("conversationId", conversation)
                .binary("payload", &[])
                .str("$db", auth_source)
                .finish();
            let reply = self.exchange(Stage::Auth, &body).await?;
            let (_, done, _) = sasl_reply(&reply).ok_or_else(refused)?;
            if !done {
                self.broken = true;
                return Err(refused());
            }
        }
        Ok(())
    }

    /// Sends a command to `db` and returns its reply when `ok` is 1.
    pub(crate) async fn command(
        &mut self,
        stage: Stage,
        db: &str,
        command: DocBuf,
        kind: Kind,
    ) -> Result<Reply, MgError> {
        let command = match kind {
            Kind::Read => command.i64("maxTimeMS", self.timeouts.max_time_ms()).doc(
                "$readPreference",
                DocBuf::new().str("mode", "secondaryPreferred"),
            ),
            Kind::Setup => command,
        };
        let body = command.str("$db", db).finish();
        self.exchange(stage, &body).await
    }

    /// Kills a cursor the connector will not read further (a batch cut by
    /// the reply limit, a truncated listing). Never `getMore`.
    pub(crate) async fn kill_cursor(&mut self, db: &str, collection: &str, id: i64) {
        let command = DocBuf::new()
            .str("killCursors", collection)
            .array_i64("cursors", &[id]);
        if let Err(e) = self.command(Stage::Kill, db, command, Kind::Setup).await {
            tracing::warn!(
                stage = e.stage.as_str(),
                server_code = e.server_code,
                "killCursors failed: the cursor stays open until the server's idle cursor timeout"
            );
            // The connection is dropped: the next command reconnects.
            self.broken = true;
        }
    }

    /// One round trip with the client-side deadline and the `ok` check.
    async fn exchange(&mut self, stage: Stage, body: &[u8]) -> Result<Reply, MgError> {
        if self.broken {
            return Err(MgError::new(FailureCode::Internal, stage));
        }
        let result =
            tokio::time::timeout(self.timeouts.exchange(), self.wire.round_trip(body)).await;
        self.last_used = Instant::now();
        let reply = match result {
            Err(_) => {
                self.broken = true;
                return Err(MgError::new(FailureCode::Timeout, stage));
            }
            Ok(Err(e)) => {
                self.broken = true;
                return Err(MgError::from_wire(e, stage));
            }
            Ok(Ok(reply)) => reply,
        };
        let doc = reply.doc();
        match doc.flag("ok") {
            Ok(Some(true)) => Ok(reply),
            Ok(_) => {
                let code = doc
                    .int("code")
                    .ok()
                    .flatten()
                    .and_then(|c| i32::try_from(c).ok());
                let e = MgError::server(code, stage);
                if e.fatal {
                    self.broken = true;
                }
                Err(e)
            }
            Err(_) => {
                self.broken = true;
                Err(MgError::new(FailureCode::Internal, stage))
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

    /// Closes the connection.
    pub(crate) async fn close(mut self) {
        self.wire.shutdown().await;
    }
}

/// `conversationId`, `done` and `payload` of a SASL reply.
fn sasl_reply(reply: &Reply) -> Option<(i32, bool, Vec<u8>)> {
    let doc = reply.doc();
    let conversation = i32::try_from(doc.int("conversationId").ok()??).ok()?;
    let done = doc.flag("done").ok()??;
    let payload = match doc.get("payload").ok()? {
        Some(Value::Binary(_, data)) => data.to_vec(),
        _ => return None,
    };
    Some((conversation, done, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_are_never_zero() {
        assert_eq!(Timeouts::new(Duration::ZERO).max_time_ms(), 100);
        assert_eq!(Timeouts::new(Duration::from_secs(30)).max_time_ms(), 30_000);
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
    fn endpoints() {
        let t =
            target("{id: t, engine: mongodb, host: db.internal, account: a, secret: {env: PW}}");
        assert!(matches!(
            endpoint(&t).unwrap(),
            Endpoint::Tcp { port: 27017, .. }
        ));
        let t = target(
            "{id: t, engine: mongodb, socket: /tmp/mongodb-27017.sock, account: a, \
             secret: {env: PW}, mongodb: {tls: disable}}",
        );
        assert!(matches!(endpoint(&t).unwrap(), Endpoint::Unix { .. }));
    }

    #[tokio::test]
    async fn an_unreadable_secret_fails_before_connecting() {
        let t = target(
            "{id: t, engine: mongodb, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_MONGO_SECRET}, mongodb: {tls: disable}}",
        );
        let e = Session::connect(&t, Timeouts::new(Duration::from_secs(1)))
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
        assert_eq!(e.stage, Stage::Secret);
    }
}
