//! Redis / Valkey connector for the DataBastion agent (phase 9, ADR-0052).
//!
//! - [`check`](Connector::check): reachability (socket peer, TLS, `AUTH`,
//!   `HELLO 3`), engine and version (Redis 6.2.7+ and Valkey 7.2+ only),
//!   Sentinel refused and Cluster noted, the account evaluated with
//!   `ACL DRYRUN` over one closed probe table (writes, reads beyond
//!   Discovery, administration, scripting, pub/sub; the refusal list stops
//!   the target), the declared key patterns and databases confirmed, the
//!   CAS guard's key privilege, and the server's `default` user probe.
//! - Discovery ([`discover`](Connector::discover)): per logical database, a
//!   bounded `SCAN` walk, names filtered against the declared patterns and
//!   the CAS guard before any `TYPE`, normalized into key patterns emitted
//!   after the walk, then bounded sampling per type. Values are classified
//!   through `ScanJob::classify`; only masked findings reach the sink (I2).
//!   Locations: `db<index>`, the Redis type, the key pattern, the field.
//! - Audit: not in this version (a later lot of P9-B); `check()` reports
//!   `audit.stream_not_available`.
//!
//! The connector only reads (I4): its own RESP3 client can encode no
//! write command. It connects only to the declared node and Discovery node
//! (I5; no Cluster or Sentinel topology following), with credentials from
//! `agent.yaml` references (I3), over rustls TLS, or a Unix socket or a
//! loopback address.

#![forbid(unsafe_code)]
// Server input is sliced in this crate: slicing must be proven safe.
#![cfg_attr(not(test), deny(clippy::string_slice, clippy::indexing_slicing))]

mod acl;
mod check;
mod cmd;
mod conn;
mod discover;
mod error;
mod glob;
mod guard;
mod info;
mod net;
mod node;
mod resp;

/// Fuzz target entry points (`agent/fuzz`); `fuzzing` feature only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;

#[cfg(test)]
mod it;
#[cfg(test)]
mod proptests;

use async_trait::async_trait;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, Connector, ConnectorError, Engine, EventSink, FindingSink, ScanJob, TargetHealth,
};

/// Redis / Valkey connector. One instance serves every declared Redis and
/// Valkey target.
#[derive(Default)]
#[non_exhaustive]
pub struct RedisConnector {
    state: check::CheckState,
}

impl std::fmt::Debug for RedisConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConnector").finish_non_exhaustive()
    }
}

impl RedisConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Connector for RedisConnector {
    fn engine(&self) -> Engine {
        Engine::Redis
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        check::check(&self.state, target).await
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        discover::discover(job, sink, &self.state).await
    }

    async fn audit_stream(
        &self,
        _cfg: &AuditConfig,
        _sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        Err(ConnectorError::NotImplemented {
            engine: Engine::Redis,
            operation: "audit_stream",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_core::{AuditLevel, FailureCode};

    fn target(yaml: &str) -> TargetConfig {
        let config = databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
        ))
        .unwrap();
        config.targets[0].clone()
    }

    #[tokio::test]
    async fn unreadable_secret_is_reported_without_connecting() {
        let connector = RedisConnector::new();
        let t = target(
            "{id: t, engine: valkey, host: 127.0.0.1, port: 9, account: a, \
             secret: {env: DATABASTION_TEST_UNSET_REDIS_SECRET}, redis: {tls: disable}}",
        );
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(
            health.notes[0].code(),
            databastion_core::NoteCode::CheckStageFailed
        );
    }

    #[tokio::test]
    async fn default_job_without_target_fails_closed() {
        let connector = RedisConnector::new();
        assert_eq!(connector.engine(), Engine::Redis);
        assert!(!connector.supports_audit());
        let (findings, _rx) = FindingSink::channel(1);
        let r = connector.discover(&ScanJob::default(), &findings).await;
        assert!(matches!(
            r,
            Err(ConnectorError::Target {
                engine: Engine::Redis,
                code: FailureCode::Internal,
                ..
            })
        ));
    }

    #[test]
    fn configuration_rules() {
        let parse = |yaml: &str| {
            databastion_core::AgentConfig::parse(&format!(
                "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{yaml}]}}"
            ))
        };
        // `default` is never the agent's account.
        assert!(
            parse("{id: t, engine: redis, host: r.example, account: default, secret: {env: X}}")
                .is_err()
        );
        // No cleartext on a network.
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {tls: disable}}").is_err());
        assert!(parse("{id: t, engine: redis, host: 127.0.0.1, account: a, secret: {env: X}, redis: {tls: disable}}").is_ok());
        assert!(parse("{id: t, engine: redis, host: localhost, account: a, secret: {env: X}, redis: {tls: disable}}").is_err());
        // A socket needs `disable`.
        assert!(parse("{id: t, engine: valkey, socket: /run/valkey/valkey.sock, account: a, secret: {env: X}}").is_err());
        assert!(parse("{id: t, engine: valkey, socket: /run/valkey/valkey.sock, account: a, secret: {env: X}, redis: {tls: disable, server_uid: 999}}").is_ok());
        // Limits and declarations.
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {max_keys: 10}}").is_err());
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {key_patterns: []}}").is_err());
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {client_cert: /c.pem}}").is_err());
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {databases: [0, 0]}}").is_err());
        assert!(parse("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}, redis: {discovery_node: {host: replica.example}, key_patterns: ['user:*'], databases: [0, 1], unevaluated_acl: accept}}").is_ok());
        // The block belongs to Redis / Valkey targets.
        assert!(parse("{id: t, engine: postgres, host: p.example, account: a, secret: {env: X}, redis: {}}").is_err());
        let t = target("{id: t, engine: redis, host: r.example, account: a, secret: {env: X}}");
        assert_eq!(t.effective_port(), Some(6379));
    }
}
