//! Opening a declared node, identifying it and evaluating the account
//! (ADR-0052 decisions 2 to 5 and 9), shared by `check()` and Discovery.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use databastion_core::FailureCode;
use databastion_core::config::redis::{RedisTargetConfig, RedisTlsMode, UnevaluatedAcl};
use databastion_core::config::{TargetConfig, TargetEngine};
use zeroize::Zeroizing;

use crate::acl::{self, Evaluation, PROBES, Verdict};
use crate::cmd::{Cmd, InfoSection, KeyProbe};
use crate::conn::{MAX_PIPELINE, Session};
use crate::error::{RdError, Stage};
use crate::info::{self, Server};
use crate::net::{self, Endpoint};
use crate::resp::Value;

/// Period of the privilege report (decision 9).
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);

/// Which declared node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Which {
    /// The target's node (`check()`, Audit).
    Target,
    /// `redis.discovery_node` when declared, else the target's node.
    Discovery,
}

/// The endpoint of a node.
pub(crate) fn endpoint(target: &TargetConfig, which: Which) -> Option<Endpoint> {
    let settings = target.redis_settings();
    let (host, port, socket) = match (which, &settings.discovery_node) {
        (Which::Discovery, Some(n)) => (n.host.clone(), n.port, n.socket.clone()),
        _ => (target.host.clone(), target.port, target.socket.clone()),
    };
    match (host, socket) {
        (Some(host), None) => Some(Endpoint::Tcp {
            host,
            port: port.unwrap_or(databastion_core::config::redis::DEFAULT_PORT),
        }),
        (None, Some(path)) => Some(Endpoint::Unix {
            path,
            server_uid: settings.server_uid,
        }),
        _ => None,
    }
}

/// What the connector knows of an opened node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodeInfo {
    pub(crate) server: Server,
    pub(crate) cluster: bool,
    pub(crate) replica: bool,
}

/// Why a node cannot be used, beyond an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `unevaluated_acl` set on a server with `ACL DRYRUN` (configuration
    /// error, implementation obligation).
    MisplacedOptIn,
    /// Redis 6.2 without `unevaluated_acl: accept`.
    NotEvaluated,
    /// The refusal list (decision 4).
    Listed,
}

/// Opens an authenticated session to a node and identifies it.
pub(crate) async fn open(
    target: &TargetConfig,
    which: Which,
    timeout: Duration,
) -> Result<(Session, NodeInfo), RdError> {
    let settings = target.redis_settings();
    let endpoint = endpoint(target, which)
        .ok_or_else(|| RdError::new(FailureCode::Internal, Stage::Connect))?;
    let password: Zeroizing<String> = target
        .secret
        .read()
        .map_err(|_| RdError::new(FailureCode::AuthenticationFailed, Stage::Secret))?;
    let tls = tls_of(&settings)?;
    let mut session = Session::open(&endpoint, tls, &target.account, &password, timeout).await?;
    drop(password);
    let info = identify(&mut session, timeout).await?;
    Ok((session, info))
}

/// The TLS configuration of a target (`None`: `disable`).
pub(crate) fn tls_of(
    settings: &RedisTargetConfig,
) -> Result<Option<std::sync::Arc<rustls::ClientConfig>>, RdError> {
    match settings.tls {
        RedisTlsMode::Disable => Ok(None),
        RedisTlsMode::VerifyFull => {
            let client = match (&settings.client_cert, &settings.client_key) {
                (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
                _ => None,
            };
            net::tls_config(settings.ca_file.as_deref(), client).map(Some)
        }
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_bytes()
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(str::to_owned)
}

/// `INFO server`, `INFO replication`, `INFO cluster`: the engine, version,
/// mode and role. Sentinel and versions below the floors are refused.
pub(crate) async fn identify(
    session: &mut Session,
    timeout: Duration,
) -> Result<NodeInfo, RdError> {
    let replies = session
        .pipeline(
            &[
                Cmd::Info(InfoSection::Server),
                Cmd::Info(InfoSection::Replication),
                Cmd::Info(InfoSection::Cluster),
            ],
            timeout,
            Stage::Introspection,
        )
        .await?;
    let unsupported = || RdError::new(FailureCode::Unsupported, Stage::Introspection);
    let [server, replication, cluster] = replies.as_slice() else {
        return Err(unsupported());
    };
    if let Some(w) = server.error() {
        return Err(RdError::reply(w, Stage::Introspection));
    }
    let server_text = text(server).ok_or_else(unsupported)?;
    if session.hello.sentinel || info::is_sentinel(&server_text) {
        tracing::warn!("Redis / Valkey: a Sentinel node is not a target (ADR-0052 decision 5)");
        return Err(unsupported());
    }
    let engine = info::server(&server_text).ok_or_else(unsupported)?;
    let v = engine.version();
    tracing::info!(
        engine = if engine.is_valkey() {
            "valkey"
        } else {
            "redis"
        },
        version = format!("{}.{}.{}", v.0, v.1, v.2),
        "Redis / Valkey server identified"
    );
    if !engine.supported() {
        tracing::warn!("Redis / Valkey: server version below the supported floor");
        return Err(unsupported());
    }
    Ok(NodeInfo {
        server: engine,
        cluster: text(cluster).is_some_and(|t| info::cluster_enabled(&t)),
        replica: text(replication).is_some_and(|t| info::is_replica(&t)),
    })
}

/// The evaluation of the account, with the declarations it confirmed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// `None`: not evaluated (Redis 6.2).
    pub(crate) eval: Option<Evaluation>,
    /// Declared key patterns the account cannot read (`None`: not
    /// evaluated), by index in `key_patterns`.
    pub(crate) patterns_not_readable: Option<Vec<usize>>,
    /// Declared databases the account cannot select (Valkey 9.1+).
    pub(crate) databases_not_readable: Option<Vec<u16>>,
    /// CAS-guarded probe keys the account could read (`None`: not
    /// evaluated).
    pub(crate) ticket_keys_readable: Option<u64>,
}

impl Report {
    /// Why Discovery must not run, if it must not.
    pub(crate) fn refusal(&self, settings: &RedisTargetConfig, server: Server) -> Option<Refusal> {
        let opt_in = settings.unevaluated_acl == Some(UnevaluatedAcl::Accept);
        if server.has_dryrun() {
            if opt_in {
                return Some(Refusal::MisplacedOptIn);
            }
            return match &self.eval {
                Some(e) if !e.refuses() => None,
                _ => Some(Refusal::Listed),
            };
        }
        (!opt_in).then_some(Refusal::NotEvaluated)
    }
}

/// Key names probed for the CAS guard's key privilege (decision 6).
const GUARD_PROBE_KEYS: [&[u8]; 2] = [
    b"TGT-1-databastion-probe",
    b"CAS_TICKET:TGT-1-databastion-probe",
];

/// Evaluates the account with `ACL DRYRUN` (decision 4): the probes, the
/// declared key patterns and databases, the CAS guard's key privilege. The
/// first `DRYRUN` is sent alone: when it is refused (no `+acl|dryrun`),
/// nothing more is sent, so the evaluation costs at most one `ACL LOG`
/// entry.
pub(crate) async fn evaluate(
    session: &mut Session,
    target: &TargetConfig,
    server: Server,
    timeout: Duration,
) -> Result<Report, RdError> {
    if !server.has_dryrun() {
        return Ok(Report::default());
    }
    let user = target.account.as_str();
    let settings = target.redis_settings();
    let mut verdicts: Vec<Verdict> = Vec::with_capacity(PROBES.len());
    let mut probes = PROBES.iter();
    if let Some(first) = probes.next() {
        let reply = session
            .call(&Cmd::DryRun { user, probe: first }, timeout, Stage::Check)
            .await?;
        if reply.error().is_some() {
            tracing::warn!(
                "Redis / Valkey: ACL DRYRUN is not granted to the agent's account \
                 (+acl|dryrun): the account cannot be evaluated"
            );
            return Ok(Report {
                eval: Some(Evaluation::of(&[])),
                ..Report::default()
            });
        }
        verdicts.push(acl::verdict(&reply));
    }
    let rest: Vec<&'static acl::Probe> = probes.collect();
    for chunk in rest.chunks(MAX_PIPELINE) {
        let cmds: Vec<Cmd<'_>> = chunk
            .iter()
            .map(|probe| Cmd::DryRun { user, probe })
            .collect();
        let replies = session.pipeline(&cmds, timeout, Stage::Check).await?;
        verdicts.extend(replies.iter().map(acl::verdict));
    }
    let eval = Evaluation::of(&verdicts);

    // Declared key patterns (a constant key matching each).
    let declared: Vec<&String> = settings.key_patterns.iter().collect();
    let mut not_readable = Vec::new();
    let examples: Vec<(usize, Vec<u8>)> = declared
        .iter()
        .enumerate()
        .filter_map(|(i, p)| match crate::glob::example(p.as_bytes()) {
            Some(k) => Some((i, k)),
            None => {
                not_readable.push(i);
                None
            }
        })
        .collect();
    for chunk in examples.chunks(MAX_PIPELINE) {
        let cmds: Vec<Cmd<'_>> = chunk
            .iter()
            .map(|(_, key)| Cmd::DryRunKey {
                user,
                probe: KeyProbe::Type,
                key,
            })
            .collect();
        let replies = session.pipeline(&cmds, timeout, Stage::Check).await?;
        for ((i, _), r) in chunk.iter().zip(&replies) {
            if acl::readable(r) != Some(true) {
                not_readable.push(*i);
            }
        }
    }

    // Declared databases (Valkey 9.1+ `db=`).
    let databases_not_readable = match (&settings.databases, server.has_db_acl()) {
        (Some(dbs), true) => {
            let mut out = Vec::new();
            for chunk in dbs.chunks(MAX_PIPELINE) {
                let cmds: Vec<Cmd<'_>> = chunk
                    .iter()
                    .map(|db| Cmd::DryRunSelect { user, db: *db })
                    .collect();
                let replies = session.pipeline(&cmds, timeout, Stage::Check).await?;
                for (db, r) in chunk.iter().zip(&replies) {
                    if acl::readable(r) != Some(true) {
                        out.push(*db);
                    }
                }
            }
            Some(out)
        }
        _ => Some(Vec::new()),
    };

    // The CAS guard's key privilege.
    let mut guard_keys: Vec<Vec<u8>> = GUARD_PROBE_KEYS.iter().map(|k| k.to_vec()).collect();
    if let Some(stores) = target.cas_stores() {
        for p in stores.ticket_registry.iter().take(16) {
            if let Some(k) = crate::glob::example(p.as_bytes()) {
                guard_keys.push(k);
            }
        }
    }
    let cmds: Vec<Cmd<'_>> = guard_keys
        .iter()
        .map(|key| Cmd::DryRunKey {
            user,
            probe: KeyProbe::GetRange,
            key,
        })
        .collect();
    let replies = session.pipeline(&cmds, timeout, Stage::Check).await?;
    let readable = replies
        .iter()
        .filter(|r| acl::readable(r) != Some(false))
        .count() as u64;

    Ok(Report {
        eval: Some(eval),
        patterns_not_readable: Some(not_readable),
        databases_not_readable,
        ticket_keys_readable: Some(readable),
    })
}

/// Reports per target, at most every [`REPORT_INTERVAL`].
#[derive(Default)]
pub(crate) struct Reports(Mutex<HashMap<String, (Instant, Report)>>);

impl Reports {
    pub(crate) fn fresh(&self, target_id: &str) -> Option<Report> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .filter(|(at, _)| at.elapsed() < REPORT_INTERVAL)
            .map(|(_, r)| r.clone())
    }

    pub(crate) fn store(&self, target_id: &str, report: Report) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), (Instant::now(), report));
    }
}

/// Whether the declared engine differs from the server's (decision 9).
pub(crate) fn engine_mismatch(target: &TargetConfig, server: Server) -> Option<bool> {
    match (target.engine, server.is_valkey()) {
        (TargetEngine::Redis, true) => Some(true),
        (TargetEngine::Valkey, false) => Some(false),
        _ => None,
    }
}
