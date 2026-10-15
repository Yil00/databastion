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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// The server run ([`info::run_hash`]).
    pub(crate) run: Option<u64>,
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
    session.register_own(&target.id, info.run);
    // The address the target's node reports for it, before any other
    // command (the Audit stream reads that node's logs only).
    if node_of(target, which) == Which::Target {
        session.learn_own_address(&target.id, timeout).await?;
    }
    Ok((session, info))
}

/// After an evaluation on the target's node: whether the account holds
/// `+client|list` there (when evaluated), and this session's address if it
/// is not recorded yet ([`Session::learn_own_address`]).
async fn after_evaluation(
    session: &mut Session,
    target: &TargetConfig,
    which: Which,
    report: &Report,
    timeout: Duration,
) -> Result<(), RdError> {
    if which != Which::Target {
        return Ok(());
    }
    if let Some(granted) = report.audit.client_list {
        crate::audit::own::set_client_list(&target.id, granted);
    }
    session.learn_own_address(&target.id, timeout).await
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
        run: info::run_hash(&server_text),
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
    /// The account may run `ACL DRYRUN` (the first probe was answered).
    pub(crate) dryrun_granted: bool,
    /// The Audit reads the account may run (decision 8).
    pub(crate) audit: acl::AuditGrants,
}

/// The union of two optional index lists (`None` when either is).
fn union<T: Ord + Clone>(a: Option<&Vec<T>>, b: Option<&Vec<T>>) -> Option<Vec<T>> {
    let (a, b) = (a?, b?);
    let mut out: Vec<T> = a.iter().chain(b).cloned().collect();
    out.sort();
    out.dedup();
    Some(out)
}

impl Report {
    /// The worse of two nodes' reports (the target's node and the
    /// Discovery node, security review M2): what either node allows or
    /// leaves unevaluated counts.
    pub(crate) fn worst(&self, other: &Self) -> Self {
        Self {
            eval: match (&self.eval, &other.eval) {
                (Some(a), Some(b)) => Some(a.worst(b)),
                _ => None,
            },
            patterns_not_readable: union(
                self.patterns_not_readable.as_ref(),
                other.patterns_not_readable.as_ref(),
            ),
            databases_not_readable: union(
                self.databases_not_readable.as_ref(),
                other.databases_not_readable.as_ref(),
            ),
            ticket_keys_readable: match (self.ticket_keys_readable, other.ticket_keys_readable) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            },
            dryrun_granted: self.dryrun_granted && other.dryrun_granted,
            // Audit reads the target's node only.
            audit: self.audit,
        }
    }

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

    // The Audit reads (decision 8): each sent only when allowed (H3).
    let reads: Vec<acl::AuditRead> = acl::AuditRead::ALL
        .into_iter()
        .filter(|r| *r != acl::AuditRead::Commandlog || server.has_commandlog())
        .collect();
    let cmds: Vec<Cmd<'_>> = reads
        .iter()
        .map(|r| Cmd::DryRun {
            user,
            probe: r.probe(),
        })
        .collect();
    let replies = session.pipeline(&cmds, timeout, Stage::Check).await?;
    let mut audit = acl::AuditGrants::default();
    for (r, reply) in reads.iter().zip(&replies) {
        audit.set(
            *r,
            match acl::verdict(reply) {
                Verdict::Allowed => Some(true),
                Verdict::Denied => Some(false),
                Verdict::NotEvaluated => None,
            },
        );
    }
    if !server.has_commandlog() {
        audit.commandlog = Some(false);
    }

    Ok(Report {
        eval: Some(eval),
        patterns_not_readable: Some(not_readable),
        databases_not_readable,
        ticket_keys_readable: Some(readable),
        dryrun_granted: true,
        audit,
    })
}

/// The node a report belongs to: the Discovery node when one is declared,
/// else the target's node for both.
fn node_of(target: &TargetConfig, which: Which) -> Which {
    match which {
        Which::Discovery if target.redis_settings().discovery_node.is_some() => Which::Discovery,
        _ => Which::Target,
    }
}

/// What the `default` user probe found (decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DefaultUser {
    /// `None`: the probe could not run.
    pub(crate) open: Option<bool>,
    /// Refusal-list commands the `default` user may run (`None`: not
    /// graded).
    pub(crate) grade: Option<u64>,
}

type Cached<T> = Mutex<HashMap<String, (Instant, T)>>;
/// A node's report and the server it was read on.
type NodeReports = Mutex<HashMap<(String, Which), (Instant, Report, Server)>>;

/// Reports per target and node, and the `default` user probe per target,
/// each recomputed at most every [`REPORT_INTERVAL`] (security review M2,
/// L3).
#[derive(Default)]
pub(crate) struct Reports {
    nodes: NodeReports,
    default_user: Cached<DefaultUser>,
}

impl Reports {
    fn fresh(&self, target_id: &str, which: Which) -> Option<(Report, Server)> {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(target_id.to_owned(), which))
            .filter(|(at, _, _)| at.elapsed() < REPORT_INTERVAL)
            .map(|(_, r, s)| (r.clone(), *s))
    }

    fn store(&self, target_id: &str, which: Which, report: Report, server: Server) {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                (target_id.to_owned(), which),
                (Instant::now(), report, server),
            );
    }

    /// The account's report on the node `session` is open on (`which`),
    /// from the cache or evaluated now.
    pub(crate) async fn of_session(
        &self,
        session: &mut Session,
        target: &TargetConfig,
        which: Which,
        server: Server,
        timeout: Duration,
    ) -> Result<Report, RdError> {
        let which = node_of(target, which);
        if let Some((r, _)) = self.fresh(&target.id, which) {
            return Ok(r);
        }
        let r = evaluate(session, target, server, timeout).await?;
        self.store(&target.id, which, r.clone(), server);
        after_evaluation(session, target, which, &r, timeout).await?;
        Ok(r)
    }

    /// The account's report on the target's node, from the cache or on a
    /// session opened for it, with the server it was read on.
    pub(crate) async fn of_target(
        &self,
        target: &TargetConfig,
        timeout: Duration,
    ) -> Result<(Report, Server), RdError> {
        if let Some(x) = self.fresh(&target.id, Which::Target) {
            return Ok(x);
        }
        let (mut s, info) = open(target, Which::Target, timeout).await?;
        let r = evaluate(&mut s, target, info.server, timeout).await;
        if let Ok(r) = &r {
            // Best effort: the report stands whatever the outcome.
            let _ = after_evaluation(&mut s, target, Which::Target, r, timeout).await;
        }
        s.close().await;
        let r = r?;
        self.store(&target.id, Which::Target, r.clone(), info.server);
        Ok((r, info.server))
    }

    /// The cached `default` user probe of a target, if fresh.
    pub(crate) fn default_user(&self, target_id: &str) -> Option<DefaultUser> {
        self.default_user
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .filter(|(at, _)| at.elapsed() < REPORT_INTERVAL)
            .map(|(_, d)| *d)
    }

    pub(crate) fn store_default_user(&self, target_id: &str, d: DefaultUser) {
        self.default_user
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), (Instant::now(), d));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::info::Version;

    fn clean() -> Report {
        Report {
            eval: Some(Evaluation::default()),
            patterns_not_readable: Some(vec![1]),
            databases_not_readable: Some(Vec::new()),
            ticket_keys_readable: Some(0),
            dryrun_granted: true,
            audit: acl::AuditGrants::default(),
        }
    }

    /// Security review M2: a refusal on either node refuses the target,
    /// and the notes show the worse node.
    #[test]
    fn the_worse_node_counts() {
        let settings = RedisTargetConfig::default();
        let server = Server::Valkey(Version(9, 0, 0));
        let target = clean();
        let mut discovery = clean();
        discovery.eval = Some(Evaluation {
            writes: 2,
            refused: 1,
            no_touch: true,
            ..Evaluation::default()
        });
        discovery.patterns_not_readable = Some(vec![0, 1]);
        discovery.ticket_keys_readable = Some(1);
        assert_eq!(target.refusal(&settings, server), None);
        assert_eq!(discovery.refusal(&settings, server), Some(Refusal::Listed));
        let w = target.worst(&discovery);
        assert_eq!(w.refusal(&settings, server), Some(Refusal::Listed));
        let e = w.eval.unwrap();
        assert_eq!((e.writes, e.no_touch), (2, false));
        assert_eq!(w.patterns_not_readable, Some(vec![0, 1]));
        assert_eq!(w.ticket_keys_readable, Some(1));
        // A node not evaluated leaves the merge not evaluated.
        assert_eq!(target.worst(&Report::default()).eval, None);
        assert!(!target.worst(&Report::default()).dryrun_granted);
    }
}
