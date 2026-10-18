//! `check()` (ADR-0052 decision 9): reachability (socket peer, TLS,
//! `AUTH`, `HELLO 3`), engine and version, mode, role and the Discovery
//! node's role, the account's evaluation (decision 4), the `default` user
//! probe, the CAS guard's key privilege, and the Audit level of decision 8
//! (Limited at best, `crate::audit::level`).
//! 3 s per command, 9 s in total; the privilege report is recomputed at most
//! every 10 minutes per target. Every explanation is a closed note.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use databastion_core::config::TargetConfig;
use databastion_core::config::redis::{RedisTargetConfig, UnevaluatedAcl};
use databastion_core::{AuditLevel, FailureCode, NoteCode, NoteLabel, TargetHealth, TargetNote};

use crate::acl::{self, Verdict};
use crate::cmd::Cmd;
use crate::conn::{MAX_PIPELINE, parse_hello};
use crate::error::{RdError, Stage};
use crate::node::{self, Refusal, Reports, Which};

/// Timeout of each command.
const CHECK_OP_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Bound of the declared Discovery node's whole step (opening, identifying
/// and evaluating it): a node that accepts the connection and then hangs
/// or answers slowly costs at most this, so the target's own result still
/// fits in [`CHECK_TIMEOUT`] (#275 review L2).
const DISCOVERY_NODE_TIMEOUT: Duration = Duration::from_millis(3500);

/// What the latest scan of a target saw, reported by `check()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanFacts {
    pub(crate) module_patterns: u64,
    pub(crate) declared_not_readable: u64,
}

/// Per-target state shared by `check()`, Discovery and Audit.
#[derive(Default)]
pub(crate) struct CheckState {
    pub(crate) reports: Reports,
    scans: Mutex<HashMap<String, ScanFacts>>,
    pub(crate) audit: crate::audit::state::Shared,
    levels: Mutex<HashMap<String, AuditLevel>>,
}

impl CheckState {
    pub(crate) fn record_scan(&self, target_id: &str, facts: ScanFacts) {
        self.scans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), facts);
    }

    /// The Audit level `check()` last reported.
    pub(crate) fn level(&self, target_id: &str) -> AuditLevel {
        self.levels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .copied()
            .unwrap_or(AuditLevel::None)
    }

    fn scan(&self, target_id: &str) -> ScanFacts {
        self.scans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .copied()
            .unwrap_or_default()
    }
}

fn stage_note(stage: Stage) -> TargetNote {
    TargetNote::new(NoteCode::CheckStageFailed).with_labels([NoteLabel::stage(stage.as_str())])
}

/// Adds a `check.stage_failed` label: into the note already there, if any
/// (one note per code is sent, the first kept), so no stage hides another
/// (#275 review L4).
fn push_stage(notes: &mut Vec<TargetNote>, stage: Stage) {
    match notes
        .iter_mut()
        .find(|n| n.code() == NoteCode::CheckStageFailed)
    {
        Some(n) => {
            let note = std::mem::replace(n, TargetNote::new(NoteCode::CheckStageFailed));
            *n = note.with_labels([NoteLabel::stage(stage.as_str())]);
        }
        None => notes.push(stage_note(stage)),
    }
}

/// The declared Discovery node, opened and evaluated under
/// [`DISCOVERY_NODE_TIMEOUT`]: whether it reports a replica role (`None`:
/// not opened), and its report and server.
async fn discovery_node(
    state: &CheckState,
    target: &TargetConfig,
) -> (
    Option<bool>,
    Result<(node::Report, crate::info::Server), RdError>,
) {
    let deadline = tokio::time::Instant::now() + DISCOVERY_NODE_TIMEOUT;
    let opened = tokio::time::timeout_at(
        deadline,
        node::open(target, Which::Discovery, CHECK_OP_TIMEOUT),
    )
    .await
    .map_err(|_| RdError::new(FailureCode::Timeout, Stage::Connect));
    let (mut s, dinfo) = match opened {
        Ok(Ok(x)) => x,
        Ok(Err(e)) | Err(e) => return (None, Err(e)),
    };
    let d = tokio::time::timeout_at(
        deadline,
        state
            .reports
            .of_session(&mut s, target, Which::Discovery, dinfo, CHECK_OP_TIMEOUT),
    )
    .await;
    let r = match d {
        Ok(Ok(d)) => {
            s.close().await;
            Ok((d, dinfo.server))
        }
        Ok(Err(e)) => {
            s.close().await;
            Err(e)
        }
        // Timed out: the session is dropped, not closed politely.
        Err(_) => Err(RdError::new(FailureCode::Timeout, Stage::Check)),
    };
    (Some(dinfo.replica), r)
}

fn failed(e: RdError, notes: Vec<TargetNote>) -> TargetHealth {
    let mut notes = notes;
    push_stage(&mut notes, e.stage);
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "Redis / Valkey check failed at stage {} ({})",
            e.stage.as_str(),
            e.word.map_or("no error reply", |w| w.as_str())
        )),
        notes,
    }
}

/// Runs `check()` on a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TIMEOUT, run(state, target)).await {
        Ok(h) => h,
        Err(_) => TargetHealth {
            reachable: false,
            audit_level: AuditLevel::None,
            failure: Some(FailureCode::Timeout),
            detail: Some("Redis / Valkey check timed out".to_owned()),
            notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
        },
    }
}

async fn run(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let settings = target.redis_settings();
    let (mut session, info) = match node::open(target, Which::Target, CHECK_OP_TIMEOUT).await {
        Ok(x) => x,
        Err(e) => return failed(e, Vec::new()),
    };
    let mut notes: Vec<TargetNote> = Vec::new();
    match node::engine_mismatch(target, info.server) {
        Some(true) => notes.push(TargetNote::new(NoteCode::CheckServerIsValkey)),
        Some(false) => notes.push(TargetNote::new(NoteCode::CheckServerIsRedis)),
        None => {}
    }
    if info.cluster {
        notes.push(TargetNote::new(NoteCode::CoverageClusterNodeOnly).with_count(1));
    }
    let report = match state
        .reports
        .of_session(&mut session, target, Which::Target, info, CHECK_OP_TIMEOUT)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            session.close().await;
            return failed(e, notes);
        }
    };
    session.close().await;
    let mut refusal = report.refusal(&settings, info.server);
    let mut report = report;
    let mut has_dryrun = info.server.has_dryrun();

    // The Discovery node: a replica (decision 5), and the account's
    // evaluation there too, since ACLs are per node: the target is refused
    // when either node refuses, and the notes show the worse of the two
    // (security review M2). A Discovery node that cannot be reached or
    // evaluated does not make the target unreachable: `check()` and Audit
    // read the target's node, which answered (#237). It is reported as a
    // `check.stage_failed` note with its stage and as the target's failure
    // (Discovery cannot run); the node's last report, while fresh, still
    // counts in the worse of the two.
    let mut discovery_failed: Option<RdError> = None;
    if settings.discovery_node.is_some() {
        let (replica, evaluated) = discovery_node(state, target).await;
        if replica == Some(false) {
            tracing::warn!("Redis / Valkey: redis.discovery_node does not report a replica role");
            push_stage(&mut notes, Stage::Check);
        }
        let evaluated = match evaluated {
            Ok(x) => Some(x),
            Err(e) => {
                tracing::warn!(
                    stage = e.stage.as_str(),
                    "Redis / Valkey: the declared Discovery node (redis.discovery_node) \
                     failed; the target's node answers, check() and Audit go on, \
                     Discovery cannot run"
                );
                discovery_failed = Some(e);
                // Its fresh report counts whole; a stale one only by its
                // refusal, which only a new evaluation clears (L3).
                match state.reports.cached(target, Which::Discovery) {
                    Some(fresh) => Some(fresh),
                    None => {
                        if let Some((d, dserver)) = state.reports.last(target, Which::Discovery) {
                            refusal = refusal.or(d.refusal(&settings, dserver));
                        }
                        None
                    }
                }
            }
        };
        if let Some((d, dserver)) = evaluated {
            refusal = refusal.or(d.refusal(&settings, dserver));
            report = report.worst(&d);
            has_dryrun = has_dryrun && dserver.has_dryrun();
        }
    }

    let scan = state.scan(&target.id);
    privilege_notes(
        &report,
        &settings,
        has_dryrun,
        scan.declared_not_readable
            .saturating_add(state.audit.own_denials(&target.id)),
        &mut notes,
    );
    if scan.module_patterns > 0 {
        notes.push(
            TargetNote::new(NoteCode::CoverageModuleTypesNotSampled)
                .with_count(scan.module_patterns),
        );
    }

    // The `default` user probe (decision 4), cached like the report (L3);
    // graded only when the account may run `ACL DRYRUN`, so the grade
    // never writes `ACL LOG` entries.
    let default_user = match state.reports.default_user(&target.id) {
        Some(d) => d,
        None => {
            let open = default_user_probe(target).await;
            let grade = if open == Some(true) && info.server.has_dryrun() && report.dryrun_granted {
                default_user_grade(target).await
            } else {
                None
            };
            let d = node::DefaultUser { open, grade };
            state.reports.store_default_user(&target.id, d);
            d
        }
    };
    if default_user.open == Some(true) {
        notes.push(
            TargetNote::new(NoteCode::SecurityDefaultUserNopass)
                .with_count(default_user.grade.unwrap_or(0)),
        );
    }

    // Audit (decision 8): Limited at best; None with the refusal list.
    let (audit_level, audit_notes) = crate::audit::level(
        state,
        &target.id,
        info.server.has_dryrun().then_some(report.audit),
        refusal.is_some(),
    );
    notes.extend(audit_notes);
    state
        .levels
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(target.id.clone(), audit_level);

    let failure = match refusal {
        None => discovery_failed.as_ref().map(|e| e.code),
        Some(Refusal::Listed) => Some(FailureCode::PermissionDenied),
        Some(Refusal::NotEvaluated | Refusal::MisplacedOptIn) => Some(FailureCode::Unsupported),
    };
    if let Some(e) = &discovery_failed {
        push_stage(&mut notes, e.stage);
    }
    if refusal == Some(Refusal::MisplacedOptIn) {
        tracing::warn!(
            "Redis / Valkey: redis.unevaluated_acl applies to Redis 6.2 only; remove it \
             (the target is refused until then)"
        );
        push_stage(&mut notes, Stage::Check);
    }
    TargetHealth {
        reachable: true,
        audit_level,
        failure,
        detail: refusal
            .map(refusal_detail)
            .or_else(|| discovery_failed.map(discovery_detail)),
        notes,
    }
}

/// The local detail of a refusal (logs only).
fn refusal_detail(r: Refusal) -> String {
    match r {
        Refusal::Listed => {
            "the account can run a refusal-list command (or it could not be evaluated): \
             Discovery does not run (ADR-0052 decision 4)"
        }
        Refusal::NotEvaluated => {
            "Redis 6.2 has no ACL DRYRUN: set redis.unevaluated_acl: accept after \
             reviewing the account by hand (ADR-0052 decision 4)"
        }
        Refusal::MisplacedOptIn => "redis.unevaluated_acl is for Redis 6.2 only",
    }
    .to_owned()
}

/// The local detail of a failed Discovery node (logs only).
fn discovery_detail(e: RdError) -> String {
    format!(
        "the declared Discovery node (redis.discovery_node) failed at stage {} ({}): \
         Discovery cannot run; the target's node answers",
        e.stage.as_str(),
        e.word.map_or("no error reply", |w| w.as_str())
    )
}

/// The privilege notes of a report (counts only).
fn privilege_notes(
    report: &node::Report,
    settings: &RedisTargetConfig,
    has_dryrun: bool,
    scan_not_readable: u64,
    notes: &mut Vec<TargetNote>,
) {
    let mut add = |code: NoteCode, n: u64| {
        if n > 0 {
            notes.push(TargetNote::new(code).with_count(n));
        }
    };
    let Some(eval) = report.eval.as_ref().filter(|_| has_dryrun) else {
        // Redis 6.2: nothing is evaluated; with the opt-in, shown
        // permanently, and the declarations and the CAS key privilege are
        // not evaluated either (never passed).
        // The count: every probe, plus the declared patterns and the CAS
        // key privilege, none of which can be evaluated.
        let _ = settings.unevaluated_acl == Some(UnevaluatedAcl::Accept);
        notes.push(
            TargetNote::new(NoteCode::PrivilegeNotEvaluated)
                .with_count(acl::PROBES.len() as u64 + 2),
        );
        return;
    };
    add(NoteCode::PrivilegeWriteActions, eval.writes);
    add(NoteCode::PrivilegeReadBeyondDiscovery, eval.read_beyond);
    add(NoteCode::PrivilegeAdminCommands, eval.admin);
    add(NoteCode::PrivilegeScripting, eval.scripting);
    add(NoteCode::PrivilegePubsubChannels, eval.pubsub);
    add(NoteCode::PrivilegeNotEvaluated, eval.not_evaluated);
    let declared = report.patterns_not_readable.as_ref().map_or(0, Vec::len)
        + report.databases_not_readable.as_ref().map_or(0, Vec::len);
    add(
        NoteCode::PrivilegeDeclaredKeysNotReadable,
        (declared as u64).saturating_add(scan_not_readable),
    );
    add(
        NoteCode::PrivilegeTicketCredentialsReadable,
        report.ticket_keys_readable.unwrap_or(0),
    );
}

/// Whether the server's `default` user is enabled without a password: a
/// second, unauthenticated connection sends only `HELLO 3` and closes.
/// `None`: the probe could not run.
async fn default_user_probe(target: &TargetConfig) -> Option<bool> {
    let settings = target.redis_settings();
    let endpoint = node::endpoint(target, Which::Target)?;
    let tls = node::tls_of(&settings).ok()?;
    let mut io = endpoint.open(tls).await.ok()?;
    let r = probe_hello(&mut io).await;
    let _ = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::io::AsyncWriteExt::shutdown(&mut io),
    )
    .await;
    r
}

async fn probe_hello(io: &mut crate::net::Transport) -> Option<bool> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cmd = Cmd::HelloProbe;
    let mut out = Vec::new();
    cmd.encode(&mut out);
    let exchange = async {
        io.write_all(&out).await.ok()?;
        let mut decoder = crate::resp::Decoder::new(cmd.limits());
        let mut chunk = vec![0u8; 4096];
        loop {
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            if let (_, Some(v)) = decoder.feed(chunk.get(..n)?).ok()? {
                return Some(v);
            }
        }
    };
    let reply = tokio::time::timeout(CHECK_OP_TIMEOUT, exchange)
        .await
        .ok()??;
    Some(parse_hello(&reply).is_ok())
}

/// The number of refusal-list commands the `default` user may run
/// (`ACL DRYRUN default …`, on the agent's own session).
async fn default_user_grade(target: &TargetConfig) -> Option<u64> {
    let (mut s, _) = node::open(target, Which::Target, CHECK_OP_TIMEOUT)
        .await
        .ok()?;
    let refusal: Vec<&'static acl::Probe> = acl::PROBES.iter().filter(|p| p.refusal).collect();
    let mut allowed = 0u64;
    for chunk in refusal.chunks(MAX_PIPELINE) {
        let cmds: Vec<Cmd<'_>> = chunk
            .iter()
            .map(|probe| Cmd::DryRun {
                user: "default",
                probe,
            })
            .collect();
        let replies = s
            .pipeline(&cmds, CHECK_OP_TIMEOUT, Stage::Check)
            .await
            .ok()?;
        allowed += replies
            .iter()
            .filter(|r| acl::verdict(r) != Verdict::Denied)
            .count() as u64;
    }
    s.close().await;
    Some(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::{Fake, serve};
    use std::time::Instant;

    fn target(id: &str) -> TargetConfig {
        // Nothing listens on port 1: only the stand-in connections handed
        // through the test transports answer (the `default` user probe
        // finds nothing).
        databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{{id: {id}, \
             engine: valkey, host: 127.0.0.1, port: 1, account: databastion, \
             secret: {{env: PATH}}, redis: {{tls: disable, \
             discovery_node: {{host: 127.0.0.1, port: 1}}}}}}]}}"
        ))
        .unwrap()
        .targets[0]
            .clone()
    }

    /// The target's node: answers, every probe denied (no refusal).
    fn healthy() -> Fake {
        Fake {
            deny_dryrun: true,
            ..Fake::new(1)
        }
    }

    fn stages(h: &TargetHealth) -> Vec<Vec<NoteLabel>> {
        h.notes
            .iter()
            .filter(|n| n.code() == NoteCode::CheckStageFailed)
            .map(|n| n.labels().to_vec())
            .collect()
    }

    /// #275 review L2: a Discovery node that never answers, or answers
    /// each command just under the per-command timeout, costs at most its
    /// own deadline: the target stays reachable.
    #[tokio::test]
    async fn a_hanging_discovery_node_keeps_the_target_reachable() {
        for (id, fake) in [
            (
                "check-dn-silent",
                Fake {
                    hang_on: Some("AUTH"),
                    ..Fake::new(2)
                },
            ),
            (
                "check-dn-slow",
                Fake {
                    delay: Duration::from_millis(2500),
                    ..Fake::new(2)
                },
            ),
        ] {
            serve(id, &[healthy(), fake]);
            let started = Instant::now();
            let h = check(&CheckState::default(), &target(id)).await;
            assert!(started.elapsed() < Duration::from_secs(6), "{id}");
            assert!(h.reachable, "{id}: {h:?}");
            assert_eq!(h.failure, Some(FailureCode::Timeout), "{id}");
            assert_eq!(stages(&h).len(), 1, "{id}: {h:?}");
            assert!(!h.notes.iter().any(|n| n.code() == NoteCode::CheckTimedOut));
        }
    }

    /// #275 review L4: a Discovery node that is not a replica and then
    /// fails gives one `check.stage_failed` note holding every stage.
    #[tokio::test]
    async fn a_failing_primary_as_discovery_node_gives_one_stage_note() {
        let id = "check-dn-primary";
        serve(
            id,
            &[
                healthy(),
                Fake {
                    hang_on: Some("ACL"),
                    ..Fake::new(2)
                },
            ],
        );
        let h = check(&CheckState::default(), &target(id)).await;
        assert!(h.reachable, "{h:?}");
        assert_eq!(h.failure, Some(FailureCode::Timeout));
        assert_eq!(
            stages(&h),
            [vec![NoteLabel::stage(Stage::Check.as_str())]],
            "{h:?}"
        );
        // Labels of different stages are merged, never dropped.
        let mut notes = vec![stage_note(Stage::Check)];
        push_stage(&mut notes, Stage::Connect);
        push_stage(&mut notes, Stage::Check);
        assert_eq!(notes.len(), 1);
        let mut want = vec![
            NoteLabel::stage(Stage::Check.as_str()),
            NoteLabel::stage(Stage::Connect.as_str()),
        ];
        want.sort_unstable();
        assert_eq!(notes[0].labels(), want.as_slice());
    }

    /// #275 review L3: the Discovery node's last refusal still refuses the
    /// target while the node cannot be reached, however old; a stale report
    /// without a refusal adds nothing.
    #[tokio::test]
    async fn a_down_discovery_node_keeps_its_last_refusal() {
        let Some(old) = Instant::now().checked_sub(node::REPORT_INTERVAL + Duration::from_secs(60))
        else {
            return;
        };
        let server = crate::info::Server::Valkey(crate::info::Version(9, 0, 6));
        for (id, refused) in [("check-dn-refused", true), ("check-dn-clean", false)] {
            // Only the target's node answers; the Discovery node is down.
            serve(id, &[healthy()]);
            let t = target(id);
            let state = CheckState::default();
            let report = node::Report {
                eval: Some(crate::acl::Evaluation {
                    refused: u64::from(refused),
                    ..crate::acl::Evaluation::default()
                }),
                ..node::Report::default()
            };
            state
                .reports
                .store_for_test(&t, Which::Discovery, report, server, old);
            assert!(state.reports.cached(&t, Which::Discovery).is_none());
            let h = check(&state, &t).await;
            assert!(h.reachable, "{id}: {h:?}");
            if refused {
                assert_eq!(h.failure, Some(FailureCode::PermissionDenied), "{id}");
                assert_eq!(h.audit_level, AuditLevel::None);
            } else {
                assert_eq!(h.failure, Some(FailureCode::TargetUnreachable), "{id}");
            }
        }
    }
}
