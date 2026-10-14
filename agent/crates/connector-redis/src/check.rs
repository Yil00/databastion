//! `check()` (ADR-0052 decision 9): reachability (socket peer, TLS,
//! `AUTH`, `HELLO 3`), engine and version, mode, role and the Discovery
//! node's role, the account's evaluation (decision 4), the `default` user
//! probe, the CAS guard's key privilege, and the Audit level: None in this
//! version (Audit comes with a later lot), noted `audit.stream_not_available`.
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

/// What the latest scan of a target saw, reported by `check()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanFacts {
    pub(crate) module_patterns: u64,
    pub(crate) declared_not_readable: u64,
}

/// Per-target state shared by `check()` and Discovery.
#[derive(Default)]
pub(crate) struct CheckState {
    pub(crate) reports: Reports,
    scans: Mutex<HashMap<String, ScanFacts>>,
}

impl CheckState {
    pub(crate) fn record_scan(&self, target_id: &str, facts: ScanFacts) {
        self.scans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), facts);
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

fn failed(e: RdError, notes: Vec<TargetNote>) -> TargetHealth {
    let mut notes = notes;
    notes.push(stage_note(e.stage));
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
        .of_session(
            &mut session,
            target,
            Which::Target,
            info.server,
            CHECK_OP_TIMEOUT,
        )
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
    // (security review M2).
    if settings.discovery_node.is_some() {
        match node::open(target, Which::Discovery, CHECK_OP_TIMEOUT).await {
            Ok((mut s, dinfo)) => {
                if !dinfo.replica {
                    tracing::warn!(
                        "Redis / Valkey: redis.discovery_node does not report a replica role"
                    );
                    notes.push(stage_note(Stage::Check));
                }
                let d = state
                    .reports
                    .of_session(
                        &mut s,
                        target,
                        Which::Discovery,
                        dinfo.server,
                        CHECK_OP_TIMEOUT,
                    )
                    .await;
                s.close().await;
                match d {
                    Ok(d) => {
                        refusal = refusal.or(d.refusal(&settings, dinfo.server));
                        report = report.worst(&d);
                        has_dryrun = has_dryrun && dinfo.server.has_dryrun();
                    }
                    Err(e) => return failed(e, notes),
                }
            }
            Err(e) => return failed(e, notes),
        }
    }

    let scan = state.scan(&target.id);
    privilege_notes(
        &report,
        &settings,
        has_dryrun,
        scan.declared_not_readable,
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

    // Audit is not implemented in this version: None.
    notes.push(TargetNote::new(NoteCode::AuditStreamNotAvailable));

    let failure = match refusal {
        None => None,
        Some(Refusal::Listed) => Some(FailureCode::PermissionDenied),
        Some(Refusal::NotEvaluated | Refusal::MisplacedOptIn) => Some(FailureCode::Unsupported),
    };
    if refusal == Some(Refusal::MisplacedOptIn) {
        tracing::warn!(
            "Redis / Valkey: redis.unevaluated_acl applies to Redis 6.2 only; remove it \
             (the target is refused until then)"
        );
        notes.push(stage_note(Stage::Check));
    }
    TargetHealth {
        reachable: true,
        audit_level: AuditLevel::None,
        failure,
        detail: refusal.map(|r| {
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
        }),
        notes,
    }
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
