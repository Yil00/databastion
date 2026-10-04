//! `check()` of a `cas` target (ADR-0041 decisions 10 and 11): closed
//! notes, counts only, at most [`CHECK_BUDGET`].
//!
//! - Reachable when at least one declared source is readable.
//! - Service registry: the directory is listed (never its files' content
//!   here); refused when the agent could write it
//!   (`privilege.registry_writable`) or when it holds CAS configuration
//!   files (`privilege.config_readable`); a directory that cannot be
//!   listed, or no longer resolves where it did at load, is a failed stage
//!   (`check.stage_failed`). Registry files refused because the agent
//!   could write them in the last scan also give
//!   `privilege.registry_writable`. The last Discovery scan's counts give
//!   `coverage.registry_files_skipped` and
//!   `security.client_secrets_in_clear`.
//! - Audit log: at most [`CHECK_TAIL_BYTES`] of its end are parsed;
//!   `audit.log_not_readable` when it cannot be read or is refused,
//!   `audit.log_format_unsupported` when it has records but none is one
//!   JSON object, `security.audit_headers_logged` when records carry
//!   `headers`. The level follows [`crate::audit::level`], from the
//!   records parsed here and by the stream; never Full.
//!
//! TODO(P8-C): wired to the protocol types in P8-C ([`CasHealth`] becomes
//! the core's `TargetHealth` with `TargetNote`s).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use databastion_core::AuditLevel;

use crate::audit::level::Evidence;
use crate::audit::stream::parse_lines;
use crate::config::CasSettings;
use crate::fsread::{self, Policy, Refusal};
use crate::notes::{CasNote, CasNoteCode};
use crate::state::CasState;

/// Time budget of one check.
pub const CHECK_BUDGET: Duration = Duration::from_secs(5);
/// Bytes of the audit log's end read by a check.
pub const CHECK_TAIL_BYTES: u64 = 64 * 1024;

/// Health of a `cas` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasHealth {
    /// At least one declared source is readable.
    pub reachable: bool,
    /// Audit level actually reachable (never Full).
    pub audit_level: AuditLevel,
    /// Closed notes, sorted, without duplicates.
    pub notes: Vec<CasNote>,
}

/// Checks a `cas` target within [`CHECK_BUDGET`].
pub async fn check(settings: &CasSettings, state: &Arc<CasState>) -> CasHealth {
    check_with(settings, state, Policy::STRICT).await
}

pub(crate) async fn check_with(
    settings: &CasSettings,
    state: &Arc<CasState>,
    policy: Policy,
) -> CasHealth {
    let s = settings.clone();
    let st = Arc::clone(state);
    let task =
        tokio::task::spawn_blocking(move || check_blocking(&s, &st, policy, SystemTime::now()));
    match tokio::time::timeout(CHECK_BUDGET, task).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            let _ = databastion_core::resume_panic(e);
            failed(CasNoteCode::CheckStageFailed)
        }
        Err(_) => failed(CasNoteCode::CheckTimedOut),
    }
}

fn failed(code: CasNoteCode) -> CasHealth {
    CasHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        notes: vec![CasNote::flag(code)],
    }
}

pub(crate) fn check_blocking(
    settings: &CasSettings,
    state: &CasState,
    policy: Policy,
    now: SystemTime,
) -> CasHealth {
    let mut notes = Vec::new();
    let mut reachable = false;
    let snap = state.snapshot();
    if let Some(dir) = &settings.registry_dir {
        let listed = if dir.still_resolves() {
            fsread::list_registry(dir.path(), policy)
        } else {
            Err(Refusal::ResolvedChanged)
        };
        match listed {
            Ok(l) => {
                reachable = true;
                let facts = snap.registry.unwrap_or_default();
                let skipped = facts.skipped.max(l.over_cap);
                if skipped > 0 {
                    notes.push(CasNote::counted(
                        CasNoteCode::CoverageRegistryFilesSkipped,
                        skipped,
                    ));
                }
                if facts.writable > 0 {
                    notes.push(CasNote::flag(CasNoteCode::PrivilegeRegistryWritable));
                }
                if facts.clear_secrets > 0 {
                    notes.push(CasNote::counted(
                        CasNoteCode::SecurityClientSecretsInClear,
                        facts.clear_secrets,
                    ));
                }
            }
            Err(Refusal::Writable) => {
                notes.push(CasNote::flag(CasNoteCode::PrivilegeRegistryWritable))
            }
            Err(Refusal::ConfigFiles) => {
                notes.push(CasNote::flag(CasNoteCode::PrivilegeConfigReadable))
            }
            Err(Refusal::NotReadable | Refusal::ResolvedChanged) => {
                notes.push(CasNote::flag(CasNoteCode::CheckStageFailed));
            }
        }
    }
    let mut level = AuditLevel::None;
    if let Some(log) = &settings.audit_log {
        let tail = if log.path.still_resolves() {
            fsread::read_log_tail(log.path.path(), CHECK_TAIL_BYTES, policy)
        } else {
            Err(Refusal::ResolvedChanged)
        };
        match tail {
            Err(_) => notes.push(CasNote::flag(CasNoteCode::AuditLogNotReadable)),
            Ok(tail) => {
                reachable = true;
                let batch = parse_lines(tail.bytes.split(|b| *b == b'\n'), log.offset, now);
                drop(tail);
                let mut evidence: Evidence = snap.evidence;
                evidence.merge(&batch.evidence);
                state.note_evidence(&batch.evidence);
                let unsupported = (batch.json == 0 && batch.non_json > 0)
                    || (batch.json == 0 && snap.format_unsupported);
                if batch.headers || snap.headers_logged {
                    notes.push(CasNote::flag(CasNoteCode::SecurityAuditHeadersLogged));
                }
                if snap.dropped > 0 {
                    notes.push(CasNote::counted(
                        CasNoteCode::AuditRecordsDropped,
                        snap.dropped,
                    ));
                }
                if snap.stream_stopped {
                    notes.push(CasNote::flag(CasNoteCode::AuditStreamStopped));
                } else if unsupported {
                    notes.push(CasNote::flag(CasNoteCode::AuditLogFormatUnsupported));
                } else {
                    let (l, n) = evidence.level(now);
                    level = l;
                    notes.extend(n);
                }
            }
        }
    }
    notes.sort();
    notes.dedup();
    CasHealth {
        reachable,
        audit_level: level,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsread::tests::TempDir;
    use crate::state::RegistryFacts;

    fn codes(h: &CasHealth) -> Vec<CasNoteCode> {
        h.notes.iter().map(|n| n.code).collect()
    }

    fn settings(dir: &TempDir) -> CasSettings {
        CasSettings::from_yaml(
            &format!(
                "{{service_registry: {{json_dir: {d}/services}}, audit_log: {{path: {d}/cas_audit.log}}}}",
                d = dir.path().display()
            ),
            &[],
        )
        .unwrap()
    }

    fn ms(t: SystemTime) -> u128 {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }

    #[tokio::test]
    async fn nothing_readable() {
        let dir = TempDir::new("check-none");
        let state = Arc::new(CasState::default());
        let h = check_with(&settings(&dir), &state, Policy::TESTS).await;
        assert!(!h.reachable);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert_eq!(
            codes(&h),
            [
                CasNoteCode::AuditLogNotReadable,
                CasNoteCode::CheckStageFailed
            ]
        );
        // The strict policy refuses what the test user owns.
        std::fs::create_dir(dir.path().join("services")).unwrap();
        std::fs::write(dir.path().join("cas_audit.log"), "").unwrap();
        let h = check_with(&settings(&dir), &state, Policy::STRICT).await;
        assert!(!h.reachable);
        assert_eq!(
            codes(&h),
            [
                CasNoteCode::AuditLogNotReadable,
                CasNoteCode::PrivilegeRegistryWritable
            ]
        );
    }

    #[test]
    fn levels_and_notes_from_the_tail() {
        let dir = TempDir::new("check-level");
        std::fs::create_dir(dir.path().join("services")).unwrap();
        let s = settings(&dir);
        let state = CasState::default();
        let now = SystemTime::now();
        std::fs::write(dir.path().join("cas_audit.log"), "").unwrap();
        let h = check_blocking(&s, &state, Policy::TESTS, now);
        assert!(h.reachable);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert_eq!(codes(&h), [CasNoteCode::AuditLimitedPendingFirstRecord]);

        std::fs::write(
            dir.path().join("cas_audit.log"),
            "WHO: jdoe\nWHAT: TGT-1-FAKE\nACTION: AUTHENTICATION_SUCCESS\n",
        )
        .unwrap();
        let h = check_blocking(&s, &state, Policy::TESTS, now);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert_eq!(codes(&h), [CasNoteCode::AuditLogFormatUnsupported]);

        let t = ms(now);
        std::fs::write(
            dir.path().join("cas_audit.log"),
            format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"a\", \"when\": {t}, \"headers\": {{\"Cookie\": \"TGC=FAKE\"}}}}\n\
                 {{\"action\": \"SERVICE_TICKET_CREATED\", \"who\": \"a\", \"when\": {t}}}\n"
            ),
        )
        .unwrap();
        state.note_registry(
            RegistryFacts {
                skipped: 2,
                clear_secrets: 1,
                writable: 1,
            },
            None,
        );
        let h = check_blocking(&s, &state, Policy::TESTS, now);
        assert_eq!(h.audit_level, AuditLevel::Partial);
        assert_eq!(
            codes(&h),
            [
                CasNoteCode::AuditAuthFailuresNotSeen,
                CasNoteCode::CoverageRegistryFilesSkipped,
                CasNoteCode::SecurityClientSecretsInClear,
                CasNoteCode::SecurityAuditHeadersLogged,
                CasNoteCode::PrivilegeRegistryWritable,
            ]
        );
        assert!(h.notes.contains(&CasNote::counted(
            CasNoteCode::SecurityClientSecretsInClear,
            1
        )));
        state.set_stream_stopped(true);
        let h = check_blocking(&s, &state, Policy::TESTS, now);
        assert_eq!(h.audit_level, AuditLevel::None);
        assert!(codes(&h).contains(&CasNoteCode::AuditStreamStopped));
    }

    #[test]
    fn configuration_files_are_reported() {
        let dir = TempDir::new("check-config");
        std::fs::create_dir(dir.path().join("services")).unwrap();
        std::fs::write(
            dir.path().join("services/cas.properties"),
            "x=hunter2-SECRET",
        )
        .unwrap();
        let s = CasSettings::from_yaml(
            &format!(
                "{{service_registry: {{json_dir: {}/services}}}}",
                dir.path().display()
            ),
            &[],
        )
        .unwrap();
        let h = check_blocking(&s, &CasState::default(), Policy::TESTS, SystemTime::now());
        assert!(!h.reachable);
        assert_eq!(codes(&h), [CasNoteCode::PrivilegeConfigReadable]);
    }
}
