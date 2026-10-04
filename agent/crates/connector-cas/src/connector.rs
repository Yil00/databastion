//! The `Connector` of the `cas` engine (ADR-0041): one instance serves every
//! declared `cas` target.
//!
//! - [`check`](Connector::check): [`crate::check`], its notes and level
//!   given to the core as `TargetHealth` (closed codes and counts only).
//! - [`discover`](Connector::discover): [`crate::discover`] on the job's
//!   target; only masked findings reach the sink (I2).
//! - [`audit_stream`](Connector::audit_stream): the JSON audit log through
//!   [`AuditRunner`] (the core tailer, this crate's checks on every opened
//!   file), each poll on a blocking thread; events are handed over as
//!   `MaskedEvent`s and the position is saved after them. The service index
//!   comes from the last Discovery scan, or is built at the stream's start
//!   when no scan ran since the agent started. The failed-login windows are
//!   keyed by tags of a fresh random key (never persisted nor sent), and
//!   their overflow is counted in the heartbeat metric
//!   `audit_window_overflow_total`.
//!
//! The settings come from the core (`TargetConfig::cas_settings`, validated
//! and resolved when `agent.yaml` is loaded). Per-target state (what the
//! scans and the stream found, for `check()`) is kept per target id and
//! reset when the target's settings change (a reload).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use databastion_classifiers::masking::EventSource;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, AuditLevel, Connector, ConnectorError, Engine, EventSink, FailureCode,
    FindingSink, NoteCode, ScanJob, TargetHealth, TargetNote,
};

use crate::audit::events::{Builder, TAG_PURPOSE};
use crate::audit::stream::AuditRunner;
use crate::config::CasSettings;
use crate::discover::{CasError, index_registry};
use crate::fsread::{Policy, Refusal};
use crate::state::CasState;

/// Name of the persisted audit log cursor.
pub const CURSOR: &str = "cas_audit_log";

fn error(code: FailureCode) -> ConnectorError {
    ConnectorError::Target {
        engine: Engine::Cas,
        code,
        engine_code: None,
    }
}

fn joined<T>(r: Result<T, tokio::task::JoinError>) -> Result<T, ConnectorError> {
    r.map_err(|e| {
        let _ = databastion_core::resume_panic(e);
        error(FailureCode::Internal)
    })
}

impl From<CasError> for ConnectorError {
    fn from(e: CasError) -> Self {
        match e {
            CasError::Cancelled => Self::Cancelled,
            CasError::SinkClosed(s) => Self::SinkClosed(s),
            CasError::Internal => error(FailureCode::Internal),
        }
    }
}

/// Apereo CAS connector (local files only).
#[derive(Default)]
#[non_exhaustive]
pub struct CasConnector {
    /// Per target id: the settings the state belongs to, and the state.
    targets: Mutex<HashMap<String, (CasSettings, Arc<CasState>)>>,
}

impl std::fmt::Debug for CasConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasConnector").finish_non_exhaustive()
    }
}

impl CasConnector {
    /// Creates the connector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The target's validated settings and its state (a new state when the
    /// settings changed since it was made).
    fn target(&self, target: &TargetConfig) -> Option<(CasSettings, Arc<CasState>)> {
        let settings = target.cas_settings()?.clone();
        let mut targets = self.targets.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = targets
            .entry(target.id.clone())
            .or_insert_with(|| (settings.clone(), Arc::new(CasState::default())));
        if entry.0 != settings {
            *entry = (settings.clone(), Arc::new(CasState::default()));
        }
        Some((settings, Arc::clone(&entry.1)))
    }
}

#[async_trait]
impl Connector for CasConnector {
    fn engine(&self) -> Engine {
        Engine::Cas
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        let Some((settings, state)) = self.target(target) else {
            return TargetHealth {
                reachable: false,
                audit_level: AuditLevel::None,
                failure: Some(FailureCode::Internal),
                detail: Some("cas target without validated settings".to_owned()),
                notes: vec![TargetNote::new(NoteCode::CheckStageFailed)],
            };
        };
        crate::check::check(&settings, &state)
            .await
            .into_target_health()
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        let target = job.target().ok_or_else(|| error(FailureCode::Internal))?;
        let (settings, state) = self
            .target(target)
            .ok_or_else(|| error(FailureCode::Internal))?;
        crate::discover::discover(&settings, job, sink, &state)
            .await
            .map_err(ConnectorError::from)
    }

    async fn audit_stream(
        &self,
        cfg: &AuditConfig,
        sink: &EventSink,
    ) -> Result<(), ConnectorError> {
        let target = cfg.target().ok_or_else(|| error(FailureCode::Internal))?;
        let (settings, state) = self
            .target(target)
            .ok_or_else(|| error(FailureCode::Internal))?;
        stream(cfg, sink, settings, state).await
    }

    fn supports_audit(&self) -> bool {
        true
    }

    fn audit_source(&self, target: &TargetConfig) -> Option<EventSource> {
        target
            .cas_settings()?
            .audit_log
            .as_ref()
            .map(|_| EventSource::CasAuditLog)
    }
}

/// The audit stream of one target (see the module documentation). Runs
/// until the core drops it; a refused or unreadable log is retried at each
/// poll interval (warned once per change of the reason).
async fn stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    settings: CasSettings,
    state: Arc<CasState>,
) -> Result<(), ConnectorError> {
    if settings.audit_log.is_none() {
        return Err(error(FailureCode::Unsupported));
    }
    let policy = Policy::agent();
    if state.services().is_none() && settings.registry_dir.is_some() {
        let s = settings.clone();
        if let Some((index, facts)) =
            joined(tokio::task::spawn_blocking(move || index_registry(&s, policy)).await)?
        {
            state.note_registry(facts, Some(Arc::new(index)));
        }
    }
    let key = databastion_core::audit::ephemeral_tag_key(TAG_PURPOSE)
        .ok_or_else(|| error(FailureCode::Internal))?;
    let builder = Builder::new(
        key,
        &settings.clear_principals,
        settings.client_addr,
        state.services(),
    );
    let mut runner = AuditRunner::with_policy(
        &settings,
        cfg.cursor(CURSOR),
        builder,
        Arc::clone(&state),
        policy,
    )
    .ok_or_else(|| error(FailureCode::Internal))?;
    let mut overflow_reported = 0u64;
    let mut refused: Option<Refusal> = None;
    loop {
        runner.builder_mut().set_services(state.services());
        let (r, polled) = joined(
            tokio::task::spawn_blocking(move || {
                let polled = runner.poll(SystemTime::now());
                (runner, polled)
            })
            .await,
        )?;
        runner = r;
        let polled = match polled {
            Ok(p) => {
                if refused.take().is_some() {
                    tracing::info!(target_id = cfg.target_id(), "CAS audit log readable again");
                }
                p
            }
            Err(reason) => {
                if refused != Some(reason) {
                    tracing::warn!(
                        target_id = cfg.target_id(),
                        reason = ?reason,
                        "CAS audit log refused or not readable; nothing of it is read (retrying)"
                    );
                }
                refused = Some(reason);
                tokio::time::sleep(cfg.poll_interval()).await;
                continue;
            }
        };
        let overflow = runner.builder_mut().overflow;
        if overflow > overflow_reported {
            databastion_core::audit::count_window_overflow(overflow - overflow_reported);
            overflow_reported = overflow;
        }
        for e in polled.events {
            sink.submit(e.into_masked()).await?;
        }
        // Everything read so far was handed over: save the position.
        runner = joined(
            tokio::task::spawn_blocking(move || {
                runner.commit();
                runner
            })
            .await,
        )?;
        if !polled.more {
            tokio::time::sleep(cfg.poll_interval()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsread::tests::TempDir;

    fn target(dir: &TempDir) -> TargetConfig {
        let config = databastion_core::AgentConfig::parse(&format!(
            "{{console: {{url: \"https://c.example\"}}, state_dir: /s, targets: [{{id: cas-prod, \
             engine: cas, cas: {{audit_log: {{path: {}/missing.log}}}}}}]}}",
            dir.path().display()
        ))
        .unwrap();
        config.targets[0].clone()
    }

    #[tokio::test]
    async fn an_unreadable_target_is_reported_with_closed_notes() {
        let dir = TempDir::new("connector");
        let connector = CasConnector::new();
        assert_eq!(connector.engine(), Engine::Cas);
        assert!(connector.supports_audit());
        let t = target(&dir);
        assert_eq!(connector.audit_source(&t), Some(EventSource::CasAuditLog));
        let health = connector.check(&t).await;
        assert!(!health.reachable);
        assert_eq!(health.audit_level, AuditLevel::None);
        assert_eq!(health.failure, Some(FailureCode::TargetUnreachable));
        assert_eq!(health.notes.len(), 1);
        assert_eq!(health.notes[0].code(), NoteCode::AuditLogNotReadable);
        // Other engines' targets have no CAS settings.
        let pg = databastion_core::AgentConfig::parse(
            "{console: {url: \"https://c.example\"}, state_dir: /s, targets: [{id: pg, \
             engine: postgres, host: 127.0.0.1, account: a, secret: {env: X}}]}",
        )
        .unwrap();
        let health = connector.check(&pg.targets[0]).await;
        assert_eq!(health.failure, Some(FailureCode::Internal));
        assert_eq!(connector.audit_source(&pg.targets[0]), None);
    }

    #[tokio::test]
    async fn jobs_without_a_target_fail_closed() {
        let connector = CasConnector::new();
        let (findings, _rx) = FindingSink::channel(1);
        assert!(matches!(
            connector.discover(&ScanJob::default(), &findings).await,
            Err(ConnectorError::Target {
                engine: Engine::Cas,
                code: FailureCode::Internal,
                ..
            })
        ));
        let (events, _rx) = EventSink::channel(1);
        assert!(matches!(
            connector
                .audit_stream(&AuditConfig::default(), &events)
                .await,
            Err(ConnectorError::Target {
                engine: Engine::Cas,
                code: FailureCode::Internal,
                ..
            })
        ));
    }

    #[test]
    fn the_state_is_reset_when_the_settings_change() {
        let dir = TempDir::new("connector-state");
        let connector = CasConnector::new();
        let t = target(&dir);
        let (_, a) = connector.target(&t).unwrap();
        let (_, b) = connector.target(&t).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let other = TempDir::new("connector-state-2");
        let mut moved = target(&other);
        moved.id = t.id.clone();
        let (_, c) = connector.target(&moved).unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
    }
}
