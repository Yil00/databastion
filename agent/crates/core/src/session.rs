//! Authenticated calls and secret rotation (ADR-0008).
//!
//! `401` handling, per the contract (`Unauthorized` response):
//! - with a pending secret `S1`, requests try `S1` first and fall back to
//!   the current secret `S0` on `401` (`S1` never registered); a `401` with
//!   `S0` while `S1` is pending is retried with `S1` before anything else;
//! - the first success with `S1` promotes it (persisted atomically);
//! - a `401` for a secret that is no longer current (switched meanwhile) is
//!   retried once with the current one;
//! - otherwise the `401` is fatal for normal operation
//!   ([`CallError::Unauthorized`]); the runtime then only sends one
//!   heartbeat every 15 min.
//!
//! Rotation: `S1` is generated locally and persisted as pending (`0600`,
//! fsync) **before** `POST /rotate`; a pending `S1` is always reused (retry,
//! redelivered job, restart). A `rotation_conflict` is fatal.

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use databastion_protocol::{AgentSecret, ErrorCode, RotateRequest, RotateResponse, Uuid};
use reqwest::Method;
use zeroize::Zeroizing;

use crate::identity::{self, Identity, IdentityError, StateDir};
use crate::uplink::{Auth, Reply, Uplink, UplinkError};

/// Errors of an authenticated call.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CallError {
    /// `401` with the current secret: stop normal operation.
    #[error("unauthorized with the current secret")]
    Unauthorized,
    /// `rotation_conflict`: the console locked this agent.
    #[error("rotation conflict: the console locked this agent; re-enrollment required")]
    RotationConflict,
    /// Other uplink error.
    #[error(transparent)]
    Uplink(UplinkError),
    /// Local state error.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

impl From<UplinkError> for CallError {
    fn from(e: UplinkError) -> Self {
        match e {
            UplinkError::Unauthorized => Self::Unauthorized,
            UplinkError::Rejected {
                code: Some(ErrorCode::RotationConflict),
                ..
            } => Self::RotationConflict,
            other => Self::Uplink(other),
        }
    }
}

struct Creds {
    identity: Identity,
    /// Incremented on every change of the secret in use.
    generation: u64,
    /// `S1` got a `401` in this process: use `S0` first (and redo `/rotate`).
    pending_rejected: bool,
    /// Job id of the last rotation, persisted with the identity.
    last_rotation_job: Option<Uuid>,
}

/// Outcome of [`Session::rotate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotateOutcome {
    /// `S1` registered as pending (`duplicate` on an idempotent retry).
    Registered { duplicate: bool },
    /// The job already completed a rotation (redelivery after promotion).
    AlreadyDone,
}

/// Authenticated client.
pub(crate) struct Session {
    uplink: Uplink,
    state: StateDir,
    creds: Mutex<Creds>,
}

impl Session {
    pub(crate) fn new(uplink: Uplink, state: StateDir, identity: Identity) -> Self {
        let last_rotation_job = identity.rotation_job;
        Self {
            uplink,
            state,
            creds: Mutex::new(Creds {
                identity,
                generation: 0,
                pending_rejected: false,
                last_rotation_job,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Creds> {
        // A poisoned lock only means a panic elsewhere; the data is intact.
        self.creds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn heartbeat_interval_s(&self) -> u64 {
        self.lock().identity.heartbeat_interval_s
    }

    /// Whether a pending `S1` exists and must be registered again.
    pub(crate) fn needs_rotation_retry(&self) -> bool {
        let creds = self.lock();
        creds.identity.pending.is_some() && creds.pending_rejected
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Identity {
        self.lock().identity.clone()
    }

    /// Secrets to try, in order, with a flag telling whether it is `S1`.
    fn candidates(&self) -> (u64, Uuid, Vec<(AgentSecret, bool)>) {
        let creds = self.lock();
        let current = (creds.identity.secret.clone(), false);
        let list = match &creds.identity.pending {
            None => vec![current],
            Some(s1) if creds.pending_rejected => vec![current, (s1.clone(), true)],
            Some(s1) => vec![(s1.clone(), true), current],
        };
        (creds.generation, creds.identity.agent_id, list)
    }

    /// Sends an authenticated request, handling `401` per the contract.
    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Reply, CallError> {
        let mut retried_after_switch = false;
        loop {
            let (generation, agent_id, candidates) = self.candidates();
            let mut s1_unauthorized = false;
            for (secret, is_pending) in &candidates {
                let auth = Auth::Agent {
                    agent_id: &agent_id,
                    secret,
                };
                match self
                    .uplink
                    .request(method.clone(), path, query, auth, body, timeout)
                    .await
                {
                    Ok(reply) => {
                        if *is_pending {
                            self.promote(secret)?;
                        } else if s1_unauthorized {
                            self.lock().pending_rejected = true;
                            tracing::warn!(
                                "pending secret not registered by the console; rotation will be retried"
                            );
                        }
                        return Ok(reply);
                    }
                    Err(UplinkError::Unauthorized) => {
                        if *is_pending {
                            s1_unauthorized = true;
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !retried_after_switch && self.lock().generation != generation {
                retried_after_switch = true;
                continue;
            }
            return Err(CallError::Unauthorized);
        }
    }

    /// Makes `S1` the current secret (first success with it).
    fn promote(&self, used: &AgentSecret) -> Result<(), IdentityError> {
        let mut creds = self.lock();
        let matches = creds
            .identity
            .pending
            .as_ref()
            .is_some_and(|p| p.expose() == used.expose());
        if !matches {
            return Ok(());
        }
        let mut next = creds.identity.clone();
        if let Some(s1) = next.pending.take() {
            next.secret = s1;
        }
        // Persist first; on failure the file still holds S0 + pending S1,
        // which a restart handles (S1 tried first).
        self.state.save_identity(&next)?;
        creds.identity = next;
        creds.generation += 1;
        creds.pending_rejected = false;
        tracing::info!("rotated agent secret promoted");
        Ok(())
    }

    /// Records a new heartbeat interval (already clamped) in memory and on
    /// disk (best effort).
    pub(crate) fn set_heartbeat_interval(&self, seconds: u64) {
        let mut creds = self.lock();
        if creds.identity.heartbeat_interval_s == seconds {
            return;
        }
        creds.identity.heartbeat_interval_s = seconds;
        if let Err(e) = self.state.save_identity(&creds.identity) {
            tracing::warn!(error = %e, "cannot persist the heartbeat interval");
        }
    }

    /// Returns the pending secret, creating and persisting one first if
    /// there is none. Persistence happens before any network call.
    fn pending_or_create(&self, job_id: Option<Uuid>) -> Result<Option<AgentSecret>, CallError> {
        let mut creds = self.lock();
        if let Some(s1) = &creds.identity.pending {
            return Ok(Some(s1.clone()));
        }
        if job_id.is_some() && job_id == creds.last_rotation_job {
            return Ok(None);
        }
        let s1 = identity::generate_secret()?;
        let mut next = creds.identity.clone();
        next.pending = Some(s1.clone());
        next.rotation_job = job_id;
        self.state.save_identity(&next)?;
        creds.identity = next;
        creds.last_rotation_job = job_id;
        creds.pending_rejected = false;
        Ok(Some(s1))
    }

    fn discard_pending(&self) -> Result<(), IdentityError> {
        let mut creds = self.lock();
        let mut next = creds.identity.clone();
        next.pending = None;
        self.state.save_identity(&next)?;
        creds.identity = next;
        creds.pending_rejected = false;
        Ok(())
    }

    /// `POST /rotate` with the current secret, registering the pending `S1`
    /// (created and persisted first if needed).
    pub(crate) async fn rotate(&self, job_id: Option<Uuid>) -> Result<RotateOutcome, CallError> {
        let Some(s1) = self.pending_or_create(job_id)? else {
            return Ok(RotateOutcome::AlreadyDone);
        };
        let (agent_id, s0) = {
            let creds = self.lock();
            (creds.identity.agent_id, creds.identity.secret.clone())
        };
        let request = RotateRequest {
            job_id,
            new_secret: s1,
        };
        let body = Zeroizing::new(
            serde_json::to_vec(&request).map_err(|_| UplinkError::Setup("rotate body"))?,
        );
        let auth = Auth::Agent {
            agent_id: &agent_id,
            secret: &s0,
        };
        let result = self
            .uplink
            .request(
                Method::POST,
                "/rotate",
                &[],
                auth,
                Some(&body),
                crate::uplink::REQUEST_TIMEOUT,
            )
            .await;
        match result {
            Ok(reply) => {
                let response: RotateResponse =
                    serde_json::from_slice(&reply.body).map_err(|_| {
                        UplinkError::UnexpectedResponse {
                            status: reply.status.as_u16(),
                        }
                    })?;
                let mut creds = self.lock();
                creds.pending_rejected = false;
                // Subsequent requests use S1 first.
                creds.generation += 1;
                Ok(RotateOutcome::Registered {
                    duplicate: response.duplicate,
                })
            }
            Err(UplinkError::Rejected {
                code: Some(ErrorCode::InvalidSecret),
                ..
            }) => {
                // The console did not register S1: safe to discard it.
                self.discard_pending()?;
                Err(CallError::Uplink(UplinkError::Rejected {
                    status: 400,
                    code: Some(ErrorCode::InvalidSecret),
                }))
            }
            Err(UplinkError::Unauthorized) => {
                // S0 refused while S1 is pending: S1 may already be promoted
                // (deadline). Next calls try S1 first.
                self.lock().pending_rejected = false;
                Err(CallError::Unauthorized)
            }
            Err(e) => Err(e.into()),
        }
    }
}
