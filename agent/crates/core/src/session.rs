//! Authenticated calls and secret rotation (ADR-0008).
//!
//! `401` handling, per the contract (`Unauthorized` response):
//! - with a pending secret `S1`, requests try `S1` first and fall back to
//!   the current secret `S0` on `401` (`S1` never registered); a `401` with
//!   `S0` while `S1` is pending is retried with `S1` before anything else;
//! - any other error on `S1` (notably `429` / `503`, answered before the
//!   console recognizes the secret) is returned as is, **without** falling
//!   back to `S0`: `S1` may already be promoted and `S0` past the 60 s
//!   window, where using it locks the agent (ADR-0010, ADR-0011);
//! - the first success with `S1` promotes it (persisted atomically). A
//!   success only counts once the caller's per-endpoint checker
//!   (`uplink::accept`) accepts the reply (status, media type, body): a
//!   `2xx` from a middlebox (e.g. a TLS-inspection proxy's `200` page) is
//!   an `UnexpectedResponse` and leaves `S0` current and `S1` pending;
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
use std::time::{Duration, Instant};

use databastion_protocol::{AgentSecret, ErrorCode, RotateRequest, Uuid};
use reqwest::Method;

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
    /// `S1` got a `401` **after** the latest `/rotate` attempt: use `S0`
    /// first (and redo `/rotate`). Reset by every `/rotate` attempt, since
    /// an attempt with an unknown outcome may have registered `S1`.
    pending_rejected: bool,
    /// Incremented at the start of every `/rotate` attempt and when its
    /// answer is received (`200`, or `401` with `S0`); a `401` on `S1` only
    /// marks it rejected if neither happened since the request started.
    rotate_epoch: u64,
    /// Last promotion in this process: no new rotation within the console's
    /// 60 s tolerance window.
    ///
    /// In memory only, by design: after a restart the window is not
    /// enforced. This is harmless under ADR-0010: a new rotation within 60 s
    /// of a promotion only shortens the console's tolerance for the
    /// previous secret, which the restarted agent no longer uses (it loads
    /// the promoted secret from disk).
    promoted_at: Option<Instant>,
}

/// Console tolerance window after a promotion (ADR-0008).
const PROMOTION_WINDOW: Duration = Duration::from_secs(60);

/// Outcome of [`Session::rotate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotateOutcome {
    /// `S1` registered as pending (`duplicate` on an idempotent retry).
    Registered { duplicate: bool },
    /// The job already completed a rotation (redelivery after promotion).
    AlreadyDone,
    /// A promotion happened less than 60 s ago: the job is left
    /// unacknowledged and will be redelivered.
    Deferred,
}

/// Authenticated client.
pub(crate) struct Session {
    uplink: Uplink,
    state: StateDir,
    creds: Mutex<Creds>,
}

impl Session {
    pub(crate) fn new(uplink: Uplink, state: StateDir, identity: Identity) -> Self {
        Self {
            uplink,
            state,
            creds: Mutex::new(Creds {
                identity,
                generation: 0,
                pending_rejected: false,
                rotate_epoch: 0,
                promoted_at: None,
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
    fn candidates(&self) -> (u64, u64, Uuid, Vec<(AgentSecret, bool)>) {
        let creds = self.lock();
        let current = (creds.identity.secret.clone(), false);
        let list = match &creds.identity.pending {
            None => vec![current],
            Some(s1) if creds.pending_rejected => vec![current, (s1.clone(), true)],
            Some(s1) => vec![(s1.clone(), true), current],
        };
        (
            creds.generation,
            creds.rotate_epoch,
            creds.identity.agent_id,
            list,
        )
    }

    /// Sends an authenticated request, handling `401` per the contract.
    /// `accept` checks a `2xx` reply against the endpoint contract and
    /// extracts its value; a pending `S1` is promoted only after that. A
    /// reply it refuses is `UnexpectedResponse` and changes no credential
    /// state.
    pub(crate) async fn call<T>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&[u8]>,
        timeout: Duration,
        accept: impl Fn(&Reply) -> Option<T>,
    ) -> Result<T, CallError> {
        let mut retried_after_switch = false;
        loop {
            let (generation, epoch, agent_id, candidates) = self.candidates();
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
                        let Some(value) = accept(&reply) else {
                            tracing::warn!(
                                status = reply.status.as_u16(),
                                "success reply does not match the contract; ignored"
                            );
                            return Err(UplinkError::UnexpectedResponse {
                                status: reply.status.as_u16(),
                            }
                            .into());
                        };
                        if *is_pending {
                            self.promote(secret)?;
                        } else if s1_unauthorized {
                            let mut creds = self.lock();
                            if creds.rotate_epoch == epoch {
                                creds.pending_rejected = true;
                                tracing::warn!(
                                    "pending secret not registered by the console; rotation will be retried"
                                );
                            }
                        }
                        return Ok(value);
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
        creds.promoted_at = Some(Instant::now());
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
    /// there is none. Persistence happens before any network call. The job
    /// id joins the bounded set of jobs satisfied by this secret.
    fn pending_or_create(&self, job_id: Option<Uuid>) -> Result<Pending, CallError> {
        let mut creds = self.lock();
        if let Some(s1) = creds.identity.pending.clone() {
            if let Some(id) = job_id
                && !creds.identity.rotation_jobs.contains(&id)
            {
                let mut next = creds.identity.clone();
                push_bounded(&mut next.rotation_jobs, id);
                self.state.save_identity(&next)?;
                creds.identity = next;
            }
            return Ok(Pending::Use(s1));
        }
        if job_id.is_some_and(|id| creds.identity.rotation_jobs.contains(&id)) {
            return Ok(Pending::AlreadyDone);
        }
        if creds
            .promoted_at
            .is_some_and(|t| t.elapsed() < PROMOTION_WINDOW)
        {
            return Ok(Pending::Deferred);
        }
        let s1 = identity::generate_secret()?;
        let mut next = creds.identity.clone();
        next.pending = Some(s1.clone());
        next.rotation_jobs = job_id.into_iter().collect();
        self.state.save_identity(&next)?;
        creds.identity = next;
        creds.pending_rejected = false;
        Ok(Pending::Use(s1))
    }

    /// Drops a pending secret the console refused (never registered), and
    /// the jobs it was meant to satisfy.
    fn discard_pending(&self) -> Result<(), IdentityError> {
        let mut creds = self.lock();
        let mut next = creds.identity.clone();
        next.pending = None;
        next.rotation_jobs.clear();
        self.state.save_identity(&next)?;
        creds.identity = next;
        creds.pending_rejected = false;
        Ok(())
    }

    /// `POST /rotate` with the current secret, registering the pending `S1`
    /// (created and persisted first if needed). No probe: see
    /// [`Self::rotate_probed`] (tests).
    #[cfg(test)]
    pub(crate) async fn rotate(&self, job_id: Option<Uuid>) -> Result<RotateOutcome, CallError> {
        self.rotate_probed(job_id, None).await
    }

    /// Like [`Self::rotate`], but when a pending `S1` already exists (its
    /// registration outcome is unknown), first sends one ordinary request
    /// (`POST /heartbeat` with `probe` as body) authenticated with `S1`
    /// alone. If the console accepts it, `S1` was registered and promoted on
    /// the console side: it is promoted here and no `/rotate` is sent with
    /// `S0` (which may already be past its grace period and would count as a
    /// rotation conflict).
    pub(crate) async fn rotate_probed(
        &self,
        job_id: Option<Uuid>,
        probe: Option<&[u8]>,
    ) -> Result<RotateOutcome, CallError> {
        let pending_before = self.lock().identity.pending.is_some();
        let s1 = match self.pending_or_create(job_id)? {
            Pending::Use(s1) => s1,
            Pending::AlreadyDone => return Ok(RotateOutcome::AlreadyDone),
            Pending::Deferred => return Ok(RotateOutcome::Deferred),
        };
        if let (true, Some(body)) = (pending_before, probe)
            && self.probe_pending(&s1, body).await?
        {
            return Ok(RotateOutcome::AlreadyDone);
        }
        let (agent_id, s0) = {
            let mut creds = self.lock();
            // The outcome of this attempt may be unknown (lost response):
            // S1 goes first again until it gets a 401 after this point.
            creds.rotate_epoch += 1;
            creds.pending_rejected = false;
            (creds.identity.agent_id, creds.identity.secret.clone())
        };
        let request = RotateRequest {
            job_id,
            new_secret: s1,
        };
        let body = crate::identity::json_zeroizing(&request, false)
            .map_err(|_| UplinkError::Setup("rotate body"))?;
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
                // Same contract check as every other endpoint: a
                // middlebox's `2xx` page proves nothing, and the outcome
                // of this attempt stays unknown (S1 keeps going first).
                let Some(response) = crate::uplink::accept::rotate(&reply) else {
                    tracing::warn!(
                        status = reply.status.as_u16(),
                        "rotate reply does not match the contract; ignored"
                    );
                    return Err(UplinkError::UnexpectedResponse {
                        status: reply.status.as_u16(),
                    }
                    .into());
                };
                let mut creds = self.lock();
                // S1 is now registered: a `401` on S1 obtained by a request
                // sent before this point is stale and must not put S0
                // first again (it would outlive the 60 s window and lock
                // the agent, ADR-0010).
                creds.rotate_epoch += 1;
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
                    unknown_field: false,
                }))
            }
            Err(UplinkError::Unauthorized) => {
                // S0 refused while S1 is pending: S1 may already be promoted
                // (deadline). Next calls try S1 first; a stale S1 `401`
                // from before this answer must not undo that.
                let mut creds = self.lock();
                creds.rotate_epoch += 1;
                creds.pending_rejected = false;
                Err(CallError::Unauthorized)
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Session {
    /// Sends `POST /heartbeat` with `S1` only. `true`: accepted with a
    /// contract `HeartbeatResponse`, `S1` promoted. `false`: `401` (not
    /// registered yet). A success status whose body is not a
    /// `HeartbeatResponse` (e.g. a proxy page) is an error: nothing is
    /// promoted and no `/rotate` is sent in this attempt.
    async fn probe_pending(&self, s1: &AgentSecret, body: &[u8]) -> Result<bool, CallError> {
        let agent_id = self.lock().identity.agent_id;
        let auth = Auth::Agent {
            agent_id: &agent_id,
            secret: s1,
        };
        match self
            .uplink
            .request(
                Method::POST,
                "/heartbeat",
                &[],
                auth,
                Some(body),
                crate::uplink::REQUEST_TIMEOUT,
            )
            .await
        {
            Ok(reply) => {
                // Check before promoting: only a contract answer proves the
                // console accepted S1.
                if crate::uplink::accept::heartbeat(&reply).is_none() {
                    return Err(UplinkError::UnexpectedResponse {
                        status: reply.status.as_u16(),
                    }
                    .into());
                }
                self.promote(s1)?;
                tracing::info!("pending secret already registered; promoted without /rotate");
                Ok(true)
            }
            Err(UplinkError::Unauthorized) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// Pending secret to register, or why none is needed.
enum Pending {
    Use(AgentSecret),
    AlreadyDone,
    Deferred,
}

fn push_bounded(jobs: &mut Vec<Uuid>, id: Uuid) {
    jobs.push(id);
    let excess = jobs.len().saturating_sub(identity::MAX_ROTATION_JOBS);
    jobs.drain(..excess);
}
