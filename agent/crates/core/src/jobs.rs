//! Job list parsing and deduplication (protocol types review gate).
//!
//! - At most [`MAX_JOBS_PER_POLL`] jobs are handled per poll; the others
//!   are left leased and will be redelivered.
//! - The list is deserialized as raw JSON values, then **each** job into the
//!   generated `Job` type, so one unknown or malformed job cannot make the
//!   agent drop the whole list (forward compatibility). An unparseable job
//!   is reported `failed` with a fixed code when its `job_id` can be
//!   extracted; otherwise it is counted and logged (without its content).
//! - Delivery is at least once: a bounded ledger deduplicates by `job_id`
//!   and replays the recorded outcome of a redelivered job.

use std::collections::{HashMap, VecDeque};

use databastion_protocol::{FailureCode, Job, JobStatusUpdateStatus, Uuid};

/// Gate: maximum jobs handled per poll (also the contract's `maxItems`).
pub(crate) const MAX_JOBS_PER_POLL: usize = 16;
/// Job ids remembered for deduplication.
const LEDGER_CAPACITY: usize = 1024;

/// Job types known to this agent version.
const KNOWN_TYPES: [&str; 4] = [
    "discovery.scan",
    "audit.configure",
    "agent.config.reload",
    "agent.rotate_secret",
];

/// One entry of a polled job list.
#[derive(Debug)]
pub(crate) enum PolledJob {
    /// A job that matches the contract.
    Parsed(Box<Job>),
    /// A job that does not: unknown type or invalid parameters.
    Unparseable {
        /// Its id, when present and canonical.
        job_id: Option<Uuid>,
        /// Fixed failure code to report.
        code: FailureCode,
    },
}

/// Result of parsing a `200` body of `GET /jobs`.
#[derive(Debug)]
pub(crate) struct PolledList {
    pub(crate) jobs: Vec<PolledJob>,
    /// Jobs beyond [`MAX_JOBS_PER_POLL`], left for redelivery.
    pub(crate) deferred: usize,
}

/// The body is not a job list at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed job list")]
pub(crate) struct MalformedJobList;

/// Parses a job list body, job by job.
pub(crate) fn parse_job_list(body: &[u8]) -> Result<PolledList, MalformedJobList> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| MalformedJobList)?;
    let object = value.as_object().ok_or(MalformedJobList)?;
    let raw = object
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .ok_or(MalformedJobList)?;
    let deferred = raw.len().saturating_sub(MAX_JOBS_PER_POLL);
    let jobs = raw
        .iter()
        .take(MAX_JOBS_PER_POLL)
        .map(|v| parse_one(v.clone()))
        .collect();
    Ok(PolledList { jobs, deferred })
}

fn parse_one(value: serde_json::Value) -> PolledJob {
    let job_id = value
        .get("job_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::try_from(s).ok());
    let known_type = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|t| KNOWN_TYPES.contains(&t));
    match serde_json::from_value::<Job>(value) {
        Ok(job) => PolledJob::Parsed(Box::new(job)),
        Err(_) => PolledJob::Unparseable {
            job_id,
            code: if known_type {
                FailureCode::InvalidParams
            } else {
                FailureCode::Unsupported
            },
        },
    }
}

/// Job id of a parsed job.
pub(crate) fn job_id(job: &Job) -> Uuid {
    match job {
        Job::DiscoveryScanJob(j) => j.job_id,
        Job::AuditConfigureJob(j) => j.job_id,
        Job::AgentConfigReloadJob(j) => j.job_id,
        Job::AgentRotateSecretJob(j) => j.job_id,
    }
}

/// Type name of a parsed job (closed set, safe to log).
pub(crate) fn job_type(job: &Job) -> &'static str {
    match job {
        Job::DiscoveryScanJob(_) => "discovery.scan",
        Job::AuditConfigureJob(_) => "audit.configure",
        Job::AgentConfigReloadJob(_) => "agent.config.reload",
        Job::AgentRotateSecretJob(_) => "agent.rotate_secret",
    }
}

/// Expiry of a parsed job, if any.
pub(crate) fn expires_at(job: &Job) -> Option<chrono::DateTime<chrono::Utc>> {
    match job {
        Job::DiscoveryScanJob(j) => j.expires_at.as_ref().map(|t| t.0),
        Job::AuditConfigureJob(j) => j.expires_at.as_ref().map(|t| t.0),
        Job::AgentConfigReloadJob(j) => j.expires_at.as_ref().map(|t| t.0),
        Job::AgentRotateSecretJob(j) => j.expires_at.as_ref().map(|t| t.0),
    }
}

/// Terminal outcome of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) status: JobStatusUpdateStatus,
    pub(crate) error: Option<FailureCode>,
    /// Discovery coverage reported by the connector (`discovery.scan`).
    pub(crate) coverage: Option<crate::sink::ScanCoverage>,
    /// The scan stopped before its deadline (Discovery pacing,
    /// `Paced::OutOfTime`): some objects were not sampled. Reported as
    /// `succeeded` only with the coverage counters that show it; without
    /// them (console without `job_progress.coverage`), as `failed` with
    /// `timeout` (security review of #93, R3).
    pub(crate) out_of_time: bool,
}

impl Outcome {
    pub(crate) const SUCCEEDED: Self = Self {
        status: JobStatusUpdateStatus::Succeeded,
        error: None,
        coverage: None,
        out_of_time: false,
    };

    /// Not terminal: the `running` acknowledgement of a scan.
    pub(crate) const RUNNING: Self = Self {
        status: JobStatusUpdateStatus::Running,
        error: None,
        coverage: None,
        out_of_time: false,
    };

    pub(crate) const fn failed(code: FailureCode) -> Self {
        Self {
            status: JobStatusUpdateStatus::Failed,
            error: Some(code),
            coverage: None,
            out_of_time: false,
        }
    }

    /// Status and error sent for this outcome, depending on whether the
    /// coverage counters go with it: a scan that ran out of time succeeds
    /// only when the console sees what it did not sample.
    pub(crate) fn reported(
        &self,
        with_coverage: bool,
    ) -> (JobStatusUpdateStatus, Option<FailureCode>) {
        if self.out_of_time && !with_coverage && self.status == JobStatusUpdateStatus::Succeeded {
            (JobStatusUpdateStatus::Failed, Some(FailureCode::Timeout))
        } else {
            (self.status, self.error)
        }
    }
}

/// State of a job in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LedgerEntry {
    pub(crate) outcome: Outcome,
    /// Whether the console acknowledged the terminal status.
    pub(crate) reported: bool,
}

/// Bounded deduplication ledger (FIFO eviction).
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    entries: HashMap<Uuid, LedgerEntry>,
    order: VecDeque<Uuid>,
}

impl Ledger {
    pub(crate) fn get(&self, id: &Uuid) -> Option<LedgerEntry> {
        self.entries.get(id).copied()
    }

    pub(crate) fn record(&mut self, id: Uuid, entry: LedgerEntry) {
        if self.entries.insert(id, entry).is_none() {
            self.order.push_back(id);
            while self.order.len() > LEDGER_CAPACITY {
                if let Some(old) = self.order.pop_front() {
                    self.entries.remove(&old);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared/protocol/fixtures/valid")
            .join(name);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn every_valid_job_list_fixture_parses_fully() {
        for name in [
            "JobList.audit-configure.json",
            "JobList.config-reload.json",
            "JobList.discovery-scan-minimal.json",
            "JobList.discovery-scan.json",
            "JobList.mixed.json",
            "JobList.rotate-secret.json",
        ] {
            let list = parse_job_list(&fixture(name)).unwrap();
            assert!(!list.jobs.is_empty(), "{name}");
            assert_eq!(list.deferred, 0);
            for job in &list.jobs {
                assert!(matches!(job, PolledJob::Parsed(_)), "{name}: {job:?}");
            }
        }
    }

    #[test]
    fn unknown_job_type_does_not_drop_the_list() {
        let mixed: serde_json::Value =
            serde_json::from_slice(&fixture("JobList.mixed.json")).unwrap();
        let mut jobs = mixed["jobs"].as_array().unwrap().clone();
        let known = jobs.len();
        jobs.insert(
            1,
            serde_json::json!({
                "job_id": "01920f5f-0c30-7e6f-a043-2b3c4d5e6f99",
                "type": "discovery.future_thing",
                "created_at": "2026-09-28T10:00:00Z",
                "params": {"x": 1}
            }),
        );
        jobs.push(serde_json::json!({"type": "agent.config.reload", "params": {}}));
        jobs.push(serde_json::json!("not an object"));
        let body = serde_json::to_vec(&serde_json::json!({ "jobs": jobs })).unwrap();
        let list = parse_job_list(&body).unwrap();
        assert_eq!(list.jobs.len(), known + 3);
        let parsed = list
            .jobs
            .iter()
            .filter(|j| matches!(j, PolledJob::Parsed(_)))
            .count();
        assert_eq!(parsed, known);
        match &list.jobs[1] {
            PolledJob::Unparseable { job_id, code } => {
                assert_eq!(
                    job_id.unwrap().to_string(),
                    "01920f5f-0c30-7e6f-a043-2b3c4d5e6f99"
                );
                assert_eq!(*code, FailureCode::Unsupported);
            }
            other => panic!("{other:?}"),
        }
        match &list.jobs[known + 1] {
            PolledJob::Unparseable { job_id, code } => {
                assert!(job_id.is_none());
                assert_eq!(*code, FailureCode::InvalidParams);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn jobs_beyond_the_cap_are_deferred() {
        let one: serde_json::Value =
            serde_json::from_slice(&fixture("JobList.config-reload.json")).unwrap();
        let job = one["jobs"][0].clone();
        let jobs: Vec<_> = (0..40).map(|_| job.clone()).collect();
        let body = serde_json::to_vec(&serde_json::json!({ "jobs": jobs })).unwrap();
        let list = parse_job_list(&body).unwrap();
        assert_eq!(list.jobs.len(), MAX_JOBS_PER_POLL);
        assert_eq!(list.deferred, 24);
    }

    #[test]
    fn malformed_bodies_are_rejected() {
        for body in [&b"[]"[..], b"{}", b"{\"jobs\": 3}", b"not json"] {
            assert_eq!(parse_job_list(body).unwrap_err(), MalformedJobList);
        }
    }

    #[test]
    fn ledger_is_bounded() {
        let mut ledger = Ledger::default();
        for _ in 0..(LEDGER_CAPACITY + 10) {
            let id =
                Uuid::try_from(databastion_protocol::new_batch_id().to_string().as_str()).unwrap();
            ledger.record(
                id,
                LedgerEntry {
                    outcome: Outcome::SUCCEEDED,
                    reported: true,
                },
            );
        }
        assert_eq!(ledger.len(), LEDGER_CAPACITY);
    }
}
