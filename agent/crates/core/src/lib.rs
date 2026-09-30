//! Core of the DataBastion agent (ADR-0002).
//!
//! - [`engine`]: engines, audit levels and target health.
//! - [`connector`]: the [`Connector`] trait every connector implements.
//! - [`job`]: job parameters handed to connectors ([`ScanJob`],
//!   [`AuditConfig`]), only built through the contract `TryFrom` gates and
//!   the `agent.yaml` clamp.
//! - [`sink`]: channels through which connectors hand results to the core.
//!   They only carry masked types from `databastion_classifiers::masking`.
//! - [`audit`]: persisted audit cursors ([`audit::CursorStore`]), and
//!   (crate-private) pre-aggregation and the `audit.configure` filter.
//! - [`notes`]: closed target notes ([`NoteCode`], [`TargetNote`]) that
//!   `check()` reports with [`TargetHealth`].
//! - [`config`]: the local `agent.yaml` (targets, secret references, hard
//!   limits).
//! - [`runtime`]: enrollment and the heartbeat / jobs loops. This is all the
//!   binary gets.
//! - crate-private: `uplink` (HTTPS client, rustls, TLS 1.3), `session`
//!   (authentication, `401` handling, secret rotation), `identity` (`0600`
//!   state files), `jobs` (per-job parsing, dedup), `backoff`, `sanitize`
//!   (per-item validation, ADR-0009), `spool` (bounded disk spool),
//!   `detect` (local engine detection, ADR-0006).
//!
//! The uplink only accepts masked types for findings and events (I2,
//! ADR-0003). It is not exported: connectors depend on this crate but can
//! neither name nor construct it.
//!
//! Protocol types are generated from `shared/protocol/openapi.yaml` in the
//! `databastion-protocol` crate (I6). Only this crate uses them, and it does
//! not re-export them: connectors cannot build a protocol payload (they are
//! also barred from depending on `databastion-protocol`, see
//! `crates/agent/tests/architecture.rs`).

#![forbid(unsafe_code)]

pub mod audit;
mod backoff;
mod capabilities;
mod checks;
pub mod config;
pub mod connector;
mod detect;
pub mod engine;
mod fsutil;
pub mod identity;
pub mod job;
mod jobs;
pub mod notes;
mod panics;
pub mod runtime;
mod sanitize;
mod session;
pub mod sink;
mod spool;
#[cfg(feature = "test-support")]
pub mod test_support;
mod uplink;

pub use config::AgentConfig;
pub use connector::{Connector, ConnectorError};
pub use engine::{AuditLevel, Engine, FailureCode, TargetHealth};
pub use job::{AuditConfig, AuditParams, ParamsError, ScanJob, ScanParams};
pub use notes::{CountMerge, NoteCode, NoteLabel, Notes, TargetNote};
pub use panics::{install_panic_hook, isolate, resume_panic};
pub use runtime::{AgentError, EnrollOptions, enroll, run};
pub use sink::{EventSink, FindingSink, ScanCoverage};
