//! Core of the DataBastion agent (ADR-0002).
//!
//! - [`engine`]: engines, audit levels and target health.
//! - [`connector`]: the [`Connector`] trait every connector implements.
//! - [`sink`]: channels through which connectors hand results to the core.
//!   They only carry masked types from `databastion_classifiers::masking`.
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

mod backoff;
pub mod config;
pub mod connector;
mod detect;
pub mod engine;
mod fsutil;
pub mod identity;
mod jobs;
pub mod runtime;
mod sanitize;
mod session;
pub mod sink;
mod spool;
mod uplink;

pub use config::AgentConfig;
pub use connector::{AuditConfig, Connector, ConnectorError, ScanJob};
pub use engine::{AuditLevel, Engine, FailureCode, TargetHealth};
pub use runtime::{AgentError, EnrollOptions, enroll, run};
pub use sink::{EventSink, FindingSink};
