//! Core of the DataBastion agent (ADR-0002).
//!
//! - [`engine`]: engines, audit levels and target health.
//! - [`connector`]: the [`Connector`] trait every connector implements.
//! - [`sink`]: channels through which connectors hand results to the core.
//!   They only carry masked types from `databastion_classifiers::masking`.
//! - `uplink` (crate-private): HTTPS client towards the console (stub). Only
//!   accepts masked types, so unmasked data cannot reach it (I2, ADR-0003).
//!   It is not exported: connectors depend on this crate but can neither name
//!   nor construct it. The core runtime (not written yet) will own it and
//!   drain the sinks into it; the binary will only get that runtime.
//!
//! Protocol types are generated from `shared/protocol/openapi.yaml` in the
//! `databastion-protocol` crate (I6). Only the crate-private uplink uses
//! them, and this crate does not re-export them: connectors cannot build a
//! protocol payload (they are also barred from depending on
//! `databastion-protocol`, see `crates/agent/tests/architecture.rs`).
//!
//! Skeleton status (P0-D): no enrollment, scheduler, spool or network code.

#![forbid(unsafe_code)]

pub mod connector;
pub mod engine;
pub mod sink;
#[allow(
    dead_code,
    reason = "owned by the core runtime, which is not written yet"
)]
mod uplink;

pub use connector::{AuditConfig, Connector, ConnectorError, ScanJob};
pub use engine::{AuditLevel, Engine, TargetHealth};
pub use sink::{EventSink, FindingSink};
