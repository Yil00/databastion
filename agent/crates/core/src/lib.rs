//! Core of the DataBastion agent (ADR-0002).
//!
//! - [`engine`]: engines, audit levels and target health.
//! - [`connector`]: the [`Connector`] trait every connector implements.
//! - [`sink`]: channels through which connectors hand results to the core.
//!   They only carry masked types from `databastion_classifiers::masking`.
//! - [`uplink`]: HTTPS client towards the console (stub). Only accepts masked
//!   types, so unmasked data cannot reach it (I2, ADR-0003).
//! - [`protocol`]: placeholder for the types generated from
//!   `shared/protocol/openapi.yaml` (I6).
//!
//! Skeleton status (P0-D): no enrollment, scheduler, spool or network code.

#![forbid(unsafe_code)]

pub mod connector;
pub mod engine;
pub mod protocol;
pub mod sink;
pub mod uplink;

pub use connector::{AuditConfig, Connector, ConnectorError, ScanJob};
pub use engine::{AuditLevel, Engine, TargetHealth};
pub use sink::{EventSink, FindingSink};
