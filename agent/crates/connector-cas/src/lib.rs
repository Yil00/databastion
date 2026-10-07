//! Apereo CAS connector for the DataBastion agent (phase 8, ADR-0041).
//!
//! CAS has no query protocol of its own: this crate reads **local files
//! only**, declared in `agent.yaml` ([`config`]), and opens no network
//! connection of any kind (ADR-0041 decisions 2 and 13): no HTTP client,
//! no database client, no actuator endpoint, no credential. The CAS stores
//! held in a supported engine (JPA tables, MongoDB collections, the LDAP
//! service registry) are read by that engine's connector, with the CAS
//! store guard (ADR-0041 decision 5, a later task).
//!
//! [`CasConnector`] is the `Connector` of the `cas` engine ([`connector`]);
//! the `cas:` block of a target is validated and resolved by the core
//! (`databastion_core::config::cas`, re-exported in [`config`]). A `cas`
//! target is never detected locally (ADR-0041 decision 3, I5).
//!
//! - Discovery ([`discover`]): the JSON service registry, opened with
//!   `openat` / `fstat` checks ([`fsread`]: no symlink, `st_nlink` = 1, no
//!   file the agent could write, directories holding CAS configuration
//!   refused), parsed by a closed, bounded visitor
//!   ([`parse::definition`]); credential fields are never sampled, URLs
//!   lose their userinfo, query and fragment; values are classified
//!   through `ScanJob::classify`, so only masked samples and fingerprints
//!   leave (I2). Also the `who` of successful authentications in the end
//!   of the audit log.
//! - Audit ([`audit`]): the JSON audit log, tailed by the core tailer,
//!   parsed by a closed visitor ([`parse::record`]: duplicate keys drop the
//!   record, `what` is reduced to a service at parse time, ticket ids are
//!   never kept), principals fingerprinted except `clear_principals`,
//!   client addresses reduced per `client_addr`, failed-login signals with
//!   bounded windows, per-record panic isolation.
//! - [`check`]: readable sources, closed notes with counts only, an honest
//!   audit level (never Full).
//!
//! **Ticket ids are live SSO bearer credentials**: they are never sampled,
//! logged, fingerprinted nor reported. The audit record's `what` (which can
//! hold one) is dropped once reduced; the registry holds none.
//!
//! The crate's closed types ([`notes`], [`audit::events::CasEvent`],
//! [`check::CasHealth`]) are mapped exhaustively to the core's
//! (`NoteCode`, `TargetHealth`) and to the masked types
//! (`MaskedEvent`, `Signal`) before they leave the crate.

#![forbid(unsafe_code)]
// Log and file input is sliced in this crate: slicing a string must be
// proven on ASCII or on a boundary found by the code (as connector-openldap).
#![cfg_attr(not(test), deny(clippy::string_slice, clippy::indexing_slicing))]

pub mod audit;
pub mod check;
pub mod config;
pub mod connector;
pub mod discover;
pub mod fsread;
pub mod notes;
pub mod parse;
pub mod registry;
pub mod state;

/// Fuzz target entry points (`agent/fuzz`); `fuzzing` feature only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;

#[cfg(test)]
mod proptests;

pub use audit::events::{Builder, CasEvent, CasPrincipal};
pub use audit::stream::AuditRunner;
pub use check::{CasHealth, check};
pub use config::{CasSettings, ClientAddrMode, ConfigError};
pub use connector::CasConnector;
pub use discover::{CasError, discover};
pub use notes::{CasNote, CasNoteCode, CasSignal};
pub use state::CasState;

/// Test support only (feature `test-support`, enabled from other crates'
/// `[dev-dependencies]`, never by the agent binary): lets their tests run
/// the connector on files the test's own user created (see
/// [`fsread::allow_agent_owned_files_for_tests`]).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use fsread::allow_agent_owned_files_for_tests;
