//! SQLite connector (ADR-0059): Discovery of declared local database files,
//! read by the bundled SQLite C library (`rusqlite`, a reviewed exception to
//! "no C client library", decision 1) **only in a sandboxed reader
//! process** (decision 4): a fresh `execve` of the agent's own binary in
//! the hidden `sqlite-reader` mode, its environment cleared, no new
//! privileges, not dumpable, under resource limits, Landlock (read access
//! to the declared file's directory only) and seccomp (no socket, no
//! process, no write), talking to the agent over a bounded IPC channel and
//! killed at its deadline.
//!
//! - Declared files only (`targets[].sqlite.path`, I5); the path never
//!   leaves the agent and is never logged (decision 2).
//! - Read-only by layers (decision 3): no file the agent could write is
//!   read, the file system must be mounted read-only for the agent,
//!   Landlock and seccomp refuse writes, SQLite opens the file
//!   `mode=ro&readonly_shm=1` with `query_only`, and every descriptor on
//!   the file is checked `O_RDONLY` at run time.
//! - Hardened against hostile files (decision 5): compile-time options
//!   checked at every reader start, lowered limits, a heap limit, a
//!   progress handler with a deadline, an authorizer returning
//!   `SQLITE_DENY`, a closed list of statements, no view, trigger or
//!   virtual table ever executed.
//! - Discovery only: Audit is `none` (decision 7).
//!
//! Raw names and values cross the IPC channel to the agent, which
//! normalizes the names and classifies and masks the values (I2).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::string_slice))]

pub mod auth;
pub mod check;
pub mod db;
pub mod discover;
pub mod files;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzz;
pub mod header;
pub mod ipc;
pub mod process;
pub mod reader;
pub mod sandbox;
pub mod sql;

#[cfg(test)]
mod it;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditConfig, AuditLevel, Connector, ConnectorError, Engine, EventSink, FailureCode,
    FindingSink, ScanJob, TargetHealth,
};

pub use process::READER_MODE;
#[cfg(any(test, feature = "test-support"))]
pub use process::{set_reader_credentials_for_tests, set_reader_executable_for_tests};
pub use sql::statement_allow_list;

/// The reader mode's entry point: the agent binary calls it first in
/// `main` when its first argument is [`READER_MODE`], before any
/// configuration, state or identity file is read, and exits with its
/// status.
#[must_use]
pub fn reader_main() -> i32 {
    reader::main()
}

/// The SQLite connector: one per agent, serving every `sqlite` target.
#[derive(Debug, Default)]
pub struct SqliteConnector {
    targets: Mutex<HashMap<String, Arc<check::TargetState>>>,
}

impl SqliteConnector {
    /// A connector with no target state yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self, id: &str) -> Arc<check::TargetState> {
        let mut map = self
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(map.entry(id.to_owned()).or_default())
    }
}

fn unsupported() -> ConnectorError {
    ConnectorError::Target {
        engine: Engine::Sqlite,
        code: FailureCode::Unsupported,
        engine_code: None,
    }
}

#[async_trait]
impl Connector for SqliteConnector {
    fn engine(&self) -> Engine {
        Engine::Sqlite
    }

    async fn check(&self, target: &TargetConfig) -> TargetHealth {
        let Some(settings) = target.sqlite_settings() else {
            return TargetHealth {
                reachable: false,
                audit_level: AuditLevel::None,
                failure: Some(FailureCode::Internal),
                detail: None,
                notes: Vec::new(),
            };
        };
        check::check(&target.id, settings, self.state(&target.id)).await
    }

    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<(), ConnectorError> {
        let Some(target) = job.target() else {
            return Err(unsupported());
        };
        let Some(settings) = target.sqlite_settings() else {
            return Err(unsupported());
        };
        discover::discover(job, sink, target, settings, &self.state(&target.id)).await
    }

    /// SQLite has no access log: Audit is `none` by nature (decision 7).
    async fn audit_stream(&self, _: &AuditConfig, _: &EventSink) -> Result<(), ConnectorError> {
        Err(unsupported())
    }
}
