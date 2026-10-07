//! The `cas:` block of a target in `agent.yaml` (ADR-0041 decision 3).
//!
//! The block belongs to the core's target schema (`targets[].cas`,
//! `databastion_core::config::cas`): the core validates it and resolves its
//! paths when the configuration is loaded or reloaded, and refuses `host`,
//! `port`, `socket`, `account` and `secret` for `engine: cas`. This module
//! re-exports those types under the names this crate uses; the connector
//! reads them through `TargetConfig::cas_settings`.

pub use databastion_core::config::cas::{
    AuditLogSettings, CasConfigError as ConfigError, CasSettings, ClientAddrMode,
    MAX_CLEAR_PRINCIPALS, MAX_PRINCIPAL_BYTES, RawAuditLog, RawCasSettings, RawServiceRegistry,
    ResolvedPath, UtcOffset, parse_timezone,
};
