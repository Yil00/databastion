# ADR-0002: A single agent with per-engine connectors

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
The initial scope planned one agent per database type (SQL, MongoDB, OpenLDAP). Yet enrollment, uplink, spool, classifiers, and masking are identical for all of them. A single host often runs several engines.

## Decision
A single Rust binary `databastion-agent`, organized as a Cargo workspace:
`core`, `classifiers` (including masking), `connector-postgres`, `connector-mysql`, `connector-mongodb`, `connector-openldap`.
Connectors are enabled through Cargo *features*. The official image includes all of them; a minimal binary can be compiled.

Each connector implements a common trait (sketch):
```rust
trait Connector {
    fn engine(&self) -> Engine;
    async fn check(&self) -> TargetHealth;          // reachable? audit level?
    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<()>;
    async fn audit_stream(&self, cfg: &AuditConfig, sink: &EventSink) -> Result<()>;
}
```

## Consequences
- Security-critical code (masking, uplink) written **only once**.
- One agent per host, even with several engines.
- Connectors can be developed in parallel by different agents: clear boundary = the trait.

## Rejected alternatives
- **One binary per engine**: duplication, N enrollments per host.
- **Dynamic plugins (.so / WASM)**: premature for the MVP.
