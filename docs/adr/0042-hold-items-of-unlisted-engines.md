# ADR-0042: Engine capability tokens: items of an unlisted engine are held, not stripped

- **Status**: Accepted (2026-10-04; the maintainer delegated the phase 8 technical decisions; subject to the P8-C security review of PR #137)
- **Date**: 2026-10-04
- **Refines**: [ADR-0022](0022-protocol-capability-negotiation.md) decision 9 (which stays Accepted), for the engine values gated by [ADR-0039](0039-engine-scope-expansion.md) decision 8 and [ADR-0041](0041-cas-connector.md) decision 12
- **Context references**: ROADMAP P8-C, PR #137 (`feat/p8-c-protocol-cas`, commit c14c160); `agent/crates/core/src/capabilities.rs` (`engine_token`, `connector_token`, `audit_source_token`, `withhold_unaccepted_engines`, `enroll_connectors`), `agent/crates/core/src/uplink.rs` (`ResultBatch::held_back`, `ResultBatch::stripped`, `UplinkError::ItemsRejected::unknown_value`), `agent/crates/core/src/spool.rs` (`front_sendable`), `agent/crates/core/src/runtime.rs` (`resend_stripped`, heartbeat building); [docs/09-agent-protocol.md](../09-agent-protocol.md#compatible-changes-and-capability-negotiation)

## Context
ADR-0022 decision 9 says what the agent does when a console rejects a gated **optional field**: it clears the capabilities and resends the items with the field stripped, because an older console accepts them without it.

ADR-0039 decision 8 gates something else: new **values** of the closed enums `Engine`, `Connector` and `AuditSource`, the first being `cas` and `cas_audit_log` under the token `engine.cas` (ADR-0041 decision 12). These enums have no fallback value. A console built before `cas` rejects any body naming it, and the value cannot be stripped: a finding without `Location.engine`, or an event without `source`, is not a valid item, and replacing the value would misreport the target. ADR-0022 decision 4 (send the fallback `other`) does not apply either.

Dropping such items would lose data during the very situations negotiation exists for: a rolling upgrade, a rolled-back console, or replicas that do not all list the token yet (ADR-0022 decision 8).

## Decision
1. **Heartbeats and `/enroll` leave out what cannot be stripped.** Until the console's latest heartbeat response lists an engine's token, a heartbeat leaves out the connectors, targets and detected targets of that engine, and drops the `audit_source` of a kept target when that source is gated. The agent logs the targets left out as a too-old console, once per change of their count. `/enroll` precedes every heartbeat response, so it lists only the connectors of protocol 0.1.0; the others appear in the first heartbeat after a response that lists their token. The engines of protocol 0.1.0 have no token and are never left out. The token functions are exhaustive matches, so a new contract engine does not compile until it is given its token.
2. **Result batches are held, not sent.** A findings or events batch whose items carry a gated value (`Location.engine` for a finding, `AccessEvent.source` for an event, every source belonging to one engine) stays in the spool while any of its tokens is not listed. It is sent once a heartbeat response lists them all; a change of the listed set wakes the spool worker. The spool's existing bounds and eviction rules apply to held batches. Other batches are not blocked behind a held one: the worker takes the first sendable batch in FIFO order.
3. **A `400` `enum` on a gated-engine item keeps the item.** When `/findings` or `/events` answers `400` with item pointers, the agent records the items pointed at with the keyword `enum`. If the batch carries a gated engine value, the agent:
   - clears the capabilities, as for an unknown field (ADR-0022 decision 9);
   - keeps every rejected item that carries a gated engine value and was pointed at with `enum`, under a new `batch_id`; with the capabilities cleared, the new batch is held (decision 2) until a heartbeat response lists the token again;
   - drops the other rejected items by the ordinary rule (a `0.1.0`-engine item rejected with `enum`, e.g. an unregistered classifier, is dropped; so is any item rejected for another keyword).

   Each such replacement is counted with the stripped batches (`gated_fields_stripped_total`).
4. **Bound.** While replicas disagree, the agent sends gated items only after a response listing the token, and the first rejection clears the list. So there is at most one rejected request carrying gated values per heartbeat interval (a heartbeat or a result batch). The console records each rejected batch as an agent-integrity event (`batch_rejected`), so a misconfigured rollout is visible.

## Consequences
- Rolling upgrades, console rollbacks and mixed replicas lose no item of a new engine: the items wait in the spool instead.
- Every new engine (Microsoft SQL Server, Redis, Valkey, SQLite, Firebird) reuses this mechanism with its own `engine.<value>` token; no further ADR is needed for the pattern, only the token.
- A kept item may be sent again under a new `batch_id` after a console already stored it (lost `202`), as with stripped batches (docs/09).
- Deciding whether a batch is held requires reading it from the spool. Only batches of gated engines are held, and the console sends jobs only for targets it was told about, so this is rare.

### Residual risks
- **Spool fill while a console is older.** Held batches accumulate for as long as the console does not list the token (an agent with a CAS target attached to an old console). They count against `spool.max_bytes` and `spool.max_batches`; when the spool is full, the oldest batch of its class is evicted and counted (`dropped_batches`, `dropped_items`), and held batches, usually the oldest, go first. The agent warns about withheld targets once per change of their count; there is no separate warning for held batches beyond the spool metrics.
- **An item rejected with `enum` on another field.** Decision 3 keeps a gated-engine item pointed at with `enum` whatever the pointer's field. If a console that lists the token still rejects it with `enum` (for example a classifier that console does not know), the item cycles at most once per heartbeat interval, each time an agent-integrity event, until the spool evicts it. Restricting the kept items to pointers on `location/engine` and `source` would remove this; it is left to the P8-C security review.

## Rejected alternatives
- **Strip the value or send a placeholder engine**: not valid against the contract, and a placeholder would attribute a CAS finding to another engine.
- **Drop the items as rejected**: loses data in every rolling upgrade and rollback, which ADR-0022 decision 9 already refused for optional fields.
- **Hold the whole spool behind a held batch**: one unlisted engine would stop every other engine's findings and events.
- **Split the gated items into their own batch at the first rejection only**: the agent already avoids sending them before the token is listed; holding at the source is simpler and costs no rejected request in the common case.
