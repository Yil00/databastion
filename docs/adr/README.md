# Architecture Decision Records

Every structural decision is recorded here. **An agent (human or AI) does not challenge an accepted ADR as part of a task**: it proposes a new ADR that supersedes it (`Status: Superseded by ADR-XXXX`).

An accepted ADR is not edited. A new ADR either supersedes it, or refines it (a `Refines: ADR-XXXX (which stays Accepted)` line under its date) when it only makes a point precise or adds to it.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-transport-https-outbound.md) | Outbound HTTPS transport with long-poll | Accepted |
| [0002](0002-single-agent-connectors.md) | A single agent with per-engine connectors | Accepted |
| [0003](0003-data-minimization-at-source.md) | No raw sensitive value leaves the agent | Accepted |
| [0004](0004-observability-via-console.md) | Agent metrics reported through the console | Accepted |
| [0005](0005-open-core-license.md) | Apache 2.0, open-core model | Accepted |
| [0006](0006-target-discovery.md) | Declared targets + local detection, no network scanning | Accepted |
| [0007](0007-mask-access-events.md) | Audit access events are masked in the agent (extends 0003) | Accepted |
| [0008](0008-agent-generated-secret-rotation.md) | Agent-generated secret rotation with conflict lock | Accepted |
| [0009](0009-name-normalization-and-item-sanitization.md) | Name normalization and per-item sanitization before the uplink | Accepted |
| [0010](0010-rotation-conflict-window.md) | Rotation conflict window and "just promoted" definition (refines 0008) | Accepted |
| [0011](0011-late-rotation-retry.md) | Late rotation retry with the previous secret (refines 0010) | Accepted |
| [0012](0012-postgresql-agent-grants.md) | Grant set of the agent's PostgreSQL role (Discovery, Audit) | Accepted |
| [0013](0013-frozen-error-codes.md) | Error codes are frozen within a protocol major version | Accepted |
| [0014](0014-policy-and-incident-model.md) | Policy and incident model: per-source conditions, durable work markers, dedup (resolved means remediated) and false-positive alignment | Accepted |
| [0015](0015-postgresql-connector-decisions.md) | PostgreSQL connector: TLS policy, authentication refusals, RLS policy allow-list, audit level before P4-A, partition and byte bounds (refines 0012) | Accepted |
| [0016](0016-classifier-semantics-2026-09-1.md) | Classifier semantics for set 2026.09.1: value-based decision, personal e-mail, placeholders, age reference year, NFC, held-out evaluation process | Accepted |
| [0017](0017-alerting.md) | Alerting: webhook signature, channel secrets, outbox delivery, skipped slugs, system alerts, SMTP client, SSRF model, volume bounds | Accepted |
| [0018](0018-mysql-mariadb-grants-and-connector.md) | MySQL / MariaDB agent grants (minimal variant) and connector decisions: engine allow-list, own protocol client, authentication and TLS policy, audit level before P4-B | Accepted |
| [0019](0019-incident-reopen-cutoff.md) | "Seen after the resolution" decided on the scan job's first delivery (refines 0014) | Accepted |
| [0020](0020-mysql-mariadb-connector-as-merged.md) | MySQL / MariaDB connector as merged: row estimates read after the engine check, `extended_grants` opt-in, parser property tests, dev accounts on the minimal variant (refines 0018) | Accepted |
| [0021](0021-access-event-correlation.md) | Access-event correlation: insert-only event storage, owner-defined purge with a 7-day floor, volume × sensitivity score, capped EWMA baselines, per-hour dedup with coarse unknown principals, per-target hourly cap with severe-event bypass, fair draining and back-pressure (refines 0014) | Accepted |
| [0022](0022-protocol-capability-negotiation.md) | Protocol capability negotiation: optional fields added after 0.1.0 sent only once announced (`HeartbeatResponse.accepts` for request fields, `HeartbeatRequest.accepts` for response and job fields); form-only registries need none (refines 0013) | Accepted |
| [0023](0023-mysql-mariadb-audit-sources-and-levels.md) | MySQL / MariaDB Audit sources and levels: `server_audit`, `audit_log` JSON and `performance_schema`, never Full, file sources Partial only with a record in the last 24 h, `performance_schema` grant only while Audit runs, no reliance on server password masks, export signals, own-account rule, no DDL / DCL names from text (refines 0018 and 0020) | Accepted |
| [0024](0024-shared-rate-limits.md) | Console rate limits shared through PostgreSQL: fixed windows in `rate_limit_counters` on the database clock, HMAC-keyed rows, in-memory pre-check that only refuses earlier, fail closed for authentication and user actions, per-process fallback for ingest, budgets and late rotate retries, worker pruning (refines 0017 and 0021) | Accepted |

Template: copy [template.md](template.md).
