# Architecture Decision Records

Every structural decision is recorded here. **An agent (human or AI) does not challenge an accepted ADR as part of a task**: it proposes a new ADR that supersedes it (`Status: Superseded by ADR-XXXX`).

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

Template: copy [template.md](template.md).
