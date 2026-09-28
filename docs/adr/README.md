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

Template: copy [template.md](template.md).
