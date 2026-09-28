# CONTEXT.md – DataBastion

Project context for every contributor, human or AI agent. Read it **before** any task.

## In one sentence
DataBastion is an open-source DLP (Apache 2.0) that finds sensitive data in PostgreSQL, MySQL/MariaDB, MongoDB and OpenLDAP (*Discovery*) and detects abnormal extractions of it (*Audit*), using agents that never accept an inbound connection.

## Where the project stands
- **Current phase**: 2 – SQL Discovery (see [docs/ROADMAP.md](docs/ROADMAP.md)). Phase 0 – Foundations is done. Phase 1 – Console foundation & agent core is signed off: exit criterion met (#22), console P1-D follow-ups merged (#27), end-of-phase security review at 9cc314a with no Critical or High finding. Its non-blocking follow-ups are carried over (see below).
- Agent core done (P1-B, #16, #20): `agent.yaml` configuration, enrollment with `0600` identity storage, rustls uplink with retry / backoff, heartbeat and jobs loops (interval clamp, at most 16 jobs per poll, per-job parsing), agent-generated secret rotation ([ADR-0008](docs/adr/0008-agent-generated-secret-rotation.md), refined by [ADR-0010](docs/adr/0010-rotation-conflict-window.md) and [ADR-0011](docs/adr/0011-late-rotation-retry.md)), bounded disk spool, per-item sanitization and name normalization skeleton ([ADR-0009](docs/adr/0009-name-normalization-and-item-sanitization.md)), local engine detection. Connectors are still stubs and HMAC fingerprints are not wired (P2-A). No Discovery or Audit logic yet.
- Protocol v1 contract merged (P0-B): `shared/protocol/openapi.yaml` + fixtures is the source of truth ([docs/09-agent-protocol.md](docs/09-agent-protocol.md) is an overview). Types are generated on both sides (console: openapi-typescript + Ajv runtime validator; agent: typify), with drift tests. Both sides implement the enrollment, heartbeat, jobs and rotation parts of the contract (#16, #17, #21, #25).
- Dev environment merged (P0-C): `make dev` starts PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog, Mailpit, Prometheus and Grafana, with seeded fake PII and a ground truth ([dev/README.md](dev/README.md)). The console and the agent are not containerized in it yet and run on the host.
- Console backend part 1 merged (P1-A, #17: DB schema with separate owner / runtime database roles, local auth, audit log, enrollment tokens, agent API `/enroll`, `/heartbeat`, `/jobs`). Console part 2 merged (#21: `/rotate`, `/metrics`, Agents & Targets UI, console Dockerfile).
- End-to-end harness merged (#22: `e2e/`, `.github/workflows/e2e.yml`, agent Dockerfile): enrollment, `online` status, `/metrics` and revocation (88–111 ms measured, criterion < 60 s) in containers, with no secret in container logs, the console database dump or the proxy log. Target reachability is not asserted yet (stub connectors).
- Console P1-D follow-ups merged (#27): bounded `S0` argon2id cost, keyed and persisted known-good fingerprint, dedicated `/metrics` listener (`DATABASTION_METRICS_PORT`), digest-pinned console image, PostgreSQL in the Console CI job. Dependency advisory scanning runs in CI (`.github/workflows/advisories.yml`), outside the required checks.
- Carried over from phase 1 (in progress, non-blocking): console hardening (per-IP / per-username limit scoping, `DELETE` revoked on `security_events`, bounded `/enroll` argon2id pool, `pgboss` owner guard, deploy example digest pins; `fix/p1-d-console-hardening` and related console work) and agent rotation fixes (`fix/p1-d-agent-rotation`: `rotate_epoch`, `S0` fallback on `429` / `503`, `accept::rotate`, `TargetHealth` failure code). See ROADMAP P1-C and P1-D.
- Before the P2 PostgreSQL connector: the production grants of the agent's PostgreSQL role (ROADMAP P2-0) are decided in [ADR-0012](docs/adr/0012-postgresql-agent-grants.md) (#28).

## Invariants (non-negotiable)
| # | Invariant | Source |
|---|-----------|--------|
| I1 | Agents open no inbound port; only the agent initiates connections (HTTPS 443) | ADR-0001, ADR-0004 |
| I2 | No raw sensitive value leaves the agent: masked samples + HMAC only | ADR-0003 |
| I3 | Database credentials never leave the agent host | ADR-0003 |
| I4 | The agent only reads, with a dedicated least-privilege account | 05-security |
| I5 | No network scanning: declared targets + local detection only | ADR-0006 |
| I6 | The protocol is defined by `shared/protocol/openapi.yaml`; no hand-written protocol types | 03-STACK |
| I7 | Public repository = Apache 2.0 only; no Enterprise code here | ADR-0005 |

## Glossary
| Term | Definition |
|-------|-----------|
| **Console** | Control plane: Next.js UI (`web`) + `worker` + internal PostgreSQL |
| **Agent** | Rust binary deployed close to the databases; the console's only client |
| **Connector** | Engine-specific agent module (`connector-postgres`…) |
| **Target** | A database or directory instance monitored by an agent |
| **Enrollment** | Exchange of a single-use token for an agent identity |
| **Job** | Console order fetched by the agent via long-poll (e.g. `discovery.scan`) |
| **Classifier** | Detector for a data type (`pii.email`, `pii.iban`, `secret.aws_key`…) |
| **Finding** | Discovery result: a location contains a sensitive data type |
| **Access event** | Normalized Audit result: who read what, how much, with which signals |
| **Signal** | Exfiltration indicator: `signature.*`, `shape.*`, `volume.*` |
| **Policy** | Condition → action rule applied by the worker |
| **Incident** | What a policy creates, and what the user handles |
| **Audit level** | Full / Partial / Limited / None, depending on the engine (docs/08) |

## Documentation map
- Why / what: [docs/01-overview.md](docs/01-overview.md), [docs/04-mvp-scope.md](docs/04-mvp-scope.md)
- How: [docs/02-architecture.md](docs/02-architecture.md), [docs/03-tech-stack.md](docs/03-tech-stack.md), [docs/09-agent-protocol.md](docs/09-agent-protocol.md)
- Per-engine limits: [docs/08-engine-capabilities.md](docs/08-engine-capabilities.md)
- Security: [docs/05-security.md](docs/05-security.md)
- Settled decisions: [docs/adr/](docs/adr/README.md)
- Plan: [docs/ROADMAP.md](docs/ROADMAP.md)
