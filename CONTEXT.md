# CONTEXT.md – DataBastion

Project context for every contributor, human or AI agent. Read it **before** any task.

## In one sentence
DataBastion is an open-source DLP (Apache 2.0) that finds sensitive data in PostgreSQL, MySQL/MariaDB, MongoDB and OpenLDAP (*Discovery*) and detects abnormal extractions of it (*Audit*), using agents that never accept an inbound connection.

## Where the project stands
- **Current phase**: 2 – SQL Discovery (see [docs/ROADMAP.md](docs/ROADMAP.md)). Phase 0 – Foundations is done. Phase 1 – Console foundation & agent core is signed off: exit criterion met (#22), console P1-D follow-ups merged (#27), end-of-phase security review at 9cc314a with no Critical or High finding. Its follow-ups have all landed (see below). Phase 3 console work (policies, incidents, alerting) is merged ahead of the phase 2 exit.
- Agent core done (P1-B, #16, #20): `agent.yaml` configuration, enrollment with `0600` identity storage, rustls uplink with retry / backoff, heartbeat and jobs loops (interval clamp, at most 16 jobs per poll, per-job parsing), agent-generated secret rotation ([ADR-0008](docs/adr/0008-agent-generated-secret-rotation.md), refined by [ADR-0010](docs/adr/0010-rotation-conflict-window.md) and [ADR-0011](docs/adr/0011-late-rotation-retry.md)), bounded disk spool, per-item sanitization and name normalization skeleton ([ADR-0009](docs/adr/0009-name-normalization-and-item-sanitization.md)), local engine detection. The PostgreSQL connector is implemented (#47); the MySQL / MariaDB connector is in review; the MongoDB and OpenLDAP connectors are still stubs.
- Protocol v1 contract merged (P0-B): `shared/protocol/openapi.yaml` + fixtures is the source of truth ([docs/09-agent-protocol.md](docs/09-agent-protocol.md) is an overview). Types are generated on both sides (console: openapi-typescript + Ajv runtime validator; agent: typify), with drift tests. Both sides implement the enrollment, heartbeat, jobs and rotation parts of the contract (#16, #17, #21, #25).
- Dev environment merged (P0-C): `make dev` starts PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog, Mailpit, Prometheus and Grafana, with seeded fake PII and a ground truth ([dev/README.md](dev/README.md)). The console and the agent are not containerized in it yet and run on the host.
- Console backend part 1 merged (P1-A, #17: DB schema with separate owner / runtime database roles, local auth, audit log, enrollment tokens, agent API `/enroll`, `/heartbeat`, `/jobs`). Console part 2 merged (#21: `/rotate`, `/metrics`, Agents & Targets UI, console Dockerfile).
- End-to-end harness merged (#22: `e2e/`, `.github/workflows/e2e.yml`, agent Dockerfile): enrollment, `online` status, `/metrics` and revocation (88–111 ms measured, criterion < 60 s) in containers, with no secret in container logs, the console database dump or the proxy log. Since #47 the harness also asserts that the PostgreSQL target is `reachable`.
- Console P1-D follow-ups merged (#27): bounded `S0` argon2id cost, keyed and persisted known-good fingerprint, dedicated `/metrics` listener (`DATABASTION_METRICS_PORT`), digest-pinned console image, PostgreSQL in the Console CI job. Dependency advisory scanning runs in CI (`.github/workflows/advisories.yml`), outside the required checks.
- Phase 1 review follow-ups merged: agent rotation fixes (#30: `rotate_epoch` bumped on `/rotate` answers, `/rotate` reply checked against the contract, `TargetHealth` failure code reported as `last_error`; the `S0` fallback on `429` / `503` was withdrawn, `S1` stays first) and console hardening (#32: argon2-backed and cheap per-IP agent failure counters with known-good exemptions, login limits per (username, IP) with a slow-down instead of a lock-out and device cookies, bounded `/enroll` pool, insert-only `security_events`, `pgboss` owner guard migration, deploy example digest pins). Console Low follow-ups merged in #37: `DATABASTION_ENCRYPTION_KEY` is required in production (web and worker refuse to start without it unless `DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1`), growing login slow-down for unknown IPs, device-cookie failures counted globally, `pgboss` owner pre-flight on every `migrate`. The last P1-D follow-up (values split across dots in names) landed with the P2-A core wiring (#39).
- PostgreSQL agent grants decided in [ADR-0012](docs/adr/0012-postgresql-agent-grants.md) (#28, minimal variant by default); the dev and E2E roles use it (#31). Its connector obligations and integration probes were met by the PostgreSQL connector (#47).
- Phase 2 merged so far: frozen classifier ids and the `classifiers` crate (detectors, masking with at most 4 digits kept and a keyed per-column sample order, domain-separated HMAC fingerprints, property tests; #34); an independent held-out corpus for the exit criterion (#35, `dev/holdout/`); console findings ingestion with masked samples encrypted at rest, scan launching, findings view and admin-only false positives (#36, bounds and hardening #37); the classifier registry (`shared/protocol/classifiers.json` + lock) and the console-side checks, replay rule, `501` handling and per-job cap in the contract (#38); the P2-A agent core wiring (#39: HMAC fingerprints including `db_user` fingerprints, classifier-based name normalization with a first-name heuristic, job-parameter gates via `TryFrom` then the `agent.yaml` clamp, per-target `phone_region`, `limits.min_audit_poll_interval_s`, a scan worker stopped on deadline, revocation or shutdown). `Error.code` values are frozen for v1 ([ADR-0013](docs/adr/0013-frozen-error-codes.md), #40).
- Console classifier registry checks merged (P2-D, #41): scan jobs and findings must carry a registered `classifiers_version` and registered classifier ids.
- Agent follow-ups merged (#42): per-endpoint `501` parking on `/findings` and `/events` (running scans back-pressured while `/findings` is parked), classifier-set refusal (`unsupported`), the 50 000 per-job findings cap, scan windows counted from job reception, and the Low findings of the #39 review (name normalization bounds, `%uXXXX` escapes, CJK numerals).
- Phase 2 status: the PostgreSQL Discovery connector and `check()` are merged (P2-B, #47; [ADR-0015](docs/adr/0015-postgresql-connector-decisions.md): `verify_full` TLS by default, cleartext / MD5 / weak SCRAM refused without TLS, RLS policy allow-list, audit level Limited or None with Full withheld until P4-A, 32 MiB per-relation byte budget with server-side cancel). Value-based classification meets the classifier part of the exit criterion on the held-out corpus, and the held-out gate is blocking in CI (P2-F, #48; [ADR-0016](docs/adr/0016-classifier-semantics-2026-09-1.md)). In review, not merged: the MySQL / MariaDB connector (P2-C; grants and decisions in [ADR-0018](docs/adr/0018-mysql-mariadb-grants-and-connector.md)). The I2 invariant test is merged (P2-E, #50, E2E workflow). The phase 2 exit criterion is therefore not met yet: only P2-C remains.
- Phase 3 status: console work done. Policy engine and incident lifecycle (P3-A, P3-B, #45; [ADR-0014](docs/adr/0014-policy-and-incident-model.md), refined by [ADR-0019](docs/adr/0019-incident-reopen-cutoff.md)); e-mail and HMAC-signed webhook alerting, silent-agent and agent-integrity alerts (P3-C, #49; [ADR-0017](docs/adr/0017-alerting.md)). Remaining: the `audit.configure` confirmation and warning of P3-A, which depends on phase 4.

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
