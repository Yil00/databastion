# MVP Roadmap – DataBastion

The MVP (v0.1.0) is split into phases. Each phase is divided into independent **workstreams**, assignable to different agents working in parallel (see [AGENTS.md](../AGENTS.md#multi-agent-work)).

Legend: `[ ]` to do · `[~]` in progress · `[x]` done. Update this file at the end of every task.

Items prefixed with **Gate** come from a security review: they block the completion of the workstream they sit in, which cannot be checked off while a gate is open.

**Current phase: 0**

---

## Phase 0 – Foundations
*Objective: a repository where several agents can work without stepping on each other's toes.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P0-A Repository & CI | `docs-keeper` | [x] Target directory tree (`console/`, `agent/`, `shared/`; `dev/` is created by P0-C, which owns its content) · [x] Protected `main` + `dev` branches ([RELEASE.md](../RELEASE.md)) · [x] GitHub Actions CI: docs, gitleaks, console, agent, protocol (enabled depending on whether the component exists) · [x] DCO check + PR title format · [x] Release workflow (`release-it` on merge to `main`, `[skip-release]`) · [x] Signed multi-arch images workflow on `-*` tags and release · [x] Version bump script · [x] Pre-commit hooks verified · [x] Dependabot · [ ] `RELEASE_TOKEN` secret configured · [x] Add npm/cargo to Dependabot once `console/` and `agent/` exist · [x] `timeout-minutes` on every CI job · [x] Agent CI: minimal build (`--no-default-features`) + `cargo-deny` (bans, licenses, sources) · [x] Console CI: `pnpm typecheck` · [x] Gitleaks rules for agent secrets and enrollment tokens (`.gitleaks.toml`) |
| P0-B Protocol | `agent-engineer` + `security-reviewer` review | [x] `shared/protocol/openapi.yaml` v1 (source of truth; overview in [09-agent-protocol.md](09-agent-protocol.md)) · [x] Valid / invalid JSON fixtures · [x] TS and Rust type generation · [ ] Keep the agent guards in step with new dependencies: `agent/deny.toml` bans (OpenSSL / native-tls, HTTP server frameworks, Prometheus exporter) and `crates/agent/tests/architecture.rs` |
| P0-C Dev env. | `agent-engineer` | [ ] `dev/docker-compose.yml`: PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog; Mailpit (SMTP alert testing, P3-C), Prometheus (scraping the console `/metrics`, [ADR-0004](adr/0004-observability-via-console.md)), Grafana (base dashboard) · [ ] Root `Makefile`: `make dev` starts the dev environment, console and agent · [ ] Seeded fake PII datasets (Faker, FR + intl) with ground truth (`dev/ground-truth.json`) · [ ] Ground truth includes value-bearing names: MongoDB dynamic keys, LDAP `ou=` containers named after persons, table names containing values (security review M2, [ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)) |
| P0-D Skeletons | `console-engineer` / `agent-engineer` | [x] Next.js + Drizzle + pg-boss that starts · [x] Cargo workspace that compiles, `cargo clippy -D warnings` green |

**Exit criterion**: `make dev` starts everything; CI green; protocol contract validated.

## Phase 1 – Console foundation & agent core
*Objective: an agent enrolls and shows up as "online" in the console.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P1-A Console | `console-engineer` | [ ] DB schema (users, agents, targets, jobs, findings, events, incidents, policies, audit_log) · [ ] Local auth (argon2id) · [ ] Console audit log · [ ] Enrollment tokens · [ ] Agent API: `/enroll`, `/heartbeat`, `/jobs` (long-poll) · [ ] Agents & Targets page · [ ] Agent API validation: Ajv 2020 with `ajv-formats`, `strict: true`, `strictRequired: false`, `x-databastion-*` keywords declared ([shared/protocol/README.md](../shared/protocol/README.md)) · [ ] Console-side cross-field checks listed in `openapi.yaml` · [ ] Agent-integrity alert on rejected batches, `batch_conflict` and `rotation_conflict` · [ ] Escaping of `db_user` / `application` on display and export · [ ] Low-entropy secret check on `/rotate` ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)) · [ ] **Gate** (protocol types review): every agent API handler calls `checkSemantics` after `validateSchema`; `ok: true` from `validateSchema` never counts as full contract compliance |
| P1-B Agent core | `agent-engineer` | [ ] `agent.yaml` config · [ ] Enrollment + `0600` identity storage · [ ] Uplink (retry, backoff, `batch_id`) · [ ] Bounded disk spool · [ ] Heartbeat + metrics · [ ] Local engine detection (ADR-0006) · [ ] Atomic pending-secret storage for rotation ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)) · [ ] Per-item validation and sanitization before spooling, 1 MiB batch cap ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)) · [ ] **Gate** (protocol types review): clamp `heartbeat_interval_s` received from the console to [10, 300] and reject values ≤ 0 (no hot loop, no silent agent) · [ ] **Gate** (protocol types review): cap the jobs handled per poll (≤ 16) and parse jobs individually, reporting an unparseable job as `failed` instead of dropping the whole list (forward compatibility) |
| P1-C Review | `security-reviewer` | [ ] Review of enrollment / secret storage / API input validation |

**Exit criterion**: end-to-end enrollment in containers; revocation effective in < 60 s.

## Phase 2 – SQL Discovery
*Objective: first real findings on PostgreSQL and MySQL/MariaDB.* → **v0.1.0-alpha**

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P2-A Classifiers | `agent-engineer` | [ ] `classifiers` crate: regex + validators (Luhn, IBAN mod 97, NIR key), secrets, column-name hints · [ ] Masking + HMAC · [ ] Property tests on masking · [ ] Name normalizer (indices, dynamic keys, classifier-matching segments, LDAP DNs) + property tests ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)) · [ ] **Gate** (protocol types review): the name normalizer enforces the Identifier `not` rule (card / phone numbers used as names), with property tests (I2) · [ ] **Gate** (protocol types review): `DiscoveryScanParams` / `AuditConfigureParams` are mapped into internal `ScanJob` / `AuditConfig` only via `TryFrom` enforcing the contract ranges (`sample_rows` 1..10000, `max_duration_s`, `statement_timeout_ms` 100..600000; `0` means unlimited on PostgreSQL / MySQL, I4), then clamped to the local hard limits from `agent.yaml`; empty filter lists are rejected. Owned here if the internal types live in a shared crate, otherwise by P2-B / P2-C |
| P2-B PG connector | `agent-engineer` | [ ] Schema introspection · [ ] Bounded sampling (`TABLESAMPLE`, `statement_timeout`) · [ ] `check()` + audit level · [ ] **Gate** (protocol types review): job parameters reach the connector only through the `TryFrom` mapping + `agent.yaml` clamp (see P2-A); `statement_timeout` is never set to `0` |
| P2-C MySQL connector | `agent-engineer` (another instance) | [ ] Same as PG for MySQL / MariaDB, including the job-parameter **Gate** (statement timeout never `0`) |
| P2-D Console findings | `console-engineer` | [ ] `/findings` ingestion (strict validation, cross-field checks, rejected-batch alerts) · [ ] **Gate** (protocol types review): `/findings` calls `checkSemantics` after `validateSchema`; `ok: true` never counts as full contract compliance · [ ] Scan launching · [ ] Findings view per target / classifier · [ ] False positive marking |
| P2-E Invariant test | `security-reviewer` | [ ] Automated test: no PII from `dev/ground-truth.json` in clear text in the console database, including value-bearing object and field names |

**Exit criterion**: recall ≥ 90 %, precision ≥ 85 % on the ground truth; invariant test green.

## Phase 3 – Policies, incidents, alerting
| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P3-A Policy engine | `console-engineer` | [ ] Condition → action model · [ ] Execution in the worker · [ ] Exceptions |
| P3-B Incidents | `console-engineer` | [ ] Lifecycle (open, acknowledged, resolved, false positive) · [ ] UI |
| P3-C Alerting | `console-engineer` | [ ] SMTP · [ ] HMAC-signed webhook · [ ] "Silent agent" alert |

## Phase 4 – SQL Audit
| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P4-A PG Audit | `agent-engineer` | [ ] pgaudit reading (csvlog / jsonlog) · [ ] `pg_stat_statements` degraded mode · [ ] `pg_dump`, `COPY` signatures |
| P4-B MySQL/MariaDB Audit | `agent-engineer` | [ ] `server_audit` · [ ] Percona `audit_log` · [ ] `performance_schema` · [ ] `mysqldump`, `INTO OUTFILE` signatures |
| P4-C Correlation | `console-engineer` | [ ] `/events` ingestion · [ ] Volume × sensitivity score · [ ] Per-principal baselines |

**Exit criterion**: `pg_dump` and `mysqldump` in `dev/` → incident in < 2 min.

## Phase 5 – MongoDB
[ ] Discovery (document sampling, nested fields) · [ ] Enterprise/Percona audit (`auditLog`) · [ ] Community audit (JSON logs + profiler, level shown as "Limited") · [ ] `mongodump` / `mongoexport` detection

## Phase 6 – OpenLDAP
[ ] Discovery (sensitive attributes: `userPassword`, `mail`, `telephoneNumber`, custom attributes) · [ ] Audit via `cn=accesslog` · [ ] Bulk search detection

## Phase 7 – Hardening & v0.1.0 release
[ ] Signed distroless multi-arch images (cosign) · [ ] `.deb` package + systemd unit · [ ] "Installation < 15 min" test · [ ] Load / database impact tests · [ ] 72 h stability test · [ ] User documentation · [ ] Published security policy

---

## After the MVP
| Phase | Contents |
|-------|---------|
| 1.5 | CAS connector |
| 2 | Prevention mode (proxy), Helm, mTLS, gRPC, OTLP export, large-scale event storage |
| 3+ | Anomaly detection ML, other OSes |
