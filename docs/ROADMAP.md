# MVP Roadmap – DataBastion

The MVP (v0.1.0) is split into phases. Each phase is divided into independent **workstreams**, assignable to different agents working in parallel (see [AGENTS.md](../AGENTS.md#multi-agent-work)).

Legend: `[ ]` to do · `[~]` in progress · `[x]` done. Update this file at the end of every task.

**Current phase: 0**

---

## Phase 0 – Foundations
*Objective: a repository where several agents can work without stepping on each other's toes.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P0-A Repository & CI | `docs-keeper` | [~] Target directory tree (`console/`, `agent/` done; `shared/` comes with P0-B, `dev/` with P0-C) · [x] Protected `main` + `dev` branches ([RELEASE.md](../RELEASE.md)) · [x] GitHub Actions CI: docs, gitleaks, console, agent, protocol (enabled depending on whether the component exists) · [x] DCO check + PR title format · [x] Release workflow (`release-it` on merge to `main`, `[skip-release]`) · [x] Signed multi-arch images workflow on `-*` tags and release · [x] Version bump script · [x] Pre-commit hooks verified · [x] Dependabot · [ ] `RELEASE_TOKEN` secret configured · [x] Add npm/cargo to Dependabot once `console/` and `agent/` exist · [x] `timeout-minutes` on every CI job · [x] Agent CI: minimal build (`--no-default-features`) + `cargo-deny` (bans, licenses, sources) · [x] Console CI: `pnpm typecheck` · [x] Gitleaks rules for agent secrets and enrollment tokens (`.gitleaks.toml`) |
| P0-B Protocol | `agent-engineer` + `security-reviewer` review | [~] `shared/protocol/openapi.yaml` v1 from [09-agent-protocol.md](09-agent-protocol.md) (in review) · [~] Valid / invalid JSON fixtures (in review) · [ ] TS and Rust type generation · [ ] Keep the agent guards in step with new dependencies: `agent/deny.toml` bans (OpenSSL / native-tls, HTTP server frameworks, Prometheus exporter) and `crates/agent/tests/architecture.rs` |
| P0-C Dev env. | `agent-engineer` | [ ] `dev/docker-compose.yml`: PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog; Mailpit (SMTP alert testing, P3-C), Prometheus (scraping the console `/metrics`, [ADR-0004](adr/0004-observability-via-console.md)), Grafana (base dashboard) · [ ] Root `Makefile`: `make dev` starts the dev environment, console and agent · [ ] Seeded fake PII datasets (Faker, FR + intl) with ground truth (`dev/ground-truth.json`) |
| P0-D Skeletons | `console-engineer` / `agent-engineer` | [x] Next.js + Drizzle + pg-boss that starts · [x] Cargo workspace that compiles, `cargo clippy -D warnings` green |

**Exit criterion**: `make dev` starts everything; CI green; protocol contract validated.

## Phase 1 – Console foundation & agent core
*Objective: an agent enrolls and shows up as "online" in the console.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P1-A Console | `console-engineer` | [ ] DB schema (users, agents, targets, jobs, findings, events, incidents, policies, audit_log) · [ ] Local auth (argon2id) · [ ] Console audit log · [ ] Enrollment tokens · [ ] Agent API: `/enroll`, `/heartbeat`, `/jobs` (long-poll) · [ ] Agents & Targets page |
| P1-B Agent core | `agent-engineer` | [ ] `agent.yaml` config · [ ] Enrollment + `0600` identity storage · [ ] Uplink (retry, backoff, `batch_id`) · [ ] Bounded disk spool · [ ] Heartbeat + metrics · [ ] Local engine detection (ADR-0006) |
| P1-C Review | `security-reviewer` | [ ] Review of enrollment / secret storage / API input validation |

**Exit criterion**: end-to-end enrollment in containers; revocation effective in < 60 s.

## Phase 2 – SQL Discovery
*Objective: first real findings on PostgreSQL and MySQL/MariaDB.* → **v0.1.0-alpha**

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P2-A Classifiers | `agent-engineer` | [ ] `classifiers` crate: regex + validators (Luhn, IBAN mod 97, NIR key), secrets, column-name hints · [ ] Masking + HMAC · [ ] Property tests on masking |
| P2-B PG connector | `agent-engineer` | [ ] Schema introspection · [ ] Bounded sampling (`TABLESAMPLE`, `statement_timeout`) · [ ] `check()` + audit level |
| P2-C MySQL connector | `agent-engineer` (another instance) | [ ] Same as PG for MySQL / MariaDB |
| P2-D Console findings | `console-engineer` | [ ] `/findings` ingestion (strict validation) · [ ] Scan launching · [ ] Findings view per target / classifier · [ ] False positive marking |
| P2-E Invariant test | `security-reviewer` | [ ] Automated test: no PII from `dev/ground-truth.json` in clear text in the console database |

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
