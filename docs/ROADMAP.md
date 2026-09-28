# MVP Roadmap – DataBastion

The MVP (v0.1.0) is split into phases. Each phase is divided into independent **workstreams**, assignable to different agents working in parallel (see [AGENTS.md](../AGENTS.md#multi-agent-work)).

Legend: `[ ]` to do · `[~]` in progress · `[x]` done. Update this file at the end of every task.

Items prefixed with **Gate** come from a security review: they block the completion of the workstream they sit in, which cannot be checked off while a gate is open.

**Current phase: 1** (phase 0 closed)

---

## Phase 0 – Foundations
*Objective: a repository where several agents can work without stepping on each other's toes.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P0-A Repository & CI | `docs-keeper` | [x] Target directory tree (`console/`, `agent/`, `shared/`; `dev/` is created by P0-C, which owns its content) · [x] Protected `main` + `dev` branches ([RELEASE.md](../RELEASE.md)) · [x] GitHub Actions CI: docs, gitleaks, console, agent, protocol (enabled depending on whether the component exists) · [x] DCO check + PR title format · [x] Release workflow (`release-it` on merge to `main`, `[skip-release]`) · [x] Signed multi-arch images workflow on `-*` tags and release · [x] Version bump script · [x] Pre-commit hooks verified · [x] Dependabot · [ ] `RELEASE_TOKEN` secret configured · [x] Add npm/cargo to Dependabot once `console/` and `agent/` exist · [x] `timeout-minutes` on every CI job · [x] Agent CI: minimal build (`--no-default-features`) + `cargo-deny` (bans, licenses, sources) · [x] Console CI: `pnpm typecheck` · [x] Gitleaks rules for agent secrets and enrollment tokens (`.gitleaks.toml`) |
| P0-B Protocol | `agent-engineer` + `security-reviewer` review | [x] `shared/protocol/openapi.yaml` v1 (source of truth; overview in [09-agent-protocol.md](09-agent-protocol.md)) · [x] Valid / invalid JSON fixtures · [x] TS and Rust type generation · [ ] Keep the agent guards in step with new dependencies: `agent/deny.toml` bans (OpenSSL / native-tls, HTTP server frameworks, Prometheus exporter) and `crates/agent/tests/architecture.rs` |
| P0-C Dev env. | `agent-engineer` | [x] `dev/docker-compose.yml`: PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog; Mailpit (SMTP alert testing, P3-C), Prometheus (scraping the console `/metrics`, [ADR-0004](adr/0004-observability-via-console.md)), Grafana (base dashboard) · [x] Root `Makefile`: `make dev` starts the dev environment (databases, Mailpit, Prometheus, Grafana) and waits until healthy; the console and agent containers are not in `make dev` yet (end-to-end containers in P1, images in P7) · [x] Seeded fake PII datasets (Faker, FR + intl) with ground truth (`dev/ground-truth.json`) · [x] Ground truth includes value-bearing names: MongoDB dynamic keys, LDAP `ou=` containers named after persons, table names containing values (security review M2, [ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)) |
| P0-D Skeletons | `console-engineer` / `agent-engineer` | [x] Next.js + Drizzle + pg-boss that starts · [x] Cargo workspace that compiles, `cargo clippy -D warnings` green |

**Exit criterion**: `make dev` starts everything; CI green; protocol contract validated.

**Status: met** (#13, #14), with one nuance: `make dev` starts all databases and the observability stack; containerization of the console and the agent is tracked in P1 (end-to-end enrollment in containers) and P7 (images). CI is green, including the `dev-env` job on real containers (all smoke checks passed). The protocol contract is validated by fixtures and drift tests on both sides. Open phase 0 items that do not block the exit: `RELEASE_TOKEN` secret (P0-A, needed before the first release) and the agent dependency guards (P0-B, continuous).

`dev-env` workflow and required checks (recommendation, not applied): keep it out of the required checks for now. It is path-filtered (`dev/**`, `Makefile`, its own file), and a required check that does not run on a PR blocks that PR. Once the console and agent are containerized in `make dev` (P1 end to end), make it required, either without path filters or with an always-running job that reports success when `dev/` is untouched.

## Phase 1 – Console foundation & agent core
*Objective: an agent enrolls and shows up as "online" in the console.*

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P1-A Console | `console-engineer` | [x] DB schema (users, agents, targets, jobs, audit_log; findings/events/incidents/policies tables come with their phases) (#17) · [x] Local auth (argon2id) · [x] Console audit log · [x] Enrollment tokens · [x] Agent API: `/enroll`, `/heartbeat`, `/jobs` (long-poll) · [x] Agents & Targets page (#21) · [x] Agent API validation: Ajv 2020 with `ajv-formats`, `strict: true`, `strictRequired: false`, `x-databastion-*` keywords declared ([shared/protocol/README.md](../shared/protocol/README.md)) · [ ] Console-side cross-field checks listed in `openapi.yaml` · [ ] Agent-integrity alert on rejected batches, `batch_conflict` and `rotation_conflict` (#21 records `rotation_conflict` locks in a `security_events` placeholder table; alerts come with P3) · [ ] Escaping of `db_user` / `application` on display and export · [x] Low-entropy secret check on `/rotate` ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)) (#21) · [x] **Gate** (protocol types review): every agent API handler calls `checkSemantics` after `validateSchema`; `ok: true` from `validateSchema` never counts as full contract compliance · [x] **Gate** (protocol contract review, #13): the console validates every outgoing `JobList` against the schema before sending it (also P2-D for scan jobs) · [x] `/metrics` endpoint (#21) exposing `databastion_agent_*` and `databastion_agent_reported_*` ([ADR-0004](adr/0004-observability-via-console.md)); freeze the metric names used by the provisional Grafana dashboard in `dev/grafana/` (`databastion_agent_last_seen_seconds`, `databastion_agent_reported_spool_bytes`) and update the dashboard if they change · [x] `/rotate` (#21), following [ADR-0008](adr/0008-agent-generated-secret-rotation.md), [ADR-0010](adr/0010-rotation-conflict-window.md) and [ADR-0011](adr/0011-late-rotation-retry.md) · [x] Console Docker image (`console/Dockerfile`, #21) |
| P1-B Agent core | `agent-engineer` | [x] `agent.yaml` config (#16) · [x] Enrollment + `0600` identity storage (#16) · [x] Uplink (retry, backoff, `batch_id`) (#16) · [x] Bounded disk spool (#20) · [x] Heartbeat + metrics (#16; spool metrics #20) · [x] Local engine detection (ADR-0006) (#20) · [x] Atomic pending-secret storage for rotation ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)) (#16) · [x] Per-item validation and sanitization before spooling, 1 MiB batch cap ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)) (#20) · [x] **Gate** (protocol types review): clamp `heartbeat_interval_s` received from the console to [10, 300] and reject values ≤ 0 (no hot loop, no silent agent) · [x] **Gate** (protocol types review): cap the jobs handled per poll (≤ 16) and parse jobs individually, reporting an unparseable job as `failed` instead of dropping the whole list (forward compatibility) |
| P1-C Review | `security-reviewer` | [ ] Review of enrollment / secret storage / API input validation |
| P1-D Follow-ups | per item | [x] [ADR-0010](adr/0010-rotation-conflict-window.md) rotation conflict window (#18) · [x] Align the `POST /rotate` contract text in `shared/protocol/openapi.yaml` with ADR-0010 (#19) · [x] [ADR-0011](adr/0011-late-rotation-retry.md) late rotation retry with `S0` · [~] Contract wording: `409` "authenticated with the current secret" → "with `S0`" / "while no secret is pending", plus the ADR-0011 late-retry rule (`agent-engineer`, `security-reviewer` review required) · [x] Console `/rotate` implementation following ADR-0010 and ADR-0011 (#21) · [ ] Serve `/metrics` on a separate port or behind an allowlist instead of relying on the reverse proxy blocking the path (`console-engineer`, security review L6) · [ ] Pin the console base images by digest (`console-engineer`; `console/Dockerfile` in #21 pins `node` by tag only, the agent image in `feat/p1-e2e-enrollment` pins by tag and digest) · [ ] Agent: parse the `HeartbeatResponse` before promoting `S1` after a heartbeat probe (`agent-engineer`, #20 re-review, Low) · [ ] Agent: count batches whose serialization fails (`agent-engineer`, #20 re-review, Low) · [ ] Agent: values split across dots in names (e.g. `a.0612.345678`) escape the > 6 digits rule; handled by classifier-based name normalization in P2-A (#20 re-review, Low) · [ ] Console: bound the argon2id cost of previous-secret (`S0`) hash checks (`console-engineer`, security review, Low) · [ ] Console: persist the agent "known good" fingerprint across console restarts (`console-engineer`, security review, Low) · [ ] Guard in migration `0004` for databases built from intermediate commits of #17 (`console-engineer`, development databases only) |

**Exit criterion**: end-to-end enrollment in containers; revocation effective in < 60 s.

**Status: not met yet.** Agent core done (#16, #20); console part 2 merged (#21: `/rotate`, `/metrics`, UI, console image); end-to-end harness in review (#22: `e2e/`, `.github/workflows/e2e.yml`, agent image `agent/Dockerfile`), which checks enrollment, `online` status, `/metrics` and revocation latency in containers. The P1-C security review is still open.

## Phase 2 – SQL Discovery
*Objective: first real findings on PostgreSQL and MySQL/MariaDB.* → **v0.1.0-alpha**

| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P2-A Classifiers | `agent-engineer` | [ ] Freeze the classifier ids; `dev/ground-truth.json` uses provisional ids to align on (or rename there): `pii.birth_date`, `pii.card_number`, `pii.email`, `pii.iban`, `pii.nir`, `pii.person_name`, `pii.phone`, `pii.postal_address`, `secret.aws_key`, `secret.password_hash` · [ ] `classifiers` crate: regex + validators (Luhn, IBAN mod 97, NIR key), secrets, column-name hints · [ ] Masking + HMAC · [ ] Property tests on masking · [ ] Name normalizer (indices, dynamic keys, classifier-matching segments, LDAP DNs) + property tests ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)); skeleton and > 6 digits rule done in P1-B (#20) · [ ] Classifier-based name normalization (segments matching a classifier → `*`, including values split across dots) · [ ] HMAC fingerprint wiring (replace the agent `sanitize::NoFingerprints` stub; today an event whose account name needs a fingerprint is dropped and counted) · [ ] **Gate** (protocol types review): the name normalizer enforces the Identifier `not` rule (card / phone numbers used as names), with property tests (I2) · [ ] **Gate** (protocol types review): `DiscoveryScanParams` / `AuditConfigureParams` are mapped into internal `ScanJob` / `AuditConfig` only via `TryFrom` enforcing the contract ranges (`sample_rows` 1..10000, `max_duration_s`, `statement_timeout_ms` 100..600000; `0` means unlimited on PostgreSQL / MySQL, I4), then clamped to the local hard limits from `agent.yaml`; empty filter lists are rejected. Owned here if the internal types live in a shared crate, otherwise by P2-B / P2-C |
| P2-B PG connector | `agent-engineer` | [ ] Schema introspection · [ ] Bounded sampling (`TABLESAMPLE`, `statement_timeout`) · [ ] `check()` + audit level · [ ] **Gate** (protocol types review): job parameters reach the connector only through the `TryFrom` mapping + `agent.yaml` clamp (see P2-A); `statement_timeout` is never set to `0` · [ ] **Gate** (protocol contract review, #13): the scan-job `TryFrom` mapping rejects empty filter lists (`Some([])`); turn the TODO in `agent/crates/protocol/tests/fixtures.rs::empty_scan_filters_stay_distinct_from_absent` into an assertion (also P2-C) |
| P2-C MySQL connector | `agent-engineer` (another instance) | [ ] Same as PG for MySQL / MariaDB, including the job-parameter **Gate** (statement timeout never `0`) and the empty-filter **Gate** (`Some([])` rejected by `TryFrom`, see P2-B) |
| P2-D Console findings | `console-engineer` | [ ] `/findings` ingestion (strict validation, cross-field checks, rejected-batch alerts) · [ ] **Gate** (protocol types review): `/findings` calls `checkSemantics` after `validateSchema`; `ok: true` never counts as full contract compliance · [ ] **Gate** (protocol contract review, #13): every outgoing `JobList` is validated against the schema (see P1-A) · [ ] Scan launching · [ ] Findings view per target / classifier · [ ] False positive marking |
| P2-E Invariant test | `security-reviewer` | [ ] Automated test: no PII from `dev/ground-truth.json` in clear text in the console database, including value-bearing object and field names |

**Exit criterion**: recall ≥ 90 %, precision ≥ 85 % on the ground truth; invariant test green.

## Phase 3 – Policies, incidents, alerting
| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P3-A Policy engine | `console-engineer` | [ ] Condition → action model · [ ] Execution in the worker · [ ] Exceptions · [ ] Confirmation, console audit-log entry and a warning on the target when an `audit.configure` change makes `sensitive_objects` empty or removes many objects (protocol contract review, #13; also P4-C) |
| P3-B Incidents | `console-engineer` | [ ] Lifecycle (open, acknowledged, resolved, false positive) · [ ] UI |
| P3-C Alerting | `console-engineer` | [ ] SMTP · [ ] HMAC-signed webhook · [ ] "Silent agent" alert |

## Phase 4 – SQL Audit
| Workstream | Owner | Tasks |
|----------|--------------|--------|
| P4-A PG Audit | `agent-engineer` | [ ] pgaudit reading (csvlog / jsonlog) · [ ] `pg_stat_statements` degraded mode · [ ] `pg_dump`, `COPY` signatures |
| P4-B MySQL/MariaDB Audit | `agent-engineer` | [ ] `server_audit` · [ ] Percona `audit_log` · [ ] `performance_schema` · [ ] `mysqldump`, `INTO OUTFILE` signatures |
| P4-C Correlation | `console-engineer` | [ ] `audit.configure` sending: confirmation + audit trail + target warning when `sensitive_objects` becomes empty or loses many objects (see P3-A) · [ ] `/events` ingestion · [ ] Volume × sensitivity score · [ ] Per-principal baselines |

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
