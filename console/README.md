# DataBastion console

Control plane of DataBastion: a Next.js (App Router) application serving the UI,
the user API and the agent API, plus a `worker` process running background jobs
with pg-boss. Both processes share this codebase and the internal PostgreSQL
database (also used as the job queue: no Redis). See
[docs/02-architecture.md](../docs/02-architecture.md) and
[docs/03-tech-stack.md](../docs/03-tech-stack.md).

> Status: phase 1 (ROADMAP P1-A): database schema, local auth, console audit log, enrollment
> tokens, agent API `/enroll`, `/heartbeat`, `/jobs` (long-poll), `/jobs/{job_id}/status`,
> `/rotate`; Prometheus `/metrics`; UI pages (login, agents, agent detail, enrollment tokens);
> Docker image. Phase 2 (P2-D): `/findings` ingestion, scan launching, findings view, false
> positives. Phase 3 (P3-A, P3-B): policy engine in the worker, exceptions, incidents and their
> lifecycle (see "Policies and incidents"); P3-C: e-mail and HMAC-signed webhook notifications,
> "silent agent" and agent-integrity alerts (see "Alerting"). Phase 4 (P4-C): `/events`
> ingestion, volume x sensitivity scoring, per-principal baselines, policies over access events,
> `audit.configure` settings with confirmation (see "Audit correlation").

## Requirements
- Node.js 24 (22.22+ also works for development)
- pnpm, version pinned by `packageManager` in `package.json` (`corepack enable`)
- PostgreSQL 17 for the internal database (the dev environment will provide it)

## Configuration
| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` / `DATABASE_URL_FILE` | Internal PostgreSQL connection string used by the web and worker processes, directly or via a file (Docker secret). Setting both is an error. In production: the non-owner runtime role (see "Database roles") |
| `DATABASE_MIGRATION_URL` / `_FILE` | `pnpm db:migrate` only: connection string of the OWNER role. Unset: `DATABASE_URL` is used (single-role development setups) |
| `LOG_LEVEL` | pino level (`info` by default) |
| `NEXT_OUTPUT_STANDALONE=1` | At build time: produce `.next/standalone` for the Docker image |
| `DATABASTION_PUBLIC_URL` | Public origin of the console (e.g. `https://console.example.com`). State-changing user requests must come from this origin; unset: the request's own origin. The worker also uses it for the links in notifications (unset: notifications carry ids only) |
| `DATABASTION_SILENT_AGENT_INTERVALS` | Worker: "silent agent" alert after this many heartbeat intervals (30 s) without a heartbeat; integer 3 to 2880, default 10 (5 minutes). See "Alerting" |
| `DATABASTION_EVENTS_RETENTION_DAYS` | Worker: Audit access events older than this many days (event `ts`) are deleted every hour; integer 7 to 3650, default 90; other values fall back to the default. Baselines and incidents are kept. See "Audit correlation" |
| `DATABASTION_EVENT_INCIDENTS_PER_POLICY_HOUR` | Worker: new incidents an `access_event` policy may open per clock hour, 1 to 10000, default 50; beyond, the matches go to one overflow incident of the policy. See "Audit correlation" |
| `DATABASTION_BASELINES_PER_TARGET` | Worker: principal baselines kept per target, 10 to 1000000, default 10000; the least recently updated are evicted beyond. See "Audit correlation" |
| `DATABASTION_NOTIFY_MAX_PER_HOUR` | Worker: incident notifications per channel and clock hour, 1 to 10000, default 30; beyond, they are skipped (`rate_limited`) and one digest per channel and hour reports the count. See "Alerting" |
| `DATABASTION_ALERTING_INSECURE_DEV=1` | **Development only**: allows `http://` webhooks, webhooks to private / loopback addresses and plain-text SMTP to a non-loopback relay (link-local and metadata addresses stay refused). In production the web and worker processes **refuse to start** when it is set (any value), unless `DATABASTION_ALERTING_INSECURE_DEV_I_UNDERSTAND=1` is also set (then a warning is logged) |
| `DATABASTION_TRUST_PROXY=1` | One trusted reverse proxy: the last `X-Forwarded-For` entry is the client IP used for per-IP rate limits. **Set it only behind a reverse proxy that sets or overwrites `X-Forwarded-For`** (otherwise clients choose their IP). Unset: the client IP is unknown, per-IP limits are off (per-user / per-agent limits and the argon2 concurrency cap remain), and a warning is logged at startup in production |
| `DATABASTION_TRUSTED_PROXY_HOPS=N` | Same, for N (1 to 10) chained trusted proxies: the N-th `X-Forwarded-For` entry from the right is used. Takes precedence over `DATABASTION_TRUST_PROXY`. When the selected entry is missing or not an IP, a warning is logged (at most once a minute) |
| `DATABASTION_METRICS_TOKEN` / `_FILE` | Bearer token required by `GET /metrics` (at least 32 characters, e.g. `openssl rand -base64 32`). Unset or too short: `/metrics` answers `404`. See "Metrics" |
| `DATABASTION_METRICS_PORT` | Serve `GET /metrics` on a dedicated listener on this port (e.g. `9464`) instead of the main port, which then answers `404` on `/metrics`. Unset: no dedicated listener, `/metrics` stays on the main port (a startup warning is logged in production when the token is set). Must differ from `PORT`. See "Metrics" |
| `DATABASTION_METRICS_HOST` | Bind address (IP literal) of that listener: `127.0.0.1` by default; `0.0.0.0` inside a container whose metrics port is not published. Invalid port / host: `/metrics` is disabled everywhere and an error is logged |
| `DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1` | Let the web and worker processes start in production without a usable `DATABASTION_ENCRYPTION_KEY(_FILE)` (see below; not recommended) |
| `DATABASTION_INSECURE_COOKIES=1` | Drop `Secure` / `__Host-` from the session cookie in production (plain-HTTP test setups only; warned at startup) |
| `DATABASTION_BOOTSTRAP_ADMIN_USERNAME` | `pnpm admin:bootstrap` only: login of the first administrator |
| `DATABASTION_BOOTSTRAP_ADMIN_PASSWORD` / `_FILE` | `pnpm admin:bootstrap` only: its password (12 to 1024 characters) |
| `TEST_DATABASE_URL`, `PG_BIN` | Tests only: an existing admin URL, or the PostgreSQL binaries used to start a throwaway cluster (default `/usr/lib/postgresql/16/bin`) |
| `DATABASTION_TEST_SMTP`, `DATABASTION_TEST_MAILPIT_API` | Tests only: `host:port` of a Mailpit SMTP listener (e.g. `127.0.0.1:1025` from `make dev`) and its API (default `http://<host>:8025`); unset or unreachable: the Mailpit test is skipped with a message (the in-process SMTP server tests always run) |

`DATABASTION_ENCRYPTION_KEY(_FILE)` from
[deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml) (at least 32 characters,
e.g. `openssl rand -base64 32`) is the console server key of the web and worker processes. It keys the agent "known good" fingerprints (HKDF-SHA256
subkey, domain `agent-known-good.v1`, see "Data at rest") and the login device cookies (domain
`login-device.v1`, see "Brute-force protection") and encrypts masked samples at rest (domain
`masked-samples.v1`, see "Data at rest") and the notification channel secrets (domain
`notification-channels.v1`, see "Alerting"). **Set it in production: the shared-IP protection
of agents (P1-D M1) and the device-cookie protection of logins (N1) require it.** Unset, too short
or unreadable: fingerprints and device cookies are neither issued nor accepted (fail closed: agents
lose the lock-out exemption, so agents behind a shared NAT / proxy IP can be blocked by floods from
it, and a distributed guessing attack on a username can keep its user out), and in production the
web and worker processes **refuse to start** (a `fatal` log, exit code 1), unless
`DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1` is set: they then start and log an **error** naming
those disabled protections (masked samples are then neither stored nor shown). Changing it
invalidates the stored fingerprints and makes the stored channel secrets unusable (re-enter them). The console only knows its own database: it never stores target
database credentials (invariant I3).

## Commands
| Command | What it does |
|---------|--------------|
| `pnpm install --frozen-lockfile` | Install the pinned dependencies |
| `pnpm dev` | Web process in development mode (http://localhost:3000) |
| `pnpm build` | Production build (also type-checks) |
| `pnpm start` | Serve the production build (web process) |
| `pnpm worker` | Worker process (pg-boss); stops gracefully on `SIGTERM` / `SIGINT` |
| `pnpm lint` | ESLint, zero warnings allowed |
| `pnpm typecheck` | `next typegen` + `tsc --noEmit` |
| `pnpm test` | Unit tests (vitest) |
| `pnpm protocol:generate` | Regenerate `src/generated/protocol/` from `shared/protocol/openapi.yaml` (checked by `pnpm test`) |
| `pnpm db:generate --name <slug>` | Generate a versioned SQL migration in `drizzle/` from `src/db/schema.ts` |
| `pnpm db:generate --custom --name <slug>` | Empty versioned migration for SQL drizzle-kit cannot express (triggers, grants, guards): `0002`–`0004`, `0009`, `0010` |
| `pnpm db:migrate` | Apply pending migrations to `DATABASE_URL(_FILE)` |
| `pnpm admin:bootstrap` | Create the first administrator (refused if any user exists) |

`pnpm test` starts a throwaway PostgreSQL cluster on `127.0.0.1` (random port, temporary
directory, deleted afterwards; run as the `postgres` system user when the tests run as root) for
the database tests. Without `TEST_DATABASE_URL` or PostgreSQL binaries, those tests are skipped
with a message and the unit tests still run.

## Database roles
The append-only guarantee of `audit_log` (a trigger) only holds if the console cannot remove it,
and migrations must never run code planted by the console. Production uses three roles:

| Role | Used by | Rights |
|------|---------|--------|
| Bootstrap superuser (`POSTGRES_USER`) | the initdb script only | Creates the roles below, then is never used |
| `databastion_owner` (LOGIN, NOSUPERUSER, NOCREATEROLE) | `pnpm db:migrate` via `DATABASE_MIGRATION_URL(_FILE)` | Owns the database, `public`, `pgboss` and every console table and trigger. `search_path` pinned to `public` (role setting and migration session) |
| `databastion_runtime` (LOGIN), member of `databastion_app` (NOLOGIN) | web + worker via `DATABASE_URL(_FILE)` | Not superuser, not owner. `SELECT, INSERT, UPDATE, DELETE` on the console tables, only `SELECT, INSERT` on `audit_log`, only `SELECT, INSERT` and `UPDATE (acknowledged_at, acknowledged_by)` on `security_events` (no `DELETE`: an integrity alert cannot be erased or rewritten), only `SELECT, INSERT` and `UPDATE` of the evaluation columns on `access_events` (deleted only through the purge function), `USAGE, CREATE` on schema `pgboss` (pg-boss tables). **No** `CREATE` on the database (no new schemas) nor on `public` |

Grants come from migrations `0003_runtime_role_grants.sql`, `0004_pgboss_schema_hardening.sql`,
`0010_security_events_no_delete.sql`, `0012_findings_runtime_grants.sql` (`findings_batches`:
`SELECT, INSERT` only; `findings`: no `DELETE`, `TRUNCATE`), `0015_incidents_runtime_grants.sql`
(`incidents`: no `DELETE`, `TRUNCATE`), `0016_incidents_update_columns.sql` (`incidents`:
`UPDATE` only on the lifecycle columns and the engine's re-match counters, never the policy
snapshot, severity, dedup key or subject) and `0019_notification_deliveries_grants.sql`
(`notification_deliveries`: no `DELETE`, `TRUNCATE`, `UPDATE` only on the delivery-state columns)
and `0022_p4c_events_grants.sql` (`access_events`: `SELECT, INSERT`, `UPDATE` only on the
evaluation columns `evaluated_at`, `sensitivity`, `score`, `anomaly`, `baseline_rows`;
`events_batches`, `incident_events`: `SELECT, INSERT` only; `principal_baselines`,
`audit_configs`: no `DELETE`, `TRUNCATE`; `incidents`: `UPDATE` also on the event re-match columns
`event_score`, `event_rows`, `event_signals`, `last_event_at`; `EXECUTE` on the owner-defined
`SECURITY DEFINER` function `databastion_purge_access_events(retention_days, max_rows)`, the only
way for the runtime role to delete events: never those younger than 7 days) and
`0024_p4c_review_purge.sql` (the purge function also keeps unevaluated events, keeps the batch
records 30 more days and purges idle baselines; `EXECUTE` on
`databastion_evict_principal_baselines(agent_id, target_id, n)`, a bounded delete of a target's
least recently updated baselines; `UPDATE (event_anomaly)` on `incidents`)
(custom, every name schema-qualified). Migration
`0009_pgboss_owner_guard.sql` refuses to run (the whole `migrate` run is rolled back) when schema
`pgboss` exists and is owned by a role other than the migration role: fix the ownership as the
superuser (`ALTER SCHEMA pgboss OWNER TO databastion_owner`, after checking the schema for planted
objects), then run `migrate` again. `migrate` repeats the same check as a pre-flight on every run,
before any migration SQL (also when no migration is pending). The roles and passwords are created outside migrations (the
owner has no `CREATEROLE`); with the example compose file,
[deploy/initdb/10-databastion-roles.sh](../deploy/initdb/10-databastion-roles.sh) does it at the
first database initialization, reading the passwords from the Docker secret files inside psql
(never on a command line). The worker runs pg-boss with `schema: 'pgboss'`, `createSchema: false`.

At startup, the web and worker processes log a warning if their database role is a superuser or
owns `audit_log`, if it can delete incidents or rewrite their snapshot columns, or if it can
delete or rewrite access events.

Rule: the owner role must never run SQL against objects inside schema `pgboss` (DML, DDL, manual
maintenance). pg-boss creates them as the runtime role, so a trigger or function planted there by
a compromised console would run with the owner's rights. A future migration that needs to touch
`pgboss` must `SET ROLE databastion_runtime` first, or check object owners before acting.

Limitation: in a single-role setup (`DATABASE_URL` is the owner or a superuser, e.g. development),
the console could drop the trigger; the audit log is then append-only only against the application
code, not against a compromised console process.

### Upgrading an existing deployment
Deployments created before the role split (single `POSTGRES_USER` role used by everything; the
initdb script only runs on an empty data directory) switch as follows, once, as the superuser:

```sql
\set owner_password `cat /run/secrets/db_owner_password`
\set app_password `cat /run/secrets/db_app_password`
CREATE ROLE databastion_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'owner_password';
ALTER ROLE databastion_owner SET search_path = public;
CREATE ROLE databastion_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE databastion_runtime LOGIN IN ROLE databastion_app PASSWORD :'app_password';
ALTER DATABASE databastion OWNER TO databastion_owner;
REASSIGN OWNED BY <old console role> TO databastion_owner;  -- tables, triggers, schemas (incl. pgboss, drizzle)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

Then drop any schema the old role created other than `public`, `pgboss` and `drizzle`, point
`db_owner_url` at `databastion_owner` and `db_url` at `databastion_runtime`, run `migrate`, and
restart the web and worker processes (check that they log no database role warning).

## First administrator
There is no default account and no default password. After `pnpm db:migrate`:

```sh
DATABASTION_BOOTSTRAP_ADMIN_USERNAME=admin \
DATABASTION_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/admin_password \
pnpm admin:bootstrap
```

The command refuses to run once a user exists, and writes `user.bootstrap` to the audit log.

The CI runs `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm test` and
`pnpm build` with Node 24.

## HTTP endpoints
| Route | Purpose |
|-------|---------|
| `GET /api/health` | Liveness: `{"status":"ok"}`, never touches the database |
| `GET /api/health/ready` | Readiness: `200 {"status":"ok"}` or `503 {"status":"unavailable"}`; the cause is only logged |
| `/api/agent/v1/*` | Agent API (see [its README](src/app/api/agent/v1/README.md)) |
| `GET /metrics` | Prometheus text format, bearer token (see "Metrics"); on the dedicated listener when `DATABASTION_METRICS_PORT` is set; internal network only |
| `POST /api/auth/login` | `{username, password}` → session cookie + `{user, csrf_token}`; failed logins rate limited per IP, per username + IP, and per username (slow-down, never a lock-out; see "Brute-force protection") |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/auth/session` | Current user + CSRF token |
| `GET` / `POST /api/enrollment-tokens` | List / create (admin). The `dbe_…` token is returned once, only its SHA-256 is stored; valid 24 h |
| `DELETE /api/enrollment-tokens/{id}` | Revoke an unused token (admin) |
| `GET /api/agents` | Agents and their reported targets (audit level, reachability) |
| `POST /api/agents/{id}/revoke` | Revoke an agent (admin): secrets unusable immediately, held long-polls closed, pending jobs cancelled |
| `POST /api/agents/{id}/rotate` | Queue an `agent.rotate_secret` job (admin, `202 {job_id}`); `409` while a secret is pending, within 60 s of a promotion, or while another rotate job is open (ADR-0010) |
| `POST /api/agents/{id}/targets/{target_id}/scan` | Queue a `discovery.scan` job (admin, `202 {job_id}`, audited `discovery.scan_request`). Body: contract `DiscoveryScanParams`, every key optional (defaults `sample_rows` 200, `max_duration_s` 900, `statement_timeout_ms` 30000); unknown keys, out-of-range values and empty include filters: `400 invalid_params`. `404` unknown / inactive agent or target not currently reported; `409 agent_not_ready` (the agent's latest heartbeat carries no `classifiers_version`), `409 classifiers_version_unregistered` (that version is not in the contract classifier registry `classifiers.json`: no job is issued), `422 unknown_classifiers` (`classifiers` holds ids that are not classifiers of that version); each refusal is audited (`discovery.scan_request`, `failure`, with the reason and the version). The job carries the version of the agent's latest heartbeat. `409 scan_in_progress` (a scan of the target is pending, delivered or running). Expires after 6 h. Before the busy check, the agent's dead scans are swept: pending past `expires_at` → `expired`, delivered / running past `delivered_at + max_duration_s + 1 h` → `failed` (`timeout`, audited `job.timeout`, `finished_at` = that deadline) |
| `POST /api/agents/{id}/targets/{target_id}/audit` | Audit settings of a target, queued as an `audit.configure` job (admin, CSRF; P4-C). Body `{enabled, aggregation_window_s?, poll_interval_s?, min_rows?, derive_from_findings?, manual_objects?, confirm?}` (defaults 60, 10, none, `true`, `[]`; `manual_objects`: contract `SensitiveObject[]`); unknown keys and non-conforming objects: `400 {"error": "invalid_audit_settings", "field"}`; `404` unknown / inactive agent or target not currently reported. `202 {job_id, warning, previous_objects, next_objects, added_objects, removed_objects, truncated_objects}`. A change that disables Audit, empties `sensitive_objects` or removes many objects answers `409 {"error": "confirmation_required", warning, ...counts, digest}` and queues nothing: post the same settings again with `confirm: digest`. Audited `audit.configure` (counts, flags, warning, `confirmed`; refusals as failures). See "Audit correlation" |
| `POST /api/findings/{id}/false-positive` | `{"false_positive": true\|false}` (admin, CSRF, audited `finding.false_positive` with agent, target and classifier); `204`, `404` unknown finding. The mark stores `matched` and `classifiers_version`; a rescan that matches more values or uses another classifier set clears it (audited `finding.false_positive_reset`, system actor). Marking closes the finding's open / acknowledged incidents as `false_positive` (audited `incident.transition`); unmarking makes the policies apply to it again |
| `POST /api/policies` | Create a policy (admin, CSRF): `{name, description?, enabled?, source?, conditions, actions}`, strictly validated (see "Policies and incidents"); `201 {id}`, `400 {"error": "invalid_policy", "field"}`, `409 name_taken` (case-insensitive). Audited `policy.create` (identifiers, flags and counts only: never the name or description) |
| `PATCH` / `DELETE /api/policies/{id}` | Update any subset of the create keys (`source` is fixed) / delete (admin, CSRF); `204`, `404`. A deleted policy's exceptions go with it, its incidents are kept. Audited `policy.update` (with the changed keys) / `policy.delete` |
| `POST /api/policy-exceptions` | Create an exception (admin, CSRF): `{policy_id?, agent_id?, target_id?, classifier?, location?, reason, expires_at?}`, at least one of agent / target / classifier / location; `201 {id}`, `400 {"error": "invalid_exception", "field"}`, `404` unknown policy or agent. Audited `policy_exception.create` (never the reason) |
| `DELETE /api/policy-exceptions/{id}` | Delete an exception (admin, CSRF); the policies it covered are re-applied to the existing findings. Audited |
| `GET` / `POST /api/notification-channels` | List / create a notification channel (admin; create with CSRF). Body `{slug, type: "email" \| "webhook", enabled?, system_alerts?, config, password?}`; `config` e-mail: `{host, port, tls: "starttls" \| "implicit" \| "none", from, recipients, username?}`, webhook: `{url}`. `201 {id}` (webhook: also `signing_secret`, returned this once only), `400 {"error": "invalid_channel", "field"}`, `409 slug_taken`, `409 encryption_key_unavailable`. The list never returns a secret (`secret_set` flag; webhooks: URL origin only). Audited `notification_channel.create` (slug, type, flags, TLS mode, port, recipient count: never a host, URL, address, user or secret) |
| `PATCH` / `DELETE /api/notification-channels/{id}` | Update any of `{enabled, system_alerts, config, password}` (e-mail settings replaced as a whole; `password: null` removes it; slug and type fixed) / delete (admin, CSRF); `204`. Audited |
| `POST /api/notification-channels/{id}/rotate-secret` | New webhook signing secret (admin, CSRF): `200 {signing_secret}`, shown once; audited `notification_channel.rotate_signing_key` |
| `POST /api/notification-channels/{id}/test` | Queue a test notification (admin, CSRF): `202`, audited `notification_channel.test`; sent even when the channel is disabled |
| `POST /api/incidents/{id}/transition` | `{"status": "acknowledged" \| "resolved" \| "false_positive"}` (CSRF). Any signed-in user acknowledges and resolves; `false_positive` is admin only (`403`, audited `user.access_denied`). `409 {"error": "invalid_transition", "from"}` outside the lifecycle; `204`. Audited `incident.transition` with actor, `from`, `to`; refusals as failures |

UI pages (server components; data read server-side, only the user and the CSRF token reach the
browser): `/login`, `/agents` (name, hostname, version, status online / silent (no heartbeat for
90 s) / revoked / locked, last seen, targets with audit level), `/agents/{id}` (targets; admin:
"Rotate secret" and "Revoke" with confirmation dialogs), `/enrollment-tokens` (admin: create, the
`dbe_…` token is shown once with a copy button; list; revoke), `/findings` (counts per target and
classifier, then one row per location with its masked samples decrypted server side; filters
`?agent=&target=&classifier=`, false positives hidden unless `fp=1`; "False positive" toggle per
row, admins only; analysts see a hint). The view fetches at most 500 rows round-robin over targets
(most recently seen first within each), so one noisy agent or target cannot hide the others; the
counts show at most 1000 (target, classifier) groups, fetched round-robin over agents then over
the targets of each agent. The agent detail page shows the last scan of each target, a link to its findings and (admin)
a "Scan" dialog. `/incidents` lists the incidents (active ones by default; filters
`?status=open|acknowledged|resolved|false_positive|all&severity=&agent=&target=`, at most 500, most
severe first); `/incidents/{id}` shows the incident, its lifecycle (who and when), the transition
buttons ("False positive" for admins only, with a confirmation) and the linked finding with its
masked samples, decrypted server side through the same path as `/findings` (`no-store`), and its
notifications (channel, status, attempts, last error code with its explanation).
`/notifications` (admin) lists the channels (create, edit, enable / disable, test, new webhook
secret, delete) and the last 100 deliveries.
`/events` lists the Audit access events (newest first, at most 500; filters
`?agent=&target=&principal=<key>&signal=<id or family>&from=&to=&anomaly=1`) with their score,
signals, baseline anomaly flag and the incidents they matched, and the principals with a baseline;
`/events/principal?agent=&target=&principal=<key>` shows one principal's baseline, incidents and
latest events. The principal is designated by its key (SHA-256), never by the account name in a
URL. `/agents/{id}/targets/{target_id}/audit` shows a target's Audit settings, the objects its
findings make sensitive, and (admin) the settings form with the confirmation step; the agent page
shows each target's settings and the warning left by a narrowing change. Incidents raised from
events show the principal, database, hour, rows, score and signals, and their events.
`/policies` lists the policies and exceptions (admin: create, enable / disable, delete, add or
delete exceptions); `/policies/{id}` shows one policy with its exceptions (admin: edit form) and
warns when a notify channel name matches no channel or a disabled one (the form warns as you type). A scan that failed with `unsupported` while its `classifiers_version` differs from
the agent's current heartbeat version is shown as "classifier set mismatch" (the agent build runs
another classifier set) instead of a bare `unsupported`. Agent-reported strings are rendered
as React text nodes only (no `dangerouslySetInnerHTML` anywhere). UI components follow shadcn/ui
(new-york) in `src/components/ui/`, written without Radix / `class-variance-authority` (the
confirmation dialog uses the native `<dialog>` element).

### Security headers
- UI pages: `Content-Security-Policy` with a per-request nonce set by `src/proxy.ts`
  (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `style-src 'self' 'nonce-…'`, `object-src 'none'`,
  `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`; `'unsafe-eval'` in `next dev`
  only). Every page is rendered per request (root layout `force-dynamic`), so no prerendered page
  lacks the nonce. Not applied to `/api/*` and `/metrics` (no HTML). UI pages also get
  `Cache-Control: no-store` (the findings view carries decrypted masked samples); `/findings` and
  `/incidents` (the incident page shows the linked finding's samples) also get it from
  `next.config.ts` `headers()`, and links to them are not prefetched.
- Every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` / `-Resource-Policy: same-origin`,
  a restrictive `Permissions-Policy` (`next.config.ts`). HSTS is set by the TLS reverse proxy.

User sessions: 256-bit cookie (`HttpOnly`, `SameSite=Strict`, `Secure` + `__Host-` prefix in
production), only its SHA-256 stored, 12 h absolute / 2 h idle. State-changing user routes require
a same-origin request and the `X-CSRF-Token` header (HMAC of the session token, returned by login
and `/api/auth/session`). Every user action (login, logout, token creation / revocation, agent
revocation, authorization failures) and every enrollment, successful or not, is written to the
`audit_log` table. It holds no secrets and is append-only at the database level: a trigger rejects
any `UPDATE`, `DELETE` or `TRUNCATE`. Expired and idle sessions are deleted at each login, and
logging in again from the same browser ends its previous session.

Brute-force protection: every login or agent-authentication attempt that needs an argon2id
verification is counted before it runs (and refunded on success), so concurrent requests cannot
exceed the limits. Logins, agent authentications and enrollments use separate argon2id pools (4, 8
and 2 concurrent operations per process, `503` + `Retry-After` beyond; a `503` on `/enroll` does
not consume the token), plus a pool reserved for agents presenting their last verified secret, so a
login flood can never block agents. Failed logins on unknown usernames share a process-wide budget
(30 per 5 minutes). Per-IP limits bucket IPv6 addresses by /64 and only apply when the client IP is
known (trusted proxy).

Failed logins (P1-D M2), all over 15 minutes:
- 20 per source IP (IPv6 bucketed by /56 for logins, not /64);
- 5 per username **and** source IP: a failure flood from one IP never locks the account out for
  another IP (`429` from that IP only);
- when the client IP is unknown (no trusted proxy), that counter is per username alone, shared by
  everyone: reaching it never answers `429`, the username degrades like below (N2), with a
  slow-down that grows with the username's failed degraded attempts: 2 s, doubling per failure
  (4, 8, 16 s), capped at 30 s (15-minute window; a success refunds its own attempt only);
- 100 per username across all IPs. Reaching it never refuses the login: the username degrades to a
  slow-down (2 s before the verification) with one attempt in flight at a time, other concurrent
  attempts for that username get `503 busy` + `Retry-After`. Wrong passwords still answer `401`
  (the degraded state is not revealed as `429`).

Device cookies (P1-D N1, OWASP "device cookies"): every successful login sets a long-lived
(90 days) `__Host-databastion_device` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`;
`databastion_device` without `Secure` outside production, like the session cookie) carrying the
user id, the issue time and a random nonce, signed with HMAC-SHA256 under the server-key subkey
`login-device.v1`; nothing is stored server side. A login presenting a valid device cookie for the
username it tries skips the global per-username cap and its degraded single slot, so an attacker
spread over many IPs cannot keep the real user out by holding that slot. It never replaces the
password (nor the growing slow-down of an unknown IP), its failures still count toward the global
per-username cap, and it stays subject to the per-(username, IP) limit, a limit of 5 failures per cookie
(beyond, the cookie gives no bypass: a stolen cookie cannot be used to guess) and the login
argon2id pool. A cookie for another user, tampered, expired or signed with another key is ignored.
Without the server key, no device cookie is issued or accepted.

Failed agent authentications (P1-D M1), all over 5 minutes: 10 per (agent, source IP), 50 per
source IP. Only failures that ran an argon2id verification count; cheap failures (missing or
malformed headers or secret, unknown or inactive agent, `/rotate` body missing its read deadline)
count toward a separate limit of 500 per source IP that only gates reaching argon2id. No failure
limit holds a secret verified less than 25 s ago or a known-good secret (current or pending, see
"Data at rest"): agents sharing a NAT or proxy IP cannot be blocked by junk requests from it, which
need no secret. The known-good exemption is checked first against an in-memory copy of the agent
row (refreshed on every request of the agent), then against the row itself; that database read is
skipped while the source IP is over the cheap limit, and a read that grants no exemption counts as
a cheap failure (N4). Consequence: right after a console restart, while an IP is over the cheap
limit, a known-good agent behind it waits for the window (at most 5 minutes) like the others. The
known-good exemption requires the server key (`DATABASTION_ENCRYPTION_KEY`); the 25 s cache does not.

## Agent secret rotation
`POST /api/agent/v1/rotate` follows [ADR-0008](../docs/adr/0008-agent-generated-secret-rotation.md)
as refined by ADR-0010 (`S0` previous secret, `S1` new one):
- the agent sends `S1` (`AgentSecret` format; a malformed or low-entropy value, fewer than 16
  distinct characters, or `S1` equal to the current secret: `400 invalid_secret`), authenticated
  with its current secret; the console stores its argon2id hash as pending, `grace_expires_at` =
  now + 300 s (never extended);
- same `S1` again with `S0` (while pending, or within 60 s of the promotion): `200 duplicate: true`;
- promotion: first successful request with `S1`, or the deadline (applied lazily on the agent's
  next request, with the deadline as promotion time);
- `S0` within 60 s of the promotion: `401` without incident on every endpoint but `/rotate`;
- `/rotate` with `S0` and the promoted `S1` (it verifies against the current hash) is a late retry
  at **any** time (ADR-0011, refining ADR-0010): `200 duplicate: true` with that rotation's deadline
  (`promoted_grace_expires_at`, kept even when a newer rotation has started), never a lock. Only the
  holder of `S1` can send it; this check runs only on the `/rotate` path authenticated with `S0`.
  After the window, a `/rotate` with `S0` has exactly two outcomes: that duplicate, or a lock.
  Any invalid body, low-entropy or other secret, unknown `job_id`, or more than 10 late retries in
  5 min locks the agent; once `S0` is recognized, this path never answers `400` / `404` / `429` /
  `503` and never uses the per-agent rotate bucket. Its only argon2id work (does `new_secret`
  verify against the current hash?) runs inside the authentication itself, under the pool slot and
  the counted attempt that verified `S0` (P1-D): the `/rotate` body is read before the argon2id
  authentication for that, but after its cheap checks (headers, secret format, failure limits),
  with a 64 KiB cap (`413` after authentication beyond) and a 10 s read deadline (`400` before any
  argon2id work, never a lock); nothing else about it is answered before authentication;
- `rotation_conflict` (`409`): `/rotate` with `S0` and any other secret while pending or at any time
  after the promotion, or any other request with `S0` after the window. The agent is locked (every secret hash
  cleared, held long-polls closed, open jobs cancelled), `agent.rotation_conflict` is written to the
  audit log and a `critical` row to `security_events`. Only revocation + re-enrollment recovers;
- `/rotate` authenticated with the current secret (e.g. `S1` right after promotion) always starts
  a new rotation, never a conflict.

The previous hash is kept after the 60 s window, until the next promotion replaces it, only to
detect a later use of `S0`; it never authenticates. A wrong secret therefore costs up to three
argon2id verifications (current, pending, previous) under a single pool slot and a single
rate-limit attempt. A request with `S0` is genuine but never authenticates: its attempt stays
counted against the per-agent / per-IP failure limits like a wrong secret (P1-D), so repeated uses
of `S0` cannot cost unbounded argon2id work; only a `/rotate` answered `duplicate` gives it back. `/rotate` runs its own argon2id work (hash of `S1`, comparison with the
pending / promoted hash) in a dedicated pool of 2 (`503` + `Retry-After` beyond) and is limited
to 10 calls per agent per 5 min (`429`). Concurrent `/rotate` calls are serialized by conditional
updates: of two different secrets sent together with `S0`, one is registered and the other one
locks the agent. The body is never logged; responses are `no-store`.

All rotation instants (registration deadline, promotion time, window checks) use the console
(Node) clock. Held long-polls are bound to the secret that opened them: a promotion, a lock or a
revocation wakes them (locally and via `NOTIFY` in other processes) and a poll whose secret is no
longer the current one is closed with `401`.

`security_events` holds agent-integrity alerts (they are not policy incidents: the P3-B `incidents`
table only holds what policies raise; merging both views is left to a later task):
`agent.rotation_conflict` (`critical`), and since P2-D `agent.batch_rejected` (a `400` on
`/findings`), `agent.batch_conflict` and `agent.foreign_target` (a finding for a target the agent
never reported), all `high`, each with an audit-log entry of the same name; since P3-C also
`agent.silent` (`medium`, see "Alerting"). Each one is notified to the system-alert channels. Their details are the
endpoint, the status and the first error `{pointer, keyword}` only. At most 20 are written per agent
per 10 minutes; beyond, they are counted, logged once per window, and the next recorded event of the
agent carries the count (`suppressed_before`). The budget is in memory, per web process (like the
rate limiters): with N web processes an agent can get up to N x 20 rows per window.

## Metrics
`GET /metrics` (Prometheus text format 0.0.4, [ADR-0004](../docs/adr/0004-observability-via-console.md)):
Prometheus scrapes the console only, never the agents. Protected by
`Authorization: Bearer <DATABASTION_METRICS_TOKEN>` (constant-time comparison; `401` otherwise,
`404` when the token is unset). **Internal network only**.

Recommended: `DATABASTION_METRICS_PORT` (P1-D). The web process then starts a second, minimal
`node:http` listener (from `src/instrumentation.ts`, next to the Next.js standalone server) bound to
`DATABASTION_METRICS_HOST` (`127.0.0.1` by default) that serves only `GET /metrics` (same token,
same answers; any other path `404`, other methods `405`; 16 connections, 10 s timeouts), and the
main port answers `404` on `/metrics`. The metrics endpoint is then never reachable through the
public reverse proxy, whatever its configuration, and nothing depends on client IPs (an IP allowlist
would rely on `X-Forwarded-For` behind the proxy). A dedicated port was chosen over a custom
Next.js server because it keeps the generated standalone `server.js` unchanged. In a container,
set `DATABASTION_METRICS_HOST=0.0.0.0` and do **not** publish the port: Prometheus scrapes it over
the internal network (see [deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml)).
The listener belongs to the web process only (one per process).

Without `DATABASTION_METRICS_PORT` (default, and the dev setup: `pnpm dev` scraped on port 3000),
`/metrics` stays on the main port: block the path at the public reverse proxy and scrape the console
directly.

Frozen names (renaming one is a breaking change; the provisional Grafana dashboard in
`dev/grafana/` uses the first and the spool one):

| Metric | Labels | Source |
|--------|--------|--------|
| `databastion_agent_last_seen_seconds` | `agent_id` | console: seconds since the last heartbeat |
| `databastion_agent_up` | `agent_id` | console: 1 if the last heartbeat is < 90 s old |
| `databastion_agent_clock_skew_seconds` | `agent_id` | console: agent minus console clock |
| `databastion_agent_target_reachable` | `agent_id`, `target_id` | heartbeat target status (1 / 0) |
| `databastion_agent_target_audit_level` | `agent_id`, `target_id` | full 3, partial 2, limited 1, none 0 |
| `databastion_agent_reported_uptime_seconds` | `agent_id` | heartbeat `uptime_s` |
| `databastion_agent_reported_spool_bytes`, `_spool_max_bytes`, `_spool_batches` | `agent_id` | heartbeat `spool` |
| `databastion_agent_reported_<name>` | `agent_id` | heartbeat `metrics` map |
| `databastion_agent_reported_target_<name>` | `agent_id`, `target_id` | heartbeat `targets[].metrics` map |
| `databastion_agents` | `status` | agents by status |
| `databastion_jobs` | `status` | jobs by status |
| `databastion_enrollment_tokens_active` | | usable enrollment tokens |
| `databastion_security_events` | | rows of `security_events` |
| `databastion_console_argon2_operations_total` | | argon2id operations of this process |
| `databastion_metrics_series_dropped` | | series dropped by the caps in the last scrape |

Per-agent series cover enrolled / online agents (not revoked or locked). Agent-provided metric
names (contract: `^[a-z][a-z0-9_]{0,63}$`, numeric values) on the reserved list (`last_seen_seconds`,
`up`, `revoked`, `locked`, `status`, `info`, `clock_skew_seconds`, `uptime_seconds`, `spool_*`) or,
at agent level, starting with `target_` are ignored, so an agent cannot shadow a console series.
Cardinality caps: 1000 agents (applied in SQL, targets joined to those agents), 50 000 agent-driven series per scrape (agent-reported and per-target series) (the contract already caps
128 metrics per map and 64 targets per agent).

## Docker image
[`Dockerfile`](Dockerfile) (build context `console/`): multi-stage on `node:24-bookworm-slim`,
base image and Dockerfile syntax frontend pinned by tag and digest, `next build` with
`NEXT_OUTPUT_STANDALONE=1`, runtime as uid/gid 10001 with root-owned, read-only
files: compatible with `read_only: true` (only `/tmp` as tmpfs). Entrypoint commands
([docker/entrypoint.sh](docker/entrypoint.sh)): `web` (default, standalone `server.js` on port
3000, plus the metrics listener when `DATABASTION_METRICS_PORT` is set), `worker`, `migrate`, `bootstrap-admin`. The worker, the migrator and the bootstrap command run
from the TypeScript sources with `tsx` (`node --import tsx`, cache disabled): `tsx` is already the
production runner of `pnpm worker` / `pnpm db:migrate`, so the image runs exactly the code the tests
run, with no second bundler configuration to keep in sync; the cost is a larger image (production
`node_modules` next to the standalone web bundle) and a short transpilation at startup.
`HEALTHCHECK` ([docker/healthcheck.sh](docker/healthcheck.sh)) probes `/api/health` for `web` and
reports healthy for the other commands. The image is not built by the CI yet.

## Data at rest
| Data | Storage |
|------|---------|
| User passwords, agent secrets (current / pending / previous) | argon2id (`@node-rs/argon2`, m = 19 MiB, t = 2, p = 1) |
| Agent "known good" fingerprints (`agents.known_good_fingerprint`, `known_good_at`, `known_good_pending_fingerprint`) | HMAC-SHA256 (subkey of `DATABASTION_ENCRYPTION_KEY`) over the bound argon2id hash and the 256-bit agent secret; never authenticate, only exempt the last verified secret (24 h, survives restarts) and the pending secret registered by the authenticated agent from the per-agent failure limit; the pending one becomes the current one at promotion; cleared on lock and revocation |
| Security events (`security_events`) | console-computed kind / severity / scalar details, never a secret or hash |
| Findings (`findings`) | one row per (agent, target, location, classifier), keyed by `location_key` = SHA-256 of that tuple; names, counts, confidence, first / last seen, false-positive decision in plain columns (normalized names, escaped on display) |
| Masked samples (`findings.masked_samples`) | AES-256-GCM, key = HKDF-SHA256 subkey `masked-samples.v1` of `DATABASTION_ENCRYPTION_KEY`, random 96-bit nonce, AAD = `"databastion.masked-samples.v1" ‖ 0x01 ‖ finding id`; layout `0x01 ‖ nonce ‖ ciphertext ‖ tag`. Without a usable key no sample is stored (the finding is); a key change makes stored samples "unavailable" in the view until the next scan |
| HMAC fingerprints (`findings.fingerprints`) | as sent by the agent (keyed by its local key, which never leaves it) |
| Findings batches (`findings_batches`) | `(agent_id, batch_id)`, SHA-256 of the validated batch in canonical JSON (keys sorted recursively), job, item count: idempotency only, never the body. Append-only for the runtime role (migration `0012`: no `UPDATE`, `DELETE`, `TRUNCATE`); `findings` rows cannot be deleted by it either |
| Policies, exceptions (`policies`, `policy_exceptions`) | plain columns: admin-typed name, description, reason; condition and action documents holding only identifiers, globs on normalized names, thresholds, severities and channel references; never a sampled value |
| Access events (`access_events`) | exactly the contract `AccessEvent` fields, in plain columns (principal `db_user` or its `hmac-sha256:` fingerprint, client address, application, action, normalized object names, rows, signals, source, counts, timestamps; escaped on display), `principal_key` = SHA-256 of the principal, and the worker's evaluation (sensitivity, score, anomaly flag, baseline snapshot). No query text, bound parameter or returned value: the contract has no field for them and unknown fields are rejected before anything is stored (ADR-0007). The runtime role cannot rewrite or delete them; deleted after `DATABASTION_EVENTS_RETENTION_DAYS` (migration `0022`) |
| Events batches (`events_batches`) | `(agent_id, batch_id)`, SHA-256 of the validated batch in canonical JSON, item count: idempotency only, never the body. Insert-only for the runtime role; purged with the events |
| Principal baselines (`principal_baselines`) | per (agent, target, principal key): EWMA mean and variance of `ln(1 + rows)` and `ln(1 + score)`, counters, first / last event; the account name or fingerprint for display. Aggregates only: no object name, no event. Kept after the events are purged |
| Incident links (`incident_events`) | (incident, event) pairs, insert-only; go with a purged event |
| Audit settings (`audit_configs`) | per target: the settings last sent, the manual sensitive objects (normalized names and classifier ids), the `sensitive_objects` list last sent, the last job, and the warning of the last change (`disabled` / `emptied` / `shrunk` with the number of objects removed) |
| Incidents (`incidents`) | plain columns: policy snapshot (id, name, revision), severity, status and who / when of each transition, finding id, agent, target, classifier, `matched` and `classifiers_version` snapshots, `dedup_key`; no sampled value (the samples stay encrypted on the finding). Never deleted by the runtime role, which may only update the lifecycle and re-match columns (migrations `0015`, `0016`) |
| Enrollment tokens, session tokens | SHA-256 only (256-bit random values) |
| Database credentials, connection strings | never received nor stored (invariant I3) |
| Agent-reported metadata (hostname, versions, target ids, audit levels, metrics) | plain columns, bounded by the protocol schema, escaped on display |
| Notification channels (`notification_channels`) | slug, type, flags and the non-secret settings in plain columns (SMTP host, port, TLS mode, sender, recipients, user; webhook URL **origin** only). `secret`: AES-256-GCM, key = HKDF-SHA256 subkey `notification-channels.v1`, random 96-bit nonce, AAD = `"databastion.notification-channels.v1" ‖ 0x01 ‖ channel id ‖ 0x00 ‖ type`, plaintext = JSON `{"password"}` (SMTP AUTH) or `{"url", "signing_secret"}` (webhook: the full URL is treated as a secret, many embed a token). Never returned by the API, never logged, never in the audit log |
| Notification deliveries (`notification_deliveries`) | the outbox and delivery record: event, channel (id and slug), incident / agent / security event, payload (identifiers, counts, normalized names, console URL: never a sampled value, masked or not), status, attempts, next attempt, last error (closed code, never a server response). The runtime role cannot delete rows nor rewrite the key, subject or payload (migration `0019`) |

Rate limiters, the argon2 concurrency cap and the 25 s verified-secret cache are in-memory, per
process (the known-good fingerprint is in the database): the MVP runs one web process. Several web replicas would need a shared store for the
limiters (the secret cache is already safe across processes, as it is bound to the stored hash).

## Policies and incidents
*P3-A, P3-B. Model and lifecycle: `src/lib/policy-model.ts`, `src/lib/incident-lifecycle.ts`;
engine: `src/server/incidents.ts`; CRUD: `src/server/policies.ts`.*

- **Conditions** (source `finding`; source `access_event`: see "Audit correlation"; every key
  optional, all present keys must hold, the values of a list are alternatives): `classifiers` (registered ids of any classifier set, or families such as
  `pii.*`), `agent_ids`, `target_ids`, `engines`, `location` (`database`, `schema`, `object`,
  `field` globs on the normalized names: `*`, `?`, `\` escape, case-insensitive, matched without
  regular expression in O(n x m) worst case on bounded names and patterns, no exponential
  backtracking), `min_confidence`, `min_match_ratio` (matched / sampled), `min_matched`. Unknown keys are
  rejected. A document is validated against its policy's source (fixed at creation), so existing
  policies keep their meaning.
- **Actions**: exactly one `{"type": "create_incident", "severity": "low|medium|high|critical"}`,
  and up to 5 `{"type": "notify", "channel": "<slug>"}`. Channel references are stored on the policy
  and copied to each incident (`notify_channels`); a new incident is notified to them (see
  "Alerting").
- **Exceptions**: scoped to one policy or to all, by agent, target, classifier (id or family) and / or
  location globs (at least one), with a mandatory reason and an optional expiry. A covered finding
  opens no incident; expired exceptions are listed as expired and ignored. An exception without a
  policy is global: scoped to a classifier family (e.g. `pii.*`) alone, it silences that family for
  every policy and every target. Only administrators create one, and it is audited
  (`policy_exception.create`).
- **Execution** (worker, pg-boss queue `policies.evaluate`, `stately`, no payload): the web process
  sends a wake-up after the commit of an accepted findings batch and after a policy or exception
  change; the worker also schedules it every minute. The work itself is recorded in the tables, so a
  lost or repeated job loses or repeats nothing: a finding is pending while
  `findings.policy_evaluated_at` differs from `last_seen_at` (every rescan, and unmarking a false
  positive, makes it pending); a policy gets a full pass over the existing findings while
  `evaluated_at` is older than `changed_at` (creation, edit of conditions / actions / enablement,
  deletion of one of its exceptions) or than the expiry of one of its exceptions. Findings are
  processed in chunks of 200 per transaction, row-locked (`SKIP LOCKED`: rows held by an ingestion
  are left pending), so an evaluation never races an ingestion or a false-positive marking. An
  incomplete full pass leaves its policy pending without holding back the pending findings. A job
  runs for at most 50 s and re-queues itself when work remains.
- **Dedup**: `dedup_key = policy:<id>|finding:<id>`; a partial unique index allows one open or
  acknowledged incident per key. A later scan of the same finding increments `match_count` once per
  finding revision. **`resolved` means remediated**: when a scan that read the data after the
  resolution still sees the finding, or when the finding matches more values or is reclassified by
  another classifier set, a new incident opens; re-evaluations without a new scan open nothing.
  "Read after the resolution" compares `resolved_at` with the first console-side delivery of the
  scan job that produced the finding's latest revision (`jobs.first_delivered_at`, set when the
  agent first fetches the job and never moved by a redelivery; both from the database clock), not
  with the ingestion time: a scan already in flight when the incident is resolved does not reopen
  it (N1). A finding whose job is gone falls back to its `last_seen_at`. Durable suppression is an administrator
  decision only: a false positive (a false-positive finding never opens an incident) or an
  exception. Incident creation is audited `incident.create` (system actor).
- **Lifecycle**: `open` -> `acknowledged` -> `resolved`, `open` -> `resolved`, `open` /
  `acknowledged` -> `false_positive`; `resolved` and `false_positive` are final. Checked server side
  under row locks taken in the same order as the policy engine and the findings writers (the finding,
  then the incident). `false_positive` is the finding's false-positive decision (admin only, as on
  `/findings`): it marks the finding (with its `matched` / `classifiers_version` snapshot) and closes
  every active incident of it.
- The `audit.configure` confirmation of P3-A is implemented with P4-C (see "Audit correlation").

## Audit correlation
*P4-C. Model: `src/lib/event-model.ts`; ingestion and views: `src/server/events.ts`; engine:
`src/server/event-engine.ts`; settings: `src/server/audit-config.ts`; migrations `0021`, `0022`.*

- **Ingestion** (`POST /api/agent/v1/events`): same pipeline and bounds as `/findings`
  (authentication, 4 MiB body cap `413`, schema then `checkSemantics`: unknown fields such as query
  text, names or account names failing the contract patterns, a batch over 1 MiB (`maxBytes`) and
  `ts_last < ts` (`/events/<i>/ts_last`, `formatMinimum`) are `400`). Then, in one transaction
  serialized per agent: the idempotency check on (`agent_id`, `batch_id`) over the canonical JSON
  (replay `202 duplicate: true`, other content `409 batch_conflict`), target ownership (`404`,
  `/events/<i>/target_id`, `notFound`), timestamps at most 5 min ahead (`/events/<i>/ts` or
  `ts_last`, `formatMaximum`), storage. Rejected batches, conflicts and foreign targets are
  agent-integrity events (endpoint `events`). Events whose `ts` is older than the retention period
  are refused (`400`, `/events/<i>/ts`, `formatMinimum`; possible from a conforming agent with an
  old spool, so counted in `databastion_console_events_expired_total`, not an integrity event).
  Events of a target the agent no longer reports, or whose Audit settings are disabled, are stored
  with `unexpected_target` set (shown in the view, counted in
  `databastion_console_events_unexpected_target_total`). Limits per agent and process: 300
  requests and 60 stored batches (30 000 events) per minute (`429`), and `429` + `Retry-After: 30`
  while the agent has more than 20 000 events not evaluated yet (back-pressure, counted in
  `databastion_console_events_backpressure_total`). An accepted batch wakes the policy worker.
- **Sensitivity** of an object: for each classifier found on it (any column, false positives
  excluded), its weight times the highest confidence, summed, capped at 30. An event's sensitivity
  is that of its most sensitive object; an event object without schema matches the findings of any
  schema. Weights:

  | Classifier | Weight | Classifier | Weight |
  |------------|--------|------------|--------|
  | `secret.aws_key` | 10 | `pii.birth_date` | 3 |
  | `secret.password_hash` | 8 | `pii.email` | 3 |
  | `pii.card_number` | 8 | `pii.phone` | 3 |
  | `pii.iban` | 7 | `pii.postal_address` | 3 |
  | `pii.nir` | 7 | `pii.person_name` | 2 |

  Unlisted ids: 8 for `secret.*`, 2 for `pii.*`, 1 otherwise.
- **Score** = sensitivity x log10(1 + rows), 0 when the source reports no `rows` or no object is
  sensitive. For an event pre-aggregated by the agent, `rows` is the total of the merged events.
- **Baselines** per (agent, target, principal), over the events that report `rows` (never
  `connect` nor `auth_failure`, so failed logins with random account names create none): exponentially
  weighted mean and variance of `ln(1 + rows)`, weight `max(0.05, 1/n)` (the plain mean for the first
  20 events, then about the last 20). Warm after 20 events. A warm baseline flags an event as an
  **anomaly** when `rows >= 1000` and `ln(1 + rows) > mean + max(ln 10, 3 sd)` (ten times the
  typical volume, and three standard deviations). The verdict uses the baseline before the event;
  the event then updates it, capped at that threshold, so one dump does not raise the baseline
  while a lasting change is learnt gradually. The same statistics on `ln(1 + score)` are shown. A
  target keeps at most `DATABASTION_BASELINES_PER_TARGET` baselines (default 10 000, 10 to
  1 000 000): past it, the least recently updated ones are evicted (owner-defined function); new
  principals beyond the cap within one chunk get no baseline. Baselines not updated for longer
  than the retention period are purged.
- **Evaluation** runs first in `policies.evaluate` (before the findings, so an exfiltration never
  waits behind a full pass), within 60 % of the run's time budget; the finding work always runs
  after it. Chunks hold at most 200 events and at most 50 per agent, agents interleaved, so a busy
  agent never delays the others; each agent's events are taken in arrival order (batch, then
  position in the batch). Serialized by an advisory lock. Each event gets its sensitivity, score, anomaly flag and baseline snapshot, then every
  enabled `access_event` policy is applied. A policy applies to the events evaluated after its
  creation or change, never to past ones.
- **Conditions** (source `access_event`; all present keys must hold, the values of a list are
  alternatives; at least one of `signals`, `event_actions`, `principals`, `objects`, `min_rows`,
  `min_score`, `min_sensitivity`, `anomaly`): `signals` (contract ids or families `signature.*`,
  `shape.*`, `volume.*`; the event carries one of them), `event_actions`, `sources`, `agent_ids`,
  `target_ids`, `engines` (of the target), `principals` and `exclude_principals` (globs on the
  account name, or on the fingerprint sent in its place), `objects` (`database`, `schema`,
  `object` globs; one object of the event matches), `min_rows`, `min_score`, `min_sensitivity`,
  `anomaly: true`. Exceptions apply by agent, target and location (`database` / `schema` /
  `object` globs covering every retained object); a classifier-scoped exception never covers an
  event. Signals are the agent's (P4-A emits `signature.pg_dump`, `signature.copy_to_file`,
  `signature.copy_to_program`, `shape.full_table_copy`, `shape.full_table_read`,
  `volume.large_result`; any contract-valid id is accepted). The console's own baseline verdict
  is the `anomaly` condition, not a signal.
- **Dedup**: `dedup_key = policy:<id>|agent:<id>|target:<id>|principal:<key>|database:<sha256 of the name, or ->|hour:<UTC hour of the event ts>`.
  For an unknown account (a fingerprint sent instead of the name) and for every `auth_failure`,
  the principal part is `unknown:<sha256 of client_addr>`: all such events from one client count
  as one principal, so random account names cannot open one incident each. The database is that
  of the most sensitive retained object. While the incident of a key is open or acknowledged,
  later events of the key are added to it (`match_count`, total rows, highest score, signals,
  anomaly, and a link in `incident_events`). Once it is a **false positive**, the rest of that hour
  is only linked to it. Once it is **resolved**, a later event of the hour opens a new incident
  (`reopened_from` in the notification) only when it is worse: a higher score, above the baseline
  while the incident was not, or a signal the incident did not have; otherwise it is linked to the
  resolved incident. The next hour opens a new incident. A `pg_dump` (one event per table) thus
  raises one incident per policy, principal, database and hour.
- **Cap**: a policy opens at most `DATABASTION_EVENT_INCIDENTS_PER_POLICY_HOUR` new incidents per
  clock hour (default 50, 1 to 10 000). Beyond, the matches of the hour go to one **overflow**
  incident of the policy (no agent, target or principal; `event_overflow` set; `match_count` and the
  links count them), notified once, so a flood cannot bury the other incidents. Incident creation is audited
  (`incident.create`, source `access_event`) and notified through the outbox: `incident.opened`
  with `source: "access_event"`, the principal, database, hour and the first event's action,
  source, rows, score, sensitivity, anomaly flag, signals and objects (no value).
- **Promptness** (phase 4 exit criterion, incident in < 2 min): the accepted batch wakes the worker
  (polling every 2 s); a lost wake-up is caught up by the one-minute schedule.
- **Retention**: `events.purge` (hourly, and at worker start) deletes the events whose `ts` is older
  than `DATABASTION_EVENTS_RETENTION_DAYS` (default 90) through the owner-defined purge function,
  10 000 at a time within a 50 s budget, never an event not evaluated yet. The events batches
  (replay records) are kept 30 days longer, so a late replay is still recognized. Baselines idle
  for longer than the retention are purged too. Incidents keep their counts; their event list
  shows what is left.
- **Audit settings** (`audit.configure`, admin): enabled, aggregation window, polling interval,
  `min_rows`, sensitive objects derived from the findings (objects with a finding that is not a
  false positive, with their classifiers) and / or added by hand; at most 1000 objects, manual
  ones first, then the most sensitive. The console validates the contract `AuditConfigureParams`,
  cancels the pending settings jobs of the target and queues the job. A change that **disables**
  Audit, **empties** `sensitive_objects`, or **shrinks** it by at least 20 objects or at least 50 %
  of those sent last time needs a confirmation of the exact settings (a digest: if the findings
  change in between, confirm again), is audited, and leaves a warning on the target until a later
  change that does not narrow Audit. The first configuration of a target never warns.

## Alerting
*P3-C. Channels: `src/server/channels.ts`, `src/server/channel-secrets.ts`; outbox and delivery:
`src/server/notifications.ts`; senders: `src/server/senders/`; address policy:
`src/server/net-guard.ts`; silent agents and integrity alerts: `src/server/system-alerts.ts`;
contents: `src/lib/notification-render.ts`.*

- **Channels** (admin only, CSRF, audited without secrets), referenced by `slug` from the policies'
  `notify` actions:
  - `email`: SMTP host, port, TLS mode, sender, 1 to 20 recipients, optional SMTP AUTH user and
    password. `starttls` requires the server to offer STARTTLS (never a silent downgrade),
    `implicit` is TLS from the first byte, `none` is accepted only towards a loopback relay
    (`localhost`, `127.0.0.0/8`, `::1`) or with `DATABASTION_ALERTING_INSECURE_DEV=1`; AUTH (PLAIN or
    LOGIN) only over TLS (same exceptions). Certificates are always verified.
  - `webhook`: `https://` URL only (`http://` with the dev flag), no credentials, no fragment. The
    console generates a 256-bit signing secret (`whsec_…`), returned once on creation or rotation.
  - `system_alerts`: the channel also receives the console alerts below.
- **Unknown or disabled channel**: the incident is always created; the delivery for that slug is
  recorded as `skipped` (`unknown_channel` / `channel_disabled`) and shown on the incident page. A
  channel created later does not receive past incidents. The policy page and form warn about such
  names; the API accepts them (policies may be written before their channels).
- **Events and payload**: `incident.opened` (a new incident, `incident.reopened_from` set when it
  follows a resolved one for the same policy and finding), `agent.silent`, `agent.recovered`,
  `agent.integrity`, `channel.test`, `notifications.suppressed`. Payload: event, time, console URL, incident id, severity, status,
  policy id / name / revision, agent and target ids, classifier and classifier set, normalized
  location (engine, database, schema, object, field), counts (sampled, matched, confidence), and
  `source: "finding"` (absent in rows written before P4-C). An incident raised from access events
  has `source: "access_event"` and, instead of the classifier, location and counts: `principal`,
  `principal_fingerprinted`, `database`, `hour` and `access` (the first event's `ts`, action,
  source, rows, score, sensitivity, anomaly flag, signals and objects); receivers should switch on
  `source`. **Never a sampled value, masked or not** (I2); the masked samples stay encrypted on the
  finding, and access events carry none.
- **Webhook**: `POST` of `{"version": 1, "delivery_id", ...payload}` with `Content-Type:
  application/json`, `X-DataBastion-Event`, `X-DataBastion-Delivery` (stable across retries: the
  receiver deduplicates on it) and `X-DataBastion-Signature: t=<unix seconds>,v1=<hex>`, where `v1` =
  HMAC-SHA256 keyed with the UTF-8 bytes of the signing secret over `"<t>.<raw body>"`. `t` is the
  time of the attempt: receivers recompute the MAC, compare in constant time and reject `t` older than
  5 minutes (replay protection); `verifyWebhookSignature` in `src/server/senders/webhook.ts` is the
  reference. 2xx = delivered; redirects are never followed (3xx fails); 408, 425, 429, 5xx, network
  and TLS errors are retried; other 4xx fail. 5 s to connect, 15 s in total, response read up to 64 KiB
  and discarded.
- **E-mail**: plain text, UTF-8 (base64 body, RFC 2047 subject), `Message-ID` derived from the
  delivery id, `Auto-Submitted: auto-generated`. 10 s to connect, 30 s per reply, 60 s in total. A 4xx
  reply or a network / TLS error is retried; a 5xx reply fails.
- **SSRF defense** (webhooks; outbound connections are made by the worker only): the host is resolved
  and **every** address checked; the socket connects to the vetted addresses only (no second
  resolution, so no DNS rebinding), in the resolver's order with a fallback to the next one on a
  connection error (happy eyeballs, so an unreachable IPv6 address does not fail a dual-stack
  destination); TLS is always verified against the host name. Always refused: unspecified (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16`,
  `fe80::/10`, including the metadata endpoints `169.254.169.254`, `fd00:ec2::254`), multicast,
  broadcast, reserved. Refused unless `DATABASTION_ALERTING_INSECURE_DEV=1`: loopback, RFC 1918, CGNAT,
  ULA, documentation / benchmark ranges and the IPv6 prefixes embedding an IPv4 address (NAT64,
  6to4, Teredo). IPv4-mapped IPv6 addresses are checked as IPv4. SMTP relays may be internal
  (loopback and private allowed), never link-local / metadata. No HTTP proxy is used.
- **Delivery** (transactional outbox, `notification_deliveries`): rows are written in the same
  transaction as the incident (policy engine) or the alert, one per (subject, event, channel) with a
  unique idempotency key, so retried or concurrent evaluations never notify twice. The worker queue
  `notifications.deliver` (pg-boss, `stately`, no payload: the outbox is the work) is woken after
  new incidents, integrity events and tests, and scheduled every minute. Due rows are claimed with
  `FOR UPDATE SKIP LOCKED` and a 2-minute lease (a crashed worker's attempt is claimed again), sent
  outside any transaction, 10 in parallel, and recorded: `delivered`; `pending` again after 1, 2, 4,
  8, 16, 32 then 60 minutes; `failed` after 8 attempts or on a permanent error; `skipped` for a
  disabled channel. At least once: a crash after sending and before recording sends again (same
  delivery id). `last_error` is a closed code (`http_503`, `smtp_550`, `address_internal`,
  `tls_failed`, …), never the response text, a host or a URL; logs carry the delivery id, event,
  channel slug and code only. A deleted channel fails its pending deliveries (`channel_deleted`);
  a secret that no longer decrypts (server key changed) is retried as `secret_unavailable`.
- **Silent agent**: an agent that was online (at least one heartbeat), is neither revoked nor locked,
  and has sent no heartbeat for `DATABASTION_SILENT_AGENT_INTERVALS` x 30 s (default 5 minutes;
  the Agents page already shows "silent" after 90 s) raises one alert per silence episode
  (`agents.silence_alerted_for` = the `last_seen_at` of the alerted episode, set by a conditional
  update, so concurrent workers alert once): a `security_events` row `agent.silent` (`medium`), an
  audit entry (system) and a notification to the system-alert channels. The next heartbeat ends the
  episode: audit `agent.recovered` and a recovery notice to the same channels; a later silence is a
  new episode. The check runs every minute in the worker; no new silence alert is raised during the
  first threshold after the worker starts, so a console outage (no heartbeat could be received) does
  not become one alert per agent. It is recorded in `security_events`, not `incidents`: incidents are
  what policies raise (policy snapshot, dedup key, lifecycle column grants, ADR-0014), while agent
  health is an integrity signal that must not be erasable by the runtime role. Limitation: an outage
  of the web process alone (worker up) makes every agent silent after the threshold.
- **Volume limit** (L6): at most `DATABASTION_NOTIFY_MAX_PER_HOUR` (default 30) incident
  notifications per channel and clock hour (a soft limit: concurrent evaluations may overshoot by a
  few). Beyond, the delivery is recorded as `skipped` (`rate_limited`, visible on the incident) and,
  once the hour is over, one `notifications.suppressed` digest per channel and hour reports how many
  were suppressed (counts only, link to the incidents list). System alerts, tests and digests are
  not counted.
- **Hardening (security review)**: moving an e-mail channel with a stored password to another host,
  port, TLS mode or user requires the password again (`400 password_required`); SMTP ports 25, 465,
  587 and 2525 only (any port with the dev flag); SMTP replies capped at 100 lines / 64 KiB; any
  byte received in clear after the STARTTLS `220` aborts the session; the upgraded certificate is
  verified against the configured host; channel tests are limited to 10 per administrator and 3 per
  channel per 10 minutes (`429`), and report refused and filtered connections alike
  (`connect_failed`).
- **Agent-integrity alerts**: every `security_events` row written by the console
  (`agent.rotation_conflict`, `agent.batch_rejected`, `agent.batch_conflict`,
  `agent.foreign_target`) is notified to the system-alert channels, at most once per agent, kind
  and hour per channel (the events themselves are all recorded, within their own budget).

## Layout
```
drizzle/                  versioned SQL migrations (generated, never edited by hand)
scripts/protocol/         protocol code generator (`pnpm protocol:generate`)
src/app/                  Next.js App Router (UI + API routes)
src/app/api/agent/v1/     agent API routes (thin, logic in src/server/agent-api/)
src/app/api/{auth,agents,enrollment-tokens,findings,policies,policy-exceptions,incidents,notification-channels}/
                          user API routes (logic in src/server/user-api.ts)
src/app/(console)/, src/app/login/  UI pages (server components)
src/app/metrics/          Prometheus endpoint on the main port (logic in src/server/metrics.ts;
                          dedicated listener: src/server/metrics-listener.ts)
src/components/           UI components (ui/: shadcn-style primitives, console/: pages' parts)
src/proxy.ts              per-request CSP nonce for UI pages
docker/                   image entrypoint and healthcheck
src/cli/                  admin bootstrap command
src/server/               auth, audit log, enrollment, agents, jobs, rotation, metrics, rate limiting,
                          policies, incidents, notification channels and outbox
src/server/senders/       SMTP and webhook senders (worker only)
src/test/                 test harness (throwaway PostgreSQL cluster, fixture helpers)
src/config/               configuration loading (NAME / NAME_FILE)
src/db/                   Drizzle schema, client, migrator
src/generated/protocol/   types + JSON Schema bundle generated from shared/protocol/ (never edited)
src/lib/                  logger (pino, JSON on stdout), shadcn/ui helpers,
                          protocol/validate.ts (agent API body validator)
src/worker/               pg-boss worker entrypoint and queue handlers
```

## Conventions
- TypeScript `strict` + `noUncheckedIndexedAccess`; no unjustified `any`.
- Logs are structured JSON on stdout; never log secrets, connection strings or
  agent-provided samples.
- Database schema changes only through `pnpm db:generate` + a committed migration.
- UI components: shadcn/ui (`pnpm dlx shadcn@latest add <component>`), configured in
  `components.json`.
