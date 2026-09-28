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
> positives.

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
| `DATABASTION_PUBLIC_URL` | Public origin of the console (e.g. `https://console.example.com`). State-changing user requests must come from this origin; unset: the request's own origin |
| `DATABASTION_TRUST_PROXY=1` | One trusted reverse proxy: the last `X-Forwarded-For` entry is the client IP used for per-IP rate limits. **Set it only behind a reverse proxy that sets or overwrites `X-Forwarded-For`** (otherwise clients choose their IP). Unset: the client IP is unknown, per-IP limits are off (per-user / per-agent limits and the argon2 concurrency cap remain), and a warning is logged at startup in production |
| `DATABASTION_TRUSTED_PROXY_HOPS=N` | Same, for N (1 to 10) chained trusted proxies: the N-th `X-Forwarded-For` entry from the right is used. Takes precedence over `DATABASTION_TRUST_PROXY`. When the selected entry is missing or not an IP, a warning is logged (at most once a minute) |
| `DATABASTION_METRICS_TOKEN` / `_FILE` | Bearer token required by `GET /metrics` (at least 32 characters, e.g. `openssl rand -base64 32`). Unset or too short: `/metrics` answers `404`. See "Metrics" |
| `DATABASTION_METRICS_PORT` | Serve `GET /metrics` on a dedicated listener on this port (e.g. `9464`) instead of the main port, which then answers `404` on `/metrics`. Unset: no dedicated listener, `/metrics` stays on the main port (a startup warning is logged in production when the token is set). Must differ from `PORT`. See "Metrics" |
| `DATABASTION_METRICS_HOST` | Bind address (IP literal) of that listener: `127.0.0.1` by default; `0.0.0.0` inside a container whose metrics port is not published. Invalid port / host: `/metrics` is disabled everywhere and an error is logged |
| `DATABASTION_INSECURE_COOKIES=1` | Drop `Secure` / `__Host-` from the session cookie in production (plain-HTTP test setups only; warned at startup) |
| `DATABASTION_BOOTSTRAP_ADMIN_USERNAME` | `pnpm admin:bootstrap` only: login of the first administrator |
| `DATABASTION_BOOTSTRAP_ADMIN_PASSWORD` / `_FILE` | `pnpm admin:bootstrap` only: its password (12 to 1024 characters) |
| `TEST_DATABASE_URL`, `PG_BIN` | Tests only: an existing admin URL, or the PostgreSQL binaries used to start a throwaway cluster (default `/usr/lib/postgresql/16/bin`) |

`DATABASTION_ENCRYPTION_KEY(_FILE)` from
[deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml) (at least 32 characters,
e.g. `openssl rand -base64 32`) is the console server key of the web process. It keys the agent "known good" fingerprints (HKDF-SHA256
subkey, domain `agent-known-good.v1`, see "Data at rest") and the login device cookies (domain
`login-device.v1`, see "Brute-force protection") and encrypts masked samples at rest (domain
`masked-samples.v1`, see "Data at rest"). **Set it in production: the shared-IP protection
of agents (P1-D M1) and the device-cookie protection of logins (N1) require it.** Unset, too short
or unreadable: fingerprints and device cookies are neither issued nor accepted (fail closed: agents
lose the lock-out exemption, so agents behind a shared NAT / proxy IP can be blocked by floods from
it, and a distributed guessing attack on a username can keep its user out), and in production the
web process logs an **error** at startup naming those disabled protections (it still starts). Changing it
invalidates the stored fingerprints. The console only knows its own database: it never stores target
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
| `databastion_runtime` (LOGIN), member of `databastion_app` (NOLOGIN) | web + worker via `DATABASE_URL(_FILE)` | Not superuser, not owner. `SELECT, INSERT, UPDATE, DELETE` on the console tables, only `SELECT, INSERT` on `audit_log`, only `SELECT, INSERT` and `UPDATE (acknowledged_at, acknowledged_by)` on `security_events` (no `DELETE`: an integrity alert cannot be erased or rewritten), `USAGE, CREATE` on schema `pgboss` (pg-boss tables). **No** `CREATE` on the database (no new schemas) nor on `public` |

Grants come from migrations `0003_runtime_role_grants.sql`, `0004_pgboss_schema_hardening.sql` and
`0010_security_events_no_delete.sql` (custom, every name schema-qualified). Migration
`0009_pgboss_owner_guard.sql` refuses to run (the whole `migrate` run is rolled back) when schema
`pgboss` exists and is owned by a role other than the migration role: fix the ownership as the
superuser (`ALTER SCHEMA pgboss OWNER TO databastion_owner`, after checking the schema for planted
objects), then run `migrate` again. The roles and passwords are created outside migrations (the
owner has no `CREATEROLE`); with the example compose file,
[deploy/initdb/10-databastion-roles.sh](../deploy/initdb/10-databastion-roles.sh) does it at the
first database initialization, reading the passwords from the Docker secret files inside psql
(never on a command line). The worker runs pg-boss with `schema: 'pgboss'`, `createSchema: false`.

At startup, the web and worker processes log a warning if their database role is a superuser or
owns `audit_log`.

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
| `/api/agent/v1/*` | Agent API (see [its README](src/app/api/agent/v1/README.md)); `/events` still `501` (phase 4) |
| `GET /metrics` | Prometheus text format, bearer token (see "Metrics"); on the dedicated listener when `DATABASTION_METRICS_PORT` is set; internal network only |
| `POST /api/auth/login` | `{username, password}` → session cookie + `{user, csrf_token}`; failed logins rate limited per IP, per username + IP, and per username (slow-down, never a lock-out; see "Brute-force protection") |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/auth/session` | Current user + CSRF token |
| `GET` / `POST /api/enrollment-tokens` | List / create (admin). The `dbe_…` token is returned once, only its SHA-256 is stored; valid 24 h |
| `DELETE /api/enrollment-tokens/{id}` | Revoke an unused token (admin) |
| `GET /api/agents` | Agents and their reported targets (audit level, reachability) |
| `POST /api/agents/{id}/revoke` | Revoke an agent (admin): secrets unusable immediately, held long-polls closed, pending jobs cancelled |
| `POST /api/agents/{id}/rotate` | Queue an `agent.rotate_secret` job (admin, `202 {job_id}`); `409` while a secret is pending, within 60 s of a promotion, or while another rotate job is open (ADR-0010) |
| `POST /api/agents/{id}/targets/{target_id}/scan` | Queue a `discovery.scan` job (admin, `202 {job_id}`, audited `discovery.scan_request`). Body: contract `DiscoveryScanParams`, every key optional (defaults `sample_rows` 200, `max_duration_s` 900, `statement_timeout_ms` 30000); unknown keys, out-of-range values and empty include filters: `400 invalid_params`. `404` unknown / inactive agent or target not currently reported; `409 agent_not_ready` (no `classifiers_version` reported yet), `409 scan_in_progress` (a scan of the target is pending, delivered or running). Expires after 6 h |
| `POST /api/findings/{id}/false-positive` | `{"false_positive": true\|false}` (any authenticated user, CSRF, audited `finding.false_positive`); `204`, `404` unknown finding |

UI pages (server components; data read server-side, only the user and the CSRF token reach the
browser): `/login`, `/agents` (name, hostname, version, status online / silent (no heartbeat for
90 s) / revoked / locked, last seen, targets with audit level), `/agents/{id}` (targets; admin:
"Rotate secret" and "Revoke" with confirmation dialogs), `/enrollment-tokens` (admin: create, the
`dbe_…` token is shown once with a copy button; list; revoke), `/findings` (counts per target and
classifier, then one row per location with its masked samples decrypted server side; filters
`?agent=&target=&classifier=`, false positives hidden unless `fp=1`; "False positive" toggle per
row). The agent detail page shows the last scan of each target, a link to its findings and (admin)
a "Scan" dialog. Agent-reported strings are rendered
as React text nodes only (no `dangerouslySetInnerHTML` anywhere). UI components follow shadcn/ui
(new-york) in `src/components/ui/`, written without Radix / `class-variance-authority` (the
confirmation dialog uses the native `<dialog>` element).

### Security headers
- UI pages: `Content-Security-Policy` with a per-request nonce set by `src/proxy.ts`
  (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `style-src 'self' 'nonce-…'`, `object-src 'none'`,
  `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`; `'unsafe-eval'` in `next dev`
  only). Every page is rendered per request (root layout `force-dynamic`), so no prerendered page
  lacks the nonce. Not applied to `/api/*` and `/metrics` (no HTML). UI pages also get
  `Cache-Control: no-store` (the findings view carries decrypted masked samples).
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
  everyone: reaching it never answers `429`, the username degrades like below (N2);
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
password, and stays subject to the per-(username, IP) limit, a limit of 5 failures per cookie
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

`security_events` is a placeholder for the incident model of phase 3 (agent-integrity alerts):
`agent.rotation_conflict` (`critical`), and since P2-D `agent.batch_rejected` (a `400` on
`/findings`), `agent.batch_conflict` and `agent.foreign_target` (a finding for a target the agent
never reported), all `high`, each with an audit-log entry of the same name. Their details are the
endpoint, the status and the first error `{pointer, keyword}` only. At most 20 are written per agent
per 10 minutes; beyond, they are counted and logged once per window.

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
| Masked samples (`findings.masked_samples`) | AES-256-GCM, key = HKDF-SHA256 subkey `masked-samples.v1` of `DATABASTION_ENCRYPTION_KEY`, random 96-bit nonce, AAD = label + finding id; layout `0x01 ‖ nonce ‖ ciphertext ‖ tag`. Without a usable key no sample is stored (the finding is); a key change makes stored samples "unavailable" in the view until the next scan |
| HMAC fingerprints (`findings.fingerprints`) | as sent by the agent (keyed by its local key, which never leaves it) |
| Findings batches (`findings_batches`) | `(agent_id, batch_id)`, SHA-256 of the validated batch, job, item count: idempotency only, never the body |
| Enrollment tokens, session tokens | SHA-256 only (256-bit random values) |
| Database credentials, connection strings | never received nor stored (invariant I3) |
| Agent-reported metadata (hostname, versions, target ids, audit levels, metrics) | plain columns, bounded by the protocol schema, escaped on display |
| Webhook / SMTP settings (later) | AES-256-GCM with a subkey of `DATABASTION_ENCRYPTION_KEY`, like masked samples |

Rate limiters, the argon2 concurrency cap and the 25 s verified-secret cache are in-memory, per
process (the known-good fingerprint is in the database): the MVP runs one web process. Several web replicas would need a shared store for the
limiters (the secret cache is already safe across processes, as it is bound to the stored hash).

## Layout
```
drizzle/                  versioned SQL migrations (generated, never edited by hand)
scripts/protocol/         protocol code generator (`pnpm protocol:generate`)
src/app/                  Next.js App Router (UI + API routes)
src/app/api/agent/v1/     agent API routes (thin, logic in src/server/agent-api/)
src/app/api/{auth,agents,enrollment-tokens}/  user API routes (logic in src/server/user-api.ts)
src/app/(console)/, src/app/login/  UI pages (server components)
src/app/metrics/          Prometheus endpoint on the main port (logic in src/server/metrics.ts;
                          dedicated listener: src/server/metrics-listener.ts)
src/components/           UI components (ui/: shadcn-style primitives, console/: pages' parts)
src/proxy.ts              per-request CSP nonce for UI pages
docker/                   image entrypoint and healthcheck
src/cli/                  admin bootstrap command
src/server/               auth, audit log, enrollment, agents, jobs, rotation, metrics, rate limiting
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
