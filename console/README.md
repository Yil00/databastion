# DataBastion console

Control plane of DataBastion: a Next.js (App Router) application serving the UI,
the user API and the agent API, plus a `worker` process running background jobs
with pg-boss. Both processes share this codebase and the internal PostgreSQL
database (also used as the job queue: no Redis). See
[docs/02-architecture.md](../docs/02-architecture.md) and
[docs/03-tech-stack.md](../docs/03-tech-stack.md).

> Status: phase 1 backend (ROADMAP P1-A part 1): database schema, local auth, console audit
> log, enrollment tokens, agent API `/enroll`, `/heartbeat`, `/jobs` (long-poll),
> `/jobs/{job_id}/status`. No UI page yet.

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
| `DATABASTION_INSECURE_COOKIES=1` | Drop `Secure` / `__Host-` from the session cookie in production (plain-HTTP test setups only; warned at startup) |
| `DATABASTION_BOOTSTRAP_ADMIN_USERNAME` | `pnpm admin:bootstrap` only: login of the first administrator |
| `DATABASTION_BOOTSTRAP_ADMIN_PASSWORD` / `_FILE` | `pnpm admin:bootstrap` only: its password (12 to 1024 characters) |
| `TEST_DATABASE_URL`, `PG_BIN` | Tests only: an existing admin URL, or the PostgreSQL binaries used to start a throwaway cluster (default `/usr/lib/postgresql/16/bin`) |

`DATABASTION_ENCRYPTION_KEY(_FILE)` from
[deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml) is not
used yet (see "Data at rest"). The console only knows its own database: it never stores target
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
| `pnpm db:generate --custom --name <slug>` | Empty versioned migration for SQL drizzle-kit cannot express (triggers); used only for `0002_audit_log_append_only.sql` |
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
| `databastion_runtime` (LOGIN), member of `databastion_app` (NOLOGIN) | web + worker via `DATABASE_URL(_FILE)` | Not superuser, not owner. `SELECT, INSERT, UPDATE, DELETE` on the console tables, only `SELECT, INSERT` on `audit_log`, `USAGE, CREATE` on schema `pgboss` (pg-boss tables). **No** `CREATE` on the database (no new schemas) nor on `public` |

Grants come from migrations `0003_runtime_role_grants.sql` and `0004_pgboss_schema_hardening.sql`
(custom, every name schema-qualified). The roles and passwords are created outside migrations (the
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
| `/api/agent/v1/*` | Agent API (see [its README](src/app/api/agent/v1/README.md)); `/findings`, `/events`, `/rotate` still `501` |
| `POST /api/auth/login` | `{username, password}` → session cookie + `{user, csrf_token}`; failed logins rate limited per IP and per username |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/auth/session` | Current user + CSRF token |
| `GET` / `POST /api/enrollment-tokens` | List / create (admin). The `dbe_…` token is returned once, only its SHA-256 is stored; valid 24 h |
| `DELETE /api/enrollment-tokens/{id}` | Revoke an unused token (admin) |
| `GET /api/agents` | Agents and their reported targets (audit level, reachability) |
| `POST /api/agents/{id}/revoke` | Revoke an agent (admin): secrets unusable immediately, held long-polls closed, pending jobs cancelled |

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
exceed the limits. Logins and agent authentications use separate argon2id pools (4 and 8 concurrent
verifications per process, `503` + `Retry-After` beyond), plus a pool reserved for agents
presenting their last verified secret, so a login flood can never block agents. Failed logins on
unknown usernames share a process-wide budget (30 per minute). Per-IP limits bucket IPv6
addresses by /64.

## Data at rest
| Data | Storage |
|------|---------|
| User passwords, agent secrets (current / pending / previous) | argon2id (`@node-rs/argon2`, m = 19 MiB, t = 2, p = 1) |
| Enrollment tokens, session tokens | SHA-256 only (256-bit random values) |
| Database credentials, connection strings | never received nor stored (invariant I3) |
| Agent-reported metadata (hostname, versions, target ids, audit levels, metrics) | plain columns, bounded by the protocol schema, escaped on display |
| Masked samples (P2-D), webhook / SMTP settings (later) | AES-256-GCM with `DATABASTION_ENCRYPTION_KEY`, introduced with the first such column |

Rate limiters, the argon2 concurrency cap and the verified-secret cache are in-memory, per
process: the MVP runs one web process. Several web replicas would need a shared store for the
limiters (the secret cache is already safe across processes, as it is bound to the stored hash).

## Layout
```
drizzle/                  versioned SQL migrations (generated, never edited by hand)
scripts/protocol/         protocol code generator (`pnpm protocol:generate`)
src/app/                  Next.js App Router (UI + API routes)
src/app/api/agent/v1/     agent API routes (thin, logic in src/server/agent-api/)
src/app/api/{auth,agents,enrollment-tokens}/  user API routes (logic in src/server/user-api.ts)
src/cli/                  admin bootstrap command
src/server/               auth, audit log, enrollment, agents, jobs, rate limiting
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
