# DataBastion console

Control plane of DataBastion: a Next.js (App Router) application serving the UI,
the user API and the agent API, plus a `worker` process running background jobs
with pg-boss. Both processes share this codebase and the internal PostgreSQL
database (also used as the job queue: no Redis). See
[docs/02-architecture.md](../docs/02-architecture.md) and
[docs/03-tech-stack.md](../docs/03-tech-stack.md).

> Status: phase 0 skeleton (ROADMAP P0-D). No business feature and no agent
> endpoint yet.

## Requirements
- Node.js 24 (22.22+ also works for development)
- pnpm, version pinned by `packageManager` in `package.json` (`corepack enable`)
- PostgreSQL 17 for the internal database (the dev environment will provide it)

## Configuration
| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` / `DATABASE_URL_FILE` | Internal PostgreSQL connection string, directly or via a file (Docker secret). Setting both is an error. |
| `LOG_LEVEL` | pino level (`info` by default) |
| `NEXT_OUTPUT_STANDALONE=1` | At build time: produce `.next/standalone` for the Docker image |

`DATABASTION_ENCRYPTION_KEY(_FILE)` and `DATABASTION_PUBLIC_URL` from
[deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml) are not
used yet. The console only knows its own database: it never stores target
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
| `pnpm db:migrate` | Apply pending migrations to `DATABASE_URL(_FILE)` |

The CI runs `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm test` and
`pnpm build` with Node 24.

## HTTP endpoints
| Route | Purpose |
|-------|---------|
| `GET /api/health` | Liveness: `{"status":"ok"}`, never touches the database |
| `GET /api/health/ready` | Readiness: `200 {"status":"ok"}` or `503 {"status":"unavailable"}`; the cause is only logged |
| `/api/agent/v1/*` | Agent API placeholder, `501 not_implemented` (see [its README](src/app/api/agent/v1/README.md)) |

## Layout
```
drizzle/                  versioned SQL migrations (generated, never edited by hand)
scripts/protocol/         protocol code generator (`pnpm protocol:generate`)
src/app/                  Next.js App Router (UI + API routes)
src/app/api/agent/v1/     agent API (placeholder)
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
