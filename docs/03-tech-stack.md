# Tech stack – DataBastion MVP

## Console (Control Plane)
| Component | Technology | Comment |
|-----------|-------------|-------------|
| Frontend + Backend | Next.js 16 (App Router) + React 19, strict TypeScript 5.9 | Inspired by Portabase |
| UI | Tailwind CSS 4 + shadcn/ui | |
| Internal database | PostgreSQL 17 | Also used as the job queue |
| ORM / migrations | **Drizzle** (`drizzle-orm` 0.45, `drizzle-kit` 0.31) | Close to SQL, versioned SQL migrations |
| Jobs / worker | **pg-boss** 12 | Job queue on PostgreSQL, no Redis |
| Logs | pino 10 | JSON on stdout |
| Tests | vitest | |
| Lint | ESLint 9 (`eslint-config-next`) | Stays on ESLint 9: `eslint-plugin-react` 7.37, pulled in by `eslint-config-next`, does not support ESLint 10 |
| Authentication | Local + OIDC | SAML / SCIM → Enterprise (see [EDITIONS.md](EDITIONS.md)) |
| Package manager | pnpm 10 (pinned by `packageManager`) | Node.js 24 in CI |
| Packaging | Single Docker image (`web` and `worker` = two commands) | |
| Health endpoints | `GET /api/health` (liveness, no database access), `GET /api/health/ready` (readiness, checks the database) | |

Exact versions are pinned in `console/package.json` and `console/pnpm-lock.yaml`; this table gives the major versions only.

## Agent (Data Plane)
| Component | Technology | Comment |
|-----------|-------------|-------------|
| Language | **Rust** (stable, edition 2024, MSRV 1.85) | Lightweight, safe, static binary |
| Async runtime | tokio | |
| CLI / logs | clap, `tracing` + `tracing-subscriber` (JSON) | |
| PostgreSQL + MySQL/MariaDB | sqlx | Not added yet (P2) |
| MongoDB | official `mongodb` crate | Not added yet (phase 5) |
| OpenLDAP | `ldap3` | Not added yet (phase 6) |
| HTTP client | reqwest + rustls | Not added yet (P1-B). No OpenSSL → portable binary; OpenSSL / native-tls are banned by `agent/deny.toml` |
| Packaging | Distroless Docker image + `.deb` | |
| Architectures | x86_64 + arm64 | |

A single binary, `databastion-agent`, with connectors enabled through Cargo *features* (`postgres`, `mysql`, `mongodb`, `openldap`, all on by default) ([ADR-0002](adr/0002-single-agent-connectors.md)). Every crate is named with the `databastion-` prefix.

## Protocol & shared contract
- **Source of truth**: `shared/protocol/openapi.yaml` (OpenAPI 3.1 + JSON Schema)
- Generated types: TypeScript (console) and Rust (agent). **No hand-written protocol types.**
- Versioning: URL prefix `/api/agent/v1`, `X-DataBastion-Protocol` header

## Transport security
- TLS 1.3 mandatory (terminated by the reverse proxy in front of the console)
- No more application-level AES-GCM encryption of payloads: it is redundant with TLS as long as the key lives on the console. The real protection is data minimization at the source ([ADR-0003](adr/0003-data-minimization-at-source.md)).
- Encryption **at rest** of the console's sensitive fields (masked samples, webhook secrets) with a key provided via Docker secret

## Observability
- Console: `/metrics` endpoint in Prometheus format (internal network, authenticated), which aggregates the agent metrics received via heartbeat
- Agent: **no port exposed by default**. Option `metrics.local_listen: 127.0.0.1:9464`, disabled by default, for local debugging.
- Logs: structured JSON on stdout (console and agent)

## Deployment
- **Docker Compose** → MVP and small installations ([deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml))
- **Helm** → phase 2

## Repository structure
```
databastion/
├── console/            # Next.js (web + worker), package @databastion/console
│   ├── drizzle/        #   versioned SQL migrations
│   └── src/            #   app/ (UI + API routes), db/, worker/, config/, lib/
├── agent/              # Cargo workspace, crates prefixed databastion-
│   ├── crates/agent/   #   binary databastion-agent
│   ├── crates/core/
│   ├── crates/classifiers/
│   ├── crates/connector-postgres/
│   ├── crates/connector-mysql/
│   ├── crates/connector-mongodb/
│   └── crates/connector-openldap/
├── shared/protocol/    # openapi.yaml + JSON Schemas + fixtures (P0-B, not merged yet)
├── deploy/             # docker-compose, later helm/
├── dev/                # dev environment: databases seeded with fake PII (P0-C, not created yet)
├── scripts/            # link check, version bump
└── docs/
```
