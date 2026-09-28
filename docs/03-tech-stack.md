# Tech stack – DataBastion MVP

## Console (Control Plane)
| Component | Technology | Comment |
|-----------|-------------|-------------|
| Frontend + Backend | Next.js (App Router, strict TypeScript) | Inspired by Portabase |
| UI | Tailwind CSS + shadcn/ui | |
| Internal database | PostgreSQL 17 | Also used as the job queue |
| ORM / migrations | **Drizzle** | Close to SQL, versioned SQL migrations |
| Jobs / worker | **pg-boss** | Job queue on PostgreSQL, no Redis |
| Authentication | Local + OIDC | SAML / SCIM → Enterprise (see [EDITIONS.md](EDITIONS.md)) |
| Package manager | pnpm | |
| Packaging | Single Docker image (`web` and `worker` = two commands) | |

## Agent (Data Plane)
| Component | Technology | Comment |
|-----------|-------------|-------------|
| Language | **Rust** (stable) | Lightweight, safe, static binary |
| Async runtime | tokio | |
| PostgreSQL + MySQL/MariaDB | sqlx | |
| MongoDB | official `mongodb` crate | |
| OpenLDAP | `ldap3` | |
| HTTP client | reqwest + rustls | No OpenSSL → portable binary |
| Packaging | Distroless Docker image + `.deb` | |
| Architectures | x86_64 + arm64 | |

A single binary, connectors enabled through Cargo *features* ([ADR-0002](adr/0002-single-agent-connectors.md)).

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

## Repository structure (target)
```
databastion/
├── console/            # Next.js (web + worker)
├── agent/              # Cargo workspace
│   ├── crates/core/
│   ├── crates/classifiers/
│   ├── crates/connector-postgres/
│   ├── crates/connector-mysql/
│   ├── crates/connector-mongodb/
│   └── crates/connector-openldap/
├── shared/protocol/    # openapi.yaml + JSON Schemas + fixtures
├── deploy/             # docker-compose, later helm/
├── dev/                # dev environment: databases seeded with fake PII
└── docs/
```
