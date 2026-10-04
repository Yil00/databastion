# DataBastion – Project summary (MVP)

## Vision
**DataBastion** is an open-source **Data Loss Prevention (DLP)** platform dedicated to open-source databases and directories.

It detects, audits and (eventually) prevents leaks of sensitive data **as close to the source as possible**:
- PostgreSQL
- MySQL / MariaDB
- MongoDB
- OpenLDAP
- CAS (Central Authentication Service) — *planned after the MVP, ROADMAP phase 8*
- Microsoft SQL Server, Redis, Valkey, SQLite and Firebird — *planned, ROADMAP phases 9 and 10 ([ADR-0039](adr/0039-engine-scope-expansion.md)); not supported yet*

## Problem addressed
Traditional DLPs monitor workstations, email or the network. They do not know **where** sensitive data lives in databases, nor **who** is extracting it in bulk (`pg_dump`, `mysqldump`, `mongoexport`, LDIF exports, `SELECT *` on a customer table…). DataBastion answers these two questions:
1. **Where is my sensitive data?** → *Discovery* (data classification)
2. **Who is accessing it abnormally?** → *Audit* (monitoring of accesses and exports)

## Main objectives
- Protect data as close to the source as possible (databases and directories)
- Simple, secure architecture, deployable with Docker in under 15 minutes
- **Linux**-only MVP (Ubuntu, Debian and derivatives)
- Modern web interface for policies, findings and incidents

## Architecture principles
Inspired by **Portabase** (*outbound* agents) and by the *agent / collector* split popularized by Prometheus — but **without** its *pull* model (see [ADR-0004](adr/0004-observability-via-console.md)):

- **Central Console** (Control Plane): web interface, policies, storage of findings and incidents, alerting
- **Lightweight Agent** (Data Plane): a single binary with per-engine *connectors*, deployed as close to the databases as possible
- **Outbound-only**: agents initiate all communications; the console **never** contacts the agents → no inbound port on the database side
- **Data minimization at the source**: no raw sensitive value leaves the agent; database credentials never leave the agent
- Everything runs in Docker (or as a `.deb` package for the agent)

## MVP scope (Linux only)
Full details: [04-mvp-scope.md](04-mvp-scope.md).

### Included
- Web console (Next.js)
- Agent with PostgreSQL, MySQL/MariaDB, MongoDB, OpenLDAP connectors
- **Discovery** and **Audit** modes (audit level depends on the engine edition, see [08-engine-capabilities.md](08-engine-capabilities.md))
- Simple policies, findings, incidents, basic alerting (email, webhook)
- Docker Compose deployment

### Deliberately excluded
- Windows / macOS / iOS
- Endpoint agents on user workstations
- Real-time Prevention mode: blocking is Enterprise; the Community edition plans recommended actions and response hooks only ([ADR-0040](adr/0040-prevention-mode-scope.md), ROADMAP phase 12)
- CAS (ROADMAP phase 8)

## Name
Chosen name: **DataBastion**. History of candidates: [06-project-name.md](06-project-name.md).

---
*MVP framing document – September 2026*
