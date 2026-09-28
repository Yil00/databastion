# DataBastion Architecture – MVP

## Overall diagram

```
                   Prometheus / Grafana (optional)
                              │ scrape (internal console network)
                              ▼
┌──────────────────────────────────────────────────────────┐
│                    DataBastion Console                   │
│                 (Control Plane – Docker)                 │
│                                                          │
│  web     : Next.js UI + user API + agent API             │
│  worker  : correlation, policies, alerting (pg-boss)     │
│  postgres: state, findings, incidents, job queue         │
│                                                          │
│  /metrics : aggregated console + agent metrics           │
└───────────────────────────▲──────────────────────────────┘
                            │ HTTPS 443 (TLS 1.3)
                            │ initiated ONLY by the agents
                            │ long-poll jobs · send results · heartbeat
          ┌─────────────────┼─────────────────┐
          │                 │                 │
┌─────────┴──────┐ ┌────────┴───────┐ ┌───────┴────────┐
│ Agent (host A) │ │ Agent (host B) │ │ Agent (host C) │
│ ─ postgres     │ │ ─ mongodb      │ │ ─ openldap     │
│ ─ mysql        │ │                │ │                │
└───┬────────┬───┘ └───────┬────────┘ └───────┬────────┘
    │        │             │                  │
PostgreSQL MariaDB      MongoDB           OpenLDAP
 (read-only, dedicated account, credentials local to the agent)
```

## Components

### Console
| Process | Role |
|-----------|------|
| `web` | UI, user API, agent API (`/api/agent/v1/*`) |
| `worker` | Same image, different command. Applies policies, correlates events, creates incidents, sends alerts |
| `postgres` | Internal database. Also serves as the job queue (pg-boss) → **no Redis** |

### Agent
A **single Rust binary** ([ADR-0002](adr/0002-single-agent-connectors.md)) made up of:

```
agent
├── core        enrollment, configuration, scheduler, HTTPS uplink, disk spool
├── connectors  postgres · mysql · mongodb · openldap   (Cargo features)
├── classifiers PII / secrets detection (regex + validators: Luhn, IBAN, NIR…)
└── masking     masking + HMAC fingerprints before anything is sent
```

An agent can monitor several targets, of different engines, on the same host.

## Key principles
1. **Outbound-only** ([ADR-0001](adr/0001-transport-https-outbound.md)): the agent opens all connections to the console over HTTPS/443. This gets through corporate proxies and there is no port to open towards the database zone.
2. **Data minimization at the source** ([ADR-0003](adr/0003-data-minimization-at-source.md)): the agent only sends metadata (location, detected type, volume, **masked** sample, HMAC fingerprint). If the console is compromised, no sensitive data and no database credential is exposed.
3. **Database credentials local to the agent**: the console never knows the database passwords.
4. **Declared targets + local detection** ([ADR-0006](adr/0006-target-discovery.md)): no network scanning.
5. **Observability via the console** ([ADR-0004](adr/0004-observability-via-console.md)): agents expose no port; their metrics travel in the heartbeat.

## Agent operating modes
1. **Discovery**: periodic traversal of schemas / collections / entries, sampling, classification. Produces *findings* ("column `clients.email` contains email addresses, confidence 0.97").
2. **Audit**: reading native logs, normalizing them into *access events*, pre-aggregation. The available level depends on the engine and its edition: [08-engine-capabilities.md](08-engine-capabilities.md).
3. **Prevention** (phase 2): proxy or hooks to block certain operations.

**Discovery feeds Audit**: locations classified as sensitive by Discovery are used to weight the accesses observed by Audit. A large volume read from a table with no sensitive data does not carry the same weight as a large volume read from `clients`.

## Exfiltration detection (Audit)
Detecting an export combines three signals, from simplest to most robust:

| Signal | Example | Robustness |
|--------|---------|------------|
| **Signature** | `application_name = 'pg_dump'`, `appName: mongodump`, mysqldump's `SELECT /*!40001 SQL_NO_CACHE */` pattern | Low (spoofable), but useful and cheap |
| **Shape** | `COPY … TO`, sequential read of every table in a schema, LDAP subtree search `(objectClass=*)` from the root | Medium |
| **Volume × sensitivity** | rows returned from locations classified as sensitive, above a per-account baseline | High |

An event's score = f(signals, location sensitivity, deviation from baseline). Policies turn scores into incidents.

## Console ↔ agent communication
Detailed specification: [09-agent-protocol.md](09-agent-protocol.md).

- **Transport**: HTTPS (TLS 1.3), versioned JSON, OpenAPI contract in `shared/protocol/`
- **Responsiveness**: *long-poll* on `GET /jobs` (request held for up to 25 s), which gives near-real-time responsiveness without WebSocket or gRPC
- **Authentication**: single-use enrollment token → agent ID + long secret, stored hashed on the console side, rotatable. mTLS as an option (phase 2).
- **Resilience**: if the console is unreachable, the agent queues to disk (bounded spool) and resends on reconnection.

## Agent deployment modes
| Mode | When |
|------|-------|
| `.deb` package + systemd service on the database host | Databases installed "the old-fashioned way", access to native log files |
| Container in the same Docker network as the database | Containerized databases; logs are mounted read-only |
