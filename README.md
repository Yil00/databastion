<p align="center">
  <img src="docs/assets/logo.jpg" alt="DataBastion" width="140">
</p>

<h1 align="center">DataBastion</h1>

<p align="center">
  <b>Open-source DLP for databases and directories.</b><br>
  Know where your sensitive data lives, and who is extracting it.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://github.com/Yil00/databastion/releases/latest"><img src="https://img.shields.io/github/v/release/Yil00/databastion?sort=semver" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/status-early--stage-orange.svg" alt="Status: early-stage">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey.svg" alt="Platform: Linux">
</p>

> **v0.3.1** (2026-10-04, after v0.3.0 of 2026-10-03: honest PostgreSQL audit levels and 14 engine versions tested weekly), after the first release (MVP) v0.1.0 of 2026-09-30: [release notes and signed artifacts](https://github.com/Yil00/databastion/releases/latest). This is early-stage software: read the known limitations in the [CHANGELOG](CHANGELOG.md) and in [SECURITY.md](SECURITY.md#known-limitations-and-residual-risks) before relying on it. What comes next: [roadmap](docs/ROADMAP.md).

## Why
Traditional DLPs monitor endpoints and the network. They know neither **where** sensitive data sits in your databases, nor **who** is exporting it in bulk (`pg_dump`, `mysqldump`, `mongoexport`, LDIF exports…).

DataBastion sits **as close to the data as possible**:
- **Discovery**: automatically classifies the columns, fields and attributes that contain personal data or secrets.
- **Audit**: uses the engines' native logs to detect abnormal access and exports, weighted by the sensitivity of the data involved.

## Supported databases
| Engine | Discovery | Audit (best level) | Audit source | Versions tested | Notes |
|--------|-----------|--------------------|--------------|--------------|-------|
| PostgreSQL | ✅ | Full with pgaudit and `pgaudit.log_rows = on` (Partial without it); Limited with `pg_stat_statements` only | pgaudit log (`jsonlog` / `csvlog`), `pg_stat_statements` | 14, 15, 16, 17, 18 (**17.11** with pgaudit on every change) | pgaudit `jsonlog` needs PostgreSQL 15+, `csvlog` on 14. 14 is the minimum supported version: end-of-life versions (12, 13) are not supported ([ADR-0039](docs/adr/0039-engine-scope-expansion.md)), and the `pg_stat_statements` Audit mode relies on `pg_stat_statements_info` (PostgreSQL 14+) |
| MySQL Community | ✅ | Partial / Limited, never Full | `performance_schema` | 8.0, 8.4, 9.7 (**8.4.11** on every change) | Requires MySQL 8.0+ (enforced; 5.7, end of life, is not supported). Privileges held through roles evaluated on 8.0.19+ |
| Percona Server for MySQL | ✅ | Partial, never Full | `audit_log` / `audit_log_filter` JSON log | 8.4 (8.4.11-11) | |
| MariaDB | ✅ | Partial, never Full | `server_audit` log file, or `performance_schema` | 10.11, 11.4, 11.8 (**11.4.13** on every change) | `PUBLIC` grants checked on 10.11+ |
| MongoDB Community | ✅ | Limited (slow operations only) | Server log, profiler | 6.0, 7.0, 8.0 (**8.0.32** on every change) | Requires MongoDB 5.0+ (enforced; 4.x, end of life, is not supported), SCRAM-SHA-256, one declared host |
| MongoDB Enterprise / Percona Server for MongoDB | ✅ | Partial, never Full | `auditLog` JSON file | Percona Server for MongoDB 8.0 (8.0.32-14) | MongoDB Enterprise: recorded log samples only |
| OpenLDAP | ✅ | Full when reads and failed operations are proven logged for every naming context; Partial / Limited otherwise | `slapo-accesslog` (`cn=accesslog`) | Debian bookworm `slapd` (OpenLDAP 2.5) | |
| Apereo CAS (on `dev`, next release) | ✅ JSON service registry and audit log files | Partial at best (authentications and service tickets logged), never Full | JSON audit log file | 8.0.2 (dev service, in the end-to-end and load tests; not in the engine matrix) | Local files only, no network connection to CAS. Ticket ids never sampled. CAS stores kept in PostgreSQL, MySQL / MariaDB, MongoDB or OpenLDAP are read by those targets under the CAS store guard (ticket registries: counts only) |

*Planned, not supported yet*: Microsoft SQL Server, Redis and Valkey (phase 9), SQLite and Firebird (phase 10). Their expected audit levels are lower than the engines above for some (Redis and Valkey Limited at best, SQLite Discovery only): see the [roadmap](docs/ROADMAP.md#after-the-mvp) and [ADR-0039](docs/adr/0039-engine-scope-expansion.md), proposed. End-of-life engine versions are not supported.

- **Versions tested**: the connector integration tests run weekly on every listed version, and on changes to the connectors or the dev images (engine-matrix workflow, [`.github/workflows/engine-matrix.yml`](.github/workflows/engine-matrix.yml); not a required check). The version in bold is also tested on every change, with the end-to-end tests. Percona Server and OpenLDAP: the version listed only. Apereo CAS: 8.0.2 in the CAS end-to-end test (on changes to the agent, the console or the CAS dev service) and the load run, not in the engine matrix. Other versions are expected to work but are not tested.
- **Audit levels** (Full / Partial / Limited / None), their prerequisites and each engine's limits: [capability matrix](docs/08-engine-capabilities.md#matrix). Each target reports its actual level in the console.

## Quick start
**Use the release.** Verify the signed artifacts, install the console with Docker Compose and the agent `.deb`, enroll the agent and run a first scan: [deploy/README.md](deploy/README.md), summarized step by step in [the tutorial, part A](docs/11-tutorial.md#part-a--try-databastion-from-the-release).

**Develop.** On Linux with Docker, Node.js and Rust:

```sh
make doctor
make install
make dev
make check
make help
```

`make doctor` checks your tools, `make install` installs the dependencies as CI does, `make dev` starts the seeded databases (fake data only), Mailpit, Prometheus and Grafana on `127.0.0.1`, `make check` runs the linters and the fast tests, and `make help` lists every target. Running the console and an agent on your host, and the other tests: [the tutorial, part B](docs/11-tutorial.md#part-b--develop-with-make) and [dev/README.md](dev/README.md).

## How it works
```
        DataBastion Console  (UI, policies, incidents, alerting)
                  ▲
                  │  HTTPS 443, initiated only by the agents
      ┌───────────┼───────────┐
   Agent        Agent       Agent        ← no inbound port
     │            │           │
 PostgreSQL    MongoDB     OpenLDAP
```
- **Outbound-only**: no port to open toward your database servers.
- **Data minimization at the source**: no raw sensitive value and no database credential ever leaves the agent. The console only sees locations, masked samples and fingerprints.
- **Linux, Docker, installed in under 15 minutes**: the installation path is timed in CI.

Details: [architecture](docs/02-architecture.md) · [security](docs/05-security.md) · [protocol](docs/09-agent-protocol.md). Installation and use: [user guide](docs/10-user-guide.md).

## Editions
| | Community | Enterprise |
|---|---|---|
| License | Apache 2.0 | Commercial |
| Discovery + Audit, all connectors | ✅ | ✅ |
| Policies, incidents, email / webhook alerting | ✅ | ✅ |
| Local auth and OpenID Connect single sign-on (OIDC on `dev`, next release, [ADR-0038](docs/adr/0038-console-oidc-login.md)), console audit log | ✅ | ✅ |
| Multi-tenancy, fine-grained RBAC, SAML / SCIM | | ✅ |
| Advanced Prevention mode, SIEM export, compliance reports | | ✅ |
| Support & SLA | | ✅ |

Details: [docs/EDITIONS.md](docs/EDITIONS.md).

## Contributing
Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). PRs target the `dev` branch; run `make check` before opening one.
Dev environment: `make dev` starts the seeded databases (fake PII only), Mailpit, Prometheus and Grafana (port 3001) on `127.0.0.1`; see [dev/README.md](dev/README.md) and the [tutorial](docs/11-tutorial.md#part-b--develop-with-make).
Versions and releases: [RELEASE.md](RELEASE.md) · [CHANGELOG.md](CHANGELOG.md).
Vulnerabilities: **do not open a public issue**, see [SECURITY.md](SECURITY.md).

## License
DataBastion Community Edition is distributed under the [Apache 2.0 license](LICENSE).
The "DataBastion" name and logo are not covered by this license: see [TRADEMARKS.md](TRADEMARKS.md).
