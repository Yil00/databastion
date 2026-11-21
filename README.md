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

<p align="center">
  <b>Latest release: <a href="https://github.com/Yil00/databastion/releases/latest">v0.10.0</a></b> (2026-11-08): SQLite and Firebird join the supported engines.<br>
  <a href="https://github.com/Yil00/databastion/releases/latest">Release notes and signed artifacts</a> · <a href="CHANGELOG.md">All releases</a> · <a href="docs/ROADMAP.md">Roadmap</a>
</p>

> [!WARNING]
> DataBastion is early-stage software. Read the known limitations in the [CHANGELOG](CHANGELOG.md) and in [SECURITY.md](SECURITY.md#known-limitations-and-residual-risks) before relying on it.

## Why
Traditional DLPs monitor endpoints and the network. They know neither **where** sensitive data sits in your databases, nor **who** is exporting it in bulk (`pg_dump`, `mysqldump`, `mongoexport`, LDIF exports…).

DataBastion sits **as close to the data as possible**:
- **Discovery**: automatically classifies the columns, fields and attributes that contain personal data or secrets.
- **Audit**: uses the engines' native logs to detect abnormal access and exports, weighted by the sensitivity of the data involved.

## Supported databases
Every engine gets **Discovery** (where the sensitive data is). **Audit** (who reads it) depends on what the engine logs natively: DataBastion never claims more than the engine provides, and each target reports its actual level in the console.

**Audit levels:** 🟢 Full · 🔵 Partial · 🟡 Limited · ⚪ None ([what each level means](docs/08-engine-capabilities.md#audit-levels))

| Engine | Discovery | Audit, best level | Audit source | Tested versions | Details |
|:-------|:---------:|:------------------|:-------------|:----------------|:-------:|
| **PostgreSQL** | ✅ | 🟢 Full | pgaudit log; `pg_stat_statements` (🟡 Limited) | 14 – 18 | [docs](docs/08-engine-capabilities.md#postgresql-audit) |
| **MySQL** Community | ✅ | 🔵 Partial | `performance_schema` | 8.0, 8.4, 9.7 | [docs](docs/08-engine-capabilities.md#mysql--mariadb-audit) |
| **Percona Server for MySQL** | ✅ | 🔵 Partial | `audit_log` JSON log | 8.4 | [docs](docs/08-engine-capabilities.md#mysql--mariadb-audit) |
| **MariaDB** | ✅ | 🔵 Partial | `server_audit` log, `performance_schema` | 10.11, 11.4, 11.8 | [docs](docs/08-engine-capabilities.md#mysql--mariadb-audit) |
| **MongoDB** Community | ✅ | 🟡 Limited | Server log, profiler (slow operations) | 6.0, 7.0, 8.0 | [docs](docs/08-engine-capabilities.md#mongodb-audit) |
| **MongoDB** Enterprise, **Percona Server for MongoDB** | ✅ | 🔵 Partial | `auditLog` JSON file | Percona 8.0 | [docs](docs/08-engine-capabilities.md#mongodb-audit) |
| **OpenLDAP** | ✅ | 🟢 Full | `slapo-accesslog` | 2.5 | [docs](docs/08-engine-capabilities.md#openldap-audit) |
| **Apereo CAS** <sup>0.4</sup> | ✅ | 🔵 Partial | JSON audit log | 8.0 | [docs](docs/08-engine-capabilities.md#apereo-cas) |
| **Redis**, **Valkey** <sup>0.8</sup> | ✅ | 🟡 Limited | `SLOWLOG`, `COMMANDLOG`, `ACL LOG` | Redis 6.2 – 8.10, Valkey 7.2 – 9.1 | [docs](docs/08-engine-capabilities.md#redis--valkey-discovery) |
| **Microsoft SQL Server** <sup>0.8</sup> | ✅ ¹ | 🔵 Partial | SQL Server Audit, Extended Events | 2019, 2022, 2025 | [docs](docs/08-engine-capabilities.md#microsoft-sql-server-discovery) |
| **SQLite** <sup>0.10</sup> | ✅ ² | ⚪ None | none (no access log) | 3.40 – 3.54 files | [docs](docs/08-engine-capabilities.md#sqlite-discovery) |
| **Firebird** <sup>0.10</sup> | ✅ | 🔵 Partial | System audit trace log | 4.0, 5.0 | [docs](docs/08-engine-capabilities.md#firebird-discovery) |

<sup>0.x</sup> release that added the engine. ¹ Only with the row-level security opt-in (`rls_visibility: view_definition`). ² Declared database files only, read by a sandboxed reader process.

The best level needs the prerequisites of each engine (for example pgaudit with `pgaudit.log_rows = on` for PostgreSQL Full): see the [capability matrix](docs/08-engine-capabilities.md#matrix). End-of-life engine versions are not supported and are refused at connection.

<details>
<summary><b>Prerequisites and notes per engine</b></summary>

- **PostgreSQL**: 14+ (older servers refused). Full with pgaudit and `pgaudit.log_rows = on`, Partial without it, Limited with `pg_stat_statements` only. pgaudit `jsonlog` needs 15+, `csvlog` on 14.
- **MySQL / MariaDB / Percona**: MySQL 8.0+, MariaDB 10.11+ (older servers refused). Never Full. Privileges held through roles are evaluated (MySQL 8.0.19+); MariaDB `PUBLIC` grants are checked.
- **MongoDB**: 5.0+, SCRAM-SHA-256, one declared host. Community has no audit log, so only slow operations are seen. MongoDB Enterprise: recorded log samples only.
- **OpenLDAP**: Full only when reads and failed operations are proven logged for every naming context; Partial or Limited otherwise.
- **Apereo CAS**: local files only (JSON service registry and audit log), no network connection to CAS. Ticket ids are never sampled. CAS stores kept in another supported engine are read under the CAS store guard (ticket registries: counts only).
- **Redis / Valkey**: mostly a Discovery engine, fast reads leave no record. Key names are reported as normalized key patterns. Redis 6.2.7+ and Valkey 7.2+; ACL user with an explicit allow-list checked by `ACL DRYRUN`. One declared node, no Cluster or Sentinel topology following.
- **Microsoft SQL Server**: SQL logins only, over verified TLS (TDS 8.0 strict or mandatory encryption) with a server certificate naming the host. Accounts holding `sysadmin`, `db_owner`, `CONTROL SERVER` or another refused right are refused; Azure SQL is refused. SQL Server Audit on 2022 / 2025 (no row counts), Extended Events on every version (the only source on 2019), whose grant exposes every statement text on the server.
- **SQLite**: one declared file per target, no directory, glob or search; the path is never sent. Needs a Linux kernel with Landlock, and a file system mounted read-only for the agent. Rollback-journal files only with `sqlite.rollback_mode: read`. `TEXT` and `INTEGER` values only.
- **Firebird**: 4.0 and 5.0 (3.0 and 6.0 refused). Loopback connections only, `Srp256` with ChaCha wire encryption required, a dedicated account with `SELECT` grants. Audit needs the trace log read locally with `max_log_size = 0` and the readers check passed (the agent on the host, or the host's identity files mounted read-only into its container). Failed logins are not audited. After an agent restart without a usable checkpoint, or a kill, the agent's own reads can be reported under its account: never exclude that account from "every read" policies. Setup: [user guide](docs/10-user-guide.md#firebird-targets).

</details>

<details>
<summary><b>How versions are tested</b></summary>

The connector integration tests run weekly on every listed version, and on changes to the connectors or the dev images ([engine-matrix workflow](.github/workflows/engine-matrix.yml), not a required check). One version per engine is also tested on every change, with the end-to-end tests: PostgreSQL 17.11 with pgaudit, MySQL 8.4.11, MariaDB 11.4.13, MongoDB 8.0.32, Valkey 9.0.6 and Redis 8.10.2, SQL Server 2022 Express with SQL Server Audit, Firebird 5.0.4, files written by the bundled SQLite 3.54.1, and Apereo CAS 8.0.2 (end-to-end and load tests only, not in the engine matrix). Percona Server (8.4.11-11, Percona Server for MongoDB 8.0.32-14) and OpenLDAP (Debian bookworm `slapd`): the version listed only. SQLite: files written by SQLite 3.40 (Debian 12), 3.45 (Ubuntu 24.04), 3.46 (Debian 13) and 3.54.1, in every journal mode. Load runs measure the impact on the database for every engine family ([measurements](docs/08-engine-capabilities.md#load-and-database-impact-measured)). Other versions are expected to work but are not tested.

</details>

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
DataBastion follows an open-core model ([ADR-0005](docs/adr/0005-open-core-license.md)). **Everything available today is the Community Edition, in this repository, under Apache 2.0.** There is no commercial version yet: the Enterprise column shows the planned scope, which may change.

| | Community | Enterprise |
|:--|:--:|:--:|
| Availability | ✅ **Available** | 🗓️ **Planned**, not available yet |
| License | Apache 2.0 | Commercial |
| Discovery + Audit, every connector | ✅ | included |
| Policies, incidents, email / webhook alerting | ✅ | included |
| Local accounts and OpenID Connect single sign-on, console audit log | ✅ | included |
| Recommended actions and response hooks ([ADR-0040](docs/adr/0040-prevention-mode-scope.md)) | 🗓️ planned | included |
| Multi-tenancy, fine-grained RBAC, SAML / SCIM | — | 🗓️ planned |
| Blocking Prevention mode, SIEM export, compliance reports | — | 🗓️ planned |
| Support & SLA | GitHub issues, best effort | 🗓️ planned |

Baseline security (TLS, data minimization, single sign-on, the console audit log) always stays in Community, and no Community feature is ever moved to Enterprise. Details: [docs/EDITIONS.md](docs/EDITIONS.md).

## Contributing
Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). PRs target the `dev` branch; run `make check` before opening one.
Dev environment: `make dev` starts the seeded databases (fake PII only), Mailpit, Prometheus and Grafana (port 3001) on `127.0.0.1`; see [dev/README.md](dev/README.md) and the [tutorial](docs/11-tutorial.md#part-b--develop-with-make).
Versions and releases: [RELEASE.md](RELEASE.md) · [CHANGELOG.md](CHANGELOG.md).
Vulnerabilities: **do not open a public issue**, see [SECURITY.md](SECURITY.md).

## License
DataBastion Community Edition is distributed under the [Apache 2.0 license](LICENSE).
The "DataBastion" name and logo are not covered by this license: see [TRADEMARKS.md](TRADEMARKS.md).
