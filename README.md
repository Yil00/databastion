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
  <img src="https://img.shields.io/badge/status-pre--alpha-orange.svg" alt="Status: pre-alpha">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey.svg" alt="Platform: Linux">
</p>

> ⚠️ **Pre-release.** The v0.1.0 MVP is in its last phase (hardening and release); no version has been released yet and nothing is production-ready. See the [roadmap](docs/ROADMAP.md).

## Why
Traditional DLPs monitor endpoints and the network. They know neither **where** sensitive data sits in your databases, nor **who** is exporting it in bulk (`pg_dump`, `mysqldump`, `mongoexport`, LDIF exports…).

DataBastion sits **as close to the data as possible**:
- **Discovery**: automatically classifies the columns, fields and attributes that contain personal data or secrets.
- **Audit**: uses the engines' native logs to detect abnormal access and exports, weighted by the sensitivity of the data involved.

## Supported engines (MVP)
PostgreSQL · MySQL / MariaDB · MongoDB · OpenLDAP — *CAS planned right after the MVP.*

The audit level depends on the engine and its edition: see [the capability matrix](docs/08-engine-capabilities.md).

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
- **Linux, Docker, installed in under 15 minutes** (MVP goal).

Details: [architecture](docs/02-architecture.md) · [security](docs/05-security.md) · [protocol](docs/09-agent-protocol.md). Installation and use: [user guide](docs/10-user-guide.md).

## Editions
| | Community | Enterprise |
|---|---|---|
| License | Apache 2.0 | Commercial |
| Discovery + Audit, all connectors | ✅ | ✅ |
| Policies, incidents, email / webhook alerting | ✅ | ✅ |
| Local auth (OIDC planned), console audit log | ✅ | ✅ |
| Multi-tenancy, fine-grained RBAC, SAML / SCIM | | ✅ |
| Advanced Prevention mode, SIEM export, compliance reports | | ✅ |
| Support & SLA | | ✅ |

Details: [docs/EDITIONS.md](docs/EDITIONS.md).

## Contributing
Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). PRs target the `dev` branch.
Dev environment: `make dev` starts the seeded databases (fake PII only), Mailpit, Prometheus and Grafana (port 3001) on `127.0.0.1`; see [dev/README.md](dev/README.md).
Versions and releases: [RELEASE.md](RELEASE.md) · [CHANGELOG.md](CHANGELOG.md).
Vulnerabilities: **do not open a public issue**, see [SECURITY.md](SECURITY.md).

## License
DataBastion Community Edition is distributed under the [Apache 2.0 license](LICENSE).
The "DataBastion" name and logo are not covered by this license: see [TRADEMARKS.md](TRADEMARKS.md).
