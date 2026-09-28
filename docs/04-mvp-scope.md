# MVP scope – DataBastion

## MVP objective
Ship a first **useful and stable** version (v0.1.0), focused on Linux and the priority use cases. Breakdown into phases: [ROADMAP.md](ROADMAP.md).

## Included in the MVP
- Web console (Next.js): agents, targets, findings, incidents, policies
- Rust agent with connectors:
  - PostgreSQL: Discovery + Audit
  - MySQL / MariaDB: Discovery + Audit
  - MongoDB: Discovery + Audit (level depends on the edition)
  - OpenLDAP: Discovery + Audit (via the `accesslog` overlay)
- Basic classifiers: email, FR/intl phone number, IBAN, payment card (Luhn), NIR, secrets (API keys, password hashes, private keys)
- Simple DLP policies (conditions + actions: create an incident, alert, ignore)
- Exception list / "false positive" feedback
- Basic alerting: email (SMTP) and signed webhook
- Secure outbound communication (HTTPS, long-poll)
- Docker Compose deployment

## Audit levels: what the MVP promises
Auditing depends on what the engine logs natively. DataBastion **does not promise more than what the engine provides** and shows it in the console. See [08-engine-capabilities.md](08-engine-capabilities.md).

## Deliberately excluded from the MVP
| Item | Reason | Planned phase |
|---------|--------|--------------|
| CAS | Lower priority | 1.5 |
| Real-time Prevention mode | Requires proxy / hooks | 2 |
| Helm / Kubernetes | Compose is enough for the MVP | 2 |
| Agent ↔ console mTLS | Token + TLS are enough for the MVP | 2 |
| Advanced machine learning | Too heavy for an MVP | 2/3 |
| Multi-tenancy, fine-grained RBAC, SAML | Enterprise ([EDITIONS.md](EDITIONS.md)) | 2+ |
| Windows / macOS / iOS | High complexity | 3+ |
| Endpoint agent on user workstations | Outside the "as close to the database as possible" positioning | 3+ |

## MVP success criteria
- Console + one agent deployed in **under 15 minutes** via Docker Compose
- An agent starts with no inbound port open
- Correct detection of PII in the test dataset (`dev/`): recall ≥ 90 %, precision ≥ 85 %
- Detection of a `pg_dump`, a `mysqldump`, a `mongodump` and a bulk LDAP search in the test environment
- **No raw sensitive value** present in the console database (automated test)
- Impact on the monitored database < 2 % CPU during Discovery (bounded sampling)
- Agents stable for 72 h on Ubuntu 24.04 and Debian 12
