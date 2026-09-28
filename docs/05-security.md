# Security & best practices – DataBastion

A security tool that reads sensitive data is itself a target. These rules are non-negotiable.

## Security invariants
1. **Outbound-only**: no inbound port to the agents or to the databases.
2. **No raw sensitive value leaves the agent.** Only: location, detected type, confidence, volume, masked sample, HMAC fingerprint ([ADR-0003](adr/0003-data-minimization-at-source.md)).
3. **Database credentials never leave the agent host.** The console neither stores nor receives them.
4. **Least privilege**: the agent connects with a dedicated **read-only** account.
5. **No secrets in images or in the repository**: environment variables, Docker secrets, mounted files.
6. **Console audit log**: every user action (login, policy change, incident acknowledgment, agent enrollment or revocation) is logged.

## Threat model (summary)
| Compromise | What the attacker gets | What they do not get |
|---------------|----------------------------|------------------------|
| Console | The map of sensitive locations, masked samples | The data itself, database credentials, network access to the databases |
| An agent | Its own secret, the read-only account of its targets | The other agents, the console secrets |
| Network between agent and console | Nothing (TLS 1.3) | |

The map remains sensitive information: the console must be protected (HTTPS, authentication, public exposure not recommended).

## Masking and fingerprints
- **Masked sample**: `jane.doe@example.com` → `j*******@e******.com`; IBAN → `FR76 **** **** **** **** ***1 89`
- **Fingerprint**: `HMAC-SHA256(agent_local_key, normalized_value)`. It allows deduplication and correlation without revealing the value. The key is generated at enrollment and **never leaves the agent**.
- Masking is implemented in a single crate (`classifiers`/`masking`) and covered by regression tests.

## Encryption
- **In transit**: TLS 1.3 mandatory. No additional application-level AES-GCM encryption on top: without a key held outside the console, it adds nothing to TLS.
- **At rest (console)**: sensitive columns (masked samples, webhook secrets, SMTP configuration) are encrypted with AES-256-GCM using a `DATABASTION_ENCRYPTION_KEY` key provided via Docker secret.
- Agent secrets are stored **hashed** (argon2id) on the console side.

## Agent secret management
- Single-use, short-lived (24 h) enrollment token, generated in the console
- At enrollment, the agent receives `agent_id` + a long secret; it stores it in a `0600` file
- Rotation from the console (the agent retrieves the new secret on its next call)
- Immediate revocation
- Vault integration: later

## Recommended database accounts (read-only)
```sql
-- PostgreSQL 14+
CREATE ROLE databastion LOGIN PASSWORD '...';
GRANT pg_read_all_data TO databastion;   -- Discovery (sampling)
GRANT pg_monitor       TO databastion;   -- statistics, pg_stat_statements

-- MySQL / MariaDB
CREATE USER 'databastion'@'localhost' IDENTIFIED BY '...';
GRANT SELECT, PROCESS, SHOW VIEW ON *.* TO 'databastion'@'localhost';
GRANT SELECT ON performance_schema.* TO 'databastion'@'localhost';
```
MongoDB: `read` roles on the targeted databases + `clusterMonitor`. OpenLDAP: a service DN with read rights on the tree and on `cn=accesslog`.

## Deployment recommendations
- Agents and console run as a **non-root** user, read-only file system, `cap_drop: ALL`, `no-new-privileges`
- Console behind a reverse proxy (Traefik / Nginx / Caddy) with HTTPS
- The console's internal database is never exposed outside the Docker network
- Enable the databases' native logs (pgaudit, MariaDB audit plugin, OpenLDAP `accesslog`…)

## Points of attention
- **Performance**: bounded sampling (N rows per column, `TABLESAMPLE` when possible), configurable off-peak execution, `statement_timeout` on every agent query
- **False positives**: exceptions per location / classifier, "false positive" feedback that feeds the exceptions
- **Upgrades**: the agent stays compatible with protocol version N-1; the console advertises the minimum expected version
