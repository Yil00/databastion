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
- **Fingerprint**: `hmac-sha256:` + hex of `HMAC-SHA256(agent_local_key, normalized_value)`. It allows deduplication and correlation without revealing the value. The key is generated at enrollment and **never leaves the agent**.
- **Names** (tables, fields, LDAP containers) can embed values: the agent normalizes them before the uplink and sanitizes each item rather than dropping the batch ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)).
- Masking is implemented in a single crate (`classifiers`/`masking`) and covered by regression tests.

## Encryption
- **In transit**: TLS 1.3 mandatory. No additional application-level AES-GCM encryption on top: without a key held outside the console, it adds nothing to TLS.
- **At rest (console)**: sensitive columns (masked samples, webhook secrets, SMTP configuration) are encrypted with AES-256-GCM using a `DATABASTION_ENCRYPTION_KEY` key provided via Docker secret.
- Agent secrets are stored **hashed** (argon2id) on the console side.

## Agent secret management
Normative details: [`shared/protocol/openapi.yaml`](../shared/protocol/openapi.yaml) (`/enroll`, `/rotate`, `agentSecret` security scheme); overview in [09-agent-protocol.md](09-agent-protocol.md#secret-rotation).

- **Enrollment token**: single use, valid 24 h, generated in the console. The console stores only its SHA-256 hash and consumes it **atomically** (one conditional update: unused and not expired → used), so two concurrent enrollments with the same token cannot both succeed. `/enroll` is rate limited per source IP.
- At enrollment, the agent receives `agent_id` + a 256-bit secret; it stores them in a `0600` file, then generates its local HMAC key (never transmitted).
- **Secret storage**: argon2id hash on the console side. The bodies of `/enroll` and `/rotate` are excluded from every request, APM and error log, on both sides.
- **Authentication**: failed authentications are rate limited per agent id **and** per source IP (when known, see [Authentication rate limits](#authentication-rate-limits)) **before** the argon2id verification runs, so the hash cost cannot be used for denial of service. A cache of verified secrets, if any, keeps entries less than 30 s and is purged on revocation and on rotation.
- **Rotation** ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)): the **agent generates** the new secret, persists it as pending before any network call, and registers it with `POST /rotate`, authenticated with the current secret. Retries resend the same secret and are idempotent. The console rejects a new secret equal to the current one or obviously low-entropy (`invalid_secret`). A different new secret while one is pending, or use of the old secret after a **60 s tolerance window** following promotion, is a `rotation_conflict`: the console locks the agent, revokes all its secrets and raises a security incident; the agent stops and must be re-enrolled. [ADR-0010](adr/0010-rotation-conflict-window.md) makes the window precise: only a `/rotate` authenticated with the previous secret and carrying a different new secret can be a conflict inside the window (the same new secret is an idempotent `duplicate`), and a `/rotate` authenticated with the current secret always starts a new rotation.
- **Revocation** invalidates the current and the pending secret and closes the agent's held long-polls. It is effective in **less than 60 s**.
- **Suspected compromise** of an agent secret is not handled by rotation (whoever holds the secret could rotate it too): the administrator revokes the agent and re-enrolls it.
- Vault integration: later

## Console internal database
*Introduced by P1-A (#17); details in `console/README.md` ("Database roles").*

### Database roles
The console uses three PostgreSQL roles, so that a compromised console process can neither remove the append-only trigger on `audit_log` nor plant code that migrations would run:
- a bootstrap superuser, used only by the init script that creates the two roles below;
- an **owner** role (not superuser, no `CREATEROLE`) used only for migrations: it owns the database, the `public` and `pgboss` schemas and every console table and trigger; its `search_path` is pinned to `public`;
- a **runtime** role used by the web and worker processes: DML only on the console tables, only `SELECT` and `INSERT` on `audit_log`, `USAGE` and `CREATE` on schema `pgboss` for the pg-boss tables, and no `CREATE` on the database or on `public`.

The owner role never runs SQL against objects inside `pgboss`: they are created by the runtime role, so a trigger or function planted there would run with the owner's rights. In a single-role setup (development), the audit log is append-only against the application code only.

### Authentication rate limits
Every login or agent authentication that needs an argon2id verification is counted **before** the verification runs and refunded on success, so concurrent requests cannot exceed the limits. Logins and agent authentications use separate, bounded argon2id pools (`503` + `Retry-After` when full), plus a pool reserved for agents presenting their last verified secret, so a login flood or a flood of wrong agent secrets cannot block a legitimate agent. Per-IP limits apply only when the client IP is known, that is behind a trusted reverse proxy explicitly configured (`DATABASTION_TRUST_PROXY` / `DATABASTION_TRUSTED_PROXY_HOPS`); otherwise only the per-user / per-agent limits and the pool caps apply. Limiters are in memory, per process (one web process in the MVP).

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
**MySQL / MariaDB system schemas**: `SELECT ON *.*` also grants read access to `mysql.user` (password hashes) and the other system tables. Discovery must exclude the system schemas `mysql`, `information_schema`, `performance_schema` and `sys` from sampling (`performance_schema` is read for Audit only). Where practical, grant `SELECT` on the application databases only instead of `*.*`.

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
