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
- **Rotation** ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)): the **agent generates** the new secret, persists it as pending before any network call, and registers it with `POST /rotate`, authenticated with the current secret. Retries resend the same secret and are idempotent. The console rejects a new secret equal to the current one or obviously low-entropy (`invalid_secret`). A different new secret while one is pending, or use of the old secret after a **60 s tolerance window** following promotion, is a `rotation_conflict`: the console locks the agent, revokes all its secrets and raises a security incident; the agent stops and must be re-enrolled. [ADR-0010](adr/0010-rotation-conflict-window.md) makes the window precise: only a `/rotate` authenticated with the previous secret and carrying a different new secret can be a conflict inside the window (the same new secret is an idempotent `duplicate`), and a `/rotate` authenticated with the current secret always starts a new rotation while no secret is pending. [ADR-0011](adr/0011-late-rotation-retry.md) adds the late retry: a `/rotate` authenticated with the previous secret whose new secret matches the current (promoted) one is an idempotent `duplicate` at any time, bounded to 10 per agent per 5 min; any other `/rotate` outcome with the previous secret after the window locks the agent. When the outcome of a `/rotate` is unknown, the agent first probes its pending secret with a heartbeat before re-sending `/rotate` with the previous one (#20).
- **Security events** (#21): a `rotation_conflict` lock writes a `critical` row to the `security_events` table (console-computed kind, severity and scalar details, never a secret or hash) in addition to the console audit log. It is a placeholder for the incident model of phase 3.
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

### Metrics endpoint (#21)
`GET /metrics` requires `Authorization: Bearer <DATABASTION_METRICS_TOKEN>` (at least 32 characters, constant-time comparison, `401` otherwise). When the token is unset or too short, the endpoint answers `404`. It is meant for the internal network only: block the path on the public reverse proxy and scrape the console directly. Serving it on a separate port or behind an allowlist is a follow-up (ROADMAP P1-D).

### Web UI headers (#21)
UI pages get a `Content-Security-Policy` with a per-request nonce: `script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`. It is not applied to `/api/*` and `/metrics`, which serve no HTML.

### Authentication rate limits
Every login or agent authentication that needs an argon2id verification is counted **before** the verification runs and refunded on success, so concurrent requests cannot exceed the limits. Logins and agent authentications use separate, bounded argon2id pools (`503` + `Retry-After` when full), plus a pool reserved for agents presenting their last verified secret, so a login flood or a flood of wrong agent secrets cannot block a legitimate agent. Per-IP limits apply only when the client IP is known, that is behind a trusted reverse proxy explicitly configured (`DATABASTION_TRUST_PROXY` / `DATABASTION_TRUSTED_PROXY_HOPS`); otherwise only the per-user / per-agent limits and the pool caps apply. Limiters are in memory, per process (one web process in the MVP).

## Agent local state and results path
*Introduced by P1-B (#16, #20); details in `agent/README.md`.*

- **State directory**: must be owned by the agent user and not group / world writable (`0700` expected, another mode warns). State files (`identity.json`, `hmac.key`, spool batches) are `0600`, written atomically, opened with `O_NOFOLLOW` and checked on the handle (regular file, owner, no group / other access).
- **Spool**: bounded by `spool.max_bytes` (default 256 MiB) and `spool.max_batches` (default 10000), oldest dropped first. A file that cannot be parsed or fails the state-file checks is moved to `spool/quarantine/` (32 kept), counted and never logged; it does not crash the agent. A response that is not a contract answer (e.g. an HTML page from a middlebox) keeps the batch, so an intermediary cannot empty the spool.
- **Name normalization** ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)): array indices of up to 6 digits become `[]`; any segment with more than 6 digits, UUIDs and e-mail addresses become `*`; an LDAP entry DN is reduced to its parent container. Segments matching a classifier, including values split across dots, are only handled from P2-A.
- **Per-item sanitization**: every finding or event is checked against the contract before spooling; an item still invalid is dropped and counted, not the whole batch. HMAC fingerprints are not wired yet (P2-A): an event whose account name would need one is dropped.
- **Local engine detection** ([ADR-0006](adr/0006-target-discovery.md)): read-only and local, no network I/O. The agent checks a fixed list of Unix socket paths (never connects), `LISTEN` entries of `/proc/net/tcp{,6}` for the default engine ports (addresses not reported) and process names in `/proc/<pid>/comm` (never the command line); at most 16 entries. In a container without host networking, it sees only its own network namespace and processes, so detection finds little or nothing on the host.

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
