# User guide – DataBastion 0.1

How to install the console and an agent, enroll the agent, declare targets, give the agent least-privilege accounts, and read findings and incidents. This page only describes what the code on `dev` does; the component READMEs linked below hold the full reference.

> **Status.** v0.1.0 is being prepared (ROADMAP [phase 7](ROADMAP.md#phase-7--hardening--v010-release)). The "installation in under 15 minutes" goal, the load tests and the 72 h stability test are not done yet. Read [08-engine-capabilities.md](08-engine-capabilities.md) before relying on Audit for an engine.

## 1. What you deploy
| Component | Where | Network |
|-----------|-------|---------|
| **Console**: `web`, `worker`, one-shot `migrate`, internal PostgreSQL 17 | One host, behind an HTTPS reverse proxy | Inbound HTTPS from users and agents; outbound from the worker to the SMTP relay and webhook receivers |
| **Agent**: `databastion-agent`, one per host or network zone | Close to the monitored databases; on the database host itself when Audit reads a log file | Outbound HTTPS to the console and connections to its declared targets only; **no listening port** (I1) |

The agent is the only client of the console's agent API. Database credentials stay in the agent's configuration on its host (I3); the console only receives locations, masked samples and keyed fingerprints (I2). Architecture: [02-architecture.md](02-architecture.md). Security model: [05-security.md](05-security.md).

## 2. Get the images
The console and agent images are built from [console/Dockerfile](../console/Dockerfile) and [agent/Dockerfile](../agent/Dockerfile). Published tags (`X.Y.Z`, `X.Y.Z-rc.N`…, no `v` prefix) are on GHCR as `ghcr.io/yil00/databastion-console` and `ghcr.io/yil00/databastion-agent`, signed with cosign: verify them as described in [SECURITY.md](../SECURITY.md#verifying-release-artifacts) and pin the digest. Use the same version for the console and the agents ([RELEASE.md](../RELEASE.md#2-versions)).

Until a tag is published, build the images from a checkout:
```sh
docker build -t databastion-console:local console/
docker build -t databastion-agent:local agent/
```

<!-- TODO(packaging): the agent .deb package + systemd unit and the release console image are in the
     packaging PR (feat/p7-packaging). When it merges, replace this comment with "See deploy/README.md"
     and link it here and in section 4. -->
The `.deb` package of the agent (with a systemd unit) is not available yet.

## 3. Install the console
The reference is [deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml), with [deploy/initdb/](../deploy/initdb/10-databastion-roles.sh). Every console setting is described in [console/README.md](../console/README.md#configuration).

1. **Copy** `docker-compose.example.yml` and the `initdb/` directory to the console host. Set the console image tag (`x-console-image`) to the version you verified.
2. **Create the secret files** in `./secrets/` (mode `0600`), as listed at the end of the compose file: `db_password` (bootstrap superuser, used only by the initdb script), `db_owner_password` and `db_owner_url` (owner role, used only by `migrate`), `db_app_password` and `db_url` (runtime role of `web` and `worker`), `encryption_key` and `metrics_token` (`openssl rand -base64 32` each). The three database roles are explained in [console/README.md](../console/README.md#database-roles).
3. **Set `DATABASTION_PUBLIC_URL`** to the public HTTPS origin of the console, in both the `console` and `worker` services.
4. **Put an HTTPS reverse proxy** in front of `127.0.0.1:8080`. Keep `DATABASTION_TRUST_PROXY: "1"` only if that proxy sets or overwrites `X-Forwarded-For`. The proxy must not log the `Authorization`, `Cookie` or `X-CSRF-Token` headers ([05-security.md](05-security.md#deployment-recommendations)). Session cookies are `Secure`: the UI is not usable over plain HTTP.
5. **Start**: `docker compose up -d`. `migrate` applies the database migrations and exits; `console` and `worker` start after it.
6. **Create the first administrator** (there is no default account), once:
   ```sh
   docker compose run --rm -e DATABASTION_BOOTSTRAP_ADMIN_USERNAME=admin \
     -e DATABASTION_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/admin_password \
     console bootstrap-admin
   ```
   with an `admin_password` secret (12 to 1024 characters) added for that run and removed afterwards ([console/README.md](../console/README.md#first-administrator)). The command refuses to run once a user exists.
7. **Check**: `GET /api/health/ready` answers `200`, and you can sign in.

Notes:
- 0.1 has one user role in practice: the bootstrap administrator. There is no user-management page or API yet; the `analyst` role exists in the schema but no account can be created with it from the console.
- Without a usable `DATABASTION_ENCRYPTION_KEY`, the web and worker processes refuse to start in production. Changing it later makes the stored masked samples and notification channel secrets unusable ([console/README.md](../console/README.md#configuration)).
- Prometheus metrics: `/metrics` on the dedicated port `9464`, with the `metrics_token` as bearer token ([console/README.md](../console/README.md#metrics)). Never publish that port: it must be reachable only by Prometheus, on the internal network.
- Plan the internal database's `max_connections` from the sizing in [console/README.md](../console/README.md#docker-image).

## 4. Install an agent
Deploy the agent on the host or network of the databases it monitors, not next to the console. With the image:

| Mount | Content |
|-------|---------|
| `/etc/databastion/agent.yaml` (read-only) | Configuration: console URL, limits, targets |
| `/var/lib/databastion` (volume, `0700`, owned by uid 10001) | Identity, local HMAC key, spool |
| Secret files referenced by `agent.yaml` (read-only, `0600`, owned by uid 10001) | Database passwords |
| Log directories of the targets (read-only), for file-based Audit sources | e.g. the pgaudit or `server_audit` log |

The commented agent block at the end of the deployment example currently uses the `:latest` tag and keeps the enrollment token in its `secrets`. This is a known issue, to be fixed in `deploy/`. Until then, pin the image by a verified digest ([SECURITY.md](../SECURITY.md#verifying-release-artifacts)) and remove the token secret once the agent is enrolled.

Run it as uid/gid 10001, with `read_only: true`, `cap_drop: ALL` and `no-new-privileges` ([agent/README.md](../agent/README.md#docker-image)). The image has no health check because the agent has no listener: its health is shown by the console (agent status, `databastion_agent_up`).

**`agent.yaml`**: start from [agent/agent.example.yaml](../agent/agent.example.yaml). Unknown keys are rejected. The main settings:
- `console.url`: the console's public HTTPS URL. `console.ca_file` pins a private CA (it then is the only trusted root). TLS 1.3 minimum. `HTTPS_PROXY` / `NO_PROXY` are honored.
- `state_dir`: a directory owned by the agent user, not group- or world-writable.
- `limits`: local caps that console jobs cannot exceed (rows sampled per object, statement timeout, scan duration, audit poll interval).
- `spool`: bounded disk buffer for results while the console is unreachable. When it is full, batches are dropped by priority: findings and events can each grow to 3/4 of the bounds, so each keeps at least 1/4 (an events flood can evict findings down to that quarter); batches with a `signature.*` signal go last; otherwise the oldest first. and the console raises an `agent.batches_dropped` alert.
- `targets`: see [section 6](#6-declare-targets).

Keep the agent host's clock in sync (NTP): it must stay within 5 minutes of the console's. Logs are JSON on stdout; `DATABASTION_LOG` sets the level.

## 5. Enroll the agent
1. In the console, **Enrollment tokens** (administrator): create a token. The `dbe_…` token is shown **once**; it is single-use and valid 24 h.
2. On the agent host, write it to a file readable by the agent user only (`0600`); the agent refuses a token file readable by others. Create the file empty with the right mode first, then paste the token with an editor or `read -rs`; never `echo <token> > file`, which leaves the token in the shell history:
   ```sh
   install -m 0600 -o <agent user> /dev/null /path/to/token
   read -rs TOKEN && printf '%s' "$TOKEN" > /path/to/token && unset TOKEN
   ```
3. Enroll, once:
   ```sh
   databastion-agent enroll --config /etc/databastion/agent.yaml --token-file /path/to/token
   ```
   With the image, run the same subcommand in a one-shot container with the mounts of section 4 plus the token file, e.g. `docker compose run --rm agent enroll --config /etc/databastion/agent.yaml --token-file /run/secrets/enrollment_token`. `DATABASTION_ENROLLMENT_TOKEN_FILE` can replace `--token-file`.
4. Delete the token file, then start the agent: `databastion-agent run --config /etc/databastion/agent.yaml` (the image's default command).
5. The agent appears under **Agents** as `online`, with its targets, their reachability and their audit level.

Enrollment stores the agent identity (`identity.json`) and generates the local HMAC key (`hmac.key`) in `state_dir`, both `0600`; the HMAC key never leaves the host. Protocol details: [09-agent-protocol.md](09-agent-protocol.md#enrollment).

Afterwards, from the agent page (administrator):
- **Rotate secret**: the agent generates its new secret itself ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)).
- **Revoke**: effective immediately. To bring the host back, create a new token and run `enroll --force` (it replaces the identity and keeps the HMAC key unless `--new-hmac-key` is given). A suspected compromise is handled by revocation and re-enrollment, never by rotation.

## 6. Declare targets
Targets are declared **only** in `agent.yaml`, on the agent host: the console cannot add a target, and the agent never scans the network (I5). The agent also reports, in its heartbeat, the undeclared database engines it detects on its own host (Unix sockets, local listening ports, process names; never an address; [agent/README.md](../agent/README.md#local-engine-detection-adr-0006-i5)). The console stores them but the 0.1 UI does not display them.

Each target has:
- `id`: a slug shown in the console (do not put a host name in it);
- `engine`: `postgres`, `mysql`, `mariadb`, `mongodb` or `openldap`;
- `host` and `port`, or `socket`;
- `account` and `secret`: a **reference** to the password, `env: VAR_NAME` or `file: /path` (`0600`, owned by the agent user), never the password itself. OpenLDAP with `bind: sasl_external` over `ldapi://` needs no secret;
- an optional engine block (`postgres`, `mysql`, `mongodb`, `openldap`): databases to connect to, `tls` (`verify_full` by default; `disable` only on a socket or a loopback address; `disable_insecure` is an explicit, warned opt-in and does not exist for OpenLDAP), `ca_file`, and the Audit source files:
  - PostgreSQL: `postgres.audit_log: {path, format: jsonlog | csvlog}` (the pgaudit server log; without it, Audit uses `pg_stat_statements`);
  - MySQL / MariaDB: `mysql.audit_log: {path, format: server_audit | json}` (without it, `performance_schema`);
  - MongoDB: `mongodb.audit_log: {path, format: audit_log | server_log}` (without it, the profiler if granted);
  - OpenLDAP: `openldap.accesslog_base` (read over LDAP) and `openldap.clear_principals`.

The example file documents each key with its range. After changing `agent.yaml`, restart the agent.

## 7. Least-privilege accounts
Give each target a **dedicated, read-only** account (I4). The recommended accounts, with the exact statements, are in [05-security.md, "Recommended database accounts"](05-security.md#recommended-database-accounts-read-only):

| Engine | Discovery | Audit | Reference |
|--------|-----------|-------|-----------|
| PostgreSQL | `CONNECT` + per-schema `USAGE` / `SELECT` | `pg_read_all_stats`; the pgaudit log file readable by the agent | [ADR-0012](adr/0012-postgresql-agent-grants.md), [connector README](../agent/crates/connector-postgres/README.md) |
| MySQL / MariaDB | per-database `SELECT`, `REQUIRE SSL`, host restricted to the agent | no grant with a log file source; `SELECT ON performance_schema.*` only when it is the source | [ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md), [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md), [connector README](../agent/crates/connector-mysql/README.md) |
| MongoDB | custom role with `find` + `listCollections` per database, SCRAM-SHA-256, `authenticationRestrictions` with `clientSource` = the agent's address(es) | no grant with a file source; `find` on `system.profile` only for the profiler source | [ADR-0026](adr/0026-mongodb-connector.md), [ADR-0027](adr/0027-mongodb-audit.md), [connector README](../agent/crates/connector-mongodb/README.md) |
| OpenLDAP | service DN with `read` on the tree; rule `{0}` names **every** credential attribute of the loaded schemas (`userPassword`, `userPKCS12`, and the Samba, Kerberos, ppolicy… ones where loaded), never readable; a `peername.ip` restriction to the agent's address, since the accesslog records no client address | `read` on `cn=accesslog` only while Audit runs for the target (otherwise `privilege.accesslog_without_audit`) | [ADR-0029](adr/0029-openldap-connector.md), [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md), [connector README](../agent/crates/connector-openldap/README.md) |

Also:
- Size the account's connection limit as the recommended statements say: Audit holds its own connections.
- For file-based Audit sources, give the agent's OS user **read** access to the log directory only, never to the data directory. Run the agent as a dedicated non-root user: it refuses a log file its own account could write (`audit.log_not_readable`).
- At every heartbeat the agent checks each account and reports over-privilege and coverage problems as **target notes** on the agent page. A note about over-privilege means the account has more rights than recommended: remove them.

## 8. Audit prerequisites and levels
What Audit can see depends on the engine, its edition and its logging settings. The console shows the level reached for each target: **Full**, **Partial**, **Limited** or **None** (Discovery only). The prerequisites per engine (pgaudit, `server_audit`, `performance_schema`, `auditLog`, `slowms`, `slapo-accesslog`…) and the known limits are in [08-engine-capabilities.md](08-engine-capabilities.md). In 0.1, MySQL / MariaDB and MongoDB never reach Full, and MongoDB Community only sees slow operations.

## 9. Discovery: scans and findings
1. On the agent page, open **Scan** on a target (administrator). Parameters are optional: rows sampled per object (default 200), maximum duration (900 s), statement timeout (30 s), database / schema / object filters and classifiers. The agent caps them with its local `limits`.
2. The agent page shows the last scan of each target and a link to its findings.
3. **Findings** lists, per target and classifier, the locations (database, schema or container, object, field) that hold a sensitive data type, with masked samples (at most 4 digits kept). Filter by agent, target and classifier.
4. An administrator can mark a finding as a **false positive**; the mark is cleared automatically when a later scan matches more values or uses another classifier set.

Classifiers and their semantics: [agent/crates/classifiers/README.md](../agent/crates/classifiers/README.md).

## 10. Audit: enabling it and reading events
1. On the agent page, open a target's **Audit** settings (administrator): enable Audit, set the aggregation window, poll interval and minimum rows, and choose the sensitive objects (derived from the findings by default, plus manual objects). A change that disables Audit or removes objects asks for a confirmation.
2. **Events** lists the access events, newest first, with their principal, score, signals (`signature.*` for known export tools such as `pg_dump` or `mongodump`, `shape.*`, `volume.*`), baseline anomaly flag and the incidents they matched. A principal's page shows its baseline, incidents and latest events. Principals are designated by a key, never by the account name in a URL; OpenLDAP users are sent as keyed fingerprints, except `anonymous`, the agent's own DN and the DNs listed in `openldap.clear_principals`.

Audit read positions (log offsets, cursors, profiler positions) and the agent's own-account row counters are kept in `state_dir` across agent restarts, so a restart resumes where the agent stopped, within what the source still holds; `pg_stat_statements` counters are the exception. Keep `state_dir` on a persistent volume.

The export signatures recognized per engine are listed in [08-engine-capabilities.md](08-engine-capabilities.md#known-export-signatures).

## 11. Policies, incidents and notifications
- **Policies** (administrator): a policy applies to findings or to access events (fixed at creation). Conditions on findings: classifiers or families (`pii.*`), agents, targets, engines, location globs, confidence and match thresholds. Conditions on access events: signals or families, actions, principals, objects, minimum rows, score or sensitivity, baseline anomaly ([console/README.md](../console/README.md#audit-correlation)). Action: create an incident with a severity, and notify up to 5 channels. **Exceptions** (with a mandatory reason and an optional expiry) silence a scope. Model: [ADR-0014](adr/0014-policy-and-incident-model.md), [console/README.md](../console/README.md#policies-and-incidents).
- **Incidents**: active incidents by default, most severe first. An incident shows its finding (with masked samples) or its events, its lifecycle and its notifications. Lifecycle: `open` → `acknowledged` → `resolved`, or `false_positive` (administrator). `resolved` means remediated: if a later scan still sees the data, a new incident opens.
- **Notifications** (administrator): e-mail (SMTP with STARTTLS or TLS) and HMAC-signed webhook (`https://` only) channels, with a test button. Webhook receivers must escape the names they render, because a database account name is chosen by the client ([console/README.md](../console/README.md#alerting)). Channels flagged for system alerts also receive the console's own alerts: silent agent, agent integrity, dropped batches, stopped Audit stream, within an hourly budget per channel.

## 12. Upgrading
Upgrade the **console first**, then the agents; a console `X.Y` accepts agents `X.Y` and `X.(Y-1)` ([RELEASE.md](../RELEASE.md#compatibility)). For **0.1.0**, upgrade the console and every agent together: agent builds from before the protocol capability negotiation (#60) cannot decode the console's heartbeat response ([ADR-0022](adr/0022-protocol-capability-negotiation.md)). `migrate` applies the console migrations on start; deployments created before the database role split need the one-time steps in [console/README.md](../console/README.md#upgrading-an-existing-deployment).

## 13. Reporting a problem
Bugs: GitHub issues. Vulnerabilities: never in a public issue, see [SECURITY.md](../SECURITY.md).
