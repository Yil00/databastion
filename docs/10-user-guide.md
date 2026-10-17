# User guide – DataBastion

How to install the console and an agent, enroll the agent, declare targets, give the agent least-privilege accounts, and read findings and incidents. This page only describes what the code on `dev` does; the component READMEs linked below hold the full reference.

> **Status.** v0.1.0, the first release, was published on 2026-09-30, v0.2.0, a maintenance release, and v0.3.0 (PostgreSQL audit levels: Full requires `pgaudit.log_rows`, [ADR-0037](adr/0037-postgresql-full-requires-pgaudit-log-rows.md)), both on 2026-10-03, then v0.3.1 on 2026-10-04 (MSRV Rust 1.88, masking of typographic separators, automated release notes), v0.4.0 on 2026-10-07 (OpenID Connect login, Users page, Apereo CAS targets), v0.5.0 on 2026-10-08 (maintenance: MySQL / MariaDB Audit fails closed, Apereo CAS YAML service registries), v0.6.0 on 2026-10-10 (maintenance: MySQL / MariaDB Audit reports reads of statement-text tables and calls of functions that are not built in, Apereo CAS YAML registries read by the agent's own parser) and v0.7.0 on 2026-10-14 (maintenance: PostgreSQL Audit reports failed and cancelled reads and reads of the statistics, statement-text and credential-bearing catalogs, MySQL / MariaDB Audit reports `EXPLAIN` of a statement, MongoDB Audit reports failed operations and server-side JavaScript) ([latest release](https://github.com/Yil00/databastion/releases/latest)); it is early-stage software, and its known limitations are listed in the [CHANGELOG](../CHANGELOG.md) and [SECURITY.md](../SECURITY.md#known-limitations-and-residual-risks). The installation test passes in CI in under 15 minutes and the load tests are done; the 72 h stability test is deferred to v0.1.x ([ROADMAP](ROADMAP.md#v01x-follow-ups)). Read [08-engine-capabilities.md](08-engine-capabilities.md) before relying on Audit for an engine.

> **New in 0.8.0** (phase 9, [ROADMAP](ROADMAP.md#phase-9--engine-scope-wave-1-microsoft-sql-server-redis-valkey)): Microsoft SQL Server targets, with Audit from SQL Server Audit or an Extended Events session ([section 6](#microsoft-sql-server-targets)), and Redis and Valkey targets, mainly for Discovery ([section 6](#redis--valkey-targets)). They need a 0.8.0 console. Upgrading from 0.7.x: read [section 12](#12-upgrading) first.

> **New in 0.4.0** (phase 8, [ROADMAP](ROADMAP.md#phase-8--oidc-login--cas-connector)): console login with OpenID Connect and the Users page ([section 3](#single-sign-on-with-openid-connect)), and Apereo CAS targets with the CAS store guard in the other connectors ([section 6](#6-declare-targets)). Upgrading from 0.3.x: read [section 12](#12-upgrading) first.

New to DataBastion? The [tutorial](11-tutorial.md) walks through a first installation and a first scan step by step, and through a development setup with `make`.

## 1. What you deploy
| Component | Where | Network |
|-----------|-------|---------|
| **Console**: `web`, `worker`, one-shot `migrate`, internal PostgreSQL 17 | One host, behind an HTTPS reverse proxy | Inbound HTTPS from users and agents; outbound from the worker to the SMTP relay and webhook receivers, and from `web` to the OpenID Connect provider when single sign-on is on |
| **Agent**: `databastion-agent`, one per host or network zone | Close to the monitored databases; on the database host itself when Audit reads a log file | Outbound HTTPS to the console and connections to its declared targets only; **no listening port** (I1) |

The agent is the only client of the console's agent API. Database credentials stay in the agent's configuration on its host (I3); the console only receives locations, masked samples and keyed fingerprints (I2). Architecture: [02-architecture.md](02-architecture.md). Security model: [05-security.md](05-security.md).

## 2. Get the images
The step-by-step installation, with the commands, is in [deploy/README.md](../deploy/README.md); this guide does not repeat it. Each release publishes, from [publish.yml](../.github/workflows/publish.yml) only:
- the console and agent images, `ghcr.io/yil00/databastion-console` and `ghcr.io/yil00/databastion-agent` (amd64, arm64, distroless, non-root), with an SBOM and a provenance attestation;
- on the GitHub release: the agent package `databastion-agent_<version>_<arch>.deb` (amd64, arm64), the deployment files `databastion-deploy-<version>.tar.gz`, `image-digests.txt`, and a `SHA256SUMS` list with its cosign bundle.

Tags are `X.Y.Z` or `X.Y.Z-rc.N`, without a `v` prefix. Use the same version for the console and the agents ([RELEASE.md](../RELEASE.md#2-versions)).

**Verify before installing.** Everything is signed with cosign in keyless mode, only in the run of `publish.yml` triggered by the push of the release tag ([ADR-0034](adr/0034-release-signing-from-tag-push.md)). Check the certificate identity exactly, never with a pattern:

```
--certificate-identity "https://github.com/Yil00/databastion/.github/workflows/publish.yml@refs/tags/<version>"
--certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-github-workflow-trigger push
```

Verify `SHA256SUMS` with `cosign verify-blob`, every downloaded file against it, and each image of `image-digests.txt` with `cosign verify`, as in [deploy/README.md, "Verify the artifacts"](../deploy/README.md#verify-the-artifacts) (also [SECURITY.md](../SECURITY.md#verifying-release-artifacts)). Then deploy the images **by digest**, never by a bare tag.

Until a release is published, build the images from a checkout (and the `.deb` as in [deploy/README.md](../deploy/README.md#building-the-deb)):
```sh
docker build -t databastion-console:local console/
docker build -t databastion-agent:local agent/
```

## 3. Install the console
Follow [deploy/README.md, "Console"](../deploy/README.md#1-console). In short: extract the verified deployment bundle, copy [docker-compose.example.yml](../deploy/docker-compose.example.yml) to `compose.yaml` and [.env.example](../deploy/.env.example) to `.env`, set in `.env` the console image **with its digest** (the console line of `image-digests.txt`), the console's DNS name (`DATABASTION_DOMAIN`) and the TLS mode (`DATABASTION_TLS`: an e-mail address for a Let's Encrypt certificate, or `internal` for Caddy's own CA, which the agents then pin), generate the secrets with `./init-secrets.sh`, start with `docker compose --profile proxy up -d`, and create the first administrator once with `docker compose run --rm bootstrap-admin` (there is no default account; the command refuses to run once a user exists; delete `secrets/admin_password` afterwards). Every console setting is described in [console/README.md](../console/README.md#configuration); the three database roles in [console/README.md](../console/README.md#database-roles).

The bundled Caddy proxy (`proxy` profile) is the only published port. To use your own HTTPS reverse proxy instead, add [docker-compose.own-proxy.example.yml](../deploy/docker-compose.own-proxy.example.yml), which publishes the console on `127.0.0.1:8080`, as described in deploy/README.md. Keep `DATABASTION_TRUST_PROXY: "1"` only if that proxy is the single hop and sets or overwrites `X-Forwarded-For`. The proxy must not log the `Authorization`, `Cookie` or `X-CSRF-Token` headers ([05-security.md](05-security.md#deployment-recommendations)). Session cookies are `Secure`: the UI is not usable over plain HTTP.

Check: `GET /api/health/ready` answers `200`, and you can sign in. `secrets/encryption_key` protects the secrets the console stores: keep a copy offline.

Notes:
- Roles: `admin` and `analyst` (read-only). Versions up to 0.3.1 have no user-management page: the bootstrap administrator is the only account. Since 0.4.0, administrators create local users, change roles and disable accounts on the **Users** page (`/users`); the console always keeps one enabled administrator ([console/README.md](../console/README.md#first-administrator)).
- Without a usable `DATABASTION_ENCRYPTION_KEY`, the web and worker processes refuse to start in production. Changing it later makes the stored masked samples and notification channel secrets unusable ([console/README.md](../console/README.md#configuration)).
- Prometheus metrics: `/metrics` on the dedicated port `9464`, with the `metrics_token` as bearer token ([console/README.md](../console/README.md#metrics)). Never publish that port: it must be reachable only by Prometheus, on the internal network.
- Plan the internal database's `max_connections` from the sizing in [console/README.md](../console/README.md#docker-image).
- With your own PostgreSQL for the console, create its database with a UTF-8 character type (`LC_CTYPE` such as `en_US.UTF-8` or `C.UTF-8`, not `C` or `POSIX`); the bundled image already does. Under `C` / `POSIX`, object matching stays correct but the worker reads every finding of an agent for each batch of events that names a non-ASCII object, which is slower on large installations ([deploy/README.md](../deploy/README.md#1-console)).

### Single sign-on with OpenID Connect
*Since 0.4.0 (ROADMAP P8-A, [ADR-0038](adr/0038-console-oidc-login.md)).* The console can sign users in through one OpenID Connect provider (Keycloak, Microsoft Entra ID, Okta, Authentik…). Every setting is in [console/README.md, "Single sign-on (OIDC)"](../console/README.md#single-sign-on-oidc); the security model and residual risks in [05-security.md](05-security.md#console-login-with-openid-connect). OIDC needs `DATABASTION_PUBLIC_URL` and a usable `DATABASTION_ENCRYPTION_KEY`: without them the console refuses to start.

**1. Register a client at the provider.** A confidential client (client secret), standard flow (authorization code) only, PKCE `S256` if the provider enforces a method, redirect URI `https://<console>/api/auth/oidc/callback` and post-logout redirect URI `https://<console>/login`. Release the user's groups in the ID token through a claim **only the provider's administrators can set**. With Keycloak (a realm `acme`):
- *Clients* → *Create client*: client type OpenID Connect, client id `databastion`; *Client authentication* on; *Standard flow* only (no direct access grants, no implicit flow); the two URIs above; under *Advanced*, PKCE method `S256`;
- the client's *Client scopes* tab → `databastion-dedicated` → *Configure a new mapper* → *Group Membership*: token claim name `groups`, *Full group path* off, *Add to ID token* on;
- groups `databastion-admins` and `databastion-analysts`, with the users as members;
- the client secret from the client's *Credentials* tab, stored in a file on the console host.

The [Keycloak dev realm](../dev/README.md#keycloak-oidc-test-realm) is a complete example, with test users for each refusal case.

**2. Configure the console** in the environment of the `console` service of `compose.yaml`, where [docker-compose.example.yml](../deploy/docker-compose.example.yml) has the commented lines, with the secret `oidc_client_secret` (the client secret file) declared at the end of the file and added to that service's `secrets:`:

```yaml
DATABASTION_OIDC_ENABLED: "1"
DATABASTION_OIDC_ISSUER_URL: https://sso.example.com/realms/acme      # exact issuer, https://
DATABASTION_OIDC_CLIENT_ID: databastion
DATABASTION_OIDC_CLIENT_SECRET_FILE: /run/secrets/oidc_client_secret
DATABASTION_OIDC_DISPLAY_NAME: Keycloak
DATABASTION_OIDC_GROUPS_ATTRIBUTE_PATH: groups
DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "contains(groups, 'databastion-admins') && 'admin' || contains(groups, 'databastion-analysts') && 'analyst'"
DATABASTION_OIDC_ALLOWED_GROUPS: databastion-admins,databastion-analysts
# DATABASTION_OIDC_CA_FILE: /run/secrets/oidc_ca                      # provider behind a private CA
```

- **Groups and roles.** The role expression must yield exactly `admin` or `analyst`; anything else is no role, and with strict mode (`DATABASTION_OIDC_ROLE_ATTRIBUTE_STRICT=1`, the default) such a login is refused. The role is applied again at each login. Never base the role, groups or domains on `email`, `preferred_username` or `name`: users can often edit them at the provider. The groups claim must be a **list**: in the role expression, `groups` is the validated list, and a groups claim sent as a single string counts as no groups (so `x-databastion-admins-y` can never match `contains(groups, 'databastion-admins')`); with Keycloak, keep the Group Membership mapper as shown above.
- **New users.** Sign-up is off by default: a first login of an unknown identity is refused and listed as a **pending login** on the Users page, where an administrator approves it as a new user or discards it. While the provider sets roles (a role expression without `DATABASTION_OIDC_SKIP_ROLE_SYNC=1`), the page shows the role the provider maps the login to and only offers approval with that role, since the next login would apply it anyway; otherwise the administrator chooses the role. `DATABASTION_OIDC_ALLOW_SIGN_UP=1` creates the user directly, and requires `DATABASTION_OIDC_ALLOWED_GROUPS` or a strict role expression.
- **Sessions** last at most `DATABASTION_OIDC_SESSION_MAX_AGE` (12 h by default) with the usual 2 h idle timeout. A user disabled at the provider keeps an open console session until then, unless `DATABASTION_OIDC_USE_REFRESH_TOKEN=1` (the session then ends at the first failed refresh). A refresh checks the groups and role again only when the provider returns claims: a new ID token, or, with `DATABASTION_OIDC_USE_USERINFO=1`, the userinfo endpoint, as plain JSON (signed userinfo is not supported), which must then release the login claim (`preferred_username`), `email` and `email_verified` when `DATABASTION_OIDC_ALLOWED_DOMAINS` is set, and the `groups` claim (with Keycloak, turn *Add to userinfo* on in the mapper); the console warns at startup when refresh is on without it. Without either, a user removed from `databastion-admins` keeps the administrator role until their next login. Disable the user in the console as well to end their sessions at once.

**3. Local login.** `DATABASTION_LOCAL_LOGIN` keeps the password form for local accounts:
- `admins` (the default while OIDC is on): local administrators only, the **break-glass** path if the provider is down or misconfigured. Each such login raises the `user.local_login` system alert on the channels flagged for system alerts; keep at least one local administrator with a strong password, stored offline (the console logs an error at startup when there is none);
- `enabled`: every local user; `disabled` (only when set explicitly): no local login at all, and recovery then needs access to the console host.

Existing local users who are not administrators cannot sign in with their password once OIDC is on (`admins`). To move them to single sign-on, open a short migration window: set `DATABASTION_LOCAL_LOGIN: enabled` and restart (the console logs a warning at startup for as long as it stays so), tell the users to sign in locally and link single sign-on from **Account** (step 4), follow the links on the Users page and in the audit log (`user.identity_link`), then remove the variable (back to `admins`) and restart, and disable the local users who did not link. Details in [console/README.md, "Migrating local users"](../console/README.md#single-sign-on-oidc).

**4. Linking and unlinking.** An existing local user binds their provider identity themselves: sign in locally, open **Account**, choose **Link single sign-on**, and authenticate again at the provider. Identities are matched by issuer and subject, never by e-mail or username: a provider user whose username or e-mail equals an existing console account is refused, not merged, and administrators cannot link an identity to someone else's account. An administrator can unlink a wrongly linked identity on the Users page (its sessions end), but not the last way a user can sign in.

Check: the login page shows "Sign in with Keycloak"; a first login of a member of `databastion-analysts` appears as a pending login on the Users page and, once approved, lands on `/agents` as an analyst; a user outside both groups is refused with a `user.login_denied` entry (reason `group`) in the console audit log.

## 4. Install an agent
Deploy the agent on the host or network of the databases it monitors, not next to the console. Two ways:

- **`.deb` package** (Debian 12, Ubuntu 24.04, amd64 or arm64, with systemd), the documented path on a database host: [deploy/README.md, "Agent (`.deb`)"](../deploy/README.md#2-agent-deb). The package creates the `databastion` system user, installs `/etc/databastion/agent.yaml` and a hardened `databastion-agent` service (no capability, read-only system, `bind()` / `listen()` / `accept()` refused by the system-call filter), neither enabled nor started before enrollment. Paths, modes and service customization (group access to audit log files, sockets under `/tmp`, proxy): [deploy/README.md, "Agent package reference"](../deploy/README.md#agent-package-reference).
- **Image**, for container hosts: [agent-compose.example.yml](../deploy/agent-compose.example.yml), copied to the agent host, image pinned by version and digest. Run it as uid/gid 10001, with `read_only: true`, `cap_drop: ALL` and `no-new-privileges` ([agent/README.md](../agent/README.md#docker-image)). The image has no health check because the agent has no listener: its health is shown by the console (agent status, `databastion_agent_up`).

| Path | Content |
|------|---------|
| `/etc/databastion/agent.yaml` (read-only for the agent) | Configuration: console URL, limits, targets |
| `/var/lib/databastion` (`0700`, owned by the agent user) | Identity, local HMAC key, spool, audit cursors |
| Secret files referenced by `agent.yaml` (`0600`, owned by the agent user) | Database passwords |
| Log files of the targets (read access through a group, never ownership), for file-based Audit sources | e.g. the pgaudit or `server_audit` log |

**`agent.yaml`**: start from [agent/agent.example.yaml](../agent/agent.example.yaml). Unknown keys are rejected. The main settings:
- `console.url`: the console's public HTTPS URL. `console.ca_file` pins a private CA (it then is the only trusted root). TLS 1.3 minimum. `HTTPS_PROXY` / `NO_PROXY` are honored.
- `state_dir`: a directory owned by the agent user, not group- or world-writable.
- `limits`: local caps that console jobs cannot exceed (rows sampled per object, statement timeout, scan duration, audit poll interval), and `discovery_duty_cycle_percent`, the Discovery pacing (see [section 9](#9-discovery-scans-and-findings)).
- `spool`: bounded disk buffer for results while the console is unreachable. When it is full, batches are dropped by priority: findings and events can each grow to 3/4 of the bounds, so each keeps at least 1/4 (an events flood can evict findings down to that quarter); batches with a `signature.*` signal go last; otherwise the oldest first; the console raises an `agent.batches_dropped` alert.
- `targets`: see [section 6](#6-declare-targets).

Keep the agent host's clock in sync (NTP): it must stay within 5 minutes of the console's. Logs are JSON on stdout (with the `.deb`, `journalctl -u databastion-agent`); `DATABASTION_LOG` sets the level.

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
   With the `.deb`, run it as the service's user, so that the identity it writes is owned by that account: `sudo runuser -u databastion -- databastion-agent enroll …` ([deploy/README.md](../deploy/README.md#2-agent-deb)). With the image, use the one-shot `agent-enroll` service of [agent-compose.example.yml](../deploy/agent-compose.example.yml): `docker compose --profile enroll run --rm agent-enroll`. `DATABASTION_ENROLLMENT_TOKEN_FILE` can replace `--token-file`.
4. Delete the token file, then start the agent: `sudo systemctl enable --now databastion-agent` with the `.deb`, `docker compose up -d agent` with the image, or `databastion-agent run --config /etc/databastion/agent.yaml` by hand.
5. The agent appears under **Agents** as `online`, with its targets, their reachability and their audit level.

Enrollment stores the agent identity (`identity.json`) and generates the local HMAC key (`hmac.key`) in `state_dir`, both `0600`; the HMAC key never leaves the host. Protocol details: [09-agent-protocol.md](09-agent-protocol.md#enrollment).

Afterwards, from the agent page (administrator):
- **Rotate secret**: the agent generates its new secret itself ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)).
- **Revoke**: effective immediately. To bring the host back, create a new token and run `enroll --force` (it replaces the identity and keeps the HMAC key unless `--new-hmac-key` is given). A suspected compromise is handled by revocation and re-enrollment, never by rotation.

## 6. Declare targets
Targets are declared **only** in `agent.yaml`, on the agent host: the console cannot add a target, and the agent never scans the network (I5). The agent also reports, in its heartbeat, the undeclared database engines it detects on its own host (Unix sockets, local listening ports, process names; never an address; [agent/README.md](../agent/README.md#local-engine-detection-adr-0006-i5)). The console stores them but the 0.1 UI does not display them.

Each target has:
- `id`: a slug shown in the console (do not put a host name in it);
- `engine`: `postgres`, `mysql`, `mariadb`, `mongodb`, `openldap` or `cas` (Apereo CAS, below; since 0.4.0); `redis`, `valkey` and `sqlserver` since 0.8.0 ([Redis / Valkey](#redis--valkey-targets), [Microsoft SQL Server](#microsoft-sql-server-targets));
- `host` and `port`, or `socket`;
- `account` and `secret`: a **reference** to the password, `env: VAR_NAME` or `file: /path` (`0600`, owned by the agent user), never the password itself. OpenLDAP with `bind: sasl_external` over `ldapi://` needs no secret;
- an optional engine block (`postgres`, `mysql`, `mongodb`, `openldap`): databases to connect to, `tls` (`verify_full` by default; `disable` only on a socket or a loopback address; `disable_insecure` is an explicit, warned opt-in and does not exist for OpenLDAP), `ca_file`, and the Audit source files:
  - PostgreSQL: `postgres.audit_log: {path, format: jsonlog | csvlog}` (the pgaudit server log; without it, Audit uses `pg_stat_statements`);
  - MySQL / MariaDB: `mysql.audit_log: {path, format: server_audit | json}` (without it, `performance_schema`);
  - MongoDB: `mongodb.audit_log: {path, format: audit_log | server_log}` (without it, the profiler if granted);
  - OpenLDAP: `openldap.accesslog_base` (read over LDAP) and `openldap.clear_principals`;
  - every engine block (since 0.4.0): `cas_stores`, the names of Apereo CAS stores kept under custom names (`ticket_registry`, `service_registry`, `audit_trail`), for the CAS store guard below.

**PostgreSQL: declare every database that monitoring tools connect to** in `postgres.databases`, `postgres` included when an exporter (`postgres_exporter`, pgwatch, check_postgres…) or a pool health check connects there. A pgaudit log and `pg_stat_statements` cover every database of the server, but the agent checks for user functions, operators and types that shadow built-in ones only in the declared databases ([ADR-0049](adr/0049-postgresql-statement-text-views-as-reads.md) decision 8). In an undeclared database, every catalog query that calls a function or uses an operator such as `=`, `LIKE` or `IN` is reported as a read of `*`, from every role ([08-engine-capabilities.md](08-engine-capabilities.md#user-code-next-to-catalogs)).

The example file documents each key with its range. After changing `agent.yaml`, restart the agent.

**Apereo CAS targets** (`engine: cas`, [ADR-0041](adr/0041-cas-connector.md)) are local files on the agent's host, nothing else: no `host`, `port`, `socket`, `account` or `secret` (refused), and the agent never contacts CAS. Declare a `cas:` block with at least one of `service_registry.json_dir` or `service_registry.yaml_dir` (the JSON or YAML service registry directory; YAML files with anchors, aliases, merge keys or tags other than CAS class hints are skipped) and `audit_log.path` (the audit log), optionally `audit_log.timezone` (`UTC` or `±HH:MM`), `clear_principals` (service accounts sent by name; end users are fingerprinted) and `client_addr` (`truncated` by default: IPv4 `/24`, IPv6 `/56`; `clear`; `omitted`). The CAS side needs:
- `cas.audit.engine.audit-format: JSON`, written to a file by the audit log's logger with a layout that writes the message alone (`%m%n`), one record per line; preferably without request headers (`cas.audit.engine.http-request-headers` empty, or `auditable-fields` without `headers`), else the note `security.audit_headers_logged`;
- client secrets of OAuth / OIDC services encrypted (`security.client_secrets_in_clear` counts the clear ones), and the ticket registry's `crypto.enabled: true` when it lives in a database;
- the agent's OS user with **read** access to the registry directory and the audit log through a group without write permission (`0640` files, `0750` directory), no write access anywhere on the path (refused, `privilege.registry_writable` / `audit.log_not_readable`), and **no access to the CAS configuration** (`cas.properties`, `cas.yml`): a registry directory holding configuration or key files is refused (`privilege.config_readable`).

A console older than the `cas` engine (it does not list `engine.cas`) shows no CAS target: the agent keeps its findings and events spooled until the console is upgraded. CAS stores held in PostgreSQL, MySQL / MariaDB, MongoDB or OpenLDAP (JPA ticket and service tables, MongoDB collections) are read by those engines' targets, under the **CAS store guard**, on by default: ticket registries are never sampled (ticket counts only), ticket ids are dropped before classification wherever they appear, and the agent reports an account that can read ticket or audit-trail credential columns (`privilege.ticket_credentials_readable`) at every heartbeat ([08-engine-capabilities.md](08-engine-capabilities.md#cas-store-guard-postgresql-mysql--mariadb-mongodb-openldap)). List stores kept under custom names in that target's `cas_stores`. Levels and limits: [08-engine-capabilities.md](08-engine-capabilities.md#apereo-cas).

### Redis / Valkey targets
*Since 0.8.0 (phase 9, P9-B, [ADR-0052](adr/0052-redis-valkey-connector.md)).* The connector needs a console that lists the `engine.redis` and `engine.valkey` capabilities; until then the agent keeps the items spooled. Redis and Valkey are mainly Discovery engines: Audit is Limited at best ([08-engine-capabilities.md](08-engine-capabilities.md#redis--valkey-audit)).

Supported: Redis 6.2.7 and later and Valkey 7.2 and later. Declare one node per target, with `engine: redis` or `engine: valkey`, a named ACL user as `account` (never `default`) and its password as `secret`:

```yaml
targets:
  - id: cache-eu-1
    engine: valkey
    host: cache-eu-1.internal
    port: 6379
    account: databastion
    secret: { file: /etc/databastion/secrets/cache-eu-1 }
    redis:
      tls: verify_full                     # default; TLS from the first byte
      ca_file: /etc/databastion/tls/cache-ca.pem
      # client_cert: /etc/databastion/tls/agent.pem   # with tls-auth-clients yes
      # client_key: /etc/databastion/tls/agent.key    # 0600, owned by the agent's user
      key_patterns: ["app:*", "session:*"] # the ACL's read patterns; default ["*"]
      databases: [0, 1]                    # default: every database
      max_keys: 100000                     # keys examined per database and scan (1000 to 10000000)
      discovery_node: { host: cache-eu-1-replica.internal, port: 6379 }  # a replica, for Discovery
      replicas: [10.0.4.12]                # known replica addresses, compared for full syncs only
      # cas_stores: { ticket_registry: ["CAS_TICKET:*"] }
```

- **`tls`**: `verify_full` (default) or `disable`. `disable` is accepted only with `socket` (a Unix socket) or a loopback IP literal such as `127.0.0.1`, never `localhost`. There is no `disable_insecure`, because `AUTH` sends the password itself. `ca_file`, `client_cert` and `client_key` need `verify_full`.
- **Unix socket**: `socket: /run/valkey/valkey.sock` instead of `host` / `port`, with `tls: disable`. The agent checks the server process's uid on the socket before sending the password. Set **`server_uid`** to the server's uid; without it, the socket file's owner is trusted only when no other user can write to the socket's directory (as with `/run/valkey`). On a socket, Audit cannot attribute any entry to an account, the agent's own included ([08-engine-capabilities.md](08-engine-capabilities.md#redis--valkey-audit)).
- **`key_patterns`**: if the ACL user's key patterns are narrower than `%R~*`, list them here with the server's glob syntax (at most 64). The agent never sends a command the ACL would refuse, because each refusal writes an `ACL LOG` entry. A pattern the account cannot read is reported as `privilege.declared_keys_not_readable`.
- **`databases`**: the logical databases to scan (indexes). On Valkey 9.1+ with `db=` ACL permissions, list the same databases.
- **`discovery_node`**: a replica that Discovery reads instead of the target's node (`host` / `port` or `socket`, with the target's account and TLS settings). Declaring one is recommended, so the scan load and lazy expirations stay off the primary. `check()` and Audit still read the target's node, since the logs are per node. If the Discovery node is down, the whole target shows as unreachable.
- **`replicas`**: the replicas' IP addresses as the server lists them. A full synchronization is always reported (`signature.full_sync`); a syncing replica not listed here becomes the event's client address.
- **`unevaluated_acl: accept`**: Redis 6.2 only. Redis 6.2 cannot evaluate the account (no `ACL DRYRUN`), so it is refused unless you set this after reviewing the ACL by hand; the target then shows `privilege.not_evaluated` permanently. On Redis 7.0+ or Valkey it is a configuration error.
- **Cluster**: each node is a separate target; the agent never follows `MOVED` / `ASK` or the cluster topology. Sentinel is refused.

Create the ACL user on each node the agent reads, as in [05-security.md, "Recommended database accounts"](05-security.md#recommended-database-accounts-read-only): `-@all` plus the listed read commands on `%R~*` (or the declared patterns), `resetchannels`, and the Audit commands (`slowlog|get`, `acl|log`, `client|list`, Valkey 8.1+ `commandlog|get`) only where Audit runs. An account that can run `CONFIG SET`, `MODULE LOAD`, `ACL SETUSER`, scripts, `REPLICAOF`, `MIGRATE` or another refusal-list command is refused for Discovery and Audit. For Audit, set the server's `slowlog-log-slower-than` (Valkey 8.1+: `commandlog-execution-slower-than`) low enough for the commands you want to see: only commands slower than it are logged.

**What a stolen agent credential reads.** The server enforces the ACL, not the agent's sampling bounds. Whoever holds the agent's password can run every command of the recommended ACL with any arguments ([05-security.md](05-security.md#redis--valkey-connector)):
- **Every string in full**: with `%R~*` (or the declared patterns) and `+getrange`, `GETRANGE key 0 -1` reads a whole string, as `GET` would. The 4 KiB bound (`GETRANGE key 0 4095`) is the agent's, not the server's, and so are its member counts for `HRANDFIELD`, `SRANDMEMBER`, `ZRANDMEMBER`, `LRANGE`, `XREVRANGE` and `HMGET`. Leaving out `GET` does not protect the values.
- **Other clients' commands and the connection map** (Audit commands only): `+slowlog|get`, `+commandlog|get` (Valkey 8.1+) and `+client|list` return other clients' logged command arguments, values included (at most 32 arguments of 128 bytes per entry), and every connection's address, user and client name.
- **`ACL LOG RESET`**: `+acl|log` also allows the reset, so a stolen credential can clear the log of failed authentications and refused commands. A reset shows only as a gap, and only if entries were lost.
- **An oracle on users**: `+acl|dryrun` lets the credential ask which commands any user may run, and whether a user name exists. It returns no password hash.

The agent itself never sends `ACL LOG RESET`, a `GETRANGE` beyond 4 KiB, or `ACL DRYRUN` for a user other than its own and `default`: its client has a closed command set. Grant the Audit commands only on nodes where Audit runs, prefer narrower `key_patterns` where you can, and protect the password like the data.

### Microsoft SQL Server targets
*Since 0.8.0 (phase 9, P9-A: `check()` and Discovery in #242 and #243, Audit from SQL Server Audit in #247 and from Extended Events in #249).* Audit reads an operator-created SQL Server Audit on SQL Server 2022 and 2025 ([below](#sql-server-audit)), or an operator-created Extended Events session, the only Audit source on **SQL Server 2019** ([below](#sql-server-audit-through-extended-events)). The agent needs a console that lists the `engine.sqlserver` capability; until then it keeps the items spooled. Limits and measurements: [08-engine-capabilities.md](08-engine-capabilities.md#microsoft-sql-server-discovery); decisions: [ADR-0051](adr/0051-sqlserver-connector.md) and its refinement of 2026-10-14.

Supported: SQL Server 2019, 2022 and 2025, Standard, Enterprise, Developer and Express editions; Azure SQL is refused. Tested: 2022 Express in CI (the integration job `agent-sqlserver`, and the end-to-end job `e2e-sqlserver` with SQL Server Audit), and 2019, 2022 and 2025 Express in the engine matrix. Declare one `host` and `port` per target (default 1433; no Unix socket): the agent does not use the SQL Server Browser, so a named instance is reached by its port. The `account` is a **SQL login**: Windows integrated authentication, Microsoft Entra ID and contained database users are not supported. Local detection reports a SQL Server listening on port 1433 or running as a `sqlservr` process; it is monitored only once declared.

```yaml
targets:
  - id: erp-eu-1
    engine: sqlserver
    host: erp-db-1.internal              # a name (or IP literal) in the server certificate
    port: 1433
    account: databastion_agent
    secret: { file: /etc/databastion/secrets/erp-eu-1 }
    sqlserver:
      tls: auto                          # default; or strict, or mandatory
      ca_file: /etc/databastion/tls/sqlserver-ca.pem   # absolute path; otherwise the system store
      databases: [app]                   # default: every user database the login can access
      rls_visibility: view_definition    # opt-in, see below: without it, nothing is sampled
      # extended_grants: true            # db_datareader instead of per-schema SELECT
      # max_tables: 16384                # tables per database and scan (1 to 16384, the default)
      # audit:                           # Audit source (see below)
      #   source: sqlserver_audit        # or sqlserver_xevents; default auto
      #   audit_name: databastion_audit  # the server audit (2022+), created by the operator
      #   xe_session: databastion_xe     # the Extended Events session (2019+), created by the operator
```

The block also takes `cas_stores`, as the other engines do ([section 6](#6-declare-targets)). Unknown keys are refused.

**TLS.** Every connection is encrypted, loopback included, because the SQL Server login packet carries the password in a reversible form: there is no `disable` mode. Every mode verifies the server certificate against `ca_file` (then the only trusted root) or the system store, and the declared host. Install on the server a certificate issued by a CA the agent trusts, whose subject alternative name holds the declared host or IP literal (`127.0.0.1` as an IP SAN for a loopback target). Without one, SQL Server uses a self-signed fallback certificate with no subject alternative name, regenerated at each service start: the agent refuses it, and there is no mode that trusts a server certificate without verifying it.
- **`auto`** (default): TDS 8.0 strict encryption first (TLS from the first byte). If the strict handshake fails before any TDS byte, the agent falls back once to `mandatory`, fully verified, then connects in `mandatory` for an hour before trying strict again (in memory only; every agent start tries strict first). A certificate error never causes a fallback.
- **`strict`**: TDS 8.0 only. On Linux, strict encryption exists from SQL Server 2025 (`network.forcestrict`); against 2019 or 2022 on Linux the connection fails, and the agent's log says "strict encryption not available on this server".
- **`mandatory`**: TDS 7.x, encryption required for the whole session; a server that offers login-only encryption or none is refused. Use `tls: mandatory` for SQL Server 2019, and for 2022 on Linux, to avoid a failed strict handshake every hour.
- **"Strict seen" mark**: once `auto` has completed one authenticated strict session with a target, the agent writes `<state_dir>/sqlserver-strict-seen/<target_id>` (mode `0600`, holding the declared host and port) and from then on never falls back to `mandatory` for that target: a strict failure fails the connection, so that someone on the network path cannot downgrade a known strict server. Setting the target's `tls` to `strict` or `mandatory` removes the mark at its next connection attempt, and a mark for another host or port is ignored. If you move the server to a version or configuration without strict encryption and keep `tls: auto`, the target shows as unreachable with a TLS-stage error: stop the agent, delete the file and start the agent again (the agent also keeps the mark in memory while it runs, so deleting the file alone has no effect until a restart), or set `tls: mandatory`, let the target attempt a connection, then set `tls: auto` again. Details: [08-engine-capabilities.md](08-engine-capabilities.md#tls-modes-and-the-strict-seen-mark).
- **What the console shows**: a TLS failure has no failure code of its own. The target is unreachable with `target_unreachable` (the fallback certificate, a certificate that does not verify, strict encryption not available), `timeout`, or `unsupported` (the server does not encrypt the whole session), with the note `check.stage_failed` labelled `stage_tls`; the exact reason is in the agent's log.

**The account (minimal grant).** As the login's administrator, with a client that does not log the statement text (it holds the password):

```sql
-- Once per server. Type the password at a prompt.
CREATE LOGIN databastion_agent WITH PASSWORD = '<from a prompt>',
  CHECK_POLICY = ON, DEFAULT_DATABASE = [app];
-- In each monitored database
USE [app];
CREATE USER databastion_agent FOR LOGIN databastion_agent;   -- grants CONNECT
GRANT SELECT ON SCHEMA::[crm] TO databastion_agent;          -- present and future tables of the schema
-- Row-level security opt-in (sqlserver.rls_visibility: view_definition), in each monitored database:
GRANT VIEW DEFINITION TO databastion_agent;
```

- Grant `SELECT` per schema to cover; a schema without it is not sampled. With `extended_grants: true`, membership of `db_datareader` replaces the per-schema grants and is reported as `privilege.extended_variant`; without the flag it is reported as over-privilege.
- `CHECK_POLICY = ON` applies the server's account lockout policy to the login: repeated failures (a wrong password in `agent.yaml`, or someone guessing it) lock the agent out, reported as `authentication_failed` with "login locked out" in the agent's log.
- The Audit grants are needed only where Audit runs: `VIEW SERVER SECURITY AUDIT` and `VIEW ANY SECURITY DEFINITION` for SQL Server Audit ([below](#sql-server-audit)), or `VIEW SERVER STATE` (2019) / `VIEW SERVER PERFORMANCE STATE` (2022+) for Extended Events ([below](#sql-server-audit-through-extended-events)), which **exposes every statement text on the server**. Held while no Audit stream uses them, they are reported as `privilege.audit_grant_without_audit`, like any Audit permission the agent does not use (`VIEW SERVER SECURITY STATE`, and `VIEW SERVER STATE` on 2022+).

**With the minimal grant, Discovery samples nothing.** SQL Server has no table-level flag that tells a table with a row-level security policy from one without (measured negative on SQL Server 2022), and the minimal account cannot see the policy catalog. Sampling such a table would run the policy's predicate function, user code, in the agent's session, and would silently miss the rows it hides. So, unless you opt in, **every table of every monitored database is skipped** (`skipped_row_level_security`), and `check()` reports `coverage.rls_not_verifiable` with the number of databases from the first heartbeat; the agent's log gives the reason. To sample:
1. declare `rls_visibility: view_definition` in the target's `sqlserver` block;
2. grant database `VIEW DEFINITION` to the agent's user in each monitored database (above).

`check()` then proves, per database, that `VIEW DEFINITION` is effective and that no `DENY` hides a policy again: no `DENY` of `VIEW DEFINITION`, `VIEW SECURITY DEFINITION` or `CONTROL` at database, schema or object scope, and no server-level `DENY` of `VIEW ANY DEFINITION`, `VIEW ANY SECURITY DEFINITION`, `VIEW SERVER SECURITY STATE` or `CONTROL SERVER`, to the agent, one of its roles or `public`. Any such `DENY`, or a proof that cannot be read, keeps the whole database skipped. With the proof, only the tables that have an enabled policy are skipped (`coverage.relations_rls_skipped`). Granting `VIEW DEFINITION` on single policies or schemas does not lift the skip: a policy created later would stay invisible. There is no setting that asserts "this database has no policy" in place of the proof.

**The cost of the opt-in**: database `VIEW DEFINITION` makes the definitions of the database readable by whoever holds the agent's credentials: the bodies of procedures, views, functions and triggers (which can hold literals, sometimes credentials or values), and, per ADR-0051, check and default constraint definitions, computed-column definitions and partition boundary values. The agent itself never reads them: its statements are a reviewed allow-list, and a test forbids every definition-bearing catalog, function and column in them. Decide per server whether Discovery is worth that exposure.

Not sampled in any case: views, synonyms, external and Stretch tables, computed columns, Always Encrypted columns (the server holds ciphertext only), and columns of types other than character types, `text` / `ntext`, `int`, `bigint`, `decimal`, `numeric`, `date`, `datetime`, `datetime2` and `smalldatetime` (so not binary types, `money`, `float` / `real`, `uniqueidentifier`, `time`, `datetimeoffset`…); at most 512 columns per table ([08-engine-capabilities.md](08-engine-capabilities.md#scope-and-sampling)). Columns under dynamic data masking are sampled as the agent's account sees them, masked. Masked, encrypted and computed columns and views are counted in target notes.

**What a stolen agent credential reads.** Measured with the minimal account on SQL Server 2022, beyond the tables it is granted ([08-engine-capabilities.md](08-engine-capabilities.md#what-a-stolen-agent-credential-reads)):
- **Always Encrypted key metadata**, through `public`'s default `VIEW ANY COLUMN ENCRYPTION KEY DEFINITION` and `VIEW ANY COLUMN MASTER KEY DEFINITION`: the encrypted column encryption key values and the column master key paths. The keys stay encrypted by the column master key, which is outside the server. `check()` accepts these two permissions only when they come from `public`; granted to the agent's login, user or roles they are reported as `privilege.beyond_select`.
- **`sys.servers.data_source`**: the host names of linked servers. Their `provider_string` was empty in the measurement; the agent never reads either column. A provider string can hold connection options and, when badly configured, a password: keep credentials out of it.
- **With the row-level security opt-in**: the module bodies and the security policies of the monitored databases (above).
- Also visible: the names and types of the objects the account can read, and `sys.masked_columns.masking_function` (a partial mask can hold a literal).
- Not readable with the minimal account (measured): other logins' password hashes, credentials, linked logins, keys and certificates, logon triggers, the `msdb` mail and proxy tables, other sessions and their statement texts.
- Not measured yet: whether `xp_dirtree` / `xp_fileexist` are executable by `public` on your server (they would let the account make the server open an outbound SMB connection). The agent never sends them.

**Refused accounts and what `check()` reports.** At every heartbeat, `check()` reads the login's effective permissions and its securable-level grants, in **every** database it can access, not only the monitored ones, following its server and database roles (up to 64). An account that holds any right of the refusal list is **refused**: `check()` reports `privilege.refused` with the rights as labels, and neither Discovery nor Audit runs. The refusal list:
- membership of `sysadmin`, `securityadmin` or `##MS_LoginManager##`, and of `db_owner` in any accessible database;
- `CONTROL SERVER`, `CONTROL` on any accessible database, `ALTER ANY SERVER AUDIT`, `ALTER ANY DATABASE AUDIT`;
- the event-session rights, server and database scope: `ALTER ANY EVENT SESSION` and its granular forms (`… ENABLE`, `… DISABLE`, `… ADD EVENT`, `… DROP EVENT`, `… ADD TARGET`, `… DROP TARGET`, `… OPTION`), `CREATE ANY EVENT SESSION`, `DROP ANY EVENT SESSION`, and their `DATABASE EVENT SESSION` counterparts;
- `ALTER ANY LOGIN`, `ALTER ANY SERVER ROLE`, `IMPERSONATE ANY LOGIN`, and `IMPERSONATE`, `CONTROL`, `ALTER` or `TAKE OWNERSHIP` on any login or database user;
- `VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION`;
- other logins' password hashes readable: a one-bit probe asks the server whether any other login's hash is visible, and no hash reaches the agent (label `password_hash_probe`).

The check fails closed: when one of these reads fails or is cut, `check()` reports `privilege.not_evaluated` with the label `refusal_list_probe`, and Discovery does not run. Rights beyond the minimal grant that are not refused are reported as over-privilege, to remove: `privilege.global_privileges` (server permissions such as `VIEW ANY DEFINITION`, `ADMINISTER BULK OPERATIONS`, `ALTER ANY LINKED SERVER`, `ALTER TRACE`), `privilege.server_roles`, `privilege.database_roles`, `privilege.beyond_select` (database permissions beyond `CONNECT` and `SELECT`, such as `UNMASK`, `VIEW DATABASE STATE`, `SHOWPLAN`, `EXECUTE`), `privilege.grant_option` and `privilege.owner_of_objects`. Logon triggers are visible only with rights the minimal account does not hold, so a minimal account shows `privilege.not_evaluated` with the label `logon_trigger_probe` at every heartbeat: that is expected, and the agent never reports "no logon trigger" while it cannot see them. A CAS store guard read that fails gives the label `cas_store_guard_probe`.

#### SQL Server Audit
Audit reads an operator-created **SQL Server Audit** with a `FILE` target, through `sys.fn_get_audit_file` over the agent's own connection. The agent never creates, alters, starts or stops the audit or its specifications. It works on **SQL Server 2022 and 2025** only: on 2019, reading the audit needs `CONTROL SERVER`, which is refused (`audit.sqlserver_audit_needs_control_server`); use the [Extended Events source](#sql-server-audit-through-extended-events) there. With both an audit and a session named, the agent uses SQL Server Audit when it is usable (2022 or later, its two grants held, the named audit found), otherwise the session. Levels, proofs and limits: [08-engine-capabilities.md](08-engine-capabilities.md#microsoft-sql-server-audit).

**1. Create the audit** (as an administrator, in `master`). A minimal example, adapted from the dev service (`dev/sqlserver/initdb/30-audit.sql`); choose the folder, sizes and `ON_FAILURE` for your server:

```sql
USE master;
CREATE SERVER AUDIT databastion_audit
  TO FILE (FILEPATH = N'/var/opt/mssql/audit/', MAXSIZE = 64 MB, MAX_ROLLOVER_FILES = 8)
  WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);   -- no WHERE predicate
CREATE SERVER AUDIT SPECIFICATION databastion_audit_spec FOR SERVER AUDIT databastion_audit
  ADD (SCHEMA_OBJECT_ACCESS_GROUP),       -- reads and writes, in every database
  ADD (AUDIT_CHANGE_GROUP),               -- changes of the audit itself
  ADD (FAILED_LOGIN_GROUP),               -- recommended: failed logins
  ADD (SERVER_PRINCIPAL_CHANGE_GROUP),    -- recommended: logins, users, roles and passwords (DCL)
  ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
  ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP),
  ADD (LOGIN_CHANGE_PASSWORD_GROUP),
  ADD (BACKUP_RESTORE_GROUP)              -- recommended: BACKUP DATABASE (signature.backup_database)
  WITH (STATE = ON);
ALTER SERVER AUDIT databastion_audit WITH (STATE = ON);
```

- **Required for Partial**: the audit enabled, with a `FILE` target and **no `WHERE` predicate** (`audit.server_audit_filtered` otherwise); `SCHEMA_OBJECT_ACCESS_GROUP` in an enabled server audit specification, or, per monitored database, an enabled database audit specification with `SCHEMA_OBJECT_ACCESS_GROUP` or `SELECT ON DATABASE::<db> BY public` (`audit.reads_not_logged` with the number of databases otherwise); `AUDIT_CHANGE_GROUP` in an enabled server audit specification (`audit.audit_changes_not_audited` otherwise).
- **Recommended**: `FAILED_LOGIN_GROUP` (`audit.failed_logins_not_audited` otherwise, not required for Partial), the principal and password change groups (password-bearing DCL, reported by class only) and `BACKUP_RESTORE_GROUP`.
- **Name**: an audit name with `/` or `\` is refused. The agent builds the file pattern from the catalog (folder, name, GUID), never from `agent.yaml`.
- **File sizes**: size `MAXSIZE` and `MAX_ROLLOVER_FILES` so that a file outlives a few poll intervals. A file lost to rollover before the agent read it is a gap.
- **`ON_FAILURE = CONTINUE`**: records lost when the audit cannot write are counted in `sys.dm_server_audit_status`, which the agent's grants do not read, so `check()` reports `privilege.not_evaluated` (label `other` until the contract has one). `SHUTDOWN` and `FAIL_OPERATION` lose no record but stop the server or fail statements when the audit cannot write: your choice.

**2. Grant the two Audit permissions** to the agent's login, in `master`, only on servers where Audit runs:

```sql
USE master;
GRANT VIEW SERVER SECURITY AUDIT TO databastion_agent;     -- reads the audit
GRANT VIEW ANY SECURITY DEFINITION TO databastion_agent;   -- the audit and specification catalogs
```

Never grant `VIEW SERVER SECURITY STATE` (not needed: the audit's own start and stop records prove its restarts) nor `CONTROL SERVER`, `ALTER ANY SERVER AUDIT` or `ALTER ANY DATABASE AUDIT` (refused: the account then gets no Discovery and no Audit). Without `VIEW ANY SECURITY DEFINITION` the level is None with `privilege.not_evaluated`. What these two permissions let a stolen credential read (the audit files, every login's name, certificate and key metadata of `master`; not password hashes, statement-text views or other sessions) is measured in [08-engine-capabilities.md](08-engine-capabilities.md#what-the-audit-grants-expose-measured).

**3. Name the audit in `agent.yaml`**, in the target's `sqlserver` block, then enable Audit for the target in the console ([section 10](#10-audit-enabling-it-and-reading-events)):

```yaml
    sqlserver:
      audit:
        source: sqlserver_audit          # or auto (default), which also takes xe_session (below)
        audit_name: databastion_audit    # sys.server_file_audits.name, 1 to 128 characters
```

`source: sqlserver_audit` requires `audit_name`.

**Levels.** Every SQL Server Audit target notes `audit.log_without_row_counts`: boxed SQL Server writes no row counts, so events carry no `rows`, raise no `volume.*` signal and score 0; incidents come from signals (`shape.full_table_read`, `signature.bcp`, `signature.backup_database`, `signature.remote_data_access`), objects and principals. With every proof held, the target is **Limited** (`audit.partial_pending_first_record`) until the stream reads its first record, then **Partial** while the stream runs; **never Full**. After a gap (a file lost to rollover, the audit stopped, restarted, recreated or moved, an unreadable position), the target notes `audit.records_dropped` and stays Limited for 24 h. The first start skips what the audit already holds.

**Not covered**: SQL Server 2019 (use Extended Events); reads through a view or procedure under ownership chaining are recorded on the view or procedure only; reads refused by a missing server permission leave no record; Windows servers and the Developer edition are not measured. The end-to-end and load tests (#254) run SQL Server Audit on 2022 Express only. The server's own telemetry process reads audited objects under the principal `<host name>$` (observed on Linux): those reads are reported, and match policies on every read; exclude that principal in those policies, scoped to the target, if they are noise ([08-engine-capabilities.md](08-engine-capabilities.md#known-limits-6)). The agent's own statements are left out only from its own sessions, by exact text or per-execution credit; the records of a session's last statement are matched up to 250 ms after the session's clean end, for that statement's exact text only, because they were stamped up to 2.5 ms after the computed end on 2022 (re-measured on 2019, 2022 and 2025 in #249: the audit's `event_time` stayed within two `SYSUTCDATETIME()` reads around a statement; not measured on Windows) ([08-engine-capabilities.md](08-engine-capabilities.md#microsoft-sql-server-audit)).

**Upgrade note.** The SQL Server labels above (`refusal_list_probe`, `logon_trigger_probe`, the database event-session permissions…) belong to the note-label revision `target_status.note_labels.2026_10_b`, and the agent sends `other` in their place until the console lists that token. Upgrade the console first, as usual. With several console replicas behind a load balancer, **upgrade every replica before any agent sees the `2026_10_b` token** (and `engine.sqlserver`): an agent uses a token as soon as one replica lists it, and a replica that does not know the values rejects them ([ADR-0022](adr/0022-protocol-capability-negotiation.md) decision 8).

#### SQL Server Audit through Extended Events
Audit can read an operator-created **Extended Events session** with an `event_file` target, through `sys.fn_xe_file_target_read_file` over the agent's own connection (#249). It is the only Audit source on **SQL Server 2019**, and it also works on 2022 and 2025. The agent never creates, alters, starts or stops the session. Partial at best, with row counts; levels, proofs and limits: [08-engine-capabilities.md](08-engine-capabilities.md#extended-events-source-and-grants).

**1. Create the session** (as an administrator). A minimal example, adapted from the dev service (`dev/sqlserver/initdb/30-audit.sql`); choose the folder and sizes for your server:

```sql
CREATE EVENT SESSION databastion_xe ON SERVER
  ADD EVENT sqlserver.sql_statement_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  ADD EVENT sqlserver.sp_statement_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  ADD EVENT sqlserver.rpc_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  -- recommended: failed logins (error 18456)
  ADD EVENT sqlserver.error_reported (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)
    WHERE ([error_number] = (18456)))
  ADD TARGET package0.event_file (SET filename = N'/var/opt/mssql/xe/databastion_xe.xel',
    max_file_size = 64, max_rollover_files = 8)
  WITH (TRACK_CAUSALITY = ON, STARTUP_STATE = ON, MAX_DISPATCH_LATENCY = 5 SECONDS);
ALTER EVENT SESSION databastion_xe ON SERVER STATE = START;
```

- **Required for Partial**: the session running with an `event_file` target; `sql_statement_completed`, `sp_statement_completed` and `rpc_completed`, each with the five actions above (`audit.xe_events_missing` otherwise); statement collection left on for the first two (do not set `collect_statement = 0`); **no `WHERE` predicate on these three events** (`audit.xe_session_filtered` otherwise). A predicate on `error_reported`, as above, is fine.
- **`error_reported` for failed logins**: without it, failed logins are not seen (the agent's log says so; no target note yet). The agent reads the error number and the name tried (fingerprinted), never the message. The predicate on 18456 keeps out error 17830, which every bare TCP connection such as a health check produces.
- **`TRACK_CAUSALITY = ON`** is recommended, not required: without it the target notes `audit.xe_causality_off`, statements are grouped by session and event order, and the statistics exclusions that need causality do not apply: the empty internal statements of each statistics build are reported as always-reported reads of `*`, and, on a new server, the agent's own statistics builds as reads of system tables by its login.
- **`MAX_DISPATCH_LATENCY`**: how long events can wait in memory before reaching the file. Keep it finite and short (the dev service uses 5 seconds): it bounds the first-start floor and the deferral of statistics builds; with `INFINITE`, the floor lasts up to 5 minutes.
- **Retention**: the default `EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS` can drop events under load; drops are counted by the server, and the target then notes `audit.records_dropped` and stays Limited for 24 h. `NO_EVENT_LOSS` can slow the server under load: your choice. The mode only appears in the agent's log.
- **File**: give the session a folder of its own (the agent reads every file named `<stem>_<n>_*.xel` in it, so another session with a matching name in the same folder would be read too), with a name of at most 260 characters without `*` or `?`. Size `max_file_size` and `max_rollover_files` so that a file outlives a few poll intervals: a file lost to rollover before the agent read it is a gap. The agent takes the path from the server, never from `agent.yaml`.
- A stop and start of the session (a new `create_time`) is a gap, and so is a change of the file name or folder.

**2. Grant the Extended Events permission** to the agent's login, in `master`, only on servers where Audit runs:

```sql
USE master;
GRANT VIEW SERVER STATE TO databastion_agent;               -- SQL Server 2019
GRANT VIEW SERVER PERFORMANCE STATE TO databastion_agent;   -- SQL Server 2022 and later, instead
```

**What it exposes**: with this permission, the agent's credentials read **every statement text on the server, with its literals**, through the statement-text views (`sys.dm_exec_sql_text`, `sys.dm_exec_query_stats`, cached plans, Query Store texts, `DBCC INPUTBUFFER`), every Extended Events file the server lets `sys.fn_xe_file_target_read_file` read, with the parameter values of every RPC that `rpc_completed` records, and the other sessions (measured on 2022: [08-engine-capabilities.md](08-engine-capabilities.md#extended-events-source-and-grants)). Grant it only where Audit runs, and protect the agent's password like the data. On 2022 and later, grant `VIEW SERVER PERFORMANCE STATE`, not `VIEW SERVER STATE`: the agent does not use the latter there and reports it as `privilege.audit_grant_without_audit`. Never grant `ALTER ANY EVENT SESSION` or the other event-session rights: they are refused, and the account then gets no Discovery and no Audit.

**3. Name the session in `agent.yaml`**, in the target's `sqlserver` block, then enable Audit for the target in the console ([section 10](#10-audit-enabling-it-and-reading-events)):

```yaml
    sqlserver:
      audit:
        source: sqlserver_xevents        # or auto (default)
        xe_session: databastion_xe       # the session's name, 1 to 128 characters
        # audit_name: databastion_audit  # with auto: SQL Server Audit when usable, else the session
```

`source: sqlserver_xevents` requires `xe_session`. With `source: auto` naming both, the agent uses SQL Server Audit when it is usable (2022 or later, its two grants held, the named audit found), otherwise the session, and checks again every 5 minutes; a switch between the two sources is a gap.

**Levels.** With every proof held, the target is **Limited** (`audit.partial_pending_first_record`) until the stream reads its first event, then **Partial** while the stream runs; **never Full**. Events carry row counts (`volume.large_result` above 10 000 rows). Objects are taken from the statement text: whenever the text may not name every object (dynamic SQL, a user function, an ambiguous or cut text…), and for every DDL and DCL statement, the event names `*` and is always reported. The first start skips what the session's files already hold, however large the backlog (since #255 the history boundary goes by the order of the events read; a step back of the server's clock beyond the delivery delay, at least 5 s, is counted as `audit.records_dropped`).

**Statistics builds: noise outside three server builds.** When a statement needs statistics that are missing or stale, SQL Server builds them inside the caller's request: an internal `SELECT StatMan(…) FROM [schema].[table] …`, followed by one to three internal statements with an empty text. The agent leaves these out **only on three exact builds** (`SERVERPROPERTY('ProductVersion')`), where users were shown unable to call `StatMan` themselves: **15.0.4500.2** (2019), **16.0.4305.5** (2022) and **17.0.5015.4** (2025), the builds of the engine matrix. On any other build, a newer cumulative update included, every automatic statistics build is reported:
- as a read of the table it builds statistics on, by whichever client's statement triggered it;
- with each of its empty internal statements as a read of `*`, always reported;
- on a new server, as reads of system base tables (`sys.sysschobjs`, `sys.syscolpars`…) by the agent's own login, triggered by the agent's catalog reads.

What to do:
- On another build, expect this noise: from every client, on new tables and after large data changes, whenever statistics are missing or stale.
- **Do not exclude the agent's account** in your policies: the exclusion would also hide reads made with a stolen copy of its credential.
- If an exclusion is needed, keep it narrow: a location exception on the table concerned, scoped to the target and the policy. Never an exception whose object glob matches the name `*` (the glob `*` itself, or `\*`): it would hide every read the agent could not name ([09-agent-protocol.md](09-agent-protocol.md#the-object-)).
- The list of builds changes only with an agent release, once a new build has been measured; it is refreshed per release, and a [phase 9 follow-up](ROADMAP.md#phase-9-follow-ups) makes the engine matrix's drift test check it for each cumulative update. After a SQL Server update, the exclusions come back with the first agent release that lists the new build. Details: [08-engine-capabilities.md](08-engine-capabilities.md#extended-events-statistics-builds).

**Not covered**: a refused `xp_cmdshell` leaves no event on this source; the plan cache (`sys.dm_exec_query_stats`) is not a source, so a server where neither SQL Server Audit nor a session is usable reports None; RPC calls of user procedures, `event_file` rollover while the agent reads, Windows servers and the Developer edition are not measured; this source is not in the end-to-end or load tests (integration tests and the engine matrix only).

## 7. Least-privilege accounts
Give each target a **dedicated, read-only** account (I4). The recommended accounts, with the exact statements, are in [05-security.md, "Recommended database accounts"](05-security.md#recommended-database-accounts-read-only):

| Engine | Discovery | Audit | Reference |
|--------|-----------|-------|-----------|
| PostgreSQL | `CONNECT` + per-schema `USAGE` / `SELECT` | `pg_read_all_stats`; the pgaudit log file readable by the agent | [ADR-0012](adr/0012-postgresql-agent-grants.md), [connector README](../agent/crates/connector-postgres/README.md) |
| MySQL / MariaDB | per-database `SELECT`, `REQUIRE SSL`, host restricted to the agent | no grant with a log file source; `SELECT ON performance_schema.*` only when it is the source | [ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md), [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md), [connector README](../agent/crates/connector-mysql/README.md) |
| MongoDB | custom role with `find` + `listCollections` per database, SCRAM-SHA-256, `authenticationRestrictions` with `clientSource` = the agent's address(es) | no grant with a file source; `find` on `system.profile` only for the profiler source | [ADR-0026](adr/0026-mongodb-connector.md), [ADR-0027](adr/0027-mongodb-audit.md), [connector README](../agent/crates/connector-mongodb/README.md) |
| OpenLDAP | service DN with `read` on the tree; rule `{0}` names **every** credential attribute of the loaded schemas (`userPassword`, `userPKCS12`, and the Samba, Kerberos, ppolicy… ones where loaded), never readable; a `peername.ip` restriction to the agent's address, since the accesslog records no client address | `read` on `cn=accesslog` only while Audit runs for the target (otherwise `privilege.accesslog_without_audit`) | [ADR-0029](adr/0029-openldap-connector.md), [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md), [connector README](../agent/crates/connector-openldap/README.md) |
| Apereo CAS (`cas`) | no account: the registry directory (`0750`) and its files (`0640`) readable through the agent's group, never writable, no access to the CAS configuration | the audit log (`0640`, directory `2750`) readable the same way | [ADR-0041](adr/0041-cas-connector.md), [05-security.md](05-security.md#recommended-database-accounts-read-only) (also the column grants for CAS tables held in a database), [connector README](../agent/crates/connector-cas/README.md) |
| Microsoft SQL Server (since 0.8.0) | SQL login with `CHECK_POLICY = ON`, a database user and `SELECT` per schema in each monitored database; database `VIEW DEFINITION` too with the row-level security opt-in, or Discovery samples nothing; never `sysadmin`, `db_owner` or the other refused rights | Only where Audit runs. SQL Server Audit (2022+): `VIEW SERVER SECURITY AUDIT` and `VIEW ANY SECURITY DEFINITION`. Extended Events: `VIEW SERVER STATE` (2019) or `VIEW SERVER PERFORMANCE STATE` (2022+), which expose every statement text on the server. Never `VIEW SERVER SECURITY STATE` or `CONTROL SERVER` | [ADR-0051](adr/0051-sqlserver-connector.md), [section 6](#microsoft-sql-server-targets), [05-security.md](05-security.md#microsoft-sql-server-connector) |
| Redis / Valkey (since 0.8.0) | ACL user: `-@all` plus `select`, `scan`, `type`, `getrange`, `hrandfield`, `hstrlen`, `hmget`, `srandmember`, `zrandmember`, `lrange`, `xrevrange`, `info`, `acl\|dryrun`, on `%R~*` or the declared patterns, `resetchannels`; never `default` | `slowlog\|get`, `acl\|log`, `client\|list` (Valkey 8.1+: `commandlog\|get`) | [ADR-0052](adr/0052-redis-valkey-connector.md), [05-security.md](05-security.md#redis--valkey-connector) |

Also:
- Size the account's connection limit as the recommended statements say: Audit holds its own connections.
- For file-based Audit sources, give the agent's OS user **read** access to the log directory only, never to the data directory. Run the agent as a dedicated non-root user: it refuses a log file its own account could write (`audit.log_not_readable`).
- At every heartbeat the agent checks each account and reports over-privilege and coverage problems as **target notes** on the agent page. A note about over-privilege means the account has more rights than recommended: remove them.

## 8. Audit prerequisites and levels
What Audit can see depends on the engine, its edition and its logging settings. The console shows the level reached for each target: **Full**, **Partial**, **Limited** or **None** (Discovery only). The prerequisites per engine (pgaudit, `server_audit`, `performance_schema`, `auditLog`, `slowms`, `slapo-accesslog`…) and the known limits are in [08-engine-capabilities.md](08-engine-capabilities.md). In 0.1, MySQL / MariaDB and MongoDB never reach Full, and MongoDB Community only sees slow operations. CAS never reaches Full either: Partial means authentications and ticket issuance are logged. SQL Server (since 0.8.0) reaches Partial at best, through SQL Server Audit on 2022 and 2025 or through Extended Events (the only source on 2019), and Redis / Valkey (since 0.8.0) Limited at best. PostgreSQL reaches Full only with pgaudit and `pgaudit.log_rows = on` (row counts in the log); without `log_rows` it is Partial ([ADR-0037](adr/0037-postgresql-full-requires-pgaudit-log-rows.md)). Since 0.7.0, Full also needs `log_min_messages` and `log_min_error_statement` at `error` or lower (the PostgreSQL defaults), so that failed and cancelled statements are logged with their text, for every role: no `ALTER ROLE … SET`, `ALTER ROLE … IN DATABASE … SET`, `ALTER DATABASE … SET` or function `SET` clause raising them above `error`, and, on PostgreSQL 15+, no `SET` or `ALTER SYSTEM` grant on them (`GRANT SET ON PARAMETER …`) to a role other than superusers (a grant to the agent's role is reported as an over-privilege). The agent reads these two settings only, filtered by the server ([05-security.md](05-security.md#recommended-database-accounts-read-only)). It reads them from `pg_db_role_setting` and `pg_proc` (and, on PostgreSQL 15+, the grants from `pg_parameter_acl`), which every role can read by default: no grant is needed. If `SELECT` on `pg_db_role_setting` was revoked from `PUBLIC`, grant it to the agent's role, or the target stays at Partial; check with `SELECT pg_catalog.has_table_privilege('databastion_agent', 'pg_catalog.pg_db_role_setting', 'SELECT')` (your agent role's name). An override or grant shows the target at Partial, and the agent's log names the database, the setting and the roles or functions. To get Full back, reset them (`ALTER ROLE app RESET log_min_error_statement`, `ALTER DATABASE shop RESET log_min_messages`, `ALTER FUNCTION f() RESET log_min_messages`) and revoke the grants (`REVOKE SET ON PARAMETER log_min_messages FROM app`); the level follows at the next heartbeat. Some operators raise `log_min_error_statement` for an application role to keep its statement texts out of the server log: that role's failed reads then leave no text, so the target is Partial.

**PostgreSQL failed and cancelled reads.** With `pgaudit.log_rows = on`, which Full requires, pgaudit writes its record only when a statement completes, so a read that ends in an error or a cancel, including one that already sent rows to the client, has no pgaudit record. Since 0.7.0, the agent reports such reads from the server's `ERROR` lines in the same log file, by SQLSTATE only (it never reads their message, which can quote the value read): a read of the statement's relations with no row count, always reported ([08-engine-capabilities.md](08-engine-capabilities.md#failed-and-cancelled-statements)). Keep `log_min_messages` and `log_min_error_statement` at `error` or lower (the defaults); otherwise the target shows Partial and the agent's log says which setting. Expect events from applications whose queries fail (a missing table, a constraint violation on an `UPDATE`). **Up to 0.6.x**, such reads are not reported at Full: if that matters more than row counts there, set `pgaudit.log_rows = off` for the monitored databases (such reads are then reported, with no row count, and the target shows Partial).

## 9. Discovery: scans and findings
1. On the agent page, open **Scan** on a target (administrator). Parameters are optional: rows sampled per object (default 200), maximum duration (3600 s since #94, to leave room for paced scans), statement timeout (30 s), database / schema / object filters and classifiers. The agent caps them with its local `limits`.
2. The agent page shows the last scan of each target and a link to its findings.
3. **Findings** lists, per target and classifier, the locations (database, schema or container, object, field) that hold a sensitive data type, with masked samples (at most 4 digits kept). Filter by agent, target and classifier.
4. An administrator can mark a finding as a **false positive**; the mark is cleared automatically when a later scan matches more values or uses another classifier set.

**Scans are paced, and therefore long.** To keep the monitored database under 2 % CPU while a scan runs, the agent pauses after each object's sampling and each catalog read so that its time in queries is at most `limits.discovery_duty_cycle_percent` of the scan's time (`agent.yaml`, default `1`, range 1 to 100, `100` disables pacing; [ADR-0035](adr/0035-discovery-pacing.md)). A scan uses one connection and the agent runs one scan at a time, so a scan costs the server at most about that share of one core. The cost is time: a scan lasts about `100 / d` times its query time, e.g. about 2 minutes instead of 7 seconds for 200 MariaDB tables at the default of 1 %.

Sizing the scan's **maximum duration** (`max_duration_s`, console default 3600 s, capped by the agent's `limits.max_scan_duration_s`, default 3600 s):
- at 1 %, each second of query time needs about 100 s of scan budget: 3600 s covers about 36 s of query time (some 7 000 objects at 5 ms each);
- measure first: the agent logs each scan's busy and paused time at its end, and whether it ran out of time (`scan pacing`);
- a paced scan that would run past its maximum duration stops before the next object, reports the objects left as **`skipped_limit`** in its coverage (and a warning in the agent log), and **succeeds**. A database, LDAP naming context or whole MySQL / MariaDB target not reached counts as 1, so the counter can be far below the number of objects left. On a console that does not take the coverage counters (`job_progress.coverage`), the same scan ends **`failed` (`timeout`)** instead, so that the gap does not show as a success;
- either way, the remedy is the same as for any timeout: raise the scan's maximum duration, and `limits.max_scan_duration_s` above it (up to 86 400 s), or raise `limits.discovery_duty_cycle_percent` where the server has spare cores (2 % on a 4-core server is 0.5 % of it), or narrow the scan with filters. Each scan rotates its databases (or LDAP naming contexts) and the objects inside them from another starting point, so successive scans do not skip the same objects;
- the agent page shows the coverage of each target's last scan (#95): the objects sampled, each non-zero `skipped_*` reason with a label and, when there is one, a remedy, and the objects never reached when the agent reports them. A **succeeded** scan gets a **"partial coverage"** badge and warning when it has an actionable gap: `skipped_limit` (time budget or connector limit), `skipped_error` (sampling failed), `skipped_not_readable`, `skipped_row_level_security`, objects never reached, or a `skipped_*` reason this console does not know (shown raw and treated as a gap). By-design skips, `skipped_unsupported` (views, merge tables) and `skipped_remote` (foreign tables, LDAP continuation references, never read under I5), are listed without the badge, so a target with views is not flagged at every scan. A failed scan lists its counters without the badge. The badge is shown in the UI only: it raises no incident, notification or system alert. An agent that does not report coverage shows none.

Scans of several targets of one agent run one after the other, so several scans can be launched at once. Since #98 the console sends an agent one scan at a time: a scan requested while another scan of the same agent is in flight shows **"pending (waiting for the previous scan of this agent)"** on the agent page and is sent when that scan ends, so its maximum duration starts only when the agent receives it. A full pass over N targets of one agent therefore takes about N × the scan budget. A waiting scan does not expire while its agent is online, but a scan still waiting 24 h after it was requested expires: request it again ([ADR-0036](adr/0036-console-discovery-scan-scheduling.md)).

Classifiers and their semantics: [agent/crates/classifiers/README.md](../agent/crates/classifiers/README.md).

## 10. Audit: enabling it and reading events
1. On the agent page, open a target's **Audit** settings (administrator): enable Audit, set the aggregation window, poll interval and minimum rows, and choose the sensitive objects (derived from the findings by default, plus manual objects). A change that disables Audit or removes objects asks for a confirmation.
2. **Events** lists the access events, newest first, with their principal, score, signals (`signature.*` for known export tools such as `pg_dump` or `mongodump`, `shape.*`, `volume.*`), baseline anomaly flag and the incidents they matched. A principal's page shows its baseline, incidents and latest events. Principals are designated by a key, never by the account name in a URL; OpenLDAP users are sent as keyed fingerprints, except `anonymous`, the agent's own DN and the DNs listed in `openldap.clear_principals`.

Audit read positions (log offsets, cursors, profiler positions) and the agent's own-account row counters are kept in `state_dir` across agent restarts, so a restart resumes where the agent stopped, within what the source still holds; `pg_stat_statements` counters are the exception. Keep `state_dir` on a persistent volume.

**MySQL / MariaDB** (since 0.5.0): Audit fails closed. Writes to `information_schema`, `performance_schema` and `sys`, server and audit configuration changes, and statements it cannot read with certainty (version comments, double-quoted names, `ANALYZE`, `SET STATEMENT`, reads inside `SET` or `DO`, any statement outside a short allow-list of harmless ones) are reported, some of them against the object `*`, and configuration changes are never dropped by the minimum rows. What is and is not reported: [08-engine-capabilities.md](08-engine-capabilities.md#statement-text-and-passwords).

**MySQL / MariaDB statement-text tables** (since 0.6.0): reads of the system tables that hold other sessions' statement texts with their literal values (`performance_schema.events_statements_*`, `threads`, `information_schema.PROCESSLIST` and the others listed in [08-engine-capabilities.md](08-engine-capabilities.md#statement-text-tables)) are read events naming these tables, always reported whatever the minimum rows, from every account, the agent's included. `SHOW PROCESSLIST` is a read of `information_schema.PROCESSLIST`; `SHOW ENGINE INNODB STATUS`, `SHOW BINLOG EVENTS` / `SHOW RELAYLOG EVENTS` and the plan of another connection's statement (`SHOW EXPLAIN`, `EXPLAIN … FOR CONNECTION`) are reads of `*`. Monitoring tools (PMM, Datadog DBM, `sys`-based dashboards) read these tables on a schedule, so their accounts show regular events. Since 0.7.0 ([ADR-0047](adr/0047-mysql-mariadb-explain-as-a-read.md)), an `EXPLAIN` / `DESCRIBE` of a statement is a read of the tables that statement names, always reported (the optimizer reads the rows of primary-key lookups while it plans): developers' tools and query analysers that run `EXPLAIN` (PMM Query Analytics, `pt-query-digest --explain`) appear as readers of the tables they explain ([08-engine-capabilities.md](08-engine-capabilities.md#explains-of-a-statement)). A sample policy that opens an incident when any other account reads them (access events; `exclude_principals` takes globs on the account name):

| Key | Value |
|-----|-------|
| `engines` | `mysql`, `mariadb` |
| `event_actions` | `read` |
| `objects` | `{database: performance_schema, object: events_statements_*}`, `{database: performance_schema, object: threads}`, `{database: performance_schema, object: processlist}`, `{database: performance_schema, object: prepared_statements_instances}`, `{database: performance_schema, object: data_locks}`, `{database: performance_schema, object: user_variables_by_thread}`, `{database: information_schema, object: PROCESSLIST}`, `{database: information_schema, object: INNODB_*}`, `{database: information_schema, object: QUERY_CACHE_INFO}`, `{database: sys, object: *}` |
| `exclude_principals` | your monitoring account, for example `pmm` |
| Action | an incident of severity `high` |

The agent has no allow-list of monitoring accounts: a monitoring credential is often shared and holds exactly these grants, so it is excluded in the console, where the exclusion is visible. Keep such an exclusion inside a policy scoped by these objects, as above, and **never exclude an agent account** (the account DataBastion connects with): the exclusion would also hide the reads made with a stolen copy of its credential. The agent's own `performance_schema` polls are left out by the agent itself, by their exact text.

**One agent account per server.** When several targets point at the same MySQL / MariaDB server (one target per database, for example), declare them all with the same agent account. Each target's `performance_schema` stream sees the polls of the others: with one account they are the agent's own statements and are left out; with a different account per target, each stream reports the other targets' polls as reads of the statement tables by another account. Since 0.7.0 the agent recognizes its own ended poll and Discovery sessions on the same server run; a few events by an unidentified principal can still follow an agent restart. Give each agent its own account: two agents sharing one account on one server report each other's ended sessions as unidentified reads ([08-engine-capabilities.md](08-engine-capabilities.md#statement-text-tables)). Size the account's connection limit for all its Audit targets ([section 7](#7-least-privilege-accounts)).

**MySQL / MariaDB function calls** (since 0.6.0): an unqualified call of a name that is not a built-in function of the server's release series (`SELECT f()`, `DO f()`, `SET @x = f()`) may run a stored function, possibly with its definer's privileges, or a loadable function (UDF): it is a read of `*`, always reported. Applications that call stored functions or UDFs get one such event per principal and aggregation window; there is no allow-list. Upgrade the agent when you upgrade the server to a new release series ([08-engine-capabilities.md](08-engine-capabilities.md#unqualified-function-calls)).

**Statistics catalogs** (since 0.7.0, [ADR-0048](adr/0048-statistics-catalogs-as-reads.md), PostgreSQL and MySQL / MariaDB): the optimizer's statistics hold sampled column values (most common values, histogram bounds, minimum and maximum). Reads of PostgreSQL `pg_stats`, `pg_stats_ext`, `pg_stats_ext_exprs`, `pg_statistic` and `pg_statistic_ext_data`, MySQL `information_schema.COLUMN_STATISTICS` and MariaDB `mysql.column_stats` are read events naming them (PostgreSQL: in schema `pg_catalog`), always reported whatever the minimum rows, from every account, the agent's included (it never reads them). With pgaudit, **keep `pgaudit.log_catalog = on`** (the pgaudit default) on the monitored databases: with `off`, pgaudit does not log a statement that reads only catalogs, so a read of `pg_stats` alone gives no event, and `check()` says so in the agent's log. Bloat checks and monitoring tools that read `pg_stats` on a schedule, `mysqldump --column-statistics` and `mariadb-dump --system=stats` appear as readers ([08-engine-capabilities.md](08-engine-capabilities.md#statistics-catalogs)). On PostgreSQL, reads and writes against `*` (objects the source cannot name: a function that runs SQL, a text that does not parse) are now always reported as well, and **application statements that name 16 or more relations now carry `*` and are always reported** on `pg_stat_statements` and on pgaudit (with `pgaudit.log_relation` too, unless pgaudit names a `pg_catalog` relation of the statement), since a statistics catalog could hide past the analyzer's bound. A sample policy that opens an incident when any other account reads them:

| Key | Value |
|-----|-------|
| `engines` | `postgres`, `mysql`, `mariadb` |
| `event_actions` | `read` |
| `objects` | `{schema: pg_catalog, object: pg_stats*}`, `{schema: pg_catalog, object: pg_statistic*}`, `{database: information_schema, object: COLUMN_STATISTICS}`, `{database: mysql, object: column_stats}` |
| `exclude_principals` | your monitoring account running bloat checks, if any |
| Action | an incident of severity `high` |

**PostgreSQL credential-bearing catalogs** (since 0.7.0, [ADR-0050](adr/0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md)): reads of `pg_authid.rolpassword`, `pg_shadow.passwd`, `pg_roles.rolconfig`, `pg_user.useconfig`, `pg_db_role_setting.setconfig`, `pg_user_mapping(s).umoptions`, `pg_foreign_server.srvoptions`, `pg_subscription.subconninfo`, `pg_proc.proconfig`, and any read of `pg_largeobject`, `pg_file_settings`, `pg_hba_file_rules` and the `information_schema` user-mapping and server-option views, are read events naming the catalog (in schema `pg_catalog`), always reported whatever the minimum rows, from every account, the agent's included. Reads of these catalogs without the secret columns (`psql`'s `\du`, exporters, ORMs, `SELECT rolname FROM pg_roles`) stay quiet. `pg_dump` / `pg_dumpall`, PgBouncer's default `auth_query` on `pg_shadow`, admin tools that show role or function properties, and reads of your own views over `pg_roles` appear as readers ([08-engine-capabilities.md](08-engine-capabilities.md#credential-bearing-catalogs)). Keep `pgaudit.log_catalog = on`. A sample policy that opens an incident when any other account reads password verifiers or settings:

| Key | Value |
|-----|-------|
| `engines` | `postgres` |
| `event_actions` | `read` |
| `objects` | `{schema: pg_catalog, object: pg_authid}`, `{schema: pg_catalog, object: pg_shadow}`, `{schema: pg_catalog, object: pg_db_role_setting}`, `{schema: pg_catalog, object: pg_user_mapping*}`, `{schema: pg_catalog, object: pg_subscription}` |
| `exclude_principals` | your backup account (`pg_dumpall`) and connection pooler (`auth_query`), if any |
| Action | an incident of severity `high` |

**PostgreSQL statement-text views** (since 0.7.0, [ADR-0049](adr/0049-postgresql-statement-text-views-as-reads.md)): a read of `pg_stat_activity` or of `pg_stat_statements` that may select the statement text (other sessions' statements, with their literal values) is a read event naming the view, always reported whatever the minimum rows, from every account, the agent's included. Reads that provably select no text (`postgres_exporter`'s activity query, `SELECT queryid, calls FROM pg_stat_statements`) stay quiet. Query-sampling tools (Datadog Database Monitoring, pganalyze, PMM, PoWA, pgAdmin's dashboard) appear as readers: scope the policies by object and exclude their principals there. A statement whose relations are all catalogs is a read of `*`, always reported, when it calls a function, operator or cast that is not built in for that database, and `EXPLAIN`, cursors and prepared statements are reported as the query they wrap ([08-engine-capabilities.md](08-engine-capabilities.md#statement-text-views)).

**MongoDB failed operations and server-side JavaScript** (since 0.7.0, [ADR-0027](adr/0027-mongodb-audit.md)): on the server log and the profiler, a failed operation whose error code may quote the values it read (a failed conversion, a `$where` error, a duplicate key on an update) is always reported, and on every source so is every operation that runs server-side JavaScript (`$where`, `$function`, `$accumulator`, `mapReduce`, `system.js`); both from every account, the agent's included. Applications that use these operators, or whose queries fail this way, produce always-reported events, one per principal, object set and aggregation window ([08-engine-capabilities.md](08-engine-capabilities.md#what-is-kept)).

The export signatures recognized per engine are listed in [08-engine-capabilities.md](08-engine-capabilities.md#known-export-signatures).

## 11. Policies, incidents and notifications
- **Policies** (administrator): a policy applies to findings or to access events (fixed at creation). Conditions on findings: classifiers or families (`pii.*`), agents, targets, engines, location globs, confidence and match thresholds. Conditions on access events: signals or families, actions, principals, objects, minimum rows, score or sensitivity, baseline anomaly ([console/README.md](../console/README.md#audit-correlation)). Action: create an incident with a severity, and notify up to 5 channels. **Exceptions** (with a mandatory reason and an optional expiry) silence a scope. Model: [ADR-0014](adr/0014-policy-and-incident-model.md), [console/README.md](../console/README.md#policies-and-incidents).
- **How object patterns match**: location and object globs (`*`, `?`, `\` escapes) ignore case on every engine, so `crm.customers` also matches an event on `CRM.CUSTOMERS`. Since 0.8.0 the comparison is a Unicode lowercase with the final sigma `ς` read as `σ`, an event object gets the sensitivity of its findings whatever its case, and trailing spaces in names are ignored in policy conditions and in sensitivity scores on every engine, but in exceptions only on SQL Server, MySQL and MariaDB targets, where identifiers compare that way; on PostgreSQL, MongoDB, Redis and Valkey a name with a trailing space is a distinct object and an exception for `customers` does not cover `customers `. Exceptions are case-insensitive on case-sensitive engines too: an exception for `customers` also silences `Customers`. The agent's Audit sensitive-object filter compares names as policy conditions do ([ADR-0014](adr/0014-policy-and-incident-model.md#implementation-note-2026-10-17-object-names-matched-without-case-or-trailing-spaces)).
- **Incidents**: active incidents by default, most severe first. An incident shows its finding (with masked samples) or its events, its lifecycle and its notifications. Lifecycle: `open` → `acknowledged` → `resolved`, or `false_positive` (administrator). `resolved` means remediated: if a later scan still sees the data, a new incident opens.
- **Notifications** (administrator): e-mail (SMTP with STARTTLS or TLS) and HMAC-signed webhook (`https://` only) channels, with a test button. Webhook receivers must escape the names they render, because a database account name is chosen by the client ([console/README.md](../console/README.md#alerting)). Channels flagged for system alerts also receive the console's own alerts: silent agent, agent integrity, dropped batches, stopped Audit stream and, with OIDC on (since 0.4.0), break-glass local administrator logins (`user.local_login`) and role sync guards (`user.role_sync`), within an hourly budget per channel.

## 12. Upgrading
Upgrade the **console first**, then the agents; a console `X.Y` accepts agents `X.Y` and `X.(Y-1)` ([RELEASE.md](../RELEASE.md#compatibility)). For **0.1.0**, upgrade the console and every agent together: agent builds from before the protocol capability negotiation (#60) cannot decode the console's heartbeat response ([ADR-0022](adr/0022-protocol-capability-negotiation.md)). The console's default scan budget of 3600 s also assumes agents that pace Discovery (every released agent does). `migrate` applies the console migrations on start; deployments created before the database role split need the one-time steps in [console/README.md](../console/README.md#upgrading-an-existing-deployment). Upgrade commands for the Compose console and the `.deb` agent: [deploy/README.md](../deploy/README.md#agent-package-reference) ("Upgrade").

From 0.7.x to **0.8.0** (new engines: Microsoft SQL Server, Redis and Valkey; one console migration; two Audit behaviour changes on every engine; the full list is in the upgrade notes of the [CHANGELOG](../CHANGELOG.md)):
- **Events with more than 15 objects are always reported.** Up to 0.7.x, an event kept at most 16 objects and silently dropped the others (PostgreSQL, MySQL / MariaDB, OpenLDAP containers), so a sensitive table named after 16 others could be missed. From 0.8.0 such an event names 15 objects and `*`, and is always reported, whatever the minimum rows. Expect more events for statements that touch many tables ([08-engine-capabilities.md](08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine)).
- **Object names match without case or trailing spaces**, in the agent's sensitive-object filter and in the console's policies, exceptions and sensitivity ([section 11](#11-policies-incidents-and-notifications)). On MySQL / MariaDB with `lower_case_table_names` other than 0, events on `CRM.CUSTOMERS` now count as events on the sensitive `crm.customers`. Check that the console database has a UTF-8 character type (`SELECT datctype FROM pg_database WHERE datname = current_database();`; the bundled image uses `en_US.utf8`): under `C` or `POSIX` matching stays correct but is slower ([deploy/README.md](../deploy/README.md#1-console)).
- **Upgrade the console first.** A 0.8.0 agent keeps its SQL Server items spooled until the console lists `engine.sqlserver`, and its Redis / Valkey items until it lists `engine.redis` and `engine.valkey` ([ADR-0042](adr/0042-hold-items-of-unlisted-engines.md)). The console migration `0040` adds the `account_not_recorded` principal; its check is validated after the migration, without a long lock.
- **Several console replicas**: upgrade every replica before any agent sees the note-label token `target_status.note_labels.2026_10_b`. An agent uses the token as soon as one replica lists it, and a replica that does not know its labels rejects them ([ADR-0022](adr/0022-protocol-capability-negotiation.md) decision 8).
- **Policies with `exclude_principals: ["*"]`** do not hide Redis / Valkey events whose account is not recorded (`account_not_recorded`): such an event has no account name to match, by design.
- **Minimum rows on Redis / Valkey targets**: their events carry no row count, and key patterns cannot be listed as sensitive objects yet. A minimum rows value in a Redis / Valkey target's Audit settings therefore drops the target's read and write events that carry no signal (always-reported events, such as scripts, still pass), and a policy's minimum rows condition never matches them. Leave minimum rows unset on these targets.
- **SQL Server**: Discovery samples nothing without the row-level security opt-in ([section 6](#microsoft-sql-server-targets)); Audit needs an audit or an Extended Events session created by the operator, and the Extended Events grant exposes every statement text on the server. Outside the three listed server builds, expect statistics-build noise on Extended Events, and do not exclude the agent's account ([above](#sql-server-audit-through-extended-events)).
- **MySQL / MariaDB** (recommended): raise `performance_schema_max_digest_length` and `max_digest_length` to 2048, so that the agent's poll digests are not cut at the default 1024 bytes and its exact-text rule applies to them.

From 0.6.x to **0.7.0** (mainly agent changes: the console gains two target-note codes and dependency updates, no console migration; the full list is in the upgrade notes of the [CHANGELOG](../CHANGELOG.md)):
- **No grant is added on any engine.** Upgrade the console first: a 0.6.x console shows the new MySQL / MariaDB target notes `audit.digest_consumer_disabled` and `audit.statement_text_limit_low` as raw codes.
- **PostgreSQL Full needs the log settings**: `log_min_messages` and `log_min_error_statement` at `error` or lower, with no per-role, per-database or per-function override above `error`, no `SET` or `ALTER SYSTEM` grant on them to roles other than superusers (PostgreSQL 15+; a grant to the agent's role is reported as an over-privilege), and `pg_db_role_setting` readable by the agent's role ([section 8](#8-audit-prerequisites-and-levels)). Otherwise the target shows Partial after the upgrade. Keep `pgaudit.log_catalog = on`, and declare in `postgres.databases` every database that monitoring tools connect to ([section 6](#6-declare-targets)).
- **PostgreSQL Audit reports more**: failed and cancelled reads (from the server's `ERROR` lines), reads of the statistics catalogs, of the statement-text views and of the credential- and value-bearing catalogs, user code next to catalogs only, explains, cursors and prepared statements. Expect events from `pg_dump` / `pg_dumpall`, connection poolers' `auth_query`, monitoring and query-sampling tools, admin tools, and applications whose queries fail.
- **MySQL / MariaDB Audit reports more**: `EXPLAIN` / `DESCRIBE` of a statement, reads of the statistics tables, reads into variables (never dropped by the minimum rows), and the sources of `CREATE … AS SELECT`. Keep the `statements_digest` consumer enabled and the statement-text limits (`server_audit_query_log_limit`, `performance_schema_max_sql_text_length`) at 1024 or more; give each agent its own account.
- **MongoDB Audit reports more**: failed operations whose error can show a value, and operations that run server-side JavaScript, always.
- **OpenLDAP Discovery** reads at most `sample_rows` entries per normalized container name and scan; the containers past the cap are counted `skipped_limit` and sampled by later scans.
- Review the policies and baselines of these targets: scope them by object, as in [section 10](#10-audit-enabling-it-and-reading-events), and do not exclude agent accounts.

From 0.5.x to **0.6.0** (agent changes only; the full list is in the upgrade notes of the [CHANGELOG](../CHANGELOG.md)):
- **MySQL / MariaDB Audit reports more**: reads of the statement-text tables (monitoring accounts such as PMM now produce regular events), `SHOW PROCESSLIST` and the other statements that show other sessions' texts, `LOAD_FILE` and server-side `LOAD DATA INFILE`, unqualified calls of stored and loadable functions, cut texts, and, with `server_audit_events = QUERY_DML`, table records without a statement record. All are always reported. Review the policies of these targets: scope them by object, as in [section 10](#10-audit-enabling-it-and-reading-events), and do not exclude agent accounts.
- **One agent account per server**: targets of one server declared with different accounts report each other's `performance_schema` polls.
- **MySQL / MariaDB grants are unchanged.** A session whose `VERSION()` after TLS does not match the server's handshake (flavor and release series) is now refused.
- **Apereo CAS**: token responses of the `refresh_token`, `client_credentials` and `password` grants now name the client's registry entry; a YAML service definition whose class hint stands alone on a later line is now skipped.

From 0.4.x to **0.5.0** (the full list is in the upgrade notes of the [CHANGELOG](../CHANGELOG.md)):
- **MySQL / MariaDB Audit reports more**: system-schema writes, configuration changes and statements outside a closed allow-list are now reported, so expect more events, some against the object `*` (for example from applications that write string literals in double quotes). A multi-statement text that holds a write is a `write` event that keeps the signals of its reads: a policy limited to the action `read` does not match it ([section 10](#10-audit-enabling-it-and-reading-events)).
- **MySQL / MariaDB log limits**: keep `server_audit_query_log_limit` and `performance_schema_max_sql_text_length` at 1024 or more (the defaults), otherwise the CAS store guard's statements are reported at every heartbeat as the agent's own reads.
- **Console worker**: at its first start the worker upgrades the pg-boss schema (to version 44) with its usual database role; back up the console database first.
- **Agent package**: the systemd unit sets `LimitCORE=0` (no core dumps).

From 0.3.x to **0.4.0** (the full list is in the upgrade notes of the [CHANGELOG](../CHANGELOG.md)):
- **Audit log paths**: every log-file Audit source now refuses an `audit_log.path` whose last component is a symlink, and a log file with more than one hard link (`audit.log_not_readable`, [ADR-0043](adr/0043-audit-logs-opened-without-following-a-final-symlink.md)). Point the path at the real file; symlinked parent directories still work.
- **Single sign-on**: once OIDC is on, `DATABASTION_LOCAL_LOGIN` defaults to `admins`, so local users who are not administrators can no longer sign in with their password; see the migration window in [section 3](#single-sign-on-with-openid-connect) ("Local login").
- **CAS targets** need a 0.4.0 console: a 0.4.0 agent keeps its `cas` targets, findings and events in its spool until the console lists the `engine.cas` capability. Upgrade the console first, as usual.
- **New notes on existing targets**: the CAS store guard runs in the PostgreSQL, MySQL / MariaDB, MongoDB and OpenLDAP connectors, so existing targets may report `coverage.cas_guard_tripped`, and MariaDB accounts holding roles other than their default one `privilege.not_evaluated` ([08-engine-capabilities.md](08-engine-capabilities.md#cas-store-guard-postgresql-mysql--mariadb-mongodb-openldap)).

## 13. Reporting a problem
Bugs: GitHub issues. Vulnerabilities: never in a public issue, see [SECURITY.md](../SECURITY.md).
