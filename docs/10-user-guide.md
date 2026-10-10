# User guide – DataBastion

How to install the console and an agent, enroll the agent, declare targets, give the agent least-privilege accounts, and read findings and incidents. This page only describes what the code on `dev` does; the component READMEs linked below hold the full reference.

> **Status.** v0.1.0, the first release, was published on 2026-09-30, v0.2.0, a maintenance release, and v0.3.0 (PostgreSQL audit levels: Full requires `pgaudit.log_rows`, [ADR-0037](adr/0037-postgresql-full-requires-pgaudit-log-rows.md)), both on 2026-10-03, then v0.3.1 on 2026-10-04 (MSRV Rust 1.88, masking of typographic separators, automated release notes), v0.4.0 on 2026-10-07 (OpenID Connect login, Users page, Apereo CAS targets), v0.5.0 on 2026-10-08 (maintenance: MySQL / MariaDB Audit fails closed, Apereo CAS YAML service registries) and v0.6.0 on 2026-10-10 (maintenance: MySQL / MariaDB Audit reports reads of statement-text tables and calls of functions that are not built in, Apereo CAS YAML registries read by the agent's own parser) ([latest release](https://github.com/Yil00/databastion/releases/latest)); it is early-stage software, and its known limitations are listed in the [CHANGELOG](../CHANGELOG.md) and [SECURITY.md](../SECURITY.md#known-limitations-and-residual-risks). The installation test passes in CI in under 15 minutes and the load tests are done; the 72 h stability test is deferred to v0.1.x ([ROADMAP](ROADMAP.md#v01x-follow-ups)). Read [08-engine-capabilities.md](08-engine-capabilities.md) before relying on Audit for an engine.

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
- `engine`: `postgres`, `mysql`, `mariadb`, `mongodb`, `openldap` or `cas` (Apereo CAS, below; since 0.4.0);
- `host` and `port`, or `socket`;
- `account` and `secret`: a **reference** to the password, `env: VAR_NAME` or `file: /path` (`0600`, owned by the agent user), never the password itself. OpenLDAP with `bind: sasl_external` over `ldapi://` needs no secret;
- an optional engine block (`postgres`, `mysql`, `mongodb`, `openldap`): databases to connect to, `tls` (`verify_full` by default; `disable` only on a socket or a loopback address; `disable_insecure` is an explicit, warned opt-in and does not exist for OpenLDAP), `ca_file`, and the Audit source files:
  - PostgreSQL: `postgres.audit_log: {path, format: jsonlog | csvlog}` (the pgaudit server log; without it, Audit uses `pg_stat_statements`);
  - MySQL / MariaDB: `mysql.audit_log: {path, format: server_audit | json}` (without it, `performance_schema`);
  - MongoDB: `mongodb.audit_log: {path, format: audit_log | server_log}` (without it, the profiler if granted);
  - OpenLDAP: `openldap.accesslog_base` (read over LDAP) and `openldap.clear_principals`;
  - every engine block (since 0.4.0): `cas_stores`, the names of Apereo CAS stores kept under custom names (`ticket_registry`, `service_registry`, `audit_trail`), for the CAS store guard below.

The example file documents each key with its range. After changing `agent.yaml`, restart the agent.

**Apereo CAS targets** (`engine: cas`, [ADR-0041](adr/0041-cas-connector.md)) are local files on the agent's host, nothing else: no `host`, `port`, `socket`, `account` or `secret` (refused), and the agent never contacts CAS. Declare a `cas:` block with at least one of `service_registry.json_dir` or `service_registry.yaml_dir` (the JSON or YAML service registry directory; YAML files with anchors, aliases, merge keys or tags other than CAS class hints are skipped) and `audit_log.path` (the audit log), optionally `audit_log.timezone` (`UTC` or `±HH:MM`), `clear_principals` (service accounts sent by name; end users are fingerprinted) and `client_addr` (`truncated` by default: IPv4 `/24`, IPv6 `/56`; `clear`; `omitted`). The CAS side needs:
- `cas.audit.engine.audit-format: JSON`, written to a file by the audit log's logger with a layout that writes the message alone (`%m%n`), one record per line; preferably without request headers (`cas.audit.engine.http-request-headers` empty, or `auditable-fields` without `headers`), else the note `security.audit_headers_logged`;
- client secrets of OAuth / OIDC services encrypted (`security.client_secrets_in_clear` counts the clear ones), and the ticket registry's `crypto.enabled: true` when it lives in a database;
- the agent's OS user with **read** access to the registry directory and the audit log through a group without write permission (`0640` files, `0750` directory), no write access anywhere on the path (refused, `privilege.registry_writable` / `audit.log_not_readable`), and **no access to the CAS configuration** (`cas.properties`, `cas.yml`): a registry directory holding configuration or key files is refused (`privilege.config_readable`).

A console older than the `cas` engine (it does not list `engine.cas`) shows no CAS target: the agent keeps its findings and events spooled until the console is upgraded. CAS stores held in PostgreSQL, MySQL / MariaDB, MongoDB or OpenLDAP (JPA ticket and service tables, MongoDB collections) are read by those engines' targets, under the **CAS store guard**, on by default: ticket registries are never sampled (ticket counts only), ticket ids are dropped before classification wherever they appear, and the agent reports an account that can read ticket or audit-trail credential columns (`privilege.ticket_credentials_readable`) at every heartbeat ([08-engine-capabilities.md](08-engine-capabilities.md#cas-store-guard-postgresql-mysql--mariadb-mongodb-openldap)). List stores kept under custom names in that target's `cas_stores`. Levels and limits: [08-engine-capabilities.md](08-engine-capabilities.md#apereo-cas).

## 7. Least-privilege accounts
Give each target a **dedicated, read-only** account (I4). The recommended accounts, with the exact statements, are in [05-security.md, "Recommended database accounts"](05-security.md#recommended-database-accounts-read-only):

| Engine | Discovery | Audit | Reference |
|--------|-----------|-------|-----------|
| PostgreSQL | `CONNECT` + per-schema `USAGE` / `SELECT` | `pg_read_all_stats`; the pgaudit log file readable by the agent | [ADR-0012](adr/0012-postgresql-agent-grants.md), [connector README](../agent/crates/connector-postgres/README.md) |
| MySQL / MariaDB | per-database `SELECT`, `REQUIRE SSL`, host restricted to the agent | no grant with a log file source; `SELECT ON performance_schema.*` only when it is the source | [ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md), [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md), [connector README](../agent/crates/connector-mysql/README.md) |
| MongoDB | custom role with `find` + `listCollections` per database, SCRAM-SHA-256, `authenticationRestrictions` with `clientSource` = the agent's address(es) | no grant with a file source; `find` on `system.profile` only for the profiler source | [ADR-0026](adr/0026-mongodb-connector.md), [ADR-0027](adr/0027-mongodb-audit.md), [connector README](../agent/crates/connector-mongodb/README.md) |
| OpenLDAP | service DN with `read` on the tree; rule `{0}` names **every** credential attribute of the loaded schemas (`userPassword`, `userPKCS12`, and the Samba, Kerberos, ppolicy… ones where loaded), never readable; a `peername.ip` restriction to the agent's address, since the accesslog records no client address | `read` on `cn=accesslog` only while Audit runs for the target (otherwise `privilege.accesslog_without_audit`) | [ADR-0029](adr/0029-openldap-connector.md), [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md), [connector README](../agent/crates/connector-openldap/README.md) |
| Apereo CAS (`cas`) | no account: the registry directory (`0750`) and its files (`0640`) readable through the agent's group, never writable, no access to the CAS configuration | the audit log (`0640`, directory `2750`) readable the same way | [ADR-0041](adr/0041-cas-connector.md), [05-security.md](05-security.md#recommended-database-accounts-read-only) (also the column grants for CAS tables held in a database), [connector README](../agent/crates/connector-cas/README.md) |

Also:
- Size the account's connection limit as the recommended statements say: Audit holds its own connections.
- For file-based Audit sources, give the agent's OS user **read** access to the log directory only, never to the data directory. Run the agent as a dedicated non-root user: it refuses a log file its own account could write (`audit.log_not_readable`).
- At every heartbeat the agent checks each account and reports over-privilege and coverage problems as **target notes** on the agent page. A note about over-privilege means the account has more rights than recommended: remove them.

## 8. Audit prerequisites and levels
What Audit can see depends on the engine, its edition and its logging settings. The console shows the level reached for each target: **Full**, **Partial**, **Limited** or **None** (Discovery only). The prerequisites per engine (pgaudit, `server_audit`, `performance_schema`, `auditLog`, `slowms`, `slapo-accesslog`…) and the known limits are in [08-engine-capabilities.md](08-engine-capabilities.md). In 0.1, MySQL / MariaDB and MongoDB never reach Full, and MongoDB Community only sees slow operations. CAS never reaches Full either: Partial means authentications and ticket issuance are logged. PostgreSQL reaches Full only with pgaudit and `pgaudit.log_rows = on` (row counts in the log); without `log_rows` it is Partial ([ADR-0037](adr/0037-postgresql-full-requires-pgaudit-log-rows.md)).

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

**MySQL / MariaDB statement-text tables** (since 0.6.0): reads of the system tables that hold other sessions' statement texts with their literal values (`performance_schema.events_statements_*`, `threads`, `information_schema.PROCESSLIST` and the others listed in [08-engine-capabilities.md](08-engine-capabilities.md#statement-text-tables)) are read events naming these tables, always reported whatever the minimum rows, from every account, the agent's included. `SHOW PROCESSLIST` is a read of `information_schema.PROCESSLIST`; `SHOW ENGINE INNODB STATUS`, `SHOW BINLOG EVENTS` / `SHOW RELAYLOG EVENTS` and the plan of another connection's statement (`SHOW EXPLAIN`, `EXPLAIN … FOR CONNECTION`) are reads of `*`. Monitoring tools (PMM, Datadog DBM, `sys`-based dashboards) read these tables on a schedule, so their accounts show regular events. Since [ADR-0047](adr/0047-mysql-mariadb-explain-as-a-read.md), an `EXPLAIN` / `DESCRIBE` of a statement is a read of the tables that statement names, always reported (the optimizer reads the rows of primary-key lookups while it plans): developers' tools and query analysers that run `EXPLAIN` (PMM Query Analytics, `pt-query-digest --explain`) appear as readers of the tables they explain ([08-engine-capabilities.md](08-engine-capabilities.md#explains-of-a-statement)). A sample policy that opens an incident when any other account reads them (access events; `exclude_principals` takes globs on the account name):

| Key | Value |
|-----|-------|
| `engines` | `mysql`, `mariadb` |
| `event_actions` | `read` |
| `objects` | `{database: performance_schema, object: events_statements_*}`, `{database: performance_schema, object: threads}`, `{database: performance_schema, object: processlist}`, `{database: performance_schema, object: prepared_statements_instances}`, `{database: performance_schema, object: data_locks}`, `{database: performance_schema, object: user_variables_by_thread}`, `{database: information_schema, object: PROCESSLIST}`, `{database: information_schema, object: INNODB_*}`, `{database: information_schema, object: QUERY_CACHE_INFO}`, `{database: sys, object: *}` |
| `exclude_principals` | your monitoring account, for example `pmm` |
| Action | an incident of severity `high` |

The agent has no allow-list of monitoring accounts: a monitoring credential is often shared and holds exactly these grants, so it is excluded in the console, where the exclusion is visible. Keep such an exclusion inside a policy scoped by these objects, as above, and **never exclude an agent account** (the account DataBastion connects with): the exclusion would also hide the reads made with a stolen copy of its credential. The agent's own `performance_schema` polls are left out by the agent itself, by their exact text.

**One agent account per server.** When several targets point at the same MySQL / MariaDB server (one target per database, for example), declare them all with the same agent account. Each target's `performance_schema` stream sees the polls of the others: with one account they are the agent's own statements and are left out; with a different account per target, each stream reports the other targets' polls as reads of the statement tables by another account. A few events by an unknown principal can still follow an agent restart or a reconnection of the poll session ([08-engine-capabilities.md](08-engine-capabilities.md#statement-text-tables)). Size the account's connection limit for all its Audit targets ([section 7](#7-least-privilege-accounts)).

**MySQL / MariaDB function calls** (since 0.6.0): an unqualified call of a name that is not a built-in function of the server's release series (`SELECT f()`, `DO f()`, `SET @x = f()`) may run a stored function, possibly with its definer's privileges, or a loadable function (UDF): it is a read of `*`, always reported. Applications that call stored functions or UDFs get one such event per principal and aggregation window; there is no allow-list. Upgrade the agent when you upgrade the server to a new release series ([08-engine-capabilities.md](08-engine-capabilities.md#unqualified-function-calls)).

**Statistics catalogs** ([ADR-0048](adr/0048-statistics-catalogs-as-reads.md), PostgreSQL and MySQL / MariaDB): the optimizer's statistics hold sampled column values (most common values, histogram bounds, minimum and maximum). Reads of PostgreSQL `pg_stats`, `pg_stats_ext`, `pg_stats_ext_exprs`, `pg_statistic` and `pg_statistic_ext_data`, MySQL `information_schema.COLUMN_STATISTICS` and MariaDB `mysql.column_stats` are read events naming them (PostgreSQL: in schema `pg_catalog`), always reported whatever the minimum rows, from every account, the agent's included (it never reads them). With pgaudit, **keep `pgaudit.log_catalog = on`** (the pgaudit default) on the monitored databases: with `off`, pgaudit does not log a statement that reads only catalogs, so a read of `pg_stats` alone gives no event, and `check()` says so in the agent's log. Bloat checks and monitoring tools that read `pg_stats` on a schedule, `mysqldump --column-statistics` and `mariadb-dump --system=stats` appear as readers ([08-engine-capabilities.md](08-engine-capabilities.md#statistics-catalogs)). A sample policy that opens an incident when any other account reads them:

| Key | Value |
|-----|-------|
| `engines` | `postgres`, `mysql`, `mariadb` |
| `event_actions` | `read` |
| `objects` | `{schema: pg_catalog, object: pg_stats*}`, `{schema: pg_catalog, object: pg_statistic*}`, `{database: information_schema, object: COLUMN_STATISTICS}`, `{database: mysql, object: column_stats}` |
| `exclude_principals` | your monitoring account running bloat checks, if any |
| Action | an incident of severity `high` |

The export signatures recognized per engine are listed in [08-engine-capabilities.md](08-engine-capabilities.md#known-export-signatures).

## 11. Policies, incidents and notifications
- **Policies** (administrator): a policy applies to findings or to access events (fixed at creation). Conditions on findings: classifiers or families (`pii.*`), agents, targets, engines, location globs, confidence and match thresholds. Conditions on access events: signals or families, actions, principals, objects, minimum rows, score or sensitivity, baseline anomaly ([console/README.md](../console/README.md#audit-correlation)). Action: create an incident with a severity, and notify up to 5 channels. **Exceptions** (with a mandatory reason and an optional expiry) silence a scope. Model: [ADR-0014](adr/0014-policy-and-incident-model.md), [console/README.md](../console/README.md#policies-and-incidents).
- **Incidents**: active incidents by default, most severe first. An incident shows its finding (with masked samples) or its events, its lifecycle and its notifications. Lifecycle: `open` → `acknowledged` → `resolved`, or `false_positive` (administrator). `resolved` means remediated: if a later scan still sees the data, a new incident opens.
- **Notifications** (administrator): e-mail (SMTP with STARTTLS or TLS) and HMAC-signed webhook (`https://` only) channels, with a test button. Webhook receivers must escape the names they render, because a database account name is chosen by the client ([console/README.md](../console/README.md#alerting)). Channels flagged for system alerts also receive the console's own alerts: silent agent, agent integrity, dropped batches, stopped Audit stream and, with OIDC on (since 0.4.0), break-glass local administrator logins (`user.local_login`) and role sync guards (`user.role_sync`), within an hourly budget per channel.

## 12. Upgrading
Upgrade the **console first**, then the agents; a console `X.Y` accepts agents `X.Y` and `X.(Y-1)` ([RELEASE.md](../RELEASE.md#compatibility)). For **0.1.0**, upgrade the console and every agent together: agent builds from before the protocol capability negotiation (#60) cannot decode the console's heartbeat response ([ADR-0022](adr/0022-protocol-capability-negotiation.md)). The console's default scan budget of 3600 s also assumes agents that pace Discovery (every released agent does). `migrate` applies the console migrations on start; deployments created before the database role split need the one-time steps in [console/README.md](../console/README.md#upgrading-an-existing-deployment). Upgrade commands for the Compose console and the `.deb` agent: [deploy/README.md](../deploy/README.md#agent-package-reference) ("Upgrade").

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
