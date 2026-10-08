# End-to-end tests

Phase 1 exit criterion ([ROADMAP](../docs/ROADMAP.md)): *end-to-end enrollment in containers;
revocation effective in < 60 s*; and the invariant I2 test (P2-E): *no value of
[`dev/ground-truth.json`](../dev/ground-truth.json) in clear text in the console, including
value-bearing object and field names*, for the PostgreSQL, MySQL, MariaDB, MongoDB and OpenLDAP
targets; and the Audit path (P4-D) with the phase 4 exit criterion *`pg_dump` / `mysqldump` in dev →
incident in under 2 minutes*, on the PostgreSQL target (pgaudit), the MariaDB target
(`server_audit` log, P4-B, [ADR-0023](../docs/adr/0023-mysql-mariadb-audit-sources-and-levels.md)),
the MongoDB target (structured JSON server log, [ADR-0027](../docs/adr/0027-mongodb-audit.md): a
real `mongodump`) and the OpenLDAP target (`cn=accesslog`,
[ADR-0029](../docs/adr/0029-openldap-connector.md): a bulk `ldapsearch`), the two **v0.1.0 release
gates** of phase 7; and a password-bearing DCL statement on the Audit path (PostgreSQL `CREATE USER`
/ `ALTER ROLE … PASSWORD`, MariaDB `CREATE USER` / `ALTER USER … IDENTIFIED BY`, phase 7); see also
[Adding an Audit target](#adding-an-audit-target). The console's OIDC login against Keycloak (P8-D)
is a separate scenario on part of this stack: [OIDC login scenario](#oidc-login-scenario), and so
is the Apereo CAS target (P8-D): [CAS target](#cas-target).
[`run.sh`](run.sh) drives [`docker-compose.yml`](docker-compose.yml); the CI job is `e2e` in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml), required through the `CI result` gate.
It runs when `agent/`, `console/`, `shared/`, `e2e/`, `deploy/`, `dev/seed/out/`,
`dev/ground-truth.json`, `dev/mysql/`, `dev/mariadb/`, `dev/postgres/`, `dev/mongo/`, `dev/openldap/` or `ci.yml` change (and
whenever the changed files cannot be listed). It prints the time of each phase and the measured
dump → incident time.

## What runs
| Service | Image | Role |
|---------|-------|------|
| `db` | PostgreSQL 17 | Console internal database; roles created by `deploy/initdb/` |
| `migrate` | `console/Dockerfile` | One-shot migrations as the owner role |
| `web`, `worker` | `console/Dockerfile` | Console processes (runtime role) |
| `proxy` | Caddy | TLS 1.3 reverse proxy, certificate from a throwaway CA; `/metrics` answers `404` |
| `mailpit` | Mailpit 1.31 | Mail sink of the incident notifications: SMTP on 2525 with STARTTLS and SMTP AUTH required (a generated password, registered as a secret; certificate from the throwaway CA for `mailpit`, verified by the worker through `NODE_EXTRA_CA_CERTS`); its HTTP API is read from the web container, on `console-net` only |
| `target-pg` | [`dev/postgres`](../dev/postgres/Dockerfile) (PostgreSQL 17 + pgaudit) | Declared target of the agent, database `shop` loaded with the committed dev seed [`dev/seed/out/postgres.sql`](../dev/seed/out/postgres.sql) (schemas `crm`, `billing`, `ops`, value-bearing table names included); [`target-initdb/`](target-initdb/) creates the agent's read-only role and its per-schema Discovery grants, then ([`30-audit.sh`](target-initdb/30-audit.sh)) the Audit setup of the dev image, per database: pgaudit `read, write, role` session audit, object audit of the seeded tables through `databastion_auditor`, `log_relation`, `log_rows`, no catalog, no parameters; `pg_stat_statements`; and the test client roles `e2e_exporter` / `e2e_analyst` (read-only on the seeded schemas) and `e2e_admin` (`CREATEROLE`, no table privilege: the DCL test). Its jsonlog goes to the `target-pg-log` volume (directory `0750`, files `0640`, owner `postgres` 999:999) |
| `pg-client` | PostgreSQL 17 | One-shot database client of the Audit test (`tools` profile): `pg_dump` as `e2e_exporter`, queries as `e2e_analyst`; rows go to `/dev/null` inside the container |
| `my-client` | MariaDB 11.4 | Same for `target-mariadb` (`tools` profile): `mariadb-dump` as `e2e_exporter`, queries as `e2e_analyst`, DCL as `e2e_admin`, TLS verified against the target's dev CA |
| `mongo-client` | MongoDB 8.0 (dev image pin) | Same for `target-mongo` (`tools` profile): `mongodump --db app` as `e2e_exporter@admin` (password in a `--config` file on its `tmpfs`), a `mongosh` script as `e2e_analyst@admin` (`connect()` with the password read from the secret file) |
| `ldap-client` | [`dev/openldap`](../dev/openldap/Dockerfile) | Same for `target-ldap` (`tools` profile): a bulk subtree `ldapsearch` as the exporter entry, value filters (`-f` file) as the analyst entry, over LDAPS verified against the dev CA; the bind DN comes from an `ldaprc` file, the password from the secret file (`-y`) |
| `target-mysql` | MySQL 8.4 (dev image pin) | Declared target, the dev configuration mounted read-only: [`dev/mysql/databastion.cnf`](../dev/mysql/databastion.cnf), seed [`dev/seed/out/mysql.sql`](../dev/seed/out/mysql.sql) (database `hr`), [`dev/mysql/initdb/20-databastion.sh`](../dev/mysql/initdb/20-databastion.sh) (agent account) and `30-tls.sh` (throwaway CA, certificate for the network alias `mysql`); [`target-initdb/15-agent-password.sh`](target-initdb/15-agent-password.sh) feeds the agent password from its Docker secret |
| `target-mariadb` | MariaDB 11.4 (dev image pin) | Same with [`dev/mariadb/`](../dev/mariadb/) (`server_audit` on: `CONNECT,QUERY_DML,TABLE` to a file), seed [`dev/seed/out/mariadb.sql`](../dev/seed/out/mariadb.sql) (database `support`, one value-bearing table name), alias `mariadb`; [`target-initdb/35-mariadb-clients.sh`](target-initdb/35-mariadb-clients.sh) adds the Audit test accounts `e2e_exporter` / `e2e_analyst` (`SELECT` on `support.*` only). `UMASK=0640`: the `server_audit` log on the `target-mariadb-log` volume (directory `0750`, `mysql` 999:999) is readable by the agent through its group 999 only; the agent account keeps the ADR-0018 minimal grants (no `performance_schema` grant, [ADR-0023](../docs/adr/0023-mysql-mariadb-audit-sources-and-levels.md) decision 3) |
| `target-mongo` | MongoDB 8.0 Community (dev image pin) | Declared target, `app` loaded with [`dev/seed/out/mongo.json`](../dev/seed/out/mongo.json) (dynamic keys that are e-mails and phones included) by dev's [`initdb/10-seed.js`](../dev/mongo/initdb/10-seed.js), which also creates the [ADR-0026](../docs/adr/0026-mongodb-connector.md) account `databastion` (custom role `databastionDiscovery`: `find` + `listCollections` on `app` only, SCRAM-SHA-256; password from the secret file, `DATABASTION_DB_PASSWORD_FILE`); [`target-initdb/mongo-20-clients.js`](target-initdb/mongo-20-clients.js) adds `e2e_exporter` / `e2e_analyst` (`read` on `app`). `--slowms 0`, the structured JSON log to the `target-mongo-log` volume (directory `0750`, file `0640` created by `run.sh`, `mongodb` 999:999), read by the agent (`mongodb.audit_log`, `format: server_log`: [ADR-0027](../docs/adr/0027-mongodb-audit.md), Limited); no profiler grant. No TLS: `tls: disable_insecure` on the internal network (SCRAM-SHA-256 only) |
| `target-ldap` | [`dev/openldap`](../dev/openldap/Dockerfile) (Debian slapd) | Declared target, the dev `cn=config` ([`config.ldif`](../dev/openldap/config.ldif): accesslog overlay logging reads, writes and sessions, failed operations included; the service DN reads the tree except the credential attributes, and `cn=accesslog`), loaded with [`dev/seed/out/openldap.ldif`](../dev/seed/out/openldap.ldif) plus the two Audit test client entries under `ou=services`, whose DNs hold a ground-truth person name (`run.sh` writes both into the private work directory); passwords from secret files (`*_FILE`, hashed with `slappasswd -T`). LDAPS with the dev CA (SAN `openldap`, the network alias), `tls: verify_full` with the CA pinned; no `clear_principals` |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | `databastion-agent`, HTTPS only (`ca_file` pins the test CA), `DATABASTION_LOG=debug` so the I2 log scan covers debug-level logging; `target-pg-log`, `target-mariadb-log` and `target-mongo-log` mounted read-only, readable through the supplementary group 999 (the e2e stand-in for the production ACL on the log directory, [ADR-0012](../docs/adr/0012-postgresql-agent-grants.md)) and declared as `postgres.audit_log {path, format: jsonlog}`, `mysql.audit_log` and `mongodb.audit_log` |
| `bootstrap-admin`, `agent-files` | console / PostgreSQL | One-shot helpers (`tools` profile) |

Networks: the agent sits on an `internal` network with the proxy and the targets only; it
cannot reach the console database or the outside. Only the proxy is published, on
`127.0.0.1:${E2E_HTTPS_PORT:-8443}`. Every service runs with a read-only root filesystem,
`cap_drop: ALL` (PostgreSQL, MySQL, MariaDB, MongoDB and OpenLDAP get back what their entrypoints
need, OpenLDAP also `NET_BIND_SERVICE` for 389 / 636; their data lives in `tmpfs`) and
`no-new-privileges`.

## Flow
1. Generate every secret (database passwords, metrics token, admin password, target superuser,
   agent and test client passwords) and the test CA + proxy and Mailpit certificates into a
   private temporary directory,
   write `agent.yaml`. The agent connects to the target as `databastion_agent` (minimal
   variant of [ADR-0012](../docs/adr/0012-postgresql-agent-grants.md): `LOGIN`, no superuser /
   createdb / createrole / replication / bypassrls, `CONNECTION LIMIT 5`, `CONNECT`,
   `pg_read_all_stats`, role defaults `default_transaction_read_only = on` and statement / lock /
   idle-in-transaction timeouts; Discovery grants `USAGE` + `SELECT` on `crm`, `billing`, `ops`
   and default privileges, after the seed: I4); the superuser password never leaves `target-pg`.
   The MySQL / MariaDB agents connect as `databastion`, the [ADR-0018](../docs/adr/0018-mysql-mariadb-grants-and-connector.md)
   minimal variant as the dev scripts create it ([ADR-0020](../docs/adr/0020-mysql-mariadb-connector-as-merged.md)):
   `SELECT` on the application database only, `REQUIRE SSL`, `MAX_USER_CONNECTIONS 5` (MariaDB:
   `MAX_STATEMENT_TIME 30`); root passwords stay in the targets.
   The MongoDB agent connects as `databastion` of `admin` (ADR-0026), the OpenLDAP agent as the
   service DN `cn=databastion,ou=services,dc=example,dc=org` (ADR-0029). Two passwords for the
   DCL test go to a registry of their own (they are statement literals: they do reach the targets'
   own audit logs, which the secret registry must not match).
   Before anything starts, the I2 scanner's positive control checks, per engine, that every
   searchable value of the ground truth is visible in the committed seed (the LDIF seed's base64
   values through the `ldif` view).
2. Build the console, agent, target PostgreSQL and OpenLDAP images, hand the log volumes to the
   targets' server users (`999:999`, `0750`; mongod's log file created `0640`), start the console
   stack, Mailpit and the five targets, wait for
   `/api/health/ready` through the proxy and for the MySQL / MariaDB / MongoDB / OpenLDAP targets to
   be healthy (MongoDB: a TCP connect to the container's own address, which only the final server
   listens on; no command, nothing in its log); copy their CA (created by dev's `mysql/initdb/30-tls.sh`, `mariadb/tls-entrypoint.sh` and
   dev's OpenLDAP entrypoint, checked to be that CA and to hold no key) into the work directory,
   mounted into the agent as `ca_file`.
3. `bootstrap-admin` with the random password (Docker secret file), log in through the user API
   (session cookie + `X-CSRF-Token`), create an enrollment token.
4. Hand the token to the agent as a `0600` file owned by uid 10001 (sent on stdin, never on a
   command line), run `databastion-agent enroll --token-file …` and assert that
   `identity.json` is `10001:10001 0600`, then `databastion-agent run`.
5. Assert through `GET /api/agents` that the agent is `online` with target `pg-e2e` reported
   and `reachable` (the PostgreSQL connector connects with `databastion_agent`, TLS disabled on
   the internal network through the explicit insecure opt-in
   `postgres: {databases: [shop], tls: disable_insecure, audit_log: {…}}` in `agent.yaml`, SCRAM
   only; the audit level is printed here and asserted in step 7), that `databastion_agent` has exactly the
   attributes above (memberships exactly `pg_read_all_stats`, role settings in
   `pg_db_role_setting` exactly the four defaults) and, in its own session, gets the defaults and
   is denied `pg_authid` / `pg_user_mapping`, that its Discovery grants are exactly `USAGE`
   (no `CREATE`) on the seeded schemas, `SELECT` on their tables and no write privilege outside
   the system catalogs, and that `/metrics` (scraped from inside the web
   container with the metrics token) shows `databastion_agent_up{agent_id="…"} 1`.
   Targets `mysql-e2e` and `mariadb-e2e` must be `reachable` too (`tls: verify_full` with the
   pinned test CA; audit level `none` without a `performance_schema` grant, printed only). As
   root in each target: the grants of `databastion` are exactly `USAGE ON *.*` and
   `SELECT ON <db>.*`, with `ssl_type = ANY`, `max_user_connections = 5` (MariaDB
   `max_statement_time = 30`), no role and no other `databastion` account; it logs in over TLS
   and is refused without TLS (error 1045). MariaDB's `e2e_admin` has exactly `CREATE USER ON *.*`;
   `server_audit_events` gets `QUERY_DCL` at run time (after the initialization).
   MongoDB, as root (password read by `mongosh` from the secret file): `databastion` has exactly
   the role `databastionDiscovery` of `admin`, whose privileges are exactly `find` +
   `listCollections` on `app`, SCRAM-SHA-256 only, one account of that name; the test accounts have
   `read` on `app` only; `mongod.log` is `999:999 0640`. OpenLDAP, as root over `ldapi` (`cn=config`
   is not audited): the test clients get read on the data tree, then the `olcAccess` of both
   databases and the accesslog settings (`reads writes session`, `olcAccessLogSuccess: FALSE`) must
   be exactly the expected ones (compared, never printed: they name the clients' DNs).
6. Audit setup (P4-D), through the user API as a user would: an e-mail channel to Mailpit
   (`starttls`, port 2525), three `access_event` policies, `e2e dump signature` (signal
   `signature.pg_dump`, `signature.mysqldump`, `signature.mongodump` or `shape.bulk_search` on the
   Audit targets → **critical** incident + e-mail), `e2e reads` (every `read` on the Audit targets
   → medium incident + e-mail) and `e2e dcl` (every `dcl` on the targets of the DCL test → medium
   incident + e-mail). After
   each policy creation, the web process's wake-up (#63) must queue a `policies.evaluate` pg-boss
   job within 5 s. Jobs the worker's schedule produced (sent while a `__pgboss__send-it` job of
   that queue ran) do not count; a job not cancelled, created within the previous 60 s or the 5 s
   after, and not started at that time (the schedule's included) is accepted as a coalesced
   wake-up (the queue is stately), but at least one wake-up per kind of action must be a job of
   its own. Then `audit.configure` of every Audit target
   (enabled, contract defaults: aggregation 60 s, poll 10 s, no `min_rows`; sensitive objects
   derived from the findings, none yet). The harness waits for the job and for the agent's
   `audit source: pgaudit log` / `audit source: audit log file` / `audit source: log file` /
   `audit source: cn=accesslog` line, **before** the Discovery scan, so the agent's own Discovery
   reads go through the Audit stream.
7. Discovery (P2-E): launch a `discovery.scan` of the five targets together through the user API (admin session + CSRF) and wait for every job to succeed (360 s
   at most). The agent reports the job status before
   its spooled findings batches are uploaded, so the test then waits (90 s at most) for a
   heartbeat received after the last job ended whose spool status (`agents.spool`) reports no batch
   left and no dropped batch or item, checks that the agent log shows no lost / dropped /
   rejected result batch, and that the stored findings count of every target is non-zero and
   stable.
   [`i2_check.py findings`](i2_check.py) asserts at least one finding, the presence of
   `pii.email`, `pii.card_number`, `pii.iban` and `secret.aws_key`, that the value-bearing table
   `crm.export_client_<phone>` is stored under its `expected_normalized_name` (`*`) and that no
   finding stores a raw value-bearing name; it also prints how many ground-truth locations were
   found (informational). For `mysql-e2e`, `mariadb-e2e`, `mongo-e2e` and `ldap-e2e`, `i2_check.py findings
   --require-expected-classifiers --forbid-negative-controls` requires a finding for every
   classifier the ground truth expects for the engine, no finding on a negative-control location
   (MariaDB's value-bearing table included, under its normalized name) and no stored name holding
   a value-bearing name, even partially. The part of a location's name that carries the value is
   the table (SQL), the container (OpenLDAP `ou=<person name>,…`, stored `ou=*,…`) or the field
   (MongoDB dynamic keys, `contacts.<email>.phone` stored `contacts.*.phone`; the negative control
   `members.<phone>.points`). The findings page is fetched with the session (masked samples are
   decrypted there; they are encrypted at rest in the database); [`i2_check.py page`](i2_check.py)
   asserts it is complete (every finding listed, fewer than the 500-row listing cap, every
   finding with stored samples renders them, none `unavailable`) and that no masked sample keeps
   more than 4 digits (a partial masking regression the value search cannot see).
8. Audit (P4-D), the Audit targets side by side (their waits overlap):
   - `audit.configure` again, per target: the sensitive objects derived from the findings must
     cover every object with a finding (checked in `audit_configs.sent_objects`); the stream
     restarts from its cursor.
   - The dumps, one per target, one after the other; a background poller watches, for each
     started dump, the incidents page and the console database (below), while the literal queries
     and DCL statements of every target run.
   - **Exit criterion**: `pg_dump` of `shop` as `e2e_exporter` from the `pg-client` container (not
     the agent's account). The time from the start of the dump to the incident appearing on the
     console (the `Active: N critical` count of the incidents page, fetched with the session
     through the proxy, polled every second) must rise, and the console must hold an incident of
     this target, this principal and the dump policy, carrying the dump signal, with `created_at`
     after the dump started. Both times (page, `created_at`) are printed and must be **under
     120 s**.
     On MariaDB the same with `mariadb-dump --single-transaction --no-tablespaces support` from
     `my-client` (signal `signature.mysqldump`); on MongoDB `mongodump --db app --archive` from
     `mongo-client` as `e2e_exporter@admin` (signal `signature.mongodump`); on OpenLDAP a subtree
     `ldapsearch '(objectClass=*)'` of `dc=example,dc=org` from `ldap-client` as the exporter entry
     (signal `shape.bulk_search`; its principal is a fingerprint). The page count must have risen by
     one more than the dump incidents already seen.
   - As `e2e_analyst` (PostgreSQL): `SELECT * FROM crm.customers WHERE email = '<ground-truth e-mail>'`,
     `COPY (SELECT * FROM billing.payment_methods WHERE iban = '<ground-truth IBAN>') TO STDOUT`
     and `COPY ops.app_credentials TO STDOUT`, fed on stdin (the literals are on no command line
     and in no log of the harness). MariaDB: `SELECT … FROM tickets WHERE requester_email = '<…>'`
     and `… WHERE requester_phone = '<…>'`, then `SELECT * FROM tickets INTO OUTFILE …`, which must
     be refused (`ERROR 1227`, MariaDB's missing-`FILE`-privilege error) and still carry `signature.into_outfile`.
     MongoDB (a `mongosh` script as `e2e_analyst@admin`): `users.find({email: …})`,
     `users.find({iban: …})` and `integrations.find({})` (`shape.full_table_read`). OpenLDAP (as
     the analyst entry): `(mail=…)` and `(telephoneNumber=…)` under `ou=people`. Then the DCL
     statements as `e2e_admin` (PostgreSQL `CREATE USER e2e_dcl_probe PASSWORD '…'` and
     `ALTER ROLE … PASSWORD '…'`, MariaDB `CREATE USER … IDENTIFIED BY '…'` and
     `ALTER USER … IDENTIFIED BY '…'`, the two DCL passwords, on stdin). The harness waits (240 s at
     most) until, on every target, the object sets read (PostgreSQL 3, MariaDB 1, MongoDB 2,
     OpenLDAP 1) and every literal-bearing read statement (3, 3, 3, 2: the sum of `aggregated_count`
     of the query principal's read events; OpenLDAP: the reads of the fingerprinted principal none
     of whose events carries `shape.bulk_search`, the analyst) are stored, a `e2e reads` incident exists for the query principal, both
     DCL statements are stored as `dcl` events of `e2e_admin` with their `e2e dcl` incident, every
     event is evaluated and no notification is pending. The grants of `e2e_exporter` /
     `e2e_analyst` on MariaDB are checked to be exactly `USAGE` and `SELECT ON support.*` (step 5).
   - The heartbeat must report audit level `partial` or `full` with source `pgaudit`
     (PostgreSQL), `partial` with source `mariadb_server_audit` (MariaDB: never Full, ADR-0023),
     `limited` with source `mongodb_log` (MongoDB Community: never more, ADR-0027), `full` with
     source `openldap_accesslog` (OpenLDAP, ADR-0029 decision 10). Its notes must not hold an
     over-privilege of the account (MongoDB: `privilege.*`; OpenLDAP:
     `privilege.password_attributes_readable`, `privilege.config_readable`,
     `privilege.accesslog_without_audit`) nor a missing audit prerequisite (OpenLDAP).
   - Every notification to the channel is `delivered`. For every Audit target, a `e2e dump
     signature` incident has a `delivered` notification row, and Mailpit holds its e-mail: a text
     part naming the incident id and the target id (so the e-mail scan of step 12 reads a
     notification of every engine); the same for the `e2e dcl` incident of each DCL target
     (PostgreSQL, MariaDB). Every message has a text part naming an Audit target or principal.
   - [`i2_check.py audit`](i2_check.py) on the target's events and incidents: an event of
     `e2e_exporter` with the dump signal, an event of `e2e_analyst` (MariaDB: with
     `signature.into_outfile`), the dump incident (policy, principal, signal) and the `e2e reads`
     incident of `e2e_analyst`; **no event and no incident of the agent's account**
     (`databastion_agent`, `databastion`, `databastion@admin`, the service DN: its own Discovery
     reads, which ran while Audit was on, must not surface); no stored event object holding a raw
     value-bearing name, even partially; the `dcl` events of `e2e_admin` and their incident
     (DCL test). OpenLDAP: every principal a fingerprint (`--fingerprinted-only`, a principal in
     clear is counted, never printed), exactly two distinct fingerprints over every event and
     incident, any action (`--min-fingerprints 2` readers, `--max-fingerprints 2`: the exporter and
     the analyst, nothing of the agent), and the `e2e reads` incident is the analyst's
     (`@fingerprint!shape.bulk_search`: the fingerprinted principal without a bulk search, so the
     exporter's reads cannot satisfy it). Also no fingerprinted event with a `ts` before the first
     client operation (the dump): Audit ran from before the Discovery scan, so that window held
     the agent's own reads only.
   - Positive control of the literal search: every literal must be found in the file the agent
     reads, alone: the pgaudit jsonlog; the `server_audit` log and its rotations (not
     `performance_schema`, which the agent's account cannot read); mongod's log; `cn=accesslog`
     (exported with `slapcat` as root in the target: no LDAP operation), where the OpenLDAP
     clients' DNs must be found too. `E2E_PG_AUDIT=pss` has no such control. DCL passwords in the
     target's own log (searched like on the console side, below): neither may be there, and the
     masked statements must be (pgaudit writes `<REDACTED>` after the `password` token of CREATE /
     ALTER ROLE, `server_audit` writes `*****`; `server_audit` logs CREATE USER only, not ALTER
     USER). These prove the sources' masking; the agent's own redaction of DCL text is covered by
     the classifier and connector tests.
   - After all targets: no event carries a `db_user_fingerprint` (but on the OpenLDAP target); every stored events batch woke
     the policy engine (as above, per batch received at `events_batches.received_at`); `web.log`
     holds no `wake-up not sent` warning. The agent's page, each Audit target's settings page and
     `GET /api/agents` are fetched for the I2 scan.
9. Revoke the agent through the user API; within 60 s the agent must log
   `console rejected the current secret (401)`; the measured latency is printed and the test
   fails at 60 s or more. The console must show `revoked`, and the proxy access log must show no
   `/api/agent/v1/jobs` request during a 10 s window afterwards.
10. Dump every container log (plus the one-shot command outputs); fail if `agent.log` or
   `web.log` is empty; run a positive control (a random canary written to the log directory must
   be found by the scan and redacted, then it is removed); fail if any generated secret
   (enrollment token, agent secret, admin password, session cookie, metrics token, database and
   target passwords, encryption key) appears in clear text.
11. The targets' audit logs (pgaudit jsonlog, `server_audit` log and rotations), copied into the
   private directory, must be non-empty and hold no registered secret; they must hold reads of
   the seeded data by the agent's own account since the Discovery scan started (pgaudit `READ`
   records of `databastion_agent` on a `crm.`, `billing.` or `ops.` relation; `server_audit`
   `READ` / `QUERY` records of `databastion` on `support`; mongod slow-query lines on `app.*` of
   the connections that authenticated as `databastion` of `admin`; `auditSearch` records of the
   service DN on `dc=example,dc=org`): the positive control of "no
   own-account event", the reads were seen and filtered, not missed (not in `pss` mode). Then
   `pg_dump` the console database into the private temporary directory (never the log directory)
   and fail if any registered secret (the whole registry: the Mailpit SMTP password and its
   base64 AUTH PLAIN / AUTH LOGIN forms included) is stored in clear text. The registry also
   holds the session cookie and the CSRF token; neither is expected in the database:
   `console/src/server/auth/session.ts` stores only the SHA-256 of the session cookie
   (`sessions.token_hash`) and derives the CSRF token as an HMAC of the cookie, never stored.
12. Invariant I2, for each engine (`postgresql`, `mysql`, `mariadb`, `mongodb`, `openldap`):
    [`i2_check.py scan`](i2_check.py) searches the plain dump of the whole console database
    (every schema, `pgboss` included), every container log except the targets' own (`target-*.log`,
    the source databases; `all.log` includes them; the agent's and Mailpit's included) and the
    rendered findings page for every value of the engine in the ground truth and every
    value-bearing name. A canary file holding one ground-truth e-mail of the engine must be
    reported by the log scan first (positive control).
    For each engine with an Audit target, the same search runs on: every column of
    `access_events` (`objects`, `signals` included), `incidents`, `incident_events`,
    `notification_deliveries` (the notification payloads), `principal_baselines` and
    `audit_configs` (exported as JSON rows, each of the first three non-empty); the events page,
    each principal page, the incidents page (all statuses), each Audit incident page, the
    notifications page, the agent page, each Audit target's settings page and `GET /api/agents`;
    the e-mails in Mailpit (summary, decoded text and HTML parts, raw source).
    Then the query literals of step 8 alone (`scan --needle`; OpenLDAP: the clients' DNs too) on
    every console-side artifact above, the console database dump and the logs: they must be
    nowhere. Then the two DCL passwords (`scan --secret-file`: case-insensitive, whole, every
    16-character window, base64 / base64url at the three byte alignments and hex, in every view)
    on the console database dump, the Audit table exports, the pages, the e-mails, the findings
    page and the logs (but the targets' own): they must be nowhere either. Last, the OpenLDAP
    clients' DNs must not be in the console database dump, the Audit tables, pages or e-mails as
    an unkeyed digest (SHA-256 or empty-key HMAC-SHA256 of the DN as written, lowercased, without
    a space after a comma; `scan --literal-file`, a planted digest must be found first): the agent
    sends keyed fingerprints.

### What "in clear" means (I2)
The definition is in the docstring of [`i2_check.py`](i2_check.py); unit tests in
[`test_i2_check.py`](test_i2_check.py) (`python3 -m unittest discover -s e2e -p 'test_*.py'`),
including pg_dump COPY-format and React Server Components payload excerpts with planted leaks.
- Case-, accent- and NFC / NFD-insensitive substring search, on the file as is and after decoding
  JSON `\uXXXX`, URL `%XX`, HTML character references and SQL doubled quotes, and HTML as rendered
  text (`html-text`: comments such as React's `<!-- -->` and inline tags removed, other tags
  replaced by a space, character references decoded).
- Values with fewer than 8 letters / digits must stand at word boundaries (`_` is a boundary:
  `archive_lucas_martin` matches `martin`, `Martinez` does not).
- Phones, cards, IBANs, NIRs and digit names (at least 9 letters / digits, 6 of them digits) are
  also searched without separators (space, `.`, `-`, `/`, `(`, `)`, `+`, `_`), in national and
  international phone forms and as the national significant number, IBANs also as their BBAN,
  never as part of a longer digit run. Masked samples (at most 4 digits, `*` elsewhere) cannot
  match: `*` is not a separator.
- E-mail local parts with at least 8 letters / digits are extra needles, at word boundaries.
- Partial digit runs (e.g. 8 of 16 card digits) are not searched in the dump and logs (the seed's
  shared prefixes would match timestamps and hashes); the findings page check bounds the clear
  digits of every masked sample instead.
- LDIF (a file with a `dn:` line) is also searched with its folded lines joined and its base64
  values (`attr:: …`) decoded (`ldif` view: the OpenLDAP seed and the `cn=accesslog` export).
- Excluded, and counted in the output: values with fewer than 4 letters / digits (`Ava`, `Mia`,
  `Noé`, `Léa`, `Zoé`), and folded single words listed in `COMMON_WORDS` with a justification
  (empty today).
- Output: counts, needle ids (`L<location>.v<value>`, `.n<name value>`, `.object`), the location
  (a value-bearing name is shown as `<value-bearing name>`) and the file name; never a value.

Each secret is registered in a private pattern file as soon as it is generated or obtained
(and masked with `::add-mask::` under GitHub Actions); values are matched from files
(`grep -Ff`), never passed on a command line. On exit, whatever the result: logs are written to
`$E2E_LOG_DIR` (default `e2e/.logs/`, ignored by git), every registered secret is replaced in
them by `<REDACTED:name>` (a file that cannot be redacted is deleted), then the stack and its
volumes are removed and the temporary directory is deleted.

## Adding an Audit target
The Audit steps are driven by `E2E_AUDIT_TARGETS` in [`run.sh`](run.sh), one line per target:
`<target id> <ground-truth engine> <client> <agent account> <dump signal>`, and by the
`audit_client_<client>_*` functions (`started`, `levels`, `source`, `principals`, `dump`,
`queries`, `target_log`), which hold everything engine-specific: the agent log line of a started
stream, the expected level and source, the test roles, the dump tool, the literal queries and the
target's own audit log (plus `object_sets`, `query_statements`, `query_signal`, `log_user_records`,
`time`; optional: `dcl`, `has_dcl`, `dcl_statements` and `dcl_masked` for the DCL test, `forbidden_notes`,
`i2_args`). A principal `@fingerprint` stands for one the agent sends as a fingerprint (OpenLDAP
entry DNs), `@fingerprint!<signal>` for the fingerprinted principal none of whose events carries
that signal. A new target adds a line, a client
service, its test accounts, its audit log mounted read-only into the agent and declared in
`agent.yaml`, and its dev directory in the CI path filter. Not covered: MySQL Community (its only
source, `performance_schema`, needs a grant the minimal agent account must not have in the e2e
stack, ADR-0023 decision 3), Percona's `audit_log_filter` (another target and image; the
connector's integration tests cover it against `dev/percona`), the MongoDB profiler and `auditLog`
sources (the file source is preferred, ADR-0027 decision 5; `auditLog` needs Enterprise or Percona
Server for MongoDB) and OpenLDAP SASL `EXTERNAL` over `ldapi://`. The policies, the channel, the
timing, the Audit and I2 checks are shared.

## Running locally
Requirements: Docker with Compose v2, `openssl`, `curl`, `jq`, bash.

```sh
e2e/run.sh
E2E_HTTPS_PORT=9443 e2e/run.sh      # if 8443 is taken on 127.0.0.1
```

The first run builds the console, agent, target PostgreSQL (dev/postgres, pgaudit from the PGDG
apt repository) and OpenLDAP (dev/openldap, Debian's slapd) images (several minutes). No secret is
written to the repository; nothing listens outside `127.0.0.1`. `E2E_SKIP_BUILD=1` (ignored under
GitHub Actions) reuses `databastion-console:e2e`, `databastion-agent:e2e`,
`databastion-dev/postgres:17.11-pgaudit` and `databastion-dev/openldap:bookworm-20260918` as
already built (`E2E_CONSOLE_IMAGE`, `E2E_AGENT_IMAGE`, `E2E_TARGET_PG_IMAGE`,
`E2E_TARGET_LDAP_IMAGE` name other tags),
for hosts where the Dockerfiles cannot build as is (e.g. a TLS-intercepting proxy). Behind an HTTP
proxy, add `console.e2e.internal` to `NO_PROXY` so that curl reaches the local TLS proxy directly.
Where the apt mirrors are blocked, `E2E_PG_AUDIT=pss` (local runs only; refused under GitHub
Actions) runs `target-pg` on the plain pinned PostgreSQL image with `pg_stat_statements` only: the
agent reports the Limited level from that source, the Audit steps run the same way (the dump is
recognized by its `COPY … TO STDOUT` of several whole tables), and the pgaudit-only checks (level,
source, literal positive control in the target's log) are replaced or skipped, as printed. It is not
a substitute for the CI run.

## OIDC login scenario
ROADMAP P8-D: the console's single sign-on ([ADR-0038](../docs/adr/0038-console-oidc-login.md))
against Keycloak with the [dev test realm](../dev/README.md#keycloak-oidc-test-realm).
[`oidc.sh`](oidc.sh) merges [`docker-compose.oidc.yml`](docker-compose.oidc.yml) over this stack
(Compose project `databastion-e2e-oidc`) and starts only `db`, `migrate`, `web`, `proxy`,
`bootstrap-admin` and `keycloak`: no agent, no target, no worker. [`run.sh`](run.sh) never reads the
override. The CI job is `e2e-oidc` in [`ci.yml`](../.github/workflows/ci.yml) (25 min budget,
`oidc.sh` at most 1320 s with the console image build at most 900 s, about 2 minutes of scenario); it runs when `console/`, `e2e/`,
`deploy/initdb/`, `dev/keycloak/`, `dev/docker-compose.yml` or `ci.yml` change, and is not part of
the required `CI result` check yet.

**TLS.** Inside the containers the issuer is not a loopback address, so decision 2 requires
`https://` for it and every endpoint, and the console runs the production image (`NODE_ENV=production`,
checked; no plain-HTTP exception, no development build). `oidc.sh` generates a throwaway CA and two
certificates at run time: the proxy's (`console.e2e.internal`) and Keycloak's
(`keycloak.e2e.internal`); the CA key is deleted once they are issued. Keycloak runs in production
mode (`start`), HTTPS only (TLS 1.3 and 1.2; `oidc.sh` checks that its port refuses plain HTTP),
with the embedded `dev-file` database and local caches in the container. The console trusts the CA
for the provider only, through `DATABASTION_OIDC_CA_FILE` (decision 3). Keycloak listens on the
same port inside and on `127.0.0.1` (`E2E_KEYCLOAK_PORT`, default 8444), so that the issuer
`https://keycloak.e2e.internal:8444/realms/databastion` is the same for the console (network alias
on `console-net`) and for the scenario's browser on the host.

**Realm and secrets.** The realm is generated at run time from
[`dev/keycloak/databastion-realm.json`](../dev/keycloak/databastion-realm.json) with `jq`: redirect
URI `https://console.e2e.internal:8443/api/auth/oidc/callback`, post-logout redirect URI
`…/login`, `sslRequired: all`, and one more user, `link.grace` (like `admin.alice`), for the
self-service link. The client secret and the users' password stay `${…}` placeholders, resolved by
Keycloak at import. Keycloak's master administrator password, the client secret, the users'
password and the two local administrators' passwords are random, generated for the run, given to
Keycloak as Docker secrets that a wrapper exports for its process only (never in the container's
environment) and to the console as `DATABASTION_OIDC_CLIENT_SECRET_FILE`. The Keycloak image is the
one [`dev/docker-compose.yml`](../dev/docker-compose.yml) pins (tag and index digest, whose
provenance against quay.io the dev environment workflow checks); `oidc.sh` refuses a different pin.

**Console configuration.** `GROUPS_ATTRIBUTE_PATH=groups`, a role expression on the `groups` claim
only, `ROLE_ATTRIBUTE_STRICT=1`, local login `admins` (the default with OIDC on). The scenario
([`oidc_scenario.py`](oidc_scenario.py), Python standard library) runs twice, the web container
being recreated in between:

| Phase | Console settings | Cases |
|-------|------------------|-------|
| `signup-off` | `ALLOW_SIGN_UP=0`, `ALLOWED_GROUPS=databastion-admins,databastion-analysts`, `ALLOWED_DOMAINS=databastion.test` | Break-glass login of the local administrator `e2e-admin` (`user.login` with `break_glass`); with an e-mail channel flagged "system alerts" (never contacted: no worker runs), a second one queues the `user.local_login` delivery row (`pending`, user id and name). A local analyst `e2e-analyst` is refused (`401`, no session, `user.login` failures only) since `DATABASTION_LOCAL_LOGIN` is `admins`. `outsider.carol` refused (`group`), `unverified.dave` (`email_unverified`), `nogroup.erin` (`group`), no pending login for them. `admin.alice`: pending login (`sign_up`) listed with issuer, subject, login, mapped role `admin` (`syncedRole`) and groups; since role sync is on, approval as `analyst` is refused (`409 role_mismatch`, a failed `user.pending_login_approve` with `reason` and `mapped_role`, the pending login kept), approval as `admin` succeeds and her first login keeps `admin` with no `user.role_change`. `analyst.bob`: the same pattern (as `admin` refused, as `analyst` approved, no role change at login). Role sync at every login: `analyst.bob` is added to `databastion-admins` through the Keycloak admin API and his next login promotes him to `admin`, then removed from it and his next login demotes him to `analyst` (`user.role_change`, source `oidc`, both ways). `mallory` (Alice's e-mail and name): pending, never signed in to Alice's account; her username is then changed at runtime to `e2e-admin` through the Keycloak admin API (the realm lets her make the same edit in the account console; either way the next `id_token` carries the same claims): the same pending login (keyed by issuer and subject), mapped role `analyst`, approval refused `409 username_taken`, discarded, bound to no user. Self-service link: refused from an OIDC session (`409 local_session_required`); from the local session of a new local administrator `e2e-linker` whose browser already holds a Keycloak SSO session as `link.grace` (signed in to Keycloak's account console, proven by a form-less authorization), `prompt=login` / `max_age=0` make Keycloak show its login form again, nothing is recorded before the credentials are posted, then `user.identity_link` is audited with the session method, issuer and subject; `link.grace` then signs in to `e2e-linker`'s account. Logout of Alice's OIDC session: `200 {redirect_url}` with `client_id`, `logout_hint` (her subject) and `post_logout_redirect_uri`, no `id_token_hint`; console session gone, `user.logout` audited, Keycloak's confirmation submitted, the browser's Keycloak session ended, a new sign-in asks for credentials |
| `signup-on` | `ALLOW_SIGN_UP=1`, no group or domain filter, `USE_REFRESH_TOKEN=1` | `nogroup.erin` (no `groups` claim) and `outsider.carol` refused under strict mapping (`role`), no pending login. `mallory`, still named `e2e-admin`: refused (`username`), no user created, no identity bound, `e2e-admin` unchanged (role, local password, no identity, its session still valid). Positive control: `unverified.dave` signs up as `analyst`; his refresh token is stored as an AES-256-GCM blob (format byte 1, no JWT bytes) and his logout revokes it at Keycloak (`user.logout` with `refresh_revoked: true`) and deletes the session row. Never admin: the administrators are `admin.alice` (group), `e2e-admin` and `e2e-linker` (local) only, and no role change to `admin` but Bob's (the group granted at runtime, then removed) |

Every login goes through the real flow: `/api/auth/oidc/start` (checked: code flow, PKCE `S256`,
`state`, `nonce`, `query` response mode, exact redirect URI), Keycloak's login form, the callback
(RFC 9207 `iss` checked), the console's same-origin page (`/agents`, or the generic
`/login?sso_error=1` page) and a `__Host-` session cookie. Each refusal is checked in the console's
audit log (`user.login_denied` with exactly `{method: oidc, reason}`, and no login, sign-up, role
change or link). The browser is a headless HTTP client (urllib, no JavaScript) that follows each
redirect itself and resolves the two host names to `127.0.0.1`, with TLS verified against the run's
CA only and no proxy; the audit log and tables are read with `psql` in the `db` container, in
read-only transactions (`PGOPTIONS=-c default_transaction_read_only=on`, checked). The Keycloak admin
token is fetched again when the admin API answers `401`. The link's freshness is shown only on the
provider side (Keycloak re-prompts despite the SSO session); the console's own `auth_time` refusal
of a stale link is covered by the console's unit tests, not here.

**Secret hygiene.** Every generated secret is registered as in `run.sh`. The scenario records every
one-time value it sees: session tokens, CSRF tokens, Keycloak's admin token, the URL-borne
authorization codes, states and nonces, and Keycloak's session ids. After both phases, `oidc.sh` fails if any secret or
recorded value is found in the logs of `db`, `migrate`, `web`, `keycloak` and `bootstrap-admin` or
in a `pg_dump` of the console database, or if any secret, session or CSRF token is found in the
proxy's access log. That log records the callback URLs, and so the codes and states, by design: the
scan must find them there, as its positive control. Keycloak's session ids (`session_state`, the
provider `sid` the console keeps with the session, decision 13) are looked for in every log but the
proxy's, not in the dump. The tokens the scenario never sees (`id_token`, access and refresh tokens,
all JWTs at Keycloak) are looked for by shape (`eyJ….eyJ….`) in the web and Keycloak logs and the
dump, the scenario's Keycloak admin tokens excepted (their recognition is the positive control), and
the dump must hold no `"id_token"`, `"access_token"` or `"refresh_token"` field. `oidc.sh` also checks that
the first web process logged the provider discovery and the break-glass error of decision 11 (no
local administrator yet), and that the second one did not log that error. Logs are redacted in
place on exit, whatever the result.

```sh
e2e/oidc.sh                          # or: make e2e-oidc
E2E_KEYCLOAK_PORT=9444 e2e/oidc.sh   # if 8444 is taken on 127.0.0.1
```

The `E2E_OIDC_*` variables of the two configurations are set by `oidc.sh` itself (reset at start).
Logs go to `e2e/.logs-oidc/` (`E2E_LOG_DIR`, ignored by git). `E2E_SKIP_BUILD=1` reuses the console
image as for `run.sh` (`E2E_CONSOLE_IMAGE`), and
`E2E_KEYCLOAK_IMAGE` (local runs only, ignored under GitHub Actions) names a registry mirror of the
pinned image, which must carry the same digest (e.g.
`mirror.gcr.io/keycloak/keycloak@sha256:…`).

## CAS target
ROADMAP P8-D, [ADR-0041](../docs/adr/0041-cas-connector.md) decision 14: a `cas` target with
Discovery, Audit and the I2 check, and the CAS store guard against a real JPA ticket table.
[`cas.sh`](cas.sh) merges [`docker-compose.cas.yml`](docker-compose.cas.yml) over this stack (Compose
project `databastion-e2e-cas`, Compose v2.24 or later for `!override`) and starts only `db`,
`migrate`, `web`, `worker`, `proxy`, `cas-db`, `cas` and `agent`; [`run.sh`](run.sh) never reads the
override. The CI job is `e2e-cas` in [`ci.yml`](../.github/workflows/ci.yml) (45 min budget, `cas.sh`
at most 2400 s); it runs when `agent/`, `console/`, `shared/`, `e2e/`, `deploy/initdb/`, `dev/cas/`,
`dev/ground-truth.json`, `dev/docker-compose.yml` or `ci.yml` change, and is not part of the
required `CI result` check until it has run green on `dev`. It is a job of its own rather than a
part of `run.sh`: building the CAS overlay (its modules come from Maven Central, locked and
SHA-256 verified, [dev/README.md](../dev/README.md#apereo-cas)) and starting CAS add about five
minutes and an external dependency to the required `e2e` job.

| Service | Image | Role |
|---------|-------|------|
| `cas` | [`dev/cas`](../dev/cas/Dockerfile) (CAS 8.0.2 overlay: JSON service registry, OIDC, JPA ticket registry) | The dev service's image and configuration ([`cas.properties`](../dev/cas/config/cas.properties), [`log4j2.xml`](../dev/cas/config/log4j2.xml), mounted read-only): static users, the JSON audit trail to `/var/log/cas/cas_audit.log`, tickets encrypted by default. Plain HTTP published on `127.0.0.1:${E2E_CAS_PORT:-8281}` only (the agent never contacts CAS, ADR-0041 decision 9). The users' and database passwords are Docker secrets that a wrapper exports for the CAS process only (`cas.sh` checks that no password is in the container's environment). On `cas-backend` (internal, its database only) and `cas-net` (the published port), never on `agent-net`: `cas.sh` checks that CAS has no `agent-net` endpoint and that, from the agent container's network namespace, `cas` does not resolve and CAS's address does not answer |
| `cas-db` | PostgreSQL 17 (pinned) | The JPA ticket registry's database `cas` (owner `cas`, network alias `postgres` on `cas-backend` as in the dev JDBC URL), and the agent's PostgreSQL target `casdb-e2e` (`cas-db` on `agent-net`): the agent's role is checked against the ADR-0012 attributes and role settings as in `run.sh`; [`target-initdb/01-agent-role.sh`](target-initdb/01-agent-role.sh) (the ADR-0012 minimal role) and [`40-cas.sh`](target-initdb/40-cas.sh) (the role `cas`, `USAGE` on `public` for the agent, no `PUBLIC` access); once CAS created `cas_tickets`, `cas.sh` grants the agent `SELECT (type, creation_time, expiration_time)` only (ADR-0041 decision 6) and checks the table's shape and grants |
| `cas-files` | busybox (pinned) | One-shot, no network: [`dev/cas/files-init.sh`](../dev/cas/files-init.sh) on the volumes `cas-registry` (the definitions of [`dev/cas/services`](../dev/cas/services), directory `0750`, files `0640`) and `cas-log` (directory `2750`, the log `0640`), owner the CAS user (10041), group the agent's (10001). CAS mounts them without the image's copy-up (`nocopy`), the agent read-only at `/srv/cas/services` and `/var/log/cas`: nothing it could write, no symlink (ADR-0041 decision 3, [ADR-0043](../docs/adr/0043-audit-logs-opened-without-following-a-final-symlink.md)); `cas.sh` checks every mode, owner and link count |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | Targets `cas-e2e` (`engine: cas`, `json_dir`, `audit_log`, `clear_principals: [svc-monitoring]`, client addresses `truncated` by default) and `casdb-e2e` (`databases: [cas]`, the CAS store guard on by default) |

**Scenario.** The CAS traffic comes from [`cas_scenario.py`](cas_scenario.py) (Python standard
library, unit tests in [`test_cas_scenario.py`](test_cas_scenario.py)) on the host, as a browser:
the login form, the credentials, the service ticket from the redirect, its validation. Every login
uses a fresh cookie jar (no SSO reuse).
1. The agent is online with both targets; the console lists `engine.cas` (ADR-0042), so the `cas`
   target is reported: reachable, audit level **None** with `audit.limited_pending_first_record`
   before any record.
2. Two `access_event` policies on `cas-e2e` (every `read`; `volume.failed_logins_many_accounts`),
   Audit enabled on `cas-e2e`.
3. Two logins of each of the three e-mail users and one of `svc-monitoring`, each with a validated
   service ticket for `https://intranet.example.org/login` (`Intranet`); then 20 failed logins from
   the host, each with a distinct typed name (one of them a random password-like string) and a random
   password: a credential-stuffing burst from one client address.
4. Discovery of both targets. `cas-e2e`: [`i2_check.py findings`](i2_check.py) with every expected
   classifier and no negative control, and every `cas` location of the ground truth with an expected
   classifier found (contacts, the static release value, the required-attribute value, the audit
   trail's `who`), none on a credential field (`never_sampled`).
5. Audit: the heartbeat level becomes **Partial** (`cas_audit_log`), with
   `security.client_secrets_in_clear` (count 1: HR-Portal) and none of the "not seen", unreadable,
   unsupported-format, dropped, headers, writable or skipped notes. Events, exactly: 6 `connect`
   fingerprinted plus 1 of `svc-monitoring` in clear, 7 `read` of `service_registry` / `Intranet`
   (the object-form `what` of CAS 8.0, #143), 16 `auth_failure` with their own fingerprinted
   principal (the 16th with the signal) and the 4 others in the `*` aggregate with
   `volume.failed_logins_many_accounts`; every client address truncated to its /24, none stored as CAS
   logged it; no principal in clear but `svc-monitoring` and `*`; incidents of both policies (failed
   logins share one incident per client network, ADR-0031 decision 1: the stuffing incident links
   the `*` aggregate).
6. CAS store guard, real table: `cas_tickets` holds encoded tickets only; the agent logged
   `CAS ticket registry: metadata only` with `encrypted` > 0 and `unencrypted` 0 and did not sample
   it; the next heartbeat reports neither `security.ticket_registry_unencrypted`,
   `privilege.ticket_credentials_readable` nor `coverage.cas_guard_tripped`; no finding on it.
7. CAS store guard, clear tickets: the table emptied, CAS restarted with
   `cas.ticket.registry.jpa.crypto.enabled=false`, one more login per e-mail user with the service
   tickets left unvalidated (they stay in the table, ids in clear); then, as the superuser, a copy
   `sso_archive` of the table (clear ids, bodies and principals) and a plain table `app_sessions`
   holding every service ticket of the run next to contact e-mails, both readable in full by the
   agent. The run's ticket-granting ticket ids are read from the copy and searched like the service
   tickets. After a new scan: `security.ticket_registry_unencrypted`,
   `privilege.ticket_credentials_readable` (count 1: the copy, recognized by its column shape; the
   real table keeps its column grants) and `coverage.cas_guard_tripped`; no finding on either
   ticket table nor on `app_sessions.session_ref`, and `app_sessions.contact` found (positive
   control).
8. I2 and secret hygiene: no `cas` value of the ground truth (the `never_sampled` client secrets
   and header included; positive control: a canary file holding one) in a `pg_dump` of the console
   database, the exports of its Audit tables, the findings, events, incidents and agent pages, the
   agent's state volume (spool, cursors, settings) or the logs of every container but CAS and
   `cas-db` (the target side). No service ticket, ticket-granting ticket, ticket-granting cookie,
   nor SHA-256 / SHA-512 of a ticket, no typed name of a failed login, no password (typed or
   generated) in the same places (positive control: the copy of the ticket table holds tickets of the
   run); no generated secret in any log, CAS's included. Also by shape, as `oidc.sh` scans for JWTs:
   no `(TGT|ST|PT|PGT|PGTIOU|TST|OC|AT|RT|ODT|ODUC|CIBA|OPAR)-<digits>-<8+ characters>` value in the same places,
   which covers the tickets never seen on the wire (the ticket-granting tickets of the encrypted
   phase); positive control: the ids of the ticket table's copy. The pages' scans have their own
   controls (the events and incidents pages list `svc-monitoring`, the findings page names
   `cas-e2e`). At the end the CAS audit trail (rotations included) is read again: every typed name
   must be in it (the control of the typed-name scans), and every ticket-shaped token in it is
   registered and searched like the run's tickets. CAS's audit appender masks ticket ids (dev's
   `make dev-cas-smoke` checks it), so the exact ticket values come from the scenario's redirects
   and the table's copy; their absence is proven by those exact scans and the shape scan. CAS logs
   the typed names itself: they are redacted from the kept logs like the secrets. The harness reads
   the console database and, but for its fixtures, the CAS database in read-only transactions.

```sh
e2e/cas.sh                         # builds the console, agent and CAS images first
E2E_SKIP_BUILD=1 e2e/cas.sh        # reuse them (E2E_CONSOLE_IMAGE, E2E_AGENT_IMAGE, E2E_CAS_IMAGE)
E2E_CAS_PORT=9281 e2e/cas.sh       # if 8281 is taken on 127.0.0.1
```

Logs go to `e2e/.logs-cas/` (`E2E_LOG_DIR`, ignored by git). Behind a TLS-intercepting proxy the CAS
overlay cannot be built as is (Gradle must trust the proxy's CA): build it beforehand with a local
Gradle base image that trusts it (`docker build --build-arg GRADLE_IMAGE=<that image> -t
databastion-dev/cas:8.0.2-overlay dev/cas`, never committed), then run with `E2E_SKIP_BUILD=1`.

## Load / database impact
The load harness ([`load/`](load/README.md), phase 7) reuses this stack's targets and accounts to
measure the database CPU impact of Discovery, the Audit path under a sustained workload and the
agent's resource use, and, with [`load/cas.sh`](load/README.md#cas-target), the CAS target under a
login workload. It runs in its own workflow, outside the required `CI result` check.
