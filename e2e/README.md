# End-to-end tests

Phase 1 exit criterion ([ROADMAP](../docs/ROADMAP.md)): *end-to-end enrollment in containers;
revocation effective in < 60 s*; and the invariant I2 test (P2-E): *no value of
[`dev/ground-truth.json`](../dev/ground-truth.json) in clear text in the console, including
value-bearing object and field names*, for the PostgreSQL, MySQL and MariaDB targets; and the Audit
path (P4-D) with the phase 4 exit criterion *`pg_dump` / `mysqldump` in dev → incident in under 2
minutes*, on the PostgreSQL target (pgaudit) and the MariaDB target (`server_audit` log, P4-B,
[ADR-0023](../docs/adr/0023-mysql-mariadb-audit-sources-and-levels.md)); see also
[Adding an Audit target](#adding-an-audit-target).
[`run.sh`](run.sh) drives [`docker-compose.yml`](docker-compose.yml); the CI job is `e2e` in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml), required through the `CI result` gate.
It runs when `agent/`, `console/`, `shared/`, `e2e/`, `deploy/`, `dev/seed/out/`,
`dev/ground-truth.json`, `dev/mysql/`, `dev/mariadb/`, `dev/postgres/` or `ci.yml` change (and
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
| `target-pg` | [`dev/postgres`](../dev/postgres/Dockerfile) (PostgreSQL 17 + pgaudit) | Declared target of the agent, database `shop` loaded with the committed dev seed [`dev/seed/out/postgres.sql`](../dev/seed/out/postgres.sql) (schemas `crm`, `billing`, `ops`, value-bearing table names included); [`target-initdb/`](target-initdb/) creates the agent's read-only role and its per-schema Discovery grants, then ([`30-audit.sh`](target-initdb/30-audit.sh)) the Audit setup of the dev image, per database: pgaudit `read, write` session audit, object audit of the seeded tables through `databastion_auditor`, `log_relation`, `log_rows`, no catalog, no parameters; `pg_stat_statements`; and the test client roles `e2e_exporter` / `e2e_analyst` (read-only on the seeded schemas). Its jsonlog goes to the `target-pg-log` volume (directory `0750`, files `0640`, owner `postgres` 999:999) |
| `pg-client` | PostgreSQL 17 | One-shot database client of the Audit test (`tools` profile): `pg_dump` as `e2e_exporter`, queries as `e2e_analyst`; rows go to `/dev/null` inside the container |
| `my-client` | MariaDB 11.4 | Same for `target-mariadb` (`tools` profile): `mariadb-dump` as `e2e_exporter`, queries as `e2e_analyst`, TLS verified against the target's dev CA |
| `target-mysql` | MySQL 8.4 (dev image pin) | Declared target, the dev configuration mounted read-only: [`dev/mysql/databastion.cnf`](../dev/mysql/databastion.cnf), seed [`dev/seed/out/mysql.sql`](../dev/seed/out/mysql.sql) (database `hr`), [`dev/mysql/initdb/20-databastion.sh`](../dev/mysql/initdb/20-databastion.sh) (agent account) and `30-tls.sh` (throwaway CA, certificate for the network alias `mysql`); [`target-initdb/15-agent-password.sh`](target-initdb/15-agent-password.sh) feeds the agent password from its Docker secret |
| `target-mariadb` | MariaDB 11.4 (dev image pin) | Same with [`dev/mariadb/`](../dev/mariadb/) (`server_audit` on: `CONNECT,QUERY_DML,TABLE` to a file), seed [`dev/seed/out/mariadb.sql`](../dev/seed/out/mariadb.sql) (database `support`, one value-bearing table name), alias `mariadb`; [`target-initdb/35-mariadb-clients.sh`](target-initdb/35-mariadb-clients.sh) adds the Audit test accounts `e2e_exporter` / `e2e_analyst` (`SELECT` on `support.*` only). `UMASK=0640`: the `server_audit` log on the `target-mariadb-log` volume (directory `0750`, `mysql` 999:999) is readable by the agent through its group 999 only; the agent account keeps the ADR-0018 minimal grants (no `performance_schema` grant, [ADR-0023](../docs/adr/0023-mysql-mariadb-audit-sources-and-levels.md) decision 3) |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | `databastion-agent`, HTTPS only (`ca_file` pins the test CA), `DATABASTION_LOG=debug` so the I2 log scan covers debug-level logging; `target-pg-log` mounted read-only, readable through the supplementary group 999 (the e2e stand-in for the production ACL on the log directory, [ADR-0012](../docs/adr/0012-postgresql-agent-grants.md)) and declared as `postgres.audit_log {path, format: jsonlog}` |
| `bootstrap-admin`, `agent-files` | console / PostgreSQL | One-shot helpers (`tools` profile) |

Networks: the agent sits on an `internal` network with the proxy and the targets only; it
cannot reach the console database or the outside. Only the proxy is published, on
`127.0.0.1:${E2E_HTTPS_PORT:-8443}`. Every service runs with a read-only root filesystem,
`cap_drop: ALL` (PostgreSQL, MySQL and MariaDB get back what their entrypoints need; their data
lives in `tmpfs`) and `no-new-privileges`.

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
   Before anything starts, the I2 scanner's positive control checks, per engine, that every
   searchable value of the ground truth is visible in the committed seed.
2. Build the console, agent and target PostgreSQL images, hand the `target-pg-log` volume to the
   target's `postgres` user (`999:999`, `0750`), start the console stack, Mailpit and the three
   targets, wait for
   `/api/health/ready` through the proxy and for the MySQL / MariaDB targets to be healthy; copy
   their CA (created by dev's `30-tls.sh`, checked to be that CA and to hold no key) into the work
   directory, mounted into the agent as `ca_file`.
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
   and is refused without TLS (error 1045).
6. Audit setup (P4-D), through the user API as a user would: an e-mail channel to Mailpit
   (`starttls`, port 2525), two `access_event` policies, `e2e dump signature` (signal
   `signature.pg_dump` or `signature.mysqldump` on the Audit targets → **critical** incident +
   e-mail) and `e2e reads` (every `read` on the Audit targets → medium incident + e-mail). After
   each policy creation, the web process's wake-up (#63) must queue a `policies.evaluate` pg-boss
   job within 5 s. Jobs the worker's schedule produced (sent while a `__pgboss__send-it` job of
   that queue ran) do not count; a job not cancelled, created within the previous 60 s or the 5 s
   after, and not started at that time (the schedule's included) is accepted as a coalesced
   wake-up (the queue is stately), but at least one wake-up per kind of action must be a job of
   its own. Then `audit.configure` of `pg-e2e` and `mariadb-e2e`
   (enabled, contract defaults: aggregation 60 s, poll 10 s, no `min_rows`; sensitive objects
   derived from the findings, none yet). The harness waits for the job and for the agent's
   `audit source: pgaudit log` / `audit source: audit log file` line, **before** the Discovery
   scan, so the agent's own Discovery reads go through the Audit stream.
7. Discovery (P2-E): launch a `discovery.scan` of `pg-e2e`, `mysql-e2e` and `mariadb-e2e`
   together through the user API (admin session + CSRF) and wait for every job to succeed (360 s
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
   found (informational). For `mysql-e2e` and `mariadb-e2e`, `i2_check.py findings
   --require-expected-classifiers --forbid-negative-controls` requires a finding for every
   classifier the ground truth expects for the engine, no finding on a negative-control location
   (MariaDB's value-bearing table included, under its normalized name) and no stored name holding
   a value-bearing name, even partially. The findings page is fetched with the session (masked samples are
   decrypted there; they are encrypted at rest in the database); [`i2_check.py page`](i2_check.py)
   asserts it is complete (every finding listed, fewer than the 500-row listing cap, every
   finding with stored samples renders them, none `unavailable`) and that no masked sample keeps
   more than 4 digits (a partial masking regression the value search cannot see).
8. Audit (P4-D), for each Audit target:
   - `audit.configure` again: the sensitive objects derived from the findings must cover every
     object with a finding (checked in `audit_configs.sent_objects`); the stream restarts from its
     cursor.
   - **Exit criterion**: `pg_dump` of `shop` as `e2e_exporter` from the `pg-client` container (not
     the agent's account). The time from the start of the dump to the incident appearing on the
     console (the `Active: N critical` count of the incidents page, fetched with the session
     through the proxy, polled every second) must rise, and the console must hold an incident of
     this target, this principal and the dump policy, carrying the dump signal, with `created_at`
     after the dump started. Both times (page, `created_at`) are printed and must be **under
     120 s**.
     On MariaDB the same with `mariadb-dump --single-transaction --no-tablespaces support` from
     `my-client` (signal `signature.mysqldump`).
   - As `e2e_analyst` (PostgreSQL): `SELECT * FROM crm.customers WHERE email = '<ground-truth e-mail>'`,
     `COPY (SELECT * FROM billing.payment_methods WHERE iban = '<ground-truth IBAN>') TO STDOUT`
     and `COPY ops.app_credentials TO STDOUT`, fed on stdin (the literals are on no command line
     and in no log of the harness). MariaDB: `SELECT … FROM tickets WHERE requester_email = '<…>'`
     and `… WHERE requester_phone = '<…>'`, then `SELECT * FROM tickets INTO OUTFILE …`, which must
     be refused (`ERROR 1227`, MariaDB's missing-`FILE`-privilege error) and still carry `signature.into_outfile`. The
     harness waits (240 s at most) until the object sets read (PostgreSQL 3, MariaDB 1) and every
     literal-bearing read statement (3 on each target, the sum of `aggregated_count` of the
     `e2e_analyst` read events) are stored, every event is evaluated, a `e2e reads` incident exists
     for `e2e_analyst` and no notification is pending. The grants of `e2e_exporter` /
     `e2e_analyst` on MariaDB are checked to be exactly `USAGE` and `SELECT ON support.*` (step 5).
   - The heartbeat must report audit level `partial` or `full` with source `pgaudit`
     (PostgreSQL), `partial` with source `mariadb_server_audit` (MariaDB: never Full, ADR-0023).
   - Every notification to the channel is `delivered` and Mailpit holds the e-mail of the dump
     incident; every message has a text part naming an Audit target or principal.
   - [`i2_check.py audit`](i2_check.py) on the target's events and incidents: an event of
     `e2e_exporter` with the dump signal, an event of `e2e_analyst` (MariaDB: with
     `signature.into_outfile`), the dump incident (policy, principal, signal) and the `e2e reads`
     incident of `e2e_analyst`; **no event and no incident of the agent's account**
     (`databastion_agent`, `databastion`: its own Discovery reads, which ran while Audit was on,
     must not surface); no stored event object holding a raw value-bearing name, even partially.
   - Positive control of the literal search: every literal must be found in the file the agent
     reads, alone: the pgaudit jsonlog; the `server_audit` log and its rotations (not
     `performance_schema`, which the agent's account cannot read). `E2E_PG_AUDIT=pss` has no such
     control.
   - After all targets: no event carries a `db_user_fingerprint`; every stored events batch woke
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
   `READ` / `QUERY` records of `databastion` on `support`): the positive control of "no
   own-account event", the reads were seen and filtered, not missed (not in `pss` mode). Then
   `pg_dump` the console database into the private temporary directory (never the log directory)
   and fail if any registered secret (the whole registry: the Mailpit SMTP password and its
   base64 AUTH PLAIN / AUTH LOGIN forms included) is stored in clear text. The registry also
   holds the session cookie and the CSRF token; neither is expected in the database:
   `console/src/server/auth/session.ts` stores only the SHA-256 of the session cookie
   (`sessions.token_hash`) and derives the CSRF token as an HMAC of the cookie, never stored.
12. Invariant I2, for each engine (`postgresql`, `mysql`, `mariadb`):
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
    Then the query literals of step 8 alone (`scan --needle`) on every console-side artifact above,
    the console database dump and the logs: they must be nowhere.

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
target's own audit log (plus `object_sets` and `query_signal`). A new target adds a line, a client
service, its test accounts, its audit log mounted read-only into the agent and declared in
`agent.yaml`, and its dev directory in the CI path filter. Not covered: MySQL Community (its only
source, `performance_schema`, needs a grant the minimal agent account must not have in the e2e
stack, ADR-0023 decision 3) and Percona's `audit_log_filter` (a fourth target and image; the
connector's integration tests cover it against `dev/percona`). The policies, the channel, the
timing, the Audit and I2 checks are shared.

## Running locally
Requirements: Docker with Compose v2, `openssl`, `curl`, `jq`, bash.

```sh
e2e/run.sh
E2E_HTTPS_PORT=9443 e2e/run.sh      # if 8443 is taken on 127.0.0.1
```

The first run builds the console, agent and target PostgreSQL (dev/postgres, pgaudit from the PGDG
apt repository) images (several minutes). No secret is written to the repository; nothing listens
outside `127.0.0.1`. `E2E_SKIP_BUILD=1` (ignored under GitHub Actions) reuses
`databastion-console:e2e`, `databastion-agent:e2e` and `databastion-dev/postgres:17.11-pgaudit`
as already built (`E2E_CONSOLE_IMAGE`, `E2E_AGENT_IMAGE`, `E2E_TARGET_PG_IMAGE` name other tags),
for hosts where the Dockerfiles cannot build as is (e.g. a TLS-intercepting proxy). Behind an HTTP
proxy, add `console.e2e.internal` to `NO_PROXY` so that curl reaches the local TLS proxy directly.
Where the apt mirrors are blocked, `E2E_PG_AUDIT=pss` (local runs only; refused under GitHub
Actions) runs `target-pg` on the plain pinned PostgreSQL image with `pg_stat_statements` only: the
agent reports the Limited level from that source, the Audit steps run the same way (the dump is
recognized by its `COPY … TO STDOUT` of several whole tables), and the pgaudit-only checks (level,
source, literal positive control in the target's log) are replaced or skipped, as printed. It is not
a substitute for the CI run.
