# Dev environment

Local databases seeded with **fake** sensitive data, plus the tooling around the console (Mailpit, Prometheus, Grafana). Everything runs in Docker Compose ([docker-compose.yml](docker-compose.yml)); the console and the agent are not containerized yet and run on the host.

## Quick start
```sh
make dev          # copies dev/.env.example to dev/.env if missing, builds, starts, waits until healthy
make dev-smoke    # checks accounts, audit logs and UIs
make dev-down     # stops (keeps volumes)
make dev-reset    # stops, deletes volumes and dev/.state (the seed is reloaded on the next `make dev`)
make dev-logs     # last 200 log lines of every service (TAIL=n to change)
make seed         # regenerates dev/seed/out/* and dev/ground-truth.json
make test-dev     # unit tests of the seed generator
make agent-it     # connector integration tests against this environment (ENGINE=postgres|mysql|mongodb|openldap)
```
`make help` lists every target by section (setup with `make install` / `make doctor`, console, agent, protocol, `make check`, end-to-end, release). The CI workflow `.github/workflows/dev-env.yml` runs the same steps as `make dev` / `make dev-smoke`; `make agent-it` ([agent-it.sh](agent-it.sh)) runs the "dev image" step of the CI connector jobs, with the variables shown below.

## Services
All ports are published on **127.0.0.1 only**; host ports can be changed in `dev/.env`.

| Service | Host port | Seeded database | Audit source | Audit level ([docs/08](../docs/08-engine-capabilities.md)) |
|---------|-----------|-----------------|--------------|-------|
| PostgreSQL 17.11 + pgaudit (`postgres`) | 5432 | `shop` (schemas `crm`, `billing`, `ops`) | pgaudit in `jsonlog`, `pg_stat_statements`, `log_connections` | Full |
| MariaDB 11.4 LTS (`mariadb`) | 3307 | `support` | `server_audit` plugin (`CONNECT,QUERY_DML,TABLE`), `performance_schema` | Partial (no row counts in the log) |
| MySQL 8.4 LTS Community (`mysql`) | 3306 | `hr` | `performance_schema` history consumers (`events_statements_history_long`) | Partial |
| Percona Server 8.4 (`percona`) | 3308 | `hr` (the MySQL seed) | `audit_log_filter` component, JSON (`log_all` for every account but `root@localhost`) | Partial (no row counts in the log) |
| MongoDB 8.0 Community (`mongo`) | 27017 | `app` | profiler level 1 (`slowms` from `MONGO_SLOWMS`, default 0) + JSON log | Limited ([ADR-0027](../docs/adr/0027-mongodb-audit.md): server log or profiler) |
| Percona Server for MongoDB 8.0 (`psmdb`, opt-in: profile `psmdb`) | 27019 | `app` (the MongoDB seed) | `auditLog` JSON file (`auditAuthorizationSuccess`) in `dev/.state/logs/psmdb/auditLog.json` | Partial ([ADR-0027](../docs/adr/0027-mongodb-audit.md): once a successful `authCheck` was read) |
| OpenLDAP (Debian slapd) (`openldap`) | 1389 (LDAPS 1636) | `dc=example,dc=org` | `slapo-accesslog` in `cn=accesslog` (`reads writes session`) | Full ([ADR-0029](../docs/adr/0029-openldap-connector.md): once each naming context shows a search record) |
| Mailpit (`mailpit`) | SMTP 1025, UI 8025 | | | |
| Prometheus (`prometheus`) | 9090 | | | |
| Grafana (`grafana`) | 3001 | | | |

- Mailpit UI: <http://127.0.0.1:8025> (SMTP `127.0.0.1:1025`, no auth), for alert e-mails (P3-C).
- Prometheus: <http://127.0.0.1:9090>. Following [ADR-0004](../docs/adr/0004-observability-via-console.md), it scrapes a single target, the console `/metrics` at `host.docker.internal:3000`; agents are never scraped. That job is **DOWN** until the host console runs with the scrape token (below).
- Metrics token: the console `/metrics` requires `Authorization: Bearer <token>` (`DATABASTION_METRICS_TOKEN(_FILE)`, at least 32 characters; otherwise `/metrics` answers `404`). `make dev` (target `dev-metrics-token`) generates `dev/.state/metrics_token` once (48 random characters, mode `0600`, git-ignored, removed by `make dev-reset`); the one-shot `metrics-token-init` service (busybox, no network, only the `CHOWN`, `DAC_READ_SEARCH` and `FOWNER` capabilities) copies it into the `prometheus-secrets` volume as `0400`, owned by the Prometheus user (65534), and Prometheus reads it read-only (`credentials_file: /etc/prometheus/secrets/metrics_token`). After changing the token, run `make dev` again (the init service re-runs on `up`). Start the host console with the same file:

  ```bash
  DATABASTION_METRICS_TOKEN_FILE="$PWD/dev/.state/metrics_token" pnpm dev   # from console/: ../dev/.state/metrics_token
  ```

  Prometheus itself runs as non-root. Run `make dev-metrics-token` first if you call `docker compose` directly (otherwise Docker creates a directory at that path).
- Grafana: <http://127.0.0.1:3001> (user `admin`, password `GRAFANA_ADMIN_PASSWORD`). Dashboard *DataBastion / DataBastion - overview*: agents online, silent agents, heartbeat age, spool size. Metric names (`databastion_agent_last_seen_seconds`, `databastion_agent_reported_spool_bytes`) are provisional until the console implements `/metrics`.

## Credentials
Dev-only values in [.env.example](.env.example), copied to `dev/.env` (git-ignored). The agent uses only the read-only account `databastion` (password `DATABASTION_DB_PASSWORD`) created in every engine as recommended in [docs/05-security.md](../docs/05-security.md#recommended-database-accounts-read-only):

| Engine | Account | Rights |
|--------|---------|--------|
| PostgreSQL | `databastion` | [ADR-0012](../docs/adr/0012-postgresql-agent-grants.md) minimal variant: `CONNECTION LIMIT 5` (scan, `check()`, `KILL`/cancel, and the held `pg_stat_statements` Audit session plus its re-probe; ADR-0025 decision 11), no superuser / createdb / createrole / replication / bypassrls; `CONNECT`, `USAGE` + `SELECT` on `crm`, `billing`, `ops` (+ default privileges `FOR ROLE postgres`), `pg_read_all_stats`; role defaults `default_transaction_read_only=on`, `statement_timeout=30s`, `lock_timeout=2s`, `idle_in_transaction_session_timeout=60s` |
| MariaDB / MySQL / Percona | `databastion@'%'` | ADR-0018 minimal variant: `SELECT` on the application database only (`support` / `hr`), `REQUIRE SSL`, `MAX_USER_CONNECTIONS 5` (scan, `check()`, the connector's `KILL QUERY` session and a file-source Audit re-probe; ADR-0025 decision 11: 6 with `performance_schema` Audit); MariaDB also `MAX_STATEMENT_TIME 30`. No global privilege, no `PROCESS`, no `SHOW VIEW`, no `performance_schema` grant: MariaDB and Percona Audit reads their log files; on MySQL (whose only source is `performance_schema`), the Audit tests create their own account with that grant (ADR-0018 gives it only with Audit, and `check()` reports it as over-privilege while no Audit stream runs) |
| MongoDB | `databastion` (auth db `admin`) | [ADR-0026](../docs/adr/0026-mongodb-connector.md): custom role `databastionDiscovery` with `find` and `listCollections` on `app` only, SCRAM-SHA-256 credentials only. No `read` role (change streams, `system.js`), no `clusterMonitor` (other sessions' operations, `system.profile`). As a dev-only deviation, no `authenticationRestrictions` (the agent connects through the published port). The container healthcheck runs `getCmdLineOpts` as `root`, since the agent account cannot |
| OpenLDAP | `cn=databastion,ou=services,dc=example,dc=org` | read on the tree (except the credential attributes `userPassword` and `userPKCS12`) and on `cn=accesslog` |

PostgreSQL: no `pg_read_all_data` / `pg_monitor` (they expose `pg_authid`, `pg_user_mapping`, `pg_subscription`, large objects and raw statistics, ADR-0012); a schema added to the seed needs its own `USAGE` / `SELECT` grants in [postgres/initdb/20-databastion.sh](postgres/initdb/20-databastion.sh). `make dev-smoke` checks that the account cannot read `pg_authid` nor `pg_user_mapping`.

MySQL / MariaDB: no `SELECT ON *.*` (it would expose the `mysql.user` / `mysql.global_priv` password hashes and `mysql.servers` credentials, ADR-0018); a database added to the seed needs its own `GRANT SELECT` in `initdb/20-databastion.sh`. The account requires TLS (clients: `--ssl-mode=REQUIRED` / `--ssl`, which the dev certificates allow). `make dev-smoke` checks that it cannot read `mysql.user` / `mysql.global_priv` nor connect without TLS. The `'%'` host is only because the agent connects through the published port in dev.

Administrator accounts (`postgres`, `root`, `cn=admin,dc=example,dc=org`) exist for seeding and manual inspection only.

## Connecting
```sh
set -a; . dev/.env; set +a
PGPASSWORD=$DATABASTION_DB_PASSWORD psql -h 127.0.0.1 -U databastion shop
MYSQL_PWD=$DATABASTION_DB_PASSWORD mariadb -h 127.0.0.1 -P 3307 -u databastion support
MYSQL_PWD=$DATABASTION_DB_PASSWORD mysql -h 127.0.0.1 -P 3306 -u databastion hr
MYSQL_PWD=$DATABASTION_DB_PASSWORD mysql -h 127.0.0.1 -P 3308 -u databastion hr   # Percona
mongosh "mongodb://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:27017/app?authSource=admin"
ldapsearch -x -H ldap://127.0.0.1:1389 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -b dc=example,dc=org
ldapsearch -x -H ldap://127.0.0.1:1389 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -b cn=accesslog
LDAPTLS_CACERT=ca.pem ldapsearch -x -H ldaps://localhost:1636 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -b dc=example,dc=org
```
Without local clients, use `docker compose -f dev/docker-compose.yml exec <service> …`.

## Engine configuration
- **PostgreSQL**: image built from `postgres:17.11-bookworm` + `postgresql-17-pgaudit` (PGDG). `shared_preload_libraries=pgaudit,pg_stat_statements`. Following the docs/08 advice to restrict pgaudit, `pgaudit.log` is `none` server-wide and `read, write` on the `shop` database only; object audit covers the seeded tables through the `databastion_auditor` role (`pgaudit.role`). A `SELECT` on an audited table therefore logs both a `SESSION` and an `OBJECT` line. `pgaudit.log_parameter=off`. Logs: `dev/.state/logs/postgres/postgresql.json`, with `log_file_mode=0644` as a dev-only convenience (production: `0640` plus an ACL for the agent's OS user, ADR-0012).
- **MariaDB**: [mariadb/databastion.cnf](mariadb/databastion.cnf). The image's `healthcheck` user is excluded from the `QUERY` / `TABLE` audit events (its connections are still logged). Log: `dev/.state/logs/mariadb/server_audit.log`, created `0644` through `UMASK=0644` as a dev-only convenience (production: the agent's OS user gets read access on the log directory only). `performance_schema` has `events_statements_current` on, without which MariaDB fills no statement history. TLS with dev-only material from [mariadb/initdb/30-tls.sh](mariadb/initdb/30-tls.sh) (below).
- **MySQL**: [mysql/databastion.cnf](mysql/databastion.cnf). No file log: the agent reads `performance_schema`, a ring buffer (10 000 statements). The `FEDERATED` engine is enabled as a test fixture only (the connector test proves such a table is never read). TLS with dev-only material from [mysql/initdb/30-tls.sh](mysql/initdb/30-tls.sh) (below).
- **Percona Server**: [percona/databastion.cnf](percona/databastion.cnf) and [percona/initdb/20-databastion.sh](percona/initdb/20-databastion.sh): the `audit_log_filter` component, installed at initialization, writes JSON to `dev/.state/logs/percona/audit_filter.log` (`0644` through `UMASK`, dev only; rotated at each server start). Every account is logged but `root@localhost`, which the healthcheck uses on the socket. Same seed and TLS script as MySQL.
- **MongoDB**: `--profile 1 --slowms $MONGO_SLOWMS`. `0` makes every operation visible in dev; use a higher value to reproduce the production trade-off (a fast `mongodump` can go unnoticed). Log: `dev/.state/logs/mongodb/mongod.log`.
- **OpenLDAP**: image built from Debian's `slapd` package ([openldap/Dockerfile](openldap/Dockerfile)): osixia/openldap is unmaintained and the Bitnami catalog no longer publishes free versioned tags. Configuration in [openldap/config.ldif](openldap/config.ldif) (`olcAccessLogOps: reads writes session`, purge after 7 days). Healthchecks use `ldapi://` on `cn=config`, so they do not add entries to `cn=accesslog`. A dev-only custom schema (`cn=databastion-dev`: the `databastionContractor` class and its NIR, IBAN and code attributes, under `ou=contractors`) tests Discovery of custom attributes. LDAPS (1636) and StartTLS use a dev-only CA and server certificate (`localhost`, `127.0.0.1`, `openldap`) generated by [openldap/entrypoint.sh](openldap/entrypoint.sh) on the first start of the data volume (the CA key is deleted at once); get the CA with `docker compose -f dev/docker-compose.yml exec -T openldap cat /var/lib/ldap/tls/ca.pem`. For the SASL `EXTERNAL` integration test, [openldap/compose.ldapi.yml](openldap/compose.ldapi.yml) publishes the `ldapi://` socket directory to `dev/.state/ldapi/` (not part of `make dev`); CI then maps the runner's uid to the service DN with `olcAuthzRegexp` (see `.github/workflows/ci.yml`, job `agent-openldap`). A volume created before phase 6 has neither: `make dev-reset dev`.

`make dev` creates `dev/.state/logs/{postgres,mariadb,mongodb,percona}` world-writable (the engines run as non-root users with other UIDs). Run `make dev-dirs dev-metrics-token` first if you call `docker compose` directly.

## Connector integration tests
The PostgreSQL connector tests (`agent/crates/connector-postgres/src/it.rs`) run against this
environment when these variables are set, and are skipped otherwise:

```sh
set -a; . dev/.env; set +a
export DATABASTION_TEST_PG_URL="postgresql://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:${POSTGRES_PORT:-5432}/shop"
# ADR-0012 fixture probes (database databastion_probe, role databastion_it_ext): a superuser.
export DATABASTION_TEST_PG_ADMIN_URL="postgresql://postgres:$POSTGRES_ADMIN_PASSWORD@127.0.0.1:${POSTGRES_PORT:-5432}/shop"
(cd agent && cargo test -p databastion-connector-postgres -- --nocapture)
```

Without Docker, [postgres/local-cluster.sh](postgres/local-cluster.sh) starts a throwaway cluster
from the host's PostgreSQL binaries (127.0.0.1:55432, same seed, same `20-databastion.sh`, no
pgaudit unless installed; TLS with a throwaway CA, exported as `DATABASTION_TEST_PG_CA_FILE` for the
`verify_full` test; `pg_hba` lines for the md5 / cleartext refusal test) and prints the variables: `eval "$(dev/postgres/local-cluster.sh start)"`,
then `dev/postgres/local-cluster.sh stop` (deletes it). The pgaudit probe of ADR-0012 only runs
where pgaudit is loaded (the dev image). A skipped check prints `skipped: …`;
`DATABASTION_TEST_REQUIRE` (comma-separated: `pg`, `admin`, `pss`, `pgaudit`, `weak-auth`, `tls`,
or `all`) turns the listed skips into failures, as CI does for each server.

The MySQL / MariaDB connector tests (`agent/crates/connector-mysql/src/it.rs`) run against the
`mysql` and `mariadb` services the same way. Both servers use dev-only TLS material created at
initialization by `initdb/30-tls.sh` (a throwaway CA, whose key is deleted, signs a certificate for
`127.0.0.1`, `::1`, `localhost` and the service name), so that the tests use the connector's default
`tls: verify_full` with the CA pinned. Export the CAs once the services are up (on volumes created
before this script existed, run `make dev-reset dev` first):

```sh
set -a; . dev/.env; set +a
mkdir -p dev/.state/tls
docker compose -f dev/docker-compose.yml exec -T mysql cat /var/lib/mysql/ca.pem > dev/.state/tls/mysql-ca.pem
docker compose -f dev/docker-compose.yml exec -T mariadb cat /var/lib/mysql/databastion-tls/ca.pem > dev/.state/tls/mariadb-ca.pem
export DATABASTION_TEST_MYSQL_URL="mysql://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:${MYSQL_PORT:-3306}/hr"
export DATABASTION_TEST_MYSQL_ADMIN_URL="mysql://root:$MYSQL_ROOT_PASSWORD@127.0.0.1:${MYSQL_PORT:-3306}/"
export DATABASTION_TEST_MYSQL_CA_FILE="$PWD/dev/.state/tls/mysql-ca.pem"
export DATABASTION_TEST_MARIADB_URL="mysql://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:${MARIADB_PORT:-3307}/support"
export DATABASTION_TEST_MARIADB_ADMIN_URL="mysql://root:$MARIADB_ROOT_PASSWORD@127.0.0.1:${MARIADB_PORT:-3307}/"
export DATABASTION_TEST_MARIADB_CA_FILE="$PWD/dev/.state/tls/mariadb-ca.pem"
# Optional: the container address, for the mysql_native_password refusal on a network without TLS.
export DATABASTION_TEST_MARIADB_NETWORK_HOST="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' databastion-dev-mariadb-1)"
(cd agent && cargo test -p databastion-connector-mysql -- --nocapture)
```

The admin URLs are for the probe fixtures (databases `databastion_probe` and
`databastion_probe_sink`, accounts `databastion_it_*`, the `ha_federatedx` and `auth_pam` plugins
installed on MariaDB). MySQL accounts use `caching_sha2_password`, whose full authentication the
connector only performs over TLS, and the dev agent account requires TLS: without
`DATABASTION_TEST_<S>_CA_FILE` the tests of that server are skipped. The probes scan with test
accounts (`databastion_it_scan` on the probe database, `databastion_it_min`, `databastion_it_rw`,
`databastion_it_ext` for the extended variant) so that the dev account keeps its minimal grants. `DATABASTION_TEST_REQUIRE` accepts `mysql`, `mariadb`, `mysql-admin`, `mariadb-admin`,
`mysql-tls`, `mariadb-tls`, `federated`, `pam`, `network`, and the Audit keys below (or `all`).

The Audit tests (`agent/crates/connector-mysql/src/it/audit_it.rs`, P4-B) also read the audit logs
on the host and use the `percona` service; the dump commands run the real tools inside the
containers (their sessions are logged too):

```sh
docker compose -f dev/docker-compose.yml exec -T percona cat /var/lib/mysql/ca.pem > dev/.state/tls/percona-ca.pem
export DATABASTION_TEST_MARIADB_AUDIT_LOG="$PWD/dev/.state/logs/mariadb/server_audit.log"
export DATABASTION_TEST_PERCONA_URL="mysql://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:${PERCONA_PORT:-3308}/hr"
export DATABASTION_TEST_PERCONA_ADMIN_URL="mysql://root:$PERCONA_ROOT_PASSWORD@127.0.0.1:${PERCONA_PORT:-3308}/"
export DATABASTION_TEST_PERCONA_CA_FILE="$PWD/dev/.state/tls/percona-ca.pem"
export DATABASTION_TEST_PERCONA_AUDIT_LOG="$PWD/dev/.state/logs/percona/audit_filter.log"
C="docker compose -f $PWD/dev/docker-compose.yml exec -T"
export DATABASTION_TEST_MARIADB_DUMP_CMD="$C -e MYSQL_PWD=$MARIADB_ROOT_PASSWORD mariadb mariadb-dump -uroot --single-transaction support"
export DATABASTION_TEST_MYSQL_DUMP_CMD="$C -e MYSQL_PWD=$MYSQL_ROOT_PASSWORD mysql mysqldump -uroot --single-transaction hr"
export DATABASTION_TEST_PERCONA_DUMP_CMD="$C -e MYSQL_PWD=$PERCONA_ROOT_PASSWORD percona mysqldump -h 127.0.0.1 --protocol=TCP -uroot --single-transaction hr"
```

Audit keys of `DATABASTION_TEST_REQUIRE`: `mariadb-audit`, `percona`, `percona-audit`,
`mysqldump`. The `performance_schema` test runs on MySQL and MariaDB with a test account
(`databastion_it_pfs`) granted `SELECT` on the application database and on `performance_schema`.

The MongoDB connector tests (`agent/crates/connector-mongodb/src/it.rs`, P5-A) run against the
`mongo` service. It has no TLS: the tests connect with `tls: disable` on the loopback address (TLS
and the SCRAM-SHA-256 exchange, including hostile server answers, are covered by the scripted server
of `src/fake.rs`, which also scans the dev seed against the ground truth without a server). The
admin URL is for the probe fixtures (database `databastion_probe`, role `databastion_it_discovery`,
accounts `databastion_it_*`); the probes read the probe database's profiler (`--profile 1`, `slowms`
0 in dev) to check that every agent read carries `maxTimeMS` and that no cursor is left open:

```sh
set -a; . dev/.env; set +a
export DATABASTION_TEST_MONGO_URL="mongodb://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:${MONGO_PORT:-27017}/app?authSource=admin"
export DATABASTION_TEST_MONGO_ADMIN_URL="mongodb://root:$MONGO_ROOT_PASSWORD@127.0.0.1:${MONGO_PORT:-27017}/?authSource=admin"
(cd agent && cargo test -p databastion-connector-mongodb -- --nocapture)
```

`DATABASTION_TEST_REQUIRE` accepts `mongo` and `mongo-admin` for these tests. On volumes created
before ADR-0026, run `make dev-reset dev` first: the init script creates the account only once.

`verify_full` against a real server (phase 7) runs on a separate, throwaway TLS-only server:
`dev/mongo/tls-test-server.sh` generates a test CA and a server certificate for `localhost` at run
time (in `$RUNNER_TEMP` or a fresh `mktemp -d` directory, never committed, the CA key deleted once used), starts the same
pinned image with `--tlsMode requireTLS` on `127.0.0.1:27018` and creates the ADR-0026 account:

```sh
eval "$(dev/mongo/tls-test-server.sh start)"
(cd agent && cargo test -p databastion-connector-mongodb tls_real_server -- --nocapture)
dev/mongo/tls-test-server.sh stop
```

`DATABASTION_TEST_REQUIRE` accepts `mongo-tls` for these tests.

The Audit tests (`src/it_audit.rs`, P5-B / P5-C, [ADR-0027](../docs/adr/0027-mongodb-audit.md))
read the server log as the agent host sees it (make it readable first: `mongod` may create it
`0600`), and create a profiler account (`databastion_it_profiler`: the ADR-0026 role on `app` plus
`find` on `app.system.profile`). The `mongo` server is Community: its `auditLog` test runs against
the opt-in `psmdb` service (Percona Server for MongoDB, phase 7), started by naming it:
`docker compose -f dev/docker-compose.yml up -d psmdb` (then `DATABASTION_TEST_PSMDB_URL`,
`DATABASTION_TEST_PSMDB_ADMIN_URL` with port `PSMDB_PORT`, and `DATABASTION_TEST_PSMDB_AUDIT_LOG`
pointing at `dev/.state/logs/psmdb/auditLog.json`; prerequisite `psmdb-audit`). The optional commands run the real tools inside the container (their application
name is what the agent flags):

```sh
sudo chmod a+r dev/.state/logs/mongodb/mongod.log
export DATABASTION_TEST_MONGO_LOG="$PWD/dev/.state/logs/mongodb/mongod.log"
export DATABASTION_TEST_MONGO_DUMP_CMD="docker compose -f $PWD/dev/docker-compose.yml exec -T mongo mongodump --quiet --uri 'mongodb://root:$MONGO_ROOT_PASSWORD@127.0.0.1:27017/?authSource=admin' --db app --collection users --archive=/dev/null"
export DATABASTION_TEST_MONGO_EXPORT_CMD="docker compose -f $PWD/dev/docker-compose.yml exec -T mongo mongoexport --quiet --uri 'mongodb://root:$MONGO_ROOT_PASSWORD@127.0.0.1:27017/?authSource=admin' --db app --collection users --out /dev/null"
```

Audit keys of `DATABASTION_TEST_REQUIRE` for MongoDB: `mongo-log`, `mongodump`, `psmdb-audit`.

## Seed data and ground truth
[seed/generate.py](seed/generate.py) (Python standard library, fixed seed) writes the per-engine seed files in [seed/out/](seed/out/) and [ground-truth.json](ground-truth.json). The MySQL and MariaDB files start with `SET NAMES utf8mb4`: the MySQL image loads them with a client whose default character set follows the container locale (latin1), which double-encoded every non-ASCII value before (fixed in P2-C; run `make dev-reset dev` to reload). They are committed (about 0.4 MB) and a test fails if they drift from the generator. The containers load them only on an empty volume: after `make seed`, run `make dev-reset dev`.

All values are fake: `example.com/.org/.net` e-mails, French phone numbers in the ARCEP ranges reserved for fiction, UK 07700 900xxx, US 555-01xx, IBANs with valid mod-97 on fictitious bank codes, NIRs with a valid key, Luhn-valid card numbers from the 411111 / 555555 test ranges, AWS-shaped keys containing `EXAMPLE`.

`ground-truth.json` lists every seeded location (engine, database, container, object, field) with the expected classifiers and the seeded values, plus:
- **negative controls** (`negative_control: true`): look-alike columns (`email_opt_in`, Luhn-invalid 16-digit references, year-named columns…) that must produce no finding;
- **value-bearing names** (`name_contains_value: true`, [ADR-0009](../docs/adr/0009-name-normalization-and-item-sanitization.md), security review M2): MongoDB dynamic keys that are e-mail addresses or digit-only phone numbers, an LDAP `ou=` named after a person, SQL tables whose names embed a phone number, a person name or an e-mail address. Their `name_values` must never reach the console (invariant I2 test, P2-E).

Classifier ids in the ground truth are provisional until the classifier set is frozen (P2-A).
