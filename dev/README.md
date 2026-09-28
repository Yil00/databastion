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
```
`make help` lists every target. The CI workflow `.github/workflows/dev-env.yml` runs the same steps.

## Services
All ports are published on **127.0.0.1 only**; host ports can be changed in `dev/.env`.

| Service | Host port | Seeded database | Audit source | Audit level ([docs/08](../docs/08-engine-capabilities.md)) |
|---------|-----------|-----------------|--------------|-------|
| PostgreSQL 17.11 + pgaudit (`postgres`) | 5432 | `shop` (schemas `crm`, `billing`, `ops`) | pgaudit in `jsonlog`, `pg_stat_statements`, `log_connections` | Full |
| MariaDB 11.4 LTS (`mariadb`) | 3307 | `support` | `server_audit` plugin (`CONNECT,QUERY_DML,TABLE`), `performance_schema` | Full |
| MySQL 8.4 LTS Community (`mysql`) | 3306 | `hr` | `performance_schema` history consumers (`events_statements_history_long`) | Partial |
| MongoDB 8.0 Community (`mongo`) | 27017 | `app` | profiler level 1 (`slowms` from `MONGO_SLOWMS`, default 0) + JSON log | Limited → Partial |
| OpenLDAP (Debian slapd) (`openldap`) | 1389 | `dc=example,dc=org` | `slapo-accesslog` in `cn=accesslog` (`reads writes session`) | Full |
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
| PostgreSQL | `databastion` | `pg_read_all_data`, `pg_monitor`, `default_transaction_read_only=on` |
| MariaDB / MySQL | `databastion@'%'` | `SELECT, PROCESS, SHOW VIEW ON *.*`, `SELECT ON performance_schema.*` |
| MongoDB | `databastion` (auth db `admin`) | `read` on `app`, `clusterMonitor` |
| OpenLDAP | `cn=databastion,ou=services,dc=example,dc=org` | read on the tree (except `userPassword`) and on `cn=accesslog` |

MySQL / MariaDB: `SELECT ON *.*` also covers the system schemas; Discovery excludes `mysql`, `information_schema`, `performance_schema` and `sys` from sampling. The `'%'` host is only because the agent connects through the published port in dev.

Administrator accounts (`postgres`, `root`, `cn=admin,dc=example,dc=org`) exist for seeding and manual inspection only.

## Connecting
```sh
set -a; . dev/.env; set +a
PGPASSWORD=$DATABASTION_DB_PASSWORD psql -h 127.0.0.1 -U databastion shop
MYSQL_PWD=$DATABASTION_DB_PASSWORD mariadb -h 127.0.0.1 -P 3307 -u databastion support
MYSQL_PWD=$DATABASTION_DB_PASSWORD mysql -h 127.0.0.1 -P 3306 -u databastion hr
mongosh "mongodb://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:27017/app?authSource=admin"
ldapsearch -x -H ldap://127.0.0.1:1389 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -b dc=example,dc=org
ldapsearch -x -H ldap://127.0.0.1:1389 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -b cn=accesslog
```
Without local clients, use `docker compose -f dev/docker-compose.yml exec <service> …`.

## Engine configuration
- **PostgreSQL**: image built from `postgres:17.11-bookworm` + `postgresql-17-pgaudit` (PGDG). `shared_preload_libraries=pgaudit,pg_stat_statements`. Following the docs/08 advice to restrict pgaudit, `pgaudit.log` is `none` server-wide and `read, write` on the `shop` database only; object audit covers the seeded tables through the `databastion_auditor` role (`pgaudit.role`). A `SELECT` on an audited table therefore logs both a `SESSION` and an `OBJECT` line. `pgaudit.log_parameter=off`. Logs: `dev/.state/logs/postgres/postgresql.json`.
- **MariaDB**: [mariadb/databastion.cnf](mariadb/databastion.cnf). The image's `healthcheck` user is excluded from the audit trail. Log: `dev/.state/logs/mariadb/server_audit.log`.
- **MySQL**: [mysql/databastion.cnf](mysql/databastion.cnf). No file log: the agent reads `performance_schema`, a ring buffer (10 000 statements).
- **MongoDB**: `--profile 1 --slowms $MONGO_SLOWMS`. `0` makes every operation visible in dev; use a higher value to reproduce the production trade-off (a fast `mongodump` can go unnoticed). Log: `dev/.state/logs/mongodb/mongod.log`.
- **OpenLDAP**: image built from Debian's `slapd` package ([openldap/Dockerfile](openldap/Dockerfile)): osixia/openldap is unmaintained and the Bitnami catalog no longer publishes free versioned tags. Configuration in [openldap/config.ldif](openldap/config.ldif) (`olcAccessLogOps: reads writes session`, purge after 7 days). Healthchecks use `ldapi://` on `cn=config`, so they do not add entries to `cn=accesslog`.

`make dev` creates `dev/.state/logs/{postgres,mariadb,mongodb}` world-writable (the engines run as non-root users with other UIDs). Run `make dev-dirs dev-metrics-token` first if you call `docker compose` directly.

## Seed data and ground truth
[seed/generate.py](seed/generate.py) (Python standard library, fixed seed) writes the per-engine seed files in [seed/out/](seed/out/) and [ground-truth.json](ground-truth.json). They are committed (about 0.4 MB) and a test fails if they drift from the generator. The containers load them only on an empty volume: after `make seed`, run `make dev-reset dev`.

All values are fake: `example.com/.org/.net` e-mails, French phone numbers in the ARCEP ranges reserved for fiction, UK 07700 900xxx, US 555-01xx, IBANs with valid mod-97 on fictitious bank codes, NIRs with a valid key, Luhn-valid card numbers from the 411111 / 555555 test ranges, AWS-shaped keys containing `EXAMPLE`.

`ground-truth.json` lists every seeded location (engine, database, container, object, field) with the expected classifiers and the seeded values, plus:
- **negative controls** (`negative_control: true`): look-alike columns (`email_opt_in`, Luhn-invalid 16-digit references, year-named columns…) that must produce no finding;
- **value-bearing names** (`name_contains_value: true`, [ADR-0009](../docs/adr/0009-name-normalization-and-item-sanitization.md), security review M2): MongoDB dynamic keys that are e-mail addresses or digit-only phone numbers, an LDAP `ou=` named after a person, SQL tables whose names embed a phone number, a person name or an e-mail address. Their `name_values` must never reach the console (invariant I2 test, P2-E).

Classifier ids in the ground truth are provisional until the classifier set is frozen (P2-A).
