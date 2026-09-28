# Capabilities by engine

DataBastion can only audit what the engine logs. This page states **honestly** what is possible for each engine and each edition. The console shows the level reached for each target: a "Limited" audit must never pass for a full audit.

## Audit levels
| Level | Meaning |
|--------|---------------|
| **Full** | Every access is logged with the user, the object, and the volume returned |
| **Partial** | Accesses are visible, but some information is missing (volume, exact object) or depends on sampling |
| **Limited** | Only slow accesses, or aggregated statistics, are visible. Export detection is likely, not guaranteed |
| **None** | Discovery only |

**Discovery** (data classification) works the same way on every engine: it only needs a read-only account.

## Matrix

| Engine / edition | Audit source | Level | Database-side prerequisites |
|------------------|----------------|--------|---------------------|
| **PostgreSQL** + pgaudit | pgaudit log (`csvlog` / `jsonlog`) + `pg_stat_statements` | Full | `pgaudit` extension (PGDG packages, free), `log_connections=on`, `application_name` in the logs |
| PostgreSQL without pgaudit | `pg_stat_statements` + polling of `pg_stat_activity` | Limited | `pg_stat_statements` enabled |
| **MariaDB** | `server_audit` plugin (bundled, free) + slow log / `performance_schema` for volumes | Full | `plugin_load_add = server_audit`, `server_audit_events=CONNECT,QUERY_DML,TABLE` |
| **Percona Server for MySQL** | `audit_log` plugin | Full | Plugin enabled, JSON format |
| **MySQL Community** | `performance_schema` (`events_statements_history_long`, `ROWS_SENT`) | Partial | `performance_schema=ON`, history consumers enabled |
| **MongoDB Enterprise** | `auditLog` (JSON) + profiler for volumes | Full | `auditLog.destination=file`, filter on reads |
| **Percona Server for MongoDB** | `auditLog` | Full | Same |
| **MongoDB Community** | Structured JSON logs (slow operations: `appName`, `nreturned`) + profiler | Limited → Partial | Profiler level 1 with low `slowms`; level 2 = Partial but costly |
| **OpenLDAP** | `slapo-accesslog` overlay (`cn=accesslog` database, queryable over LDAP) | Full | `olcAccessLogOps: reads writes session`, read account on `cn=accesslog` |

> **PostgreSQL, as implemented (P2-B, [ADR-0015](adr/0015-postgresql-connector-decisions.md))**: the connector's `check()` reports **Limited** when `pg_stat_statements` is installed and loaded in a monitored database and the agent's role sees other users' statements (member of `pg_read_all_stats`), and **None** otherwise. It never reports **Full** yet: Full needs a readable pgaudit log, and the log path is only configured with the Audit connector (P4-A); a loaded pgaudit is only mentioned in the agent's logs. The level describes the prerequisites found on the target. The PostgreSQL Audit connector itself (reading `pg_stat_statements` or pgaudit, producing access events) is P4-A and not implemented: no PostgreSQL access event is collected yet.

> **MongoDB Community**: this edition has no audit log. DataBastion sees *slow* operations (or all of them, at the cost of a level 2 profiler). A fast `mongodump` of a small collection can go unnoticed. **This must be stated clearly in the user documentation and in the console.**

> **MySQL Community**: the official audit plugin is reserved for MySQL Enterprise. `performance_schema` provides recent queries and the number of rows returned, but its history is a ring buffer: the agent must read it often enough not to lose anything.

## Known export signatures
| Tool | Observable signature | Engine |
|-------|---------------------|--------|
| `pg_dump` / `pg_dumpall` | `application_name = 'pg_dump'`, `COPY … TO STDOUT` on every table, `REPEATABLE READ` transaction | PostgreSQL |
| `COPY … TO` / `\copy` | Outbound `COPY` statement | PostgreSQL |
| `mysqldump` | `SELECT /*!40001 SQL_NO_CACHE */ * FROM`, `SHOW CREATE TABLE` in sequence, `FLUSH TABLES WITH READ LOCK` | MySQL / MariaDB |
| `SELECT … INTO OUTFILE` | Explicit statement | MySQL / MariaDB |
| `mongodump` / `mongoexport` | Tool's `appName`, unfiltered `find` over the whole collection | MongoDB |
| LDIF export / bulk `ldapsearch` | `scope=sub` search from the root, `(objectClass=*)` filter, high `reqEntries` | OpenLDAP |

Signatures are easy to forge (`application_name` is chosen by the client). They are only **one** of the three signals; the volume × sensitivity combination remains the primary signal (see [02-architecture.md](02-architecture.md#exfiltration-detection-audit)).

## Cost for the monitored database
| Source | Cost | Recommendation |
|--------|------|----------------|
| pgaudit (`read` class) | Medium: log volume | Restrict to sensitive roles and objects (`pgaudit.role`) |
| MariaDB `server_audit` | Low to medium | Filter out service accounts |
| `performance_schema` | Low | OK |
| MongoDB profiler level 2 | **High** | Avoid in production; level 1 with a suitable `slowms` |
| OpenLDAP `accesslog` | Low | Purge with `olcAccessLogPurge` |
