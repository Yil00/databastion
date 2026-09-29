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
| **PostgreSQL** + pgaudit | pgaudit log (`csvlog` / `jsonlog`), read locally by the agent; row counts from `pgaudit.log_rows` | Full / Partial | `pgaudit` loaded with the `read` class (or object audit through `pgaudit.role`), log file readable by the agent and declared in `agent.yaml`; Full also needs a volume source (see below) |
| PostgreSQL without a readable pgaudit log | `pg_stat_statements` (polled counters) | Limited | `pg_stat_statements` installed and loaded; agent role member of `pg_read_all_stats` |
| **MariaDB** | `server_audit` plugin (bundled, free) + slow log / `performance_schema` for volumes | Full | `plugin_load_add = server_audit`, `server_audit_events=CONNECT,QUERY_DML,TABLE` |
| **Percona Server for MySQL** | `audit_log` plugin | Full | Plugin enabled, JSON format |
| **MySQL Community** | `performance_schema` (`events_statements_history_long`, `ROWS_SENT`) | Partial | `performance_schema=ON`, history consumers enabled |
| **MongoDB Enterprise** | `auditLog` (JSON) + profiler for volumes | Full | `auditLog.destination=file`, filter on reads |
| **Percona Server for MongoDB** | `auditLog` | Full | Same |
| **MongoDB Community** | Structured JSON logs (slow operations: `appName`, `nreturned`) + profiler | Limited → Partial | Profiler level 1 with low `slowms`; level 2 = Partial but costly |
| **OpenLDAP** | `slapo-accesslog` overlay (`cn=accesslog` database, queryable over LDAP) | Full | `olcAccessLogOps: reads writes session`, read account on `cn=accesslog` |

> **PostgreSQL, as implemented (P2-B, P4-A #58; [ADR-0015](adr/0015-postgresql-connector-decisions.md))**: see [PostgreSQL Audit](#postgresql-audit) below.

> **MySQL / MariaDB, as implemented (P2-C, #52, [ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md))**: `check()` reports **Partial** when `performance_schema` is on and the `events_statements_history_long` consumer is enabled and readable, **Limited** when only the per-thread statement consumers are, and **None** otherwise. **Full** is not reported before the Audit connectors (P4-B): it needs the agent to read the `server_audit` / `audit_log` file; an active audit plugin is only noted. No MySQL / MariaDB access event is collected yet.

> **`FEDERATED` and other remote engines**: on MySQL 8.4, computing `information_schema.TABLES.TABLE_ROWS` for a `FEDERATED` table opens its handler, which connects to the remote server. The connector therefore reads no statistics column during introspection, asks for a table's `TABLE_ROWS` only after reading its engine alone and finding a local one ([ADR-0020](adr/0020-mysql-mariadb-connector-as-merged.md)), and never samples tables of remote-access engines (I5).

> **MongoDB Community**: this edition has no audit log. DataBastion sees *slow* operations (or all of them, at the cost of a level 2 profiler). A fast `mongodump` of a small collection can go unnoticed. **This must be stated clearly in the user documentation and in the console.**

> **MySQL Community**: the official audit plugin is reserved for MySQL Enterprise. `performance_schema` provides recent queries and the number of rows returned, but its history is a ring buffer: the agent must read it often enough not to lose anything.

## PostgreSQL Audit

What the PostgreSQL connector does, as merged in P4-A (#58). The reference is [the connector README](../agent/crates/connector-postgres/README.md).

### Sources and level

The connector reads one source at a time, chosen with the same probe and rule as `check()`, and re-evaluates the choice every 5 minutes.

| Level | Condition | Source |
|-------|-----------|--------|
| **Full** | The log declared in `agent.yaml` is readable by the agent, pgaudit is loaded with the `read` class, a volume source exists (`pgaudit.log_rows = on`, or `pg_stat_statements`), **and** the stream has parsed a pgaudit record in the last 24 h | pgaudit log |
| **Partial** | Log readable and pgaudit logging reads (or object audit through `pgaudit.role`), but no volume source or no record parsed in the last 24 h | pgaudit log |
| **Limited** | No usable pgaudit log; `pg_stat_statements` installed, loaded and showing other roles' statements | `pg_stat_statements` |
| **None** | None of the above | none |

- **pgaudit log.** Declared per target as `targets[].postgres.audit_log` in `agent.yaml`, with `path` (absolute path of the current log file, fixed `log_filename`) and `format` (`jsonlog`, PostgreSQL 15+, or `csvlog`). The agent reads the file locally and incrementally, never through SQL, with a cursor persisted by the core; rotation by rename or truncation is followed. Only `AUDIT:` records are parsed. `volume.large_result` on this source needs `pgaudit.log_rows = on`.
- **`pg_stat_statements` (degraded mode).** The counters are polled and the deltas between two polls become events; the first poll is a baseline only. This source attributes the role, the database, the number of calls and the rows returned or affected in the poll interval, and the relations named by the normalized text. It sees no client address, no application name, no per-execution time or row count, no statement evicted between polls (`pg_stat_statements.max`), and no utility statement when `pg_stat_statements.track_utility` is off. Unqualified names carry no schema. The level stays Limited.

Statement text never leaves the agent: it is analyzed locally to name objects the log does not name and to compute the signals. An access whose objects cannot be told (a function body without `pgaudit.log_relation`, text that does not parse) is reported against the object `*`, never dropped. `*` is a literal name, not a wildcard: console policy globs match it only as the string `*` ([09-agent-protocol.md](09-agent-protocol.md#the-object-)), so policies scoped to named objects do not see these accesses. Statements that name only catalogs (`pg_catalog`, `information_schema`, `pg_toast`, unqualified `pg_*`, `pg_stat_statements*`) are skipped.

### Signals

The signal ids are registered in [`shared/protocol/signals.json`](../shared/protocol/signals.json) (append-only, #60).

| Signal | When it is set |
|--------|----------------|
| `signature.pg_dump` | `application_name` is `pg_dump` or `pg_dumpall` (pgaudit only; spoofable), or one session (with `pg_stat_statements`: one role within one poll) copied at least 3 distinct whole relations to the client (`COPY … TO STDOUT`) |
| `signature.copy_to_file` | `COPY … TO '<file>'`; also a pgaudit `COPY` record whose text does not show the `COPY` (dynamic `EXECUTE`, `format()`, nested `DO`), since PL/pgSQL cannot copy to the client |
| `signature.copy_to_program` | `COPY … TO PROGRAM` |
| `shape.full_table_copy` | `COPY` out of a whole relation, or of a query without filter, aggregation or small limit |
| `shape.full_table_read` | A read (`SELECT`, `TABLE`) of a non-catalog relation without a top-level `WHERE`, `GROUP BY` or aggregate-only list, or derived table, and with no limit or a limit above 10 000 rows |
| `volume.large_result` | More than 10 000 rows returned or affected, by one statement (pgaudit with `pgaudit.log_rows`) or in one `pg_stat_statements` counter delta |

Both 10 000 thresholds sit just above the largest Discovery sample (`limits.max_sample_rows` is at most 10 000), so the agent's own Discovery statements never carry these signals. The `shape.*` and `signature.*` signals are heuristics, evadable by design (`WHERE true`, `LIMIT 10000` pages, a spoofed `application_name`); the volume × sensitivity score computed by the console is the robust signal.

`DO` blocks: the body is analyzed (one level deep) only when it is PL/pgSQL, meaning no `LANGUAGE` clause or `LANGUAGE plpgsql`. A body in any other language (`plv8`, `plperl`, `plpython3u`…), a `LANGUAGE` clause that cannot be read, or a body whose reading depends on `standard_conforming_strings` is not lexed as SQL at all (fail closed): no object name is taken from it, and the event carries only what pgaudit names, or `*`.

### The agent's own account

The agent's own Discovery reads would otherwise show up as access events. An event of the agent's account is left out only when **all** of these hold:

- it comes from the agent's `application_name` (`databastion-agent`; checked with pgaudit only);
- it comes from the agent's own client address as the server sees it (`inet_client_addr()`, probed at stream start; checked with pgaudit only). When the agent's address cannot be read, or a record carries no address, nothing is left out;
- it carries no signal: events with a signal are always kept;
- the agent's reads of each object stay within `limits.max_sample_rows` rows over a rolling 24 h. A statement with an unknown row count (no `pgaudit.log_rows`) is charged the whole budget. A second Discovery scan of the same table within 24 h therefore shows up as events of the agent's account.

With `pg_stat_statements`, application and address are not visible: only the signal and row-budget rules apply.

Limits of these rules:
- Behind a connection pooler (PgBouncer…) every client has the pooler's address, and another process on the agent host shares the agent's address: there the address check only separates remote clients.
- Someone holding the agent's credentials on the agent host (or behind the same pooler), spoofing its `application_name` and reading at most the budget per object and day with filtered queries stays unreported.
- The row counters are kept per target for the life of the agent process. Restarting a stream (a failure, a source switch, the agent's sessions terminated on purpose) does not reset them; an **agent restart** does, since they are not persisted, and gives a fresh budget per object.

The agent's database credentials never leave its host (I3).

### Known limits

- **At-most-once delivery.** The log cursor advances once events are handed to the core, which aggregates them for up to `aggregation_window_s` before spooling. An agent crash within that window loses those events; they remain in the database's own log.
- **First start, rotation while stopped.** Without a cursor, reading starts at the end of the log (no history). If the log was rotated while the agent was stopped, the rest of the previous file is not read.
- **Forged records.** Any role can write `AUDIT: …` lines into the server log (`RAISE LOG` in PL/pgSQL). The connector drops records whose severity is not `pgaudit.log_level` or that carry an error context (pgaudit hides its context; `RAISE` always has one). Roles that can hide the context or run native code (C extensions, untrusted languages) can still forge records. A server-wide `log_error_verbosity = terse` removes every context, and with it this protection: keep it at `default`. A forged record can add false events; it cannot remove real ones. Records dropped because of their severity (likely genuine, when the setting differs per database or role) are counted, logged, and noted in `check()` for 24 h (in the agent logs: the agent does not send `TargetStatus.notes` yet, ROADMAP P4-D).
- **Heuristic signals.** `shape.*` and `signature.*` are evadable by design; see [the classifiers README](../agent/crates/classifiers/README.md).

## Known export signatures
| Tool | Observable signature | Engine |
|-------|---------------------|--------|
| `pg_dump` / `pg_dumpall` | `application_name = 'pg_dump'`, `COPY … TO STDOUT` on every table, `REPEATABLE READ` transaction | PostgreSQL |
| `COPY … TO` / `\copy` | Outbound `COPY` statement | PostgreSQL |
| `mysqldump` | `SELECT /*!40001 SQL_NO_CACHE */ * FROM`, `SHOW CREATE TABLE` in sequence, `FLUSH TABLES WITH READ LOCK` | MySQL / MariaDB |
| `SELECT … INTO OUTFILE` | Explicit statement | MySQL / MariaDB |
| `mongodump` / `mongoexport` | Tool's `appName`, unfiltered `find` over the whole collection | MongoDB |
| LDIF export / bulk `ldapsearch` | `scope=sub` search from the root, `(objectClass=*)` filter, high `reqEntries` | OpenLDAP |

As implemented: on PostgreSQL (P4-A) the agent uses the `application_name` and the whole-relation `COPY … TO STDOUT` parts of the `pg_dump` signature (not the `REPEATABLE READ` transaction) and the outbound `COPY` signatures; see [PostgreSQL Audit](#postgresql-audit). The MySQL / MariaDB (P4-B), MongoDB (phase 5) and OpenLDAP (phase 6) signatures are not implemented yet.

Signatures are easy to forge (`application_name` is chosen by the client). They are only **one** of the three signals; the volume × sensitivity combination remains the primary signal (see [02-architecture.md](02-architecture.md#exfiltration-detection-audit)). The console computes it from the row count the source reports ([ADR-0021](adr/0021-access-event-correlation.md)): an event without `rows` scores 0 and feeds no baseline (the contract has an optional `AccessEvent.bytes` since #60, but no connector produces it and the console does not use it), so on a source that gives no volume only signatures, shapes and object or principal conditions can raise an incident. Sensitivity is per object (table, collection), not per column.

## Cost for the monitored database
| Source | Cost | Recommendation |
|--------|------|----------------|
| pgaudit (`read` class) | Medium: log volume | Restrict to sensitive roles and objects (`pgaudit.role`) |
| MariaDB `server_audit` | Low to medium | Filter out service accounts |
| `performance_schema` | Low | OK |
| MongoDB profiler level 2 | **High** | Avoid in production; level 1 with a suitable `slowms` |
| OpenLDAP `accesslog` | Low | Purge with `olcAccessLogPurge` |
