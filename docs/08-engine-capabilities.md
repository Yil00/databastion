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
| **MariaDB** | `server_audit` log file, read locally by the agent; otherwise `performance_schema` | Partial (Limited without a record parsed in the last 24 h); never Full | `server_audit` loaded, logging to a file with `QUERY` (or `QUERY_DML`) and `TABLE` events, log file readable by the agent and declared in `agent.yaml`; or `performance_schema` as for MySQL Community (see below) |
| **Percona Server for MySQL** | `audit_log` plugin or `audit_log_filter` component, JSON file read locally by the agent; otherwise `performance_schema` | Partial (Limited without a record parsed in the last 24 h); never Full | JSON format, a policy or filter logging queries, log file readable by the agent and declared in `agent.yaml` |
| **MySQL Community** | `performance_schema` (`events_statements_history_long`, `ROWS_SENT`) | Partial / Limited; never Full | `performance_schema=ON`, statement consumers enabled with the consumers they depend on, `SELECT ON performance_schema.*` for the agent |
| **MongoDB Enterprise**, **Percona Server for MongoDB** | `auditLog` JSON file (`mongo` schema), read locally by the agent; no document counts | Partial once a successful `authCheck` record was parsed in the last 24 h, Limited once any record was parsed in the last 24 h, None before; never Full | `auditLog.destination: file`, `format: JSON`, `auditAuthorizationSuccess: true` (otherwise reads and writes are not logged), file readable by the agent and declared in `agent.yaml` |
| **MongoDB** (any edition) | Structured JSON server log (slow operations: `appName`, `nreturned`), read locally by the agent | Limited once a record was parsed in the last 24 h, None before | `systemLog.destination: file`, a `slowms` low enough for the operations to audit, file readable by the agent and declared in `agent.yaml` |
| **MongoDB** (any edition, not a `mongos`), no readable file | Profiler (`system.profile`), polled over the agent's connection | Limited once an entry was read in the last 24 h, None before | Profiling on (level 1 with a suitable `slowms`, set by the operator); `find` on `system.profile` of each database to audit (see [05-security.md](05-security.md#recommended-database-accounts-read-only)) |
| **OpenLDAP** | `slapo-accesslog` overlay (`cn=accesslog` database), read over LDAP by the agent | Full once reads **and** failed operations are proven logged for every naming context; Partial / Limited otherwise | `olcAccessLogOps: reads writes session`, `olcAccessLogSuccess: FALSE`, an `entryCSN` index on the log database, `read` on `cn=accesslog` for the agent's service DN |

> **PostgreSQL, as implemented (P2-B, P4-A #58; [ADR-0015](adr/0015-postgresql-connector-decisions.md))**: see [PostgreSQL Audit](#postgresql-audit) below.

> **MySQL / MariaDB, as implemented (P2-C #52, P4-B #64; [ADR-0023](adr/0023-mysql-mariadb-audit-sources-and-levels.md))**: see [MySQL / MariaDB Audit](#mysql--mariadb-audit) below. **Full is never reported** for these engines: no source gives both every statement and its row count.

> **`FEDERATED` and other remote engines**: on MySQL 8.4, computing `information_schema.TABLES.TABLE_ROWS` for a `FEDERATED` table opens its handler, which connects to the remote server. The connector therefore reads no statistics column during introspection, asks for a table's `TABLE_ROWS` only after reading its engine alone and finding a local one ([ADR-0020](adr/0020-mysql-mariadb-connector-as-merged.md)), and never samples tables of remote-access engines (I5).

> **MongoDB Community**: this edition has no audit log. DataBastion sees *slow* operations only: those the server logs or profiles (slower than `slowms`, sampled by `slowOpSampleRate`; the profiler is also a ring buffer). A fast `mongodump` of a small collection can go unnoticed. The console shows the level Limited and the note `audit.slow_operations_only`.

> **MongoDB, as implemented (P5-A #74; P5-B / P5-C #76, [ADR-0027](adr/0027-mongodb-audit.md))**: see [MongoDB Audit](#mongodb-audit) below. **Full is never reported** for MongoDB: the `auditLog` has no document counts, and the server log and the profiler only hold the operations the server records.

> **OpenLDAP, as implemented (#79, [ADR-0029](adr/0029-openldap-connector.md))**: see [OpenLDAP Discovery](#openldap-discovery) and [OpenLDAP Audit](#openldap-audit) below. Full is reported only when `check()` has proof, for every naming context, that searches and failed operations are logged; the log records no client address.

> **MySQL Community**: the official audit plugin is reserved for MySQL Enterprise. `performance_schema` provides recent queries and the number of rows returned, but its history is a ring buffer: the agent must read it often enough not to lose anything.

## Audit log files and failing streams (every engine)

- **Log files the agent could write are refused.** Every file source (PostgreSQL pgaudit log, MariaDB `server_audit`, the MySQL / Percona JSON logs, the MongoDB `auditLog` and server log) must be written and owned by the database server. The agent refuses, on the opened handle and after following symlinks, a file owned by its own effective uid, world-writable, or group-writable by one of its groups: `check()` reports `audit.log_not_readable` (#83, [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md) decision 8). An agent running as root while the log belongs to root, or as the database server's user, cannot use the file: run it as its own user with group or ACL read access ([05-security.md](05-security.md#recommended-database-accounts-read-only)).
- **Records that crash a parser.** Each audit record is parsed, and on the file sources converted, in isolation: a record whose handling panics is dropped alone (on PostgreSQL, conversion is isolated per statement, so the whole statement's group of records is dropped), counted in `audit.records_dropped` and in the heartbeat metric `audit_record_panics_total`. The events of such a record are lost; the console raises no alert on these counters.
- **Streams that keep failing.** A panic that still ends a stream restarts it after a backoff (at least the poll interval). The OpenLDAP stream then locates the entry at fault and skips it after 3 panics at that exact position (`audit_records_skipped_total`); the file sources do not skip. A stream is stopped, with level None and the note `audit.stream_stopped`, after 7 panics at one position with no progress, more than 8 skips or 64 panics within an hour, or 3 panics in a row on a source whose position is in memory (`pg_stat_statements`, `performance_schema`, the MongoDB profiler). The console then raises an `agent.audit_stream_stopped` alert every hour while it stays stopped ([05-security.md](05-security.md#alerting)). Reconfiguring Audit or restarting the agent starts it again from its persisted cursor.
- **Event times.** The console stores access event times with whole-second precision.

## PostgreSQL Audit

What the PostgreSQL connector does, as merged in P4-A (#58) and fixed in #65. The reference is [the connector README](../agent/crates/connector-postgres/README.md).

### Sources and level

The connector reads one source at a time, chosen with the same probe and rule as `check()`, and re-evaluates the choice every 5 minutes.

| Level | Condition | Source |
|-------|-----------|--------|
| **Full** | The log declared in `agent.yaml` is readable by the agent, pgaudit is loaded with the `read` class, a volume source exists (`pgaudit.log_rows = on`, or `pg_stat_statements`), **and** the stream has parsed a pgaudit record in the last 24 h | pgaudit log |
| **Partial** | Log readable and pgaudit logging reads (or object audit through `pgaudit.role`), but no volume source or no record parsed in the last 24 h | pgaudit log |
| **Limited** | No usable pgaudit log; `pg_stat_statements` installed, loaded and showing other roles' statements | `pg_stat_statements` |
| **None** | None of the above | none |

- **pgaudit loaded is proven, not assumed.** A `pgaudit.*` value set in `postgresql.conf`, `ALTER DATABASE` or `ALTER ROLE` without the library loaded is a placeholder that `current_setting()` still returns. The probe therefore requires the library's own `pgaudit.log_catalog` setting, typed `bool`, in `pg_settings` (which hides placeholders); `shared_preload_libraries` itself is not readable without `pg_read_all_settings`. Settings without the library give no pgaudit level (at best Limited), with the note "pgaudit settings are set but the pgaudit library is not loaded". Like every setting the probe reads, the proof reflects the agent's own session in each monitored database: a library loaded or `pgaudit.*` values set for some roles or databases only may differ for other roles.
- **pgaudit log.** Declared per target as `targets[].postgres.audit_log` in `agent.yaml`, with `path` (absolute path of the current log file, fixed `log_filename`) and `format` (`jsonlog`, PostgreSQL 15+, or `csvlog`). The agent reads the file locally and incrementally, never through SQL, with a cursor persisted by the core; rotation by rename or truncation is followed. Only `AUDIT:` records are parsed. `volume.large_result` on this source needs `pgaudit.log_rows = on`.
- **`pg_stat_statements` (degraded mode).** The counters are polled and the deltas between two polls become events; the first poll is a baseline only. This source attributes the role, the database, the number of calls and the rows returned or affected in the poll interval, and the relations named by the normalized text. It sees no client address, no application name, no per-execution time or row count, no statement evicted between polls (`pg_stat_statements.max`), and no utility statement when `pg_stat_statements.track_utility` is off. Unqualified names carry no schema. The level stays Limited.

Statement text never leaves the agent: it is analyzed locally to name objects the log does not name and to compute the signals. An access whose objects cannot be told (a function body without `pgaudit.log_relation`, text that does not parse) is reported against the object `*`, never dropped. `*` is a literal name, not a wildcard: console policy globs match it only as the string `*` ([09-agent-protocol.md](09-agent-protocol.md#the-object-)), so policies scoped to named objects do not see these accesses. Statements that name only catalogs are skipped. What counts as a catalog:

- relations in `pg_catalog`, `information_schema`, `pg_toast` and the temporary schemas, whether the text or pgaudit (`pgaudit.log_catalog`, `log_relation`) names them;
- `pg_stat_statements` and `pg_stat_statements_info` **only in the extension's schema** of that database, as probed from the agent's session. A `pg_stat_statements_x`, or a `pg_stat_statements` in another schema, is application data (any role with `CREATE` can make one). A database the target does not list has no known extension schema;
- an **unqualified** `pg_*` name, whose schema the text does not tell: with pgaudit and `pgaudit.log_catalog = off` (as the agent's session sees it), it is a catalog only when pgaudit names it in `pg_catalog` for the same statement, otherwise it is reported as a relation without schema; with `log_catalog` on (the pgaudit default) or unknown, and with `pg_stat_statements`, it counts as a catalog. An unqualified `pg_stat_statements` / `pg_stat_statements_info` counts as a catalog when the extension is installed in the database.

With `pgaudit.log_statement_once = on`, only the first record of a statement and substatement carries the text; later ones carry `<previously logged>`. The connector analyzes those with the first record's text of the same substatement when it read it. When it did not (the first record fell before the cursor, or in another read), the record's objects are unknown (`*`, fail safe), and the text-derived signals come only from the records whose text is known.

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

- it is a read or a connection: **writes, DDL and DCL of the agent's account are always reported** (the agent never writes, I4, so such an event with its identity is someone else using it; #76, commit `35c6459`, [ADR-0027](adr/0027-mongodb-audit.md) decision 7);
- it comes from the agent's `application_name` (`databastion-agent`; checked with pgaudit only);
- it comes from the agent's own client address as the server sees it (`inet_client_addr()`, probed at stream start; checked with pgaudit only). When the agent's address cannot be read, or a record carries no address, nothing is left out;
- it carries no signal: events with a signal are always kept;
- the agent's reads of each object stay within `limits.max_sample_rows` rows over a rolling 24 h. A statement with an unknown row count (no `pgaudit.log_rows`) is charged the whole budget. A second Discovery scan of the same table within 24 h therefore shows up as events of the agent's account.

With `pg_stat_statements`, application and address are not visible: only the action, signal and row-budget rules apply.

**The connector's own table-less statements** (#65). The connector sends a few statements that read no relation: the per-connection and per-transaction `pg_catalog.set_config(…)` / `current_setting(…)` (one per transaction, about 90 per Discovery scan), `pg_catalog.host(pg_catalog.inet_client_addr())`, and, in `pg_stat_statements` mode, its text query through the extension's `pg_stat_statements(true)` function. They form a closed allow-list (a unit test fails on any other connector statement that names no relation). Such a statement of the agent's account that passes the identity and signal rules above is never reported and is not charged to any row budget. It is recognized by its exact text with pgaudit and by its normalized shape with `pg_stat_statements`. Anything else of the agent's account whose objects are unknown (`*`: any other function call, including `pg_catalog` functions that run SQL such as `query_to_xml`, text that does not parse, several statements) is **always reported and never budgeted**, so no traffic can use up a `*` budget. The same statements from any other role, or from the agent's account under another application or address, are reported against `*`.

Limits of these rules:
- Behind a connection pooler (PgBouncer…) every client has the pooler's address, and another process on the agent host shares the agent's address: there the address check only separates remote clients.
- Someone holding the agent's credentials on the agent host (or behind the same pooler), spoofing its `application_name` and reading at most the budget per object and day with filtered queries stays unreported. Writes, DDL and DCL with the agent's identity are always reported.
- Someone holding the agent's credentials who passes the identity checks can run the allow-listed table-less statements unreported. They read no row of any relation (`set_config` changes their own session only, `current_setting` reads settings the role may read, and the text query returns statement texts, as a read of the view `pg_stat_statements` does). With `pg_stat_statements`, where only the shape is visible, the settings read by `current_setting(…)` are not checked. The text query is recognized in pgaudit records written during a `pg_stat_statements` period only if the agent did not restart in between.
- The row counters are kept per target for the life of the agent process. Restarting a stream (a failure, a source switch, the agent's sessions terminated on purpose) does not reset them; an **agent restart** does, since they are not persisted, and gives a fresh budget per object.

The agent's database credentials never leave its host (I3).

### Known limits

- **At-most-once delivery.** The log cursor advances once events are handed to the core, which aggregates them for up to `aggregation_window_s` before spooling. An agent crash within that window loses those events; they remain in the database's own log.
- **First start, rotation while stopped.** Without a cursor, reading starts at the end of the log (no history). If the log was rotated while the agent was stopped, the rest of the previous file is not read.
- **Forged records.** Any role can write `AUDIT: …` lines into the server log (`RAISE LOG` in PL/pgSQL). The connector drops records whose severity is not `pgaudit.log_level` or that carry an error context (pgaudit hides its context; `RAISE` always has one). Roles that can hide the context or run native code (C extensions, untrusted languages) can still forge records. A server-wide `log_error_verbosity = terse` removes every context, and with it this protection: keep it at `default`. A forged record can add false events; it cannot remove real ones. Records dropped because of their severity (likely genuine, when the setting differs per database or role) are counted, logged, and noted in `check()` for 24 h, reported to the console as the target note `audit.records_dropped_severity` (#68, sent while the console lists `target_status.notes`).
- **Shadowing an unqualified catalog name.** When an unqualified `pg_*` name counts as a catalog (above), a role that can create a relation named `pg_*` in a schema of its search path (`CREATE TABLE public.pg_loot AS SELECT …`) and later reads it by its unqualified name is not reported for that later read; the copy itself reads the source relation and is reported. With pgaudit, `pgaudit.log_relation = on` (every relation named with its schema) or `pgaudit.log_catalog = off` closes this. The same residual applies to a relation shadowing `pg_stat_statements` earlier in the search path.
- **Per-role pgaudit settings.** The level says what holds for the agent's session (see "pgaudit loaded" above), not that every role is audited alike.
- **Passwords in DCL text.** pgaudit writes `<REDACTED>` in place of the text after the `password` token of `CREATE ROLE` / `ALTER ROLE` (checked by the end-to-end test, #82). `pg_stat_statements` keeps the text of such statements, passwords in clear, and the agent's account (`pg_read_all_stats`) can read it: on that source, the agent's own redaction of DCL text is the only thing that keeps the password out of what the agent derives from the text (statement text itself never leaves the agent, but it is read into its memory). The end-to-end test has no positive control of that redaction yet (ROADMAP follow-up). Set role passwords with psql's `\password` ([05-security.md](05-security.md#recommended-database-accounts-read-only)).
- **Heuristic signals.** `shape.*` and `signature.*` are evadable by design; see [the classifiers README](../agent/crates/classifiers/README.md).

## MySQL / MariaDB Audit

What the MySQL / MariaDB connector does, as merged in P4-B (#64). Decisions in [ADR-0023](adr/0023-mysql-mariadb-audit-sources-and-levels.md); the reference is [the connector README](../agent/crates/connector-mysql/README.md).

### Sources and level

`check()` and the Audit stream choose the source with the same probe and rule, re-evaluated every 5 minutes. In order of preference:

| Level | Condition | Source (`audit_source`) |
|-------|-----------|--------|
| **Partial** | The audit log declared in `agent.yaml` is readable by the agent, its plugin is active and logs statements in a supported format, **and** the stream has parsed a record of it in the last 24 h (**Limited** until then) | `mariadb_server_audit` or `mysql_audit_log` |
| **Partial** | `performance_schema` on, `events_statements_history_long` enabled together with the consumers it depends on (`events_statements_current`, `global_instrumentation`, `thread_instrumentation`), and readable by the account | `performance_schema` |
| **Limited** | With the same dependent consumers enabled, only `events_statements_history` or `events_statements_current` enabled and readable | `performance_schema` |
| **None** | The dependent consumers off, nothing readable, or `performance_schema` off | none |

**Full is never reported for MySQL / MariaDB.** Neither the MariaDB `server_audit` log nor the Percona `audit_log` plugin or `audit_log_filter` component logs the rows a statement returned; `performance_schema` has row counts but is a ring buffer (statements pushed out between two polls are lost), and the account, client host and `program_name` of a session are only readable while it is connected.

- **Audit log.** Declared per target as `mysql.audit_log` in `agent.yaml`, with an absolute `path` and a `format`: `server_audit` (MariaDB `server_audit`, with `server_audit_output_type = file` and `server_audit_events` including `QUERY` or `QUERY_DML`, and `TABLE`) or `json` (Percona `audit_log` with `audit_log_format = JSON` and `audit_log_policy = ALL` or `QUERIES`; Percona `audit_log_filter` with `audit_log_filter.format = JSON` and a filter logging the accounts to audit; MySQL Enterprise Audit JSON). The agent reads the file locally and incrementally, never through SQL. The XML and CSV `audit_log` formats and the syslog outputs are not supported: the configuration refuses them, and a server writing them is noted by `check()` and not used. The general log is never used as a source.
- **`performance_schema`.** Statement history from `events_statements_history_long`, otherwise `events_statements_history`, otherwise `events_statements_current`, polled at `poll_interval_s`; a wrap of the ring buffer between two polls is logged. MariaDB leaves `events_statements_current` off by default: enable it. The source needs `SELECT ON performance_schema.*` ([05-security.md](05-security.md#recommended-database-accounts-read-only)); the audit-log sources need no database grant.
- **No row counts on the file sources.** The console scores an event without `rows` 0 ([ADR-0021](adr/0021-access-event-correlation.md)): on those sources only signatures, shapes and object or principal conditions raise incidents, and `volume.large_result` is never set.

### Statement text and passwords

Statement text never leaves the agent (the `AccessEvent` contract has no field for it). From `performance_schema`, the connector reads `DIGEST_TEXT` first (literals already replaced by the server) and `SQL_TEXT` only for a statement without a digest. **The agent relies on no server-side password mask**: measured on the dev images, MariaDB `performance_schema` `SQL_TEXT` keeps passwords in clear (`CREATE USER … IDENTIFIED BY`, `SET PASSWORD`, `GRANT … IDENTIFIED BY` and the other forms listed in the README), MySQL 8.4 `performance_schema` and the Percona logs write `<secret>`, and `server_audit` writes `*****`. DCL coverage of `server_audit` depends on its event set: with `QUERY_DML` (one of the recommended sets) it logs no DCL at all; with `QUERY_DCL` (as in the end-to-end test, MariaDB 11.4) it logs `CREATE USER` but **not `ALTER USER`**, so a password change by `ALTER USER` is not audited. Whether `QUERY` logs `ALTER USER` has not been tested. Every literal is replaced by the query normalizer whatever the statement, and a statement that does not lex (for example a password cut at the server's text limit) keeps no text and no names.

Because the session `sql_mode` of a logged statement is unknown, the normalizer reads ambiguous text under each possible mode (`NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`, version comments); readings that differ keep only the statement kind. Text that is not UTF-8, or that has a byte >= 0x80 directly followed by `\` or a backtick (the trail byte of a two-byte character in gbk, big5, sjis, cp932 or gb18030), keeps only the statement kind and the event names `*` (fail closed). This last rule is not applied to `performance_schema` texts, which the server has already transcoded to UTF-8.

DDL and DCL events take no object names from the statement text; objects come from the log's table records when it has them (`server_audit` `TABLE`, `audit_log_filter` `table_access`), otherwise from the text for reads and writes. A failed statement is reported unless the server refused it before reading anything (syntax, unknown object and access errors), it sent no row, and the audit log has no table read record for it.

### Signals

The signal ids are registered for `mysql` and `mariadb` in [`shared/protocol/signals.json`](../shared/protocol/signals.json).

| Signal | When it is set |
|--------|----------------|
| `signature.mysqldump` | A whole-table read by a client whose `program_name` is `mysqldump`, `mariadb-dump`, `mysqlpump` or `mydumper`, or carrying `SQL_NO_CACHE`, or in a session that took a consistent snapshot, a global read lock or `LOCK TABLES`, or of a table the session ran `SHOW CREATE TABLE` on (session state from successful statements only) |
| `signature.into_outfile` | `SELECT … INTO OUTFILE` / `INTO DUMPFILE`, also when the server refused it |
| `shape.full_table_read` | A read without top-level `WHERE`, aggregation or derived table, and with no limit or a limit above 10 000 rows |
| `volume.large_result` | More than 10 000 rows returned or affected by one statement (`performance_schema` only) |

`signature.mysqldump` is a heuristic and can be evaded. Known evasions: a plain `SELECT *` per table (no `SQL_NO_CACHE`, no dump `program_name`, no snapshot or lock); `mysqldump --skip-lock-tables` without `--single-transaction` (only `SQL_NO_CACHE` and the program name remain, which a modified client or another tool does not send); chunked reads (`mydumper` with a chunk size, `WHERE` ranges: no whole-table read); a statement padded past `server_audit_query_log_limit` or the `performance_schema` text limit (the cut text gives no shape). `server_audit` with `QUERY_DML` logs no `SHOW`, `FLUSH`, `LOCK` or `START TRANSACTION`, so only the `SQL_NO_CACHE` and program-name rules apply there, and `server_audit` has no `program_name`. On `performance_schema`, a session that ended before the poll (a short `mysqldump` run) is reported as an unidentified account.

### The agent's own account

As for PostgreSQL, an event of the agent's account is left out only when **all** of these hold:

- it is a read or a connection: **writes, DDL and DCL of the agent's account are always reported** (the agent never writes, I4, so such an event with its identity is someone else using it; #76, commit `35c6459`, [ADR-0027](adr/0027-mongodb-audit.md) decision 7);
- it comes from the agent's client address as the server sees it (`USER()`, read at each re-probe). Only an IP literal counts: a host name there, such as `localhost` for a Unix socket, leaves nothing out;
- it comes from the agent's `program_name` (`databastion-agent`) when the source shows one;
- it carries no signal;
- the agent's reads of each object stay within `limits.max_sample_rows` rows over a rolling 24 h. The audit-log sources have no row count, so each statement is charged the whole budget: a second read of a table within 24 h is reported.

Behind a proxy every client has the proxy's address, and another process on the agent host shares the agent's address. Someone holding the agent's credentials on the agent host, spoofing its `program_name` and reading at most the budget per table and day with filtered queries stays unreported. Writes, DDL and DCL with the agent's identity are always reported.

### Known limits

- **Never Full; no row counts on the file sources** (above).
- **Signal stripping on the audit log files.** A client can make its own statement keep only its kind by putting a non-ASCII character right before a backslash or a backtick (`` 1 AS `é` ``, `/* é\ */`), through the fail-closed multibyte rule. The event is still reported, against `*` (with the tables named by the log's table records where it has them), but without text-derived signals (`signature.*`, `shape.*`).
- **Dump heuristic evasions** (above).
- **At-most-once delivery**, as for PostgreSQL: an agent crash within the aggregation window loses the events the cursor has already passed.
- **Cursors and counters in memory.** The `performance_schema` cursor is not persisted: after an agent restart, reading starts at the newest statement, and what ran while the agent was stopped is not reported. The own-account row counters are reset by an agent restart. Without a cursor, a log file is read from its end; a log rotated while the agent was stopped is read from the start of the new file.
- **A file source is Limited until a record is parsed**: after the log is configured, after an agent restart (the time of the last record is not persisted), and when nothing was written to the log for 24 h.
- **`server_audit` times are local**, converted with the server's time-zone offset read at each re-probe; a DST change in between shifts times until the next re-probe.
- **Forged and dropped records.** The audit logs are written by the server only; a client cannot put a newline in a record, so it cannot add records. A damaged record is dropped and the following ones are kept; dropped records are counted by `check()` for 24 h, logged by the agent and reported to the console as the target note `audit.records_dropped` (#68, sent while the console lists `target_status.notes`).
- **The audit-log file ACL is the operator's job** ([05-security.md](05-security.md#recommended-database-accounts-read-only)).
- **Failed-login flood.** A client that can reach the database port, even without valid credentials, can try many made-up user names. Each name becomes its own `auth_failure` event group: the aggregation key includes the account name, and `auth_failure` always passes the `audit.configure` filter. The agent flushes every 10 000 groups and keeps spooling while the console answers `429`. The console accepts at most 60 batches of 500 events per minute per agent and applies back-pressure at 20 000 pending events. The effects are:
  - the batches of a later dump queue behind the flood, so its incident is delayed;
  - once the spool is full, the oldest batches, findings included, are evicted;
  - the console can store about 30 000 rows per minute per agent, kept for the event retention.
  The flood shows in the spool's dropped counters and the console's back-pressure metric. When the agent drops batches, the console raises an `agent.batches_dropped` alert to the `system_alerts` channels, at most once per agent and hour (#75, [05-security.md](05-security.md#alerting)); the dropped events are still lost. This is a residual of the Audit design ([ADR-0023](adr/0023-mysql-mariadb-audit-sources-and-levels.md)), recorded in [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md); caps per window and priority-aware eviction are phase-7 follow-ups.
- **Audit uses its own connections.** A `performance_schema` stream holds a session on the agent's account. Every 5 minutes the stream re-probes its prerequisites on another connection, and a file-source stream does too. Size `MAX_USER_CONNECTIONS` as in [05-security.md](05-security.md#recommended-database-accounts-read-only): 6 with `performance_schema`, 5 with an audit log file, plus one per additional Audit target on the account ([ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) decision 11). A connection refused at the limit fails the check or scan that needed it. For an Audit stream, the stream restarts after a backoff, counted in `audit_stream_failures_total`, and it can miss what ran in between.
- **Role privileges only partly visible on MariaDB.** `check()` evaluates the privileges held through roles, including a `performance_schema` grant held through a role, with the rules for direct grants (#70, [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md)). MySQL (8.0.19+) shows every applicable role; when `APPLICABLE_ROLES` cannot be read (older MySQL, or an error), the roles are counted from the account's own `SHOW GRANTS` role lines and `mandatory_roles`, all as not evaluated, or the privileges are reported as `privilege.not_evaluated` when those cannot be read either (fail closed, #83). MariaDB shows a least-privilege account the grants of its current (default) role only: every other role is reported as `privilege.roles_not_evaluated`, and `PUBLIC` grants (10.11+) are not read.
- **Level of a target whose check timed out.** Targets that share an account take turns within the heartbeat's 10 s deadline. A target whose `check()` did not finish in time, or waited for its turn behind a slow check of the same account, is reported unreachable (`timeout`, `check.timed_out`) with level None for that heartbeat. This does not mean its Audit stream stopped.
- **Heuristic signals.** `shape.*` and `signature.*` are evadable by design; see [the classifiers README](../agent/crates/classifiers/README.md).

## MongoDB Discovery

What the MongoDB connector does, as merged in P5-A (#74, [ADR-0026](adr/0026-mongodb-connector.md)). The reference is [the connector README](../agent/crates/connector-mongodb/README.md); the account is in [05-security.md](05-security.md#recommended-database-accounts-read-only).

### Scope
- **One declared host**: a standalone, one replica-set member or a `mongos`, reached directly. The other replica-set members are never contacted and `mongodb+srv` is not supported: to scan a replica set, declare the member to read from (a secondary spares the primary). Reads carry `secondaryPreferred`. MongoDB 5.0 or later; SCRAM-SHA-256 accounts only.
- **Databases and collections** the account holds privileges on (`authorizedDatabases`, `authorizedCollections`), at most 1024 databases and 4096 collections per database, filtered by the job's filters. `admin`, `local`, `config`, `system.*` and queryable-encryption state collections (`enxcol_.*`) are never read. Collections the account cannot see are not listed, so they cannot be reported as not covered.
- **Views are not sampled** (their pipeline could read other collections or run JavaScript): counted as `skipped_unsupported`, with the note `coverage.views_not_sampled`. Data reachable only through a view is not covered.
- **Time-series collections** are read through their view with `find` and a limit, without a size estimate. If the server refuses the read to the account, the collection is counted as `skipped_not_readable` and `check()` reports `coverage.timeseries_not_readable` with the count observed in the last scan; the fallback grant is in [05-security.md](05-security.md#recommended-database-accounts-read-only). Reading through the unpacking view costs more than reading a plain collection.

### Sampling
- The size estimate is a `count` without a filter (collection metadata), reported as the object's estimated rows; on a sharded cluster it may include orphaned documents.
- Above 20 times `sample_rows` documents (and above 100), `$sample` picks `sample_rows` documents at random (random cursor, no collection scan). Otherwise the first `sample_rows` documents in natural (storage) order are read.
- One reply per collection, at most 16 MiB + 64 KiB: a batch cut by the server gives a smaller sample, never a second read.
- Per document: at most 20 levels of nesting, the first 16 elements of each array, 512 values. Per collection: at most 1024 distinct field paths and `sample_rows` values per path; values cut to 4096 bytes.
- Values classified: strings; `int32` / `int64` as digits; integral doubles below 2^53; finite `Decimal128`; dates as `YYYY-MM-DD`; generic and user-defined binaries only when they are UTF-8 text. Never read: UUID, encrypted, compressed, sensitive and vector binaries, ObjectIds, booleans, JavaScript code, timestamps, non-integral doubles.

### Field paths
A finding's location is the database, the collection (`object`) and a normalized field path (`field`); there is no schema. `_id` is a field like any other.

- An embedded document adds a key; an array adds `[]` (`orders[].items[].sku`, arrays of arrays included).
- Keys that are digits only, contain a dot, or look like values (e-mail addresses, phone or card numbers, UUIDs…) become `*`: `contacts.*.phone`.
- Object levels that the sample shows to be maps keyed by data (more than 16 distinct keys across the sampled documents, or at least 3 keys each seen in one document only, across at least 2 documents) have their keys replaced by `*`: `acl.*.role`. The collection's top-level fields are never collapsed.
- The values of every raw path with the same normalized path are pooled before classification.
- Limits of the key rule: a small map whose keys recur across the sampled documents (at most 16), a map with fewer than 3 keys, or a sample of one document can leave data-derived keys in the path when they do not look like values; conversely, a sub-document with more than 16 fields, or with optional fields each present in one sampled document, is reported as `parent.*`.

### Coverage counters and notes
| Counter | Meaning |
|---------|---------|
| `objects_sampled` | Collections read |
| `skipped_not_readable` | Refused by the server (`Unauthorized`), including time-series collections |
| `skipped_unsupported` | Views and collection types the connector does not know |
| `skipped_limit` | Database or collection listing cut at its bound |
| `skipped_error` | Any other failure on one collection (dropped since listed, `maxTimeMS` expired, reply over the limit, malformed document) |

`check()` notes for MongoDB targets, Discovery part: `coverage.views_not_sampled`; `coverage.timeseries_not_readable`; the over-privilege notes `privilege.write_actions`, `privilege.read_beyond_discovery`, `privilege.cluster_actions`, `privilege.any_database`, `privilege.system_collections` and `privilege.not_evaluated`; `security.tls_disabled`; `check.stage_failed`, `check.timed_out`. The privilege and coverage report is recomputed at most every 10 minutes per target. The Audit notes are listed in [MongoDB Audit](#mongodb-audit); `audit.stream_not_available` is no longer sent (the code stays registered).

## MongoDB Audit

What the MongoDB connector does for Audit, as merged in P5-B / P5-C (#76). Decisions in [ADR-0027](adr/0027-mongodb-audit.md); the reference is [the connector README](../agent/crates/connector-mongodb/README.md#audit).

### Sources and level

`check()` and the Audit stream choose one source per target with the same rule, re-evaluated every 5 minutes. In order of preference:

| Level | Condition | Source (`audit_source`) |
|-------|-----------|--------|
| **Partial** | The `auditLog` JSON file declared in `agent.yaml` (`format: audit_log`) is readable by the agent, `buildInfo` reports MongoDB Enterprise or Percona Server for MongoDB, **and** the stream has parsed a successful `authCheck` record in the last 24 h | `mongodb_audit_log` |
| **Limited** | The same `auditLog`, and the stream has parsed a valid record of it in the last 24 h, but no successful `authCheck` (note `audit.authcheck_success_pending`); **None** until any record is parsed (notes `audit.limited_pending_first_record` and `audit.authcheck_success_pending`; the file is still read meanwhile) | `mongodb_audit_log` |
| **Limited** | The structured JSON server log declared in `agent.yaml` (`format: server_log`) is readable by the agent, on any edition, **and** the stream has parsed a record of it in the last 24 h (**None** until then) | `mongodb_log` |
| **Limited** | No usable file; the target is not a `mongos`; the account holds `find` on `system.profile` of at least one database, **and** the stream has read a profiler entry in the last 24 h (**None** until then) | `mongodb_profiler` |
| **None** | None of the above (note `audit.source_not_configured`; `audit.log_not_readable` when a declared file cannot be read) | none |

**Full is never reported for MongoDB.** The `auditLog` logs every authorized command (with `auditAuthorizationSuccess`) but no document count (note `audit.log_without_row_counts`); the server log and the profiler have counts, but only for the operations the server records (slower than `slowms`, sampled by `slowOpSampleRate`; the profiler is a capped collection that overwrites itself), with the note `audit.slow_operations_only`. The agent cannot read `slowms`, `slowOpSampleRate`, the profiling level or `auditAuthorizationSuccess` without cluster privileges, so a level is proven from records read, never predicted from settings: an `auditLog`, a server log or a profiler that recorded nothing in the last 24 h reports **None** with the note `audit.limited_pending_first_record` (the source is still read meanwhile; [ADR-0030](adr/0030-mongodb-auditlog-freshness.md) for the `auditLog`, since #83). Any valid `auditLog` record counts, the agent's own `authenticate` at each check included, so a written file reaches Limited within one poll of the first check; a stale file falls to None within 24 h of its last record. The proof is in memory: after an agent restart the level is None until the next record is parsed.

- **`auditLog`.** `auditLog.destination: file`, `format: JSON`, the `mongo` schema. The BSON format, the OCSF schema and the `syslog` / `console` destinations are not supported: their records do not parse and are counted as dropped (`audit.records_dropped`). An `auditLog` declared on a Community server is not used (`audit.auditlog_on_community`). An `auditLog.filter` that leaves reads out cannot be detected, and `auditAuthorizationSuccess` turned off is only noticed after 24 h without a successful `authCheck`.
- **Server log.** `systemLog.destination: file` (JSON, MongoDB 4.4 and later). Operations come from the slow-query lines; a slow-query line has no user, so the connector follows connections by `ctx` (accept, client metadata and authentication lines, at most 4096). An operation on a connection that authenticated before the agent started reading the log is reported as an unidentified account.
- **Profiler.** Per database and poll, one bounded `find` on `system.profile` (`ts` filter, fixed server-side projection, `limit: 1000`, `singleBatch`, `maxTimeMS`), at most 64 databases per poll, never `admin`, `local` or `config`. The position is kept in memory and the first poll starts at the newest entry. An entry whose `command` the server truncated (`{$truncated: …}`) or that is not a document has an **unknown shape** (no whole-read signal from a filter that was cut off); when its command name was lost too, it is reported as a write if it wrote documents, else as a read if it returned documents, never dropped. An entry that does not parse is skipped and counted as dropped (`audit.records_dropped`); it never fails the whole poll (#83, [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md) decision 7). Profiling itself is set by the operator; level 2 is costly ([below](#cost-for-the-monitored-database)).
- **One node.** The log and the profiler are per node, and the connector never follows the replica-set topology: only the declared node's activity is seen.

### What is kept

Closed-shape facts only (I2, [ADR-0007](adr/0007-mask-access-events.md)): the time, the command name (compared with a closed list), the normalized namespace, the user (`name@authdb`), the client IP (port dropped), the application name, the document counts, a failure flag, whether the filter has keys (a count, never a key or a value), a numeric `limit`, and the aggregation stage operators compared with a closed list. Command documents (`param.args`, `command`, `originatingCommand`), `errMsg`, `planSummary` and every other field hold other users' literals: they are skipped without being copied in the files, and never fetched from the profiler (the facts are computed by the server's projection). A failed operation is reported only when it returned documents.

### Signals

The signal ids are registered for `mongodb` in [`shared/protocol/signals.json`](../shared/protocol/signals.json).

| Signal | When it is set |
|--------|----------------|
| `signature.mongodump` | A read of a collection (`find`, `aggregate`, `getMore`) by a client whose application name (`appName`) is `mongodump`, alone or followed by a space, `/`, `-` or a digit |
| `signature.mongoexport` | The same with `mongoexport` |
| `shape.full_table_read` | A `find` whose filter has no key, without a limit or with a limit above 10 000; an `aggregate` with no stage or only pass-through stages (`$project`, `$addFields`, `$set`, `$unset`, `$sort`, `$replaceRoot`, `$replaceWith`); a `getMore` of such a cursor when the source shows the command that opened it (log, profiler) |
| `volume.large_result` | More than 10 000 documents returned or written by one operation (server log and profiler only) |

These are heuristics, evadable by design. The application name is declared by the client: a dump tool run under another name carries no signature, and any client can declare the tools' names. The shape rule is cheap to evade: a filter that selects everything (`{_id: {$exists: true}}`), an `aggregate` with `{$match: {}}` or a large `$sample`, or a dump in many small filtered reads is not a whole-collection shape; `getMore` batches split a large read into operations below the volume threshold. On the `auditLog`, `getMore` records carry no filter, so only the application-name signatures apply to them. The volume × sensitivity score computed by the console remains the robust signal, and it needs row counts: `auditLog` events have none and score 0 ([ADR-0021](adr/0021-access-event-correlation.md)).

### The agent's own account

As for PostgreSQL and MySQL / MariaDB, an event of the agent's account is left out only when **all** of these hold:

- it is a read or a connection: writes, DDL and DCL of the agent's account are always reported;
- the account is `<account>@<auth_source>` of the target;
- the application name is `databastion-agent` when the source shows one;
- the client address is the agent's own address as the server sees it (the `whatsmyuri` command, read at each re-probe). Only an IP literal counts: a Unix socket leaves nothing out;
- it carries no signal;
- the documents it read stay within `limits.max_sample_rows` per collection over a rolling 24 h. On the `auditLog`, which has no counts, only a `find` with a numeric limit in `1..=max_sample_rows` is left out, charged that limit; any other read (an `aggregate`, including the agent's own `$sample`, a `find` without a limit) is reported.

Not charged to the budget (same identity rules): the agent's `count` without a filter (it reads no document), and, **on the profiler source only**, the agent's own profiler polls with their exact shape: a `find` on `system.profile` with a one-key filter and `limit: 1000`, or the newest-entry probe with no filter and `limit: 1`. Any other read of `system.profile` with the agent's identity is charged like any read, and a read of it by any other account is reported.

Limits of these rules: behind a proxy or NAT every client has the same address. Someone holding the agent's credentials on the agent host, spoofing its application name and reading at most the budget per collection and day stays unreported (on the `auditLog`, with `find`s whose limits add up to the budget); on the profiler source, a read with the agent's exact poll shape is uncharged only up to the number of polls the agent actually sent to that database (unused credits capped at 64), so such a client can at most take the place of the agent's own polls before its reads are charged and reported. The row counters are reset by an agent restart.

### Notes

`check()` Audit notes for MongoDB targets: `audit.authcheck_success_pending`, `audit.auditlog_on_community`, `audit.log_without_row_counts`, `audit.slow_operations_only`, `audit.limited_pending_first_record`, `audit.source_not_configured`, `audit.log_not_readable`, `audit.records_dropped`. `check()` counts `find` on `<db>.system.profile` as the Audit grant only while a stream reads the profiler; otherwise it reports it as `privilege.system_collections`.

### Known limits

- **Never Full; no document counts on the `auditLog`** (above).
- **Slow operations only on the server log and the profiler.** A fast `mongodump` of a small collection, or any read under `slowms`, is not seen; a sampled log misses operations at random.
- **Profiler ring buffer.** Entries overwritten between two polls are lost without a trace.
- **Heuristic signals** and **own-account residuals** (above).
- **Log literals on the agent host.** The files the agent reads hold other users' literals; the agent keeps none (zeroized buffers, never logged or sent), but a compromised agent host can read them through the file ACL it was given ([05-security.md](05-security.md#recommended-database-accounts-read-only)).
- **At-most-once delivery**, as for the other engines; the profiler position is in memory, so an agent restart skips what the profiler recorded while the agent was stopped.

## OpenLDAP Discovery

What the OpenLDAP connector does, as implemented in phase 6 (#79, [ADR-0029](adr/0029-openldap-connector.md)). The reference is [the connector README](../agent/crates/connector-openldap/README.md); the account is in [05-security.md](05-security.md#recommended-database-accounts-read-only).

### Scope
- **One declared server**, over LDAPS, StartTLS, or cleartext on `ldapi://` / loopback only. Referrals and continuation references are never followed (counted as `skipped_remote`); aliases are never dereferenced.
- **Naming contexts** from the root DSE (at most 64), filtered by the job's `databases`; the Audit log base (`openldap.accesslog_base`, default `cn=accesslog`) is never scanned.
- **Containers**: per naming context, one subtree listing of `organizationalUnit`, `organization`, `dcObject`, `domain`, `country` and `locality` entries (DNs only, at most 1024; a cut listing counts `skipped_limit`), filtered by the job's `schemas`. Entries whose parent is not a container (`uid=x,cn=group,ou=a,…`) and the root entry of each naming context are not read.
- **Attributes**: from the server's schema (subschema subentry, `SUP` chains resolved), only `userApplications` attributes of a text syntax: Directory String, IA5 String, Printable String, Numeric String, Country String, Telephone Number, Postal Address, Generalized Time, Integer. Custom attributes are covered like standard ones. DN-valued attributes (group members, `seeAlso`), octet strings, binaries, certificates, photos, UUIDs and unknown syntaxes are never requested (fail closed). At most 1024 attributes.
- **Password attributes are never read**: `userPassword`, `authPassword`, their subtypes and a closed list of other credential attributes (Samba, Kerberos, `pwdHistory`, `userPKCS12`) are never requested, whatever the ACL grants, and no finding is produced for them; their presence and hash schemes are not reported. `check()` only flags an account that could read them (`privilege.password_attributes_readable`, from an attributes-only search of the first 64 entries of each naming context: the values never cross the wire).

### Sampling
- Per container (and the naming context itself), one one-level search, filter `(objectClass=*)`, `sizeLimit` = the job's `sample_rows`, `timeLimit` from the job's statement timeout (at least 1 s). No paged results: a server size limit below `sample_rows` gives a smaller sample.
- The sample is the first entries of each container **in server order** (entry id order on `back-mdb`: oldest entries first), not a random sample.
- Entries are grouped by normalized container and structural object class; per group at most `sample_rows` values per attribute, values cut to 4096 bytes, values that are not UTF-8 skipped, Generalized Time read as `YYYY-MM-DD`, attribute options (`;lang-fr`) pooled with the base attribute. Each search is read to its end before any finding is submitted.

### Locations
`database` = the naming context, `schema` = the entry's container, `object` = the structural object class, `field` = the attribute (lowercased). The container is the entry's parent DN reduced to container RDNs, a value that looks like data becoming `*` (`ou=Oliver O'Connor,ou=teams,…` → `ou=*,ou=teams,…`). **Entry DNs never leave the agent** and are never logged ([09-agent-protocol.md](09-agent-protocol.md#location-mapping-per-engine)). A container named after a person or a customer that the normalization does not recognize keeps its name.

### Coverage counters and notes
| Counter | Meaning |
|---------|---------|
| `objects_sampled` | (container, structural object class) groups read |
| `skipped_not_readable` | A container the server refuses (`insufficientAccessRights`, or `noSuchObject` hiding it) |
| `skipped_remote` | Continuation references (referrals, never followed) |
| `skipped_limit` | Container listing cut at its bound |
| `skipped_error` | Any other failure of one search |

`check()` notes for OpenLDAP targets, Discovery part: `privilege.password_attributes_readable`, `privilege.config_readable` (`cn=config` readable: ACLs, root password hashes), `privilege.accesslog_without_audit` (`cn=accesslog` readable while no Audit stream runs), `privilege.write_not_evaluated` (always: OpenLDAP shows a read-only account neither its ACLs nor its effective rights, so write access is never evaluated; check `olcAccess`), `check.stage_failed`, `check.timed_out`. The privilege report is recomputed at most every 10 minutes per target.

## OpenLDAP Audit

What the OpenLDAP connector does for Audit, as implemented in phase 6 (#79, [ADR-0029](adr/0029-openldap-connector.md) decisions 7 to 10). The reference is [the connector README](../agent/crates/connector-openldap/README.md#audit).

### Source and level

One source: the `slapo-accesslog` database (`audit_source` `openldap_accesslog`), read over LDAP with the agent's service DN and transport. Recommended overlay settings on each monitored database: `olcAccessLogOps: reads writes session`, `olcAccessLogSuccess: FALSE` (failed operations logged too), a purge (`olcAccessLogPurge`), and `olcDbIndex: entryCSN eq` on the log database.

- **Incremental by `entryCSN`** (commit order). `reqStart` is not used as the cursor: a long search is written at its end with an early `reqStart`, so a `reqStart` cursor would skip exactly the long exports. Each poll reads the records from the cursor minus a 10 s overlap (records already read are recognized by their CSN), `sizeLimit` 1000 per search, repeated at most 16 times while the server cuts the result. The cursor is persisted with the CSNs read within the overlap (at most 1000), so after a restart only the overlap entries not read yet are reported; the first start reads from one minute back (no history replay).

| Level | Condition |
|-------|-----------|
| **Full** | For **every** scanned naming context: a successful search record in `cn=accesslog` from the last 24 h (reads are logged) **and** a logged failed operation from the last 24 h (failed operations are logged, so a search cut by a size, time or administrative limit after returning entries leaves a record) |
| **Partial** | Reads proven logged for some contexts only (`audit.reads_not_logged`, count of contexts), or reads proven for every context but failed operations not proven for at least one (`audit.failed_operations_not_logged`, count of contexts) |
| **Limited** | `cn=accesslog` readable, but no context shows a search record (`audit.reads_not_logged`); binds and writes may still be logged |
| **None** | `cn=accesslog` not readable or absent (`audit.accesslog_not_readable`), or the Audit stream stopped after repeated internal errors (`audit.stream_stopped`, [below](#audit-log-files-and-failing-streams-every-engine)) |

How the level is proven: `check()` looks, per naming context, for a search record under the context; when there is none, it runs one base-scope search on the context (attributes `1.1`) and looks again, so a server that logs reads proves it at once. Records under a deeper naming context (held by another database) do not count for the parent context. For failed operations, `check()` reads, at every privilege report (at most every 10 minutes per target, at most 8 naming contexts per report, the oldest answers first), an entry that does not exist below the context, `cn=databastion-absent-probe-<suffix>,<context>` with a suffix unique to that probe (`noSuchObject`, which reads nothing), and looks for that probe's own failed-search record. Only the latest answer counts: it replaces the previous one (#83, [ADR-0032](adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md) decision 6). With `olcAccessLogSuccess: TRUE`, only successful operations are logged: the level is capped at Partial from the next report that probes the context. A context whose failed-operation proof is missing or not known yet (a probe refused, a context not probed yet, a report cut by its time bound) also caps the level at Partial. The stream's own search records renew the proof that reads are logged; a failed search that returned entries, seen by the stream, counts as a logged failed operation until the next probe of that context.

Limits of the Full proof:
- **Freshness**: a change of `olcAccessLogSuccess` is seen at the next report that probes the context (10 minutes, longer with more than 8 naming contexts). The proof that reads are logged is kept up to 24 h, so a later change of `olcAccessLogOps` can go unseen for as long.
- **Probe records**: each probe leaves one failed-search record in `cn=accesslog` per context and report.
- An `olcAccessLogBase` that covers only part of a naming context cannot be seen: the proof may fall inside it.

Full means docs/08's definition is met (every search logged with its authorization identity, base, scope and entry count); what the log does not have is listed below.

### What is kept

Read from each record: `reqType`, `reqStart`, `reqSession`, `reqAuthzID`, `reqDN`, `reqResult`, `reqScope`, `reqFilter`, `reqAttr`, `reqAttrsOnly`, `reqEntries`, `reqSizeLimit`, `entryCSN`. Never requested: `reqMod`, `reqOld`, `reqAssertion`, `reqMessage`, the controls and the other value-bearing attributes. `reqFilter` (which carries assertion values) and `reqDN` are reduced in memory to closed facts: whether the filter selects entries by value, whether it is one of the agent's own filters, the naming context, the normalized container and a keyed hash of the base (for paged totals). Neither is kept, logged or sent.

- **Actions**: search and compare are `read` (`rows` = `reqEntries` for a search); add, modify (password changes included), delete and modrdn are `write`; bind is `connect`, or `auth_failure` when it failed. Unbind, abandon and extended operations give no event. A failed search that returned entries is reported; other failed operations are not.
- **Principal**: the authorization DN (`reqAuthzID`), `anonymous` when empty; the bind DN for a bind. Sent in clear only for `anonymous`, the agent's own DN and the DNs listed in `openldap.clear_principals`; **every other principal is a keyed fingerprint** (an entry DN usually names a person). Failed binds are always fingerprinted.
- **Objects**: the naming context of `reqDN`, and the console's `sensitive_objects` of that context the operation could reach (from the base's container, and for a subtree search every container below it; at most 16, the first ones in the console's most-sensitive-first order, [ADR-0031](adr/0031-openldap-principals-dedup-and-stream-alerts.md) decision 4). With none, the object is `*` with the container as `schema`: the log does not give the object class of the entries a search returned.
- **Missing from the log**: the client address (events carry none) and the application name.

### Signals

The signal ids are registered for `openldap` in [`shared/protocol/signals.json`](../shared/protocol/signals.json).

| Signal | When it is set |
|--------|----------------|
| `shape.bulk_search` | A search with scope one-level, subtree or children whose filter selects no entry by value: only presence tests (`(objectClass=*)`, `(mail=*)`) and `objectClass` equality assertions, combined with `&` / `|`. The shape of an LDIF export or a bulk `ldapsearch` |
| `volume.large_result` | More than 10 000 entries returned by one search, **or by the pages of one paged search**: the records of one connection with the same base and scope are summed, and the record crossing 10 000 and the later ones carry the signal |

There is no `signature.*` for OpenLDAP: `ldapsearch` declares nothing, and `slapcat` (an offline LDIF export on the server host) performs no LDAP operation, so it leaves no `cn=accesslog` record and is not seen. These are heuristics: a selective filter that matches everything (`(uid=a*)` … `(uid=z*)`, `(!(uid=nobody))`), per-entry base-scope reads, or pages spread over several connections evade them. The volume × sensitivity score remains the robust signal, and it works here (`reqEntries` on every search).

### The agent's own account

An event is left out only when it is a read or a connection of the agent's identity (the DN returned by Who am I?), carries no signal, and the agent's reads of each object stay within `limits.max_sample_rows` entries over a rolling 24 h. The log has no client address, so **no address rule applies** (unlike the other engines). The agent's exact container listing and check probes are not charged to the budget; its entry sampling is. Writes, and anything else with the agent's identity, are always reported.

Limit: someone holding the agent's DN and password can bind from anywhere unreported and read up to the budget per object and day with the agent's sampling shape. Restricting the service DN to the agent's address in `olcAccess` (`peername.ip`, [05-security.md](05-security.md#recommended-database-accounts-read-only)) is the recommended control.

### Notes

`check()` Audit notes for OpenLDAP targets: `audit.accesslog_not_readable`, `audit.reads_not_logged`, `audit.failed_operations_not_logged`, `audit.records_dropped` (log entries that do not parse, counted for 24 h), `audit.stream_stopped`.

### Known limits

- **No client address** in the log: principals carry none.
- **Incidents per fingerprint** (end-of-phase-6 review M1, fixed in #81 by [ADR-0031](adr/0031-openldap-principals-dedup-and-stream-alerts.md)): each fingerprinted user has its own incident key; every unidentified principal of one agent (SASL binds) shares one.
- **Records committed out of CSN order** (review L3, reduced in #83): the persisted overlap CSNs cover restarts; a record committed more than 10 s below the cursor, or beyond the 1000 persisted CSNs, is lost.
- **Container names** (review L4): the normalized container (`schema`) keeps `ou`, `o`, `dc`, `c`, `l` and `st` values that do not look like data; a container named after a person or a customer that the normalization does not recognize reaches the console.
- **Log gaps**: records purged by `olcAccessLogPurge` before the agent read them (agent stopped longer than the purge age) are lost; on first start, a server clock behind the agent's by more than 60 s skips records until it catches up.
- **`slapcat` and other offline exports** are not visible.
- **Heuristic signals** and **own-account residuals** (above).
- **Delivery**: at most once, as for the other engines; after a caught internal error (panic), the stream restarts from its persisted cursor and the events of at most one search round may be sent twice. A log entry that makes the connector panic is dropped alone; one that ends the stream repeatedly is located (isolation mode: position saved after every entry) and skipped after 3 panics at its exact position. Its events are lost (counted in `audit.records_dropped` and `audit_records_skipped_total`). The stream stops only on the thresholds of [Audit log files and failing streams](#audit-log-files-and-failing-streams-every-engine), with a console alert.

## Known export signatures
| Tool | Observable signature | Engine |
|-------|---------------------|--------|
| `pg_dump` / `pg_dumpall` | `application_name = 'pg_dump'`, `COPY … TO STDOUT` on every table, `REPEATABLE READ` transaction | PostgreSQL |
| `COPY … TO` / `\copy` | Outbound `COPY` statement | PostgreSQL |
| `mysqldump` | `SELECT /*!40001 SQL_NO_CACHE */ * FROM`, `SHOW CREATE TABLE` in sequence, `FLUSH TABLES WITH READ LOCK` | MySQL / MariaDB |
| `SELECT … INTO OUTFILE` | Explicit statement | MySQL / MariaDB |
| `mongodump` / `mongoexport` | Tool's `appName`, unfiltered `find` over the whole collection | MongoDB |
| LDIF export / bulk `ldapsearch` | One-level or subtree search with an unselective filter (`(objectClass=*)`, presence tests), high `reqEntries` | OpenLDAP |

As implemented: on PostgreSQL (P4-A) the agent uses the `application_name` and the whole-relation `COPY … TO STDOUT` parts of the `pg_dump` signature (not the `REPEATABLE READ` transaction) and the outbound `COPY` signatures; see [PostgreSQL Audit](#postgresql-audit). On MySQL / MariaDB (P4-B) the agent uses the `SQL_NO_CACHE`, `SHOW CREATE TABLE` and `FLUSH TABLES WITH READ LOCK` parts of the `mysqldump` signature, plus the dump tools' `program_name`, consistent snapshots and `LOCK TABLES`, as one heuristic `signature.mysqldump`, and the `INTO OUTFILE` / `INTO DUMPFILE` signature; see [MySQL / MariaDB Audit](#mysql--mariadb-audit). On MongoDB (P5-B / P5-C, #76) the agent uses the tools' `appName` (`signature.mongodump`, `signature.mongoexport`) and, separately, the whole-collection `find` shape (`shape.full_table_read`); see [MongoDB Audit](#mongodb-audit). On OpenLDAP (#79) there is no tool signature (`ldapsearch` declares nothing): the agent uses the search shape (`shape.bulk_search`) and the entry count summed over the pages of a paged search (`volume.large_result`); `slapcat` leaves no log record; see [OpenLDAP Audit](#openldap-audit).

Signatures are easy to forge (`application_name` and `program_name` are chosen by the client). They are only **one** of the three signals; the volume × sensitivity combination remains the primary signal (see [02-architecture.md](02-architecture.md#exfiltration-detection-audit)). The console computes it from the row count the source reports ([ADR-0021](adr/0021-access-event-correlation.md)): an event without `rows` scores 0 and feeds no baseline (the contract has an optional `AccessEvent.bytes` since #60; no connector produces it yet, and the console stores and shows it but does not use it in the score, #62), so on a source that gives no volume only signatures, shapes and object or principal conditions can raise an incident. Sensitivity is per object (table, collection), not per column.

## Cost for the monitored database
| Source | Cost | Recommendation |
|--------|------|----------------|
| pgaudit (`read` class) | Medium: log volume | Restrict to sensitive roles and objects (`pgaudit.role`) |
| MariaDB `server_audit` | Low to medium | Filter out service accounts |
| `performance_schema` | Low | OK |
| MongoDB profiler level 2 | **High** | Avoid in production; level 1 with a suitable `slowms` |
| MongoDB profiler polling by the agent | Low to medium: each poll scans `system.profile` from the start in natural order (no `ts` index), bounded by `maxTimeMS` (at most 30 s) | A failing poll (for example a `maxTimeMS` expiry) is logged by the agent; with no entry read for 24 h the target shows the level None |
| OpenLDAP `accesslog` | Low | Purge with `olcAccessLogPurge` |
