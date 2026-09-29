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
| **MongoDB Enterprise** | `auditLog` (JSON) + profiler for volumes | Full | `auditLog.destination=file`, filter on reads |
| **Percona Server for MongoDB** | `auditLog` | Full | Same |
| **MongoDB Community** | Structured JSON logs (slow operations: `appName`, `nreturned`) + profiler | Limited → Partial | Profiler level 1 with low `slowms`; level 2 = Partial but costly |
| **OpenLDAP** | `slapo-accesslog` overlay (`cn=accesslog` database, queryable over LDAP) | Full | `olcAccessLogOps: reads writes session`, read account on `cn=accesslog` |

> **PostgreSQL, as implemented (P2-B, P4-A #58; [ADR-0015](adr/0015-postgresql-connector-decisions.md))**: see [PostgreSQL Audit](#postgresql-audit) below.

> **MySQL / MariaDB, as implemented (P2-C #52, P4-B #64; [ADR-0023](adr/0023-mysql-mariadb-audit-sources-and-levels.md))**: see [MySQL / MariaDB Audit](#mysql--mariadb-audit) below. **Full is never reported** for these engines: no source gives both every statement and its row count.

> **`FEDERATED` and other remote engines**: on MySQL 8.4, computing `information_schema.TABLES.TABLE_ROWS` for a `FEDERATED` table opens its handler, which connects to the remote server. The connector therefore reads no statistics column during introspection, asks for a table's `TABLE_ROWS` only after reading its engine alone and finding a local one ([ADR-0020](adr/0020-mysql-mariadb-connector-as-merged.md)), and never samples tables of remote-access engines (I5).

> **MongoDB Community**: this edition has no audit log. DataBastion sees *slow* operations (or all of them, at the cost of a level 2 profiler). A fast `mongodump` of a small collection can go unnoticed. **This must be stated clearly in the user documentation and in the console.**

> **MySQL Community**: the official audit plugin is reserved for MySQL Enterprise. `performance_schema` provides recent queries and the number of rows returned, but its history is a ring buffer: the agent must read it often enough not to lose anything.

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

- it comes from the agent's `application_name` (`databastion-agent`; checked with pgaudit only);
- it comes from the agent's own client address as the server sees it (`inet_client_addr()`, probed at stream start; checked with pgaudit only). When the agent's address cannot be read, or a record carries no address, nothing is left out;
- it carries no signal: events with a signal are always kept;
- the agent's reads of each object stay within `limits.max_sample_rows` rows over a rolling 24 h. A statement with an unknown row count (no `pgaudit.log_rows`) is charged the whole budget. A second Discovery scan of the same table within 24 h therefore shows up as events of the agent's account.

With `pg_stat_statements`, application and address are not visible: only the signal and row-budget rules apply.

**The connector's own table-less statements** (#65). The connector sends a few statements that read no relation: the per-connection and per-transaction `pg_catalog.set_config(…)` / `current_setting(…)` (one per transaction, about 90 per Discovery scan), `pg_catalog.host(pg_catalog.inet_client_addr())`, and, in `pg_stat_statements` mode, its text query through the extension's `pg_stat_statements(true)` function. They form a closed allow-list (a unit test fails on any other connector statement that names no relation). Such a statement of the agent's account that passes the identity and signal rules above is never reported and is not charged to any row budget. It is recognized by its exact text with pgaudit and by its normalized shape with `pg_stat_statements`. Anything else of the agent's account whose objects are unknown (`*`: any other function call, including `pg_catalog` functions that run SQL such as `query_to_xml`, text that does not parse, several statements) is **always reported and never budgeted**, so no traffic can use up a `*` budget. The same statements from any other role, or from the agent's account under another application or address, are reported against `*`.

Limits of these rules:
- Behind a connection pooler (PgBouncer…) every client has the pooler's address, and another process on the agent host shares the agent's address: there the address check only separates remote clients.
- Someone holding the agent's credentials on the agent host (or behind the same pooler), spoofing its `application_name` and reading at most the budget per object and day with filtered queries stays unreported.
- Someone holding the agent's credentials who passes the identity checks can run the allow-listed table-less statements unreported. They read no row of any relation (`set_config` changes their own session only, `current_setting` reads settings the role may read, and the text query returns statement texts, as a read of the view `pg_stat_statements` does). With `pg_stat_statements`, where only the shape is visible, the settings read by `current_setting(…)` are not checked. The text query is recognized in pgaudit records written during a `pg_stat_statements` period only if the agent did not restart in between.
- The row counters are kept per target for the life of the agent process. Restarting a stream (a failure, a source switch, the agent's sessions terminated on purpose) does not reset them; an **agent restart** does, since they are not persisted, and gives a fresh budget per object.

The agent's database credentials never leave its host (I3).

### Known limits

- **At-most-once delivery.** The log cursor advances once events are handed to the core, which aggregates them for up to `aggregation_window_s` before spooling. An agent crash within that window loses those events; they remain in the database's own log.
- **First start, rotation while stopped.** Without a cursor, reading starts at the end of the log (no history). If the log was rotated while the agent was stopped, the rest of the previous file is not read.
- **Forged records.** Any role can write `AUDIT: …` lines into the server log (`RAISE LOG` in PL/pgSQL). The connector drops records whose severity is not `pgaudit.log_level` or that carry an error context (pgaudit hides its context; `RAISE` always has one). Roles that can hide the context or run native code (C extensions, untrusted languages) can still forge records. A server-wide `log_error_verbosity = terse` removes every context, and with it this protection: keep it at `default`. A forged record can add false events; it cannot remove real ones. Records dropped because of their severity (likely genuine, when the setting differs per database or role) are counted, logged, and noted in `check()` for 24 h, reported to the console as the target note `audit.records_dropped_severity` (#68, sent while the console lists `target_status.notes`).
- **Shadowing an unqualified catalog name.** When an unqualified `pg_*` name counts as a catalog (above), a role that can create a relation named `pg_*` in a schema of its search path (`CREATE TABLE public.pg_loot AS SELECT …`) and later reads it by its unqualified name is not reported for that later read; the copy itself reads the source relation and is reported. With pgaudit, `pgaudit.log_relation = on` (every relation named with its schema) or `pgaudit.log_catalog = off` closes this. The same residual applies to a relation shadowing `pg_stat_statements` earlier in the search path.
- **Per-role pgaudit settings.** The level says what holds for the agent's session (see "pgaudit loaded" above), not that every role is audited alike.
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

Statement text never leaves the agent (the `AccessEvent` contract has no field for it). From `performance_schema`, the connector reads `DIGEST_TEXT` first (literals already replaced by the server) and `SQL_TEXT` only for a statement without a digest. **The agent relies on no server-side password mask**: measured on the dev images, MariaDB `performance_schema` `SQL_TEXT` keeps passwords in clear (`CREATE USER … IDENTIFIED BY`, `SET PASSWORD`, `GRANT … IDENTIFIED BY` and the other forms listed in the README), MySQL 8.4 `performance_schema` and the Percona logs write `<secret>`, and `server_audit` writes `*****`. Every literal is replaced by the query normalizer whatever the statement, and a statement that does not lex (for example a password cut at the server's text limit) keeps no text and no names.

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

- it comes from the agent's client address as the server sees it (`USER()`, read at each re-probe). Only an IP literal counts: a host name there, such as `localhost` for a Unix socket, leaves nothing out;
- it comes from the agent's `program_name` (`databastion-agent`) when the source shows one;
- it carries no signal;
- the agent's reads of each object stay within `limits.max_sample_rows` rows over a rolling 24 h. The audit-log sources have no row count, so each statement is charged the whole budget: a second read of a table within 24 h is reported.

Behind a proxy every client has the proxy's address, and another process on the agent host shares the agent's address. Someone holding the agent's credentials on the agent host, spoofing its `program_name` and reading at most the budget per table and day with filtered queries stays unreported.

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
  The flood shows in the spool's dropped counters and the console's back-pressure metric. This is a residual of the Audit design ([ADR-0023](adr/0023-mysql-mariadb-audit-sources-and-levels.md)), recorded in [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md); caps per window and priority-aware eviction are phase-7 follow-ups.
- **Audit uses its own connections.** A `performance_schema` stream holds a session on the agent's account. Every 5 minutes the stream re-probes its prerequisites on another connection, and a file-source stream does too. Size `MAX_USER_CONNECTIONS` as in [05-security.md](05-security.md#recommended-database-accounts-read-only): 6 with `performance_schema`, 5 with an audit log file, plus one per additional Audit target on the account ([ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) decision 11). A connection refused at the limit fails the check or scan that needed it. For an Audit stream, the stream restarts after a backoff, counted in `audit_stream_failures_total`, and it can miss what ran in between.
- **Role privileges only partly visible on MariaDB.** `check()` evaluates the privileges held through roles, including a `performance_schema` grant held through a role, with the rules for direct grants (#70, [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md)). MySQL (8.0.19+) shows every applicable role. MariaDB shows a least-privilege account the grants of its current (default) role only: every other role is reported as `privilege.roles_not_evaluated`, and `PUBLIC` grants (10.11+) are not read.
- **Level of a target whose check timed out.** Targets that share an account take turns within the heartbeat's 10 s deadline. A target whose `check()` did not finish in time, or waited for its turn behind a slow check of the same account, is reported unreachable (`timeout`, `check.timed_out`) with level None for that heartbeat. This does not mean its Audit stream stopped.
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

As implemented: on PostgreSQL (P4-A) the agent uses the `application_name` and the whole-relation `COPY … TO STDOUT` parts of the `pg_dump` signature (not the `REPEATABLE READ` transaction) and the outbound `COPY` signatures; see [PostgreSQL Audit](#postgresql-audit). On MySQL / MariaDB (P4-B) the agent uses the `SQL_NO_CACHE`, `SHOW CREATE TABLE` and `FLUSH TABLES WITH READ LOCK` parts of the `mysqldump` signature, plus the dump tools' `program_name`, consistent snapshots and `LOCK TABLES`, as one heuristic `signature.mysqldump`, and the `INTO OUTFILE` / `INTO DUMPFILE` signature; see [MySQL / MariaDB Audit](#mysql--mariadb-audit). The MongoDB (phase 5) and OpenLDAP (phase 6) signatures are not implemented yet.

Signatures are easy to forge (`application_name` and `program_name` are chosen by the client). They are only **one** of the three signals; the volume × sensitivity combination remains the primary signal (see [02-architecture.md](02-architecture.md#exfiltration-detection-audit)). The console computes it from the row count the source reports ([ADR-0021](adr/0021-access-event-correlation.md)): an event without `rows` scores 0 and feeds no baseline (the contract has an optional `AccessEvent.bytes` since #60; no connector produces it yet, and the console stores and shows it but does not use it in the score, #62), so on a source that gives no volume only signatures, shapes and object or principal conditions can raise an incident. Sensitivity is per object (table, collection), not per column.

## Cost for the monitored database
| Source | Cost | Recommendation |
|--------|------|----------------|
| pgaudit (`read` class) | Medium: log volume | Restrict to sensitive roles and objects (`pgaudit.role`) |
| MariaDB `server_audit` | Low to medium | Filter out service accounts |
| `performance_schema` | Low | OK |
| MongoDB profiler level 2 | **High** | Avoid in production; level 1 with a suitable `slowms` |
| OpenLDAP `accesslog` | Low | Purge with `olcAccessLogPurge` |
