# ADR-0045: MySQL / MariaDB Audit reports reads of the system tables that hold statement text, and unqualified calls of functions that are not built in

- **Status**: Accepted (2026-10-09; the maintainer accepted the recommended answers to the eight open questions)
- **Date**: 2026-10-09
- **Refines**: [ADR-0023](0023-mysql-mariadb-audit-sources-and-levels.md) (which stays Accepted): decision 4 (what the statement analysis takes from a text) and decision 6 (the agent's own account, as already refined by [ADR-0027](0027-mongodb-audit.md) decision 7: reads and connections only). Levels (decision 2) and sources (decision 1) are unchanged.
- **Context references**: ROADMAP [phase 8 follow-ups](../ROADMAP.md#phase-8-follow-ups) (the `performance_schema` / `sys` / `information_schema` statement-text item from the review of #165, and the unqualified function call item from the reviews of #168); [08-engine-capabilities.md, MySQL / MariaDB Audit, Known limits](../08-engine-capabilities.md#known-limits-1); `agent/crates/connector-mysql/src/audit/events.rs` (`is_system_schema`, `is_system_relation`, the CAS store guard's exact-text rule), `agent/crates/connector-mysql/src/sql.rs` (`PS_*`, `ps_stats`, `ps_statements`), `agent/crates/classifiers/src/query.rs` (`has_function_call`, `has_qualified_call`, `is_audit_function`), `agent/crates/core/src/audit.rs` (`reportable`: the `audit.configure` filter)

## Context

Two residuals of the MySQL / MariaDB Audit analysis are documented in [08-engine-capabilities.md](../08-engine-capabilities.md#known-limits-1) and listed as phase 8 follow-ups. Both leave a read of personal data with **no access event, from any account**, on every source.

### (a) Reads of the system tables that hold statement text

Objects in `information_schema`, `performance_schema` and `sys` (with the internal statistics tables and `DUAL`) are dropped from the objects of **reads**, and a read left with no object produces no event (`is_system_relation`). Writes to them have been reported since #168. The rule was made for noise: drivers, ORMs, admin tools and the agent itself read the dictionary all the time, and `information_schema.TABLES` holds no row of application data.

Some of these tables are not metadata, though. They hold **the statement texts of other sessions, with their literal values**: `WHERE email = 'alice@example.org'`, `INSERT … VALUES ('FR76…')`, and on MariaDB `performance_schema` `SQL_TEXT` the clear-text passwords of `CREATE USER` / `SET PASSWORD` (ADR-0023 decision 4). An account with `SELECT ON performance_schema.*`, or with `PROCESS`, can read them without an event. The agent's own account holds that grant whenever `performance_schema` is its Audit source, so a stolen agent credential reads them unseen too.

What the agent itself sends to these tables (`connector-mysql/src/sql.rs`):

| Statement | Tables | Text |
|---|---|---|
| `PS_CONSUMERS` (`check()` and re-probe) | `performance_schema.setup_consumers` | constant |
| `PS_HISTORY_LONG`, `PS_HISTORY`, `PS_CURRENT` (`COUNT(*)`, readability probes) | `events_statements_history_long`, `_history`, `_current` | constant |
| `PS_OWN_THREAD` | `threads` | constant |
| `ps_stats(table, own_thread)` (each poll) | `events_statements_current` and the polled table | **varies**: the thread id is a literal |
| `ps_statements(table, own_thread, from, limit, with_program, sql_text_from)` (each poll) | the polled table, `threads`, `session_connect_attrs` | **varies**: thread id, timer, text threshold are literals |

The poll statements exclude their own thread (`h.THREAD_ID <> own_thread`), so a stream never sees its own polls. Others can see them: the `check()` probes run on heartbeat sessions, which the poll does see; a second target declared on the same server has its own stream; and when the source moves between `performance_schema` and an audit log file (re-evaluated every 5 minutes), the log has the earlier statements.

### (b) Unqualified function calls

`SELECT f()`, `DO f()` and `SET @x = f()` name no table. When `f` is a **stored function** (`CREATE FUNCTION`), its body can read any table its definer can read: `SQL SECURITY DEFINER` is the default, a function can return a `GROUP_CONCAT` of a whole table (`group_concat_max_len` is a session variable), and a loop of `SELECT get_customer_email(n)` reads a table row by row. An application account that holds only `EXECUTE` on a function created by a privileged account reads data it cannot read with `SELECT`. **That is the real risk**: the read is invisible, and it can bypass table privileges by design.

Today, an unqualified call in a table-less statement produces no event, because the agent cannot tell `f()` from `NOW()`. The exceptions are the audit log administration functions (a closed list, DDL) and, being added now, `LOAD_FILE(` (`*`, always reported, never the agent's own; #168 review L2). Schema-qualified calls (`hr.f()`) are reported against `*` since #168, always reported and never the agent's own. Whether the function body's own statements show up depends on the source: MariaDB `server_audit` logs the statements of a stored procedure on their own (checked on 11.4.13); this was not checked for stored functions, and `performance_schema` records nested statements (`statement/sp/stmt`, `NESTING_EVENT_ID`) only when those instruments are enabled.

How the servers resolve an unqualified name followed by `(` (MySQL 8.4 reference manual, "Function Name Parsing and Resolution"; MariaDB knowledge base): built-in functions come first, then loadable functions (UDFs, component functions), then a stored function **of the default database**. A stored function that shares a built-in's name must be called with its schema. So "not a built-in" is exactly "may be a stored function or a loadable function". The servers have some exceptions, to verify per series: built-in names that are keywords and are followed by a space without `IGNORE_SPACE`, and MariaDB `sql_mode=ORACLE`, which adds names.

## Options

### Part (a)

- **(a1) Name the statement-text tables in read events.** Keep dropping every other system object from reads, but name the tables of a closed list, so a read of them is a read of named objects, as any table read is. Policies and per-principal baselines can then scope them.
- **(a2) Report every read of the system schemas.** This is the noise the rule was made against: every ORM's `information_schema.COLUMNS` read, every driver's `SHOW` and dictionary query.
- **(a3) Keep the residual** (documented today).

### Part (b)

- **(i) A per-version list of built-in names.** An unqualified call of a name that is not on the list for the server's flavor and series is a possible stored (or loadable) function. It is reported against `*`, like a schema-qualified call: always reported, and never the agent's own.
- **(ii) Every table-less statement with any function call is a read of `*`.** This catches everything, but `SELECT NOW()`, `SELECT LAST_INSERT_ID()`, `SELECT DATABASE()`, Connector/J's and the Python and Go drivers' session probes, and pool pings with a function would each become an event. Most applications would get several per connection and window, on every source.
- **(iii) Keep the residual** (documented today).

## Decision

### Part (a): option (a1)

1. **The statement-text tables.** Reads of these tables keep their objects, compared ASCII-case-insensitively on the resolved schema and table name (an unqualified name resolves in the statement's current database, as today). This is the candidate list. The drift test of decision 5 confirms it on each engine-matrix image before implementation, and the implementation writes the confirmed list into docs/08:

   | Table | Column with statement text | MySQL 8.0 / 8.4 / 9.x | MariaDB 10.11 / 11.4 / 11.8 |
   |---|---|---|---|
   | `performance_schema.events_statements_current`, `_history`, `_history_long` | `SQL_TEXT` (literals; MariaDB: clear passwords) | yes | yes |
   | `performance_schema.events_statements_summary_by_digest` | `QUERY_SAMPLE_TEXT` (literals; MySQL 8.0.3+) | yes | no such column (to verify on 11.8); digest only, not listed |
   | `performance_schema.prepared_statements_instances` | `SQL_TEXT` (the prepared text) | yes | yes (10.5+) |
   | `performance_schema.threads` | `PROCESSLIST_INFO` | yes | yes |
   | `performance_schema.processlist` | `INFO` | yes (8.0.22+) | no such table |
   | `information_schema.PROCESSLIST` | `INFO` (and `INFO_BINARY` on MariaDB); other sessions need `PROCESS` | yes | yes |
   | `information_schema.INNODB_TRX` | `trx_query`; needs `PROCESS` | yes | yes |
   | `information_schema.QUERY_CACHE_INFO` | `STATEMENT_TEXT` (`query_cache_info` plugin) | no | when the plugin is loaded |
   | `sys.processlist`, `sys.x$processlist`, `sys.session`, `sys.x$session` | `current_statement`, `last_statement` | yes | yes (`sys` since 10.6) |
   | `sys.innodb_lock_waits`, `sys.x$innodb_lock_waits` | `waiting_query`, `blocking_query` | yes | yes (10.6+) |
   | `sys.schema_table_lock_waits`, `sys.x$schema_table_lock_waits` | `waiting_query` (to verify) | yes | yes (10.6+) |

   A table holding only digests (`DIGEST_TEXT`, literals replaced by the server) is not listed. Neither are the other summaries, the `setup_*` tables (whose writes are already reported) and the dictionary views. Already reported today, unchanged: `mysql.general_log` and `mysql.slow_log` with `log_output = TABLE` (the `mysql` schema is not a system schema for the agent), a user view built on these tables (named by its own name), and the `sys` routines that return statement texts (`sys.ps_thread_trx_info()`, `CALL sys.ps_trace_thread(…)`: schema-qualified calls and `CALL`, reported against `*`).
   **Added by the answer to open question 1**: `performance_schema.data_locks` (`LOCK_DATA`, MySQL 8.0+) and `information_schema.INNODB_LOCKS` (`lock_data`, where the server has it), whose lock data holds values of locked index records, are on the list too; digest-only tables stay out.
2. **`SHOW [FULL] PROCESSLIST`** is analyzed as a read of `information_schema.PROCESSLIST`, today a quiet `SHOW`. This holds whatever the server reads it from (MySQL 8.0.22+ with `performance_schema_show_processlist` reads `performance_schema.processlist`). `SHOW ENGINE INNODB STATUS` is a read of `*`, always reported and never the agent's own (open question 3); MariaDB `SHOW EXPLAIN FOR` / `SHOW ANALYZE FOR` are decided once verified on 11.4 (reported as reads of `*` if they show another session's statement text).
3. **Always reported.** A read event that names a statement-text table is marked always reported (the agent-internal mark of #168, never sent nor spooled), so the `audit.configure` filter never drops it. Without the mark, a `min_rows` setting would drop it on the file sources (no row count: `reportable` needs `rows >= min_rows`), and on `performance_schema` whenever a monitoring poll returns few rows: the change would be invisible exactly where it matters. The other objects of the statement are named as usual. No signal is added: `volume.large_result` (more than 10 000 rows) keeps its meaning, and the default `events_statements_history_long` size is 10 000.
4. **The agent's own account.**
   - **Constant poll texts.** `ps_stats` and `ps_statements` become constant texts: the thread id, the timer and the `SQL_TEXT` threshold move to session user variables, set by one `SET @databastion_thread = …, @databastion_from = …, @databastion_text_from = …` on the same session right before. A session `SET` of user variables is a quiet statement today (no event). The `LIMIT` is the constant `BATCH`. That leaves 3 tables × 2 (`program_name` subquery or not) poll texts and 3 `ps_stats` texts, each kept within the 900-byte rule of the agent's statements.
   - **Exact text, as the CAS store guard.** A statement of the agent's identity (account, client address as an IP literal, `program_name` when the source shows one, no signal) is left out **uncharged** only when it meets all of these:
     - its whole text equals one of these constant texts: the probes `PS_HISTORY_LONG`, `PS_HISTORY`, `PS_CURRENT`, `PS_OWN_THREAD`, the poll and stats texts above, and `PS_CONSUMERS`, which reads no listed table and needs no change;
     - the source does not mark the record as cut;
     - its table records (if any) read only the tables that text names.

     It is never matched by prefix, by digest or by shape. A digest-only record cannot match, because the rule needs the uncut `SQL_TEXT`, which `ps_statements` already reads for the agent's own sessions.
   - **Never the agent's own otherwise.** Any other read of a statement-text table with the agent's identity is reported, whatever the per-object row budget: the agent sends no other statement to these tables. Charging the budget instead would let a stolen agent credential read up to `limits.max_sample_rows` statement texts per table and day unseen.
   **Refinement (2026-10-09, implementation of part (a))**:
   - `check()`'s readability probes of `events_statements_*` are `EXPLAIN SELECT 1 FROM …` instead of `SELECT COUNT(*)`. A heartbeat session ends before the next poll, so the poll sees it with no account and digest text only, and the exact-text rule could never match it. `EXPLAIN` needs the same `SELECT` privilege, reads no row and is quiet for every account; checked on MySQL 8.4 and MariaDB 11.4: error 1142 without the grant, 1146 for a missing table.
   - MariaDB `EXPLAIN` / `DESCRIBE … FOR CONNECTION`, and MySQL `EXPLAIN FORMAT=TREE FOR CONNECTION`, show another session's statement or its literals. They are reads of `*`, always reported, like `SHOW EXPLAIN` / `SHOW ANALYZE` (verified on MariaDB 10.11, 11.4 and 11.8).
   - At the analyzer's bounds (16 relations per statement, 64 statements per text), a statement adds `*`, is always reported and is never the agent's own, so a listed table past the bound cannot be dropped silently.
5. **Drift test** (integration, engine matrix). On each image, a query lists every column of `information_schema`, `performance_schema` and `sys` whose name is in a closed set of statement-text column names (`SQL_TEXT`, `QUERY_SAMPLE_TEXT`, `INFO`, `INFO_BINARY`, `PROCESSLIST_INFO`, `trx_query`, `STATEMENT_TEXT`, `current_statement`, `last_statement`, `waiting_query`, `blocking_query`) or that ends in `_query` / `_statement`. The test fails when such a table is missing from the list for that flavor and series, as the MongoDB guard drift test (#162) does for MongoDB. A new server version that adds such a table fails the weekly engine-matrix run instead of being missed silently.
6. **I2.** Only names leave the agent: fixed system table names, through the existing normalization ([ADR-0009](0009-name-normalization-and-item-sanitization.md)). No column of these tables is read by the analysis, no statement text is kept beyond what decision 4 of ADR-0023 already allows, and the `AccessEvent` contract is unchanged (objects are names; no new field, signal or note).

### Part (b): option (i)

7. **Built-in name lists.** The server parser's tables are the source of truth, per flavor and release series:
   - MySQL: `sql/item_create.cc`, the native function registry, plus the keyword functions of `sql/sql_yacc.yy` / `sql/lex.h`;
   - MariaDB: `sql/item_create.cc` `native_func_registry_array` and its Oracle-mode overrides, the keyword functions of `sql/sql_yacc.yy` / `sql/lex.h`, and the functions of the plugins built in by default (for example `type_inet`, `type_uuid`).

   A script in `agent/crates/connector-mysql/builtins/` extracts them at a pinned source tag and writes one sorted, committed list per series (MySQL 8.0, 8.4, each 9.x; MariaDB 10.11, 11.4, 11.8; Percona Server takes the MySQL list of its series). It also records the tag, and adds the other words that may come before `(` in a table-less statement without being a call: type names in `CAST` / `CONVERT` (`DECIMAL(`, `CHAR(`), `INTERVAL`, `OVER`, `AGAINST`, `IN`, `VALUES`. The checks against the server are in decision 11: `mysql.help_topic` and an empirical probe. The documentation is a cross-check only, never the source.
8. **Which list.** The connector picks the list from the flavor and version it already reads at connect. For a newer series than the newest list, it uses the newest list of the flavor and logs it once: names added since then are reported (fail closed). A series older than the oldest list is end of life ([ADR-0039](0039-engine-scope-expansion.md) decision 1) and uses the oldest list. A union over all series is not used: a stored function named after a function added in a later series (a `VECTOR_DIM` created on 8.4) would hide behind it. In MariaDB, a name built in only under `sql_mode=ORACLE` counts as not built in (fail closed), because the session's `sql_mode` is unknown (ADR-0023 decision 4).
9. **Analysis.** A name followed by `(`, unqualified, in any statement, is an **unknown call** when it is not on the list. This covers `SELECT`, `DO`, `SET`, a `WHERE`, a select list, a `VALUES` list and a `CALL` argument. It does not cover a table with a column list in the positions `has_qualified_call` already excludes. The name and its quoting (plain, backquoted, or double-quoted under `ANSI_QUOTES`, both readings) are compared in place on bytes and never kept. An unknown call:
   - adds `*` to the event's objects, so a table-less statement becomes a read of `*`, and a statement that names tables keeps them plus `*`;
   - is **always reported**, like a schema-qualified call (open question 6);
   - is **never left out as the agent's own**. A unit test proves that every statement the agent sends has no unknown call (the agent calls `USER()`, `CONNECTION_ID()`, `COUNT`, `MIN`, `MAX`, `LENGTH`, `SUBSTRING_INDEX`, `CONVERT_TZ`, `UTC_TIMESTAMP` and a few others, all built in).

   `LOAD_FILE(` keeps its own rule. The audit log administration functions stay DDL.
10. **No name leaves the agent.** The object is `*`, not the routine's name: event objects are tables in the contract, and a routine name from text is free text from an untrusted statement.
11. **Maintenance.**
    - **Drift test, both directions**, in the engine matrix, on each image:
      - every function name in `mysql.help_topic` (the help categories of functions) must be on the list or on a short, commented exception list (help entries that are not callable names);
      - each listed name, called with no argument in an empty schema (`SELECT name()`), must not fail with `ER_SP_DOES_NOT_EXIST` (1305, "FUNCTION … does not exist"), which is the server's own answer for a name that is not built in. Other errors, such as a wrong argument count, mean built in.
    - **Updates.** A new series gets its list in the same PR that adds it to the engine matrix. Until then, the drift test of the newest image fails the weekly run.
    - **False positives.** A built-in added by a newer server and not yet listed is reported as a read of `*`: more noise, never a blind spot. This is fail closed by design. Loadable functions (UDFs, component functions such as `version_tokens_*`, `keyring_*`) are not built in, so they are reported too. A UDF is native code that can read files, so this stays the decision; open question 7 asks whether operators may declare known loadable functions.

## Consequences

- **Code** (`agent-engineer`, `security-reviewer` review for both parts):
  - part (a): `connector-mysql`, in `audit/events.rs` (the statement-text set, the always-reported mark, `SHOW PROCESSLIST`, the own exact-text set) and `sql.rs` / `audit/pfs.rs` (constant poll texts with session variables);
  - part (b): `classifiers/src/query.rs` (the unknown-call detection, with a caller-provided built-in predicate so that the classifiers crate stays engine-version agnostic), plus `connector-mysql`, which holds the lists, picks one by version and wires them in.

  No `shared/protocol/` change: no new signal, note or field, and `*` already has its meaning.
- **Tests**:
  - part (a): unit tests for each listed table (qualified, unqualified with a current database, backquoted, in a `JOIN` with an application table, in a subquery of a `SET`), for a dictionary read that stays quiet, for `SHOW FULL PROCESSLIST`, and for each constant agent text left out uncharged, while the same text with one byte changed, cut, or with an extra table record is reported. Integration tests on MySQL 8.4 and MariaDB 11.4: a second account reads `events_statements_history_long` and `information_schema.PROCESSLIST` and gets read events naming them, and the agent's own polls and probes produce none. The drift test of decision 5 runs in the engine matrix.
  - part (b): a stored function reading `hr.customers`, called as `SELECT f()`, `DO f()` and `SET @x = f()`, is reported against `*` on every source. Each listed built-in, called table-less, gives no event. Unknown names are tested under backquotes and `ANSI_QUOTES`. The every-agent-statement test is extended. The drift test of decision 11 runs in the engine matrix. The query normalizer's property tests gain the guarantee that an unknown call never removes an object.
  - **Load harness** (`e2e/load/`, `load` job): the MariaDB scenario gains a monitoring-like reader (a PMM-style account reading `events_statements_summary_by_digest`, `threads` and `information_schema.PROCESSLIST` every second) and a table-less built-in mix (`SELECT NOW()`, `SELECT LAST_INSERT_ID()`, `SELECT DATABASE()`, driver session probes). The run must show at most one event per principal, object set and aggregation window for the reader, zero events for the built-in mix, Audit events still equal to the statements issued for the application load, and no change in agent CPU and memory beyond noise.
- **Volume.** Part (a) adds events only for accounts that read these tables. Aggregation bounds them: one event per principal, object set, action and source per `aggregation_window_s` (default 60 s), so a monitoring account polling three statement-text tables gives at most a few thousand events per day per target, under the console's per-target hourly cap ([ADR-0021](0021-access-event-correlation.md)). Part (b) adds events only for calls of non-built-in names: zero for applications that use no stored or loadable functions, and one aggregated event per principal and window for those that do.
- **Monitoring tools.** PMM (QAN and `mysqld_exporter` with the `info_schema.processlist` collector), Datadog DBM, `sys`-based Grafana dashboards and MySQL Workbench performance reports read these tables on a schedule. Their accounts will show regular reads of named statement-text tables. The per-principal baselines learn that pattern, and a console policy can match these objects by name for every other account, or exclude a known monitoring principal. There is no agent-side allow-list (open question 2).
- **Documentation** (`docs-keeper`, after the implementation): in [08-engine-capabilities.md](../08-engine-capabilities.md#mysql--mariadb-audit), the known limits "Reads of the system schemas are not reported, statement texts included" and "Unqualified function calls are not reported" become described behaviour, with the table list, the always-reported mark, the constant poll texts, the monitoring-tool note, the built-in lists and their false positives. [05-security.md](../05-security.md#recommended-database-accounts-read-only) notes that `PROCESS` and `SELECT ON performance_schema.*` reads are now visible. [10-user-guide.md](../10-user-guide.md) gains a sample policy for statement-text tables.
- **Estimated size.**
  - Part (a): about 300 lines of production code and 500 of tests, plus the drift test; 2 days with one review round.
  - Part (b): about 250 lines of analysis code, a 150-line extraction script, 7 generated lists (roughly 400 to 700 names each), 500 lines of tests and the two-way drift test; 3 to 4 days with one review round.
  - They are independent and can be two PRs.
- **Residual risks.**
  - A read through a user view, a stored function or a trigger over a statement-text table is named by what the statement shows (the view, or `*`), not by the listed table.
  - `SHOW ENGINE INNODB STATUS` (open question 3).
  - Within MySQL 8.0 only, a stored function named after a function added in a later 8.0 patch release is taken as built in on an earlier patch (open question 8).
  - A stored function shadowing a keyword built-in called with a space before `(` (to verify per series: such calls are treated as unknown when the drift test shows the server resolves them as stored).
  - A loadable function under a built-in name is either refused by the server or never called by an unqualified name (the built-in runs first; which of the two, per series, is to verify), so it cannot hide a read.
  - A function's body is invisible on sources that do not log nested statements. The `*` event says that a function ran and who ran it, not what it read.

## Rejected alternatives

- **Option (a2)**, every system-schema read: the noise the current rule exists for, with no gain on the dictionary views, which hold no row data.
- **Charging the own-account budget for the agent's reads of statement-text tables**, as for sampled tables: it would hide up to `max_sample_rows` statement texts per table and day read with a stolen agent credential.
- **Credits for the poll texts** (as the Discovery sampling batches use, granted before each poll): this works, but needs state, expiry and a residual for unlogged polls. Constant texts need none.
- **Prefix or digest matching of the poll texts**: a prefix match lets any statement that starts like a poll pass. A digest match replaces literals, so another `WHERE` value would match too.
- **Option (ii)**: every table-less call becomes an event (`SELECT NOW()`, driver probes), on every connection of every application.
- **A union list across series**: a stored function named after a built-in of a later series hides behind it.
- **Reading `information_schema.ROUTINES`** to learn the stored functions: the minimal agent grant sees only routines it has a privilege on, and a function created after the read is missed, so it cannot fail closed.
- **Naming the routine as the event's object**: event objects are tables, and the name is untrusted statement text.

## Open questions (answered)
Each answer is the recommendation of this ADR, accepted by the maintainer on 2026-10-09.

1. Is the candidate list of decision 1 the right scope: statement texts with literals only, with digest-only tables left out? Or should the digest tables (`events_statements_summary_by_digest` on MariaDB, `sys.statement_analysis`), which show which objects other sessions use but no values, and `performance_schema.data_locks` / `information_schema.INNODB_LOCKS` (`LOCK_DATA`: values of locked index records, such as a primary key that is an e-mail address) be added?
   **Answer (decided by the maintainer on 2026-10-09)**: statement texts with literals as proposed, plus `data_locks` / `INNODB_LOCKS`, whose `LOCK_DATA` holds row values; digest-only tables stay out.
2. Monitoring noise: rely on console-side policies and per-principal baselines, as proposed, or add an agent-side allow-list of principals (`mysql.audit_quiet_principals` in `agent.yaml`) whose reads of these tables produce no event?
   **Answer (decided by the maintainer on 2026-10-09)**: no agent-side allow-list. Monitoring credentials are often shared across hosts and hold exactly these grants, so silencing them in the agent hides the reads that matter. The aggregation bounds the volume, and the console can scope or exclude principals.
3. `SHOW ENGINE INNODB STATUS` (its transaction section can show other sessions' current statements; `PROCESS` needed) and MariaDB `SHOW EXPLAIN FOR` / `SHOW ANALYZE FOR` (whether they show another session's text is to verify): report them as reads of `*` (always reported), or keep them quiet and documented?
   **Answer (decided by the maintainer on 2026-10-09)**: report `SHOW ENGINE INNODB STATUS` as a read of `*`, always reported (exporters run it on a schedule, so it aggregates like the other monitoring reads), and decide `SHOW EXPLAIN` / `SHOW ANALYZE` once verified on 11.4.
4. Always report reads of statement-text tables (decision 3), or let the `audit.configure` filter apply, so that operators who want them add the tables to `sensitive_objects`?
   **Answer (decided by the maintainer on 2026-10-09)**: always report. With `min_rows` set, the file sources (no row count) would otherwise never report them, and nothing in the console would show they were missing.
5. Constant poll texts through session user variables (decision 4), or credits for the varying texts?
   **Answer (decided by the maintainer on 2026-10-09)**: constant texts. They need no state and no expiry, and they follow the CAS store guard's exact-text rule.
6. Unknown calls in statements that also name tables: always reported, like schema-qualified calls (proposed), or `*` added without the always-reported mark, like the double-quote backstop, so that `min_rows` still applies?
   **Answer (decided by the maintainer on 2026-10-09)**: always reported, as for schema-qualified calls: one rule for "code that runs out of sight". Applications that call stored functions in most statements get more events, but those calls are exactly where a read can hide.
7. Loadable functions (UDFs, component functions) are not built in and are reported. Should operators be able to declare known loadable function names per target in `agent.yaml`, to silence them?
   **Answer (decided by the maintainer on 2026-10-09)**: not in this ADR. Report them; revisit if the load runs or users show real noise. A loadable function is native code that can read files.
8. Part (b) scope: per series as proposed, or per patch release for MySQL 8.0, whose patch releases added functions?
   **Answer (decided by the maintainer on 2026-10-09)**: per series. The 8.0 list is the union of its patch releases, so on an early 8.0 patch a stored function named after a function added in a later 8.0 patch is taken as built in. MySQL 8.0 is end of life, the LTS and MariaDB series add no functions in patch releases, and each 9.x innovation release is its own series, so this residual stays limited to 8.0.
