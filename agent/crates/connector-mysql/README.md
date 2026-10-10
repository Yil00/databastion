# databastion-connector-mysql

MySQL / MariaDB connector of the DataBastion agent: Discovery (P2-C,
[ADR-0018](../../../docs/adr/0018-mysql-mariadb-grants-and-connector.md),
[ADR-0020](../../../docs/adr/0020-mysql-mariadb-connector-as-merged.md)) and
Audit (P4-B). The Discovery side is described in
[agent/README.md](../../README.md#mysql--mariadb-connector); this page
records the Audit behavior that the user documentation (docs/08) builds on.

## Audit sources and level

`check()` and the Audit stream use the same probe and rule
(`check::choose`), re-evaluated every 5 minutes. In order of preference:

| Level | Condition | Source (`audit_source`) |
|---|---|---|
| Partial | `mysql.audit_log` readable by the agent, its plugin active and logging statements, **and** a record of it parsed by the stream in the last 24 h (Limited until then) | `mariadb_server_audit` or `mysql_audit_log` |
| Partial | `performance_schema` on, `events_statements_history_long` enabled with the consumers it depends on (`global_instrumentation`, `thread_instrumentation`, `events_statements_current`), readable by the account | `performance_schema` |
| Limited | only `events_statements_history` (per thread) or `events_statements_current` active and readable | `performance_schema` |
| None | none of the above | — |

**Full is never reported.** Neither `server_audit` nor `audit_log` /
`audit_log_filter` logs the rows a statement returned, so the audit-log
sources miss the volume; `performance_schema` has volumes but loses
statements (ring buffer) and the account of sessions that ended before the
poll. The console scores an event without `rows` 0 (ADR-0021): on the
audit-log sources, only signatures, shapes and object or principal
conditions raise incidents.

| Source | Server setup | `agent.yaml` |
|---|---|---|
| MariaDB `server_audit` | `plugin_load_add = server_audit`, `server_audit_logging = ON`, `server_audit_output_type = file`, `server_audit_events` including `QUERY` (or `QUERY_DML`) and `TABLE` (empty = all) | `mysql.audit_log: {path: …/server_audit.log, format: server_audit}` |
| Percona `audit_log` plugin | `plugin-load-add = audit_log.so`, `audit_log_format = JSON`, `audit_log_policy = ALL` or `QUERIES` | `mysql.audit_log: {path: …/audit.log, format: json}` |
| Percona `audit_log_filter` component (8.4), MySQL Enterprise JSON | component installed, `audit_log_filter.format = JSON`, a filter logging the accounts to audit | `mysql.audit_log: {path: …/audit_filter.log, format: json}` |
| `performance_schema` (MySQL Community, or no readable log) | `performance_schema = ON` and the consumers above (MariaDB leaves `events_statements_current` off by default: enable it) | none |

The XML and CSV `audit_log` formats and the syslog outputs are not
supported (the configuration refuses them; a server writing them is noted by
`check()` and not used).

## Grants and file access

- **Audit-log sources: no database grant.** The agent reads the file
  through the file system on its own host (the log path never goes through
  SQL). Give the agent's OS user read access to the log directory only
  (for example an ACL `u:databastion:rx` on the directory and default ACL
  `u:databastion:r` for the files the server creates), never to the data
  directory. The dev environment makes the files `0644` (`UMASK` in
  `dev/docker-compose.yml`), a dev-only convenience. The plugin probes
  (`information_schema.PLUGINS`, `@@server_audit_*`, `@@audit_log_*`,
  `@@audit_log_filter.format`) need no privilege.
- **`performance_schema` source: `GRANT SELECT ON performance_schema.* TO
  'databastion'@…`**, only when Audit is enabled for the target
  (ADR-0018 decision 1). It exposes the statement text of every session,
  literals included, and on MariaDB clear-text passwords (see below). The
  connector reads `DIGEST_TEXT` first (literals already replaced by the
  server) and `SQL_TEXT` only for a statement without a digest, and puts
  any text through the query normalizer. `check()` reports this grant as
  over-privilege (`SELECT on performance_schema without Audit enabled`)
  while no Audit stream runs for the target; while one runs, it says
  nothing when `performance_schema` is the source, and reports the grant as
  unused (`SELECT on performance_schema unused`) when the audit log is the
  source (on MariaDB it exposes clear-text passwords for nothing). No other
  grant is added: no `PROCESS`, no global privilege.
- `USER()` gives the agent's own client address as the server sees it; no
  privilege needed.

## Password masking by engine (ROADMAP P4-D research)

Measured on the dev images (MariaDB 11.4.13, MySQL 8.4.11, Percona Server
8.4.11-11) with `CREATE USER … IDENTIFIED BY`, `ALTER USER … IDENTIFIED
[WITH plugin] BY`, `SET PASSWORD [= PASSWORD(…)]`, `GRANT … IDENTIFIED
BY`, `IDENTIFIED VIA … USING PASSWORD(…)`, `CHANGE MASTER TO
MASTER_PASSWORD` / `CHANGE REPLICATION SOURCE TO SOURCE_PASSWORD`, and
`CREATE SERVER … OPTIONS (PASSWORD …)`:

| Where | What the server writes |
|---|---|
| MariaDB `server_audit` log | password replaced by `*****` for every form above (`QUERY_DCL` / `QUERY_DDL` events; with `QUERY_DML` these statements are not logged at all) |
| MariaDB `performance_schema` `SQL_TEXT` | **the password in clear** for every form above; `DIGEST_TEXT` has `?` |
| MySQL 8.4 `performance_schema` `SQL_TEXT` | `<secret>` (the server rewrites the statement); `DIGEST_TEXT` has `?` |
| Percona `audit_log` / `audit_log_filter` | `<secret>` (the rewritten statement) |

The agent does not rely on these masks: every literal is replaced by the
normalizer whatever the statement, a statement that does not lex (a
password cut by `server_audit_query_log_limit` or
`performance_schema_max_sql_text_length`, an unterminated quote) keeps no
text and no names, and only DML keeps a normalized text (which never leaves
the agent anyway: the contract has no field for it). A password typed
without quotes is a syntax error; the connector drops statements the server
could not parse (errors 1064, 1149).

Character sets: in gbk, big5, sjis, cp932 and gb18030, `\` (0x5c) and a
backtick (0x60) can be the second byte of a two-byte character, which the
server reads as part of the character and a byte-level lexer as an escape
or a quote. Statement texts are kept as raw bytes: text that is not UTF-8,
or that has a byte >= 0x80 directly followed by 0x5c or 0x60, keeps only
its statement kind (the event names `*`), never names. The second rule
does not apply to `performance_schema` texts, which the server has already
transcoded to UTF-8 (read through a utf8mb4 connection), so non-ASCII
identifiers stay readable there; on the audit log files it applies to any
such pair, UTF-8 or not. A JSON record that
is not UTF-8 (a latin1 client) is parsed from a lossy decoding with its
text treated the same way, instead of being dropped.

## Signals

`signature.mysqldump` (whole-table read with `SQL_NO_CACHE`, a dump
`program_name`, or in a session that took a consistent snapshot, a global
read lock or `LOCK TABLES`, or ran `SHOW CREATE TABLE` on the table),
`signature.into_outfile` (`SELECT … INTO OUTFILE` / `INTO DUMPFILE`, also
refused ones), `shape.full_table_read`, and `volume.large_result`
(`performance_schema` only). Details in
[../classifiers/README.md](../classifiers/README.md#access-events-and-signals-adr-0007-p4-a).
Heuristic signals are evadable by design. Known evasions of
`signature.mysqldump`: a plain `SELECT *` per table (no `SQL_NO_CACHE`, no
dump `program_name`, no snapshot or lock); `mysqldump --skip-lock-tables`
without `--single-transaction` (no snapshot or lock evidence: only
`SQL_NO_CACHE` and the program name remain, which a modified client or
another tool does not send); chunked reads
(`mydumper` with a chunk size, `WHERE` ranges: no whole-table read); and a
statement padded past `server_audit_query_log_limit` or the
`performance_schema` text limit (the cut text gives no shape). Volumes
(`performance_schema`) and the console's volume × sensitivity score do not
depend on these. On the audit log files, a client can also strip every
text-derived signal (`signature.*`, `shape.*`) from its statement by adding
a non-ASCII character just before a backslash or a backtick (`` 1 AS `é` ``,
`/* é\ */`): the statement keeps only its kind (the multibyte rule above),
so it is still reported, against `*`, but without signals. The
`server_audit` TABLE records still name the tables; the Percona
`audit_log_filter` `table_access` records too.

## Audit connections

A `performance_schema` stream holds one session on the agent's account. It
re-probes its prerequisites (every 5 minutes) **on that session**, and
closes a stale or broken session **before** opening its replacement (phase
7), so the stream holds one connection at a time; the probe's session
becomes the stream's session when `performance_schema` is chosen. A
file-source stream holds no session: its re-probe opens one and closes it.
The only other Audit connection is the `KILL QUERY` sent when a guarded
Audit statement is cancelled (the stream stopped or reconfigured
mid-statement), opened while the Audit session still exists. ADR-0025
decision 11 counts that connection in the same slot as the re-probe and
the reconnect, so the sizing is unchanged: keep `MAX_USER_CONNECTIONS 6`
with a `performance_schema` stream (5 with an audit log file), plus one per
additional Audit target on the account. What changed is that a re-probe or
a reconnect no longer competes with a `KILL QUERY` for that slot.

## Known limits

- **No volumes on the audit-log sources** (above).
- **At-most-once delivery**, as for PostgreSQL: the log cursor advances once
  the events are handed to the core, which aggregates them for up to
  `aggregation_window_s`; an agent crash within that window loses them. On
  `performance_schema` the cursor (end timers and ids of the statements
  read, never a statement) is persisted with the server's start time
  (`SHOW GLOBAL STATUS LIKE 'Uptime'`) after each poll (phase 7): an agent
  restart resumes after the last statement read when the server did not
  restart, and reads a restarted server's statements from its start;
  what the history no longer holds (`events_statements_history_long`
  wrapped while the agent was stopped) is lost and counted. The sessions'
  accounts are not persisted: a statement of a session that ended while
  the agent was stopped is reported as an unidentified account. Without a
  saved cursor (first start, or the start time unreadable: a saved cursor
  is then removed), reading starts at the newest statement. The cursor is removed while an audit log file
  is the source, so a later switch back does not re-read that period.
- **First start / rotation while stopped**: without a cursor, reading
  starts at the end of the log. A log rotated while the agent was stopped
  is read from the start of the new file. A log truncated in place
  (`copytruncate`) while the agent was stopped is detected by the keyed
  fingerprints of the saved cursor, even when it has grown back past the
  saved offset: the cursor and its replay are discarded and the file is
  read from its start (logged, `audit_cursor_reset_total`), so no new
  record is skipped as already reported (end-of-phase-7 review L1; see
  the agent README).
- **`server_audit` times are local**: converted with the server's system
  time-zone offset read at stream start and every 5 minutes (a DST change
  in between shifts times by the difference until the next re-probe).
  Times are never later than the agent's clock.
- **`server_audit` with `QUERY_DML`** logs no `SHOW`, `FLUSH`, `LOCK` or
  `START TRANSACTION`: only the `SQL_NO_CACHE` and program-name rules of
  `signature.mysqldump` apply there (both match `mysqldump` and
  `mariadb-dump`). `server_audit` also has no `program_name`.
- **`performance_schema`**: a ring buffer (`…_history_long_size`), polled
  at `poll_interval_s`; a wrap between two polls is logged. The account,
  client host and `program_name` are read from the live session: a session
  that ended before the poll (a short `mysqldump` run) is reported as an
  unidentified account (a `db_user` fingerprint, which the console treats
  as unknown). Statements running inside stored programs are reported with
  their own text.
- **Objects**: from the table records (`server_audit` `TABLE`,
  `audit_log_filter` `table_access`) when present, otherwise from the text
  (the legacy `audit_log` and `performance_schema` log no table), for reads
  and writes only: DDL and DCL events take no name from the text (it can
  hold program bodies, such as MySQL JavaScript routines, that the SQL
  lexer does not delimit), except `CREATE TABLE … AS <query>` and
  `CREATE` / `ALTER … VIEW … AS <query>`, which hold no body: one DDL
  event names the created table or view and the sources of the query, as
  an `INSERT … SELECT` write names its target and sources. A read whose
  values go into variables (`SELECT … INTO @v`, `@v := …`, `SET` / `DO`
  with a subquery) is always reported, with no row count, and never the
  agent's own (docs/08). An unqualified name is in the statement's
  current database. A name holding
  a dot is sent as `*` (as in Discovery). A text that does not lex (cut at
  the server's limit, an ambiguous `sql_mode` reading) and `CALL` are
  reported against `*`. Under `ANSI_QUOTES`, a `"…"` name is not read
  (never a name), so such an object is missed or `*`.
- **One event per statement.** The table records and the statement record
  of one statement are grouped per connection id and query id (without
  query ids, `audit_log_filter`: by text), not by position in the log:
  concurrent sessions interleave their records (`READ a`, `READ b`,
  `QUERY a`, `QUERY b`). A statement's table records wait for its statement
  record across polls and log rotations; they are reported without it at
  the connection's next statement, its disconnect, after 11 minutes (longer than the
  longest `statement_timeout_ms`), when
  the audit source changes, or when more than 1024 connections have a
  statement waiting (the oldest first; logged and counted in the
  heartbeat metric `audit_pending_evicted_total`). The waiting state is
  bounded: 1024 statements, 64 distinct tables each, 16 MiB in all (names
  of at most 1 KiB each, statement text, which only JSON `table_access`
  records carry, and a fixed overhead per record); the memory of
  statements reported early is at most 16384 statements of 64 table
  hashes (8 MiB). A statement
  reported before its statement record is remembered by its query id and
  the tables already reported: a late table record of one of these tables
  is ignored, one of another table is reported (with the statement record
  when it comes, or at the next flush), and a late statement record alone
  yields a second event only when its text shows a signal (a whole-table
  read by a dump that ran longer than 11 minutes). That memory is kept 22
  minutes.
  The saved cursor is moved back to the first record of the oldest
  statement still waiting in the current file, with the end read so far
  and the connections waiting (`Tailer::commit_from`): after a restart, a
  crash, a stream restart or a reconfiguration, the stream re-reads from
  there and replays only the waiting statements' records, so they are
  neither lost nor counted twice. The replay applies only when the bytes
  before the saved offset and end still match the cursor's keyed
  fingerprints; otherwise (the log was truncated or rewritten while the
  agent was stopped) it is dropped and the file is read from its start. A
  replayed statement has been waiting
  since its log time, not since the restart: an agent that restarts more
  often than every 11 minutes still reports it after 11 minutes, and its
  cursor moves on instead of staying pinned to it. When the stream ends gracefully (the
  source changes, the log becomes unreadable), the waiting statements are
  reported and the cursor saved without them. Residuals: statements
  waiting in a rotated (earlier) file are lost if the agent stops before
  their statement record (the old file cannot be re-read); the memory of
  statements reported early does not survive a restart or a new stream,
  so their late statement record is then reported on its own (with the
  objects its text names). Without query ids (`audit_log_filter`), two
  consecutive statements of one connection with the same text whose table
  records are not separated by the first one's statement record are merged
  into one event (the log gives no way to tell them apart): such repeats
  are undercounted. Stored procedures: MariaDB 11.4 (checked on 11.4.13)
  gives each statement of a procedure its own query id, with its own table
  and statement records, and logs the `CALL` last with none; each is
  reported on its own, the `CALL` against `*`. The late-table rule above
  does not depend on it. `performance_schema` has one row per statement
  (deduplicated on thread and event id), so it has no grouping. Before
  phase 7 (load tests) records were merged only when adjacent, and
  interleaved sessions counted about 12 % of their statements twice.
- **The agent's own account.** Its statements are left out only when they
  come from its account, from its client address as the server sees it
  (`USER()`, read at each re-probe; a host name there, such as `localhost`
  for a Unix socket, leaves nothing out), with its `program_name`
  (`databastion-agent`) when the source shows one, carry no signal, and the
  agent's reads of the object stay within `limits.max_sample_rows` rows
  over a rolling 24 h (the audit-log sources have no row count: each
  statement is charged the whole budget, so a second read of a table
  within 24 h is reported). Limits of the address check, as for
  PostgreSQL: behind a proxy every client has its address, and another
  process on the agent host shares the agent's address. Residual: someone
  holding the agent's credentials on the agent host, spoofing its
  `program_name` and reading at most that many rows per table and day with
  filtered queries stays unreported.
- **Statement-text tables** (ADR-0045 part (a)): reads of the system
  tables that hold other sessions' statement texts
  (`audit::events::STATEMENT_TEXT_TABLES`: `performance_schema`
  `events_statements_*`, `threads`, `processlist`, `data_locks`,
  `information_schema.PROCESSLIST`, `INNODB_TRX`, the `sys` session and
  lock-wait views…), and `SHOW [FULL] PROCESSLIST`, are read events naming
  them, always reported, never the agent's own; `SHOW ENGINE INNODB
  STATUS` and the plan of another connection (`SHOW EXPLAIN`, `EXPLAIN …
  FOR CONNECTION`) are reads of `*`. The agent's own `performance_schema`
  polls are constant texts (the server computes their own thread and
  `SQL_TEXT` threshold; only the cursor is a session user variable,
  `sql::ps_poll_variables`), left out uncharged only by their whole uncut
  text with table records of their own tables
  (`sql::own_performance_schema_reads`); its readability probes are
  `EXPLAIN`s (the same privilege, no row read, quiet). Details:
  [docs/08](../../../docs/08-engine-capabilities.md#statement-text-tables).
- **Forged records**: the audit logs are written by the server only; a
  client can put any text in a statement, but not a newline (escaped by
  `server_audit`, JSON-encoded by `audit_log`), so it cannot add records.
  `server_audit` escapes `'`, `\`, newline, carriage return, tab,
  backspace and form feed; a record with any other escape is kept with
  its text used for the statement kind only (the event names `*`). A
  damaged JSON record is dropped, the following ones are kept; records
  dropped (not parsable, oversized, damaged) are counted and shown by
  `check()` for 24 h.
- **Failed statements** are skipped only when the server refused them
  before reading anything, they sent no row, and (audit log files) the log
  has no table read record for them: a syntax error (1064,
  1149; never an event), an unknown database, table or column (1049, 1051,
  1054, 1109, 1146), an ambiguous or duplicate name (1052, 1066), access
  denied (1044, 1142, 1143, 1227, 1370) or an unknown routine (1305);
  `INTO OUTFILE` attempts are kept. The table-read condition closes an
  evasion: a function can `SIGNAL SQLSTATE … SET MYSQL_ERRNO = 1146` after
  rows were sent; the log's READ / `table_access` records show the read,
  so the statement is reported (a genuine 1146 has no such record). Any other failure (a timeout or kill
  after rows were sent, 3024, 1317…), and on `performance_schema` any
  statement with `ROWS_SENT > 0`, is reported. Session state (snapshot,
  `SHOW CREATE TABLE`) is only recorded from statements that succeeded. Failed connections become `auth_failure` events with a
  fingerprinted account, except handshake network errors (a port probe).

## Tests

- Unit tests: `src/audit/records.rs` (log formats, escapes, times, fail
  closed), `src/audit/events.rs` (grouping, objects, signals, own account,
  sessions), `src/check.rs` (source choice, levels, the
  `performance_schema` grant rule), `src/sql.rs` (the poll statement reads
  text only through the digest rule; the poll texts are constant).
- Normalizer property tests: `../classifiers/tests/query_mysql_props.rs`.
- Integration tests against `dev/` (`src/it/audit_it.rs`): the MariaDB
  `server_audit` log, the Percona `audit_log_filter` JSON log and
  `performance_schema` on MySQL and MariaDB, each with a simulated and a
  real `mysqldump` / `mariadb-dump` run, `INTO OUTFILE`, a marker literal
  that must reach no event and no log line, the agent's own Discovery scan,
  and the agent's address as the server sees it (the Docker bridge gateway
  in CI). Environment variables are listed at the top of that file; CI
  requires them (`DATABASTION_TEST_REQUIRE`).
- Statement-text tables (`src/it/stmt_text_it.rs`): the drift test of the
  list against each server's `information_schema.COLUMNS` (engine matrix),
  and a second account's reads of `events_statements_history_long` and
  `information_schema.PROCESSLIST` reported, while the agent's own probes
  and polls (two targets on one server) are not.
