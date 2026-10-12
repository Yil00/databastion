# databastion-connector-postgres

PostgreSQL connector of the DataBastion agent: Discovery (P2-B,
[ADR-0012](../../../docs/adr/0012-postgresql-agent-grants.md),
[ADR-0015](../../../docs/adr/0015-postgresql-connector-decisions.md)) and
Audit (P4-A). This page records the Audit behavior that the user
documentation (docs/08) builds on.

## Audit sources and level

| Level | Condition (same probe for `check()` and the stream) | Source |
|---|---|---|
| Full | `postgres.audit_log` readable by the agent, pgaudit loaded with the `read` class, `pgaudit.log_rows` proven on, `log_min_messages` and `log_min_error_statement` proven `error` or lower, **and** a pgaudit record parsed by the stream in the last 24 h | pgaudit log (`AUDIT:` records and `ERROR` / `FATAL` lines) |
| Partial | log readable and pgaudit logging reads (or object audit through `pgaudit.role`), but no `pgaudit.log_rows`, a log setting above `error` or not read, or no recent record | pgaudit log (`AUDIT:` records and `ERROR` / `FATAL` lines) |
| Limited | `pg_stat_statements` installed, loaded and showing other roles | `pg_stat_statements` |
| None | none of the above | — |

The source is re-evaluated every 5 minutes. `volume.large_result` on the
pgaudit source needs `pgaudit.log_rows = on`. `pg_stat_statements` is not a
volume source for Full: the stream never polls it alongside the pgaudit log
([ADR-0037](../../../docs/adr/0037-postgresql-full-requires-pgaudit-log-rows.md)).

"pgaudit loaded" is proven, not assumed: a `pgaudit.*` value set in
`postgresql.conf`, `ALTER DATABASE` or `ALTER ROLE` without pgaudit in
`shared_preload_libraries` is a placeholder that `current_setting()` still
returns. `shared_preload_libraries` is not readable without
`pg_read_all_settings`, so the probe requires the library's own
`pgaudit.log_catalog` setting, typed `bool`, in `pg_settings` (which hides
placeholders). Settings without the library give no pgaudit level (at best
Limited), with the note "pgaudit settings are set but the pgaudit library
is not loaded".

The proof, like every setting the probe reads, reflects **the agent's own
session** in each monitored database. A library loaded for some roles or
databases only (`session_preload_libraries`, `ALTER ROLE … SET
session_preload_libraries`, `LOAD`) or `pgaudit.*` values set per role
(`ALTER ROLE … SET pgaudit.log`) may differ for other roles: the level
says what holds for the agent's session, not that every role is audited
alike. pgaudit itself requires `shared_preload_libraries` (it refuses to
load otherwise), so a server-wide load is the normal case.

## Known limits

- **At-most-once delivery.** The log cursor advances once the events are
  handed to the core, which pre-aggregates them for up to
  `aggregation_window_s` before spooling them. An agent crash within that
  window loses those events; they stay in the database's own log.
- **First start / rotation while stopped.** Without a cursor, reading starts
  at the end of the log (no history). If the log was rotated while the
  agent was stopped, the rest of the previous file is not read. A log
  truncated in place while the agent was stopped (`copytruncate`,
  `log_truncate_on_rotation`) is read from its start, even when it has
  grown back past the saved offset: the cursor keeps a keyed fingerprint
  of the bytes before its offset, checked at open (mismatch: logged and
  counted in `audit_cursor_reset_total`; see the agent README).
- **Forged records.** Any role can write `AUDIT: …` lines into the server
  log (`RAISE LOG` in PL/pgSQL). The connector drops records whose severity
  is not `pgaudit.log_level` or that carry an error context (pgaudit hides
  its context; `RAISE` always has one). Still forgeable by native code
  that hides its context (C extensions, untrusted PLs).
  `log_error_verbosity = terse` does not remove the context from jsonlog
  nor csvlog (verified on PostgreSQL 16.13 for the failed statements
  work: a `RAISE` line keeps its context with `terse`). A forged record
  can add false events; it cannot remove real ones, except that such
  native code could also write a record with no row count and the text of
  a statement that fails next in its own session, which then reports the
  failed read from the forged record (item 4 of the failed statements,
  below). Records dropped because their
  severity is not `pgaudit.log_level` (likely genuine: the setting differs
  per database or role) are counted, logged, and noted in `check()` (for 24 h).
- **Server-side exports hidden in dynamic SQL.** A `COPY` record whose text
  does not show the `COPY` (dynamic `EXECUTE`, `format()`, nested `DO`) is
  reported with `signature.copy_to_file`: PL/pgSQL cannot copy to the
  client, so it is a server-side export (file or program).
- **Objects not named by the log** (function or procedure bodies without
  `pgaudit.log_relation`, text that does not parse) are reported as `*` in
  the database, never dropped. Relations named by pgaudit itself
  (`pgaudit.log_catalog`, `log_relation`) are skipped when they are
  catalogs, like catalogs named by the text.
- **What counts as a catalog.** Relations in `pg_catalog`,
  `information_schema`, `pg_toast` and the temporary schemas; and the two
  relations of the `pg_stat_statements` extension
  (`pg_stat_statements`, `pg_stat_statements_info`) **only in the
  extension's schema** of that database, as probed from the agent's
  session (a `pg_stat_statements_x` or a `pg_stat_statements` in another
  schema is application data: any role with `CREATE` can make one). A
  database the target does not list has no known extension schema. An
  **unqualified** `pg_*` name (the text does not tell its schema):
  - pgaudit with `pgaudit.log_catalog = off` (as the agent's session sees
    it): statements on catalogs only are not logged, so an unqualified
    `pg_*` name in a logged record without object name is a catalog only
    when pgaudit names it in `pg_catalog` for the same statement;
    otherwise it is reported as a relation without schema.
  - pgaudit with `log_catalog` on (the pgaudit default) or unknown, and
    `pg_stat_statements` (which names no object): it counts as a catalog.
    **Residual:** a role that can create a relation named `pg_*` in a
    schema of its search path (`CREATE TABLE public.pg_loot AS SELECT …`)
    and reads it later by its unqualified name is not reported for that
    later read (the copy itself reads the source relation and is
    reported). With pgaudit, `pgaudit.log_relation = on` names every
    relation with its schema and closes this (`log_catalog = off` is no
    longer advised: it hides reads of the statistics catalogs alone).
    An unqualified `pg_stat_statements` / `pg_stat_statements_info` counts
    as a catalog when the extension is installed in the database (the same
    residual for a shadowing relation earlier in the search path).
- **Statistics catalogs** ([ADR-0048](../../../docs/adr/0048-statistics-catalogs-as-reads.md)).
  `pg_stats`, `pg_stats_ext`, `pg_stats_ext_exprs`, `pg_statistic` and
  `pg_statistic_ext_data` (`audit::events::STATISTICS_RELATIONS`) hold
  sampled column values and are not catalogs for these rules: named by a
  pgaudit relation record in `pg_catalog`, or by the text qualified with
  `pg_catalog` or unqualified, they are objects named
  `pg_catalog.<name>`, always reported and never the agent's own (it
  sends no statement naming them: `sql.rs` unit test). With relation
  records, the text's statistics relations are added to the events of
  every action class too; an unqualified one is left out only with
  `pgaudit.log_catalog = on`, when a record of the same substatement
  names it in another schema and none in `pg_catalog` (shadowing). `U&"…"` names are compared decoded. A text
  that decides (relation records naming no `pg_catalog` relation of the
  substatement included) and reaches the analyzer's 16-relation bound,
  DDL included, adds `*`,
  always reported, never the agent's own, even when every kept relation
  is a catalog. Every read or write against `*` is always reported. `check()` says `pgaudit.log_catalog = off` in
  its local detail when pgaudit is the source. Details:
  [docs/08](../../../docs/08-engine-capabilities.md#statistics-catalogs).
- **Statement-text views** ([ADR-0049](../../../docs/adr/0049-postgresql-statement-text-views-as-reads.md)).
  The core list (`pg_stat_activity`, `pg_stat_get_activity(`,
  `pg_stat_get_backend_activity(`, the extension's `pg_stat_statements`
  view and function: `audit::events::listed`) and the extension list
  (`pg_stat_monitor`, `pg_store_plans`, `pg_show_plans`, `pg_qualstats*`,
  in any schema) are named in events (`pg_catalog.pg_stat_activity`,
  `<ext>.pg_stat_statements`, the extension names as written), always
  reported, in every action class, unless a core-list read has the
  no-text shape (`text_reads`, with the token scan
  `classifiers::query::pg_scan`: no `query` identifier, no `*` but
  `count(*)`, no whole-row reference, no column alias list (whatever
  the alias's word) but on constant `VALUES`, no `NATURAL`, only
  catalogs and listed entries named, and no schema-qualified call
  outside `pg_catalog` and the lists, refinement item 7, kept with
  decision 8 as defence in depth). pgaudit relation records of a listed entry the substatement's
  text does not name, or next to a view outside `pg_catalog`, make a text
  read. The `pg_catalog` functions of decision 7 (`DATA_FUNCTIONS`:
  SQL-running, file, logical decoding, large objects) add `*`, also next
  to catalogs only. The connector's `pss_texts` is left out only by exact
  text (`OwnKind::StatementText`; on pgaudit only within a
  `pg_stat_statements` period of the target, `PssPeriods`, whose closed
  periods end 5 s early for clock skew), never
  otherwise. `check()` says `pg_read_all_stats` is held while pgaudit is
  the source in its local detail. Drift and pinning tests in `it.rs`.
  Details:
  [docs/08](../../../docs/08-engine-capabilities.md#statement-text-views).
- **User code next to catalogs only** ([ADR-0049](../../../docs/adr/0049-postgresql-statement-text-views-as-reads.md)
  decision 8, part 2 refinement proposed). In a text whose relations are
  all catalogs (`audit::events::code_use`), whatever its statements
  (a statement that wraps a query, `EXPLAIN`, `PREPARE … AS`,
  `DECLARE … CURSOR FOR`, `CREATE … AS`, is scanned from its query; any
  other is scanned whole), a call, an operator (written, or implied by
  `LIKE`, `IN`, `BETWEEN`…) or a cast that is not built in for that
  database adds `*` in every action class, always reported, never the
  agent's own (`audit::user_code::user_code`, decided when the
  event is built, from the code uses that `classifiers::query::PgScan::code`
  extracts). "Built in": the lists of the server's major version
  (`builtins/<major>/{functions,operators,types,keywords}.txt`, generated
  by `builtins/generate.sh` from the engine-matrix images, embedded by
  `audit::builtins`; a newer major uses the newest lists, with a warning)
  minus what the collision probe (`sql::USER_CODE_PROBE`, run by `check()`
  in each declared database at every heartbeat, at most 20 000 rows,
  names in memory only) finds: user overloads a built-in value or literal
  reaches, user types named like built-in ones, user-function casts
  between built-in types (an implicit one: every catalog-only statement
  is `*`), and, with a `$n` in the text, user overloads whose code is
  not C, and user domains whose `CHECK` runs non-C code (a parameterized
  statement is then `*` unless it is exactly a connector statement from
  the agent's identity: `PgOwn::connector_sent`, `agent_identity`, and on
  `pg_stat_statements` `connector_pss_form` in the agent's slot). The
  probes are kept per target in `CheckState` and marked stale by the
  streams on routine, type, cast and extension DDL (`UserCode`), until
  two probes that started after the mark; a failed, cut, stale, old
  (15 min) or missing probe makes every unqualified call, operator and
  cast `*`. Every connector statement stays under the 8 192-character
  `pg_stat_statements` read bound (unit test). Every connector statement is
  written with qualified functions and types and
  `OPERATOR(pg_catalog.…)` (unit test `statements_never_trigger_decision_8`).
  Integration tests in `it_user_code.rs` (scenarios on every source, a
  database with `citext`, `hstore` and 3 000 relations, server facts,
  list drift). Details:
  [docs/08](../../../docs/08-engine-capabilities.md#user-code-next-to-catalogs).
- **Statements that wrap a query** ([ADR-0048](../../../docs/adr/0048-statistics-catalogs-as-reads.md#refinement-2026-10-12-accepted-statements-that-wrap-a-query),
  refinement of 2026-10-12, accepted). `EXPLAIN [ANALYZE]`, `DECLARE …
  CURSOR … FOR` and `PREPARE … AS` (`classifiers::query::PgWrapped`, on
  `StatementInfo::pg_wrapped`) are their query: its relations, with every
  rule a bare query has (catalogs, statistics relations, statement-text
  views and the no-text shape, user code, the relation bound). Before,
  `pg_stat_statements` gave no event for these statements (kind `Other`),
  so a cursor read (psql's `FETCH_COUNT`), an `EXPLAIN ANALYZE` and the
  `EXECUTE`s of a prepared statement (counted under the `PREPARE` text)
  went unreported there. The action (`wrapped_action`): a plain
  `EXPLAIN` reads (planned with the statistics, as ADR-0047 on MySQL /
  MariaDB; pgaudit's `WRITE` record of a plain `EXPLAIN DELETE` is a read
  too); `EXPLAIN ANALYZE`, a cursor and a prepared statement act as their
  query (a write writes, `CREATE … AS` is DDL). Explains and cursors are
  always reported with no row count (`WrapperUse::rows_unknown`: an
  explain sends no row, a cursor's rows go out through `FETCH`, which
  names no relation); a prepared statement's executions keep their rows
  and the filters. A cursor's or prepared statement's query keeps its
  `shape.full_table_read`. Never the agent's own (unit test
  `no_statement_wraps_a_query`). `FETCH`, `MOVE`, `CLOSE` and
  `DEALLOCATE` give no event (pgaudit logs them in the `misc` class; their
  `pg_stat_statements` row counts are not attributed). Unit tests
  `wrapped_queries_are_reads_of_their_query`,
  `pgaudit_records_of_wrapped_queries`; integration test
  `it_wrapped::wrapped_queries_are_reads_of_their_query`.
- **Failed and cancelled statements** ([ADR-0037 refinement of
  2026-10-12](../../../docs/adr/0037-postgresql-full-requires-pgaudit-log-rows.md#refinement-2026-10-12-accepted-failed-and-cancelled-statements),
  `audit/failures.rs`, `audit/records.rs`, `PgauditEvents::error_event`).
  With `pgaudit.log_rows = on` (needed for Full), pgaudit writes a
  statement's records when it ends, so a statement that fails or is
  cancelled leaves no `AUDIT:` record. When the pgaudit log is the source
  (Full or Partial), the stream therefore also parses the server's `ERROR`
  lines, and `FATAL` lines that carry a statement, of client backends,
  from the same file, cursor and tailer.
  - **Read (I2):** severity, SQLSTATE, user, database, application, client
    address, session, virtual transaction, time and the statement text
    only. `message`, `detail`, `hint`, `context` and `internal_query` are
    skipped as `serde::de::IgnoredAny` in jsonlog and walked without
    being copied inside the tailer's zeroized buffer in csvlog
    (`csv_pick`, whose statement buffer is reserved at the record's
    length so it never reallocates); the jsonlog statement is deserialized
    straight into a `Zeroizing` buffer (`serde_json`'s scratch buffer for
    a string with escapes stays outside the connector's reach, as for
    `AUDIT:` messages); of `context`, only its presence is used. The statement
    text is never logged; `ErrorLine`'s `Debug` prints no text and no
    identity. Lines of a closed list of the server's own processes
    (`records::SYSTEM_PROCESSES`: autovacuum, parallel workers, whose
    errors their leader re-raises, checkpointer, WAL writer, logical
    replication workers…) are not read; `walsender`, extensions'
    background workers, unknown and missing types are (fails closed).
    `LOG` lines (the `LOG` 08006
    "could not send data to client" before a `FATAL` 08006) are not read.
    A line of that severity that does not parse is counted in
    `audit.records_dropped`. Unit test
    `values_quoted_by_the_line_never_leave_it`.
  - **Classes, by SQLSTATE only** (`failures::base_class`). Refused (no
    event): `25P02` without a context field whose text calls only
    built-in code (ADR-0049 decision 8's lists and collision probe; a
    text that cannot be scanned keeps the line), `28xxx` / `3D000` without
    a statement, and `42601` without a context whose text does not lex
    and holds none of `( : $` or an operator character. Quiet: every
    other code of classes `42`, `3F`, `0A`, `25`, and `57014`, `57P01` to
    `57P05`, `40001`, `40P01`, `55P03`, classes `53`, `54`, `08`, `58`.
    Telling: every other code, a missing or malformed one included.
  - **Event:** the text is analyzed like a pgaudit record's (relations,
    catalogs skipped, statistics catalogs, statement-text views, user
    code next to catalogs, wrapped queries, shape signals); an
    unqualified `pg_*` name is not a catalog here (no record confirms
    it). Never a row count. Quiet: a read (a DDL or DCL keeps its
    action), always reported; from the agent's identity charged the
    whole budget like an unknown row count. Telling: the statement's
    action (the read first in a multi-statement text), always reported
    except a plain `INSERT … VALUES` (one relation, no query,
    `RETURNING` or `ON CONFLICT`, only built-in code), never the agent's
    own. `DO`, `CALL`, `EXECUTE`, `FETCH` and any other statement whose
    code or rows the text does not name add `*`; transaction control,
    `SET`, `SHOW` and the like give none. An `ERROR` line without a
    statement text is a read of `*`; a `FATAL` line without one ends an
    idle session and gives none where the stream's probe proved the log
    settings for its database (`Catalogs::error_lines_proven`), a read of
    `*` elsewhere (proposed item 9 of the ADR).
  - **Not twice:** a line is not reported when its session's last
    pgaudit record has the same text, the same virtual transaction and no
    row count (written at the statement's start, `log_rows = off`); texts
    are compared as hashes keyed per stream, 4096 sessions followed.
  - **`check()`:** `log_min_messages` and `log_min_error_statement`
    (readable by every role, read with the pgaudit settings) must be
    `error` or lower in every monitored database where pgaudit is loaded;
    otherwise the target is capped at Partial and the local detail names
    the setting and the database (no target note, no protocol change).
  - **Load:** a line costs one parse (about 2 µs) and one analysis of its
    text (about 45 µs, release build), as an `AUDIT:` record does; the
    last text's analysis is cached, so a storm of one failing statement
    (an application looping on a missing table, 42P01) costs about 15 µs
    per line (ignored test `error_line_throughput`), and the core's
    aggregator merges its events into one per principal, action, objects
    and window (at most 10 000 groups per window before an early flush,
    then the bounded spool).
  - Integration tests `it_wrapped::failed_reads_and_what_is_reported`
    (22P02 quoting the value, 59 of 60 rows then 22012, 57014 by timeout
    and by the client, `FATAL` 08006 mid-result, from another role and
    the agent's role, `log_rows` on and off, jsonlog and csvlog) and
    `it_wrapped::forced_25p02_and_42601_through_user_code` (F1: `25P02`
    and `42601` raised after rows were sent through a view, a row-level
    security policy, a user operator, a user cast and a domain `CHECK`,
    from another role and the agent's role, reported; a genuine `25P02`
    and `42601`, no event).
  - Residuals: a backend that crashes during a read writes nothing of its
    own (the postmaster's line is not read); `pg_stat_statements` counts
    no failed statement (Limited); native code that hides its context can
    forge a refused `25P02` / `42601`; any role can add false events with
    `RAISE … USING ERRCODE`; the log settings are read in the agent's
    session, so per-role or per-database overrides (superuser only,
    reported by pgaudit when set) are not seen (`pg_db_role_setting` is
    never read; ADR item 14, ROADMAP follow-up); the core's aggregation adds a failed read with no row count
    to a successful read of the same group, whose count then stands for
    both.
- **`pgaudit.log_statement_once = on`.** Only the first record of a
  statement and substatement carries the text; later ones carry
  `<previously logged>`. The connector analyzes those with the first
  record's text of the same substatement when it read it; when it did not
  (the first record fell before the cursor, or in another read), the text
  does not parse and the record's objects are unknown (`*`, fail safe).
  Signals computed from the text then come from the records whose text is
  known.
- **The agent's own account.** Its statements are left out only when all
  hold: they come from its `application_name` (`databastion-agent`, pgaudit
  only) and from its own client address as the server sees it
  (`inet_client_addr()`, probed at stream start; when it cannot be read,
  nothing is left out), they carry no signal, and the agent's reads of the
  object stay within `limits.max_sample_rows` rows over a rolling 24 h
  (unknown rows, without `pgaudit.log_rows`, are charged the whole budget
  per statement). A second Discovery scan of a table within 24 h therefore
  shows up as events of the agent's own account. With
  `pg_stat_statements`, application and address are not visible: only the
  signal and row-budget rules apply. Limits of the address check: behind a
  connection pooler (PgBouncer…) every client has the pooler's address, and
  another process on the agent host shares the agent's address; there the
  check only separates remote clients. Residual: someone holding the
  agent's credentials on the agent host (or behind the same pooler),
  spoofing its `application_name` and reading at most that many rows per
  object and day with filtered queries stays unreported. The counters are
  kept per target for the life of the agent process: restarting a stream
  (a failure, a source switch, the agent's sessions terminated on purpose)
  does not reset them, and they are persisted across **agent restarts**
  (phase 7; `<state_dir>/audit/<target>.own_usage.counters`, `0600`,
  written atomically at most every 30 s while charging, by a periodic
  flush every 30 s when a charge is not saved yet (even with no further
  activity), and when a stream ends: normalized object names and row
  counts per hour only), so a restart no longer gives a fresh budget per
  object; at most the charges of the last 30 s before a crash are lost. The agent's database
  credentials never leave its host (I3).
- **The agent's own table-less statements.** The connector sends a few
  statements that read no relation: the per-connection and
  per-transaction `pg_catalog.set_config(…)` / `current_setting(…)`
  (`SESSION_SETUP`, `SET_LOCAL_TIMEOUTS`: one per transaction, about 90 per
  Discovery scan), `pg_catalog.host(pg_catalog.inet_client_addr())`, and,
  in `pg_stat_statements` mode, its text query through the extension's
  `pg_stat_statements(true)` function. They are a closed list
  (`sql::OWN_TABLELESS`, plus the text query registered by the stream; a
  unit test fails on any other connector statement that names no
  relation). Such a statement of the agent's account is left out on the
  same identity and signal rules as above, and is **not charged** to any
  row budget; it is never reported. It is recognized by its exact text with
  pgaudit (pgaudit logs the text as sent; bound parameter values are not
  part of it) and, with `pg_stat_statements`, by its exact text as
  `pg_stat_statements` stores it: constants (booleans included) replaced by
  `$n` numbered after the bound parameters, and the connector's bound
  parameters in place (`audit::events::pss_form`, phase 7). The same
  statement sent with constants instead of parameters has another
  `queryid` and another text, and is reported. The text alone is not
  enough: an entry with an own text is the connector's only when its
  `userid` is the agent's role (its oid, read once per connection), it is
  a top-level entry, the connector runs that statement in that database
  (the session and transaction statements in the declared databases, the
  text query only in the poller's database), and its `queryid` is the one
  first seen in that slot. Anything else with the same text is reported:
  another role, a non-target database, a nested execution, or another
  `queryid` (the text prepared with every constant bound as a parameter).
  If such an entry is seen in the agent's own slot before the agent's
  own, the agent's own executions are reported instead: loud, not hidden.
  The slots are a closed set, so other roles cannot exhaust them. Anything else of
  the agent's account whose objects are unknown (`*`: any other function
  call, including `pg_catalog` ones that run SQL such as `query_to_xml`,
  text that does not parse, several statements) is **always reported** and
  never budgeted, so no traffic can use up a `*` budget. The same
  statements from any other role, or from the agent's account under
  another application or address, are reported against `*` as before.
  Residuals: someone holding the agent's credentials who passes the
  identity checks can run these exact statements unreported; they read no
  row of any relation (`set_config` changes their own session only;
  `current_setting` reads settings the role may read; the text query
  returns statement texts, as a read of the view `pg_stat_statements`
  does, which is skipped as statistics for every role). With
  `pg_stat_statements`, where constants are not visible, the settings read
  by `current_setting(…)` are not checked (a client using the same bound
  parameters shares the agent's `queryid` and entry). The text query is recognized in
  pgaudit records written during a `pg_stat_statements` period only if the
  agent did not restart in between.
- **Heuristic signals** (`shape.*`, `signature.*`) are evadable by design;
  see `../classifiers/README.md`.
- **Audit connections.** The `pg_stat_statements` stream holds one session
  on the agent's role. Its re-probe (every 5 minutes) runs on that session
  when the target declares one database; with several, the session is
  closed first, the databases are probed one at a time, and the session is
  reopened on the same database (phase 7). A pgaudit stream holds no
  session: its re-probe opens one per database, one at a time. Either way
  Audit holds one connection at a time, one less than the ADR-0025
  decision 11 sizing counted for `pg_stat_statements` (the recommended
  `CONNECTION LIMIT` in docs/05 is unchanged until the documentation
  follows).
- **`pg_stat_statements` mode** sees no client address, application name,
  per-execution time or rows, nor statements evicted between polls.
