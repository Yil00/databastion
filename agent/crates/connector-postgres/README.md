# databastion-connector-postgres

PostgreSQL connector of the DataBastion agent: Discovery (P2-B,
[ADR-0012](../../../docs/adr/0012-postgresql-agent-grants.md),
[ADR-0015](../../../docs/adr/0015-postgresql-connector-decisions.md)) and
Audit (P4-A). This page records the Audit behavior that the user
documentation (docs/08) builds on.

## Audit sources and level

| Level | Condition (same probe for `check()` and the stream) | Source |
|---|---|---|
| Full | `postgres.audit_log` readable by the agent, pgaudit loaded with the `read` class, a volume source (`pgaudit.log_rows = on` or `pg_stat_statements`), **and** a pgaudit record parsed by the stream in the last 24 h | pgaudit log |
| Partial | log readable and pgaudit logging reads (or object audit through `pgaudit.role`), but no volume source or no recent record | pgaudit log |
| Limited | `pg_stat_statements` installed, loaded and showing other roles | `pg_stat_statements` |
| None | none of the above | — |

The source is re-evaluated every 5 minutes. `volume.large_result` on the
pgaudit source needs `pgaudit.log_rows = on`.

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
  agent was stopped, the rest of the previous file is not read.
- **Forged records.** Any role can write `AUDIT: …` lines into the server
  log (`RAISE LOG` in PL/pgSQL). The connector drops records whose severity
  is not `pgaudit.log_level` or that carry an error context (pgaudit hides
  its context; `RAISE` always has one). Still forgeable by roles that can
  hide the context (`log_error_verbosity = terse` is superuser-only) or run
  native code (C extensions, untrusted PLs). **A server-wide
  `log_error_verbosity = terse` removes every context, and with it this
  protection**: keep it at `default`. A forged record can add false
  events; it cannot remove real ones. Records dropped because their
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
    relation with its schema and closes this; so does `log_catalog = off`.
    An unqualified `pg_stat_statements` / `pg_stat_statements_info` counts
    as a catalog when the extension is installed in the database (the same
    residual for a shadowing relation earlier in the search path).
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
  written atomically at most every 30 s while charging and when a stream
  ends: normalized object names and row counts per hour only), so a
  restart no longer gives a fresh budget per object; at most the charges
  of the last 30 s before a crash are lost. The agent's database
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
  part of it) and by its normalized shape with `pg_stat_statements`
  (constants, booleans included, are placeholders there). Anything else of
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
  `pg_stat_statements`, where only the shape is visible, the settings read
  by `current_setting(…)` are not checked. The text query is recognized in
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
