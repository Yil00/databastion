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
  per database or role) are counted, logged, and noted in `check()`.
- **Server-side exports hidden in dynamic SQL.** A `COPY` record whose text
  does not show the `COPY` (dynamic `EXECUTE`, `format()`, nested `DO`) is
  reported with `signature.copy_to_file`: PL/pgSQL cannot copy to the
  client, so it is a server-side export (file or program).
- **Objects not named by the log** (function or procedure bodies without
  `pgaudit.log_relation`, text that does not parse) are reported as `*` in
  the database, never dropped.
- **The agent's own account.** Its statements are left out only when they
  come from its `application_name` (`databastion-agent`) and from its own
  client address (as the server sees it), carry no signal, and read at
  most `limits.max_sample_rows` rows per object within the aggregation
  window (per poll with `pg_stat_statements`, where application and
  address are not visible). Residual: someone holding the agent's
  credentials, on the agent host (same address), spoofing its
  `application_name` and reading at most that many rows per object and
  window with filtered queries stays unreported; without
  `pgaudit.log_rows` the row budget cannot be applied (rows unknown count
  as 0). The agent's database credentials never leave its host (I3).
- **Heuristic signals** (`shape.*`, `signature.*`) are evadable by design;
  see `../classifiers/README.md`.
- **`pg_stat_statements` mode** sees no client address, application name,
  per-execution time or rows, nor statements evicted between polls.
