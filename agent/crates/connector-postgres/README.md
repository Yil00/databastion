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
  native code (C extensions, untrusted PLs). A forged record can add false
  events; it cannot remove real ones.
- **Objects not named by the log** (function or procedure bodies without
  `pgaudit.log_relation`, text that does not parse) are reported as `*` in
  the database, never dropped.
- **The agent's own account.** Its statements are left out only when they
  come from its `application_name` (`databastion-agent`) and carry no
  signal; with `pg_stat_statements`, only when they carry no signal.
- **Heuristic signals** (`shape.*`, `signature.*`) are evadable by design;
  see `../classifiers/README.md`.
- **`pg_stat_statements` mode** sees no client address, application name,
  per-execution time or rows, nor statements evicted between polls.
