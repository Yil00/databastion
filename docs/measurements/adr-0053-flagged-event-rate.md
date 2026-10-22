# ADR-0053 decision 6: flagged-event rate (load run with an ORM-style principal)

Measurement for the precondition of acceptance of [ADR-0053](../adr/0053-overflowed-event-objects-flag.md#6-precondition-of-acceptance-measure-the-flagged-event-rate): how often an access event would carry `objects_overflowed` (its objects passed the bound of 15 named objects plus `*`, [08-engine-capabilities.md](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine)), next to how often an event names an unknown-object `*` without overflow (ADR-0053 open question 1). Recorded on 2026-10-20, with a second SQL Server run the same day after the CAS store guard fix of #293. The maintainer accepted ADR-0053 on 2026-10-20 on these figures, with no mitigation from decision 6. The remainder of decision 6 (the end-to-end census, MongoDB Audit, the Valkey `*` events and an Extended Events load run) was recorded on 2026-10-22, from the census of #310 ([below](#remainder-2026-10-22-end-to-end-census-valkey-and-extended-events)).

## Runs

- **First run**: load run 39453966277, on the branch `feat/adr-0053-overflow-rate` (`e2e/load/` harness); a 600 s soak.
- **Regular load**: `pgbench` (PostgreSQL), `sysbench` (MariaDB) and `sqlcmd` (SQL Server) at 300 statements/s under the principal `load_app`, as in the usual load jobs; Valkey `GET`s and the CAS audit records as in `load-redis` and `load-cas`.
- **ORM-style principal** `load_orm`, mixed with the regular load on the SQL engines: one 18-statement cycle every 2 s (300 cycles, 5 400 statements in 600 s):
  - 6 lazy loads (one table each);
  - 5 eager loads over 2 to 6 tables;
  - 3 join chains over 8, 12 and 15 tables;
  - 1 pagination count over 3 tables;
  - 3 reporting queries over 16, 20 (`UNION ALL`) and 24 tables.

  So 3 of the 18 statements (900 per run) reach more than 15 objects; the 15-table chain reaches exactly the bound and does not overflow.
- **Second run (SQL Server only)**: load run 39476569869 at `bbfcab7`, the CAS store guard fix of #293 (merged in `485bf11`), with the same workloads and soak; its figures follow those of the first run.
- **Where the agent counts**: the census of `agent/crates/core/src/audit/census.rs` (#293) counts events when the aggregator is flushed, after the `audit.configure` filter and before the spool, so an event later dropped while built into batches or lost on a spool error is still counted ([e2e/load/README.md](../../e2e/load/README.md#event-census-adr-0053-decision-6-informational)). The per-principal figures are read from the console database.
- **Counted**: "overflowed" = events whose object list passed the bound (they name `*` past the 15th object, the events ADR-0053 would flag); "unknown `*`" = events naming `*` without an overflow (an object the agent could not name). Percentages of statements are of all statements issued to the engine during the soak (regular and ORM).

## Results (first run, 39453966277)

| Engine (source) | Events | Statements | Overflowed events | Overflowed statements | Unknown `*` events (no overflow) | Unknown `*` statements |
|---|---|---|---|---|---|---|
| PostgreSQL (pgaudit) | 714 | 185 836 | 37 (5.18 %) | 880 (0.47 %) | 59 (8.26 %) | 59 (0.03 %) |
| MariaDB (`server_audit`) | 625 | 186 889 | 30 (4.80 %) | 900 (0.48 %) | 10 (1.60 %) | 300 (0.16 %) |
| SQL Server (SQL Server Audit) | 928 | 185 397 | 120 (12.93 %) | 878 (0.47 %) | 0 | 0 |
| Valkey | 10 | 120 000 `GET`s | 0 | 0 | 10 (100 %) | not counted |
| Apereo CAS | 93 | 5 400 records | 0 | 0 | 0 | 0 |

Events are fewer than statements because the agent aggregates statements of one principal, object set and window into one event ([08-engine-capabilities.md](../08-engine-capabilities.md)).

Per principal, as stored by the console ("`*` events" = events with a `*` object, overflowed or unknown):

| Engine | Principal | Events | Statements | `*` events |
|---|---|---|---|---|
| PostgreSQL | `load_orm` | 294 | 5 466 | 96 (37 overflowed, 59 unknown) |
| PostgreSQL | `load_app` | 400 | 179 709 | 0 |
| MariaDB | `load_orm` | 181 | 5 401 | 40 (30 overflowed, 10 unknown) |
| MariaDB | `load_app` | 401 | 180 209 | 0 |
| SQL Server | `load_orm` | 490 | 5 318 | 46 |
| SQL Server | `load_app` | 360 | 180 000 | 0 |
| SQL Server | `databastion` (the agent's own account) | 74 | 75 | 74, at most 16 objects each (the CAS store guard, below) |
| SQL Server | `<host name>$` (SQL Server's telemetry process) | 4 | not counted | not counted |

Notes on the figures:

- **SQL Server, the agent's own account.** 74 of the 120 overflowed SQL Server events were the agent's own reads (`databastion`), every one with `*` and at most 16 objects. They came from the CAS store guard's `check()` read, which called a column-level `HAS_PERMS_BY_NAME` on every column of every user table: SQL Server Audit writes one `SL` record on each table such a call checks, so at every check the agent's statement reached more than 15 tables of the load database and overflowed. Own events whose objects overflowed are never left out under the own-read budget (ADR-0053 context, [08-engine-capabilities.md](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine)), so they were reported. Fixed in #293: the guard now checks column `SELECT` only on recognized CAS stores, one table per statement ([ADR-0041 implementation note of 2026-10-20](../adr/0041-cas-connector.md#implementation-note-2026-10-20-the-sql-server-guard-check-one-table-at-a-time)). Without them, 46 of 854 SQL Server events overflowed (5.4 %, derived from the table above); the second run below confirms the figure.
- **MariaDB, statement texts cut at 1024 bytes.** A local replay of a real `server_audit` log of one ORM cycle gave overflowed events for the 16-, 20- and 24-table statements. The 15-table chain (1 239 bytes of text) was cut at `server_audit_query_log_limit` = 1024 and became an unknown-object `*`, not an overflow, although all 15 tables were in its `TABLE` records. This bears on ADR-0053 open question 1: on MariaDB a long ORM statement can produce an unknown `*` rather than a flagged event.
- **Valkey.** All 10 events name `*`. Checked on 2026-10-22 ([below](#valkey-the--events)): not a real `*` key pattern but keys the agent did not attribute.
- **CAS.** No event overflowed or named `*`: CAS events name one or two objects.

## Second SQL Server run (39476569869, after the CAS guard fix)

| Engine (source) | Events | Statements | Overflowed events | Overflowed statements | Unknown `*` events (no overflow) |
|---|---|---|---|---|---|
| SQL Server (SQL Server Audit) | 805 | 185 270 | 43 (5.34 %) | 812 | 0 |

Per principal, as stored by the console:

| Principal | Events | Statements | `*` events | Longest object list |
|---|---|---|---|---|
| `load_orm` | 401 | 5 266 | 43 | 16 |
| `load_app` | 400 | 180 000 | 0 | not recorded |
| `databastion` (the agent's own account) | 0 (74 in the first run) | 0 | 0 | - |
| `<host name>$` (SQL Server's telemetry process) | 4 | not counted | not counted | not counted |

Every overflowed event came from the ORM-style principal; the agent's own account gave no event.

## Remainder (2026-10-22): end-to-end census, Valkey and Extended Events

The census of #310 reads the console database read-only when an end-to-end or load run ends and prints, per engine, the events, the statements, the overflowed events and the unknown-object `*` events, then the `*` events by source, action, principal kind and signals ([e2e/load/README.md](../../e2e/load/README.md#event-census-adr-0053-decision-6-informational)).

### End-to-end runs

CI run 39687126318, job `E2E`, on PR #310 (2026-10-21):

| Engine | Events | Statements | Overflowed events | Unknown `*` events (no overflow) |
|---|---|---|---|---|
| MariaDB | 10 | 115 | 0 | 2 |
| MongoDB (Audit) | 9 | 24 | 0 | 0 |
| OpenLDAP | 4 | 5 | 0 | 0 |
| PostgreSQL | 14 | 25 | 0 | 2 (the `pg_dump` full-table copies, and a read in `shop` over 7 statements) |

The four `*` events are the dump signatures (`signature.mysqldump`, `signature.pg_dump`), a MariaDB write to a `mysql` system table and a read recorded by pgaudit. No end-to-end event overflowed, MongoDB Audit included.

### Valkey: the `*` events

- **Load**: run 39679876881, job `load-valkey` (2026-10-21): 120 000 `GET`s gave 10 events, every one naming only `*`, in the database `*` (the slow log records no database, and Discovery found keys in two databases), none overflowed. Discovery had learned 4 patterns in `db0` and 1 in `db1`.
- **End to end**: the job `e2e-redis` gave 10 events, every one naming only `*`, in `db0`.
- **Conclusion**: the Valkey `*` is never a real `*` key pattern (the learned set never holds `*`). It is a key the agent did not attribute: the database is `*` because the slow log records none, and the key matched no learned pattern and no learned literal prefix ([08-engine-capabilities.md](../08-engine-capabilities.md#redis--valkey-audit)). Why the load keys match no learned pattern is not explained yet, a [phase 9 follow-up](../ROADMAP.md#phase-9-follow-ups).

### SQL Server, Extended Events source

Load run 39695590686 at `527eb08` (#311, 2026-10-22), `load-sqlserver` with the Extended Events source (`sqlserver_xevents`), 50 `SELECT`s per second and a statistics reset every 10 s:

| Principal | Events | Overflowed events |
|---|---|---|
| `load_orm` | 162 | 27 (16.7 %) |
| `load_app` | 360 | 0 |

As with SQL Server Audit, only the ORM-style principal overflowed (27 of its 162 events, against 43 of 401 in the second SQL Server Audit run, at a lower statement rate); the regular application traffic gave no overflowed event.

## Interpretation

- The regular application traffic (`load_app`, about 180 000 statements per SQL engine) produced no overflowed event and no `*` event.
- Overflowed events came only from the ORM-style principal (and, in the first SQL Server run, from the agent's own account, through the CAS store guard bug fixed in #293). Their number follows that principal's statement mix: 3 of its 18 statements, about 900 statements per run, in 30 to 46 events per engine.
- Incidents are bounded further than events: access-event incidents are deduplicated per policy, database, principal and hour ([ADR-0021](../adr/0021-access-event-correlation.md) decision 6), so a principal whose reporting queries overflow every hour adds events to one incident per policy and database per hour, not one incident per event.
- Unknown-object `*` events without overflow were frequent on Valkey (every event of this run) and on PostgreSQL (8.26 % of events), and occurred on MariaDB (1.60 %), partly through the text cut. Extending the flag, or a sibling field, to unknown `*` (open question 1) would apply the bound score to those events too; these figures do not support that extension without more data.

## Limits

- One load run per engine (two on SQL Server Audit, one on Extended Events), with a synthetic workload: the ORM-style cycle is a fixed mix written for this measurement, not traffic from a real application or ORM.
- MongoDB Audit and OpenLDAP are counted only in the end-to-end run, whose scenarios are small (at most 115 statements per engine) and have no ORM-style principal; there are no figures here for MySQL or for Redis load.
- Why the Valkey load keys are not attributed to learned patterns is an open item, above.
