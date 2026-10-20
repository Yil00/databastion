# ADR-0053 decision 6: flagged-event rate (load run with an ORM-style principal)

Measurement for the precondition of acceptance of [ADR-0053](../adr/0053-overflowed-event-objects-flag.md#6-precondition-of-acceptance-measure-the-flagged-event-rate): how often an access event would carry `objects_overflowed` (its objects passed the bound of 15 named objects plus `*`, [08-engine-capabilities.md](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine)), next to how often an event names an unknown-object `*` without overflow (ADR-0053 open question 1). Recorded on 2026-10-20. This record does not change the ADR; the decision, and any mitigation of decision 6, is the maintainer's.

## Run

- **Run**: load run 39453966277, on the branch `feat/adr-0053-overflow-rate` (`e2e/load/` harness); a 600 s soak.
- **Regular load**: `pgbench` (PostgreSQL), `sysbench` (MariaDB) and `sqlcmd` (SQL Server) at 300 statements/s under the principal `load_app`, as in the usual load jobs; Valkey `GET`s and the CAS audit records as in `load-redis` and `load-cas`.
- **ORM-style principal** `load_orm`, mixed with the regular load on the SQL engines: one 18-statement cycle every 2 s (300 cycles, 5 400 statements in 600 s):
  - 6 lazy loads (one table each);
  - 5 eager loads over 2 to 6 tables;
  - 3 join chains over 8, 12 and 15 tables;
  - 1 pagination count over 3 tables;
  - 3 reporting queries over 16, 20 (`UNION ALL`) and 24 tables.

  So 3 of the 18 statements (900 per run) reach more than 15 objects; the 15-table chain reaches exactly the bound and does not overflow.
- **Counted**: "overflowed" = events whose object list passed the bound (they name `*` past the 15th object, the events ADR-0053 would flag); "unknown `*`" = events naming `*` without an overflow (an object the agent could not name). Percentages of statements are of all statements issued to the engine during the soak (regular and ORM).

## Results

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
| SQL Server | `databastion` (the agent's own account) | 74 | 75 | 74, at most 16 objects each |
| SQL Server | `<host name>$` (SQL Server's telemetry process) | 4 | not counted | not counted |

Notes on the figures:

- **SQL Server, the agent's own account.** 74 of the 120 overflowed SQL Server events are the agent's own reads (`databastion`), every one with `*` and at most 16 objects. Why the agent's own reads overflow is under investigation. Own events whose objects overflowed are never left out under the own-read budget (ADR-0053 context, [08-engine-capabilities.md](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine)), so they are reported. Without them, 46 of 854 SQL Server events overflowed (5.4 %, derived from the table above).
- **MariaDB, statement texts cut at 1024 bytes.** A local replay of a real `server_audit` log of one ORM cycle gave overflowed events for the 16-, 20- and 24-table statements. The 15-table chain (1 239 bytes of text) was cut at `server_audit_query_log_limit` = 1024 and became an unknown-object `*`, not an overflow, although all 15 tables were in its `TABLE` records. This bears on ADR-0053 open question 1: on MariaDB a long ORM statement can produce an unknown `*` rather than a flagged event.
- **Valkey.** All 10 events name `*`. Not yet checked: whether this is a real `*` key pattern (the load key space collapsed into one pattern by Discovery's normalization) or a key the agent could not attribute.
- **CAS.** No event overflowed or named `*`: CAS events name one or two objects.

## Interpretation

- The regular application traffic (`load_app`, about 180 000 statements per SQL engine) produced no overflowed event and no `*` event.
- Overflowed events came only from the ORM-style principal (and, on SQL Server, from the agent's own account, under investigation). Their number follows that principal's statement mix: 3 of its 18 statements, about 900 statements per run, in 30 to 46 events per engine.
- Incidents are bounded further than events: access-event incidents are deduplicated per policy, database, principal and hour ([ADR-0021](../adr/0021-access-event-correlation.md) decision 6), so a principal whose reporting queries overflow every hour adds events to one incident per policy and database per hour, not one incident per event.
- Unknown-object `*` events without overflow were frequent on Valkey (every event of this run) and on PostgreSQL (8.26 % of events), and occurred on MariaDB (1.60 %), partly through the text cut. Extending the flag, or a sibling field, to unknown `*` (open question 1) would apply the bound score to those events too; these figures do not support that extension without more data.

## Limits

- One run, with a synthetic workload: the ORM-style cycle is a fixed mix written for this measurement, not traffic from a real application or ORM.
- MongoDB Audit is not in the load run; there are no figures here for MySQL, Redis or OpenLDAP.
- The end-to-end runs that decision 6 also names are not counted yet.
- The SQL Server own-account overflow and the Valkey `*` events are open items, above.
