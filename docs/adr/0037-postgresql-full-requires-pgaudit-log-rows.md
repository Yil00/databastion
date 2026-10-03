# ADR-0037: PostgreSQL Full audit level requires `pgaudit.log_rows`

- **Status**: Accepted
- **Date**: 2026-10-03
- **Refines**: [ADR-0015](0015-postgresql-connector-decisions.md) (which stays Accepted), decision 4 (audit levels), as implemented by P4-A (#58) and [docs/08](../08-engine-capabilities.md#postgresql-audit)
- **Context references**: security review M1 of #121; ROADMAP v0.1.x item (l); `agent/crates/connector-postgres/src/check.rs` (`AuditProbe::level`, `pgaudit_rows_on`), `agent/crates/connector-postgres/src/audit/mod.rs` (`source_for`, `audit_stream`); [ADR-0012](0012-postgresql-agent-grants.md)

## Context
ADR-0015 decision 4 withheld Full until P4-A. P4-A (#58) then defined Full in [docs/08](../08-engine-capabilities.md#postgresql-audit): the pgaudit log declared in `agent.yaml` is readable, pgaudit is loaded with the `read` class, a pgaudit record was parsed in the last 24 h, and "a volume source exists": `pgaudit.log_rows = on`, **or** `pg_stat_statements` usable by the agent (the Limited prerequisites). In code, `AuditProbe::level` granted Full with `pgaudit_reads && (pgaudit_rows || limited)`.

The stream does not match that rule. At Full and Partial, `source_for` picks the pgaudit log, and the `pg_stat_statements` poller is dropped: the agent reads one source at a time. With pgaudit loaded but without row counts (`pgaudit.log_rows = off`, or pgaudit before 1.6, where the setting does not exist and #121 proves it through `pg_settings`), a server with `pg_stat_statements` was reported Full. Yet no event carried a row count, so `volume.large_result` and every `volume.*` policy of the console could never fire on that target. The console showed Full for a source that misses the volume, which [docs/08](../08-engine-capabilities.md) defines as Partial ("some information is missing (volume, exact object)"). This is an honesty bug in `check()`, recorded as M1 by the security review of #121; it existed since P4-A.

## Decision
1. **Full requires the row counts of the source the Full stream reads.** On PostgreSQL that source is the pgaudit log, so Full requires `pgaudit.log_rows` proven on (`pgaudit_rows_on`: the library loaded, the setting defined as a boolean in `pg_settings`, its value `on` in the agent's session of a monitored database, #121). `pg_stat_statements` no longer counts as a volume source for Full. `AuditProbe::level` becomes:
   - **Full**: log readable, pgaudit loaded, `read` class, `pgaudit.log_rows` on (and, as before, a pgaudit record parsed in the last 24 h, otherwise Partial with `audit.full_pending_first_record`);
   - **Partial**: log readable, pgaudit loaded, and the `read` class without `log_rows`, or object audit only (`pgaudit.role`);
   - **Limited**: no usable pgaudit log, `pg_stat_statements` usable;
   - **None** otherwise.
2. **Partial with pgaudit still reads the pgaudit log** (`source_for(Partial)` is unchanged). Its events keep the principal, client address, application, objects and the `signature.*` / `shape.*` signals; they carry no row count, so `volume.large_result` is absent. The agent's own reads with unknown rows are still charged the whole per-object budget (docs/08, "The agent's own account").
3. **No new protocol note.** The registered `audit.log_without_row_counts` note does not list PostgreSQL, and `shared/protocol/` is not changed by this decision. The reason is given in the local `check()` detail (agent log) and documented in docs/08. Adding `postgres` to that note's engines is a compatible, append-only registry change left as a follow-up.

## Consequences
- **Upgrade impact.** A server with pgaudit logging reads, `pg_stat_statements`, and `pgaudit.log_rows` off (or pgaudit before 1.6) reported Full and now reports **Partial** after the agent upgrade. Nothing else changes for it: same source, same events. To get Full back, set `pgaudit.log_rows = on` (pgaudit 1.6+, PostgreSQL 14+) for the monitored databases. Servers that already have `log_rows` on keep Full.
- The console level now matches what `volume.*` policies can see: a Full PostgreSQL target always has row counts in its events.
- A server with pgaudit without `log_rows` and `pg_stat_statements` gets per-statement attribution (pgaudit, Partial) but no volumes, while the `pg_stat_statements` mode alone (Limited) would have volumes per role and poll. The agent keeps preferring pgaudit, as before; the operator turns `log_rows` on to have both.
- The dev environment (`dev/docker-compose.yml`, `dev/postgres/local-cluster.sh`) and the end-to-end target (`e2e/target-initdb/30-audit.sh`) set `pgaudit.log_rows = on`, so they still reach Full. The end-to-end test accepts Partial or Full; the connector integration test asserts Full only when `log_rows` is on in the monitored database, Partial otherwise.

### Residual risks
- **Level per target is the best database.** As for every other condition, `check()` reports the highest level over the monitored databases: a target whose first database has `log_rows` on and whose second has it off (`ALTER DATABASE … SET`) reports Full while the second database's events carry no row count. Unchanged by this ADR.
- **Session view.** Like every setting the probe reads, `log_rows` is read in the agent's session: an `ALTER ROLE … SET pgaudit.log_rows = off` for other roles is not visible to the agent, and their records carry no row count while the target reports Full.

## Rejected alternatives
- **Option B: poll `pg_stat_statements` volumes alongside the pgaudit stream** (keep Full with `pg_stat_statements` as the volume source, and make the stream read it). Rejected for now:
  - new concurrent query load on the monitored database, on top of the pgaudit log reading, against the < 2 % impact criterion ([ADR-0035](0035-discovery-pacing.md) and the load measurements of docs/08) and the one Audit connection at a time of [ADR-0025](0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) decision 11;
  - two sources of different granularity (per normalized statement text, role and poll interval for `pg_stat_statements`; per record, with client and application, for pgaudit): correlating them, or adding a volume to the right pgaudit event, is not reliable, and reporting both double-counts the same reads in the console's volume × sensitivity score and baselines;
  - more attack and failure surface (a second parser and state machine on the Full path, eviction between polls, `track_utility`), for a gap the operator closes with one setting.

  It can be revisited by a new ADR if servers without `pgaudit.log_rows` turn out to be common.
- **Keep the rule and document it**: the console would keep showing Full for targets where `volume.*` policies cannot fire, against the docs/08 rule that a degraded audit never passes for a full one.
