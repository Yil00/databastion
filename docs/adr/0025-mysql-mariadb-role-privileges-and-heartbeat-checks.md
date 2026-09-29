# ADR-0025: MySQL / MariaDB role privileges in `check()`, per-account heartbeat checks, connection sizing with Audit, and the scan status hold

- **Status**: Accepted
- **Date**: 2026-09-29
- **Refines**: [ADR-0012](0012-postgresql-agent-grants.md), [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) and [ADR-0020](0020-mysql-mariadb-connector-as-merged.md) (all stay Accepted): the `CONNECTION LIMIT` of the ADR-0012 account; ADR-0018 decision 1 (over-privilege of granted roles, and the `MAX_USER_CONNECTIONS` sizing, which ignored Audit sessions) and its residual risk "role privileges are not evaluated"; ADR-0020 decision 2 (granted roles under `extended_grants`)
- **Context references**: P4-D and P2-G, merged in #70 (`agent/crates/connector-mysql/src/check.rs`, `grants.rs`, `sql.rs`; `agent/crates/core/src/runtime.rs`, `spool.rs`; `agent/README.md`)

## Context
ADR-0018 decision 1 made `check()` report every granted role as over-privilege, because it counted roles without knowing what they grant, and listed "role privileges are not evaluated" as a residual risk. A role granting only `SELECT` on an application database, which is a clean way to apply the minimal variant, was therefore always flagged. A role granting write or global privileges was flagged the same way, with nothing to tell the two apart.

`information_schema` lists only the privileges granted to the account itself. Without a grant on the `mysql` database, which the minimal variant forbids, a least-privilege account can read the privileges of its roles only through `SHOW GRANTS`, and the two engines differ:
- MySQL (8.0.19+) accepts `SHOW GRANTS FOR CURRENT_USER() USING <roles>` for roles granted to the account, and expands the roles those roles grant.
- MariaDB shows a role's grants to such an account only for the session's current role (`SHOW GRANTS FOR CURRENT_ROLE`). `SHOW GRANTS FOR <other role>` is refused without `SELECT` on `mysql`.

Two P2-G items from the end-of-phase-2 review were merged in the same change:
- Heartbeat target checks ran one after the other, each bounded at 10 s, so N slow targets delayed the heartbeat by up to N × 10 s and could raise a false `agent.silent`.
- A scan's terminal status could reach the console before its findings batches did.

Running the checks concurrently raises a sizing question: ADR-0018 sizes `MAX_USER_CONNECTIONS` for one check next to one scan (at least 3, 4 recommended). The end-of-phase-4 security review found that this sizing, and the PostgreSQL `CONNECTION LIMIT 4` of [ADR-0012](0012-postgresql-agent-grants.md), ignore the connections of Audit (P4-A, P4-B):
- a MySQL / MariaDB `performance_schema` Audit stream holds its own session on the account for as long as it runs;
- every 5 minutes the Audit stream re-probes its prerequisites on a new connection, opened while that session is still held;
- when the held session goes stale, the new session is opened before the old one is closed;
- a guarded Audit statement that is cancelled opens a `KILL QUERY` connection;
- a file-source Audit stream holds no session, but its 5-minute re-probe opens one;
- on PostgreSQL, the `pg_stat_statements` session is held while the re-probe connects.

## Decision
1. **Roles in scope.** `check()` reads every role in `information_schema.APPLICABLE_ROLES`, enabled or not: roles granted directly or through another role, MySQL mandatory roles and the MariaDB default role. The read is capped at 1 000 rows (`LIMIT 1001`). The privileges of these roles are evaluated with the same rules as direct grants (any global privilege, privileges beyond `SELECT`, `SELECT` on `mysql` / `sys`, `SELECT` on `performance_schema` without a running Audit stream). `WITH ADMIN OPTION`, on a role grant or in `APPLICABLE_ROLES.IS_GRANTABLE`, counts as a grant option. A role that grants only the minimal variant is not over-privilege.
2. **MySQL.** `check()` runs one `SHOW GRANTS FOR CURRENT_USER() USING …` statement with the roles granted directly to the account and its mandatory roles, at most 16 of them. The server expands the roles those roles grant, so one statement covers every applicable role.
3. **MariaDB.** `check()` reads `SELECT CURRENT_ROLE()`. If that role is one of the applicable roles, it evaluates it with `SHOW GRANTS FOR CURRENT_ROLE`. Every other applicable role, including the roles granted by the default role, is reported as not evaluated (`privilege.roles_not_evaluated`, with their count). They are never assumed harmless.
4. **`SET ROLE` is not used.** Switching the agent's session to each role would make every role readable on MariaDB. It would also enable that role's privileges, write privileges included, on the agent's session, against I4. The MariaDB gap is accepted instead.
5. **Server-derived role names in SQL.** Role names and hosts come from the server, so whoever administers the server chooses them. They are written into the MySQL statement only when they match an allow-list: ASCII letters, digits and `_ $ . % - : /`, at most 255 bytes, name not empty. They are then quoted as `'name'@'host'`. A name outside the allow-list is never written: the statement is not sent, and the roles are reported as not evaluated. The MariaDB statements take no name.
6. **Fail closed.** Every role is reported as not evaluated when:
   - the `APPLICABLE_ROLES` list is cut at its limit (the count is then at least one more than the rows read) or has a skipped row (a value that is not UTF-8);
   - on MySQL: there are more than 16 direct and mandatory roles, a name is outside the allow-list, the statement fails, a row is skipped, or a `SHOW GRANTS` line is not fully understood.
   On MariaDB, the default role is reported as not evaluated when its `SHOW GRANTS` fails, has a skipped row or has a line that is not understood. The `SHOW GRANTS` parser (`grants.rs`) works on bounded lines (64 KiB) and refuses anything it does not fully parse. It ignores `REVOKE` lines (MySQL partial revokes) and `SET DEFAULT ROLE`: ignoring a revoke can only over-report.
7. **Database grants are `LIKE` patterns.** A database name in a grant is matched as a case-insensitive `LIKE` pattern with `\` escapes, for direct and role grants alike: `%`, `m%` and `performance\_schema` count as the system database they match. For a name that is literal on the server (a table-level grant, or `partial_revokes` ON), this over-reports and never under-reports.
8. **Incomplete direct privilege lists.** A list of direct privileges that reaches its `LIMIT` or has a skipped row (not UTF-8) leaves the privileges not evaluated (`privilege.not_evaluated`). Before this change, that note only covered an account name that could not be matched.
9. **Per-account heartbeat check turns.** The heartbeat runs the targets' `check()` concurrently under one shared deadline of 10 s from its start, so it waits at most 10 s for all targets. Targets that reach the same account take turns, one check at a time. The account is the tuple (engine, host lowercased or socket, port, account). The turns cover `check()` only: a check can hold two connections (its session and a `KILL QUERY` connection), and with the turns an account has at most one check next to one scan. Scans already run one at a time. Audit streams are not part of the turns: each target with Audit enabled runs its own stream, next to the checks and the scan (decision 11). A check still running, or still waiting for its turn, at the deadline is dropped. Its target is reported unreachable with `last_error = timeout` and the note `check.timed_out`, and the connector cancels its statement server-side.
10. **Scan status hold.** After a scan ends, its terminal status is held until the console has answered every findings batch spooled for that job, for at most 120 s (`STATUS_FLUSH_WAIT`). There is no hold for a cancelled scan, when no spool worker runs, while `/findings` is parked after a `501`, while the spool worker is in a retry backoff (console unreachable, `5xx`, `429`), once the agent stops being active, or on shutdown. A status sent with batches of its job still spooled is counted in `scan_status_before_flush_total`. The batches stay durably spooled and are sent later; the console accepts them for 24 h after the terminal status.
11. **Connection sizing with Audit (refines ADR-0018 decision 1 and the ADR-0012 account).** The recommended per-account limits count the Audit connections listed in the context:
    - MySQL / MariaDB: `MAX_USER_CONNECTIONS 4` for Discovery only; **5** with a file-source Audit stream (`server_audit`, `audit_log`); **6** with a `performance_schema` Audit stream. The 6 are one scan and its `KILL QUERY` connection, one check and its `KILL QUERY` connection, the Audit session, and one re-probe, reconnect or Audit `KILL QUERY` connection.
    - PostgreSQL: `CONNECTION LIMIT 4` for Discovery or pgaudit Audit; **5** with `pg_stat_statements` as the Audit source.
    - Add **one per additional target on the same account that runs Audit**.
    A connection refused at the limit fails the operation that needed it: the check reports the target unreachable, the scan fails, or the Audit stream restarts after a backoff (`audit_stream_failures_total`) and can miss what ran in between. It never widens a privilege.

## Consequences
- **Replaces the ADR-0018 residual risk "role privileges are not evaluated".** It remains for:
  - MariaDB roles other than the session's current (default) role;
  - privileges granted to `PUBLIC` (MariaDB 10.11+), which `APPLICABLE_ROLES` does not list and `check()` does not read;
  - MySQL before 8.0.19, which has no `information_schema.APPLICABLE_ROLES`, and any non-fatal error reading that table (a permission or unknown-object error): the roles are then neither counted nor reported, which is not fail-closed (a phase-7 follow-up);
  - the fail-closed cases of decision 6, which are reported as not evaluated.
- **ADR-0018 decision 1 and ADR-0020 decision 2 in effect.** A granted role is no longer over-privilege in itself: only what it grants is, or the fact that it could not be evaluated. With `extended_grants: true`, a global `SELECT` held through a role is an expected warning, like a direct one.
- On MariaDB, an account whose Discovery grant is held by a non-default role, or by a role that the default role grants, always gets `privilege.roles_not_evaluated`. Granting the minimal variant directly, or through the default role alone, avoids it.
- **Account keys are literal.** Targets naming the same server differently are not recognized as the same account: an IP address and a host name, an alias, or an omitted port and an explicit default port. Their checks can then run at the same time and use more of `MAX_USER_CONNECTIONS` than the sizing assumes.
- **No "account busy" distinction.** A hung check keeps its account's turn until the shared deadline. The other targets of that account then report `timeout` / `check.timed_out`, the same as if they were slow themselves. The order of the turns is not rotated between heartbeats.
- **Connection limits.** The account blocks of [05-security.md](../05-security.md#recommended-database-accounts-read-only) follow decision 11. Existing accounts created with `MAX_USER_CONNECTIONS 4` or `CONNECTION LIMIT 4` that run Audit must be raised. Until then, a re-probe or reconnect can be refused while a scan and a check are running. The dev and E2E accounts use 5 (`MAX_USER_CONNECTIONS 5`, `CONNECTION LIMIT 5`, raised on `fix/p4-d-event-ts-clamp`), which matches decision 11 for file-source and `pg_stat_statements` Audit. The MySQL Audit tests create their own account for `performance_schema`.
- **Re-probe connection.** The extra Audit connection exists because the 5-minute re-probe and the stale-session reconnect open a new connection while the Audit session is still held. Re-probing on the held session, and closing the old session before reconnecting, would remove it. This is a phase-7 follow-up.
- **Queued scans wait behind the hold.** Scans run one at a time, and a scan counts as in flight until its status is sent. The next queued scan can therefore start up to 120 s later. Its `max_duration_s` window, which counts queue time, shrinks by as much.
- `check()` sends a few more read-only statements per MySQL / MariaDB target and heartbeat: two or three role statements. They are bounded like every `check()` statement and cancelled with `KILL QUERY` when the deadline drops them (MySQL's `max_execution_time` does not apply to `SHOW`).
- **Recorded with this ADR, in the scope of [ADR-0023](0023-mysql-mariadb-audit-sources-and-levels.md) (which stays Accepted): the failed-login flood.** A client that can reach the database port without credentials can try many made-up user names. Each name becomes its own `auth_failure` event group, because the aggregation key includes the account fingerprint and `auth_failure` always passes the `audit.configure` filter. The effects are:
  - the aggregator flushes every 10 000 groups;
  - events keep spooling while the console answers `429`;
  - the console accepts at most 60 batches of 500 events per minute per agent, and applies back-pressure at 20 000 pending events;
  - the batches of a later dump queue behind the flood, so its detection is delayed;
  - once the spool is full, the oldest batches, findings included, are evicted;
  - the console can store about 30 000 rows per minute per agent, kept 90 days.
  The flood shows in the spool's dropped counters and the back-pressure metric. Phase-7 follow-ups: cap `auth_failure` groups per window with an overflow event, spool eviction that keeps `signature.*` batches with a separate quota for events, and a console alert when an agent's `dropped_batches` rises. See [08-engine-capabilities.md](../08-engine-capabilities.md#known-limits-1).
- The `privilege.not_evaluated` description in `shared/protocol/target-notes.json` now also covers privilege lists that could not be fully read. The code is unchanged.

## Rejected alternatives
- **`SET ROLE <role>` then `SHOW GRANTS FOR CURRENT_ROLE` for each MariaDB role**: it enables the role's privileges, write privileges included, on the agent's session (I4).
- **Grant `SELECT` on the `mysql` database so that every role is readable**: it exposes the password hashes and `FEDERATED` credentials that ADR-0018 keeps out of reach.
- **Treat unreadable roles as harmless, or keep reporting every role as over-privilege**: the first under-reports. The second cannot tell a read-only role from a write role, and it penalizes applying the minimal variant through a role.
- **Quote server-derived role names without an allow-list**: quoting alone depends on the server and the client agreeing on every escaping rule (`sql_mode`, character set). The allow-list keeps a hostile name from shaping the statement at all.
- **One concurrent check per target without per-account turns**: N targets on one account would open up to 2 × N connections next to a scan and exceed `MAX_USER_CONNECTIONS`, so checks would fail at login.
- **A result cache refreshed in the background**: every heartbeat would report stale reachability and audit levels, and it would need an extra task with its own lifecycle, for the same bound.
- **Hold the scan status without a bound, or during a console outage**: queued scans would wait for the whole outage. The findings are already durable in the spool, and the console accepts them for 24 h after the status.
