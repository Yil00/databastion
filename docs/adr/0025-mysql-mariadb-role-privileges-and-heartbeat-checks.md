# ADR-0025: MySQL / MariaDB role privileges in `check()`, per-account heartbeat checks, and the scan status hold

- **Status**: Accepted
- **Date**: 2026-09-29
- **Refines**: [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) and [ADR-0020](0020-mysql-mariadb-connector-as-merged.md) (both stay Accepted): ADR-0018 decision 1 (over-privilege of granted roles), its `MAX_USER_CONNECTIONS` sizing and its residual risk "role privileges are not evaluated"; ADR-0020 decision 2 (granted roles under `extended_grants`)
- **Context references**: P4-D and P2-G, merged in #70 (`agent/crates/connector-mysql/src/check.rs`, `grants.rs`, `sql.rs`; `agent/crates/core/src/runtime.rs`, `spool.rs`; `agent/README.md`)

## Context
ADR-0018 decision 1 made `check()` report every granted role as over-privilege, because it counted roles without knowing what they grant, and listed "role privileges are not evaluated" as a residual risk. A role granting only `SELECT` on an application database, which is a clean way to apply the minimal variant, was therefore always flagged. A role granting write or global privileges was flagged the same way, with nothing to tell the two apart.

`information_schema` lists only the privileges granted to the account itself. Without a grant on the `mysql` database, which the minimal variant forbids, a least-privilege account can read the privileges of its roles only through `SHOW GRANTS`, and the two engines differ:
- MySQL (8.0.19+) accepts `SHOW GRANTS FOR CURRENT_USER() USING <roles>` for roles granted to the account, and expands the roles those roles grant.
- MariaDB shows a role's grants to such an account only for the session's current role (`SHOW GRANTS FOR CURRENT_ROLE`). `SHOW GRANTS FOR <other role>` is refused without `SELECT` on `mysql`.

Two P2-G items from the end-of-phase-2 review were merged in the same change:
- Heartbeat target checks ran one after the other, each bounded at 10 s, so N slow targets delayed the heartbeat by up to N × 10 s and could raise a false `agent.silent`.
- A scan's terminal status could reach the console before its findings batches did.

Running the checks concurrently raises a sizing question: ADR-0018 sizes `MAX_USER_CONNECTIONS` for one check next to one scan.

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
9. **Per-account heartbeat check turns.** The heartbeat runs the targets' `check()` concurrently under one shared deadline of 10 s from its start, so it waits at most 10 s for all targets. Targets that reach the same account take turns, one check at a time. The account is the tuple (engine, host lowercased or socket, port, account). This keeps ADR-0018's `MAX_USER_CONNECTIONS` sizing: a check can hold two connections (its session and a `KILL QUERY` connection), and the sizing allows one check next to one scan. A check still running, or still waiting for its turn, at the deadline is dropped. Its target is reported unreachable with `last_error = timeout` and the note `check.timed_out`, and the connector cancels its statement server-side.
10. **Scan status hold.** After a scan ends, its terminal status is held until the console has answered every findings batch spooled for that job, for at most 120 s (`STATUS_FLUSH_WAIT`). There is no hold for a cancelled scan, when no spool worker runs, while `/findings` is parked after a `501`, while the spool worker is in a retry backoff (console unreachable, `5xx`, `429`), once the agent stops being active, or on shutdown. A status sent with batches of its job still spooled is counted in `scan_status_before_flush_total`. The batches stay durably spooled and are sent later; the console accepts them for 24 h after the terminal status.

## Consequences
- **Replaces the ADR-0018 residual risk "role privileges are not evaluated".** It remains for:
  - MariaDB roles other than the session's current (default) role;
  - privileges granted to `PUBLIC` (MariaDB 10.11+), which `APPLICABLE_ROLES` does not list and `check()` does not read;
  - MySQL before 8.0.19, which has no `information_schema.APPLICABLE_ROLES`: its roles are neither counted nor reported;
  - the fail-closed cases of decision 6, which are reported as not evaluated.
- **ADR-0018 decision 1 and ADR-0020 decision 2 in effect.** A granted role is no longer over-privilege in itself: only what it grants is, or the fact that it could not be evaluated. With `extended_grants: true`, a global `SELECT` held through a role is an expected warning, like a direct one.
- On MariaDB, an account whose Discovery grant is held by a non-default role, or by a role that the default role grants, always gets `privilege.roles_not_evaluated`. Granting the minimal variant directly, or through the default role alone, avoids it.
- **Account keys are literal.** Targets naming the same server differently are not recognized as the same account: an IP address and a host name, an alias, or an omitted port and an explicit default port. Their checks can then run at the same time and use more of `MAX_USER_CONNECTIONS` than the sizing assumes.
- **No "account busy" distinction.** A hung check keeps its account's turn until the shared deadline. The other targets of that account then report `timeout` / `check.timed_out`, the same as if they were slow themselves. The order of the turns is not rotated between heartbeats.
- **Queued scans wait behind the hold.** Scans run one at a time, and a scan counts as in flight until its status is sent. The next queued scan can therefore start up to 120 s later. Its `max_duration_s` window, which counts queue time, shrinks by as much.
- `check()` sends a few more read-only statements per MySQL / MariaDB target and heartbeat: two or three role statements. They are bounded like every `check()` statement and cancelled with `KILL QUERY` when the deadline drops them (MySQL's `max_execution_time` does not apply to `SHOW`).
- The `privilege.not_evaluated` description in `shared/protocol/target-notes.json` now also covers privilege lists that could not be fully read. The code is unchanged.

## Rejected alternatives
- **`SET ROLE <role>` then `SHOW GRANTS FOR CURRENT_ROLE` for each MariaDB role**: it enables the role's privileges, write privileges included, on the agent's session (I4).
- **Grant `SELECT` on the `mysql` database so that every role is readable**: it exposes the password hashes and `FEDERATED` credentials that ADR-0018 keeps out of reach.
- **Treat unreadable roles as harmless, or keep reporting every role as over-privilege**: the first under-reports. The second cannot tell a read-only role from a write role, and it penalizes applying the minimal variant through a role.
- **Quote server-derived role names without an allow-list**: quoting alone depends on the server and the client agreeing on every escaping rule (`sql_mode`, character set). The allow-list keeps a hostile name from shaping the statement at all.
- **One concurrent check per target without per-account turns**: N targets on one account would open up to 2 × N connections next to a scan and exceed `MAX_USER_CONNECTIONS`, so checks would fail at login.
- **A result cache refreshed in the background**: every heartbeat would report stale reachability and audit levels, and it would need an extra task with its own lifecycle, for the same bound.
- **Hold the scan status without a bound, or during a console outage**: queued scans would wait for the whole outage. The findings are already durable in the spool, and the console accepts them for 24 h after the status.
