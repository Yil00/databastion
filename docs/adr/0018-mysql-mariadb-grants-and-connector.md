# ADR-0018: MySQL / MariaDB agent grants and connector decisions

- **Status**: Accepted
- **Date**: 2026-09-28
- **Context references**: P2-C, branch `feat/p2-c-mysql-discovery` (`agent/crates/connector-mysql`, `agent/README.md` "MySQL / MariaDB connector", `dev/mysql/`, `dev/mariadb/`); the MySQL / MariaDB counterpart of [ADR-0012](0012-postgresql-agent-grants.md) and [ADR-0015](0015-postgresql-connector-decisions.md)

## Context
The MySQL / MariaDB block of [05-security.md](../05-security.md) recommended `GRANT SELECT, PROCESS, SHOW VIEW ON *.*` plus `SELECT ON performance_schema.*`. Writing the connector (P2-C) showed that these grants expose much more than Discovery needs, and that the engines have their own ways of making the server run code or connect out on the agent's behalf:

- a global `SELECT` reads `mysql.user` / `mysql.global_priv` (password hashes; a `mysql_native_password` hash is enough to log in as that account), `mysql.servers` (`FEDERATED` credentials), and the general and slow log tables;
- `performance_schema` statement tables carry the text of other sessions' statements, literals included (the same issue as ADR-0012 obligation 5);
- tables of remote-access engines (`FEDERATED`, `CONNECT`, `SPIDER`…) make the server connect to another host when read (I5), and on MySQL 8.4 merely computing `information_schema.TABLES.TABLE_ROWS` opens the table's handler, so a `FEDERATED` table connects to its remote server;
- views run their definition with the definer's rights;
- the client protocol lets a server ask the client for a local file (`LOAD DATA LOCAL INFILE`), for its password in clear (`mysql_clear_password`), or hand it an RSA public key to encrypt the password with, which an attacker on the path can substitute.

## Decision
1. **Grants: minimal variant (default).**
   - `SELECT` per application database only (`GRANT SELECT ON app.* …`), never `ON *.*`.
   - `SELECT ON performance_schema.*` only when Audit (phase 4) is enabled for the target. It comes with the statement-text obligation of ADR-0012 obligation 5: any `SQL_TEXT` / `DIGEST_TEXT` read goes through the query normalizer before it reaches the uplink or a log line.
   - No `PROCESS`, no `SHOW VIEW`, no global privilege.
   - Account options: `REQUIRE SSL`, `MAX_USER_CONNECTIONS` of at least 3 (a running scan, a concurrent `check()` and the separate connection used for `KILL QUERY`; 4 recommended), a restricted host instead of `'%'`. MariaDB: `MAX_STATEMENT_TIME` on the account as a safety net (the connector sets its own).
   - **Extended variant**: a global `SELECT`, for servers with many or dynamically created databases, behind an explicit `extended_grants` opt-in in `agent.yaml`, reported by `check()` as an expected warning. The opt-in is not implemented yet; until it is, a global `SELECT` is reported as over-privilege.
   - `check()` reports over-privilege (warned, not refused): any global privilege (including `SELECT ON *.*`, `PROCESS`, `SUPER`, `FILE`), any privilege other than `SELECT` (including `CREATE TEMPORARY TABLES`), any grant `WITH GRANT OPTION`, `SELECT` on the `mysql` or `sys` database, granted roles (their privileges are not evaluated), and a non-empty `init_connect`.
2. **Connector obligations.**
   - Introspection through `information_schema` without any statistics column (`TABLE_ROWS`, `DATA_LENGTH`…). Row estimates are read per sampled table, filtered on local engines, which re-checks the engine inside the sampling transaction.
   - Sampling scope: base tables of an allow-list of local storage engines (InnoDB, MyISAM, Aria, MEMORY, ARCHIVE, RocksDB, TokuDB), outside `mysql`, `sys`, `information_schema` and `performance_schema`. Never read: `FEDERATED`, `CONNECT`, `SPIDER`, `S3`, `SPHINX`, NDB and `MERGE` tables, unknown engines (fail closed), views, MariaDB sequences, and virtual generated columns. A partitioned table is one table.
   - Read-only: `SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY`, and every unit of work in `START TRANSACTION READ ONLY` whose OK packet must show a read-only transaction. Pinned and verified `sql_mode` (`NO_BACKSLASH_ESCAPES`, never `ANSI_QUOTES`) and utf8mb4. One statement per query, no user-defined function, procedure or view called; the only function applied to a sampled column is the built-in `LEFT()`.
   - Timeouts: `max_execution_time` (MySQL) / `max_statement_time` (MariaDB) from the clamped job parameter, never `0`, per session and per sampling statement; `wait_timeout` 60 s, `net_read_timeout` / `net_write_timeout` 30 s, `lock_wait_timeout` / `innodb_lock_wait_timeout` 2 s, MariaDB `idle_transaction_timeout` / `idle_readonly_transaction_timeout` 10 s.
   - Cancellation: a statement whose future is dropped, and a sample stopped at its byte budget (32 MiB per table, checked per row), is killed with `KILL QUERY <connection id>` from a separate connection; the session is then dropped.
   - No transaction or unread result held across `FindingSink::submit().await`.
   - Server errors reduced to error number, SQLSTATE and a closed stage; the message text is never stored.
3. **Own protocol implementation, no driver crate.** The connector speaks the text client protocol itself. Reasons: refusing the RSA public-key retrieval of `caching_sha2_password`; choosing the capability flags (never `CLIENT_LOCAL_FILES`, and a `LOCAL INFILE` request is refused anyway; never `CLIENT_MULTI_STATEMENTS`; no compression); reducing error packets while parsing; reading rows one packet at a time so the byte budget can stop a read. The available pure-Rust driver cannot refuse the RSA retrieval nor choose the flags, and pulls the `rsa` crate (RUSTSEC-2023-0071, no fix); a driver would also bring network dependencies that the architecture guard bans for connectors (`socket2`). Cost: the connector owns the parsers and their robustness against a hostile server. They work on bounded buffers and fail closed, and are covered by unit tests and a scripted fake server; fuzz or property tests of the parsers are still to be added.
4. **Authentication and TLS policy.**
   - `caching_sha2_password` scramble (fast path): on any transport. Its full authentication (the password itself) only over TLS or a Unix socket; never through RSA key retrieval.
   - `mysql_native_password`: only over TLS, a Unix socket or a loopback IP literal; refused on a network without TLS (a SHA-1 challenge-response is cheap to attack offline, like MD5 on PostgreSQL).
   - Always refused, whatever the transport: `mysql_clear_password` (even over TLS), PAM `dialog`, `sha256_password`, `client_ed25519`, GSSAPI and older plugins. A refusal ends the connection before any password-derived byte is sent for that exchange.
   - TLS placement follows [ADR-0015](0015-postgresql-connector-decisions.md) decision 1: `verify_full` by default (pinned CA or system store, DNS name or IP SAN checked, the server must offer TLS), `disable` only for a Unix socket or a loopback IP literal, `disable_insecure` as an explicit, warned opt-in on a network.
   - Proxies (ProxySQL, MaxScale) are not supported: `KILL QUERY` needs the real server connection id, and a connection id that differs from the handshake is refused.
5. **Audit level honesty.** `check()` reports **Partial** when `performance_schema` is on and the `events_statements_history_long` consumer is enabled and readable, **Limited** when only the per-thread consumers are, **None** otherwise. **Full** is never reported before the MySQL / MariaDB Audit connector (P4-B): it needs the agent to read an audit log file (`server_audit`, `audit_log`) whose path is configured with that connector; an active audit plugin is only noted.

## Open questions
Listed, not decided here:
- Support for accounts using `client_ed25519` (MariaDB) or PAM, which are refused today.
- Password masking in `performance_schema` and `server_audit` / `audit_log` statement text, per engine and version (what the server already redacts, and what the normalizer must drop).
- Where the audit log files live and which file ACL the agent needs to read them (P4-B).
- Coverage reporting when `information_schema` hides tables the account has no privilege on: they cannot be listed as not covered, unlike PostgreSQL's `pg_class`.

## Consequences
- **docs/05-security.md**: the MySQL / MariaDB account block is replaced by the minimal variant.
- **Dev environment** (`dev/mysql/initdb/20-databastion.sh`, `dev/mariadb/initdb/20-databastion.sh`): they still grant `SELECT, PROCESS, SHOW VIEW ON *.*` and are not a reference; moving them to the minimal variant is a follow-up, as was done for PostgreSQL (#31).
- Existing deployments that followed the old recommendation get over-privilege warnings from `check()` until their grants are reduced.
- Targets behind a MySQL proxy cannot be scanned.
- The console shows at most Partial for MySQL / MariaDB targets until P4-B, even with an audit plugin active.

### Residual risks
- **`disable_insecure`** accepts the `caching_sha2_password` fast-path scramble on a network without TLS: an observer can brute-force the password offline, exactly as with `mysql_native_password`, and an active attacker can force this path with an auth switch, and an active attacker can relay the authentication and send its own statements (no read-only guarantee), as with PostgreSQL.
- **Engine change race**: a table altered to a remote engine between the in-transaction engine check and the `SELECT` would be read once through that engine (a small window; it needs `ALTER` rights on the table).
- **Temporary tables**: a read-only transaction still allows `CREATE TEMPORARY TABLE`. The connector never creates one, and the privilege is flagged as over-privilege.
- **Sampling bias**: `LIMIT` without `ORDER BY` reads the first rows in storage order (no `ORDER BY RAND()`, which is a full scan and sort), so the sample is not random.
- **`LEFT()` runs on the server** on sampled text columns. It is a built-in and cannot resolve to a stored function under the pinned `sql_mode`, but it is still server-side work on the value.
- **`init_connect`** runs at every login of the account, before the connector can do anything; it is reported, not prevented.
- **Role privileges are not evaluated**: `check()` counts granted roles but does not inspect what they grant.
- **Minimum versions**: MySQL 8.0 and MariaDB 10.6; older servers are refused.

## Rejected alternatives
- **Keep `SELECT, PROCESS, SHOW VIEW ON *.*`**: exposes password hashes, `FEDERATED` credentials and log tables, and `PROCESS` shows other sessions' statement text, for no Discovery need.
- **Exclude the system schemas from sampling but keep the global grant**: relies on the connector alone; a compromised agent or a connector bug still reads the hashes.
- **Read `TABLE_ROWS` during introspection**: connects to `FEDERATED` remotes on MySQL 8.4 (I5).
- **Sample views**: runs definer code, possibly stored functions, with the definer's rights.
- **A driver crate (`mysql_async`)**: cannot refuse RSA key retrieval or choose the capability flags, and pulls a crate with an unfixed advisory.
- **Accept `mysql_clear_password` over TLS**: sends the password itself to whatever terminates TLS; the scramble-based plugins suffice.
- **`REPEATABLE READ` snapshots**: long snapshots on large tables, and the isolation level `mysqldump --single-transaction` uses, which would make the agent harder to tell apart from an export.
