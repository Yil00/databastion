# ADR-0012: Grant set of the agent's PostgreSQL role

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
[05-security.md](../05-security.md#recommended-database-accounts-read-only) recommends `GRANT pg_read_all_data` (Discovery) and `GRANT pg_monitor` (statistics, `pg_stat_statements`) for the agent's PostgreSQL account. The end-to-end harness ([`e2e/target-initdb/01-agent-role.sh`](../../e2e/target-initdb/01-agent-role.sh)) and the dev environment (`dev/postgres/initdb/20-databastion.sh`) use the same grants, plus `default_transaction_read_only = on`. Before the PostgreSQL connector ships (P2-B), the production grant set must be settled against invariants I4 (read-only, least privilege) and I2 (no raw value leaves the agent), for Discovery and for the three Audit levels of [08-engine-capabilities.md](../08-engine-capabilities.md) (Full with pgaudit, Limited with `pg_stat_statements` + `pg_stat_activity`).

### Verification (PostgreSQL 16.13, throwaway cluster)
A scratch cluster (`initdb`, Unix socket only, `shared_preload_libraries = pg_stat_statements`, `jsonlog`) was seeded with an application schema `crm` owned by `app_owner`, a table with fake emails / IBANs (`ANALYZE`d), a table with a row-level security policy hiding every row, a `postgres_fdw` user mapping with a password option, a subscription created with `connect = false` whose connection string holds a password, a large object, two login roles with SCRAM passwords, and a `SECURITY DEFINER` function owned by `app_owner` that inserts a row. A second login role ran queries with literals, including a 20 s `pg_sleep` query carrying an email literal. All secrets were fake markers; the cluster was stopped and deleted afterwards.

Four agent roles were compared, all `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` with `CONNECT` on the database:

- `rad`: `pg_read_all_data` + `pg_monitor` (current docs/05 and E2E grants);
- `min`: `USAGE ON SCHEMA crm`, `SELECT ON ALL TABLES IN SCHEMA crm`, `ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA crm GRANT SELECT ON TABLES`, plus role defaults for `default_transaction_read_only`, `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`;
- `stats`: `pg_read_all_stats` only;
- `none`: no grant besides `CONNECT`.

| Probe (as the agent role) | `rad` | `min` | `stats` | `none` |
|---|---|---|---|---|
| `SELECT rolpassword FROM pg_authid` / `pg_shadow` | **readable**: `SCRAM-SHA-256$…` verifiers of every role | denied | denied | denied |
| `SELECT umoptions FROM pg_user_mapping` | **readable**: `{user=remote_u,password=…}` in clear | denied | denied | denied |
| `SELECT subconninfo FROM pg_subscription` | **readable**: `… password=…` in clear | denied | denied | denied |
| `SELECT data FROM pg_largeobject` | **readable**: large object content in clear (while `lo_get()` is denied) | denied | denied | denied |
| `pg_statistic` / `pg_statistic_ext_data` | **readable** (raw most-common values of every column) | denied | denied | denied |
| `pg_stats.most_common_vals` of `crm.customer.iban` | raw IBANs | raw IBANs (view filtered to readable columns) | none | none |
| `SELECT count(*) FROM crm.customer` | 200 | 200 | denied | denied |
| Table with an RLS policy hiding every row | 0 rows (`pg_read_all_data` does not bypass RLS) | 0 rows | denied | denied |
| Table created later in `crm` by `app_owner` | readable | readable (default privileges) | denied | denied |
| Table created later in `crm` by another role | readable | **denied** (default privileges only cover `FOR ROLE app_owner`) | denied | denied |
| Table in a schema created later | readable | **denied** (no `USAGE`) | denied | denied |
| `information_schema.tables` / `.columns` for `crm` | 2 / 5 | 2 / 5 | 0 / 0 | 0 / 0 |
| `pg_class`, `pg_attribute`, `pg_namespace` for `crm` | visible | visible | visible | visible (public catalogs, names only) |
| `pg_stat_activity.query` of another user | **raw text with the email literal** | `<insufficient privilege>` | **raw text with the email literal** | `<insufficient privilege>` |
| `pg_stat_statements.query` of other users | visible (0 hidden) | 63 of 72 rows hidden | visible (0 hidden) | 85 of 92 rows hidden |
| Normalization in `pg_stat_statements` | `WHERE email = $1` (DML is normalized) | – | same | – |
| Utility statements in `pg_stat_statements` | **not normalized**: `ALTER ROLE other_user PASSWORD '…'` and `ALTER SYSTEM SET primary_conninfo = '… password=…'` in clear | – | same | – |
| `pg_read_file()`, `pg_ls_logdir()` | `pg_read_file` denied, `pg_ls_logdir` allowed | denied | denied | denied |
| `shared_preload_libraries`, `log_directory`, `data_directory` in `pg_settings` | visible (`pg_read_all_settings` via `pg_monitor`) | hidden | hidden | visible only once `pg_read_all_settings` is granted |
| `log_destination`, `logging_collector`, `log_connections`, `log_file_mode` | visible | visible | visible | visible |
| `pg_extension` | visible | visible | visible | visible |

Read-only behavior, identical for `rad` and `min`:

| Probe | Result |
|---|---|
| `INSERT INTO crm.customer …` with `default_transaction_read_only = off` | `permission denied` (no write privilege) |
| `CREATE TABLE public.x …` | `permission denied for schema public` (PostgreSQL 15+ default) |
| `SELECT crm.touch()` (`SECURITY DEFINER`, writes) with the role default `default_transaction_read_only = on` | `cannot execute INSERT in a read-only transaction` |
| `SET default_transaction_read_only = off; SELECT crm.touch()` | **the row is written**: `EXECUTE` is granted to `PUBLIC` by default, privileges alone do not make the role read-only |
| `BEGIN READ ONLY; SELECT crm.touch()` | `cannot execute INSERT in a read-only transaction` |
| `BEGIN READ ONLY; SET TRANSACTION READ WRITE` (before the first query) | accepted: read-only mode is chosen by the client |
| `CREATE TEMP TABLE` outside / inside a read-only transaction | allowed (`TEMP` is granted to `PUBLIC` on the database) / `cannot execute CREATE TABLE in a read-only transaction` |
| Role defaults `statement_timeout = 30s`, `lock_timeout = 2s` | applied at login (`SHOW` → `30s`, `2s`), then `SET statement_timeout = 0` is accepted: role settings are session defaults the client can override |

Second verification (security review; same PostgreSQL 16.13 build, fresh throwaway cluster, `pg_stat_statements`, `postgres_fdw`, `dblink`, `pgcrypto`, `track_activity_query_size = 100`). A foreign server points to an unresolvable `*.invalid` host; the agent role has `USAGE` on `crm` and `SELECT` on its tables only.

| Probe | Result |
|---|---|
| `BEGIN READ ONLY; SELECT count(*) FROM crm.p` (partitioned root, one local leaf, one foreign leaf) | **the database tries to connect out**: `could not connect to server "remote"`, the `DETAIL` quoting the foreign host name |
| Same on the local leaf `crm.p_local` | 0 rows, no connection |
| `SELECT count(*) FROM crm.parent` (inheritance parent with a foreign child) / `FROM ONLY crm.parent` | connection attempt / 0 rows, no connection |
| `pg_partition_tree('crm.p')` | lists the root (`p`), the local leaf (`r`) and the foreign leaf (`f`) |
| `BEGIN READ ONLY; SELECT count(*) FROM crm.rls_t`, RLS policy `USING (crm.pol(owner))`, `pol` a `SECURITY DEFINER` function calling `dblink_exec` on a loopback connection | 1 row returned, **and a row is inserted in another table** through the dblink session: a read-only transaction does not contain side effects of user code run implicitly by a policy |
| `pg_foreign_server.srvoptions`, `pg_db_role_setting.setconfig` as the agent role (no extra grant) | readable by `PUBLIC`: server options (host names, and any option an FDW keeps there) and per-role / per-database settings |

Leaks through `pg_stat_statements.query` (statements run by a superuser; fake markers):

| Statement | Text stored |
|---|---|
| `SELECT 1 /* customer jean.dupont@example.test */ WHERE 'a' = 'a'` | `SELECT $1 /* customer jean.dupont@example.test */ WHERE $2 = $3`: literals replaced, **comment kept** |
| `CREATE USER MAPPING … OPTIONS (user 'u2', password 'MappingPw2-FAKE')` | kept verbatim, password included |
| `COPY (SELECT 1) TO PROGRAM 'echo ProgramMarker-FAKE …'` | kept verbatim |
| `DO $$ BEGIN PERFORM 'DoBlockMarker-FAKE'; END $$` | kept verbatim |
| `SET application_name = 'SetMarker-FAKE'`, `COMMENT ON TABLE … IS 'CommentMarker-FAKE'` | kept verbatim |
| `SELECT pgp_sym_encrypt('PlainMarker-FAKE', 'PgcryptoKey-FAKE')` | `SELECT pgp_sym_encrypt($1, $2)` (normalized) |
| `SELECT $tag$…$tag$, E'…', X'DEAD'` | normalized, no marker left |
| `pg_stat_activity.query` of a 130-character statement | 99 characters (`track_activity_query_size - 1`), the tail literal cut off |

Not verified here (no package on the verification host): pgaudit itself, and whether `pgaudit.log` is readable through `current_setting()` without `pg_read_all_settings`. Both are checked in P2-B against the dev image (`dev/postgres/`, PostgreSQL 17 + pgaudit).

### What this shows
1. `pg_read_all_data` is not "read all application data": it also reads catalog tables that hold credentials (SCRAM verifiers in `pg_authid`, cleartext passwords in `pg_user_mapping` and `pg_subscription`), large objects, and raw column statistics. None of them is needed by Discovery.
2. Neither variant bypasses row-level security; `NOBYPASSRLS` must stay.
3. Metadata (`pg_class`, `pg_attribute`, `pg_namespace`) is readable without any grant; `information_schema` only lists what the role may read. Discovery introspection needs no extra grant.
4. Privileges do not make the role read-only (a `SECURITY DEFINER` function owned by an application role writes on the agent's behalf), and `default_transaction_read_only` / `BEGIN READ ONLY` are client-controlled. Read-only is therefore enforced by the combination of no write privilege, read-only transactions opened by the connector, and the connector never calling, explicitly or through RLS policies or casts, user-defined functions. Even then, a read-only transaction only stops in-cluster writes: user code run implicitly (an RLS policy function using dblink) still has side effects.
5. `pg_read_all_stats` (needed for any Audit level, since the agent must see other users' statements) exposes raw query text: literals in `pg_stat_activity` (possibly truncated mid-literal), cleartext passwords and other literals in non-normalized utility statements of `pg_stat_statements`, and comments kept in normalized DML. The pgaudit log carries statement text too ([ADR-0007](0007-mask-access-events.md)).
6. `pg_monitor` = `pg_read_all_stats` + `pg_read_all_settings` + `pg_stat_scan_tables`. The last one (functions such as `pgstattuple`, which scan relations and take locks) is not needed by the agent.
7. Scanning a partitioned root or an inheritance parent reaches its foreign leaves / children, so excluding relkind `f` is not enough to prevent outbound connections (I5).

## Decision

### Grant variants
**Minimal variant (recommended default).** Discovery through explicit per-schema grants; Audit through `pg_read_all_stats` only.

```sql
-- Once per cluster. Set the password with psql's \password: it is hashed client-side and only
-- the SCRAM verifier reaches the server (it still appears in pg_stat_statements and statement
-- logs, where obligation 5 drops it). Never use PASSWORD '...' with a cleartext value.
-- Requires password_encryption = 'scram-sha-256' (the default since PostgreSQL 14); an md5
-- verifier can be used to log in.
CREATE ROLE databastion_agent LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4;
\password databastion_agent
-- Safety net for any session on this account; the connector sets its own values (see below).
ALTER ROLE databastion_agent SET default_transaction_read_only = on;
ALTER ROLE databastion_agent SET statement_timeout = '30s';
ALTER ROLE databastion_agent SET lock_timeout = '2s';
ALTER ROLE databastion_agent SET idle_in_transaction_session_timeout = '60s';

-- Per monitored database
GRANT CONNECT ON DATABASE app TO databastion_agent;

-- Discovery: per application schema, and per role that creates tables in it
GRANT USAGE ON SCHEMA crm TO databastion_agent;
GRANT SELECT ON ALL TABLES IN SCHEMA crm TO databastion_agent;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA crm
  GRANT SELECT ON TABLES TO databastion_agent;

-- Audit (Full and Limited): other users' statements in pg_stat_statements / pg_stat_activity.
-- Omit for a Discovery-only target.
GRANT pg_read_all_stats TO databastion_agent;
```

**Extended variant (opt-in).** For clusters where schemas are too many or created dynamically, and the operator accepts the catalog exposure listed in the context. It requires an explicit flag on the target in `agent.yaml`; with the flag set, `check()` reports the role's `pg_read_all_data` / `pg_read_all_settings` membership as an expected, persistent warning (not as "over-privileged"). Without the flag, the same membership is reported as over-privileged (obligation 6).

```sql
-- Same CREATE ROLE, \password and ALTER ROLE ... SET as the minimal variant, then:
GRANT CONNECT ON DATABASE app TO databastion_agent;
GRANT pg_read_all_data     TO databastion_agent;  -- every schema, present and future
GRANT pg_read_all_stats    TO databastion_agent;  -- Audit
GRANT pg_read_all_settings TO databastion_agent;  -- richer check(): shared_preload_libraries, log_directory
```

**Never granted**: `SUPERUSER`, `REPLICATION`, `BYPASSRLS`, `pg_monitor` (use its two useful members instead), `pg_stat_scan_tables`, `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`, `pg_signal_backend`, `pg_write_all_data`, `pg_maintain` / the `MAINTAIN` privilege, `pg_create_subscription`, `pg_checkpoint`, `pg_use_reserved_connections`, any write privilege (including `TRUNCATE` and `TRIGGER`), `UPDATE` on sequences, `CREATE` on any schema, `EXECUTE` on `pg_read_file` / `pg_read_binary_file`, membership of any non-predefined role, ownership of any object.

**Comparison with the current docs/05 recommendation**

| | docs/05 today | Minimal (recommended) | Extended |
|---|---|---|---|
| Discovery scope | every schema (`pg_read_all_data`) | declared schemas; new schemas / other owners need grants | every schema |
| Credential-bearing catalogs (`pg_authid`, `pg_user_mapping`, `pg_subscription`), `pg_largeobject`, `pg_statistic` | readable | denied | readable; excluded by the connector (obligation 1) |
| Other users' query text | readable (`pg_monitor`) | readable (`pg_read_all_stats`), Audit only | readable |
| Server settings (`shared_preload_libraries`, paths) | readable | hidden; `check()` degrades honestly | readable |
| `pg_stat_scan_tables` | granted | no | no |
| Read-only default, timeouts, role attributes | not stated | stated | stated |
| Password set with a literal | yes (`PASSWORD '...'`) | no (`\password`, SCRAM verifier only) | no |
| `agent.yaml` flag | – | none | required |

### Connector obligations (P2-B)
1. **Sampling scope.** Sample only relations of kind `r` and `m` (tables, materialized views) that the role can read (`has_table_privilege`), in schemas other than `pg_catalog`, `information_schema`, `pg_toast`, `pg_temp_*` and `pg_toast_temp_*`, and never an extension's own objects (`pg_depend` with `deptype = 'e'`). Foreign tables (`f`) are excluded, and so is any relation whose scan can reach one: every `r` is read with `FROM ONLY`, and a partitioned table (`p`) is never read through its root. Its leaf partitions are sampled individually as `r` (enumerated with `pg_partition_tree()`), and foreign leaves are skipped. A leaf partition or inheritance child is sampled only if no ancestor (`pg_partition_ancestors()`, or `pg_inherits` followed recursively for inheritance) has `relrowsecurity`; otherwise it is skipped and reported by `check()` as not covered. Row-level security applies to the relation named in the query, so reading a leaf directly would bypass the policies of its root or parent. Reading a foreign table makes the database open a connection to another host (I5). The connector never reads `pg_authid`, `pg_shadow`, `pg_user_mapping`, `pg_subscription`, `pg_largeobject`, `pg_db_role_setting.setconfig` or `pg_foreign_server.srvoptions` (the last two are readable by `PUBLIC`), never calls `lo_*` functions, and never reads `pg_statistic`, `pg_statistic_ext_data`, `pg_stats` or `pg_stats_ext` values. This catalog denylist applies to every connector query, Discovery, Audit and `check()` alike, and to both variants, so the extended variant does not leak catalog secrets through the agent.
2. **Introspection** uses `pg_namespace`, `pg_class`, `pg_attribute` filtered with `has_schema_privilege` / `has_table_privilege`. Object names go through name normalization ([ADR-0009](0009-name-normalization-and-item-sanitization.md)). Tables with `relrowsecurity` are sampled only if every object their `pg_policy` expressions depend on (`pg_depend` rows with `classid = 'pg_policy'::regclass`) is either in `pg_catalog` or is the policy's own table (`refobjid = polrelid`). Any other dependency skips the table, which `check()` then reports as not covered. Such a dependency can be a function, operator or type outside `pg_catalog`, or any other relation: a subquery on a view or a foreign table runs user code or connects out without recording a function dependency. Sampled RLS tables are marked as possibly incomplete in the agent's logs and metrics (a protocol field, if wanted, is a separate compatible change).
3. **Read-only transactions.** At connection: `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`, `SET search_path = ''`, `SET application_name = 'databastion-agent'`. Every unit of work runs in `BEGIN TRANSACTION READ ONLY` (never `REPEATABLE READ`, to stay distinguishable from `pg_dump`), and the connector never issues `SET TRANSACTION READ WRITE`. Queries use schema-qualified, quoted identifiers and only built-in `pg_catalog` functions, plus the extension objects of the second bullet below; the connector never calls a user-defined function or operator. Sampling queries never cast or apply operators to sampled columns: values are fetched in their wire format and decoded in Rust. The output / send functions of extension types (C functions installed by a superuser) are trusted. Read-only transactions stop in-cluster writes only; they do not stop side effects of implicitly executed user code (dblink / FDW loopback, untrusted PLs), which is why RLS tables with user functions are skipped. `check()` warns when an enabled `login` event trigger exists (`pg_event_trigger.evtevent = 'login'`, PostgreSQL 17+).
   - Queries use the extended query protocol only (no simple-query / multi-statement strings); identifiers come from the catalogs and are quoted with a single audited quoting function; job parameters never carry SQL text or identifiers used unquoted.
   - Extension objects (`pg_stat_statements`) are qualified with the schema read from `pg_extension.extnamespace` and used only if `pg_depend` shows them as members of that extension (`deptype = 'e'`). Audit through `pg_stat_statements` requires that `CREATE EXTENSION pg_stat_statements` has run in the database the agent connects to.
4. **Timeouts.** Inside each transaction: `SET LOCAL statement_timeout` from the job parameter after the `TryFrom` mapping and the `agent.yaml` clamp (never `0`), `SET LOCAL lock_timeout` (default 2 s), and `SET LOCAL idle_in_transaction_session_timeout`. The role-level values are only a safety net: the client can override them.
5. **Query text is masked.** Any text read from `pg_stat_activity.query`, `pg_stat_statements.query` or the pgaudit log goes through `classifiers::masking` (query normalizer, [ADR-0007](0007-mask-access-events.md)) before it reaches the uplink or a log line. Only DML text (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `VALUES`, `TABLE`, `WITH`) is kept after normalization. Every other statement (utility statements: DDL, `SET`/`RESET`, `ALTER SYSTEM`, `ALTER ROLE|DATABASE … SET`, `CREATE|ALTER ROLE|USER|GROUP`, `CREATE|ALTER USER MAPPING|SERVER|FOREIGN DATA WRAPPER|FOREIGN TABLE`, `IMPORT FOREIGN SCHEMA`, `CREATE|ALTER SUBSCRIPTION`, `COPY` (all forms, including `PROGRAM`), `DO`, `CREATE|ALTER FUNCTION|PROCEDURE`, `PREPARE`/`EXECUTE`, `CREATE EXTENSION`, `SECURITY LABEL`, `COMMENT`) keeps only its command tag and target object; its text is dropped, even after normalization. The normalizer removes comments (`--`, nested `/* */`), and replaces every literal form (`'…'`, `E'…'`, `U&'…'`, `$tag$…$tag$`, `B'…'`, `X'…'`, numbers, and backslash escapes when `standard_conforming_strings = off`). Text that fails to parse, and `pg_stat_activity.query` text whose length reaches `track_activity_query_size - 1` (possibly truncated), is dropped. The DML allow-list still lets through function calls that take secrets as arguments (`pgp_sym_encrypt(…, key)`, `dblink_connect(…, conninfo)`): they pass only after literal replacement, like any other DML. The [ADR-0007](0007-mask-access-events.md) property tests of the normalizer cover comments (including nested and unterminated ones), every literal form above including dollar quoting with arbitrary tags, and truncated input (a literal cut before its closing quote).
6. **`check()` reports honestly.** Audit level: Full when the `pgaudit` extension is present, the configured log file is readable and `pg_stat_statements` is readable with other users' rows; Limited with `pg_stat_statements` alone; None otherwise. When a prerequisite cannot be read (for instance `shared_preload_libraries` without `pg_read_all_settings`), `check()` reports the lower level it can prove, never a higher one. `check()` also warns when the role is over-privileged: `rolsuper`, `rolbypassrls`, `rolreplication`, membership of `pg_read_all_data`, `pg_monitor`, `pg_write_all_data` or `pg_*_server_*` (`pg_read_all_data` / `pg_read_all_settings` are an expected warning when the extended-variant flag is set), a write-type privilege (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `TRIGGER`, `MAINTAIN`) on a monitored table, `UPDATE` on a sequence, ownership of any object, or membership of any non-predefined role, `pg_maintain` or `pg_create_subscription`. For the minimal variant it lists the schemas without `USAGE` as not covered, so Discovery coverage is visible; RLS tables skipped under obligation 2 are listed as not covered too.
7. **Server messages are not data.** From `jsonlog`, only pgaudit `AUDIT:` records are parsed, and only their structured fields plus the statement text (through obligation 5); `message`, `detail`, `context`, `hint`, `internal_query` and parameter details of other records are discarded. The pgaudit record's parameter field is discarded whatever `pgaudit.log_parameter` is set to, and a record whose CSV does not parse is dropped. Errors returned to the connector are logged and reported by SQLSTATE and statement kind only, never with their message, detail or context text (the verification shows a `DETAIL` quoting a foreign host name).

### Audit log files
The agent reads the pgaudit / `jsonlog` files locally (docs/08), through the file system, not through SQL: no database grant is involved, and `pg_read_file`, `pg_ls_logdir` and `pg_read_server_files` are not used. Production prerequisites: `log_file_mode = 0640`; read access through a POSIX ACL (or a dedicated group) on `log_directory` and its files only; the agent's OS user is never a member of the group owning the data directory, and `log_directory` should be outside `PGDATA`; the log path declared in `agent.yaml`, and `pgaudit.log_parameter = off`. Full-level volume figures come from `pg_stat_statements`, hence `pg_read_all_stats` in both Audit levels.

## Consequences
- The recommended account no longer reads password hashes, FDW / subscription credentials, large objects or raw statistics. The price is maintenance: every new application schema, and every role that creates tables, needs grants, and `check()` makes the gaps visible.
- Audit keeps a real exposure: `pg_read_all_stats` shows raw query text, including passwords typed as literals by DBAs and SCRAM verifiers set with `\password`. This is inherent to Audit on PostgreSQL; it is contained by the allow-list of obligation 5 and by the property tests of the query normalizer. The user documentation recommends `\password` over `PASSWORD '...'` for every role.
- With the extended variant, whoever obtains the agent's database credentials (they stay on the agent host, I3, but a compromised host exposes them) can read every role's SCRAM verifier, which allows offline password cracking and, if any role still has an md5 verifier, direct login as that role; and the cleartext FDW and subscription passwords, which give access to other servers. The minimal variant limits a credential theft to the declared schemas and the query text of `pg_read_all_stats`.
- **docs/05-security.md** (docs-keeper): replace the PostgreSQL block with the minimal variant, point to this ADR for the extended one, and remove the "grants are provisional" note once accepted.
- **E2E harness** (`e2e/target-initdb/01-agent-role.sh` and the role assertion in `e2e/run.sh`, which expects `pg_monitor+pg_read_all_data`): move to the minimal variant. The `app` target has no application schema, so it becomes `CONNECT` + `pg_read_all_stats` + the role defaults, and the assertion changes accordingly. Once the PG connector samples in E2E, a schema with per-schema grants is added. Until then the E2E grants are not a reference.
- **Dev environment** (`dev/postgres/initdb/20-databastion.sh`): same move, with per-schema grants on `crm`, `billing`, `ops`, so that P2-B integration tests run with the production grants. `log_file_mode = 0644` stays a dev-only convenience; production uses `0640`.
- **P2-A** (classifiers, query normalizer): the DML allow-list of obligation 5, comment removal, every literal form, the truncation rule, and property tests on comments, dollar quoting and truncated input.
- **P2-B** (PG connector) gains the obligations above as acceptance criteria. Its integration tests include:
  - a role with the minimal variant and the negative probes of the context (`pg_authid`, `pg_user_mapping`, write through a `SECURITY DEFINER` function);
  - a partitioned table and an inheritance parent with a foreign leaf / child pointing to an unresolvable host: no connection attempt during a scan;
  - an RLS table whose policy calls a user function: skipped and reported as not covered;
  - an RLS table whose policy uses a subquery on a view calling a user function: skipped and reported as not covered;
  - a partitioned root with an RLS policy hiding every row and a leaf without RLS: the leaf is skipped and reported as not covered;
  - a role with the extended variant: no catalog marker (SCRAM verifier, FDW / subscription password, large object content, `setconfig` / `srvoptions` value, statistics value) appears in agent output (uplink payloads, logs, metrics);
  - the check that `pgaudit` and `current_setting('pgaudit.log')` are readable without `pg_read_all_settings` (dev image).

## Rejected alternatives
- **Keep `pg_read_all_data` + `pg_monitor` as the default**: violates least privilege (credentials and raw statistics are readable for no Discovery need) and grants `pg_stat_scan_tables` for nothing.
- **`pg_read_all_data` with `REVOKE SELECT ON pg_authid …`**: the privileges of a predefined role are not per-object grants and cannot be revoked object by object.
- **Rely on `default_transaction_read_only` alone for read-only**: a session default the client can turn off. It stays as a safety net only.
- **Drop `pg_stat_statements` and poll `pg_stat_activity` only**: still needs `pg_read_all_stats`, and loses the short statements that polling misses.
- **Read the log files through `pg_read_file` / `pg_read_server_files`**: gives the database account arbitrary server-side file reads (configuration, keys) instead of access to one directory.
- **Revoke `TEMP` from `PUBLIC` on the database**: would close temporary tables for the agent, but changes the behavior of every other role; read-only transactions already block them for the connector.
- **A denylist of secret-bearing statements** (the first draft of obligation 5): any statement kind not on the list (`COPY … PROGRAM`, `DO`, `COMMENT`, `SET`, new syntax in a later release) would leave with its literals. An allow-list of normalized DML fails closed.
- **Sampling partitioned tables and inheritance parents through their root**: the scan reaches foreign leaves and children, and the database connects to another host (I5).
