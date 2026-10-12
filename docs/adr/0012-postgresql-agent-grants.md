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

## Refinement (2026-10-12, accepted): a two-key read of `pg_db_role_setting`

**Status: accepted by the maintainer on 2026-10-12**, with the recommended answers to open questions 1 to 7. Proposed and amended on 2026-10-12 after the security review of the proposal, PR #215 (C1: the function-`SET` statement named, item 1; M1: grants on the two parameters read from `pg_parameter_acl` and capping Full; L3: never sent while a `pg_stat_statements` stream runs) (ROADMAP [phase 8 follow-ups](../ROADMAP.md#phase-8-follow-ups); security review of #214, M2; [ADR-0037](0037-postgresql-full-requires-pgaudit-log-rows.md) refinement items 6 and 14). It adds one exception to the catalog denylist of obligation 1 and extends obligation 6 (`check()` reports honestly) for the Full level. The grant sets are unchanged. Accepted together with [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md), which reports other roles' reads of `pg_db_role_setting.setconfig`.

- **Context** (verified on PostgreSQL 16.13 with pgaudit 16.0 and `pg_stat_statements` 1.10 on 2026-10-12, in the throwaway cluster described in [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md#what-the-servers-expose-verified-on-postgresql-1613-on-2026-10-12); not run on 14, 15, 17 and 18):
  - ADR-0037 item 6 reads `log_min_messages` and `log_min_error_statement` in the agent's session of each monitored database. That session sees the server-wide value, a database-wide `ALTER DATABASE … SET` and the agent role's own overrides, but **not another role's** `ALTER ROLE … SET` or `ALTER ROLE … IN DATABASE … SET` (verified: the agent's session showed `warning` and `error` while other roles had overrides). Verified effects: with `ALTER ROLE other IN DATABASE postgres SET log_min_messages = fatal`, a failed `SELECT 1/0` by `other` wrote **no `ERROR` line**; with `ALTER ROLE app SET log_min_error_statement = panic`, `app`'s failure wrote an `ERROR` line **without its statement**. So a target reports Full while a role's failed and cancelled reads leave no line (or one without text): the ADR-0037 item 14 residual.
  - `pg_db_role_setting` is readable by every role (the second verification above; again on 16.13: the agent role of the minimal variant, `pg_read_all_stats` only, read every entry, including the fake `app.api_key` and `app.jwt_secret` values). It holds **every** per-role, per-database and per-role-in-database setting, and those can be secrets ([ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md)), which is why obligation 1 forbids reading it.
  - Setting names are stored in their canonical form: `ALTER ROLE app SET "LOG_MIN_ERROR_STATEMENT" = 'PANIC'` is stored as `log_min_error_statement=PANIC` (name in lower case, value as given).
  - Who can set them: superusers, and since PostgreSQL 15 a role granted `SET` on the parameter, which can then `SET` it in its own sessions (verified: no `ERROR` line) and `ALTER ROLE <itself> SET` it (verified: stored in `pg_db_role_setting`). Grants are listed in `pg_parameter_acl` (15+, readable by every role; verified). A function created with `SET log_min_messages = fatal` (`pg_proc.proconfig`) hid the `ERROR` line of a caller's failure inside it (verified). Since PostgreSQL 15, `GRANT ALTER SYSTEM ON PARAMETER` lets a non-superuser change the server-wide value (verified: `ALTER SYSTEM SET log_min_error_statement = panic` by a grantee); a `SET` grantee can also pass the setting in the startup packet (`options=-c log_min_messages=fatal`), which leaves nothing persistent. A second throwaway cluster of the same build verified the grant facts and the statement of item 2 below, and was deleted.
- **Decision.**
  1. **The exact statement.** A new constant of `sql.rs`, `ROLE_LOG_OVERRIDES`, sent as one statement with no bound parameter:

     ```sql
     SELECT s.setdatabase OPERATOR(pg_catalog.<>) 0::pg_catalog.oid AS in_database,
            s.setrole OPERATOR(pg_catalog.=) 0::pg_catalog.oid AS every_role,
            CASE WHEN s.setrole OPERATOR(pg_catalog.<>) 0::pg_catalog.oid
                 THEN pg_catalog.pg_get_userbyid(s.setrole) END AS role_name,
            pg_catalog.lower(pg_catalog.split_part(c.item, '=', 1)) AS setting_name,
            pg_catalog."left"(pg_catalog.lower(pg_catalog.split_part(c.item, '=', 2)), 16) AS setting_level
       FROM pg_catalog.pg_db_role_setting s
      CROSS JOIN LATERAL pg_catalog.unnest(s.setconfig) AS c(item)
      WHERE (s.setdatabase OPERATOR(pg_catalog.=) 0::pg_catalog.oid
             OR s.setdatabase OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d
                  WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()))
        AND pg_catalog.lower(pg_catalog.split_part(c.item, '=', 1))
            OPERATOR(pg_catalog.=) ANY ('{log_min_messages,log_min_error_statement}'::pg_catalog.text[])
      ORDER BY role_name, setting_name
      LIMIT 1001
     ```

     - **Only the two keys leave the server.** The `WHERE` is evaluated by the server in the same statement, so no other `setconfig` entry is sent: it is not in the wire buffer, the agent's memory or its logs (verified: as the minimal-variant role, the statement returned the four overrides of the two keys and none of the `app.*` or `search_path` entries). Each row carries two booleans, a role name (already readable by every role in `pg_roles`; `pg_get_userbyid` reads no relation and returns a name only), a key and its level, lower-cased and cut at 16 characters.
     - **Scope**: role-wide entries (`setdatabase = 0`), database-wide entries and role-in-database entries for the session's database. It runs in each monitored database, in the session that reads `PGAUDIT_SETTINGS`.
     - **Form**: the connector's rules hold (qualified functions, `OPERATOR(pg_catalog.…)`, one array literal rather than a list, `ORDER BY` on names, under the 8 192-character `pg_stat_statements` read bound: [ADR-0049](0049-postgresql-statement-text-views-as-reads.md) refinement items 12 and 16). Its constants are **literals in the text, never bound parameters**: pgaudit logs the text as sent and never the parameters (`pgaudit.log_parameter = off`, the Audit log files section above), so only literals let the exact-text rule of [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) decision 5 tell this statement from a replay that reads other keys.
     - **Bound**: a 1 001st row means the result is not proven (fail closed, item 3).

     **Function `SET` clauses** (open question 3, accepted; security review C1). In the same probe, a third constant, `FUNCTION_LOG_OVERRIDES`, reads the two keys of `pg_proc.proconfig` in the session's database, filtered by the server, literals only, with the same rules of form and the same bound:

     ```sql
     SELECT n.nspname AS schema_name, p.proname AS function_name,
            pg_catalog.lower(pg_catalog.split_part(c.item, '=', 1)) AS setting_name,
            pg_catalog."left"(pg_catalog.lower(pg_catalog.split_part(c.item, '=', 2)), 16) AS setting_level
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace
      CROSS JOIN LATERAL pg_catalog.unnest(p.proconfig) AS c(item)
      WHERE pg_catalog.lower(pg_catalog.split_part(c.item, '=', 1))
            OPERATOR(pg_catalog.=) ANY ('{log_min_messages,log_min_error_statement}'::pg_catalog.text[])
      ORDER BY schema_name, function_name, setting_name
      LIMIT 1001
     ```

     No other `proconfig` entry leaves the server. A function whose `SET` clause raises either key above `error` makes the database not proven (item 3), and the local detail names the functions (schema and name, normalized, at most 10, then a count). Like `ROLE_LOG_OVERRIDES`, it names a secret column of [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) (`proconfig`), so it is left out as the agent's own only by exact text on pgaudit with the agent's identity, never on `pg_stat_statements`, and it is not sent while a `pg_stat_statements` stream of the target runs (item 3).

     **Grants on the two parameters** (PostgreSQL 15+; security review of PR #215, M1). In the same probe, a fourth statement, `PARAMETER_GRANTS`, reads `pg_parameter_acl` (readable by every role, verified; it holds parameter names and ACLs, no secret), with the same rules of form:

     ```sql
     SELECT a.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid AS public_grant,
            CASE WHEN a.grantee OPERATOR(pg_catalog.<>) 0::pg_catalog.oid
                 THEN pg_catalog.pg_get_userbyid(a.grantee) END AS role_name,
            p.parname AS setting_name,
            a.privilege_type
       FROM pg_catalog.pg_parameter_acl p
      CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) AS a
      WHERE p.parname OPERATOR(pg_catalog.=) ANY ('{log_min_messages,log_min_error_statement}'::pg_catalog.text[])
        AND a.grantee OPERATOR(pg_catalog.<>) (SELECT r.oid FROM pg_catalog.pg_roles r
             WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles s
             WHERE s.oid OPERATOR(pg_catalog.=) a.grantee AND s.rolsuper)
      ORDER BY role_name, setting_name, a.privilege_type
      LIMIT 1001
     ```

     It returns the `SET` and `ALTER SYSTEM` grants on the two parameters to any role other than the agent's and other than superusers, a `PUBLIC` grant included (verified: as the minimal-variant role, it returned a `SET` grant and an `ALTER SYSTEM` grant to `app`, and left out the same grant to a superuser and to the agent's role). Superusers are not flagged: they can hide their failures in any case, and so can turn pgaudit off. A grant to the agent's own role is an over-privilege: it is added to the list of obligation 6 (`check()` warns), not to this proof. On PostgreSQL 14 the catalog does not exist and only superusers can set the parameters: the statement is not sent and nothing is missing from the proof. It reads `pg_roles` with named columns only, so it has the no-secret shape of [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) decision 2 and needs no own-statement rule.
  2. **Readable without a grant.** `pg_db_role_setting` is readable by `PUBLIC` by default (verified above), so neither variant gains a grant. The operator verifies it with `SELECT pg_catalog.has_table_privilege('databastion_agent', 'pg_catalog.pg_db_role_setting', 'SELECT')`; the integration test asserts it with the minimal-variant role. An operator who revoked it from `PUBLIC` can grant `SELECT` on it to the agent's role (the default exposure); otherwise item 3 fails closed.
  3. **What `check()` does with the result.**
     - **When it runs**: in each monitored database where pgaudit is loaded, only while the target's level before this check would be **Full**, the only level it can change, so that pgaudit is the source, and **only when no `pg_stat_statements` stream of the target runs** (security review of PR #215, L3): [ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) decision 5 never leaves `ROLE_LOG_OVERRIDES` out on that source, so while such a stream runs (during a source change, or a stream kept for another database) the statement would be reported there at every probe. While one runs, the database is not proven (fail closed). It runs in `check()` and in the stream's 5-minute probe ([ADR-0037](0037-postgresql-full-requires-pgaudit-log-rows.md) item 9). `FUNCTION_LOG_OVERRIDES` follows the same condition for the same reason; `PARAMETER_GRANTS` names no secret column and runs under the same condition, to keep the probe one unit.
     - **Proof**: a level is proven when it is `debug5` to `error` (the existing `logs_errors` rule); `log`, `fatal`, `panic` or any other value is above `error`. Any override of either key above `error` in a scope that applies to the database, any function `SET` clause above `error` (`FUNCTION_LOG_OVERRIDES`), **any `SET` or `ALTER SYSTEM` grant returned by `PARAMETER_GRANTS`** (a grantee can hide its failures with a session `SET` or a startup option, which nothing persistent shows, or raise the server-wide value), a statement that fails or is refused, or a cut result (1 001 rows) means the database is **not proven**.
     - **Level**: a database not proven caps the target **from Full to Partial**, as ADR-0037 item 6 does for the session's own values (item 13's cap): item 6's proof now covers every role, not only the agent's session.
     - **Shown**: the agent's local detail only (no target note, no `shared/protocol/` change; the console shows the level), as for item 6: the database (normalized name, [ADR-0009](0009-name-normalization-and-item-sanitization.md)), the setting, and the scope: "every role" for a database-wide entry, or the roles, by name, at most 10, then a count; for a grant, the grantee roles (or "every role" for `PUBLIC`), the privilege (`SET` or `ALTER SYSTEM`) and the setting. The detail never quotes a level or any other value; it says "above error" or "not proven".
  4. **ADR-0037 item 9, per role.** Item 9 gives no event for a `FATAL` line without a statement when item 6 is proven for its database. A role with an override of `log_min_error_statement` above `error` in that database writes its `FATAL` lines without the statement even while one runs, so for a line whose user is such a role, item 9's exemption is withdrawn and the line is item 5's read of `*`, always reported. The role is matched by the name the line carries. When the stream reads a pgaudit record of `ALTER ROLE … SET`, `RESET` or `RENAME`, or `ALTER DATABASE … SET` or `RESET`, it marks that database's override list stale until the next probe, and item 9's exemption is withdrawn for the whole database meanwhile (over-reported, never missed). This also covers a role renamed between two probes.
  5. **The denylist exception.** Obligation 1 now reads: the connector never reads `pg_db_role_setting.setconfig`, **except through `ROLE_LOG_OVERRIDES`**, and `pg_proc.proconfig` (listed by ADR-0050) **joins the denylist**, read only through `FUNCTION_LOG_OVERRIDES`. The unit test `no_statement_touches_the_catalog_denylist` adds `proconfig` to its list, exempts exactly these two constants and asserts their full texts, so any change to it fails the test and needs a `security-reviewer` review; every other statement is still refused on `setconfig`, `pg_db_role_setting`, `rolconfig` and the rest of the list. The extended-variant integration test of the Consequences (no catalog marker in agent output) adds a fake secret in `ALTER ROLE … SET` and in `ALTER DATABASE … SET` and asserts it appears in no uplink payload, log line or metric, and that every row of `ROLE_LOG_OVERRIDES` and `FUNCTION_LOG_OVERRIDES` holds one of the two keys (with a fake secret in a function's `SET` clause too).
  6. **Why the exception is safe.**
     - **I2**: no other `setconfig` entry reaches the agent, so none can leave it; what the agent keeps is a proven or not-proven flag per database and role names for its local detail. Nothing new is sent to the console: the level was already sent.
     - **I3**: the statement reads other roles' settings, not the agent's credentials; the credentials stay on the agent host as before.
     - **`PARAMETER_GRANTS`** reads parameter names and ACLs, which hold no secret, from a catalog every role can read; it is not an exception to the denylist.
     - **I4**: a read-only `SELECT` on a catalog every role can read, in the connector's read-only transactions, with no new grant and no user code (built-in functions only).
     - **A stolen agent credential gains nothing**: every role can already read `pg_db_role_setting`. With ADR-0050, any read of it is reported except this exact text on pgaudit, which returns the two keys only.
  7. **ADR-0037 items 6 and 14.** Item 6 is unchanged for the session and extended by item 3 to every role. Item 14's residual narrows to what `pg_db_role_setting` does not show (residuals below).
- **Consequences.**
  - **Code** (`agent-engineer`, `security-reviewer` review): `connector-postgres/src/sql.rs` (`ROLE_LOG_OVERRIDES`, `FUNCTION_LOG_OVERRIDES`, `PARAMETER_GRANTS`, the denylist test), `check.rs` (the probe, the cap, the local detail), the stream's probe and `audit/events.rs` (item 4: per-role exemption, stale marking). No `shared/protocol/` change.
  - **Tests**: unit tests for the row parsing (levels proven or not, unknown values, 1 001 rows, a refused statement: not proven), the cap and the detail, and item 4 (a `FATAL` line without a statement from an overriding role is a read of `*`; from another role, quiet; any line while stale, a read of `*`); integration tests on PostgreSQL 16 with pgaudit and on the engine matrix: `ALTER ROLE other SET log_min_messages = fatal`, `ALTER ROLE other IN DATABASE … SET log_min_error_statement = panic` and `ALTER DATABASE … SET log_min_messages = log` each cap a Full target at Partial with the detail, and `RESET` restores Full at the next probe; `REVOKE SELECT ON pg_catalog.pg_db_role_setting FROM PUBLIC` caps it too; on 15+, `GRANT SET ON PARAMETER log_min_messages TO other` and `GRANT ALTER SYSTEM ON PARAMETER log_min_error_statement TO other` each cap it, the same grant to a superuser or to `PUBLIC` is respectively ignored and capping, and `REVOKE` restores Full; with a `pg_stat_statements` stream running for the target, neither statement is sent; the minimal-variant role reads the catalog with no grant; fake secrets in other `setconfig` entries appear in no agent output.
  - **Load**: three statements per monitored database and probe (two on 14), on catalogs of usually a few dozen rows; nothing when the target is not at Full.
  - **Documentation** (`docs-keeper`, after the implementation): [08-engine-capabilities.md](../08-engine-capabilities.md#known-limits) narrows the overrides limit to the residuals below; [05-security.md](../05-security.md#recommended-database-accounts-read-only) says the agent reads the two keys of `pg_db_role_setting`, filtered by the server; [10-user-guide.md](../10-user-guide.md) tells operators to reset such overrides to get Full.
  - **Estimated size**: about 120 lines of production code, 250 lines of tests; one day with one review round.
- **Residual risks.**
  - A session-level `SET log_min_messages` (or `log_min_error_statement`) or a startup option (`options=-c …`) by a **superuser** is not seen; by a `SET` grantee, the grant caps the target (item 3).
  - A function created with such a `SET` clause between two probes hides failures inside it until the next probe.
  - An override set between two probes hides failures until the next probe (at most the probe interval), unless the stream reads its `ALTER ROLE` record (item 4).
  - The server facts were verified on 16.13 only; the integration test runs them on the engine matrix.
- **Alternatives considered.** Reading the whole `setconfig` and filtering in the agent: every secret of every role and database would reach the agent's memory and wire buffers, and a later bug could log or send it. Reading `pg_roles.rolconfig`: the same values (role-wide only), the same exposure. Reading other roles' values through `SET ROLE`: needs memberships that obligation 6 forbids. Keeping the residual: the target would report Full while a role's failed reads leave no line, against the rule that a degraded audit never passes for a full one.
- **Open questions** (each with the answer this refinement recommends; **decided on 2026-10-12: the maintainer accepted the recommended answers to questions 1 to 7**):
  1. Cap the target from Full to Partial for an override above `error` (item 3), or only name it in the local detail and keep Full?
     **Recommended**: cap, as ADR-0037 item 6 does for the same settings in the session. A role whose failures leave no line is not covered, and Full says they are. Some operators set `log_min_error_statement` higher for an application role to keep statement texts out of the server log; they get Partial and the detail tells them why.
  2. Count role-wide, database-wide and role-in-database entries for the session's database (item 1), and nothing for databases the target does not monitor?
     **Recommended**: yes. Database-wide entries are already seen by the session, unless the agent's role has its own override, which only a superuser can set; counting them again costs nothing. Undeclared databases are not probed, as ADR-0037 already says.
  3. Function `SET` clauses (`pg_proc.proconfig`, readable by every role, which can hold other secrets too): add a second statement of the same form (the two keys filtered by the server, functions of the session's database), with the same cap?
     **Recommended**: yes, in the same change. It is the same hiding mechanism, verified, and only a superuser or a `SET` grantee can create such a function; the same exact-text rules apply to the second statement.
  4. Roles granted `SET` or `ALTER SYSTEM` on these parameters (`pg_parameter_acl`, PostgreSQL 15+, readable by every role, no secret in it): cap Full at Partial like an override, or name them in the local detail only?
     **Recommended** (changed after the security review of PR #215, M1): **cap**, with the roles named in the local detail, superusers and the agent's role excluded. A grantee can hide its own failed reads in every session with a `SET` or a startup option, leaving nothing persistent, and an `ALTER SYSTEM` grantee can change the server-wide value; the grant is the only persistent trace, so it is what the proof can check.
  5. `pg_db_role_setting` not readable (the operator revoked it from `PUBLIC`): fail closed (cap), with a detail that suggests granting `SELECT` on it to the agent's role?
     **Recommended**: yes. An unread setting is not proven, as item 6 already rules for the session's values.
  6. Item 4 (per-role withdrawal of item 9's exemption, stale marking on `ALTER ROLE` and `ALTER DATABASE` records)?
     **Recommended**: yes. Without it, an overriding role's `FATAL` lines would still be taken for idle-session ends at Partial, where the target is not capped further.
  7. Send the statements only while the level would otherwise be Full and no `pg_stat_statements` stream of the target runs (item 3), the database being not proven otherwise?
     **Recommended**: yes. The proof changes nothing at a lower level, and on `pg_stat_statements` the stored text of `ROLE_LOG_OVERRIDES` cannot be told from a replay with other keys ([ADR-0050](0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) decision 5), so it would be reported there at every probe (security review of PR #215, L3).
