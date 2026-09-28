# ADR-0012: Grant set of the agent's PostgreSQL role

- **Status**: Proposed
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

Not verified here (no package on the verification host): pgaudit itself, and whether `pgaudit.log` is readable through `current_setting()` without `pg_read_all_settings`. Both are checked in P2-B against the dev image (`dev/postgres/`, PostgreSQL 17 + pgaudit).

### What this shows
1. `pg_read_all_data` is not "read all application data": it also reads catalog tables that hold credentials (SCRAM verifiers in `pg_authid`, cleartext passwords in `pg_user_mapping` and `pg_subscription`), large objects, and raw column statistics. None of them is needed by Discovery.
2. Neither variant bypasses row-level security; `NOBYPASSRLS` must stay.
3. Metadata (`pg_class`, `pg_attribute`, `pg_namespace`) is readable without any grant; `information_schema` only lists what the role may read. Discovery introspection needs no extra grant.
4. Privileges do not make the role read-only (a `SECURITY DEFINER` function owned by an application role writes on the agent's behalf), and `default_transaction_read_only` / `BEGIN READ ONLY` are client-controlled. Read-only is therefore enforced by the combination of no write privilege, read-only transactions opened by the connector, and the connector never calling user-defined functions.
5. `pg_read_all_stats` (needed for any Audit level, since the agent must see other users' statements) exposes raw query text: literals in `pg_stat_activity`, and cleartext passwords in non-normalized utility statements of `pg_stat_statements`. The pgaudit log carries statement text too ([ADR-0007](0007-mask-access-events.md)).
6. `pg_monitor` = `pg_read_all_stats` + `pg_read_all_settings` + `pg_stat_scan_tables`. The last one (functions such as `pgstattuple`, which scan relations and take locks) is not needed by the agent.

## Decision

### Grant variants
**Minimal variant (recommended default).** Discovery through explicit per-schema grants; Audit through `pg_read_all_stats` only.

```sql
-- Once per cluster. Set the password with psql's \password (hashed client-side),
-- never with PASSWORD '...': a literal password ends up in pg_stat_statements and logs.
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

**Extended variant (opt-in).** For clusters where schemas are too many or created dynamically, and the operator accepts the catalog exposure listed in the context:

```sql
-- Same CREATE ROLE, \password and ALTER ROLE ... SET as the minimal variant, then:
GRANT CONNECT ON DATABASE app TO databastion_agent;
GRANT pg_read_all_data     TO databastion_agent;  -- every schema, present and future
GRANT pg_read_all_stats    TO databastion_agent;  -- Audit
GRANT pg_read_all_settings TO databastion_agent;  -- richer check(): shared_preload_libraries, log_directory
```

**Never granted**: `SUPERUSER`, `REPLICATION`, `BYPASSRLS`, `pg_monitor` (use its two useful members instead), `pg_stat_scan_tables`, `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`, `pg_signal_backend`, `pg_write_all_data`, any write privilege, `CREATE` on any schema, `EXECUTE` on `pg_read_file` / `pg_read_binary_file`.

**Comparison with the current docs/05 recommendation**

| | docs/05 today | Minimal (recommended) | Extended |
|---|---|---|---|
| Discovery scope | every schema (`pg_read_all_data`) | declared schemas; new schemas / other owners need grants | every schema |
| Credential-bearing catalogs (`pg_authid`, `pg_user_mapping`, `pg_subscription`), `pg_largeobject`, `pg_statistic` | readable | denied | readable; excluded by the connector (obligation 1) |
| Other users' query text | readable (`pg_monitor`) | readable (`pg_read_all_stats`), Audit only | readable |
| Server settings (`shared_preload_libraries`, paths) | readable | hidden; `check()` degrades honestly | readable |
| `pg_stat_scan_tables` | granted | no | no |
| Read-only default, timeouts, role attributes | not stated | stated | stated |
| Password set with a literal | yes (`PASSWORD '...'`) | no (`\password`) | no |

### Connector obligations (P2-B)
1. **Sampling scope.** Sample only relations of kind `r`, `p`, `m` (tables, partitioned tables, materialized views), that the role can read (`has_table_privilege`), in schemas other than `pg_catalog`, `information_schema`, `pg_toast`, `pg_temp_*` and `pg_toast_temp_*`, and never an extension's own objects (`pg_depend` with `deptype = 'e'`). Foreign tables (`f`) are excluded: reading them makes the database open a connection to another host (I5). The connector never reads `pg_largeobject`, never calls `lo_*` functions, and never reads `pg_statistic`, `pg_statistic_ext_data`, `pg_stats` or `pg_stats_ext` values. This holds for both variants, so the extended variant does not leak catalog secrets through Discovery.
2. **Introspection** uses `pg_namespace`, `pg_class`, `pg_attribute` filtered with `has_schema_privilege` / `has_table_privilege`. Object names go through name normalization ([ADR-0009](0009-name-normalization-and-item-sanitization.md)). Tables with `relrowsecurity` are sampled under RLS and their result is marked as possibly incomplete in the agent's logs and metrics (a protocol field, if wanted, is a separate compatible change).
3. **Read-only transactions.** At connection: `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`, `SET search_path = ''`, `SET application_name = 'databastion-agent'`. Every unit of work runs in `BEGIN TRANSACTION READ ONLY` (never `REPEATABLE READ`, to stay distinguishable from `pg_dump`), and the connector never issues `SET TRANSACTION READ WRITE`. Queries use schema-qualified, quoted identifiers and only built-in `pg_catalog` functions; the connector never calls a user-defined function or operator.
4. **Timeouts.** Inside each transaction: `SET LOCAL statement_timeout` from the job parameter after the `TryFrom` mapping and the `agent.yaml` clamp (never `0`), `SET LOCAL lock_timeout` (default 2 s), and `SET LOCAL idle_in_transaction_session_timeout`. The role-level values are only a safety net: the client can override them.
5. **Query text is masked.** Any text read from `pg_stat_activity.query`, `pg_stat_statements.query` or the pgaudit log goes through `classifiers::masking` (query normalizer, [ADR-0007](0007-mask-access-events.md)) before it reaches the uplink or a log line. Because utility statements are not normalized by `pg_stat_statements`, statements that can carry a secret (`CREATE|ALTER ROLE|USER … PASSWORD`, `CREATE|ALTER USER MAPPING`, `CREATE|ALTER SERVER … OPTIONS`, `CREATE|ALTER SUBSCRIPTION … CONNECTION`, `ALTER SYSTEM`, `dblink_connect*`) keep only their statement kind and target object: their text is dropped, even after normalization. The same rule applies to text that fails to parse.
6. **`check()` reports honestly.** Audit level: Full when the `pgaudit` extension is present, the configured log file is readable and `pg_stat_statements` is readable with other users' rows; Limited with `pg_stat_statements` alone; None otherwise. When a prerequisite cannot be read (for instance `shared_preload_libraries` without `pg_read_all_settings`), `check()` reports the lower level it can prove, never a higher one. `check()` also warns when the role is over-privileged: `rolsuper`, `rolbypassrls`, `rolreplication`, membership of `pg_read_all_data`, `pg_monitor`, `pg_write_all_data` or `pg_*_server_*`, or a write privilege on a monitored table. For the minimal variant it lists the schemas without `USAGE` as not covered, so Discovery coverage is visible.

### Audit log files
The agent reads the pgaudit / `jsonlog` files locally (docs/08), through the file system, not through SQL: no database grant is involved, and `pg_read_file`, `pg_ls_logdir` and `pg_read_server_files` are not used. Production prerequisites: `log_file_mode = 0640`, the agent's OS user in the group owning `log_directory` (or an equivalent read-only ACL), the log path declared in `agent.yaml`, and `pgaudit.log_parameter = off`. Full-level volume figures come from `pg_stat_statements`, hence `pg_read_all_stats` in both Audit levels.

## Consequences
- The recommended account no longer reads password hashes, FDW / subscription credentials, large objects or raw statistics. The price is maintenance: every new application schema, and every role that creates tables, needs grants, and `check()` makes the gaps visible.
- Audit keeps a real exposure: `pg_read_all_stats` shows raw query text, including passwords typed as literals by DBAs. This is inherent to Audit on PostgreSQL; it is contained by obligation 5 and by the property tests of the query normalizer. The user documentation recommends `\password` over `PASSWORD '...'` for every role.
- **docs/05-security.md** (docs-keeper): replace the PostgreSQL block with the minimal variant, point to this ADR for the extended one, and remove the "grants are provisional" note once accepted.
- **E2E harness** (`e2e/target-initdb/01-agent-role.sh` and the role assertion in `e2e/run.sh`, which expects `pg_monitor+pg_read_all_data`): move to the minimal variant. The `app` target has no application schema, so it becomes `CONNECT` + `pg_read_all_stats` + the role defaults, and the assertion changes accordingly. Once the PG connector samples in E2E, a schema with per-schema grants is added. Until then the E2E grants are not a reference.
- **Dev environment** (`dev/postgres/initdb/20-databastion.sh`): same move, with per-schema grants on `crm`, `billing`, `ops`, so that P2-B integration tests run with the production grants. `log_file_mode = 0644` stays a dev-only convenience; production uses `0640`.
- P2-B gains the obligations above as acceptance criteria. A test role with the minimal variant is part of its integration tests, including the negative probes of the context (`pg_authid`, `pg_user_mapping`, write through a `SECURITY DEFINER` function).

## Rejected alternatives
- **Keep `pg_read_all_data` + `pg_monitor` as the default**: violates least privilege (credentials and raw statistics are readable for no Discovery need) and grants `pg_stat_scan_tables` for nothing.
- **`pg_read_all_data` with `REVOKE SELECT ON pg_authid …`**: the privileges of a predefined role are not per-object grants and cannot be revoked object by object.
- **Rely on `default_transaction_read_only` alone for read-only**: a session default the client can turn off. It stays as a safety net only.
- **Drop `pg_stat_statements` and poll `pg_stat_activity` only**: still needs `pg_read_all_stats`, and loses the short statements that polling misses.
- **Read the log files through `pg_read_file` / `pg_read_server_files`**: gives the database account arbitrary server-side file reads (configuration, keys) instead of access to one directory.
- **Revoke `TEMP` from `PUBLIC` on the database**: would close temporary tables for the agent, but changes the behavior of every other role; read-only transactions already block them for the connector.
