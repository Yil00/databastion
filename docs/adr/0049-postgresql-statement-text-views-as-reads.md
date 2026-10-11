# ADR-0049: PostgreSQL Audit reports reads of the views and functions that hold other sessions' statement texts

- **Status**: Proposed
- **Date**: 2026-10-11
- **Refines**: the PostgreSQL catalog rule of the Audit connector (P4-A, #58, #65), which no ADR records, as already refined by [ADR-0048](0048-statistics-catalogs-as-reads.md) (which stays Accepted); and the connector's own-statement rule for `pg_stat_statements` (#65, #90), described in [08-engine-capabilities.md](../08-engine-capabilities.md#the-agents-own-account). Levels and sources are unchanged. [ADR-0012](0012-postgresql-agent-grants.md) (grants, obligation 5 on query text) is unchanged.
- **Context references**: ROADMAP [phase 8 follow-ups](../ROADMAP.md#phase-8-follow-ups) (the statement-text view item); [ADR-0048](0048-statistics-catalogs-as-reads.md) open question 8; [ADR-0045](0045-mysql-mariadb-statement-text-tables-and-unqualified-calls.md) part (a) and decision 4, the MySQL / MariaDB counterpart; [08-engine-capabilities.md, PostgreSQL Audit](../08-engine-capabilities.md#postgresql-audit); `agent/crates/connector-postgres/src/audit/events.rs` (`is_catalog`, `is_pss_relation`, `CatalogRule`, `user_relations`, `PgOwn`, `OwnKind`, `pss_form`, `pss_event`, the pgaudit `flush`), `agent/crates/connector-postgres/src/audit/pss.rs` (`OwnKeys`, `connect`, `record_text`), `agent/crates/connector-postgres/src/sql.rs` (`pss_counters`, `pss_texts`, `pss_probe`, `AUDIT_PREREQUISITES`, `PGAUDIT_SETTINGS`, `OWN_TABLELESS`, `policy_function_ok`), `agent/crates/connector-postgres/src/check.rs` (memberships, `privilege.predefined_roles`), `agent/crates/classifiers/src/query.rs` (`collect_relations`, `read_relation`)

## Context

### What the agent does today

Read from the code at `0f64d7d` (`dev`); not run for this ADR.

- **Catalog rule.** A relation in `pg_catalog`, `information_schema`, `pg_toast` or a temporary schema is a catalog, and so are `pg_stat_statements` and `pg_stat_statements_info` in the extension's schema of that database, and an unqualified `pg_*` name (under the `pgaudit.log_catalog` rule of [08](../08-engine-capabilities.md#postgresql-audit)). A read whose relations are all catalogs produces no event, on both sources, for every account. The exception is the five statistics relations of ADR-0048.
- **So these reads produce no event today, from any account:** `SELECT query FROM pg_stat_activity`, `SELECT query FROM pg_stat_statements` (qualified with the extension schema or unqualified), and any read that joins them with other catalogs only.
- **Function forms.** The analyzer does not take a name followed by `(` as a relation (`read_relation`). A statement that names no relation at all (`SELECT * FROM pg_stat_get_activity(NULL)`, `SELECT pg_stat_get_backend_activity(1)`, `SELECT query FROM public.pg_stat_statements(true)`) is therefore a read of `*`, always reported, never the agent's own unless it is one of the connector's exact own texts. The same call in a statement that also names a catalog (`… FROM pg_stat_get_activity(NULL) a JOIN pg_catalog.pg_database d …`) is catalog-only and produces no event.
- **SQL text inside a function argument.** For the same reason, `SELECT pg_catalog.query_to_xml('select query from pg_stat_activity', true, false, '') FROM pg_catalog.pg_class LIMIT 1` produces no event: the call is invisible and the only relation named is a catalog. The same holds for `table_to_xml('crm.customer', …)`, which reads an application table. Table-less, these calls are reads of `*` (unit test of ADR-0048 for `query_to_xml`).
- **What the connector itself sends** (`sql.rs`, `sql::all_statements()`):

  | Statement | Reads | Text read? | Own-account handling today |
  |---|---|---|---|
  | `pss_counters(schema, toplevel)` (each poll) | `<ext>.pg_stat_statements(false)` joined with `pg_catalog.pg_database` | no (`showtext => false`) | catalog-only: no event for any account |
  | `pss_texts(schema, toplevel)` (new entries only) | `<ext>.pg_stat_statements(true)`, `s.query` cut at 8 192 characters, `WHERE s.queryid = ANY($1)` | **yes, every role's texts** | table-less: left out uncharged on its exact text (as sent with pgaudit; as stored with `pg_stat_statements`, with the agent's role oid, top level, the poller's database and the pinned `queryid`, #90); registered per target (`PgOwn::allow_statement`) |
  | `pss_probe(schema)` (`check()`, stream start) | `<ext>.pg_stat_statements_info` | no (`dealloc`, `stats_reset`) | catalog-only |
  | `AUDIT_PREREQUISITES`, `PSS_FUNCTION_SCHEMA` | `pg_extension`, `pg_depend`, `pg_class`, `pg_proc`, `pg_namespace` | no; the names `pg_stat_statements` and `pg_stat_statements_info` appear only as string literals | catalog-only |
  | `PGAUDIT_SETTINGS` | `pg_catalog.pg_settings` | no (settings) | catalog-only |

  No connector statement reads `pg_stat_activity`, `pg_stat_get_activity` or `pg_stat_get_backend_activity`, and `check()` reads none of them. The connector's integration tests (`it.rs`) read `pg_stat_activity` through their own test connections, for counts and states only.

### What the servers expose (PostgreSQL 14 to 18, the engine matrix)

From the PostgreSQL documentation and the system views' definitions as known on 2026-10-11, **not verified on the engine-matrix images for this ADR**. The drift and pinning tests of decision 8 verify them before the implementation is merged.

| Object | Kind | Statement text | Who sees other sessions' text | Versions |
|---|---|---|---|---|
| `pg_catalog.pg_stat_activity` | view over `pg_stat_get_activity(NULL)` | `query`: the current or last statement of each backend, as sent (literals included), cut at `track_activity_query_size` (1 024 bytes by default) | its own role's sessions and those of roles it has the privileges of; every session for superusers and `pg_read_all_stats` members (`pg_monitor` includes it) | 14 to 18 |
| `pg_catalog.pg_stat_get_activity(integer)` | set-returning function | the same `query` column (`NULL`: every backend) | same | 14 to 18 |
| `pg_catalog.pg_stat_get_backend_activity(integer)` | scalar function | the statement text of one backend (by backend id, enumerated with `pg_stat_get_backend_idset()`) | same | 14 to 18 |
| `<ext>.pg_stat_statements` | view of the extension over `pg_stat_statements(true)` | `query`: normalized for planned statements (constants as `$n`, comments kept); utility statements kept as sent on 14 and 15, partly normalized from 16 on (to verify per version), so `ALTER ROLE … PASSWORD` literals and SCRAM verifiers can be in it (ADR-0012) | `SELECT` is granted to `PUBLIC` by the extension script (to verify); other roles' texts need superuser or `pg_read_all_stats`, otherwise `<insufficient privilege>` | extension 1.9 to 1.12 (PostgreSQL 14 to 18) |
| `<ext>.pg_stat_statements(boolean)` | set-returning function | the same `query` column, `NULL` when called with `false` | same | same |

Not listed, and why:

- `<ext>.pg_stat_statements_info` (counters), `pg_stat_progress_vacuum`, `_analyze`, `_cluster`, `_create_index`, `_basebackup`, `_copy` (relation oids, phases, counters; no text column known on 14 to 18), `pg_locks`, `pg_stat_replication`, `pg_stat_wal_receiver` (`conninfo` with the password obfuscated), `pg_stat_subscription`, `pg_stat_ssl`, `pg_stat_gssapi`, `pg_stat_io` and the other cumulative statistics views: no statement text.
- `pg_prepared_statements` (`statement`), `pg_cursors` (`statement`) and `pg_backend_memory_contexts` (`ident`, which can hold the text of cached plans, 14+): **the reading session's own** statements only. Behind a transaction-mode pooler (PgBouncer with protocol-level prepared statements, 1.21+), one server session carries the prepared statements of several clients; this is a residual (open question 1).
- `pg_log_backend_memory_contexts(pid)` (14+, superuser by default) writes another backend's memory contexts to the server log, not to the client; table-less, it is already a read of `*`.
- **Extensions other than `pg_stat_statements`** that keep statement texts or constants: `pg_stat_monitor` (`query`, and literals when its normalization is off), `pg_qualstats` (constant values of predicates), `pg_store_plans` and `pg_show_plans` (plans with constants). Not in the dev or engine-matrix images, so nothing here is verified; open question 8. An **unqualified** `pg_*` name counts as a catalog today, so `SELECT * FROM pg_stat_monitor` gives no event, while `public.pg_stat_monitor` is reported as an ordinary relation.

### Who reads these views routinely

From the tools' documentation and common practice, not measured here:

- **Without the text.** Prometheus `postgres_exporter` (its default `pg_stat_activity` metrics: counts and longest transaction per database, state, user and application), pgwatch and check_postgres (`backends`, `txn_idle`), Patroni, connection-pool health checks, and applications that terminate their own idle sessions (`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND …`). `postgres_exporter`'s `pg_stat_statements` collector reads `queryid` and counters; the query text only when asked to.
- **With the text.** pgAdmin's dashboard, Datadog Database Monitoring and pganalyze (query samples from `pg_stat_activity`, normalized texts from `pg_stat_statements`), PMM, PoWA, and DBAs' scripts (`WHERE query NOT LIKE '%pg_stat_activity%'`).

`pg_stat_activity` is polled far more often than the statistics catalogs of ADR-0048, most often without the text. Every role can read its own role's texts: a shared application account sees the statements of every other session of that account, other end users' literals included.

### What the audit sources record

- **`pg_stat_statements`**: one entry per normalized text and role, `SELECT pid, query FROM pg_stat_activity WHERE state <> $1`. Function bodies are not recorded with `pg_stat_statements.track = top` (the default).
- **pgaudit**: a `READ` record with the text as sent. With `pgaudit.log_relation`, relation records name `pg_catalog.pg_stat_activity` and, as seen with the statistics views, probably the relations behind it (`pg_database`, `pg_authid`; to verify). With `pgaudit.log_catalog = off`, a statement whose relations are all in `pg_catalog` is not logged ([ADR-0048](0048-statistics-catalogs-as-reads.md) decision 5): a read of `pg_stat_activity` alone is invisible there. The `pg_stat_statements` view is in the extension's schema, not in `pg_catalog`, so its reads are logged whatever `log_catalog` says. Whether pgaudit logs a statement that names **no** relation (`SELECT * FROM pg_stat_get_activity(NULL)`) with `log_catalog = off` is to verify. `FUNCTION` class records are ignored by the connector, as today.

## Options

- **(a) A closed list, every read reported.** The listed views and functions are named as objects in read events, always reported, never the agent's own except its exact poll texts (ADR-0045 part (a), ADR-0048).
- **(b) The same, but a read that provably selects no text stays quiet.** A statement whose only access to the list is a read that names no text column, no whole row and no column renaming (decision 2) stays a catalog read, for every account. Every other read is (a).
- **(c) Report by reader**: only reads by roles that can see other roles' texts (`pg_read_all_stats` members, superusers).
- **(d) Document only** (the current state).

(c) does not hold: the sources do not say what the reader held at the time, a shared application account reads other sessions' texts of its own role with no special privilege, and checking every reader's grants would need catalog reads per principal. (d) leaves other sessions' literals, and on `pg_stat_statements` passwords and SCRAM verifiers in utility texts, readable with no event. (a) is the ADR-0045 and ADR-0048 answer, and ADR-0048 open question 4 rejected a column test for the statistics catalogs because whole-row references fail open. Here the noise is of another order (exporters, pools and health checks poll `pg_stat_activity` every few seconds, mostly without the text), and the column that matters is one, named `query`, in every listed relation. (b) keeps (a) for everything it cannot prove, so it fails closed as (a) does.

## Decision: option (b)

1. **The statement-text list** (identical on PostgreSQL 14 to 18; the drift test of decision 8 confirms it per image):

   | Name in the text | Kind | Named in events as | Text access |
   |---|---|---|---|
   | `pg_stat_activity` (qualified with `pg_catalog` or unqualified) | view | `pg_catalog.pg_stat_activity` | the column `query` |
   | `pg_stat_get_activity(` (same) | set-returning function | `pg_catalog.pg_stat_activity` | the column `query` |
   | `pg_stat_get_backend_activity(` (same) | scalar function | `pg_catalog.pg_stat_activity` | always (the result is the text) |
   | `pg_stat_statements` (qualified with the extension's schema of that database, or unqualified while the extension is installed there) | view | `<ext>.pg_stat_statements` | the column `query` |
   | `pg_stat_statements(` (same) | set-returning function | `<ext>.pg_stat_statements` | the column `query` |

   - Names are compared after the analyzer's identifier folding and `U&"…"` decoding, as in ADR-0048 (a quoted `"PG_STAT_ACTIVITY"`, a `public.pg_stat_activity` or a `pg_stat_statements` outside the extension's schema is an ordinary relation, reported as today).
   - An unqualified name is the catalog's: `pg_catalog` comes first in the search path unless a session lists it later, so a relation or function shadowing it is over-reported, never missed. An unqualified `pg_stat_statements(` in a database where the extension is not installed is a read of `*` (a user function).
   - **Function forms are named by their view**: the objects of events are relations in the contract, the three `pg_catalog` names read the same data, and policies then need one object per data set (open question 4).
   - `pg_stat_statements_info` stays a catalog (no text).
2. **The no-text shape, quiet for every account.** A statement that names a listed view or a listed set-returning function stays a catalog read for that name (no object, so no event when the other relations are catalogs too) only when **all** of these hold on the whole text:
   - the text lexes completely, is not cut (`pg_stat_statements` texts at the 8 192-character read bound, `<previously logged>` without its first record), and is below the analyzer's 16-relation bound;
   - no identifier token, quoted or not, after folding and `U&` decoding, equals `query`, anywhere in the text (a select list, a `WHERE`, `ORDER BY`, `USING (query)`, an alias `AS query`: the last one over-reports, never misses);
   - no `*` token, except the exact sequence `count(*)`;
   - no whole-row reference: every occurrence of a listed name, or of the alias that follows it in a `FROM` item, is either that `FROM` item or followed by `.` and a column name (so `row_to_json(a)`, `a::text`, `SELECT a FROM pg_stat_activity a`, `WHERE pg_stat_activity = …` and `(a).*` are text reads);
   - no column alias list after a listed `FROM` item (`FROM pg_stat_activity AS a(c1, …, c7)` renames `query` positionally);
   - no `NATURAL` join (a natural join with a relation that has a `query` column compares other sessions' texts without naming them);
   - a listed set-returning function appears only as a `FROM` item (`SELECT pg_stat_get_activity(NULL)` returns whole rows);
   - no `TABLE` form on a listed view (`TABLE pg_stat_activity`);
   - `pg_stat_get_backend_activity(` does not appear (it returns the text itself).

   Anything else that names a listed entry is a **text read**: the entry's object of decision 1, kept in the event even when every other relation is a catalog, in every action class, as ADR-0048 does for the statistics relations (`CREATE TABLE t AS SELECT query FROM pg_stat_activity`, `INSERT INTO t SELECT …`, `COPY (SELECT query FROM pg_stat_activity) TO STDOUT`). A text read at the analyzer's relation bound adds `*`, as today.

   The shape is decided on the statement text on both sources, never on pgaudit's relation records (they name relations, not columns). It covers the common monitoring reads (`SELECT state, count(*) FROM pg_stat_activity GROUP BY state`, `postgres_exporter`'s activity query, `SELECT pid FROM pg_stat_activity WHERE state = 'idle'`, `SELECT queryid, calls FROM pg_stat_statements`), and the connector's own `pss_counters` (decision 4).
3. **Always reported.** A text read carries the agent-internal always-reported mark (`MaskedEvent::always_report`), so the `audit.configure` filter (`min_rows`, `sensitive_objects`) never drops it, as in ADR-0045 decision 3 and ADR-0048 decision 3: one row of `pg_stat_activity` is one statement with its literals, and the pgaudit log without `pgaudit.log_rows` has no row count. The row count, when the source has one, counts rows of the view. No signal is added. Shape reads (decision 2) produce no event, so the filter does not apply to them.
4. **The agent's own account** (the counterpart of ADR-0045 decision 4).
   - **`pss_counters`** reads `pg_stat_statements(false)` with no text column: it has the no-text shape of decision 2 and stays a catalog-only read for every account, as today. A unit test proves it for both `toplevel` forms.
   - **`pss_texts`** is a text read, left out uncharged only by **exact text**, under a new own kind (`OwnKind::StatementText`):
     - with pgaudit: the whole text equals `pss_texts(schema, toplevel)` as sent, for a schema registered by an earlier `pg_stat_statements` stream of the target (`PgOwn::allow_statement`, as today), from the agent's account, `application_name` and client address, with no signal; its relation records, if any, name only relations that text names (none: it names a function);
     - with `pg_stat_statements`: the stored text equals its `pss_form`, and `OwnKeys::admit` holds (the agent's role oid, a top-level entry, the poller's database, the `queryid` pinned for that slot), as #90 does today.

     It is never matched by prefix, by normalized shape or by `queryid` alone. The text is already constant per (schema, `toplevel`): the entry list is a bound parameter, and the cut length and `LIMIT` are fixed in the text, so no change of the statement is needed (unlike ADR-0045's MySQL polls).
   - **Never the agent's own otherwise.** Any other text read of a listed entry with the agent's identity is reported and never charged to the row budget: the connector sends no other statement to them. This covers `SELECT query FROM pg_stat_activity` and `SELECT query FROM <ext>.pg_stat_statements` from the agent's role, which a stolen credential with `pg_read_all_stats` reads unreported today.
   - **Not listed, unchanged**: `check()` reads `pg_settings` (`PGAUDIT_SETTINGS`) and `pg_stat_statements_info` (`pss_probe`), which hold no statement text; they stay catalog reads. The connector reads `pg_stat_activity` nowhere.
   - A unit test over `sql::all_statements()` proves that every connector statement either names no listed entry, has the no-text shape, or is `pss_texts`, and that the names in `AUDIT_PREREQUISITES` and `PSS_FUNCTION_SCHEMA`, which are string literals, are not taken as names.
5. **`pgaudit.log_catalog`.** With `log_catalog = off`, a read of `pg_stat_activity` (or its functions, to verify) alone is not logged, as for the statistics catalogs. The `check()` local detail of ADR-0048 decision 5 names this effect too; the level is unchanged and no target note is added. The documentation keeps recommending `log_catalog = on`.
6. **SQL text passed to `pg_catalog` functions.** A call of a `pg_catalog` function that runs SQL text or reads a relation named by its argument (`query_to_xml`, `query_to_xmlschema`, `query_to_xml_and_xmlschema`, `cursor_to_xml`, `cursor_to_xmlschema`, `table_to_xml`, `table_to_xmlschema`, `table_to_xml_and_xmlschema`, `schema_to_xml*`, `database_to_xml*`, `ts_stat`, `ts_rewrite`: the list `sql.rs` already refuses in row-level security policies, `policy_function_ok`) adds `*` to the statement's read, always reported, never the agent's own, **also when every relation the statement names is a catalog**. Without this, any listed entry can be read through `query_to_xml('select query from pg_stat_activity', …)` next to a catalog. The connector calls none of them (unit test; the names appear only in a regular-expression literal). Wider cases are open question 7.
7. **Readers.**
   - **The agent's role.** `pg_read_all_stats` stays the expected Audit grant (ADR-0012 minimal variant), and `pg_monitor` stays flagged by `privilege.predefined_roles`, as today. When pgaudit is the source (Full or Partial), `pg_read_all_stats` serves only the fallback to `pg_stat_statements` and still exposes every role's texts to whoever holds the agent's credentials: `check()` says so in the agent's local detail, as `privilege.performance_schema_unused` does on MySQL / MariaDB. No new target note in this ADR (open question 5).
   - **Other roles.** `check()` does not report other roles' memberships of `pg_read_all_stats` or `pg_monitor`: it reports on the agent's own account. [05-security.md](../05-security.md#recommended-database-accounts-read-only) gives the catalog query that lists them (open question 6). The events of decisions 2 and 3 do not depend on the reader's privileges: a role that sees only its own role's texts is reported too.
8. **Drift and pinning tests** (integration, engine matrix, every PostgreSQL image, with `pg_stat_statements` created):
   - every relation of `pg_catalog`, `information_schema` and the extension's schema with a column named `query`, `statement`, `query_text`, `current_query`, `ident`, `plan`, or ending in `_query` / `_statement`, and every function of `pg_catalog` and the extension with an `OUT` / `TABLE` argument of those names or whose name matches `pg_stat_get_%activity%`, is listed or on a commented exception list (`pg_prepared_statements`, `pg_cursors`, `pg_backend_memory_contexts` and their functions: the reading session's own; `pg_stat_get_backend_activity_start` and similar: timestamps);
   - pinning, one assertion each: a role without `pg_read_all_stats` sees `<insufficient privilege>` in another role's `pg_stat_activity.query` and its own texts in clear; `PUBLIC` can read the `pg_stat_statements` view; a utility statement with a literal is kept as sent in `pg_stat_statements` (per version, so that a normalization change is seen).
9. **I2.** Only fixed names leave the agent (decision 1, through [ADR-0009](0009-name-normalization-and-item-sanitization.md) normalization; the extension's schema name as probed today). No column of these views is read by the analysis, the agent keeps no statement text beyond what it keeps today, and the `AccessEvent` contract is unchanged: no new field, signal or note.

## Consequences

- **Code** (`agent-engineer`, `security-reviewer` review):
  - `connector-postgres/src/audit/events.rs`: the list of decision 1, `is_catalog` false for a listed entry in a text read, the shape test of decision 2, the always-reported mark, `OwnKind::StatementText` and its exact-text rule on both sources, the SQL-running function rule of decision 6;
  - `connector-postgres/src/audit/pss.rs`: the own text query admitted under the new kind (the `OwnKeys` slot rule is unchanged);
  - `connector-postgres/src/check.rs`: the local detail of decision 7;
  - `classifiers/src/query.rs`: a token-level helper for the PostgreSQL dialect that reports calls of given names and the facts of the shape test (identifier tokens equal to a name, `*` outside `count(*)`, whole-row references, column alias lists, `NATURAL`), so that `connector-postgres` holds the names.

  No `shared/protocol/` change.
- **Tests**:
  - unit tests on both sources (pgaudit with and without `log_relation`, `log_catalog` on and off; `pg_stat_statements`): each listed entry qualified, unqualified, quoted, `U&`-escaped, in a join with an application table, in a subquery, a CTE, a `DO` body, a `COPY (…) TO`, a `CREATE TABLE … AS`; each condition of decision 2 met (quiet) and broken one at a time (`query`, `"query"`, `U&"\0071uery"`, `*`, `a.*`, `row_to_json(a)`, `a::text`, a column alias list, `NATURAL JOIN`, `TABLE pg_stat_activity`, `SELECT pg_stat_get_activity(NULL)`, `pg_stat_get_backend_activity(1)`, a cut text), each a text read, always reported with `min_rows` set, never charged to the agent; `pss_counters` quiet and `pss_texts` left out for the agent only on its exact text, reported with one byte changed, from another role, nested, in another database, under a second `queryid`; `query_to_xml` and `table_to_xml` next to a catalog reported against `*`; the every-connector-statement test of decision 4.
  - integration tests on PostgreSQL 14 to 18 (engine matrix) and on the every-change PostgreSQL version: a second role with `pg_read_all_stats` reads `pg_stat_activity.query` and `pg_stat_statements.query` and gets read events naming them, on `pg_stat_statements` and on pgaudit (`log_catalog = on`, the dev setting since ADR-0048); `SELECT state, count(*) FROM pg_stat_activity GROUP BY state` gives none; a role without `pg_read_all_stats` reading its own role's texts gets an event; the agent's own polls give none on either source. The drift and pinning tests of decision 8.
  - **Load harness** (`e2e/load/`, `load` job, PostgreSQL scenario, both sources): an exporter-like account running `postgres_exporter`'s activity query every 5 s (zero events), a monitoring-like account reading `SELECT pid, query FROM pg_stat_activity WHERE state <> 'idle'` and `SELECT queryid, query FROM pg_stat_statements` every 10 s (at most one event per principal, object set and aggregation window). Audit events must still equal the application statements, and agent CPU and memory must not change beyond noise.
- **Load impact.** The shape test runs only on texts that name a listed entry (a token scan of a text the analyzer already lexes); nothing changes for other statements. No new query is sent to the database. Events: none for no-text monitoring; for text readers, one event per principal, object set, action and source per `aggregation_window_s` (60 s by default), under the console's per-target hourly cap ([ADR-0021](0021-access-event-correlation.md)): a monitoring account reading texts every 10 s is at most 1 440 events per day and target.
- **Noise.** Query-sampling tools (Datadog DBM, pganalyze, PMM, PoWA, pgAdmin's dashboard) and DBAs' scripts now produce events. As in ADR-0045 and ADR-0048, there is no agent-side allow-list; the console can scope or exclude principals, and baselines learn the pattern.
- **Documentation** (`docs-keeper`, after the implementation): in [08-engine-capabilities.md](../08-engine-capabilities.md#postgresql-audit), the known limit "statement-text views" becomes described behaviour (the list, the no-text shape, the always-reported mark, the own text query, the noise note); the own-account section names `pss_texts` as a text read matched by exact text; [05-security.md](../05-security.md#recommended-database-accounts-read-only) lists who reads statement texts (`pg_read_all_stats`, `pg_monitor`, superusers, and every role for its own role's sessions) with the membership query; [10-user-guide.md](../10-user-guide.md) gains a sample policy on `pg_catalog.pg_stat_activity` and `<ext>.pg_stat_statements`.
- **Estimated size.** About 250 lines of production code (150 in `connector-postgres`, 100 in the classifiers helper), 600 lines of unit tests, 200 lines of integration tests, the drift and pinning tests and the load scenario; 2 to 3 days with one review round.
- **Residual risks.**
  - With pgaudit and `pgaudit.log_catalog = off`, a read of `pg_stat_activity` alone gives no event (decision 5).
  - A user view, a SQL or PL/pgSQL function or a procedure over a listed entry is named by what the statement shows (the view, or `*`); with `pg_stat_statements.track = top`, function bodies are not recorded. Dynamic SQL in PL/pgSQL (`EXECUTE`) is not analyzed; pgaudit logs it as a substatement with its own text.
  - On `pg_stat_statements`, a read through a cursor (`DECLARE … CURSOR FOR SELECT query FROM pg_stat_activity`, then `FETCH`) or an `EXPLAIN ANALYZE` of such a read gives no event (the ADR-0048 residual, ROADMAP follow-up).
  - The no-text shape lets every account read the other columns of `pg_stat_activity` unreported: user names, client addresses, application names, states and times, which are session metadata. A column holding statement text added by a later server version is caught by the drift test, not by the shape.
  - The agent's own text query stays a way for a holder of the agent's credentials to read every role's texts unreported, when it passes the identity rules (pgaudit) or shares the pinned entry (`pg_stat_statements`): the existing residual of [08](../08-engine-capabilities.md#the-agents-own-account), unchanged.
  - Own-session views behind a transaction-mode pooler (open question 1), extensions other than `pg_stat_statements` (open question 8), and function calls next to catalogs other than decision 6's list (open question 7).
  - The server facts of the context table were not run for this ADR; the pinning tests confirm them before the implementation is merged.

## Rejected alternatives

- **Option (a)**, every read reported: the no-text reads of exporters, pools and health checks would each be an always-reported event per principal and window on most targets, for reads that return no statement text. Kept for everything decision 2 cannot prove.
- **Option (c)**, by reader: the sources do not record the reader's privileges, and a shared application role reads its own sessions' texts with none.
- **Option (d)**, document only: other sessions' literals, passwords and SCRAM verifiers readable with no event.
- **A column test that looks for `query` only** (as ADR-0048 open question 4 rejected): whole-row references, column alias lists and natural joins read or compare the text without naming it. Decision 2 refuses each of them, so it proves the absence of text access instead of looking for its presence.
- **Charging the agent's row budget** for its text query or for other reads of the list: the connector's one text read is matched exactly, and a budget would let a stolen agent credential read up to `limits.max_sample_rows` texts per object and day unseen.
- **Naming the function forms by their own names** (`pg_catalog.pg_stat_get_activity`): two objects for one data set, which policies would both have to name (open question 4).

## Open questions

Each question has the answer this ADR recommends; the maintainer decides.

1. Scope: is the list of decision 1 right (`pg_stat_activity`, `pg_stat_get_activity`, `pg_stat_get_backend_activity`, `pg_stat_statements` view and function), with the reading session's own views (`pg_prepared_statements`, `pg_cursors`, `pg_backend_memory_contexts`) left out?
   **Recommended**: yes. The own-session views show what the reading session itself prepared or opened; behind a transaction-mode pooler they can show other clients' prepared texts, which is documented as a residual rather than listed, because every pooled application would then report its own driver's reads.
2. Option (b), the no-text shape quiet for every account, or option (a), every read reported as in ADR-0048?
   **Recommended**: (b). Unlike the statistics catalogs, `pg_stat_activity` is polled every few seconds by exporters, pools and health checks, mostly without the text; the shape refuses every way of reading or comparing `query` without naming it that is known here, and anything it cannot prove is (a).
3. Always report text reads, whatever `min_rows` and `sensitive_objects` say (decision 3), or let the filter apply?
   **Recommended**: always report, as ADR-0045 and ADR-0048 do. One row is one statement with its literals, and the pgaudit log without `log_rows` has no row count.
4. Name the function forms by their view (`pg_catalog.pg_stat_activity`, `<ext>.pg_stat_statements`), by their own names, or as `*`?
   **Recommended**: by their view: one object per data set for policies and baselines, fixed names only (I2).
5. `pg_read_all_stats` held while pgaudit is the source: the agent's local detail only (decision 7), or a new target note mirroring MySQL / MariaDB `privilege.performance_schema_unused` (an addition to `shared/protocol/target-notes.json`, with its console phrase and a security review)?
   **Recommended**: local detail and documentation only in this ADR. The grant is the fallback source ADR-0012 sets in the minimal variant; revisit with a note if operators want the console to show it.
6. Other roles holding `pg_read_all_stats` or `pg_monitor`: a `check()` count note, or documentation only?
   **Recommended**: documentation only, with the membership query in 05-security. `check()` reports on the agent's own account, and the events already show who reads the texts.
7. Decision 6 (the SQL-running `pg_catalog` functions next to catalogs): keep it in this ADR, and should calls of non-`pg_catalog` functions in catalog-only statements (`dblink(…)`, a user function next to `pg_class`), which give no event today either, be covered too?
   **Recommended**: keep decision 6 here, since it closes a direct bypass of the list. The wider case is a PostgreSQL counterpart of ADR-0045 part (b) and gets its own ROADMAP follow-up.
8. Extensions that keep statement texts or constants (`pg_stat_monitor`, `pg_qualstats`, `pg_store_plans`, `pg_show_plans`): list them here, scoped to their extension's schema like `pg_stat_statements`, or a follow-up?
   **Recommended**: a follow-up, once a dev or engine-matrix image carries them so that their columns can be verified; until then, documented as a known limit, with the note that their unqualified names count as catalogs.
9. The pinning facts of decision 8 and the pgaudit behaviour for function-only statements with `log_catalog = off` are unverified here: verify them in the implementation PR, or before the ADR is accepted?
   **Recommended**: in the implementation PR, before merge, as ADR-0048 did; a fact that differs is recorded as a refinement of this ADR.
