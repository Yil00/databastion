# ADR-0055: Name case semantics reported by the agent for MySQL / MariaDB and SQL Server

- **Status**: Accepted (2026-10-21). **Accepted** by the maintainer on 2026-10-21 with the proposed answer to every open question (see [Open questions](#open-questions-answered)). History: proposed on 2026-10-20, revised the same day after its security review ("sound after changes": H1, M1 to M3, L1 to L9)
- **Date**: 2026-10-20
- **Refines**: [ADR-0054](0054-case-sensitive-location-exceptions.md) (which stays Accepted), decision 3 (exceptions on MySQL / MariaDB and SQL Server stay case-insensitive "until the agent reports the case semantics"); this is its option D, whose ADR the maintainer asked for on 2026-10-20 (ADR-0054 open question 3). Uses [ADR-0022](0022-protocol-capability-negotiation.md) (capability negotiation) without changing it
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups); [ADR-0009](0009-name-normalization-and-item-sanitization.md) (name normalization), [ADR-0014](0014-policy-and-incident-model.md) decision 1, [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) / [ADR-0020](0020-mysql-mariadb-connector-as-merged.md) (MySQL / MariaDB account and statements), [ADR-0021](0021-access-event-correlation.md) decision 5, [ADR-0045](0045-mysql-mariadb-statement-text-tables-and-unqualified-calls.md) (the agent's own constant texts), [ADR-0051](0051-sqlserver-connector.md) decisions 4 and 5 and its statement allow-list (end-of-phase-9 review L1); [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine) (collation residuals); `shared/protocol/openapi.yaml` (`TargetStatus`, `Identifier`); `console/src/lib/policy-common.ts` (`exceptionGlobOptions`, `TRAILING_SPACE_BLIND_ENGINES`), `console/src/lib/policy-model.ts` (`exceptionCovers`), `console/src/lib/event-model.ts` (`exceptionCoversEvent`), `console/src/server/agent-api/capabilities.ts`; `agent/crates/classifiers/src/query.rs` (MySQL tokenizer and `RelationName`), `agent/crates/classifiers/src/tsql.rs`, `agent/crates/connector-mysql/src/sql.rs`, `check.rs` and `audit/own_threads.rs` (`ServerRun`), `agent/crates/connector-sqlserver/src/sql.rs` (`STATEMENTS`, `VERSION`, `ACCESSIBLE_DATABASES`, `USER_DATABASES`) and `check.rs` (read at `4cd45dd`, `dev`)

## Context

ADR-0054 (accepted on 2026-10-20) makes location exceptions compare with case on PostgreSQL, MongoDB, Redis, Valkey, CAS and unknown engines: an exception must match both with and without the case fold. On `mysql`, `mariadb` and `sqlserver` exceptions stay case-insensitive, because whether two names that differ only by case are two objects depends on server settings the console does not know. ADR-0054 decision 3 records the residual: `lower_case_table_names = 0` is the Linux default, so most MySQL / MariaDB targets keep the over-suppression ADR-0054 removes elsewhere, and so do SQL Server databases under a case-sensitive collation.

What the engines do:

- **MySQL / MariaDB.** `lower_case_table_names` decides database and table names (and table aliases, triggers): **0** stored as given and compared with case (the Linux default); **1** stored in lowercase and compared without case (the Windows default); **2** stored as given and compared in lowercase (the macOS default). Column names are always compared without case, and so are routine names and `information_schema` names, whatever the setting. MySQL 8.0+ sets the value at data directory initialization only; MariaDB reads it at each start. Both variables below are readable by any account (`@@GLOBAL.…`, no privilege). Facts from the security review, to record in the [phase 9 engine facts](../measurements/phase9-engine-facts.md) when measured:
  - 2 on a case-sensitive file system is forced to 0 by the server; the agent reads the effective `@@GLOBAL` value, never a configuration file;
  - 0 on a file system that ignores case (`lower_case_file_system = ON`): MySQL 8.0+ refuses to start; MariaDB switches to 2 unless forced. Only a MariaDB server forced to 0 there runs with 0 on such a file system (open question 2);
  - a database directory or a table's `DATA DIRECTORY` on another file system (MariaDB symbolic links, per-table tablespaces) may ignore case; the agent's account cannot inspect that (no `FILE` privilege, invariant I4).
- **SQL Server.** Database names are compared under the server collation (`SERVERPROPERTY('Collation')`). Schema, object and column names are compared under the database's catalog collation: the database collation (`sys.databases.collation_name`), except in a contained database, whose catalog collation is fixed (`Latin1_General_100_CI_AS_KS_WS_SC`, case-insensitive), and a database whose `sys.databases.catalog_collation_type` names another one (decision 4). A collation compares with case when `COLLATIONPROPERTY(<name>, 'ComparisonStyle')` lacks the ignore-case bit (1): every `_CS_` collation, and every binary (`_BIN`, `_BIN2`) collation, for which it returns 0. Trailing spaces are padded, so ignored, under binary collations too. `collation_name` is `NULL` for a database that is not online, and for one closed by `AUTO_CLOSE` (on by default on Express). The connector reads `SERVERPROPERTY` (`sql::VERSION`) and `sys.databases` today, but only the databases it can enter: `ACCESSIBLE_DATABASES` and `USER_DATABASES` filter on `HAS_DBACCESS`, `state = 0` and `source_database_id IS NULL` (snapshots left out), and `sys.databases` lists every database only with `VIEW ANY DATABASE` (granted to `public` by default, and revocable).

**Names as the agent sends them.** A case-sensitive rule is only as good as the spelling it compares. On SQL Server the statement text keeps the client's spelling (`classifiers::tsql`), and under a case-sensitive collation a statement naming an object in another case than stored fails. On MySQL / MariaDB, `classifiers::query` lowercases every unquoted identifier in ASCII while tokenizing (`Tok::Word(… .to_ascii_lowercase())`; `RelationName` documents "unquoted ones lowercased"), and only backquoted names keep their case. With `lower_case_table_names = 0`, a read of `crm.Customers` written without backquotes therefore reaches the console as `crm.customers`, the name of another table: a case-sensitive exception would both over-suppress (a read of `Customers` covered by an exception for `customers`) and miss (an exception for `Customers` not covering unquoted reads of it). Reporting `sensitive` for MySQL / MariaDB names is only correct once every source sends the server's spelling (decision 3).

On a case-insensitive engine the names the console receives may be spelled as the client wrote them, while Discovery sends the catalog's spelling; a case-sensitive exception there would stop covering `CRM.CUSTOMERS` for the table `crm.customers`, which is one object: more incidents, not fewer. On a case-sensitive one, a case-insensitive exception also covers a distinct object. The console needs to know which one it is, per database for SQL Server, and per location part (database names and object names can differ on SQL Server; column names never compare with case on MySQL / MariaDB).

Phase 10 engines: SQLite compares identifiers without case for ASCII letters only, whatever the configuration; Firebird folds unquoted identifiers to uppercase and keeps quoted ones, which makes its names case-sensitive as sent (the PostgreSQL rule). Neither depends on a server setting as far as known today; their connector ADRs decide.

## Options

### (1) A `TargetStatus` field negotiated per ADR-0022

The agent reports, at each `check()`, how the target compares names: one value for database names, a default for schema, object and column names, and the databases that differ from that default (bounded). An optional `TargetStatus` field under a capability token; the console keeps the latest value per target, as it does for `notes`, and applies it at every exception evaluation (findings at their next evaluation, events at ingestion).

### (2) A per-location flag on findings and events

`Location` and the event object carry a flag (`case_sensitive`, or one per part), set by the connector for each name it sends. Exact at the time of the observation; but one more field on every item, two schemas changed (`Location` and the event object) with their tokens, a column on findings and event objects, stored rows without it forever, and two bits per item (SQL Server database names under the server collation, the other parts under the database's). Exception evaluation of stored findings (a full pass after an exception change) would read the flag stored with each finding, not the server's current setting.

### (3) One target-level value in the heartbeat

A single `sensitive | insensitive | unknown` per target. Enough for MySQL / MariaDB (the setting is server-wide), not for SQL Server, where a server under the default collation can hold one database with a `_CS_` collation: either that database's exceptions stay loose, or every database's become strict.

### (4) Target notes

A registered note code (`check.names_case_sensitive`) needs no negotiation (ADR-0022 decision 5). But notes explain a status to a human, carry no database names, are capped at 16 per target, and would turn a rendering registry into a matching input.

### (5) Declared by an administrator on the console

A per-target setting "names compare with case". The console cannot verify it, it is wrong after a server is rebuilt, and on SQL Server it is per database. Only a "stricter only" form would be safe (open question 4).

## Decision

Option (1).

1. **Contract.** `TargetStatus` gains an optional `name_case`, under the capability token `target_status.name_case` (ADR-0022 decision 2), for `mysql`, `mariadb` and `sqlserver` targets only:

   ```yaml
   NameCase:
     type: string
     enum: [sensitive, insensitive, unknown]
   TargetNameCase:
     type: object
     additionalProperties: false
     required: [databases, objects]
     properties:
       databases: { $ref: NameCase }   # how database names compare
       objects:   { $ref: NameCase }   # default for schema, object and column names
       except:                         # databases whose object names compare otherwise
         type: array
         maxItems: 32
         items:
           type: object
           additionalProperties: false
           required: [database, objects]
           properties:
             database: { $ref: Identifier }
             objects:  { $ref: NameCase }
   ```

   No free text, no collation name, no setting value: three closed values and database names (I2, decision 9). Types generated on both sides (I6).
2. **Always sent, never omitted (security review M1).** Once the console lists the token, an agent that implements this ADR sends `name_case` in every `TargetStatus` of a `mysql`, `mariadb` or `sqlserver` target, also when `check()` fails, times out or cannot reach the server: then it sends the last value read on the same server run (`ServerRun`, the identity the MySQL / MariaDB connector already keeps in `audit/own_threads.rs`, and, for SQL Server, an identity to add with this ADR, such as `sqlserver_start_time` from `sys.dm_os_sys_info` with the server name; the SQL Server connector keeps none today), else `{databases: unknown, objects: unknown}`. Only agents built before this ADR omit it. Otherwise an insider who exhausts the agent's connections would turn exceptions back to case-insensitive.
3. **MySQL / MariaDB spelling prerequisite (security review H1).** The agent reports `sensitive` for MySQL / MariaDB names (`databases` and `objects`) only once every Discovery and Audit source of that connector sends names as the server stores them under `lower_case_table_names = 0`:
   - Discovery sends the catalog's names (already the case);
   - the statement-text analysis (`classifiers::query`, used for `server_audit`, Percona `audit_log` and `performance_schema` texts) keeps unquoted identifiers as written and folds them only for its own analysis (keyword matching, the always-reported lists, own-text matching): under 0 a statement naming a table in another case than stored fails, so the text's spelling is the stored one for every statement that read it. The fold becomes dialect- and setting-dependent (the setting read by `check()`; with 1 or 2, or unknown, names may stay lowercased since the console compares them without case);
   - names taken from audit records (`server_audit` table records, Percona `table_access`) are sent as the record gives them.

   Until this lands (a ROADMAP follow-up, `agent-engineer`, with its own `security-reviewer` review), an agent implementing this ADR reports `insensitive` for MySQL / MariaDB whatever the setting, with the setting in `check()`'s local detail: today's behaviour, no new over-suppression. SQL Server needs no such change: `classifiers::tsql` keeps the text's spelling.
4. **What the agent reports**, from statements added to each connector's constants, read at each `check()` with the existing timeouts; no grant changes (I4):
   - **MySQL / MariaDB**: `SELECT @@GLOBAL.lower_case_table_names, @@GLOBAL.lower_case_file_system`, a constant that joins the connector's own constant texts and the guard's exact-text matching (ADR-0045) (security review L7). With decision 3 met: 0 gives `databases` and `objects` `sensitive`, also with `lower_case_file_system = ON` (a MariaDB forced to 0; the stricter answer, open question 2); 1 or 2 give `insensitive`; anything else, or a failed read, `unknown`. No `except`: the setting is server-wide. Column names are not reported: the console never compares MySQL / MariaDB `field` globs with case (decision 6).
   - **SQL Server** (security review M3, L5): one new statement over **every** `sys.databases` row, without the `HAS_DBACCESS`, `state` or `source_database_id` filters (snapshots and databases the login cannot enter included), with `TOP (n + 1)`, reading for each row its name, `database_id`, `create_date`, `collation_name`, `containment`, `is_auto_close_on`, `state` and, where it exists, `catalog_collation_type`; plus `SERVERPROPERTY('Collation')` and `HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE')`. It joins `sql::STATEMENTS`, with the deny-list check and a test that its own text is matched exactly (`own_text == Exact`) (L7). Then:
     - `databases` from the server collation's `ComparisonStyle`;
     - each database's catalog collation: `catalog_collation_type` 0 is the database collation, or for a contained database the fixed `Latin1_General_100_CI_AS_KS_WS_SC`; 2 is `SQL_Latin1_General_CP1_CI_AS`; any other value is `unknown`. On a version where the column does not exist the target reports `objects: unknown` until a measurement decides otherwise (the field is still sent, never omitted);
     - `objects` is the server collation's value (new databases take it by default); a database whose value differs is listed in `except`; a database whose collation reads `NULL` or whose `ComparisonStyle` cannot be read is listed as `unknown`;
     - `AUTO_CLOSE` (M2): while a database has `is_auto_close_on = 1` and `state = 0` and its `collation_name` reads `NULL`, the agent keeps its last known collation for the same (`database_id`, `create_date`) on the same server run, so that the value does not flap with each close; with none known it is `unknown`. Whether `DATABASEPROPERTYEX(name, 'Collation')` answers on a closed database is measured, and if it does it replaces the memory;
     - `objects: unknown`, with `except` omitted, when `HAS_PERMS_BY_NAME(…, 'VIEW ANY DATABASE')` is 0 (the list may be partial), when the row bound is reached, when more than 32 databases would be listed, or when the serialized `except` would pass an agent-side byte bound (L4: 8 KiB, well under the console's 4 MiB default heartbeat limit; the request has no maximum-size header the agent could read).
   - **Merged names.** Database names go through the same `classifiers::names` pipeline as locations (ADR-0009 normalization and sanitization; L3). Databases whose names reach the console as one name (the `*` of a classifier-matched name, stripped characters) are one entry with the stricter value (`sensitive` before `unknown` before `insensitive`).
5. **Fail-closed direction.** A case-sensitive exception covers a subset of what a case-insensitive one covers (ADR-0054 decision 1), so "sensitive" is the stricter reading, and its cost is noise (an exception written in another case than the stored name stops covering it), never a hidden read:
   - `unknown` is treated as `sensitive`;
   - a missing `name_case`, which only an agent built before this ADR or a console that did not list the token produces (decision 2), keeps today's behaviour, case-insensitive, so that upgrading the console alone changes nothing on these engines (open question 1);
   - the value is replaced at every heartbeat; a rolled-back agent falls back to today's behaviour.
6. **Console rule.** `name_case` is applied only when the item's engine is `mysql`, `mariadb` or `sqlserver`; on every other engine it is ignored, whatever its value (L6). Then `exceptionGlobOptions` takes the target's `name_case` and the location's database and returns options per part:
   - `database` part: `matchCase` when `databases` is `sensitive` or `unknown`;
   - `schema`, `object`: `matchCase` when the database's value is `sensitive` or `unknown`. The database's value is looked up in `except`: when `databases` is `insensitive`, among the entries whose name matches after the N1 fold; otherwise it is the stricter of the exact entry (or `objects` without one) and every entry that matches after the fold (L2). On `sqlserver`, `mysql` and `mariadb` the lookup ignores trailing spaces (the N1 rule). Among several entries the stricter value wins;
   - `field`: on `sqlserver` as `object`; on `mysql` and `mariadb` never with case (column names);
   - an event object whose database is `*` takes the strictest of `objects` and every `except` value (L1).

   The matcher, the conjunction of ADR-0054 decision 1, trailing spaces, conditions, scores, the dedup key and the agent's `sensitive_objects` match are unchanged.
7. **Storage, inventory and notice.** The console stores the value with a compare-and-set in the heartbeat's transaction, so that exactly one replica sees each change (L8). When a target's effective rule changes (its first `name_case`, a change of any value, or its loss), that replica runs the ADR-0054 decision 6 inventory for that target (same bound, ids and counts only, JavaScript comparison). The inventory and its audit entry are debounced: at most one per target and hour, changes within the hour coalesced into the next run (M2). The target page shows how its names are compared (with case, without case, per database, unknown and treated as with case, not reported), and the exception form's ADR-0054 hint names these engines as "according to the server's settings".
8. **Compatibility.**
   - Old agent, new console: no `name_case`, today's behaviour.
   - New agent, old console: the token is not listed, nothing is sent (ADR-0022 decision 2).
   - Multi-replica consoles list the token only once every replica accepts the field (ADR-0022 decision 8).
   - A `400` on a heartbeat carrying it clears the capabilities (ADR-0022 decision 9, already implemented for heartbeats).
9. **Database names in the heartbeat (L3).** `except` can name databases the agent never sent in a finding or an event (SQL Server databases out of the scan's scope, snapshots, databases the login cannot enter): the heartbeat becomes an inventory of database names for the console. Names only, normalized and sanitized like every location, so I2 holds. [05-security.md](../05-security.md) and [09-agent-protocol.md](../09-agent-protocol.md) record it among the connector and protocol obligations when this ADR is implemented.
10. **Test obligations.**
    - Contract: schema, fixtures with each value and an `except` list, drift tests, the token in the console's constant and behind `console_accepts` in the agent.
    - Agent, spelling (H1): per source (`server_audit`, Percona `audit_log`, `performance_schema`; SQL Server Audit and the Extended Events relation pass), with `lower_case_table_names = 0` and a case-sensitive collation respectively, tables `Customers` and `customers` read unquoted and quoted (backquoted, bracketed) reach the console as written; the analysis results (always-reported lists, own texts, signatures) unchanged by the spelling; with 1 the old lowercasing is allowed.
    - Agent, MySQL / MariaDB: integration tests on every engine-matrix version with 0 (the dev default), and one MySQL and one MariaDB entry initialized with 1, asserting the reported values (and `insensitive` while decision 3 is not met); unit tests of the mapping, a failed read as `unknown`, and a failed `check()` sending the last value of the server run or `unknown` (M1); the new constant matched as an own text.
    - Agent, SQL Server: on 2019, 2022 and 2025, a server under the default collation holding a database with a `_CS_` collation, one with a `_BIN2` collation, a default one, a snapshot, an `AUTO_CLOSE` database closed between two checks (no flapping), and, where the dev service can enable contained databases, a contained database with a `_CS_` collation (reported `insensitive`); `VIEW ANY DATABASE` revoked from `public` (`objects: unknown`); the row, entry and byte bounds; an offline database (`unknown`); the presence of `catalog_collation_type`, `AUTO_CLOSE` behaviour and the `DATABASEPROPERTYEX` answer on a closed database recorded in the [phase 9 engine facts](../measurements/phase9-engine-facts.md); a unit test where a database name matched by a classifier reaches `except` as `*` (L3).
    - Console (L6): a property test that, on any engine other than the three, the exception result is the same for any `name_case` value, hostile ones included; a property test that, on the three, a cover under `name_case` implies today's cover, with the trailing-space rule unchanged; per-part option tests over every combination of `databases`, `objects`, `except` and a missing field; lookups folded and exact, the merged `*` entry and the database `*`; the compare-and-set and the debounced inventory.
    - End to end: on the SQL Server end-to-end target, a `_CS_` database holding `Customers` and `customers`, with an exception for one of them only, raising an incident for the other; the same on MySQL with `lower_case_table_names = 0` once decision 3 is met; the I2 check unchanged.
11. **Review.** The protocol change, the classifier change of decision 3 and the console rule get `security-reviewer` reviews before they merge (CLAUDE.md, `shared/protocol/`).

## Consequences

- On SQL Server databases under a case-sensitive collation, and, once decision 3 is met, on MySQL / MariaDB with `lower_case_table_names = 0` (the common Linux case), an exception no longer suppresses an object whose name differs from its globs by case only, once both sides run this change.
- More incidents after the agents are upgraded where exceptions are written in another case than the stored names (the inventory names them), and noise wherever `unknown` is reported, on a MariaDB forced to 0 on a case-insensitive file system, and for routine and `information_schema` names under 0 (compared without case by the server).
- The own-read budget keys are lowercased on every engine (security review of #197, M2): under `lower_case_table_names = 0` two tables that differ only by case share one budget. That only reports sooner (fail closed); a follow-up may key them by the server's rule once decision 3 lands.
- The heartbeat carries up to 32 database names per SQL Server target, some never sent before (decision 9).
- Each new engine's connector ADR states whether it reports `name_case` or has a fixed rule in the console's engine lists (ADR-0054 consequences).
- Statement allow-lists and grant documentation gain the new reads (05-security), with no new privilege.

### Residual risks

- **Between two heartbeats.** A database whose collation changes (`ALTER DATABASE … COLLATE`), or one created with a non-default collation, is judged by the previous report until the next `check()`: events of that interval use the older rule.
- **Collation is more than case.** Accent-, kana- and width-insensitive collations, Turkish case pairs and `ß` are not modelled (docs/08, collation residuals): on those, exceptions cover less than the server's notion of one name, never more.
- **ADR-0009 merges** (stripped characters, NFKC) remain the ADR-0054 residual; decision 4 only keeps the stricter value for merged database names.
- **A wrong `insensitive` report** (a compromised agent or a connector bug) loosens exceptions back to today's behaviour on that target, no further; a compromised agent can already withhold events.

## Rejected alternatives

- **(2) A per-location flag**: one more field and column on every item for a setting that changes only with DDL or a server rebuild; stored findings would keep the flag of their scan rather than the server's current rule.
- **(3) A single target-level value**: wrong for SQL Server servers mixing collations; decision 4 falls back to it (`objects` without `except`) when the list overflows, in the stricter direction.
- **(4) Target notes**: a human-facing registry used as a matching input, without database names and with a 16-note cap.
- **(5) An administrator's declaration**: unverifiable and stale; see open question 4 for a stricter-only variant.
- **A missing field read as `sensitive`**: every MySQL / MariaDB and SQL Server exception would turn strict when the console is upgraded before the agents, including on the default case-insensitive SQL Server collation, where text spellings vary; the noise would push administrators towards broad `*` exceptions. Open question 1.
- **Omitting the field when `check()` fails**: anyone who can make `check()` fail would loosen exceptions (security review M1).
- **Reporting `sensitive` on MySQL / MariaDB before decision 3**: names folded by the agent would be compared with case, both over-suppressing and adding noise (security review H1).
- **Listing only the databases the login can enter** (the existing `ACCESSIBLE_DATABASES` read): databases it cannot enter, snapshots and offline databases would silently take `objects` (security review M3).
- **Reporting the collation names or the setting values**: free-form strings the console does not need; three closed values say what matters.

## Open questions (answered)

Each answer is the proposed one, accepted by the maintainer on 2026-10-21.

1. A missing `name_case` (agents built before this ADR): keep today's case-insensitive behaviour (proposed), or treat it as `unknown`, so as `sensitive`, from a given release on? Proposed answer: today's behaviour; the upgrade notes ask to upgrade agents, and the target page shows "not reported".
   **Answer (decided by the maintainer on 2026-10-21)**: today's case-insensitive behaviour for a missing `name_case`; the upgrade notes ask to upgrade agents, and the target page shows "not reported".
2. A MariaDB forced to `lower_case_table_names = 0` with `lower_case_file_system = ON` (MySQL 8.0+ refuses to start in that state): report `sensitive` (proposed, stricter) or `unknown` (also strict, but shown as unknown on the target page)? Proposed answer: `sensitive`, with a local detail in `check()`; both behave the same in the console.
   **Answer (decided by the maintainer on 2026-10-21)**: `sensitive`, with a local detail in `check()`.
3. The `except` bounds: 32 entries and 8 KiB (proposed), overflowing to `objects: unknown`? Proposed answer: yes; servers with more databases of a non-default collation than that are rare, and the overflow is strict.
   **Answer (decided by the maintainer on 2026-10-21)**: 32 entries and 8 KiB at most; past either bound, `objects: unknown` with `except` omitted.
4. A console-side "names compare with case" setting per target, stricter only (it can turn `insensitive` or a missing value into `sensitive`, never the reverse), for targets whose agents cannot be upgraded soon? Proposed answer: not now; reconsider if agents lag behind consoles in practice.
   **Answer (decided by the maintainer on 2026-10-21)**: no per-target console setting for now; reconsider if agents lag behind consoles in practice.
5. Timing: implement together with the ADR-0054 console change, or after it? Proposed answer: after, so that the ADR-0054 cut-over and its inventory ship first and this change reuses them; the SQL Server part may ship before the MySQL / MariaDB spelling change of decision 3.
   **Answer (decided by the maintainer on 2026-10-21)**: after the ADR-0054 console change (done, #291) and after the decision 3 prerequisite (security review H1: the agent sends unquoted MySQL / MariaDB identifiers as written); the SQL Server part may ship before the MySQL / MariaDB spelling change.

## Implementation note (2026-10-21)

Implemented by #300 (the decision 3 prerequisite), #301 (contract, decision 1), #302 (console, decisions 5 to 8), #303 (agent, decisions 2 to 4, 9 and 10) and the documentation ([05-security.md](../05-security.md#access-events-ingestion-and-correlation), [08-engine-capabilities.md](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine), [09-agent-protocol.md](../09-agent-protocol.md#heartbeat), [10-user-guide.md](../10-user-guide.md#11-policies-incidents-and-notifications), the [phase 9 engine facts](../measurements/phase9-engine-facts.md#name-case-semantics-adr-0055-2026-10-21)). The decisions are unchanged; this note records the choices the ADR left open and the residuals of each lot.

### Prerequisite: MySQL / MariaDB names as written (#300)

- **Spelling.** The MySQL tokenizer of `classifiers::query` keeps, for each word, the written spelling and a folded form. Every comparison (keywords, function names, built-in lists, shapes, `signature.mysqldump`) uses the folded form; relation, schema, created-table and CTE names use the spelling. The `server_audit` `QUERY` text, the Percona `audit_log` text and the `performance_schema` `SQL_TEXT` and digests therefore give names as written; the `server_audit` `TABLE` records and the Percona `table_access` records already gave them as stored. PostgreSQL still folds unquoted names, as the server does.
- **System schemas.** `information_schema` and `performance_schema` are recognized in any case (the server compares them without case). `sys` and `mysql` are left out of reads only when written exactly so: under `lower_case_table_names = 0` a database `SYS` or `MySQL` is another database. The always-reported lists (system-schema writes, the [ADR-0045](0045-mysql-mariadb-statement-text-tables-and-unqualified-calls.md) statement-text tables, the [ADR-0048](0048-statistics-catalogs-as-reads.md) statistics tables) still match without case, so recasing a name never removes an event or its always-reported status (property tests).
- **`case_variant_in` removed.** The scan that looked for a case variant of a statistics table among the `server_audit` records of a statement is gone: with names as written, the ADR-0048 rule (a statistics load dropped only when every relation the text names has an exact record) is applied by exact matching on the true spelling. This is the one intended reduction; the review found no path where a read reported before goes unreported.
- **Own-read budget keys stay folded** on every engine (Consequences): two tables that differ only by case share one budget, so the agent's own reads are reported sooner, never later.
- **Name heuristics** (review L2): the first-name heuristic of `classifiers::names` also checks the folded form of each run, so `JoHn` is still masked, and the `md5`-shaped hash pattern ignores case. Masking only widens.
- **Security review** (`security-reviewer` on `98a6df1`): approved, no Critical or High finding; L2 fixed and L1 documented in `1df841c`, with the property tests and the integration test `name_case_it` (`server_audit`, Percona `audit_log_filter`, `performance_schema`; `lower_case_table_names = 0`, the dev default; CI job `agent-mysql`).
- **Residual (review L1).** Case variants of one name (`Customers` and `customers` written unquoted) are now separate pre-aggregation groups. Under `lower_case_table_names` 1 or 2, where they are one table, `min_rows` can drop each group although their sum passes it, as backquoted spellings already could before #300. Folded grouping keys are possible once the setting is known to the stream (decision 4); not done.

### Contract (#301)

- **Engine gating in the schema.** A `TargetStatus.allOf` `if` / `then` entry allows `name_case` only when `engine` is `mysql`, `mariadb` or `sqlserver`; the console refuses it elsewhere with `400`. The Rust generator drops `if` / `then`, so the agent enforces the rule itself (the field is built only for those engines).
- **`except`** holds at most 32 entries, sorted by `database` in the byte order of its UTF-8 form with one entry per name (review L2): a producer rule stated in the contract, not checked by the schema (`uniqueItems` compares whole entries, not names); the console reads several entries of one name as the stricter of their values. The **8 KiB bound is agent-side only**: JSON Schema cannot bound a serialized size, and the console must not refuse a heartbeat for it (below).
- **Heartbeat `400` resend (behaviour change, ADR-0022 decision 9).** A heartbeat answered `400` with the keyword `additionalProperties` while it carried a gated `TargetStatus` field (`notes`, `name_case`) clears the capabilities, as before, and is now **sent again once** without those fields instead of being lost (counted in `gated_fields_stripped_total`); a stripped heartbeat carries no gated field, so there is no loop. Engine values are kept in the resend (the refusal named a field, not a value). Any other `400` keeps the previous behaviour.
- **Fixtures**: 3 valid and 7 invalid (a bad value, a collation name, a connection string as a database name, a missing `objects`, the field on a PostgreSQL target, 33 entries, an unknown field).
- **Security review** (`security-reviewer` on `6ccdf38`): approve, no Critical or High finding; L2 (sorted, unique entries) and I-2 (a test that catches a gated field missing from the strip helpers) fixed in `2321619`; L1 (docs/09), L3 (an oversized `except` on the console), I-3 (the rotation probe body) and I-4 (producer and console rules) carried to the later lots and met there.

### Console (#302)

- **Canonical form.** The console stores `name_case` with `except` sorted in UTF-8 byte order and one entry per name with the stricter value, and compares values only in that form, never as raw JSON. Migration `0044` adds nullable columns to `agent_targets` (`name_case` with a bounded `jsonb` `CHECK`, and the change, inventory-due and inventory times), validated in the migration (one row per declared target).
- **Oversized or malformed `except`** (#301 review L3): stored as `objects: unknown` without `except`, never answered with `400`, so an agent with a slightly different size computation never loses its heartbeat. A stored value that does not parse is read as the strict rule. A missing field is stored as `NULL`, meaning today's rule.
- **Compare-and-set** (L8): the heartbeat transaction writes the canonical value only when it differs (`IS DISTINCT FROM` on `jsonb`), and in the same statement marks the target's inventory due; a concurrent heartbeat of the same target from another replica waits for the row lock and no longer sees a difference, so exactly one replica sees each change.
- **Per-part rule** (`exceptionPartOptions`): only `matchCase` is added on top of the ADR-0054 conjunction matcher; `database` from `databases`, `schema` and `object` from the matching `except` entry or `objects` (the decision 6 lookup, review L2), `field` as `object` on SQL Server and never with case on MySQL / MariaDB; `unknown` counts as `sensitive`. It applies only when the item's engine is `mysql`, `mariadb` or `sqlserver` (for an event, the engine of its Audit source first). **The database `*` rule is applied to findings too**, not only to event objects: a location whose database is `*` takes the strictest of `objects` and every `except` value.
- **Inventory in the worker.** The replica that sees a change marks the target due; the worker queue `targets.name_case_inventory` runs every 5 minutes and runs each due target's ADR-0054 inventory at most once per target and hour (changes within the hour coalesced into the next run, which reads the value stored then). Claims take targets never inventoried first, then the oldest run, then the earliest due time, at most 20 targets per job and 8 per agent (review L1, so that one agent whose targets flap cannot starve the others), with `FOR UPDATE SKIP LOCKED`. Each run is recorded under its own audit action, `policy_exception.name_case_inventory` (actor `system`, target ids, counts and the closed display value of the rule; a failure with an error code only), apart from the startup and on-demand `policy_exception.case_inventory` of ADR-0054.
- **Agent page.** A "Names compared" column per target: with case, without case, per database (the database names rendered as escaped text), unknown (treated as with case), or not reported; with the latest per-target inventory of the last 30 days (review L2: a bounded status query). The exception form's hint says these engines follow the server's settings.
- **Security review** (`security-reviewer` on `821fb52`): approved, no Critical, High or Medium finding: no agent value can make an exception cover more than before. L1 (inventory starvation), L2 (unbounded status query), L3 (a throw on a non-canonical rule), I-3 (queue settings) and I-4 fixed in `0a52b9d`.
- **Residual.** A change of a target's engine with the same `name_case` value (`mysql` to `mariadb`, or a target id redeclared on another engine) is not counted as a change: no inventory runs for it, although the `field` rule differs between SQL Server and MySQL / MariaDB. Exceptions follow the new engine's rule at once; only the inventory is missing.

### Agent (#303)

- **Sending rules** (decision 2). `name_case` is built only for `mysql`, `mariadb` and `sqlserver` targets and only while the console's latest `accepts` lists `target_status.name_case`; then it is in every `TargetStatus` of those targets, also for a failed, timed-out or busy check: the connector's last value of the server run, else `{databases: unknown, objects: unknown}`. The core merges entries of one name (stricter value), drops entries equal to `objects`, sorts them, and past 32 entries or 8 KiB serialized sends `objects: unknown` without `except`.
- **Rotation probe** (#301 review I-3, agent review M1). The heartbeat that probes `S1` before a `/rotate` is re-sent ([09-agent-protocol.md](../09-agent-protocol.md#secret-rotation)) is now a full heartbeat, gated fields included, since the console reads it as a heartbeat and a missing `name_case` as a loss. On a `400` reporting an unknown field it is sent once more without the gated fields, and `S1` is still promoted when that probe is accepted, so such a refusal never costs a rotation.
- **MySQL / MariaDB.** A constant own text per flavor, `SELECT @@GLOBAL.lower_case_table_names, @@GLOBAL.lower_case_file_system, UNIX_TIMESTAMP(), <server identity columns>`, runs right after connect in `check()`, so the value and the server run it was read on come from one statement; it is in the connector's own-text list and the guard's exact-text matching (L7). Mapping: 0 is `sensitive` (also with `lower_case_file_system = ON`, open question 2), 1 and 2 `insensitive`, anything else or a failed read `unknown`. The `performance_schema` poller resets the kept value to `unknown` when its session is on another server run than the value's, at stream start too (agent review L1 and L5).
- **SQL Server.** `DATABASE_COLLATIONS` reads every `sys.databases` row with `TOP (1025)` (1 024 databases, one more meaning the list is cut), without the `HAS_DBACCESS`, `state` or `source_database_id` filters: `database_id`, name, `create_date`, the `ComparisonStyle` of the database collation, `containment`, `is_auto_close_on`, `state`, `catalog_collation_type`, and on every row the server collation's `ComparisonStyle`, `HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE')` and the server name. Collation names are never read. `DATABASE_COLLATIONS_V0`, identical but for a `NULL` in place of `catalog_collation_type`, is used when the column is missing (error 207); the target then reports `objects: unknown`. Both are on the allow-list, pass the deny-list and are matched as exact own texts.
- **`CATALOG_READS`.** Both statements join the connector's catalog reads (the Extended Events case 2 rule of [ADR-0051](0051-sqlserver-connector.md)): statistics builds in their activity are left out only when they are the agent's own builds on listed `sys` base tables. The review checked that this widening cannot hide a client read; the fresh-server Extended Events test shows no new base-table build.
- **Server run** (decision 2). The ADR suggested `sqlserver_start_time` from `sys.dm_os_sys_info`, which needs `VIEW SERVER STATE`, not held by the minimal account; the server run is the server name with `tempdb`'s `create_date` (`tempdb` is created at every start and always listed).
- **`catalog_collation_type`.** Only 0 (the database collation, or the fixed `Latin1_General_100_CI_AS_KS_WS_SC` for a contained database) and 2 (`SQL_Latin1_General_CP1_CI_AS`) are mapped, as the accepted text says; any other value is `unknown` (agent review M2). Measured on 2022 (16.0.4305.5): a contained database reads **1**, with `catalog_collation_type_desc` `Latin1_General_100_CI_AS_KS_WS_SC`, and refuses a second table whose name differs by case only (error 2714). A contained database was therefore reported `unknown` in #303, the stricter reading (more incidents, never fewer). Since the [refinement of 2026-10-21](#refinement-2026-10-21-accepted-by-the-maintainer-contained-databases), measured on 2019, 2022 and 2025, 1 on a contained database is `insensitive`; 1 elsewhere and every other value stay `unknown`.
- **`AUTO_CLOSE` memory** (M2). Measured: `DATABASEPROPERTYEX(name, 'Collation')` returns `NULL` on a closed database, like `collation_name`, so it cannot replace the memory. An online `AUTO_CLOSE` database whose collation reads `NULL` keeps its last known value for the same (`database_id`, `create_date`) on the same server run. Express sets `AUTO_CLOSE` on every new database, so a database never seen open since the agent started (or since the server run changed) is `unknown`, treated as sensitive: more incidents on that database until a read opens it.
- **Database names** go through the ADR-0009 normalization; a name matched by a classifier becomes `*` (decision 4, L3), merged with the stricter value.
- **Security review** (`security-reviewer`, two rounds): on `57b4749` approved, no Critical or High finding; M1 (rotation probe), M2 (catalog type 1) and L1 (server-run reset) fixed in `c7d79e0`; L2 to L4 documented or checked. On `c7d79e0` approved; L5 (the reset at stream start) fixed in `c94b166`.
- **Residuals.** The server-run reset exists only on the MySQL / MariaDB `performance_schema` source: with an audit-log file as the source, and on SQL Server, a value kept from a check is not reset by the stream when the server restarts with another setting; it is replaced at the next successful `check()` (the next heartbeat), and a failed check meanwhile sends the kept value of the previous run. SQL Server 2019 and 2025, and MySQL / MariaDB servers initialized with `lower_case_table_names = 1`, are not in the engine matrix for this yet (ROADMAP follow-ups).

### Residuals

Those of the ADR stand. In addition: events and findings judged while one console replica does not list the token, or after a heartbeat resent without `name_case`, use today's case-insensitive rule until the next heartbeat; the upgrade notes say to upgrade every console replica before the agents.

## Refinement (2026-10-21, accepted by the maintainer): contained databases

Refines decision 4 (each database's catalog collation). Accepted by the maintainer on 2026-10-21, after the measurement below; it answers the follow-up left by the [implementation note](#implementation-note-2026-10-21) (`catalog_collation_type`, agent review M2).

### Decision

The SQL Server reader maps `sys.databases.catalog_collation_type` as follows:

| `catalog_collation_type` | Database | `objects` for that database |
|---|---|---|
| 0 | not contained | from the database collation's `ComparisonStyle` (unchanged) |
| 0 | contained | `insensitive`, the fixed `Latin1_General_100_CI_AS_KS_WS_SC` (unchanged) |
| **1** | **contained** (`containment` = 1 (`PARTIAL`)) | **`insensitive`** (new) |
| 1 | not contained | `unknown` (unchanged) |
| 2 | any | `insensitive`, `SQL_Latin1_General_CP1_CI_AS` (unchanged) |
| any other value | any | `unknown` (unchanged) |

Everything else in decision 4 is unchanged: a database whose collation cannot be read (offline, or closed by `AUTO_CLOSE` with no value kept) is `unknown` unless its `catalog_collation_type` names a fixed collation (2, or 0 or 1 on a contained database), as before; a missing column, a revoked `VIEW ANY DATABASE` and the row, entry and byte bounds still give `objects: unknown`.

### Basis

Engine matrix run 39579407465 (2026-10-21), integration test `name_case_follows_the_collations` (`[it] name_case:` lines), on SQL Server 2019 (15.0.4500.2), 2022 (16.0.4305.5) and 2025 (17.0.5015.4):

- the contained database (`CONTAINMENT = PARTIAL`, a `_CS_` database collation) reads `catalog_collation_type` **1** with `catalog_collation_type_desc` `Latin1_General_100_CI_AS_KS_WS_SC` on all three versions, and `CREATE TABLE T` after `CREATE TABLE t` fails with error **2714**: the server refuses a second table whose name differs by case only;
- every non-contained test database reads **0** (`DATABASE_DEFAULT`);
- `COLLATIONPROPERTY(…, 'ComparisonStyle')`: `_BIN2` 0, `_CS_AS` 196608, the case-insensitive collations 196609, an offline database `NULL`;
- the server collation is `SQL_Latin1_General_CP1_CI_AS` (196609).

The value 1 on a contained database thus names the fixed case-insensitive catalog collation that SQL Server documents for contained databases, on every supported version. Details: [phase 9 engine facts](../measurements/phase9-engine-facts.md#name-case-semantics-adr-0055-2026-10-21).

### Consequences

- Contained databases are listed with `objects: insensitive` (or left out of `except` when that equals the target's `objects`), so exceptions on them compare without case, as the server does. Before, they were `unknown` (treated as `sensitive`): exceptions written in another case than the stored names did not cover them.
- The integration test expects `insensitive` for a contained database reading 1 (and the decision 4 values otherwise), and prints one `[it] name_case:` line per test database plus the server's answer to a case-only duplicate table; the engine matrix's "Measurement tables" step keeps them in `name_case.txt` in each SQL Server entry's measurement artifact.
- No contract, console or grant change.

### Residual risk

- A future SQL Server version that gives the value 1 another meaning would still be read `insensitive`, but only for contained databases, whose catalog collation is documented as fixed and case-insensitive. A wrong `insensitive` loosens that database's exceptions back to the behaviour before this ADR, no further (ADR residual "A wrong `insensitive` report").
