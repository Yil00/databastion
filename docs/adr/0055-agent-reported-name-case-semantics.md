# ADR-0055: Name case semantics reported by the agent for MySQL / MariaDB and SQL Server

- **Status**: Proposed (revised on 2026-10-20 after its security review, "sound after changes": H1, M1 to M3, L1 to L9). Acceptance is the maintainer's; it changes `shared/protocol/` and what location exceptions suppress
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

## Decision (proposed)

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
2. **Always sent, never omitted (security review M1).** Once the console lists the token, an agent that implements this ADR sends `name_case` in every `TargetStatus` of a `mysql`, `mariadb` or `sqlserver` target, also when `check()` fails, times out or cannot reach the server: then it sends the last value read on the same server run (`ServerRun`, the identity the MySQL / MariaDB connector already keeps in `audit/own_threads.rs`, and its SQL Server equivalent), else `{databases: unknown, objects: unknown}`. Only agents built before this ADR omit it. Otherwise an insider who exhausts the agent's connections would turn exceptions back to case-insensitive.
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

## Open questions (for the maintainer)

1. A missing `name_case` (agents built before this ADR): keep today's case-insensitive behaviour (proposed), or treat it as `unknown`, so as `sensitive`, from a given release on? Proposed answer: today's behaviour; the upgrade notes ask to upgrade agents, and the target page shows "not reported".
2. A MariaDB forced to `lower_case_table_names = 0` with `lower_case_file_system = ON` (MySQL 8.0+ refuses to start in that state): report `sensitive` (proposed, stricter) or `unknown` (also strict, but shown as unknown on the target page)? Proposed answer: `sensitive`, with a local detail in `check()`; both behave the same in the console.
3. The `except` bounds: 32 entries and 8 KiB (proposed), overflowing to `objects: unknown`? Proposed answer: yes; servers with more databases of a non-default collation than that are rare, and the overflow is strict.
4. A console-side "names compare with case" setting per target, stricter only (it can turn `insensitive` or a missing value into `sensitive`, never the reverse), for targets whose agents cannot be upgraded soon? Proposed answer: not now; reconsider if agents lag behind consoles in practice.
5. Timing: implement together with the ADR-0054 console change, or after it? Proposed answer: after, so that the ADR-0054 cut-over and its inventory ship first and this change reuses them; the SQL Server part may ship before the MySQL / MariaDB spelling change of decision 3.
