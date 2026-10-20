# ADR-0055: Name case semantics reported by the agent for MySQL / MariaDB and SQL Server

- **Status**: Proposed (needs a `security-reviewer` review before acceptance: it changes `shared/protocol/` and what location exceptions suppress)
- **Date**: 2026-10-20
- **Refines**: [ADR-0054](0054-case-sensitive-location-exceptions.md) (which stays Accepted), decision 3 (exceptions on MySQL / MariaDB and SQL Server stay case-insensitive "until the agent reports the case semantics"); this is its option D, whose ADR the maintainer asked for on 2026-10-20 (ADR-0054 open question 3). Uses [ADR-0022](0022-protocol-capability-negotiation.md) (capability negotiation) without changing it
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups); [ADR-0009](0009-name-normalization-and-item-sanitization.md) (name normalization), [ADR-0014](0014-policy-and-incident-model.md) decision 1, [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) / [ADR-0020](0020-mysql-mariadb-connector-as-merged.md) (MySQL / MariaDB account and statements), [ADR-0021](0021-access-event-correlation.md) decision 5, [ADR-0051](0051-sqlserver-connector.md) decisions 4 and 5 and its statement allow-list (end-of-phase-9 review L1); [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine) (collation residuals); `shared/protocol/openapi.yaml` (`TargetStatus`, `Identifier`); `console/src/lib/policy-common.ts` (`exceptionGlobOptions`, `TRAILING_SPACE_BLIND_ENGINES`), `console/src/lib/policy-model.ts` (`exceptionCovers`), `console/src/lib/event-model.ts` (`exceptionCoversEvent`), `console/src/server/agent-api/capabilities.ts`; `agent/crates/connector-mysql/src/sql.rs` and `check.rs`, `agent/crates/connector-sqlserver/src/sql.rs` (`STATEMENTS`, `VERSION`, `ACCESSIBLE_DATABASES`) and `check.rs` (read at `4cd45dd`, `dev`)

## Context

ADR-0054 (accepted on 2026-10-20) makes location exceptions compare with case on PostgreSQL, MongoDB, Redis, Valkey, CAS and unknown engines: an exception must match both with and without the case fold. On `mysql`, `mariadb` and `sqlserver` exceptions stay case-insensitive, because whether two names that differ only by case are two objects depends on server settings the console does not know. ADR-0054 decision 3 records the residual: `lower_case_table_names = 0` is the Linux default, so most MySQL / MariaDB targets keep the over-suppression ADR-0054 removes elsewhere, and so do SQL Server databases under a case-sensitive collation.

What the engines do:

- **MySQL / MariaDB.** `lower_case_table_names` decides database and table names (and table aliases, triggers): **0** stored as given and compared with case (the Linux default); **1** stored in lowercase and compared without case (the Windows default); **2** stored as given and compared in lowercase (the macOS default). Column names are always compared without case, whatever the setting. MySQL 8.0+ sets the value at data directory initialization only; MariaDB reads it at each start. `lower_case_file_system` tells whether the data directory's file system ignores case. With 0 on a file system that ignores case (an unsupported configuration), or with a database directory or a table's `DATA DIRECTORY` on such a file system (symbolic links on MariaDB, per-table tablespaces), whether two names that differ by case can coexist depends on the file system, which the agent's account cannot inspect (no `FILE` privilege, invariant I4). Both variables are readable by any account (`@@GLOBAL.…`, no privilege).
- **SQL Server.** Database names are compared under the server collation (`SERVERPROPERTY('Collation')`). Schema, object and column names are compared under the database's catalog collation: the database collation (`sys.databases.collation_name`), except in a contained database (`sys.databases.containment` 1), whose catalog collation is fixed (`Latin1_General_100_CI_AS_KS_WS_SC`, case-insensitive), and, where the column exists, a database whose `sys.databases.catalog_collation_type` is not the database default. A collation compares with case when `COLLATIONPROPERTY(<name>, 'ComparisonStyle')` lacks the ignore-case bit (1): every `_CS_` collation and every binary (`_BIN`, `_BIN2`) collation. The minimal login sees `sys.databases` for every database (`VIEW ANY DATABASE` is granted to `public` by default) and the server properties; `collation_name` is `NULL` for a database that is not online. The connector already reads `SERVERPROPERTY` (`sql::VERSION`) and `sys.databases` (`sql::ACCESSIBLE_DATABASES`, `sql::USER_DATABASES`).

On a case-insensitive engine the names the console receives may be spelled as the client wrote them (statement texts), while Discovery sends the catalog's spelling; a case-sensitive exception there would stop covering `CRM.CUSTOMERS` for the table `crm.customers`, which is one object: more incidents, not fewer. On a case-sensitive one, a case-insensitive exception also covers a distinct object. The console needs to know which one it is, per database for SQL Server, and per location part (database names and object names can differ on SQL Server; column names never compare with case on MySQL / MariaDB).

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

1. **Contract.** `TargetStatus` gains an optional `name_case`, sent only when the latest `HeartbeatResponse.accepts` lists `target_status.name_case` (ADR-0022 decision 2), on `mysql`, `mariadb` and `sqlserver` targets only (the console ignores it on other engines, whose rule ADR-0054 fixes):

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

   No free text, no collation name, no setting value: three closed values and database names that findings and events already carry, normalized and sanitized by ADR-0009 like them (I2). Types generated on both sides (I6).
2. **What the agent reports**, from statements added to each connector's constants (the SQL Server statement allow-list `sql::STATEMENTS` included), read at each `check()` with the existing timeouts; no grant changes (I4):
   - **MySQL / MariaDB**: `SELECT @@GLOBAL.lower_case_table_names, @@GLOBAL.lower_case_file_system`. 0 gives `databases` and `objects` `sensitive`, whatever `lower_case_file_system` says (the agent cannot see per-directory file systems; `sensitive` is the stricter answer, below); 1 or 2 give `insensitive`; anything else, or a failed read, `unknown`. No `except`: the setting is server-wide. Column names are not reported: the console never compares MySQL / MariaDB `field` globs with case (decision 4).
   - **SQL Server**: `databases` from the server collation; for each database in the target's scope (the databases its Discovery and Audit may name, system databases included), its catalog collation as in the Context (database collation, the fixed catalog collation of a contained database, `catalog_collation_type` where it exists), judged by `COLLATIONPROPERTY(…, 'ComparisonStyle')`. `objects` is the server collation's value (new databases take it by default); a database whose value differs from it is listed in `except`; a database that is not online, whose collation reads `NULL` or whose `ComparisonStyle` cannot be read is listed as `unknown`. Over 32 entries, `objects` becomes `unknown` and `except` is omitted.
   - **Merged names.** Databases whose names reach the console as one name after ADR-0009 normalization (the `*` of a classifier-matched name, stripped characters) are one entry with the stricter value (`sensitive` before `unknown` before `insensitive`).
3. **Fail-closed direction.** A case-sensitive exception covers a subset of what a case-insensitive one covers (ADR-0054 decision 1), so "sensitive" is the stricter reading, and its cost is noise (an exception written in another case than the stored name stops covering it), never a hidden read:
   - `unknown` from an agent that implements this ADR is treated as `sensitive`;
   - a missing `name_case` (an agent built before this ADR, a console that did not list the token, a heartbeat whose status was stripped) keeps today's behaviour, case-insensitive, so that upgrading the console alone changes nothing on these engines (open question 1);
   - the value is replaced at every heartbeat, never kept from an earlier one: a rolled-back agent falls back to today's behaviour.
4. **Console rule.** `exceptionGlobOptions` takes the target's `name_case` and the location's database and returns options per part:
   - `database` part: `matchCase` when `databases` is `sensitive` or `unknown`;
   - `schema`, `object`: `matchCase` when the database's value (its `except` entry, else `objects`) is `sensitive` or `unknown`; the `except` lookup compares the database name with case when `databases` says so, else after the N1 fold, and on `sqlserver` and `mysql` / `mariadb` without trailing spaces (the N1 rule); when the lookup finds several entries, the stricter value wins;
   - `field`: on `sqlserver` as `object`; on `mysql` and `mariadb` never with case (column names);
   - an event object whose database is `*` uses `objects` when no entry is named `*`.

   The matcher, the conjunction of ADR-0054 decision 1, trailing spaces, conditions, scores, the dedup key and the agent's `sensitive_objects` match are unchanged.
5. **Inventory and notice.** When a target's effective rule changes (its first `name_case`, a change of any value, or its loss), the console runs the ADR-0054 decision 6 inventory for that target (same bound, ids and counts only, JavaScript comparison) and records one audit entry. The target page shows how its names are compared (with case, without case, per database, unknown and treated as with case), and the exception form's ADR-0054 hint names these engines as "according to the server's settings".
6. **Compatibility.**
   - Old agent, new console: no `name_case`, today's behaviour.
   - New agent, old console: the token is not listed, nothing is sent (ADR-0022 decision 2).
   - Multi-replica consoles list the token only once every replica accepts the field (ADR-0022 decision 8).
   - A `400` on a heartbeat carrying it clears the capabilities (ADR-0022 decision 9, already implemented for heartbeats).
7. **Test obligations.**
   - Contract: schema, fixtures with each value and an `except` list, drift tests, the token in the console's constant and behind `console_accepts` in the agent.
   - Agent, MySQL / MariaDB: integration tests on every engine-matrix version with `lower_case_table_names = 0` (the dev default), and one MySQL and one MariaDB entry initialized with 1, asserting the reported values; unit tests of the mapping, including a failed read as `unknown`.
   - Agent, SQL Server: on 2019, 2022 and 2025, a server under the default collation holding a database with a `_CS_` collation, one with a `_BIN2` collation, a default one and, where the dev service can enable contained databases, a contained database with a `_CS_` collation (reported `insensitive`); the `except` bound (33 databases) giving `unknown`; an offline database giving `unknown`; whether `catalog_collation_type` exists on each version, recorded in the [phase 9 engine facts](../measurements/phase9-engine-facts.md).
   - Console: per-part option tests over every combination of `databases`, `objects`, `except` and a missing field; the ADR-0054 subset property extended to these options; lookups folded and exact, with trailing spaces and the merged `*` entry; the inventory run on a change.
   - End to end: on the SQL Server end-to-end target, a `_CS_` database holding `Customers` and `customers`, with an exception for one of them only, raising an incident for the other; the same on MySQL with `lower_case_table_names = 0`; the I2 check unchanged.
8. **Review.** The protocol change and the console rule get a `security-reviewer` review before acceptance (CLAUDE.md, `shared/protocol/`).

## Consequences

- On MySQL / MariaDB with `lower_case_table_names = 0` (the common Linux case) and on SQL Server databases under a case-sensitive collation, an exception no longer suppresses an object whose name differs from its globs by case only, once both sides run this change.
- More incidents after the agents are upgraded where exceptions are written in another case than the stored names (the inventory names them), and noise wherever `unknown` is reported or `lower_case_table_names = 0` sits on a case-insensitive file system.
- The heartbeat carries up to 32 database names per SQL Server target, names already sent in findings and events.
- Each new engine's connector ADR states whether it reports `name_case` or has a fixed rule in the console's engine lists (ADR-0054 consequences).
- Statement allow-lists and grant documentation gain the new reads (05-security), with no new privilege.

### Residual risks

- **Between two heartbeats.** A database whose collation changes (`ALTER DATABASE … COLLATE`), or one created with a non-default collation, is judged by the previous report until the next `check()`: events of that interval use the older rule.
- **Collation is more than case.** Accent-, kana- and width-insensitive collations, Turkish case pairs and `ß` are not modelled (docs/08, collation residuals): on those, exceptions cover less than the server's notion of one name, never more.
- **ADR-0009 merges** (stripped characters, NFKC) remain the ADR-0054 residual; decision 2 only keeps the stricter value for merged database names.
- **A wrong `insensitive` report** (a compromised agent or a connector bug) loosens exceptions back to today's behaviour on that target, no further; a compromised agent can already withhold events.

## Rejected alternatives

- **(2) A per-location flag**: one more field and column on every item for a setting that changes only with DDL or a server rebuild; stored findings would keep the flag of their scan rather than the server's current rule.
- **(3) A single target-level value**: wrong for SQL Server servers mixing collations; decision 1 falls back to it (`objects` without `except`) when the list overflows, in the stricter direction.
- **(4) Target notes**: a human-facing registry used as a matching input, without database names and with a 16-note cap.
- **(5) An administrator's declaration**: unverifiable and stale; see open question 4 for a stricter-only variant.
- **A missing field read as `sensitive`**: every MySQL / MariaDB and SQL Server exception would turn strict when the console is upgraded before the agents, including on the default case-insensitive SQL Server collation, where text spellings vary; the noise would push administrators towards broad `*` exceptions. Open question 1.
- **Reporting the collation names or the setting values**: free-form strings the console does not need; three closed values say what matters.

## Open questions (for the maintainer)

1. A missing `name_case` (agents built before this ADR): keep today's case-insensitive behaviour (proposed), or treat it as `unknown`, so as `sensitive`, from a given release on? Proposed answer: today's behaviour; the upgrade notes ask to upgrade agents, and the target page shows "not reported".
2. MySQL / MariaDB with `lower_case_table_names = 0` and `lower_case_file_system = ON`: report `sensitive` (proposed, stricter) or `unknown` (also strict, but shown as unknown on the target page)? Proposed answer: `sensitive`, with a local detail in `check()`; both behave the same in the console.
3. The `except` bound: 32 entries (proposed), more, or a list of the databases in scope whatever their value? Proposed answer: 32, overflowing to `objects: unknown`; servers with more databases of a non-default collation than that are rare, and the overflow is strict.
4. A console-side "names compare with case" setting per target, stricter only (it can turn `insensitive` or a missing value into `sensitive`, never the reverse), for targets whose agents cannot be upgraded soon? Proposed answer: not now; reconsider if agents lag behind consoles in practice.
5. Timing: implement together with the ADR-0054 console change, or after it? Proposed answer: after, so that the ADR-0054 cut-over and its inventory ship first and this change reuses them.
