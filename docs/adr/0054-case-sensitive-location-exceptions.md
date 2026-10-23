# ADR-0054: Case-sensitive location exceptions on case-sensitive engines

- **Status**: Accepted (2026-10-20). **Accepted** by the maintainer on 2026-10-20 with the proposed answer to every open question (see [Open questions](#open-questions-answered)). History: proposed on 2026-10-18, revised the same day after its security review ("sound after changes": M1, M2, L1 to L3)
- **Date**: 2026-10-18
- **Refined by**: [ADR-0055](0055-agent-reported-name-case-semantics.md) (Accepted 2026-10-21), option D: case semantics reported by the agent for MySQL / MariaDB and SQL Server; [ADR-0056](0056-names-altered-by-normalization-marker.md) (Accepted 2026-10-22), the marker on names altered by normalization of the residual risks
- **Refines**: [ADR-0014](0014-policy-and-incident-model.md) (which stays Accepted), decision 1 ("globs … are case-insensitive"), for location exceptions only, and [ADR-0021](0021-access-event-correlation.md) (which stays Accepted), decision 5 (exceptions on access events)
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Console, after N1"; ADR-0014 implementation note of 2026-10-17; [ADR-0009](0009-name-normalization-and-item-sanitization.md) (name normalization); [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine); [09-agent-protocol.md, location mapping per engine](../09-agent-protocol.md#location-mapping-per-engine); `console/src/lib/policy-common.ts` (`foldName`, `exceptionGlobOptions`), `console/src/lib/policy-model.ts` (`exceptionCovers`), `console/src/lib/event-model.ts` (`exceptionCoversEvent`), `agent/crates/classifiers/src/names.rs` (read at `72e87d5`, `dev`)

## Context

ADR-0014 decision 1 makes every glob case-insensitive: policy conditions (`location` on findings, `objects` on access events), and the location of exceptions. Since N1 (#261, released in 0.8.0) the console folds both the glob and the name (trailing U+0020 dropped, Unicode lowercase, final sigma `ς` read as `σ`), except that exceptions ignore trailing spaces only on `sqlserver`, `mysql` and `mariadb` (`TRAILING_SPACE_BLIND_ENGINES`), because "looser exceptions suppress more". The same argument applies to case, and N1 left it open: exceptions stay case-insensitive on every engine.

How the engines compare the names the console sees (database, schema, object):

| Engine | Names | Case |
|---|---|---|
| PostgreSQL | quoted identifiers keep their case, unquoted ones fold to lowercase; the agent sends the catalog's name (pgaudit records; statement text folded as the server does, `classifiers::query::pg_scan`) | **sensitive**: `crm.customers` and `crm."Customers"` are two tables |
| MongoDB | collections and fields | **sensitive** for collections; database names cannot differ only by case on one server |
| Redis / Valkey | key patterns, `db<index>` | **sensitive** |
| MySQL / MariaDB | databases and tables are files or keys | depends on `lower_case_table_names`: **0, the default on Linux, sensitive**; 1 stored in lowercase and compared without case (the Windows default); 2 stored as given and compared in lowercase (macOS); column names never |
| SQL Server | identifiers compared under a collation | depends on the collation: database names under the server collation, object names under each database's (the default `SQL_Latin1_General_CP1_CI_AS` is insensitive; a `_CS_` collation is sensitive) |
| OpenLDAP | DN attribute values of the usual naming attributes | insensitive (matching rules of `cn`, `ou`, `dc`) |
| Apereo CAS | locations from the content of the service definitions (`service_registry`, the service type, the service name), never from a file name ([09-agent-protocol.md](../09-agent-protocol.md#location-mapping-per-engine)) | **sensitive**: the names are strings of the definitions, and two services whose names differ only by case are two definitions; nothing on CAS compares them without case |

On PostgreSQL, MongoDB, Redis, Valkey and CAS, an exception written for `crm.customers` therefore also covers a distinct `crm."Customers"`, `Customers` collection, `Customers:*` key pattern or `Portal` service: an object that may hold other data, created by anyone with `CREATE` on the schema (or the right to add a service). On MySQL / MariaDB with `lower_case_table_names = 0`, the Linux default and so the common case for the servers DataBastion targets, and on SQL Server databases with a case-sensitive collation the same holds, but the console does not know the setting: the agent does not report it.

Conditions and per-object sensitivity are a different matter: a looser match only reports more, so they stay case-insensitive (ADR-0014 implementation note of 2026-10-17). The agent's `sensitive_objects` match is likewise looser only.

Names are also not sent exactly as the engine stores them. ADR-0009 normalization (`agent/crates/classifiers/src/names.rs`) strips forbidden characters (zero-width characters such as U+200B, the soft hyphen U+00AD, bidirectional controls) and applies NFKC, so a table named `"customers<U+200B>"`, a fullwidth `ｃｕｓｔｏｍｅｒｓ` or a name with a ligature reaches the console as `customers`: a case-sensitive exception for `customers` still covers it, although the engine holds two distinct objects. Case sensitivity does not change that; it is a separate residual of normalization.

Exceptions are created by hand in an admin form (no pre-fill from a finding or an event), so their globs are spelled by an administrator. Making them stricter turns into incidents what they suppressed only through case folding: findings at their next evaluation (a rescan, or a full pass after a policy or exception change, ADR-0014 decision 2) and access events evaluated after the change (past events are never re-evaluated, ADR-0021 decision 5).

## Options

### (A) Case-sensitive exceptions on engines that are case-sensitive by definition

Location exceptions compare case-sensitively when the item's engine is `postgres`, `mongodb`, `redis`, `valkey` or `cas`, and when the engine is unknown (as for trailing spaces: an unknown engine never gets the looser rule). They stay case-insensitive on `sqlserver`, `mysql`, `mariadb` and `openldap`. Conditions and scores stay case-insensitive everywhere. Trailing spaces keep the N1 rule. No new setting, no protocol change; the engine is the one the console already uses for `exceptionGlobOptions`.

### (B) A per-exception flag

An exception gains `match_case` (boolean), chosen by the administrator. With a default of `false`, nothing changes unless an administrator acts; with a default of `true` everywhere, exceptions on SQL Server databases under the default collation and on MySQL / MariaDB with `lower_case_table_names` 1 or 2 stop covering names the statement text spells in another case (`CRM.CUSTOMERS`), which the server treats as the same object. Either default is wrong on some engine, and the choice is left to whoever writes the exception, with a form field whose effect depends on server settings the form does not show.

### (C) Keep as is and document

Exceptions stay case-insensitive on every engine; docs/08 and the user guide say that on PostgreSQL, MongoDB, Redis, Valkey and CAS (and MySQL / MariaDB with `lower_case_table_names = 0`, SQL Server with a case-sensitive collation) an exception also covers objects whose names differ only by case. No migration, no new incidents; the over-suppression stays.

### (D) Option A, then case semantics reported by the agent

The agent reports, per monitored database, whether its object names compare with case (MySQL / MariaDB `lower_case_table_names`, SQL Server's database and server collation through `COLLATIONPROPERTY(…, 'ComparisonStyle')` or the collation name), in an optional `TargetStatus` field negotiated by a capability token (ADR-0022), and the console applies case-sensitive exceptions to the databases reported sensitive. A protocol change with its own security review; it extends A to the two engines whose case depends on configuration.

## Decision

Option A now; option D in a separate ADR, [ADR-0055](0055-agent-reported-name-case-semantics.md), written on 2026-10-20 (open question 3).

1. **Rule.** `exceptionGlobOptions(engine)` gains a `matchCase` option, true for `postgres`, `mongodb`, `redis`, `valkey`, `cas` and for an unknown engine (`null`). With `matchCase`, an exception covers a name only when **both** the current folded match (`foldName`, the N1 rules) **and** an exact match without the case fold (same matcher, same trailing-space handling) hold. The conjunction, rather than the exact match alone, is required because `?` and case mappings that change a string's length (`İ` lowercases to two code points) make the two matches differ in both directions: with the conjunction, the case-sensitive result is a subset of today's. The matcher stays linear (two passes). It applies to finding exceptions (`exceptionCovers`) and to access-event exceptions (`exceptionCoversEvent`) on every location part (`database`, `schema`, `object`, `field`).
2. **Unchanged.** Policy conditions, per-object sensitivity and scores, the dedup key, the agent's `sensitive_objects` match, and exceptions on `sqlserver`, `mysql`, `mariadb` and `openldap`.
3. **MySQL / MariaDB and SQL Server.** Exceptions stay case-insensitive there until the agent reports the case semantics (option D). The residual is not an edge case: `lower_case_table_names = 0` is the Linux default, so most MySQL / MariaDB targets keep the over-suppression this ADR removes elsewhere; SQL Server keeps it on databases with a case-sensitive collation. Both are documented in docs/08 and the user guide.
4. **Names as the console receives them.** Case-sensitive exceptions compare the names the agent sends, which are the engine's names after ADR-0009 normalization, not the stored names unchanged: forbidden characters are stripped and NFKC is applied, so names that differ only by such characters (zero-width characters, the soft hyphen, fullwidth or ligature forms) reach the console as one name and an exception covers both (residual risks). Within that, the spelling must be the engine's: on PostgreSQL every Discovery and Audit source must send the catalog's spelling (unquoted names folded, quoted names kept); on MongoDB, Redis, Valkey and CAS the names come from the server or the definitions, except the CAS `field`: the agent converts definition keys to snake_case and lowercases their ASCII capitals while doing so (`snake()`, `agent/crates/connector-cas/src/registry.rs`), so on CAS a case-sensitive `field` glob compares a name the agent has already folded (residual risks). Where a source cannot tell (an unqualified name in a `pg_stat_statements` text is already reported without schema), the stricter exception covers less, never more.
5. **Test obligations.**
   - Console: a property test that, for any glob and name, a `matchCase` cover implies today's cover (subset), including `?`, `*`, escapes, trailing spaces and length-changing case mappings (`İ`, `ß`, final sigma).
   - Agent: an integration test on PostgreSQL with a mixed-case quoted relation proving that pgaudit `csvlog`, `jsonlog` and `pg_stat_statements` events, and Discovery findings, name it as in the catalog; and with a relation whose name holds a stripped character (U+200B) and an NFKC-mapped one (a fullwidth letter), recording what reaches the console, so that the residual of item 4 is pinned by a test.
6. **Migration of existing exceptions.** No data migration: the rule changes at upgrade. The inventory is computed from stored data, so that it names exactly the exceptions whose effect changes:
   - at the first start after the upgrade, and on demand from the policies page, the console lists the active exceptions with a location that cover, compared without case but not with case, at least one stored finding (false positives included) or one access event within the event retention of a target whose engine is in the case-sensitive list;
   - the policies page shows those exceptions with the number of findings and events concerned; the startup log and one audit entry record exception ids and counts only, never globs or names;
   - the upgrade notes of the release tell administrators to review the listed exceptions after upgrading, and that mixed-case names (camelCase MongoDB collections, Redis / Valkey key prefixes, quoted PostgreSQL identifiers, CAS service names) are the ones affected, whatever the case of the exception.
   - Implementation obligation: the inventory compares the distinct (target, database, schema, object) names of the stored findings and events, bounded per run (a run that reaches the bound says so and lists what it compared), not every event row; and it uses the console's JavaScript comparison (`globMatch` with and without `matchCase`), so a console database with a `C` / `POSIX` ctype gives the same result as a UTF-8 one.

   An exception written in another case than the real name (`CRM.Customers` for `crm.customers`, `useraccounts` for `userAccounts`) stops covering it on these engines and has to be corrected by an administrator (audited, ADR-0014 decision 5).
7. **UI.** The exception form says, next to the location fields, that names are compared with case on PostgreSQL, MongoDB, Redis, Valkey and CAS, and without case elsewhere.

## Consequences

- On PostgreSQL, MongoDB, Redis, Valkey and CAS an exception no longer suppresses objects whose names differ from its globs by case only; `crm."Customers"` raises its own incidents.
- More incidents after the upgrade where an exception's case differs from the real name, until it is corrected; the inventory names those exceptions from stored data. They are bounded by the dedup and the per-target hourly cap (ADR-0021 decisions 6 and 8). Findings reappear at their next evaluation, events from the upgrade on.
- An exception that must cover both spellings needs a glob for each (two exceptions, or a `?` in place of the letter).
- Two engine lists in the console (`TRAILING_SPACE_BLIND_ENGINES` and the new case-sensitive list) must be kept in step with every engine added (phase 10: SQLite compares identifiers without case for ASCII letters; Firebird folds unquoted identifiers to uppercase and keeps quoted ones), each decided in that engine's connector ADR.
- A console database with a `C` / `POSIX` ctype keeps its JavaScript fallback for the SQL pre-filter; the exact match needs no fold, so it adds no fallback.

### Residual risks

- MySQL / MariaDB with `lower_case_table_names = 0` (the Linux default, the common case) and SQL Server databases with a case-sensitive collation keep the over-suppression until option D.
- **Normalization merges names.** Names that differ only by characters ADR-0009 strips or maps (zero-width characters, the soft hyphen, NFKC compatibility forms) reach the console as one name, so a case-sensitive exception for `customers` still covers `"customers<U+200B>"` or `ｃｕｓｔｏｍｅｒｓ`. A possible ADR-0009 follow-up, in its own ADR: a negotiated marker on a name altered by normalization (a capability-gated field on the location or object), which exceptions refuse to cover, as decision 3 item 6 of [ADR-0053](0053-overflowed-event-objects-flag.md) refuses an overflow `*`.
  - *Update (2026-10-23)*: closed by [ADR-0056](0056-names-altered-by-normalization-marker.md) (accepted on 2026-10-22, option (B); implemented by #323, #324 and #331, [implementation note](0056-names-altered-by-normalization-marker.md#implementation-note-2026-10-23)): with an agent and a console of ADR-0056 (since 0.9.0), the agent marks altered parts in `Location.altered` and `ObjectRef.altered`, and an exception covers an altered part only with a pattern absent or exactly `*`. The residual stays for items without the marker (agents before 0.9.0, rows stored before the upgrade, findings sent while the agent does not know the console's capabilities); the residuals of the marker are in ADR-0056.
- **CAS fields are folded by the agent.** `snake()` lowercases ASCII capitals while converting a definition key to snake_case, so `userName`, `UserName` and `user_name` all arrive as `user_name`: on CAS a case-sensitive `field` glob compares an already folded name, and keys that differ only by case or by an underscore are merged. The database, schema and object of a CAS location (`service_registry`, the service type, the service name) are not converted.
  - *Update (2026-10-23)*: since ADR-0056 a `field` whose conversion changed the key is marked altered, so a `field` glob that names it no longer covers it; keys are still merged into one name.
- Unicode case pairs outside simple lowercase (the residuals of N1, docs/08) stay on the insensitive engines; on the case-sensitive ones the conjunction of decision 1 can only cover less.

## Rejected alternatives

- **(B) A per-exception flag**: either default is wrong on some engine, and it puts a server setting the form cannot show in the hands of each exception's author. It also keeps a looser exception available on engines where it is never right.
- **(C) Keep and document**: exceptions are the console's only durable suppression besides false positives (ADR-0014 decision 3), and N1 already chose the stricter rule for trailing spaces with the same argument.
- **Case-sensitive conditions and scores too**: a stricter condition reports less, and statement texts on case-insensitive engines spell names as the client wrote them; N1 deliberately made them looser.
- **The exact match alone for `matchCase`**: with `?` and length-changing case mappings it can cover a name today's fold does not, so a stricter rule would loosen some exceptions.
- **An inventory from the globs' spelling** (globs holding a cased letter): it misses lowercase globs written for mixed-case names, the common MongoDB and Redis case, and lists exceptions whose effect does not change.
- **Grandfathering existing exceptions as case-insensitive**: it keeps every current over-suppression with no end date, and needs the per-exception flag of option B in storage. The inventory and the upgrade notes give administrators the same chance to adapt without keeping the hole. This is open question 1.
- **CAS case-insensitive like OpenLDAP**: CAS locations are definition strings, not directory names under case-insensitive matching rules; nothing on CAS treats `Portal` and `portal` as one service.

## Open questions (answered)

Each answer is the proposed one, accepted by the maintainer on 2026-10-20.

1. Cut over at upgrade (proposed) or grandfather the existing exceptions as case-insensitive until an administrator converts them? Proposed answer: cut over, with the inventory and upgrade notes of decision 6; grandfathering keeps the over-suppression indefinitely when nobody acts.
   **Answer (decided by the maintainer on 2026-10-20)**: cut over at upgrade, with the inventory and the upgrade notes of decision 6; no grandfathering.
2. MongoDB database names: case-sensitive like collections (proposed, one rule per engine), or insensitive since one server cannot hold two databases differing only by case? Proposed answer: sensitive; it can only make an exception written in the wrong case cover less.
   **Answer (decided by the maintainer on 2026-10-20)**: case-sensitive, like collections.
3. Option D (agent-reported case semantics for MySQL / MariaDB and SQL Server): when to write its ADR? Since `lower_case_table_names = 0` is the Linux default, the residual of decision 3 covers most MySQL / MariaDB targets, which weighs for writing it soon, possibly with this ADR's implementation; waiting for the phase 10 connector ADRs would let SQLite and Firebird share the same field. Recommendation: weigh writing it sooner; the timing is the maintainer's decision.
   **Answer (decided by the maintainer on 2026-10-20)**: write it now: [ADR-0055](0055-agent-reported-name-case-semantics.md), proposed on 2026-10-20.
4. The ADR-0009 "altered by normalization" marker of the residual risks: record it as a ROADMAP follow-up now? Proposed answer: yes, as a follow-up needing its own ADR and a `security-reviewer` review, not part of this change.
   **Answer (decided by the maintainer on 2026-10-20)**: yes, recorded as a ROADMAP [phase 9 follow-up](../ROADMAP.md#phase-9-follow-ups) needing its own ADR and a `security-reviewer` review, not part of this change.

## Implementation note (2026-10-20)

Implemented by #291 (console, decisions 1, 6 and 7) and #289 (agent test of decision 5). The decisions are unchanged; the choices the ADR left open:

- **Engine list.** `exceptionMatchesCase(engine)` is true for every engine that is not in `CASE_BLIND_EXCEPTION_ENGINES` (`sqlserver`, `mysql`, `mariadb`, `openldap`), and for a null engine, rather than for a list of case-sensitive engines: an engine added without a decision gets the stricter rule, as decision 1 requires for an unknown engine.
- **Engine of an event.** The engine an access event's exceptions use is the one its Audit source tells (`auditSourceEngine`, checked against the target at ingest), else its target's current engine (security review L1: a target's engine may change after ingest). The sources MySQL and MariaDB share, and those Redis and Valkey share, give no single engine; each pair has the same rule.
- **Startup trigger.** The worker runs the inventory at its start while the audit log holds no successful `policy_exception.case_inventory` entry; a failed run is audited and retried at the next start.
- **Stored result.** The audit entry is the stored result: the policies page reads the latest success and failure entries (exception ids and counts only; a failure holds an error code only: a SQLSTATE, `internal`, `actor_gone` or `inventory_running`). No table was added.
- **On demand.** An administrator's request is queued on `policy_exceptions.case_inventory` (stately, no retry, finished jobs kept one day) and run by the worker, never in the web process (security review M1), under the shared limiter `case_inventory.per_user` (3 per 10 minutes, fail closed). Details in [05-security.md](../05-security.md#access-events-ingestion-and-correlation).
- **Bounds.** Per run: 20 000 distinct finding names and 20 000 distinct event object names, 100 000 (exception, event name) pairs, and a comparison budget of 2.5·10^6 exception × name evaluations, each exception charged only the names within its agent / target scope. Exceptions are compared oldest first (creation time, then id), so when the budget runs out the most recently created ones are left out, and the page says how many. A run that reaches any bound says so.
- **Counts are upper bounds** (security review L2): a finding or event counted for an exception may still be covered by another exception, and an event is counted when at least one of its objects is no longer covered by that exception, even if it raises no incident. The exception's policy scope is not considered.
- **Agent test (decision 5).** `agent/crates/connector-postgres/src/it_names.rs`: a quoted mixed-case relation in a quoted mixed-case schema is named as in the catalog by the pgaudit `jsonlog` and `csvlog`, `pg_stat_statements` and Discovery, and its lowercase twin keeps its own name; relations whose names differ from `crm.names_it` only by U+200B or a fullwidth `ｎ` reach the console as `crm.names_it`, which pins the normalization residual as the current behaviour.
