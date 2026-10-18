# ADR-0054: Case-sensitive location exceptions on case-sensitive engines

- **Status**: Proposed
- **Date**: 2026-10-18
- **Refines**: [ADR-0014](0014-policy-and-incident-model.md) (which stays Accepted), decision 1 ("globs … are case-insensitive"), for location exceptions only, and [ADR-0021](0021-access-event-correlation.md) (which stays Accepted), decision 5 (exceptions on access events)
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Console, after N1"; ADR-0014 implementation note of 2026-10-17; [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine); `console/src/lib/policy-common.ts` (`foldName`, `exceptionGlobOptions`), `console/src/lib/policy-model.ts` (`exceptionCovers`), `console/src/lib/event-model.ts` (`exceptionCoversEvent`) (read at `72e87d5`, `dev`)

## Context

ADR-0014 decision 1 makes every glob case-insensitive: policy conditions (`location` on findings, `objects` on access events), and the location of exceptions. Since N1 (#261, released in 0.8.0) the console folds both the glob and the name (trailing U+0020 dropped, Unicode lowercase, final sigma `ς` read as `σ`), except that exceptions ignore trailing spaces only on `sqlserver`, `mysql` and `mariadb` (`TRAILING_SPACE_BLIND_ENGINES`), because "looser exceptions suppress more". The same argument applies to case, and N1 left it open: exceptions stay case-insensitive on every engine.

How the engines compare the names the console sees (database, schema, object):

| Engine | Names | Case |
|---|---|---|
| PostgreSQL | quoted identifiers keep their case, unquoted ones fold to lowercase; the agent sends the catalog's name (pgaudit records; statement text folded as the server does, `classifiers::query::pg_scan`) | **sensitive**: `crm.customers` and `crm."Customers"` are two tables |
| MongoDB | collections and fields | **sensitive** for collections; database names cannot differ only by case on one server |
| Redis / Valkey | key patterns, `db<index>` | **sensitive** |
| MySQL / MariaDB | databases and tables are files or keys | depends on `lower_case_table_names`: 0 (the Linux default) sensitive, 1 stored in lowercase and compared without case, 2 stored as given and compared in lowercase; column names never |
| SQL Server | identifiers compared under a collation | depends on the collation: database names under the server collation, object names under each database's (the default `SQL_Latin1_General_CP1_CI_AS` is insensitive; a `_CS_` collation is sensitive) |
| OpenLDAP | DN attribute values of the usual naming attributes | insensitive (matching rules of `cn`, `ou`, `dc`) |
| Apereo CAS | local files and service names | treated as insensitive today; no engine-side identifier comparison |

On PostgreSQL, MongoDB, Redis and Valkey, an exception written for `crm.customers` therefore also covers a distinct `crm."Customers"`, `Customers` collection or `Customers:*` key pattern: an object that may hold other data, created by anyone with `CREATE` on the schema. On MySQL / MariaDB with `lower_case_table_names = 0` and on SQL Server databases with a case-sensitive collation the same holds, but the console does not know the setting: the agent does not report it.

Conditions and per-object sensitivity are a different matter: a looser match only reports more, so they stay case-insensitive (ADR-0014 implementation note of 2026-10-17). The agent's `sensitive_objects` match is likewise looser only.

Exceptions are created by hand in an admin form (no pre-fill from a finding or an event), so their globs are spelled by an administrator. Making them stricter turns into incidents what they suppressed only through case folding: findings at their next evaluation (a rescan, or a full pass after a policy or exception change, ADR-0014 decision 2) and access events evaluated after the change (past events are never re-evaluated, ADR-0021 decision 5).

## Options

### (A) Case-sensitive exceptions on engines that are case-sensitive by definition

Location exceptions compare case-sensitively when the item's engine is `postgres`, `mongodb`, `redis` or `valkey`, and when the engine is unknown (as for trailing spaces: an unknown engine never gets the looser rule). They stay case-insensitive on `sqlserver`, `mysql`, `mariadb`, `openldap` and `cas`. Conditions and scores stay case-insensitive everywhere. Trailing spaces keep the N1 rule. No new setting, no protocol change; the engine is the one the console already uses for `exceptionGlobOptions`.

### (B) A per-exception flag

An exception gains `match_case` (boolean), chosen by the administrator. With a default of `false`, nothing changes unless an administrator acts; with a default of `true` everywhere, exceptions on SQL Server databases under the default collation and on MySQL / MariaDB with `lower_case_table_names` 1 or 2 stop covering names the statement text spells in another case (`CRM.CUSTOMERS`), which the server treats as the same object. Either default is wrong on some engine, and the choice is left to whoever writes the exception, with a form field whose effect depends on server settings the form does not show.

### (C) Keep as is and document

Exceptions stay case-insensitive on every engine; docs/08 and the user guide say that on PostgreSQL, MongoDB, Redis and Valkey (and MySQL / MariaDB with `lower_case_table_names = 0`, SQL Server with a case-sensitive collation) an exception also covers objects whose names differ only by case. No migration, no new incidents; the over-suppression stays.

### (D) Option A, then case semantics reported by the agent

The agent reports, per monitored database, whether its object names compare with case (MySQL / MariaDB `lower_case_table_names`, SQL Server's database and server collation through `COLLATIONPROPERTY(…, 'ComparisonStyle')` or the collation name), in an optional `TargetStatus` field negotiated by a capability token (ADR-0022), and the console applies case-sensitive exceptions to the databases reported sensitive. A protocol change with its own security review; it extends A to the two engines whose case depends on configuration.

## Decision (proposed)

Option A now; option D as a later, separate ADR.

1. **Rule.** `exceptionGlobOptions(engine)` gains a `matchCase` option, true for `postgres`, `mongodb`, `redis`, `valkey` and for an unknown engine (`null`). With `matchCase`, the glob and the name are compared without the case fold (`foldCase`), with every other part of `foldName` and of the matcher unchanged: `*`, `?` and `\` escapes, linear time, and trailing spaces handled by the N1 rule (never ignored on these engines). It applies to finding exceptions (`exceptionCovers`) and to access-event exceptions (`exceptionCoversEvent`) on every location part (`database`, `schema`, `object`, `field`).
2. **Unchanged.** Policy conditions, per-object sensitivity and scores, the dedup key, the agent's `sensitive_objects` match, and exceptions on `sqlserver`, `mysql`, `mariadb`, `openldap` and `cas`.
3. **MySQL / MariaDB and SQL Server.** Exceptions stay case-insensitive there, with a documented residual (`lower_case_table_names = 0`; case-sensitive collations), until the agent reports the case semantics (option D).
4. **Normalization (implementation obligation).** Case-sensitive exceptions are correct only if the names the agent sends are spelled as the engine resolves them. On PostgreSQL, every Discovery and Audit source must send the catalog's spelling (unquoted names folded, quoted names kept); an integration test with a mixed-case quoted relation proves it for pgaudit `csvlog`, `jsonlog` and `pg_stat_statements`. On MongoDB, Redis and Valkey the names come from the server and are sent unchanged. Where a source cannot tell (an unqualified name in a `pg_stat_statements` text is already reported without schema), the stricter exception covers less, never more.
5. **Migration of existing exceptions.** No data migration: the rule changes at upgrade. To make the new incidents expected rather than surprising:
   - the console lists, on the policies page and in its startup log, the active exceptions whose location globs contain a cased letter (a character whose lowercase differs) and that can apply to a case-sensitive engine (no target, or a target of one of those engines), with a notice that they now match case-sensitively there;
   - the console records one audit entry at the first start after the upgrade, naming the number of such exceptions (no globs, no names);
   - the upgrade notes of the release tell administrators to review these exceptions before upgrading, and that exceptions written in lowercase for lowercase names (the PostgreSQL norm) are not affected.
   An exception written in another case than the real name (`CRM.Customers` for `crm.customers`) stops covering it on these engines and has to be corrected by an administrator (audited, ADR-0014 decision 5).
6. **UI.** The exception form says, next to the location fields, that names are compared with case on PostgreSQL, MongoDB, Redis and Valkey, and without case elsewhere.

## Consequences

- On PostgreSQL, MongoDB, Redis and Valkey an exception no longer suppresses objects whose names differ from its globs by case only; `crm."Customers"` raises its own incidents.
- More incidents after the upgrade where an exception's case differs from the real name, until it is corrected. They are bounded by the dedup and the per-target hourly cap (ADR-0021 decisions 6 and 8). Findings reappear at their next evaluation, events from the upgrade on.
- An exception that must cover both spellings needs a glob for each (two exceptions, or a `?` in place of the letter).
- Two engine lists in the console (`TRAILING_SPACE_BLIND_ENGINES` and the new case-sensitive list) must be kept in step with every engine added (phase 10: SQLite compares identifiers without case for ASCII letters; Firebird folds unquoted identifiers to uppercase and keeps quoted ones), each decided in that engine's connector ADR.
- A console database with a `C` / `POSIX` ctype keeps its JavaScript fallback for the SQL pre-filter; the case-sensitive comparison needs no fold, so it adds no fallback.

### Residual risks

- MySQL / MariaDB with `lower_case_table_names = 0` and SQL Server databases with a case-sensitive collation keep the over-suppression until option D.
- Unicode case pairs outside simple lowercase (the residuals of N1, docs/08) are irrelevant once case is compared exactly; they remain on the insensitive engines.

## Rejected alternatives

- **(B) A per-exception flag**: either default is wrong on some engine, and it puts a server setting the form cannot show in the hands of each exception's author. It also keeps a looser exception available on engines where it is never right.
- **(C) Keep and document**: exceptions are the console's only durable suppression besides false positives (ADR-0014 decision 3), and N1 already chose the stricter rule for trailing spaces with the same argument.
- **Case-sensitive conditions and scores too**: a stricter condition reports less, and statement texts on case-insensitive engines spell names as the client wrote them; N1 deliberately made them looser.
- **Grandfathering existing exceptions as case-insensitive**: it keeps every current over-suppression with no end date, and needs the per-exception flag of option B in storage. The listed inventory and the upgrade notes give administrators the same chance to adapt without keeping the hole. This is open question 1.

## Open questions (for the maintainer)

1. Cut over at upgrade (proposed) or grandfather the existing exceptions as case-insensitive until an administrator converts them? Proposed answer: cut over, with the inventory and upgrade notes of decision 5; grandfathering keeps the over-suppression indefinitely when nobody acts.
2. MongoDB database names: case-sensitive like collections (proposed, one rule per engine), or insensitive since one server cannot hold two databases differing only by case? Proposed answer: sensitive; it can only make an exception written in the wrong case cover less.
3. Option D (agent-reported case semantics for MySQL / MariaDB and SQL Server): write its ADR now, or after the phase 10 connector ADRs? Proposed answer: after phase 10's ADRs, so that SQLite and Firebird are covered by the same field.
