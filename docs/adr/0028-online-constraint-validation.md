# ADR-0028: Constraints on large console tables are validated outside the migration transaction

- **Status**: Accepted
- **Date**: 2026-09-29
- **Context references**: P7 (ROADMAP item "Console migration `0027`: the `access_events_bytes` CHECK constraint should be added `NOT VALID` then `VALIDATE`d", from the P4-D review, Low), PR #75, commits 285594e and 3da8ea9 (security review L1, L2): `console/src/db/online-constraints.ts`, `console/src/db/run-migrations.ts`, `console/src/db/migrations.test.ts`, `console/README.md` ("Constraints on large tables")

## Context
The console schema changes only through versioned Drizzle migrations ([AGENTS.md](../../AGENTS.md), "Conventions – Console"), applied by `migrate` with drizzle's migrator.

Migration `0027` (#62) adds the column `access_events.bytes` and the CHECK constraint `access_events_bytes` (`bytes is null or bytes >= 0`). Adding a CHECK to an existing table scans every row under an `ACCESS EXCLUSIVE` lock: no read or write of `access_events` can run meanwhile. `access_events` can be large: events are kept for the retention period (90 days by default), and a single agent can have about 30 000 rows per minute stored during a failed-login flood ([08-engine-capabilities.md](../08-engine-capabilities.md#known-limits-1)).

PostgreSQL avoids the long lock with two steps:
1. `ADD CONSTRAINT … NOT VALID`: no scan, a short `ACCESS EXCLUSIVE` lock;
2. `VALIDATE CONSTRAINT`: a scan under `SHARE UPDATE EXCLUSIVE`, during which reads and writes go on.

This only works if step 2 runs after the transaction of step 1 has committed. Drizzle's migrator applies **all pending migrations in one transaction**, so:
- editing `0027` to `NOT VALID` + `VALIDATE` in the same file still holds `ACCESS EXCLUSIVE` until the whole run commits;
- a new migration (e.g. `0032`) that drops the constraint and adds it again as `NOT VALID` comes too late: on an upgrade, `0027` runs in the same transaction and has already scanned the table under the lock.

Migration `0027` has shipped on `dev` and must not be edited: the hash recorded by installs that applied it would no longer match the file.

Migrations `0021` (which creates `access_events`) to `0026` were merged together (#54), and no release has been tagged. So an install whose `access_events` can hold rows while `0027` is pending has exactly `0026` as its last applied migration.

## Decision
1. **Pre-flight for `0027`.** Before drizzle's migrator runs, `migrate` (`applyAccessEventsBytesOnline` in `console/src/db/online-constraints.ts`) applies `0027` itself when, and only when, all of the following hold:
   - the migrations folder contains `0027` right after `0026`, and the file matches its journal entry;
   - the last migration recorded in `drizzle.__drizzle_migrations` is `0026` (checked again after taking an `EXCLUSIVE` lock on that table, as a second guard behind the run lock of decision 6);
   - `access_events` exists and has no `bytes` column.

   It then runs:
   - **one short transaction**: `ADD COLUMN bytes bigint` (catalog only), `ADD CONSTRAINT access_events_bytes CHECK (…) NOT VALID` (no scan), and the insertion of `0027`'s row in drizzle's journal table, with the **hash of the unchanged `0027` file** and its journal timestamp;
   - **then, in a statement of its own** (autocommit): `VALIDATE CONSTRAINT access_events_bytes`.

   Drizzle's migrator then sees `0027` as applied and runs `0028` onwards. The statements are those of `0027`, word for word, except for `NOT VALID`. The final schema (column, constraint name and expression, validated) is the one of `0027`. Drizzle-kit's snapshots therefore stay exact, and a later `migrate` run makes no change.
2. **Every other state keeps the plain `0027`.** A fresh install runs it as shipped (the table is created empty in the same run). An install that already applied it keeps its validated constraint. An install whose last migration is before `0021` has no `access_events` table yet.
3. **`DEFERRED_VALIDATIONS`.** `migrate` validates, after drizzle's migrator and on every run, each constraint of the constant list `DEFERRED_VALIDATIONS` (`online-constraints.ts`) that exists and is still `NOT VALID`. Each constraint is validated in its own autocommit statement. This finishes a run interrupted between the two steps of decision 1. The list holds constant, owner-defined names only; never input. Every table and constraint name must be a plain lower-case identifier (`^[a-z_][a-z0-9_]{0,62}$`), checked for the whole list before any query; a name that does not match is a programming error and fails `migrate`.
4. **Rule for new migrations.** A `CHECK` or foreign key added to a console table that may be large is written `NOT VALID` in a custom migration and listed in `DEFERRED_VALIDATIONS`. It is never validated inside the migration itself.
5. **Precise exception to "schema only through versioned migrations".** The migrate runner may change the schema outside a migration SQL file in two cases only:
   - (a) applying `0027` as in decision 1: same statements with `NOT VALID`, recorded under `0027`'s real hash, only on an install at exactly `0026`;
   - (b) `VALIDATE CONSTRAINT` for the constraints of `DEFERRED_VALIDATIONS`.

   Neither case changes the final schema that the migration files define. Any other change outside a migration file needs a new ADR.
6. **Concurrent `migrate` runs are serialized.** Each run holds a session-level PostgreSQL advisory lock (`MIGRATION_LOCK_KEY` in `console/src/db/run-migrations.ts`) on a dedicated connection for the whole run: the `pgboss` ownership pre-flight, the `0027` pre-flight, drizzle's migrator and the deferred validations. The lock is released in a `finally` block, and by the server if the connection drops. A second run waits for it, then finds nothing pending.

## Consequences
- An upgrade from `0026` no longer blocks `access_events` for a full-table scan: the `ACCESS EXCLUSIVE` lock is held for milliseconds, and the validation scan lets the web and worker processes read and write.
- `migrate` now writes to drizzle's journal table in one case (decision 1). This relies on drizzle's current migrator behaviour: it compares the pending migrations only with the latest recorded `created_at`, and it stores each migration's hash. A drizzle upgrade that changes the journal format or this comparison must be checked against `online-constraints.ts`. The test `console/src/db/migrations.test.ts` ("0027: access_events_bytes without a long lock") compares the recorded hashes and timestamps with those of the migration files, and the resulting schema with a fresh install.
- An install that stops between the two steps of decision 1 has the constraint `NOT VALID`: new and updated rows are checked, and existing rows are not checked yet until the next `migrate` run validates them (decision 3). A row that fails the check makes that validation fail, and `migrate` fails with it until the row is fixed. The check is `bytes is null or bytes >= 0`, and the column did not exist before, so existing rows are all `null`.
- Validation still reads the whole table. It takes time and I/O, but no longer blocks other sessions (`SHARE UPDATE EXCLUSIVE` conflicts only with schema changes, index builds, `VACUUM` and `ANALYZE` on the table).

## Limits
- **Only installs at exactly `0026`** take the online path. The only other states in which `access_events` holds rows while `0027` is pending are builds from inside #54 (`0021` to `0025`). Those were never merged states, and they take the plain `0027` with its lock.
- **Only `0027`** is covered by decision 1. Every other shipped migration that added a constraint to an existing table keeps its locking behaviour. Future ones follow decision 4.
- A `migrate` run blocked on a long validation keeps any other `migrate` run waiting (decision 6); the web and worker processes are not affected.
- The rule of decision 4 relies on review: no check fails a migration that adds a validated constraint to a large table.

## Rejected alternatives
- **Edit `0027`** (`NOT VALID` then `VALIDATE` in the file): it does not remove the lock, because both steps run in the migrator's single transaction. It also changes the hash of a migration that installs have already recorded.
- **A new migration that re-adds the constraint `NOT VALID`**: on an upgrade from `0026`, `0027` runs first in the same transaction and has already done the locking scan.
- **Replace drizzle's migrator with a runner that commits each migration separately**: this would solve the general case, but it is a larger change to the migration path, it breaks the "all or nothing" upgrade that operators get today, and it cannot fix `0027` anyway: `ADD` and `VALIDATE` are in the same file. It may be reconsidered later with its own ADR.
- **Document a manual procedure for operators** (apply `0027` by hand before upgrading): error-prone, and it cannot be tested in CI.
- **Accept the lock** (the finding was rated Low): the lock time grows with the event volume, which an attacker who can cause failed logins can inflate. Every console process then blocks on its next read or write of `access_events` during the upgrade.
- **Drop the CHECK**: this loses the database-level guarantee that `bytes` is never negative, which the application code alone would then have to provide.
