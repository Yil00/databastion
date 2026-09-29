import { readFileSync } from "node:fs";
import path from "node:path";

import { readMigrationFiles } from "drizzle-orm/migrator";
import type { Pool, PoolClient } from "pg";

/**
 * Lock-friendly CHECK constraints on large tables (P7, P4-D review Low).
 *
 * Why this is not a migration: drizzle's migrator applies every pending migration in ONE
 * transaction. A `CHECK` added by a migration scans the whole table under an `ACCESS EXCLUSIVE`
 * lock, and a later migration in the same run cannot help: `NOT VALID` + `VALIDATE CONSTRAINT`
 * only avoids the long lock when the validation runs in a transaction of its own, after the one
 * that added the constraint has committed. A migration that already shipped is never edited.
 *
 * So the migrate runner (`run-migrations.ts`) does two things around drizzle's migrator:
 *
 * 1. `applyAccessEventsBytesOnline` (pre-flight, once): an install whose last applied migration is
 *    `0026` (the only state in which `access_events` can already hold rows while `0027` is still
 *    pending) gets `0027` applied here instead, in its lock-friendly form, and recorded in drizzle's
 *    journal table with the hash of the unchanged `0027` file, so the migrator skips it:
 *      - transaction 1: `ADD COLUMN bytes` (catalog only), `ADD CONSTRAINT ... NOT VALID` (no scan),
 *        the journal row; the `ACCESS EXCLUSIVE` lock is held for milliseconds;
 *      - statement 2 (autocommit): `VALIDATE CONSTRAINT`, which scans under `SHARE UPDATE
 *        EXCLUSIVE` only: reads and writes of `access_events` go on meanwhile.
 *    Any other state keeps the plain `0027`: a fresh install (the table is created empty in the same
 *    run) or an install that already applied it (the constraint exists, validated).
 * 2. `validateDeferredConstraints` (every run, after the migrator): validates, one autocommit
 *    statement each, the listed constraints still `NOT VALID` (a run interrupted between the two
 *    steps above, or a future migration that adds a constraint `NOT VALID` and lists it here).
 *
 * The final schema is the one of `0027` (same column, same constraint name and expression,
 * validated): drizzle-kit's snapshots stay exact.
 */

/** Constraints validated outside the migration transaction, in this order. Owner-defined names. */
export const DEFERRED_VALIDATIONS: readonly { table: string; constraint: string }[] = [
  { table: "access_events", constraint: "access_events_bytes" },
];

const PLAIN_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

/** Quotes a plain lower-case identifier; anything else is a programming error (security review L2). */
export function quotePlainIdentifier(name: string): string {
  if (!PLAIN_NAME.test(name)) throw new Error(`not a plain identifier: ${JSON.stringify(name)}`);
  return `"${name}"`;
}

export const ONLINE_0027_TAG = "0027_p4d_access_events_bytes";

/** The statements of `0027`, with the constraint added `NOT VALID` (validated separately). */
export const ONLINE_0027_STATEMENTS = [
  'ALTER TABLE "access_events" ADD COLUMN "bytes" bigint',
  'ALTER TABLE "access_events" ADD CONSTRAINT "access_events_bytes" CHECK ("access_events"."bytes" is null or "access_events"."bytes" >= 0) NOT VALID',
] as const;

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

function readJournal(migrationsFolder: string): JournalEntry[] {
  const raw = JSON.parse(readFileSync(path.join(migrationsFolder, "meta", "_journal.json"), "utf8")) as { entries: JournalEntry[] };
  return raw.entries;
}

async function lastAppliedMillis(c: PoolClient): Promise<number | null> {
  const { rows: exists } = await c.query<{ present: boolean }>(
    "select to_regclass('drizzle.__drizzle_migrations') is not null as present",
  );
  if (!exists[0]?.present) return null;
  const { rows } = await c.query<{ created_at: string | null }>(
    "select created_at from drizzle.__drizzle_migrations order by created_at desc limit 1",
  );
  const v = rows[0]?.created_at;
  return v === undefined || v === null ? null : Number(v);
}

export type Online0027Outcome = "applied" | "not_needed";

/**
 * Step 1 above. Returns `applied` when it applied `0027` itself (the migrator then skips it).
 * Folders without `0027` (tests migrating a truncated journal) are left alone.
 */
export async function applyAccessEventsBytesOnline(pool: Pool, migrationsFolder: string): Promise<Online0027Outcome> {
  const journal = readJournal(migrationsFolder);
  const at = journal.findIndex((e) => e.tag === ONLINE_0027_TAG);
  const previous = journal[at - 1];
  if (at < 1 || !previous) return "not_needed";
  const migration = readMigrationFiles({ migrationsFolder })[at];
  if (!migration || migration.folderMillis !== journal[at]?.when) return "not_needed";
  const c = await pool.connect();
  try {
    // Exactly 0026 applied: 0027 is the next one, so recording it keeps drizzle's order (it only
    // compares the pending migrations with the latest recorded one).
    if ((await lastAppliedMillis(c)) !== previous.when) return "not_needed";
    const { rows } = await c.query<{ table_present: boolean; column_present: boolean }>(
      `select to_regclass('public.access_events') is not null as table_present,
              exists (select 1 from information_schema.columns
                      where table_schema = 'public' and table_name = 'access_events' and column_name = 'bytes') as column_present`,
    );
    if (!rows[0]?.table_present || rows[0].column_present) return "not_needed";
    await c.query("BEGIN");
    try {
      // Re-checked under the lock: a concurrent migrate run may have applied 0027 meanwhile.
      await c.query("LOCK TABLE drizzle.__drizzle_migrations IN EXCLUSIVE MODE");
      if ((await lastAppliedMillis(c)) !== previous.when) {
        await c.query("ROLLBACK");
        return "not_needed";
      }
      for (const stmt of ONLINE_0027_STATEMENTS) await c.query(stmt);
      await c.query('insert into drizzle.__drizzle_migrations ("hash", "created_at") values ($1, $2)', [
        migration.hash,
        migration.folderMillis,
      ]);
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => undefined);
      throw err;
    }
  } finally {
    c.release();
  }
  await validateDeferredConstraints(pool);
  return "applied";
}

/**
 * Step 2 above: `VALIDATE CONSTRAINT` for every listed constraint that exists and is still
 * `NOT VALID`, each in its own autocommit statement. Returns the constraints validated.
 */
export async function validateDeferredConstraints(pool: Pool): Promise<string[]> {
  const done: string[] = [];
  for (const { table, constraint } of DEFERRED_VALIDATIONS) {
    quotePlainIdentifier(table);
    quotePlainIdentifier(constraint);
  }
  for (const { table, constraint } of DEFERRED_VALIDATIONS) {
    const { rows } = await pool.query<{ pending: boolean }>(
      `select not c.convalidated as pending
         from pg_catalog.pg_constraint c
         join pg_catalog.pg_class t on t.oid = c.conrelid
         join pg_catalog.pg_namespace n on n.oid = t.relnamespace
        where n.nspname = 'public' and t.relname = $1 and c.conname = $2`,
      [table, constraint],
    );
    if (!rows[0]?.pending) continue;
    // Names come from the constant list above, never from input, and are checked anyway.
    await pool.query(`ALTER TABLE public.${quotePlainIdentifier(table)} VALIDATE CONSTRAINT ${quotePlainIdentifier(constraint)}`);
    done.push(constraint);
  }
  return done;
}
