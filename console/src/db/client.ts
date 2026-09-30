import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import { getDatabaseUrl } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";
import { processGlobal } from "@/server/process-global";

import * as schema from "./schema";

export type Database = NodePgDatabase<typeof schema>;

/**
 * The pool is process-wide (globalThis, see src/server/process-global.ts): `next build` bundles this
 * module once per layer (route handlers, server components, startup hook), and a pool per copy
 * would multiply the connections of the web process. `pg` is an external package, so every copy
 * shares the same `Pool` class. The Drizzle wrapper stays per copy (Drizzle is bundled).
 */
const shared = processGlobal<{ pool?: Pool; rateLimitPool?: Pool }>("dbPool", () => ({}));
let db: Database | undefined;
let dbPool: Pool | undefined;

/** Lazily creates the shared pool so that `next build` never needs a database. */
export function getPool(): Pool {
  if (!shared.pool) {
    const pool = new Pool({
      connectionString: getDatabaseUrl(),
      application_name: "databastion-console",
      max: 10,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
    });
    pool.on("error", (err) => {
      // Idle client errors (e.g. DB restart). Message only: no connection details.
      logger.error({ error: errorSummary(err) }, "postgres pool error");
    });
    shared.pool = pool;
  }
  return shared.pool;
}

export function getDb(): Database {
  const pool = getPool();
  if (!db || dbPool !== pool) {
    db = drizzle(pool, { schema });
    dbPool = pool;
  }
  return db;
}

/**
 * Dedicated pool of the shared rate limiters (P4-D, `src/server/rate-limit.ts`): a flood on one hot
 * counter row can only contend for these connections, never starve the main pool. Every
 * connection runs with `lock_timeout` and `statement_timeout`, so a statement that waits too long
 * is cancelled by the server (it never commits after the limiter gave up on it), and waiting for a
 * free connection is bounded by `connectionTimeoutMillis`.
 */
export const RATE_LIMIT_POOL = {
  max: 3,
  connectionTimeoutMs: 2_000,
  lockTimeoutMs: 1_500,
  statementTimeoutMs: 2_000,
};
let rateLimitDb: Database | undefined;
let rateLimitDbPool: Pool | undefined;

export function getRateLimitPool(): Pool {
  if (!shared.rateLimitPool) {
    const pool = new Pool({
      connectionString: getDatabaseUrl(),
      application_name: "databastion-console-rate-limits",
      max: RATE_LIMIT_POOL.max,
      connectionTimeoutMillis: RATE_LIMIT_POOL.connectionTimeoutMs,
      idleTimeoutMillis: 30_000,
      lock_timeout: RATE_LIMIT_POOL.lockTimeoutMs,
      statement_timeout: RATE_LIMIT_POOL.statementTimeoutMs,
    });
    pool.on("error", (err) => {
      logger.error({ error: errorSummary(err) }, "postgres rate-limit pool error");
    });
    shared.rateLimitPool = pool;
  }
  return shared.rateLimitPool;
}

export function getRateLimitDb(): Database {
  const pool = getRateLimitPool();
  if (!rateLimitDb || rateLimitDbPool !== pool) {
    rateLimitDb = drizzle(pool, { schema });
    rateLimitDbPool = pool;
  }
  return rateLimitDb;
}

export async function closeDb(): Promise<void> {
  const current = shared.pool;
  const rateLimits = shared.rateLimitPool;
  shared.pool = undefined;
  shared.rateLimitPool = undefined;
  db = undefined;
  dbPool = undefined;
  rateLimitDb = undefined;
  rateLimitDbPool = undefined;
  await Promise.all([current?.end(), rateLimits?.end()]);
}
