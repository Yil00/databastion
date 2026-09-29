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
const shared = processGlobal<{ pool?: Pool }>("dbPool", () => ({}));
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

export async function closeDb(): Promise<void> {
  const current = shared.pool;
  shared.pool = undefined;
  db = undefined;
  dbPool = undefined;
  await current?.end();
}
