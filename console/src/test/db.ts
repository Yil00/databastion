import { randomBytes } from "node:crypto";
import path from "node:path";

import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client } from "pg";
import { inject } from "vitest";

import { closeDb, getDb } from "@/db/client";
import { jobHub } from "@/server/agent-api/job-hub";

export const pgAdminUrl = inject("pgAdminUrl");
export const hasDb = pgAdminUrl !== null;

/**
 * Creates a fresh database for the calling test file, migrates it with the committed migrations
 * and points `DATABASE_URL` at it. Returns a teardown that drops it.
 */
export async function setupTestDatabase(): Promise<() => Promise<void>> {
  if (!pgAdminUrl) throw new Error("no test database");
  const name = `t_${randomBytes(6).toString("hex")}`;
  const admin = new Client({ connectionString: pgAdminUrl });
  await admin.connect();
  await admin.query(`create database ${name}`);
  await admin.end();
  const url = new URL(pgAdminUrl);
  url.pathname = `/${name}`;
  process.env.DATABASE_URL = url.toString();
  await migrate(getDb(), { migrationsFolder: path.resolve(__dirname, "../../drizzle") });
  return async () => {
    await jobHub.close();
    await closeDb();
    const c = new Client({ connectionString: pgAdminUrl });
    await c.connect();
    await c.query(`drop database if exists ${name} with (force)`);
    await c.end();
  };
}
