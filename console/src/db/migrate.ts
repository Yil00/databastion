import path from "node:path";
import { fileURLToPath } from "node:url";

import { migrate } from "drizzle-orm/node-postgres/migrator";

import { readEnvOrFile } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";

import { closeDb, getDb } from "./client";

const migrationsFolder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../drizzle");

/**
 * Migrations run as the database OWNER role: `DATABASE_MIGRATION_URL(_FILE)` when set, else
 * `DATABASE_URL(_FILE)` (single-role setups, development). The web and worker processes use
 * `DATABASE_URL`, which should be a non-owner member of `databastion_app` (see README).
 */
async function main(): Promise<void> {
  const ownerUrl = readEnvOrFile("DATABASE_MIGRATION_URL");
  if (ownerUrl) {
    process.env.DATABASE_URL = ownerUrl;
    delete process.env.DATABASE_URL_FILE;
  }
  logger.info({ migrationsFolder, ownerRole: ownerUrl !== undefined }, "applying database migrations");
  await migrate(getDb(), { migrationsFolder });
  logger.info("database migrations applied");
}

main()
  .catch((err: unknown) => {
    logger.error({ error: errorSummary(err) }, "migration failed");
    process.exitCode = 1;
  })
  .finally(() => closeDb());
