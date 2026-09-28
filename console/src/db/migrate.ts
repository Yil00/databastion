import path from "node:path";
import { fileURLToPath } from "node:url";

import { migrate } from "drizzle-orm/node-postgres/migrator";

import { errorSummary, logger } from "@/lib/logger";

import { closeDb, getDb } from "./client";

const migrationsFolder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../drizzle");

async function main(): Promise<void> {
  logger.info({ migrationsFolder }, "applying database migrations");
  await migrate(getDb(), { migrationsFolder });
  logger.info("database migrations applied");
}

main()
  .catch((err: unknown) => {
    logger.error({ error: errorSummary(err) }, "migration failed");
    process.exitCode = 1;
  })
  .finally(() => closeDb());
