import { getDatabaseUrl, readEnvOrFile } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";

import { MIGRATIONS_FOLDER, runMigrations } from "./run-migrations";

/**
 * `pnpm db:migrate`. Migrations run as the database OWNER role: `DATABASE_MIGRATION_URL(_FILE)`
 * when set, else `DATABASE_URL(_FILE)` (single-role development setups). The web and worker
 * processes use `DATABASE_URL`, a non-owner member of `databastion_app` (see README).
 */
async function main(): Promise<void> {
  const ownerUrl = readEnvOrFile("DATABASE_MIGRATION_URL");
  logger.info(
    { migrationsFolder: MIGRATIONS_FOLDER, ownerRole: ownerUrl !== undefined },
    "applying database migrations",
  );
  await runMigrations(ownerUrl ?? getDatabaseUrl());
  logger.info("database migrations applied");
}

main().catch((err: unknown) => {
  logger.error({ error: errorSummary(err) }, "migration failed");
  process.exitCode = 1;
});
