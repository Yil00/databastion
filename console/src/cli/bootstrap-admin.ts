import { readEnvOrFile } from "@/config/env";
import { closeDb, getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { bootstrapAdmin, BootstrapError } from "@/server/auth/users";

/**
 * `pnpm admin:bootstrap`: creates the first administrator from
 * `DATABASTION_BOOTSTRAP_ADMIN_USERNAME` and `DATABASTION_BOOTSTRAP_ADMIN_PASSWORD(_FILE)`.
 * Refuses when any user exists. There is no default account and no default password.
 * The password is never logged.
 */
async function main(): Promise<void> {
  const username = readEnvOrFile("DATABASTION_BOOTSTRAP_ADMIN_USERNAME");
  const password = readEnvOrFile("DATABASTION_BOOTSTRAP_ADMIN_PASSWORD");
  if (!username || !password) {
    throw new BootstrapError(
      "Set DATABASTION_BOOTSTRAP_ADMIN_USERNAME and DATABASTION_BOOTSTRAP_ADMIN_PASSWORD(_FILE).",
    );
  }
  const id = await bootstrapAdmin(getDb(), username, password);
  logger.info({ userId: id }, "first administrator created");
}

main()
  .catch((err: unknown) => {
    logger.error({ error: errorSummary(err) }, "administrator bootstrap failed");
    process.exitCode = 1;
  })
  .finally(() => closeDb());
