/** Next.js startup hook: configuration warnings of the web process. */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startupWarnings } = await import("@/server/startup-checks");
  const { logger, errorSummary } = await import("@/lib/logger");
  for (const warning of startupWarnings()) logger.warn(warning);
  if (!process.env.DATABASE_URL && !process.env.DATABASE_URL_FILE) return;
  try {
    const { getPool } = await import("@/db/client");
    const { runtimeRoleWarnings } = await import("@/server/db-role-check");
    for (const warning of await runtimeRoleWarnings(getPool())) logger.warn(warning);
  } catch (err) {
    logger.warn({ error: errorSummary(err) }, "database role check skipped");
  }
}
