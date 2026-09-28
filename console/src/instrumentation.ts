/** Next.js startup hook: configuration warnings of the web process. */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startupWarnings } = await import("@/server/startup-checks");
  const { logger } = await import("@/lib/logger");
  for (const warning of startupWarnings()) logger.warn(warning);
}
