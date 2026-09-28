/**
 * Node.js part of the Next.js startup hook (src/instrumentation.ts): configuration warnings and the
 * dedicated /metrics listener of the web process.
 */
export async function registerNode(): Promise<void> {
  const { startupWarnings } = await import("@/server/startup-checks");
  const { logger, errorSummary } = await import("@/lib/logger");
  for (const warning of startupWarnings()) logger.warn(warning);
  await startMetricsListenerOnce();
  if (!process.env.DATABASE_URL && !process.env.DATABASE_URL_FILE) return;
  try {
    const { getPool } = await import("@/db/client");
    const { runtimeRoleWarnings } = await import("@/server/db-role-check");
    for (const warning of await runtimeRoleWarnings(getPool())) logger.warn(warning);
  } catch (err) {
    logger.warn({ error: errorSummary(err) }, "database role check skipped");
  }
}

const STARTED = Symbol.for("databastion.metricsListener");

/** DATABASTION_METRICS_PORT: dedicated /metrics listener, started once per process. */
async function startMetricsListenerOnce(): Promise<void> {
  const { logger, errorSummary } = await import("@/lib/logger");
  const { metricsListenerConfig } = await import("@/server/metrics");
  const state = globalThis as { [STARTED]?: boolean };
  if (state[STARTED]) return;
  let config;
  try {
    config = metricsListenerConfig();
  } catch (err) {
    // /metrics is then disabled everywhere (the main-port route answers 404 too).
    logger.error({ error: errorSummary(err) }, "metrics listener configuration error: /metrics disabled");
    return;
  }
  if (config === null) return;
  state[STARTED] = true;
  try {
    const { startMetricsListener } = await import("@/server/metrics-listener");
    await startMetricsListener(config);
    logger.info({ host: config.host, port: config.port }, "metrics listener started");
  } catch (err) {
    state[STARTED] = false;
    logger.error({ error: errorSummary(err) }, "metrics listener not started: /metrics unavailable");
  }
}
