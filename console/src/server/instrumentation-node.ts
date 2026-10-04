/**
 * Node.js part of the Next.js startup hook (src/instrumentation.ts): fatal configuration check
 * (exits), configuration warnings and the dedicated /metrics listener of the web process.
 */
export async function registerNode(): Promise<void> {
  const { startupErrors, startupFatal, startupWarnings } = await import("@/server/startup-checks");
  const { logger, errorSummary } = await import("@/lib/logger");
  const fatal = startupFatal();
  if (fatal !== null) {
    // Exit explicitly: an error thrown from register() is not guaranteed to stop `next start`.
    logger.fatal(fatal);
    logger.flush();
    process.exit(1);
  }
  for (const warning of startupWarnings()) logger.warn(warning);
  for (const message of startupErrors()) logger.error(message);
  await startMetricsListenerOnce();
  if (!process.env.DATABASE_URL && !process.env.DATABASE_URL_FILE) return;
  // Policy engine wake-ups after findings ingestion and policy changes (sent to the worker).
  const { installPgBossPolicySender } = await import("@/server/policy-queue-boss");
  installPgBossPolicySender();
  try {
    const { getPool } = await import("@/db/client");
    const { runtimeRoleWarnings } = await import("@/server/db-role-check");
    for (const warning of await runtimeRoleWarnings(getPool())) logger.warn(warning);
  } catch (err) {
    logger.warn({ error: errorSummary(err) }, "database role check skipped");
  }
  // ADR-0038: provider discovery (hosts logged, retried while down) and the break-glass check.
  try {
    const { currentLocalLoginMode, warmUpOidcProvider } = await import("@/server/oidc/runtime");
    const { localLoginStartupError } = await import("@/server/oidc/startup");
    const { getDb } = await import("@/db/client");
    warmUpOidcProvider();
    const message = await localLoginStartupError(getDb(), currentLocalLoginMode());
    if (message !== null) logger.error(message);
  } catch (err) {
    logger.warn({ error: errorSummary(err) }, "local login check skipped");
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
