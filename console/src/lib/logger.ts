import pino from "pino";

/**
 * Structured JSON logger (stdout). Never log secrets, connection strings,
 * or agent-provided samples: the redact list is a safety net, not a licence.
 */
export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  base: { service: "databastion-console" },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level: (label) => ({ level: label }),
  },
  redact: {
    paths: [
      "password",
      "*.password",
      "connectionString",
      "*.connectionString",
      "databaseUrl",
      "*.databaseUrl",
      "authorization",
      "*.authorization",
      "headers.authorization",
      "req.headers.authorization",
      "secret",
      "*.secret",
      "token",
      "*.token",
    ],
    censor: "[REDACTED]",
  },
});

export type Logger = typeof logger;

/**
 * Reduces an unknown error to its message (and its cause's message, e.g. the
 * pg error wrapped by drizzle), for logging without stack or bound values.
 */
export function errorSummary(err: unknown): { message: string; cause?: string } {
  if (!(err instanceof Error)) {
    return { message: String(err) };
  }
  const cause = err.cause instanceof Error ? err.cause.message : undefined;
  return cause === undefined ? { message: err.message } : { message: err.message, cause };
}
