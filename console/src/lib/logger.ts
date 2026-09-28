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
      "agent_secret",
      "*.agent_secret",
      "new_secret",
      "*.new_secret",
      "cookie",
      "*.cookie",
      "headers.cookie",
      "req.headers.cookie",
      // Request bodies are never logged; these paths are a safety net for /enroll and /rotate.
      "body",
      "*.body",
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
  const message = withoutParams(err.message);
  const cause = err.cause instanceof Error ? withoutParams(err.cause.message) : undefined;
  return cause === undefined ? { message } : { message, cause };
}

/**
 * Drizzle's query errors end with `\nparams: <bound values>`: bound values (hashes, agent data)
 * are never logged.
 */
function withoutParams(message: string): string {
  const i = message.indexOf("\nparams:");
  return i === -1 ? message : `${message.slice(0, i)} [params redacted]`;
}
