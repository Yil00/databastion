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
 * Reduces an unknown error for logging, without stack or bound values.
 * - PostgreSQL errors (the error itself or its cause, e.g. wrapped by drizzle) are reduced to the
 *   SQLSTATE `code` and the constraint name: pg message texts can quote values (L8).
 * - Other errors keep their message, minus drizzle's `\nparams: <bound values>` suffix.
 */
export function errorSummary(err: unknown): {
  message: string;
  cause?: string;
  code?: string;
  constraint?: string;
} {
  if (!(err instanceof Error)) {
    return { message: String(err) };
  }
  const pg = pgError(err) ?? pgError(err.cause);
  if (pg) {
    return pg.constraint
      ? { message: "database error", code: pg.code, constraint: pg.constraint }
      : { message: "database error", code: pg.code };
  }
  const message = withoutParams(err.message);
  const cause = err.cause instanceof Error ? withoutParams(err.cause.message) : undefined;
  return cause === undefined ? { message } : { message, cause };
}

const SQLSTATE = /^[0-9A-Z]{5}$/;

function pgError(e: unknown): { code: string; constraint?: string } | undefined {
  if (!(e instanceof Error)) return undefined;
  const { code, constraint } = e as Error & { code?: unknown; constraint?: unknown };
  if (typeof code !== "string" || !SQLSTATE.test(code)) return undefined;
  return typeof constraint === "string" && /^[A-Za-z0-9_]{1,63}$/.test(constraint)
    ? { code, constraint }
    : { code };
}

function withoutParams(message: string): string {
  const i = message.indexOf("\nparams:");
  return i === -1 ? message : `${message.slice(0, i)} [params redacted]`;
}
