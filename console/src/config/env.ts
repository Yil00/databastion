import { readFileSync } from "node:fs";

/**
 * Configuration loading helpers.
 *
 * Secrets are provided either directly (`NAME`) or through a file (`NAME_FILE`,
 * e.g. a Docker secret mounted under /run/secrets). Error messages NEVER
 * contain the secret value, only the variable names.
 */

export type Env = Readonly<Record<string, string | undefined>>;
export type FileReader = (path: string) => string;

const defaultReader: FileReader = (path) => readFileSync(path, "utf8");

export class ConfigError extends Error {
  override name = "ConfigError";
}

/**
 * Reads `name` from the environment, or from the file pointed to by
 * `${name}_FILE`. Returns `undefined` if neither is set.
 *
 * - Setting both is an error (ambiguous configuration).
 * - The file content is trimmed of surrounding whitespace (trailing newline).
 * - An empty value is an error.
 */
export function readEnvOrFile(
  name: string,
  env: Env = process.env,
  readFile: FileReader = defaultReader,
): string | undefined {
  const fileVar = `${name}_FILE`;
  const direct = env[name];
  const filePath = env[fileVar];

  if (direct !== undefined && direct !== "" && filePath !== undefined && filePath !== "") {
    throw new ConfigError(`Both ${name} and ${fileVar} are set; set only one of them.`);
  }

  if (filePath !== undefined && filePath !== "") {
    let content: string;
    try {
      content = readFile(filePath);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "unknown error";
      throw new ConfigError(`Cannot read the file referenced by ${fileVar} (${code}).`);
    }
    const value = content.trim();
    if (value === "") {
      throw new ConfigError(`The file referenced by ${fileVar} is empty.`);
    }
    return value;
  }

  if (direct === undefined) {
    return undefined;
  }
  const value = direct.trim();
  if (value === "") {
    throw new ConfigError(`${name} is set but empty.`);
  }
  return value;
}

/** Same as {@link readEnvOrFile}, but the value is mandatory. */
export function requireEnvOrFile(
  name: string,
  env: Env = process.env,
  readFile: FileReader = defaultReader,
): string {
  const value = readEnvOrFile(name, env, readFile);
  if (value === undefined) {
    throw new ConfigError(`Missing configuration: set ${name} or ${name}_FILE.`);
  }
  return value;
}

/**
 * Returns the internal PostgreSQL connection string (console database only;
 * the console never stores target database credentials, invariant I3).
 */
export function getDatabaseUrl(
  env: Env = process.env,
  readFile: FileReader = defaultReader,
): string {
  const value = requireEnvOrFile("DATABASE_URL", env, readFile);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError("DATABASE_URL is not a valid URL.");
  }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new ConfigError("DATABASE_URL must use the postgres:// or postgresql:// scheme.");
  }
  return value;
}

/**
 * `DATABASTION_AGENT_TOKENS_HOLD` (ADR-0022 decision 8, multi-replica rollout; end-of-phase-9
 * review L1): the console release line (`X.Y`) whose capability tokens the heartbeat answer lists,
 * set on every replica during a rolling upgrade from that release line. Only the listing changes;
 * the console accepts every field it knows (src/server/agent-api/capabilities.ts). The values are
 * the release lines whose token set the console knows.
 */
export const AGENT_TOKENS_HOLD_VAR = "DATABASTION_AGENT_TOKENS_HOLD";
export const AGENT_TOKENS_HOLD_RELEASES = ["0.8"] as const;
export type AgentTokensHold = (typeof AGENT_TOKENS_HOLD_RELEASES)[number];

/**
 * The release line of `DATABASTION_AGENT_TOKENS_HOLD`, or `null` when it is unset or empty (no
 * hold: every token is listed). Any other value is a {@link ConfigError}: the web and worker
 * processes refuse to start (`startupFatal`). Exact match after trimming, no patch level.
 */
export function agentTokensHold(env: Env = process.env): AgentTokensHold | null {
  const raw = env[AGENT_TOKENS_HOLD_VAR]?.trim();
  if (raw === undefined || raw === "") return null;
  const release = AGENT_TOKENS_HOLD_RELEASES.find((r) => r === raw);
  if (release === undefined) {
    throw new ConfigError(
      `${AGENT_TOKENS_HOLD_VAR} must be unset or one of: ${AGENT_TOKENS_HOLD_RELEASES.join(", ")} (the release line of the oldest console replica).`,
    );
  }
  return release;
}
