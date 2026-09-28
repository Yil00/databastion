import { HEARTBEAT_INTERVAL_S } from "./agent-api/pipeline";

/**
 * Alerting configuration (P3-C), read at use time by the web process (validation of channel
 * settings) and the worker (delivery). Never logs a value.
 */
type Env = Readonly<Record<string, string | undefined>>;

/**
 * `DATABASTION_ALERTING_INSECURE_DEV=1` (development and tests only): allows `http://` webhook
 * URLs, webhooks towards internal (private / loopback) addresses, and plain-text SMTP towards a
 * non-loopback host. Link-local, metadata, multicast and reserved addresses stay refused. A
 * warning is logged at startup when it is set in production.
 */
export const INSECURE_DEV_VAR = "DATABASTION_ALERTING_INSECURE_DEV";

export function insecureDevAllowed(env: Env = process.env): boolean {
  return env[INSECURE_DEV_VAR] === "1";
}

/**
 * Silent-agent threshold: an online agent without heartbeat for `N` heartbeat intervals raises
 * one alert. `DATABASTION_SILENT_AGENT_INTERVALS`, default 10 (5 minutes at the 30 s interval),
 * accepted 3 to 2880 (1 day); other values fall back to the default.
 */
export const SILENT_AGENT_INTERVALS_VAR = "DATABASTION_SILENT_AGENT_INTERVALS";
export const DEFAULT_SILENT_AGENT_INTERVALS = 10;

export function silentAgentIntervals(env: Env = process.env): number {
  const raw = env[SILENT_AGENT_INTERVALS_VAR];
  if (raw === undefined || raw.trim() === "") return DEFAULT_SILENT_AGENT_INTERVALS;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 3 && n <= 2880 ? n : DEFAULT_SILENT_AGENT_INTERVALS;
}

export function silentAgentThresholdS(env: Env = process.env): number {
  return silentAgentIntervals(env) * HEARTBEAT_INTERVAL_S;
}

/**
 * Absolute console URL of `path` for notifications, from `DATABASTION_PUBLIC_URL` (origin only);
 * `null` when it is unset or invalid (the notification then carries ids only).
 */
export function consoleUrl(path: string, env: Env = process.env): string | null {
  const base = env.DATABASTION_PUBLIC_URL;
  if (!base) return null;
  try {
    const origin = new URL(base).origin;
    if (!origin.startsWith("https://") && !origin.startsWith("http://")) return null;
    return new URL(path, origin).toString();
  } catch {
    return null;
  }
}

/** Startup warnings (web and worker), never containing values. */
export function alertingWarnings(env: Env = process.env): string[] {
  const out: string[] = [];
  if (env.NODE_ENV === "production" && insecureDevAllowed(env)) {
    out.push(
      `${INSECURE_DEV_VAR}=1 in production: http:// webhooks, webhooks to private / loopback addresses and plain-text SMTP are allowed; use it for development only.`,
    );
  }
  const raw = env[SILENT_AGENT_INTERVALS_VAR];
  if (raw !== undefined && raw.trim() !== "" && silentAgentIntervals(env) === DEFAULT_SILENT_AGENT_INTERVALS && raw.trim() !== String(DEFAULT_SILENT_AGENT_INTERVALS)) {
    out.push(`${SILENT_AGENT_INTERVALS_VAR} must be an integer from 3 to 2880: the default (${DEFAULT_SILENT_AGENT_INTERVALS}) is used.`);
  }
  return out;
}
