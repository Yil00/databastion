import { serverSubkey } from "./crypto";
import { trustedProxyHops } from "./request";

/**
 * Configuration warnings logged once when the web process starts (src/instrumentation.ts).
 * Warnings only: they never contain configuration values.
 */
export function startupWarnings(env: NodeJS.ProcessEnv = process.env): string[] {
  const warnings: string[] = [];
  const production = env.NODE_ENV === "production";
  if (production && trustedProxyHops(env) === 0) {
    warnings.push(
      "No trusted reverse proxy (DATABASTION_TRUST_PROXY / DATABASTION_TRUSTED_PROXY_HOPS): client IPs are unknown and per-IP rate limits are disabled.",
    );
  }
  if (production && env.DATABASTION_INSECURE_COOKIES === "1") {
    warnings.push(
      "DATABASTION_INSECURE_COOKIES=1 in production: session cookies are sent without Secure; use it only for plain-HTTP test setups.",
    );
  }
  if (production && !env.DATABASTION_METRICS_PORT && (env.DATABASTION_METRICS_TOKEN || env.DATABASTION_METRICS_TOKEN_FILE)) {
    warnings.push(
      "/metrics is served on the main port: set DATABASTION_METRICS_PORT to move it to a dedicated listener, or block /metrics at the reverse proxy.",
    );
  }
  return warnings;
}

/**
 * Configuration errors logged once (level `error`) when the web process starts in production (P1-D
 * N3). The process still starts (no required-configuration fail-fast exists yet), but the log says
 * exactly which protections are off. Never contains configuration values.
 */
export function startupErrors(env: NodeJS.ProcessEnv = process.env): string[] {
  const errors: string[] = [];
  if (env.NODE_ENV !== "production") return errors;
  if (serverSubkey("startup-check.v1", env) === null) {
    errors.push(
      "DATABASTION_ENCRYPTION_KEY(_FILE) unset, shorter than 32 characters or unreadable: PROTECTIONS DISABLED: " +
        "(1) agent known-good fingerprints: agents behind a shared (NAT / proxy) IP can be locked out by failure floods from that IP, " +
        "and any agent loses its lock-out exemption after 25 s; " +
        "(2) login device cookies: a distributed password-guessing attack on a username can keep its real user out. " +
        "Set DATABASTION_ENCRYPTION_KEY_FILE (e.g. openssl rand -base64 32).",
    );
  }
  return errors;
}
