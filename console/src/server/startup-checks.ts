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
