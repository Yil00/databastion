import { errorSummary, logger } from "@/lib/logger";
import { processGlobal } from "@/server/process-global";

import { loadOidcConfig, localLoginMode, type LocalLoginMode, type OidcConfig } from "./config";
import { OidcProvider } from "./provider";

/**
 * The process-wide OIDC provider (one per console, ADR-0038), built once from the environment.
 * Process-wide through `processGlobal` (#63): every bundled copy of this module shares it.
 * `null` when OIDC is off, or misconfigured (the startup check then stopped the process; a test or
 * a tool that skipped it sees OIDC as unavailable, never a partial configuration).
 */
interface OidcState {
  provider: OidcProvider | null;
  built: boolean;
}

const state = processGlobal<OidcState>("oidc.provider", () => ({ provider: null, built: false }));

export function oidcProvider(): OidcProvider | null {
  if (!state.built) {
    state.built = true;
    let cfg: OidcConfig | null = null;
    try {
      cfg = loadOidcConfig();
    } catch (err) {
      logger.error({ component: "oidc", error: errorSummary(err) }, "OIDC configuration error: single sign-on disabled");
    }
    state.provider = cfg ? new OidcProvider(cfg) : null;
  }
  return state.provider;
}

/** Test hook: replaces (or resets with `undefined`) the process-wide provider. */
export function setOidcProviderForTests(p: OidcProvider | null | undefined): void {
  state.built = p !== undefined;
  state.provider = p ?? null;
}

/** The local login mode; a malformed value (refused at startup) falls back to `disabled`. */
export function currentLocalLoginMode(): LocalLoginMode {
  try {
    return localLoginMode();
  } catch {
    return "disabled";
  }
}

/**
 * Startup (web process): discovers the provider so its hosts are logged, and keeps retrying with
 * backoff while it is unreachable (the console runs meanwhile; the local login keeps working).
 */
export function warmUpOidcProvider(): void {
  const p = oidcProvider();
  if (p === null) return;
  let delayMs = 5_000;
  const attempt = () => {
    p.getMetadata().catch(() => {
      delayMs = Math.min(delayMs * 2, 300_000);
      setTimeout(attempt, delayMs).unref();
    });
  };
  attempt();
}
