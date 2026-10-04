import { errorSummary, logger } from "@/lib/logger";
import { processGlobal } from "@/server/process-global";

import { decryptRefreshToken } from "./tokens";

/**
 * Best-effort RFC 7009 revocation of the refresh tokens of sessions that end other than by logout
 * (security review L5): disabled users, demotions, unlinked identities, expired or idle sessions
 * purged, failed refreshes. Runs in the background after the rows are deleted: the local action
 * never waits for, nor depends on, the provider. At most {@link MAX_REVOCATIONS_PER_CALL} tokens per
 * call, two attempts each. Tokens are never logged.
 */
export const MAX_REVOCATIONS_PER_CALL = 100;
/** Background revocation jobs per process; beyond, new ones are skipped (logged), never queued. */
export const MAX_CONCURRENT_REVOCATION_JOBS = 8;

const pending = processGlobal("oidc.pendingRevocations", () => new Set<Promise<void>>());

export interface EndedSessionRow {
  h: string;
  enc: Buffer | null;
}

export function revokeRefreshTokensInBackground(rows: readonly EndedSessionRow[]): void {
  const held = rows.filter((r): r is { h: string; enc: Buffer } => r.enc !== null);
  if (held.length === 0) return;
  const tokens = held
    .slice(0, MAX_REVOCATIONS_PER_CALL)
    .map((r) => decryptRefreshToken(r.enc, r.h))
    .filter((t): t is string => t !== null);
  if (tokens.length === 0) return;
  if (pending.size >= MAX_CONCURRENT_REVOCATION_JOBS) {
    logger.warn({ component: "oidc", skipped: tokens.length }, "OIDC refresh token revocation skipped: too many revocations in progress (best effort)");
    return;
  }
  const job = (async () => {
    try {
      // Imported lazily: auth/session.ts imports this module (no static import cycle).
      const { oidcProvider } = await import("./runtime");
      const { revokeRefreshToken } = await import("./client");
      const provider = oidcProvider();
      if (provider === null) return;
      const md = await provider.getMetadata();
      if (md.revocationEndpoint === null) return;
      let failed = 0;
      for (const t of tokens) {
        if (!(await revokeRefreshToken(provider, md, t)) && !(await revokeRefreshToken(provider, md, t))) failed++;
      }
      if (failed > 0) logger.warn({ component: "oidc", failed, total: tokens.length }, "OIDC refresh token revocation failed (best effort)");
    } catch (err) {
      logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC refresh token revocation skipped (provider unavailable)");
    }
  })();
  pending.add(job);
  void job.finally(() => pending.delete(job));
}

/** Test hook: waits for the background revocations started so far. */
export async function settleRevocationsForTests(): Promise<void> {
  await Promise.all([...pending]);
}
