import { and, eq, isNotNull, lt, or, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { sessions, userIdentities, users } from "@/db/schema";
import { errorSummary, logger } from "@/lib/logger";
import { writeAudit } from "@/server/audit";
import { deleteSession, OIDC_REFRESH_INTERVAL_MS, revokeOtherSessions, type Session } from "@/server/auth/session";

import { mapClaims } from "./claims";
import { refreshTokens, withUserinfo } from "./client";
import { oidcProvider } from "./runtime";
import { decryptRefreshToken, encryptRefreshToken } from "./tokens";

/**
 * Token refresh of an OIDC session (ADR-0038 decisions 9 and 13), on user activity, at most every
 * 5 minutes: one process claims the refresh with a conditional update. A failed refresh (provider
 * refusal, invalid `id_token`, filters no longer passed) ends the session. The mapped role is
 * applied again when the provider returns claims (a refreshed `id_token`, or userinfo).
 * A provider that is merely unreachable also ends the session: the console cannot tell a disabled
 * user from an outage, and fails closed.
 */
export async function refreshOidcSession(db: Database, session: Session): Promise<Session | null> {
  const provider = oidcProvider();
  const cutoff = new Date(Date.now() - OIDC_REFRESH_INTERVAL_MS);
  const claimed = await db
    .update(sessions)
    .set({ refreshedAt: sql`now()` })
    .where(
      and(
        eq(sessions.tokenHash, session.tokenHash),
        isNotNull(sessions.refreshTokenEnc),
        or(isNull(sessions.refreshedAt), lt(sessions.refreshedAt, cutoff)),
      ),
    )
    .returning({ enc: sessions.refreshTokenEnc, identityId: sessions.identityId });
  const row = claimed[0];
  // Another request (or process) is refreshing it: keep the session meanwhile.
  if (!row) return session;
  const end = async (reason: string) => {
    await deleteSession(db, session.tokenHash);
    await writeAudit(db, {
      actorType: "system",
      action: "user.logout",
      targetType: "user",
      targetId: session.user.id,
      details: { method: "oidc", reason },
    });
    return null;
  };
  if (provider === null || row.enc === null || row.identityId === null) return end("refresh_unavailable");
  const refreshToken = decryptRefreshToken(row.enc, session.tokenHash);
  if (refreshToken === null) return end("refresh_unavailable");
  const [ident] = await db.select({ subject: userIdentities.subject }).from(userIdentities).where(eq(userIdentities.id, row.identityId));
  if (!ident) return end("refresh_unavailable");
  try {
    const md = await provider.getMetadata();
    const { tokens, claims } = await refreshTokens(provider, md, refreshToken, ident.subject);
    const merged = claims !== null ? await withUserinfo(provider, md, claims, tokens.accessToken) : null;
    let role = session.user.role;
    if (merged !== null) {
      const mapping = mapClaims(merged, provider.config);
      if (!mapping.ok) return end(`refresh_${mapping.reason}`);
      if (!provider.config.skipRoleSync && mapping.effectiveRole !== role) {
        const from = role;
        role = mapping.effectiveRole;
        await db.transaction(async (tx) => {
          await tx.update(users).set({ role }).where(eq(users.id, session.user.id));
          await writeAudit(tx, {
            actorType: "system",
            action: "user.role_change",
            targetType: "user",
            targetId: session.user.id,
            details: { source: "oidc", from, to: role },
          });
          if (from === "admin") await revokeOtherSessions(tx, session.user.id, session.tokenHash);
        });
      }
    }
    if (tokens.refreshToken !== null && tokens.refreshToken !== refreshToken) {
      await db
        .update(sessions)
        .set({ refreshTokenEnc: encryptRefreshToken(tokens.refreshToken, session.tokenHash) })
        .where(eq(sessions.tokenHash, session.tokenHash));
    }
    return { ...session, user: { ...session.user, role } };
  } catch (err) {
    logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC token refresh failed: session ended");
    return end("refresh_failed");
  }
}
