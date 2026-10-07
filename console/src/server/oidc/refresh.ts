import { and, eq, isNotNull, lt, or, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { sessions, userIdentities } from "@/db/schema";
import { errorSummary, logger } from "@/lib/logger";
import { writeAudit } from "@/server/audit";
import { deleteSession, OIDC_REFRESH_INTERVAL_MS, type Session } from "@/server/auth/session";

import { mapClaims } from "./claims";
import { fetchUserinfo, refreshTokens, withUserinfo } from "./client";
import { revokeRefreshTokensInBackground, type EndedSessionRow } from "./revoke";
import { syncRole } from "./service";
import { oidcProvider } from "./runtime";
import { decryptRefreshToken, encryptRefreshToken } from "./tokens";

/**
 * Token refresh of an OIDC session (ADR-0038 decisions 9 and 13), on user activity, at most every
 * 5 minutes: one process claims the refresh with a conditional update. A failed refresh (provider
 * refusal, invalid `id_token`, filters no longer passed) ends the session. The filters and the
 * mapped role are checked again when the provider returns claims: a refreshed `id_token` (merged
 * with userinfo when `DATABASTION_OIDC_USE_USERINFO=1`), or, when the refresh response has no
 * `id_token`, userinfo alone with `DATABASTION_OIDC_USE_USERINFO=1` (end-of-phase-8 review L2; its
 * `sub` must be the session identity's, else the session ends). With neither, the refresh only
 * proves the provider still honors the refresh token: role and filters are not re-checked.
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
  // A refresh token rotated by this refresh but not stored yet: when the session ends before it is
  // stored, it is revoked too (best effort, the same background path as the stored one).
  let rotated: string | null = null;
  const revokeRotated = () => {
    if (rotated !== null) revokeRefreshTokensInBackground([{ h: session.tokenHash, enc: encryptRefreshToken(rotated, session.tokenHash) }]);
  };
  const endRotated = (reason: string) => {
    revokeRotated();
    return end(reason);
  };
  try {
    const md = await provider.getMetadata();
    const { tokens, claims } = await refreshTokens(provider, md, refreshToken, ident.subject);
    if (tokens.refreshToken !== null && tokens.refreshToken !== refreshToken) rotated = tokens.refreshToken;
    let merged: Record<string, unknown> | null = null;
    if (claims !== null) merged = await withUserinfo(provider, md, claims, tokens.accessToken);
    else if (provider.config.useUserinfo) {
      const info = await fetchUserinfo(provider, md, tokens.accessToken);
      // Bound to the session's identity: another subject's claims never apply to it.
      if (typeof info.sub !== "string" || info.sub !== ident.subject) return endRotated("refresh_subject");
      merged = info;
    }
    let role = session.user.role;
    if (merged !== null) {
      const mapping = mapClaims(merged, provider.config);
      if (!mapping.ok) return endRotated(`refresh_${mapping.reason}`);
      if (!provider.config.skipRoleSync && mapping.effectiveRole !== role) {
        const from = role;
        const ended: EndedSessionRow[] = [];
        role = await db.transaction((tx) => syncRole(tx, session.user.id, from, mapping.effectiveRole, { ip: null, keepTokenHash: session.tokenHash, ended }));
        revokeRefreshTokensInBackground(ended);
      }
    }
    if (rotated !== null) {
      await db
        .update(sessions)
        .set({ refreshTokenEnc: encryptRefreshToken(rotated, session.tokenHash) })
        .where(eq(sessions.tokenHash, session.tokenHash));
      rotated = null;
    }
    return { ...session, user: { ...session.user, role } };
  } catch (err) {
    logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC token refresh failed: session ended");
    return endRotated("refresh_failed");
  }
}
