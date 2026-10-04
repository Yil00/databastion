import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

import { lte, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { oidcConsumedStates } from "@/db/schema";
import type { Env } from "@/config/env";
import { serverSubkey } from "@/server/crypto";
import { secureCookies } from "@/server/auth/session";

/**
 * OIDC flow state (ADR-0038 decision 5): a 256-bit `state`, a 256-bit `nonce` and the PKCE verifier,
 * kept in a cookie encrypted with AES-256-GCM under the HKDF subkey `oidc-state.v1`: `__Host-`
 * prefixed, `HttpOnly`, `Secure` (production), `SameSite=Lax` (the callback is a cross-site
 * top-level navigation from the provider), 10-minute lifetime. Single use is enforced server side
 * by {@link consumeState}. Nothing here logs its input.
 */

export const STATE_DOMAIN = "oidc-state.v1";
export const STATE_TTL_S = 600;
const FORMAT = 0x01;
const AAD = Buffer.from("databastion.oidc-state.v1", "utf8");

export type FlowPurpose = "login" | "link";

export interface FlowState {
  state: string;
  nonce: string;
  verifier: string;
  purpose: FlowPurpose;
  /** `link` only: the user and the SHA-256 of the local session that started the link. */
  linkUserId?: string;
  linkSessionHash?: string;
  /** Issue time, epoch seconds. */
  iat: number;
}

export function stateCookieName(env: Env = process.env): string {
  return secureCookies(env as NodeJS.ProcessEnv) ? "__Host-databastion_oidc" : "databastion_oidc";
}

const b64 = (n: number) => randomBytes(n).toString("base64url");

export function newFlowState(purpose: FlowPurpose, link?: { userId: string; sessionHash: string }, now = Date.now()): FlowState {
  return {
    state: b64(32),
    nonce: b64(32),
    // RFC 7636: 43 to 128 characters of [A-Za-z0-9-._~]; 32 random bytes in base64url give 43.
    verifier: b64(32),
    purpose,
    ...(link ? { linkUserId: link.userId, linkSessionHash: link.sessionHash } : {}),
    iat: Math.floor(now / 1000),
  };
}

export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

function key(env: Env): Buffer {
  const k = serverSubkey(STATE_DOMAIN, env);
  // OIDC refuses to start without the key (config.ts): reaching this is a programming error.
  if (k === null) throw new Error("OIDC state key unavailable");
  return k;
}

export function sealState(s: FlowState, env: Env = process.env): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(env), nonce, { authTagLength: 16 });
  cipher.setAAD(AAD);
  const body = Buffer.concat([cipher.update(JSON.stringify(s), "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from([FORMAT]), nonce, body, cipher.getAuthTag()]).toString("base64url");
}

const FIELD = /^[A-Za-z0-9_-]{43}$/;

/** The state of a sealed cookie value, or `null` (tampered, wrong key, malformed or expired). */
export function openState(value: string, env: Env = process.env, now = Date.now()): FlowState | null {
  if (value.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const blob = Buffer.from(value, "base64url");
  if (blob.length < 1 + 12 + 16 || blob[0] !== FORMAT) return null;
  let s: FlowState;
  try {
    const d = createDecipheriv("aes-256-gcm", key(env), blob.subarray(1, 13), { authTagLength: 16 });
    d.setAAD(AAD);
    d.setAuthTag(blob.subarray(blob.length - 16));
    s = JSON.parse(Buffer.concat([d.update(blob.subarray(13, blob.length - 16)), d.final()]).toString("utf8")) as FlowState;
  } catch {
    return null;
  }
  if (!FIELD.test(s.state) || !FIELD.test(s.nonce) || !FIELD.test(s.verifier) || (s.purpose !== "login" && s.purpose !== "link")) return null;
  if (typeof s.iat !== "number") return null;
  const age = now / 1000 - s.iat;
  if (age < -60 || age >= STATE_TTL_S) return null;
  return s;
}

export function stateCookie(value: string, env: Env = process.env): string {
  const parts = [`${stateCookieName(env)}=${value}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${STATE_TTL_S}`];
  if (secureCookies(env as NodeJS.ProcessEnv)) parts.push("Secure");
  return parts.join("; ");
}

export function clearStateCookie(env: Env = process.env): string {
  const parts = [`${stateCookieName(env)}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (secureCookies(env as NodeJS.ProcessEnv)) parts.push("Secure");
  return parts.join("; ");
}

export function readStateCookie(req: Request, env: Env = process.env): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  const name = stateCookieName(env);
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

/**
 * Records the state as consumed (its SHA-256, kept until the cookie's expiry). Returns `false`
 * when it was consumed already (a replayed callback). One statement: concurrent callbacks with the
 * same state cannot both succeed.
 */
export async function consumeState(db: Database, s: FlowState): Promise<boolean> {
  const stateHash = createHash("sha256").update(`oidc-state\0${s.state}`, "utf8").digest("hex");
  const expiresAt = new Date((s.iat + STATE_TTL_S + 60) * 1000);
  const rows = await db
    .insert(oidcConsumedStates)
    .values({ stateHash, expiresAt })
    .onConflictDoNothing()
    .returning({ h: oidcConsumedStates.stateHash });
  return rows.length === 1;
}

/** Deletes expired consumed-state records (run on callbacks, bounded). */
export async function pruneConsumedStates(db: Database): Promise<void> {
  await db.delete(oidcConsumedStates).where(lte(oidcConsumedStates.expiresAt, sql`now()`));
}
