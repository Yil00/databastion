import { randomBytes } from "node:crypto";

import { hmacSha256Hex, safeEqual, serverSubkey } from "@/server/crypto";

import { secureCookies } from "./session";

/**
 * Login "device cookies" (OWASP, "Slow Down Online Guessing Attacks with Device Cookies"; P1-D N1).
 * A browser that logged in successfully as a user gets a long-lived cookie proving it. A login
 * presenting a valid device cookie for the username it tries skips the global per-username cap and
 * its degraded single slot, so a distributed guessing attack on that username cannot keep the real
 * user out. It stays subject to its own (username, IP) limit, a per-cookie failure limit and the
 * argon2id pool. The cookie never authenticates by itself: the password is always verified.
 *
 * Value: `v1.<user id>.<issued at, epoch s>.<nonce>.<mac>`, where `mac` is an HMAC-SHA256 (hex)
 * over the first four fields, keyed by the HKDF subkey `login-device.v1` of the console server key
 * (`DATABASTION_ENCRYPTION_KEY`). Nothing is stored server side. Without the key, no cookie is
 * issued and none is accepted (fail closed: logins then only have the regular limits).
 */
export const DEVICE_COOKIE_DOMAIN = "login-device.v1";
export const DEVICE_COOKIE_TTL_S = 90 * 24 * 60 * 60;

const VALUE = /^v1\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(\d{1,12})\.([A-Za-z0-9_-]{22})\.([0-9a-f]{64})$/;

export interface DeviceCookie {
  userId: string;
  /** Random per-cookie identifier (key of the per-cookie failure limit). */
  nonce: string;
}

export function deviceCookieName(env: NodeJS.ProcessEnv = process.env): string {
  return secureCookies(env) ? "__Host-databastion_device" : "databastion_device";
}

function mac(key: Buffer, userId: string, issuedAtS: string, nonce: string): string {
  return hmacSha256Hex(key, `v1\0${userId}\0${issuedAtS}\0${nonce}`);
}

/** `Set-Cookie` value of a fresh device cookie for `userId`, or null when the server key is unavailable. */
export function issueDeviceCookie(userId: string, env: NodeJS.ProcessEnv = process.env, now = Date.now()): string | null {
  const key = serverSubkey(DEVICE_COOKIE_DOMAIN, env);
  if (key === null) return null;
  const issuedAtS = String(Math.floor(now / 1000));
  const nonce = randomBytes(16).toString("base64url");
  const value = `v1.${userId}.${issuedAtS}.${nonce}.${mac(key, userId, issuedAtS, nonce)}`;
  const parts = [`${deviceCookieName(env)}=${value}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${DEVICE_COOKIE_TTL_S}`];
  if (secureCookies(env)) parts.push("Secure");
  return parts.join("; ");
}

/** The valid (signature, not expired) device cookie of the request, or null. */
export function readDeviceCookie(req: Request, env: NodeJS.ProcessEnv = process.env, now = Date.now()): DeviceCookie | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  const name = deviceCookieName(env);
  let value: string | undefined;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      value = v.join("=");
      break;
    }
  }
  const m = value === undefined ? null : VALUE.exec(value);
  if (!m) return null;
  const [, userId = "", issuedAtS = "", nonce = "", presented = ""] = m;
  const age = now / 1000 - Number(issuedAtS);
  if (age < -300 || age >= DEVICE_COOKIE_TTL_S) return null;
  const key = serverSubkey(DEVICE_COOKIE_DOMAIN, env);
  if (key === null || !safeEqual(presented, mac(key, userId, issuedAtS, nonce))) return null;
  return { userId, nonce };
}
