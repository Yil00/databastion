import { isIP } from "node:net";

import { logger } from "@/lib/logger";

/**
 * Number of trusted reverse proxies in front of the console:
 * `DATABASTION_TRUSTED_PROXY_HOPS=N` (1..10), or `DATABASTION_TRUST_PROXY=1` (same as 1 hop).
 * 0 means no trusted proxy: `X-Forwarded-For` is ignored.
 */
export function trustedProxyHops(env: NodeJS.ProcessEnv = process.env): number {
  const hops = env.DATABASTION_TRUSTED_PROXY_HOPS;
  if (hops !== undefined && /^(10|[1-9])$/.test(hops)) return Number(hops);
  return env.DATABASTION_TRUST_PROXY === "1" ? 1 : 0;
}

/**
 * Source IP used for rate limiting, or `null` when unknown. Route handlers do not see the socket
 * address, so the console relies on its reverse proxies: with N trusted hops, the N-th
 * `X-Forwarded-For` entry from the right is the address seen by the outermost trusted proxy
 * (entries further left are client-controlled). Without a trusted proxy, the IP is unknown and
 * per-IP limits are NOT applied (a shared bucket would let anyone lock everyone out): per-user /
 * per-agent limits and the argon2 concurrency cap still apply.
 */
export function clientIp(req: Request, env: NodeJS.ProcessEnv = process.env): string | null {
  const hops = trustedProxyHops(env);
  if (hops === 0) return null;
  const entries = (req.headers.get("x-forwarded-for") ?? "").split(",").map((e) => e.trim());
  const entry = entries.length >= hops ? entries[entries.length - hops] : undefined;
  if (entry && isIP(entry)) return entry;
  warnBadForwardedFor();
  return null;
}

let lastXffWarning = 0;
export const xffWarningStats = { warned: 0 };

/** L-b: misconfigured proxy chain. At most one warning per minute; never logs the header value. */
function warnBadForwardedFor(): void {
  const now = Date.now();
  if (now - lastXffWarning < 60_000) return;
  lastXffWarning = now;
  xffWarningStats.warned++;
  logger.warn(
    "trusted proxy hops are configured but the selected X-Forwarded-For entry is missing or not an IP",
  );
}

/**
 * Rate-limit bucket of an IP: IPv6 addresses are aggregated by /64 (one host usually owns a whole
 * /64), or by /56 (`v6Prefix = 56`: logins, P1-D N1, where a customer allocation often is a /56),
 * IPv4-mapped IPv6 addresses are reduced to their IPv4 address.
 */
export function ipBucket(ip: string, v6Prefix: 48 | 56 | 64 = 64): string {
  if (isIP(ip) !== 6) return ip;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped?.[1]) return mapped[1];
  const parts = ip.toLowerCase().split("::");
  const head = parts[0] ?? "";
  const tail = ip.includes("::") ? (parts[1] ?? "") : "";
  const toGroups = (part: string) => (part === "" ? [] : part.split(":"));
  let headGroups = toGroups(head);
  let tailGroups = toGroups(tail);
  // An embedded IPv4 suffix only affects the last 32 bits: outside the /64 prefix.
  if (tailGroups.at(-1)?.includes(".")) tailGroups = [...tailGroups.slice(0, -1), "0", "0"];
  if (headGroups.at(-1)?.includes(".")) headGroups = [...headGroups.slice(0, -1), "0", "0"];
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = [...headGroups, ...Array<string>(Math.max(0, missing)).fill("0"), ...tailGroups];
  const prefix = groups.slice(0, 4).map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : 0));
  if (v6Prefix === 56) prefix[3] = (prefix[3] ?? 0) & 0xff00;
  if (v6Prefix === 48) prefix[3] = 0;
  return `${prefix.map((g) => g.toString(16)).join(":")}::/${v6Prefix}`;
}

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

export type BodyResult =
  | { ok: true; value: unknown }
  | {
      ok: false;
      reason: "too_large" | "invalid_json" | "unsupported_media_type";
      /** The read deadline expired (reported as `invalid_json`). */
      timedOut?: true;
    };

const JSON_CONTENT_TYPE = /^application\/json\s*(;\s*charset\s*=\s*"?utf-8"?\s*)?$/i;

export interface ReadBodyOptions {
  maxBytes?: number;
  /**
   * Wall-clock limit for reading the whole body (P1-D L1): past it, the stream is cancelled and the
   * body is `invalid_json` (a slow-loris sender never holds the request open indefinitely).
   * Unset: no deadline (the server timeouts apply).
   */
  deadlineMs?: number;
}

/** Default body read deadline of the agent API bodies read before authentication (`/rotate`). */
export const BODY_READ_DEADLINE_MS = 10_000;

/**
 * Reads a JSON body with a hard byte cap (the stream is cancelled as soon as the cap is exceeded,
 * whatever `Content-Length` says) and an optional read deadline. Never logs or returns any part of
 * the body on failure. `maxBytes` may be given directly (legacy form) or in the options.
 */
export async function readJsonBody(req: Request, opts: number | ReadBodyOptions = {}): Promise<BodyResult> {
  const { maxBytes = MAX_BODY_BYTES, deadlineMs } = typeof opts === "number" ? { maxBytes: opts } : opts;
  const contentType = req.headers.get("content-type") ?? "";
  if (!JSON_CONTENT_TYPE.test(contentType.trim())) {
    return { ok: false, reason: "unsupported_media_type" };
  }
  const declared = req.headers.get("content-length");
  if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > maxBytes) {
    return { ok: false, reason: "too_large" };
  }
  if (!req.body) return { ok: false, reason: "invalid_json" };
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired =
    deadlineMs === undefined
      ? null
      : new Promise<"expired">((resolve) => {
          timer = setTimeout(() => resolve("expired"), deadlineMs);
        });
  try {
    for (;;) {
      const next = expired ? await Promise.race([reader.read(), expired]) : await reader.read();
      if (next === "expired") {
        await reader.cancel().catch(() => undefined);
        return { ok: false, reason: "invalid_json", timedOut: true };
      }
      const { done, value } = next;
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, reason: "too_large" };
      }
      chunks.push(value);
    }
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    return { ok: false, reason: "invalid_json" };
  }
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, reason: "invalid_json" };
  }
}
