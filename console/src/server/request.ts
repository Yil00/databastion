import { isIP } from "node:net";

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
  return entry && isIP(entry) ? entry : null;
}

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

export type BodyResult =
  | { ok: true; value: unknown }
  | { ok: false; reason: "too_large" | "invalid_json" | "unsupported_media_type" };

const JSON_CONTENT_TYPE = /^application\/json\s*(;\s*charset\s*=\s*"?utf-8"?\s*)?$/i;

/**
 * Reads a JSON body with a hard byte cap (the stream is cancelled as soon as the cap is exceeded,
 * whatever `Content-Length` says). Never logs or returns any part of the body on failure.
 */
export async function readJsonBody(req: Request, maxBytes = MAX_BODY_BYTES): Promise<BodyResult> {
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
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
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
