import { isIP } from "node:net";

/**
 * Source IP used for rate limiting. Route handlers do not see the socket address, so the console
 * relies on its reverse proxy: with `DATABASTION_TRUST_PROXY=1`, the last `X-Forwarded-For` entry
 * (the one appended by the proxy) is used. Without it, every request shares the `direct` bucket
 * (spoofable headers are never trusted by default).
 */
export function clientIp(req: Request, env: NodeJS.ProcessEnv = process.env): string {
  if (env.DATABASTION_TRUST_PROXY === "1") {
    const xff = req.headers.get("x-forwarded-for");
    const last = xff?.split(",").at(-1)?.trim();
    if (last && isIP(last)) return last;
  }
  return "direct";
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
