import { createHmac, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

import { pinnedLookup, resolveOutbound, type Resolver } from "../net-guard";
import type { SendResult } from "./types";

/**
 * Webhook sender (P3-C, worker only).
 *
 * - `POST` of the JSON body; headers `X-DataBastion-Event`, `X-DataBastion-Delivery` (the delivery
 *   id: stable across retries, for idempotency on the receiver side) and
 *   `X-DataBastion-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`, the
 *   key being the UTF-8 bytes of the `whsec_…` signing secret. `t` is the time of the attempt:
 *   receivers reject signatures older than a few minutes (replay protection) and compare in
 *   constant time (see `verifyWebhookSignature`).
 * - SSRF defense: the host is resolved and every address checked (`net-guard.ts`); the socket
 *   connects to the vetted address only (no second resolution). Internal addresses need
 *   `DATABASTION_ALERTING_INSECURE_DEV=1`; link-local / metadata ones are always refused.
 * - Redirects are never followed (a 3xx is a permanent failure). Timeouts: 5 s to connect, 15 s in
 *   total. The response body is read up to 64 KiB and discarded. No proxy (direct egress).
 * - Outcome: 2xx delivered; 408, 425, 429, 5xx, network and TLS errors retried; other 4xx failed.
 *   Errors are closed codes, never the response text.
 */

export const WEBHOOK_CONNECT_TIMEOUT_MS = 5_000;
export const WEBHOOK_TOTAL_TIMEOUT_MS = 15_000;
export const WEBHOOK_MAX_RESPONSE_BYTES = 64 * 1024;
export const SIGNATURE_HEADER = "X-DataBastion-Signature";
export const SIGNATURE_TOLERANCE_S = 300;

export function webhookSignature(secret: string, t: number, body: string): string {
  const mac = createHmac("sha256", Buffer.from(secret, "utf8")).update(`${t}.${body}`, "utf8").digest("hex");
  return `t=${t},v1=${mac}`;
}

/**
 * Reference verification for receivers (and the tests): the header parses, `t` is within
 * `toleranceS` of `nowS`, and one `v1` value matches in constant time.
 */
export function verifyWebhookSignature(
  secret: string,
  header: string | null | undefined,
  body: string,
  opts: { nowS?: number; toleranceS?: number } = {},
): boolean {
  if (!header || header.length > 1024) return false;
  let t: number | null = null;
  const macs: string[] = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=", 2);
    if (k === "t" && v && /^\d{1,12}$/.test(v)) t = Number(v);
    else if (k === "v1" && v && /^[0-9a-f]{64}$/.test(v)) macs.push(v);
  }
  if (t === null || macs.length === 0) return false;
  const now = opts.nowS ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - t) > (opts.toleranceS ?? SIGNATURE_TOLERANCE_S)) return false;
  const expected = Buffer.from(createHmac("sha256", Buffer.from(secret, "utf8")).update(`${t}.${body}`, "utf8").digest("hex"));
  return macs.some((m) => {
    const b = Buffer.from(m);
    return b.length === expected.length && timingSafeEqual(b, expected);
  });
}

export interface WebhookMessage {
  deliveryId: string;
  event: string;
  body: string;
}

export interface WebhookOptions {
  allowInternal: boolean;
  allowHttp: boolean;
  resolver?: Resolver;
  /** Extra trusted CA (tests only). */
  ca?: string | Buffer;
  nowS?: () => number;
  connectTimeoutMs?: number;
  totalTimeoutMs?: number;
}

const TLS_CODE = /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|HOSTNAME_MISMATCH|ERR_OSSL_)/;

function classifyError(err: unknown): SendResult {
  const code = String((err as { code?: unknown } | null)?.code ?? "");
  if (TLS_CODE.test(code)) return { ok: false, code: "tls_failed", retryable: true };
  return { ok: false, code: "connect_failed", retryable: true };
}

export function statusOutcome(status: number): SendResult {
  if (status >= 200 && status < 300) return { ok: true };
  if (status >= 300 && status < 400) return { ok: false, code: "redirect_refused", retryable: false };
  const retryable = status === 408 || status === 425 || status === 429 || status >= 500;
  return { ok: false, code: `http_${status}`, retryable };
}

export async function sendWebhook(urlText: string, signingSecret: string, msg: WebhookMessage, opts: WebhookOptions): Promise<SendResult> {
  let url: URL;
  try {
    url = new URL(urlText);
  } catch {
    return { ok: false, code: "internal", retryable: false };
  }
  const isHttps = url.protocol === "https:";
  if (!isHttps && !(url.protocol === "http:" && opts.allowHttp)) return { ok: false, code: "insecure_refused", retryable: false };
  const resolved = await resolveOutbound(url.hostname, { allowInternal: opts.allowInternal, resolver: opts.resolver });
  if (!resolved.ok) return { ok: false, code: resolved.code, retryable: resolved.retryable };

  const t = opts.nowS ? opts.nowS() : Math.floor(Date.now() / 1000);
  const headers = {
    "Content-Type": "application/json",
    "Content-Length": String(Buffer.byteLength(msg.body, "utf8")),
    "User-Agent": "DataBastion-Console",
    "X-DataBastion-Event": msg.event,
    "X-DataBastion-Delivery": msg.deliveryId,
    [SIGNATURE_HEADER]: webhookSignature(signingSecret, t, msg.body),
  };
  const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
  const options: https.RequestOptions = {
    method: "POST",
    host,
    port: url.port === "" ? (isHttps ? 443 : 80) : Number(url.port),
    path: `${url.pathname}${url.search}`,
    headers,
    agent: false,
    // Only the checked addresses, tried in order (a refused / unreachable one falls back to the
    // next within the connect budget).
    lookup: pinnedLookup(resolved.addresses) as unknown as https.RequestOptions["lookup"],
    // Passed through to net.connect (not in the http RequestOptions typings).
    ...({ autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 1_000 } as object),
    // `ca` (tests only) replaces the default roots for this request.
    // SNI and certificate checks use the host name (never an IP literal as SNI).
    ...(isHttps ? { ...(isIP(host) === 0 ? { servername: host } : {}), ...(opts.ca ? { ca: opts.ca } : {}) } : {}),
  };

  return new Promise<SendResult>((resolve) => {
    let done = false;
    const finish = (r: SendResult) => {
      if (done) return;
      done = true;
      clearTimeout(total);
      clearTimeout(connect);
      resolve(r);
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      clearTimeout(connect);
      const outcome = statusOutcome(res.statusCode ?? 0);
      let received = 0;
      res.on("data", (chunk: Buffer) => {
        received += chunk.length;
        // Size cap: stop reading; the status line already decided the outcome.
        if (received > WEBHOOK_MAX_RESPONSE_BYTES) {
          finish(outcome);
          res.destroy();
          req.destroy();
        }
      });
      res.on("end", () => finish(outcome));
      res.on("error", () => finish(outcome));
      res.on("close", () => finish(outcome));
    });
    const connect = setTimeout(() => {
      finish({ ok: false, code: "connect_timeout", retryable: true });
      req.destroy();
    }, opts.connectTimeoutMs ?? WEBHOOK_CONNECT_TIMEOUT_MS);
    const total = setTimeout(() => {
      finish({ ok: false, code: "timeout", retryable: true });
      req.destroy();
    }, opts.totalTimeoutMs ?? WEBHOOK_TOTAL_TIMEOUT_MS);
    req.on("socket", (socket) => {
      socket.once(isHttps ? "secureConnect" : "connect", () => clearTimeout(connect));
    });
    req.on("error", (err) => finish(classifyError(err)));
    req.end(msg.body);
  });
}
