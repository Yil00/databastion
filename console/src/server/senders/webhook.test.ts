import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { selfSignedCert } from "@/test/tls";

import { sendWebhook, statusOutcome, verifyWebhookSignature, webhookSignature } from "./webhook";

const SECRET = "whsec_test-signing-secret-0123456789abcdefghijk";
const MSG = { deliveryId: "01890a5d-ac96-774b-bcce-b302099a8057", event: "incident.opened", body: '{"version":1,"event":"incident.opened"}' };

interface Received {
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

/** Local test receiver: records every request; the per-path handler decides the answer. */
function receiver(tlsCert: { key: string; cert: string } | null) {
  const received: Received[] = [];
  const handlers = new Map<string, Handler>();
  const onRequest = (req: http.IncomingMessage, res: http.ServerResponse) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (body += c));
    req.on("end", () => {
      received.push({ path: req.url ?? "", headers: req.headers, body });
      const h = handlers.get(req.url ?? "") ?? ((_q, r) => r.writeHead(204).end());
      h(req, res);
    });
  };
  const server = tlsCert ? https.createServer(tlsCert, onRequest) : http.createServer(onRequest);
  return {
    received,
    handlers,
    server,
    async start(): Promise<number> {
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      return (server.address() as AddressInfo).port;
    },
    stop: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

describe("webhook signature", () => {
  it("t=<unix>,v1=<hex HMAC-SHA256 of t.body>; verification checks the MAC and the age", () => {
    const header = webhookSignature(SECRET, 1_790_000_000, MSG.body);
    expect(header).toMatch(/^t=1790000000,v1=[0-9a-f]{64}$/);
    expect(verifyWebhookSignature(SECRET, header, MSG.body, { nowS: 1_790_000_100 })).toBe(true);
    // Replay: older than the tolerance (5 min).
    expect(verifyWebhookSignature(SECRET, header, MSG.body, { nowS: 1_790_000_301 })).toBe(false);
    // Tampered body, other secret, malformed header.
    expect(verifyWebhookSignature(SECRET, header, `${MSG.body} `, { nowS: 1_790_000_000 })).toBe(false);
    expect(verifyWebhookSignature(`${SECRET}x`, header, MSG.body, { nowS: 1_790_000_000 })).toBe(false);
    expect(verifyWebhookSignature(SECRET, "v1=abc", MSG.body)).toBe(false);
    // The timestamp is bound: moving it breaks the MAC.
    const moved = header.replace("t=1790000000", "t=1790000200");
    expect(verifyWebhookSignature(SECRET, moved, MSG.body, { nowS: 1_790_000_200 })).toBe(false);
  });

  it("maps statuses: 2xx ok, 3xx refused, 408/425/429/5xx retried, other 4xx failed", () => {
    expect(statusOutcome(200)).toEqual({ ok: true });
    expect(statusOutcome(302)).toEqual({ ok: false, code: "redirect_refused", retryable: false });
    expect(statusOutcome(429)).toEqual({ ok: false, code: "http_429", retryable: true });
    expect(statusOutcome(503)).toEqual({ ok: false, code: "http_503", retryable: true });
    expect(statusOutcome(404)).toEqual({ ok: false, code: "http_404", retryable: false });
  });
});

describe("webhook sender over HTTP (dev flag: internal address allowed)", () => {
  const r = receiver(null);
  let base = "";
  beforeAll(async () => {
    base = `http://127.0.0.1:${await r.start()}`;
  });
  afterAll(() => r.stop());
  const dev = { allowInternal: true, allowHttp: true };

  it("posts the body with event, delivery id and a valid signature", async () => {
    const before = Math.floor(Date.now() / 1000);
    expect(await sendWebhook(`${base}/hook?x=1`, SECRET, MSG, dev)).toEqual({ ok: true });
    const got = r.received.at(-1);
    expect(got?.path).toBe("/hook?x=1");
    expect(got?.body).toBe(MSG.body);
    expect(got?.headers["content-type"]).toBe("application/json");
    expect(got?.headers["x-databastion-event"]).toBe("incident.opened");
    expect(got?.headers["x-databastion-delivery"]).toBe(MSG.deliveryId);
    const sig = String(got?.headers["x-databastion-signature"]);
    expect(verifyWebhookSignature(SECRET, sig, got?.body ?? "")).toBe(true);
    expect(Number(/t=(\d+)/.exec(sig)?.[1])).toBeGreaterThanOrEqual(before);
  });

  it("never follows a redirect", async () => {
    r.handlers.set("/redirect", (_q, res) => res.writeHead(307, { Location: `${base}/target` }).end());
    const n = r.received.length;
    expect(await sendWebhook(`${base}/redirect`, SECRET, MSG, dev)).toEqual({ ok: false, code: "redirect_refused", retryable: false });
    expect(r.received.slice(n).map((x) => x.path)).toEqual(["/redirect"]);
  });

  it("reports HTTP failures by status only (retryable or not)", async () => {
    r.handlers.set("/down", (_q, res) => res.writeHead(503).end("upstream says: secret-looking text"));
    r.handlers.set("/gone", (_q, res) => res.writeHead(410).end());
    expect(await sendWebhook(`${base}/down`, SECRET, MSG, dev)).toEqual({ ok: false, code: "http_503", retryable: true });
    expect(await sendWebhook(`${base}/gone`, SECRET, MSG, dev)).toEqual({ ok: false, code: "http_410", retryable: false });
  });

  it("times out (total deadline) on a receiver that never answers", async () => {
    r.handlers.set("/hang", () => undefined);
    const start = Date.now();
    expect(await sendWebhook(`${base}/hang`, SECRET, MSG, { ...dev, totalTimeoutMs: 300 })).toEqual({ ok: false, code: "timeout", retryable: true });
    expect(Date.now() - start).toBeLessThan(10_000);
  });

  it("caps the response size: an endless 200 body does not hold the sender", async () => {
    r.handlers.set("/flood", (_q, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      const chunk = "x".repeat(16 * 1024);
      const pump = () => {
        while (res.write(chunk)) {
          /* until the socket buffer is full */
        }
        if (!res.destroyed) res.once("drain", pump);
      };
      pump();
    });
    expect(await sendWebhook(`${base}/flood`, SECRET, MSG, { ...dev, totalTimeoutMs: 10_000 })).toEqual({ ok: true });
  });

  it("refuses http:// without the dev flag, and connection errors are retryable", async () => {
    expect(await sendWebhook(`${base}/hook`, SECRET, MSG, { allowInternal: true, allowHttp: false })).toEqual({
      ok: false,
      code: "insecure_refused",
      retryable: false,
    });
    const closed = receiver(null);
    const port = await closed.start();
    await closed.stop();
    expect(await sendWebhook(`http://127.0.0.1:${port}/`, SECRET, MSG, dev)).toEqual({ ok: false, code: "connect_failed", retryable: true });
  });

  it("SSRF: internal and metadata destinations are refused before any connection", async () => {
    const n = r.received.length;
    // No dev flag: loopback refused.
    expect(await sendWebhook(`${base}/hook`, SECRET, MSG, { allowInternal: false, allowHttp: true })).toEqual({
      ok: false,
      code: "address_internal",
      retryable: false,
    });
    // A public-looking name resolving to an internal or metadata address.
    const resolver = async (host: string) =>
      host === "rebind.example" ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "169.254.169.254", family: 4 }];
    const port = new URL(base).port;
    expect(await sendWebhook(`http://rebind.example:${port}/hook`, SECRET, MSG, { allowInternal: false, allowHttp: true, resolver })).toMatchObject({
      code: "address_internal",
    });
    expect(await sendWebhook(`http://meta.example:${port}/hook`, SECRET, MSG, { ...dev, resolver })).toMatchObject({
      code: "address_forbidden",
      retryable: false,
    });
    expect(r.received.length).toBe(n);
  });

  it("connects to the vetted address only (the name is not resolved again)", async () => {
    const port = new URL(base).port;
    const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
    // `pinned.invalid` cannot resolve through DNS: the request reaches the receiver only through
    // the pinned address.
    expect(await sendWebhook(`http://pinned.invalid:${port}/pinned`, SECRET, MSG, { ...dev, resolver })).toEqual({ ok: true });
    expect(r.received.at(-1)?.headers.host).toBe(`pinned.invalid:${port}`);
  });

  it("falls back to the next checked address when the first one does not answer (dual stack)", async () => {
    const port = new URL(base).port;
    // The receiver listens on 127.0.0.1 only: ::1 is refused, 127.0.0.1 answers.
    const resolver = async () => [
      { address: "::1", family: 6 },
      { address: "127.0.0.1", family: 4 },
    ];
    expect(await sendWebhook(`http://dual.invalid:${port}/dual`, SECRET, MSG, { ...dev, resolver })).toEqual({ ok: true });
    expect(r.received.at(-1)?.path).toBe("/dual");
  });

  it("a forbidden address anywhere in the resolved set still refuses, before any connection", async () => {
    const port = new URL(base).port;
    const n = r.received.length;
    const resolver = async () => [
      { address: "127.0.0.1", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ];
    expect(await sendWebhook(`http://mixed.invalid:${port}/mixed`, SECRET, MSG, { ...dev, resolver })).toMatchObject({ code: "address_forbidden" });
    expect(r.received.length).toBe(n);
  });
});

const cert = selfSignedCert();
if (!cert) {
  // eslint-disable-next-line no-console -- test harness message
  console.warn("[webhook tests] HTTPS receiver SKIPPED: openssl unavailable.");
}

describe.skipIf(!cert)("webhook sender over HTTPS", () => {
  const r = receiver(cert);
  let port = 0;
  beforeAll(async () => {
    port = await r.start();
  });
  afterAll(() => r.stop());

  it("verifies the receiver certificate", async () => {
    const opts = { allowInternal: true, allowHttp: false, ca: cert?.cert };
    expect(await sendWebhook(`https://localhost:${port}/tls`, SECRET, MSG, opts)).toEqual({ ok: true });
    expect(verifyWebhookSignature(SECRET, String(r.received.at(-1)?.headers["x-databastion-signature"]), MSG.body)).toBe(true);
    // Untrusted certificate: refused (retryable: the certificate may be fixed).
    expect(await sendWebhook(`https://localhost:${port}/tls`, SECRET, MSG, { allowInternal: true, allowHttp: false })).toEqual({
      ok: false,
      code: "tls_failed",
      retryable: true,
    });
  });
});
