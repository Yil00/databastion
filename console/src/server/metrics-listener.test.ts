import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { GET } from "@/app/metrics/route";
import { hasDb, setupTestDatabase } from "@/test/db";

import { DEFAULT_METRICS_HOST, metricsListenerConfig, metricsOnMainPort } from "./metrics";
import { startMetricsListener } from "./metrics-listener";
import { startupWarnings } from "./startup-checks";

// Test value, >= 32 characters, allowlisted form (gitleaks).
const TOKEN = "hunter2-SECRET-metrics-0123456789abcdef";

describe("DATABASTION_METRICS_PORT / _HOST", () => {
  it("is disabled when unset: /metrics stays on the main port", () => {
    expect(metricsListenerConfig({})).toBeNull();
    expect(metricsOnMainPort({})).toBe(true);
  });

  it("binds to 127.0.0.1 by default and moves /metrics off the main port", () => {
    expect(metricsListenerConfig({ DATABASTION_METRICS_PORT: "9464" })).toEqual({
      host: DEFAULT_METRICS_HOST,
      port: 9464,
    });
    expect(DEFAULT_METRICS_HOST).toBe("127.0.0.1");
    expect(metricsOnMainPort({ DATABASTION_METRICS_PORT: "9464" })).toBe(false);
    expect(metricsListenerConfig({ DATABASTION_METRICS_PORT: "9464", DATABASTION_METRICS_HOST: "0.0.0.0" })).toEqual({
      host: "0.0.0.0",
      port: 9464,
    });
    expect(metricsListenerConfig({ DATABASTION_METRICS_PORT: "9464", DATABASTION_METRICS_HOST: "::1" })?.host).toBe("::1");
  });

  it.each([
    [{ DATABASTION_METRICS_HOST: "127.0.0.1" }],
    [{ DATABASTION_METRICS_PORT: "0" }],
    [{ DATABASTION_METRICS_PORT: "65536" }],
    [{ DATABASTION_METRICS_PORT: "94a" }],
    [{ DATABASTION_METRICS_PORT: "9464", DATABASTION_METRICS_HOST: "localhost" }],
    [{ DATABASTION_METRICS_PORT: "3000" }],
    [{ DATABASTION_METRICS_PORT: "8080", PORT: "8080" }],
  ])("rejects %o, and then serves /metrics nowhere", (env) => {
    expect(() => metricsListenerConfig(env)).toThrow();
    expect(metricsOnMainPort(env)).toBe(false);
  });

  it("warns in production when /metrics is enabled on the main port", () => {
    const env = { NODE_ENV: "production", DATABASTION_TRUST_PROXY: "1" } as unknown as NodeJS.ProcessEnv;
    expect(startupWarnings({ ...env, DATABASTION_METRICS_TOKEN: TOKEN }).join()).toContain("DATABASTION_METRICS_PORT");
    expect(
      startupWarnings({ ...env, DATABASTION_METRICS_TOKEN: TOKEN, DATABASTION_METRICS_PORT: "9464" }).join(),
    ).not.toContain("DATABASTION_METRICS_PORT");
    expect(startupWarnings(env).join()).not.toContain("DATABASTION_METRICS_PORT");
  });
});

describe("dedicated metrics listener", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = await startMetricsListener({ host: "127.0.0.1", port: 0 });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise((r) => server.close(r));
  });
  afterEach(() => {
    delete process.env.DATABASTION_METRICS_TOKEN;
    delete process.env.DATABASTION_METRICS_PORT;
  });

  it("serves only GET /metrics, with the bearer token", async () => {
    expect((await fetch(`${base}/metrics`)).status).toBe(404); // token unset
    process.env.DATABASTION_METRICS_TOKEN = TOKEN;
    const denied = await fetch(`${base}/metrics`, { headers: { Authorization: "Bearer wrong" } });
    expect(denied.status).toBe(401);
    expect(denied.headers.get("www-authenticate")).toContain("Bearer");
    expect(denied.headers.get("cache-control")).toBe("no-store");
    expect((await fetch(`${base}/metrics`)).status).toBe(401);
    expect((await fetch(`${base}/`, { headers: { Authorization: `Bearer ${TOKEN}` } })).status).toBe(404);
    expect((await fetch(`${base}/api/health`, { headers: { Authorization: `Bearer ${TOKEN}` } })).status).toBe(404);
    const post = await fetch(`${base}/metrics`, { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(post.status).toBe(405);
  });

  it("the main-port route answers 404 once the dedicated listener is configured", async () => {
    process.env.DATABASTION_METRICS_TOKEN = TOKEN;
    process.env.DATABASTION_METRICS_PORT = "9464";
    const res = await GET(new Request("http://console.test/metrics", { headers: { Authorization: `Bearer ${TOKEN}` } }));
    expect(res.status).toBe(404);
  });

  describe.skipIf(!hasDb)("with PostgreSQL", () => {
    let teardown: () => Promise<void>;
    beforeAll(async () => {
      teardown = await setupTestDatabase();
    });
    afterAll(async () => {
      await teardown?.();
    });

    it("exposes the Prometheus text format with the right token", async () => {
      process.env.DATABASTION_METRICS_TOKEN = TOKEN;
      process.env.DATABASTION_METRICS_PORT = "9464";
      const res = await fetch(`${base}/metrics?x=1`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
      expect(await res.text()).toContain("# TYPE databastion_security_events gauge");
    });
  });
});
