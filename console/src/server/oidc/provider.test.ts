import { createServer } from "node:https";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { selfSignedCert } from "@/test/tls";
import { oidcEnv, startFakeProvider, type FakeProvider } from "@/test/fake-oidc";

import { loadOidcConfig, type OidcConfig } from "./config";
import { providerRequest, ProviderHttpError } from "./http";
import { DiscoveryError, JWKS_MIN_REFETCH_MS, JWKS_REFRESH_MS, OidcProvider, parseDiscovery } from "./provider";

let fp: FakeProvider;
let cfg: OidcConfig;

beforeAll(async () => {
  fp = await startFakeProvider();
  cfg = loadOidcConfig({ ...process.env, ...oidcEnv(fp) }) as OidcConfig;
});
afterAll(async () => {
  await fp.close();
});

const code = (p: Promise<unknown>) => p.then(() => "ok", (e: unknown) => (e instanceof ProviderHttpError ? e.code : String(e)));

describe("provider HTTP calls (ADR-0038 decision 2)", () => {
  const t = { ca: null, allowHttp: true };
  it("follows no redirect, caps sizes before parsing, times out", async () => {
    expect(await code(providerRequest(`${fp.issuer}/redirect`, { maxBytes: 65536 }, t))).toBe("redirect");
    expect(await code(providerRequest(`${fp.issuer}/huge`, { maxBytes: 65536 }, t))).toBe("too_large");
    expect(await code(providerRequest(`${fp.issuer}/slow`, { maxBytes: 65536 }, { ...t, timeoutMs: 200 }))).toBe("timeout");
    expect(await code(providerRequest(`${fp.issuer}/nothing`, { maxBytes: 65536 }, t))).toBe("status");
  });

  it("refuses plain HTTP unless allowed on loopback, and verifies TLS (CA file adds a root)", async () => {
    expect(await code(providerRequest(`${fp.issuer}/jwks`, { maxBytes: 65536 }, { ca: null, allowHttp: false }))).toBe("url");
    const cert = selfSignedCert();
    if (cert === null) {
      // eslint-disable-next-line no-console -- test harness message
      console.warn("[oidc tls test] SKIPPED: openssl unavailable");
      return;
    }
    const srv = createServer({ key: cert.key, cert: cert.cert }, (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const url = `https://127.0.0.1:${(srv.address() as AddressInfo).port}/x`;
    try {
      expect(await code(providerRequest(url, { maxBytes: 1024 }, { ca: null, allowHttp: false }))).toBe("network");
      expect(await code(providerRequest(url, { maxBytes: 1024 }, { ca: cert.cert, allowHttp: false }))).toBe("ok");
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });
});

describe("discovery", () => {
  it("requires the exact issuer, https endpoints, code + S256 + query, and a common algorithm", () => {
    const ok = parseDiscovery(fp.discovery, cfg);
    expect(ok.idTokenAlgs).toEqual(["RS256", "ES256"]);
    const bad = (over: Record<string, unknown>) => () => parseDiscovery({ ...fp.discovery, ...over }, cfg);
    expect(bad({ issuer: `${fp.issuer}/` })).toThrow(DiscoveryError);
    expect(bad({ token_endpoint: "http://evil.example.com/token" })).toThrow(DiscoveryError);
    expect(bad({ code_challenge_methods_supported: ["plain"] })).toThrow(DiscoveryError);
    expect(bad({ response_modes_supported: ["form_post"] })).toThrow(DiscoveryError);
    expect(bad({ id_token_signing_alg_values_supported: ["HS256", "none"] })).toThrow(DiscoveryError);
    expect(bad({ id_token_signing_alg_values_supported: undefined })).toThrow(DiscoveryError);
    expect(bad({ token_endpoint_auth_methods_supported: ["private_key_jwt"] })).toThrow(DiscoveryError);
  });

  it("backs off while the provider is unreachable, then recovers", async () => {
    let now = 1_000_000;
    let down = true;
    const fetcher: typeof providerRequest = (url, req, t) => (down ? Promise.reject(new ProviderHttpError("network")) : providerRequest(url, req, t));
    const p = new OidcProvider(cfg, fetcher, () => now);
    await expect(p.getMetadata()).rejects.toThrow();
    down = false;
    await expect(p.getMetadata()).rejects.toThrow(/backing off/);
    now += 2_001;
    await expect(p.getMetadata()).resolves.toMatchObject({ issuer: fp.issuer });
  });
});

describe("JWKS cache (ADR-0038 decision 4)", () => {
  it("refetches at least hourly, honors a shorter max-age, and refetches an unknown kid at most once a minute", async () => {
    let now = 5_000_000;
    const p = new OidcProvider(cfg, providerRequest, () => now);
    const fetches = () => fp.hits["/jwks"] ?? 0;
    const start = fetches();
    expect(await p.keysFor(fp.rsKid)).toHaveLength(1);
    expect(fetches()).toBe(start + 1);
    // Unknown kid within a minute: no refetch.
    expect(await p.keysFor("rotated")).toHaveLength(0);
    expect(fetches()).toBe(start + 1);
    now += JWKS_MIN_REFETCH_MS;
    expect(await p.keysFor("rotated")).toHaveLength(0);
    expect(fetches()).toBe(start + 2);
    // Cached for known keys until the hourly refresh, even with a long max-age.
    fp.jwksHeaders = { "Cache-Control": "max-age=86400" };
    now += JWKS_REFRESH_MS;
    await p.keysFor(fp.rsKid);
    expect(fetches()).toBe(start + 3);
    now += JWKS_REFRESH_MS - 1000;
    await p.keysFor(fp.rsKid);
    expect(fetches()).toBe(start + 3);
    now += 1000;
    await p.keysFor(fp.rsKid);
    expect(fetches()).toBe(start + 4);
    // A shorter max-age is honored (at least one minute).
    fp.jwksHeaders = { "Cache-Control": "max-age=120" };
    now += JWKS_REFRESH_MS;
    await p.keysFor(fp.rsKid);
    now += 121_000;
    await p.keysFor(fp.rsKid);
    expect(fetches()).toBe(start + 6);
    fp.jwksHeaders = {};
  });
});
