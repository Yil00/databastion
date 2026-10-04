import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { assertSafeDetails } from "./audit";
import { jobHub } from "./agent-api/job-hub";
import { DEVICE_COOKIE_TTL_S, issueDeviceCookie, readDeviceCookie } from "./auth/device-cookie";
import { startupErrors, startupFatal, startupWarnings } from "./startup-checks";
import { parseWait } from "./agent-api/handlers";
import {
  argon2Hash,
  argon2Verify,
  isLowEntropySecret,
  newAgentSecret,
  newEnrollmentToken,
  AGENT_SECRET_FORMAT,
  ENROLLMENT_TOKEN_FORMAT,
  Semaphore,
  serverSubkey,
} from "./crypto";
import { RateLimiter } from "./rate-limit";
import { clientIp, ipBucket, readJsonBody, xffWarningStats } from "./request";

describe("crypto", () => {
  it("generates contract-conforming, high-entropy tokens and secrets", () => {
    for (let i = 0; i < 200; i++) {
      const s = newAgentSecret();
      expect(s).toMatch(AGENT_SECRET_FORMAT);
      expect(isLowEntropySecret(s)).toBe(false);
      expect(newEnrollmentToken()).toMatch(ENROLLMENT_TOKEN_FORMAT);
    }
  });

  it("flags low-entropy secrets (fixture secrets included)", () => {
    expect(isLowEntropySecret(`dbs_${"A".repeat(43)}`)).toBe(true);
    expect(isLowEntropySecret("dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1")).toBe(true);
  });

  it("hashes with argon2id", async () => {
    const h = await argon2Hash("s3cret-value");
    expect(h).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await argon2Verify(h, "s3cret-value")).toBe(true);
    expect(await argon2Verify(h, "other")).toBe(false);
    expect(await argon2Verify("not a hash", "x")).toBe(false);
  });
});

describe("RateLimiter", () => {
  it("limits after `limit` hits within the window, then resets", () => {
    let now = 0;
    const rl = new RateLimiter(2, 1000, 10, () => now);
    expect(rl.check("k").limited).toBe(false);
    rl.hit("k");
    expect(rl.hit("k").limited).toBe(true);
    expect(rl.check("k").retryAfterS).toBe(1);
    now = 1000;
    expect(rl.check("k").limited).toBe(false);
  });

  it("bounds its memory", () => {
    const rl = new RateLimiter(1, 1000, 3);
    for (let i = 0; i < 10; i++) rl.hit(`k${i}`);
    expect(rl.check("k0").limited).toBe(false);
    expect(rl.check("k9").limited).toBe(true);
  });
});

describe("ipBucket", () => {
  it("aggregates IPv6 by /64 and unmaps IPv4-mapped addresses", () => {
    expect(ipBucket("192.0.2.1")).toBe("192.0.2.1");
    expect(ipBucket("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:0db8:0001:0002:ffff::")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipBucket("::1")).toBe("0:0:0:0::/64");
    expect(ipBucket("::ffff:198.51.100.7")).toBe("198.51.100.7");
    expect(ipBucket("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
  });

  it("aggregates IPv6 by /56 on request (logins, P1-D N1)", () => {
    expect(ipBucket("2001:db8:1:2ab::1", 56)).toBe("2001:db8:1:200::/56");
    expect(ipBucket("2001:db8:1:2ff:ffff::", 56)).toBe("2001:db8:1:200::/56");
    expect(ipBucket("2001:db8:1:300::1", 56)).toBe("2001:db8:1:300::/56");
    expect(ipBucket("192.0.2.1", 56)).toBe("192.0.2.1");
    expect(ipBucket("::ffff:198.51.100.7", 56)).toBe("198.51.100.7");
  });
});

describe("X-Forwarded-For misconfiguration warning (L-b)", () => {
  it("warns at most once per minute when the selected entry is not an IP", () => {
    const env = { DATABASTION_TRUSTED_PROXY_HOPS: "2" } as unknown as NodeJS.ProcessEnv;
    const before = xffWarningStats.warned;
    for (let i = 0; i < 5; i++) {
      expect(clientIp(new Request("http://x/", { headers: { "x-forwarded-for": "192.0.2.1" } }), env)).toBeNull();
    }
    expect(xffWarningStats.warned - before).toBeLessThanOrEqual(1);
  });
});

describe("RateLimiter.reserve", () => {
  it("counts before the work and refunds on success, synchronously", () => {
    const rl = new RateLimiter(2, 60_000);
    const a = rl.reserve("k");
    const b = rl.reserve("k");
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(rl.reserve("k")).toBeNull();
    a?.();
    a?.(); // idempotent
    expect(rl.reserve("k")).not.toBeNull();
    expect(rl.reserve("k")).toBeNull();
  });
});

describe("Semaphore", () => {
  it("caps concurrent holders and releases once", () => {
    const sem = new Semaphore(2);
    const r1 = sem.tryAcquire();
    const r2 = sem.tryAcquire();
    expect(sem.tryAcquire()).toBeNull();
    r1?.();
    r1?.();
    expect(sem.inUse).toBe(1);
    expect(sem.tryAcquire()).not.toBeNull();
    r2?.();
  });
});

describe("startupWarnings", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;
  it("warns in production without a trusted proxy or with insecure cookies", () => {
    const prod = { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: "/run/secrets/encryption_key" };
    expect(startupWarnings(env(prod))).toHaveLength(1);
    expect(startupWarnings(env({ ...prod, DATABASTION_TRUST_PROXY: "1" }))).toHaveLength(0);
    expect(startupWarnings(env({ ...prod, DATABASTION_TRUST_PROXY: "1", DATABASTION_INSECURE_COOKIES: "1" }))).toHaveLength(1);
    // The missing server key is an error now (startupErrors, P1-D N3), not a warning.
    expect(startupWarnings(env({ NODE_ENV: "production", DATABASTION_TRUST_PROXY: "1" }))).toHaveLength(0);
    expect(startupWarnings(env({ NODE_ENV: "development" }))).toHaveLength(0);
  });

  it("warns when the local login stays enabled for every local user while OIDC is on (end-of-phase-8 review L4)", () => {
    const oidc = { NODE_ENV: "development", DATABASTION_OIDC_ENABLED: "1" };
    const warned = (e: Record<string, string>) => startupWarnings(env(e)).some((w) => w.startsWith("DATABASTION_LOCAL_LOGIN=enabled while OIDC is enabled"));
    expect(warned({ ...oidc, DATABASTION_LOCAL_LOGIN: "enabled" })).toBe(true);
    expect(warned({ ...oidc, DATABASTION_LOCAL_LOGIN: "admins" })).toBe(false);
    expect(warned(oidc)).toBe(false);
    expect(warned({ NODE_ENV: "development", DATABASTION_LOCAL_LOGIN: "enabled" })).toBe(false);
    expect(warned({ ...oidc, DATABASTION_LOCAL_LOGIN: "bogus" })).toBe(false);
  });
});

describe("startupErrors (P1-D N3)", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;
  it("names the disabled protections when the server key is missing, short or unreadable in production", () => {
    const cases: Record<string, string>[] = [
      { NODE_ENV: "production" },
      { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: "too-short" },
      { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: "/nonexistent/encryption_key" },
    ];
    for (const e of cases) {
      const errors = startupErrors(env(e));
      expect(errors).toHaveLength(1);
      expect(errors[0]).toContain("DATABASTION_ENCRYPTION_KEY");
      expect(errors[0]).toContain("shared (NAT / proxy) IP");
      expect(errors[0]).toContain("device cookies");
      expect(errors[0]).not.toContain("too-short");
    }
    expect(startupErrors(env({ NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: "k".repeat(44) }))).toEqual([]);
    expect(startupErrors(env({ NODE_ENV: "development" }))).toEqual([]);
  });
});

describe("startupFatal (missing server key in production)", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;
  const dir = mkdtempSync(join(tmpdir(), "databastion-key-"));
  const goodFile = join(dir, "encryption_key");
  const shortFile = join(dir, "short_key");
  writeFileSync(goodFile, "k".repeat(44) + "\n");
  writeFileSync(shortFile, "short\n");

  it("refuses to start in production without a usable key", () => {
    const cases: Record<string, string>[] = [
      { NODE_ENV: "production" },
      { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: "too-short" },
      { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: "/nonexistent/encryption_key" },
      { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: shortFile },
      // Only "1" overrides.
      { NODE_ENV: "production", DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY: "true" },
    ];
    for (const e of cases) {
      const fatal = startupFatal(env(e));
      expect(fatal).toContain("refusing to start");
      expect(fatal).toContain("DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1");
      expect(fatal).not.toContain("too-short");
      expect(fatal).not.toContain("short\n");
    }
  });

  it("starts with a usable key (direct or file), outside production, or with the override", () => {
    expect(startupFatal(env({ NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: "k".repeat(44) }))).toBeNull();
    expect(startupFatal(env({ NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: goodFile }))).toBeNull();
    expect(startupFatal(env({ NODE_ENV: "development" }))).toBeNull();
    expect(startupFatal(env({ NODE_ENV: "test" }))).toBeNull();
    const overridden = env({ NODE_ENV: "production", DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY: "1" });
    expect(startupFatal(overridden)).toBeNull();
    // The override keeps the loud error naming the disabled protections.
    expect(startupErrors(overridden)).toHaveLength(1);
    expect(startupErrors(overridden)[0]).toContain("PROTECTIONS DISABLED");
    expect(startupErrors(env({ NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY_FILE: goodFile }))).toEqual([]);
  });
});

describe("startupFatal (alerting dev flag in production, L5)", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;
  const KEY = { DATABASTION_ENCRYPTION_KEY: "k".repeat(44) };

  it("refuses to start with DATABASTION_ALERTING_INSECURE_DEV in production without the second opt-in", () => {
    for (const value of ["1", "true", "0"]) {
      const fatal = startupFatal(env({ NODE_ENV: "production", ...KEY, DATABASTION_ALERTING_INSECURE_DEV: value }));
      expect(fatal).toContain("refusing to start");
      expect(fatal).toContain("DATABASTION_ALERTING_INSECURE_DEV_I_UNDERSTAND=1");
    }
    // Only "1" acknowledges.
    expect(
      startupFatal(env({ NODE_ENV: "production", ...KEY, DATABASTION_ALERTING_INSECURE_DEV: "1", DATABASTION_ALERTING_INSECURE_DEV_I_UNDERSTAND: "yes" })),
    ).toContain("refusing to start");
  });

  it("starts with the opt-in (still warned), outside production, or without the flag", () => {
    const acked = env({ NODE_ENV: "production", ...KEY, DATABASTION_ALERTING_INSECURE_DEV: "1", DATABASTION_ALERTING_INSECURE_DEV_I_UNDERSTAND: "1" });
    expect(startupFatal(acked)).toBeNull();
    expect(startupWarnings(acked).some((w) => w.includes("DATABASTION_ALERTING_INSECURE_DEV=1 in production"))).toBe(true);
    expect(startupFatal(env({ NODE_ENV: "development", DATABASTION_ALERTING_INSECURE_DEV: "1" }))).toBeNull();
    expect(startupFatal(env({ NODE_ENV: "production", ...KEY }))).toBeNull();
  });
});

describe("login device cookies (P1-D N1)", () => {
  const KEY_A = "device-cookie-test-key-A-0123456789abcdefghijkl";
  const KEY_B = "device-cookie-test-key-B-0123456789abcdefghijkl";
  const USER = "0192f0a1-0000-7000-8000-000000000001";
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;
  const req = (cookie: string) => new Request("http://console.test/api/auth/login", { headers: { cookie } });
  const pair = (setCookie: string | null) => (setCookie ?? "").split(";")[0] ?? "";

  it("is signed, bound to the user id, and has the expected attributes", () => {
    const set = issueDeviceCookie(USER, env({ NODE_ENV: "test", DATABASTION_ENCRYPTION_KEY: KEY_A }));
    expect(set).toMatch(/^databastion_device=v1\./);
    expect(set).toContain("HttpOnly");
    expect(set).toContain("SameSite=Strict");
    expect(set).toContain("Path=/");
    const cookie = readDeviceCookie(req(pair(set)), env({ NODE_ENV: "test", DATABASTION_ENCRYPTION_KEY: KEY_A }));
    expect(cookie?.userId).toBe(USER);
    expect(cookie?.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const prod = issueDeviceCookie(USER, env({ NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: KEY_A }));
    expect(prod).toMatch(/^__Host-databastion_device=/);
    expect(prod).toContain("Secure");
  });

  it("rejects a tampered cookie, another key, an expired one, and everything without a key", () => {
    const e = env({ NODE_ENV: "test", DATABASTION_ENCRYPTION_KEY: KEY_A });
    const value = pair(issueDeviceCookie(USER, e));
    const other = value.replace(USER, "0192f0a1-0000-7000-8000-000000000002");
    const flipped = value.slice(0, -1) + (value.endsWith("0") ? "1" : "0");
    expect(readDeviceCookie(req(other), e)).toBeNull();
    expect(readDeviceCookie(req(flipped), e)).toBeNull();
    expect(readDeviceCookie(req(value), env({ NODE_ENV: "test", DATABASTION_ENCRYPTION_KEY: KEY_B }))).toBeNull();
    expect(readDeviceCookie(req(value), e, Date.now() + DEVICE_COOKIE_TTL_S * 1000)).toBeNull();
    expect(issueDeviceCookie(USER, env({ NODE_ENV: "test" }))).toBeNull();
    expect(readDeviceCookie(req(value), env({ NODE_ENV: "test" }))).toBeNull();
  });
});

describe("job hub", () => {
  it("does not lose a job wake-up that arrives before the waiter registers", async () => {
    const agentId = "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a";
    const release = jobHub.reserveSlot(agentId);
    expect(typeof release).toBe("function");
    const seq = jobHub.seq(agentId);
    jobHub.notifyJob(agentId);
    expect(await jobHub.wait(agentId, 10_000, undefined, seq)).toBe("job");
    if (typeof release === "function") release();
  });

  it("reserves at most MAX_HELD_POLLS_PER_AGENT slots per agent", () => {
    const agentId = "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5b";
    const slots = [jobHub.reserveSlot(agentId), jobHub.reserveSlot(agentId), jobHub.reserveSlot(agentId)];
    expect(slots[2]).toBe("agent");
    for (const s of slots) if (typeof s === "function") s();
    expect(jobHub.heldPolls(agentId)).toBe(0);
  });
});

describe("parseWait", () => {
  const w = (q: string) => parseWait(new URL(`http://x/jobs${q}`));
  it("defaults to 25 and accepts 0..25", () => {
    expect(w("")).toBe(25);
    expect(w("?wait=0")).toBe(0);
    expect(w("?wait=25")).toBe(25);
  });
  it("rejects anything else", () => {
    for (const q of ["?wait=26", "?wait=", "?wait=1.5", "?wait=+1", "?x=1", "?wait=1&wait=1"]) {
      expect(w(q)).toBeNull();
    }
  });
});

describe("request helpers", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;

  it("only trusts X-Forwarded-For behind a declared proxy, else the IP is unknown", () => {
    const req = new Request("http://x/", { headers: { "x-forwarded-for": "198.51.100.7, 192.0.2.1" } });
    expect(clientIp(req, env({}))).toBeNull();
    expect(clientIp(req, env({ DATABASTION_TRUST_PROXY: "1" }))).toBe("192.0.2.1");
    expect(clientIp(req, env({ DATABASTION_TRUSTED_PROXY_HOPS: "2" }))).toBe("198.51.100.7");
    expect(clientIp(req, env({ DATABASTION_TRUSTED_PROXY_HOPS: "3" }))).toBeNull();
    const spoofed = new Request("http://x/", { headers: { "x-forwarded-for": "not-an-ip" } });
    expect(clientIp(spoofed, env({ DATABASTION_TRUST_PROXY: "1" }))).toBeNull();
    expect(clientIp(new Request("http://x/"), env({ DATABASTION_TRUST_PROXY: "1" }))).toBeNull();
  });

  it("caps the body size even without Content-Length", async () => {
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        c.enqueue(new Uint8Array(1024).fill(32));
      },
    });
    const req = new Request("http://x/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(await readJsonBody(req, 10_000)).toEqual({ ok: false, reason: "too_large" });
  });

  it("gives up on a body that is not received within the read deadline (P1-D L1)", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('{"a":'));
      },
      cancel() {
        cancelled = true;
      },
    });
    const req = new Request("http://x/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half",
    } as RequestInit);
    const start = Date.now();
    expect(await readJsonBody(req, { maxBytes: 10_000, deadlineMs: 50 })).toEqual({
      ok: false,
      reason: "invalid_json",
      timedOut: true,
    });
    expect(Date.now() - start).toBeLessThan(2_000);
    expect(cancelled).toBe(true);
    // A body received in time is unaffected by the deadline.
    const ok = new Request("http://x/", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(await readJsonBody(ok, { deadlineMs: 1_000 })).toEqual({ ok: true, value: {} });
  });
});

describe("audit details", () => {
  it("refuses secret-looking keys", () => {
    expect(() => assertSafeDetails({ agent_secret: "x" })).toThrow();
    expect(() => assertSafeDetails({ password: "x" })).toThrow();
    expect(() => assertSafeDetails({ role: "admin" })).not.toThrow();
  });
});

describe("server subkeys (P1-D I2)", () => {
  const KEY = "hunter2-SECRET-unit-server-key-0123456789abcdef";
  it("derives independent 256-bit subkeys per domain and key, and fails closed without a key", () => {
    const a = serverSubkey("agent-known-good.v1", { DATABASTION_ENCRYPTION_KEY: KEY });
    expect(a).toHaveLength(32);
    expect(serverSubkey("agent-known-good.v1", { DATABASTION_ENCRYPTION_KEY: KEY })?.equals(a!)).toBe(true);
    expect(serverSubkey("other.v1", { DATABASTION_ENCRYPTION_KEY: KEY })?.equals(a!)).toBe(false);
    expect(serverSubkey("agent-known-good.v1", { DATABASTION_ENCRYPTION_KEY: `${KEY}x` })?.equals(a!)).toBe(false);
    expect(serverSubkey("agent-known-good.v1", {})).toBeNull();
    expect(serverSubkey("agent-known-good.v1", { DATABASTION_ENCRYPTION_KEY: "short" })).toBeNull();
    expect(
      serverSubkey("agent-known-good.v1", { DATABASTION_ENCRYPTION_KEY: KEY, DATABASTION_ENCRYPTION_KEY_FILE: "/nonexistent" }),
    ).toBeNull();
  });
});
