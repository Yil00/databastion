import { describe, expect, it } from "vitest";

import { assertSafeDetails } from "./audit";
import { jobHub } from "./agent-api/job-hub";
import { startupWarnings } from "./startup-checks";
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
} from "./crypto";
import { RateLimiter } from "./rate-limit";
import { clientIp, readJsonBody } from "./request";

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
    expect(startupWarnings(env({ NODE_ENV: "production" }))).toHaveLength(1);
    expect(startupWarnings(env({ NODE_ENV: "production", DATABASTION_TRUST_PROXY: "1" }))).toHaveLength(0);
    expect(
      startupWarnings(env({ NODE_ENV: "production", DATABASTION_TRUST_PROXY: "1", DATABASTION_INSECURE_COOKIES: "1" })),
    ).toHaveLength(1);
    expect(startupWarnings(env({ NODE_ENV: "development" }))).toHaveLength(0);
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
});

describe("audit details", () => {
  it("refuses secret-looking keys", () => {
    expect(() => assertSafeDetails({ agent_secret: "x" })).toThrow();
    expect(() => assertSafeDetails({ password: "x" })).toThrow();
    expect(() => assertSafeDetails({ role: "admin" })).not.toThrow();
  });
});
