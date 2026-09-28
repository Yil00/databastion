import { describe, expect, it } from "vitest";

import { assertSafeDetails } from "./audit";
import { parseWait } from "./agent-api/handlers";
import {
  argon2Hash,
  argon2Verify,
  isLowEntropySecret,
  newAgentSecret,
  newEnrollmentToken,
  AGENT_SECRET_FORMAT,
  ENROLLMENT_TOKEN_FORMAT,
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
  it("only trusts X-Forwarded-For behind a declared proxy", () => {
    const req = new Request("http://x/", { headers: { "x-forwarded-for": "198.51.100.7, 192.0.2.1" } });
    expect(clientIp(req, {} as NodeJS.ProcessEnv)).toBe("direct");
    expect(clientIp(req, { DATABASTION_TRUST_PROXY: "1" } as unknown as NodeJS.ProcessEnv)).toBe("192.0.2.1");
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
