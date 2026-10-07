import { describe, expect, it } from "vitest";

import { newFlowState, openState, pkceChallenge, sealState, STATE_TTL_S } from "./state-cookie";

const KEY = { DATABASTION_ENCRYPTION_KEY: "hunter2-SECRET-test-server-key-0123456789abcdef" };
const OTHER = { DATABASTION_ENCRYPTION_KEY: "another-test-server-key-0123456789abcdefghij" };

describe("OIDC state cookie (ADR-0038 decision 5)", () => {
  it("round-trips 256-bit state, nonce and verifier, encrypted (nothing readable in the cookie)", () => {
    const s = newFlowState("login");
    expect(s.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(s.nonce).not.toBe(s.state);
    const sealed = sealState(s, KEY);
    expect(sealed).not.toContain(s.state);
    expect(Buffer.from(sealed, "base64url").toString("latin1")).not.toContain(s.nonce);
    expect(openState(sealed, KEY)).toEqual(s);
  });

  it("refuses a tampered value, another key and an expired state", () => {
    const s = newFlowState("link", { userId: "00000000-0000-4000-8000-000000000000", sessionHash: "a".repeat(64) });
    const sealed = sealState(s, KEY);
    const flipped = Buffer.from(sealed, "base64url");
    flipped[20] = (flipped[20] ?? 0) ^ 1;
    expect(openState(flipped.toString("base64url"), KEY)).toBeNull();
    expect(openState(sealed, OTHER)).toBeNull();
    expect(openState(sealed, KEY, Date.now() + STATE_TTL_S * 1000)).toBeNull();
    expect(openState("not base64 !", KEY)).toBeNull();
  });

  it("computes the S256 PKCE challenge (RFC 7636 appendix B)", () => {
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});
