import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { validateIdToken, type IdTokenExpectations } from "./id-token";
import type { Jwk } from "./provider";

const ISS = "https://sso.example.com/realms/acme";
const CLIENT = "databastion";
const NONCE = "n".repeat(43);

let rsa: Awaited<ReturnType<typeof generateKeyPair>>;
let rsaOther: Awaited<ReturnType<typeof generateKeyPair>>;
let ec: Awaited<ReturnType<typeof generateKeyPair>>;
let rsaJwk: JWK;
let ecJwk: JWK;

beforeAll(async () => {
  rsa = await generateKeyPair("RS256", { extractable: true });
  rsaOther = await generateKeyPair("RS256", { extractable: true });
  ec = await generateKeyPair("ES256", { extractable: true });
  rsaJwk = { ...(await exportJWK(rsa.publicKey)), kid: "rsa", alg: "RS256", use: "sig" };
  ecJwk = { ...(await exportJWK(ec.publicKey)), kid: "ec" };
});

const now = () => Math.floor(Date.now() / 1000);
const claims = (extra: Record<string, unknown> = {}) => ({ iss: ISS, aud: CLIENT, sub: "user-1", iat: now(), exp: now() + 300, nonce: NONCE, ...extra });

function expectations(keys: JWK[] = [rsaJwk, ecJwk], over: Partial<IdTokenExpectations> = {}): IdTokenExpectations {
  return {
    issuer: ISS,
    clientId: CLIENT,
    nonce: NONCE,
    algorithms: ["RS256", "ES256"],
    keysFor: async (kid) => (kid === undefined ? keys : keys.filter((k) => k.kid === kid)) as Jwk[],
    ...over,
  };
}

const sign = (c: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "rsa" }, key = rsa.privateKey) =>
  new SignJWT(c).setProtectedHeader(header as { alg: string }).sign(key);

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

async function failure(token: string, x = expectations()): Promise<string> {
  try {
    await validateIdToken(token, x);
    return "accepted";
  } catch (err) {
    return (err as { failure?: string }).failure ?? "error";
  }
}

describe("id_token validation (ADR-0038 decision 4)", () => {
  it("accepts a valid RS256 and ES256 token", async () => {
    await expect(validateIdToken(await sign(claims()), expectations())).resolves.toMatchObject({ sub: "user-1" });
    await expect(validateIdToken(await sign(claims(), { alg: "ES256", kid: "ec" }, ec.privateKey), expectations())).resolves.toMatchObject({ sub: "user-1" });
  });

  it("refuses alg none, HS256 forged with the public key, and algorithms outside the allowed set", async () => {
    const none = `${b64({ alg: "none", kid: "rsa" })}.${b64(claims())}.`;
    expect(await failure(none)).toBe("alg");
    const hs = await new SignJWT(claims()).setProtectedHeader({ alg: "HS256", kid: "rsa" }).sign(new TextEncoder().encode(JSON.stringify(rsaJwk)));
    expect(await failure(hs)).toBe("alg");
    const psKey = await generateKeyPair("PS256");
    const ps = await sign(claims(), { alg: "PS256", kid: "rsa" }, psKey.privateKey);
    expect(await failure(ps)).toBe("alg");
    // RS256 not in the intersection (e.g. provider supports ES256 only).
    expect(await failure(await sign(claims()), expectations(undefined, { algorithms: ["ES256"] }))).toBe("alg");
  });

  it("refuses an unknown kid, a JWK whose kty, alg or use does not match, and a key without kid among several", async () => {
    expect(await failure(await sign(claims(), { alg: "RS256", kid: "nope" }))).toBe("key");
    // ES256 header pointing at the RSA key.
    expect(await failure(await sign(claims(), { alg: "ES256", kid: "rsa" }, ec.privateKey))).toBe("key");
    const encJwk = { ...rsaJwk, use: "enc" };
    expect(await failure(await sign(claims()), expectations([encJwk]))).toBe("key");
    const otherAlg = { ...rsaJwk, alg: "PS256" };
    expect(await failure(await sign(claims()), expectations([otherAlg]))).toBe("key");
    expect(await failure(await sign(claims(), { alg: "RS256" }), expectations([rsaJwk, { ...rsaJwk, kid: "rsa2" }]))).toBe("key");
    // Without a kid and a single matching key: accepted.
    await expect(validateIdToken(await sign(claims(), { alg: "RS256" }), expectations([rsaJwk]))).resolves.toBeTruthy();
  });

  it("refuses a bad signature (another key with the same kid)", async () => {
    expect(await failure(await sign(claims(), { alg: "RS256", kid: "rsa" }, rsaOther.privateKey))).toBe("signature");
  });

  it("checks exp, nbf and iat with 60 s skew, iat at most 10 minutes old", async () => {
    expect(await failure(await sign(claims({ exp: now() - 61 })))).toBe("exp");
    await expect(validateIdToken(await sign(claims({ exp: now() - 30 })), expectations())).resolves.toBeTruthy();
    expect(await failure(await sign(claims({ nbf: now() + 120 })))).toBe("nbf");
    expect(await failure(await sign(claims({ iat: now() - 11 * 60 - 61 })))).toBe("iat");
    expect(await failure(await sign(claims({ iat: now() + 120 })))).toBe("iat");
    expect(await failure(await sign(claims({ iat: "now" })))).toBe("iat");
  });

  it("checks iss, aud, azp, nonce and sub", async () => {
    expect(await failure(await sign(claims({ iss: `${ISS}/` })))).toBe("iss");
    expect(await failure(await sign(claims({ aud: "other" })))).toBe("aud");
    expect(await failure(await sign(claims({ aud: ["other", CLIENT] })))).toBe("azp");
    expect(await failure(await sign(claims({ aud: ["other", CLIENT], azp: "other" })))).toBe("azp");
    await expect(validateIdToken(await sign(claims({ aud: ["other", CLIENT], azp: CLIENT })), expectations())).resolves.toBeTruthy();
    expect(await failure(await sign(claims({ nonce: "x".repeat(43) })))).toBe("nonce");
    expect(await failure(await sign(claims({ nonce: undefined })))).toBe("nonce");
    expect(await failure(await sign(claims({ sub: "" })))).toBe("sub");
    expect(await failure(await sign(claims({ sub: 42 })))).toBe("sub");
  });

  it("refuses malformed tokens", async () => {
    expect(await failure("a.b")).toBe("format");
    expect(await failure("x".repeat(40_000))).toBe("format");
    expect(await failure(`${b64({ alg: "RS256", kid: "rsa", crit: ["exp"] })}.${b64(claims())}.sig`)).toBe("format");
  });
});
