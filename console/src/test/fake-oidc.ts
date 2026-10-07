import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";

/**
 * In-process fake OIDC provider for the console tests (no network): discovery, JWKS, token,
 * userinfo, revocation and end-session endpoints on 127.0.0.1 (plain HTTP, accepted on loopback
 * outside production only). Codes are registered by the test with the claims to return.
 */

export interface FakeCode {
  claims: Record<string, unknown>;
  /** PKCE verifier the token request must present (checked as S256 by the test via `seen`). */
  refreshToken?: string;
  noIdToken?: boolean;
  /** Userinfo claims served for the access token of this answer (default: `claims`). */
  userinfo?: Record<string, unknown>;
  /** Overrides of the signed `id_token` (header / signing key). */
  sign?: (claims: Record<string, unknown>) => Promise<string>;
}

export interface FakeProvider {
  issuer: string;
  clientId: string;
  clientSecret: string;
  rsKid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
  discovery: Record<string, unknown>;
  jwksHeaders: Record<string, string>;
  /** Extra keys published in the JWKS. */
  extraJwks: JWK[];
  codes: Map<string, FakeCode>;
  refreshes: Map<string, FakeCode>;
  hits: Record<string, number>;
  tokenRequests: { form: URLSearchParams; authorization: string | undefined }[];
  revoked: string[];
  /** Userinfo claims per issued access token. */
  userinfo: Map<string, Record<string, unknown>>;
  signIdToken(claims: Record<string, unknown>, header?: Record<string, unknown>, key?: CryptoKey): Promise<string>;
  close(): Promise<void>;
}

async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export async function startFakeProvider(opts: { clientId?: string; clientSecret?: string } = {}): Promise<FakeProvider> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const rsKid = "rs-1";
  const publicJwk = { ...(await exportJWK(publicKey)), kid: rsKid, alg: "RS256", use: "sig" };
  const server: Server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const issuer = `http://127.0.0.1:${port}/realms/test`;
  const fp: FakeProvider = {
    issuer,
    clientId: opts.clientId ?? "databastion-console",
    clientSecret: opts.clientSecret ?? "fake-client-secret-0123456789",
    rsKid,
    privateKey,
    publicJwk,
    discovery: {
      issuer,
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      userinfo_endpoint: `${issuer}/userinfo`,
      end_session_endpoint: `${issuer}/logout`,
      revocation_endpoint: `${issuer}/revoke`,
      response_types_supported: ["code"],
      response_modes_supported: ["query", "fragment", "form_post"],
      code_challenge_methods_supported: ["plain", "S256"],
      id_token_signing_alg_values_supported: ["RS256", "ES256", "HS256", "none"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    },
    jwksHeaders: {},
    extraJwks: [],
    codes: new Map(),
    refreshes: new Map(),
    hits: {},
    tokenRequests: [],
    revoked: [],
    userinfo: new Map(),
    async signIdToken(claims, header = {}, key = privateKey) {
      return new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: rsKid, ...header } as { alg: string }).sign(key);
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
  const send = (res: ServerResponse, status: number, json: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "Content-Type": "application/json", ...headers });
    res.end(JSON.stringify(json));
  };
  const tokenAnswer = async (c: FakeCode) => {
    const idToken = c.noIdToken ? undefined : c.sign ? await c.sign(c.claims) : await fp.signIdToken(c.claims);
    const accessToken = `at-${Math.random()}`;
    fp.userinfo.set(accessToken, c.userinfo ?? c.claims);
    return { token_type: "Bearer", access_token: accessToken, expires_in: 300, ...(idToken ? { id_token: idToken } : {}), ...(c.refreshToken ? { refresh_token: c.refreshToken } : {}) };
  };
  server.on("request", (req, res) => {
    void (async () => {
      const path = new URL(req.url ?? "/", issuer).pathname.replace("/realms/test", "");
      fp.hits[path] = (fp.hits[path] ?? 0) + 1;
      if (path === "/.well-known/openid-configuration") return send(res, 200, fp.discovery);
      if (path === "/jwks") return send(res, 200, { keys: [fp.publicJwk, ...fp.extraJwks] }, fp.jwksHeaders);
      if (path === "/token" && req.method === "POST") {
        const form = new URLSearchParams(await body(req));
        fp.tokenRequests.push({ form, authorization: req.headers.authorization });
        const expected = `Basic ${Buffer.from(`${fp.clientId}:${fp.clientSecret}`).toString("base64")}`;
        const postAuth = form.get("client_id") === fp.clientId && form.get("client_secret") === fp.clientSecret;
        if (req.headers.authorization !== expected && !postAuth) return send(res, 401, { error: "invalid_client" });
        if (form.get("grant_type") === "authorization_code") {
          const c = fp.codes.get(form.get("code") ?? "");
          fp.codes.delete(form.get("code") ?? "");
          if (!c) return send(res, 400, { error: "invalid_grant" });
          return send(res, 200, await tokenAnswer(c));
        }
        if (form.get("grant_type") === "refresh_token") {
          const c = fp.refreshes.get(form.get("refresh_token") ?? "");
          if (!c) return send(res, 400, { error: "invalid_grant" });
          return send(res, 200, await tokenAnswer(c));
        }
        return send(res, 400, { error: "unsupported_grant_type" });
      }
      if (path === "/userinfo") {
        const info = fp.userinfo.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
        return info ? send(res, 200, info) : send(res, 401, { error: "invalid_token" });
      }
      if (path === "/revoke" && req.method === "POST") {
        const form = new URLSearchParams(await body(req));
        fp.revoked.push(form.get("token") ?? "");
        res.writeHead(200);
        return res.end();
      }
      if (path === "/redirect") {
        res.writeHead(302, { Location: `${issuer}/.well-known/openid-configuration` });
        return res.end();
      }
      if (path === "/huge") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ pad: "x".repeat(300 * 1024) }));
      }
      if (path === "/slow") return; // never answers
      return send(res, 404, { error: "not_found" });
    })();
  });
  return fp;
}

/** Standard claims of a fresh `id_token` for `sub`, with the nonce of the flow. */
export function idClaims(fp: FakeProvider, sub: string, nonce: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: fp.issuer, aud: fp.clientId, sub, iat: now, exp: now + 300, nonce, ...extra };
}

/** Environment of a console using `fp`. */
export function oidcEnv(fp: FakeProvider, extra: Record<string, string> = {}): Record<string, string> {
  return {
    DATABASTION_OIDC_ENABLED: "1",
    DATABASTION_OIDC_ISSUER_URL: fp.issuer,
    DATABASTION_OIDC_CLIENT_ID: fp.clientId,
    DATABASTION_OIDC_CLIENT_SECRET: fp.clientSecret,
    DATABASTION_PUBLIC_URL: "http://console.test",
    ...extra,
  };
}
