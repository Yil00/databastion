import { describe, expect, it } from "vitest";

import { ConfigError } from "@/config/env";
import { startupFatal } from "@/server/startup-checks";

import { loadOidcConfig, localLoginMode, oidcStartupFatal, parseDuration } from "./config";

const SECRET = "hunter2-SECRET-oidc-client-secret-canary";
const KEY = "hunter2-SECRET-test-server-key-0123456789abcdef";
const env = (over: Record<string, string | undefined> = {}): Record<string, string | undefined> => ({
  NODE_ENV: "test",
  DATABASTION_ENCRYPTION_KEY: KEY,
  DATABASTION_OIDC_ENABLED: "1",
  DATABASTION_OIDC_ISSUER_URL: "https://sso.example.com/realms/acme",
  DATABASTION_OIDC_CLIENT_ID: "databastion",
  DATABASTION_OIDC_CLIENT_SECRET: SECRET,
  DATABASTION_PUBLIC_URL: "https://console.example.com",
  ...over,
});

function error(e: Record<string, string | undefined>, readFile?: (p: string) => string): string {
  try {
    loadOidcConfig(e, readFile);
    return "ok";
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigError);
    return (err as Error).message;
  }
}

describe("OIDC configuration (ADR-0038 decision 16)", () => {
  it("is off by default and applies the confirmed defaults when on", () => {
    expect(loadOidcConfig({})).toBeNull();
    const c = loadOidcConfig(env());
    expect(c).toMatchObject({
      tokenAuthMethod: "client_secret_basic",
      scopes: ["openid", "profile", "email"],
      displayName: "Single sign-on",
      idTokenAlgs: ["RS256", "PS256", "ES256"],
      roleStrict: true,
      allowSignUp: false,
      skipRoleSync: true, // no role expression: roles managed in the console
      autoLogin: false,
      useRefreshToken: false,
      useUserinfo: false,
      sessionMaxAgeMs: 12 * 3600_000,
      redirectUri: "https://console.example.com/api/auth/oidc/callback",
    });
    expect(loadOidcConfig(env({ DATABASTION_OIDC_SCOPES: "profile groups" }))?.scopes).toEqual(["openid", "profile", "groups"]);
  });

  it("local login: enabled with OIDC off, admins with OIDC on, disabled only explicitly", () => {
    expect(localLoginMode({})).toBe("enabled");
    expect(localLoginMode(env())).toBe("admins");
    expect(localLoginMode(env({ DATABASTION_LOCAL_LOGIN: "disabled" }))).toBe("disabled");
    expect(localLoginMode({ DATABASTION_LOCAL_LOGIN: "enabled" })).toBe("enabled");
    expect(() => localLoginMode({ DATABASTION_LOCAL_LOGIN: "off" })).toThrow(ConfigError);
    expect(oidcStartupFatal({ DATABASTION_LOCAL_LOGIN: "nobody" })).toMatch(/DATABASTION_LOCAL_LOGIN/);
  });

  it("requires the issuer, client, secret, public URL and a usable server key", () => {
    expect(error(env({ DATABASTION_OIDC_ISSUER_URL: undefined }))).toMatch(/ISSUER_URL/);
    expect(error(env({ DATABASTION_OIDC_CLIENT_ID: undefined }))).toMatch(/CLIENT_ID/);
    expect(error(env({ DATABASTION_OIDC_CLIENT_SECRET: undefined }))).toMatch(/CLIENT_SECRET/);
    expect(error(env({ DATABASTION_PUBLIC_URL: undefined }))).toMatch(/DATABASTION_PUBLIC_URL/);
    expect(error(env({ DATABASTION_ENCRYPTION_KEY: undefined }))).toMatch(/DATABASTION_ENCRYPTION_KEY/);
    expect(error(env({ DATABASTION_ENCRYPTION_KEY: "short" }))).toMatch(/DATABASTION_ENCRYPTION_KEY/);
    // The override for the other protections does not apply to OIDC.
    expect(startupFatal({ ...env({ DATABASTION_ENCRYPTION_KEY: undefined }), NODE_ENV: "production", DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY: "1" })).toMatch(/OIDC/);
  });

  it("never puts the client secret or a _FILE content in an error", () => {
    const messages = [
      error(env({ DATABASTION_OIDC_CLIENT_SECRET_FILE: "/run/secrets/x" })),
      error(env({ DATABASTION_OIDC_CLIENT_SECRET: undefined, DATABASTION_OIDC_CLIENT_SECRET_FILE: "/nonexistent" })),
      error(env({ DATABASTION_OIDC_CLIENT_SECRET: undefined, DATABASTION_OIDC_CLIENT_SECRET_FILE: "/x" }), () => "   "),
      error(env({ DATABASTION_OIDC_ISSUER_URL: `https://u:${SECRET}@sso.example.com` })),
      error(env({ DATABASTION_OIDC_CA_FILE: "/ca.pem" }), () => SECRET),
      oidcStartupFatal(env({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" })) ?? "",
    ];
    for (const m of messages) {
      expect(m).not.toBe("ok");
      expect(m).not.toContain(SECRET);
      expect(m).not.toContain("hunter2");
    }
    expect(loadOidcConfig(env({ DATABASTION_OIDC_CLIENT_SECRET: undefined, DATABASTION_OIDC_CLIENT_SECRET_FILE: "/x" }), () => `${SECRET}\n`)?.clientSecret).toBe(SECRET);
  });

  it("sign-up guard: ALLOW_SIGN_UP=1 needs allowed groups or a strict role expression", () => {
    expect(error(env({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" }))).toMatch(/ALLOW_SIGN_UP/);
    expect(error(env({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "role", DATABASTION_OIDC_ROLE_ATTRIBUTE_STRICT: "0" }))).toMatch(/ALLOW_SIGN_UP/);
    expect(error(env({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "role" }))).toBe("ok");
    expect(error(env({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_ALLOWED_GROUPS: "g", DATABASTION_OIDC_GROUPS_ATTRIBUTE_PATH: "groups" }))).toBe("ok");
    expect(error(env({ DATABASTION_OIDC_ALLOWED_GROUPS: "g" }))).toMatch(/GROUPS_ATTRIBUTE_PATH/);
  });

  it("refuses none / HS* algorithms, plain-HTTP issuers in production, bad expressions and long sessions", () => {
    expect(error(env({ DATABASTION_OIDC_ID_TOKEN_ALGS: "RS256,none" }))).toMatch(/ID_TOKEN_ALGS/);
    expect(error(env({ DATABASTION_OIDC_ID_TOKEN_ALGS: "HS256" }))).toMatch(/ID_TOKEN_ALGS/);
    expect(error(env({ DATABASTION_OIDC_ISSUER_URL: "http://sso.example.com" }))).toMatch(/ISSUER_URL/);
    expect(error(env({ DATABASTION_OIDC_ISSUER_URL: "http://127.0.0.1:8080/realms/x" }))).toBe("ok");
    expect(error(env({ NODE_ENV: "production", DATABASTION_OIDC_ISSUER_URL: "http://127.0.0.1:8080/realms/x" }))).toMatch(/ISSUER_URL/);
    expect(error(env({ DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "groups[" }))).toMatch(/ROLE_ATTRIBUTE_PATH/);
    expect(error(env({ DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: `'${"a".repeat(1100)}'` }))).toMatch(/1024 bytes/);
    expect(error(env({ DATABASTION_OIDC_SESSION_MAX_AGE: "13h" }))).toMatch(/SESSION_MAX_AGE/);
    expect(loadOidcConfig(env({ DATABASTION_OIDC_SESSION_MAX_AGE: "8h" }))?.sessionMaxAgeMs).toBe(8 * 3600_000);
    expect(error(env({ DATABASTION_OIDC_TOKEN_AUTH_METHOD: "private_key_jwt" }))).toMatch(/TOKEN_AUTH_METHOD/);
    expect(error(env({ DATABASTION_OIDC_ENABLED: "yes" }))).toMatch(/ENABLED/);
    expect(error(env({ DATABASTION_OIDC_ALLOWED_DOMAINS: "*.example.com" }))).toMatch(/ALLOWED_DOMAINS/);
    expect(parseDuration("90m")).toBe(90 * 60_000);
    expect(parseDuration("1d")).toBeNull();
  });

  it("is fatal at startup in every environment", () => {
    expect(startupFatal(env({ DATABASTION_OIDC_CLIENT_ID: undefined }))).toMatch(/OIDC login configuration error/);
    expect(startupFatal(env())).toBeNull();
  });
});
