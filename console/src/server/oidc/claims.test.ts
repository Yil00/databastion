import { describe, expect, it } from "vitest";

import { compileExpression, emailDomain, mapClaims, type ClaimMappingConfig } from "./claims";

const base: ClaimMappingConfig = {
  loginPath: compileExpression("preferred_username"),
  emailPath: compileExpression("email"),
  namePath: compileExpression("name"),
  groupsPath: compileExpression("groups"),
  rolePath: compileExpression("contains(groups[*], 'databastion-admins') && 'admin' || 'analyst'"),
  roleStrict: true,
  allowedGroups: [],
  allowedDomains: [],
};
const cfg = (over: Partial<ClaimMappingConfig> = {}): ClaimMappingConfig => ({ ...base, ...over });

describe("claim mapping (ADR-0038 decision 7)", () => {
  it("maps the Grafana-style role expression on provider-controlled groups", () => {
    const admin = mapClaims({ sub: "1", preferred_username: "Alice", groups: ["databastion-admins"] }, cfg());
    expect(admin).toMatchObject({ ok: true, effectiveRole: "admin", identity: { login: "alice", role: "admin" } });
    const analyst = mapClaims({ sub: "2", preferred_username: "bob", groups: ["staff"] }, cfg());
    expect(analyst).toMatchObject({ ok: true, effectiveRole: "analyst" });
  });

  it("a user editing their own attributes (username, e-mail, name) cannot gain admin", () => {
    const r = mapClaims(
      { sub: "3", preferred_username: "admin", email: "databastion-admins@example.com", name: "databastion-admins", groups: ["staff"], role: "admin" },
      cfg(),
    );
    expect(r).toMatchObject({ ok: true, effectiveRole: "analyst" });
  });

  it("anything but exactly admin / analyst is no role: strict mode refuses, otherwise analyst (never admin)", () => {
    const strict = cfg({ rolePath: compileExpression("role") });
    for (const role of ["Admin", "ADMIN", " admin", ["admin"], { admin: true }, 1, true, null, undefined, "root"]) {
      expect(mapClaims({ preferred_username: "u", role }, strict)).toMatchObject({ ok: false, reason: "role" });
      expect(mapClaims({ preferred_username: "u", role }, { ...strict, roleStrict: false })).toMatchObject({ ok: true, effectiveRole: "analyst" });
    }
    // An evaluation error (contains() on a non-array) is no role too.
    expect(mapClaims({ preferred_username: "u", groups: "databastion-admins" }, cfg())).toMatchObject({ ok: false, reason: "role" });
  });

  it("without a role expression, roles are managed in the console (no role mapped)", () => {
    expect(mapClaims({ preferred_username: "u" }, cfg({ rolePath: null }))).toMatchObject({ ok: true, identity: { role: null }, effectiveRole: "analyst" });
  });

  it("allowed groups: at least one mapped group must match; bounds refuse oversize groups", () => {
    const c = cfg({ allowedGroups: ["databastion-users"] });
    expect(mapClaims({ preferred_username: "u", groups: ["other"] }, c)).toMatchObject({ ok: false, reason: "group" });
    expect(mapClaims({ preferred_username: "u", groups: ["databastion-users"] }, c)).toMatchObject({ ok: true });
    expect(mapClaims({ preferred_username: "u", groups: "databastion-users" }, c)).toMatchObject({ ok: false, reason: "group" });
    expect(mapClaims({ preferred_username: "u", groups: Array.from({ length: 300 }, (_, i) => `g${i}`) }, cfg())).toMatchObject({ ok: false, reason: "group" });
    expect(mapClaims({ preferred_username: "u", groups: ["x".repeat(300)] }, cfg())).toMatchObject({ ok: false, reason: "group" });
  });

  it("allowed domains: verified e-mail, exact domain after the last @, never a suffix", () => {
    const c = cfg({ allowedDomains: ["example.com"] });
    const ok = (email: string, verified: unknown = true) => mapClaims({ preferred_username: "u", groups: [], email, email_verified: verified }, c);
    expect(ok("a@example.com")).toMatchObject({ ok: true });
    expect(ok("a@EXAMPLE.com")).toMatchObject({ ok: true });
    expect(ok("a@example.com", false)).toMatchObject({ ok: false, reason: "email_unverified" });
    expect(ok("a@example.com", "true")).toMatchObject({ ok: false, reason: "email_unverified" });
    expect(ok("a@evil-example.com")).toMatchObject({ ok: false, reason: "domain" });
    expect(ok("a@sub.example.com")).toMatchObject({ ok: false, reason: "domain" });
    expect(ok("a@example.com.evil.net")).toMatchObject({ ok: false, reason: "domain" });
    expect(ok("example.com@evil.net")).toMatchObject({ ok: false, reason: "domain" });
    expect(emailDomain("a@b@example.com")).toBe("example.com");
  });

  it("the login claim must be a valid console username (lower-cased, never rewritten)", () => {
    expect(mapClaims({ preferred_username: "Jane.Doe", groups: [] }, cfg())).toMatchObject({ ok: true, identity: { login: "jane.doe" } });
    for (const bad of ["jane doe", "-jane", "", "é", "a".repeat(65), 42, null]) {
      expect(mapClaims({ preferred_username: bad, groups: [] }, cfg())).toMatchObject({ ok: false, reason: "username" });
    }
  });

  it("refuses claims over 64 KiB and treats prototype-like claim names as plain data", () => {
    expect(mapClaims({ preferred_username: "u", pad: "x".repeat(70_000) }, cfg())).toMatchObject({ ok: false, reason: "id_token" });
    const proto = JSON.parse('{"preferred_username":"u","groups":[],"__proto__":{"role":"admin"}}') as Record<string, unknown>;
    expect(mapClaims(proto, cfg({ rolePath: compileExpression("role"), roleStrict: false }))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims({ preferred_username: "u" }, cfg({ rolePath: compileExpression("constructor"), roleStrict: true }))).toMatchObject({ ok: false, reason: "role" });
  });

  it("rejects invalid expressions at configuration time", () => {
    expect(() => compileExpression("groups[")).toThrow();
  });
});
