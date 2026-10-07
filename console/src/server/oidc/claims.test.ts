import { describe, expect, it } from "vitest";

import { compileExpression, emailDomain, mapClaims, plainPath, type ClaimMappingConfig } from "./claims";

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

describe("JMESPath truthiness on claim objects (security review L2)", () => {
  const keycloak = (expr: string) => cfg({ rolePath: compileExpression(expr), groupsPath: null });
  const claims = { preferred_username: "kc", realm_access: { roles: ["offline_access", "databastion-admin"] }, resource_access: { databastion: { roles: ["viewer"] } } };

  it("evaluates Keycloak-style realm_access.roles expressions with && / || / ! and filters", () => {
    expect(mapClaims(claims, keycloak("realm_access && contains(realm_access.roles, 'databastion-admin') && 'admin' || 'analyst'"))).toMatchObject({ ok: true, effectiveRole: "admin" });
    expect(mapClaims(claims, keycloak("contains(realm_access.roles, 'nope') && 'admin' || 'analyst'"))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims(claims, keycloak("!missing && 'analyst' || 'admin'"))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims(claims, keycloak("!realm_access && 'admin' || 'analyst'"))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims(claims, keycloak("missing || resource_access.databastion && 'analyst'"))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims(claims, keycloak("length(realm_access.roles[?@ == 'databastion-admin']) > `0` && 'admin' || 'analyst'"))).toMatchObject({ ok: true, effectiveRole: "admin" });
    const list = { preferred_username: "kc", grants: [{ name: "databastion", role: "admin" }, { name: "other", role: "x" }] };
    expect(mapClaims(list, keycloak("grants[?name == 'databastion'].role | [0]"))).toMatchObject({ ok: true, effectiveRole: "admin" });
  });

  it("keeps __proto__, constructor and hasOwnProperty claim keys as data, without pollution", () => {
    const raw = JSON.parse('{"preferred_username":"kc","__proto__":{"role":"admin"},"constructor":"admin","x":{"hasOwnProperty":"admin"}}') as Record<string, unknown>;
    expect(mapClaims(raw, keycloak("role"))).toMatchObject({ ok: false, reason: "role" });
    expect(mapClaims(raw, keycloak("__proto__.role"))).toMatchObject({ ok: true, effectiveRole: "admin" });
    expect(mapClaims(raw, keycloak("constructor"))).toMatchObject({ ok: true, effectiveRole: "admin" });
    // Nothing inherited is reachable when the claim is absent.
    expect(mapClaims({ preferred_username: "kc" }, keycloak("constructor"))).toMatchObject({ ok: false, reason: "role" });
    expect(mapClaims({ preferred_username: "kc" }, keycloak("toString"))).toMatchObject({ ok: false, reason: "role" });
    // A claim named hasOwnProperty makes truthiness tests on its object an error: no role.
    expect(mapClaims(raw, keycloak("x && 'admin' || 'analyst'"))).toMatchObject({ ok: false, reason: "role" });
    expect(({} as Record<string, unknown>).role).toBeUndefined();
  });
});

describe("the role expression sees the validated groups (end-of-phase-8 review L5)", () => {
  // The documented example (docs/10-user-guide.md, console/README.md, deploy/docker-compose.example.yml).
  const DOC_ROLE = "contains(groups, 'databastion-admins') && 'admin' || contains(groups, 'databastion-analysts') && 'analyst'";
  const doc = (over: Partial<ClaimMappingConfig> = {}) => cfg({ rolePath: compileExpression(DOC_ROLE), ...over });

  it("a string groups claim is never a substring match: the documented example does not yield admin", () => {
    const claims = { preferred_username: "u", groups: "x-databastion-admins-y" };
    expect(mapClaims(claims, doc())).toMatchObject({ ok: false, reason: "role" });
    const lax = mapClaims(claims, doc({ roleStrict: false }));
    expect(lax).toMatchObject({ ok: true, effectiveRole: "analyst", identity: { role: null, groups: [] } });
    // Also without a groups expression (the raw `groups` claim), and for an exact string.
    expect(mapClaims(claims, doc({ groupsPath: null, roleStrict: false }))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    expect(mapClaims({ preferred_username: "u", groups: "databastion-admins" }, doc({ roleStrict: false }))).toMatchObject({ ok: true, effectiveRole: "analyst" });
    // A string group never passes the group filter either.
    expect(mapClaims({ preferred_username: "u", groups: "databastion-admins" }, doc({ allowedGroups: ["databastion-admins"] }))).toMatchObject({ ok: false, reason: "group" });
    // The array form still maps.
    expect(mapClaims({ preferred_username: "u", groups: ["databastion-admins"] }, doc())).toMatchObject({ ok: true, effectiveRole: "admin" });
    expect(mapClaims({ preferred_username: "u", groups: ["x-databastion-admins-y", "databastion-analysts"] }, doc())).toMatchObject({ ok: true, effectiveRole: "analyst" });
  });

  it("replaces the claim at a plain groups path, and exposes the mapped groups as `groups`", () => {
    const nested = { preferred_username: "u", realm_access: { roles: "x-databastion-admins-y" } };
    const viaPath = cfg({ groupsPath: compileExpression("realm_access.roles"), rolePath: compileExpression("contains(realm_access.roles, 'databastion-admins') && 'admin' || 'analyst'"), roleStrict: false });
    expect(mapClaims(nested, viaPath)).toMatchObject({ ok: true, effectiveRole: "analyst" });
    const viaGroups = cfg({ groupsPath: compileExpression("realm_access.roles"), rolePath: compileExpression(DOC_ROLE) });
    expect(mapClaims({ preferred_username: "u", groups: ["databastion-admins"], realm_access: { roles: ["databastion-analysts"] } }, viaGroups)).toMatchObject({ ok: true, effectiveRole: "analyst" });
    const quoted = cfg({ groupsPath: compileExpression('resource_access."databastion-console".roles[*]'), rolePath: compileExpression(DOC_ROLE) });
    expect(mapClaims({ preferred_username: "u", resource_access: { "databastion-console": { roles: ["databastion-admins"] } } }, quoted)).toMatchObject({ ok: true, effectiveRole: "admin" });
    // A filtering groups expression: the role expression sees its result.
    const filtered = cfg({ groupsPath: compileExpression("groups[?starts_with(@, 'databastion-')]"), rolePath: compileExpression(DOC_ROLE) });
    expect(mapClaims({ preferred_username: "u", groups: ["databastion-analysts", "other"] }, filtered)).toMatchObject({ ok: true, effectiveRole: "analyst", identity: { groups: ["databastion-analysts"] } });
  });

  it("parses plain paths only", () => {
    expect(plainPath("groups")).toEqual(["groups"]);
    expect(plainPath("realm_access.roles[*]")).toEqual(["realm_access", "roles"]);
    expect(plainPath('resource_access."a-b".roles')).toEqual(["resource_access", "a-b", "roles"]);
    for (const p of ["groups[?x]", "a..b", "a.", "foo(bar)", "a[0]", "a | b"]) expect(plainPath(p)).toBeNull();
  });
});
