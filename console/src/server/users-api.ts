import { getDb } from "@/db/client";
import { readJsonBody } from "@/server/request";
import { oidcProvider } from "@/server/oidc/runtime";
import { guardedUser, requireUser } from "@/server/user-api";
import {
  approvePendingLogin,
  createLocalUser,
  discardPendingLogin,
  listPendingLogins,
  listUsers,
  setUserDisabled,
  setUserRole,
  type AdminResult,
  type Role,
} from "@/server/users-admin";

/**
 * User management API (admin only; ADR-0038): `GET/POST /api/users`, `PATCH /api/users/:id`,
 * `GET /api/oidc/pending-logins`, `POST` (approve) / `DELETE` (discard)
 * `/api/oidc/pending-logins/:id`. Same-origin + CSRF on every state-changing request, audit
 * logged in `users-admin.ts`.
 */

const NO_STORE = { "Cache-Control": "no-store" } as const;
const MAX_BODY = 16 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const json = (body: unknown, status = 200) => Response.json(body, { status, headers: NO_STORE });
const error = (status: number, code: string) => json({ error: code }, status);
const isRole = (v: unknown): v is Role => v === "admin" || v === "analyst";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
const onlyKeys = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).every((k) => allowed.includes(k));

function result(r: AdminResult<object>, okStatus = 200): Response {
  if (!r.ok) return error(r.status, r.code);
  const { ok: _ok, ...rest } = r as { ok: true } & Record<string, unknown>;
  return json(Object.keys(rest).length > 0 ? rest : { ok: true }, okStatus);
}

async function body(req: Request): Promise<Record<string, unknown> | null> {
  const b = await readJsonBody(req, MAX_BODY);
  return b.ok && isPlainObject(b.value) ? b.value : null;
}

/** Role sync is on when OIDC maps roles and SKIP_ROLE_SYNC is off (ADR-0038 decision 9). */
function roleSyncOn(): boolean {
  const p = oidcProvider();
  return p !== null && !p.config.skipRoleSync;
}

export function handleListUsers(req: Request): Promise<Response> {
  return guardedUser("user.list", async () => {
    const g = await requireUser(req, { admin: true, route: "user.list" });
    if (!g.ok) return g.response;
    return json({ users: await listUsers(getDb()) });
  });
}

export function handleCreateUser(req: Request): Promise<Response> {
  return guardedUser("user.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "user.create" });
    if (!g.ok) return g.response;
    const v = await body(req);
    if (!v || !onlyKeys(v, ["username", "password", "role"]) || typeof v.username !== "string" || typeof v.password !== "string" || !isRole(v.role)) {
      return error(400, "invalid_request");
    }
    return result(await createLocalUser(getDb(), { username: v.username, password: v.password, role: v.role }, { userId: g.session.user.id, ip: g.ip }), 201);
  });
}

export function handleUpdateUser(req: Request, id: string): Promise<Response> {
  return guardedUser("user.update", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "user.update" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const v = await body(req);
    if (!v || !onlyKeys(v, ["role", "disabled"]) || (v.role !== undefined && !isRole(v.role)) || (v.disabled !== undefined && typeof v.disabled !== "boolean") || Object.keys(v).length !== 1) {
      return error(400, "invalid_request");
    }
    const actor = { userId: g.session.user.id, ip: g.ip };
    if (isRole(v.role)) return result(await setUserRole(getDb(), id, v.role, actor, roleSyncOn()));
    return result(await setUserDisabled(getDb(), id, v.disabled === true, actor));
  });
}

export function handleListPendingLogins(req: Request): Promise<Response> {
  return guardedUser("oidc_pending_login.list", async () => {
    const g = await requireUser(req, { admin: true, route: "oidc_pending_login.list" });
    if (!g.ok) return g.response;
    return json(await listPendingLogins(getDb()));
  });
}

export function handleApprovePendingLogin(req: Request, id: string): Promise<Response> {
  return guardedUser("oidc_pending_login.approve", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "oidc_pending_login.approve" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const v = await body(req);
    if (!v || !onlyKeys(v, ["role"]) || !isRole(v.role)) return error(400, "invalid_request");
    return result(await approvePendingLogin(getDb(), id, v.role, { userId: g.session.user.id, ip: g.ip }), 201);
  });
}

export function handleDiscardPendingLogin(req: Request, id: string): Promise<Response> {
  return guardedUser("oidc_pending_login.discard", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "oidc_pending_login.discard" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    return result(await discardPendingLogin(getDb(), id, { userId: g.session.user.id, ip: g.ip }));
  });
}
