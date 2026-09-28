import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { eq } from "drizzle-orm";

import { getDb } from "@/db/client";
import { users } from "@/db/schema";
import bundle from "@/generated/protocol/schemas.gen.json";
import { validateSchema } from "@/lib/protocol/validate";
import { bootstrapAdmin } from "@/server/auth/users";
import { createEnrollmentToken } from "@/server/enrollment";
import { handleEnroll } from "@/server/agent-api/handlers";

export const FIXTURES = path.resolve(__dirname, "../../../shared/protocol/fixtures");

export function fixtures(kind: "valid" | "invalid", schema: string): [string, unknown][] {
  const dir = path.join(FIXTURES, kind);
  return readdirSync(dir)
    .filter((f) => f.startsWith(`${schema}.`) && f.endsWith(".json"))
    .map((f) => [f, JSON.parse(readFileSync(path.join(dir, f), "utf8")) as unknown]);
}

export const BASE = "http://console.test/api/agent/v1";

export function agentHeaders(auth?: { agentId: string; secret: string }): Record<string, string> {
  const h: Record<string, string> = {
    "X-DataBastion-Protocol": "1",
    "User-Agent": "databastion-agent/0.1.0",
    "Content-Type": "application/json",
  };
  if (auth) {
    h["X-DataBastion-Agent-Id"] = auth.agentId;
    h.Authorization = `Bearer ${auth.secret}`;
  }
  return h;
}

export function agentRequest(
  method: string,
  p: string,
  opts: { body?: unknown; raw?: string; auth?: { agentId: string; secret: string }; headers?: Record<string, string> } = {},
): Request {
  const body = opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body));
  return new Request(`${BASE}${p}`, {
    method,
    headers: { ...agentHeaders(opts.auth), ...opts.headers },
    body,
  });
}

let adminId: string | undefined;

export async function adminUser(): Promise<string> {
  if (adminId) return adminId;
  const [existing] = await getDb().select({ id: users.id }).from(users).where(eq(users.role, "admin")).limit(1);
  adminId = existing?.id ?? (await bootstrapAdmin(getDb(), "admin", "correct horse battery staple"));
  return adminId;
}

export async function newToken(): Promise<string> {
  const userId = await adminUser();
  return (await createEnrollmentToken(getDb(), { userId, ip: "direct" }, null)).token;
}

export async function enroll(hostname = "db-host-1"): Promise<{ agentId: string; secret: string }> {
  const token = await newToken();
  const res = await handleEnroll(
    agentRequest("POST", "/enroll", {
      body: { token, hostname, agent_version: "0.1.0", connectors: ["postgres"] },
    }),
  );
  if (res.status !== 200) throw new Error(`enroll failed: ${res.status}`);
  const body = (await res.json()) as { agent_id: string; agent_secret: string };
  return { agentId: body.agent_id, secret: body.agent_secret };
}

/** Asserts a contract-conforming error body that echoes none of the submitted string values. */
export async function expectConformingError(res: Response, submitted: unknown): Promise<Record<string, unknown>> {
  const text = await res.text();
  const body = JSON.parse(text) as Record<string, unknown>;
  const check = validateSchema("Error", body);
  if (!check.ok) throw new Error(`error body does not conform: ${JSON.stringify(check.details)}`);
  for (const value of stringsOf(submitted)) {
    if (value.length >= 6 && text.includes(value)) {
      throw new Error("error body echoes a submitted value");
    }
  }
  return body;
}

function contractNames(node: unknown, into = new Set<string>()): Set<string> {
  if (Array.isArray(node)) node.forEach((x) => contractNames(x, into));
  else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "properties" && v && typeof v === "object") Object.keys(v).forEach((n) => into.add(n));
      contractNames(v, into);
    }
  }
  return into;
}
const KNOWN = contractNames(bundle);

/** Submitted string values and unknown (non-contract) keys. */
function stringsOf(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => stringsOf(x, out));
  else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (!KNOWN.has(k)) out.push(k);
      stringsOf(x, out);
    }
  }
  return out;
}
