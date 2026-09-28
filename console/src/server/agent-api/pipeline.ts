import { checkSemantics, validateSchema, type SchemaName, type Schemas } from "@/lib/protocol/validate";
import { errorSummary, logger } from "@/lib/logger";
import { readJsonBody } from "@/server/request";

import { agentError, invalidRequest, NO_STORE, unavailable } from "./errors";

/** Protocol major versions accepted on /api/agent/v1. */
export const CONSOLE_MIN_PROTOCOL = 1;
export const MAX_PROTOCOL_V1 = 1;
export const HEARTBEAT_INTERVAL_S = 30;

const PROTOCOL_HEADER = /^[0-9]{1,3}$/;
const USER_AGENT = /^databastion-agent\/[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]*)?$/;

/**
 * Required headers of every agent request (`X-DataBastion-Protocol`, `User-Agent`).
 * A protocol below the console minimum is answered `426` with `min_protocol`.
 */
export function checkProtocolHeaders(req: Request): Response | null {
  const protocol = req.headers.get("x-databastion-protocol");
  if (protocol === null || !PROTOCOL_HEADER.test(protocol)) return invalidRequest();
  const major = Number(protocol);
  if (major < CONSOLE_MIN_PROTOCOL) {
    return agentError(426, "protocol_unsupported", { minProtocol: CONSOLE_MIN_PROTOCOL });
  }
  if (major > MAX_PROTOCOL_V1) return invalidRequest();
  const ua = req.headers.get("user-agent");
  if (ua === null || ua.length > 128 || !USER_AGENT.test(ua)) return invalidRequest();
  return null;
}

/**
 * Reads and validates a request body: 4 MiB cap (413), JSON, then `validateSchema` **and**
 * `checkSemantics` (ROADMAP P1-A Gate: schema-valid alone never counts as contract compliance).
 * The body is never logged.
 */
export async function readValidBody<K extends SchemaName>(
  req: Request,
  name: K,
): Promise<{ ok: true; value: Schemas[K] } | { ok: false; response: Response }> {
  const body = await readJsonBody(req);
  if (!body.ok) {
    if (body.reason === "too_large") {
      return { ok: false, response: agentError(413, "payload_too_large") };
    }
    return { ok: false, response: invalidRequest() };
  }
  const schema = validateSchema(name, body.value);
  if (!schema.ok) return { ok: false, response: invalidRequest(schema.details) };
  const semantics = checkSemantics(name, schema.value);
  if (!semantics.ok) return { ok: false, response: invalidRequest(semantics.details) };
  return { ok: true, value: semantics.value };
}

/**
 * Serializes a console -> agent body after validating it against the contract (defense in depth,
 * security review M2). A non-conforming outgoing body is a console bug: `500`, never sent.
 */
export function conformingJson<K extends SchemaName>(
  name: K,
  value: Schemas[K],
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const schema = validateSchema(name, value);
  const ok = schema.ok && checkSemantics(name, schema.value).ok;
  if (!ok) {
    logger.error({ schema: name }, "outgoing agent API body does not conform to the contract");
    return agentError(500, "internal");
  }
  return Response.json(value, {
    status: init.status ?? 200,
    headers: { ...NO_STORE, ...init.headers },
  });
}

/** Maps unexpected failures (e.g. database down) to `503` without leaking details. */
export async function guarded(route: string, fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    logger.error({ route, error: errorSummary(err) }, "agent API request failed");
    return unavailable();
  }
}
