import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, agents, agentTargets, eventsBatches, findings, findingsBatches, securityEvents } from "@/db/schema";
import { MAX_VALIDATION_DETAILS } from "@/lib/protocol/validate";
import { integrityWriteBudget } from "@/server/integrity";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, expectConformingError, fixtures, newToken, uuidv7 } from "@/test/helpers";

import { failuresPerAgent } from "./auth";
import type * as Capabilities from "./capabilities";
import { CONSOLE_ACCEPTS, connectorTokens, unlistedEngineDetails } from "./capabilities";
import {
  enrollPerIp,
  eventsPerAgent,
  eventsRequestsPerAgent,
  findingsPerAgent,
  findingsRequestsPerAgent,
  handleEnroll,
  handleEvents,
  handleFindings,
  handleHeartbeat,
} from "./handlers";

/**
 * The engine-token gate at handler level (ADR-0042, P9-C review H1; security review L1 of #391).
 * Since P10-E this console lists every engine token of the contract, so no fixture reaches the gate
 * through the real `CONSOLE_ACCEPTS`. Here `unlistedEngineDetails` runs, by default, against
 * `CONSOLE_ACCEPTS` minus one engine token ({@link gate}), as a console built before that engine
 * would: each endpoint must answer `400` `invalid_request` with the `enum` pointers, record one
 * `agent.batch_rejected` on `/findings` and `/events`, and store nothing.
 */
const gate = vi.hoisted(() => ({ withheld: "engine.firebird" }));

vi.mock("./capabilities", async (importOriginal) => {
  const actual = await importOriginal<typeof Capabilities>();
  return {
    ...actual,
    unlistedEngineDetails: (...args: Parameters<typeof actual.unlistedEngineDetails>) => {
      const [name, value, accepts] = args;
      return actual.unlistedEngineDetails(name, value, accepts ?? actual.CONSOLE_ACCEPTS.filter((t) => t !== gate.withheld));
    },
  };
});


type Auth = { agentId: string; secret: string };
type Detail = { pointer: string; keyword: string };

const ENGINE_TOKENS = CONSOLE_ACCEPTS.filter((t) => t.startsWith("engine."));
const CONNECTORS = ["cas", "sqlserver", "redis", "sqlite", "firebird"] as const;

/** Details of the real gate for `CONSOLE_ACCEPTS` minus `token` (the expected answer). */
function expected(name: Parameters<typeof unlistedEngineDetails>[0], body: unknown, token: string): Detail[] {
  return unlistedEngineDetails(name, body, CONSOLE_ACCEPTS.filter((t) => t !== token));
}

function gated(name: "HeartbeatRequest" | "FindingsBatch" | "EventsBatch", token: string): [string, unknown][] {
  return fixtures("valid", name).filter(([, body]) => expected(name, body, token).length > 0);
}

async function integrityRows(agentId: string, kind: string) {
  return getDb()
    .select()
    .from(securityEvents)
    .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, kind)));
}

describe.skipIf(!hasDb)("engine-token gate in the handlers (PostgreSQL)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => teardown?.());
  beforeEach(() => {
    gate.withheld = "engine.firebird";
    enrollPerIp.clear();
    failuresPerAgent.clear();
    integrityWriteBudget.clear();
    findingsPerAgent.clear();
    findingsRequestsPerAgent.clear();
    eventsPerAgent.clear();
    eventsRequestsPerAgent.clear();
  });

  it("the mock withholds exactly one token, and every engine token has gated fixtures", () => {
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["firebird"] })).toEqual([{ pointer: "/connectors/0", keyword: "enum" }]);
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["firebird"] }, CONSOLE_ACCEPTS)).toEqual([]);
    for (const token of ENGINE_TOKENS) expect(gated("HeartbeatRequest", token).length, token).toBeGreaterThan(0);
    expect(gated("FindingsBatch", "engine.firebird").map(([f]) => f)).toContain("FindingsBatch.firebird.json");
    expect(gated("EventsBatch", "engine.firebird").map(([f]) => f)).toContain("EventsBatch.firebird.json");
  });

  describe.each(ENGINE_TOKENS)("withholding %s", (token) => {
    beforeEach(() => {
      gate.withheld = token;
    });

    it.each(CONNECTORS.filter((c) => connectorTokens(c).includes(token as never)))(
      "POST /enroll with the %s connector -> 400 enum, no agent, token not consumed",
      async (connector) => {
        const before = (await getDb().select({ id: agents.id }).from(agents)).length;
        const tokenValue = await newToken();
        const body = { token: tokenValue, hostname: "db-host-1", agent_version: "0.1.0", connectors: ["postgres", connector] };
        const res = await handleEnroll(agentRequest("POST", "/enroll", { body }));
        expect(res.status).toBe(400);
        const err = await expectConformingError(res, body);
        expect(err.code).toBe("invalid_request");
        expect(err.details).toEqual([{ pointer: "/connectors/1", keyword: "enum" }]);
        expect((await getDb().select({ id: agents.id }).from(agents)).length).toBe(before);
        // The same token still enrolls once the connector is left out (it was not consumed).
        const ok = await handleEnroll(agentRequest("POST", "/enroll", { body: { ...body, connectors: ["postgres"] } }));
        expect(ok.status).toBe(200);
      },
    );

    it.each(gated("HeartbeatRequest", token))("POST /heartbeat %s -> 400 enum, nothing stored", async (_f, body) => {
      const auth: Auth = await enroll();
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.code).toBe("invalid_request");
      expect(err.details).toEqual(expected("HeartbeatRequest", body, token));
      expect((err.details as Detail[]).every((d) => d.keyword === "enum")).toBe(true);
      expect(await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId))).toHaveLength(0);
    });

    it.each(gated("FindingsBatch", token))("POST /findings %s -> 400 enum, one batch_rejected, nothing stored", async (_f, fixture) => {
      const auth: Auth = await enroll();
      const body = { ...(structuredClone(fixture) as Record<string, unknown>), job_id: uuidv7(), batch_id: uuidv7() };
      const res = await handleFindings(agentRequest("POST", "/findings", { auth, body }));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.code).toBe("invalid_request");
      const details = expected("FindingsBatch", body, token);
      expect(details.every((d) => /^\/findings\/\d+\/location\/engine$/.test(d.pointer) && d.keyword === "enum")).toBe(true);
      expect(err.details).toEqual(details);
      const rejected = await integrityRows(auth.agentId, "agent.batch_rejected");
      expect(rejected).toHaveLength(1);
      expect(rejected[0]?.details).toMatchObject({ endpoint: "findings", status: 400 });
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
      expect(await getDb().select().from(findingsBatches).where(eq(findingsBatches.agentId, auth.agentId))).toHaveLength(0);
    });

    it.each(gated("EventsBatch", token))("POST /events %s -> 400 enum, one batch_rejected, nothing stored", async (_f, fixture) => {
      const auth: Auth = await enroll();
      const body = { ...(structuredClone(fixture) as Record<string, unknown>), batch_id: uuidv7() };
      const res = await handleEvents(agentRequest("POST", "/events", { auth, body }));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.code).toBe("invalid_request");
      const details = expected("EventsBatch", body, token);
      expect(details.every((d) => /^\/events\/\d+\/source$/.test(d.pointer) && d.keyword === "enum")).toBe(true);
      expect(err.details).toEqual(details);
      const rejected = await integrityRows(auth.agentId, "agent.batch_rejected");
      expect(rejected).toHaveLength(1);
      expect(rejected[0]?.details).toMatchObject({ endpoint: "events", status: 400 });
      expect(await getDb().select().from(accessEvents).where(eq(accessEvents.agentId, auth.agentId))).toHaveLength(0);
      expect(await getDb().select().from(eventsBatches).where(eq(eventsBatches.agentId, auth.agentId))).toHaveLength(0);
    });
  });

  it("withholding engine.firebird: the firebird fixtures get the exact pointers", async () => {
    const auth: Auth = await enroll();
    const [, hb] = fixtures("valid", "HeartbeatRequest").find(([f]) => f === "HeartbeatRequest.firebird.json") ?? [];
    const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: hb }));
    expect(res.status).toBe(400);
    const details = (await expectConformingError(res, hb)).details as Detail[];
    const hbBody = hb as { connectors: string[]; targets: { audit_source?: string }[]; detected_targets: unknown[] };
    const want: Detail[] = [];
    hbBody.connectors.forEach((c, i) => c === "firebird" && want.push({ pointer: `/connectors/${i}`, keyword: "enum" }));
    hbBody.targets.forEach((t, i) => {
      want.push({ pointer: `/targets/${i}/engine`, keyword: "enum" });
      if (t.audit_source !== undefined) want.push({ pointer: `/targets/${i}/audit_source`, keyword: "enum" });
    });
    hbBody.detected_targets.forEach((_d, i) => {
      want.push({ pointer: `/detected_targets/${i}/engine`, keyword: "enum" }, { pointer: `/detected_targets/${i}/process`, keyword: "enum" });
    });
    expect(details).toEqual(want.slice(0, details.length));
    expect(details.length).toBe(Math.min(want.length, MAX_VALIDATION_DETAILS));
  });
});
