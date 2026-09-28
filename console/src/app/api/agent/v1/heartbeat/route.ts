import { handleHeartbeat } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/heartbeat (contract: shared/protocol/openapi.yaml). */
export function POST(req: Request): Promise<Response> {
  return handleHeartbeat(req);
}
