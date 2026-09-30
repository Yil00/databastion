import { handleEvents } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/events (contract: shared/protocol/openapi.yaml, P4-C). */
export function POST(req: Request): Promise<Response> {
  return handleEvents(req);
}
