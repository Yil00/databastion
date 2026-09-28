import { handleRotate } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/rotate (contract: shared/protocol/openapi.yaml, ADR-0008, ADR-0010). */
export function POST(req: Request): Promise<Response> {
  return handleRotate(req);
}
