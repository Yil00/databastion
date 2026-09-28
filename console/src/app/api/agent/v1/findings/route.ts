import { handleFindings } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/findings (contract: shared/protocol/openapi.yaml, P2-D). */
export function POST(req: Request): Promise<Response> {
  return handleFindings(req);
}
