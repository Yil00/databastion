import { handlePollJobs } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** GET /api/agent/v1/jobs?wait= (long-poll, contract: shared/protocol/openapi.yaml). */
export function GET(req: Request): Promise<Response> {
  return handlePollJobs(req);
}
