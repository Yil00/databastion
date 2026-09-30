import { handleJobStatus } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/jobs/{job_id}/status (contract: shared/protocol/openapi.yaml). */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ job_id: string }> },
): Promise<Response> {
  const { job_id: jobId } = await ctx.params;
  return handleJobStatus(req, jobId);
}
