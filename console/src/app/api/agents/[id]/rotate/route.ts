import { handleRotateAgent } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Queues an `agent.rotate_secret` job (admin, CSRF). The job carries no secret (ADR-0008). */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
): Promise<Response> {
  return handleRotateAgent(req, (await ctx.params).id);
}
