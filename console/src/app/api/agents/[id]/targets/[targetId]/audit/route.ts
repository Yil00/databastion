import { handleConfigureAudit } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Sets the Audit settings of one target and queues an `audit.configure` job (admin, CSRF, P4-C). */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string; targetId: string }> },
): Promise<Response> {
  const { id, targetId } = await ctx.params;
  return handleConfigureAudit(req, id, targetId);
}
