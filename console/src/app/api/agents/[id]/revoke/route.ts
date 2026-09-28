import { handleRevokeAgent } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
): Promise<Response> {
  return handleRevokeAgent(req, (await ctx.params).id);
}
