import { handleUnlinkIdentity } from "@/server/users-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(req: Request, ctx: { params: Promise<{ id: string; identityId: string }> }): Promise<Response> {
  const { id, identityId } = await ctx.params;
  return handleUnlinkIdentity(req, id, identityId);
}
