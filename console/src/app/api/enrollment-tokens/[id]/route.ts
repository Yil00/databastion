import { handleRevokeToken } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function DELETE(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
): Promise<Response> {
  return handleRevokeToken(req, (await ctx.params).id);
}
