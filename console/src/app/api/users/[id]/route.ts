import { handleUpdateUser } from "@/server/users-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleUpdateUser(req, (await ctx.params).id);
}
