import { handleDeleteException } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Deletes a policy exception (admin, CSRF). */
export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleDeleteException(req, (await ctx.params).id);
}
