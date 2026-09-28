import { handleDeletePolicy, handleUpdatePolicy } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Updates a policy (admin, CSRF). */
export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleUpdatePolicy(req, (await ctx.params).id);
}

/** Deletes a policy (admin, CSRF); its incidents are kept. */
export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleDeletePolicy(req, (await ctx.params).id);
}
