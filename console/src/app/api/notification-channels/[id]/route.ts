import { handleDeleteChannel, handleUpdateChannel } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Updates a notification channel (admin, CSRF). */
export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleUpdateChannel(req, (await ctx.params).id);
}

/** Deletes a notification channel (admin, CSRF); its delivery records are kept. */
export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleDeleteChannel(req, (await ctx.params).id);
}
