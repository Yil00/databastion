import { handleApprovePendingLogin, handleDiscardPendingLogin } from "@/server/users-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Approves the pending login as a new user (body: `{ "role": "admin" | "analyst" }`). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleApprovePendingLogin(req, (await ctx.params).id);
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleDiscardPendingLogin(req, (await ctx.params).id);
}
