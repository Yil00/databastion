import { handleTestChannel } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Queues a test notification (admin, CSRF). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleTestChannel(req, (await ctx.params).id);
}
