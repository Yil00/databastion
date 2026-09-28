import { handleRotateChannelSecret } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** New signing secret of a webhook channel (admin, CSRF), returned once. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleRotateChannelSecret(req, (await ctx.params).id);
}
