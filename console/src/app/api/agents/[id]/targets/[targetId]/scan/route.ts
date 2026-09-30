import { handleRequestScan } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Queues a `discovery.scan` job for one target (admin, CSRF). Body: contract `DiscoveryScanParams`. */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string; targetId: string }> },
): Promise<Response> {
  const { id, targetId } = await ctx.params;
  return handleRequestScan(req, id, targetId);
}
