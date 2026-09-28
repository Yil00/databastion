import { handleFalsePositive } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Marks or unmarks a finding as a false positive (`{"false_positive": boolean}`, CSRF). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleFalsePositive(req, (await ctx.params).id);
}
