import { handleIncidentTransition } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Moves an incident through its lifecycle (`{"status": ...}`, CSRF; `false_positive`: admin). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handleIncidentTransition(req, (await ctx.params).id);
}
