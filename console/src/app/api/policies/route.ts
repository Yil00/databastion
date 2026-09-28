import { handleCreatePolicy } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Creates a policy (admin, CSRF). */
export async function POST(req: Request): Promise<Response> {
  return handleCreatePolicy(req);
}
