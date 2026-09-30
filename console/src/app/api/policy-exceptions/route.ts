import { handleCreateException } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Creates a policy exception (admin, CSRF). */
export async function POST(req: Request): Promise<Response> {
  return handleCreateException(req);
}
