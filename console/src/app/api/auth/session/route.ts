import { handleSession } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleSession(req);
}
