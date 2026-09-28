import { handleListAgents } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleListAgents(req);
}
