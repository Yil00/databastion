import { handleListPendingLogins } from "@/server/users-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleListPendingLogins(req);
}
