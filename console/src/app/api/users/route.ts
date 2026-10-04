import { handleCreateUser, handleListUsers } from "@/server/users-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleListUsers(req);
}

export function POST(req: Request): Promise<Response> {
  return handleCreateUser(req);
}
