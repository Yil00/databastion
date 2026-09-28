import { handleLogin } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function POST(req: Request): Promise<Response> {
  return handleLogin(req);
}
