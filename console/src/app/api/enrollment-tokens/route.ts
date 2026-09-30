import { handleCreateToken, handleListTokens } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleListTokens(req);
}

export function POST(req: Request): Promise<Response> {
  return handleCreateToken(req);
}
