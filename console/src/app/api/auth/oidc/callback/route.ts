import { handleOidcCallback } from "@/server/oidc/routes";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(req: Request): Promise<Response> {
  return handleOidcCallback(req);
}
