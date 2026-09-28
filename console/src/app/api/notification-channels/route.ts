import { handleCreateChannel, handleListChannels } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Lists the notification channels (admin; never a secret). */
export async function GET(req: Request): Promise<Response> {
  return handleListChannels(req);
}

/** Creates a notification channel (admin, CSRF). */
export async function POST(req: Request): Promise<Response> {
  return handleCreateChannel(req);
}
