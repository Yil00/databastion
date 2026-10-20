import { handleCaseInventory } from "@/server/user-api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Runs the case-sensitive exception inventory (ADR-0054 decision 6; admin, CSRF). */
export async function POST(req: Request): Promise<Response> {
  return handleCaseInventory(req);
}
