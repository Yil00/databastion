import { notFound } from "next/navigation";

import { EnrollmentTokens } from "@/components/console/enrollment-tokens";
import { getDb } from "@/db/client";
import { listEnrollmentTokens } from "@/server/enrollment";
import { requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/** Admin only. Lists token metadata (the tokens themselves are never stored). */
export default async function EnrollmentTokensPage() {
  const session = await requirePageSession();
  if (session.user.role !== "admin") notFound();
  const tokens = (await listEnrollmentTokens(getDb())).map((t) => ({
    id: t.id,
    label: t.label,
    state: t.state,
    createdAt: t.createdAt.toISOString(),
    expiresAt: t.expiresAt.toISOString(),
    consumedByAgentId: t.consumedByAgentId,
  }));
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold tracking-tight">Enrollment tokens</h1>
      <EnrollmentTokens tokens={tokens} csrfToken={session.csrfToken} />
    </div>
  );
}
