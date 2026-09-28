import Link from "next/link";

import { AgentsTable } from "@/components/console/agents-table";
import { getDb } from "@/db/client";
import { listAgents } from "@/server/agents";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

export default async function AgentsPage() {
  const session = await requirePageSession();
  const agents = await listAgents(getDb());
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
        {session.user.role === "admin" && (
          <Link href="/enrollment-tokens" className="text-sm hover:underline">
            Enroll an agent
          </Link>
        )}
      </div>
      <AgentsTable agents={agents} now={requestTime()} />
    </div>
  );
}
