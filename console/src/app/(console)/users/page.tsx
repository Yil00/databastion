import { notFound } from "next/navigation";

import { UsersAdmin } from "@/components/console/users-admin";
import { getDb } from "@/db/client";
import { oidcProvider, oidcRoleSyncOn } from "@/server/oidc/runtime";
import { requirePageSession } from "@/server/ui-session";
import { listPendingLogins, listUsers } from "@/server/users-admin";

export const dynamic = "force-dynamic";

/** Admin only: users, roles, disabling, and pending single sign-on logins (ADR-0038). */
export default async function UsersPage() {
  const session = await requirePageSession();
  if (session.user.role !== "admin") notFound();
  const db = getDb();
  const users = await listUsers(db);
  const roleSyncOn = oidcRoleSyncOn();
  const { pending, evicted } = await listPendingLogins(db, roleSyncOn);
  const oidcEnabled = oidcProvider() !== null;
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
      <UsersAdmin users={users} pending={pending} evicted={evicted} oidcEnabled={oidcEnabled} roleSyncOn={roleSyncOn} currentUserId={session.user.id} csrfToken={session.csrfToken} />
    </div>
  );
}
