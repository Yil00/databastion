import Link from "next/link";
import type { ReactNode } from "react";

import { LogoutButton } from "@/components/console/logout-button";
import { requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

export default async function ConsoleLayout({ children }: { children: ReactNode }) {
  const session = await requirePageSession();
  return (
    <div className="min-h-screen">
      <header className="border-b">
        <nav className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-3 text-sm">
          <span className="font-semibold">DataBastion</span>
          <Link href="/agents" className="hover:underline">
            Agents
          </Link>
          <Link href="/findings" prefetch={false} className="hover:underline">
            Findings
          </Link>
          <Link href="/events" prefetch={false} className="hover:underline">
            Access events
          </Link>
          <Link href="/incidents" prefetch={false} className="hover:underline">
            Incidents
          </Link>
          <Link href="/policies" prefetch={false} className="hover:underline">
            Policies
          </Link>
          {session.user.role === "admin" && (
            <>
              <Link href="/notifications" prefetch={false} className="hover:underline">
                Notifications
              </Link>
              <Link href="/enrollment-tokens" className="hover:underline">
                Enrollment tokens
              </Link>
              <Link href="/users" prefetch={false} className="hover:underline">
                Users
              </Link>
            </>
          )}
          <Link href="/account" prefetch={false} className="ml-auto text-muted-foreground hover:underline">
            {session.user.username} ({session.user.role})
          </Link>
          <LogoutButton csrfToken={session.csrfToken} />
        </nav>
      </header>
      <main className="mx-auto max-w-6xl p-6">{children}</main>
    </div>
  );
}
