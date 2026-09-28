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
          {session.user.role === "admin" && (
            <Link href="/enrollment-tokens" className="hover:underline">
              Enrollment tokens
            </Link>
          )}
          <span className="ml-auto text-muted-foreground">
            {session.user.username} ({session.user.role})
          </span>
          <LogoutButton csrfToken={session.csrfToken} />
        </nav>
      </header>
      <main className="mx-auto max-w-6xl p-6">{children}</main>
    </div>
  );
}
