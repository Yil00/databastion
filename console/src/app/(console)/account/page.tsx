import { AccountSettings } from "@/components/console/account-settings";
import { getDb } from "@/db/client";
import { oidcProvider } from "@/server/oidc/runtime";
import { requirePageSession } from "@/server/ui-session";
import { accountView } from "@/server/users-admin";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

/** The current user's account: linked single sign-on identities and "Link single sign-on" (ADR-0038 decision 6). */
export default async function AccountPage({ searchParams }: { searchParams: SearchParams }) {
  const session = await requirePageSession();
  const params = await searchParams;
  const account = await accountView(getDb(), session.user.id);
  const provider = oidcProvider();
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold tracking-tight">Account</h1>
      <AccountSettings
        username={session.user.username}
        role={session.user.role}
        identities={account?.identities ?? []}
        providerName={provider?.config.displayName ?? null}
        canLink={provider !== null && session.method === "local" && (account?.identities.length ?? 0) === 0}
        sessionMethod={session.method}
        linked={params.linked === "1"}
        linkError={params.link_error === "1"}
        csrfToken={session.csrfToken}
      />
    </div>
  );
}
