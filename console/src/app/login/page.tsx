import { redirect } from "next/navigation";

import { LoginForm } from "@/components/console/login-form";
import { Card, CardContent } from "@/components/ui/card";
import { currentLocalLoginMode, oidcProvider } from "@/server/oidc/runtime";
import { pageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const SSO_ERRORS: Record<string, string> = {
  rate_limited: "Too many sign-in attempts. Try again later.",
  unavailable: "Single sign-on is unavailable. Try again later.",
};

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function LoginPage({ searchParams }: { searchParams: SearchParams }) {
  if (await pageSession()) redirect("/agents");
  const params = await searchParams;
  const one = (k: string) => (typeof params[k] === "string" ? params[k] : undefined);
  const provider = oidcProvider();
  const mode = currentLocalLoginMode();
  const ssoError = one("sso_error");
  const forceLocal = one("local") === "1" && mode !== "disabled";
  const loggedOut = one("logged_out") === "1";
  // ADR-0038 decision 12: auto-login, except after a failed attempt (no redirect loop), with
  // ?local=1, or right after a logout (review L4: it would sign the user straight back in).
  if (provider !== null && provider.config.autoLogin && ssoError === undefined && !forceLocal && !loggedOut) redirect("/api/auth/oidc/start");
  const showLocal = mode !== "disabled" && (provider === null || !provider.config.autoLogin || forceLocal || ssoError !== undefined || loggedOut);
  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-6 p-8">
      <h1 className="text-2xl font-semibold tracking-tight">DataBastion</h1>
      {loggedOut && ssoError === undefined && <p role="status" className="text-sm text-muted-foreground">You are signed out.</p>}
      {ssoError !== undefined && (
        // Generic message only: the provider's error description is never shown (decision 5).
        <p role="alert" className="text-sm text-destructive">
          {SSO_ERRORS[ssoError] ?? "Single sign-on failed. Contact your administrator if this persists."}
        </p>
      )}
      {provider !== null && (
        <Card>
          <CardContent>
            {/* A plain navigation: the start route sets the state cookie and redirects to the provider. */}
            <a
              href="/api/auth/oidc/start"
              className="inline-flex h-9 w-full items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Sign in with {provider.config.displayName}
            </a>
          </CardContent>
        </Card>
      )}
      {showLocal && <LoginForm adminsOnly={mode === "admins" && provider !== null} />}
      {provider === null && mode === "disabled" && <p className="text-sm text-muted-foreground">Local login is disabled.</p>}
    </main>
  );
}
