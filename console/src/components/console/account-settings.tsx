"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

import { userApi } from "./client-api";

/**
 * The user's own account. "Link single sign-on" (ADR-0038 decision 6) is self-service only, from a
 * LOCAL session: the console starts the OIDC flow and binds the returned (issuer, subject) to this
 * account, if that identity is not bound already.
 */
export function AccountSettings({
  username,
  role,
  identities,
  providerName,
  canLink,
  sessionMethod,
  linked,
  linkError,
  csrfToken,
}: {
  username: string;
  role: string;
  identities: { issuer: string; subject: string; email: string | null }[];
  providerName: string | null;
  canLink: boolean;
  sessionMethod: "local" | "oidc";
  linked: boolean;
  linkError: boolean;
  csrfToken: string;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function link() {
    setBusy(true);
    setError(null);
    const res = await userApi("/api/auth/oidc/link", { method: "POST", csrfToken }).catch(() => null);
    const body = res?.ok ? ((await res.json().catch(() => null)) as { redirect_url?: unknown } | null) : null;
    if (typeof body?.redirect_url === "string" && /^https?:\/\//.test(body.redirect_url)) {
      window.location.assign(body.redirect_url);
      return;
    }
    setBusy(false);
    setError(res?.status === 429 ? "Too many attempts. Try again later." : "Single sign-on is unavailable.");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {username} ({role})
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        {linked && <p role="status">Single sign-on linked: you can now sign in with {providerName ?? "single sign-on"}.</p>}
        {linkError && (
          <p role="alert" className="text-destructive">
            The single sign-on identity could not be linked (already bound to a user, session expired, or refused by the login rules).
          </p>
        )}
        {identities.length > 0 ? (
          <ul className="list-disc pl-5">
            {identities.map((i) => (
              <li key={`${i.issuer}|${i.subject}`}>
                Single sign-on: <span className="font-mono text-xs break-all">{i.subject}</span> at <span className="font-mono text-xs break-all">{i.issuer}</span>
                {i.email ? ` (${i.email})` : ""}
              </li>
            ))}
          </ul>
        ) : (
          <p>No single sign-on identity is linked to this account.</p>
        )}
        {canLink && (
          <div>
            <Button onClick={link} disabled={busy}>
              Link single sign-on{providerName ? ` (${providerName})` : ""}
            </Button>
          </div>
        )}
        {providerName !== null && identities.length === 0 && sessionMethod !== "local" && <p>Linking requires a session opened with your local password.</p>}
        {error && (
          <p role="alert" className="text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
