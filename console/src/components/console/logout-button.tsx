"use client";

import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";

import { userApi } from "./client-api";

export function LogoutButton({ csrfToken }: { csrfToken: string }) {
  const router = useRouter();
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={async () => {
        const res = await userApi("/api/auth/logout", { method: "POST", csrfToken }).catch(() => null);
        // OIDC sessions: RP-initiated logout at the provider (ADR-0038 decision 14).
        if (res?.status === 200) {
          const body = (await res.json().catch(() => null)) as { redirect_url?: unknown } | null;
          if (typeof body?.redirect_url === "string" && /^https?:\/\//.test(body.redirect_url)) {
            window.location.assign(body.redirect_url);
            return;
          }
        }
        router.replace("/login");
        router.refresh();
      }}
    >
      Sign out
    </Button>
  );
}
