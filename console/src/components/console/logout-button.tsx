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
        await userApi("/api/auth/logout", { method: "POST", csrfToken }).catch(() => undefined);
        router.replace("/login");
        router.refresh();
      }}
    >
      Sign out
    </Button>
  );
}
