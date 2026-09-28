"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";

import { userApi } from "./client-api";

/** Marks / unmarks a finding as a false positive (user API, CSRF header; audited server side). */
export function FalsePositiveButton({
  findingId,
  falsePositive,
  csrfToken,
}: {
  findingId: string;
  falsePositive: boolean;
  csrfToken: string;
}) {
  const router = useRouter();
  const [failed, setFailed] = useState(false);

  async function toggle() {
    setFailed(false);
    const res = await userApi(`/api/findings/${findingId}/false-positive`, {
      method: "POST",
      csrfToken,
      body: { false_positive: !falsePositive },
    }).catch(() => null);
    if (!res?.ok) setFailed(true);
    router.refresh();
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button size="sm" variant={falsePositive ? "outline" : "ghost"} onClick={toggle}>
        {falsePositive ? "Not a false positive" : "False positive"}
      </Button>
      {failed && (
        <span role="alert" className="text-xs text-destructive">
          Update failed.
        </span>
      )}
    </div>
  );
}
