"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { canTransition, transitionNeedsAdmin, type IncidentStatus } from "@/lib/incident-lifecycle";

import { userApi } from "./client-api";

const LABELS: Partial<Record<IncidentStatus, string>> = {
  acknowledged: "Acknowledge",
  resolved: "Resolve",
  false_positive: "False positive",
};

/** Transitions the current user may request from `status` (the server checks them again). */
export function availableTransitions(status: IncidentStatus, isAdmin: boolean): IncidentStatus[] {
  return (["acknowledged", "resolved", "false_positive"] as const).filter(
    (to) => canTransition(status, to) && (isAdmin || !transitionNeedsAdmin(to)),
  );
}

export function transitionErrorMessage(status: number): string {
  if (status === 409) return "The incident changed meanwhile: reload the page.";
  if (status === 403) return "Not allowed.";
  if (status === 404) return "The incident no longer exists.";
  return `The change failed (${status}).`;
}

/** Lifecycle buttons of an incident (user API, CSRF header; audited server side). */
export function IncidentActions({
  incidentId,
  status,
  isAdmin,
  csrfToken,
}: {
  incidentId: string;
  status: IncidentStatus;
  isAdmin: boolean;
  csrfToken: string;
}) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const transitions = availableTransitions(status, isAdmin);

  async function move(to: IncidentStatus) {
    setMessage(null);
    const res = await userApi(`/api/incidents/${incidentId}/transition`, {
      method: "POST",
      csrfToken,
      body: { status: to },
    }).catch(() => null);
    if (!res) setMessage("The console is unreachable.");
    else if (!res.ok) setMessage(transitionErrorMessage(res.status));
    router.refresh();
  }

  if (transitions.length === 0) return null;
  return (
    <div className="flex flex-col items-start gap-2">
      <div className="flex gap-2">
        {transitions.map((to) =>
          to === "false_positive" ? (
            <ConfirmDialog
              key={to}
              trigger={LABELS[to] as string}
              title="Mark as a false positive?"
              description="The linked finding is marked as a false positive too: every open incident of it is closed, and policies ignore it until a rescan matches more values or uses another classifier set."
              confirmLabel="Mark false positive"
              variant="outline"
              onConfirm={() => move(to)}
            />
          ) : (
            <Button key={to} size="sm" variant={to === "resolved" ? "default" : "outline"} onClick={() => move(to)}>
              {LABELS[to]}
            </Button>
          ),
        )}
      </div>
      {!isAdmin && status !== "resolved" && (
        <p className="text-xs text-muted-foreground">Only administrators can mark an incident as a false positive.</p>
      )}
      {message && (
        <p role="alert" className="text-xs text-destructive">
          {message}
        </p>
      )}
    </div>
  );
}
