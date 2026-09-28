"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";

import { userApi } from "./client-api";

const ROTATE_ERRORS: Record<number, string> = {
  409: "A rotation is already in progress or just completed: try again in a minute.",
  404: "The agent is no longer active.",
};

/** Admin actions of the agent detail page. Both go through the user API with the CSRF header. */
export function AgentActions({
  agentId,
  agentName,
  csrfToken,
  rotationBlocked,
}: {
  agentId: string;
  agentName: string;
  csrfToken: string;
  rotationBlocked: boolean;
}) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);

  async function call(path: string, errors: Record<number, string>, ok: string) {
    setMessage(null);
    try {
      const res = await userApi(path, { method: "POST", csrfToken });
      setMessage(res.ok ? ok : (errors[res.status] ?? `The action failed (${res.status}).`));
    } catch {
      setMessage("The console is unreachable.");
    }
    router.refresh();
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2">
        <ConfirmDialog
          trigger="Rotate secret"
          title="Rotate the agent secret?"
          description={
            <>
              The agent <strong>{agentName}</strong> will generate a new secret at its next job poll and register it.
              No secret is sent by the console. This is maintenance: if the secret may be compromised, revoke the agent
              instead.
            </>
          }
          confirmLabel="Rotate"
          disabled={rotationBlocked}
          onConfirm={() =>
            call(`/api/agents/${agentId}/rotate`, ROTATE_ERRORS, "Rotation requested: the agent picks it up at its next poll.")
          }
        />
        <ConfirmDialog
          trigger="Revoke"
          title="Revoke this agent?"
          description={
            <>
              The agent <strong>{agentName}</strong> loses access immediately and its pending jobs are cancelled. It must
              be re-enrolled with a new token. This cannot be undone.
            </>
          }
          confirmLabel="Revoke"
          variant="destructive"
          onConfirm={() => call(`/api/agents/${agentId}/revoke`, { 404: "Already revoked." }, "Agent revoked.")}
        />
      </div>
      {message && (
        <p role="status" className="text-sm text-muted-foreground">
          {message}
        </p>
      )}
    </div>
  );
}
