"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Input, Label } from "@/components/ui/input";

import { userApi } from "./client-api";

/** Policy row actions (admin): enable / disable and delete, through the user API with CSRF. */
export function PolicyRowActions({
  policyId,
  policyName,
  enabled,
  csrfToken,
}: {
  policyId: string;
  policyName: string;
  enabled: boolean;
  csrfToken: string;
}) {
  const router = useRouter();
  const [failed, setFailed] = useState(false);

  async function call(method: string, body?: unknown) {
    setFailed(false);
    const res = await userApi(`/api/policies/${policyId}`, { method, csrfToken, body }).catch(() => null);
    if (!res?.ok) setFailed(true);
    router.refresh();
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={() => call("PATCH", { enabled: !enabled })}>
          {enabled ? "Disable" : "Enable"}
        </Button>
        <ConfirmDialog
          trigger="Delete"
          title="Delete this policy?"
          description={
            <>
              The policy <strong>{policyName}</strong> and its exceptions are deleted. Its incidents are kept.
            </>
          }
          confirmLabel="Delete policy"
          variant="destructive"
          onConfirm={() => call("DELETE")}
        />
      </div>
      {failed && (
        <span role="alert" className="text-xs text-destructive">
          Update failed.
        </span>
      )}
    </div>
  );
}

/** Deletes an exception (admin). */
export function DeleteExceptionButton({ exceptionId, csrfToken }: { exceptionId: string; csrfToken: string }) {
  const router = useRouter();
  const [failed, setFailed] = useState(false);
  return (
    <div className="flex flex-col items-end gap-1">
      <ConfirmDialog
        trigger="Delete"
        title="Delete this exception?"
        description="The findings it covered become subject to the policies again: the worker re-evaluates them."
        confirmLabel="Delete exception"
        variant="destructive"
        onConfirm={async () => {
          setFailed(false);
          const res = await userApi(`/api/policy-exceptions/${exceptionId}`, { method: "DELETE", csrfToken }).catch(() => null);
          if (!res?.ok) setFailed(true);
          router.refresh();
        }}
      />
      {failed && (
        <span role="alert" className="text-xs text-destructive">
          Delete failed.
        </span>
      )}
    </div>
  );
}

/**
 * Exception request body from the form values: empty inputs omitted, the expiry date (a local
 * `datetime-local` value) converted to an RFC 3339 instant.
 */
export function exceptionRequestBody(values: Record<string, string>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const text = (k: string) => (values[k] ?? "").trim();
  if (text("policy_id")) body.policy_id = text("policy_id");
  if (text("agent_id")) body.agent_id = text("agent_id");
  if (text("target_id")) body.target_id = text("target_id");
  if (text("classifier")) body.classifier = text("classifier");
  const location: Record<string, string> = {};
  for (const part of ["database", "schema", "object", "field"]) {
    if (text(`location.${part}`)) location[part] = text(`location.${part}`);
  }
  if (Object.keys(location).length > 0) body.location = location;
  body.reason = text("reason");
  if (text("expires_at")) {
    const t = new Date(text("expires_at"));
    body.expires_at = Number.isNaN(t.getTime()) ? text("expires_at") : t.toISOString();
  }
  return body;
}

const EXCEPTION_ERRORS: Record<string, string> = {
  scope: "Set at least one of agent, target, classifier or location.",
  reason: "A reason is required (at most 500 printable characters).",
  expires_at: "The expiry must be in the future (at most 10 years).",
  classifier: "Classifier: a registered id (e.g. pii.email) or a family (e.g. pii.*).",
  target_id: "Target: a target id as declared in agent.yaml.",
  agent_id: "Agent: an agent UUID.",
};

export function exceptionErrorMessage(status: number, body: unknown): string {
  const field =
    body !== null && typeof body === "object" && !Array.isArray(body) ? (body as { field?: unknown }).field : undefined;
  if (status === 400 && typeof field === "string") {
    if (Object.hasOwn(EXCEPTION_ERRORS, field)) return EXCEPTION_ERRORS[field] as string;
    return "Invalid exception.";
  }
  if (status === 404) return "Unknown policy or agent.";
  if (status === 403) return "Not allowed.";
  return `The exception could not be saved (${status}).`;
}

/** Exception creation form (admin). `policyId` fixes the policy; otherwise it applies to all. */
export function ExceptionForm({ csrfToken, policyId }: { csrfToken: string; policyId?: string }) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const id = (name: string) => `exception-${policyId ?? "all"}-${name.replace(".", "-")}`;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formEl = e.currentTarget;
    const values = Object.fromEntries([...new FormData(formEl).entries()].map(([k, v]) => [k, String(v)]));
    if (policyId) values.policy_id = policyId;
    setMessage(null);
    const res = await userApi("/api/policy-exceptions", { method: "POST", csrfToken, body: exceptionRequestBody(values) }).catch(
      () => null,
    );
    if (!res) {
      setMessage("The console is unreachable.");
      return;
    }
    if (!res.ok) {
      setMessage(exceptionErrorMessage(res.status, await res.json().catch(() => null)));
      return;
    }
    formEl.reset();
    setMessage("Exception added.");
    router.refresh();
  }

  const fields = [
    { name: "agent_id", label: "Agent id" },
    { name: "target_id", label: "Target" },
    { name: "classifier", label: "Classifier (id or family)" },
    { name: "location.database", label: "Database pattern" },
    { name: "location.schema", label: "Schema pattern" },
    { name: "location.object", label: "Object pattern" },
    { name: "location.field", label: "Field pattern" },
  ];
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="grid gap-3 md:grid-cols-4">
        {fields.map((f) => (
          <div key={f.name} className="flex flex-col gap-1">
            <Label htmlFor={id(f.name)}>{f.label}</Label>
            <Input id={id(f.name)} name={f.name} maxLength={256} autoComplete="off" />
          </div>
        ))}
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("expires_at")}>Expires (optional)</Label>
          <Input id={id("expires_at")} name="expires_at" type="datetime-local" />
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor={id("reason")}>Reason</Label>
        <Input id={id("reason")} name="reason" required maxLength={500} autoComplete="off" />
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit" variant="outline">
          Add exception
        </Button>
        {message && (
          <p role="status" className="text-sm text-muted-foreground">
            {message}
          </p>
        )}
      </div>
    </form>
  );
}
