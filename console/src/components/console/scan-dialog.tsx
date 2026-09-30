"use client";

import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

import { userApi } from "./client-api";

/** Contract `DiscoveryScanParams` bounds and defaults (checked again by the server). */
export const SCAN_FIELDS = [
  { name: "sample_rows", label: "Rows sampled per object", min: 1, max: 10_000, value: 200 },
  { name: "max_duration_s", label: "Scan budget (s)", min: 10, max: 86_400, value: 3600 },
  { name: "statement_timeout_ms", label: "Per-query timeout (ms)", min: 100, max: 600_000, value: 30_000 },
] as const;

export const SCAN_LISTS = [
  { name: "databases", label: "Databases (all when empty)" },
  { name: "schemas", label: "Schemas (all when empty)" },
  { name: "include_objects", label: "Only these objects (all when empty)" },
  { name: "exclude_objects", label: "Skip these objects" },
  { name: "classifiers", label: "Classifiers (all when empty)" },
] as const;

/**
 * Request body of a scan launch from the form values. Lists are comma-separated; an empty list is
 * omitted (absent = all), never sent as `[]` (the contract rejects empty include filters so that a
 * "nothing selected" bug can never widen a scan).
 */
export function scanRequestBody(values: Record<string, string>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const f of SCAN_FIELDS) {
    const raw = (values[f.name] ?? "").trim();
    if (raw !== "") body[f.name] = Number(raw);
  }
  for (const l of SCAN_LISTS) {
    const items = [...new Set((values[l.name] ?? "").split(",").map((s) => s.trim()).filter((s) => s !== ""))];
    if (items.length > 0) body[l.name] = items;
  }
  return body;
}

/** Messages per `error` code of the scan request (fallback: per HTTP status). */
export const SCAN_ERROR_CODES: Record<string, string> = {
  invalid_params: "Invalid parameters (check the ranges and the name filters).",
  not_found: "The agent or the target is no longer active.",
  scan_in_progress: "A scan of this target is already queued or running.",
  agent_not_ready: "The agent has not reported its classifier set yet: wait for its next heartbeat.",
  classifiers_version_unregistered:
    "The agent runs a classifier set this console does not know: upgrade the console or install a supported agent build.",
  unknown_classifiers: "Some classifiers are not part of the agent's classifier set.",
};

const ERRORS: Record<number, string> = {
  400: "Invalid parameters (check the ranges and the name filters).",
  404: "The agent or the target is no longer active.",
  409: "A scan of this target is already queued or running, or the agent is not ready.",
  422: "Some classifiers are not part of the agent's classifier set.",
};

/** User message of a refused scan request, from its JSON `{ error }` body when there is one. */
export function scanErrorMessage(status: number, body: unknown): string {
  const code =
    body !== null && typeof body === "object" && !Array.isArray(body) ? (body as { error?: unknown }).error : undefined;
  if (typeof code === "string" && Object.hasOwn(SCAN_ERROR_CODES, code)) return SCAN_ERROR_CODES[code] as string;
  return ERRORS[status] ?? `The scan could not be queued (${status}).`;
}

/** "Scan" action of a target (admin): a native `<dialog>` form, posted with the CSRF header. */
export function ScanDialog({
  agentId,
  targetId,
  csrfToken,
  disabled,
}: {
  agentId: string;
  targetId: string;
  csrfToken: string;
  disabled?: boolean;
}) {
  const router = useRouter();
  const ref = useRef<HTMLDialogElement>(null);
  const [message, setMessage] = useState<string | null>(null);
  const id = (name: string) => `scan-${targetId}-${name}`;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const values = Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));
    setMessage(null);
    const res = await userApi(`/api/agents/${agentId}/targets/${encodeURIComponent(targetId)}/scan`, {
      method: "POST",
      csrfToken,
      body: scanRequestBody(values),
    }).catch(() => null);
    if (!res) {
      setMessage("The console is unreachable.");
      return;
    }
    if (!res.ok) {
      setMessage(scanErrorMessage(res.status, await res.json().catch(() => null)));
      return;
    }
    ref.current?.close();
    setMessage("Scan queued: the agent picks it up at its next poll.");
    router.refresh();
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button size="sm" variant="outline" disabled={disabled} onClick={() => ref.current?.showModal()}>
        Scan
      </Button>
      {message && (
        <p role="status" className="text-xs text-muted-foreground">
          {message}
        </p>
      )}
      <dialog
        ref={ref}
        aria-labelledby={id("title")}
        className="m-auto w-full max-w-lg rounded-xl border bg-background p-6 text-foreground shadow-lg backdrop:bg-black/50"
      >
        <h2 id={id("title")} className="text-lg font-semibold">
          Scan target {targetId}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          The agent samples the target with its read-only account, within these bounds and its own local limits. Only
          masked samples and fingerprints reach the console.
        </p>
        <p className="mt-1 text-sm text-muted-foreground">
          Scans are paced to spare the database: a scan takes about 100 times its query time (at the agent&apos;s
          default 1 % duty cycle). The console sends an agent one scan at a time: a scan requested while another scan
          of the agent is in flight waits (&quot;waiting for the previous scan&quot;) and its budget starts only when
          the agent receives it, so queue time does not count. The agent caps the budget at its local limit
          (<code>limits.max_scan_duration_s</code>, 3600 s by default).
        </p>
        <form onSubmit={submit} className="mt-4 flex flex-col gap-3">
          {SCAN_FIELDS.map((f) => (
            <div key={f.name} className="flex flex-col gap-1">
              <Label htmlFor={id(f.name)}>
                {f.label} ({f.min} to {f.max})
              </Label>
              <Input id={id(f.name)} name={f.name} type="number" min={f.min} max={f.max} defaultValue={f.value} required />
            </div>
          ))}
          {SCAN_LISTS.map((l) => (
            <div key={l.name} className="flex flex-col gap-1">
              <Label htmlFor={id(l.name)}>{l.label}, comma-separated</Label>
              <Input id={id(l.name)} name={l.name} autoComplete="off" maxLength={4000} />
            </div>
          ))}
          <div className="mt-2 flex justify-end gap-2">
            <Button variant="outline" onClick={() => ref.current?.close()}>
              Cancel
            </Button>
            <Button type="submit">Queue scan</Button>
          </div>
        </form>
      </dialog>
    </div>
  );
}
