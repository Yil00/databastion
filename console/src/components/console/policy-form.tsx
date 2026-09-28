"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { SEVERITIES } from "@/lib/incident-lifecycle";

import { userApi } from "./client-api";

/**
 * Create / edit form of a policy (admin). The form is a plain view of the condition document
 * (`src/lib/policy-model.ts`); the server validates everything again and answers the failing field.
 */

export const LIST_FIELDS = [
  { name: "classifiers", label: "Classifiers (ids or families such as pii.*; all when empty)" },
  { name: "target_ids", label: "Targets (all when empty)" },
  { name: "engines", label: "Engines (all when empty)" },
  { name: "agent_ids", label: "Agent ids (all when empty)" },
] as const;

export const LOCATION_FIELDS = [
  { name: "location.database", label: "Database" },
  { name: "location.schema", label: "Schema" },
  { name: "location.object", label: "Object (table, collection, container)" },
  { name: "location.field", label: "Field (column, path, attribute)" },
] as const;

export const THRESHOLD_FIELDS = [
  { name: "min_confidence", label: "Minimum confidence (0 to 1)", step: "0.01", max: 1 },
  { name: "min_match_ratio", label: "Minimum matched / sampled (0 to 1)", step: "0.01", max: 1 },
  { name: "min_matched", label: "Minimum matched values", step: "1", max: 10_000 },
] as const;

export interface PolicyFormValues {
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  notify: string;
  [key: string]: string | boolean;
}

const list = (v: string | boolean | undefined) =>
  [...new Set(String(v ?? "").split(",").map((s) => s.trim()).filter((s) => s !== ""))];

/**
 * Request body from the form values: empty inputs are omitted (absent = no constraint), lists are
 * comma-separated, numbers parsed as typed (the server rejects anything out of range).
 */
export function policyRequestBody(values: Record<string, string | boolean>): Record<string, unknown> {
  const conditions: Record<string, unknown> = {};
  for (const f of LIST_FIELDS) {
    const items = list(values[f.name]);
    if (items.length > 0) conditions[f.name] = items;
  }
  const location: Record<string, string> = {};
  for (const f of LOCATION_FIELDS) {
    const g = String(values[f.name] ?? "").trim();
    if (g !== "") location[f.name.slice("location.".length)] = g;
  }
  if (Object.keys(location).length > 0) conditions.location = location;
  for (const f of THRESHOLD_FIELDS) {
    const raw = String(values[f.name] ?? "").trim();
    if (raw !== "") conditions[f.name] = Number(raw);
  }
  const actions: Record<string, unknown>[] = [{ type: "create_incident", severity: String(values.severity ?? "medium") }];
  for (const channel of list(values.notify)) actions.push({ type: "notify", channel });
  const description = String(values.description ?? "").trim();
  return {
    name: String(values.name ?? "").trim(),
    description: description === "" ? null : description,
    enabled: values.enabled === true || values.enabled === "on",
    conditions,
    actions,
  };
}

export const POLICY_FIELD_ERRORS: Record<string, string> = {
  name: "Name: 1 to 100 printable characters.",
  description: "Description: at most 500 printable characters.",
  classifiers: "Classifiers: registered ids (e.g. pii.email) or families (e.g. pii.*).",
  target_ids: "Targets: target ids as declared in agent.yaml.",
  engines: "Engines: postgres, mysql, mariadb, mongodb or openldap.",
  agent_ids: "Agent ids: agent UUIDs.",
  min_confidence: "Minimum confidence: a number from 0 to 1.",
  min_match_ratio: "Minimum ratio: a number from 0 to 1.",
  min_matched: "Minimum matched: a whole number from 0 to 10000.",
  "actions.channel": "Notification channels: distinct names such as secops-mail (no address or URL).",
  "actions.severity": "Pick a severity.",
};

/**
 * Warning for notify channel names that match no channel or a disabled one (saving is still
 * allowed: the incidents are opened and these notifications are recorded as skipped).
 */
export function notifyWarning(value: string, channels: readonly { slug: string; enabled: boolean }[] | undefined): string | null {
  if (!channels) return null;
  const known = new Map(channels.map((c) => [c.slug, c.enabled]));
  const problems = list(value).flatMap((slug) =>
    !known.has(slug) ? [`${slug}: no such channel`] : known.get(slug) ? [] : [`${slug}: channel disabled`],
  );
  return problems.length > 0 ? `${problems.join("; ")}. These notifications will be skipped.` : null;
}

export function policyErrorMessage(status: number, body: unknown): string {
  const b = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  if (status === 409) return "A policy with this name already exists.";
  if (status === 400 && typeof b.field === "string") {
    if (Object.hasOwn(POLICY_FIELD_ERRORS, b.field)) return POLICY_FIELD_ERRORS[b.field] as string;
    if (b.field.startsWith("location")) return "Location patterns: printable globs of at most 256 characters.";
    return "Invalid policy.";
  }
  if (status === 403) return "Not allowed.";
  if (status === 404) return "The policy no longer exists.";
  return `The policy could not be saved (${status}).`;
}

export function PolicyForm({
  csrfToken,
  policyId,
  initial,
  channels,
}: {
  csrfToken: string;
  /** Edit mode when set. */
  policyId?: string;
  initial?: Partial<PolicyFormValues>;
  /** Existing notification channels (warnings on unknown / disabled names). */
  channels?: { slug: string; enabled: boolean }[];
}) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const [notifyNote, setNotifyNote] = useState<string | null>(() =>
    notifyWarning(typeof initial?.notify === "string" ? initial.notify : "", channels),
  );
  const v = (name: string) => {
    const x = initial?.[name];
    return typeof x === "string" ? x : "";
  };
  const id = (name: string) => `policy-${policyId ?? "new"}-${name.replace(".", "-")}`;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const values: Record<string, string | boolean> = Object.fromEntries(
      [...form.entries()].map(([k, x]) => [k, String(x)]),
    );
    values.enabled = form.get("enabled") === "on";
    setMessage(null);
    const res = await userApi(policyId ? `/api/policies/${policyId}` : "/api/policies", {
      method: policyId ? "PATCH" : "POST",
      csrfToken,
      body: policyRequestBody(values),
    }).catch(() => null);
    if (!res) {
      setMessage("The console is unreachable.");
      return;
    }
    if (!res.ok) {
      setMessage(policyErrorMessage(res.status, await res.json().catch(() => null)));
      return;
    }
    if (policyId) {
      setMessage("Saved: the worker applies the change to the existing findings.");
      router.refresh();
    } else {
      router.push("/policies");
      router.refresh();
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("name")}>Name</Label>
          <Input id={id("name")} name="name" required maxLength={100} defaultValue={v("name")} autoComplete="off" />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("description")}>Description</Label>
          <Input id={id("description")} name="description" maxLength={500} defaultValue={v("description")} autoComplete="off" />
        </div>
      </div>
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-2 text-sm font-semibold">Conditions (all must hold)</legend>
        <div className="grid gap-3 md:grid-cols-2">
          {LIST_FIELDS.map((f) => (
            <div key={f.name} className="flex flex-col gap-1">
              <Label htmlFor={id(f.name)}>{f.label}, comma-separated</Label>
              <Input id={id(f.name)} name={f.name} maxLength={4000} defaultValue={v(f.name)} autoComplete="off" />
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Location patterns apply to normalized names: <code>*</code> matches any run of characters, <code>?</code> one
          character, <code>\</code> escapes the next one; case-insensitive.
        </p>
        <div className="grid gap-3 md:grid-cols-4">
          {LOCATION_FIELDS.map((f) => (
            <div key={f.name} className="flex flex-col gap-1">
              <Label htmlFor={id(f.name)}>{f.label}</Label>
              <Input id={id(f.name)} name={f.name} maxLength={256} defaultValue={v(f.name)} autoComplete="off" />
            </div>
          ))}
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {THRESHOLD_FIELDS.map((f) => (
            <div key={f.name} className="flex flex-col gap-1">
              <Label htmlFor={id(f.name)}>{f.label}</Label>
              <Input id={id(f.name)} name={f.name} type="number" min={0} max={f.max} step={f.step} defaultValue={v(f.name)} />
            </div>
          ))}
        </div>
      </fieldset>
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-2 text-sm font-semibold">Actions</legend>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="flex flex-col gap-1">
            <Label htmlFor={id("severity")}>Create an incident with severity</Label>
            <select
              id={id("severity")}
              name="severity"
              defaultValue={v("severity") || "medium"}
              className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor={id("notify")}>Notify channels, comma-separated</Label>
            <Input
              id={id("notify")}
              name="notify"
              maxLength={400}
              defaultValue={v("notify")}
              autoComplete="off"
              onChange={(e) => setNotifyNote(notifyWarning(e.target.value, channels))}
            />
            {channels && (
              <p className="text-xs text-muted-foreground">
                {channels.length > 0 ? `Channels: ${channels.map((c) => c.slug).join(", ")}` : "No notification channel yet."}
              </p>
            )}
            {notifyNote && (
              <p role="alert" className="text-xs text-destructive">
                {notifyNote}
              </p>
            )}
          </div>
        </div>
      </fieldset>
      <div className="flex items-center gap-2">
        <input
          id={id("enabled")}
          name="enabled"
          type="checkbox"
          defaultChecked={initial?.enabled ?? true}
          className="size-4"
        />
        <Label htmlFor={id("enabled")}>Enabled</Label>
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit">{policyId ? "Save" : "Create policy"}</Button>
        {message && (
          <p role="status" className="text-sm text-muted-foreground">
            {message}
          </p>
        )}
      </div>
    </form>
  );
}
