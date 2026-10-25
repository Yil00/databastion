"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { MIN_ROWS_WARNING_TEXT } from "@/lib/audit-warning";

import { userApi } from "./client-api";

/**
 * Audit settings form of one target (admin, P4-C). Manual sensitive objects are typed one per line
 * as `database/schema/object: classifier, classifier` (or `database/object: ...` without schema):
 * `/` and `:` cannot appear in a normalized name, so the format is unambiguous. On Redis / Valkey
 * targets (P9-E review M3) object names are key patterns, where `/` and `:` are separators: the
 * line is `database; object; classifier, classifier`, split on `;` only (a character neither an
 * `Identifier` nor a `KeyPattern` may hold), never on `/` or `:`. The server validates everything
 * again against the contract.
 *
 * A change that disables Audit, empties the sensitive objects or removes many of them is refused
 * with `409 confirmation_required`: the form then shows what the change does and sends it again
 * with the digest of those exact settings only when the administrator confirms.
 */

export interface ManualObject {
  database: string;
  schema?: string;
  object: string;
  classifiers: string[];
}

const LINE = /^([^/:]+)\/(?:([^/:]+)\/)?([^/:]+):(.+)$/;

/** Manual object line of the key-pattern engines: `database; object; classifier, classifier`. */
function parseKeyPatternLine(raw: string): ManualObject | null {
  const parts = raw.split(";").map((p) => p.trim());
  if (parts.length !== 3) return null;
  const [database, object, list] = parts as [string, string, string];
  const classifiers = [...new Set(list.split(",").map((c) => c.trim()).filter((c) => c !== ""))];
  if (database === "" || object === "" || classifiers.length === 0) return null;
  return { database, object, classifiers };
}

/**
 * Parses the manual objects text; returns the 1-based number of the first malformed line.
 * `keyPatterns`: the target's engine names objects with key patterns (Redis / Valkey).
 */
export function parseManualObjects(text: string, keyPatterns = false): { ok: true; objects: ManualObject[] } | { ok: false; line: number } {
  const objects: ManualObject[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = (lines[i] ?? "").trim();
    if (raw === "") continue;
    if (keyPatterns) {
      const o = parseKeyPatternLine(raw);
      if (!o) return { ok: false, line: i + 1 };
      objects.push(o);
      continue;
    }
    const m = LINE.exec(raw);
    const classifiers = [...new Set((m?.[4] ?? "").split(",").map((c) => c.trim()).filter((c) => c !== ""))];
    if (!m || classifiers.length === 0) return { ok: false, line: i + 1 };
    const [database, schema, object] = [m[1]?.trim() ?? "", m[2]?.trim(), m[3]?.trim() ?? ""];
    if (database === "" || object === "" || schema === "") return { ok: false, line: i + 1 };
    objects.push(schema === undefined ? { database, object, classifiers } : { database, schema, object, classifiers });
  }
  return { ok: true, objects };
}

export function formatManualObjects(objects: readonly ManualObject[], keyPatterns = false): string {
  if (keyPatterns) return objects.map((o) => `${o.database}; ${o.object}; ${o.classifiers.join(", ")}`).join("\n");
  return objects
    .map((o) => `${[o.database, o.schema, o.object].filter((x) => x !== undefined).join("/")}: ${o.classifiers.join(", ")}`)
    .join("\n");
}

export interface AuditFormValues {
  enabled: boolean;
  aggregationWindowS: number;
  pollIntervalS: number;
  minRows: number | null;
  deriveFromFindings: boolean;
  manualObjects: ManualObject[];
}

interface Refusal {
  warning: "disabled" | "emptied" | "shrunk";
  previous_objects: number;
  next_objects: number;
  removed_objects: number;
  digest: string;
}

/** What a narrowing change does, in one sentence. */
export function confirmationText(r: Pick<Refusal, "warning" | "previous_objects" | "next_objects" | "removed_objects">): string {
  switch (r.warning) {
    case "disabled":
      return "This change turns Audit off for this target: the agent stops reporting its accesses.";
    case "emptied":
      return `This change empties the list of sensitive objects (${r.previous_objects} today): accesses are then only reported when they carry a signal or reach the row threshold.`;
    case "shrunk":
      return `This change removes ${r.removed_objects} of the ${r.previous_objects} sensitive objects sent last time (${r.next_objects} left): accesses to the removed ones are then only reported when they carry a signal or reach the row threshold.`;
  }
}

const MANUAL_FORMAT = "database/schema/object: classifier, classifier";
const MANUAL_FORMAT_KEY_PATTERNS = "database; object; classifier, classifier";

const ERRORS: Record<string, string> = {
  aggregation_window_s: "Aggregation window: 1 to 300 seconds.",
  poll_interval_s: "Polling interval: 1 to 3600 seconds.",
  min_rows: "Row threshold: a whole number, 0 or more.",
  manual_objects: "Sensitive objects: normalized names and registered classifier ids (at most 1000 objects, 32 classifiers each).",
};

export function AuditForm({
  agentId,
  targetId,
  csrfToken,
  initial,
  keyPatterns = false,
}: {
  agentId: string;
  targetId: string;
  csrfToken: string;
  initial: AuditFormValues;
  /** Redis / Valkey target: manual objects use the `;` format (see above). */
  keyPatterns?: boolean;
}) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const [pending, setPending] = useState<{ body: Record<string, unknown>; refusal: Refusal } | null>(null);
  const id = (name: string) => `audit-${targetId}-${name}`;

  async function send(body: Record<string, unknown>): Promise<void> {
    setMessage(null);
    const res = await userApi(`/api/agents/${agentId}/targets/${encodeURIComponent(targetId)}/audit`, {
      method: "POST",
      csrfToken,
      body,
    }).catch(() => null);
    if (!res) {
      setMessage("The console is unreachable.");
      return;
    }
    const json = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    if (res.status === 409 && json?.error === "confirmation_required") {
      setPending({ body, refusal: json as unknown as Refusal });
      return;
    }
    setPending(null);
    if (!res.ok) {
      if (res.status === 409 && json?.error === "audit_unsupported") {
        setMessage("This target is Discovery only (no Audit on this engine): the settings were not saved.");
        return;
      }
      const field = typeof json?.field === "string" ? json.field : "";
      setMessage(Object.hasOwn(ERRORS, field) ? (ERRORS[field] as string) : res.status === 404 ? "The agent or the target is no longer active." : `The settings could not be saved (${res.status}).`);
      return;
    }
    const truncated = typeof json?.truncated_objects === "number" && json.truncated_objects > 0 ? ` ${json.truncated_objects} objects over the limit of 1000 were left out.` : "";
    const skipped =
      typeof json?.skipped_key_patterns === "number" && json.skipped_key_patterns > 0
        ? ` ${json.skipped_key_patterns} key-pattern objects were left out: this agent cannot receive key patterns as sensitive objects (upgrade it, then save again).`
        : "";
    // #235 review N2: saved, with a warning (min_rows on a Redis / Valkey target).
    const rows = json?.min_rows_warning === "no_row_counts" ? ` Warning: ${MIN_ROWS_WARNING_TEXT.no_row_counts}` : "";
    setMessage(`Queued: the agent applies the settings at its next poll (${String(json?.next_objects ?? 0)} sensitive objects).${truncated}${skipped}${rows}`);
    router.refresh();
  }

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const manual = parseManualObjects(String(form.get("manual_objects") ?? ""), keyPatterns);
    if (!manual.ok) {
      setMessage(`Sensitive objects, line ${manual.line}: expected ${keyPatterns ? MANUAL_FORMAT_KEY_PATTERNS : MANUAL_FORMAT}`);
      return;
    }
    const minRows = String(form.get("min_rows") ?? "").trim();
    await send({
      enabled: form.get("enabled") === "on",
      aggregation_window_s: Number(form.get("aggregation_window_s")),
      poll_interval_s: Number(form.get("poll_interval_s")),
      ...(minRows !== "" ? { min_rows: Number(minRows) } : {}),
      derive_from_findings: form.get("derive_from_findings") === "on",
      manual_objects: manual.objects,
    });
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <input id={id("enabled")} name="enabled" type="checkbox" defaultChecked={initial.enabled} className="size-4" />
        <Label htmlFor={id("enabled")}>Audit enabled</Label>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("window")}>Aggregation window (s, 1 to 300)</Label>
          <Input id={id("window")} name="aggregation_window_s" type="number" min={1} max={300} required defaultValue={initial.aggregationWindowS} />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("poll")}>Polling interval (s, 1 to 3600)</Label>
          <Input id={id("poll")} name="poll_interval_s" type="number" min={1} max={3600} required defaultValue={initial.pollIntervalS} />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={id("min-rows")}>Report other accesses from (rows)</Label>
          <Input
            id={id("min-rows")}
            name="min_rows"
            type="number"
            min={0}
            defaultValue={initial.minRows ?? ""}
            aria-describedby={keyPatterns ? id("min-rows-hint") : undefined}
          />
          {keyPatterns && (
            <p id={id("min-rows-hint")} className="text-xs text-muted-foreground">
              Leave empty: events of this engine carry no row count, so a threshold drops those without a signal.
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <input id={id("derive")} name="derive_from_findings" type="checkbox" defaultChecked={initial.deriveFromFindings} className="size-4" />
        <Label htmlFor={id("derive")}>Sensitive objects from the Discovery findings (false positives excluded)</Label>
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor={id("manual")}>Other sensitive objects, one per line: {keyPatterns ? MANUAL_FORMAT_KEY_PATTERNS : MANUAL_FORMAT}</Label>
        <textarea
          id={id("manual")}
          name="manual_objects"
          rows={5}
          maxLength={200_000}
          defaultValue={formatManualObjects(initial.manualObjects, keyPatterns)}
          className="rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm"
        />
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit">Send settings</Button>
        {message && (
          <p role="status" className="text-sm text-muted-foreground">
            {message}
          </p>
        )}
      </div>
      {pending && (
        <div role="alertdialog" aria-labelledby={id("confirm-title")} className="flex flex-col gap-3 rounded-md border border-destructive p-4 text-sm">
          <h3 id={id("confirm-title")} className="font-semibold text-destructive">
            Confirm a change that narrows Audit
          </h3>
          <p>{confirmationText(pending.refusal)}</p>
          <p className="text-muted-foreground">The change is recorded in the audit log and a warning stays on the target.</p>
          <div className="flex gap-2">
            <Button type="button" variant="destructive" onClick={() => void send({ ...pending.body, confirm: pending.refusal.digest })}>
              Confirm and send
            </Button>
            <Button type="button" variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </form>
  );
}
