import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { EventConditions, ObjectPattern } from "@/lib/event-model";
import { exceptionIsCrossTarget } from "@/lib/policy-common";
import type { FindingConditions, LocationPattern, PolicyConditions, PolicySource } from "@/lib/policy-model";
import type { CaseInventoryStatus } from "@/server/exception-case-inventory";
import type { ExceptionView, PolicyView } from "@/server/policies";

import { SeverityBadge } from "./incidents-table";
import { DeleteExceptionButton, PolicyRowActions, RunCaseInventoryButton } from "./policy-actions";

/**
 * Policies view parts (server components). Admin-typed names, descriptions and reasons, and every
 * agent-provided identifier, are rendered as React text nodes (escaped).
 */

export function locationPatternLabel(l: LocationPattern): string {
  return (["database", "schema", "object", "field"] as const)
    .filter((p) => l[p] !== undefined)
    .map((p) => `${p} ~ ${l[p]}`)
    .join(", ");
}

export function objectPatternLabel(o: ObjectPattern): string {
  return (["database", "schema", "object"] as const)
    .filter((p) => o[p] !== undefined)
    .map((p) => `${p} ~ ${o[p]}`)
    .join(", ");
}

/** One line per condition of an `access_event` policy, in reading order. */
export function eventConditionLines(c: EventConditions): string[] {
  const lines: string[] = [];
  if (c.signals) lines.push(`signal in ${c.signals.join(", ")}`);
  if (c.event_actions) lines.push(`action in ${c.event_actions.join(", ")}`);
  if (c.anomaly) lines.push("volume above the principal's baseline");
  if (c.min_score !== undefined) lines.push(`score >= ${c.min_score}`);
  if (c.min_sensitivity !== undefined) lines.push(`sensitivity >= ${c.min_sensitivity}`);
  if (c.min_rows !== undefined) lines.push(`rows >= ${c.min_rows}`);
  if (c.principals) lines.push(`principal ~ ${c.principals.join(", ")}`);
  if (c.exclude_principals) lines.push(`principal not ~ ${c.exclude_principals.join(", ")}`);
  if (c.objects) lines.push(objectPatternLabel(c.objects));
  if (c.sources) lines.push(`source in ${c.sources.join(", ")}`);
  if (c.target_ids) lines.push(`target in ${c.target_ids.join(", ")}`);
  if (c.engines) lines.push(`engine in ${c.engines.join(", ")}`);
  if (c.agent_ids) lines.push(`agent in ${c.agent_ids.length} selected`);
  return lines;
}

/** One line per condition, in reading order ("every finding" when empty). */
export function conditionLines(conditions: PolicyConditions, source: PolicySource = "finding"): string[] {
  if (source === "access_event") return eventConditionLines(conditions as EventConditions);
  const c = conditions as FindingConditions;
  const lines: string[] = [];
  if (c.classifiers) lines.push(`classifier in ${c.classifiers.join(", ")}`);
  if (c.target_ids) lines.push(`target in ${c.target_ids.join(", ")}`);
  if (c.engines) lines.push(`engine in ${c.engines.join(", ")}`);
  if (c.agent_ids) lines.push(`agent in ${c.agent_ids.length} selected`);
  if (c.location) lines.push(locationPatternLabel(c.location));
  if (c.min_confidence !== undefined) lines.push(`confidence >= ${c.min_confidence}`);
  if (c.min_matched !== undefined) lines.push(`matched >= ${c.min_matched}`);
  if (c.min_match_ratio !== undefined) lines.push(`matched / sampled >= ${c.min_match_ratio}`);
  return lines.length > 0 ? lines : ["every finding"];
}

/** Form values of an existing policy (the edit form's initial values). */
export function policyFormValues(p: PolicyView): Record<string, string | boolean> {
  const common = {
    source: p.source,
    name: p.name,
    description: p.description ?? "",
    enabled: p.enabled,
    severity: p.severity,
    notify: p.notifyChannels.join(", "),
  };
  if (p.source === "access_event") {
    const e = p.conditions as EventConditions;
    return {
      ...common,
      signals: e.signals?.join(", ") ?? "",
      event_actions: e.event_actions?.join(", ") ?? "",
      sources: e.sources?.join(", ") ?? "",
      principals: e.principals?.join(", ") ?? "",
      exclude_principals: e.exclude_principals?.join(", ") ?? "",
      target_ids: e.target_ids?.join(", ") ?? "",
      engines: e.engines?.join(", ") ?? "",
      agent_ids: e.agent_ids?.join(", ") ?? "",
      "objects.database": e.objects?.database ?? "",
      "objects.schema": e.objects?.schema ?? "",
      "objects.object": e.objects?.object ?? "",
      min_rows: e.min_rows?.toString() ?? "",
      min_score: e.min_score?.toString() ?? "",
      min_sensitivity: e.min_sensitivity?.toString() ?? "",
      anomaly: e.anomaly === true,
    };
  }
  const c = p.conditions as FindingConditions;
  return {
    ...common,
    classifiers: c.classifiers?.join(", ") ?? "",
    target_ids: c.target_ids?.join(", ") ?? "",
    engines: c.engines?.join(", ") ?? "",
    agent_ids: c.agent_ids?.join(", ") ?? "",
    "location.database": c.location?.database ?? "",
    "location.schema": c.location?.schema ?? "",
    "location.object": c.location?.object ?? "",
    "location.field": c.location?.field ?? "",
    min_confidence: c.min_confidence?.toString() ?? "",
    min_match_ratio: c.min_match_ratio?.toString() ?? "",
    min_matched: c.min_matched?.toString() ?? "",
  };
}

export function PoliciesTable({ policies, isAdmin, csrfToken }: { policies: PolicyView[]; isAdmin: boolean; csrfToken: string }) {
  if (policies.length === 0) return <p className="text-sm text-muted-foreground">No policy.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Conditions</TableHead>
          <TableHead>Incident</TableHead>
          <TableHead>Notify</TableHead>
          <TableHead>State</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {policies.map((p) => (
          <TableRow key={p.id} className={p.enabled ? undefined : "text-muted-foreground"}>
            <TableCell className="max-w-56 break-words whitespace-normal">
              <Link className="font-medium hover:underline" prefetch={false} href={`/policies/${p.id}`}>
                {p.name}
              </Link>
              {p.description && <div className="text-xs text-muted-foreground">{p.description}</div>}
            </TableCell>
            <TableCell className="max-w-80 whitespace-normal">
              <ul className="text-xs">
                <li className="text-muted-foreground">{p.source === "access_event" ? "access events" : "findings"}</li>
                {conditionLines(p.conditions, p.source).map((line, i) => (
                  <li key={i} className="break-all">
                    {line}
                  </li>
                ))}
              </ul>
            </TableCell>
            <TableCell>
              <SeverityBadge severity={p.severity} />
            </TableCell>
            <TableCell className="text-xs">{p.notifyChannels.join(", ")}</TableCell>
            <TableCell>
              <Badge variant={p.enabled ? "default" : "outline"}>{p.enabled ? "enabled" : "disabled"}</Badge>
              <div className="mt-1 text-xs text-muted-foreground">
                rev. {p.revision}
                {p.enabled && !p.evaluated ? ", applying" : ""}
              </div>
            </TableCell>
            <TableCell>
              {isAdmin ? (
                <PolicyRowActions policyId={p.id} policyName={p.name} enabled={p.enabled} csrfToken={csrfToken} />
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ExceptionsTable({
  exceptions,
  isAdmin,
  csrfToken,
  now,
}: {
  exceptions: ExceptionView[];
  isAdmin: boolean;
  csrfToken: string;
  now: number;
}) {
  if (exceptions.length === 0) return <p className="text-sm text-muted-foreground">No exception.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Policy</TableHead>
          <TableHead>Scope</TableHead>
          <TableHead>Reason</TableHead>
          <TableHead>Expires</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {exceptions.map((e) => {
          const expired = e.expiresAt !== null && e.expiresAt.getTime() <= now;
          const scope = exceptionScopeLabels(e);
          return (
            <TableRow key={e.id} className={expired ? "text-muted-foreground" : undefined}>
              <TableCell>{e.policyId ? (e.policyName ?? "?") : "all policies"}</TableCell>
              <TableCell className="max-w-80 break-all whitespace-normal text-xs">{scope.join("; ")}</TableCell>
              <TableCell className="max-w-64 break-words whitespace-normal">{e.reason}</TableCell>
              <TableCell>
                {e.expiresAt ? e.expiresAt.toISOString().slice(0, 16).replace("T", " ") + " UTC" : "never"}
                {expired && (
                  <Badge variant="outline" className="ml-2">
                    expired
                  </Badge>
                )}
              </TableCell>
              <TableCell>{isAdmin ? <DeleteExceptionButton exceptionId={e.id} csrfToken={csrfToken} /> : null}</TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

export function exceptionScopeLabels(e: ExceptionView): string[] {
  return [
    e.agentId ? `agent ${e.agentName ?? e.agentId}` : null,
    e.targetId ? `target ${e.targetId}` : null,
    e.classifier ? `classifier ${e.classifier}` : null,
    e.location ? locationPatternLabel(e.location) : null,
    // P10-C review R2: how a location exception not scoped to an agent and a target treats SQLite.
    exceptionIsCrossTarget(e) ? (e.crossTarget ? "every SQLite target (cross-target, confirmed)" : "no SQLite target (not target-scoped)") : null,
  ].filter((x): x is string => x !== null);
}

/**
 * Exceptions whose effect changed with case-sensitive matching (ADR-0054 decision 6): the latest
 * inventory (worker start after the upgrade, or an administrator's run), with the findings and
 * events each one may no longer cover (upper bounds), and a failed run more recent than it.
 * Exceptions deleted since are shown by id.
 */
export function CaseInventoryView({
  status,
  exceptions,
  isAdmin,
  csrfToken,
}: {
  status: CaseInventoryStatus;
  exceptions: ExceptionView[];
  isAdmin: boolean;
  csrfToken: string;
}) {
  const byId = new Map(exceptions.map((e) => [e.id, e]));
  const { latest: inventory, failure } = status;
  const when = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        Location exceptions compare names with case on PostgreSQL, MongoDB, Redis, Valkey, Apereo CAS and SQLite
        targets. The exceptions below covered stored findings or access events only because case was ignored: review them, and
        correct a pattern written in another case than the real name.
      </p>
      {failure && (
        <p role="alert" className="text-sm text-destructive">
          The inventory run of {when(failure.at)} ({failure.trigger === "user" ? "on demand" : "worker start"}) failed
          {failure.errorCode === "inventory_running"
            ? ": another run was in progress."
            : failure.errorCode === "actor_gone"
              ? ": the administrator who requested it is no longer an enabled administrator."
              : ` (error ${failure.errorCode}); the worker log has the details.`}
        </p>
      )}
      {inventory === null ? (
        <p className="text-sm text-muted-foreground">No inventory has run yet (the worker runs one at its first start).</p>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            Last run {when(inventory.at)} ({inventory.trigger === "user" ? "on demand" : "worker start"}):
            {" "}
            {inventory.exceptionsCompared} of {inventory.exceptionsTotal} active location exceptions compared against{" "}
            {inventory.findingNamesCompared} finding names and {inventory.eventNamesCompared} event object names.
          </p>
          {inventory.boundReached && (
            <p role="alert" className="text-sm text-destructive">
              The run reached its bound: only the names and exceptions compared above were checked, so other exceptions may be
              affected.
              {inventory.exceptionsCompared < inventory.exceptionsTotal &&
                ` The ${inventory.exceptionsTotal - inventory.exceptionsCompared} most recently created exceptions were not compared.`}
            </p>
          )}
          {inventory.entries.length === 0 ? (
            <p className="text-sm text-muted-foreground">No exception is affected.</p>
          ) : (
            <>
            <p className="text-xs text-muted-foreground">
              Counts are upper bounds: another exception may still cover an item, and an event is counted when at least one of its
              objects is no longer covered by this exception.
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Exception</TableHead>
                  <TableHead>Findings no longer covered (up to)</TableHead>
                  <TableHead>Events no longer covered (up to)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inventory.entries.map((entry) => {
                  const e = byId.get(entry.exceptionId);
                  return (
                    <TableRow key={entry.exceptionId}>
                      <TableCell className="max-w-96 break-all whitespace-normal text-xs">
                        {e ? (
                          <>
                            {e.policyId ? (e.policyName ?? "?") : "all policies"}: {exceptionScopeLabels(e).join("; ")}
                          </>
                        ) : (
                          <span className="text-muted-foreground">deleted exception {entry.exceptionId}</span>
                        )}
                      </TableCell>
                      <TableCell>{entry.findings}</TableCell>
                      <TableCell>{entry.events}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            </>
          )}
          {inventory.truncated && (
            <p className="text-xs text-muted-foreground">
              {inventory.exceptionsListed} exceptions are affected; the {inventory.entries.length} with the most items are listed.
            </p>
          )}
        </>
      )}
      {isAdmin && <RunCaseInventoryButton csrfToken={csrfToken} />}
    </div>
  );
}
