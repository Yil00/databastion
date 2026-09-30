import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { isLdapEngine, locationPartLabels } from "@/lib/location-labels";
import type { FindingSummaryRow, FindingView } from "@/server/findings";

import { FalsePositiveButton } from "./false-positive-button";

/**
 * Findings view parts (server components). Every agent-provided string (target ids, names,
 * classifiers, masked samples) is rendered as a React text node: escaped, never HTML.
 */

export function findingsHref(q: { agent?: string; target?: string; classifier?: string; fp?: boolean }): string {
  const params = new URLSearchParams();
  if (q.agent) params.set("agent", q.agent);
  if (q.target) params.set("target", q.target);
  if (q.classifier) params.set("classifier", q.classifier);
  if (q.fp) params.set("fp", "1");
  const s = params.toString();
  return s ? `/findings?${s}` : "/findings";
}

type LocationParts = Pick<FindingView, "databaseName" | "schemaName" | "objectName" | "fieldName">;

/**
 * A finding location on one line. OpenLDAP (ADR-0029 decision 6): each part is named (naming
 * context, container, object class, attribute), since `schema` and `object` do not mean a schema
 * and a table there.
 */
export function locationLabel(f: LocationParts, engine: string | null = null): string {
  if (!isLdapEngine(engine)) return [f.databaseName, f.schemaName, f.objectName, f.fieldName].filter((p) => p !== null).join(" / ");
  return ldapParts(f, engine)
    .map(([label, value]) => `${label} ${value}`)
    .join(" / ");
}

function ldapParts(f: LocationParts, engine: string | null): [string, string][] {
  const l = locationPartLabels(engine);
  const parts: [string, string | null][] = [
    [l.database, f.databaseName],
    [l.schema, f.schemaName],
    [l.object, f.objectName],
    [l.field, f.fieldName],
  ];
  return parts.filter((p): p is [string, string] => p[1] !== null);
}

/** The location cell: OpenLDAP parts one per line with their LDAP names; other engines on one line. */
export function LocationCell({ location, engine }: { location: LocationParts; engine: string | null }) {
  if (!isLdapEngine(engine)) return <>{locationLabel(location)}</>;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-2 text-xs">
      {ldapParts(location, engine).map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function FindingsSummary({ rows, showFalsePositives }: { rows: FindingSummaryRow[]; showFalsePositives: boolean }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">No finding.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Agent</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Classifier</TableHead>
          <TableHead>Locations</TableHead>
          <TableHead>Max confidence</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((r) => (
          <TableRow key={`${r.agentId}/${r.targetId}/${r.classifier}`}>
            <TableCell>{r.agentName}</TableCell>
            <TableCell>
              <Link
                className="hover:underline"
                prefetch={false}
                href={findingsHref({ agent: r.agentId, target: r.targetId, fp: showFalsePositives })}
              >
                {r.targetId}
              </Link>
            </TableCell>
            <TableCell>
              <Link
                className="hover:underline"
                prefetch={false}
                href={findingsHref({ agent: r.agentId, target: r.targetId, classifier: r.classifier, fp: showFalsePositives })}
              >
                {r.classifier}
              </Link>
            </TableCell>
            <TableCell>{r.findings}</TableCell>
            <TableCell>{r.maxConfidence.toFixed(2)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Samples({ samples }: { samples: FindingView["samples"] }) {
  if (samples.state === "none") return <span className="text-muted-foreground">none</span>;
  if (samples.state === "unavailable") {
    return <span className="text-muted-foreground" title="Encryption key unavailable or data unreadable">unavailable</span>;
  }
  return (
    <ul className="font-mono text-xs">
      {samples.values.map((s, i) => (
        <li key={i}>{s}</li>
      ))}
    </ul>
  );
}

export function FindingsTable({
  findings,
  csrfToken,
  now,
  canMark,
}: {
  findings: FindingView[];
  csrfToken: string;
  now: number;
  /** Admins only (M2): others see a hint instead of the button. */
  canMark: boolean;
}) {
  if (findings.length === 0) return <p className="text-sm text-muted-foreground">No finding.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Target</TableHead>
          <TableHead>Location</TableHead>
          <TableHead>Classifier</TableHead>
          <TableHead>Confidence</TableHead>
          <TableHead>Matched / sampled</TableHead>
          <TableHead>Est. rows</TableHead>
          <TableHead>Masked samples</TableHead>
          <TableHead>Fingerprints</TableHead>
          <TableHead>Last seen</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id} className={f.falsePositiveAt ? "text-muted-foreground" : undefined}>
            <TableCell>
              {f.agentName} / {f.targetId}
              <div className="text-xs text-muted-foreground">{f.engine}</div>
            </TableCell>
            <TableCell className="max-w-64 break-all whitespace-normal">
              <LocationCell location={f} engine={f.engine} />
            </TableCell>
            <TableCell>
              {f.classifier}
              {f.falsePositiveAt && (
                <Badge variant="outline" className="ml-2">
                  false positive
                </Badge>
              )}
            </TableCell>
            <TableCell>{f.confidence.toFixed(2)}</TableCell>
            <TableCell>
              {f.matched} / {f.sampled}
            </TableCell>
            <TableCell>{f.estimatedRows ?? ""}</TableCell>
            <TableCell>
              <Samples samples={f.samples} />
            </TableCell>
            <TableCell>{f.fingerprintCount}</TableCell>
            <TableCell>{formatAge(f.lastSeenAt, now)}</TableCell>
            <TableCell>
              {canMark ? (
                <FalsePositiveButton findingId={f.id} falsePositive={f.falsePositiveAt !== null} csrfToken={csrfToken} />
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
