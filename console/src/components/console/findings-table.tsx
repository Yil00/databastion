import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { engineDisplayName, hasNamedLocationParts, isKeyPatternEngine, locationDatabaseShown, locationPartLabels } from "@/lib/location-labels";
import { findingAlteredText, NAMES_ALTERED_TITLE } from "@/lib/names-altered";
import type { Engine } from "@/lib/protocol/enums";
import type { FindingSummaryRow, FindingView } from "@/server/findings";

import { FalsePositiveButton } from "./false-positive-button";
import { KeyPatternText } from "./key-pattern";

/**
 * Findings view parts (server components). Every agent-provided string (target ids, names,
 * classifiers, masked samples) is rendered as a React text node: escaped, never HTML.
 */

export function findingsHref(q: { agent?: string; target?: string; classifier?: string; engine?: Engine; fp?: boolean }): string {
  const params = new URLSearchParams();
  if (q.agent) params.set("agent", q.agent);
  if (q.target) params.set("target", q.target);
  if (q.classifier) params.set("classifier", q.classifier);
  if (q.engine) params.set("engine", q.engine);
  if (q.fp) params.set("fp", "1");
  const s = params.toString();
  return s ? `/findings?${s}` : "/findings";
}

type LocationParts = Pick<FindingView, "databaseName" | "schemaName" | "objectName" | "fieldName">;

/**
 * A finding location on one line. OpenLDAP (ADR-0029 decision 6), CAS (ADR-0041 decision 4) and
 * Redis / Valkey (ADR-0052 decision 7): each part is named (naming context, container, object
 * class, attribute; store, service type, service, path; database, type, key pattern, field), since
 * `schema` and `object` do not mean a schema and a table there. SQLite (ADR-0059 decision 6): table
 * and column, without the database `main`, the same on every target. Plain text: callers render it as
 * a text node (escaped), never as a link.
 */
export function locationLabel(f: LocationParts, engine: string | null = null): string {
  if (!hasNamedLocationParts(engine)) return [f.databaseName, f.schemaName, f.objectName, f.fieldName].filter((p) => p !== null).join(" / ");
  return namedParts(f, engine)
    .map(([label, value]) => `${label} ${value}`)
    .join(" / ");
}

function namedParts(f: LocationParts, engine: string | null): [string, string][] {
  const l = locationPartLabels(engine, f.databaseName);
  const parts: [string, string | null][] = [
    // SQLite: `main` on every target, left out (the target column tells files apart).
    [l.database, locationDatabaseShown(engine) ? f.databaseName : null],
    [l.schema, f.schemaName],
    [l.object, f.objectName],
    [l.field, f.fieldName],
  ];
  return parts.filter((p): p is [string, string] => p[1] !== null);
}

/**
 * The location cell: OpenLDAP, CAS and Redis / Valkey parts one per line with their names (a key
 * pattern as inline code, never a link: contract `KeyPattern` rendering rule); other engines on
 * one line.
 */
export function LocationCell({ location, engine }: { location: LocationParts; engine: string | null }) {
  if (!hasNamedLocationParts(engine)) return <>{locationLabel(location)}</>;
  const l = locationPartLabels(engine, location.databaseName);
  const keyPatterns = isKeyPatternEngine(engine);
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-2 text-xs">
      {namedParts(location, engine).map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="break-all">{keyPatterns && label === l.object ? <KeyPatternText value={value} /> : value}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * ADR-0056 decision 3 item 6: the mark of a finding whose location the agent reported altered by
 * its name normalization (nothing otherwise).
 */
export function FindingAlteredNote({ finding }: { finding: Pick<FindingView, "altered" | "engine" | "databaseName"> }) {
  const text = findingAlteredText(finding.altered, finding.engine, finding.databaseName);
  if (text === "") return null;
  return (
    <div className="text-xs text-muted-foreground first-letter:uppercase" title={NAMES_ALTERED_TITLE} data-names-altered="">
      {text}
    </div>
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
              <div className="text-xs text-muted-foreground">{engineDisplayName(f.engine)}</div>
            </TableCell>
            <TableCell className="max-w-64 break-all whitespace-normal">
              <LocationCell location={f} engine={f.engine} />
              <FindingAlteredNote finding={f} />
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
