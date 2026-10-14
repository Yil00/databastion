import Link from "next/link";

import { findingsHref, FindingsSummary, FindingsTable } from "@/components/console/findings-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import { parseFindingFilter, type SearchParams } from "@/lib/findings-filter";
import { engineDisplayName } from "@/lib/location-labels";
import { ENGINES } from "@/lib/protocol/enums";
import { listFindings, MAX_LISTED_FINDINGS, summarizeFindings } from "@/server/findings";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/**
 * Findings per target and classifier. Masked samples are decrypted server side for the
 * authenticated user and rendered into this per-request page only (`Cache-Control: no-store`, set
 * by src/proxy.ts); they never go through a JSON API. False positives are hidden unless `fp=1`.
 */
export default async function FindingsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const session = await requirePageSession();
  const filter = parseFindingFilter(await searchParams);
  const db = getDb();
  const [summary, rows] = await Promise.all([summarizeFindings(db, filter), listFindings(db, filter)]);
  const fp = filter.includeFalsePositives === true;
  const base = { agent: filter.agentId, target: filter.targetId, classifier: filter.classifier, engine: filter.engine };
  const filtered = filter.agentId || filter.targetId || filter.classifier || filter.engine;
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <div className="ml-auto flex gap-4 text-sm">
          {filtered && (
            <Link className="hover:underline" prefetch={false} href={findingsHref({ fp })}>
              Clear filters
            </Link>
          )}
          <Link className="hover:underline" prefetch={false} href={findingsHref({ ...base, fp: !fp })}>
            {fp ? "Hide false positives" : "Show false positives"}
          </Link>
        </div>
      </div>
      {filtered && (
        <p className="text-sm text-muted-foreground">
          Filtered on{filter.targetId ? ` target ${filter.targetId}` : ""}
          {filter.classifier ? ` classifier ${filter.classifier}` : ""}
          {filter.engine ? ` engine ${engineDisplayName(filter.engine)}` : ""}
          {filter.agentId && !filter.targetId ? " one agent" : ""}.
        </p>
      )}
      <nav aria-label="Engine" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className="text-muted-foreground">Engine:</span>
        <Link
          className={filter.engine ? "hover:underline" : "font-medium"}
          prefetch={false}
          href={findingsHref({ ...base, engine: undefined, fp })}
          aria-current={filter.engine ? undefined : "page"}
        >
          all
        </Link>
        {ENGINES.map((e) => (
          <Link
            key={e}
            className={filter.engine === e ? "font-medium" : "hover:underline"}
            prefetch={false}
            href={findingsHref({ ...base, engine: e, fp })}
            aria-current={filter.engine === e ? "page" : undefined}
          >
            {engineDisplayName(e)}
          </Link>
        ))}
      </nav>
      <Card>
        <CardHeader>
          <CardTitle>By target and classifier</CardTitle>
        </CardHeader>
        <CardContent>
          <FindingsSummary rows={summary} showFalsePositives={fp} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Locations</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {rows.length >= MAX_LISTED_FINDINGS && (
            <p className="text-sm text-muted-foreground">
              Showing the first {MAX_LISTED_FINDINGS} findings: filter by target or classifier to see the others.
            </p>
          )}
          {session.user.role !== "admin" && (
            <p className="text-sm text-muted-foreground">
              Only administrators can mark a finding as a false positive: ask one if a location is misclassified.
            </p>
          )}
          <FindingsTable
            findings={rows}
            csrfToken={session.csrfToken}
            now={requestTime()}
            canMark={session.user.role === "admin"}
          />
        </CardContent>
      </Card>
    </div>
  );
}
