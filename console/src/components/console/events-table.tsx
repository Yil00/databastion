import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { eventsHref, principalHref } from "@/lib/events-filter";
import {
  AGGREGATE_PRINCIPAL_TITLE,
  fingerprintNoun,
  fingerprintTitle,
  isAggregatePrincipal,
  isCasEngine,
  isKeyPatternEngine,
  isLdapEngine,
  locationPartLabels,
  shortFingerprint,
  UNRECORDED_PRINCIPAL_TITLE,
} from "@/lib/location-labels";
import { signalDescription } from "@/lib/protocol/signals";
import type { EventView, PrincipalView } from "@/server/events";

import { KeyPatternText } from "./key-pattern";

/**
 * Access events view parts (server components). Every agent-provided string (principal,
 * application, client address, object names, signals) is rendered as a React text node: escaped,
 * never HTML. Events carry no value (ADR-0007): only who, which objects, how many rows, signals.
 */

/**
 * The objects of an event. OpenLDAP (ADR-0029 decision 6): `object class <class> in container
 * <container DN>` (the naming context when no container is known), separated by `;` since DNs hold
 * commas; `*` is an object class the log does not tell (no sensitive object reachable).
 * CAS (ADR-0041 decision 7): `service <name> (<type>)` for a ticket issued to an application (`*`:
 * no registry entry recognized), `service registry` for a change of the registry itself.
 * Redis / Valkey (ADR-0052 decision 7): `key pattern <pattern> in <db>`, never joined with `.`
 * (a key-pattern separator). Plain text, rendered as a text node: never a link.
 */
export function objectsLabel(objects: EventView["objects"], max = 3, engine: string | null = null): string {
  const ldap = isLdapEngine(engine);
  const l = locationPartLabels(engine);
  const names = objects.map((o) =>
    ldap
      ? `${l.object} ${o.object} in ${o.schema !== undefined ? `${l.schema} ${o.schema}` : `${l.database} ${o.database}`}`
      : isCasEngine(engine)
        ? casObjectLabel(o)
        : isKeyPatternEngine(engine)
          ? `${l.object} ${o.object} in ${o.database}`
          : [o.database, o.schema, o.object].filter((x) => x !== undefined).join("."),
  );
  const sep = ldap ? "; " : ", ";
  return names.length > max ? `${names.slice(0, max).join(sep)} and ${names.length - max} more` : names.join(sep);
}

/**
 * The objects cell of an event: Redis / Valkey key patterns as inline code with their database
 * (contract `KeyPattern` rendering rule: escaped text, never a link); other engines as
 * {@link objectsLabel}.
 */
export function ObjectsCell({ objects, engine, max = 3 }: { objects: EventView["objects"]; engine: string | null; max?: number }) {
  if (!isKeyPatternEngine(engine)) return <>{objectsLabel(objects, max, engine)}</>;
  const shown = objects.slice(0, max);
  return (
    <ul className="flex flex-col gap-0.5">
      {shown.map((o, i) => (
        <li key={i}>
          <KeyPatternText value={o.object} /> <span className="text-muted-foreground">in {o.database}</span>
        </li>
      ))}
      {objects.length > max && <li className="text-muted-foreground">and {objects.length - max} more</li>}
    </ul>
  );
}

function casObjectLabel(o: EventView["objects"][number]): string {
  if (o.object === o.database) return o.object === "service_registry" ? "service registry" : `store ${o.object}`;
  return `service ${o.object}${o.schema !== undefined ? ` (${o.schema})` : ""}`;
}

export function formatCount(n: number | null): string {
  if (n === null) return "";
  return n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)} M` : n >= 10_000 ? `${Math.round(n / 1000)} k` : String(Math.round(n));
}

/** Size in bytes, binary units (contract `AccessEvent.bytes`); empty when not reported. */
export function formatBytes(n: number | null): string {
  if (n === null) return "";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return u === 0 ? `${n} B` : `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

/** ADR-0053: what the "objects left out" mark of a flagged event means (tooltip). */
export const OBJECTS_OVERFLOWED_TITLE =
  "The access reached more objects than the event lists: the agent left the others out under a bound (15 named objects per event, or a connector's own bound), and the event's * objects stand for them. Policies treat each * as possibly any object of its database (of the target, for the database *).";

/** The mark of an event flagged `objects_overflowed` (ADR-0053 decision 3 item 7). */
export function ObjectsOverflowedNote() {
  return (
    <div className="text-xs text-muted-foreground" title={OBJECTS_OVERFLOWED_TITLE} data-objects-overflowed="">
      more objects than listed (left out)
    </div>
  );
}

/**
 * The bound score of a flagged event, shown for information as an upper bound ("up to ...");
 * nothing when it is the named score (ADR-0053 decision 3 item 7).
 */
export function boundScoreLabel(score: number | null, boundScore: number | null): string | null {
  if (boundScore === null || boundScore <= (score ?? 0)) return null;
  return `up to ${boundScore}`;
}

export const BOUND_SCORE_TITLE =
  "Upper bound: the score if each * of the event were the most sensitive object of its database. Used by min_score and min_sensitivity conditions; incidents compare the named score only.";

export const UNREGISTERED_SIGNAL_TITLE =
  "Not in this console's signal registry: registered after this console was built, or sent by a non-conforming agent. Stored and matched like the others; a signature.* id is still treated as severe.";

/**
 * A signal id: registered ids carry their meaning as a tooltip; ids missing from the registry
 * (`shared/protocol/signals.json` as built into this console) are flagged "unregistered".
 */
export function SignalBadge({ signal }: { signal: string }) {
  const description = signalDescription(signal);
  if (description !== null) {
    return (
      <Badge variant="outline" title={description}>
        {signal}
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="border-dashed" title={UNREGISTERED_SIGNAL_TITLE}>
      {signal}
      <span className="ml-1 text-muted-foreground">unregistered</span>
    </Badge>
  );
}

/**
 * A principal: the account name (or, OpenLDAP, the DN sent in clear), or a fingerprint. A
 * fingerprint is never shown as if it were a name: labelled, shortened in a monospace font, with
 * what it is and its full value in the tooltip. The CAS `*` aggregate is shown as "several
 * accounts", never as an account named `*`. An event without a recorded account (Redis / Valkey,
 * contract `Principal.account_not_recorded`) is shown as "account not recorded".
 */
export function PrincipalLabel({
  principal,
  fingerprinted,
  engine = null,
  notRecorded = false,
}: {
  principal: string;
  fingerprinted: boolean;
  engine?: string | null;
  notRecorded?: boolean;
}) {
  if (notRecorded) {
    return (
      <span title={UNRECORDED_PRINCIPAL_TITLE} data-unrecorded-principal="" className="text-muted-foreground">
        account not recorded
      </span>
    );
  }
  if (!fingerprinted && isAggregatePrincipal(principal, engine)) {
    return (
      <span title={AGGREGATE_PRINCIPAL_TITLE} data-aggregate-principal="">
        <span className="text-muted-foreground">several accounts</span> <code className="font-mono text-xs">*</code>
      </span>
    );
  }
  if (!fingerprinted) return <span className="break-all">{principal}</span>;
  return (
    <span title={fingerprintTitle(principal, engine)} data-fingerprint="">
      <span className="text-muted-foreground">{fingerprintNoun(engine)}</span> <code className="font-mono text-xs">{shortFingerprint(principal)}</code>
    </span>
  );
}

export function EventsTable({ events, now }: { events: EventView[]; now: number }) {
  if (events.length === 0) return <p className="text-sm text-muted-foreground">No access event.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Principal</TableHead>
          <TableHead>Client</TableHead>
          <TableHead>Action</TableHead>
          <TableHead>Objects</TableHead>
          <TableHead>Rows / bytes</TableHead>
          <TableHead>Signals</TableHead>
          <TableHead>Score</TableHead>
          <TableHead>Incidents</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((e) => (
          <TableRow key={e.id}>
            <TableCell title={e.ts.toISOString()}>
              {formatAge(e.ts, now)}
              {e.aggregatedCount > 1 && <div className="text-xs text-muted-foreground">x{e.aggregatedCount}</div>}
            </TableCell>
            <TableCell>
              <Link className="hover:underline" prefetch={false} href={eventsHref({ agent: e.agentId, target: e.targetId })}>
                {e.agentName} / {e.targetId}
              </Link>
              <div className="text-xs text-muted-foreground">{e.source}</div>
            </TableCell>
            <TableCell className="max-w-48 whitespace-normal">
              {e.accountNotRecorded ? (
                // No baseline is built for these events (ADR-0052 decision 8): the link lists the
                // events of the same client network instead of a principal page.
                <Link className="hover:underline" prefetch={false} href={eventsHref({ agent: e.agentId, target: e.targetId, principal: e.principalKey })}>
                  <PrincipalLabel principal={e.principal} fingerprinted={false} engine={e.engine} notRecorded />
                </Link>
              ) : (
                <Link className="hover:underline" prefetch={false} href={principalHref(e.agentId, e.targetId, e.principalKey)}>
                  <PrincipalLabel principal={e.principal} fingerprinted={e.fingerprinted} engine={e.engine} />
                </Link>
              )}
            </TableCell>
            <TableCell className="max-w-40 break-all whitespace-normal text-xs">
              {e.clientAddr ?? ""}
              {e.application ? <div className="text-muted-foreground">{e.application}</div> : null}
            </TableCell>
            <TableCell>{e.action}</TableCell>
            <TableCell className="max-w-64 break-all whitespace-normal text-xs">
              <ObjectsCell objects={e.objects} engine={e.engine} />
              {e.objectsOverflowed && <ObjectsOverflowedNote />}
            </TableCell>
            <TableCell>
              {formatCount(e.rows)}
              {e.bytes !== null && (
                <div className="text-xs text-muted-foreground" title={`${e.bytes} bytes, as reported by the source`}>
                  {formatBytes(e.bytes)}
                </div>
              )}
            </TableCell>
            <TableCell className="max-w-48 whitespace-normal">
              <div className="flex flex-wrap gap-1">
                {e.signals.map((s) => (
                  <Link key={s} prefetch={false} href={eventsHref({ signal: s })}>
                    <SignalBadge signal={s} />
                  </Link>
                ))}
                {e.anomaly && <Badge variant="destructive">above baseline</Badge>}
                {e.unexpectedTarget && (
                  <Badge variant="outline" title="Received for a target the agent no longer reports, or whose Audit settings are disabled">
                    unexpected target
                  </Badge>
                )}
              </div>
            </TableCell>
            <TableCell>
              {e.evaluated ? (e.score ?? 0) : <span className="text-muted-foreground">pending</span>}
              {e.evaluated && e.sensitivity !== null && e.sensitivity > 0 && (
                <div className="text-xs text-muted-foreground">sensitivity {e.sensitivity}</div>
              )}
              {e.evaluated && e.objectsOverflowed && boundScoreLabel(e.score, e.boundScore) !== null && (
                <div className="text-xs text-muted-foreground" title={BOUND_SCORE_TITLE} data-bound-score="">
                  {boundScoreLabel(e.score, e.boundScore)}
                  {e.boundSensitivity !== null && ` (sensitivity ${e.boundSensitivity})`}
                </div>
              )}
            </TableCell>
            <TableCell className="text-xs">
              {e.incidentIds.map((id) => (
                <div key={id}>
                  <Link className="hover:underline" prefetch={false} href={`/incidents/${id}`}>
                    {id.slice(0, 8)}
                  </Link>
                </div>
              ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function PrincipalsTable({ principals, now }: { principals: PrincipalView[]; now: number }) {
  if (principals.length === 0) return <p className="text-sm text-muted-foreground">No principal yet.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Principal</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Events</TableHead>
          <TableHead>Typical rows</TableHead>
          <TableHead>Highest score</TableHead>
          <TableHead>Anomalies</TableHead>
          <TableHead>Last event</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {principals.map((p) => (
          <TableRow key={`${p.agentId}/${p.targetId}/${p.principalKey}`}>
            <TableCell className="max-w-48 whitespace-normal">
              <Link className="hover:underline" prefetch={false} href={principalHref(p.agentId, p.targetId, p.principalKey)}>
                <PrincipalLabel principal={p.principal} fingerprinted={p.fingerprinted} engine={p.engine} />
              </Link>
            </TableCell>
            <TableCell>
              {p.agentName} / {p.targetId}
            </TableCell>
            <TableCell>{p.events}</TableCell>
            <TableCell>{p.warm ? formatCount(p.baselineRows) : <span className="text-muted-foreground">warming up</span>}</TableCell>
            <TableCell>{p.maxScore}</TableCell>
            <TableCell>{p.anomalies}</TableCell>
            <TableCell>{formatAge(p.lastEventAt, now)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
