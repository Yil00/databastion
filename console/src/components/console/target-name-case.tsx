import { formatAge } from "@/lib/agent-status";
import { NAME_CASE_ENGINES, NAME_CASE_LABELS, nameCaseDisplay, nameCaseValueLabel, type NameCaseRule } from "@/lib/name-case";
import type { LatestNameCaseInventory } from "@/server/name-case-inventory";

/** Shown next to the value: what the rule changes (ADR-0055 decision 7). */
export const NAME_CASE_TITLE =
  "How location exceptions compare this target's names, as its agent read the server's settings (lower_case_table_names on MySQL / " +
  "MariaDB, collations on SQL Server). Unknown is treated as with case. Not reported: compared without case, as before; upgrade the agent.";

/**
 * How a target's names are compared by location exceptions (ADR-0055 decision 7): with case,
 * without case, per database, unknown (treated as with case) or not reported; for `per_database`,
 * the database names and each listed database. Database names are agent-provided strings,
 * rendered as React text nodes (escaped), never as HTML. Only on `mysql`, `mariadb` and
 * `sqlserver` targets (empty elsewhere). The latest inventory of the target, when one ran, with
 * its counts (exception ids are on the policies page).
 */
export function TargetNameCase({
  engine,
  rule,
  inventory,
  now,
}: {
  engine: string;
  rule: NameCaseRule | null;
  inventory?: LatestNameCaseInventory;
  now: number;
}) {
  if (!NAME_CASE_ENGINES.includes(engine)) return null;
  const display = nameCaseDisplay(rule);
  return (
    <div className="flex flex-col gap-0.5 text-xs" title={NAME_CASE_TITLE}>
      <span>{NAME_CASE_LABELS[display]}</span>
      {rule !== null && display === "per_database" && (
        <ul className="flex flex-col gap-0.5 text-muted-foreground">
          <li>database names: {nameCaseValueLabel(rule.databases)}</li>
          <li>other databases: {nameCaseValueLabel(rule.objects)}</li>
          {(rule.except ?? []).map((e) => (
            <li key={e.database}>
              <code className="break-all">{e.database}</code>: {nameCaseValueLabel(e.objects)}
            </li>
          ))}
        </ul>
      )}
      {inventory &&
        (inventory.ok ? (
          <span className="text-muted-foreground">
            {`inventory ${formatAge(inventory.inventory.at, now)}: ${inventory.inventory.exceptionsListed} exception${inventory.inventory.exceptionsListed === 1 ? "" : "s"} no longer covering names differing by case`}
            {inventory.inventory.boundReached ? " (bound reached)" : ""}
          </span>
        ) : (
          <span className="text-destructive">{`inventory failed ${formatAge(inventory.at, now)}`}</span>
        ))}
    </div>
  );
}
