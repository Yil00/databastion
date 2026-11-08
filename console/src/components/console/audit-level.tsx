import { Badge } from "@/components/ui/badge";
import { DISCOVERY_ONLY_LABEL, DISCOVERY_ONLY_TITLE, isDiscoveryOnlyEngine } from "@/lib/location-labels";

/**
 * A target's audit level (agent page). A Discovery-only engine (SQLite, ADR-0059 decision 7) shows
 * "Discovery only" next to its level (`none`): there is no Audit to configure there.
 */
export function AuditLevelLabel({ engine, level }: { engine: string; level: string }) {
  if (!isDiscoveryOnlyEngine(engine)) return <>{level}</>;
  return (
    <span title={DISCOVERY_ONLY_TITLE}>
      {level}{" "}
      <Badge variant="outline" data-discovery-only="">
        {DISCOVERY_ONLY_LABEL}
      </Badge>
    </span>
  );
}
