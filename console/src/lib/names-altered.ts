import { locationPartLabels } from "@/lib/location-labels";

/**
 * Display of the ADR-0056 marker (contract `Location.altered`, `ObjectRef.altered`, decision 3
 * item 6): the agent's name normalization changed these parts, so another object of the engine may
 * have been sent under the same name. The finding and event views say so, so that the
 * administrator checks the database for look-alike names. Notifications are unchanged.
 */

/** Tooltip of the "altered by normalization" mark. */
export const NAMES_ALTERED_TITLE =
  "The agent's name normalization changed these names (invisible or formatting characters removed, compatibility forms such as fullwidth letters or ligatures folded; on CAS, definition keys converted to snake_case), so another object may have been reported under the same name: check the database for look-alike names. A location exception covers an altered part only when its pattern for that part is absent or exactly *.";

const ORDER = ["database", "schema", "object", "field"] as const;

/**
 * The altered parts with the engine's part labels (`object`, `table`, `key pattern`...), in
 * location order, joined with "and" for two and commas before that; empty for no part.
 */
export function alteredPartsLabel(parts: readonly string[] | null | undefined, engine: string | null, database: string | null = null): string {
  if (!parts || parts.length === 0) return "";
  const labels = locationPartLabels(engine, database);
  const names = ORDER.filter((p) => parts.includes(p)).map((p) => labels[p]);
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** The sentence shown under a finding location (empty when nothing was altered). */
export function findingAlteredText(parts: readonly string[] | null | undefined, engine: string | null, database: string | null): string {
  const label = alteredPartsLabel(parts, engine, database);
  if (label === "") return "";
  const plural = ORDER.filter((p) => parts?.includes(p)).length > 1;
  return `${label} name${plural ? "s" : ""} altered by normalization: check for look-alike names`;
}

