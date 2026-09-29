import { SIGNAL_REGISTRY } from "@/generated/protocol/signals.gen";

/**
 * Lookups in the contract signal registry (`shared/protocol/signals.json`, generated into
 * `SIGNAL_REGISTRY`). The `Signal` schema checks the form only (ADR-0022 decision 5): an agent
 * newer than this console may send an id registered after it was built, and a non-conforming agent
 * may send any well-formed id. Such ids are accepted, stored and matched like the others, and
 * flagged as **unregistered** in the views, notifications and `/metrics`. A `signature.*` id stays
 * severe whether registered or not (fail-safe: an unknown dump tool is still a dump tool).
 *
 * Ids come from agents: they are looked up in a `Set` / with `Object.hasOwn`, never with `in` or a
 * prototype lookup, so `__proto__`, `constructor` or `toString` are never "registered".
 */
const REGISTERED: ReadonlySet<string> = new Set(Object.keys(SIGNAL_REGISTRY));

/** Registered signal ids, in registry order. */
export const REGISTERED_SIGNALS: readonly string[] = [...REGISTERED];

/** `id` is in this console's signal registry. */
export function isRegisteredSignal(id: unknown): boolean {
  return typeof id === "string" && REGISTERED.has(id);
}

/** Meaning of a registered signal, or `null` for an unregistered id. */
export function signalDescription(id: string): string | null {
  if (!Object.hasOwn(SIGNAL_REGISTRY, id)) return null;
  return SIGNAL_REGISTRY[id as keyof typeof SIGNAL_REGISTRY].description;
}

/** The ids of `signals` that are not in the registry, in their order. */
export function unregisteredSignals(signals: readonly string[]): string[] {
  return signals.filter((s) => !REGISTERED.has(s));
}
