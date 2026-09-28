import { CLASSIFIER_REGISTRY } from "@/generated/protocol/classifiers.gen";

/**
 * Lookups in the contract classifier registry (`shared/protocol/classifiers.json`, generated into
 * `CLASSIFIER_REGISTRY`). Versions and ids come from agents or users: they are looked up in a `Map`
 * of `Set`s built from the registry's own entries, never with `in`, bracket access or any other
 * prototype lookup, so `__proto__`, `constructor` or `toString` are never "registered".
 */
const REGISTRY: ReadonlyMap<string, ReadonlySet<string>> = new Map(
  Object.entries(CLASSIFIER_REGISTRY).map(([version, ids]) => [version, new Set<string>(ids)]),
);

/** The classifier ids of a registered `classifiers_version`, or `null` when it is not registered. */
export function registeredClassifiers(version: unknown): ReadonlySet<string> | null {
  return typeof version === "string" ? (REGISTRY.get(version) ?? null) : null;
}

/** `version` is a registered `classifiers_version`. */
export function isRegisteredClassifiersVersion(version: unknown): version is string {
  return registeredClassifiers(version) !== null;
}

/** `id` is a classifier id of the registered `version` (false when the version is not registered). */
export function isRegisteredClassifier(version: unknown, id: unknown): boolean {
  return typeof id === "string" && (registeredClassifiers(version)?.has(id) ?? false);
}

/** Registered versions, in registry order (diagnostics and tests). */
export function registeredClassifiersVersions(): string[] {
  return [...REGISTRY.keys()];
}
