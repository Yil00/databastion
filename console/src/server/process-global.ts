/**
 * Process-wide state that must be shared by every bundled copy of a module.
 *
 * `next build` (Turbopack) compiles a server module once per layer: the route handlers
 * (`[app-route]`), the server components (`[app-rsc]`) and the startup hook (`[instrumentation]`)
 * each get their own instance of the module, with their own module-level variables. A module
 * variable written by `src/instrumentation.ts` is therefore never seen by the route handlers, and a
 * counter incremented by a route is not the one the dedicated `/metrics` listener (started by the
 * startup hook) reads. Worse, the bundler removes a variable that one layer only writes or only
 * reads: `requestPolicyEvaluation()` compiled to an empty function in the route layer, and
 * `setPolicyJobSender()` to a no-op in the instrumentation layer.
 *
 * State that crosses layers (a sender registered at startup, counters exported on `/metrics`, the
 * database pool) is kept on `globalThis` under a `Symbol.for` key instead: one value per Node.js
 * process whatever the number of module copies, and opaque to the bundler's dead-code removal.
 * Keys are namespaced `databastion.<name>`.
 */
export function processGlobal<T>(name: string, init: () => T): T {
  const key = Symbol.for(`databastion.${name}`);
  const store = globalThis as unknown as Record<symbol, unknown>;
  if (!(key in store)) store[key] = init();
  return store[key] as T;
}

/** A mutable process-wide slot (e.g. a sender installed at startup and read by the routes). */
export interface ProcessSlot<T> {
  get(): T | null;
  set(value: T | null): void;
}

export function processSlot<T>(name: string): ProcessSlot<T> {
  const box = processGlobal<{ value: T | null }>(name, () => ({ value: null }));
  return {
    get: () => box.value,
    set: (value) => {
      box.value = value;
    },
  };
}
