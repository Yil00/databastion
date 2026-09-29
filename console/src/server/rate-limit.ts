import { sql, type SQL } from "drizzle-orm";

import { getRateLimitDb, RATE_LIMIT_POOL, type Database } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";

import { hmacSha256Hex, serverSubkey, sha256Hex } from "./crypto";
import { processGlobal } from "./process-global";

/**
 * Fixed-window rate limiters (P4-D: shared across console processes).
 *
 * A limiter created with {@link RateLimiter.shared} keeps its counters in the console's PostgreSQL
 * (`rate_limit_counters`), so N web processes enforce ONE limit, not N. Each window is anchored at
 * the first hit of the key, exactly like the in-memory limiter: one row per (limiter, key), reset in
 * place by the first hit after `expires_at`. Every shared operation is ONE statement (one
 * round-trip): an `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` for a hit, the same with a
 * `WHERE count < limit` guard for a reservation (atomic check-and-count: concurrent requests from
 * any process cannot overrun the limit), a guarded `UPDATE` for a refund, a `SELECT` for a check.
 * Window instants use the database clock; `Retry-After` is the rest of the window as the database
 * sees it. Keys are stored as an HMAC (see `rateLimitKeyHash`), never in clear. Expired rows are
 * pruned by the worker (`pruneRateLimitCounters`).
 *
 * Each limiter also keeps the in-memory counters it always had (the synchronous `check` / `hit` /
 * `reserve` / `charge` / `count`, bounded to `maxKeys` keys). For a shared limiter they are a
 * per-process PRE-CHECK: they count this process's own hits, a subset of the shared ones, so they
 * can only reject earlier (at worst at the pre-P4-D per-process limit), never admit more. A key the
 * store reports at its limit (a refused reservation, a hit or check at the limit) is also recorded
 * there as limited until the end of the store's window (a negative entry), so a flood on one key
 * costs each process at most about `limit + 1` store statements per window, not one per request
 * (security review H1). They are instance fields on purpose, not `processGlobal` state: a bundled
 * copy of this module with its own pre-check counters is still bounded by the shared store.
 * Production code uses the asynchronous `*Shared` methods; the synchronous ones only touch this
 * process (tests, and the limiters that are local by design).
 *
 * The store runs on a dedicated small pool (`getRateLimitPool`: 3 connections, `lock_timeout` and
 * `statement_timeout`), so contention on a hot counter row cannot starve the main pool, and a
 * statement the limiter gave up on is cancelled by the server instead of committing late.
 *
 * Limiters declared with `requiresServerKey` (the username-derived keys of the login) are kept per
 * process, as before P4-D, when no server key is available: their keys would otherwise be stored as
 * an unkeyed hash of what was typed in the username field (possibly a password; review M1).
 *
 * Refunds give the hit back in the shared store (and in the pre-check) only while its window is
 * still the current one; they are idempotent. A refund is fire-and-forget for the caller, but a
 * later operation of the same limiter on the same key waits for it, so it is never overtaken by the
 * next request of the same process.
 *
 * Store failures (an error, a server-side timeout, or no answer within `STORE_GUARD_MS`) follow the limiter's failure
 * mode; either way a warning is logged at most once per minute per limiter, and
 * `databastion_console_rate_limit_store_errors_total` counts them:
 * - `closed` (agent authentication, login, enrollment, rotation, test sends): the key is treated as
 *   over its limit (a reservation or a check is refused with `Retry-After:
 *   FAIL_CLOSED_RETRY_AFTER_S`, a hit reports `limited`). A `charge` (which never refuses) and a
 *   `count` fall back to this process's counters;
 * - `local` (ingest request and stored-batch rates, integrity and audit budgets, late rotate
 *   retries): this process's counters decide, i.e. the pre-P4-D per-process limit.
 */
export interface RateLimitDecision {
  limited: boolean;
  /** Seconds until the window resets (>= 1), for `Retry-After`. */
  retryAfterS: number;
}

/** Gives a counted hit back (idempotent; fire-and-forget, see the module comment). */
export type Refund = () => void;

/** Outcome of an atomic check-and-count ({@link RateLimiter.reserveShared}). */
export type Reservation = { ok: true; refund: Refund } | { ok: false; retryAfterS: number };

/** What a shared limiter does when its store fails (see the module comment). */
export type StoreFailureMode = "closed" | "local";

/** `Retry-After` of a request refused because the shared store failed (fail-closed limiters). */
export const FAIL_CLOSED_RETRY_AFTER_S = 5;
/**
 * Client-side guard: a store operation not answered within this delay counts as a store failure.
 * Longer than the dedicated pool's connection wait plus its statement timeout, so for the
 * PostgreSQL store the server cancels the statement first (it never commits after the guard).
 */
export const STORE_GUARD_MS = RATE_LIMIT_POOL.connectionTimeoutMs + RATE_LIMIT_POOL.statementTimeoutMs + 1_000;
/** At most one store-failure warning per limiter per this period. */
export const STORE_WARNING_INTERVAL_MS = 60_000;
const MAX_RETRY_AFTER_S = 3600;
const LIMITER_NAME = /^[a-z0-9_.]{1,64}$/;

/** State of one shared window, as the store returns it. */
export interface StoreWindow {
  count: number;
  /** Window start, epoch milliseconds (database clock): identifies the window for refunds. */
  windowStartMs: number;
  /** Milliseconds until the window ends (database clock), >= 0. */
  remainingMs: number;
}

export interface StoreKey {
  limiter: string;
  keyHash: string;
}

/** Persistence of the shared counters: {@link PgRateLimitStore}; tests may inject another. */
export interface RateLimitStore {
  /** Counts one hit (unconditionally) and returns the window after it. */
  hit(k: StoreKey, windowMs: number): Promise<StoreWindow>;
  /** Counts one hit only while the window holds fewer than `limit` hits (or has expired). */
  reserve(k: StoreKey, windowMs: number, limit: number): Promise<{ counted: boolean; window: StoreWindow | null }>;
  /** Current (unexpired) windows of `keys`, by {@link storeKeyId}. */
  check(keys: StoreKey[]): Promise<Map<string, StoreWindow>>;
  /** Gives one hit back, if the window starting at `windowStartMs` is still the current one. */
  refund(k: StoreKey, windowStartMs: number): Promise<void>;
  /** Deletes the window of one key, or every window of the limiter. */
  reset(limiter: string, keyHash?: string): Promise<void>;
}

export const storeKeyId = (k: StoreKey) => `${k.limiter}\0${k.keyHash}`;

/** Counters of this process (exported on `/metrics`). */
export const rateLimitStoreStats = processGlobal("rateLimitStoreStats", () => ({ errors: 0, shortCircuited: 0 }));

/**
 * Circuit breaker (security review L-A): after a store failure, the store is not called for
 * `openMs`; every operation of every limiter on that store applies its failure mode at once. Sheds
 * the waiters of the dedicated pool during an outage and bounds the latency of requests that hit
 * several limiters in a row (a login would otherwise wait for each of them). Per process and store.
 */
export const STORE_BREAKER = { openMs: 1_500 };
const breakers = processGlobal("rateLimitStoreBreakers", () => new Map<RateLimitStore, number>());

/** Test hook: closes every circuit breaker of this process. */
export function resetRateLimitBreakersForTests(): void {
  breakers.clear();
}
const lastWarning = processGlobal("rateLimitStoreWarnings", () => new Map<string, number>());

export const RATE_LIMIT_KEY_DOMAIN = "rate-limit-keys.v1";

/**
 * Stored form of a limiter key: HMAC-SHA256 under the server-key subkey `rate-limit-keys.v1`, so a
 * database dump neither reveals nor allows testing guesses of the IPs, usernames as typed (possibly
 * a password), device nonces or agent ids. Without a server key (only possible in production with the
 * explicit `DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1` override): domain-separated SHA-256.
 */
export function rateLimitKeyHash(limiter: string, key: string): string {
  const subkey = serverSubkey(RATE_LIMIT_KEY_DOMAIN);
  const input = `${limiter}\0${key}`;
  return subkey ? hmacSha256Hex(subkey, input) : sha256Hex(`databastion.${RATE_LIMIT_KEY_DOMAIN}\0${input}`);
}

type Row = {
  counted?: boolean;
  count: number;
  window_start_ms: number;
  remaining_ms: number;
  limiter?: string;
  key_hash?: string;
};

const toWindow = (r: Row): StoreWindow => ({
  count: Number(r.count),
  windowStartMs: Number(r.window_start_ms),
  remainingMs: Math.max(0, Number(r.remaining_ms)),
});

/**
 * The counters in the console's PostgreSQL (`rate_limit_counters`, migrations `0029`, `0030`), on
 * the dedicated rate-limit pool by default.
 */
export class PgRateLimitStore implements RateLimitStore {
  constructor(private readonly db: () => Database = getRateLimitDb) {}

  /** The upsert of `hit` and `reserve` (`guard`: the reservation condition, or none). */
  private upsert(k: StoreKey, windowMs: number, guard: SQL | null): SQL {
    return sql`
      insert into rate_limit_counters as c (limiter, key_hash, window_start, expires_at, count)
      values (${k.limiter}, ${k.keyHash}, date_trunc('milliseconds', now()),
              date_trunc('milliseconds', now()) + ${windowMs}::integer * interval '1 millisecond', 1)
      on conflict (limiter, key_hash) do update set
        window_start = case when c.expires_at <= now() then excluded.window_start else c.window_start end,
        expires_at = case when c.expires_at <= now() then excluded.expires_at else c.expires_at end,
        count = case when c.expires_at <= now() then 1 else least(c.count + 1, 2147483647) end
      ${guard ?? sql``}
      returning c.count,
        (extract(epoch from c.window_start) * 1000)::float8 as window_start_ms,
        (extract(epoch from (c.expires_at - now())) * 1000)::float8 as remaining_ms`;
  }

  async hit(k: StoreKey, windowMs: number): Promise<StoreWindow> {
    const res = await this.db().execute<Row>(this.upsert(k, windowMs, null));
    const row = res.rows[0];
    if (!row) throw new Error("rate-limit upsert returned no row");
    return toWindow(row);
  }

  async reserve(k: StoreKey, windowMs: number, limit: number): Promise<{ counted: boolean; window: StoreWindow | null }> {
    // The guarded upsert counts only below the limit (or in a new window). When it does not count,
    // the second branch reads the window from the statement snapshot (for `Retry-After`).
    const res = await this.db().execute<Row>(sql`
      with up as (${this.upsert(k, windowMs, sql`where c.expires_at <= now() or c.count < ${limit}::bigint`)})
      select true as counted, count, window_start_ms, remaining_ms from up
      union all
      select false, c.count, (extract(epoch from c.window_start) * 1000)::float8,
        (extract(epoch from (c.expires_at - now())) * 1000)::float8
      from rate_limit_counters c
      where c.limiter = ${k.limiter} and c.key_hash = ${k.keyHash} and not exists (select 1 from up)`);
    const row = res.rows[0];
    // No row: the upsert did not count (the conflicting row was locked and re-checked at its
    // latest version) and the row is not visible in this statement's snapshot, because a
    // concurrent transaction created or re-created it after the snapshot was taken. Not counted;
    // `Retry-After` falls back to the whole window.
    if (!row) return { counted: false, window: null };
    return { counted: row.counted === true, window: toWindow(row) };
  }

  async check(keys: StoreKey[]): Promise<Map<string, StoreWindow>> {
    const out = new Map<string, StoreWindow>();
    if (keys.length === 0) return out;
    const pairs = sql.join(
      keys.map((k) => sql`(${k.limiter}, ${k.keyHash})`),
      sql`, `,
    );
    const res = await this.db().execute<Row>(sql`
      select limiter, key_hash, count,
        (extract(epoch from window_start) * 1000)::float8 as window_start_ms,
        (extract(epoch from (expires_at - now())) * 1000)::float8 as remaining_ms
      from rate_limit_counters
      where (limiter, key_hash) in (${pairs}) and expires_at > now()`);
    for (const row of res.rows) {
      out.set(storeKeyId({ limiter: String(row.limiter), keyHash: String(row.key_hash) }), toWindow(row));
    }
    return out;
  }

  async refund(k: StoreKey, windowStartMs: number): Promise<void> {
    await this.db().execute(sql`
      update rate_limit_counters set count = count - 1
      where limiter = ${k.limiter} and key_hash = ${k.keyHash} and count > 0 and expires_at > now()
        and extract(epoch from window_start) * 1000 = ${windowStartMs}::numeric`);
  }

  async reset(limiter: string, keyHash?: string): Promise<void> {
    await this.db().execute(
      keyHash === undefined
        ? sql`delete from rate_limit_counters where limiter = ${limiter}`
        : sql`delete from rate_limit_counters where limiter = ${limiter} and key_hash = ${keyHash}`,
    );
  }
}

/**
 * Rows deleted per statement by {@link pruneRateLimitCounters}: small, so the row locks a prune
 * statement holds stay far below the dedicated pool's `lock_timeout` (1.5 s) and pruning cannot
 * make the limiters fail (and trip the circuit breaker) by itself (review L-2).
 */
export const PRUNE_CHUNK = 1_000;

/**
 * Deletes expired windows (worker queue `rate_limits.prune`), in chunks, within `budgetMs`. Deleting
 * an expired window changes no decision: the next hit of its key would reset it anyway. Returns the
 * number of rows deleted and whether expired rows may remain.
 */
export async function pruneRateLimitCounters(
  db: Database,
  opts: { budgetMs?: number; chunk?: number } = {},
): Promise<{ deleted: number; more: boolean }> {
  const deadline = Date.now() + (opts.budgetMs ?? 20_000);
  const chunk = opts.chunk ?? PRUNE_CHUNK;
  let deleted = 0;
  for (;;) {
    const res = await db.execute(sql`
      delete from rate_limit_counters
      where ctid in (select ctid from rate_limit_counters where expires_at <= now() limit ${chunk})`);
    const n = res.rowCount ?? 0;
    deleted += n;
    if (n < chunk) return { deleted, more: false };
    if (Date.now() >= deadline) return { deleted, more: true };
  }
}

const FAILED = Symbol("rate-limit store failure");

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("rate-limit store timeout")), ms);
    timer.unref?.();
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

const toRetryAfterS = (ms: number) => Math.min(MAX_RETRY_AFTER_S, Math.max(1, Math.ceil(ms / 1000)));

interface Window {
  count: number;
  resetAt: number;
}

interface SharedConfig {
  name: string;
  onStoreError: StoreFailureMode;
  store: RateLimitStore;
  timeoutMs: number;
  requiresServerKey: boolean;
}

export interface SharedOptions {
  /** Test hook: another store (e.g. one that fails). Default: the console's PostgreSQL. */
  store?: RateLimitStore;
  /** Client-side guard, default {@link STORE_GUARD_MS}. */
  timeoutMs?: number;
  /**
   * Keys derived from what a user typed (usernames): shared only when a server key is available
   * (HMAC), per process otherwise (review M1).
   */
  requiresServerKey?: boolean;
  /** Bound of the per-process pre-check counters (default 100 000 keys). */
  maxKeys?: number;
}

const defaultStore = new PgRateLimitStore();

export class RateLimiter {
  private readonly windows = new Map<string, Window>();
  private readonly sharedConfig: SharedConfig | null;
  /** Pending `clear` / `reset` in the store: every later shared operation waits for it. */
  private barrier: Promise<void> = Promise.resolve();
  /** Pending refunds per key: a later shared operation on the same key waits for them. */
  private readonly pendingRefunds = new Map<string, Promise<void>>();

  /** A process-local limiter (in memory). Shared limiters: {@link RateLimiter.shared}. */
  constructor(
    readonly limit: number,
    readonly windowMs: number,
    private readonly maxKeys = 100_000,
    private readonly now: () => number = Date.now,
    shared?: SharedConfig,
  ) {
    this.sharedConfig = shared ?? null;
  }

  /**
   * A limiter shared by every console process through the database (see the module comment).
   * `name` identifies it in the store: stable, unique, `[a-z0-9_.]{1,64}`.
   */
  static shared(name: string, limit: number, windowMs: number, onStoreError: StoreFailureMode, opts: SharedOptions = {}): RateLimiter {
    if (!LIMITER_NAME.test(name)) throw new Error("invalid rate limiter name");
    if (!Number.isInteger(windowMs) || windowMs < 1000 || windowMs > 24 * 3600_000) throw new Error("invalid rate limiter window");
    return new RateLimiter(limit, windowMs, opts.maxKeys ?? 100_000, Date.now, {
      name,
      onStoreError,
      store: opts.store ?? defaultStore,
      timeoutMs: opts.timeoutMs ?? STORE_GUARD_MS,
      requiresServerKey: opts.requiresServerKey ?? false,
    });
  }

  /** The store name of a shared limiter, `null` for a process-local one. */
  get name(): string | null {
    return this.sharedConfig?.name ?? null;
  }

  /** The failure mode of a shared limiter, `null` for a process-local one. */
  get onStoreError(): StoreFailureMode | null {
    return this.sharedConfig?.onStoreError ?? null;
  }

  // ---- This process's counters (synchronous; for a shared limiter: the pre-check) ---------------

  private current(key: string): Window | undefined {
    const w = this.windows.get(key);
    if (w && w.resetAt <= this.now()) {
      this.windows.delete(key);
      return undefined;
    }
    return w;
  }

  private decision(w: Window | undefined): RateLimitDecision {
    const limited = w !== undefined && w.count >= this.limit;
    const retryAfterS = w ? Math.max(1, Math.ceil((w.resetAt - this.now()) / 1000)) : 1;
    return { limited, retryAfterS: Math.min(retryAfterS, MAX_RETRY_AFTER_S) };
  }

  /** Whether `key` is over its limit in THIS process (does not count a hit). */
  check(key: string): RateLimitDecision {
    return this.decision(this.current(key));
  }

  /** Counts one hit in THIS process and returns the decision after it. */
  hit(key: string): RateLimitDecision {
    let w = this.current(key);
    if (!w) {
      if (this.windows.size >= this.maxKeys) {
        const oldest = this.windows.keys().next();
        if (!oldest.done) this.windows.delete(oldest.value);
      }
      w = { count: 0, resetAt: this.now() + this.windowMs };
      this.windows.set(key, w);
    }
    w.count++;
    return this.decision(w);
  }

  /**
   * Counts an attempt in THIS process, synchronously, unless the key is already at its limit
   * (null). Returns a `refund` to call if the attempt turns out to be successful.
   */
  reserve(key: string): (() => void) | null {
    if (this.check(key).limited) return null;
    return this.charge(key);
  }

  /** Counts an attempt in THIS process even when over the limit (never refuses); returns its refund. */
  charge(key: string): () => void {
    this.hit(key);
    const w = this.windows.get(key);
    let refunded = false;
    return () => {
      if (!refunded && w && this.windows.get(key) === w && w.count > 0) {
        refunded = true;
        w.count--;
      }
    };
  }

  /** Hits counted for `key` in THIS process in its current window (0 when none). */
  count(key: string): number {
    return this.current(key)?.count ?? 0;
  }

  /** Forgets `key`, here and (shared limiter) in the store; later shared operations wait for it. */
  reset(key: string): void {
    this.windows.delete(key);
    const cfg = this.sharedConfig;
    if (cfg) this.enqueueBarrier(() => cfg.store.reset(cfg.name, rateLimitKeyHash(cfg.name, key)));
  }

  /** Forgets every key, here and (shared limiter) in the store; later shared operations wait for it. */
  clear(): void {
    this.windows.clear();
    const cfg = this.sharedConfig;
    if (cfg) this.enqueueBarrier(() => cfg.store.reset(cfg.name));
  }

  // ---- Shared operations (asynchronous; this process only for a local limiter) -------------------

  /** Whether `key` is over its limit across all processes (does not count a hit). */
  async checkShared(key: string): Promise<RateLimitDecision> {
    return (await RateLimiter.checkAll([[this, key]]))[0] ?? { limited: false, retryAfterS: 1 };
  }

  /**
   * "Is any of these (limiter, key) pairs over its limit?" with at most ONE store round-trip (the
   * shared limiters among them must use the same store). When any pair is already limited in this
   * process, nothing is sent to the store (security review M-A: a source over one limit, e.g. the
   * cheap per-/48 limit, rotating the other keys costs no statement); the other decisions are then
   * this process's only, so callers must only use "any limited" and the largest `Retry-After` of
   * the limited ones (which may then be lower than the shared one).
   */
  static async checkAll(entries: readonly (readonly [RateLimiter, string])[]): Promise<RateLimitDecision[]> {
    const out: RateLimitDecision[] = entries.map(([rl, key]) => rl.check(key));
    if (out.some((d) => d.limited)) return out;
    const pending: { i: number; key: string; rl: RateLimiter; cfg: SharedConfig; sk: StoreKey }[] = [];
    entries.forEach(([rl, key], i) => {
      const cfg = rl.activeShared();
      if (cfg && !out[i]?.limited) pending.push({ i, key, rl, cfg, sk: rl.storeKey(cfg, key) });
    });
    const first = pending[0];
    if (!first) return out;
    await Promise.all(pending.map((p) => p.rl.settled(p.key)));
    const found = await first.rl.storeCall(() => first.cfg.store.check(pending.map((p) => p.sk)));
    for (const p of pending) {
      if (found === FAILED) {
        out[p.i] = p.rl.failedDecision(out[p.i] ?? { limited: false, retryAfterS: 1 });
        continue;
      }
      const w = found.get(storeKeyId(p.sk));
      if (w && w.count >= p.rl.limit) p.rl.markLimited(p.key, w.remainingMs);
      out[p.i] = w ? { limited: w.count >= p.rl.limit, retryAfterS: toRetryAfterS(w.remainingMs) } : { limited: false, retryAfterS: 1 };
    }
    return out;
  }

  /** Counts one hit across all processes and returns the decision after it. */
  async hitShared(key: string): Promise<RateLimitDecision> {
    const cfg = this.activeShared();
    if (!cfg) return this.hit(key);
    // Already limited here: the request is refused anyway, so it is counted in this process only
    // (H1: a flood on a limited key costs no store statement).
    if (this.check(key).limited) return this.hit(key);
    await this.settled(key);
    const w = await this.storeCall(() => cfg.store.hit(this.storeKey(cfg, key), this.windowMs));
    const local = this.hit(key);
    if (w === FAILED) return this.failedDecision(local);
    if (w.count >= this.limit) this.markLimited(key, w.remainingMs);
    return combine({ limited: w.count >= this.limit, retryAfterS: toRetryAfterS(w.remainingMs) }, local);
  }

  /**
   * Atomic check-and-count across all processes: counts the attempt unless the key is already at
   * its limit. Returns a `refund` to call if the attempt turns out not to count (success, duplicate).
   */
  async reserveShared(key: string): Promise<Reservation> {
    const cfg = this.activeShared();
    const local = this.check(key);
    if (local.limited) return { ok: false, retryAfterS: local.retryAfterS };
    if (!cfg) return { ok: true, refund: this.charge(key) };
    await this.settled(key);
    const r = await this.storeCall(() => cfg.store.reserve(this.storeKey(cfg, key), this.windowMs, this.limit));
    if (r === FAILED) {
      if (cfg.onStoreError === "closed") return { ok: false, retryAfterS: FAIL_CLOSED_RETRY_AFTER_S };
      const refund = this.reserve(key);
      return refund ? { ok: true, refund } : { ok: false, retryAfterS: this.check(key).retryAfterS };
    }
    if (!r.counted || !r.window) {
      const remainingMs = r.window?.remainingMs ?? this.windowMs;
      this.markLimited(key, remainingMs);
      return { ok: false, retryAfterS: toRetryAfterS(remainingMs) };
    }
    return { ok: true, refund: this.sharedRefund(cfg, key, r.window.windowStartMs, this.charge(key)) };
  }

  /** Counts an attempt across all processes even when over the limit (never refuses); returns its refund. */
  async chargeShared(key: string): Promise<Refund> {
    const cfg = this.activeShared();
    if (!cfg) return this.charge(key);
    await this.settled(key);
    const w = await this.storeCall(() => cfg.store.hit(this.storeKey(cfg, key), this.windowMs));
    const localRefund = this.charge(key);
    return w === FAILED ? localRefund : this.sharedRefund(cfg, key, w.windowStartMs, localRefund);
  }

  /** Hits counted for `key` in its current window across all processes (at least this process's). */
  async countShared(key: string): Promise<number> {
    const cfg = this.activeShared();
    if (!cfg) return this.count(key);
    await this.settled(key);
    const sk = this.storeKey(cfg, key);
    const found = await this.storeCall(() => cfg.store.check([sk]));
    const local = this.count(key);
    if (found === FAILED) return local;
    return Math.max(local, found.get(storeKeyId(sk))?.count ?? 0);
  }

  // ---- Internals ---------------------------------------------------------------------------------

  /**
   * The shared configuration in effect, or null when this limiter runs per process: a local
   * limiter, or a `requiresServerKey` limiter without a server key (review M1).
   */
  private activeShared(): SharedConfig | null {
    const cfg = this.sharedConfig;
    if (cfg?.requiresServerKey && serverSubkey(RATE_LIMIT_KEY_DOMAIN) === null) return null;
    return cfg;
  }

  /** Whether this limiter uses the shared store right now (see `activeShared`). */
  get isSharedNow(): boolean {
    return this.activeShared() !== null;
  }

  /**
   * Negative entry (H1): the store reported `key` at its limit; record it here as limited until the
   * end of the store's window, so later requests of this process are refused without a statement.
   * Only ever raises the local count: it can refuse earlier, never admit more.
   */
  private markLimited(key: string, remainingMs: number): void {
    const resetAt = this.now() + Math.max(1, remainingMs);
    const w = this.current(key);
    if (w) {
      w.count = Math.max(w.count, this.limit);
      w.resetAt = Math.max(w.resetAt, resetAt);
      return;
    }
    if (this.windows.size >= this.maxKeys) {
      const oldest = this.windows.keys().next();
      if (!oldest.done) this.windows.delete(oldest.value);
    }
    this.windows.set(key, { count: this.limit, resetAt });
  }

  private storeKey(cfg: SharedConfig, key: string): StoreKey {
    return { limiter: cfg.name, keyHash: rateLimitKeyHash(cfg.name, key) };
  }

  private failedDecision(local: RateLimitDecision): RateLimitDecision {
    return this.sharedConfig?.onStoreError === "closed" ? { limited: true, retryAfterS: FAIL_CLOSED_RETRY_AFTER_S } : local;
  }

  private async settled(key: string): Promise<void> {
    await this.barrier;
    await this.pendingRefunds.get(key);
  }

  private enqueueBarrier(op: () => Promise<void>): void {
    this.barrier = this.barrier.then(async () => {
      await this.storeCall(op);
    });
  }

  private sharedRefund(cfg: SharedConfig, key: string, windowStartMs: number, localRefund: () => void): Refund {
    let refunded = false;
    return () => {
      if (refunded) return;
      refunded = true;
      localRefund();
      const sk = this.storeKey(cfg, key);
      const p = (this.pendingRefunds.get(key) ?? Promise.resolve()).then(async () => {
        await this.storeCall(() => cfg.store.refund(sk, windowStartMs));
      });
      this.pendingRefunds.set(key, p);
      void p.then(() => {
        if (this.pendingRefunds.get(key) === p) this.pendingRefunds.delete(key);
      });
    };
  }

  /** Runs a store operation under the timeout; never throws (FAILED, with a rate-limited warning). */
  private async storeCall<T>(op: () => Promise<T>): Promise<T | typeof FAILED> {
    const cfg = this.sharedConfig;
    const store = cfg?.store;
    const openUntil = store ? breakers.get(store) : undefined;
    if (store && openUntil !== undefined) {
      if (Date.now() < openUntil) {
        rateLimitStoreStats.shortCircuited++;
        return FAILED;
      }
      breakers.delete(store);
    }
    try {
      return await withTimeout(op(), cfg?.timeoutMs ?? STORE_GUARD_MS);
    } catch (err) {
      rateLimitStoreStats.errors++;
      if (store) breakers.set(store, Date.now() + STORE_BREAKER.openMs);
      const name = cfg?.name ?? "local";
      const now = Date.now();
      const last = lastWarning.get(name);
      if (last === undefined || now - last >= STORE_WARNING_INTERVAL_MS) {
        lastWarning.set(name, now);
        // Never the key (IPs, usernames): the limiter name, its failure mode and the error summary.
        logger.warn(
          { limiter: name, onStoreError: cfg?.onStoreError, error: errorSummary(err) },
          cfg?.onStoreError === "closed"
            ? "rate-limit store unavailable: this limiter refuses its requests (fail closed)"
            : "rate-limit store unavailable: this limiter falls back to its per-process counters",
        );
      }
      return FAILED;
    }
  }
}

/** Limited when either is; `Retry-After` of the limiting one(s). */
function combine(a: RateLimitDecision, b: RateLimitDecision): RateLimitDecision {
  if (!a.limited && !b.limited) return a;
  return {
    limited: true,
    retryAfterS: Math.max(a.limited ? a.retryAfterS : 1, b.limited ? b.retryAfterS : 1),
  };
}
