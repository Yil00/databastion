/**
 * In-memory fixed-window counters (per process). The console runs a single web process in the MVP;
 * a multi-instance deployment needs a shared store (PostgreSQL or Redis): see console/README.md.
 * Memory is bounded: at most `maxKeys` entries, the oldest windows are evicted first.
 */
export interface RateLimitDecision {
  limited: boolean;
  /** Seconds until the window resets (>= 1), for `Retry-After`. */
  retryAfterS: number;
}

interface Window {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, Window>();

  constructor(
    readonly limit: number,
    readonly windowMs: number,
    private readonly maxKeys = 100_000,
    private readonly now: () => number = Date.now,
  ) {}

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
    return { limited, retryAfterS: Math.min(retryAfterS, 3600) };
  }

  /** Whether `key` is currently over its limit (does not count a hit). */
  check(key: string): RateLimitDecision {
    return this.decision(this.current(key));
  }

  /** Counts one hit (e.g. a failed attempt) and returns the decision after it. */
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

  reset(key: string): void {
    this.windows.delete(key);
  }

  clear(): void {
    this.windows.clear();
  }
}
