import { beforeEach, describe, expect, it, vi } from "vitest";

const execute = vi.fn();

vi.mock("@/db/client", () => ({
  getDb: () => ({ execute }),
}));
vi.mock("@/lib/logger", () => ({
  logger: { warn: vi.fn() },
  errorSummary: (err: unknown) => ({ message: String(err) }),
}));

const { GET: liveness } = await import("./route");
const { GET: readiness } = await import("./ready/route");

describe("GET /api/health", () => {
  it("returns ok without any detail", async () => {
    const res = liveness();
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ status: "ok" });
  });
});

describe("GET /api/health/ready", () => {
  beforeEach(() => {
    execute.mockReset();
  });

  it("returns ok when the database answers", async () => {
    execute.mockResolvedValue({ rows: [{ "?column?": 1 }] });
    const res = await readiness();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("returns a generic 503 that does not leak the database error", async () => {
    execute.mockRejectedValue(
      new Error('password authentication failed for user "databastion" at db:5432'),
    );
    const res = await readiness();
    expect(res.status).toBe(503);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ status: "unavailable" });
    expect(body).not.toMatch(/databastion|password|5432/);
  });
});
