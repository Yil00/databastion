import { describe, expect, it } from "vitest";

import { hasDb } from "./db";

/**
 * CI guard: every `describe.skipIf(!hasDb)` suite (agent API, authentication, rotation, metrics,
 * migrations) is silently skipped without a database. In CI (`CI` set, as on GitHub Actions) that
 * must fail the job instead: set TEST_DATABASE_URL (see .github/workflows/ci.yml).
 */
describe("CI database guard", () => {
  it.runIf(!!process.env.CI)("runs the DB test suites in CI (TEST_DATABASE_URL or PG_BIN set)", () => {
    expect(hasDb, "CI without a test database: the DB suites would be skipped; set TEST_DATABASE_URL").toBe(true);
  });
});
