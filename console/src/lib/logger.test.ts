import { describe, expect, it } from "vitest";

import { errorSummary } from "./logger";

describe("errorSummary", () => {
  it("keeps only the message of an error", () => {
    expect(errorSummary(new Error("boom"))).toEqual({ message: "boom" });
  });

  it("includes the cause message (e.g. pg error wrapped by drizzle)", () => {
    const err = new Error("Failed query: select 1", { cause: new Error("connection refused") });
    expect(errorSummary(err)).toEqual({
      message: "Failed query: select 1",
      cause: "connection refused",
    });
  });

  it("drops the bound parameters of drizzle query errors", () => {
    const err = new Error("Failed query: insert into agents values ($1)\nparams: dbs_x,secret");
    expect(errorSummary(err).message).toBe("Failed query: insert into agents values ($1) [params redacted]");
  });

  it("reduces PostgreSQL errors to SQLSTATE and constraint (no message text)", () => {
    const pgErr = Object.assign(new Error('duplicate key value (username)=(jane@example.com)'), {
      code: "23505",
      constraint: "users_username_key",
    });
    const wrapped = new Error("Failed query: insert ...\nparams: jane@example.com", { cause: pgErr });
    const summary = errorSummary(wrapped);
    expect(summary).toEqual({ message: "database error", code: "23505", constraint: "users_username_key" });
    expect(JSON.stringify(summary)).not.toContain("jane");
  });

  it("stringifies non-Error values", () => {
    expect(errorSummary("oops")).toEqual({ message: "oops" });
  });
});
