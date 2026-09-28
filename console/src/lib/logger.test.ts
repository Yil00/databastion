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

  it("stringifies non-Error values", () => {
    expect(errorSummary("oops")).toEqual({ message: "oops" });
  });
});
