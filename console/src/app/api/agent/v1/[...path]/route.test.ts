import { describe, expect, it } from "vitest";

import { DELETE, GET, PATCH, POST, PUT } from "./route";

describe("agent API v1 placeholder", () => {
  it.each([
    ["GET", GET],
    ["POST", POST],
    ["PUT", PUT],
    ["PATCH", PATCH],
    ["DELETE", DELETE],
  ])("%s answers 501 and accepts no input", async (_method, handler) => {
    const res = handler();
    expect(res.status).toBe(501);
    expect(await res.json()).toEqual({ error: "not_implemented" });
  });
});
