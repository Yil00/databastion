import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import { SCHEMAS_URL, TYPES_URL, renderArtifacts } from "../../../scripts/protocol/generate";

// Drift check: the committed generated files must match shared/protocol/openapi.yaml.
describe("generated protocol artifacts", () => {
  it("are up to date with shared/protocol/openapi.yaml", async () => {
    const expected = await renderArtifacts();
    const hint = "generated protocol files are stale: run `pnpm protocol:generate` in console/";
    expect((await readFile(TYPES_URL, "utf8")) === expected.types, `types.gen.ts: ${hint}`).toBe(true);
    expect((await readFile(SCHEMAS_URL, "utf8")) === expected.schemas, `schemas.gen.json: ${hint}`).toBe(true);
  }, 60_000);
});
