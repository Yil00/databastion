import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    restoreMocks: true,
    // Throwaway PostgreSQL cluster for the DB tests (skipped with a message when unavailable).
    globalSetup: ["./src/test/pg-global-setup.ts"],
    // Console server key for the tests (known-good fingerprints, P1-D). Fake test canary.
    env: { DATABASTION_ENCRYPTION_KEY: "hunter2-SECRET-test-server-key-0123456789abcdef" },
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
