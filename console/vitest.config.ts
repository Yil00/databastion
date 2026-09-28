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
    include: ["src/**/*.test.ts"],
    restoreMocks: true,
    // Throwaway PostgreSQL cluster for the DB tests (skipped with a message when unavailable).
    globalSetup: ["./src/test/pg-global-setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
