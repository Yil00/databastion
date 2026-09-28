import type { NextConfig } from "next";

import { SECURITY_HEADERS } from "./src/lib/csp";

const nextConfig: NextConfig = {
  // Self-contained server bundle for the Docker image (set by the image build).
  // Left off by default so that `pnpm start` (`next start`) keeps working locally.
  output: process.env.NEXT_OUTPUT_STANDALONE === "1" ? "standalone" : undefined,
  poweredByHeader: false,
  reactStrictMode: true,
  // The repository already has its own AGENTS.md / CLAUDE.md at the root:
  // do not let `next dev` generate extra ones in console/.
  agentRules: false,
  // Server-only packages loaded from node_modules at runtime, never bundled.
  serverExternalPackages: ["pg", "pg-boss", "pino", "@node-rs/argon2"],
  // Static security headers on every response; the nonce-based CSP of UI pages is set in src/proxy.ts.
  async headers() {
    return [
      { source: "/:path*", headers: [...SECURITY_HEADERS] },
      // The findings view carries decrypted masked samples (L4). src/proxy.ts also sets it on every
      // UI page; this rule does not depend on the proxy matcher (e.g. prefetch requests).
      { source: "/findings", headers: [{ key: "Cache-Control", value: "no-store" }] },
      { source: "/findings/:path*", headers: [{ key: "Cache-Control", value: "no-store" }] },
    ];
  },
};

export default nextConfig;
