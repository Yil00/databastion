import { NextResponse, type NextRequest } from "next/server";

import { contentSecurityPolicy } from "@/lib/csp";

/**
 * Per-request CSP nonce for UI pages (Next.js applies it to its own scripts). API routes, `/metrics`
 * and static assets are excluded: they serve no HTML. See console/README.md ("Security headers").
 */
export function proxy(request: NextRequest): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = contentSecurityPolicy(nonce, process.env.NODE_ENV === "development");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  // UI pages are per-user and some carry decrypted masked samples (findings view): never cached.
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|metrics|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
