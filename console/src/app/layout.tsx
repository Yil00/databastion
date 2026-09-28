import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

// Every page is rendered per request: the CSP nonce set by src/proxy.ts must reach Next.js scripts.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "DataBastion",
  description: "DataBastion console: sensitive data discovery and exfiltration audit.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
