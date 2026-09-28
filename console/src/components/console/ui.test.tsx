import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { displayStatus, formatAge } from "@/lib/agent-status";
import { contentSecurityPolicy } from "@/lib/csp";

import { AgentsTable, type AgentListItem } from "./agents-table";

const NOW = Date.parse("2026-09-28T12:00:00Z");

const agent = (over: Partial<AgentListItem> = {}): AgentListItem => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8057",
  name: "db-host-1",
  hostname: "db-host-1",
  version: "0.1.0",
  status: "online",
  lastSeenAt: new Date(NOW - 10_000),
  revokedAt: null,
  lockedAt: null,
  targets: [{ targetId: "pg-prod-1", auditLevel: "partial", present: true }],
  ...over,
});

describe("agent display status", () => {
  it("maps online / silent / revoked / locked", () => {
    expect(displayStatus(agent(), NOW)).toBe("online");
    expect(displayStatus(agent({ lastSeenAt: new Date(NOW - 91_000) }), NOW)).toBe("silent");
    expect(displayStatus(agent({ lastSeenAt: null, status: "enrolled" }), NOW)).toBe("silent");
    expect(displayStatus(agent({ revokedAt: new Date(NOW), status: "revoked" }), NOW)).toBe("revoked");
    expect(displayStatus(agent({ lockedAt: new Date(NOW), status: "locked" }), NOW)).toBe("locked");
    expect(formatAge(new Date(NOW - 125_000), NOW)).toBe("2 min ago");
    expect(formatAge(null, NOW)).toBe("never");
  });
});

describe("AgentsTable", () => {
  it("renders agent-reported strings as escaped text, never as HTML", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const html = renderToStaticMarkup(
      <AgentsTable agents={[agent({ name: hostile, hostname: hostile, version: hostile })]} now={NOW} />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(html).toContain("pg-prod-1: partial");
    expect(html).toContain("online");
  });

  it("shows an empty state", () => {
    expect(renderToStaticMarkup(<AgentsTable agents={[]} now={NOW} />)).toContain("No agent enrolled yet.");
  });
});

describe("content security policy", () => {
  it("allows scripts only with the nonce and forbids framing", () => {
    const csp = contentSecurityPolicy("abc");
    expect(csp).toContain("script-src 'self' 'nonce-abc' 'strict-dynamic'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(contentSecurityPolicy("abc", true)).toContain("'unsafe-eval'");
  });
});
