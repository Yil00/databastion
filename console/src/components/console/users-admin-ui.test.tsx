import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { UsersAdmin, type PendingItem } from "./users-admin";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined }) }));

const pending = (over: Partial<PendingItem> = {}): PendingItem => ({
  id: "6f1c0d2e-1111-4222-8333-444455556666",
  issuer: "https://sso.example.com/realms/acme",
  subject: "sub-hank",
  login: "hank",
  email: "hank@example.com",
  emailVerified: true,
  groups: ["databastion-admins"],
  mappedRole: "admin",
  syncedRole: null,
  attempts: 1,
  lastAttemptAt: "2026-10-04T10:00:00.000Z",
  ...over,
});

const render = (p: PendingItem, roleSyncOn: boolean) =>
  renderToStaticMarkup(<UsersAdmin users={[]} pending={[p]} evicted={0} oidcEnabled roleSyncOn={roleSyncOn} currentUserId="me" csrfToken="t" />);

const buttons = (html: string) => [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);

describe("pending logins (end-of-phase-8 review L1)", () => {
  it("role sync on: shows the mapped role and offers approval with that role only", () => {
    const html = render(pending({ syncedRole: "admin" }), true);
    expect(html).toContain("Mapped role");
    expect(html).toContain("Role sync is on");
    expect(buttons(html)).toContain("Approve as admin");
    expect(buttons(html)).not.toContain("Approve as analyst");

    const analyst = render(pending({ mappedRole: null, syncedRole: "analyst", groups: [] }), true);
    expect(buttons(analyst)).toContain("Approve as analyst");
    expect(buttons(analyst)).not.toContain("Approve as admin");
  });

  it("role sync off: the administrator chooses the role", () => {
    const html = render(pending(), false);
    expect(html).not.toContain("Mapped role");
    expect(buttons(html)).toEqual(expect.arrayContaining(["Approve as analyst", "Approve as admin", "Discard"]));
  });
});
