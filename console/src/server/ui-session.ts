import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { getDb } from "@/db/client";
import { csrfTokenFor, loadSession, sessionCookieName, type SessionUser } from "@/server/auth/session";

/**
 * Session of a server-rendered page (server components only: never imported by a client
 * component). Only the user and the per-session CSRF token reach the page; the session token and
 * every hash stay on the server.
 */
export interface PageSession {
  user: SessionUser;
  csrfToken: string;
}

export async function pageSession(): Promise<PageSession | null> {
  const value = (await cookies()).get(sessionCookieName())?.value;
  if (!value) return null;
  const req = new Request("http://console.internal/", {
    headers: { cookie: `${sessionCookieName()}=${value}` },
  });
  const session = await loadSession(getDb(), req);
  return session ? { user: session.user, csrfToken: csrfTokenFor(session.token) } : null;
}

export async function requirePageSession(): Promise<PageSession> {
  const session = await pageSession();
  if (!session) redirect("/login");
  return session;
}

/** Render time of a dynamic page (server components render once per request). */
export function requestTime(): number {
  return Date.now();
}
