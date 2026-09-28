/** Display status of an agent (Agents page). Silent = no heartbeat for 90 s (3 intervals) or never. */
export type DisplayStatus = "online" | "silent" | "revoked" | "locked";

export const SILENT_AFTER_MS = 90_000;

export function displayStatus(
  a: { status: string; lastSeenAt: Date | null; revokedAt: Date | null; lockedAt: Date | null },
  now = Date.now(),
): DisplayStatus {
  if (a.revokedAt || a.status === "revoked") return "revoked";
  if (a.lockedAt || a.status === "locked") return "locked";
  if (a.lastSeenAt && now - a.lastSeenAt.getTime() < SILENT_AFTER_MS) return "online";
  return "silent";
}

/** "12 s ago", "5 min ago", "3 h ago", "2 d ago"; "never" when null. Plain text only. */
export function formatAge(date: Date | null, now = Date.now()): string {
  if (!date) return "never";
  const s = Math.max(0, Math.round((now - date.getTime()) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}
