import type { Database } from "@/db/client";
import { auditLog } from "@/db/schema";

/**
 * Console audit log (docs/05-security.md, rule 6). Every user action and every agent identity
 * event goes through `writeAudit`. The table is append-only: this module only inserts.
 *
 * `details` must never carry a secret, token, password or agent-provided free text: keys that look
 * like secrets are refused (programming error), values are limited to scalars.
 */
export type AuditActorType = "user" | "agent" | "system";

export type AuditAction =
  | "user.bootstrap"
  | "user.login"
  | "user.logout"
  | "enrollment_token.create"
  | "enrollment_token.revoke"
  | "agent.enroll"
  | "agent.revoke"
  | "agent.rotate_request"
  | "agent.rotate"
  | "agent.secret_promote"
  | "agent.rotation_conflict"
  | "agent.batch_rejected"
  | "agent.batch_conflict"
  | "agent.foreign_target"
  | "discovery.scan_request"
  | "finding.false_positive"
  | "finding.false_positive_reset"
  | "policy.create"
  | "policy.update"
  | "policy.delete"
  | "policy_exception.create"
  | "policy_exception.delete"
  | "incident.create"
  | "incident.transition"
  | "notification_channel.create"
  | "notification_channel.update"
  | "notification_channel.delete"
  | "notification_channel.rotate_signing_key"
  | "notification_channel.test"
  | "agent.silent"
  | "agent.recovered"
  | "job.timeout"
  | "user.access_denied";

export interface AuditEntry {
  actorType: AuditActorType;
  actorId?: string | null;
  action: AuditAction;
  outcome?: "success" | "failure";
  targetType?: string;
  targetId?: string | null;
  sourceIp?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

const FORBIDDEN_KEY = /secret|token|password|authorization|cookie|hash/i;

export function assertSafeDetails(details: AuditEntry["details"]): void {
  for (const key of Object.keys(details ?? {})) {
    if (FORBIDDEN_KEY.test(key)) {
      throw new Error(`audit details key "${key}" is not allowed`);
    }
  }
}

type Executor = Pick<Database, "insert">;

export async function writeAudit(db: Executor, entry: AuditEntry): Promise<void> {
  assertSafeDetails(entry.details);
  await db.insert(auditLog).values({
    actorType: entry.actorType,
    actorId: entry.actorId ?? null,
    action: entry.action,
    outcome: entry.outcome ?? "success",
    targetType: entry.targetType ?? null,
    targetId: entry.targetId ?? null,
    sourceIp: entry.sourceIp ?? null,
    details: entry.details ?? null,
  });
}
