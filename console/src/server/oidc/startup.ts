import { and, eq, isNotNull, isNull } from "drizzle-orm";

import type { Database } from "@/db/client";
import { users } from "@/db/schema";

import type { LocalLoginMode } from "./config";

/**
 * ADR-0038 decision 11: with `DATABASTION_LOCAL_LOGIN=admins`, an error is logged at startup when no
 * enabled local administrator with a password exists (the break-glass path would be unusable).
 * Returns the message, or `null`. Never contains a user name.
 */
export async function localLoginStartupError(db: Database, mode: LocalLoginMode): Promise<string | null> {
  if (mode !== "admins") return null;
  const [row] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.role, "admin"), isNull(users.disabledAt), isNotNull(users.passwordHash)))
    .limit(1);
  if (row) return null;
  return (
    "DATABASTION_LOCAL_LOGIN=admins (the default when OIDC is enabled) but no enabled local administrator with a password exists: " +
    "there is no break-glass login if the identity provider fails. Create one (pnpm admin:bootstrap on an empty console, or the Users page), " +
    "or set DATABASTION_LOCAL_LOGIN explicitly."
  );
}
