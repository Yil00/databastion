"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Input, Label } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

import { userApi } from "./client-api";

type Role = "admin" | "analyst";

export interface UserItem {
  id: string;
  username: string;
  role: Role;
  ssoOnly: boolean;
  hasPassword: boolean;
  disabledAt: string | null;
  lastLoginAt: string | null;
  identities: { issuer: string; subject: string; email: string | null }[];
}

export interface PendingItem {
  id: string;
  issuer: string;
  subject: string;
  login: string | null;
  email: string | null;
  emailVerified: boolean;
  groups: string[];
  mappedRole: Role | null;
  attempts: number;
  lastAttemptAt: string;
}

const ERRORS: Record<string, string> = {
  self: "You cannot change your own account here.",
  last_admin: "The console must keep at least one enabled administrator.",
  role_managed_by_provider: "This user's role comes from the identity provider (role sync is on).",
  username_taken: "A user with this name already exists.",
  identity_bound: "This identity is already bound to a user.",
  invalid_login: "The identity has no valid login name: it cannot be approved.",
  invalid_username: "Invalid username (lower-case letters, digits, '.', '_' or '-', up to 64 characters).",
  invalid_password: "The password must be 12 to 1024 characters long.",
  not_found: "Not found (already handled or expired).",
};

async function errorOf(res: Response | null): Promise<string> {
  if (!res) return "The console is unreachable.";
  const body = (await res.json().catch(() => null)) as { error?: string } | null;
  return ERRORS[body?.error ?? ""] ?? "The request failed.";
}

/**
 * User management (admin): local users, roles, disabling; OIDC pending logins, shown with the
 * issuer and subject first (the identity key, ADR-0038 decision 8), approved only as new users.
 * Every value is rendered as text (React escaping); nothing provider-supplied is interpreted.
 */
export function UsersAdmin({
  users,
  pending,
  evicted,
  oidcEnabled,
  currentUserId,
  csrfToken,
}: {
  users: UserItem[];
  pending: PendingItem[];
  evicted: number;
  oidcEnabled: boolean;
  currentUserId: string;
  csrfToken: string;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function call(path: string, method: string, body?: unknown) {
    setError(null);
    const res = await userApi(path, { method, csrfToken, body }).catch(() => null);
    if (!res?.ok) setError(await errorOf(res));
    router.refresh();
    return res?.ok ?? false;
  }

  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    const ok = await call("/api/users", "POST", { username: String(f.get("username") ?? ""), password: String(f.get("password") ?? ""), role: String(f.get("role") ?? "analyst") });
    if (ok) form.reset();
  }

  return (
    <div className="flex flex-col gap-6">
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Login</TableHead>
            <TableHead>Last login</TableHead>
            <TableHead>State</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((u) => (
            <TableRow key={u.id}>
              <TableCell>{u.username}</TableCell>
              <TableCell>
                <Badge variant={u.role === "admin" ? "default" : "outline"}>{u.role}</Badge>
              </TableCell>
              <TableCell className="text-sm">
                {[u.hasPassword ? "local password" : null, ...u.identities.map((i) => `SSO ${i.subject}${i.email ? ` (${i.email})` : ""}`)].filter(Boolean).join(", ")}
              </TableCell>
              <TableCell>{u.lastLoginAt ?? "never"}</TableCell>
              <TableCell>{u.disabledAt ? <Badge variant="outline">disabled</Badge> : "enabled"}</TableCell>
              <TableCell className="flex justify-end gap-2">
                {u.id !== currentUserId && (
                  <>
                    <Button size="sm" variant="outline" onClick={() => call(`/api/users/${u.id}`, "PATCH", { role: u.role === "admin" ? "analyst" : "admin" })}>
                      Make {u.role === "admin" ? "analyst" : "admin"}
                    </Button>
                    {u.disabledAt ? (
                      <Button size="sm" variant="outline" onClick={() => call(`/api/users/${u.id}`, "PATCH", { disabled: false })}>
                        Enable
                      </Button>
                    ) : (
                      <ConfirmDialog
                        trigger="Disable"
                        title={`Disable ${u.username}?`}
                        description="The user's sessions end now, and no login method works until the account is enabled again."
                        confirmLabel="Disable"
                        variant="destructive"
                        onConfirm={() => call(`/api/users/${u.id}`, "PATCH", { disabled: true }).then(() => undefined)}
                      />
                    )}
                  </>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Card>
        <CardHeader>
          <CardTitle>New local user</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={create} className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-2">
              <Label htmlFor="new-username">Username</Label>
              <Input id="new-username" name="username" required maxLength={64} autoComplete="off" />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="new-password">Initial password</Label>
              <Input id="new-password" name="password" type="password" required minLength={12} maxLength={1024} autoComplete="new-password" />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="new-role">Role</Label>
              <select id="new-role" name="role" className="h-9 rounded-md border bg-transparent px-2 text-sm" defaultValue="analyst">
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <Button type="submit">Create user</Button>
          </form>
        </CardContent>
      </Card>

      {oidcEnabled && (
        <Card>
          <CardHeader>
            <CardTitle>Pending single sign-on logins</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <p className="text-sm text-muted-foreground">
              Refused logins of identities unknown to the console (sign-up is off). Approving one creates a NEW user bound to that issuer and subject; it never links an existing account. Pending logins
              expire after 7 days; at most 1000 are kept.
              {evicted > 0 && ` ${evicted} older pending login${evicted === 1 ? " was" : "s were"} evicted at that cap.`}
            </p>
            {pending.length === 0 ? (
              <p className="text-sm">No pending login.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Issuer</TableHead>
                    <TableHead>Subject</TableHead>
                    <TableHead>Login</TableHead>
                    <TableHead>E-mail</TableHead>
                    <TableHead>Groups</TableHead>
                    <TableHead>Last attempt</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pending.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="max-w-48 font-mono text-xs break-all">{p.issuer}</TableCell>
                      <TableCell className="max-w-48 font-mono text-xs break-all">{p.subject}</TableCell>
                      <TableCell>{p.login ?? <span className="text-destructive">invalid</span>}</TableCell>
                      <TableCell>
                        {p.email ?? ""} {!p.emailVerified && <Badge variant="destructive">email_verified: false</Badge>}
                      </TableCell>
                      <TableCell className="max-w-48 text-xs break-all">{p.groups.join(", ")}</TableCell>
                      <TableCell>
                        {p.lastAttemptAt} ({p.attempts})
                      </TableCell>
                      <TableCell className="flex justify-end gap-2">
                        <ConfirmDialog
                          trigger="Approve as analyst"
                          title="Create a new analyst?"
                          description={`A new user ${p.login ?? ""} bound to subject ${p.subject} of ${p.issuer}.`}
                          confirmLabel="Approve"
                          disabled={p.login === null}
                          onConfirm={() => call(`/api/oidc/pending-logins/${p.id}`, "POST", { role: "analyst" }).then(() => undefined)}
                        />
                        <ConfirmDialog
                          trigger="Approve as admin"
                          title="Create a new administrator?"
                          description={`A new ADMINISTRATOR ${p.login ?? ""} bound to subject ${p.subject} of ${p.issuer}. Check the issuer and subject, not only the e-mail.`}
                          confirmLabel="Approve as admin"
                          variant="destructive"
                          disabled={p.login === null}
                          onConfirm={() => call(`/api/oidc/pending-logins/${p.id}`, "POST", { role: "admin" }).then(() => undefined)}
                        />
                        <Button size="sm" variant="ghost" onClick={() => call(`/api/oidc/pending-logins/${p.id}`, "DELETE")}>
                          Discard
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
