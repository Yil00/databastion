"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Input, Label } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

import { userApi } from "./client-api";

export interface TokenItem {
  id: string;
  label: string | null;
  state: "active" | "consumed" | "expired" | "revoked";
  createdAt: string;
  expiresAt: string;
  consumedByAgentId: string | null;
}

/**
 * Create / list / revoke enrollment tokens. A created `dbe_…` token lives only in this component's
 * state: shown once, never stored by the console (only its SHA-256), gone on navigation.
 */
export function EnrollmentTokens({ tokens, csrfToken }: { tokens: TokenItem[]; csrfToken: string }) {
  const router = useRouter();
  const [created, setCreated] = useState<{ token: string; expiresAt: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const label = String(new FormData(e.currentTarget).get("label") ?? "").trim();
    setError(null);
    setCopied(false);
    const res = await userApi("/api/enrollment-tokens", {
      method: "POST",
      csrfToken,
      body: label ? { label } : {},
    }).catch(() => null);
    if (!res?.ok) {
      setError(res?.status === 400 ? "Invalid label (1 to 64 printable characters)." : "Token creation failed.");
      return;
    }
    const body = (await res.json()) as { token: string; expires_at: string };
    setCreated({ token: body.token, expiresAt: body.expires_at });
    router.refresh();
  }

  async function revoke(id: string) {
    const res = await userApi(`/api/enrollment-tokens/${id}`, { method: "DELETE", csrfToken }).catch(() => null);
    if (!res?.ok) setError("The token could not be revoked (already used, expired or revoked).");
    router.refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>New token</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <form onSubmit={create} className="flex flex-wrap items-end gap-3">
            <div className="flex min-w-64 flex-col gap-2">
              <Label htmlFor="label">Label (optional, e.g. the intended host)</Label>
              <Input id="label" name="label" maxLength={64} autoComplete="off" />
            </div>
            <Button type="submit">Create token</Button>
          </form>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          {created && (
            <div role="status" className="flex flex-col gap-2 rounded-md border border-destructive/50 p-4">
              <p className="text-sm font-medium">
                Copy this token now: it is shown only once and cannot be retrieved later. It is single-use and expires
                at {created.expiresAt}. Treat it as a secret (Docker secret or file readable only by the agent).
              </p>
              <code className="rounded bg-muted p-2 font-mono text-sm break-all select-all">{created.token}</code>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  onClick={async () => {
                    await navigator.clipboard.writeText(created.token);
                    setCopied(true);
                  }}
                >
                  {copied ? "Copied" : "Copy"}
                </Button>
                <Button size="sm" variant="outline" onClick={() => setCreated(null)}>
                  Done, hide it
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Label</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Agent</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {tokens.map((t) => (
            <TableRow key={t.id}>
              <TableCell>{t.label ?? ""}</TableCell>
              <TableCell>
                <Badge variant={t.state === "active" ? "default" : "outline"}>{t.state}</Badge>
              </TableCell>
              <TableCell>{t.createdAt}</TableCell>
              <TableCell>{t.expiresAt}</TableCell>
              <TableCell>
                {t.consumedByAgentId && (
                  <Link href={`/agents/${t.consumedByAgentId}`} className="hover:underline">
                    view
                  </Link>
                )}
              </TableCell>
              <TableCell className="text-right">
                {t.state === "active" && (
                  <ConfirmDialog
                    trigger="Revoke"
                    title="Revoke this token?"
                    description="An agent will no longer be able to enroll with it."
                    confirmLabel="Revoke"
                    variant="destructive"
                    onConfirm={() => revoke(t.id)}
                  />
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
