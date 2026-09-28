"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";

import { userApi } from "./client-api";

const MESSAGES: Record<number, string> = {
  401: "Invalid username or password.",
  429: "Too many attempts. Try again later.",
  503: "The console is busy. Try again in a moment.",
};

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await userApi("/api/auth/login", {
        method: "POST",
        body: { username: String(form.get("username") ?? ""), password: String(form.get("password") ?? "") },
      });
      if (res.ok) {
        router.replace("/agents");
        router.refresh();
        return;
      }
      setError(MESSAGES[res.status] ?? "Login failed.");
    } catch {
      setError("The console is unreachable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="username">Username</Label>
            <Input id="username" name="username" autoComplete="username" required maxLength={64} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="password">Password</Label>
            <Input id="password" name="password" type="password" autoComplete="current-password" required maxLength={1024} />
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy}>
            Sign in
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
