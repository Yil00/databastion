import { redirect } from "next/navigation";

import { LoginForm } from "@/components/console/login-form";
import { pageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  if (await pageSession()) redirect("/agents");
  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-6 p-8">
      <h1 className="text-2xl font-semibold tracking-tight">DataBastion</h1>
      <LoginForm />
    </main>
  );
}
