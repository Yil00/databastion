export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 p-8">
      <h1 className="text-3xl font-semibold tracking-tight">DataBastion</h1>
      <p className="text-muted-foreground">
        Console skeleton. Discovery, Audit, agents and incidents will appear here in the
        upcoming phases.
      </p>
      <div className="rounded-lg border bg-card p-4 text-sm text-card-foreground">
        Phase 0 – Foundations
      </div>
    </main>
  );
}
