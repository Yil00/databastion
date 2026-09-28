/**
 * Next.js startup hook. Everything lives in the Node.js-only module, imported under the
 * `NEXT_RUNTIME` check so the Edge instrumentation bundle never includes Node.js modules.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { registerNode } = await import("@/server/instrumentation-node");
    await registerNode();
  }
}
