/**
 * Client-side calls to the user API: same-origin, session cookie (HttpOnly, never readable here),
 * `X-CSRF-Token` on every state-changing request. No secret is ever embedded in the client bundle.
 */
export async function userApi(
  path: string,
  opts: { method?: string; csrfToken?: string; body?: unknown } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (opts.csrfToken) headers["X-CSRF-Token"] = opts.csrfToken;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  return fetch(path, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    credentials: "same-origin",
    cache: "no-store",
  });
}
