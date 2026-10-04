import http from "node:http";
import https from "node:https";
import { rootCertificates } from "node:tls";

import { checkProviderUrl } from "./config";

/**
 * Every call to the OIDC provider (discovery, JWKS, token, userinfo, revocation; ADR-0038 decision
 * 2): no redirect followed, a 5 s overall timeout, a size cap checked before parsing (the
 * `Content-Length` first, then the bytes actually received), TLS always verified (system roots plus
 * `DATABASTION_OIDC_CA_FILE`), `https://` only (`http://` on loopback outside production).
 * Errors carry a closed code, never a response body.
 */

export const PROVIDER_TIMEOUT_MS = 5_000;
export const MAX_DISCOVERY_BYTES = 64 * 1024;
export const MAX_JWKS_BYTES = 256 * 1024;
export const MAX_TOKEN_BYTES = 64 * 1024;

export type ProviderErrorCode = "url" | "network" | "timeout" | "redirect" | "too_large" | "content_type" | "json" | "status";

export class ProviderHttpError extends Error {
  override name = "ProviderHttpError";
  constructor(
    readonly code: ProviderErrorCode,
    readonly status: number | null = null,
  ) {
    super(`provider request failed: ${code}${status === null ? "" : ` (${status})`}`);
  }
}

export interface ProviderRequest {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  /** `application/x-www-form-urlencoded` body. */
  form?: URLSearchParams;
  maxBytes: number;
  /** Status codes whose JSON body is returned instead of thrown (e.g. 400 from the token endpoint). */
  acceptStatus?: readonly number[];
  /** Expect no body (revocation). */
  noBody?: boolean;
}

export interface ProviderResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  json: unknown;
}

export interface ProviderTransport {
  ca: string | null;
  allowHttp: boolean;
  timeoutMs?: number;
}

export function providerRequest(rawUrl: string, req: ProviderRequest, t: ProviderTransport): Promise<ProviderResponse> {
  const url = checkProviderUrl(rawUrl, t.allowHttp);
  if (url === null) return Promise.reject(new ProviderHttpError("url"));
  const body = req.form?.toString();
  const headers: Record<string, string> = { Accept: "application/json", "User-Agent": "databastion-console", ...req.headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Content-Length"] = String(Buffer.byteLength(body));
  }
  const timeoutMs = t.timeoutMs ?? PROVIDER_TIMEOUT_MS;
  return new Promise<ProviderResponse>((resolve, reject) => {
    let settled = false;
    const fail = (e: ProviderHttpError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      r.destroy();
      reject(e);
    };
    const options: https.RequestOptions = {
      method: req.method ?? "GET",
      headers,
      // The system roots stay trusted; the CA file is added, never a replacement nor a bypass.
      ...(url.protocol === "https:" && t.ca ? { ca: [...rootCertificates, t.ca] } : {}),
      rejectUnauthorized: true,
      agent: false,
    };
    const onResponse = (res: http.IncomingMessage) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        res.resume();
        return fail(new ProviderHttpError("redirect", status));
      }
      const declared = Number(res.headers["content-length"] ?? "NaN");
      if (Number.isFinite(declared) && declared > req.maxBytes) {
        res.resume();
        return fail(new ProviderHttpError("too_large", status));
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > req.maxBytes) return fail(new ProviderHttpError("too_large", status));
        chunks.push(c);
      });
      res.on("error", () => fail(new ProviderHttpError("network", status)));
      res.on("end", () => {
        if (settled) return;
        const ok = (status >= 200 && status < 300) || (req.acceptStatus ?? []).includes(status);
        if (!ok) return fail(new ProviderHttpError("status", status));
        let json: unknown = null;
        const raw = Buffer.concat(chunks).toString("utf8");
        if (!req.noBody || raw.trim() !== "") {
          const type = String(res.headers["content-type"] ?? "").toLowerCase();
          if (!/^application\/([a-z0-9.+-]+\+)?json\b/.test(type) && !req.noBody) return fail(new ProviderHttpError("content_type", status));
          try {
            json = JSON.parse(raw);
          } catch {
            if (!req.noBody) return fail(new ProviderHttpError("json", status));
          }
        }
        settled = true;
        clearTimeout(timer);
        resolve({ status, headers: res.headers, json });
      });
    };
    const r = url.protocol === "https:" ? https.request(url, options, onResponse) : http.request(url, options, onResponse);
    const timer = setTimeout(() => fail(new ProviderHttpError("timeout")), timeoutMs);
    r.on("error", () => fail(new ProviderHttpError("network")));
    if (body !== undefined) r.write(body);
    r.end();
  });
}
