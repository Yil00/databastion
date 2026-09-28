import net from "node:net";
import { hostname as osHostname } from "node:os";
import tls from "node:tls";

import type { EmailConfig } from "@/lib/notification-model";

import { classifyAddress, resolveOutbound, type Resolver } from "../net-guard";
import type { SendResult } from "./types";

/**
 * Minimal SMTP client for alert e-mails (P3-C, worker only; RFC 5321 subset, no dependency).
 *
 * - Transport: `implicit` TLS, or `starttls` (STARTTLS required: a server that does not offer it is
 *   an error, never a silent downgrade), or `none` only towards a loopback address (or with
 *   `DATABASTION_ALERTING_INSECURE_DEV=1`). Certificates are always verified against the
 *   configured host name.
 * - AUTH PLAIN or LOGIN, only over TLS (or loopback / dev flag). Credentials are never logged;
 *   nothing in this module logs.
 * - The host is resolved and checked (`net-guard.ts`): link-local, metadata, multicast and
 *   reserved addresses are refused; internal relays are allowed. The socket connects to the vetted
 *   address only.
 * - Timeouts: 10 s to connect, 30 s per reply, 60 s in total. Each reply is capped at 64 KiB and
 *   100 lines, and an unterminated line at 64 KiB (`smtp_protocol` beyond: a hostile server cannot
 *   grow the worker's memory).
 * - STARTTLS: any byte received after the `220` and before the TLS handshake is a protocol error
 *   (no plaintext command or reply injection into the encrypted session). The certificate is
 *   verified against the configured host (a name, or an IP literal), never a default name.
 * - Message: plain text, UTF-8, base64 body, RFC 2047 subject, `Message-ID` derived from the
 *   delivery id (stable across retries), `Auto-Submitted: auto-generated`.
 * - Outcome: a 4xx reply, a network or TLS error is retried; a 5xx reply fails (`smtp_<code>`).
 */

export const SMTP_CONNECT_TIMEOUT_MS = 10_000;
export const SMTP_REPLY_TIMEOUT_MS = 30_000;
export const SMTP_TOTAL_TIMEOUT_MS = 60_000;
const MAX_REPLY_BYTES = 64 * 1024;
const MAX_REPLY_LINES = 100;

export interface MailMessage {
  deliveryId: string;
  event: string;
  subject: string;
  text: string;
}

export interface SmtpOptions {
  /** Plain-text SMTP / AUTH towards a non-loopback host (dev flag). */
  allowInsecure: boolean;
  resolver?: Resolver;
  /** Extra trusted CA (tests only). */
  ca?: string | Buffer;
  connectTimeoutMs?: number;
  replyTimeoutMs?: number;
  totalTimeoutMs?: number;
}

class SmtpError extends Error {
  constructor(readonly result: { ok: false; code: string; retryable: boolean }) {
    super(result.code);
  }
}

const fail = (code: string, retryable: boolean) => new SmtpError({ ok: false, code, retryable });

function replyError(code: number): SmtpError {
  if (code >= 400 && code < 500) return fail(`smtp_${code}`, true);
  if (code >= 500 && code < 600) return fail(`smtp_${code}`, false);
  return fail("smtp_protocol", false);
}

interface Reply {
  code: number;
  lines: string[];
}

/** One SMTP conversation over a (possibly upgraded) socket. */
class Conversation {
  private buffer = "";
  private lines: string[] = [];
  private replyBytes = 0;
  private waiter: { resolve: (r: Reply) => void; reject: (e: Error) => void } | null = null;
  private failure: Error | null = null;
  socket: net.Socket;

  constructor(
    socket: net.Socket,
    private readonly replyTimeoutMs: number,
  ) {
    this.socket = socket;
    this.attach(socket);
  }

  attach(socket: net.Socket): void {
    this.socket = socket;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => this.onData(chunk));
    socket.on("error", (err: Error) => this.abort(err));
    socket.on("close", () => this.abort(fail("connect_failed", true)));
  }

  detach(): void {
    this.socket.removeAllListeners("data");
    this.socket.removeAllListeners("error");
    this.socket.removeAllListeners("close");
  }

  abort(err: Error): void {
    this.failure ??= err;
    const w = this.waiter;
    this.waiter = null;
    w?.reject(this.failure);
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    if (this.buffer.length > MAX_REPLY_BYTES) {
      this.abort(fail("smtp_protocol", false));
      this.socket.destroy();
      return;
    }
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, "");
      this.buffer = this.buffer.slice(idx + 1);
      const m = /^(\d{3})([ -])(.*)$/.exec(line);
      if (!m) {
        this.abort(fail("smtp_protocol", false));
        this.socket.destroy();
        return;
      }
      this.lines.push(m[3] ?? "");
      this.replyBytes += line.length + 2;
      // M2: a multi-line reply is bounded too, not only the unparsed buffer.
      if (this.lines.length > MAX_REPLY_LINES || this.replyBytes > MAX_REPLY_BYTES) {
        this.abort(fail("smtp_protocol", false));
        this.socket.destroy();
        return;
      }
      if (m[2] === " ") {
        const reply = { code: Number(m[1]), lines: this.lines };
        this.lines = [];
        this.replyBytes = 0;
        const w = this.waiter;
        this.waiter = null;
        if (w) w.resolve(reply);
        else {
          // Unsolicited reply (pipelining is never used): protocol error.
          this.abort(fail("smtp_protocol", false));
          this.socket.destroy();
        }
      }
    }
  }

  /** Received bytes not yet consumed as an awaited reply (or an unsolicited reply already seen). */
  hasPending(): boolean {
    return this.buffer !== "" || this.lines.length > 0 || this.failure !== null;
  }

  read(): Promise<Reply> {
    if (this.failure) return Promise.reject(this.failure);
    return new Promise<Reply>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.abort(fail("timeout", true));
        this.socket.destroy();
      }, this.replyTimeoutMs);
      this.waiter = {
        resolve: (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
    });
  }

  async command(line: string | null, expect: number[]): Promise<Reply> {
    if (line !== null) this.socket.write(`${line}\r\n`);
    const reply = await this.read();
    if (!expect.includes(reply.code)) throw replyError(reply.code);
    return reply;
  }
}

function ehloName(): string {
  const h = osHostname();
  return /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(h) ? h : "databastion-console";
}

function encodeSubject(subject: string): string {
  const clean = subject.replace(/[\r\n\t\0]+/g, " ").slice(0, 200);
  // RFC 2047 encoded-words (UTF-8, base64), split below 75 characters each.
  if (/^[\x20-\x7e]*$/.test(clean)) return clean;
  const words: string[] = [];
  let chunk = "";
  for (const ch of clean) {
    if (Buffer.byteLength(chunk + ch, "utf8") > 42) {
      words.push(chunk);
      chunk = "";
    }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, "utf8").toString("base64")}?=`).join("\r\n ");
}

/** The RFC 5322 message (CRLF line endings, base64 UTF-8 body). */
export function buildMessage(config: Pick<EmailConfig, "from" | "recipients">, msg: MailMessage, date = new Date()): string {
  const body = Buffer.from(msg.text.replace(/\r?\n/g, "\r\n"), "utf8").toString("base64");
  const wrapped = body.match(/.{1,76}/g)?.join("\r\n") ?? "";
  const headers = [
    `From: <${config.from}>`,
    `To: ${config.recipients.map((r) => `<${r}>`).join(", ")}`,
    `Subject: ${encodeSubject(msg.subject)}`,
    `Date: ${date.toUTCString()}`,
    `Message-ID: <${msg.deliveryId}@databastion.invalid>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "Auto-Submitted: auto-generated",
    `X-DataBastion-Event: ${msg.event.replace(/[^a-z0-9._-]/g, "")}`,
    `X-DataBastion-Delivery: ${msg.deliveryId.replace(/[^0-9a-f-]/g, "")}`,
  ];
  return `${headers.join("\r\n")}\r\n\r\n${wrapped}\r\n`;
}

/** Dot-stuffing (RFC 5321 4.5.2) and the end-of-data marker. */
export function dataPayload(message: string): string {
  const stuffed = message.replace(/\r\n\./g, "\r\n..").replace(/^\./, "..");
  return `${stuffed.endsWith("\r\n") ? stuffed : `${stuffed}\r\n`}.\r\n`;
}

function connectSocket(
  config: EmailConfig,
  address: string,
  opts: SmtpOptions,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const servername = net.isIP(config.host) === 0 ? config.host : undefined;
    const socket =
      config.tls === "implicit"
        ? tls.connect({ host: address, port: config.port, servername, ca: opts.ca, rejectUnauthorized: true })
        : net.connect({ host: address, port: config.port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(fail("connect_timeout", true));
    }, opts.connectTimeoutMs ?? SMTP_CONNECT_TIMEOUT_MS);
    socket.once(config.tls === "implicit" ? "secureConnect" : "connect", () => {
      clearTimeout(timer);
      socket.removeAllListeners("error");
      resolve(socket);
    });
    socket.once("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(tlsOrConnect(err));
    });
  });
}

const TLS_CODE = /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|HOSTNAME_MISMATCH|ERR_OSSL_)/;
function tlsOrConnect(err: unknown): SmtpError {
  const code = String((err as { code?: unknown } | null)?.code ?? "");
  return TLS_CODE.test(code) ? fail("tls_failed", true) : fail("connect_failed", true);
}

function upgrade(socket: net.Socket, config: EmailConfig, opts: SmtpOptions): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    // L4: `host` is what the certificate is verified against (without it Node falls back to
    // "localhost"); SNI only for a name, never an IP literal.
    const servername = net.isIP(config.host) === 0 ? config.host : undefined;
    const secure = tls.connect({ socket, host: config.host, servername, ca: opts.ca, rejectUnauthorized: true });
    const timer = setTimeout(() => {
      secure.destroy();
      reject(fail("tls_failed", true));
    }, opts.connectTimeoutMs ?? SMTP_CONNECT_TIMEOUT_MS);
    secure.once("secureConnect", () => {
      clearTimeout(timer);
      secure.removeAllListeners("error");
      resolve(secure);
    });
    secure.once("error", (err) => {
      clearTimeout(timer);
      reject(tlsOrConnect(err));
    });
  });
}

const isLoopbackAddress = (ip: string) => /^127\./.test(ip) || ip === "::1" || /^::ffff:127\./i.test(ip);

export async function sendMail(config: EmailConfig, password: string | null, msg: MailMessage, opts: SmtpOptions): Promise<SendResult> {
  const resolved = await resolveOutbound(config.host, { allowInternal: true, resolver: opts.resolver });
  if (!resolved.ok) return { ok: false, code: resolved.code, retryable: resolved.retryable };
  if (classifyAddress(resolved.address) === "forbidden") return { ok: false, code: "address_forbidden", retryable: false };
  const loopback = isLoopbackAddress(resolved.address);
  if (config.tls === "none" && !loopback && !opts.allowInsecure) return { ok: false, code: "insecure_refused", retryable: false };

  let socket: net.Socket | null = null;
  let totalTimer: NodeJS.Timeout | undefined;
  const total = new Promise<never>((_, reject) => {
    totalTimer = setTimeout(() => {
      socket?.destroy();
      reject(fail("timeout", true));
    }, opts.totalTimeoutMs ?? SMTP_TOTAL_TIMEOUT_MS);
  });
  const run = async (): Promise<void> => {
    socket = await connectSocket(config, resolved.address, opts);
    const conv = new Conversation(socket, opts.replyTimeoutMs ?? SMTP_REPLY_TIMEOUT_MS);
    let secure = config.tls === "implicit";
    await conv.command(null, [220]);
    let ehlo = await conv.command(`EHLO ${ehloName()}`, [250]);
    if (config.tls === "starttls") {
      if (!ehlo.lines.some((l) => /^STARTTLS\b/i.test(l))) throw fail("starttls_unavailable", false);
      await conv.command("STARTTLS", [220]);
      // L1: nothing may follow the 220 in clear (STARTTLS response injection, CVE-2011-0411 class).
      if (conv.hasPending()) throw fail("smtp_protocol", false);
      conv.detach();
      socket = await upgrade(socket, config, opts);
      conv.attach(socket);
      secure = true;
      ehlo = await conv.command(`EHLO ${ehloName()}`, [250]);
    }
    if (config.username !== null) {
      if (!secure && !loopback && !opts.allowInsecure) throw fail("auth_refused_plaintext", false);
      if (password === null) throw fail("secret_unavailable", true);
      const auth = ehlo.lines.find((l) => /^AUTH[ =]/i.test(l))?.slice(5).toUpperCase().split(/\s+/) ?? [];
      if (auth.includes("PLAIN")) {
        const token = Buffer.from(`\0${config.username}\0${password}`, "utf8").toString("base64");
        await conv.command(`AUTH PLAIN ${token}`, [235]);
      } else if (auth.includes("LOGIN")) {
        await conv.command("AUTH LOGIN", [334]);
        await conv.command(Buffer.from(config.username, "utf8").toString("base64"), [334]);
        await conv.command(Buffer.from(password, "utf8").toString("base64"), [235]);
      } else {
        throw fail("auth_unavailable", false);
      }
    }
    await conv.command(`MAIL FROM:<${config.from}>`, [250]);
    for (const r of config.recipients) await conv.command(`RCPT TO:<${r}>`, [250, 251]);
    await conv.command("DATA", [354]);
    await conv.command(dataPayload(buildMessage(config, msg)).replace(/\r\n$/, ""), [250]);
    // Best effort: the message is accepted at this point.
    socket.write("QUIT\r\n");
    socket.end();
  };
  try {
    await Promise.race([run(), total]);
    return { ok: true };
  } catch (err) {
    (socket as net.Socket | null)?.destroy();
    if (err instanceof SmtpError) return err.result;
    return { ok: false, code: "internal", retryable: true };
  } finally {
    clearTimeout(totalTimer);
  }
}
