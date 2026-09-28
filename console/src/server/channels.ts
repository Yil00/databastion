import { randomUUID } from "node:crypto";
import { isIP } from "node:net";

import { asc, eq, inArray, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { notificationChannels } from "@/db/schema";
import { CHANNEL_REF } from "@/lib/policy-model";
import {
  MAX_PASSWORD_LENGTH,
  MAX_RECIPIENTS,
  MAX_URL_LENGTH,
  TLS_MODES,
  type ChannelType,
  type ChannelView,
  type EmailConfig,
  type TlsMode,
  type WebhookConfig,
} from "@/lib/notification-model";

import { insecureDevAllowed } from "./alerting-config";
import { writeAudit } from "./audit";
import { channelSecretsKey, decryptChannelSecret, encryptChannelSecret, newWebhookSecret } from "./channel-secrets";
import { classifyAddress } from "./net-guard";

/**
 * Notification channels (P3-C): validation of the administrator input, storage and audit.
 *
 * Secrets never leave this module in clear except towards the sender (worker) and, once, the
 * administrator who creates or rotates a webhook signing secret. The encrypted blob
 * (`channel-secrets.ts`) holds a JSON document: `{"password"}` for an e-mail channel with SMTP
 * AUTH, `{"url", "signing_secret"}` for a webhook (the full URL is treated as a secret: webhook
 * URLs often embed a token). Audit entries hold the slug, type, flags and counts only: never a
 * host, URL, address, user name or secret.
 */

type Actor = { userId: string; ip: string | null };
type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };
const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

const HOSTNAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
/** Printable text: no control / format / private-use / separator characters. */
const TEXT = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]+$/u;
const NO_LINE_BREAK = /^[^\r\n\0]+$/;

export function isEmailAddress(v: unknown): v is string {
  return typeof v === "string" && v.length <= 254 && EMAIL.test(v);
}

/** `localhost`, `*.localhost`, `127.0.0.0/8`, `::1` (and their mapped forms). */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  const bare = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
  if (isIP(bare) === 4) return bare.startsWith("127.");
  if (isIP(bare) === 6) return bare === "::1" || /^::ffff:127\./.test(bare) || /^::ffff:7f[0-9a-f]{2}:/.test(bare);
  return false;
}

function parseHost(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const h = v.trim();
  if (isIP(h) !== 0) return classifyAddress(h) === "forbidden" ? null : h;
  return HOSTNAME.test(h) ? h.toLowerCase() : null;
}

interface EmailInput {
  config: EmailConfig;
}

function parseEmailConfig(v: unknown, insecureDev: boolean): Parsed<EmailInput> {
  if (!isPlainObject(v)) return fail("config");
  const keys = ["host", "port", "tls", "from", "recipients", "username"];
  if (Object.keys(v).some((k) => !keys.includes(k))) return fail("unknown_key");
  const host = parseHost(v.host);
  if (host === null) return fail("config.host");
  if (typeof v.port !== "number" || !Number.isInteger(v.port) || v.port < 1 || v.port > 65535) return fail("config.port");
  if (typeof v.tls !== "string" || !(TLS_MODES as readonly string[]).includes(v.tls)) return fail("config.tls");
  const tls = v.tls as TlsMode;
  // Plain text only towards a loopback relay, or with the explicit development flag.
  if (tls === "none" && !isLoopbackHost(host) && !insecureDev) return fail("config.tls");
  if (!isEmailAddress(v.from)) return fail("config.from");
  if (
    !Array.isArray(v.recipients) ||
    v.recipients.length < 1 ||
    v.recipients.length > MAX_RECIPIENTS ||
    !v.recipients.every(isEmailAddress) ||
    new Set(v.recipients.map((r: string) => r.toLowerCase())).size !== v.recipients.length
  ) {
    return fail("config.recipients");
  }
  let username: string | null = null;
  if (v.username !== undefined && v.username !== null) {
    if (typeof v.username !== "string" || v.username.length > 256 || !TEXT.test(v.username)) return fail("config.username");
    username = v.username;
  }
  return { ok: true, value: { config: { host, port: v.port, tls, from: v.from, recipients: [...v.recipients], username } } };
}

/**
 * Webhook URL: `https://` (`http://` only with the dev flag), no credentials, no fragment, at most
 * 2048 characters. A literal IP address is checked against the outbound address policy here; a
 * host name is resolved and checked by the worker at every delivery (`net-guard.ts`).
 */
export function parseWebhookUrl(v: unknown, insecureDev: boolean): URL | null {
  if (typeof v !== "string" || v.length > MAX_URL_LENGTH || !NO_LINE_BREAK.test(v)) return null;
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && insecureDev)) return null;
  if (url.username !== "" || url.password !== "" || url.hash !== "" || url.hostname === "") return null;
  const host = url.hostname;
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (isIP(bare) !== 0) {
    const cls = classifyAddress(bare);
    if (cls === "forbidden" || (cls === "internal" && !insecureDev)) return null;
  } else if (!HOSTNAME.test(bare) || (isLoopbackHost(bare) && !insecureDev)) {
    return null;
  }
  return url;
}

export interface ChannelCreateInput {
  slug: string;
  type: ChannelType;
  enabled: boolean;
  systemAlerts: boolean;
  email?: EmailConfig;
  password?: string | null;
  webhookUrl?: string;
}

function parsePassword(v: unknown): Parsed<string | null> {
  if (v === null) return { ok: true, value: null };
  if (typeof v !== "string" || v.length < 1 || v.length > MAX_PASSWORD_LENGTH || !NO_LINE_BREAK.test(v)) return fail("password");
  return { ok: true, value: v };
}

/** Create body: `{slug, type, enabled?, system_alerts?, config, password?}`; unknown keys rejected. */
export function parseChannelCreate(v: unknown, insecureDev = insecureDevAllowed()): Parsed<ChannelCreateInput> {
  if (!isPlainObject(v)) return fail("body");
  if (Object.keys(v).some((k) => !["slug", "type", "enabled", "system_alerts", "config", "password"].includes(k))) {
    return fail("unknown_key");
  }
  if (typeof v.slug !== "string" || !CHANNEL_REF.test(v.slug)) return fail("slug");
  if (v.type !== "email" && v.type !== "webhook") return fail("type");
  if (v.enabled !== undefined && typeof v.enabled !== "boolean") return fail("enabled");
  if (v.system_alerts !== undefined && typeof v.system_alerts !== "boolean") return fail("system_alerts");
  const type: ChannelType = v.type;
  const base = { slug: v.slug, type, enabled: v.enabled ?? true, systemAlerts: v.system_alerts ?? false };
  if (v.type === "email") {
    const c = parseEmailConfig(v.config, insecureDev);
    if (!c.ok) return c;
    let password: string | null = null;
    if (v.password !== undefined) {
      const p = parsePassword(v.password);
      if (!p.ok) return p;
      password = p.value;
    }
    if (password !== null && c.value.config.username === null) return fail("password");
    return { ok: true, value: { ...base, email: c.value.config, password } };
  }
  if (v.password !== undefined) return fail("password");
  if (!isPlainObject(v.config)) return fail("config");
  if (Object.keys(v.config).some((k) => k !== "url")) return fail("unknown_key");
  const url = parseWebhookUrl(v.config.url, insecureDev);
  if (url === null) return fail("config.url");
  return { ok: true, value: { ...base, webhookUrl: url.toString() } };
}

export interface ChannelUpdateInput {
  enabled?: boolean;
  systemAlerts?: boolean;
  email?: EmailConfig;
  /** `null`: remove the stored password. */
  password?: string | null;
  webhookUrl?: string;
}

/** Update body: any subset of `{enabled, system_alerts, config, password}` (slug and type fixed). */
export function parseChannelUpdate(v: unknown, type: ChannelType, insecureDev = insecureDevAllowed()): Parsed<ChannelUpdateInput> {
  if (!isPlainObject(v)) return fail("body");
  if (Object.keys(v).some((k) => !["enabled", "system_alerts", "config", "password"].includes(k))) return fail("unknown_key");
  if (Object.keys(v).length === 0) return fail("body");
  const out: ChannelUpdateInput = {};
  if (v.enabled !== undefined) {
    if (typeof v.enabled !== "boolean") return fail("enabled");
    out.enabled = v.enabled;
  }
  if (v.system_alerts !== undefined) {
    if (typeof v.system_alerts !== "boolean") return fail("system_alerts");
    out.systemAlerts = v.system_alerts;
  }
  if (type === "email") {
    if (v.config !== undefined) {
      const c = parseEmailConfig(v.config, insecureDev);
      if (!c.ok) return c;
      out.email = c.value.config;
    }
    if (v.password !== undefined) {
      const p = parsePassword(v.password);
      if (!p.ok) return p;
      out.password = p.value;
      if (p.value !== null && out.email && out.email.username === null) return fail("password");
    }
    return { ok: true, value: out };
  }
  if (v.password !== undefined) return fail("password");
  if (v.config !== undefined) {
    if (!isPlainObject(v.config)) return fail("config");
    if (Object.keys(v.config).some((k) => k !== "url")) return fail("unknown_key");
    const url = parseWebhookUrl(v.config.url, insecureDev);
    if (url === null) return fail("config.url");
    out.webhookUrl = url.toString();
  }
  return { ok: true, value: out };
}

// ----------------------------------------------------------------------------- secrets

interface EmailSecret {
  password: string;
}
interface WebhookSecret {
  url: string;
  signing_secret: string;
}

function seal(key: Buffer, id: string, type: ChannelType, doc: EmailSecret | WebhookSecret): Buffer {
  return encryptChannelSecret(key, id, type, JSON.stringify(doc));
}

function unseal(key: Buffer | null, id: string, type: ChannelType, blob: Buffer | null): Record<string, unknown> | null {
  if (!key || !blob) return null;
  const text = decryptChannelSecret(key, id, type, blob);
  if (text === null) return null;
  try {
    const doc: unknown = JSON.parse(text);
    return isPlainObject(doc) ? doc : null;
  } catch {
    return null;
  }
}

const webhookOrigin = (url: string): WebhookConfig => ({ origin: new URL(url).origin });

// ------------------------------------------------------------------------------- writes

function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: unknown; cause?: { code?: unknown } } | null;
  return (e?.code ?? e?.cause?.code) === "23505";
}

function auditConfig(type: ChannelType, config: EmailConfig | null): Record<string, string | number | boolean | null> {
  if (type === "webhook" || config === null) return {};
  return { tls: config.tls, port: config.port, recipients_count: config.recipients.length, smtp_auth: config.username !== null };
}

export type ChannelWriteOutcome =
  | { outcome: "ok"; id: string; signingSecret?: string }
  | { outcome: "slug_taken" }
  | { outcome: "not_found" }
  | { outcome: "key_unavailable" }
  | { outcome: "invalid_password" }
  | { outcome: "password_required" };

/**
 * Creates a channel. A webhook gets a signing secret generated here, returned once to the caller.
 * Without the server key, a channel that needs a secret (every webhook, an e-mail channel with a
 * password) is refused (`key_unavailable`).
 */
export async function createChannel(db: Database, input: ChannelCreateInput, actor: Actor): Promise<ChannelWriteOutcome> {
  const id = randomUUID();
  const key = channelSecretsKey();
  let secret: Buffer | null = null;
  let signingSecret: string | undefined;
  let config: EmailConfig | WebhookConfig;
  if (input.type === "webhook") {
    if (!key) return { outcome: "key_unavailable" };
    signingSecret = newWebhookSecret();
    secret = seal(key, id, "webhook", { url: input.webhookUrl as string, signing_secret: signingSecret });
    config = webhookOrigin(input.webhookUrl as string);
  } else {
    config = input.email as EmailConfig;
    if (input.password) {
      if (!key) return { outcome: "key_unavailable" };
      secret = seal(key, id, "email", { password: input.password });
    }
  }
  try {
    await db.transaction(async (tx) => {
      await tx.insert(notificationChannels).values({
        id,
        slug: input.slug,
        type: input.type,
        enabled: input.enabled,
        systemAlerts: input.systemAlerts,
        config: config as unknown as Record<string, unknown>,
        secret,
        createdBy: actor.userId,
        updatedBy: actor.userId,
      });
      await writeAudit(tx, {
        actorType: "user",
        actorId: actor.userId,
        action: "notification_channel.create",
        targetType: "notification_channel",
        targetId: id,
        sourceIp: actor.ip,
        details: {
          slug: input.slug,
          type: input.type,
          enabled: input.enabled,
          system_alerts: input.systemAlerts,
          ...auditConfig(input.type, input.email ?? null),
        },
      });
    });
  } catch (err) {
    if (isUniqueViolation(err)) return { outcome: "slug_taken" };
    throw err;
  }
  return { outcome: "ok", id, signingSecret };
}

export async function channelType(db: Database, id: string): Promise<ChannelType | null> {
  const [row] = await db.select({ type: notificationChannels.type }).from(notificationChannels).where(eq(notificationChannels.id, id));
  return row?.type ?? null;
}

/**
 * Updates a channel. A new webhook URL is sealed with the existing signing secret; e-mail settings
 * are replaced as a whole, and removing the SMTP user removes the password.
 */
export async function updateChannel(db: Database, id: string, input: ChannelUpdateInput, actor: Actor): Promise<ChannelWriteOutcome> {
  return db.transaction(async (tx) => {
    const [row] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, id)).for("update");
    if (!row) return { outcome: "not_found" as const };
    const key = channelSecretsKey();
    const set: Partial<typeof notificationChannels.$inferInsert> = {};
    if (input.enabled !== undefined) set.enabled = input.enabled;
    if (input.systemAlerts !== undefined) set.systemAlerts = input.systemAlerts;
    let secretChanged = false;
    if (row.type === "webhook" && input.webhookUrl !== undefined) {
      const doc = unseal(key, id, "webhook", row.secret);
      if (!key || !doc || typeof doc.signing_secret !== "string") return { outcome: "key_unavailable" as const };
      set.secret = seal(key, id, "webhook", { url: input.webhookUrl, signing_secret: doc.signing_secret });
      set.config = webhookOrigin(input.webhookUrl) as unknown as Record<string, unknown>;
      secretChanged = true;
    }
    if (row.type === "email") {
      const current = row.config as unknown as EmailConfig;
      const next = input.email ?? current;
      if (input.email) set.config = input.email as unknown as Record<string, unknown>;
      if (next.username === null) {
        // A password without an SMTP user is meaningless: refused rather than silently dropped.
        if (typeof input.password === "string") return { outcome: "invalid_password" as const };
        if (row.secret !== null) secretChanged = true;
        set.secret = null;
      } else if (
        // M1: the stored password is bound to the relay it was entered for. Moving the channel to
        // another host, port, TLS mode or user without re-entering it could send it to a server
        // of the editor's choice (e.g. with "Test"): a new password (or its removal) is required.
        row.secret !== null &&
        input.password === undefined &&
        (next.host !== current.host || next.port !== current.port || next.tls !== current.tls || next.username !== current.username)
      ) {
        return { outcome: "password_required" as const };
      } else if (input.password !== undefined) {
        if (input.password === null) {
          set.secret = null;
        } else {
          if (!key) return { outcome: "key_unavailable" as const };
          set.secret = seal(key, id, "email", { password: input.password });
        }
        secretChanged = true;
      }
    }
    await tx
      .update(notificationChannels)
      .set({ ...set, updatedAt: sql`now()`, updatedBy: actor.userId })
      .where(eq(notificationChannels.id, id));
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "notification_channel.update",
      targetType: "notification_channel",
      targetId: id,
      sourceIp: actor.ip,
      details: {
        slug: row.slug,
        type: row.type,
        changed: [
          input.enabled !== undefined ? "enabled" : null,
          input.systemAlerts !== undefined ? "system_alerts" : null,
          input.email !== undefined || input.webhookUrl !== undefined ? "config" : null,
          secretChanged ? "credential" : null,
        ]
          .filter((x) => x !== null)
          .join(","),
        enabled: set.enabled ?? row.enabled,
        system_alerts: set.systemAlerts ?? row.systemAlerts,
        ...auditConfig(row.type, row.type === "email" ? (input.email ?? (row.config as unknown as EmailConfig)) : null),
      },
    });
    return { outcome: "ok" as const, id };
  });
}

/** Replaces the signing secret of a webhook channel; the new one is returned once. */
export async function rotateWebhookSecret(db: Database, id: string, actor: Actor): Promise<ChannelWriteOutcome> {
  return db.transaction(async (tx) => {
    const [row] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, id)).for("update");
    if (!row || row.type !== "webhook") return { outcome: "not_found" as const };
    const key = channelSecretsKey();
    const doc = unseal(key, id, "webhook", row.secret);
    if (!key || !doc || typeof doc.url !== "string") return { outcome: "key_unavailable" as const };
    const signingSecret = newWebhookSecret();
    await tx
      .update(notificationChannels)
      .set({ secret: seal(key, id, "webhook", { url: doc.url, signing_secret: signingSecret }), updatedAt: sql`now()`, updatedBy: actor.userId })
      .where(eq(notificationChannels.id, id));
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "notification_channel.rotate_signing_key",
      targetType: "notification_channel",
      targetId: id,
      sourceIp: actor.ip,
      details: { slug: row.slug, type: row.type },
    });
    return { outcome: "ok" as const, id, signingSecret };
  });
}

/**
 * Deletes a channel. Its delivery records are kept (`channel_id` set to null, slug kept); pending
 * deliveries then fail with `channel_deleted`. Policies referencing the slug keep it (the policy
 * page warns).
 */
export async function deleteChannel(db: Database, id: string, actor: Actor): Promise<boolean> {
  return db.transaction(async (tx) => {
    const rows = await tx
      .delete(notificationChannels)
      .where(eq(notificationChannels.id, id))
      .returning({ slug: notificationChannels.slug, type: notificationChannels.type });
    const row = rows[0];
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "notification_channel.delete",
      outcome: row ? "success" : "failure",
      targetType: "notification_channel",
      targetId: id,
      sourceIp: actor.ip,
      details: row ? { slug: row.slug, type: row.type } : { reason: "not_found" },
    });
    return row !== undefined;
  });
}

// -------------------------------------------------------------------------------- reads

export async function listChannels(db: Database): Promise<ChannelView[]> {
  const rows = await db
    .select({
      id: notificationChannels.id,
      slug: notificationChannels.slug,
      type: notificationChannels.type,
      enabled: notificationChannels.enabled,
      systemAlerts: notificationChannels.systemAlerts,
      config: notificationChannels.config,
      secretSet: sql<boolean>`${notificationChannels.secret} is not null`,
      createdAt: notificationChannels.createdAt,
      updatedAt: notificationChannels.updatedAt,
    })
    .from(notificationChannels)
    .orderBy(asc(notificationChannels.slug));
  return rows.map((r) => ({ ...r, config: r.config as unknown as EmailConfig | WebhookConfig }));
}

/** State of each referenced slug (policy page warnings): `ok`, `disabled` or `unknown`. */
export async function channelStates(db: Database, slugs: readonly string[]): Promise<Record<string, "ok" | "disabled" | "unknown">> {
  const out: Record<string, "ok" | "disabled" | "unknown"> = {};
  for (const s of slugs) out[s] = "unknown";
  if (slugs.length === 0) return out;
  const rows = await db
    .select({ slug: notificationChannels.slug, enabled: notificationChannels.enabled })
    .from(notificationChannels)
    .where(inArray(notificationChannels.slug, [...slugs]));
  for (const r of rows) out[r.slug] = r.enabled ? "ok" : "disabled";
  return out;
}

export type ResolvedChannel =
  | { type: "email"; slug: string; enabled: boolean; config: EmailConfig; password: string | null; secretOk: boolean }
  | { type: "webhook"; slug: string; enabled: boolean; url: string | null; signingSecret: string | null; secretOk: boolean };

/** A channel with its decrypted secret, for the sender only (worker). */
export async function loadChannelForDelivery(db: Database, id: string): Promise<ResolvedChannel | null> {
  const [row] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id));
  if (!row) return null;
  const key = channelSecretsKey();
  if (row.type === "email") {
    const config = row.config as unknown as EmailConfig;
    const doc = row.secret ? unseal(key, id, "email", row.secret) : null;
    const password = typeof doc?.password === "string" ? doc.password : null;
    return { type: "email", slug: row.slug, enabled: row.enabled, config, password, secretOk: row.secret === null || password !== null };
  }
  const doc = unseal(key, id, "webhook", row.secret);
  const url = typeof doc?.url === "string" ? doc.url : null;
  const signingSecret = typeof doc?.signing_secret === "string" ? doc.signing_secret : null;
  return { type: "webhook", slug: row.slug, enabled: row.enabled, url, signingSecret, secretOk: url !== null && signingSecret !== null };
}
