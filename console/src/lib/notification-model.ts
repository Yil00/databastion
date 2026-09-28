/**
 * Notification channels (P3-C): types, limits and UI messages shared by the server and the UI
 * (client-safe: no Node imports). Validation lives in `src/server/channels.ts`.
 */

export const CHANNEL_TYPES = ["email", "webhook"] as const;
export type ChannelType = (typeof CHANNEL_TYPES)[number];

/**
 * SMTP transport security: `starttls` (upgrade required: a server that does not offer STARTTLS is
 * an error, never a silent downgrade), `implicit` (TLS from the first byte, usually port 465),
 * `none` (plain text: only towards a loopback host, or with `DATABASTION_ALERTING_INSECURE_DEV=1`).
 */
export const TLS_MODES = ["starttls", "implicit", "none"] as const;
export type TlsMode = (typeof TLS_MODES)[number];

export const MAX_RECIPIENTS = 20;
/** SMTP ports accepted without the dev flag: relay (25), implicit TLS (465), submission (587, 2525). */
export const SMTP_PORTS = [25, 465, 587, 2525] as const;
export const MAX_URL_LENGTH = 2048;
export const MAX_PASSWORD_LENGTH = 1024;

export interface EmailConfig {
  host: string;
  port: number;
  tls: TlsMode;
  from: string;
  recipients: string[];
  /** SMTP AUTH user; the password is the channel secret (encrypted, never returned). */
  username: string | null;
}

/**
 * Non-secret part of a webhook channel: the origin of its URL, for display. The full URL is stored
 * encrypted with the signing secret (many webhook URLs carry a token in their path or query) and
 * is never returned.
 */
export interface WebhookConfig {
  origin: string;
}

/** Channel as returned by the API and shown in the UI: never a secret. */
export interface ChannelView {
  id: string;
  slug: string;
  type: ChannelType;
  enabled: boolean;
  systemAlerts: boolean;
  config: EmailConfig | WebhookConfig;
  /** An SMTP password / a webhook signing secret is stored (the value itself is never shown). */
  secretSet: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export const DELIVERY_STATUSES = ["pending", "sending", "delivered", "failed", "skipped"] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

/** Events a delivery can report. */
export const NOTIFICATION_EVENTS = [
  "incident.opened",
  "agent.silent",
  "agent.recovered",
  "agent.integrity",
  "channel.test",
  "notifications.suppressed",
] as const;
export type NotificationEvent = (typeof NOTIFICATION_EVENTS)[number];

/**
 * Closed set of delivery error codes (`notification_deliveries.last_error`): never a server
 * response, address or secret. `http_<status>` and `smtp_<code>` carry the numeric status only.
 */
export const DELIVERY_ERROR_TEXT: Record<string, string> = {
  unknown_channel: "no channel has this name",
  rate_limited: "over the channel's hourly limit (counted in the next suppression digest)",
  channel_disabled: "the channel is disabled",
  channel_deleted: "the channel was deleted",
  secret_unavailable: "the channel secret cannot be decrypted (server key missing or changed)",
  insecure_refused: "plain-text transport refused (not a loopback host, no dev flag)",
  port_refused: "SMTP port refused (25, 465, 587 or 2525 only, no dev flag)",
  dns_failed: "name resolution failed",
  address_forbidden: "destination address refused (link-local, metadata, multicast or reserved)",
  address_internal: "destination address refused (private or loopback)",
  connect_failed: "connection failed",
  connect_timeout: "connection timed out",
  timeout: "timed out",
  tls_failed: "TLS handshake or certificate verification failed",
  redirect_refused: "the webhook answered a redirect (redirects are never followed)",
  starttls_unavailable: "the SMTP server does not offer STARTTLS",
  auth_unavailable: "the SMTP server offers no supported authentication",
  auth_refused_plaintext: "SMTP authentication refused over a plain-text connection",
  smtp_protocol: "unexpected SMTP reply",
  internal: "internal error",
};

export function deliveryErrorText(code: string | null): string {
  if (code === null) return "";
  if (Object.hasOwn(DELIVERY_ERROR_TEXT, code)) return DELIVERY_ERROR_TEXT[code] as string;
  const http = /^http_(\d{3})$/.exec(code);
  if (http) return `HTTP ${http[1]}`;
  const smtp = /^smtp_(\d{3})$/.exec(code);
  if (smtp) return `SMTP reply ${smtp[1]}`;
  return code;
}

/** UI messages for `400 {"error": "invalid_channel", "field"}`. */
export const CHANNEL_FIELD_ERRORS: Record<string, string> = {
  body: "Invalid request.",
  unknown_key: "Unknown setting.",
  slug: "Name: 1 to 63 characters, lowercase letters, digits, '.', '_' or '-', starting with a letter or digit.",
  type: "Type: email or webhook.",
  enabled: "Enabled: true or false.",
  system_alerts: "System alerts: true or false.",
  config: "Invalid settings.",
  "config.host": "SMTP host: a host name or IP address (link-local and metadata addresses are refused).",
  "config.port": "SMTP port: 25, 465, 587 or 2525.",
  "config.tls": "TLS: starttls or implicit; none only towards a loopback host (or with the dev flag).",
  "config.from": "Sender: one e-mail address.",
  "config.recipients": `Recipients: 1 to ${MAX_RECIPIENTS} distinct e-mail addresses.`,
  "config.username": "SMTP user: 1 to 256 printable characters.",
  "config.url":
    "Webhook URL: https:// only, no credentials or fragment, and not a private, loopback, link-local or metadata address (http:// and internal addresses only with the dev flag).",
  password: `SMTP password: 1 to ${MAX_PASSWORD_LENGTH} characters, no line breaks; only with a user.`,
};

export function channelErrorMessage(status: number, body: unknown): string {
  const b = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  if (status === 400 && typeof b.field === "string" && Object.hasOwn(CHANNEL_FIELD_ERRORS, b.field)) {
    return CHANNEL_FIELD_ERRORS[b.field] as string;
  }
  if (status === 400 && b.error === "password_required") {
    return "Changing the SMTP host, port, TLS mode or user requires entering the password again (or removing it).";
  }
  if (status === 409 && b.error === "slug_taken") return "A channel with this name already exists.";
  if (status === 409 && b.error === "encryption_key_unavailable") {
    return "The console server key (DATABASTION_ENCRYPTION_KEY) is not configured: secrets cannot be stored.";
  }
  if (status === 403) return "Not allowed.";
  if (status === 404) return "The channel no longer exists.";
  return `The channel could not be saved (${status}).`;
}
