import { describe, expect, it } from "vitest";

import { channelErrorMessage, deliveryErrorText } from "@/lib/notification-model";

import { channelSecretsKey, decryptChannelSecret, encryptChannelSecret, newWebhookSecret } from "./channel-secrets";
import { isLoopbackHost, parseChannelCreate, parseChannelUpdate, parseWebhookUrl } from "./channels";

const EMAIL = {
  slug: "secops-mail",
  type: "email",
  config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "dlp@example.com", recipients: ["soc@example.com"] },
};

describe("notification channel validation", () => {
  it("accepts a strict e-mail channel and rejects unknown keys", () => {
    const ok = parseChannelCreate(EMAIL, false);
    expect(ok).toMatchObject({ ok: true, value: { slug: "secops-mail", type: "email", enabled: true, systemAlerts: false } });
    expect(parseChannelCreate({ ...EMAIL, extra: 1 }, false)).toEqual({ ok: false, error: "unknown_key" });
    expect(parseChannelCreate({ ...EMAIL, config: { ...EMAIL.config, cc: "x" } }, false)).toEqual({ ok: false, error: "unknown_key" });
    expect(parseChannelCreate({ ...EMAIL, slug: "Bad Slug" }, false)).toEqual({ ok: false, error: "slug" });
  });

  it.each([
    [{ host: "169.254.169.254" }, "config.host"],
    [{ host: "bad host" }, "config.host"],
    [{ port: 0 }, "config.port"],
    [{ port: 70000 }, "config.port"],
    [{ port: 22 }, "config.port"],
    [{ port: 6379 }, "config.port"],
    [{ tls: "ssl" }, "config.tls"],
    [{ from: "not an address" }, "config.from"],
    [{ from: "a@b.com\r\nBcc: x@y.com" }, "config.from"],
    [{ recipients: [] }, "config.recipients"],
    [{ recipients: ["a@b.com", "A@B.com"] }, "config.recipients"],
    [{ recipients: ["a@b.com>, <evil@x.com"] }, "config.recipients"],
    [{ username: "line\nbreak" }, "config.username"],
  ])("rejects e-mail settings %j", (over, field) => {
    expect(parseChannelCreate({ ...EMAIL, config: { ...EMAIL.config, ...over } }, false)).toEqual({ ok: false, error: field });
  });

  it("plain-text SMTP only towards a loopback relay, or with the dev flag", () => {
    const plain = (host: string) => ({ ...EMAIL, config: { ...EMAIL.config, host, tls: "none", port: 25 } });
    expect(parseChannelCreate(plain("smtp.example.com"), false)).toEqual({ ok: false, error: "config.tls" });
    expect(parseChannelCreate(plain("10.0.0.25"), false)).toEqual({ ok: false, error: "config.tls" });
    expect(parseChannelCreate(plain("localhost"), false).ok).toBe(true);
    expect(parseChannelCreate(plain("127.0.0.1"), false).ok).toBe(true);
    expect(parseChannelCreate(plain("smtp.example.com"), true).ok).toBe(true);
  });

  it("L3: SMTP ports 25, 465, 587, 2525; any port with the dev flag", () => {
    for (const port of [25, 465, 587, 2525]) expect(parseChannelCreate({ ...EMAIL, config: { ...EMAIL.config, port } }, false).ok).toBe(true);
    expect(parseChannelCreate({ ...EMAIL, config: { ...EMAIL.config, port: 1025 } }, true).ok).toBe(true);
  });

  it("a password needs a user and has no line break", () => {
    expect(parseChannelCreate({ ...EMAIL, password: "pw" }, false)).toEqual({ ok: false, error: "password" });
    const withUser = { ...EMAIL, config: { ...EMAIL.config, username: "dlp" } };
    expect(parseChannelCreate({ ...withUser, password: "pw" }, false).ok).toBe(true);
    expect(parseChannelCreate({ ...withUser, password: "p\r\nw" }, false)).toEqual({ ok: false, error: "password" });
  });

  it("webhooks: https only, no credentials or fragment, no internal literal (dev flag aside), never metadata", () => {
    expect(parseWebhookUrl("https://hooks.example.com/services/T0/B0/xyz?x=1", false)?.toString()).toBe(
      "https://hooks.example.com/services/T0/B0/xyz?x=1",
    );
    for (const bad of [
      "http://hooks.example.com/x",
      "ftp://hooks.example.com/x",
      "https://user:pw@hooks.example.com/x",
      "https://hooks.example.com/x#frag",
      "https://127.0.0.1/x",
      "https://10.0.0.1/x",
      "https://[::1]/x",
      "https://localhost/x",
      "https://169.254.169.254/latest/meta-data",
      "https://[fd00:ec2::254]/",
      "https://0.0.0.0/",
      "not a url",
    ]) {
      expect(parseWebhookUrl(bad, false), bad).toBeNull();
    }
    expect(parseWebhookUrl("http://127.0.0.1:8080/hook", true)).not.toBeNull();
    expect(parseWebhookUrl("https://localhost/x", true)).not.toBeNull();
    expect(parseWebhookUrl("https://169.254.169.254/x", true)).toBeNull();
    expect(parseChannelCreate({ slug: "hook", type: "webhook", config: { url: "https://h.example.com/x" }, password: "x" }, false)).toEqual({
      ok: false,
      error: "password",
    });
  });

  it("updates: subsets only, slug and type fixed", () => {
    expect(parseChannelUpdate({ enabled: false }, "webhook", false)).toEqual({ ok: true, value: { enabled: false } });
    expect(parseChannelUpdate({ slug: "other" }, "email", false)).toEqual({ ok: false, error: "unknown_key" });
    expect(parseChannelUpdate({}, "email", false)).toEqual({ ok: false, error: "body" });
    expect(parseChannelUpdate({ password: null }, "email", false)).toEqual({ ok: true, value: { password: null } });
    expect(parseChannelUpdate({ config: { url: "http://h.example.com/" } }, "webhook", false)).toEqual({ ok: false, error: "config.url" });
  });

  it("recognizes loopback hosts", () => {
    for (const h of ["localhost", "LOCALHOST.", "mail.localhost", "127.0.0.1", "127.1.2.3", "::1", "[::1]"]) expect(isLoopbackHost(h), h).toBe(true);
    for (const h of ["localhost.example.com", "10.0.0.1", "::2", "example.com"]) expect(isLoopbackHost(h), h).toBe(false);
  });

  it("UI messages for errors and delivery codes", () => {
    expect(channelErrorMessage(400, { error: "invalid_channel", field: "config.url" })).toMatch(/https/);
    expect(channelErrorMessage(409, { error: "encryption_key_unavailable" })).toMatch(/DATABASTION_ENCRYPTION_KEY/);
    expect(deliveryErrorText("http_503")).toBe("HTTP 503");
    expect(deliveryErrorText("smtp_550")).toBe("SMTP reply 550");
    expect(deliveryErrorText("address_internal")).toMatch(/private/);
  });
});

describe("channel secrets at rest", () => {
  it("AES-256-GCM bound to the channel id and type; fails closed", () => {
    const key = channelSecretsKey();
    if (!key) throw new Error("the tests set DATABASTION_ENCRYPTION_KEY");
    const id = "01890a5d-ac96-774b-bcce-b302099a8057";
    const blob = encryptChannelSecret(key, id, "webhook", '{"signing_secret":"whsec_x"}');
    expect(blob.includes(Buffer.from("whsec_x"))).toBe(false);
    expect(decryptChannelSecret(key, id, "webhook", blob)).toBe('{"signing_secret":"whsec_x"}');
    expect(decryptChannelSecret(key, "01890a5d-ac96-774b-bcce-b302099a8058", "webhook", blob)).toBeNull();
    expect(decryptChannelSecret(key, id, "email", blob)).toBeNull();
    const other = channelSecretsKey({ DATABASTION_ENCRYPTION_KEY: "another-server-key-0123456789abcdefghijklmnop" });
    expect(decryptChannelSecret(other as Buffer, id, "webhook", blob)).toBeNull();
    const tampered = Buffer.from(blob);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
    expect(decryptChannelSecret(key, id, "webhook", tampered)).toBeNull();
    expect(channelSecretsKey({})).toBeNull();
  });

  it("webhook signing secrets: 256-bit, prefixed, unique", () => {
    const a = newWebhookSecret();
    expect(a).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(newWebhookSecret()).not.toBe(a);
  });
});
