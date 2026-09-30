import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { DeliveriesTable, deliveryState, type DeliveryRow } from "./deliveries-table";
import { channelRequestBody, ChannelsTable, channelSummary, type ChannelItem } from "./notification-channels";
import { notifyWarning } from "./policy-form";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined, push: () => undefined }) }));

const NOW = Date.parse("2026-09-28T12:00:00Z");
const HOSTILE = '<img src=x onerror="alert(1)">';

const delivery = (over: Partial<DeliveryRow> = {}): DeliveryRow => ({
  id: "d1",
  event: "incident.opened",
  channelSlug: "soc-hook",
  status: "pending",
  attempts: 2,
  lastAttemptAt: new Date(NOW - 60_000),
  nextAttemptAt: new Date(NOW + 120_000),
  deliveredAt: null,
  lastError: "http_503",
  createdAt: new Date(NOW - 180_000),
  ...over,
});

describe("notification UI", () => {
  it("deliveries: status, retry time and the explained error code", () => {
    expect(deliveryState(delivery(), NOW)).toBe("retry in 2 min");
    expect(deliveryState(delivery({ attempts: 0 }), NOW)).toBe("queued");
    expect(deliveryState(delivery({ status: "delivered", deliveredAt: new Date(NOW - 5000) }), NOW)).toBe("delivered 5 s ago");
    const html = renderToStaticMarkup(
      <DeliveriesTable deliveries={[delivery(), delivery({ id: "d2", status: "skipped", lastError: "unknown_channel", channelSlug: HOSTILE })]} now={NOW} />,
    );
    expect(html).toContain("http_503: HTTP 503");
    expect(html).toContain("unknown_channel: no channel has this name");
    expect(html).not.toContain("<img");
    expect(renderToStaticMarkup(<DeliveriesTable deliveries={[]} now={NOW} />)).toContain("No notification.");
  });

  it("channel form bodies: create and edit (secrets only when typed)", () => {
    expect(
      channelRequestBody({
        slug: "soc-mail",
        type: "email",
        host: "smtp.example.com",
        port: "465",
        tls: "implicit",
        from: "dlp@example.com",
        recipients: "a@example.com, b@example.com a@example.com",
        username: "",
        password: "",
        enabled: true,
        system_alerts: "on",
      }),
    ).toEqual({
      slug: "soc-mail",
      type: "email",
      enabled: true,
      system_alerts: true,
      config: { host: "smtp.example.com", port: 465, tls: "implicit", from: "dlp@example.com", recipients: ["a@example.com", "b@example.com"] },
    });
    expect(channelRequestBody({ type: "webhook", url: "", enabled: false }, true)).toEqual({ enabled: false, system_alerts: false });
    expect(channelRequestBody({ type: "webhook", slug: "h", url: "https://h.example.com/x", enabled: true })).toMatchObject({
      config: { url: "https://h.example.com/x" },
    });
  });

  it("channels table: no secret, webhook origin only, escaped", () => {
    const channels: ChannelItem[] = [
      { id: "c1", slug: "soc-hook", type: "webhook", enabled: true, systemAlerts: true, config: { origin: "https://hooks.example.com" }, secretSet: true },
      {
        id: "c2",
        slug: "soc-mail",
        type: "email",
        enabled: false,
        systemAlerts: false,
        config: { host: HOSTILE, port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: "dlp" },
        secretSet: true,
      },
    ];
    expect(channelSummary(channels[0] as ChannelItem)).toBe("https://hooks.example.com/…");
    const html = renderToStaticMarkup(<ChannelsTable channels={channels} csrfToken="t" />);
    expect(html).toContain("console alerts");
    expect(html).toContain("disabled");
    expect(html).not.toContain("<img");
  });

  it("policy form warns on unknown or disabled channel names", () => {
    const channels = [
      { slug: "soc-hook", enabled: true },
      { slug: "old-mail", enabled: false },
    ];
    expect(notifyWarning("soc-hook", channels)).toBeNull();
    expect(notifyWarning("soc-hook, old-mail, nope", channels)).toBe("old-mail: channel disabled; nope: no such channel. These notifications will be skipped.");
    expect(notifyWarning("anything", undefined)).toBeNull();
  });
});
