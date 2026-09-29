import { describe, expect, it } from "vitest";

import { renderEmail, webhookBody, type AccessIncidentOpenedPayload, type IncidentOpenedPayload } from "./notification-render";

const INCIDENT: IncidentOpenedPayload = {
  event: "incident.opened",
  occurred_at: "2026-09-28T12:00:00.000Z",
  url: "https://console.example.com/incidents/01890a5d-ac96-774b-bcce-b302099a8057",
  incident: { id: "01890a5d-ac96-774b-bcce-b302099a8057", severity: "critical", status: "open", reopened_from: null },
  policy: { id: "01890a5d-ac96-774b-bcce-b302099a8059", name: "Cards\nin prod‮", revision: 3 },
  agent_id: "01890a5d-ac96-774b-bcce-b302099a8058",
  target_id: "pg-prod-1",
  classifier: "pii.credit_card",
  classifiers_version: "2026.09.1",
  location: { engine: "postgres", database: "shop", schema: null, object: "orders", field: "pan" },
  counts: { sampled: 200, matched: 12, confidence: 0.99 },
};

const ACCESS: AccessIncidentOpenedPayload = {
  event: "incident.opened",
  source: "access_event",
  occurred_at: "2026-09-28T12:00:00.000Z",
  url: null,
  incident: { id: "01890a5d-ac96-774b-bcce-b302099a8057", severity: "high", status: "open", reopened_from: null },
  policy: { id: "01890a5d-ac96-774b-bcce-b302099a8059", name: "Dumps", revision: 1 },
  agent_id: "01890a5d-ac96-774b-bcce-b302099a8058",
  target_id: "pg-prod-1",
  overflow: null,
  principal: "=cmd|'/C calc'!A0\r\nBcc: x@example.com‮",
  principal_fingerprinted: false,
  database: "crm",
  hour: "2026-09-28T11:00:00.000Z",
  access: {
    ts: "2026-09-28T11:02:00.000Z",
    action: "read",
    source: "pgaudit",
    rows: 10,
    score: 1,
    sensitivity: 1,
    anomaly: false,
    signals: ["signature.pg_dump", "signature.unregistered_example", "shape.full_table_copy"],
    unregistered_signals: ["signature.unregistered_example"],
    objects: [{ database: "crm", schema: "public", object: "clients" }],
  },
};

describe("notification contents", () => {
  it("webhook body: version, delivery id and the payload, nothing else", () => {
    const body = JSON.parse(webhookBody("d-1", INCIDENT)) as Record<string, unknown>;
    expect(body).toEqual({ version: 1, delivery_id: "d-1", ...INCIDENT });
  });

  it("e-mail: one-line subject, readable body, link, no control characters from names", () => {
    const { subject, text } = renderEmail(INCIDENT);
    expect(subject).toBe("[DataBastion] CRITICAL incident: Cards in prod");
    expect(text).toContain("Location:   shop.orders.pan");
    expect(text).toContain("Matched:    12 of 200 sampled values");
    expect(text).toContain(`Open in the console: ${INCIDENT.url}`);
    expect(text).not.toContain("‮");
    expect(renderEmail({ ...INCIDENT, incident: { ...INCIDENT.incident, reopened_from: "prev-id" } }).text).toMatch(/after the resolution of incident prev-id/);
    expect(renderEmail({ ...INCIDENT, url: null }).text).not.toContain("Open in the console");
  });

  it("access incident: flags unregistered signal ids", () => {
    const { text } = renderEmail(ACCESS);
    expect(text).toContain("Signals:    signature.pg_dump, signature.unregistered_example (unregistered), shape.full_table_copy\n");
    // Rows written before P4-D carry no list: computed from this console's registry.
    const { unregistered_signals: _drop, ...legacy } = ACCESS.access;
    expect(renderEmail({ ...ACCESS, access: legacy }).text).toContain("signature.unregistered_example (unregistered), shape.full_table_copy\n");
    const body = JSON.parse(webhookBody("d-2", ACCESS)) as { access: { unregistered_signals: string[] } };
    expect(body.access.unregistered_signals).toEqual(["signature.unregistered_example"]);
  });

  it("access incident: db_user stays on one line in the subject and body (P1-A)", () => {
    const { subject, text } = renderEmail(ACCESS);
    expect(subject).not.toMatch(/[\r\n\u202e]/);
    expect(subject).toContain("=cmd|'/C calc'!A0 Bcc: x@example.com");
    const principalLine = text.split("\n").find((l) => l.startsWith("Principal:"));
    expect(principalLine).toBe("Principal:  =cmd|'/C calc'!A0 Bcc: x@example.com");
    expect(text).not.toMatch(/^Bcc:/m);
    expect(text).not.toContain("\u202e");
    // The webhook body is JSON: the name is a JSON string, escaped by the serializer.
    expect((JSON.parse(webhookBody("d-3", ACCESS)) as { principal: string }).principal).toBe(ACCESS.principal);
  });

  it("suppression digest: counts only", () => {
    const { subject, text } = renderEmail({
      event: "notifications.suppressed",
      occurred_at: "t",
      url: null,
      channel: "soc-hook",
      window_start: "2026-09-28T11:00:00.000Z",
      window_end: "2026-09-28T12:00:00.000Z",
      suppressed: 12,
      limit_per_hour: 30,
    });
    expect(subject).toBe("[DataBastion] 12 incident notifications suppressed");
    expect(text).toContain("limit of 30 incident notifications per hour");
  });

  it("system alerts", () => {
    const agent = { id: "a-1", name: "db-host-1", hostname: "db-host-1.example" };
    expect(
      renderEmail({ event: "agent.silent", occurred_at: "t", url: null, agent, last_seen_at: "2026-09-28T12:00:00Z", threshold_s: 300, security_event_id: "s" }).subject,
    ).toBe("[DataBastion] Agent silent: db-host-1");
    expect(renderEmail({ event: "agent.recovered", occurred_at: "t", url: null, agent, silent_since: "a", last_seen_at: "b" }).subject).toMatch(/reporting again/);
    const integrity = renderEmail({
      event: "agent.integrity",
      occurred_at: "t",
      url: null,
      kind: "agent.rotation_conflict",
      severity: "critical",
      agent_id: "a-1",
      security_event_id: "s",
      details: { reason: "old_secret", locked: true },
    });
    expect(integrity.subject).toBe("[DataBastion] CRITICAL agent-integrity event: agent.rotation_conflict");
    expect(integrity.text).toContain("locked: true");
  });
});
