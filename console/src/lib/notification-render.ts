/**
 * Notification contents (P3-C): the payload stored in the outbox, the webhook JSON body and the
 * plain-text e-mail. Payloads hold identifiers, counts, normalized names and console URLs only:
 * never a sampled value, masked or not (I2), never a secret.
 */

export interface IncidentOpenedPayload {
  event: "incident.opened";
  occurred_at: string;
  url: string | null;
  incident: { id: string; severity: string; status: "open"; reopened_from: string | null };
  policy: { id: string; name: string; revision: number };
  agent_id: string;
  target_id: string;
  classifier: string;
  classifiers_version: string;
  location: { engine: string; database: string; schema: string | null; object: string; field: string };
  counts: { sampled: number; matched: number; confidence: number };
}

export interface AgentSilentPayload {
  event: "agent.silent";
  occurred_at: string;
  url: string | null;
  agent: { id: string; name: string; hostname: string };
  last_seen_at: string;
  threshold_s: number;
  security_event_id: string;
}

export interface AgentRecoveredPayload {
  event: "agent.recovered";
  occurred_at: string;
  url: string | null;
  agent: { id: string; name: string; hostname: string };
  silent_since: string;
  last_seen_at: string;
}

export interface AgentIntegrityPayload {
  event: "agent.integrity";
  occurred_at: string;
  url: string | null;
  kind: string;
  severity: string;
  agent_id: string;
  security_event_id: string;
  details: Record<string, string | number | boolean | null>;
}

export interface ChannelTestPayload {
  event: "channel.test";
  occurred_at: string;
  url: string | null;
  channel: string;
}

export type NotificationPayload =
  | IncidentOpenedPayload
  | AgentSilentPayload
  | AgentRecoveredPayload
  | AgentIntegrityPayload
  | ChannelTestPayload;

/** Webhook body: the payload plus the format version and the delivery id. */
export function webhookBody(deliveryId: string, payload: NotificationPayload): string {
  return JSON.stringify({ version: 1, delivery_id: deliveryId, ...payload });
}

/** Keeps text on one line and bounded (names are admin- or agent-provided). */
function one(v: string, max = 200): string {
  const clean = v.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function locationText(l: IncidentOpenedPayload["location"]): string {
  return [l.database, l.schema, l.object, l.field].filter((x): x is string => x !== null).map((x) => one(x, 128)).join(".");
}

const FOOTER = "\n--\nSent by DataBastion. No data value, masked or not, is ever included in notifications.\n";

/** Subject and plain-text body of the alert e-mail. */
export function renderEmail(payload: NotificationPayload): { subject: string; text: string } {
  const link = (url: string | null) => (url ? `\nOpen in the console: ${url}\n` : "");
  switch (payload.event) {
    case "incident.opened": {
      const p = payload;
      const subject = `[DataBastion] ${p.incident.severity.toUpperCase()} incident: ${one(p.policy.name, 100)}`;
      const lines = [
        p.incident.reopened_from
          ? `A new incident was opened after the resolution of incident ${p.incident.reopened_from}: the data is still present.`
          : "A new incident was opened.",
        "",
        `Incident:   ${p.incident.id}`,
        `Severity:   ${p.incident.severity}`,
        `Policy:     ${one(p.policy.name, 100)} (rev. ${p.policy.revision}, ${p.policy.id})`,
        `Agent:      ${p.agent_id}`,
        `Target:     ${one(p.target_id, 128)} (${one(p.location.engine, 32)})`,
        `Location:   ${locationText(p.location)}`,
        `Classifier: ${one(p.classifier, 64)} (classifier set ${one(p.classifiers_version, 32)})`,
        `Matched:    ${p.counts.matched} of ${p.counts.sampled} sampled values (confidence ${p.counts.confidence})`,
        `Opened at:  ${p.occurred_at}`,
      ];
      return { subject, text: `${lines.join("\n")}\n${link(p.url)}${FOOTER}` };
    }
    case "agent.silent": {
      const p = payload;
      const name = one(p.agent.name, 100);
      return {
        subject: `[DataBastion] Agent silent: ${name}`,
        text:
          [
            `The agent ${name} (host ${one(p.agent.hostname, 100)}, id ${p.agent.id}) has sent no heartbeat since ${p.last_seen_at} (threshold ${p.threshold_s} s).`,
            "No other alert is sent for this silence; a recovery notice follows when it reports again.",
            "Check the agent service, its host and its network path to the console.",
          ].join("\n") + `\n${link(p.url)}${FOOTER}`,
      };
    }
    case "agent.recovered": {
      const p = payload;
      const name = one(p.agent.name, 100);
      return {
        subject: `[DataBastion] Agent reporting again: ${name}`,
        text: `The agent ${name} (id ${p.agent.id}), silent since ${p.silent_since}, sent a heartbeat at ${p.last_seen_at}.\n${link(p.url)}${FOOTER}`,
      };
    }
    case "agent.integrity": {
      const p = payload;
      const details = Object.entries(p.details)
        .map(([k, v]) => `${one(k, 64)}: ${one(String(v), 128)}`)
        .join("\n");
      return {
        subject: `[DataBastion] ${p.severity.toUpperCase()} agent-integrity event: ${one(p.kind, 64)}`,
        text: `The console recorded ${one(p.kind, 64)} for the agent ${p.agent_id} at ${p.occurred_at} (security event ${p.security_event_id}). A conforming agent never causes it.\n\n${details}\n${link(p.url)}${FOOTER}`,
      };
    }
    case "channel.test": {
      const p = payload;
      return {
        subject: "[DataBastion] Test notification",
        text: `This is a test of the notification channel ${one(p.channel, 64)}, sent at ${p.occurred_at}.\n${link(p.url)}${FOOTER}`,
      };
    }
  }
}
