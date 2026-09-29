import { SYSTEM_ALERT_EVENTS, type SystemAlertEvent } from "@/lib/notification-model";
import { unregisteredSignals } from "@/lib/protocol/signals";

/**
 * Notification contents (P3-C): the payload stored in the outbox, the webhook JSON body and the
 * plain-text e-mail. Payloads hold identifiers, counts, normalized names and console URLs only:
 * never a sampled value, masked or not (I2), never a secret.
 */

export interface IncidentOpenedPayload {
  event: "incident.opened";
  /** Absent in rows written before P4-C. */
  source?: "finding";
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

/**
 * A new incident raised from Audit access events (P4-C). Same `event` as a finding incident (same
 * hourly budget, same receivers); `source` tells them apart. No value: the principal, normalized
 * object names, counts, score and signals only (ADR-0007).
 */
export interface AccessIncidentOpenedPayload {
  event: "incident.opened";
  source: "access_event";
  occurred_at: string;
  url: string | null;
  /** `reopened_from`: the resolved incident of the same scope, when a worse event reopened it. */
  incident: { id: string; severity: string; status: "open"; reopened_from: string | null };
  policy: { id: string; name: string; revision: number };
  agent_id: string;
  target_id: string;
  /**
   * Set on the per-policy overflow incident: the policy reached its hourly limit of new
   * incidents; the further matches of the hour are counted in this one (`principal` is empty).
   */
  overflow: { limit_per_hour: number } | null;
  /** `db_user`, or the `hmac-sha256:` fingerprint the agent sent in its place. */
  principal: string;
  principal_fingerprinted: boolean;
  /** Database of the dedup scope (null for an event without object). */
  database: string | null;
  /** Start of the UTC hour of the dedup scope. */
  hour: string;
  /** The first event of the incident. */
  access: {
    ts: string;
    action: string;
    source: string;
    rows: number | null;
    score: number;
    sensitivity: number;
    anomaly: boolean;
    signals: string[];
    /**
     * The ids of `signals` missing from the console's signal registry (registered after the
     * console was built, or sent by a non-conforming agent). Absent in rows written before P4-D.
     */
    unregistered_signals?: string[];
    objects: { database: string; schema: string | null; object: string }[];
  };
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

/**
 * P7 (end-of-phase-4 review M2): the agent reported dropped spool batches (spool full, or batches
 * rejected with a non-retryable status): findings or access events were lost, possibly those of
 * an extraction. Console-computed counts and timestamps only: no agent-provided text.
 */
export interface AgentBatchesDroppedPayload {
  event: "agent.batches_dropped";
  occurred_at: string;
  url: string | null;
  agent_id: string;
  /** Batches dropped since `since` (sum of the increases of the agent's counter), not alerted before. */
  dropped_batches: number;
  /** When the console first saw one of these drops. */
  since: string;
  /** At most one alert per agent in this many seconds; later drops are counted in the next one. */
  min_interval_s: number;
  security_event_id: string;
}

export interface ChannelTestPayload {
  event: "channel.test";
  occurred_at: string;
  url: string | null;
  channel: string;
}

/** L6: incident notifications of a channel suppressed by its hourly budget (counts only). */
export interface SuppressedPayload {
  event: "notifications.suppressed";
  occurred_at: string;
  url: string | null;
  channel: string;
  window_start: string;
  window_end: string;
  suppressed: number;
  limit_per_hour: number;
}

/**
 * P7 (#75 review L4): system alerts of a channel suppressed by the global hourly budget of system
 * alerts. Counts only: per event, and the number of distinct agents concerned; never an agent id,
 * name or host name, nor any other agent-provided text.
 */
export interface SystemAlertsSuppressedPayload {
  event: "system_alerts.suppressed";
  occurred_at: string;
  url: string | null;
  channel: string;
  window_start: string;
  window_end: string;
  suppressed: number;
  /** Suppressed alerts per event (`agent.silent`, `agent.recovered`, `agent.integrity`, `agent.batches_dropped`); absent events are 0. */
  by_event: Partial<Record<SystemAlertEvent, number>>;
  /** Distinct agents of the suppressed alerts. */
  agents: number;
  limit_per_hour: number;
}

export type NotificationPayload =
  | SuppressedPayload
  | SystemAlertsSuppressedPayload
  | IncidentOpenedPayload
  | AccessIncidentOpenedPayload
  | AgentSilentPayload
  | AgentRecoveredPayload
  | AgentIntegrityPayload
  | AgentBatchesDroppedPayload
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

const SYSTEM_ALERT_LABEL: Record<SystemAlertEvent, string> = {
  "agent.silent": "Silent agents",
  "agent.recovered": "Agents reporting again",
  "agent.integrity": "Agent-integrity events",
  "agent.batches_dropped": "Dropped batches",
};

const FOOTER = "\n--\nSent by DataBastion. No data value, masked or not, is ever included in notifications.\n";

function objectText(o: AccessIncidentOpenedPayload["access"]["objects"][number]): string {
  return [o.database, o.schema, o.object].filter((x): x is string => x !== null).map((x) => one(x, 128)).join(".");
}

function renderAccessIncident(p: AccessIncidentOpenedPayload, link: string): { subject: string; text: string } {
  const a = p.access;
  const unregistered = new Set(a.unregistered_signals ?? unregisteredSignals(a.signals));
  const objects = a.objects.slice(0, 5).map(objectText).join(", ") + (a.objects.length > 5 ? `, and ${a.objects.length - 5} more` : "");
  const lines = [
    p.overflow
      ? `The policy reached its limit of ${p.overflow.limit_per_hour} new incidents this hour: the further matches of the hour are counted in this incident. The event below is the first of them.`
      : p.incident.reopened_from
        ? `A new incident was opened from database access events: a worse access than the one of the resolved incident ${p.incident.reopened_from}.`
        : "A new incident was opened from database access events.",
    "",
    `Incident:   ${p.incident.id}`,
    `Severity:   ${p.incident.severity}`,
    `Policy:     ${one(p.policy.name, 100)} (rev. ${p.policy.revision}, ${p.policy.id})`,
    `Agent:      ${p.agent_id}`,
    `Target:     ${one(p.target_id, 128)}`,
    `Principal:  ${p.overflow ? "several" : `${one(p.principal, 128)}${p.principal_fingerprinted ? " (fingerprint of an unknown or non-conforming account name)" : ""}`}`,
    `Database:   ${p.database === null ? "none" : one(p.database, 128)} (hour starting ${p.hour})`,
    `Access:     ${one(a.action, 16)} at ${a.ts} (${one(a.source, 32)})`,
    `Objects:    ${objects || "none"}`,
    `Rows:       ${a.rows === null ? "not reported by the source" : a.rows}`,
    `Score:      ${a.score} (sensitivity ${a.sensitivity})${a.anomaly ? ", above the principal's baseline" : ""}`,
    `Signals:    ${a.signals.map((s) => `${one(s, 64)}${unregistered.has(s) ? " (unregistered)" : ""}`).join(", ") || "none"}`,
    `Opened at:  ${p.occurred_at}`,
  ];
  return {
    subject: `[DataBastion] ${p.incident.severity.toUpperCase()} incident: ${one(p.policy.name, 100)} (${p.overflow ? "hourly limit reached" : one(p.principal, 64)})`,
    text: `${lines.join("\n")}\n${link}${FOOTER}`,
  };
}

/** Subject and plain-text body of the alert e-mail. */
export function renderEmail(payload: NotificationPayload): { subject: string; text: string } {
  const link = (url: string | null) => (url ? `\nOpen in the console: ${url}\n` : "");
  switch (payload.event) {
    case "incident.opened": {
      if (payload.source === "access_event") return renderAccessIncident(payload, link(payload.url));
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
    case "agent.batches_dropped": {
      const p = payload;
      const n = `${p.dropped_batches} batch${p.dropped_batches === 1 ? "" : "es"}`;
      return {
        subject: `[DataBastion] Agent dropped ${n}: ${p.agent_id}`,
        text: [
          `The agent ${p.agent_id} reported ${n} dropped since ${p.since} (security event ${p.security_event_id}).`,
          "Dropped batches are findings or access events that never reached the console: the spool was full, or the console rejected them. An extraction during that time may have gone undetected.",
          `Check the agent's spool size, its link to the console and, on Audit targets, floods of events (e.g. failed logins). At most one such alert is sent per agent every ${Math.round(p.min_interval_s / 60)} minutes; later drops are counted in the next one.`,
        ].join("\n") + `\n${link(p.url)}${FOOTER}`,
      };
    }
    case "notifications.suppressed": {
      const p = payload;
      return {
        subject: `[DataBastion] ${p.suppressed} incident notification${p.suppressed > 1 ? "s" : ""} suppressed`,
        text: `The channel ${one(p.channel, 64)} reached its limit of ${p.limit_per_hour} incident notifications per hour between ${p.window_start} and ${p.window_end}: ${p.suppressed} more incident${p.suppressed > 1 ? "s were" : " was"} opened without a notification. See the incidents in the console.\n${link(p.url)}${FOOTER}`,
      };
    }
    case "system_alerts.suppressed": {
      const p = payload;
      const s = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
      const lines = SYSTEM_ALERT_EVENTS.filter((e) => (p.by_event[e] ?? 0) > 0).map(
        (e) => `  ${`${SYSTEM_ALERT_LABEL[e]}:`.padEnd(24)}${p.by_event[e] ?? 0}`,
      );
      return {
        subject: `[DataBastion] ${s(p.suppressed, "system alert", "system alerts")} suppressed`,
        text: [
          `The channel ${one(p.channel, 64)} reached its limit of ${p.limit_per_hour} system alerts per hour between ${p.window_start} and ${p.window_end}: ${s(p.suppressed, "more alert was", "more alerts were")} not sent, concerning ${s(p.agents, "agent", "agents")}.`,
          "",
          ...lines,
          "",
          "Every one of them is recorded: see the agents and their security events in the console.",
        ].join("\n") + `\n${link(p.url)}${FOOTER}`,
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
