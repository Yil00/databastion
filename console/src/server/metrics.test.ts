import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { GET } from "@/app/metrics/route";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll } from "@/test/helpers";
import { handleHeartbeat } from "@/server/agent-api/handlers";

import { checkMetricsAuth, escapeLabel, Exposition, isReportedNameAllowed } from "./metrics";

// Test value, >= 32 characters, allowlisted form (gitleaks).
const TOKEN = "hunter2-SECRET-metrics-0123456789abcdef";

const scrape = (auth?: string) =>
  new Request("http://console.test/metrics", auth ? { headers: { Authorization: auth } } : {});

describe("metrics authentication", () => {
  it("is disabled (404) when no token is configured or the token is too short", () => {
    expect(checkMetricsAuth(scrape(`Bearer ${TOKEN}`), {})).toBe("disabled");
    expect(checkMetricsAuth(scrape("Bearer short"), { DATABASTION_METRICS_TOKEN: "short" })).toBe("disabled");
  });

  it("requires the exact bearer token", () => {
    const env = { DATABASTION_METRICS_TOKEN: TOKEN };
    expect(checkMetricsAuth(scrape(`Bearer ${TOKEN}`), env)).toBe("ok");
    expect(checkMetricsAuth(scrape(), env)).toBe("unauthorized");
    expect(checkMetricsAuth(scrape(`Bearer ${TOKEN}x`), env)).toBe("unauthorized");
    expect(checkMetricsAuth(scrape(`Basic ${TOKEN}`), env)).toBe("unauthorized");
    expect(checkMetricsAuth(scrape("Bearer "), env)).toBe("unauthorized");
  });

  it("reads the token from a file (_FILE), never from both", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "metrics-"));
    const file = path.join(dir, "token");
    writeFileSync(file, `${TOKEN}\n`);
    try {
      expect(checkMetricsAuth(scrape(`Bearer ${TOKEN}`), { DATABASTION_METRICS_TOKEN_FILE: file })).toBe("ok");
      expect(() =>
        checkMetricsAuth(scrape(), { DATABASTION_METRICS_TOKEN: TOKEN, DATABASTION_METRICS_TOKEN_FILE: file }),
      ).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("exposition format", () => {
  it("escapes label values and groups samples under one HELP / TYPE", () => {
    expect(escapeLabel('a"b\\c\nd')).toBe('a\\"b\\\\c\\nd');
    const x = new Exposition();
    x.add("m", "gauge", "help", 1, { a: "1" });
    x.add("n", "counter", "help", 2);
    x.add("m", "gauge", "help", 3.5, { a: "2" });
    x.add("m", "gauge", "help", Number.NaN, { a: "3" });
    expect(x.render()).toBe(
      '# HELP m help\n# TYPE m gauge\nm{a="1"} 1\nm{a="2"} 3.5\n# HELP n help\n# TYPE n counter\nn 2\n',
    );
  });

  it("ignores reserved and shadowing names", () => {
    for (const name of ["up", "last_seen_seconds", "revoked", "spool_bytes", "uptime_seconds"]) {
      expect(isReportedNameAllowed(name, "agent")).toBe(false);
      expect(isReportedNameAllowed(name, "target")).toBe(false);
    }
    expect(isReportedNameAllowed("target_rows", "agent")).toBe(false);
    expect(isReportedNameAllowed("target_rows", "target")).toBe(true);
    expect(isReportedNameAllowed("uplink_errors", "agent")).toBe(true);
    expect(isReportedNameAllowed("Bad-Name", "agent")).toBe(false);
  });
});

describe.skipIf(!hasDb)("GET /metrics (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => {
    delete process.env.DATABASTION_METRICS_TOKEN;
    await teardown?.();
  });

  it("answers 404 when unset, 401 without the token, and exposes the frozen names", async () => {
    delete process.env.DATABASTION_METRICS_TOKEN;
    expect((await GET(scrape(`Bearer ${TOKEN}`))).status).toBe(404);
    process.env.DATABASTION_METRICS_TOKEN = TOKEN;
    const denied = await GET(scrape("Bearer wrong"));
    expect(denied.status).toBe(401);
    expect(denied.headers.get("www-authenticate")).toContain("Bearer");

    const a = await enroll("metrics-host");
    const hb = await handleHeartbeat(
      agentRequest("POST", "/heartbeat", {
        auth: a,
        body: {
          ts: new Date().toISOString(),
          agent_version: "0.1.0",
          uptime_s: 42,
          connectors: ["postgres"],
          targets: [
            {
              target_id: "pg-prod-1",
              engine: "postgres",
              reachable: true,
              audit_level: "partial",
              metrics: { rows_scanned: 10, up: 5 },
            },
          ],
          detected_targets: [],
          spool: { bytes: 2048, max_bytes: 4096, batches: 3 },
          metrics: { uplink_errors: 2, up: 0, last_seen_seconds: 999999, target_fake: 1 },
        },
      }),
    );
    expect(hb.status).toBe(200);

    const res = await GET(scrape(`Bearer ${TOKEN}`));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/plain; version=0.0.4");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const text = await res.text();
    const id = a.agentId;
    expect(text).toMatch(new RegExp(`^databastion_agent_last_seen_seconds\\{agent_id="${id}"\\} [0-9.]+$`, "m"));
    expect(text).toContain(`databastion_agent_up{agent_id="${id}"} 1`);
    expect(text).toContain(`databastion_agent_reported_spool_bytes{agent_id="${id}"} 2048`);
    expect(text).toContain(`databastion_agent_reported_spool_max_bytes{agent_id="${id}"} 4096`);
    expect(text).toContain(`databastion_agent_reported_uptime_seconds{agent_id="${id}"} 42`);
    expect(text).toContain(`databastion_agent_reported_uplink_errors{agent_id="${id}"} 2`);
    expect(text).toContain(`databastion_agent_reported_target_rows_scanned{agent_id="${id}",target_id="pg-prod-1"} 10`);
    expect(text).toContain(`databastion_agent_target_audit_level{agent_id="${id}",target_id="pg-prod-1"} 2`);
    expect(text).toContain(`databastion_agent_target_reachable{agent_id="${id}",target_id="pg-prod-1"} 1`);
    // Reserved names never shadow console-computed series.
    expect(text).not.toContain("999999");
    expect(text).not.toMatch(/databastion_agent_reported_up[{ ]/);
    expect(text).not.toContain("databastion_agent_reported_last_seen_seconds");
    expect(text).not.toContain("databastion_agent_reported_target_fake");
    expect(text).toContain('databastion_agents{status="online"} 1');
    // Well-formed: every sample line is `name{labels} value`, one TYPE per family.
    const types = text.split("\n").filter((l) => l.startsWith("# TYPE "));
    expect(new Set(types).size).toBe(types.length);
    for (const line of text.split("\n")) {
      if (line === "" || line.startsWith("#")) continue;
      expect(line).toMatch(/^[a-z_][a-z0-9_]*(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? -?[0-9.e+-]+$/);
    }
  });
});
