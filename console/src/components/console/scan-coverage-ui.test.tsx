import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { coverageWarning, parseCoverage } from "@/lib/scan-coverage";

import { ScanCoverageView } from "./scan-coverage";

const render = (status: string, progress: unknown) =>
  renderToStaticMarkup(<ScanCoverageView status={status} coverage={parseCoverage(progress)} />);

describe("parseCoverage", () => {
  it("keeps the non-zero skip counters with their labels, known reasons first", () => {
    const c = parseCoverage({
      ratio: 1,
      findings: 4,
      objects_sampled: 180,
      skipped_remote: 1,
      skipped_limit: 12,
      skipped_error: 0,
      skipped_not_readable: 3,
    });
    expect(c.sampled).toBe(180);
    expect(c.reported).toBe(true);
    expect(c.skipped.map((s) => [s.key, s.count])).toEqual([
      ["skipped_limit", 12],
      ["skipped_not_readable", 3],
      ["skipped_remote", 1],
    ]);
    expect(c.notSampled).toBe(16);
  });

  it("counts objects never reached from objects_total and objects_done", () => {
    const c = parseCoverage({ objects_total: 50, objects_done: 40, objects_sampled: 40 });
    expect(c.unreached).toBe(10);
    expect(c.notSampled).toBe(10);
    expect(parseCoverage({ objects_total: 50, objects_done: 50 }).unreached).toBe(0);
    expect(parseCoverage({ objects_total: 50 }).unreached).toBe(0);
  });

  it("drops malformed values and non-object progress (defense in depth)", () => {
    for (const p of [null, undefined, 3, "x", [1, 2]]) expect(parseCoverage(p).reported).toBe(false);
    const c = parseCoverage({ skipped_limit: -1, skipped_error: 1.5, skipped_remote: "3", objects_sampled: Number.MAX_VALUE });
    expect(c).toEqual({ sampled: null, total: null, skipped: [], unreached: 0, notSampled: 0, reported: false });
    // Progress without any coverage counter (an agent that does not report it).
    expect(parseCoverage({ ratio: 1, findings: 3, batches: 1 }).reported).toBe(false);
  });

  it("shows an unknown skip reason raw, and ignores other unknown keys", () => {
    const c = parseCoverage(JSON.parse('{"skipped_quarantined": 2, "__proto__": 5, "skipped_<b>": 1, "other": 9}'));
    expect(c.skipped).toEqual([{ key: "skipped_quarantined", label: "skipped_quarantined", hint: null, count: 2, known: false }]);
  });
});

describe("coverageWarning", () => {
  it("only for a succeeded scan that did not sample everything", () => {
    const partial = parseCoverage({ objects_sampled: 10, skipped_limit: 5 });
    expect(coverageWarning("succeeded", partial)?.text).toMatch(/^Partial: 5 objects not sampled \(time budget or connector limit\); raise the scan budget/);
    expect(coverageWarning("failed", partial)).toBeNull();
    expect(coverageWarning("running", partial)).toBeNull();
    expect(coverageWarning("succeeded", parseCoverage({ objects_sampled: 10, skipped_limit: 0 }))).toBeNull();
    expect(coverageWarning("succeeded", parseCoverage(null))).toBeNull();
  });

  it("mentions the other reasons and the objects never reached", () => {
    const w = coverageWarning("succeeded", parseCoverage({ skipped_limit: 1, skipped_error: 2, objects_total: 10, objects_done: 7 }));
    expect(w?.text).toContain("Partial: 1 object not sampled");
    expect(w?.text).toContain("2 other objects not sampled for the reasons listed.");
    expect(w?.text).toContain("3 objects never reached (scan stopped early).");
    expect(coverageWarning("succeeded", parseCoverage({ skipped_not_readable: 1 }))?.text).toBe("Partial: 1 object not sampled.");
  });
});

describe("ScanCoverageView", () => {
  it("renders the partial warning on a succeeded scan with skipped_limit", () => {
    const html = render("succeeded", { objects_sampled: 180, skipped_limit: 12, skipped_unsupported: 2 });
    expect(html).toContain('role="alert"');
    expect(html).toContain("partial coverage");
    expect(html).toContain("Partial: 12 objects not sampled (time budget or connector limit); raise the scan budget");
    expect(html).toContain("limits.discovery_duty_cycle_percent");
    expect(html).toContain("180 objects sampled");
    expect(html).toContain("12 not sampled: time budget or connector limit");
    expect(html).toContain("2 not sampled: kind not sampled (views, merge tables, other storage engines)");
    expect(html).toContain('aria-label="Scan coverage"');
  });

  it("renders no warning when every counter is zero", () => {
    const zero = {
      objects_sampled: 42,
      skipped_not_readable: 0,
      skipped_row_level_security: 0,
      skipped_remote: 0,
      skipped_unsupported: 0,
      skipped_limit: 0,
      skipped_error: 0,
    };
    const html = render("succeeded", zero);
    expect(html).not.toContain("alert");
    expect(html).not.toContain("partial");
    expect(html).not.toContain("not sampled");
    expect(html).toBe('<p class="text-xs text-muted-foreground">42 objects sampled</p>');
    expect(render("succeeded", { ratio: 1, findings: 0 })).toBe("");
    expect(render("succeeded", null)).toBe("");
  });

  it("lists the counters of a failed scan without the partial badge", () => {
    const html = render("failed", { objects_sampled: 3, skipped_error: 4 });
    expect(html).not.toContain("alert");
    expect(html).toContain("4 not sampled: sampling failed; the agent log names the failure");
  });

  it("renders an unknown reason as escaped raw text", () => {
    const html = render("succeeded", { skipped_zz_new: 1 });
    expect(html).toContain("1 not sampled: skipped_zz_new (reason unknown to this console)");
    expect(html).toContain("partial coverage");
  });
});
