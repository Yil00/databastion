import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { TargetNameCase } from "./target-name-case";

const NOW = Date.parse("2026-10-21T12:00:00Z");

describe("TargetNameCase (ADR-0055 decision 7)", () => {
  it("names how the target's names are compared", () => {
    const html = (rule: Parameters<typeof TargetNameCase>[0]["rule"], engine = "sqlserver") => renderToStaticMarkup(<TargetNameCase engine={engine} rule={rule} now={NOW} />);
    expect(html(null)).toContain("not reported (without case)");
    expect(html({ databases: "sensitive", objects: "sensitive" })).toContain(">with case<");
    expect(html({ databases: "insensitive", objects: "insensitive" })).toContain(">without case<");
    expect(html({ databases: "unknown", objects: "unknown" })).toContain("unknown, treated as with case");
    expect(html({ databases: "insensitive", objects: "insensitive", except: [{ database: "crm_cs", objects: "sensitive" }] })).toContain("per database");
    // Only on the engines that report it.
    expect(html({ databases: "sensitive", objects: "sensitive" }, "postgres")).toBe("");
  });

  it("renders database names as escaped text, and the latest inventory", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const html = renderToStaticMarkup(
      <TargetNameCase
        engine="sqlserver"
        rule={{ databases: "insensitive", objects: "insensitive", except: [{ database: hostile, objects: "unknown" }] }}
        inventory={{
          ok: true,
          inventory: {
            at: new Date(NOW - 120_000),
            trigger: "name_case",
            entries: [],
            exceptionsListed: 3,
            truncated: false,
            findingNamesCompared: 1,
            eventNamesCompared: 1,
            exceptionsCompared: 1,
            exceptionsTotal: 1,
            boundReached: false,
          },
        }}
        now={NOW}
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    expect(html).toContain("3 exceptions no longer covering names differing by case");
    const failed = renderToStaticMarkup(<TargetNameCase engine="mysql" rule={null} inventory={{ ok: false, at: new Date(NOW - 60_000) }} now={NOW} />);
    expect(failed).toContain("inventory failed");
  });
});
