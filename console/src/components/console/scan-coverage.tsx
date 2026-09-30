import { Badge } from "@/components/ui/badge";
import { coverageWarning, type ScanCoverage } from "@/lib/scan-coverage";

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * Coverage of a target's latest Discovery scan (see src/lib/scan-coverage.ts): a "partial
 * coverage" warning on a succeeded scan that did not sample every object, then the non-zero
 * counters with their reason. Counts and fixed labels only; every string is a React text node.
 * Renders nothing when the scan reported no coverage and nothing was skipped.
 */
export function ScanCoverageView({ status, coverage }: { status: string; coverage: ScanCoverage }) {
  const warning = coverageWarning(status, coverage);
  const lines: { key: string; text: string; raw?: boolean }[] = [];
  if (coverage.sampled !== null) {
    lines.push({
      key: "objects_sampled",
      text:
        coverage.total !== null ? `${coverage.sampled} of ${plural(coverage.total, "object")} sampled` : `${plural(coverage.sampled, "object")} sampled`,
    });
  }
  for (const c of coverage.skipped) {
    // The remedy of `skipped_limit` is already in the warning of a succeeded scan.
    const hint = c.hint && !(warning && c.key === "skipped_limit") ? `; ${c.hint}` : "";
    lines.push({
      key: c.key,
      text: c.known ? `${c.count} not sampled: ${c.label}${hint}` : `${c.count} not sampled: ${c.key} (reason unknown to this console)`,
      raw: !c.known,
    });
  }
  if (coverage.unreached > 0) lines.push({ key: "unreached", text: `${coverage.unreached} never reached (scan stopped early)` });
  if (!warning && coverage.skipped.length === 0 && coverage.unreached === 0) {
    return coverage.sampled !== null ? <p className="text-xs text-muted-foreground">{lines[0]?.text}</p> : null;
  }
  return (
    <div className="flex flex-col gap-1 text-xs">
      {warning && (
        <div role="alert" className="flex flex-col gap-1 text-destructive">
          <Badge variant="destructive" className="w-fit">
            {warning.badge}
          </Badge>
          <p>{warning.text}</p>
        </div>
      )}
      <ul aria-label="Scan coverage" className="flex flex-col gap-0.5">
        {lines.map((l) => (
          <li key={l.key} className={l.raw ? "font-mono text-muted-foreground" : undefined}>
            {l.text}
          </li>
        ))}
      </ul>
    </div>
  );
}
