import { auditSourceEngines, isKeyPatternEngine } from "@/lib/location-labels";

/**
 * Rendering rule of Redis / Valkey key patterns (contract `KeyPattern`, ADR-0052 decision 7;
 * client-safe, no Node imports). A key pattern such as `x:javascript:alert` or
 * `www.evil.example/login` passed the agent's normalizer and the contract schema (which only
 * refuses a URL scheme in the first segment), so the console must never let it act as a link:
 * - in the views: escaped text only (a React text node in `<code>`, `KeyPatternText`), never a
 *   link, an `href` or a URL parameter, and never given to a linkifier;
 * - in plain-text e-mails (the only e-mail format of the console; there is no HTML e-mail): wrapped
 *   in inline code ({@link inlineCode}), so that the receiving client does not auto-link it;
 * - in webhook payloads: a JSON string only (the console sends JSON webhooks only, no chat format);
 * - CSV exports: the console has none.
 */

/**
 * Wraps a value in inline code: a backtick fence one longer than the longest run of backticks in
 * the value (a `KeyPattern` holds none; `Identifier`s may), with a space inside the fence when the
 * value starts or ends with a backtick, as CommonMark code spans do.
 */
export function inlineCode(value: string): string {
  const longest = Math.max(0, ...[...value.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = "`".repeat(longest + 1);
  const pad = value.startsWith("`") || value.endsWith("`") ? " " : "";
  return `${fence}${pad}${value}${pad}${fence}`;
}

/** Whether the objects of events of this audit source are key patterns (the `redis_*` sources). */
export function isKeyPatternSource(source: string): boolean {
  const engines = auditSourceEngines(source);
  return engines.length > 0 && engines.every((e) => isKeyPatternEngine(e));
}
