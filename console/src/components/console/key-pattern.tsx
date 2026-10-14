/**
 * A Redis / Valkey key pattern (contract `KeyPattern`, ADR-0052 decision 7) in the views: a React
 * text node inside `<code>`, so it is escaped, never HTML, never a link nor an `href` (the
 * contract's rendering rule, `src/lib/key-pattern.ts`). `translate="no"` keeps in-browser
 * translation from rewriting it.
 */
export function KeyPatternText({ value }: { value: string }) {
  return (
    <code className="font-mono text-xs break-all" translate="no" data-key-pattern="">
      {value}
    </code>
  );
}
