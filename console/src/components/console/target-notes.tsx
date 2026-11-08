import { renderTargetNote, type StoredTargetNote } from "@/lib/target-notes";

export const UNKNOWN_NOTE_TITLE =
  "Code not in this console's catalog (registered after this console was built): shown raw with its count and labels.";

/**
 * The notes of a target's latest heartbeat (contract `TargetStatus.notes`), rendered from the
 * phrase catalog generated from `shared/protocol/target-notes.json` (see src/lib/target-notes.ts).
 * Server component: every phrase is plain text rendered as a React text node (escaped), never
 * `dangerouslySetInnerHTML`. `engine` is the target's engine, for the labels whose display name
 * depends on it (`stage_tls` on Firebird).
 */
export function TargetNotes({ notes, engine = null }: { notes: readonly StoredTargetNote[]; engine?: string | null }) {
  if (notes.length === 0) return null;
  return (
    <ul className="flex flex-col gap-0.5 text-xs">
      {notes.map((n, i) => {
        const r = renderTargetNote(n, engine);
        return r.known ? (
          <li key={i} title={r.code}>
            {r.text}
          </li>
        ) : (
          <li key={i} title={UNKNOWN_NOTE_TITLE} className="font-mono text-muted-foreground">
            {r.text}
          </li>
        );
      })}
    </ul>
  );
}
