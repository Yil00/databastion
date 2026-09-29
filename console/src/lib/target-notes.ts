import { TARGET_NOTE_REGISTRY } from "@/generated/protocol/target-notes.gen";
import { validateSchema } from "@/lib/protocol/validate";

/**
 * Target notes (contract `TargetStatus.notes`, `TargetNote`): closed codes with a bounded count and
 * closed labels, never free text. The console stores the notes of the latest heartbeat per target
 * and renders each one from the phrase catalog generated from `shared/protocol/target-notes.json`
 * (`TARGET_NOTE_REGISTRY`, descriptions with `{count}` and `{labels}` placeholders). The console
 * never derives a decision from notes.
 *
 * Rendering rules (docs/09-agent-protocol.md, "Heartbeat"):
 * - the template is looked up with `Object.hasOwn`, so `__proto__`, `constructor` or `toString`
 *   never resolve to a template;
 * - `{count}` becomes the integer (`?` when absent) and `{labels}` the display names of the labels
 *   (`?` when absent), in a **single, non-recursive pass**: a placeholder-like string inside a
 *   substituted value is never expanded again, and `$` patterns have no meaning;
 * - a code missing from the catalog (registered after this console was built) is shown raw, with
 *   its count and labels, never rejected;
 * - the result is plain text, rendered as a React text node (escaped); never HTML.
 */

/** A note as stored (`agent_targets.notes`): the contract fields only. */
export interface StoredTargetNote {
  code: string;
  count?: number;
  labels?: string[];
}

/** Contract bounds (`TargetStatus.notes.maxItems`, `TargetNote.labels.maxItems`, `TargetNoteCode.maxLength`). */
export const MAX_TARGET_NOTES = 16;
export const MAX_NOTE_LABELS = 16;
const MAX_CODE_LENGTH = 64;
const MAX_LABEL_LENGTH = 64;
/**
 * Bound of the serialized notes of one target (the contract bounds give at most about 11 KiB); a
 * database check enforces it too (migration 0028).
 */
export const MAX_TARGET_NOTES_BYTES = 16_384;

/**
 * Size of a note as counted against {@link MAX_TARGET_NOTES_BYTES}: its JSON indented by one space,
 * which is never shorter than PostgreSQL's `jsonb::text` form (`", "` and `": "` separators) checked
 * by the database, so a stored value never trips the check and fails the heartbeat.
 */
function noteBytes(note: StoredTargetNote): number {
  return new TextEncoder().encode(JSON.stringify(note, null, 1)).length;
}

/**
 * The notes of a (validated) heartbeat target status in their stored shape: the contract fields
 * only, in a fixed shape, at most {@link MAX_TARGET_NOTES}, and the longest prefix that fits
 * {@link MAX_TARGET_NOTES_BYTES}. `null` when the heartbeat carries none.
 */
export function notesToStore(notes: readonly { code: string; count?: number; labels?: readonly string[] }[] | undefined): StoredTargetNote[] | null {
  if (notes === undefined || notes.length === 0) return null;
  const out: StoredTargetNote[] = [];
  let bytes = 2; // []
  for (const n of notes.slice(0, MAX_TARGET_NOTES)) {
    const note: StoredTargetNote = { code: n.code };
    if (n.count !== undefined) note.count = n.count;
    if (n.labels !== undefined) note.labels = n.labels.slice(0, MAX_NOTE_LABELS);
    const size = noteBytes(note) + 2; // separator
    if (bytes + size > MAX_TARGET_NOTES_BYTES) break;
    bytes += size;
    out.push(note);
  }
  return out.length > 0 ? out : null;
}

/**
 * Stored notes read back from the database, re-checked (defense in depth: a malformed row renders
 * nothing rather than anything unexpected). Entries of the wrong shape are dropped.
 */
export function parseStoredNotes(v: unknown): StoredTargetNote[] {
  if (!Array.isArray(v)) return [];
  const out: StoredTargetNote[] = [];
  for (const n of v.slice(0, MAX_TARGET_NOTES)) {
    if (n === null || typeof n !== "object" || Array.isArray(n)) continue;
    const { code, count, labels } = n as Record<string, unknown>;
    if (typeof code !== "string" || code.length === 0 || code.length > MAX_CODE_LENGTH) continue;
    const note: StoredTargetNote = { code };
    if (typeof count === "number" && Number.isSafeInteger(count) && count >= 0) note.count = count;
    if (Array.isArray(labels)) {
      note.labels = labels
        .slice(0, MAX_NOTE_LABELS)
        .filter((l): l is string => typeof l === "string" && l.length > 0 && l.length <= MAX_LABEL_LENGTH);
    }
    out.push(note);
  }
  return out;
}

/** PostgreSQL role attributes, shown in upper case as in `CREATE ROLE`. */
const ROLE_ATTRIBUTES = new Set(["superuser", "bypassrls", "replication", "createrole", "createdb"]);
/** Labels shown as sent: predefined roles, audit collection states, check stages, `other`. */
const VERBATIM = /^(pg_|stage_)|^(logging_on|logging_off|file_output|non_file_output|other)$/;

/**
 * Display name of a note label. A contract `TargetNoteLabel`: PostgreSQL role attributes in upper
 * case (`BYPASSRLS`); MySQL / MariaDB privileges in upper case with spaces (`ALTER ROUTINE`,
 * `BINLOG ADMIN`); predefined roles, audit states, check stages and `other` as sent. A label that is
 * not a contract value (e.g. stored by a newer console build) is shown raw.
 */
export function labelDisplayName(label: string): string {
  if (!validateSchema("TargetNoteLabel", label).ok) return label;
  if (ROLE_ATTRIBUTES.has(label)) return label.toUpperCase();
  if (VERBATIM.test(label)) return label;
  return label.replace(/_/g, " ").toUpperCase();
}

/** The phrase template of a registered code, or `null` (own properties only). */
export function noteTemplate(code: string): string | null {
  if (!Object.hasOwn(TARGET_NOTE_REGISTRY, code)) return null;
  return TARGET_NOTE_REGISTRY[code as keyof typeof TARGET_NOTE_REGISTRY].description;
}

const PLACEHOLDER = /\{(count|labels)\}/g;

function countText(count: number | undefined): string {
  return count !== undefined && Number.isSafeInteger(count) && count >= 0 ? String(count) : "?";
}

function labelsText(labels: readonly string[] | undefined): string {
  return labels !== undefined && labels.length > 0 ? labels.map(labelDisplayName).join(", ") : "?";
}

/**
 * Fills `{count}` and `{labels}` in one pass over the template: the replacement values are never
 * scanned again (no recursion) and are inserted literally (a replacer function, so `$&` or `$1` in
 * a value mean nothing).
 */
export function fillTemplate(template: string, note: Pick<StoredTargetNote, "count" | "labels">): string {
  const values = { count: countText(note.count), labels: labelsText(note.labels) };
  return template.replace(PLACEHOLDER, (_match, name: "count" | "labels") => values[name]);
}

export interface RenderedNote {
  /** Plain text (never HTML). */
  text: string;
  /** The code is in this console's catalog. */
  known: boolean;
  code: string;
}

/** Renders one note (see the rules above). */
export function renderTargetNote(note: StoredTargetNote): RenderedNote {
  const template = noteTemplate(note.code);
  if (template !== null) return { text: fillTemplate(template, note), known: true, code: note.code };
  const parts = [note.code];
  if (note.count !== undefined) parts.push(`count ${countText(note.count)}`);
  if (note.labels !== undefined && note.labels.length > 0) parts.push(`labels ${note.labels.join(", ")}`);
  return { text: parts.join(", "), known: false, code: note.code };
}
