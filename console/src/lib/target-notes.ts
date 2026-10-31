import { TARGET_NOTE_REGISTRY } from "@/generated/protocol/target-notes.gen";
import { validateSchema } from "@/lib/protocol/validate";

/**
 * Target notes (contract `TargetStatus.notes`, `TargetNote`): closed codes with a bounded count and
 * closed labels, never free text. The console stores the notes of the latest heartbeat per target
 * and renders each one from the phrase catalog generated from `shared/protocol/target-notes.json`
 * (`TARGET_NOTE_REGISTRY`, descriptions with `{count}` and `{labels}` placeholders). The console
 * derives one decision from notes: the system alert on `audit.stream_stopped` (ADR-0031 decision
 * 3, `src/server/audit-stream-alerts.ts`); nothing else.
 *
 * Rendering rules (docs/09-agent-protocol.md, "Heartbeat"):
 * - the template is looked up with `Object.hasOwn`, so `__proto__`, `constructor` or `toString`
 *   never resolve to a template;
 * - `{count}` becomes the integer (`?` when absent) and `{labels}` the display names of the labels
 *   (`?` when absent), in a **single, non-recursive pass**: a placeholder-like string inside a
 *   substituted value is never expanded again, and `$` patterns have no meaning;
 * - a code missing from the catalog (registered after this console was built) is shown raw, with
 *   its count and labels, never rejected;
 * - a label's display name may depend on the target's engine: `stage_tls` on `firebird` is the
 *   wire-encryption stage (ADR-0060 decision 1: Firebird has no TLS), shown as such;
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

/**
 * Firebird system privileges (revision `target_status.note_labels.2026_10_d`, ADR-0060 decision 4),
 * sent lowercased as written in `CREATE ROLE … SET SYSTEM PRIVILEGES TO`: shown in upper case with
 * their underscores, as Firebird names them (`trace_any_attachment` -> `TRACE_ANY_ATTACHMENT`).
 */
export const FIREBIRD_SYSTEM_PRIVILEGES: ReadonlySet<string> = new Set([
  "user_management",
  "read_raw_pages",
  "create_user_types",
  "use_nbackup_utility",
  "change_shutdown_mode",
  "trace_any_attachment",
  "monitor_any_attachment",
  "access_shutdown_database",
  "create_database",
  "drop_database",
  "use_gbak_utility",
  "use_gstat_utility",
  "use_gfix_utility",
  "ignore_db_triggers",
  "change_header_settings",
  "select_any_object_in_database",
  "access_any_object_in_database",
  "modify_any_object_in_database",
  "change_mapping_rules",
  "use_granted_by_clause",
  "grant_revoke_on_any_object",
  "grant_revoke_any_ddl_right",
  "create_privileged_roles",
  "get_dbcrypt_info",
  "modify_ext_conn_pool",
  "replicate_into_database",
  "profile_any_attachment",
]);

/**
 * Firebird identities of the refusal list (revision `2026_10_d`, ADR-0060 decision 4), shown as
 * Firebird names them: the `SYSDBA` account, the `RDB$ADMIN` role, the database owner and the
 * security database's administrator flag `SEC$ADMIN`.
 */
const FIREBIRD_IDENTITIES: Readonly<Record<string, string>> = {
  sysdba: "SYSDBA",
  rdb_admin: "RDB$ADMIN",
  database_owner: "database owner",
  security_database_admin: "SEC$ADMIN (security database administrator)",
};

/**
 * Firebird labels shown as sent (revision `2026_10_d`): the credential-relation and probe names
 * (`verifier_relation_readable`, `role_graph`…), the reasons of `audit.trace_config_not_evaluated`
 * (named as is by the note's catalog text), `run_confirmation_stalled`, and the trace
 * configuration settings as written in `fbtrace.conf` (`log_statement_finish`, `print_perf`…).
 * `usage`, the object right on generators, exceptions and domains, is a privilege: `USAGE`.
 */
export const FIREBIRD_VERBATIM_LABELS: ReadonlySet<string> = new Set([
  // Credential relations and check() reads not evaluated
  "verifier_relation_readable",
  "credential_relation_readable",
  "server_config_readable",
  "role_graph",
  // audit.trace_config_not_evaluated reasons
  "firebird_conf_unreadable",
  "trace_config_unreadable",
  "trace_config_file_mismatch",
  "config_changed_since_start",
  "server_process_not_visible",
  "similar_to_pattern",
  "databases_conf",
  "foreign_databases_logged",
  "database_path_not_unique",
  // audit.log_records_ambiguous
  "run_confirmation_stalled",
  // fbtrace.conf settings
  "enabled",
  "log_filename",
  "log_connections",
  "log_statement_finish",
  "log_blr_requests",
  "log_procedure_finish",
  "log_function_finish",
  "log_trigger_finish",
  "log_transactions",
  "log_initfini",
  "log_sweep",
  "log_errors",
  "log_services",
  "time_threshold",
  "print_perf",
  "include_filter",
  "exclude_filter",
  "connection_id",
]);

/**
 * What `stage_tls` means on Firebird: the wire-encryption negotiation (ChaCha64 or ChaCha after
 * SRP-256), reported as the TLS stage of the check since Firebird has no TLS (ADR-0060 decision 1).
 */
export const FIREBIRD_STAGE_TLS_DISPLAY = "wire encryption (stage_tls)";

/** PostgreSQL role attributes, shown in upper case as in `CREATE ROLE`. */
const ROLE_ATTRIBUTES = new Set(["superuser", "bypassrls", "replication", "createrole", "createdb"]);
/**
 * Labels shown as sent: predefined roles, audit collection states, check stages, `other`; SQL
 * Server fixed database roles (`db_owner`…) and check probes (revisions
 * `target_status.note_labels.2026_10`, `2026_10_b` and `2026_10_c`).
 */
const VERBATIM =
  /^(pg_|stage_|db_)|^(logging_on|logging_off|file_output|non_file_output|other|password_hash_probe|logon_trigger_probe|refusal_list_probe|cas_store_guard_probe|on_failure_probe)$/;
/** SQL Server fixed server roles, shown in lower case as SQL Server names them. */
const SQL_SERVER_FIXED_SERVER_ROLES = new Set([
  "sysadmin",
  "securityadmin",
  "serveradmin",
  "setupadmin",
  "processadmin",
  "diskadmin",
  "dbcreator",
  "bulkadmin",
]);

/**
 * Display name of a note label. A contract `TargetNoteLabel`: PostgreSQL role attributes in upper
 * case (`BYPASSRLS`); MySQL / MariaDB privileges in upper case with spaces (`ALTER ROUTINE`,
 * `BINLOG ADMIN`); predefined roles, audit states, check stages and `other` as sent. SQL Server
 * (revision `target_status.note_labels.2026_10`, ADR-0051 decision 4): fixed server and database
 * roles as SQL Server names them (`sysadmin`, `db_owner`), the SQL Server 2022 roles in their
 * `##MS_…##` form (`ms_login_manager` -> `##MS_LoginManager##`), permissions in upper case with
 * spaces (`CONTROL SERVER`, `ALTER ANY EVENT SESSION`; revision `2026_10_b`: `ALTER ANY DATABASE
 * EVENT SESSION`), check probes as sent (`logon_trigger_probe`; revision `2026_10_c`:
 * `on_failure_probe`). Firebird (revision `2026_10_d`, ADR-0060): system privileges in upper case
 * with underscores (`TRACE_ANY_ATTACHMENT`), the refusal-list identities as Firebird names them
 * (`SYSDBA`, `RDB$ADMIN`), probes, trace-configuration reasons and `fbtrace.conf` settings as sent,
 * and `stage_tls` on a `firebird` target as the wire-encryption stage. A label that is not a
 * contract value (e.g. stored by a newer console build) is shown raw.
 */
export function labelDisplayName(label: string, engine: string | null = null): string {
  if (!validateSchema("TargetNoteLabel", label).ok) return label;
  if (label === "stage_tls" && engine === "firebird") return FIREBIRD_STAGE_TLS_DISPLAY;
  if (FIREBIRD_SYSTEM_PRIVILEGES.has(label)) return label.toUpperCase();
  if (Object.hasOwn(FIREBIRD_IDENTITIES, label)) return FIREBIRD_IDENTITIES[label] as string;
  if (FIREBIRD_VERBATIM_LABELS.has(label)) return label;
  if (ROLE_ATTRIBUTES.has(label)) return label.toUpperCase();
  if (VERBATIM.test(label) || SQL_SERVER_FIXED_SERVER_ROLES.has(label)) return label;
  if (label.startsWith("ms_")) {
    const words = label.slice("ms_".length).split("_");
    return `##MS_${words.map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join("")}##`;
  }
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

function labelsText(labels: readonly string[] | undefined, engine: string | null): string {
  return labels !== undefined && labels.length > 0 ? labels.map((l) => labelDisplayName(l, engine)).join(", ") : "?";
}

/**
 * Fills `{count}` and `{labels}` in one pass over the template: the replacement values are never
 * scanned again (no recursion) and are inserted literally (a replacer function, so `$&` or `$1` in
 * a value mean nothing).
 */
export function fillTemplate(template: string, note: Pick<StoredTargetNote, "count" | "labels">, engine: string | null = null): string {
  const values = { count: countText(note.count), labels: labelsText(note.labels, engine) };
  return template.replace(PLACEHOLDER, (_match, name: "count" | "labels") => values[name]);
}

export interface RenderedNote {
  /** Plain text (never HTML). */
  text: string;
  /** The code is in this console's catalog. */
  known: boolean;
  code: string;
}

/** Renders one note of a target of `engine` (see the rules above). */
export function renderTargetNote(note: StoredTargetNote, engine: string | null = null): RenderedNote {
  const template = noteTemplate(note.code);
  if (template !== null) return { text: fillTemplate(template, note, engine), known: true, code: note.code };
  const parts = [note.code];
  if (note.count !== undefined) parts.push(`count ${countText(note.count)}`);
  if (note.labels !== undefined && note.labels.length > 0) parts.push(`labels ${note.labels.join(", ")}`);
  return { text: parts.join(", "), known: false, code: note.code };
}
