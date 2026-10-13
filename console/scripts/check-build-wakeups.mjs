#!/usr/bin/env node
// Post-build check (run after `pnpm build`): the wake-up functions of the web process must not be
// compiled away.
//
// P4-D E2E: Turbopack gives the route handlers and the startup hook separate copies of
// src/server/policy-queue.ts. With the sender kept in a module variable, each copy only wrote or
// only read it, and the bundler removed it: `requestPolicyEvaluation` compiled to
// `async function t(){}` and `setPolicyJobSender` to `function(i){}`, so no `policies.evaluate`
// wake-up was ever sent. The sender now lives on `globalThis` (src/server/process-global.ts); this
// script fails when any compiled copy of those functions is empty again.
//
// Since Next.js 16.4, production builds shorten ("mangle") the export names modules expose to each
// other (`experimental.turbopackMangleExportNames`, on by default): `requestPolicyEvaluation` is
// exported as e.g. `"f",0,function(){return t.request()}`, so the functions cannot be found by
// their names. The check is anchored on the process slot names instead (`"policyJobSender"`,
// `"notificationJobSender"`), string literals that the queue modules pass to `wakeUp()` at runtime
// and that no minifier can rename. For every Turbopack module (`<id>,<param>=>{…}`) that holds
// one, it reads the module's export call (`<param>.s([<key>,0,<value>,…])`), resolves each value
// to its function (inline, or an identifier defined in the same module) and:
// - fails when an exported function has an empty body;
// - counts the setters (body calls `.setSender(`) and the requesters (body calls `.request(`).
// It fails when a slot has no setter or no requester at all (the check would be vacuous), or when
// an export call cannot be parsed. Works the same with export names mangled or not.
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", ".next", "server");
/** Process slot name (src/server/policy-queue.ts, notification-queue.ts) → source function names. */
const SLOTS = {
  policyJobSender: { setter: "setPolicyJobSender", requester: "requestPolicyEvaluation" },
  notificationJobSender: { setter: "setNotificationJobSender", requester: "requestNotificationDelivery" },
};

function jsFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) out.push(...jsFiles(full));
    else if (name.endsWith(".js")) out.push(full);
  }
  return out;
}

const IDENT = /^[A-Za-z_$][\w$]*/;
const OPEN = { "(": ")", "[": "]", "{": "}" };

/**
 * Index just past the string literal starting at `i` (`'`, `"` or a template without nested
 * templates inside `${…}`).
 */
function skipString(src, i) {
  const quote = src[i];
  for (let j = i + 1; j < src.length; j++) {
    if (src[j] === "\\") j++;
    else if (src[j] === quote) return j + 1;
  }
  return src.length;
}

/** Index just past the bracket matching the one at `open` (string-aware). -1 when unbalanced. */
function closeBracket(src, open) {
  const stack = [];
  for (let i = open; i < src.length; ) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      i = skipString(src, i);
      continue;
    }
    if (OPEN[c]) stack.push(OPEN[c]);
    else if (c === ")" || c === "]" || c === "}") {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i + 1;
    }
    i++;
  }
  return -1;
}

/** Top-level comma-separated elements of the array literal whose `[` is at `open` (trimmed). */
function arrayElements(src, open) {
  const end = closeBracket(src, open);
  if (end < 0) return null;
  const out = [];
  let start = open + 1;
  let depth = 0;
  for (let i = open + 1; i < end - 1; ) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      i = skipString(src, i);
      continue;
    }
    if (OPEN[c]) depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push(src.slice(start, i).trim());
      start = i + 1;
    }
    i++;
  }
  const last = src.slice(start, end - 1).trim();
  if (last !== "" || out.length > 0) out.push(last);
  return out;
}

/**
 * Function expression starting at `at`: `{ empty, text }`, or null when `at` is not a function.
 * Handles `function x(…){…}`, `async function(…){…}`, `(…)=>{…}`, `x=>…` (expression bodies are
 * non-empty and run to the end of `src`, which callers bound to one element).
 */
function functionAt(src, at) {
  let i = at;
  const skipWs = () => {
    while (/\s/.test(src[i] ?? "")) i++;
  };
  skipWs();
  if (src.startsWith("async", i) && !/[\w$]/.test(src[i + 5] ?? "")) {
    i += 5;
    skipWs();
  }
  let arrow = false;
  if (src.startsWith("function", i) && !/[\w$]/.test(src[i + 8] ?? "")) {
    i += 8;
    skipWs();
    if (src[i] === "*") i++;
    skipWs();
    const name = IDENT.exec(src.slice(i));
    if (name) i += name[0].length;
    skipWs();
    if (src[i] !== "(") return null;
    i = closeBracket(src, i);
  } else if (src[i] === "(") {
    i = closeBracket(src, i);
    arrow = true;
  } else {
    const name = IDENT.exec(src.slice(i));
    if (!name) return null;
    i += name[0].length;
    arrow = true;
  }
  if (i < 0) return null;
  skipWs();
  if (arrow) {
    if (!src.startsWith("=>", i)) return null;
    i += 2;
    skipWs();
    if (src[i] !== "{") return { empty: false, text: src.slice(at) }; // expression body
  }
  if (src[i] !== "{") return null;
  const end = closeBracket(src, i);
  if (end < 0) return null;
  const body = src.slice(i + 1, end - 1);
  return { empty: body.trim() === "", text: src.slice(at, end) };
}

/** Functions bound to `ident` in `moduleText` (`function ident(…)` or `ident=<function>`). */
function resolveIdentifier(moduleText, ident) {
  const esc = ident.replace(/\$/g, "\\$");
  const patterns = [
    new RegExp(`(?:async\\s+)?function\\s*\\*?\\s*${esc}\\s*\\(`, "g"),
    new RegExp(`(?:^|[^\\w$.])${esc}\\s*=\\s*(?=(?:async\\s*)?(?:function|\\(|[A-Za-z_$][\\w$]*\\s*=>))`, "g"),
  ];
  const results = [];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(moduleText))) {
      const at = m[0].includes("function") ? m.index : m.index + m[0].length;
      const fn = functionAt(moduleText, at);
      if (fn) results.push(fn);
    }
  }
  return results;
}

// A Turbopack module factory in a chunk: `<id>,<param>=>` right after `[`, `,` or the start.
const MODULE_START = /(?:^|[[,])\s*\d+\s*,\s*([A-Za-z_$][\w$]*)\s*=>/g;

/** Start index and factory parameter of the module holding `pos`, or null. */
function moduleAt(src, pos) {
  let found = null;
  MODULE_START.lastIndex = 0;
  let m;
  while ((m = MODULE_START.exec(src)) && m.index < pos) found = { start: m.index, param: m[1] };
  return found;
}

const counts = Object.fromEntries(Object.keys(SLOTS).map((s) => [s, { setter: 0, requester: 0 }]));
const failures = [];
let files;
try {
  files = jsFiles(ROOT);
} catch {
  process.stderr.write(`check-build-wakeups: no build output in ${ROOT}; run \`pnpm build\` first.\n`);
  process.exit(2);
}
for (const file of files) {
  const src = readFileSync(file, "utf8");
  for (const slot of Object.keys(SLOTS)) {
    const re = new RegExp(`["'\`]${slot}["'\`]`, "g");
    const seenModules = new Set();
    let m;
    while ((m = re.exec(src))) {
      const where = `${path.relative(ROOT, file)} @${m.index}`;
      const mod = moduleAt(src, m.index);
      if (!mod) {
        failures.push(`${slot}: no Turbopack module around the slot name (${where})`);
        continue;
      }
      if (seenModules.has(mod.start)) continue;
      seenModules.add(mod.start);
      const exportCall = new RegExp(`(?:^|[^\\w$.])${mod.param.replace(/\$/g, "\\$")}\\.s\\(\\[`, "g");
      exportCall.lastIndex = m.index;
      const call = exportCall.exec(src);
      if (!call) {
        failures.push(`${slot}: no export call in the module (${where})`);
        continue;
      }
      const open = call.index + call[0].length - 1;
      const elements = arrayElements(src, open);
      if (!elements || elements.length % 3 !== 0) {
        failures.push(`${slot}: cannot parse the module's export call (${where})`);
        continue;
      }
      // Up to the next module factory: a function declaration may be hoisted after the export call.
      MODULE_START.lastIndex = open;
      const nextModule = MODULE_START.exec(src);
      const moduleText = src.slice(mod.start, nextModule ? nextModule.index : src.length);
      for (let k = 0; k < elements.length; k += 3) {
        const key = elements[k];
        const value = elements[k + 2];
        let fns;
        const inline = functionAt(value, 0);
        if (inline) fns = [inline];
        else if (IDENT.exec(value)?.[0] === value) fns = resolveIdentifier(moduleText, value);
        else fns = [];
        // Constants (the queue name) resolve to no function and are not checked.
        for (const fn of fns) {
          if (fn.empty) failures.push(`${slot}: export ${key} compiled to an empty function (${where})`);
          if (fn.text.includes(".setSender(")) counts[slot].setter++;
          if (fn.text.includes(".request(")) counts[slot].requester++;
        }
      }
    }
  }
}
for (const [slot, names] of Object.entries(SLOTS)) {
  for (const role of ["setter", "requester"]) {
    if (counts[slot][role] === 0) {
      failures.push(
        `${names[role]}: not found in the server chunks (no ${role} for slot ${slot}; check not applicable to this build?)`,
      );
    }
  }
}
if (failures.length > 0) {
  process.stderr.write(`check-build-wakeups: FAILED\n${failures.map((f) => `  - ${f}\n`).join("")}`);
  process.exit(1);
}
const summary = Object.entries(SLOTS)
  .flatMap(([slot, names]) => [`${names.setter} x${counts[slot].setter}`, `${names.requester} x${counts[slot].requester}`])
  .join(", ");
process.stdout.write(`check-build-wakeups: OK (${summary})\n`);
