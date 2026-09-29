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
// It reads the Turbopack server chunks (`.next/server/**/*.js`) and finds every export site of the
// functions below (`"name",0,<function or identifier>`), resolving an identifier to its definition
// in the same module. It fails when an export resolves to an empty body, when a definition cannot
// be resolved, or when a function is not found at all (the check would be vacuous).
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", ".next", "server");
const CHECKED = [
  "requestPolicyEvaluation",
  "setPolicyJobSender",
  "requestNotificationDelivery",
  "setNotificationJobSender",
];

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

/** Index of the character after the `)` matching the `(` at `open` (no strings in parameter lists). */
function closeParen(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "(") depth++;
    else if (src[i] === ")" && --depth === 0) return i + 1;
  }
  return -1;
}

/**
 * Body of the function expression starting at `at`: "empty", "non-empty" or null when `at` is
 * not a function. Handles `function x(…){…}`, `async function(…){…}`, `(…)=>{…}`, `x=>…`.
 */
function bodyAt(src, at) {
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
    i = closeParen(src, i);
  } else if (src[i] === "(") {
    i = closeParen(src, i);
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
    if (src[i] !== "{") return "non-empty"; // expression body
  }
  if (src[i] !== "{") return null;
  i++;
  skipWs();
  return src[i] === "}" ? "empty" : "non-empty";
}

/** Module text around `pos`: from the previous `"use strict"` to the next one. */
function moduleAround(src, pos) {
  const start = src.lastIndexOf('"use strict"', pos);
  const next = src.indexOf('"use strict"', pos);
  return { text: src.slice(Math.max(0, start), next < 0 ? src.length : next), offset: Math.max(0, start) };
}

function resolveIdentifier(src, pos, ident) {
  const { text } = moduleAround(src, pos);
  const esc = ident.replace(/\$/g, "\\$");
  const patterns = [
    new RegExp(`(?:async\\s+)?function\\s*\\*?\\s*${esc}\\s*\\(`, "g"),
    new RegExp(`(?:^|[^\\w$.])${esc}\\s*=\\s*(?=(?:async\\s*)?(?:function|\\(|[A-Za-z_$][\\w$]*\\s*=>))`, "g"),
  ];
  const results = [];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(text))) {
      const at = m[0].startsWith("async") || m[0].includes("function") ? m.index : m.index + m[0].length;
      const body = bodyAt(text, at);
      if (body) results.push(body);
    }
  }
  return results;
}

const found = Object.fromEntries(CHECKED.map((n) => [n, 0]));
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
  for (const name of CHECKED) {
    const re = new RegExp(`"${name}",\\s*0,\\s*`, "g");
    let m;
    while ((m = re.exec(src))) {
      found[name]++;
      const at = m.index + m[0].length;
      const where = `${path.relative(ROOT, file)} @${m.index}`;
      let body = bodyAt(src, at);
      if (body === null) {
        const ident = IDENT.exec(src.slice(at))?.[0];
        const bodies = ident ? resolveIdentifier(src, m.index, ident) : [];
        if (bodies.length === 0) {
          failures.push(`${name}: cannot resolve the exported function (${where})`);
          continue;
        }
        body = bodies.includes("empty") ? "empty" : "non-empty";
      }
      if (body === "empty") failures.push(`${name}: compiled to an empty function (${where})`);
    }
  }
}
for (const [name, count] of Object.entries(found)) {
  if (count === 0) failures.push(`${name}: not found in the server chunks (check not applicable to this build?)`);
}
if (failures.length > 0) {
  process.stderr.write(`check-build-wakeups: FAILED\n${failures.map((f) => `  - ${f}\n`).join("")}`);
  process.exit(1);
}
const summary = Object.entries(found)
  .map(([n, c]) => `${n} x${c}`)
  .join(", ");
process.stdout.write(`check-build-wakeups: OK (${summary})\n`);
