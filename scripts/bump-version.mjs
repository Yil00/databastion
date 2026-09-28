#!/usr/bin/env node
// Aligns the version number of every component in the repository.
// Called by release-it (after:bump hook), or manually: node scripts/bump-version.mjs 0.2.0
// Missing files are skipped: the script works from phase 0 onward.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const version = process.argv[2];
const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
if (!version || !SEMVER.test(version)) {
  console.error(`usage: bump-version.mjs <X.Y.Z[-pre.N]> (got: ${version ?? "nothing"})`);
  process.exit(1);
}

const updated = [];

function bumpJson(path) {
  if (!existsSync(path)) return;
  const raw = readFileSync(path, "utf8");
  const data = JSON.parse(raw);
  data.version = version;
  writeFileSync(path, JSON.stringify(data, null, 2) + (raw.endsWith("\n") ? "\n" : ""));
  updated.push(path);
}

// Replaces `version = "…"` only in the [workspace.package] (or [package]) section.
function bumpCargo(path) {
  if (!existsSync(path)) return;
  const lines = readFileSync(path, "utf8").split("\n");
  let section = "";
  let done = false;
  const out = lines.map((line) => {
    const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (header) section = header[1];
    if (!done && (section === "workspace.package" || section === "package") && /^\s*version\s*=/.test(line)) {
      done = true;
      return line.replace(/=\s*"[^"]*"/, `= "${version}"`);
    }
    return line;
  });
  if (!done) {
    console.error(`${path}: no version key in [workspace.package] or [package]`);
    process.exit(1);
  }
  writeFileSync(path, out.join("\n"));
  updated.push(path);

  const lock = path.replace(/Cargo\.toml$/, "Cargo.lock");
  if (existsSync(lock)) {
    // Updates the workspace crate versions in the lockfile without touching dependencies.
    execFileSync("cargo", ["update", "--workspace", "--offline", "--manifest-path", path], { stdio: "inherit" });
    updated.push(lock);
  }
}

function bumpYamlKeys(path, keys) {
  if (!existsSync(path)) return;
  let text = readFileSync(path, "utf8");
  for (const key of keys) {
    text = text.replace(new RegExp(`^(${key}:\\s*)["']?[^"'\\n]*["']?`, "m"), `$1"${version}"`);
  }
  writeFileSync(path, text);
  updated.push(path);
}

bumpJson("package.json");
bumpJson("console/package.json");
bumpCargo("agent/Cargo.toml");
bumpYamlKeys("helm/databastion/Chart.yaml", ["version", "appVersion"]);

console.log(`version ${version} → ${updated.length ? updated.join(", ") : "no files"}`);
