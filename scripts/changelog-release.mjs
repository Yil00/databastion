#!/usr/bin/env node
// Moves the curated "Unreleased" notes of CHANGELOG.md under the new version at each release, and
// prints them as the GitHub release notes. Called by release-it (.release-it.json):
//
//   node scripts/changelog-release.mjs changelog <version>  after:bump hook: rewrites CHANGELOG.md
//   node scripts/changelog-release.mjs notes <version>      github.releaseNotes: prints the notes
//   node scripts/changelog-release.mjs check                fails if "Unreleased" is empty or missing
//   node scripts/changelog-release.mjs preview <version>    prints both results, writes nothing
//
// `changelog` keeps the introduction, leaves an empty "## Unreleased" and puts the curated notes,
// verbatim, under "## [X.Y.Z](<repo>/compare/PREV...X.Y.Z) (YYYY-MM-DD)", where PREV is the latest
// final release tag (X.Y.Z, pre-release tags ignored) reachable from HEAD. It fails, before
// release-it commits, tags or pushes anything, when the "Unreleased" section is empty or missing.
// Run again for the same version, it changes nothing. A pre-release version (X.Y.Z-rc.N) leaves
// CHANGELOG.md as it is: the notes stay in "Unreleased" until the final release.
//
// `notes` prints the notes of the version's section (or of "Unreleased" before `changelog` ran, as
// in a dry run), with relative Markdown links made absolute (<repo>/blob/X.Y.Z/<path>), since a
// release body has no base path. The CHANGELOG itself keeps the relative links.
//
// Reads CHANGELOG.md and the local git tags only: no network access, no environment variable read
// except the optional overrides below (paths and a date, never printed).
//   CHANGELOG_RELEASE_FILE  path of the changelog (default: CHANGELOG.md in the working directory)
//   CHANGELOG_RELEASE_PREV  previous final tag, instead of reading the git tags ("" = none)
//   CHANGELOG_RELEASE_DATE  release date YYYY-MM-DD (default: today, UTC)

import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

export const REPO_URL = "https://github.com/Yil00/databastion";
const FINAL = /^(\d+)\.(\d+)\.(\d+)$/;
const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const UNRELEASED = /^## Unreleased\s*$/;

export class ChangelogError extends Error {}

const fail = (msg) => {
  throw new ChangelogError(msg);
};

// Splits the changelog into its head (everything before "## Unreleased"), the Unreleased body and
// the rest (from the next level-2 heading on). Headings inside fenced code blocks are ignored.
export function parse(text) {
  const lines = text.split("\n");
  let fence = false;
  let start = -1;
  let end = lines.length;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*(```|~~~)/.test(lines[i])) fence = !fence;
    if (fence) continue;
    if (start < 0) {
      if (UNRELEASED.test(lines[i])) start = i;
    } else if (/^## /.test(lines[i])) {
      end = i;
      break;
    }
  }
  if (start < 0) fail('CHANGELOG.md has no "## Unreleased" section: add one, with the curated notes of this release, below the introduction.');
  return {
    head: lines.slice(0, start).join("\n"),
    body: trimBlankLines(lines.slice(start + 1, end)).join("\n"),
    rest: lines.slice(end).join("\n"),
  };
}

function trimBlankLines(lines) {
  let a = 0;
  let b = lines.length;
  while (a < b && lines[a].trim() === "") a++;
  while (b > a && lines[b - 1].trim() === "") b--;
  return lines.slice(a, b);
}

function requireNotes(body) {
  if (body.trim() === "") {
    fail('The "## Unreleased" section of CHANGELOG.md is empty: write the curated notes of this release there (RELEASE.md, section 5) before releasing.');
  }
}

function checkVersion(version) {
  if (!version || !SEMVER.test(version)) fail(`expected a version X.Y.Z[-pre.N] (got: ${version ?? "nothing"})`);
}

const isPreRelease = (version) => !FINAL.test(version);

function cmpFinal(a, b) {
  const x = a.match(FINAL).slice(1).map(Number);
  const y = b.match(FINAL).slice(1).map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

// The latest final tag (X.Y.Z) below `version` among `tags`; pre-release tags are ignored.
export function previousFinalTag(tags, version) {
  const base = version.replace(/-.*$/, "");
  const finals = tags.map((t) => t.trim()).filter((t) => FINAL.test(t) && cmpFinal(t, base) < 0);
  finals.sort(cmpFinal);
  return finals.at(-1) ?? null;
}

function gitTags() {
  const out = execFileSync("git", ["tag", "--merged", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return out.split("\n").filter(Boolean);
}

export function heading(version, prev, date) {
  const link = prev ? `${REPO_URL}/compare/${prev}...${version}` : `${REPO_URL}/releases/tag/${version}`;
  return `## [${version}](${link}) (${date})`;
}

const sectionStart = (version) => `## [${version}](`;

// Index of the line starting the section of `version` in `rest`, or -1.
function findSection(rest, version) {
  return rest.split("\n").findIndex((l) => l.startsWith(sectionStart(version)));
}

// Returns the new changelog text (unchanged for a pre-release, or when already done).
export function moveUnreleased(text, version, prev, date) {
  checkVersion(version);
  const { head, body, rest } = parse(text);
  const done = findSection(rest, version) >= 0;
  if (done && body.trim() === "") return text; // already moved by an earlier run
  if (done) fail(`CHANGELOG.md already has a ${version} section, and "Unreleased" is not empty: merge them by hand.`);
  requireNotes(body);
  if (isPreRelease(version)) return text;
  const parts = [head.replace(/\n*$/, "\n"), "## Unreleased\n", heading(version, prev, date), "", body, ""];
  if (rest !== "") parts.push(rest);
  let out = parts.join("\n");
  if (!out.endsWith("\n")) out += "\n";
  return out;
}

// The notes of `version`: its section once moved, else the "Unreleased" body.
export function notesOf(text, version) {
  checkVersion(version);
  const { body, rest } = parse(text);
  const lines = rest.split("\n");
  const i = findSection(rest, version);
  let notes;
  if (i >= 0) {
    let j = i + 1;
    let fence = false;
    for (; j < lines.length; j++) {
      if (/^\s*(```|~~~)/.test(lines[j])) fence = !fence;
      if (!fence && /^## /.test(lines[j])) break;
    }
    notes = trimBlankLines(lines.slice(i + 1, j)).join("\n");
  } else {
    notes = body;
  }
  requireNotes(notes);
  return notes;
}

// Relative link target → absolute URL at the version's tag, or null to keep it as it is.
function absolute(target, version) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("#") || target.startsWith("/") || target === "") return null;
  const m = target.match(/^([^#?]*)(.*)$/);
  const p = path.posix.normalize(m[1]);
  if (p === "." || p.startsWith("../")) return null;
  return `${REPO_URL}/blob/${version}/${p}${m[2]}`;
}

// Rewrites relative Markdown link targets (inline `](target)` and reference definitions
// `[label]: target`) outside code spans and fenced blocks.
export function absoluteLinks(markdown, version) {
  let fence = false;
  return markdown
    .split("\n")
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) {
        fence = !fence;
        return line;
      }
      if (fence) return line;
      const def = line.match(/^(\s{0,3}\[[^\]]+\]:\s*)(<?)(\S+?)(>?)(\s.*)?$/);
      if (def) {
        const abs = absolute(def[3], version);
        return abs ? `${def[1]}${def[2]}${abs}${def[4]}${def[5] ?? ""}` : line;
      }
      // Odd segments are code spans: left alone.
      return line
        .split(/(`+[^`]*`+)/)
        .map((seg, k) =>
          k % 2 === 1
            ? seg
            : seg.replace(/\]\(\s*(<[^>]*>|[^)\s]+)(\s+"[^"]*")?\s*\)/g, (all, t, title) => {
                const bracketed = t.startsWith("<");
                const abs = absolute(bracketed ? t.slice(1, -1) : t, version);
                if (!abs) return all;
                return `](${bracketed ? `<${abs}>` : abs}${title ?? ""})`;
              }),
        )
        .join("");
    })
    .join("\n");
}

function today() {
  const d = process.env.CHANGELOG_RELEASE_DATE;
  if (d !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) fail("CHANGELOG_RELEASE_DATE: expected YYYY-MM-DD");
    return d;
  }
  return new Date().toISOString().slice(0, 10);
}

function prevTag(version) {
  const p = process.env.CHANGELOG_RELEASE_PREV;
  if (p !== undefined) {
    if (p !== "" && !FINAL.test(p)) fail("CHANGELOG_RELEASE_PREV: expected X.Y.Z or nothing");
    return p === "" ? null : p;
  }
  return previousFinalTag(gitTags(), version);
}

function main(argv) {
  const [command, version] = argv;
  const file = process.env.CHANGELOG_RELEASE_FILE || "CHANGELOG.md";
  const text = readFileSync(file, "utf8");
  switch (command) {
    case "changelog": {
      checkVersion(version);
      const out = moveUnreleased(text, version, prevTag(version), today());
      if (out !== text) {
        writeFileSync(file, out);
        console.error(`${file}: "Unreleased" notes moved under ${version}`);
      } else {
        console.error(`${file}: unchanged (${isPreRelease(version) ? "pre-release: the notes stay in \"Unreleased\"" : "already done"})`);
      }
      break;
    }
    case "notes":
      process.stdout.write(absoluteLinks(notesOf(text, version), version) + "\n");
      break;
    case "check":
      requireNotes(parse(text).body);
      console.error(`${file}: "Unreleased" has notes`);
      break;
    case "preview": {
      checkVersion(version);
      const out = moveUnreleased(text, version, prevTag(version), today());
      const cut = out.split("\n");
      const at = cut.findIndex((l) => l.startsWith(sectionStart(version)));
      const next = at < 0 ? -1 : cut.findIndex((l, k) => k > at && /^## /.test(l));
      process.stdout.write(`----- ${file} (would be, up to the previous section) -----\n`);
      process.stdout.write(cut.slice(0, next < 0 ? Math.min(cut.length, 40) : next + 1).join("\n") + "\n");
      process.stdout.write(`----- GitHub release notes of ${version} (would be) -----\n`);
      process.stdout.write(absoluteLinks(notesOf(out, version), version) + "\n");
      break;
    }
    default:
      fail("usage: changelog-release.mjs changelog|notes|preview <version> | check");
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("changelog-release.mjs")) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    if (err instanceof ChangelogError) {
      console.error(`changelog-release: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}
