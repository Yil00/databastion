#!/usr/bin/env python3
"""Invariant I2 end-to-end checks (ROADMAP P2-E), Python standard library only.

No value of dev/ground-truth.json, and no value-bearing object / field name, may appear in clear
text in what the console stores or logs. Driven by e2e/run.sh; unit tests in test_i2_check.py.

Subcommands
  scan      Search files / directories for the ground-truth values of one engine. Exit 1 on any
            hit ("leak"), 2 on a usage error or when there is nothing to scan.
  coverage  Positive control: every searchable value must be found in the given files (run on the
            committed seed, dev/seed/out/<engine>.sql). Exit 1 if one is missing.
  findings  Checks the console's findings rows (JSON array, see run.sh) against the ground truth:
            at least one finding, required classifiers present, value-bearing names stored in their
            expected normalized form (ADR-0009) and never in their raw form.

Output: counts, needle ids (`L<location index>.v<value index>`, `.n<name value index>`,
`.object`) and file names only. A matched value, or a value-bearing name, is never printed: the
CI log must not become the leak.

What "in clear" means (a *needle* is one ground-truth value or value-bearing name)
  Folding: both sides are NFKD-decomposed, stripped of combining marks, case-folded and NFC
  recomposed, so NFC / NFD, case and accent variants of a value match ("Lefèvre", "LEFEVRE",
  "Lefèvre").
  Views: each file is searched as is and, when it holds such escapes, after decoding JSON
  \\uXXXX escapes, URL %XX escapes, HTML character references and SQL doubled quotes.
  Plain form: the folded needle is a substring of a folded view. Needles with fewer than
  BOUNDED_BELOW letters / digits must also stand at word boundaries (no letter or digit right
  before or after; `_` and punctuation are boundaries), so that "Martin" matches in
  "archive_lucas_martin" but not in "Martinez", and random base64 / hex cannot match a short name.
  Compact form: needles with at least COMPACT_MIN_ALNUM letters / digits of which at least
  COMPACT_MIN_DIGITS are digits (phones, cards, IBANs, NIRs, value-bearing digit names) are also
  searched with their separators removed, in a projection of each view where runs of up to three
  separator characters (space, tab, . - / ( ) + _) between two letters / digits are deleted. The
  match must not be preceded or followed by a digit (no partial match inside a longer digit run).
  Phones also get their international / national variants (+33 6 12... <-> 06 12..., +44, +1).
  Masked samples (at most 4 digits kept, `*` elsewhere) cannot match: `*` is not a separator.

Exclusions (reported as counts, never silently)
  short   fewer than MIN_ALNUM letters / digits after folding (e.g. "Ava", "Mia", "Noé"): too
          short to tell a leak from an accident.
  common  a folded single word listed in COMMON_WORDS, with the reason it appears in the console
          independently of the target data. Keep this list tight and justified.
Not searched: encrypted or encoded forms (base64, hex): masked samples are encrypted at rest in the
console, which is why run.sh also scans the rendered findings page, where they are decrypted.
"""

from __future__ import annotations

import argparse
import fnmatch
import html
import json
import os
import re
import sys
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Iterator

MIN_ALNUM = 4
BOUNDED_BELOW = 8
COMPACT_MIN_ALNUM = 9
COMPACT_MIN_DIGITS = 6
MAX_FILE_BYTES = 512 * 1024 * 1024

# Folded single words that also occur in the console independently of the target data.
# word -> reason. Empty on purpose: add an entry only with evidence, never to hide a real leak.
COMMON_WORDS: dict[str, str] = {}

# Separators removed between two letters / digits in the compact projection.
_SEP_RUN = re.compile(r"(?<=[^\W_])[ \t.\-/()+_]{1,3}(?=[^\W_])")
_JSON_U = re.compile(r"\\u([0-9a-fA-F]{4})(?:\\u([0-9a-fA-F]{4}))?")

# Country calling codes of the seeded phones (dev/seed/generate.py): +33 FR, +44 UK, +1 US.
_TRUNK_PREFIX_CODES = ("33", "44")


def fold(s: str) -> str:
    """NFKD, combining marks removed, case-folded, NFC."""
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return unicodedata.normalize("NFC", stripped.casefold())


def alnum_count(s: str) -> int:
    return sum(1 for c in s if c.isalnum())


def compact(s: str) -> str:
    return "".join(c for c in s if c.isalnum())


def phone_variants(raw: str) -> set[str]:
    """Digit-only forms of the same phone number (international <-> national)."""
    digits = "".join(c for c in raw if c.isdigit())
    out = {digits}
    s = raw.strip()
    if s.startswith("+"):
        for cc in _TRUNK_PREFIX_CODES:
            if digits.startswith(cc):
                out.add("0" + digits[len(cc):])
        if digits.startswith("1") and len(digits) == 11:
            out.add(digits[1:])
    elif digits.startswith("0") and len(digits) == 10:
        out.add("33" + digits[1:])
    elif digits.startswith("33") and len(digits) == 11:
        out.add("0" + digits[2:])
    return {d for d in out if len(d) >= COMPACT_MIN_ALNUM}


@dataclass
class Needle:
    id: str
    location: int
    kind: str  # value | name_value | object
    plain: str
    bounded: bool
    compacts: set[str] = field(default_factory=set)


@dataclass
class Plan:
    needles: list[Needle]
    excluded: dict[str, int]
    locations: dict[int, dict]


def location_label(index: int, loc: dict) -> str:
    """Printable location: never a value-bearing name."""
    parts = [loc.get("engine") or "?", loc.get("database") or "-"]
    if loc.get("name_contains_value"):
        parts.append("<value-bearing name>")
    else:
        parts += [loc.get("container") or "-", loc.get("object") or "-", loc.get("field") or "-"]
    return f"L{index} " + "/".join(str(p) for p in parts)


def build_plan(ground_truth: dict, engine: str) -> Plan:
    needles: list[Needle] = []
    excluded = {"short": 0, "common": 0}
    locations: dict[int, dict] = {}
    for i, loc in enumerate(ground_truth.get("locations", [])):
        if loc.get("engine") != engine:
            continue
        locations[i] = loc
        classifiers = set(loc.get("expected_classifiers") or [])
        items: list[tuple[str, str, str, set[str]]] = []
        for j, v in enumerate(loc.get("values") or []):
            items.append((f"L{i}.v{j}", "value", v, classifiers))
        if loc.get("name_contains_value"):
            name_cls = set(loc.get("name_value_classifiers") or [])
            for j, v in enumerate(loc.get("name_values") or []):
                items.append((f"L{i}.n{j}", "name_value", v, name_cls))
            for part in ("object", "container", "field"):
                raw = loc.get(part)
                if raw and any(fold(nv) in fold(raw) for nv in loc.get("name_values") or []):
                    items.append((f"L{i}.{part}", part, raw, name_cls))
        for nid, kind, raw, cls in items:
            if not isinstance(raw, str):
                continue
            folded = fold(raw)
            n_alnum = alnum_count(folded)
            if n_alnum < MIN_ALNUM:
                excluded["short"] += 1
                continue
            if folded in COMMON_WORDS:
                excluded["common"] += 1
                continue
            needle = Needle(nid, i, kind, folded, n_alnum < BOUNDED_BELOW)
            c = compact(folded)
            if len(c) >= COMPACT_MIN_ALNUM and sum(ch.isdigit() for ch in c) >= COMPACT_MIN_DIGITS:
                needle.compacts.add(c)
                if "pii.phone" in cls:
                    needle.compacts |= phone_variants(raw)
            needles.append(needle)
    return Plan(needles, excluded, locations)


# ----------------------------------------------------------------------------------------- views
def _json_unescape(text: str) -> str:
    def rep(m: re.Match[str]) -> str:
        hi = int(m.group(1), 16)
        if m.group(2):
            lo = int(m.group(2), 16)
            if 0xD800 <= hi < 0xDC00 and 0xDC00 <= lo < 0xE000:
                return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
            return chr(hi) + chr(lo)
        return chr(hi)

    return _JSON_U.sub(rep, text)


def views(text: str) -> Iterator[tuple[str, str]]:
    """(name, folded text) of every decoded view of a file."""
    yield "raw", fold(text)
    if "\\u" in text:
        yield "json-escapes", fold(_json_unescape(text))
    if "%" in text:
        yield "url-escapes", fold(urllib.parse.unquote(text, errors="replace"))
    if "&" in text:
        yield "html-entities", fold(html.unescape(text))
    if "''" in text:
        yield "sql-quotes", fold(text.replace("''", "'"))


def projection(folded: str) -> str:
    return _SEP_RUN.sub("", folded)


def _bounded_regex(plain: str) -> re.Pattern[str]:
    left = r"(?<![^\W_])" if plain[:1].isalnum() else ""
    right = r"(?![^\W_])" if plain[-1:].isalnum() else ""
    return re.compile(left + re.escape(plain) + right)


def _compact_regex(c: str) -> re.Pattern[str]:
    left = r"(?<!\d)" if c[:1].isdigit() else ""
    right = r"(?!\d)" if c[-1:].isdigit() else ""
    return re.compile(left + re.escape(c) + right)


@dataclass
class Hit:
    needle: Needle
    form: str  # plain | compact
    file: str
    view: str


class Matcher:
    def __init__(self, plan: Plan) -> None:
        self.plan = plan
        self._bounded = {n.id: _bounded_regex(n.plain) for n in plan.needles if n.bounded}
        self._compact = {(n.id, c): _compact_regex(c) for n in plan.needles for c in n.compacts}

    def search_text(self, text: str, file: str) -> list[Hit]:
        hits: list[Hit] = []
        found: set[str] = set()
        for view_name, folded in views(text):
            proj: str | None = None
            for n in self.plan.needles:
                if n.id in found:
                    continue
                if n.bounded:
                    ok = self._bounded[n.id].search(folded) is not None
                else:
                    ok = n.plain in folded
                if ok:
                    hits.append(Hit(n, "plain", file, view_name))
                    found.add(n.id)
                    continue
                if n.compacts:
                    if proj is None:
                        proj = projection(folded)
                    for c in sorted(n.compacts):
                        if self._compact[(n.id, c)].search(proj):
                            hits.append(Hit(n, "compact", file, view_name))
                            found.add(n.id)
                            break
        return hits


# ----------------------------------------------------------------------------------------- files
def iter_files(paths: Iterable[str], excludes: list[str]) -> Iterator[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for name in sorted(files):
                    if not any(fnmatch.fnmatch(name, pat) for pat in excludes):
                        yield os.path.join(root, name)
        elif os.path.isfile(p):
            if not any(fnmatch.fnmatch(os.path.basename(p), pat) for pat in excludes):
                yield p
        else:
            raise FileNotFoundError(p)


def read_text(path: str) -> str:
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{os.path.basename(path)}: {size} bytes, over the {MAX_FILE_BYTES} limit")
    with open(path, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def load_plan(args: argparse.Namespace) -> Plan:
    with open(args.ground_truth, encoding="utf-8") as f:
        gt = json.load(f)
    plan = build_plan(gt, args.engine)
    if not plan.needles:
        raise ValueError(f"no searchable value for engine {args.engine!r} in the ground truth")
    return plan


def summary_line(plan: Plan) -> str:
    kinds: dict[str, int] = {}
    for n in plan.needles:
        kinds[n.kind] = kinds.get(n.kind, 0) + 1
    by_kind = ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
    return (
        f"{len(plan.needles)} needles from {len(plan.locations)} locations ({by_kind}); excluded: "
        f"short {plan.excluded['short']}, common {plan.excluded['common']}"
    )


def scan_files(plan: Plan, paths: list[str], excludes: list[str]) -> tuple[list[Hit], int, int]:
    matcher = Matcher(plan)
    hits: list[Hit] = []
    n_files = n_bytes = 0
    for path in iter_files(paths, excludes):
        text = read_text(path)
        n_files += 1
        n_bytes += len(text)
        hits += matcher.search_text(text, os.path.basename(path))
    return hits, n_files, n_bytes


def cmd_scan(args: argparse.Namespace, out) -> int:
    plan = load_plan(args)
    hits, n_files, n_bytes = scan_files(plan, args.paths, args.exclude)
    print(f"i2 scan [{args.label}]: {summary_line(plan)}", file=out)
    print(f"i2 scan [{args.label}]: {n_files} file(s), {n_bytes} characters", file=out)
    if n_files == 0 or n_bytes == 0:
        print(f"i2 scan [{args.label}]: nothing to scan: the check would prove nothing", file=out)
        return 2
    if not hits:
        print(f"i2 scan [{args.label}]: no ground-truth value in clear text", file=out)
        return 0
    leaked = {h.needle.id for h in hits}
    for h in sorted(hits, key=lambda h: (h.needle.location, h.needle.id, h.file)):
        loc = plan.locations[h.needle.location]
        print(
            f"LEAK {h.needle.id} ({h.needle.kind}) {location_label(h.needle.location, loc)} "
            f"form={h.form} view={h.view} file={h.file}",
            file=out,
        )
    print(f"i2 scan [{args.label}]: {len(leaked)} needle(s) in clear text, {len(hits)} hit(s)", file=out)
    return 1


def cmd_coverage(args: argparse.Namespace, out) -> int:
    plan = load_plan(args)
    hits, n_files, _ = scan_files(plan, args.paths, args.exclude)
    print(f"i2 coverage: {summary_line(plan)}; {n_files} file(s)", file=out)
    found = {h.needle.id for h in hits}
    missing = [n.id for n in plan.needles if n.id not in found]
    if missing:
        print(f"i2 coverage: {len(missing)} needle(s) NOT found (scanner cannot see them): "
              + " ".join(missing[:50]), file=out)
        return 1
    print(f"i2 coverage: all {len(plan.needles)} needles found (positive control)", file=out)
    return 0


def check_findings(rows: list[dict], ground_truth: dict, engine: str,
                   required: list[str]) -> tuple[list[str], list[str]]:
    """Returns (errors, info). Errors and info never hold a value-bearing name."""
    errors: list[str] = []
    info: list[str] = []
    if not rows:
        return ["no finding was ingested"], info
    classifiers = {r.get("classifier") for r in rows}
    info.append(f"{len(rows)} finding(s), classifiers: {', '.join(sorted(c for c in classifiers if c))}")
    for c in required:
        if c not in classifiers:
            errors.append(f"expected classifier {c} has no finding")

    def key(r: dict) -> tuple:
        return (r.get("database_name"), r.get("schema_name"), r.get("object_name"), r.get("field_name"))

    by_location: dict[tuple, set[str]] = {}
    for r in rows:
        by_location.setdefault(key(r), set()).add(r.get("classifier"))
    expected = found = 0
    for i, loc in enumerate(ground_truth.get("locations", [])):
        if loc.get("engine") != engine:
            continue
        label = location_label(i, loc)
        want = set(loc.get("expected_classifiers") or [])
        if loc.get("name_contains_value"):
            name_values = [fold(v) for v in loc.get("name_values") or []]
            # The raw name parts that carry a value (object, container or field).
            names = {
                fold(v) for v in (loc.get("object"), loc.get("container"), loc.get("field"))
                if v and any(nv in fold(v) for nv in name_values)
            }
            for r in rows:
                stored = {fold(str(r.get(k) or "")) for k in ("schema_name", "object_name", "field_name")}
                if names & stored:
                    errors.append(f"{label}: a finding stores the raw value-bearing name")
                    break
            norm = loc.get("expected_normalized_name")
            if norm and want:
                # SQL engines: the object (table) name carries the value.
                nkey = (loc.get("database"), loc.get("container"), norm, loc.get("field"))
                if not (by_location.get(nkey, set()) & want):
                    errors.append(f"{label}: no finding stored under the expected normalized name "
                                  f"{norm!r}")
                else:
                    info.append(f"{label}: stored under the expected normalized name {norm!r}")
            continue
        if want:
            expected += 1
            k = (loc.get("database"), loc.get("container"), loc.get("object"), loc.get("field"))
            if by_location.get(k, set()) & want:
                found += 1
    info.append(f"ground-truth locations with an expected classifier found: {found}/{expected} "
                "(informational)")
    return errors, info


def cmd_findings(args: argparse.Namespace, out) -> int:
    with open(args.ground_truth, encoding="utf-8") as f:
        gt = json.load(f)
    with open(args.rows, encoding="utf-8") as f:
        rows = json.load(f)
    if not isinstance(rows, list):
        print("i2 findings: rows file is not a JSON array", file=out)
        return 2
    errors, info = check_findings(rows, gt, args.engine, args.require_classifier)
    for line in info:
        print(f"i2 findings: {line}", file=out)
    for line in errors:
        print(f"i2 findings: FAIL {line}", file=out)
    return 1 if errors else 0


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "coverage"):
        s = sub.add_parser(name)
        s.add_argument("--ground-truth", required=True)
        s.add_argument("--engine", required=True)
        s.add_argument("--exclude", action="append", default=[],
                       help="basename glob of files to skip (repeatable)")
        s.add_argument("--label", default="files")
        s.add_argument("paths", nargs="+")
    f = sub.add_parser("findings")
    f.add_argument("--ground-truth", required=True)
    f.add_argument("--engine", required=True)
    f.add_argument("--require-classifier", action="append", default=[])
    f.add_argument("rows")
    args = p.parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args, out)
        if args.cmd == "coverage":
            return cmd_coverage(args, out)
        return cmd_findings(args, out)
    except (OSError, ValueError) as e:
        # OSError / ValueError messages hold file names only, never file contents.
        print(f"i2 {args.cmd}: error: {e}", file=out)
        return 2


if __name__ == "__main__":
    sys.exit(main())
