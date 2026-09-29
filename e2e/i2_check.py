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
            at least one finding, required classifiers present (listed, or every classifier the
            ground truth expects for the engine), optionally no finding on a negative-control
            location, value-bearing names stored in their expected normalized form (ADR-0009) and
            never in their raw form.
  page      Checks the rendered findings page (masked samples decrypted): the table is complete
            (expected row count, enough rendered samples, no `unavailable` samples) and no masked
            sample keeps more than MAX_CLEAR_DIGITS digits (masking contract: at most 4 kept), which
            catches partial masking regressions that the value search cannot see.
  audit     Checks the console's access events and incidents of one target (Audit path, P4-D; JSON
            arrays, see run.sh): at least one of each; no event and no incident of the agent's own
            account (--agent-account: its Discovery reads must not surface); the required events
            (principal, optionally with a signal) and incidents (policy and principal, optionally
            with a signal) are present; no stored event object (database, schema or object name)
            holds a raw value-bearing name, even partially. Values themselves are searched by
            `scan`, on the same rows.
  `scan --needle ID` restricts a scan to the given needle ids (and their e-mail local part): run.sh
  uses it to follow the ground-truth literals it put in query text, on the console side (must be
  absent) and in the target's own audit log (positive control: must be present).

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
  Phones also get their international / national variants (+33 6 12... <-> 06 12..., +44, +1)
  and their national significant number (no trunk or country prefix); IBANs also their BBAN
  (without the country code and check digits).
  E-mail local parts with at least BOUNDED_BELOW letters / digits are extra bounded needles
  ("jean.dubois" in "jean.dubois@other.example").
  Masked samples (at most 4 digits kept, `*` elsewhere) cannot match: `*` is not a separator.

Exclusions (reported as counts, never silently)
  short   fewer than MIN_ALNUM letters / digits after folding (e.g. "Ava", "Mia", "Noé"): too
          short to tell a leak from an accident.
  common  a folded single word listed in COMMON_WORDS, with the reason it appears in the console
          independently of the target data. Keep this list tight and justified.
Not searched: encrypted or encoded forms (base64, hex): masked samples are encrypted at rest in the
console, which is why run.sh also scans the rendered findings page, where they are decrypted.
Partial digit runs of a value (e.g. 8 of 16 card digits) are not needles: with the seed's shared
prefixes (411111..., 01 99 00...) they would match timestamps and hashes. The `page` subcommand
bounds the clear digits of every masked sample instead.
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
from html.parser import HTMLParser
from typing import Iterable, Iterator

MIN_ALNUM = 4
BOUNDED_BELOW = 8
COMPACT_MIN_ALNUM = 9
COMPACT_MIN_DIGITS = 6
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_CLEAR_DIGITS = 4

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
    """Digit-only forms of the same phone number: international, national (trunk prefix 0) and
    national significant number (neither prefix)."""
    digits = "".join(c for c in raw if c.isdigit())
    out = {digits}
    s = raw.strip()
    nsn = None
    if s.startswith("+"):
        for cc in _TRUNK_PREFIX_CODES:
            if digits.startswith(cc):
                nsn = digits[len(cc):]
                out.add("0" + nsn)
        if digits.startswith("1") and len(digits) == 11:
            nsn = digits[1:]
    elif digits.startswith("0") and len(digits) == 10:
        nsn = digits[1:]
        out.add("33" + nsn)
    elif digits.startswith("33") and len(digits) == 11:
        nsn = digits[2:]
        out.add("0" + nsn)
    if nsn:
        out.add(nsn)
    return {d for d in out if len(d) >= COMPACT_MIN_ALNUM}


def iban_bban(raw: str) -> str | None:
    """The BBAN (IBAN without its country code and check digits), folded and compact."""
    c = compact(fold(raw))
    if len(c) > 4 and c[:2].isalpha() and c[2:4].isdigit():
        return c[4:]
    return None


def email_local_part(raw: str) -> str | None:
    folded = fold(raw)
    if folded.count("@") != 1:
        return None
    local = folded.split("@", 1)[0]
    return local if alnum_count(local) >= BOUNDED_BELOW else None


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
                if "pii.iban" in cls:
                    bban = iban_bban(raw)
                    if bban and len(bban) >= COMPACT_MIN_ALNUM:
                        needle.compacts.add(bban)
            needles.append(needle)
            if "pii.email" in cls:
                local = email_local_part(raw)
                if local:
                    needles.append(Needle(f"{nid}.local", i, kind + "_local_part", local, True))
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
        ids = [n.id for n in plan.needles]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate needle ids")
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
    wanted = getattr(args, "needle", None) or []
    if wanted:
        plan = restrict_plan(plan, wanted)
    if not plan.needles:
        raise ValueError(f"no searchable value for engine {args.engine!r} in the ground truth")
    return plan


def restrict_plan(plan: Plan, ids: list[str]) -> Plan:
    """The plan reduced to the given needle ids and their derived needles (`<id>.local`)."""
    keep = [n for n in plan.needles if any(n.id == i or n.id.startswith(i + ".") for i in ids)]
    missing = [i for i in ids if not any(n.id == i for n in keep)]
    if missing:
        raise ValueError(f"unknown or excluded needle id(s): {' '.join(missing)}")
    locations = {n.location: plan.locations[n.location] for n in keep}
    return Plan(keep, {"short": 0, "common": 0}, locations)


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


def expected_classifiers(ground_truth: dict, engine: str) -> list[str]:
    """Every classifier the ground truth expects on a location of the engine (sorted)."""
    out: set[str] = set()
    for loc in ground_truth.get("locations", []):
        if loc.get("engine") == engine:
            out.update(loc.get("expected_classifiers") or [])
    return sorted(out)


def raw_name_parts(loc: dict) -> tuple[set[str], list[str]]:
    """Folded raw names (object, container, field) of a value-bearing location that carry a value,
    and its folded name values long enough to be searched inside a stored name."""
    name_values = [fold(v) for v in loc.get("name_values") or []]
    names = {
        fold(v) for v in (loc.get("object"), loc.get("container"), loc.get("field"))
        if v and any(nv in fold(v) for nv in name_values)
    }
    parts = [nv for nv in name_values if alnum_count(nv) >= MIN_ALNUM]
    return names, parts


def holds_raw_name(stored: Iterable[str], names: set[str], parts: list[str]) -> bool:
    """Whether a stored name is a raw value-bearing name, or holds one of its name values."""
    folded = {fold(str(s or "")) for s in stored}
    return bool(names & folded) or any(nv in st for nv in parts for st in folded)


def check_findings(rows: list[dict], ground_truth: dict, engine: str, required: list[str],
                   require_expected: bool = False,
                   forbid_negative_controls: bool = False) -> tuple[list[str], list[str]]:
    """Returns (errors, info). Errors and info never hold a value-bearing name."""
    errors: list[str] = []
    info: list[str] = []
    if not rows:
        return ["no finding was ingested"], info
    classifiers = {r.get("classifier") for r in rows}
    info.append(f"{len(rows)} finding(s), classifiers: {', '.join(sorted(c for c in classifiers if c))}")
    required = list(required)
    if require_expected:
        from_gt = expected_classifiers(ground_truth, engine)
        if not from_gt:
            errors.append(f"the ground truth expects no classifier for engine {engine!r}")
        required += [c for c in from_gt if c not in required]
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
            # The raw name parts that carry a value (object, container or field); a name value
            # inside a stored name counts too (partial normalization).
            names, parts = raw_name_parts(loc)
            for r in rows:
                if holds_raw_name((r.get(k) for k in ("schema_name", "object_name", "field_name")),
                                  names, parts):
                    errors.append(f"{label}: a finding stores the raw value-bearing name")
                    break
            norm = loc.get("expected_normalized_name")
            if norm and loc.get("negative_control") and forbid_negative_controls:
                nkey = (loc.get("database"), loc.get("container"), norm, loc.get("field"))
                hits = sorted(c for c in by_location.get(nkey, set()) if c)
                if hits:
                    errors.append(f"{label}: negative control has finding(s) under the normalized "
                                  f"name {norm!r}: {', '.join(hits)}")
            if norm and want:
                # SQL engines: the object (table) name carries the value.
                nkey = (loc.get("database"), loc.get("container"), norm, loc.get("field"))
                if not (by_location.get(nkey, set()) & want):
                    errors.append(f"{label}: no finding stored under the expected normalized name "
                                  f"{norm!r}")
                else:
                    info.append(f"{label}: stored under the expected normalized name {norm!r}")
            continue
        if loc.get("negative_control") and forbid_negative_controls:
            k = (loc.get("database"), loc.get("container"), loc.get("object"), loc.get("field"))
            hits = sorted(c for c in by_location.get(k, set()) if c)
            if hits:
                errors.append(f"{label}: negative control has finding(s): {', '.join(hits)}")
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
    errors, info = check_findings(rows, gt, args.engine, args.require_classifier,
                                  args.require_expected_classifiers, args.forbid_negative_controls)
    for line in info:
        print(f"i2 findings: {line}", file=out)
    for line in errors:
        print(f"i2 findings: FAIL {line}", file=out)
    return 1 if errors else 0


# ---------------------------------------------------------------------------------- findings page
class _FindingsTableParser(HTMLParser):
    """Rows of the findings page's locations table (the one with a "Masked samples" column):
    per row, the classifier cell text, the rendered samples (<li>) and the samples cell text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[dict] = []
        self._stack: list[dict] = []
        self._cell: list[str] | None = None
        self._li: list[str] | None = None
        self._in_head = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "table":
            self._stack.append({"headers": [], "rows": []})
        elif not self._stack:
            return
        elif tag == "thead":
            self._in_head = True
        elif tag == "tbody":
            self._in_head = False
        elif tag == "tr" and not self._in_head:
            self._stack[-1]["rows"].append({"cells": [], "samples": []})
        elif tag in ("td", "th"):
            self._cell = []
        elif tag == "li" and self._cell is not None:
            self._li = []

    def handle_endtag(self, tag: str) -> None:
        if not self._stack:
            return
        t = self._stack[-1]
        if tag == "table":
            self.tables.append(self._stack.pop())
        elif tag == "li" and self._li is not None:
            if t["rows"]:
                t["rows"][-1]["samples"].append(("".join(self._li), len(t["rows"][-1]["cells"])))
            self._li = None
        elif tag in ("td", "th") and self._cell is not None:
            text = " ".join("".join(self._cell).split())
            if self._in_head or tag == "th":
                t["headers"].append(text)
            elif t["rows"]:
                t["rows"][-1]["cells"].append(text)
            self._cell = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)
        if self._li is not None:
            self._li.append(data)


def parse_findings_page(text: str) -> list[dict]:
    """[{classifier, samples: [str], samples_cell: str}] of the locations table."""
    p = _FindingsTableParser()
    p.feed(text)
    p.close()
    tables = [t for t in p.tables if "Masked samples" in t["headers"]]
    if len(tables) != 1:
        raise ValueError(f"expected one findings table with a 'Masked samples' column, found {len(tables)}")
    t = tables[0]
    h = t["headers"]
    ci, si = h.index("Classifier"), h.index("Masked samples")
    rows = []
    for r in t["rows"]:
        cells = r["cells"]
        if len(cells) <= max(ci, si):
            continue
        rows.append({
            "classifier": cells[ci].split(" ")[0],
            "samples": [s for s, col in r["samples"] if col == si],
            "samples_cell": cells[si],
        })
    return rows


def check_page(rows: list[dict], expected_rows: int | None, min_sampled_rows: int) -> tuple[list[str], list[str]]:
    """Returns (errors, info); never a sample."""
    errors: list[str] = []
    info: list[str] = []
    with_samples = [r for r in rows if r["samples"]]
    n_samples = sum(len(r["samples"]) for r in rows)
    info.append(f"{len(rows)} row(s), {len(with_samples)} with rendered samples, {n_samples} sample(s)")
    if expected_rows is not None and len(rows) != expected_rows:
        errors.append(f"{len(rows)} row(s) rendered, {expected_rows} expected")
    if min_sampled_rows <= 0:
        errors.append("no finding with masked samples in the database: the page scan would prove nothing")
    if len(with_samples) < min_sampled_rows:
        errors.append(f"{len(with_samples)} row(s) with rendered samples, at least {min_sampled_rows} expected")
    unavailable = sum(1 for r in rows if r["samples_cell"] == "unavailable")
    if unavailable:
        errors.append(f"{unavailable} row(s) with samples 'unavailable' (not decrypted: not scanned)")
    over: dict[str, int] = {}
    for r in rows:
        for s in r["samples"]:
            if sum(c.isdigit() for c in s) > MAX_CLEAR_DIGITS:
                over[r["classifier"]] = over.get(r["classifier"], 0) + 1
    for cls, n in sorted(over.items()):
        errors.append(f"{n} masked sample(s) of {cls} keep more than {MAX_CLEAR_DIGITS} digits")
    return errors, info


def cmd_page(args: argparse.Namespace, out) -> int:
    rows = parse_findings_page(read_text(args.page))
    errors, info = check_page(rows, args.expected_rows, args.min_sampled_rows)
    for line in info:
        print(f"i2 page: {line}", file=out)
    for line in errors:
        print(f"i2 page: FAIL {line}", file=out)
    return 1 if errors else 0


# ------------------------------------------------------------------------------ audit (P4-D)
def _principal(row: dict) -> str:
    return str(row.get("db_user") or row.get("principal") or "")


def check_audit(events: list[dict], incidents: list[dict], ground_truth: dict, engine: str,
                agent_account: str, require_events: list[str],
                require_incidents: list[str]) -> tuple[list[str], list[str]]:
    """Returns (errors, info). Only principals given on the command line, policy names, signal ids
    and counts are printed: never an object name (it may be value-bearing) or a value."""
    errors: list[str] = []
    info: list[str] = []
    if not events:
        errors.append("no access event was stored")
    if not incidents:
        errors.append("no incident was opened")
    agent = fold(agent_account)
    own_events = [e for e in events if fold(_principal(e)) == agent]
    own_incidents = [i for i in incidents if fold(_principal(i)) == agent]
    info.append(f"{len(events)} event(s), {len(incidents)} incident(s); of the agent's own account "
                f"{agent_account!r}: {len(own_events)} event(s), {len(own_incidents)} incident(s)")
    if own_events:
        errors.append(f"{len(own_events)} access event(s) of the agent's own account "
                      f"{agent_account!r}: its own reads surfaced")
    if own_incidents:
        errors.append(f"{len(own_incidents)} incident(s) attributed to the agent's own account "
                      f"{agent_account!r}")
    for req in require_events:
        principal, _, signal = req.partition(":")
        mine = [e for e in events if _principal(e) == principal]
        if signal:
            mine = [e for e in mine if signal in (e.get("signals") or [])]
        what = f"principal {principal!r}" + (f" with {signal}" if signal else "")
        if mine:
            sig = sorted({s for e in mine for s in e.get("signals") or []})
            info.append(f"{len(mine)} event(s) of {what}; signals: {', '.join(sig) or 'none'}")
        else:
            errors.append(f"no access event of {what}")
    for req in require_incidents:
        parts = req.split(":")
        if len(parts) not in (2, 3):
            errors.append(f"bad --require-incident {req!r}: POLICY:PRINCIPAL[:SIGNAL]")
            continue
        policy, principal = parts[0], parts[1]
        signal = parts[2] if len(parts) == 3 else ""
        mine = [i for i in incidents if i.get("policy_name") == policy and _principal(i) == principal]
        if signal:
            mine = [i for i in mine if signal in (i.get("event_signals") or [])]
        what = f"policy {policy!r}, principal {principal!r}" + (f", signal {signal}" if signal else "")
        if mine:
            info.append(f"{len(mine)} incident(s) of {what}")
        else:
            errors.append(f"no incident of {what}")
    for i, loc in enumerate(ground_truth.get("locations", [])):
        if loc.get("engine") != engine or not loc.get("name_contains_value"):
            continue
        names, parts = raw_name_parts(loc)
        bad = sum(
            1 for e in events for o in e.get("objects") or []
            if isinstance(o, dict)
            and holds_raw_name((o.get(k) for k in ("database", "schema", "object")), names, parts)
        )
        if bad:
            errors.append(f"{location_label(i, loc)}: {bad} stored event object(s) hold the raw "
                          "value-bearing name")
    masked = sum(1 for e in events for o in e.get("objects") or []
                 if isinstance(o, dict) and o.get("object") == "*")
    info.append(f"event objects named '*' (masked or unknown): {masked} (informational)")
    return errors, info


def _load_rows(path: str, what: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise ValueError(f"{what}: not a JSON array of objects")
    return rows


def cmd_audit(args: argparse.Namespace, out) -> int:
    with open(args.ground_truth, encoding="utf-8") as f:
        gt = json.load(f)
    events = _load_rows(args.events, "events file")
    incidents = _load_rows(args.incidents, "incidents file")
    errors, info = check_audit(events, incidents, gt, args.engine, args.agent_account,
                               args.require_event, args.require_incident)
    for line in info:
        print(f"i2 audit: {line}", file=out)
    for line in errors:
        print(f"i2 audit: FAIL {line}", file=out)
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
        s.add_argument("--needle", action="append", default=[],
                       help="only this needle id and its derived needles (repeatable)")
        s.add_argument("paths", nargs="+")
    f = sub.add_parser("findings")
    f.add_argument("--ground-truth", required=True)
    f.add_argument("--engine", required=True)
    f.add_argument("--require-classifier", action="append", default=[])
    f.add_argument("--require-expected-classifiers", action="store_true",
                   help="also require every classifier the ground truth expects for the engine")
    f.add_argument("--forbid-negative-controls", action="store_true",
                   help="fail on any finding stored on a negative-control location")
    f.add_argument("rows")
    a = sub.add_parser("audit")
    a.add_argument("--ground-truth", required=True)
    a.add_argument("--engine", required=True)
    a.add_argument("--agent-account", required=True,
                   help="the agent's own database account: no event or incident may name it")
    a.add_argument("--require-event", action="append", default=[], metavar="PRINCIPAL[:SIGNAL]")
    a.add_argument("--require-incident", action="append", default=[],
                   metavar="POLICY:PRINCIPAL[:SIGNAL]")
    a.add_argument("--events", required=True)
    a.add_argument("--incidents", required=True)
    g = sub.add_parser("page")
    g.add_argument("--expected-rows", type=int, default=None)
    g.add_argument("--min-sampled-rows", type=int, required=True)
    g.add_argument("page")
    args = p.parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args, out)
        if args.cmd == "coverage":
            return cmd_coverage(args, out)
        if args.cmd == "page":
            return cmd_page(args, out)
        if args.cmd == "audit":
            return cmd_audit(args, out)
        return cmd_findings(args, out)
    except (OSError, ValueError) as e:
        # OSError / ValueError messages hold file names only, never file contents.
        print(f"i2 {args.cmd}: error: {e}", file=out)
        return 2


if __name__ == "__main__":
    sys.exit(main())
