#!/usr/bin/env python3
"""Built-in function name lists of MySQL and MariaDB (ADR-0045 decision 7).

Extracts, from the server parser sources at a pinned tag, the names an
unqualified call `name(` may resolve to a built-in function, and writes one
sorted list per release series (`<flavor>-<series>.txt`, next to this
script). The MySQL / MariaDB Audit analysis takes any other unqualified name
followed by `(` as a possible stored (or loadable) function: a read of `*`,
always reported (ADR-0045 decisions 8 to 10).

    python3 -I extract.py [--cache DIR]

The sources are fetched from raw.githubusercontent.com (a few files per tag,
no archive), into a cache directory outside the repository when one is
given. Nothing is executed from them: they are read as text.

What is extracted, per tag:

- MySQL: `sql/item_create.cc` `func_array` (the native function registry,
  without its `#ifndef NDEBUG` debug-only entries); `sql/lex.h` keywords
  (`SYM`, `SYM_HK`; not the optimizer hint names `SYM_H`) and functions
  (`SYM_FN`: the `sql_functions` set); `sql/sql_yacc.yy`, the keywords the
  grammar puts right before `(` (or before a rule that starts with `(`, such
  as `optional_braces`).
- MariaDB: the same files (`native_func_registry_array` without the Oracle
  overrides `func_array_oracle_overrides`; the grammar's `%ifdef ORACLE`
  branches skipped: a name built in only under `sql_mode=ORACLE` counts as
  not built in), `sql/item_geofunc.cc` (`func_array_geom`), and the
  `MariaDB_FUNCTION_PLUGIN` names of the plugins built in by default
  (`plugin/type_inet`, `plugin/type_uuid`, declared `MANDATORY`).

Each name gets a form, which says how the server reads `name(`:

- `n`: native (registry or default plugin). Built in whether it is written
  plainly, backquoted (or double-quoted under `ANSI_QUOTES`), or with
  whitespace before `(`: the server looks a generic call up in the native
  registry first.
- `s`: a keyword function of `lex.h`'s `sql_functions` (`COUNT`, `NOW`,
  `SUBSTR`...). The lexer reads it as the keyword only when `(` follows
  right away; with whitespace (or a comment) before `(`, and without
  `IGNORE_SPACE` (the session's `sql_mode` is unknown), it is a plain
  identifier, resolved as a stored function of the default database.
  Backquoted, it is a stored function too.
- `k`: another keyword the grammar puts before `(`: a keyword function
  (`IF`, `CHAR`, `DATABASE`, `JSON_TABLE`...) or a word that is not a call
  (`IN`, `VALUES`, `KEY`...). Plain, with or without whitespace, it is the
  keyword; backquoted, it is a stored function.

Grammar keywords that are not reserved and are not functions (`COLUMNS`,
`AGAINST`...) are left out by `NOT_FUNCTIONS` below: unreserved, `name(` is
an identifier and calls a stored function. The analysis tells their non-call
positions by context instead (after `)`, after a literal, after `AS`; see
`classifiers::query`). The drift test of decision 11
(`connector-mysql/src/it/builtins_it.rs`) checks every form against each
engine-matrix image and fails when a list is wrong in the unsafe direction.

The MySQL 8.0 list is the union of its first GA and last patch releases
(maintainer's answer to ADR-0045 open question 8); Percona Server takes the
MySQL list of its series.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (flavor, series, repository, tags): the engine-matrix images
# (.github/workflows/engine-matrix.yml) and, for MySQL 8.0, its first GA.
SERIES = [
    ("mysql", "8.0", "mysql/mysql-server", ["mysql-8.0.11", "mysql-8.0.46"]),
    ("mysql", "8.4", "mysql/mysql-server", ["mysql-8.4.11"]),
    ("mysql", "9.7", "mysql/mysql-server", ["mysql-9.7.2"]),
    ("mariadb", "10.11", "MariaDB/server", ["mariadb-10.11.19"]),
    ("mariadb", "11.4", "MariaDB/server", ["mariadb-11.4.13"]),
    ("mariadb", "11.8", "MariaDB/server", ["mariadb-11.8.9"]),
]

COMMON_FILES = ["sql/item_create.cc", "sql/lex.h", "sql/sql_yacc.yy"]
MARIADB_FILES = [
    "sql/item_geofunc.cc",
    "plugin/type_inet/plugin.cc",
    "plugin/type_uuid/plugin.cc",
]

# Grammar keywords before `(` that are neither reserved nor functions: an
# unquoted `name(` is an identifier there, so the server calls a stored
# function of that name (error 1305 in an empty schema, checked by the drift
# test). Their non-call positions are told by context in the analysis.
NOT_FUNCTIONS = {
    # MySQL: a keyword, reserved or not, is never a function name unquoted
    # (`SELECT against()` is a syntax error): nothing to leave out.
    "mysql": set(),
    # MariaDB: unreserved keywords are function names (`SELECT against()`:
    # error 1630, a stored function of the default database).
    "mariadb": {
        "against",  # MATCH (…) AGAINST (…): after `)`
        "at",  # CREATE EVENT … ON SCHEDULE AT: DDL
        "columns",  # JSON_TABLE(…, '$' COLUMNS (…)): after a literal
        "connection",  # KILL CONNECTION, … FOR CONNECTION
        "ends",  # CREATE EVENT … ENDS: DDL
        "escape",  # LIKE … ESCAPE '…'
        "every",  # CREATE EVENT … EVERY: DDL
        "fields",  # LOAD DATA … FIELDS
        "hash",  # PARTITION BY HASH (…): DDL
        "immediate",  # EXECUTE IMMEDIATE: a reported `EXECUTE`
        "indexes",  # SHOW INDEXES
        "json_table",  # FROM JSON_TABLE(…): a table position; a call elsewhere
        "list",  # PARTITION BY LIST (…): DDL
        "query",  # KILL QUERY
        "starts",  # CREATE EVENT … STARTS: DDL
        "than",  # VALUES LESS THAN (…): DDL
        "until",  # REPEAT … UNTIL (10.11): compound statements
    },
}

# Reserved words that may stand right before `(` without being a call, in
# every series (ADR-0045 decision 7: `IN`, `VALUES`...), added when the
# grammar scan misses them. Form `k`. The drift test checks that each one,
# called plainly, is not resolved as a stored function.
COMMON_WORDS = {
    "all", "and", "any", "as", "between", "binary", "by", "call", "case",
    "check", "collate", "constraint", "cross", "default", "distinct", "div",
    "dual", "else", "elseif", "end", "except", "exists", "false", "force",
    "foreign", "from", "group", "having", "high_priority", "if", "ignore",
    "in", "index", "inner", "intersect", "interval", "into", "is", "join",
    "key", "like", "limit", "lock", "loop", "natural", "not", "null",
    "offset", "on", "or", "order", "outer", "over", "partition", "primary",
    "procedure", "recursive", "references", "regexp", "return", "returning",
    "rlike", "row", "select", "separator", "set", "some", "sounds",
    "straight_join", "then", "true", "union", "unique", "use", "using",
    "value", "values", "when", "where", "while", "window", "with", "xor",
}  # fmt: skip
EXTRA_WORDS: dict[str, set[str]] = {
    # Keywords of MySQL only (`LATERAL (SELECT …)`, `x MEMBER OF (…)`).
    "mysql": COMMON_WORDS | {"escape", "lateral", "member", "of", "until"},
    "mariadb": COMMON_WORDS,
}


def fetch(repo: str, tag: str, path: str, cache: Path | None) -> str:
    """One source file at a tag (cached when a cache directory is given)."""
    if cache is not None:
        local = cache / tag / path.replace("/", "_")
        if local.exists():
            return local.read_text(encoding="utf-8", errors="replace")
    url = f"https://raw.githubusercontent.com/{repo}/{tag}/{path}"
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 (fixed https host)
        text = r.read().decode("utf-8", errors="replace")
    if cache is not None:
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(text, encoding="utf-8")
    return text


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def without_debug_blocks(text: str) -> str:
    """Drops `#ifndef NDEBUG` / `#ifndef DBUG_OFF` blocks (debug builds only)."""
    out, skip = [], 0
    for line in text.splitlines():
        s = line.strip()
        if skip:
            if s.startswith("#if"):
                skip += 1
            elif s.startswith("#endif"):
                skip -= 1
            elif s.startswith("#else") and skip == 1:
                skip = 0
            continue
        if re.match(r"#\s*ifndef\s+(NDEBUG|DBUG_OFF)\b", s) or re.match(
            r"#\s*ifdef\s+(DBUG_ON|EXTRA_DEBUG)\b", s
        ):
            skip = 1
            continue
        out.append(line)
    return "\n".join(out)


def array_block(text: str, start_pattern: str) -> str:
    m = re.search(start_pattern, text)
    if not m:
        raise SystemExit(f"array not found: {start_pattern}")
    end = text.index("};", m.end())
    return text[m.end() : end]


def native_names(item_create: str, flavor: str) -> set[str]:
    text = without_debug_blocks(strip_c_comments(item_create))
    if flavor == "mysql":
        block = array_block(text, r"func_array\[\]\s*=\s*\{")
        return {n.lower() for n in re.findall(r'\{\s*"([A-Za-z0-9_]+)"\s*,', block)}
    block = array_block(text, r"Native_func_registry\s+func_array\[\]\s*=\s*\{")
    return {n.lower() for n in re.findall(r'STRING_WITH_LEN\("([A-Za-z0-9_]+)"\)', block)}


def geom_names(geofunc: str) -> set[str]:
    text = without_debug_blocks(strip_c_comments(geofunc))
    block = array_block(text, r"func_array_geom\[\]\s*=\s*\{")
    return {n.lower() for n in re.findall(r'STRING_WITH_LEN\("([A-Za-z0-9_]+)"\)', block)}


def plugin_function_names(plugin: str) -> set[str]:
    text = strip_c_comments(plugin)
    return {
        n.lower()
        for n in re.findall(r'MariaDB_FUNCTION_PLUGIN\s*,[^"]*"([A-Za-z0-9_]+)"', text)
    }


def lex_symbols(lex_h: str, flavor: str) -> tuple[dict[str, set[str]], set[str]]:
    """(token -> names, the `sql_functions` names) from `lex.h`."""
    text = strip_c_comments(lex_h)
    tokens: dict[str, set[str]] = {}
    functions: set[str] = set()
    if flavor == "mysql":
        for kind, name, tok in re.findall(
            r"\{\s*(SYM|SYM_FN|SYM_HK|SYM_H)\(\s*\"([A-Za-z0-9_]+)\"\s*,\s*([A-Za-z0-9_]+)\s*\)\s*\}",
            text,
        ):
            if kind == "SYM_H":
                continue  # optimizer hint names: inside `/*+ */` only
            tokens.setdefault(tok, set()).add(name.lower())
            if kind == "SYM_FN":
                functions.add(name.lower())
        return tokens, functions
    start = text.index("sql_functions[]")
    for m in re.finditer(r'\{\s*"([A-Za-z0-9_]+)"\s*,\s*SYM\(\s*([A-Za-z0-9_]+)\s*\)', text):
        name, tok = m.group(1).lower(), m.group(2)
        tokens.setdefault(tok, set()).add(name)
        if m.start() > start:
            functions.add(name)
    return tokens, functions


def mariadb_default_branches(yacc: str) -> str:
    """Keeps the `%ifdef MARIADB` branches, drops the `%ifdef ORACLE` ones."""
    out: list[str] = []
    stack: list[bool] = []
    for line in yacc.splitlines():
        s = line.strip()
        m = re.match(r"%(ifdef|ifndef)\s+(\w+)", s)
        if m:
            keep = (m.group(2) == "MARIADB") == (m.group(1) == "ifdef")
            stack.append(keep)
            continue
        if s.startswith("%else"):
            stack[-1] = not stack[-1]
            continue
        if s.startswith("%endif"):
            stack.pop()
            continue
        if all(stack):
            out.append(line)
    return "\n".join(out)


def grammar_rules(yacc: str) -> dict[str, list[list[str]]]:
    """The rules section, as nonterminal -> alternatives (symbol lists),
    with comments, actions (`{ ... }`) and `%prec` removed."""
    parts = yacc.split("\n%%")
    body = parts[1] if len(parts) > 1 else yacc
    out: list[str] = []
    i, n, depth = 0, len(body), 0
    while i < n:
        c = body[i]
        if body.startswith("/*", i):
            j = body.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        if body.startswith("//", i):
            j = body.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and body[j] != c:
                j += 2 if body[j] == "\\" else 1
            if depth == 0:
                out.append(body[i : j + 1])
            i = j + 1
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth = max(0, depth - 1)
            i += 1
            out.append(" ")
            continue
        if depth == 0:
            out.append(c)
        i += 1
    text = "".join(out)
    text = re.sub(r"%prec\s+\w+", " ", text)
    syms = re.findall(r"'[^']*'|\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_.]*|[:|;]", text)
    rules: dict[str, list[list[str]]] = {}
    k = 0
    while k + 1 < len(syms):
        if syms[k + 1] != ":" or syms[k] in ":|;":
            k += 1
            continue
        name = syms[k]
        k += 2
        alts: list[list[str]] = [[]]
        while k < len(syms):
            s = syms[k]
            # The next rule may start without a `;` (`a: x b: y` is invalid
            # bison, but be lenient).
            if s == ";":
                k += 1
                break
            if k + 1 < len(syms) and syms[k + 1] == ":" and s not in ":|;":
                break
            if s == "|":
                alts.append([])
            else:
                alts[-1].append(s)
            k += 1
        rules.setdefault(name, []).extend(alts)
    return rules


def keywords_before_paren(rules: dict[str, list[list[str]]], tokens: dict[str, set[str]]) -> set[str]:
    # Nonterminals with an alternative that starts with `(`.
    starts: set[str] = set()
    changed = True
    while changed:
        changed = False
        for nt, alts in rules.items():
            if nt in starts:
                continue
            if any(a and (a[0] == "'('" or a[0] in starts) for a in alts):
                starts.add(nt)
                changed = True
    names: set[str] = set()
    for alts in rules.values():
        for a in alts:
            for x, y in zip(a, a[1:]):
                if x in tokens and (y == "'('" or y in starts):
                    names |= tokens[x]
    return names


def extract(flavor: str, repo: str, tag: str, cache: Path | None) -> dict[str, str]:
    files = {p: fetch(repo, tag, p, cache) for p in COMMON_FILES}
    native = native_names(files["sql/item_create.cc"], flavor)
    if flavor == "mariadb":
        for p in MARIADB_FILES:
            text = fetch(repo, tag, p, cache)
            native |= geom_names(text) if p.endswith("item_geofunc.cc") else plugin_function_names(text)
    tokens, sql_functions = lex_symbols(files["sql/lex.h"], flavor)
    yacc = files["sql/sql_yacc.yy"]
    if flavor == "mariadb":
        yacc = mariadb_default_branches(yacc)
    keywords = keywords_before_paren(grammar_rules(yacc), tokens)
    keywords |= sql_functions
    keywords |= EXTRA_WORDS[flavor]
    keywords -= NOT_FUNCTIONS[flavor]
    forms: dict[str, str] = {}
    for name in keywords:
        forms[name] = "s" if name in sql_functions else "k"
    for name in native:
        forms[name] = "n"
    return forms


def merge(a: dict[str, str], b: dict[str, str]) -> dict[str, str]:
    """Union of two patch releases: a name keeps its most permissive form
    (`n` over `k` over `s`)."""
    rank = {"s": 0, "k": 1, "n": 2}
    out = dict(a)
    for name, form in b.items():
        if name not in out or rank[form] > rank[out[name]]:
            out[name] = form
    return out


def write_list(flavor: str, series: str, repo: str, tags: list[str], forms: dict[str, str]) -> Path:
    path = HERE / f"{flavor}-{series}.txt"
    title = "MySQL" if flavor == "mysql" else "MariaDB"
    lines = [
        f"# Built-in function names of {title} {series} (ADR-0045 decision 7).",
        "# Generated by extract.py from the server parser sources; do not edit by hand.",
        f"# source: {repo} {' '.join(tags)}",
        "# form: n = native (plain, backquoted or spaced), k = keyword (plain, spaced),",
        "#       s = keyword right before ( only (lex.h sql_functions)",
    ]
    lines += [f"{name} {forms[name]}" for name in sorted(forms)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--cache", type=Path, help="directory for the fetched sources")
    args = ap.parse_args()
    for flavor, series, repo, tags in SERIES:
        forms: dict[str, str] = {}
        for tag in tags:
            forms = merge(forms, extract(flavor, repo, tag, args.cache))
        path = write_list(flavor, series, repo, tags, forms)
        counts = {f: sum(1 for v in forms.values() if v == f) for f in "nks"}
        print(f"{path.name}: {len(forms)} names {counts}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main())
