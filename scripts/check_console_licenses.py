#!/usr/bin/env python3
"""Console dependency license gate (invariant I7), Python standard library only.

Reads the output of `pnpm licenses list --prod --json` (run in console/) and fails on any production
dependency whose license is outside the allow-list of agent/deny.toml (`[licenses] allow`, the same
policy as the agent's cargo-deny check), unless the package is listed in
scripts/console-license-exceptions.json with a written reason.

License expressions are evaluated conservatively:
  - `A OR B`: allowed if at least one side is allowed;
  - `A AND B`: allowed only if both sides are allowed;
  - `A WITH exception`: allowed only if the whole `A WITH exception` term is in the allow-list;
  - `A+` (or later): allowed if `A` is allowed;
  - parentheses are supported; anything unparseable, empty, `UNKNOWN`, `UNLICENSED`,
    `SEE LICENSE IN ...` or a custom `LicenseRef-*` is refused.
A few non-SPDX spellings seen in package.json files are mapped to their SPDX id (ALIASES); any other
spelling is refused, so that a human looks at it.

Exceptions match a package name (fnmatch glob, e.g. platform variants) AND its exact license string:
a license change of an excepted package fails again. Each needs a non-empty "reason". An exception
that matches nothing is reported as a warning (remove it).

Usage: check_console_licenses.py [--deny-toml agent/deny.toml]
                                 [--exceptions scripts/console-license-exceptions.json] LICENSES_JSON
Exit status: 0 ok, 1 license violation, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DENY_TOML = os.path.join(REPO, "agent", "deny.toml")
DEFAULT_EXCEPTIONS = os.path.join(REPO, "scripts", "console-license-exceptions.json")

# Non-SPDX spellings -> SPDX id. Exact matches only (after trimming); keep it short and obvious.
ALIASES: dict[str, str] = {
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "Apache-2": "Apache-2.0",
    "MIT License": "MIT",
    "BSD-3": "BSD-3-Clause",
    "BSD-2": "BSD-2-Clause",
    "ISC License": "ISC",
}

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


class ExpressionError(ValueError):
    pass


def tokenize(expr: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    expr = expr.rstrip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise ExpressionError(f"unexpected character at {pos}")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ExpressionError("empty expression")
    return tokens


class _Parser:
    """SPDX expression: or := and ('OR' and)* ; and := atom ('AND' atom)* ;
    atom := '(' or ')' | id ['WITH' id]. Operators are case-insensitive."""

    def __init__(self, tokens: list[str], allowed: set[str]) -> None:
        self.t = tokens
        self.i = 0
        self.allowed = allowed

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ExpressionError("unexpected end of expression")
        self.i += 1
        return tok

    @staticmethod
    def is_op(tok: str | None, op: str) -> bool:
        return tok is not None and tok.upper() == op

    def parse(self) -> bool:
        value = self.or_expr()
        if self.peek() is not None:
            raise ExpressionError(f"unexpected token {self.peek()!r}")
        return value

    def or_expr(self) -> bool:
        value = self.and_expr()
        while self.is_op(self.peek(), "OR"):
            self.take()
            rhs = self.and_expr()
            value = value or rhs
        return value

    def and_expr(self) -> bool:
        value = self.atom()
        while self.is_op(self.peek(), "AND"):
            self.take()
            rhs = self.atom()
            value = value and rhs
        return value

    def atom(self) -> bool:
        tok = self.take()
        if tok == "(":
            value = self.or_expr()
            if self.take() != ")":
                raise ExpressionError("missing ')'")
            return value
        if tok == ")" or any(self.is_op(tok, op) for op in ("AND", "OR", "WITH")):
            raise ExpressionError(f"unexpected token {tok!r}")
        if self.is_op(self.peek(), "WITH"):
            self.take()
            exc = self.take()
            if exc in ("(", ")") or any(self.is_op(exc, op) for op in ("AND", "OR", "WITH")):
                raise ExpressionError("WITH needs an exception id")
            return f"{tok} WITH {exc}" in self.allowed
        return license_id_allowed(tok, self.allowed)


def license_id_allowed(lic: str, allowed: set[str]) -> bool:
    if lic.upper().startswith("LICENSEREF-") or lic.upper() in ("UNKNOWN", "UNLICENSED", "NONE"):
        return False
    if lic in allowed:
        return True
    return lic.endswith("+") and lic[:-1] in allowed


def expression_allowed(expr: str, allowed: set[str]) -> bool:
    """True if the license expression is acceptable under the allow-list; False otherwise
    (including anything that cannot be parsed)."""
    if not isinstance(expr, str):
        return False
    s = ALIASES.get(expr.strip(), expr.strip())
    if not s or s.upper().startswith("SEE LICEN"):
        return False
    try:
        return _Parser(tokenize(s), allowed).parse()
    except ExpressionError:
        return False


def load_allow_list(path: str) -> set[str]:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    allow = data.get("licenses", {}).get("allow")
    if not isinstance(allow, list) or not allow or not all(isinstance(x, str) for x in allow):
        raise ValueError(f"{path}: no [licenses] allow list")
    return set(allow)


@dataclass
class Exception_:
    package: str
    license: str
    reason: str
    used: bool = False


def load_exceptions(path: str | None) -> list[Exception_]:
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected an object with an \"exceptions\" array")
    out = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or set(e) != {"package", "license", "reason"}:
            raise ValueError(f"{path}: exceptions[{i}] needs exactly package, license and reason")
        if not all(isinstance(e[k], str) and e[k].strip() for k in e):
            raise ValueError(f"{path}: exceptions[{i}]: empty package, license or reason")
        out.append(Exception_(e["package"], e["license"], e["reason"].strip()))
    return out


@dataclass
class Package:
    name: str
    versions: list[str]
    license: str


def load_packages(path: str) -> list[Package]:
    """`pnpm licenses list --json` output: {license: [{name, versions, ...}, ...]}."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object keyed by license")
    out = []
    for lic, pkgs in data.items():
        if not isinstance(pkgs, list):
            raise ValueError(f"{path}: {lic!r} is not a list of packages")
        for p in pkgs:
            if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                raise ValueError(f"{path}: a package entry under {lic!r} has no name")
            # Some pnpm versions repeat the license per package; the key is authoritative only
            # if the entry has none.
            pkg_lic = p.get("license") if isinstance(p.get("license"), str) else lic
            out.append(Package(p["name"], [str(v) for v in p.get("versions") or []], pkg_lic))
    return out


def check(packages: list[Package], allowed: set[str],
          exceptions: list[Exception_]) -> tuple[list[str], list[str], list[str]]:
    """Returns (errors, excepted, warnings), one line per package."""
    errors: list[str] = []
    excepted: list[str] = []
    for p in sorted(packages, key=lambda p: (p.name, p.license)):
        if expression_allowed(p.license, allowed):
            continue
        label = f"{p.name}@{','.join(p.versions) or '?'}: {p.license!r}"
        match = next((e for e in exceptions
                      if fnmatch.fnmatchcase(p.name, e.package) and e.license == p.license), None)
        if match:
            match.used = True
            excepted.append(f"{label} (exception: {match.reason})")
        else:
            errors.append(f"{label} is not in the allow-list of agent/deny.toml")
    warnings = [f"unused exception {e.package} {e.license!r}: remove it" for e in exceptions
                if not e.used]
    return errors, excepted, warnings


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--deny-toml", default=DEFAULT_DENY_TOML)
    p.add_argument("--exceptions", default=DEFAULT_EXCEPTIONS)
    p.add_argument("licenses_json")
    args = p.parse_args(argv)
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    try:
        allowed = load_allow_list(args.deny_toml)
        exceptions = load_exceptions(args.exceptions)
        packages = load_packages(args.licenses_json)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        print(f"license check: error: {e}", file=out)
        return 2
    if not packages:
        print("license check: no package listed: the check would prove nothing", file=out)
        return 2
    errors, excepted, warnings = check(packages, allowed, exceptions)
    print(f"license check: {len(packages)} production package(s), allow-list of "
          f"{len(allowed)} license(s) from {os.path.relpath(args.deny_toml, REPO)}", file=out)
    for line in excepted:
        print(f"license check: excepted {line}", file=out)
    for line in warnings:
        print(f"::warning::license check: {line}" if gha else f"license check: WARNING {line}",
              file=out)
    for line in errors:
        print(f"::error::license check: {line}" if gha else f"license check: FAIL {line}", file=out)
    if errors:
        print(f"license check: {len(errors)} package(s) with a license outside the allow-list; "
              "replace the dependency, or add an exception with a written reason to "
              "scripts/console-license-exceptions.json (reviewed like code)", file=out)
        return 1
    print("license check: ok", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
