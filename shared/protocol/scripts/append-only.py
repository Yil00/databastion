#!/usr/bin/env python3
"""Append-only check of the protocol registries against one or more base commits.

Usage: python3 shared/protocol/scripts/append-only.py REF [REF...]   (from the repository root)

Every REF must resolve (the CI passes origin/dev, origin/main and, on push, the previous tip).
For each REF where a registry exists, the working tree must keep what REF published:
- classifiers.lock.json: every version, with the same hash (published classifier sets are
  immutable; a new version is a new key);
- signals.json, target-notes.json: every id, with at least its engines (new ids and new engines
  may be added; a description may be reworded, which reviewers check keeps the meaning).
A registry missing from the working tree while REF has it fails like a removal of every entry.
Standard library only; exits 1 with GitHub `::error` annotations on any violation.
"""

import json
import subprocess
import sys

LOCK = "shared/protocol/classifiers.lock.json"
ID_REGISTRIES = ("shared/protocol/signals.json", "shared/protocol/target-notes.json")


def git(*args, check=True):
    return subprocess.run(["git", *args], check=check, capture_output=True, text=True)


def load_at(ref, path):
    """The JSON object `path` at `ref`, or None when `ref` does not have the file."""
    if git("cat-file", "-e", f"{ref}:{path}", check=False).returncode != 0:
        return None
    return json.loads(git("show", f"{ref}:{path}").stdout)


def load_head(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def show(value):
    """A registry key or ref as printed: JSON-quoted (no newline or control character survives,
    so a key cannot start a `::` workflow command) and with `%` escaped as GitHub annotations
    expect."""
    return json.dumps(str(value)).replace("%", "%25")


def engines(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("engines"), list):
        return set()
    return {e for e in entry["engines"] if isinstance(e, str)}


def lock_errors(base, head):
    errors = []
    for version, digest in base.items():
        if version not in head:
            errors.append(f"published version {show(version)} was removed")
        elif head[version] != digest:
            errors.append(f"published version {show(version)} was changed")
    return errors


def id_errors(base, head):
    errors = []
    for key, entry in base.items():
        if key not in head:
            errors.append(f"registered id {show(key)} was removed or renamed")
        else:
            lost = sorted(engines(entry) - engines(head[key]))
            if lost:
                errors.append(f"registered id {show(key)} lost engine(s) {', '.join(show(e) for e in lost)}")
    return errors


def main(refs):
    if not refs:
        sys.exit("usage: append-only.py REF [REF...]")
    failed = False
    for ref in refs:
        if git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False).returncode != 0:
            print(f"::error::append-only check: {show(ref)} does not resolve")
            failed = True
            continue
        for path, check in [(LOCK, lock_errors)] + [(p, id_errors) for p in ID_REGISTRIES]:
            base = load_at(ref, path)
            if base is None:
                print(f"{path}: absent at {show(ref)}, nothing to compare")
                continue
            head = load_head(path)
            if not isinstance(base, dict) or not isinstance(head, dict):
                print(f"::error file={path}::must be a JSON object")
                failed = True
                continue
            errors = check(base, head)
            for e in errors:
                print(f"::error file={path}::{e} since {show(ref)} (append-only: add a new entry instead)")
            failed |= bool(errors)
            if not errors:
                added = sorted(set(head) - set(base))
                shown = ", ".join(show(k) for k in added) or "none"
                print(f"{path}: {len(base)} entr(y/ies) of {show(ref)} kept; added: {shown}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
