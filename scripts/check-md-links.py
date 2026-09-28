#!/usr/bin/env python3
"""Checks that relative links in Markdown files point to existing files."""

import os
import re
import sys

LINK = re.compile(r"\]\(([^)#\s]+)(#[^)]*)?\)")
SKIP_DIRS = {".git", "node_modules", "target", ".next"}

broken = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for name in files:
        if not name.endswith(".md"):
            continue
        path = os.path.join(root, name)
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                for m in LINK.finditer(line):
                    target = m.group(1)
                    if re.match(r"^[a-z]+:", target):  # http:, https:, mailto:…
                        continue
                    if not os.path.exists(os.path.normpath(os.path.join(root, target))):
                        broken.append(f"{path}:{lineno}: {target}")

for b in broken:
    print(f"broken link: {b}")
print(f"{len(broken)} broken link(s)")
sys.exit(1 if broken else 0)
