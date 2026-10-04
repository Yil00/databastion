#!/usr/bin/env python3
"""Dev-only CAS overlay, second step (dev/cas/Dockerfile): adds the module jars resolved by
build.gradle to the published apereo/cas war. Python standard library and the JDK `jar` tool.

    merge.py <cas.war> <modules dir> <CAS version> <Spring Boot version> <output war>

- The war must be the expected CAS version and Spring Boot version (its manifest's
  Implementation-Version and Spring-Boot-Version), the versions build.gradle resolved against.
- The war's libraries are identified by its CycloneDX SBOM (group, name, version), so that two
  artifacts with the same name in different groups (Jackson 2 and Jackson 3 modules) are told
  apart; a jar of the war that the SBOM does not list is matched by file name.
- A resolved jar already in WEB-INF/lib (same file name) is skipped. A resolved artifact that the
  war holds under another version fails the build: the war and the modules come from the same CAS
  BOM, so it means a drift to look at, never a silent second copy on the class path.
- New jars are added STORED (uncompressed), as Spring Boot's launcher needs nested jars.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SBOM = "WEB-INF/classes/META-INF/sbom/application.cdx.json"
LIB = "WEB-INF/lib/"


def main(war: str, modules: str, version: str, boot: str, out: str) -> int:
    with zipfile.ZipFile(war) as z:
        manifest = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        sbom = json.loads(z.read(SBOM))
        libs = {n[len(LIB):] for n in z.namelist()
                if n.startswith(LIB) and n.endswith(".jar") and "/" not in n[len(LIB):]}
    for key, want in (("Implementation-Version", version), ("Spring-Boot-Version", boot)):
        got = re.search(rf"^{key}: *(\S+)", manifest, re.M)
        if not got or got.group(1) != want:
            print(f"merge.py: the war's {key} is {got.group(1) if got else '?'}, expected {want}",
                  file=sys.stderr)
            return 1

    known: dict[tuple[str, str], set[str]] = {}
    sbom_files: set[str] = set()
    for c in sbom.get("components", []):
        group, name, ver = c.get("group", ""), c.get("name", ""), c.get("version", "")
        known.setdefault((group, name), set()).add(ver)
        sbom_files.add(f"{name}-{ver}.jar")
    unlisted = libs - sbom_files

    add, same, conflicts = [], 0, []
    for line in Path(modules, "modules.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        group, name, ver, file = line.split()
        if file in libs:
            same += 1
            continue
        other = known.get((group, name), set()) - {ver}
        prefix = re.compile(re.escape(name) + r"-[0-9][^/]*\.jar")
        other |= {f for f in unlisted if prefix.fullmatch(f)}
        if other:
            conflicts.append(f"{group}:{name}:{ver} resolved, the war holds {sorted(other)}")
            continue
        add.append(file)
    for c in conflicts:
        print(f"merge.py: conflict: {c}", file=sys.stderr)
    if conflicts:
        print(f"merge.py: {len(conflicts)} version conflict(s) with the war: align build.gradle",
              file=sys.stderr)
        return 1

    shutil.copyfile(war, out)
    if add:
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp, LIB)
            lib.mkdir(parents=True)
            for f in add:
                shutil.copyfile(Path(modules, f), lib / f)
            subprocess.run(["jar", "--update", "--no-compress", "--file", out, LIB],
                           cwd=tmp, check=True)
    with zipfile.ZipFile(out) as z:
        compressed = [i.filename for i in z.infolist()
                      if i.filename.startswith(LIB) and i.compress_type != zipfile.ZIP_STORED]
    if compressed:
        print(f"merge.py: {len(compressed)} nested jar(s) compressed in the output", file=sys.stderr)
        return 1
    print(f"merge.py: CAS {version} war: {len(add)} jar(s) added, {same} already in the war")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
