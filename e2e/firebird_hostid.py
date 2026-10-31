#!/usr/bin/env python3
"""Preconditions of the e2e-firebird run on the host's own identity files (ADR-0060 refinement of
2026-10-31, R52 item 2), checked before anything starts. The run mounts the host's (in CI: the
runner's) /etc/passwd, /etc/group and /etc/nsswitch.conf, and /etc/subuid and /etc/subgid when
present, read-only into the agent's container; Partial is then honest only if:

  - each file is a regular file owned by root, not group- or other-writable, with one hard link
    (R45 items 1, 3 and 4: the agent refuses it otherwise, and the run must fail here, not later);
  - each parses under the agent's strict grammar (R45 item 7: comments, compat lines, whitespace in
    names, a database named on two nsswitch lines... are `malformed`);
  - nsswitch.conf's `passwd:` line names only `files` and `systemd` (R47 item 2, N2: otherwise the
    readers check fails, `host_identity_nss`); another source on `group:` or `initgroups:` makes
    every group open, which the run's named-user ACL layout (no group grants read) allows;
  - the server's uid (84) and the agent's uid (10001) are absent from the passwd file, outside the
    subordinate ranges (or, without the files or with a `subid:` line naming another source, below
    100000), outside systemd's ranges and not a reserved uid (R48 items 3, 4 and 4a);
  - the uid of the negative step "the agent as a host user's uid" is present in the passwd file
    (R52 item 2: the runner's uid 1001).

The script never edits a file, never picks other uids, and prints counts and verdicts only: no
user or group name and no file content (the files are the host's).

  firebird_hostid.py check [--root /] [--uid 84 --uid 10001] [--present-uid 1001]
      exit 0: every precondition holds; 1: one fails (reasons printed); 2: usage.
  The paths of the files the run mounts, one per line (`--list`), for docker-compose.firebird.yml's
  generated host identity mounts.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys

# The agent's constants (agent/crates/connector-firebird/src/host_identity.rs).
RESERVED_UIDS = (65534, 4294967294, 4294967295)
SYSTEMD_RANGES = ((60001, 60513), (61184, 65519), (524288, 1879048191), (2147352576, 2147418111))
SUBORDINATE_FLOOR = 100000
MAX_LINES = 65536
BOUNDS = {"passwd": 4 << 20, "group": 4 << 20, "subuid": 1 << 20, "subgid": 1 << 20,
          "nsswitch.conf": 64 << 10}
REQUIRED = ("passwd", "group", "nsswitch.conf")
OPTIONAL = ("subuid", "subgid")


class Malformed(ValueError):
    pass


def _lines(b: bytes) -> list[bytes]:
    if b.endswith(b"\n"):
        b = b[:-1]
    if not b:
        return []
    out = b.split(b"\n")
    if len(out) > MAX_LINES:
        raise Malformed("too many lines")
    return out


def _dec(s: bytes, top: int) -> int | None:
    if not s or len(s) > 20 or not s.isdigit() or not all(48 <= c <= 57 for c in s):
        return None
    n = int(s)
    return n if n <= top else None


def _name_ok(s: bytes) -> bool:
    return bool(s) and s[:1] not in (b"#", b"+", b"-") and not any(c in b" \t\n\r\x0b\x0c" for c in s)


def parse_passwd(b: bytes) -> list[tuple[bytes, int, int]]:
    out = []
    for line in _lines(b):
        if not line:
            continue
        f = line.split(b":")
        if len(f) != 7 or not _name_ok(f[0]):
            raise Malformed("passwd line")
        uid, gid = _dec(f[2], 2**32 - 2), _dec(f[3], 2**32 - 2)
        if uid is None or gid is None:
            raise Malformed("passwd id")
        out.append((f[0], uid, gid))
    return out


def parse_group(b: bytes) -> list[tuple[int, list[bytes]]]:
    out = []
    for line in _lines(b):
        if not line:
            continue
        f = line.split(b":")
        if len(f) != 4 or not _name_ok(f[0]):
            raise Malformed("group line")
        gid = _dec(f[2], 2**32 - 2)
        if gid is None:
            raise Malformed("group id")
        members = [m for m in f[3].split(b",") if m]
        if any(any(c in b" \t\n\r\x0b\x0c" for c in m) for m in members):
            raise Malformed("group member")
        out.append((gid, members))
    return out


def parse_subid(b: bytes) -> list[tuple[int, int]]:
    out = []
    for line in _lines(b):
        if not line:
            continue
        f = line.split(b":")
        if len(f) != 3 or not _name_ok(f[0]):
            raise Malformed("subid line")
        start, count = _dec(f[1], 2**64 - 1), _dec(f[2], 2**64 - 1)
        if start is None or count is None:
            raise Malformed("subid range")
        out.append((start, count))
    return out


def _source_ok(tok: bytes) -> bool:
    return bool(tok) and all(48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b"_-."
                             for c in tok)


def parse_nsswitch(b: bytes) -> dict[str, list[str]]:
    """The databases the readers check reads, as the agent parses the file (R45 item 7 and the
    implementation note of 2026-10-31 b, item 4)."""
    seen: set[bytes] = set()
    out: dict[str, list[str]] = {}
    for raw in _lines(b):
        line = raw.split(b"#", 1)[0].strip(b" \t\r\x0b\x0c")
        if not line:
            continue
        if b":" not in line:
            raise Malformed("nsswitch line without ':'")
        db, rest = line.split(b":", 1)
        if not db or any(c in b" \t\r\x0b\x0c" for c in db) or db in seen:
            raise Malformed("nsswitch database")
        seen.add(db)
        sources: list[str] = []
        in_action = False
        for tok in rest.split():
            opens = tok[:1] == b"["
            if opens and in_action:
                raise Malformed("nsswitch action item")
            if opens or in_action:
                body = tok[1:] if opens else tok
                if b"[" in body:
                    raise Malformed("nsswitch action item")
                i = body.find(b"]")
                if i == -1:
                    in_action = True
                elif i + 1 == len(body):
                    in_action = False
                else:
                    raise Malformed("nsswitch action item")
                continue
            if not _source_ok(tok):
                raise Malformed("nsswitch source")
            sources.append(tok.decode("ascii"))
        if in_action or not sources:
            raise Malformed("nsswitch line")
        if db in (b"passwd", b"group", b"initgroups", b"subid"):
            out[db.decode("ascii")] = sources
    return out


def in_systemd_range(uid: int) -> bool:
    return any(lo <= uid <= hi for lo, hi in SYSTEMD_RANGES)


def in_ranges(uid: int, ranges: list[tuple[int, int]] | None) -> bool:
    if ranges is None:
        return uid >= SUBORDINATE_FLOOR
    return any(start <= uid < start + count for start, count in ranges)


def file_problem(path: str, bound: int) -> tuple[str | None, bytes]:
    """The reason a file is not one the agent accepts on its handle (kind only), and its content."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "missing", b""
    except OSError:
        return "not_readable", b""
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file", b""
    if st.st_nlink != 1:
        return "links", b""
    if st.st_uid != 0:
        return "owner", b""
    if st.st_mode & 0o022:
        return "mode", b""
    if st.st_size > bound:
        return "too_large", b""
    try:
        with open(path, "rb") as f:
            data = f.read(bound + 1)
    except OSError:
        return "not_readable", b""
    if len(data) > bound:
        return "too_large", b""
    return None, data


def check(root: str, uids: list[int], present_uid: int | None, out) -> tuple[list[str], list[str]]:
    """(errors, the files to mount), printing one verdict line per check."""
    errors: list[str] = []
    mounts: list[str] = []
    data: dict[str, bytes] = {}
    for name in REQUIRED + OPTIONAL:
        path = os.path.join(root, "etc", name)
        why, content = file_problem(path, BOUNDS[name])
        if why == "missing" and name in OPTIONAL:
            print(f"hostid: /etc/{name}: absent (not mounted; ids of {SUBORDINATE_FLOOR} or more "
                  "count as subordinate)", file=out)
            continue
        if why:
            errors.append(f"/etc/{name}: {why}")
            continue
        data[name] = content
        mounts.append(f"/etc/{name}")
    users: list[tuple[bytes, int, int]] = []
    try:
        if "passwd" in data:
            users = parse_passwd(data["passwd"])
            print(f"hostid: /etc/passwd: {len(users)} line(s), strict grammar", file=out)
        if "group" in data:
            print(f"hostid: /etc/group: {len(parse_group(data['group']))} line(s), strict grammar",
                  file=out)
    except Malformed as e:
        errors.append(f"malformed under the agent's grammar ({e})")
    sub: dict[str, list[tuple[int, int]] | None] = {"subuid": None, "subgid": None}
    for name in OPTIONAL:
        if name in data:
            try:
                sub[name] = parse_subid(data[name])
                print(f"hostid: /etc/{name}: {len(sub[name] or [])} range(s)", file=out)
            except Malformed as e:
                errors.append(f"/etc/{name}: malformed ({e})")
    nss: dict[str, list[str]] = {}
    if "nsswitch.conf" in data:
        try:
            nss = parse_nsswitch(data["nsswitch.conf"])
        except Malformed as e:
            errors.append(f"/etc/nsswitch.conf: malformed ({e})")
    if "nsswitch.conf" in data and not errors:
        passwd = nss.get("passwd")
        if not passwd or any(s not in ("files", "systemd") for s in passwd):
            errors.append("/etc/nsswitch.conf: the passwd: line names a source other than files and "
                          "systemd, or is missing (R47: host_identity_nss)")
        else:
            print(f"hostid: nsswitch passwd: {' '.join(passwd)} (accepted, R47 N2)", file=out)
        if "group" not in nss:
            errors.append("/etc/nsswitch.conf: no group: line (R47: host_identity_nss)")
        else:
            groups_ok = nss["group"] == ["files"] and nss.get("initgroups", ["files"]) == ["files"]
            print("hostid: nsswitch group: " + " ".join(nss["group"])
                  + ("" if "initgroups" not in nss else "; initgroups: " + " ".join(nss["initgroups"]))
                  + (" (groups provable)" if groups_ok else
                     " (another source: every group that grants read is open; the run's layout "
                     "gives no group read, named-user ACLs only)"), file=out)
        if any(s != "files" for s in nss.get("subid", ["files"])):
            sub = {"subuid": None, "subgid": None}
            print("hostid: nsswitch subid: another source (ids of "
                  f"{SUBORDINATE_FLOOR} or more count as subordinate)", file=out)
    passwd_uids = {u for _, u, _ in users}
    for uid in uids:
        if uid in RESERVED_UIDS:
            errors.append(f"uid {uid}: reserved (R48 item 3)")
        if uid in passwd_uids:
            errors.append(f"uid {uid}: present in /etc/passwd (R48 item 4: the job fails rather than "
                          "picking another uid)")
        if in_systemd_range(uid):
            errors.append(f"uid {uid}: inside a systemd range (R48 item 4a)")
        if in_ranges(uid, sub["subuid"]):
            errors.append(f"uid {uid}: inside a subordinate uid range (R48 item 4a)")
        if not any(e.startswith(f"uid {uid}:") for e in errors):
            print(f"hostid: uid {uid}: absent from /etc/passwd, outside the subordinate and systemd "
                  "ranges", file=out)
    if present_uid is not None:
        if present_uid in passwd_uids:
            print(f"hostid: uid {present_uid}: present in /etc/passwd (the uid_collision step)",
                  file=out)
        else:
            errors.append(f"uid {present_uid}: absent from /etc/passwd (needed by the uid_collision "
                          "step, R52 item 2)")
    return errors, mounts


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--root", default="/")
    c.add_argument("--uid", type=int, action="append", default=[])
    c.add_argument("--present-uid", type=int)
    c.add_argument("--list", metavar="FILE", help="write the paths to mount, one per line")
    args = p.parse_args(argv)
    if args.list and os.path.realpath(args.root) != "/":
        # The listed paths are the ones mounted into the agent: only the host's own files.
        p.error("--list is only for --root /")
    errors, mounts = check(args.root, args.uid or [84, 10001], args.present_uid, sys.stdout)
    for e in errors:
        print(f"hostid: FAIL {e}")
    if args.list and not errors:
        with open(args.list, "w", encoding="ascii") as f:
            f.write("".join(m + "\n" for m in mounts))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
