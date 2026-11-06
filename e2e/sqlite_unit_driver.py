#!/usr/bin/env python3
"""The agent's stand-in under the shipped systemd unit (e2e/sqlite-unit.sh, ROADMAP P10-A).

Run by e2e/sqlite-unit.sh as the unit's ExecStart (a drop-in under /run replaces ExecStart and
Restart only), so this process has every sandbox property of
deploy/deb/databastion-agent.service: User=databastion, NoNewPrivileges, ProtectSystem=strict,
RestrictAddressFamilies, RestrictNamespaces, MemoryDenyWriteExecute, SystemCallFilter (with
SystemCallErrorNumber=EPERM), and the rest. It starts the installed binary's SQLite reader the way
the agent does (ADR-0059 decision 4: posix_spawn of the binary with the mode as its only argument,
an empty environment, one end of a Unix socket pair as its standard input, /dev/null as its output),
then drives it over the reader's IPC (agent/crates/connector-sqlite/src/ipc.rs) through a whole
unit of work: open, catalog, one sample, close.

Proves, on this system's systemd and kernel:
  - the unit's own filter is in effect here (bind() refused with EPERM, Seccomp mode 2);
  - the reader inherits it (same filter count before its open) and stacks its own seccomp filter on
    top of it (one more filter after its open, Landlock applied: the reader answers `opened` only
    once its Landlock ruleset is enforced, its filter applied and its self-check passed; there is
    no fallback), so the unit's filter lets the sandbox calls through;
  - the reader reads the seeded file (the catalog names the table, a sample returns its rows; no
    value is printed) and exits 0 after `close`: no system call it makes is refused by the unit,
    and no signal killed it.

Prints `sqlite-unit-check-ok ...` on success; exits 1 with a reason otherwise. Standard library only.
"""

import os
import socket
import struct
import sys

READER = "/usr/bin/databastion-agent"
TABLE = b"clients"
COLUMN = b"email"
ROWS = 10

# ipc.rs CODES, in order (tag = index).
CODES = [
    "not_found", "not_readable", "path_refused", "writable", "filesystem_not_read_only",
    "network_filesystem", "sandbox_unavailable", "self_check_failed", "unrecognized_file_format",
    "wal_files_not_readable", "wal_too_large", "hot_journal", "rollback_mode_not_read", "busy",
    "interrupted", "no_memory", "too_big", "corrupt", "no_rowid", "no_such_table",
    "view_prohibited", "auth", "file_changed", "side_file_appeared", "protocol", "internal",
]


def fail(msg):
    print("sqlite-unit-check FAIL: " + msg, flush=True)
    sys.exit(1)


def status(pid):
    out = {}
    with open("/proc/%s/status" % pid, encoding="ascii", errors="replace") as f:
        for line in f:
            k, _, v = line.partition(":")
            out[k] = v.strip()
    return out


def raw(b):
    return struct.pack(">I", len(b)) + b


def frame(body):
    return struct.pack(">I", len(body)) + body


class Reader:
    def __init__(self, buf):
        self.buf = buf

    def take(self, n):
        if n > len(self.buf):
            fail("short response")
        head, self.buf = self.buf[:n], self.buf[n:]
        return head

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def i64(self):
        return struct.unpack(">q", self.take(8))[0]

    def bytes(self):
        return self.take(self.u32())


def recv_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            fail("the reader closed its channel (it died or refused)")
        out += chunk
    return out


def call(sock, body):
    sock.sendall(frame(body))
    n = struct.unpack(">I", recv_exact(sock, 4))[0]
    if n > 1024 * 1024:
        fail("response over the IPC bound")
    r = Reader(recv_exact(sock, n))
    tag = r.u8()
    if tag == 0x80:
        code = r.u8()
        fail("the reader refused: %s" % (CODES[code] if code < len(CODES) else "code %d" % code))
    return tag, r


def main():
    if len(sys.argv) != 2:
        fail("usage: sqlite_unit_driver.py DATABASE")
    path = os.fsencode(sys.argv[1])
    me = status("self")
    if me.get("NoNewPrivs") != "1" or me.get("Seccomp") != "2":
        fail("not under the unit's sandbox (NoNewPrivs %s, Seccomp %s)"
             % (me.get("NoNewPrivs"), me.get("Seccomp")))
    unit_filters = int(me.get("Seccomp_filters", "0"))
    if unit_filters < 1:
        fail("no seccomp filter from the unit")
    # The unit's SystemCallFilter=~bind ... with SystemCallErrorNumber=EPERM.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        fail("bind() was allowed: the unit's system-call filter is not in effect")
    except PermissionError:
        pass
    finally:
        s.close()

    agent, reader = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    devnull = os.open("/dev/null", os.O_RDWR)
    pid = os.posix_spawn(
        READER, [READER, "sqlite-reader"], {},
        file_actions=[
            (os.POSIX_SPAWN_DUP2, reader.fileno(), 0),
            (os.POSIX_SPAWN_DUP2, devnull, 1),
            (os.POSIX_SPAWN_DUP2, devnull, 2),
        ])
    reader.close()
    os.close(devnull)
    agent.settimeout(20)
    try:
        before = int(status(pid).get("Seccomp_filters", "0"))
        if before != unit_filters:
            fail("the reader has %d seccomp filter(s) before its open, the unit %d" % (before, unit_filters))

        # Open: the path, max_statement_ms 500, rollback_read (a rollback-journal file).
        tag, r = call(agent, bytes([1]) + raw(path) + struct.pack(">I", 500) + bytes([1]))
        if tag != 0x81:
            fail("open: response tag %#x" % tag)
        r.take(16)  # dev, ino
        wal = r.u8()
        if wal != 0:
            fail("open: the seeded file reads as WAL")
        st = status(pid)
        after = int(st.get("Seccomp_filters", "0"))
        if st.get("NoNewPrivs") != "1" or st.get("Seccomp") != "2" or after != unit_filters + 1:
            fail("reader after its open: NoNewPrivs %s, Seccomp %s, filters %d (unit %d)"
                 % (st.get("NoNewPrivs"), st.get("Seccomp"), after, unit_filters))

        tag, r = call(agent, bytes([2]))
        if tag != 0x82:
            fail("catalog: response tag %#x" % tag)
        r.u8()  # cut
        names = []
        for _ in range(r.u32()):
            r.u8()  # view
            names.append(r.bytes())
            r.i64()  # rootpage
        if TABLE not in names:
            fail("catalog: the seeded table is missing (%d object(s))" % len(names))

        # Sample: the table, rowid alias `rowid`, one column, rowid >= 1, ROWS rows.
        body = (bytes([6]) + raw(TABLE) + bytes([1]) + struct.pack(">I", 1) + raw(COLUMN)
                + bytes([1]) + struct.pack(">q", 1) + struct.pack(">I", ROWS))
        tag, r = call(agent, body)
        if tag != 0x86:
            fail("sample: response tag %#x" % tag)
        rows = r.u32()
        if r.u8() == 1:
            r.i64()  # last rowid
        r.u8()  # truncated
        ncols = r.u32()
        present = 0
        for _ in range(ncols * rows):
            if r.u8() == 1:
                v = r.bytes()  # never printed
                present += 1 if b"@" in v else 0
                del v
        if rows != ROWS or ncols != 1 or present != ROWS:
            fail("sample: %d row(s), %d column(s), %d value(s) read, expected %d" % (rows, ncols, present, ROWS))

        tag, _ = call(agent, bytes([9]))
        if tag != 0x89:
            fail("close: response tag %#x" % tag)
    finally:
        agent.close()
    _, wstatus = os.waitpid(pid, 0)
    if os.WIFSIGNALED(wstatus):
        fail("the reader was killed by signal %d" % os.WTERMSIG(wstatus))
    if os.waitstatus_to_exitcode(wstatus) != 0:
        fail("the reader exited %d" % os.waitstatus_to_exitcode(wstatus))
    print("sqlite-unit-check-ok seccomp filters: unit %d, reader %d; catalog %d object(s); %d row(s) sampled"
          % (unit_filters, unit_filters + 1, len(names), ROWS), flush=True)


if __name__ == "__main__":
    main()
