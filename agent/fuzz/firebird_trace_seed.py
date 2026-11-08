"""Writes the seed inputs of the firebird_trace_stream fuzz target (ADR-0060, review L1 of P10-F)
from the recorded trace logs committed under agent/crates/connector-firebird/testdata/ (the
pinned dev images' fake data only).

Each input is the target's settings byte, then whole records of one log, at most -max_len=4096
bytes: consecutive records packed in order, so the bindings, transactions and groups a chunk
opens are mostly closed in it. The settings byte selects the log's name-line grammar (bit 0 for
5.0), proof 11 and SuperServer (bits 1 and 2) and a run confirmed before the first record (bit
3); a second copy of every chunk has a clock step line (one byte 0x01, then 0x02) between its
records, which makes the stream run its reading-time bounds.

    python3 -I firebird_trace_seed.py TESTDATA_DIR OUT_DIR
"""

import os
import re
import sys

MAX_LEN = 4096
HEADER = re.compile(rb"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{4} \(")


def records(log: bytes) -> list[bytes]:
    out: list[bytes] = []
    cur: list[bytes] = []
    for line in log.split(b"\n"):
        if HEADER.match(line) and cur:
            out.append(b"\n".join(cur) + b"\n")
            cur = []
        cur.append(line)
    if cur:
        out.append(b"\n".join(cur) + b"\n")
    return out


def chunks(recs: list[bytes], room: int) -> list[list[bytes]]:
    out: list[list[bytes]] = []
    cur: list[bytes] = []
    size = 0
    for r in recs:
        if len(r) > room:
            continue
        if size + len(r) > room and cur:
            out.append(cur)
            cur, size = [], 0
        cur.append(r)
        size += len(r)
    if cur:
        out.append(cur)
    return out


def main(testdata: str, out: str) -> None:
    os.makedirs(out, exist_ok=True)
    n = 0
    for name in sorted(os.listdir(testdata)):
        if not (name.startswith("trace-") and name.endswith(".log")):
            continue
        with open(os.path.join(testdata, name), "rb") as f:
            log = f.read()
        v5 = 1 if name.startswith("trace-5.") else 0
        flags = bytes([v5 | 2 | 4 | 8])
        # Room for the settings byte and up to 64 step lines of two bytes.
        for i, recs in enumerate(chunks(records(log), MAX_LEN - 1 - 128)):
            base = name[: -len(".log")]
            with open(os.path.join(out, f"{base}-{i:03}"), "wb") as f:
                f.write(flags + b"".join(recs))
            stepped = bytearray(bytes([v5 | 2 | 8]))
            for j, r in enumerate(recs[:64]):
                stepped += r
                stepped += bytes([1 + j % 2]) + b"\n"
            stepped += b"".join(recs[64:])
            if len(stepped) <= MAX_LEN:
                with open(os.path.join(out, f"{base}-{i:03}-stepped"), "wb") as f:
                    f.write(stepped)
            n += 1
    if n == 0:
        sys.exit("firebird_trace_seed: no trace log found")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: firebird_trace_seed.py TESTDATA_DIR OUT_DIR")
    main(sys.argv[1], sys.argv[2])
