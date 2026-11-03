#!/usr/bin/env python3
"""Client, trace-log analyzer and state sampler of the Firebird load run (e2e/load/firebird.sh,
e2e/load/README.md "Firebird target").

Runs inside the `fb-client` container (e2e/load/firebird-client/Dockerfile: Python with
firebird-driver over the image's libfbclient), as uid 10001 in the server's network namespace; the
client subcommands connect to the loopback only. The analyzer and the sampler read files only (the
trace log through the layout's named-user ACL, the agent's state volume read-only) and print counts,
sizes, ids and timings: never a statement text, a parameter, a value or a name from the log
(the log holds the dev account names and, on a monitored server, any text: I2).

Client subcommands (passwords from files, never on a command line):
  workload   fixed-rate point reads over S sessions (absolute schedule per session), one read-only
             read-committed transaction per statement; prints one JSON line (issued, failed, the
             client-side latency mean / p95 / p99 in ms, late starts and the schedule lag)
  burst      N concurrent attaches released together by a barrier (measurement 8g), held, detached
  perrow     one per-row statement (measurement 3m): INSERT ... SELECT into LOAD_SINK (a block-less
             and a block-ful trigger per row) or SELECT LOAD_FN_LOOKUP(K) (a block-ful function per row)
  opentx     C connections x K transactions, each with an open cursor over a per-row function,
             partly fetched and held H seconds (pending groups, measurement 3m)
  ddl        statements of a file, each committed (the schema run's invalidation and cut steps)
  sql        one statement, its first column of every row printed (catalog counts, as SYSDBA)

Files:
  trace      the trace log: per-event counts, the statements of a user since a time, the attach
             bursts' order (8g), the agent's dependent-set reads (R41 item 2) and the log's size
  state      samples (size, inode, mtime) of the agent's state files under the state volume, for the
             checkpoint and ledger I/O (ADR-0060 implementation notes of 2026-11-01)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

DSN_DEFAULT = "127.0.0.1/3050:/var/lib/firebird/data/crm.fdb"
LOG_DEFAULT = "/var/lib/firebird/audit/audit.log"

# --------------------------------------------------------------------------------------- helpers


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile (as loadlib.percentile)."""
    if not values:
        return None
    v = sorted(values)
    k = max(0, min(len(v) - 1, int(-(-pct * len(v) // 100)) - 1))
    return v[k]


def emit(obj: dict) -> None:
    print(json.dumps(obj, separators=(",", ":"), sort_keys=True), flush=True)


def read_password(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def _driver():
    """firebird-driver, configured for the image's client library (imported lazily: the analyzer and
    the unit tests run without it)."""
    from firebird import driver  # noqa: PLC0415

    lib = os.environ.get("FB_CLIENT_LIBRARY", "/opt/firebird/lib/libfbclient.so")
    driver.driver_config.fb_client_library.value = lib
    _serialize_xpb(driver)
    return driver


_XPB_LOCK = threading.Lock()


def _serialize_xpb(driver) -> None:
    """firebird-driver 2.1 builds parameter blocks through the client's IUtil interface, which keeps
    one status object per process: concurrent connects race there (`AttributeError` in
    `DPB.get_buffer`, seen under 256 concurrent attaches on 4.0.7 and 5.0.4). Only the building of
    the parameter blocks (DPB, TPB) is serialized, a few microseconds each: the attaches themselves
    stay concurrent."""
    from firebird.driver import core  # noqa: PLC0415

    for cls in (core.DPB, core.TPB):
        orig = cls.get_buffer
        if getattr(orig, "_serialized", False):
            continue

        def wrapped(self, *args, _orig=orig, **kw):
            with _XPB_LOCK:
                return _orig(self, *args, **kw)

        wrapped._serialized = True
        cls.get_buffer = wrapped


_DB_LOCK = threading.Lock()
_DB_NAMES: dict[str, str] = {}
CLIENT_RETRIES = {"n": 0}


def _db_name(drv, dsn: str) -> str:
    """The DSN registered once in the driver's configuration: connect() with a bare DSN string
    clears the shared default server configuration on every call (firebird-driver 2.1), which races
    under many concurrent connects (`AttributeError` while the DPB is built)."""
    with _DB_LOCK:
        name = _DB_NAMES.get(dsn)
        if name is None:
            name = f"load{len(_DB_NAMES)}"
            drv.driver_config.register_database(name).dsn.value = dsn
            _DB_NAMES[dsn] = name
        return name


def _connect(drv, dsn: str, user: str, password: str):
    """A connection; an `AttributeError` raised while the driver builds its parameters (before any
    attach reaches the server) is retried at once, at most 3 times, and counted."""
    name = _db_name(drv, dsn)
    for attempt in range(4):
        try:
            return drv.connect(name, user=user, password=password)
        except AttributeError:
            if attempt == 3:
                raise
            with _DB_LOCK:
                CLIENT_RETRIES["n"] += 1
    raise AssertionError("unreachable")


def _read_tpb(drv):
    return drv.tpb(drv.Isolation.READ_COMMITTED_RECORD_VERSION, access_mode=drv.TraAccessMode.READ)


def _err_code(e: Exception) -> str:
    """A counter key of an error: its SQLSTATE or SQLCODE, else its type and the driver function it
    came from (never its message: it may quote a statement)."""
    for attr in ("sqlstate", "sqlcode"):
        v = getattr(e, attr, None)
        if v:
            return str(v)
    tb = e.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    where = tb.tb_frame.f_code.co_name if tb is not None else "?"
    return f"{type(e).__name__}@{where}"


# --------------------------------------------------------------------------------------- workload


def parse_statements(text: str) -> list[tuple[str, int]]:
    """Workload statements: one `<max id>\\t<SQL with one ? parameter>` per line."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        n, _, sql = line.partition("\t")
        if not n.isdigit() or int(n) < 1 or sql.count("?") != 1:
            raise ValueError("a workload line is '<max id>\\t<SQL with one ? parameter>'")
        out.append((sql, int(n)))
    if not out:
        raise ValueError("no workload statement")
    return out


def schedule(n: int, interval_s: float, t0: float, offset_s: float) -> list[float]:
    """The absolute start times of a session's `n` statements (the session's offset inside one
    interval spreads the sessions)."""
    return [t0 + offset_s + k * interval_s for k in range(n)]


@dataclass
class SessionResult:
    issued: int = 0
    failed: int = 0
    late: int = 0
    lat_ms: list[float] = field(default_factory=list)
    lag_ms: list[float] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)


def run_session(drv, a, stmts: list[tuple[str, int]], pw: str, n: int, interval: float, t0: float,
                offset: float, seed: int, res: SessionResult) -> None:
    rnd = random.Random(seed)
    try:
        con = _connect(drv, a.dsn, a.user, pw)
    except Exception as e:  # noqa: BLE001 - counted, never printed with its text
        res.failed += n
        res.errors[_err_code(e)] = res.errors.get(_err_code(e), 0) + 1
        return
    try:
        con.default_tpb = _read_tpb(drv)
        cur = con.cursor()
        prepared = [(cur.prepare(sql), m) for sql, m in stmts]
        for at in schedule(n, interval, t0, offset):
            now = time.monotonic()
            if now < at:
                time.sleep(at - now)
            else:
                res.late += 1
            start = time.monotonic()
            res.lag_ms.append(max(0.0, (start - at) * 1000.0))
            ps, m = prepared[rnd.randrange(len(prepared))]
            try:
                cur.execute(ps, (rnd.randint(1, m),))
                cur.fetchall()
                con.commit()
                res.issued += 1
                res.lat_ms.append((time.monotonic() - start) * 1000.0)
            except Exception as e:  # noqa: BLE001
                res.failed += 1
                res.errors[_err_code(e)] = res.errors.get(_err_code(e), 0) + 1
                try:
                    con.rollback()
                except Exception:  # noqa: BLE001
                    pass
        for ps, _ in prepared:
            ps.free()
        cur.close()
    finally:
        con.close()


def cmd_workload(a) -> int:
    drv = _driver()
    with open(a.statements, encoding="utf-8") as f:
        stmts = parse_statements(f.read())
    pw = read_password(a.password_file)
    per = max(1, a.rate * a.duration // a.sessions)
    interval = a.sessions / a.rate
    t0 = time.monotonic() + 1.0
    results = [SessionResult() for _ in range(a.sessions)]
    threads = [threading.Thread(target=run_session, args=(drv, a, stmts, pw, per, interval, t0,
                                                          k * interval / a.sessions, a.seed + k, results[k]))
               for k in range(a.sessions)]
    started = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lat = [x for r in results for x in r.lat_ms]
    lag = [x for r in results for x in r.lag_ms]
    errors: dict[str, int] = {}
    for r in results:
        for k, v in r.errors.items():
            errors[k] = errors.get(k, 0) + v
    emit({"kind": "fb_workload", "user": a.user, "rate": a.rate, "sessions": a.sessions,
          "issued": sum(r.issued for r in results), "failed": sum(r.failed for r in results),
          "late_starts": sum(r.late for r in results),
          "mean_ms": round(sum(lat) / len(lat), 4) if lat else None,
          "p95_ms": round(percentile(lat, 95.0), 4) if lat else None,
          "p99_ms": round(percentile(lat, 99.0), 4) if lat else None,
          "schedule_lag_p95_ms": round(percentile(lag, 95.0), 2) if lag else None,
          "t0": started, "t1": time.time(), "errors": errors})
    return 0


# --------------------------------------------------------------------------------------- 8g burst


def _burst_proc(a, pw: str, threads: int, barrier, out) -> None:
    """One process of a burst: `threads` attaches, each released by the burst-wide barrier."""
    drv = _driver()
    res = {"ok": 0, "ms": [], "errors": {}}
    lock = threading.Lock()

    def one() -> None:
        try:
            barrier.wait(timeout=60)
        except Exception:  # noqa: BLE001 - a broken barrier: not attempted
            return
        s = time.monotonic()
        try:
            con = _connect(drv, a.dsn, a.user, pw)
        except Exception as e:  # noqa: BLE001
            with lock:
                res["errors"][_err_code(e)] = res["errors"].get(_err_code(e), 0) + 1
            return
        with lock:
            res["ok"] += 1
            res["ms"].append((time.monotonic() - s) * 1000.0)
        time.sleep(a.hold)
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass

    ts = [threading.Thread(target=one) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    res["retries"] = CLIENT_RETRIES["n"]
    out.put(res)


def cmd_burst(a) -> int:
    """Measurement 8g: `n` attaches at once. firebird-driver 2.1 is not safe for hundreds of
    concurrent connects in one process (`AttributeError` while it builds the DPB, seen on both
    versions), so the attaches are spread over `procs` processes of n / procs threads, all released
    by one cross-process barrier."""
    import multiprocessing as mp  # noqa: PLC0415

    pw = read_password(a.password_file)
    procs = max(1, min(a.procs, a.n))
    per = [a.n // procs + (1 if k < a.n % procs else 0) for k in range(procs)]
    ctx = mp.get_context("fork")
    barrier = ctx.Barrier(a.n)
    out = ctx.Queue()
    ps = [ctx.Process(target=_burst_proc, args=(a, pw, k, barrier, out)) for k in per]
    t0 = time.time()
    for p in ps:
        p.start()
    results = [out.get(timeout=300) for _ in ps]
    for p in ps:
        p.join(timeout=60)
    ok = sum(r["ok"] for r in results)
    c = [x for r in results for x in r["ms"]]
    errors: dict[str, int] = {}
    for r in results:
        for k, v in r["errors"].items():
            errors[k] = errors.get(k, 0) + v
    emit({"kind": "fb_burst_client", "attempted": a.n, "connected": ok, "errors": errors, "processes": procs,
          "connect_p95_ms": round(percentile(c, 95.0), 1) if c else None,
          "connect_max_ms": round(max(c), 1) if c else None,
          "client_retries": sum(r["retries"] for r in results), "t0": t0, "t1": time.time()})
    return 0 if ok == a.n else 1


# --------------------------------------------------------------------------------------- 3m


PERROW_SQL = {
    # Per row: the block-less id trigger and the block-ful lookup trigger of LOAD_SINK.
    "insert": "INSERT INTO LOAD_SINK (SRC) SELECT K FROM LOAD_SRC WHERE ID <= ?",
    # Per row: the block-ful function LOAD_FN_LOOKUP (reads LOAD_LOOKUP).
    "select": "SELECT LOAD_FN_LOOKUP(K) FROM LOAD_SRC WHERE ID <= ?",
}
# 200 rows: the server evaluates the function for whole prefetch batches, so a larger cursor writes
# thousands of nested records per open cursor (a 6.4 GB trace log with 20 000 rows locally).
OPENTX_SQL = "SELECT LOAD_FN_LOOKUP(K) FROM LOAD_SRC WHERE ID <= 200"


def cmd_perrow(a) -> int:
    drv = _driver()
    con = _connect(drv, a.dsn, a.user, read_password(a.password_file))
    try:
        cur = con.cursor()
        t0 = time.time()
        s = time.monotonic()
        cur.execute(PERROW_SQL[a.what], (a.rows,))
        n = len(cur.fetchall()) if a.what == "select" else a.rows
        con.commit()
        emit({"kind": "fb_perrow_client", "what": a.what, "rows": n, "duration_s": round(time.monotonic() - s, 3),
              "t0": t0, "t1": time.time()})
    finally:
        con.close()
    return 0


def cmd_opentx(a) -> int:
    drv = _driver()
    pw = read_password(a.password_file)
    opened = [0] * a.connections
    errors: dict[str, int] = {}
    lock = threading.Lock()
    barrier = threading.Barrier(a.connections)

    def one(k: int) -> None:
        try:
            con = _connect(drv, a.dsn, a.user, pw)
        except Exception as e:  # noqa: BLE001
            with lock:
                errors[_err_code(e)] = errors.get(_err_code(e), 0) + 1
            try:
                barrier.abort()
            except Exception:  # noqa: BLE001
                pass
            return
        tms, curs = [], []
        try:
            for _ in range(a.tx):
                tm = con.transaction_manager(_read_tpb(drv))
                tm.begin()
                cur = tm.cursor()
                cur.execute(OPENTX_SQL)
                cur.fetchmany(a.fetch)
                tms.append(tm)
                curs.append(cur)
                opened[k] += 1
            try:
                barrier.wait(timeout=120)
            except threading.BrokenBarrierError:
                pass
            time.sleep(a.hold)
        except Exception as e:  # noqa: BLE001
            with lock:
                errors[_err_code(e)] = errors.get(_err_code(e), 0) + 1
        finally:
            for cur in curs:
                try:
                    cur.close()
                except Exception:  # noqa: BLE001
                    pass
            for tm in tms:
                try:
                    tm.commit()
                    tm.close()
                except Exception:  # noqa: BLE001
                    pass
            con.close()

    t0 = time.time()
    threads = [threading.Thread(target=one, args=(k,)) for k in range(a.connections)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    emit({"kind": "fb_opentx_client", "connections": a.connections, "tx_per_connection": a.tx,
          "cursors": sum(opened), "fetch": a.fetch, "hold_s": a.hold, "errors": errors,
          "t0": t0, "t1": time.time()})
    return 0 if sum(opened) == a.connections * a.tx else 1


def cmd_ddl(a) -> int:
    drv = _driver()
    con = _connect(drv, a.dsn, a.user, read_password(a.password_file))
    done = 0
    try:
        cur = con.cursor()
        with open(a.file, encoding="utf-8") as f:
            for stmt in f.read().split("\n--\n"):
                if stmt.strip():
                    cur.execute(stmt)
                    con.commit()
                    done += 1
    finally:
        con.close()
    emit({"kind": "fb_ddl_client", "statements": done, "t1": time.time()})
    return 0


def cmd_sql(a) -> int:
    drv = _driver()
    con = _connect(drv, a.dsn, a.user, read_password(a.password_file))
    try:
        cur = con.cursor()
        cur.execute(a.statement)
        for row in cur.fetchall():
            print(row[0], flush=True)
        con.commit()
    finally:
        con.close()
    return 0


# --------------------------------------------------------------------------------------- trace log

HEADER_RE = re.compile(rb"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{4}) \((\d+):(0x[0-9a-f]+)\) ([A-Z_ ]+)\r?$")
ATTACH_RE = re.compile(rb"^\t(.*) \(ATT_(\d+), ([^:,]*):([^,]*), ([^,]*), (.*)\)\r?$")
FETCHED_RE = re.compile(rb"^(\d+) records fetched\r?$")
PERF_RE = re.compile(rb"^\s+(\d+) ms(,|\r?$)")
# The agent's dependent-set reads (sql::VIEW_RELATIONS, DEPENDENCIES, FIELD_SOURCES, ROUTINES):
# distinctive parts of their constant texts.
CATALOG_MARKS = {
    "view_relations": b"FROM RDB$VIEW_RELATIONS V",
    "dependencies": b"FROM RDB$DEPENDENCIES D WHERE D.RDB$DEPENDENT_TYPE IN",
    "field_sources": b"FROM RDB$RELATION_FIELDS RF JOIN RDB$FIELDS F",
    "routines": b"FROM RDB$PROCEDURES P UNION ALL",
}


@dataclass
class Record:
    ts: float  # header time (the server's clock, local time read as UTC: differences only)
    pid: int
    token: str
    event: str
    db: bytes | None = None
    att: int | None = None
    user: bytes | None = None
    fetched: int | None = None
    ms: int | None = None
    marks: tuple[str, ...] = ()
    offset: int = 0
    size: int = 0


def parse_ts(b: bytes) -> float:
    return datetime.strptime(b.decode("ascii"), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()


def records(lines, start_offset: int = 0):
    """Records of a trace log given as byte lines (with their line ends): the header, the first
    attachment line, `records fetched`, the duration, and which of the agent's catalog texts the
    record holds. Nothing else of the body is kept."""
    cur: Record | None = None
    off = start_offset
    for line in lines:
        # Cheap prefilters first: a header starts with a digit, the attachment line with a tab.
        m = HEADER_RE.match(line) if line[:1].isdigit() and b") " in line else None
        if m:
            if cur is not None:
                cur.size = off - cur.offset
                yield cur
            cur = Record(parse_ts(m.group(1)), int(m.group(2)), m.group(3).decode(), m.group(4).decode().strip(),
                         offset=off)
        elif cur is not None:
            if cur.att is None and line[:1] == b"\t" and b"(ATT_" in line:
                a = ATTACH_RE.match(line)
                if a:
                    cur.db, cur.att, cur.user = a.group(1), int(a.group(2)), a.group(3)
            elif b"records fetched" in line:
                f = FETCHED_RE.match(line)
                if f:
                    cur.fetched = int(f.group(1))
            elif cur.ms is None and b" ms" in line:
                p = PERF_RE.match(line)
                if p:
                    cur.ms = int(p.group(1))
            elif b"FROM RDB$" in line:
                for k, mark in CATALOG_MARKS.items():
                    if mark in line and k not in cur.marks:
                        cur.marks += (k,)
        off += len(line)
    if cur is not None:
        cur.size = off - cur.offset
        yield cur


def read_records(path: str):
    with open(path, "rb") as f:
        yield from records(f)


def is_statement_finish(ev: str) -> bool:
    return ev.endswith("EXECUTE_STATEMENT_FINISH")


def statements_of(recs, user: bytes, since: float | None, until: float | None = None) -> dict:
    n = failed = 0
    for r in recs:
        if r.user == user and is_statement_finish(r.event) and (since is None or r.ts >= since) \
                and (until is None or r.ts <= until):
            n += 1
            failed += r.event.startswith("FAILED") or r.event.startswith("UNAUTHORIZED")
    return {"statements": n, "failed": failed}


def burst_order(recs, user: bytes, gap_s: float, since: float | None = None) -> list[dict]:
    """Measurement 8g. The ATTACH_DATABASE records of `user`, grouped into bursts (a gap of more than
    `gap_s` between two of them starts a new burst). Per burst: the largest inversion (how far below
    the highest id seen so far for its database an id was written) and the latest late record (the
    header time between a late record and the record that first raised the highest id above its id),
    over every attach of the database (other users' too) from the burst's first to its last; and
    whether the burst opened the database (no attachment of the database live at its first attach,
    from the log's ATTACH / DETACH records). ADR-0060 R7: within 256 ids and 10 s."""
    live: dict[bytes, set[int]] = {}
    highest: dict[bytes, int] = {}
    raised_at: dict[bytes, list[tuple[int, float]]] = {}
    bursts: list[dict] = []
    cur: dict | None = None
    for r in recs:
        if r.db is None or r.att is None:
            continue
        if r.event == "ATTACH_DATABASE":
            mine = r.user == user and (since is None or r.ts >= since)
            if mine and (cur is None or r.ts - cur["_last"] > gap_s):
                cur = {"attaches": 0, "max_inversion": 0, "late_records": 0, "latest_late_s": 0.0,
                       "opened_database": not live.get(r.db), "first_ts": r.ts, "_last": r.ts, "_db": r.db}
                bursts.append(cur)
            in_burst = cur is not None and r.db == cur["_db"] and r.ts - cur["_last"] <= gap_s
            h = highest.get(r.db, 0)
            if r.att < h:
                # The record that first raised the highest id above this id.
                first = next((t for i, t in raised_at.get(r.db, []) if i > r.att), r.ts)
                if in_burst:
                    cur["max_inversion"] = max(cur["max_inversion"], h - r.att)
                    cur["late_records"] += 1
                    cur["latest_late_s"] = max(cur["latest_late_s"], round(r.ts - first, 4))
            else:
                highest[r.db] = r.att
                raised_at.setdefault(r.db, []).append((r.att, r.ts))
                if len(raised_at[r.db]) > 4096:
                    del raised_at[r.db][:2048]
            live.setdefault(r.db, set()).add(r.att)
            if mine and in_burst:
                cur["attaches"] += 1
                cur["_last"] = r.ts
        elif r.event == "DETACH_DATABASE":
            live.get(r.db, set()).discard(r.att)
    for b in bursts:
        b.pop("_last", None)
        b.pop("_db", None)
    return bursts


def catalog_reads(recs, user: bytes, since: float | None) -> dict:
    """R41 item 2: the agent's dependent-set reads (its four constant catalog texts) since `since`:
    per read, how often, the server-side duration (ms) and the rows fetched; per check session (the
    attachment that ran them), the four reads' sum."""
    per: dict[str, dict] = {k: {"n": 0, "ms": [], "rows": []} for k in CATALOG_MARKS}
    sessions: dict[tuple[int, int], int] = {}
    for r in recs:
        if r.user != user or not is_statement_finish(r.event) or not r.marks:
            continue
        if since is not None and r.ts < since:
            continue
        k = r.marks[0]
        per[k]["n"] += 1
        per[k]["ms"].append(r.ms or 0)
        per[k]["rows"].append(r.fetched or 0)
        key = (r.pid, r.att or 0)
        sessions[key] = sessions.get(key, 0) + (r.ms or 0)
    out = {}
    for k, v in per.items():
        out[k] = {"reads": v["n"], "ms_max": max(v["ms"]) if v["ms"] else None,
                  "ms_p50": percentile(v["ms"], 50.0), "rows_max": max(v["rows"]) if v["rows"] else None}
    tot = list(sessions.values())
    out["sum_per_check_ms"] = {"checks": len(tot), "max": max(tot) if tot else None,
                               "p50": percentile(tot, 50.0)}
    return out


def event_counts(recs) -> dict:
    out: dict[str, list[int]] = {}
    for r in recs:
        e = out.setdefault(r.event, [0, 0])
        e[0] += 1
        e[1] += r.size
    return {k: {"records": v[0], "bytes": v[1]} for k, v in sorted(out.items())}


def cmd_trace(a) -> int:
    since = parse_ts(a.since.encode()) if a.since else None
    until = parse_ts(a.until.encode()) if a.until else None
    user = a.user.encode() if a.user else b""
    if a.what == "size":
        d = os.path.dirname(a.log)
        files = sorted(f for f in os.listdir(d) if f.startswith("audit"))
        emit({"kind": "fb_log_size", "files": len(files),
              "bytes": sum(os.stat(os.path.join(d, f)).st_size for f in files), "t": time.time()})
    elif a.what == "statements":
        emit({"kind": "fb_source", "user": a.user, **statements_of(read_records(a.log), user, since, until)})
    elif a.what == "bursts":
        emit({"kind": "fb_bursts", "user": a.user, "bursts": burst_order(read_records(a.log), user, a.gap, since)})
    elif a.what == "catalog":
        emit({"kind": "fb_catalog_reads", **catalog_reads(read_records(a.log), user, since)})
    elif a.what == "events":
        emit({"kind": "fb_trace_events", "events": event_counts(read_records(a.log))})
    return 0


# --------------------------------------------------------------------------------------- state


def state_snapshot(root: str) -> dict:
    """Size, inode and mtime (ns) of every regular file under `root`'s `audit/` directory, and the
    spool's file count and bytes (names under audit/ are target ids and source names, no value)."""
    files = {}
    adir = os.path.join(root, "audit")
    try:
        names = os.listdir(adir)
    except OSError:
        names = []
    for n in names:
        try:
            st = os.lstat(os.path.join(adir, n))
        except OSError:
            continue
        if not os.path.islink(os.path.join(adir, n)) and os.path.isfile(os.path.join(adir, n)):
            files[n] = [st.st_size, st.st_ino, st.st_mtime_ns]
    spool_n = spool_b = 0
    for dirpath, _, fnames in os.walk(os.path.join(root, "spool")):
        for n in fnames:
            try:
                spool_b += os.lstat(os.path.join(dirpath, n)).st_size
                spool_n += 1
            except OSError:
                pass
    return {"t": time.time(), "audit": files, "spool_files": spool_n, "spool_bytes": spool_b}


def cmd_state(a) -> int:
    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        print(json.dumps(state_snapshot(a.root), separators=(",", ":")), flush=True)
        time.sleep(a.interval)
    return 0


# --------------------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def client(name: str):
        s = sub.add_parser(name)
        s.add_argument("--dsn", default=DSN_DEFAULT)
        s.add_argument("--user", required=True)
        s.add_argument("--password-file", required=True)
        return s

    w = client("workload")
    w.add_argument("--statements", required=True)
    w.add_argument("--rate", type=int, required=True)
    w.add_argument("--duration", type=int, required=True)
    w.add_argument("--sessions", type=int, default=4)
    w.add_argument("--seed", type=int, default=1)
    b = client("burst")
    b.add_argument("--n", type=int, default=256)
    b.add_argument("--hold", type=float, default=1.0)
    b.add_argument("--procs", type=int, default=32)
    r = client("perrow")
    r.add_argument("--what", choices=sorted(PERROW_SQL), required=True)
    r.add_argument("--rows", type=int, required=True)
    o = client("opentx")
    o.add_argument("--connections", type=int, required=True)
    o.add_argument("--tx", type=int, required=True)
    o.add_argument("--fetch", type=int, default=50)
    o.add_argument("--hold", type=float, default=5.0)
    d = client("ddl")
    d.add_argument("--file", required=True)
    q = client("sql")
    q.add_argument("--statement", required=True)
    t = sub.add_parser("trace")
    t.add_argument("what", choices=["size", "statements", "bursts", "catalog", "events"])
    t.add_argument("--log", default=LOG_DEFAULT)
    t.add_argument("--user", default="")
    t.add_argument("--since", default="")
    t.add_argument("--until", default="")
    t.add_argument("--gap", type=float, default=5.0)
    st = sub.add_parser("state")
    st.add_argument("--root", default="/state")
    st.add_argument("--interval", type=float, default=0.5)
    st.add_argument("--duration", type=float, required=True)
    a = p.parse_args(argv)
    for k in ("rate", "duration", "sessions", "n", "rows", "connections", "tx"):
        if isinstance(getattr(a, k, None), int) and getattr(a, k) < 1:
            p.error(f"--{k} must be positive")
    return {"workload": cmd_workload, "burst": cmd_burst, "perrow": cmd_perrow, "opentx": cmd_opentx,
            "ddl": cmd_ddl, "sql": cmd_sql, "trace": cmd_trace, "state": cmd_state}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
