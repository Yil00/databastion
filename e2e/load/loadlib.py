#!/usr/bin/env python3
"""Measurement and report of the load / database impact harness (e2e/load/run.sh).

Subcommands (stdlib only; unit tests in test_loadlib.py):

  sample --out FILE [--interval S] NAME=CONTAINER_ID...
      Samples, every S seconds until SIGTERM, the cgroup counters of each container: cumulative CPU
      time (cgroup v2 `cpu.stat` usage_usec, v1 `cpuacct.usage`), anonymous memory (`memory.stat`
      anon / rss), and the resident set of its main process (`/proc/<pid>/status` VmRSS). Plus the
      host's CPU busy / total jiffies (`/proc/stat`), to tell a saturated runner. One JSON line per
      sample. Container main pids come from `docker inspect`; nothing runs inside the containers.

  pgbench --summary FILE --log FILE...
      Transactions processed / failed from a pgbench summary and latency percentiles from its
      per-transaction logs (`-l`): prints one JSON object.

  sysbench --summary FILE
      Events, read queries, errors and the 95th percentile latency of a sysbench summary.

  report --facts FILE --samples FILE... --heartbeats FILE --out DIR
      Computes every measure from the samples and the facts run.sh recorded (windows, counts),
      evaluates the checks, writes results.json and results.md, exits 1 if a check failed.

Definitions (also in e2e/load/README.md):

- Database CPU impact of a Discovery scan, per target: the CPU time of the database server's
  container over the scan (from the sample just before the job was delivered to the agent to the
  sample just after the console recorded its end), minus the server's own idle rate over that time
  (measured before the agent started), divided by the scan duration (job delivery to job end) times
  the server's CPU capacity (its cgroup CPU limit, else the host's CPU count). In words: the average
  share of the database server's CPU capacity that the agent added during the scan. The numerator
  covers a slightly longer interval than the denominator, so the figure errs on the high side.
- Agent CPU: CPU time of the agent container over a window divided by its length, in cores.
- Agent RSS: VmRSS of the agent process (the container's main process).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field

# ------------------------------------------------------------------------------------ cgroups


def parse_proc_cgroup(text: str) -> dict[str, str]:
    """`/proc/<pid>/cgroup` -> {"": v2 path} and / or {controller: v1 path}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) != 3:
            continue
        _, controllers, path = parts
        if controllers == "":
            out[""] = path
        else:
            for c in controllers.split(","):
                out[c] = path
    return out


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def parse_flat_keyed(text: str | None) -> dict[str, int]:
    """`key value` lines (cpu.stat, memory.stat) -> dict; unparsable lines are skipped."""
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return out


def parse_cpu_max(text: str | None) -> float | None:
    """cgroup v2 `cpu.max` ("max 100000" or "200000 100000") -> CPUs, None when unlimited."""
    parts = (text or "").split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        quota, period = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    return quota / period if period > 0 and quota > 0 else None


def parse_proc_status(text: str | None) -> dict[str, int]:
    """VmRSS / VmHWM of `/proc/<pid>/status`, in bytes."""
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(VmRSS|VmHWM):\s+(\d+)\s+kB", line)
        if m:
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def parse_proc_stat(text: str | None) -> tuple[int, int] | None:
    """Aggregate `cpu` line of `/proc/stat` -> (busy, total) jiffies (idle + iowait are not busy)."""
    for line in (text or "").splitlines():
        if line.startswith("cpu "):
            v = [int(x) for x in line.split()[1:]]
            total = sum(v[:8])  # guest time is already counted in user / nice
            idle = v[3] + (v[4] if len(v) > 4 else 0)
            return total - idle, total
    return None


@dataclass
class Cgroup:
    """Paths of one container's cgroup; v2 unified or v1 split hierarchies."""

    cpu_file: str | None = None  # v2 cpu.stat or v1 cpuacct.usage
    mem_file: str | None = None  # memory.stat
    cap_files: tuple[str, ...] = ()  # v2 cpu.max, or v1 (quota, period)
    v2: bool = True

    @classmethod
    def resolve(cls, pid: int, proc_root: str = "/proc", cg_root: str = "/sys/fs/cgroup") -> "Cgroup":
        paths = parse_proc_cgroup(_read(f"{proc_root}/{pid}/cgroup") or "")
        if "" in paths and os.path.exists(f"{cg_root}{paths['']}/cpu.stat"):
            d = f"{cg_root}{paths['']}"
            return cls(f"{d}/cpu.stat", f"{d}/memory.stat", (f"{d}/cpu.max",), True)
        cg = cls(v2=False)

        def v1_dir(controller: str) -> str | None:
            if controller not in paths:
                return None
            mounts = [f"{cg_root}/{controller}"]
            if controller in ("cpu", "cpuacct"):
                mounts = [f"{cg_root}/cpu,cpuacct", f"{cg_root}/cpuacct,cpu"] + mounts
            for mount in mounts:
                d = f"{mount}{paths[controller]}"
                if os.path.isdir(d):
                    return d
            return None

        acct = v1_dir("cpuacct")
        cpu = v1_dir("cpu")
        mem = v1_dir("memory")
        if acct:
            cg.cpu_file = f"{acct}/cpuacct.usage"
        if mem:
            cg.mem_file = f"{mem}/memory.stat"
        if cpu:
            cg.cap_files = (f"{cpu}/cpu.cfs_quota_us", f"{cpu}/cpu.cfs_period_us")
        return cg

    def cpu_usec(self) -> int | None:
        if not self.cpu_file:
            return None
        text = _read(self.cpu_file)
        if self.v2:
            return parse_flat_keyed(text).get("usage_usec")
        try:
            return int((text or "").strip()) // 1000
        except ValueError:
            return None

    def anon_bytes(self) -> int | None:
        stat = parse_flat_keyed(_read(self.mem_file) if self.mem_file else None)
        return stat.get("anon") if self.v2 else stat.get("total_rss", stat.get("rss"))

    def capacity(self, host_cpus: int) -> float:
        """CPUs the container may use: its quota, capped by the host's CPU count."""
        cap: float | None = None
        if self.v2 and self.cap_files:
            cap = parse_cpu_max(_read(self.cap_files[0]))
        elif len(self.cap_files) == 2:
            try:
                quota = int((_read(self.cap_files[0]) or "").strip())
                period = int((_read(self.cap_files[1]) or "").strip())
                cap = quota / period if quota > 0 and period > 0 else None
            except ValueError:
                cap = None
        return min(cap, float(host_cpus)) if cap else float(host_cpus)


def docker_pid(container: str) -> int | None:
    try:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", container],
                             capture_output=True, text=True, timeout=20, check=True).stdout.strip()
        pid = int(out)
        return pid if pid > 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def sample_once(targets: dict[str, str], state: dict, host_cpus: int, pid_of=None,
                proc_root: str = "/proc", cg_root: str = "/sys/fs/cgroup") -> dict:
    """One sample line. `state` caches (pid, Cgroup) per name; a vanished pid is looked up again
    (a restarted container)."""
    pid_of = pid_of or docker_pid
    line: dict[str, object] = {"t": round(time.time(), 3)}
    host = parse_proc_stat(_read(f"{proc_root}/stat"))
    if host:
        line["host"] = {"busy": host[0], "total": host[1], "cpus": host_cpus}
    cs: dict[str, object] = {}
    for name, cid in targets.items():
        st = state.get(name)
        if st is None or not os.path.exists(f"{proc_root}/{st[0]}"):
            pid = pid_of(cid)
            st = (pid, Cgroup.resolve(pid, proc_root, cg_root)) if pid else None
            state[name] = st
        if st is None:
            cs[name] = None
            continue
        pid, cg = st
        status = parse_proc_status(_read(f"{proc_root}/{pid}/status"))
        cs[name] = {"cpu_usec": cg.cpu_usec(), "anon": cg.anon_bytes(),
                    "rss": status.get("VmRSS"), "hwm": status.get("VmHWM"),
                    "cap": cg.capacity(host_cpus), "pid": pid}
    line["c"] = cs
    return line


def run_sampler(targets: dict[str, str], out_path: str, interval: float, should_stop, **kw: object) -> int:
    host_cpus = os.cpu_count() or 1
    state: dict = {}
    n = 0
    with open(out_path, "a", encoding="utf-8") as out:
        while not should_stop():
            out.write(json.dumps(sample_once(targets, state, host_cpus, **kw), separators=(",", ":")) + "\n")
            out.flush()
            n += 1
            deadline = time.monotonic() + interval
            while not should_stop() and time.monotonic() < deadline:
                time.sleep(min(0.1, interval))
    return n


def quiet_rates(samples: list[dict], names: list[str], now: float, window: float) -> dict[str, float | None]:
    """CPU rate (cores) of each container over the last `window` seconds before `now`."""
    return {n: rate(series(samples, n, "cpu_usec"), now - window, now, 1e6) for n in names}


def cmd_quiet(args: argparse.Namespace) -> int:
    """Waits until every named container uses at most --below cores over --window seconds (the
    background work of a bulk load: checkpoints, purge, flushes). Exit 1 on timeout (run.sh warns)."""
    names = [n for n in args.names.split(",") if n]
    deadline = time.monotonic() + args.timeout
    while True:
        rates = quiet_rates(load_jsonl([args.samples]), names, time.time(), args.window)
        if all(r is not None and r <= args.below for r in rates.values()):
            print(json.dumps({"quiet": True, "cores": {k: _r(v, 4) for k, v in rates.items()}}))
            return 0
        if time.monotonic() >= deadline:
            print(json.dumps({"quiet": False, "cores": {k: _r(v, 4) for k, v in rates.items()}}))
            return 1
        time.sleep(1.0)


def cmd_sample(args: argparse.Namespace) -> int:
    targets: dict[str, str] = {}
    for spec in args.containers:
        name, _, cid = spec.partition("=")
        if not name or not cid:
            print(f"loadlib sample: bad NAME=CONTAINER_ID '{spec}'", file=sys.stderr)
            return 2
        targets[name] = cid
    stop = False

    def on_term(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    run_sampler(targets, args.out, args.interval, lambda: stop)
    return 0


# ------------------------------------------------------------------------------------ series


def load_jsonl(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass  # a line cut by the sampler's termination
        except FileNotFoundError:
            pass
    return rows


def series(samples: list[dict], name: str, key: str) -> list[tuple[float, float]]:
    """(t, value) of one container counter, sorted, missing values skipped."""
    out = []
    for s in samples:
        c = (s.get("c") or {}).get(name)
        if isinstance(c, dict) and isinstance(c.get(key), (int, float)):
            out.append((float(s["t"]), float(c[key])))
    out.sort()
    return out


def host_series(samples: list[dict]) -> list[tuple[float, float, float]]:
    out = []
    for s in samples:
        h = s.get("host")
        if isinstance(h, dict):
            out.append((float(s["t"]), float(h["busy"]), float(h["total"])))
    out.sort()
    return out


def bracket(ser: list[tuple[float, float]], t0: float, t1: float) -> tuple[float, float, float] | None:
    """Delta of a cumulative counter from the last sample at or before t0 to the first at or after
    t1: (delta, t0', t1'), an interval that contains [t0, t1]; None if the series does not cover it."""
    before = [p for p in ser if p[0] <= t0]
    after = [p for p in ser if p[0] >= t1]
    if not before or not after:
        return None
    a, b = before[-1], after[0]
    return b[1] - a[1], a[0], b[0]


def inner(ser: list[tuple[float, float]], t0: float, t1: float) -> tuple[float, float, float] | None:
    """Delta over the samples inside [t0, t1] (first and last of them): for rates over long windows."""
    pts = [p for p in ser if t0 <= p[0] <= t1]
    if len(pts) < 2 or pts[-1][0] <= pts[0][0]:
        return None
    return pts[-1][1] - pts[0][1], pts[0][0], pts[-1][0]


def rate(ser: list[tuple[float, float]], t0: float, t1: float, scale: float = 1.0) -> float | None:
    d = inner(ser, t0, t1)
    if d is None:
        return None
    return d[0] / scale / (d[2] - d[1])


def values_in(ser: list[tuple[float, float]], t0: float, t1: float) -> list[float]:
    return [v for t, v in ser if t0 <= t <= t1]


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile (pct in 0..100)."""
    if not values:
        return None
    s = sorted(values)
    k = max(1, math.ceil(pct / 100.0 * len(s)))
    return s[min(k, len(s)) - 1]


def median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def slope_per_hour(points: list[tuple[float, float]]) -> float | None:
    """Least-squares slope of value over time, per hour."""
    if len(points) < 3:
        return None
    n = len(points)
    mt = sum(t for t, _ in points) / n
    mv = sum(v for _, v in points) / n
    den = sum((t - mt) ** 2 for t, _ in points)
    if den == 0:
        return None
    return sum((t - mt) * (v - mv) for t, v in points) / den * 3600.0


def growth(points: list[tuple[float, float]], warmup: float, abs_tol: float, rel_tol: float) -> dict:
    """Monotonic-growth verdict over a window: the first `warmup` fraction is dropped, the rest is cut
    into three equal time segments. Growth = the three medians strictly increase AND the last exceeds
    the first by more than max(abs_tol, rel_tol x first). A plateau, a spike or noise does not count."""
    if len(points) < 6:
        return {"ok": None, "reason": "too few samples"}
    t_start, t_end = points[0][0], points[-1][0]
    t0 = t_start + (t_end - t_start) * warmup
    span = (t_end - t0) / 3
    segs = [[v for t, v in points if t0 + i * span <= t <= t0 + (i + 1) * span] for i in range(3)]
    if any(not s for s in segs):
        return {"ok": None, "reason": "empty segment"}
    m = [median(s) for s in segs]
    assert all(x is not None for x in m)
    m1, m2, m3 = (float(x) for x in m)  # type: ignore[arg-type]
    increasing = m1 < m2 < m3
    grew = m3 - m1 > max(abs_tol, rel_tol * abs(m1))
    return {"ok": not (increasing and grew), "medians": [m1, m2, m3],
            "slope_per_hour": slope_per_hour([p for p in points if p[0] >= t0])}


def segment_rates(ser: list[tuple[float, float]], t0: float, t1: float, n: int, scale: float) -> list[tuple[float, float]]:
    """Rates of a cumulative counter over n equal segments of [t0, t1], as (segment mid, rate)."""
    out = []
    step = (t1 - t0) / n
    for i in range(n):
        a, b = t0 + i * step, t0 + (i + 1) * step
        r = rate(ser, a, b, scale)
        if r is not None:
            out.append(((a + b) / 2, r))
    return out


# ------------------------------------------------------------------------------------ workloads

PGBENCH_PROCESSED = re.compile(r"number of transactions actually processed:\s*(\d+)")
PGBENCH_FAILED = re.compile(r"number of failed transactions:\s*(\d+)")


def pgbench_summary(text: str) -> dict:
    m = PGBENCH_PROCESSED.search(text)
    f = PGBENCH_FAILED.search(text)
    return {"processed": int(m.group(1)) if m else None, "failed": int(f.group(1)) if f else 0}


def pgbench_latencies(lines: list[str]) -> tuple[list[float], list[float]]:
    """pgbench -l lines: client_id transaction_no time script_no time_epoch time_us [schedule_lag]
    -> (latency ms from the scheduled start, service latency ms = latency - schedule lag).
    Failed or skipped transactions (a non-numeric `time`) are ignored."""
    lat: list[float] = []
    svc: list[float] = []
    for line in lines:
        p = line.split()
        if len(p) < 6:
            continue
        try:
            t = float(p[2])
        except ValueError:
            continue
        lag = 0.0
        if len(p) >= 7:
            try:
                lag = float(p[6])
            except ValueError:
                lag = 0.0
        lat.append(t / 1000.0)
        svc.append(max(0.0, t - lag) / 1000.0)
    return lat, svc


def cmd_pgbench(args: argparse.Namespace) -> int:
    with open(args.summary, encoding="utf-8", errors="replace") as f:
        summary = pgbench_summary(f.read())
    lines: list[str] = []
    for p in args.log:
        with open(p, encoding="utf-8", errors="replace") as f:
            lines.extend(f.readlines())
    lat, svc = pgbench_latencies(lines)
    summary.update({"logged": len(lat), "p50_ms": percentile(lat, 50), "p95_ms": percentile(lat, 95),
                    "p99_ms": percentile(lat, 99), "service_p95_ms": percentile(svc, 95)})
    print(json.dumps(summary))
    return 0


SYSBENCH_READ = re.compile(r"^\s*read:\s+(\d+)", re.M)
SYSBENCH_EVENTS = re.compile(r"total number of events:\s+(\d+)")
SYSBENCH_ERRORS = re.compile(r"ignored errors:\s+(\d+)")
SYSBENCH_PCT = re.compile(r"(\d+)th percentile:\s+([\d.]+)")
SYSBENCH_AVG = re.compile(r"^\s*avg:\s+([\d.]+)", re.M)


def sysbench_summary(text: str) -> dict:
    def num(rx: re.Pattern[str], cast=int):  # type: ignore[no-untyped-def]
        m = rx.search(text)
        return cast(m.group(1)) if m else None

    pct = SYSBENCH_PCT.search(text)
    return {"events": num(SYSBENCH_EVENTS), "reads": num(SYSBENCH_READ), "errors": num(SYSBENCH_ERRORS) or 0,
            "percentile": int(pct.group(1)) if pct else None,
            "p95_ms": float(pct.group(2)) if pct and pct.group(1) == "95" else None,
            "avg_ms": num(SYSBENCH_AVG, float)}


def cmd_sysbench(args: argparse.Namespace) -> int:
    with open(args.summary, encoding="utf-8", errors="replace") as f:
        print(json.dumps(sysbench_summary(f.read())))
    return 0


# ------------------------------------------------------------------------------------ report


@dataclass
class Limits:
    discovery_pct: float = 2.0  # MVP criterion (docs/04-mvp-scope.md)
    p95_factor: float = 3.0  # Audit on: p95 <= factor x p95 off + slack
    p95_slack_ms: float = 5.0
    events_min_ratio: float = 0.99  # events received / statements issued
    events_max_ratio: float = 1.01
    drain_s: float = 240.0  # workload end -> every statement stored
    agent_cpu_cores: float = 1.0  # average over the Audit-on run
    agent_rss_mb: float = 256.0  # peak
    rss_abs_mb: float = 8.0  # growth tolerance
    rss_rel: float = 0.10
    cpu_abs_cores: float = 0.05
    cpu_rel: float = 0.5
    spool_max_batches: int = 1000  # peak spooled batches over the run

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "Limits":
        lim = cls()
        for f in lim.__dataclass_fields__:
            key = "LOAD_LIMIT_" + f.upper()
            if key in env and env[key] != "":
                cur = getattr(lim, f)
                setattr(lim, f, type(cur)(env[key]))
        return lim


@dataclass
class Checks:
    items: list[dict] = field(default_factory=list)

    def add(self, name: str, ok: bool | None, value: object, limit: object, note: str = "") -> None:
        self.items.append({"name": name, "pass": ok, "value": value, "limit": limit, "note": note})

    @property
    def passed(self) -> bool:
        return all(c["pass"] is True for c in self.items)


def _r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


def facts_of(rows: list[dict], kind: str) -> list[dict]:
    return [r for r in rows if r.get("kind") == kind]


def one_fact(rows: list[dict], kind: str, **match: object) -> dict | None:
    for r in rows:
        if r.get("kind") == kind and all(r.get(k) == v for k, v in match.items()):
            return r
    return None


def discovery_impact(samples: list[dict], container: str, t0: float, t1: float,
                     idle: tuple[float, float] | None) -> dict:
    """The database CPU impact of one scan (see the module docstring)."""
    cpu = series(samples, container, "cpu_usec")
    caps = [c for _, c in series(samples, container, "cap")]
    cap = caps[-1] if caps else None
    out: dict = {"scan_s": _r(t1 - t0), "capacity_cpus": cap}
    b = bracket(cpu, t0, t1)
    if b is None or cap is None or t1 <= t0:
        out["error"] = "no samples around the scan"
        return out
    used_s = b[0] / 1e6
    idle_rate = rate(cpu, idle[0], idle[1], 1e6) if idle else None
    if idle_rate is None:
        out["error"] = "no idle baseline"
        return out
    attributable = max(0.0, used_s - idle_rate * (b[2] - b[1]))
    out.update({"db_cpu_s": _r(used_s), "measured_s": _r(b[2] - b[1]), "idle_cores": _r(idle_rate, 4),
                "attributable_cpu_s": _r(attributable),
                "impact_pct": _r(100.0 * attributable / ((t1 - t0) * cap)),
                "one_core_pct": _r(100.0 * attributable / (t1 - t0)),
                # What a CPU graph at a one-minute resolution shows for a shorter scan (informational).
                "impact_pct_60s": _r(100.0 * attributable / (max(t1 - t0, 60.0) * cap))})
    return out


def host_busy(samples: list[dict], t0: float, t1: float) -> float | None:
    h = [(t, b, tot) for t, b, tot in host_series(samples) if t0 <= t <= t1]
    if len(h) < 2 or h[-1][2] <= h[0][2]:
        return None
    return 100.0 * (h[-1][1] - h[0][1]) / (h[-1][2] - h[0][2])


def build_report(facts: list[dict], samples: list[dict], heartbeats: list[dict], lim: Limits) -> tuple[dict, Checks]:
    ck = Checks()
    rep: dict = {"version": 1, "limits": lim.__dict__.copy()}
    cfg = one_fact(facts, "config")
    rep["config"] = {k: v for k, v in (cfg or {}).items() if k != "kind"}
    containers = {r["target"]: r["container"] for r in facts_of(facts, "target")}

    # ---- 1. Discovery
    idle_a = one_fact(facts, "window", name="idle_no_agent")
    idle_b = one_fact(facts, "window", name="idle_agent")
    disc: dict = {}
    for scan in facts_of(facts, "scan"):
        target = scan["target"]
        cont = containers.get(target, "")
        d = discovery_impact(samples, cont, scan["t0"], scan["t1"],
                             (idle_a["t0"], idle_a["t1"]) if idle_a else None)
        # Informational: the same with the agent's idle rate (heartbeat checks) as baseline.
        if idle_b:
            d2 = discovery_impact(samples, cont, scan["t0"], scan["t1"], (idle_b["t0"], idle_b["t1"]))
            d["impact_pct_vs_agent_idle"] = d2.get("impact_pct")
            d["agent_idle_cores"] = d2.get("idle_cores")
        for k in ("status", "rows", "tables", "stmt_exec_ms", "stmt_calls"):
            if k in scan:
                d[k] = scan[k]
        if d.get("attributable_cpu_s") is not None and scan.get("tables"):
            d["attributable_ms_per_object"] = _r(1000.0 * d["attributable_cpu_s"] / scan["tables"], 2)
            d["scan_ms_per_object"] = _r(1000.0 * (scan["t1"] - scan["t0"]) / scan["tables"], 2)
        found = one_fact(facts, "findings", target=target)
        d["findings"] = found.get("count") if found else None
        d["host_busy_pct"] = _r(host_busy(samples, scan["t0"], scan["t1"]), 1)
        disc[target] = d
        ck.add(f"discovery.{target}.succeeded", scan.get("status") == "succeeded", scan.get("status"), "succeeded")
        # A scan shorter than a minute is judged over one minute: below the 0.5 s CPU sampling and a
        # session's fixed cost, the per-scan average measures noise, not load (a 0.6 s scan using 0.04 s
        # of CPU reads 3.6 %). Scans of a minute or more are judged over their own duration, as before.
        short = d.get("scan_s") is not None and d["scan_s"] < 60.0
        judged = d.get("impact_pct_60s") if short else d.get("impact_pct")
        d["impact_judged_pct"] = judged
        ck.add(f"discovery.{target}.db_cpu_impact_pct", None if judged is None
               else judged < lim.discovery_pct, judged, f"< {lim.discovery_pct}",
               d.get("error", "share of the DB server's CPU capacity added during the scan"
                     + (" (scan under 60 s: averaged over 60 s)" if short else "")))
    rep["discovery"] = disc

    # ---- 2. Audit under load
    audit: dict = {}
    w_off = one_fact(facts, "window", name="workload_audit_off")
    w_on = one_fact(facts, "window", name="workload_audit_on")
    for wl in facts_of(facts, "workload"):
        if wl.get("phase") != "on":
            continue
        target = wl["target"]
        off = one_fact(facts, "workload", target=target, phase="off") or {}
        ev = one_fact(facts, "events", target=target) or {}
        a: dict = {"tool": wl.get("tool"), "rate": wl.get("rate")}
        issued_on = wl.get("issued")
        a["issued_audit_off"] = off.get("issued")
        a["issued_audit_on"] = issued_on
        a["failed_audit_on"] = wl.get("failed")
        a["p95_ms_audit_off"] = off.get("p95_ms")
        a["p95_ms_audit_on"] = wl.get("p95_ms")
        if off.get("p95_ms") is not None and wl.get("p95_ms") is not None:
            a["p95_added_ms"] = _r(wl["p95_ms"] - off["p95_ms"])
            a["p95_added_pct"] = _r(100.0 * (wl["p95_ms"] - off["p95_ms"]) / off["p95_ms"], 1) if off["p95_ms"] else None
        for k in ("service_p95_ms", "p99_ms"):
            if k in wl:
                a[f"{k}_audit_on"] = wl[k]
            if k in off:
                a[f"{k}_audit_off"] = off[k]
        src = one_fact(facts, "source", target=target)
        a["source_statements"] = src.get("statements") if src else None
        a["source_rotated_files"] = src.get("rotated_files") if src else None
        tl = one_fact(facts, "events_timeline", target=target)
        if tl:
            a["events_timeline_10s"] = tl.get("buckets")
        a["events_received"] = ev.get("received")
        a["events_rows"] = ev.get("events")
        a["lag_p95_s"] = ev.get("lag_p95_s")
        a["drain_s"] = ev.get("drain_s")
        cont = containers.get(target, "")
        cpu = series(samples, cont, "cpu_usec")
        if w_off:
            a["db_cores_audit_off"] = _r(rate(cpu, w_off["t0"], w_off["t1"], 1e6), 4)
        if w_on:
            a["db_cores_audit_on"] = _r(rate(cpu, w_on["t0"], w_on["t1"], 1e6), 4)
        audit[target] = a
        ok_wl = issued_on is not None and issued_on > 0 and not wl.get("failed")
        ck.add(f"audit.{target}.workload_ran", ok_wl, {"issued": issued_on, "failed": wl.get("failed")}, "> 0 issued, 0 failed")
        if issued_on:
            ratio = (ev.get("received") or 0) / issued_on
            a["events_ratio"] = _r(ratio, 4)
            ck.add(f"audit.{target}.events_accounted", lim.events_min_ratio <= ratio <= lim.events_max_ratio,
                   _r(ratio, 4), f"[{lim.events_min_ratio}, {lim.events_max_ratio}]",
                   "sum of aggregated_count of the workload principal's read events / statements issued")
        ck.add(f"audit.{target}.drain_s", None if ev.get("drain_s") is None else ev["drain_s"] <= lim.drain_s,
               ev.get("drain_s"), f"<= {lim.drain_s}", "workload end -> every statement stored")
        p_off, p_on = off.get("p95_ms"), wl.get("p95_ms")
        bound = None if p_off is None else _r(lim.p95_factor * p_off + lim.p95_slack_ms)
        ck.add(f"audit.{target}.p95_latency_ms", None if p_on is None or bound is None else p_on <= bound,
               p_on, f"<= {bound}", f"{lim.p95_factor} x p95 without Audit ({p_off} ms) + {lim.p95_slack_ms} ms")
    rep["audit"] = audit

    # ---- 2b. Side accounts of the Audit run (ADR-0045): a monitoring-like reader of statement-text
    # tables (at most one event per principal, object set and aggregation window) and a table-less
    # built-in mix (no event but connections). Their statements are not in the workload's count.
    side: dict = {}
    for s in facts_of(facts, "side_events"):
        target, account, role = s.get("target"), s.get("account"), s.get("role")
        runs = [w for w in facts_of(facts, "side") if w.get("target") == target and w.get("account") == account]
        on = [w for w in runs if w.get("phase") == "on"]
        issued = sum(int(w.get("issued") or 0) for w in on)
        failed = sum(int(w.get("failed") or 0) for w in runs)
        e = {"account": account, "issued_audit_on": issued, "failed": failed}
        for k in ("events", "received", "groups", "max_events_per_group", "max_excess", "non_connect",
                  "objects", "window_s"):
            e[k] = s.get(k)
        side[f"{target}/{role}"] = e
        ck.add(f"audit.{target}.{role}_ran", bool(runs) and issued > 0 and failed == 0,
               {"issued": issued, "failed": failed}, "> 0 issued, 0 failed", f"side account {account}")
        if role == "monitor":
            got = {str(o).lower() for o in (s.get("objects") or [])}
            want = [str(o) for o in (s.get("expected") or [])]
            missing = [o for o in want if o.lower() not in got]
            ck.add(f"audit.{target}.monitor_reported", bool(want) and not missing, s.get("objects"),
                   f"names {want}", "reads of statement-text tables name them (ADR-0045 part (a))")
            ex = s.get("max_excess")
            ck.add(f"audit.{target}.monitor_one_event_per_window",
                   None if ex is None or not s.get("events") else ex <= 0, ex,
                   "<= 0",
                   "per principal, action, source and object set: events - (floor(span / window) + 2), "
                   "the most windows of the agent's aggregator that span can meet")
        elif role == "builtins":
            nc, n = s.get("non_connect"), s.get("events")
            ck.add(f"audit.{target}.builtins_no_event", None if nc is None or n is None else nc == 0 and n >= 1,
                   {"non_connect": nc, "events": n}, "0 non-connect, >= 1 connect",
                   "table-less built-in calls (ADR-0045 part (b)): no event but connections, and the "
                   "account's connection was audited (the stream saw it)")
    if side:
        rep["side"] = side

    # ---- 3. Agent resources and spool
    agent: dict = {}
    cpu = series(samples, "agent", "cpu_usec")
    rss = series(samples, "agent", "rss")
    if w_on:
        t0, t1 = w_on["t0"], w_on["t1"]
        cores = rate(cpu, t0, t1, 1e6)
        agent["cpu_cores_audit_on"] = _r(cores, 4)
        rss_w = [(t, v / 2**20) for t, v in rss if t0 <= t <= t1]
        rv = [v for _, v in rss_w]
        agent["rss_mb_audit_on"] = {"min": _r(min(rv), 1) if rv else None, "max": _r(max(rv), 1) if rv else None,
                                    "median": _r(median(rv), 1)}
        g = growth(rss_w, 0.2, lim.rss_abs_mb, lim.rss_rel)
        agent["rss_growth"] = g
        cg = growth(segment_rates(cpu, t0, t1, 30, 1e6), 0.2, lim.cpu_abs_cores, lim.cpu_rel)
        agent["cpu_growth"] = cg
        issued = sum((w.get("issued") or 0) for w in facts_of(facts, "workload") if w.get("phase") == "on")
        d = inner(cpu, t0, t1)
        if d and issued:
            agent["cpu_ms_per_1000_statements"] = _r(d[0] / 1e3 / issued * 1000, 2)
        ck.add("agent.cpu_cores_audit_on", None if cores is None else cores <= lim.agent_cpu_cores,
               _r(cores, 4), f"<= {lim.agent_cpu_cores}")
        ck.add("agent.cpu_no_monotonic_growth", cg.get("ok"), cg.get("medians"),
               f"not (m1 < m2 < m3 and m3 - m1 > max({lim.cpu_abs_cores}, {lim.cpu_rel} x m1))", cg.get("reason", ""))
        ck.add("agent.rss_no_monotonic_growth", g.get("ok"), g.get("medians"),
               f"not (m1 < m2 < m3 and m3 - m1 > max({lim.rss_abs_mb} MiB, {lim.rss_rel} x m1))", g.get("reason", ""))
    if w_off:
        agent["cpu_cores_audit_off"] = _r(rate(cpu, w_off["t0"], w_off["t1"], 1e6), 4)
    all_rss = [v / 2**20 for _, v in rss]
    agent["rss_mb_peak"] = _r(max(all_rss), 1) if all_rss else None
    hwm = [v / 2**20 for _, v in series(samples, "agent", "hwm")]
    agent["rss_mb_hwm"] = _r(max(hwm), 1) if hwm else None
    ck.add("agent.rss_peak_mb", None if agent["rss_mb_peak"] is None else agent["rss_mb_peak"] <= lim.agent_rss_mb,
           agent["rss_mb_peak"], f"<= {lim.agent_rss_mb}")

    spools = [h.get("spool") or {} for h in heartbeats]
    batches = [int(s.get("batches", 0)) for s in spools]
    last = heartbeats[-1] if heartbeats else {}
    last_spool = last.get("spool") or {}
    metrics = last.get("metrics") or {}
    agent["spool"] = {"max_batches": max(batches) if batches else None,
                      "max_bytes": max((int(s.get("bytes", 0)) for s in spools), default=None),
                      "final_batches": last_spool.get("batches"),
                      "dropped_batches": last_spool.get("dropped_batches", 0),
                      "dropped_items": last_spool.get("dropped_items", 0),
                      "heartbeats": len(heartbeats)}
    keys = ("events_received_total", "events_filtered_total", "events_lost_total", "findings_lost_total",
            "batches_sent_total", "batches_rejected_total", "batches_serialization_failed_total",
            "audit_stream_failures_total", "audit_records_skipped_total", "audit_record_panics_total",
            "connector_panics_total", "spool_rejected_batches_total")
    agent["metrics"] = {k: metrics.get(k) for k in keys}
    drained = one_fact(facts, "spool_drained")
    ck.add("agent.spool_bounded", bool(batches) and max(batches) <= lim.spool_max_batches,
           max(batches) if batches else None, f"<= {lim.spool_max_batches} batches (peak)")
    ck.add("agent.spool_drained", bool(drained and drained.get("ok")), (drained or {}).get("batches"),
           "0 batches in a heartbeat after the drain")
    ck.add("agent.no_dropped_batches", last_spool.get("dropped_batches", 0) == 0 and last_spool.get("dropped_items", 0) == 0,
           {"batches": last_spool.get("dropped_batches", 0), "items": last_spool.get("dropped_items", 0)}, "0")
    for k in ("events_lost_total", "findings_lost_total", "audit_stream_failures_total",
              "audit_records_skipped_total", "audit_record_panics_total", "connector_panics_total",
              "batches_rejected_total"):
        v = metrics.get(k)
        ck.add(f"agent.{k}", v is not None and v == 0, v, "0")
    lost = one_fact(facts, "agent_log")
    if lost is not None:
        ck.add("agent.log_no_lost_batches", lost.get("lost") == 0, lost.get("lost"), "0 lines")
    rep["agent"] = agent
    rep["checks"] = ck.items
    rep["pass"] = ck.passed
    return rep, ck


def render_markdown(rep: dict) -> str:
    def fmt(v: object) -> str:
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:g}"
        if isinstance(v, (dict, list)):
            return json.dumps(v, separators=(",", ":"))
        return str(v)

    out = ["# DataBastion load / database impact results", ""]
    out.append(f"**Result: {'PASS' if rep.get('pass') else 'FAIL'}**")
    out.append("")
    cfg = rep.get("config") or {}
    if cfg:
        out.append("Configuration: " + ", ".join(f"`{k}={fmt(v)}`" for k, v in sorted(cfg.items())))
        out.append("")
    out += ["## 1. Database CPU impact of Discovery", "",
            "Share of the database server's CPU capacity added by the scan, averaged over the scan "
            "(idle baseline without the agent subtracted). MVP criterion: < 2 % (a scan shorter than 60 s is judged on the Over 60 s column).", "",
            "| Target | Objects | Rows | Findings | Scan (s) | DB CPU (s) | Attributable (s) | ms / object | Capacity (CPUs) | Impact (%) | vs agent idle (%) | % of one core | Over 60 s (%) | Agent stmt exec (ms) |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for t, d in sorted((rep.get("discovery") or {}).items()):
        out.append(f"| {t} | {fmt(d.get('tables'))} | {fmt(d.get('rows'))} | {fmt(d.get('findings'))} | {fmt(d.get('scan_s'))} | "
                   f"{fmt(d.get('db_cpu_s'))} | {fmt(d.get('attributable_cpu_s'))} | {fmt(d.get('attributable_ms_per_object'))} | "
                   f"{fmt(d.get('capacity_cpus'))} | **{fmt(d.get('impact_pct'))}** | "
                   f"{fmt(d.get('impact_pct_vs_agent_idle'))} | {fmt(d.get('one_core_pct'))} | {fmt(d.get('impact_pct_60s'))} | "
                   f"{fmt(d.get('stmt_exec_ms'))} |")
    out += ["", "## 2. Audit path under load", "",
            "| Target | Tool | Rate | Issued (Audit on) | In the target's log | Events received | Ratio | Drain (s) | Lag p95 (s) | p95 off (ms) | p95 on (ms) | Added (ms) | DB cores off / on |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for t, a in sorted((rep.get("audit") or {}).items()):
        out.append(f"| {t} | {fmt(a.get('tool'))} | {fmt(a.get('rate'))} | {fmt(a.get('issued_audit_on'))} | "
                   f"{fmt(a.get('source_statements'))} | {fmt(a.get('events_received'))} | {fmt(a.get('events_ratio'))} | {fmt(a.get('drain_s'))} | "
                   f"{fmt(a.get('lag_p95_s'))} | {fmt(a.get('p95_ms_audit_off'))} | {fmt(a.get('p95_ms_audit_on'))} | "
                   f"{fmt(a.get('p95_added_ms'))} | {fmt(a.get('db_cores_audit_off'))} / {fmt(a.get('db_cores_audit_on'))} |")
    if rep.get("side"):
        out += ["", "Side accounts of the Audit run (not in the workload counts): a monitoring-like reader and a "
                "table-less built-in mix.", "",
                "| Target / role | Account | Issued (Audit on) | Events | Received | Groups | Most events in a group | Excess over the windows | Non-connect events | Objects |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        for k, e in sorted(rep["side"].items()):
            out.append(f"| {k} | {fmt(e.get('account'))} | {fmt(e.get('issued_audit_on'))} | {fmt(e.get('events'))} | "
                       f"{fmt(e.get('received'))} | {fmt(e.get('groups'))} | {fmt(e.get('max_events_per_group'))} | "
                       f"{fmt(e.get('max_excess'))} | {fmt(e.get('non_connect'))} | {fmt(e.get('objects'))} |")
    ag = rep.get("agent") or {}
    out += ["", "## 3. Agent resources", ""]
    for k in ("cpu_cores_audit_off", "cpu_cores_audit_on", "cpu_ms_per_1000_statements", "rss_mb_audit_on",
              "rss_mb_peak", "rss_mb_hwm", "rss_growth", "cpu_growth", "spool", "metrics"):
        out.append(f"- `{k}`: {fmt(ag.get(k))}")
    out += ["", "## Checks", "", "| Check | Result | Value | Limit | Note |", "|---|---|---|---|---|"]
    for c in rep.get("checks") or []:
        res = {True: "pass", False: "**FAIL**", None: "**no data**"}[c["pass"]]
        out.append(f"| `{c['name']}` | {res} | {fmt(c['value'])} | {fmt(c['limit'])} | {c.get('note', '')} |")
    return "\n".join(out) + "\n"


def cmd_report(args: argparse.Namespace) -> int:
    facts = load_jsonl([args.facts])
    samples = load_jsonl(args.samples)
    samples.sort(key=lambda s: s.get("t", 0))
    heartbeats = load_jsonl([args.heartbeats]) if args.heartbeats else []
    lim = Limits.from_env(dict(os.environ))
    rep, ck = build_report(facts, samples, heartbeats, lim)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, sort_keys=True)
        f.write("\n")
    md = render_markdown(rep)
    with open(os.path.join(args.out, "results.md"), "w", encoding="utf-8") as f:
        f.write(md)
    for c in ck.items:
        if c["pass"] is not True:
            print(f"loadlib: check {c['name']}: {'failed' if c['pass'] is False else 'no data'} "
                  f"(value {c['value']}, limit {c['limit']})", file=sys.stderr)
    return 0 if ck.passed else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--out", required=True)
    s.add_argument("--interval", type=float, default=0.5)
    s.add_argument("containers", nargs="+")
    pb = sub.add_parser("pgbench")
    pb.add_argument("--summary", required=True)
    pb.add_argument("--log", nargs="+", required=True)
    sb = sub.add_parser("sysbench")
    sb.add_argument("--summary", required=True)
    q = sub.add_parser("quiet")
    q.add_argument("--samples", required=True)
    q.add_argument("--names", required=True, help="comma-separated sample names")
    q.add_argument("--below", type=float, default=0.05)
    q.add_argument("--window", type=float, default=5.0)
    q.add_argument("--timeout", type=float, default=120.0)
    r = sub.add_parser("report")
    r.add_argument("--facts", required=True)
    r.add_argument("--samples", nargs="+", required=True)
    r.add_argument("--heartbeats")
    r.add_argument("--out", required=True)
    a = p.parse_args(argv)
    return {"sample": cmd_sample, "pgbench": cmd_pgbench, "sysbench": cmd_sysbench, "quiet": cmd_quiet,
            "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
