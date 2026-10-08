#!/usr/bin/env python3
"""CAS login traffic of the end-to-end and load runs (ROADMAP P8-D, ADR-0041 decision 14).
Python standard library only; unit tests in test_cas_scenario.py.

Drives the CAS dev overlay (e2e/docker-compose.cas.yml, e2e/load/docker-compose.cas.yml) over plain
HTTP on 127.0.0.1, as a browser would: GET /cas/login (the form's `execution`), POST the credentials,
then, for a service, read the service ticket from the redirect and validate it
(p3/serviceValidate). Every login uses a fresh cookie jar (no SSO session reuse), so each one writes
an AUTHENTICATION_SUCCESS, a TICKET_GRANTING_TICKET_CREATED and a SERVICE_TICKET_CREATED record.

Subcommands
  logins    One login per --user (repeated --rounds times) for --service, each service ticket
            validated. Every one-time value obtained is written to --patterns, one file per value
            (never printed): the service ticket (`st_<n>`), its SHA-256 and SHA-512 hex digests
            (`st_<n>_sha256`, `st_<n>_sha512`), and the ticket-granting cookie (`tgc_<n>`). The
            password is read from --password-file. --no-validate leaves the tickets unvalidated, so
            they stay in the ticket registry (until they expire).
  failures  --count failed logins from this host, each with a distinct typed name, with a random
            wrong password: a credential-stuffing burst (ADR-0041 decision 8:
            `volume.failed_logins_many_accounts` from the 16th distinct name). The typed names go to
            --names (`name_<n>`, they must reach the console as fingerprints only; one of them is
            a random password-like string, a password typed into the username field); the wrong
            passwords to --patterns (`typed_password_<n>`).
  load      Fixed-rate logins for --duration seconds: --rate successful logins per second (with a
            validated service ticket) and --fail-rate failed ones (random typed names), on --workers
            threads. Writes --out (JSON): counts per kind, failed requests, and the latency of the
            credential POST (p50 / p95 / p99, ms). No one-time value is kept.

Output: one JSON object of counts on stdout. Never a ticket, a cookie, a password or a typed name:
the CI log must not become the leak.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import math
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

TIMEOUT_S = 30
# The first login page after a start is slow (webflow initialization).
FIRST_TIMEOUT_S = 90
MAX_BODY = 4 * 1024 * 1024
CAS_NS = {"cas": "http://www.yale.edu/tp/cas"}
_EXECUTION = re.compile(r'name="execution"\s+value="([^"]+)"')
# Ticket ids of CAS (ADR-0041 decision 5, the tripwire's shape): a prefix, a counter, then more.
TICKET_RE = re.compile(r"^(TGT|ST|PT|PGT|OC|AT|RT|[A-Z]{2,8})-\d+-[A-Za-z0-9._-]+$")


class ScenarioError(Exception):
    """A step failed. The message names the step and an HTTP status, never a value."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def opener() -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    """A fresh browser: its own cookie jar, no redirect followed, no proxy (127.0.0.1 only)."""
    jar = http.cookiejar.CookieJar()
    o = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
        _NoRedirect(),
    )
    return o, jar


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str


def request(o: urllib.request.OpenerDirector, url: str, data: dict[str, str] | None = None,
            timeout: float = TIMEOUT_S) -> Response:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if body is not None else "GET")
    try:
        with o.open(req, timeout=timeout) as r:
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()},
                            r.read(MAX_BODY).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        payload = e.read(MAX_BODY).decode("utf-8", "replace") if e.fp else ""
        return Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, payload)


def execution_of(html: str) -> str:
    """The login form's webflow `execution` value."""
    m = _EXECUTION.search(html)
    if not m:
        raise ScenarioError("login form: no execution field")
    return m.group(1)


def ticket_of(location: str, service: str) -> str:
    """The service ticket of a redirect to `service` (exactly one `ticket` parameter)."""
    url = urllib.parse.urlparse(location)
    base = urllib.parse.urlunparse(url._replace(query="", fragment=""))
    if base != service:
        raise ScenarioError("login: redirected elsewhere than the service")
    tickets = urllib.parse.parse_qs(url.query).get("ticket", [])
    if len(tickets) != 1 or not tickets[0].startswith("ST-") or not TICKET_RE.match(tickets[0]):
        raise ScenarioError("login: no service ticket in the redirect")
    return tickets[0]


def validated_user(xml_text: str) -> str | None:
    """The user of a successful p3/serviceValidate answer, else None."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    user = root.find("cas:authenticationSuccess/cas:user", CAS_NS)
    return user.text if user is not None else None


@dataclass
class Login:
    status: int
    ticket: str | None = None
    tgc: str | None = None
    post_ms: float = 0.0


def login(base: str, user: str, password: str, service: str | None,
          first: bool = False) -> Login:
    """One login with a fresh cookie jar. Raises ScenarioError on an unexpected answer."""
    o, jar = opener()
    query = "?service=" + urllib.parse.quote(service, safe="") if service else ""
    form = request(o, f"{base}/login{query}", timeout=FIRST_TIMEOUT_S if first else TIMEOUT_S)
    if form.status != 200:
        raise ScenarioError(f"login form: HTTP {form.status}")
    data = {"username": user, "password": password, "execution": execution_of(form.body),
            "_eventId": "submit"}
    t0 = time.monotonic()
    r = request(o, f"{base}/login{query}", data)
    out = Login(r.status, post_ms=(time.monotonic() - t0) * 1000)
    for c in jar:
        if c.name == "TGC":
            out.tgc = c.value
    if service and r.status == 302:
        out.ticket = ticket_of(r.headers.get("location", ""), service)
    return out


def validate(base: str, service: str, ticket: str) -> str | None:
    o, _ = opener()
    r = request(o, f"{base}/p3/serviceValidate?service={urllib.parse.quote(service, safe='')}"
                   f"&ticket={urllib.parse.quote(ticket, safe='')}")
    return validated_user(r.body) if r.status == 200 else None


def write_value(directory: str, name: str, value: str) -> None:
    """One value per file (0600), as e2e/run.sh's secret registry: read by grep -Ff, never printed."""
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")


def record_ticket(directory: str, n: int, ticket: str, tgc: str | None) -> None:
    write_value(directory, f"st_{n}", ticket)
    write_value(directory, f"st_{n}_sha256", hashlib.sha256(ticket.encode()).hexdigest())
    write_value(directory, f"st_{n}_sha512", hashlib.sha512(ticket.encode()).hexdigest())
    if tgc:
        write_value(directory, f"tgc_{n}", tgc)


def next_index(directory: str, prefix: str) -> int:
    """First free `<prefix><n>` index in the directory (several calls add to one registry)."""
    taken = set()
    for name in os.listdir(directory):
        m = re.fullmatch(re.escape(prefix) + r"(\d+)", name)
        if m:
            taken.add(int(m.group(1)))
    return max(taken, default=-1) + 1


def read_password(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        pw = f.read().strip()
    if not pw:
        raise ScenarioError("empty password file")
    return pw


def cmd_logins(args: argparse.Namespace) -> dict:
    password = read_password(args.password_file)
    n = next_index(args.patterns, "st_")
    done = 0
    first = True
    for _ in range(args.rounds):
        for user in args.user:
            r = login(args.base, user, password, args.service, first=first)
            first = False
            if r.status != 302 or not r.ticket:
                raise ScenarioError(f"login of user #{args.user.index(user)}: HTTP {r.status}")
            record_ticket(args.patterns, n, r.ticket, r.tgc)
            if args.no_validate:
                pass
            elif validate(args.base, args.service, r.ticket) != user:
                raise ScenarioError(f"service ticket of user #{args.user.index(user)} not validated")
            n += 1
            done += 1
    return {"logins": done, "service_tickets": done, "validated": 0 if args.no_validate else done}


def cmd_failures(args: argparse.Namespace) -> dict:
    if args.count < 1:
        raise ScenarioError("--count must be positive")
    refused = 0
    first = True
    for i in range(args.count):
        # One name is a random password-like string: what a user types in the wrong field.
        if i == args.count // 2:
            name = "Pw" + secrets.token_urlsafe(18)
        else:
            name = f"e2e-stuffing-{secrets.token_hex(6)}-{i:02d}@example.invalid"
        write_value(args.names, f"name_{i}", name)
        wrong = "wrong-" + secrets.token_urlsafe(18)
        write_value(args.patterns, f"typed_password_{i}", wrong)
        r = login(args.base, name, wrong, None, first=first)
        first = False
        if r.status != 401:
            raise ScenarioError(f"failed login #{i}: HTTP {r.status}, expected 401")
        refused += 1
    return {"failed_logins": refused, "distinct_names": args.count}


# ------------------------------------------------------------------------------ load
def percentile(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile (p in 0..100), None without values."""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil(p / 100.0 * len(s)) - 1))
    return s[k]


def schedule(rate: float, duration: float) -> list[float]:
    """Offsets (s) of a fixed-rate schedule: `rate` per second over `duration` seconds."""
    if rate <= 0 or duration <= 0:
        return []
    n = int(rate * duration)
    return [i / rate for i in range(n)]


@dataclass
class LoadStats:
    ok: int = 0
    failed_ok: int = 0
    errors: dict[str, int] = field(default_factory=dict)
    post_ms: list[float] = field(default_factory=list)
    fail_post_ms: list[float] = field(default_factory=list)
    late: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def error(self, kind: str) -> None:
        with self.lock:
            self.errors[kind] = self.errors.get(kind, 0) + 1


def cmd_load(args: argparse.Namespace) -> dict:
    password = read_password(args.password_file)
    stats = LoadStats()
    ok_plan = [(t, "ok") for t in schedule(args.rate, args.duration)]
    fail_plan = [(t, "fail") for t in schedule(args.fail_rate, args.duration)]
    plan = sorted(ok_plan + fail_plan)
    users = args.user

    def one(i: int, kind: str) -> None:
        try:
            if kind == "ok":
                user = users[i % len(users)]
                r = login(args.base, user, password, args.service)
                if r.status != 302 or not r.ticket:
                    stats.error(f"login_http_{r.status}")
                    return
                if validate(args.base, args.service, r.ticket) != user:
                    stats.error("validate")
                    return
                with stats.lock:
                    stats.ok += 1
                    stats.post_ms.append(r.post_ms)
            else:
                name = f"load-{secrets.token_hex(6)}@example.invalid"
                r = login(args.base, name, "wrong-" + secrets.token_urlsafe(12), None)
                if r.status != 401:
                    stats.error(f"failure_http_{r.status}")
                    return
                with stats.lock:
                    stats.failed_ok += 1
                    stats.fail_post_ms.append(r.post_ms)
        except (ScenarioError, OSError) as e:
            stats.error(type(e).__name__)

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, (offset, kind) in enumerate(plan):
            delay = start + offset - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            elif delay < -1.0:
                stats.late += 1
            pool.submit(one, i, kind)
    elapsed = time.monotonic() - start
    out = {
        "planned_logins": len(ok_plan),
        "planned_failures": len(fail_plan),
        "logins": stats.ok,
        "failed_logins": stats.failed_ok,
        "errors": dict(sorted(stats.errors.items())),
        "late_starts": stats.late,
        "elapsed_s": round(elapsed, 1),
        "post_ms": {p: (round(v, 1) if v is not None else None) for p, v in
                    (("p50", percentile(stats.post_ms, 50)), ("p95", percentile(stats.post_ms, 95)),
                     ("p99", percentile(stats.post_ms, 99)))},
        "fail_post_ms_p95": (round(percentile(stats.fail_post_ms, 95), 1)
                             if stats.fail_post_ms else None),
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=True)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("logins")
    lg.add_argument("--base", required=True, help="CAS prefix, e.g. http://127.0.0.1:8281/cas")
    lg.add_argument("--password-file", required=True)
    lg.add_argument("--user", action="append", required=True)
    lg.add_argument("--service", required=True)
    lg.add_argument("--rounds", type=int, default=1)
    lg.add_argument("--patterns", required=True)
    lg.add_argument("--no-validate", action="store_true",
                    help="leave the service tickets unvalidated (they stay in the ticket registry)")
    fl = sub.add_parser("failures")
    fl.add_argument("--base", required=True)
    fl.add_argument("--count", type=int, required=True)
    fl.add_argument("--patterns", required=True)
    fl.add_argument("--names", required=True)
    ld = sub.add_parser("load")
    ld.add_argument("--base", required=True)
    ld.add_argument("--password-file", required=True)
    ld.add_argument("--user", action="append", required=True)
    ld.add_argument("--service", required=True)
    ld.add_argument("--rate", type=float, required=True)
    ld.add_argument("--fail-rate", type=float, default=0.0)
    ld.add_argument("--duration", type=float, required=True)
    ld.add_argument("--workers", type=int, default=16)
    ld.add_argument("--out")
    args = p.parse_args(argv)
    if not args.base.startswith("http://127.0.0.1:"):
        print("cas scenario: error: --base must be http://127.0.0.1:<port>/cas", file=sys.stderr)
        return 2
    try:
        out = {"logins": cmd_logins, "failures": cmd_failures, "load": cmd_load}[args.cmd](args)
    except (ScenarioError, OSError) as e:
        # Messages name a step and an HTTP status or an error class, never a value.
        print(f"cas scenario {args.cmd}: FAIL {e if isinstance(e, ScenarioError) else type(e).__name__}",
              file=sys.stderr)
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
