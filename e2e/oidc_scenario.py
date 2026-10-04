#!/usr/bin/env python3
"""End-to-end OIDC login scenario (ROADMAP P8-D, ADR-0038 decisions 2, 3, 6 to 9, 11, 14, 15, 17).

Driven by e2e/oidc.sh, which starts the console (production build) and Keycloak (HTTPS, certificate
from the run's throwaway CA) and runs this script twice, once per console configuration:

- ``signup-off``: sign-up off (the default), ``ALLOWED_GROUPS`` and ``ALLOWED_DOMAINS`` set, strict
  role mapping. Refused group, unverified e-mail, pending logins approved as new users only with
  the role mapped from their group (role sync on: another role is ``409 role_mismatch``), role mapped
  from the group at every login (promotion and demotion after a group change at the provider), the
  attribute-editing user ``mallory``
  (Alice's e-mail and name, then her username changed at runtime to the local administrator's),
  self-service linking from a local session, logout (RP-initiated, Keycloak session ended).
- ``signup-on``: sign-up on, no group or domain filter, strict role mapping. The user without a
  ``groups`` claim refused (``role``), ``mallory`` refused (``username``) and never an
  administrator, and a sign-up as positive control.

The browser is a headless HTTP client (urllib, no JavaScript) that follows the redirects one by one
and fills in the Keycloak login form. Host names are resolved to 127.0.0.1 here (the proxy and
Keycloak publish their ports on the loopback address only), and TLS is verified against the run's
CA alone. Nothing secret is printed: user names, HTTP statuses and audit reasons only. Every
one-time flow value seen on the wire (authorization codes, states, nonces, session cookies, CSRF
tokens) is written to the pattern directory, so that oidc.sh checks that none of them reaches the
console's logs or database.

Requires Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.cookiejar
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Optional

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REALM_USERS = ("admin.alice", "analyst.bob", "outsider.carol", "unverified.dave", "mallory", "nogroup.erin", "link.grace")
LOCAL_ADMIN = "e2e-admin"
LOCAL_LINKER = "e2e-linker"
LOCAL_ANALYST = "e2e-analyst"
MAX_BODY = 1 << 20


class ScenarioError(Exception):
    """A failed expectation (the message never holds a secret)."""


def check(cond: bool, what: str) -> None:
    if not cond:
        raise ScenarioError(what)
    print(f"ok   - {what}", flush=True)


# --------------------------------------------------------------------------- HTML forms
@dataclass
class Form:
    attrs: dict[str, str]
    fields: list[tuple[str, str]] = field(default_factory=list)
    submits: list[tuple[str, str]] = field(default_factory=list)


class FormParser(HTMLParser):
    """Collects the forms of a page: action, method, named inputs and submit controls."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.title = ""
        self.meta_refresh: Optional[str] = None
        self._in_title = False
        self._current: Optional[Form] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = Form(attrs=a)
            self.forms.append(self._current)
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.match(r"\s*\d+\s*;\s*url=(.*)$", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = m.group(1).strip()
        elif self._current is not None and tag in ("input", "button"):
            name = a.get("name", "")
            kind = a.get("type", "submit" if tag == "button" else "text").lower()
            if not name:
                return
            if kind == "submit":
                self._current.submits.append((name, a.get("value", "")))
            elif kind not in ("button", "reset", "checkbox", "radio") or "checked" in a:
                self._current.fields.append((name, a.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def parse_page(body: bytes) -> FormParser:
    p = FormParser()
    p.feed(body.decode("utf-8", "replace"))
    p.close()
    p.title = " ".join(p.title.split())
    return p


# --------------------------------------------------------------------------- browser
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass
class Response:
    status: int
    headers: http.client.HTTPMessage
    body: bytes
    url: str

    def location(self) -> str:
        loc = self.headers.get("Location")
        if not loc:
            raise ScenarioError(f"HTTP {self.status} without a Location header")
        return urllib.parse.urljoin(self.url, loc)

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class Patterns:
    """One file per one-time value seen on the wire: oidc.sh scans the logs and the database."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.n = 0

    #: Values that travel in URLs (authorization request and response): the TLS proxy's access log
    #: holds them by design, so oidc.sh scans every other log and the database for them.
    URL_BORNE = ("code", "state", "nonce")
    #: Keycloak's user session id (`session_state`, the provider `sid`): the console keeps it with
    #: the session by design (ADR-0038 decision 13), so it may be in the database dump, and the proxy
    #: log has it in the callback URLs; oidc.sh looks for it in every other log.
    SID = ("sid",)

    def add(self, kind: str, value: Optional[str]) -> None:
        # Short values could match by chance; every value recorded here is long and random.
        if not value or len(value) < 16:
            return
        self.n += 1
        sub = "url" if kind in self.URL_BORNE else "sid" if kind in self.SID else ""
        # The process id keeps the names of the two phases apart.
        path = os.path.join(self.directory, sub, f"{kind}_{os.getpid()}_{self.n}")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value + "\n")


class Browser:
    """A cookie-keeping HTTP client that never follows a redirect on its own."""

    def __init__(self, env: "Env", name: str) -> None:
        self.env = env
        self.name = name
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context(cafile=env.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),  # never through a proxy of the host
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect(),
        )
        self.csrf: Optional[str] = None

    def request(self, method: str, url: str, data: Optional[bytes] = None, headers: Optional[dict[str, str]] = None) -> Response:
        if not url.startswith("https://"):
            raise ScenarioError(f"{self.name}: refusing a non-https URL")
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=30) as r:
                return Response(r.status, r.headers, r.read(MAX_BODY), url)
        except urllib.error.HTTPError as e:
            with e:
                return Response(e.code, e.headers, e.read(MAX_BODY), url)

    def get(self, url: str) -> Response:
        return self.request("GET", url)

    def post_form(self, url: str, fields: list[tuple[str, str]]) -> Response:
        data = urllib.parse.urlencode(fields).encode()
        return self.request("POST", url, data, {"Content-Type": "application/x-www-form-urlencoded"})

    def api(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> Response:
        """Console user API call: same-origin `Origin` header and, once known, the CSRF token."""
        headers = {"Origin": self.env.console_url, "Accept": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        return self.request(method, self.env.console_url + path, data, headers)

    def cookie(self, name_suffix: str) -> Optional[str]:
        for c in self.jar:
            if c.name.endswith(name_suffix):
                return c.value
        return None

    def session(self) -> Optional[dict[str, Any]]:
        r = self.api("GET", "/api/auth/session")
        if r.status == 401:
            return None
        if r.status != 200:
            raise ScenarioError(f"{self.name}: GET /api/auth/session: HTTP {r.status}")
        d = r.json()
        self.csrf = d.get("csrf_token")
        self.env.patterns.add("csrf", self.csrf)
        self.env.patterns.add("session", self.cookie("databastion_session"))
        return d["user"]


# --------------------------------------------------------------------------- environment
@dataclass
class Env:
    console_url: str
    issuer: str
    ca_file: str
    secrets: str
    patterns: Patterns
    state_file: str
    psql: list[str]
    state: dict[str, Any] = field(default_factory=dict)

    def secret(self, name: str) -> str:
        with open(os.path.join(self.secrets, name), encoding="utf-8") as f:
            return f.read()

    @property
    def keycloak_base(self) -> str:
        u = urllib.parse.urlsplit(self.issuer)
        return f"{u.scheme}://{u.netloc}"

    def save(self) -> None:
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f)


def pin_hosts(hosts: list[str]) -> None:
    """Resolves the harness host names to 127.0.0.1 (published ports), like curl --resolve."""
    real = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if isinstance(host, str) and host.lower() in hosts:
            host = "127.0.0.1"
        return real(host, *args, **kwargs)

    socket.getaddrinfo = getaddrinfo  # type: ignore[assignment]


# --------------------------------------------------------------------------- console database
def sql_json(env: Env, query: str) -> Any:
    """Read-only query on the console database (json_agg of the rows)."""
    out = subprocess.run(
        [*env.psql, "-c", f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({query}) t"],
        check=True,
        capture_output=True,
        timeout=30,
        text=True,
    ).stdout.strip()
    return json.loads(out)


def check_read_only(env: Env) -> None:
    rows = sql_json(env, "SELECT current_setting('default_transaction_read_only') AS ro")
    check(rows == [{"ro": "on"}], "console database read through a read-only psql session")


def need_uuid(v: Any, what: str) -> str:
    if not isinstance(v, str) or not UUID_RE.match(v):
        raise ScenarioError(f"{what} is not a UUID")
    return v


def db_mark(env: Env) -> str:
    rows = sql_json(env, "SELECT clock_timestamp()::text AS ts")
    return rows[0]["ts"]


def audit_since(env: Env, mark: str, action: Optional[str] = None) -> list[dict[str, Any]]:
    if not re.fullmatch(r"[0-9: .+-]+", mark):
        raise ScenarioError("unexpected timestamp format")
    where = f"at >= '{mark}'::timestamptz"
    if action is not None:
        if not re.fullmatch(r"[a-z_.]+", action):
            raise ScenarioError("unexpected audit action")
        where += f" AND action = '{action}'"
    return sql_json(env, f"SELECT action, outcome, actor_type, actor_id, target_id, details FROM audit_log WHERE {where} ORDER BY at")


def users_by_name(env: Env) -> dict[str, dict[str, Any]]:
    rows = sql_json(env, "SELECT id::text, username, role::text, sso_only, (password_hash IS NOT NULL) AS has_password FROM users")
    return {r["username"]: r for r in rows}


def identities_of_subject(env: Env, subject: str) -> list[dict[str, Any]]:
    if not UUID_RE.match(subject):
        raise ScenarioError("Keycloak subject is not a UUID")
    return sql_json(env, f"SELECT user_id::text, issuer FROM user_identities WHERE subject = '{subject}'")


def identities_of_user(env: Env, user_id: str) -> list[dict[str, Any]]:
    if not UUID_RE.match(user_id):
        raise ScenarioError("user id is not a UUID")
    return sql_json(env, f"SELECT subject, issuer FROM user_identities WHERE user_id = '{user_id}'")


def pending_count(env: Env) -> int:
    return int(sql_json(env, "SELECT count(*) AS n FROM oidc_pending_logins")[0]["n"])


# --------------------------------------------------------------------------- Keycloak admin API
class KeycloakAdmin:
    """Master realm administrator (password generated by oidc.sh), admin API of realm `databastion`."""

    def __init__(self, env: Env) -> None:
        self.env = env
        self.b = Browser(env, "keycloak-admin")
        self.realm = env.keycloak_base + "/admin/realms/databastion"
        self.token = ""
        self._authenticate()

    def _authenticate(self) -> None:
        env = self.env
        r = self.b.post_form(
            env.keycloak_base + "/realms/master/protocol/openid-connect/token",
            [("grant_type", "password"), ("client_id", "admin-cli"), ("username", "admin"), ("password", env.secret("keycloak_admin_password"))],
        )
        if r.status != 200:
            raise ScenarioError(f"Keycloak admin token: HTTP {r.status}")
        self.token = r.json()["access_token"]
        env.patterns.add("keycloak_admin_token", self.token)

    def call(self, method: str, path: str, body: Optional[Any] = None) -> Response:
        """Admin API call; a fresh admin token once on `401` (it lives 60 s in Keycloak's master realm)."""
        data = None if body is None else json.dumps(body).encode()
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            r = self.b.request(method, self.realm + path, data, headers)
            if r.status != 401 or attempt == 2:
                return r
            self._authenticate()
        raise AssertionError("unreachable")

    def user(self, username: str) -> dict[str, Any]:
        r = self.call("GET", "/users?" + urllib.parse.urlencode({"username": username, "exact": "true"}))
        if r.status != 200:
            raise ScenarioError(f"Keycloak user {username}: HTTP {r.status}")
        rows = r.json()
        if len(rows) != 1:
            raise ScenarioError(f"Keycloak user {username}: {len(rows)} matches")
        return rows[0]

    def rename(self, user_id: str, username: str) -> None:
        r = self.call("GET", f"/users/{user_id}")
        if r.status != 200:
            raise ScenarioError(f"Keycloak user read: HTTP {r.status}")
        rep = r.json()
        rep["username"] = username
        r = self.call("PUT", f"/users/{user_id}", rep)
        if r.status != 204:
            raise ScenarioError(f"Keycloak user update: HTTP {r.status}")

    def group_id(self, name: str) -> str:
        r = self.call("GET", "/groups?" + urllib.parse.urlencode({"search": name, "exact": "true"}))
        if r.status != 200:
            raise ScenarioError(f"Keycloak group {name}: HTTP {r.status}")
        rows = [g for g in r.json() if g.get("name") == name]
        if len(rows) != 1:
            raise ScenarioError(f"Keycloak group {name}: {len(rows)} matches")
        return rows[0]["id"]

    def set_member(self, user_id: str, group: str, member: bool) -> None:
        """Adds `user_id` to (or removes it from) the top-level group `group`."""
        r = self.call("PUT" if member else "DELETE", f"/users/{user_id}/groups/{self.group_id(group)}")
        if r.status != 204:
            raise ScenarioError(f"Keycloak group membership update: HTTP {r.status}")

    def sessions(self, user_id: str) -> list[Any]:
        r = self.call("GET", f"/users/{user_id}/sessions")
        if r.status != 200:
            raise ScenarioError(f"Keycloak user sessions: HTTP {r.status}")
        return r.json()


# --------------------------------------------------------------------------- flows
@dataclass
class Outcome:
    signed_in: bool
    status: int
    target: Optional[str]  # where the console's page navigates to
    provider_session: Optional[str]  # Keycloak's user session id (`session_state`)


def keycloak_login(env: Env, b: Browser, auth_url: str, username: str) -> Response:
    """Authorization request -> Keycloak login form -> credentials -> redirect to the callback."""
    r = b.get(auth_url)
    if r.status != 200:
        raise ScenarioError(f"{username}: Keycloak authorization request answered HTTP {r.status}, expected its login form")
    page = parse_page(r.body)
    forms = [f for f in page.forms if f.attrs.get("id") == "kc-form-login"]
    if len(forms) != 1:
        raise ScenarioError(f"{username}: no Keycloak login form (page title {page.title!r})")
    form = forms[0]
    action = urllib.parse.urljoin(r.url, form.attrs.get("action", ""))
    if not action.startswith(env.issuer + "/"):
        raise ScenarioError(f"{username}: login form posts outside the issuer")
    fields = [(k, v) for k, v in form.fields if k not in ("username", "password")]
    fields += [("username", username), ("password", env.secret("keycloak_user_password"))]
    r = b.post_form(action, fields)
    if r.status not in (302, 303):
        title = parse_page(r.body).title
        raise ScenarioError(f"{username}: Keycloak did not redirect after the login form (HTTP {r.status}, page title {title!r})")
    return r


def account_auth_url(env: Env) -> str:
    """Authorization request of Keycloak's own account console (public client, PKCE S256)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return env.issuer + "/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": "account-console", "redirect_uri": env.issuer + "/account/", "response_type": "code",
        "scope": "openid", "state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
        "code_challenge": challenge, "code_challenge_method": "S256",
    })


def keycloak_sso(env: Env, b: Browser, username: str) -> Optional[str]:
    """Signs `username` in to Keycloak's account console in browser `b` (the redirect back to the
    account console is not followed): the browser then holds a Keycloak SSO session."""
    r = keycloak_login(env, b, account_auth_url(env), username)
    loc = r.location()
    if not loc.startswith(env.issuer + "/account/"):
        raise ScenarioError(f"{username}: Keycloak account console sign-in did not redirect to the account console")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query + "&" + (urllib.parse.urlsplit(loc).fragment or ""))
    env.patterns.add("code", (q.get("code") or [None])[0])
    sid = (q.get("session_state") or [None])[0]
    env.patterns.add("sid", sid)
    return sid


def follow_callback(env: Env, b: Browser, r: Response, who: str) -> Outcome:
    callback = r.location()
    check(callback.startswith(env.console_url + "/api/auth/oidc/callback?"), f"{who}: Keycloak redirects to the console's callback")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
    check(q.get("iss") == [env.issuer], f"{who}: authorization response carries iss (RFC 9207)")
    env.patterns.add("code", (q.get("code") or [None])[0])
    env.patterns.add("state", (q.get("state") or [None])[0])
    # Keycloak's user session id: the provider `sid`, which the console stores with the session by
    # design (ADR-0038 decision 13), so not a value to look for.
    provider_session = (q.get("session_state") or [None])[0]
    env.patterns.add("sid", provider_session)
    r = b.get(callback)
    page = parse_page(r.body)
    env.patterns.add("session", b.cookie("databastion_session"))
    signed_in = r.status == 200 and page.meta_refresh == "/agents"
    if signed_in:
        names = {c.name for c in b.jar if c.domain == urllib.parse.urlsplit(env.console_url).hostname}
        check("__Host-databastion_session" in names, f"{who}: production session cookie (__Host- prefix, Secure)")
    return Outcome(signed_in, r.status, page.meta_refresh, provider_session)


def check_auth_request(env: Env, auth_url: str, who: str, link: bool = False) -> None:
    check(auth_url.startswith(env.issuer + "/protocol/openid-connect/auth?"), f"{who}: redirected to the issuer's authorization endpoint")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query)
    one = {k: v[0] for k, v in q.items() if len(v) == 1}
    check(
        one.get("response_type") == "code"
        and one.get("code_challenge_method") == "S256"
        and len(one.get("code_challenge", "")) >= 43
        and len(one.get("state", "")) >= 32
        and len(one.get("nonce", "")) >= 32
        and one.get("response_mode", "query") == "query"
        and one.get("redirect_uri") == env.console_url + "/api/auth/oidc/callback"
        and "openid" in one.get("scope", "").split(),
        f"{who}: authorization code flow with PKCE S256, state, nonce, query response mode, exact redirect URI",
    )
    if link:
        check(one.get("prompt") == "login" and one.get("max_age") == "0", f"{who}: link asks for a fresh authentication (prompt=login, max_age=0)")
    env.patterns.add("state", one.get("state"))
    env.patterns.add("nonce", one.get("nonce"))


def oidc_login(env: Env, username: str, b: Optional[Browser] = None) -> tuple[Browser, Outcome]:
    b = b or Browser(env, username)
    r = b.get(env.console_url + "/api/auth/oidc/start")
    if r.status != 302:
        raise ScenarioError(f"{username}: /api/auth/oidc/start answered HTTP {r.status}, expected 302")
    auth_url = r.location()
    check_auth_request(env, auth_url, username)
    env.patterns.add("oidc_state_cookie", b.cookie("databastion_oidc"))
    r = keycloak_login(env, b, auth_url, username)
    return b, follow_callback(env, b, r, username)


def local_login(env: Env, username: str, password_secret: str) -> Browser:
    b = Browser(env, username)
    r = b.api("POST", "/api/auth/login", {"username": username, "password": env.secret(password_secret)})
    if r.status != 200:
        raise ScenarioError(f"{username}: local login answered HTTP {r.status}")
    b.csrf = r.json()["csrf_token"]
    env.patterns.add("csrf", b.csrf)
    env.patterns.add("session", b.cookie("databastion_session"))
    return b


def expect_denied(env: Env, username: str, reason: str) -> None:
    mark = db_mark(env)
    b, out = oidc_login(env, username)
    check(not out.signed_in and out.status == 400 and out.target == "/login?sso_error=1", f"{username}: login refused with the generic failure page")
    check(b.session() is None, f"{username}: no console session")
    entries = [e for e in audit_since(env, mark) if e["action"].startswith("user.")]
    denied = [e for e in entries if e["action"] == "user.login_denied"]
    check(
        len(denied) == 1 and denied[0]["outcome"] == "failure" and denied[0]["details"] == {"method": "oidc", "reason": reason},
        f"{username}: audit user.login_denied, reason {reason}",
    )
    check(not any(e["action"] in ("user.login", "user.signup", "user.role_change", "user.identity_link") for e in entries), f"{username}: no login, sign-up, role change or link audited")


def pending_for(admin: Browser, subject: str) -> Optional[dict[str, Any]]:
    r = admin.api("GET", "/api/oidc/pending-logins")
    if r.status != 200:
        raise ScenarioError(f"GET /api/oidc/pending-logins: HTTP {r.status}")
    rows = [p for p in r.json()["pending"] if p["subject"] == subject]
    return rows[0] if rows else None


def expect_pending(env: Env, admin: Browser, username: str, subject: str, login: str, role: str, group: str) -> dict[str, Any]:
    mark = db_mark(env)
    b, out = oidc_login(env, username)
    check(not out.signed_in and out.status == 400, f"{username}: unknown identity, sign-up off: no session")
    check(b.session() is None, f"{username}: no console session")
    denied = audit_since(env, mark, "user.login_denied")
    check(len(denied) == 1 and denied[0]["details"] == {"method": "oidc", "reason": "sign_up"}, f"{username}: audit user.login_denied, reason sign_up")
    p = pending_for(admin, subject)
    check(p is not None, f"{username}: pending login listed (issuer and subject)")
    assert p is not None
    check(p["issuer"] == env.issuer and p["login"] == login, f"{username}: pending login shows the issuer and the mapped login {login}")
    check(p["mappedRole"] == role and group in p["groups"], f"{username}: pending login mapped role {role} from group {group}")
    return p


def approve(env: Env, admin: Browser, pending_id: str, role: str, who: str) -> str:
    mark = db_mark(env)
    r = admin.api("POST", f"/api/oidc/pending-logins/{pending_id}", {"role": role})
    check(r.status == 201, f"{who}: pending login approved as a new user with role {role}")
    user_id = r.json()["userId"]
    a = audit_since(env, mark, "user.pending_login_approve")
    check(len(a) == 1 and a[0]["target_id"] == user_id and a[0]["details"].get("role") == role, f"{who}: audit user.pending_login_approve")
    return user_id


def refuse_mismatch(env: Env, admin: Browser, pending_id: str, role: str, mapped: str, subject: str, who: str) -> None:
    """Role sync on: an approval with another role than the mapped one is refused (end-of-phase-8 review L1)."""
    mark = db_mark(env)
    r = admin.api("POST", f"/api/oidc/pending-logins/{pending_id}", {"role": role})
    check(r.status == 409 and r.json().get("error") == "role_mismatch", f"{who}: approval as {role} refused, 409 role_mismatch (mapped role {mapped}, role sync on)")
    a = audit_since(env, mark, "user.pending_login_approve")
    check(
        len(a) == 1 and a[0]["outcome"] == "failure" and a[0]["target_id"] == pending_id
        and a[0]["details"].get("reason") == "role_mismatch" and a[0]["details"].get("role") == role
        and a[0]["details"].get("mapped_role") == mapped and a[0]["details"].get("subject") == subject,
        f"{who}: audit user.pending_login_approve failure, reason role_mismatch, mapped_role {mapped}",
    )
    check(pending_for(admin, subject) is not None, f"{who}: pending login kept after the refused approval")


def expect_first_login(env: Env, username: str, user_id: str, role: str) -> tuple[Browser, Outcome]:
    """First login after approval with the mapped role: no role change."""
    mark = db_mark(env)
    b, out = oidc_login(env, username)
    check(out.signed_in, f"{username}: signed in, landing on /agents")
    s = b.session()
    check(s is not None and s["id"] == user_id and s["username"] == username and s["role"] == role, f"{username}: session as {username}, role {role} from the group")
    entries = audit_since(env, mark)
    check(not any(e["action"] == "user.role_change" for e in entries), f"{username}: no role change at the first login (approved with the mapped role)")
    logins = [e for e in entries if e["action"] == "user.login"]
    check(len(logins) == 1 and logins[0]["actor_id"] == user_id and logins[0]["details"] == {"method": "oidc"}, f"{username}: audit user.login, method oidc")
    return b, out


def expect_role_sync(env: Env, username: str, user_id: str, before: str, after: str) -> tuple[Browser, Outcome]:
    mark = db_mark(env)
    b, out = oidc_login(env, username)
    check(out.signed_in, f"{username}: signed in, landing on /agents")
    s = b.session()
    check(s is not None and s["id"] == user_id and s["username"] == username and s["role"] == after, f"{username}: session as {username}, role {after} from the group")
    entries = audit_since(env, mark)
    changes = [e for e in entries if e["action"] == "user.role_change"]
    check(
        len(changes) == 1 and changes[0]["target_id"] == user_id and changes[0]["outcome"] == "success" and changes[0]["details"] == {"source": "oidc", "from": before, "to": after},
        f"{username}: audit user.role_change {before} -> {after}, source oidc",
    )
    logins = [e for e in entries if e["action"] == "user.login"]
    check(len(logins) == 1 and logins[0]["actor_id"] == user_id and logins[0]["details"] == {"method": "oidc"}, f"{username}: audit user.login, method oidc")
    return b, out


# --------------------------------------------------------------------------- phases
def phase_signup_off(env: Env) -> None:
    kc = KeycloakAdmin(env)
    subjects = {u: kc.user(u)["id"] for u in REALM_USERS}
    for u, s in subjects.items():
        if not UUID_RE.match(s):
            raise ScenarioError(f"Keycloak subject of {u} is not a UUID")
    env.state["subjects"] = subjects
    check_read_only(env)

    print("# Break-glass local administrator (DATABASTION_LOCAL_LOGIN=admins while OIDC is on)")
    mark = db_mark(env)
    admin = local_login(env, LOCAL_ADMIN, "admin_password")
    a = audit_since(env, mark, "user.login")
    check(len(a) == 1 and a[0]["details"].get("method") == "local" and a[0]["details"].get("break_glass") is True, "e2e-admin: local login audited with break_glass")
    admin_id = need_uuid(a[0]["actor_id"], "e2e-admin id")
    # The user.local_login system alert goes to the channels flagged "system alerts": one is created
    # (never contacted: no worker runs here), then a second break-glass login must queue its delivery.
    r = admin.api("POST", "/api/notification-channels", {
        "slug": "e2e-system-alerts", "type": "email", "system_alerts": True,
        "config": {"host": "mailpit", "port": 587, "tls": "starttls", "from": "databastion@e2e.example", "recipients": ["soc@e2e.example"]},
    })
    check(r.status == 201, "system-alert e-mail channel created")
    mark = db_mark(env)
    local_login(env, LOCAL_ADMIN, "admin_password")
    rows = sql_json(env, "SELECT event, status::text AS status, channel_slug, payload->>'user_id' AS user_id, payload->>'username' AS username "
                         f"FROM notification_deliveries WHERE event = 'user.local_login' AND created_at >= '{mark}'::timestamptz")
    check(rows == [{"event": "user.local_login", "status": "pending", "channel_slug": "e2e-system-alerts", "user_id": admin_id, "username": LOCAL_ADMIN}],
          "e2e-admin: break-glass login queues the user.local_login system alert")

    print("# Local login of a non-administrator refused while OIDC is on (DATABASTION_LOCAL_LOGIN=admins)")
    r = admin.api("POST", "/api/users", {"username": LOCAL_ANALYST, "password": env.secret("analyst_password"), "role": "analyst"})
    check(r.status == 201, "e2e-analyst: local analyst created")
    mark = db_mark(env)
    b = Browser(env, LOCAL_ANALYST)
    r = b.api("POST", "/api/auth/login", {"username": LOCAL_ANALYST, "password": env.secret("analyst_password")})
    check(r.status == 401 and b.session() is None, "e2e-analyst: local login refused with 401, no session")
    logins = [e for e in audit_since(env, mark) if e["action"] == "user.login"]
    check(len(logins) >= 1 and all(e["outcome"] == "failure" for e in logins), "e2e-analyst: user.login audited as a failure only")

    print("# Refused before any pending login: group, unverified e-mail, no groups claim")
    n = pending_count(env)
    expect_denied(env, "outsider.carol", "group")
    expect_denied(env, "unverified.dave", "email_unverified")
    expect_denied(env, "nogroup.erin", "group")
    check(pending_count(env) == n, "refused logins leave no pending login")

    print("# Pending login approved only with the role mapped from the group (role sync on)")
    p = expect_pending(env, admin, "admin.alice", subjects["admin.alice"], "admin.alice", "admin", "databastion-admins")
    check(p["emailVerified"] is True, "admin.alice: pending login shows email_verified true")
    check(p.get("syncedRole") == "admin", "admin.alice: pending login shows the role it will get (admin)")
    refuse_mismatch(env, admin, p["id"], "analyst", "admin", subjects["admin.alice"], "admin.alice")
    alice_id = approve(env, admin, p["id"], "admin", "admin.alice")
    alice, alice_login = expect_first_login(env, "admin.alice", alice_id, "admin")

    p = expect_pending(env, admin, "analyst.bob", subjects["analyst.bob"], "analyst.bob", "analyst", "databastion-analysts")
    check(p.get("syncedRole") == "analyst", "analyst.bob: pending login shows the role it will get (analyst)")
    refuse_mismatch(env, admin, p["id"], "admin", "analyst", subjects["analyst.bob"], "analyst.bob")
    bob_id = approve(env, admin, p["id"], "analyst", "analyst.bob")
    expect_first_login(env, "analyst.bob", bob_id, "analyst")

    print("# Role from the group at every login: promotion, then demotion, after group changes at the provider")
    kc.set_member(subjects["analyst.bob"], "databastion-admins", True)
    expect_role_sync(env, "analyst.bob", bob_id, "analyst", "admin")
    kc.set_member(subjects["analyst.bob"], "databastion-admins", False)
    expect_role_sync(env, "analyst.bob", bob_id, "admin", "analyst")

    print("# Attribute-editing user: Alice's e-mail and name, then the local administrator's username")
    mallory_sub = subjects["mallory"]
    mark = db_mark(env)
    p = expect_pending(env, admin, "mallory", mallory_sub, "mallory", "analyst", "databastion-analysts")
    check(p["email"] == "admin.alice@databastion.test", "mallory: pending login carries Alice's e-mail (an attribute, not a key)")
    check(not any(e["action"] == "user.login" for e in audit_since(env, mark)), "mallory: never signed in to Alice's account")
    kc.rename(mallory_sub, LOCAL_ADMIN)
    check(kc.user(LOCAL_ADMIN)["id"] == mallory_sub, "mallory: username changed at the provider to e2e-admin (admin API)")
    p = expect_pending(env, admin, LOCAL_ADMIN, mallory_sub, LOCAL_ADMIN, "analyst", "databastion-analysts")
    check(p["attempts"] == 2, "mallory: same pending login (keyed by issuer and subject), second attempt")
    r = admin.api("POST", f"/api/oidc/pending-logins/{p['id']}", {"role": "analyst"})
    check(r.status == 409 and r.json().get("error") == "username_taken", "mallory: approval refused, username_taken (never merged into e2e-admin)")
    r = admin.api("DELETE", f"/api/oidc/pending-logins/{p['id']}")
    check(r.status in (200, 204), "mallory: pending login discarded")
    check(identities_of_subject(env, mallory_sub) == [], "mallory: identity bound to no console user")
    users = users_by_name(env)
    check(users[LOCAL_ADMIN]["role"] == "admin" and identities_of_user(env, users[LOCAL_ADMIN]["id"]) == [], "e2e-admin: still a local administrator without any linked identity")
    check(users["admin.alice"]["role"] == "admin" and len(identities_of_user(env, alice_id)) == 1, "admin.alice: one identity, her own")

    print("# Self-service link from a local session")
    r = alice.api("POST", "/api/auth/oidc/link")
    check(r.status == 409 and r.json().get("error") == "local_session_required", "admin.alice: no link from a single sign-on session (local_session_required)")
    r = admin.api("POST", "/api/users", {"username": LOCAL_LINKER, "password": env.secret("linker_password"), "role": "admin"})
    check(r.status == 201, "e2e-linker: local administrator created")
    linker_id = r.json()["userId"]
    linker = local_login(env, LOCAL_LINKER, "linker_password")
    # Freshness (security review L1 of ADR-0038): the browser already holds a Keycloak SSO session as
    # link.grace (signed in to Keycloak's account console), yet the link must ask for credentials.
    account = keycloak_sso(env, linker, "link.grace")
    r = linker.get(account_auth_url(env))
    check(account is not None, "e2e-linker: signed in to Keycloak's account console as link.grace")
    check(r.status in (302, 303) and r.location().startswith(env.issuer + "/account/"), "e2e-linker: the browser's Keycloak SSO session as link.grace signs in without a form")
    mark = db_mark(env)
    r = linker.api("POST", "/api/auth/oidc/link")
    check(r.status == 200, "e2e-linker: POST /api/auth/oidc/link answers the provider URL")
    auth_url = r.json()["redirect_url"]
    check_auth_request(env, auth_url, "e2e-linker", link=True)
    env.patterns.add("oidc_state_cookie", linker.cookie("databastion_oidc"))
    r = linker.get(auth_url)
    check(r.status == 200 and any(f.attrs.get("id") == "kc-form-login" for f in parse_page(r.body).forms),
          "e2e-linker: despite the SSO session, Keycloak asks for credentials again (prompt=login, max_age=0)")
    check(audit_since(env, mark, "user.identity_link") == [], "e2e-linker: no link recorded before the credentials are posted")
    r = keycloak_login(env, linker, auth_url, "link.grace")
    out = follow_callback(env, linker, r, "e2e-linker")
    check(out.status == 200 and out.target == "/account?linked=1", "e2e-linker: link callback lands on /account?linked=1")
    links = audit_since(env, mark, "user.identity_link")
    check(
        len(links) == 1 and links[0]["outcome"] == "success" and links[0]["actor_id"] == linker_id
        and links[0]["details"] == {"session_method": "local", "issuer": env.issuer, "subject": subjects["link.grace"]},
        "e2e-linker: audit user.identity_link with the session method, issuer and subject",
    )
    s = linker.session()
    check(s is not None and s["id"] == linker_id, "e2e-linker: the local session is kept")
    mark = db_mark(env)
    grace, out = oidc_login(env, "link.grace")
    s = grace.session()
    check(out.signed_in and s is not None and s["id"] == linker_id and s["username"] == LOCAL_LINKER, "link.grace: single sign-on now opens e2e-linker's account")
    logins = audit_since(env, mark, "user.login")
    check(len(logins) == 1 and logins[0]["actor_id"] == linker_id and logins[0]["details"] == {"method": "oidc"}, "link.grace: audit user.login, method oidc, as e2e-linker")

    print("# Logout: console session ended, RP-initiated logout at Keycloak")
    # Each fresh browser opened its own Keycloak session: the one of the signed-in browser must end.
    def kc_session_ids() -> set[str]:
        return {x.get("id") for x in kc.sessions(subjects["admin.alice"])}

    check(alice_login.provider_session in kc_session_ids(), "admin.alice: Keycloak session of the signed-in browser open before logout")
    mark = db_mark(env)
    r = alice.api("POST", "/api/auth/logout")
    check(r.status == 200, "admin.alice: POST /api/auth/logout answers 200 with the provider logout URL")
    url = r.json()["redirect_url"]
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
    check(
        url.startswith(env.issuer + "/protocol/openid-connect/logout?")
        and q.get("client_id") == "databastion-console"
        and q.get("logout_hint") == subjects["admin.alice"]
        and q.get("post_logout_redirect_uri") == env.console_url + "/login"
        and "id_token_hint" not in q,
        "admin.alice: RP-initiated logout with client_id, logout_hint and post_logout_redirect_uri, no id_token_hint",
    )
    check(alice.session() is None, "admin.alice: console session gone")
    lo = audit_since(env, mark, "user.logout")
    check(len(lo) == 1 and lo[0]["actor_id"] == alice_id and lo[0]["details"].get("method") == "oidc", "admin.alice: audit user.logout, method oidc")
    r = alice.get(url)
    if r.status == 200:  # Keycloak asks for a confirmation without an id_token_hint
        page = parse_page(r.body)
        forms = [f for f in page.forms if any(n == "confirmLogout" for n, _ in f.submits)]
        check(len(forms) == 1, "admin.alice: Keycloak logout confirmation page")
        f = forms[0]
        r = alice.post_form(urllib.parse.urljoin(r.url, f.attrs.get("action", "")), f.fields + [s for s in f.submits if s[0] == "confirmLogout"])
    check(r.status in (302, 303) and r.location() == env.console_url + "/login", "admin.alice: Keycloak redirects back to the console's /login")
    check(alice_login.provider_session not in kc_session_ids(), "admin.alice: Keycloak session of the signed-in browser ended")
    r = alice.get(env.console_url + "/api/auth/oidc/start")
    r = alice.get(r.location())
    check(r.status == 200 and any(f.attrs.get("id") == "kc-form-login" for f in parse_page(r.body).forms), "admin.alice: a new sign-in asks for credentials again")

    env.state.update({"alice_id": alice_id, "bob_id": bob_id, "linker_id": linker_id})


def phase_signup_on(env: Env) -> None:
    subjects = env.state["subjects"]
    mallory_sub = subjects["mallory"]
    admin = local_login(env, LOCAL_ADMIN, "admin_password")
    before = users_by_name(env)

    print("# Strict role mapping, no group filter: the user without a groups claim is refused")
    n = pending_count(env)
    expect_denied(env, "nogroup.erin", "role")
    expect_denied(env, "outsider.carol", "role")
    check(pending_count(env) == n, "sign-up on: refused logins leave no pending login")

    print("# Attribute-editing user named like the local administrator: refused, never admin")
    expect_denied(env, LOCAL_ADMIN, "username")
    after = users_by_name(env)
    check(set(after) == set(before), "mallory: no console user created")
    check(identities_of_subject(env, mallory_sub) == [], "mallory: identity bound to no console user")
    check(
        after[LOCAL_ADMIN] == before[LOCAL_ADMIN] and identities_of_user(env, after[LOCAL_ADMIN]["id"]) == [],
        "e2e-admin: unchanged (role admin, local password, no linked identity)",
    )
    s = admin.session()
    check(s is not None and s["username"] == LOCAL_ADMIN, "e2e-admin: local session still valid")

    print("# Positive control: sign-up of a user the filters admit")
    mark = db_mark(env)
    b, out = oidc_login(env, "unverified.dave")
    s = b.session()
    check(out.signed_in and s is not None and s["username"] == "unverified.dave" and s["role"] == "analyst", "unverified.dave: signed up, role analyst from the group")
    su = audit_since(env, mark, "user.signup")
    check(len(su) == 1 and su[0]["details"].get("role") == "analyst" and su[0]["details"].get("subject") == subjects["unverified.dave"], "unverified.dave: audit user.signup, role analyst")
    dave_id = need_uuid(su[0]["target_id"], "unverified.dave id")

    print("# Refresh token (DATABASTION_OIDC_USE_REFRESH_TOKEN=1): stored encrypted, revoked at logout")
    rows = sql_json(env, "SELECT length(refresh_token_enc) AS n, get_byte(refresh_token_enc, 0) AS fmt, "
                         "position(decode('65794a', 'hex') IN refresh_token_enc) AS jwt FROM sessions "
                         f"WHERE user_id = '{dave_id}' AND method = 'oidc'")
    check(len(rows) == 1 and rows[0]["n"] is not None and rows[0]["n"] > 29 and rows[0]["fmt"] == 1 and rows[0]["jwt"] == 0,
          "unverified.dave: refresh token stored as an AES-256-GCM blob (format 1), no JWT in clear")
    mark = db_mark(env)
    r = b.api("POST", "/api/auth/logout")
    check(r.status == 200 and b.session() is None, "unverified.dave: logged out")
    lo = audit_since(env, mark, "user.logout")
    check(len(lo) == 1 and lo[0]["details"] == {"method": "oidc", "refresh_revoked": True}, "unverified.dave: refresh token revoked at the provider (RFC 7009)")
    check(sql_json(env, f"SELECT 1 FROM sessions WHERE user_id = '{dave_id}'") == [], "unverified.dave: session row (and its refresh token) deleted")

    print("# Never admin: the attribute-editing user, across both configurations")
    admins = sql_json(env, "SELECT u.username FROM users u WHERE u.role = 'admin' ORDER BY 1")
    check([r["username"] for r in admins] == ["admin.alice", LOCAL_ADMIN, LOCAL_LINKER], "administrators: admin.alice (group), e2e-admin and e2e-linker (local) only")
    check(
        sql_json(env, "SELECT 1 FROM audit_log WHERE action = 'user.role_change' AND details->>'to' = 'admin' AND target_id <> "
                 f"'{need_uuid(env.state.get('bob_id'), 'bob id')}'") == [],
        "no role change to admin but analyst.bob's (databastion-admins granted at the provider, then removed)",
    )


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("phase", choices=["signup-off", "signup-on"])
    ap.add_argument("--console-url", required=True)
    ap.add_argument("--issuer", required=True)
    ap.add_argument("--ca-file", required=True)
    ap.add_argument("--secrets", required=True, help="directory of the run's secret files")
    ap.add_argument("--patterns", required=True, help="directory receiving the one-time values seen")
    ap.add_argument("--state", required=True, help="JSON state shared by the two phases")
    args = ap.parse_args(argv)
    psql = json.loads(os.environ["E2E_PSQL"])
    if not isinstance(psql, list) or not all(isinstance(x, str) for x in psql):
        raise SystemExit("E2E_PSQL must be a JSON array of strings")
    env = Env(args.console_url.rstrip("/"), args.issuer, args.ca_file, args.secrets, Patterns(args.patterns), args.state, psql)
    hosts = {urllib.parse.urlsplit(args.console_url).hostname, urllib.parse.urlsplit(args.issuer).hostname}
    pin_hosts([h.lower() for h in hosts if h])
    if os.path.exists(args.state):
        with open(args.state, encoding="utf-8") as f:
            env.state = json.load(f)
    phases: dict[str, Callable[[Env], None]] = {"signup-off": phase_signup_off, "signup-on": phase_signup_on}
    try:
        phases[args.phase](env)
    except ScenarioError as e:
        print(f"FAIL - {e}", flush=True)
        return 1
    finally:
        env.save()
    print(f"# phase {args.phase}: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
