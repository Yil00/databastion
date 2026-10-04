"""Unit tests of the OIDC scenario driver's offline parts (e2e/oidc_scenario.py): the HTML form
parser that fills in the Keycloak login and logout confirmation pages, the console's callback
pages, and the pattern files oidc.sh scans for. Run: python3 -m unittest discover -s e2e -v"""

import os
import tempfile
import unittest

import oidc_scenario as s

# Trimmed from the Keycloak 26.8 login page (theme keycloak.v2).
LOGIN_PAGE = b"""<!DOCTYPE html><html><head><title>Sign in to DataBastion</title></head><body>
<form id="kc-form-login" class="pf-v5-c-form" onsubmit="login.disabled = true; return true;"
  action="https://keycloak.e2e.internal:8444/realms/databastion/login-actions/authenticate?session_code=abc&amp;execution=e1&amp;client_id=databastion-console&amp;tab_id=t1"
  method="post" novalidate="novalidate">
  <input id="username" name="username" value="" type="text" autocomplete="username" autofocus>
  <input id="password" name="password" value="" type="password" autocomplete="current-password">
  <button class="pf-v5-c-button pf-m-control" type="button" aria-label="Show password"></button>
  <input type="hidden" id="id-hidden-input" name="credentialId" />
  <button class="pf-v5-c-button pf-m-primary" name="login" id="kc-login" type="submit">Sign In</button>
</form></body></html>"""

# Trimmed from the Keycloak 26.8 logout confirmation page (no id_token_hint).
LOGOUT_PAGE = b"""<html><head><title>Logging out</title></head><body>
<form class="form-actions" action="/realms/databastion/protocol/openid-connect/logout/logout-confirm?client_id=databastion-console&amp;tab_id=x" method="POST">
  <input type="hidden" name="session_code" value="sc1">
  <input tabindex="4" class="pf-v5-c-button" name="confirmLogout" id="kc-logout" type="submit" value="Logout"/>
</form></body></html>"""

# The console's callback pages (src/server/oidc/routes.ts navigationPage).
SIGNED_IN = b'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=/agents"><title>Signed in</title></head><body><p>Signed in. <a href="/agents">Continue</a></p></body></html>'
FAILED = b'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/login?sso_error=1"><title>Sign-in failed</title></head><body></body></html>'


class FormParserTest(unittest.TestCase):
    def test_login_form(self):
        page = s.parse_page(LOGIN_PAGE)
        self.assertEqual(page.title, "Sign in to DataBastion")
        self.assertEqual(len(page.forms), 1)
        form = page.forms[0]
        self.assertEqual(form.attrs["id"], "kc-form-login")
        # Character references are decoded in the action URL.
        self.assertIn("session_code=abc&execution=e1&client_id=databastion-console", form.attrs["action"])
        self.assertEqual(form.fields, [("username", ""), ("password", ""), ("credentialId", "")])
        self.assertEqual(form.submits, [("login", "")])

    def test_logout_confirmation(self):
        form = s.parse_page(LOGOUT_PAGE).forms[0]
        self.assertTrue(form.attrs["action"].startswith("/realms/databastion/protocol/openid-connect/logout/logout-confirm?"))
        self.assertEqual(form.fields, [("session_code", "sc1")])
        self.assertEqual(form.submits, [("confirmLogout", "Logout")])

    def test_callback_pages(self):
        self.assertEqual(s.parse_page(SIGNED_IN).meta_refresh, "/agents")
        self.assertEqual(s.parse_page(FAILED).meta_refresh, "/login?sso_error=1")

    def test_unchecked_boxes_and_inputs_outside_forms_are_skipped(self):
        page = s.parse_page(b'<input name="outside"><form action="/x"><input type="checkbox" name="a">'
                            b'<input type="checkbox" name="b" value="1" checked><input name="c" value="v"></form>')
        self.assertEqual(page.forms[0].fields, [("b", "1"), ("c", "v")])


class PatternsTest(unittest.TestCase):
    def test_files_and_url_borne_values(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "url"))
            p = s.Patterns(d)
            p.add("code", "c" * 36)
            p.add("session", "s" * 43)
            p.add("csrf", "short")  # too short to be scanned for: skipped
            p.add("state", None)
            self.assertEqual(len(os.listdir(os.path.join(d, "url"))), 1)
            root = [f for f in os.listdir(d) if f != "url"]
            self.assertEqual(len(root), 1)
            path = os.path.join(d, root[0])
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "s" * 43 + "\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class CheckTest(unittest.TestCase):
    def test_check_raises_without_printing_values(self):
        with self.assertRaises(s.ScenarioError):
            s.check(False, "expected failure")


if __name__ == "__main__":
    unittest.main()
