"""Unit tests of scripts/changelog-release.mjs, run through node
(run: python3 -m unittest discover -s scripts -p 'test_*.py')."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "changelog-release.mjs")
REPO = "https://github.com/Yil00/databastion"

INTRO = """# Changelog

All notable changes to DataBastion are recorded here.

See [RELEASE.md](RELEASE.md).
"""

NOTES = """> **Upgrade impact**: read [the guide](docs/10-user-guide.md#upgrade) first.

### ✨ Features
- New thing ([ADR-0037](docs/adr/0037-x.md)), see `[x](docs/not-a-link.md)` and <https://example.com>
- Anchors stay: [above](#changelog), absolute stay: [site](https://example.com/a.md)

### 🐛 Bug Fixes
- Fixed ([RELEASE.md § 7](RELEASE.md#7-pre-release-checklist)) (dev/README.md)

```
## not a heading
[code](docs/in-fence.md)
```

[ref]: agent/README.md#failed-login-flood"""

OLDER = """## [0.3.0](https://github.com/Yil00/databastion/compare/0.2.0...0.3.0) (2026-10-03)

### ✨ Features
- Older
"""


def changelog(notes: str = NOTES, unreleased: bool = True) -> str:
    head = INTRO + "\n"
    if unreleased:
        head += "## Unreleased\n\n" + (notes + "\n\n" if notes else "")
    return head + OLDER


@unittest.skipUnless(shutil.which("node") and shutil.which("git"), "node and git required")
class ChangelogReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.file = os.path.join(self.dir, "CHANGELOG.md")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, text: str) -> None:
        with open(self.file, "w", encoding="utf-8") as f:
            f.write(text)

    def read(self) -> str:
        with open(self.file, encoding="utf-8") as f:
            return f.read()

    def run_script(self, *args: str, prev: str | None = "0.3.0") -> subprocess.CompletedProcess:
        env = {"PATH": os.environ["PATH"], "CHANGELOG_RELEASE_FILE": self.file,
               "CHANGELOG_RELEASE_DATE": "2026-10-04"}
        if prev is not None:
            env["CHANGELOG_RELEASE_PREV"] = prev
        return subprocess.run(["node", SCRIPT, *args], cwd=self.dir, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_moves_unreleased_under_the_version(self) -> None:
        self.write(changelog())
        r = self.run_script("changelog", "0.4.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        expected = (INTRO + "\n## Unreleased\n\n"
                    f"## [0.4.0]({REPO}/compare/0.3.0...0.4.0) (2026-10-04)\n\n"
                    + NOTES + "\n\n" + OLDER)
        self.assertEqual(self.read(), expected)

    def test_second_run_changes_nothing(self) -> None:
        self.write(changelog())
        self.assertEqual(self.run_script("changelog", "0.4.0").returncode, 0)
        once = self.read()
        r = self.run_script("changelog", "0.4.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read(), once)
        self.assertEqual(once.count("## [0.4.0]"), 1)
        self.assertEqual(once.count("## Unreleased"), 1)

    def test_existing_section_with_new_notes_fails(self) -> None:
        self.write(changelog())
        self.run_script("changelog", "0.4.0")
        text = self.read().replace("## Unreleased\n", "## Unreleased\n\n- more\n", 1)
        self.write(text)
        r = self.run_script("changelog", "0.4.0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already has a 0.4.0 section", r.stderr)
        self.assertEqual(self.read(), text)

    def test_empty_unreleased_fails_and_writes_nothing(self) -> None:
        for text in (changelog(notes=""), changelog(notes="\n\n   \n")):
            self.write(text)
            for args in (("changelog", "0.4.0"), ("notes", "0.4.0"), ("check",)):
                r = self.run_script(*args)
                self.assertEqual(r.returncode, 1, args)
                self.assertIn('"## Unreleased" section of CHANGELOG.md is empty', r.stderr)
                self.assertEqual(r.stdout, "")
            self.assertEqual(self.read(), text)

    def test_missing_unreleased_fails(self) -> None:
        self.write(changelog(unreleased=False))
        r = self.run_script("changelog", "0.4.0")
        self.assertEqual(r.returncode, 1)
        self.assertIn('no "## Unreleased" section', r.stderr)

    def test_release_notes_have_absolute_links(self) -> None:
        self.write(changelog())
        before = self.run_script("notes", "0.4.0")  # dry run: read from "Unreleased"
        self.assertEqual(self.run_script("changelog", "0.4.0").returncode, 0)
        after = self.run_script("notes", "0.4.0")
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(before.stdout, after.stdout)
        out = after.stdout
        blob = f"{REPO}/blob/0.4.0/"
        self.assertIn(f"[the guide]({blob}docs/10-user-guide.md#upgrade)", out)
        self.assertIn(f"[ADR-0037]({blob}docs/adr/0037-x.md)", out)
        self.assertIn(f"[RELEASE.md § 7]({blob}RELEASE.md#7-pre-release-checklist)", out)
        self.assertIn(f"[ref]: {blob}agent/README.md#failed-login-flood", out)
        # Left as they are: code spans, fenced code, anchors, absolute URLs, plain text.
        self.assertIn("`[x](docs/not-a-link.md)`", out)
        self.assertIn("[code](docs/in-fence.md)", out)
        self.assertIn("[above](#changelog)", out)
        self.assertIn("[site](https://example.com/a.md)", out)
        self.assertIn("(dev/README.md)", out)
        self.assertNotIn("## [0.4.0]", out)
        self.assertNotIn("Older", out)
        # The CHANGELOG keeps the relative links.
        self.assertIn("[ADR-0037](docs/adr/0037-x.md)", self.read())

    def test_prerelease_leaves_the_changelog(self) -> None:
        self.write(changelog())
        r = self.run_script("changelog", "0.4.0-rc.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read(), changelog())
        notes = self.run_script("notes", "0.4.0-rc.1")
        self.assertEqual(notes.returncode, 0, notes.stderr)
        self.assertIn(f"{REPO}/blob/0.4.0-rc.1/docs/adr/0037-x.md", notes.stdout)

    def test_first_release_links_the_tag(self) -> None:
        self.write(changelog())
        self.assertEqual(self.run_script("changelog", "0.4.0", prev="").returncode, 0)
        self.assertIn(f"## [0.4.0]({REPO}/releases/tag/0.4.0) (2026-10-04)", self.read())

    def test_previous_tag_skips_prereleases_and_later_tags(self) -> None:
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "tag.gpgSign=false",
               "-c", "commit.gpgSign=false"]
        run = lambda *a: subprocess.run([*git, *a], cwd=self.dir, check=True, capture_output=True, timeout=30)
        run("init", "-q")
        self.write(changelog())
        n = 0
        for tag in ("0.1.0-rc.1", "0.1.0", "0.2.0-rc.1", "0.2.0-rc.2", "0.10.0-rc.1"):
            n += 1
            run("commit", "-q", "--allow-empty", "-m", f"c{n}")
            run("tag", tag)
        # A final tag not reachable from HEAD is ignored too.
        run("checkout", "-q", "-b", "side")
        run("commit", "-q", "--allow-empty", "-m", "side")
        run("tag", "0.1.5")
        run("checkout", "-q", "-")
        r = self.run_script("changelog", "0.2.0", prev=None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"## [0.2.0]({REPO}/compare/0.1.0...0.2.0) (2026-10-04)", self.read())

    def test_bad_arguments(self) -> None:
        self.write(changelog())
        for args in (("changelog",), ("changelog", "v1"), ("notes", "1.2"), ("nope", "0.4.0")):
            r = self.run_script(*args)
            self.assertEqual(r.returncode, 1, args)
        self.assertEqual(self.read(), changelog())

    def test_real_changelog_has_notes_or_is_parsable(self) -> None:
        # The repository's CHANGELOG.md parses; notes may be empty between releases.
        env = {"PATH": os.environ["PATH"], "CHANGELOG_RELEASE_FILE": os.path.join(HERE, "..", "CHANGELOG.md")}
        r = subprocess.run(["node", SCRIPT, "check"], env=env, capture_output=True, text=True, timeout=30)
        self.assertIn(r.returncode, (0, 1))
        self.assertNotIn('no "## Unreleased" section', r.stderr)


if __name__ == "__main__":
    unittest.main()
