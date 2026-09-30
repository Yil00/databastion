#!/usr/bin/env bash
# Tests of check-release-settings.sh's tag ruleset check on fixture rulesets (GET /rulesets/{id}
# shape). Run: .github/scripts/test_check_release_settings.sh (CI: ci.yml, Documentation job).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GITHUB_REPOSITORY=example/repo
failures=0

# expect ok|fail FIXTURE [RELEASE_APP_ID]
expect() {
  local want="$1" fixture="$2" app="${3:-}" got=ok out
  out="$(RELEASE_APP_ID="$app" "$here/check-release-settings.sh" tag-ruleset-json "$fixture" \
    <"$here/fixtures/ruleset-$fixture.json" 2>&1)" || got=fail
  if [ "$got" = "$want" ]; then
    echo "ok    $fixture${app:+ (app $app)}: $got"
  else
    echo "FAIL  $fixture${app:+ (app $app)}: expected $want, got $got"; printf '      %s\n' "$out"
    failures=$((failures + 1))
  fi
}

expect ok ok-admin
expect ok ok-all
expect ok ok-bypass-hidden
expect ok ok-include-star
expect ok ok-include-digits
expect ok app-4242 4242
expect fail app-4242
expect fail app-4242 99
expect fail bad-team
expect fail bad-include
expect fail bad-exclude
expect fail bad-exclude-minor
expect fail bad-exclude-patch
expect fail bad-include-odd
expect fail bad-rules
expect fail bad-evaluate
expect fail bad-branch

# A hidden bypass list is reported as such, never as an empty list.
out="$("$here/check-release-settings.sh" tag-ruleset-json hidden <"$here/fixtures/ruleset-ok-bypass-hidden.json")"
if grep -q 'bypass: not visible (check by hand)$' <<<"$out" && ! grep -q 'bypass: \[\]' <<<"$out"; then
  echo "ok    ok-bypass-hidden: reported as not visible"
else
  echo "FAIL  ok-bypass-hidden: output was: $out"; failures=$((failures + 1))
fi

[ "$failures" = 0 ] || { echo "$failures failure(s)"; exit 1; }
echo "all tests passed"
