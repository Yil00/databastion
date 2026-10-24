#!/usr/bin/env bash
# Tests of check-final-release.sh's pure parts (jq filters, the P..T allow-list, the tag order, the
# published-release count, the release-it job window) on inline fixtures in the shape of the GitHub
# API answers. No network, no git. Run: .github/scripts/test_check_final_release.sh (CI: ci.yml,
# Documentation job).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
s="$here/check-final-release.sh"
failures=0

# expect NAME WANT_STATUS(ok|fail) WANT_OUTPUT(- for any) STDIN -- ARGS...
expect() {
  local name="$1" want="$2" want_out="$3" input="$4" got=ok out
  shift 5
  out="$("$s" "$@" <<<"$input" 2>&1)" || got=fail
  if [ "$got" = "$want" ] && { [ "$want_out" = - ] || [ "$out" = "$want_out" ]; }; then
    echo "ok    $name: $got${want_out:+ ($want_out)}"
  else
    echo "FAIL  $name: expected $want ($want_out), got $got"; printf '      %s\n' "$out"
    failures=$((failures + 1))
  fi
}

P=6b26b05bb0427f0dc151c932b2872b9ea0ccab54
OTHER=3aa768e106558d38b3e65d2184a3c1d98092fe98
run() { # run ID PATH EVENT BRANCH SHA
  printf '{"id":%s,"path":"%s","event":"%s","head_branch":"%s","head_sha":"%s"}' "$@"
}

# --- release.yml runs on P -----------------------------------------------------------------------
expect runs-one ok '[40035014723]' \
  "{\"workflow_runs\":[$(run 40035014723 .github/workflows/release.yml push main $P),$(run 1 .github/workflows/ci.yml push main $P)]}" -- test-runs $P
expect runs-none ok '[]' '{"workflow_runs":[]}' -- test-runs $P
expect runs-missing-key ok '[]' '{}' -- test-runs $P
expect runs-other-sha ok '[]' "{\"workflow_runs\":[$(run 1 .github/workflows/release.yml push main $OTHER)]}" -- test-runs $P
expect runs-dispatch ok '[]' "{\"workflow_runs\":[$(run 1 .github/workflows/release.yml workflow_dispatch main $P)]}" -- test-runs $P
expect runs-other-branch ok '[]' "{\"workflow_runs\":[$(run 1 .github/workflows/release.yml push dev $P)]}" -- test-runs $P
expect runs-other-path ok '[]' "{\"workflow_runs\":[$(run 1 .github/workflows/release2.yml push main $P)]}" -- test-runs $P
expect runs-two ok '[1,2]' \
  "{\"workflow_runs\":[$(run 1 .github/workflows/release.yml push main $P),$(run 2 .github/workflows/release.yml push main $P)]}" -- test-runs $P

# --- release-it job -----------------------------------------------------------------------------
expect job-one ok '[{"name":"release-it","status":"completed"}]' \
  '{"jobs":[{"name":"release-it","status":"completed"},{"name":"other","status":"completed"}]}' -- test-job
expect job-none ok '[]' '{"jobs":[{"name":"release-it-2"}]}' -- test-job

# --- approvals ----------------------------------------------------------------------------------
expect approvals-ok ok '["Yil00"]' \
  '[{"state":"approved","environments":[{"name":"release-it"}],"user":{"login":"Yil00"}}]' -- test-approvals
expect approvals-rejected ok '[]' \
  '[{"state":"rejected","environments":[{"name":"release-it"}],"user":{"login":"Yil00"}}]' -- test-approvals
expect approvals-other-env ok '[]' \
  '[{"state":"approved","environments":[{"name":"release"}],"user":{"login":"Yil00"}}]' -- test-approvals
expect approvals-empty ok '[]' '[]' -- test-approvals
expect approvals-no-envs ok '[]' '[{"state":"approved","user":{"login":"Yil00"}}]' -- test-approvals

# --- P..T allow-list ----------------------------------------------------------------------------
tab=$'\t'
release_diff="M${tab}CHANGELOG.md
M${tab}agent/Cargo.lock
M${tab}agent/Cargo.toml
M${tab}agent/fuzz/Cargo.lock
M${tab}console/package.json
M${tab}package-lock.json
M${tab}package.json"
expect diff-0.9.0 ok ok "$release_diff" -- test-diff
expect diff-helm ok ok "$release_diff
M${tab}helm/databastion/Chart.yaml" -- test-diff
expect diff-extra-file fail - "$release_diff
M${tab}.github/workflows/publish.yml" -- test-diff
expect diff-added fail - "$release_diff
A${tab}agent/Cargo.toml.orig" -- test-diff
expect diff-deleted fail - "D${tab}CHANGELOG.md
M${tab}package.json" -- test-diff
expect diff-no-changelog fail - "M${tab}package.json" -- test-diff
expect diff-no-package fail - "M${tab}CHANGELOG.md" -- test-diff
expect diff-empty fail - "" -- test-diff
expect diff-prefix fail - "$release_diff
M${tab}CHANGELOG.md.bak" -- test-diff
expect diff-type-change fail - "$release_diff
T${tab}package.json" -- test-diff

# --- final tags above V -------------------------------------------------------------------------
tags='0.1.0-rc.2
0.8.2
0.8.10
0.9.0
0.9.1-rc.1
1.0.0-beta.1
latest'
expect higher-none ok '' "$tags" -- test-higher 0.9.0
expect higher-hotfix-old-line ok '0.9.0' "$tags" -- test-higher 0.8.10
expect higher-numeric ok '0.8.10
0.9.0' "$tags" -- test-higher 0.8.9
expect higher-next ok '' "$tags" -- test-higher 0.9.1

# --- published releases -------------------------------------------------------------------------
expect published-draft ok 0 '[{"tag_name":"0.9.1","draft":true}]' -- test-published 0.9.1
expect published-absent ok 0 '[{"tag_name":"0.9.0","draft":false}]' -- test-published 0.9.1
expect published-yes ok 1 '[{"tag_name":"0.9.1","draft":false}]' -- test-published 0.9.1
expect published-pages ok 1 '[{"tag_name":"0.9.0","draft":false}]
[{"tag_name":"0.9.1","draft":false}]' -- test-published 0.9.1
expect published-empty ok 0 '[]' -- test-published 0.9.1

# --- T committed during the release-it job (0.9.0: job 22:56:14Z to 22:56:55Z, T at 22:56:47Z) ---
ct=$(date -u -d 2026-10-23T22:56:47Z +%s)
expect window-0.9.0 ok in '' -- test-window "$ct" 2026-10-23T22:56:14Z 2026-10-23T22:56:55Z
expect window-slack ok in '' -- test-window $((ct + 100)) 2026-10-23T22:56:14Z 2026-10-23T22:56:55Z
expect window-late fail - '' -- test-window $((ct + 300)) 2026-10-23T22:56:14Z 2026-10-23T22:56:55Z
expect window-early fail - '' -- test-window $((ct - 3600)) 2026-10-23T22:56:14Z 2026-10-23T22:56:55Z
expect window-null fail - '' -- test-window "$ct" 2026-10-23T22:56:14Z null
expect window-bad-ct fail - '' -- test-window abc 2026-10-23T22:56:14Z 2026-10-23T22:56:55Z

# --- inputs -------------------------------------------------------------------------------------
# expect_refused NAME VERSION TAG_SHA SUBCOMMAND...: refused before any API or git call.
expect_refused() {
  local name="$1" v="$2" sha="$3" sub out
  shift 3
  for sub in "$@"; do
    if out="$(VERSION="$v" TAG_SHA="$sha" GITHUB_REPOSITORY=example/repo GH_TOKEN='' "$s" "$sub" 2>&1)"; then
      echo "FAIL  $name ($sub): accepted"; printf '      %s\n' "$out"; failures=$((failures + 1))
    elif ! grep -q '^::error::' <<<"$out"; then
      echo "FAIL  $name ($sub): failed without ::error::"; printf '      %s\n' "$out"; failures=$((failures + 1))
    else
      echo "ok    $name ($sub): refused"
    fi
  done
}
expect_refused prerelease-version 0.9.1-rc.1 $P not-superseded commit release-run tree
expect_refused empty-version '' $P not-superseded commit release-run tree
expect_refused short-sha 0.9.1 6b26b05 commit release-run tree
expect_refused empty-sha 0.9.1 '' commit release-run tree

if [ "$failures" -gt 0 ]; then echo "$failures failure(s)"; exit 1; fi
echo "all tests passed"
