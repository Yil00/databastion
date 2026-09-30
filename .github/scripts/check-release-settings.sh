#!/usr/bin/env bash
# Fails unless the repository settings that ADR-0034 relies on are in place (RELEASE.md, section 6,
# "Release prerequisites"). A defence against a forgotten or undone setup only: it reads the
# settings with the workflow's GITHUB_TOKEN, and whoever can change the workflow can remove it.
#
#   check-release-settings.sh environment NAME tag            # reviewers, no admin bypass,
#                                                             # version-tag rule only
#   check-release-settings.sh environment NAME branch BRANCH  # reviewers, no admin bypass,
#                                                             # that branch only
#   check-release-settings.sh tag-ruleset                     # active tag ruleset: version tags,
#                                                             # creation / update / deletion
#                                                             # restricted, admins-only bypass
# RELEASE_APP_ID (optional): id of the release GitHub App allowed in the bypass list.
# Requires gh and jq; GH_TOKEN and GITHUB_REPOSITORY set (the job needs `actions: read`).
set -euo pipefail

repo="${GITHUB_REPOSITORY:?}"
fail() { echo "::error::$*"; echo "See RELEASE.md, section 6, Release prerequisites." >&2; exit 1; }

# ruleset_ok ID < ruleset JSON: prints what it finds; true when the ruleset
# - is an active tag ruleset;
# - includes the version tags (`~ALL`, or a pattern matching both X.Y.Z and X.Y.Z-pre) and excludes
#   none of them;
# - restricts tag creation, update and deletion;
# - lets only admins bypass it (repository admin role, organization admins), or the release GitHub
#   App when RELEASE_APP_ID is set (repository variable of the same name). GITHUB_TOKEN may not see
#   the bypass list (GitHub returns it to users who can edit the ruleset): a warning then says to
#   check it by hand; no extra token scope is needed for the rest.
ruleset_ok() {
  local id="$1" json pattern ok_include=false
  json="$(cat)"
  if ! jq -e '.target == "tag" and .enforcement == "active"' <<<"$json" >/dev/null; then
    echo "ruleset $id: not an active tag ruleset"; return 1
  fi
  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    if [ "$pattern" = "~ALL" ]; then ok_include=true; continue; fi
    pattern="${pattern#refs/tags/}"
    # shellcheck disable=SC2053  # the pattern is a glob on purpose (fnmatch-like, as GitHub's)
    if [[ 0.1.0 == $pattern && 10.20.30-rc.1 == $pattern ]]; then ok_include=true; fi
  done < <(jq -r '.conditions.ref_name.include[]?' <<<"$json")
  if [ "$ok_include" != true ]; then
    echo "ruleset $id: its include ($(jq -c '.conditions.ref_name.include' <<<"$json")) does not cover X.Y.Z and X.Y.Z-pre tags"
    return 1
  fi
  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    pattern="${pattern#refs/tags/}"
    # shellcheck disable=SC2053
    if [[ $pattern == "~ALL" || 0.1.0 == $pattern || 10.20.30-rc.1 == $pattern ]]; then
      echo "ruleset $id: its exclude ($pattern) removes version tags"; return 1
    fi
  done < <(jq -r '.conditions.ref_name.exclude[]?' <<<"$json")
  if ! jq -e '[.rules[]?.type] | (index("creation") != null) and (index("update") != null) and (index("deletion") != null)' \
      <<<"$json" >/dev/null; then
    echo "ruleset $id: does not restrict creation, update and deletion (rules: $(jq -c '[.rules[]?.type]' <<<"$json"))"
    return 1
  fi
  if jq -e 'has("bypass_actors") | not' <<<"$json" >/dev/null; then
    echo "::warning::ruleset $id: bypass list not visible to this token; check by hand that it holds only admins (RELEASE.md, section 6)"
  else
    local others
    others="$(jq -c --arg app "${RELEASE_APP_ID:-}" '[.bypass_actors[]
        | select(((.actor_type == "RepositoryRole" and .actor_id == 5) or .actor_type == "OrganizationAdmin"
                  or (.actor_type == "Integration" and $app != "" and (.actor_id | tostring) == $app)) | not)]' <<<"$json")"
    if [ "$others" != "[]" ]; then
      echo "ruleset $id: bypass list holds more than admins / the release app: $others"; return 1
    fi
  fi
  echo "tag ruleset $id: active, covers the version tags, restricts creation, update and deletion, bypass: $(jq -c '[.bypass_actors[]? | "\(.actor_type):\(.actor_id)"]' <<<"$json")"
}

case "${1:-}" in
  environment)
    name="${2:?environment name}" kind="${3:?tag or branch}" branch="${4:-}"
    env_json="$(gh api "repos/$repo/environments/$name" 2>/dev/null)" \
      || fail "environment '$name' not found (or not readable)"
    jq -e '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?] | length > 0' \
      <<<"$env_json" >/dev/null || fail "environment '$name' has no required reviewers"
    jq -e '.can_admins_bypass == false' <<<"$env_json" >/dev/null \
      || fail "environment '$name' lets administrators bypass its protection rules"
    jq -e '.deployment_branch_policy.custom_branch_policies == true' <<<"$env_json" >/dev/null \
      || fail "environment '$name' is not limited to selected branches and tags"
    policies="$(gh api --paginate "repos/$repo/environments/$name/deployment-branch-policies" \
      --jq '.branch_policies[] | "\(.type // "branch") \(.name)"')"
    [ -n "$policies" ] || fail "environment '$name' has no deployment rule"
    case "$kind" in
      tag)
        if grep -qv '^tag ' <<<"$policies"; then fail "environment '$name' admits branches: $policies"; fi ;;
      branch)
        [ "$policies" = "branch ${branch:?branch name}" ] \
          || fail "environment '$name' must admit only branch '$branch', has: $policies" ;;
      *) fail "unknown kind '$kind'" ;;
    esac
    echo "environment '$name': required reviewers, no admin bypass, deployment rules: $(tr '\n' ',' <<<"$policies")"
    ;;
  tag-ruleset)
    ids="$(gh api --paginate "repos/$repo/rulesets" \
      --jq '.[] | select(.target == "tag" and .enforcement == "active") | .id')"
    for id in $ids; do
      if gh api "repos/$repo/rulesets/$id" | ruleset_ok "$id"; then
        exit 0
      fi
    done
    fail "no active tag ruleset covering the version tags, restricting their creation, update and deletion, with admins (or the release app) only in its bypass list"
    ;;
  tag-ruleset-json)
    # Tests (test_check_release_settings.sh): one ruleset as returned by GET /rulesets/{id}, on stdin.
    ruleset_ok "${2:-fixture}" || exit 1
    ;;
  *)
    echo "usage: $0 environment NAME tag | environment NAME branch BRANCH | tag-ruleset" >&2
    exit 64
    ;;
esac
