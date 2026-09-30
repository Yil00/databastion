#!/usr/bin/env bash
# Fails unless the repository settings that ADR-0034 relies on are in place (RELEASE.md, section 6,
# "Release prerequisites"). A defence against a forgotten or undone setup only: it reads the
# settings with the workflow's GITHUB_TOKEN, and whoever can change the workflow can remove it.
#
#   check-release-settings.sh environment NAME tag            # reviewers + version-tag rule only
#   check-release-settings.sh environment NAME branch BRANCH  # reviewers + that branch only
#   check-release-settings.sh tag-ruleset                     # active tag ruleset restricting
#                                                             # creation, update and deletion
# Requires gh and jq; GH_TOKEN and GITHUB_REPOSITORY set (the job needs `actions: read`).
set -euo pipefail

repo="${GITHUB_REPOSITORY:?}"
fail() { echo "::error::$*"; echo "See RELEASE.md, section 6, Release prerequisites." >&2; exit 1; }

case "${1:-}" in
  environment)
    name="${2:?environment name}" kind="${3:?tag or branch}" branch="${4:-}"
    env_json="$(gh api "repos/$repo/environments/$name" 2>/dev/null)" \
      || fail "environment '$name' not found (or not readable)"
    jq -e '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?] | length > 0' \
      <<<"$env_json" >/dev/null || fail "environment '$name' has no required reviewers"
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
    echo "environment '$name': required reviewers, deployment rules: $(tr '\n' ',' <<<"$policies")"
    ;;
  tag-ruleset)
    ids="$(gh api --paginate "repos/$repo/rulesets" \
      --jq '.[] | select(.target == "tag" and .enforcement == "active") | .id')"
    for id in $ids; do
      if gh api "repos/$repo/rulesets/$id" | jq -e '
          ([.rules[].type] | index("creation") and index("update") and index("deletion"))
          and ((.conditions.ref_name.include // []) | length > 0)' >/dev/null; then
        echo "tag ruleset $id: active, restricts creation, update and deletion"
        exit 0
      fi
    done
    fail "no active tag ruleset restricting tag creation, update and deletion"
    ;;
  *)
    echo "usage: $0 environment NAME tag | environment NAME branch BRANCH | tag-ruleset" >&2
    exit 64
    ;;
esac
