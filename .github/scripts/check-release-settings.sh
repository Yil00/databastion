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
# RELEASE_ALLOW_ADMIN_BYPASS (optional, repository variable): `true` accepts an environment that lets
#   administrators bypass its protection rules, with a warning (the maintainer's choice while there
#   is a single maintainer, RELEASE.md section 6); any other value refuses it.
# Requires gh and jq; GH_TOKEN and GITHUB_REPOSITORY set (the job needs `actions: read`).
set -euo pipefail

repo="${GITHUB_REPOSITORY:?}"
fail() { echo "::error::$*"; echo "See RELEASE.md, section 6, Release prerequisites." >&2; exit 1; }

# ruleset_ok ID < ruleset JSON: prints what it finds; true when the ruleset
# - is an active tag ruleset;
# - includes the version tags: `~ALL` or one of refs/tags/*, refs/tags/*.*.*,
#   refs/tags/[0-9]*.[0-9]*.[0-9]*; has an empty exclude list;
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
  # Include: `~ALL` or one of the patterns the documented setup uses (as the API returns them).
  while IFS= read -r pattern; do
    case "$pattern" in
      "~ALL" | "refs/tags/*" | "refs/tags/*.*.*" | "refs/tags/[0-9]*.[0-9]*.[0-9]*") ok_include=true ;;
    esac
  done < <(jq -r '.conditions.ref_name.include[]?' <<<"$json")
  if [ "$ok_include" != true ]; then
    echo "ruleset $id: its include ($(jq -c '.conditions.ref_name.include' <<<"$json")) has none of ~ALL, refs/tags/*, refs/tags/*.*.*, refs/tags/[0-9]*.[0-9]*.[0-9]*"
    return 1
  fi
  # Exclude: none (the documented setup needs none; any pattern could remove some version tags).
  if jq -e '(.conditions.ref_name.exclude // []) | length > 0' <<<"$json" >/dev/null; then
    echo "ruleset $id: its exclude is not empty ($(jq -c '.conditions.ref_name.exclude' <<<"$json"))"
    return 1
  fi
  if ! jq -e '[.rules[]?.type] | (index("creation") != null) and (index("update") != null) and (index("deletion") != null)' \
      <<<"$json" >/dev/null; then
    echo "ruleset $id: does not restrict creation, update and deletion (rules: $(jq -c '[.rules[]?.type]' <<<"$json"))"
    return 1
  fi
  local bypass
  if jq -e 'has("bypass_actors") | not' <<<"$json" >/dev/null; then
    echo "::warning::ruleset $id: bypass list not visible to this token; check by hand that it holds only admins (RELEASE.md, section 6)"
    bypass="not visible (check by hand)"
  else
    local others
    others="$(jq -c --arg app "${RELEASE_APP_ID:-}" '[.bypass_actors[]
        | select(((.actor_type == "RepositoryRole" and .actor_id == 5) or .actor_type == "OrganizationAdmin"
                  or (.actor_type == "Integration" and $app != "" and (.actor_id | tostring) == $app)) | not)]' <<<"$json")"
    if [ "$others" != "[]" ]; then
      echo "ruleset $id: bypass list holds more than admins / the release app: $others"; return 1
    fi
    bypass="$(jq -c '[.bypass_actors[] | "\(.actor_type):\(.actor_id)"]' <<<"$json")"
  fi
  echo "tag ruleset $id: active, covers the version tags, restricts creation, update and deletion, bypass: $bypass"
}

# env_admin_bypass NAME < environment JSON: sets admin_bypass to "no admin bypass" when
# administrators cannot bypass the environment's protection rules. When they can, it fails, unless
# RELEASE_ALLOW_ADMIN_BYPASS is `true`: it then warns and sets "admin bypass accepted". A missing
# can_admins_bypass field counts as a bypass.
env_admin_bypass() {
  local name="$1" json
  json="$(cat)"
  if jq -e '.can_admins_bypass == false' <<<"$json" >/dev/null; then
    admin_bypass="no admin bypass"; return 0
  fi
  if [ "${RELEASE_ALLOW_ADMIN_BYPASS:-}" = "true" ]; then
    echo "::warning::environment '$name' lets administrators bypass its protection rules; accepted because RELEASE_ALLOW_ADMIN_BYPASS is true (RELEASE.md, section 6)"
    admin_bypass="admin bypass accepted"; return 0
  fi
  fail "environment '$name' lets administrators bypass its protection rules (accepted only when the repository variable RELEASE_ALLOW_ADMIN_BYPASS is true)"
}

case "${1:-}" in
  environment)
    name="${2:?environment name}" kind="${3:?tag or branch}" branch="${4:-}"
    env_json="$(gh api "repos/$repo/environments/$name" 2>/dev/null)" \
      || fail "environment '$name' not found (or not readable)"
    jq -e '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?] | length > 0' \
      <<<"$env_json" >/dev/null || fail "environment '$name' has no required reviewers"
    env_admin_bypass "$name" <<<"$env_json"
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
    echo "environment '$name': required reviewers, $admin_bypass, deployment rules: $(tr '\n' ',' <<<"$policies")"
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
  environment-json)
    # Tests (test_check_release_settings.sh): the admin bypass check on one environment, as
    # returned by GET /environments/{name}, on stdin.
    env_admin_bypass "${2:-fixture}"
    echo "environment ${2:-fixture}: $admin_bypass"
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
