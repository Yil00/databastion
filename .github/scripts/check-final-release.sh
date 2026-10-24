#!/usr/bin/env bash
# Checks, before publish.yml builds or signs anything, that a final-version tag (X.Y.Z) is the one
# release-it made in an approved release.yml run, and that it is neither published nor superseded
# (ADR-0058 decision 3.2, as implemented without the release record of decision 2.10;
# implementation note of 2026-10-24). It replaces the approvals of the `release` environment for
# final versions. Pre-release tags go through the approval gate of publish.yml; the only check
# here for them is `prerelease-not-superseded`, which keeps a re-run of an old pre-release run from
# signing again and moving `next` back (re-review N1).
#
# A check of the honest path only: whoever can choose the publish.yml that a tag runs (an
# administrator, or the holder of RELEASE_TOKEN) can remove it (ADR-0058, decision 3.4).
#
#   check-final-release.sh not-superseded  # no published release V, no final tag above V (API)
#   check-final-release.sh commit          # the tag object, the release commit T, its parent P, the files
#   check-final-release.sh release-run     # the approved release.yml run on P that made T (polls)
#   check-final-release.sh tree            # T's tree recomputed from P with the after:bump hooks
#   check-final-release.sh prerelease-not-superseded  # pre-release V: no version tag above V (API)
#
# The pure parts are reachable for the tests (test_check_final_release.sh), on stdin:
#   check-final-release.sh test-runs P | test-job | test-approvals | test-diff
#   check-final-release.sh test-higher V | test-published V | test-window CT STARTED COMPLETED
#   check-final-release.sh test-above V (SemVer precedence) | test-cmp A B (prints -1, 0 or 1)
#
# Environment:
#   VERSION            the tag name (X.Y.Z; X.Y.Z-… for prerelease-not-superseded)
#   TAG_SHA            the commit the tag points to (GITHUB_SHA of the tag-push run)
#   GITHUB_REPOSITORY  owner/repo
#   GH_TOKEN           read access to contents and actions (not-superseded, commit, release-run)
#   RELEASE_EMAIL      author and committer e-mail of the release commit (commit)
#   POLL_TIMEOUT_S     release-run: how long to wait for the release-it job (default 1200)
#   POLL_INTERVAL_S    release-run: delay between two reads (default 20)
# commit, release-run and tree run from a checkout with the whole history and origin/main
# (actions/checkout, fetch-depth: 0); not-superseded needs no history.
# Requires git, gh, jq and, for tree, node and cargo.
set -euo pipefail

fail() { echo "::error::$*"; exit 1; }

FINAL_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
# Slack around the release-it job's start and end for T's committer time (review L2).
WINDOW_SLACK_S=120

# Files the after:bump hooks of .release-it.json may change: scripts/changelog-release.mjs
# (CHANGELOG.md) and scripts/bump-version.mjs (bumpJson, bumpPackageLock, bumpCargo with its
# Cargo.lock, refreshCargoLock, bumpYamlKeys). Keep in step with those scripts.
allowed_files=(
  CHANGELOG.md
  package.json
  package-lock.json
  console/package.json
  agent/Cargo.toml
  agent/Cargo.lock
  agent/fuzz/Cargo.lock
  helm/databastion/Chart.yaml
)

# --- Pure parts (stdin to stdout; no network, no git) ------------------------------------------

# runs_on P < GET /actions/runs JSON: ids of the release.yml push runs on main at P.
runs_on() {
  jq -c --arg p "$1" '[.workflow_runs[]? | select(.path == ".github/workflows/release.yml"
    and .event == "push" and .head_branch == "main" and .head_sha == $p) | .id]'
}

# release_it_jobs < GET /actions/runs/{id}/jobs JSON: the jobs named release-it.
release_it_jobs() { jq -c '[.jobs[]? | select(.name == "release-it")]'; }

# release_it_approvers < GET /actions/runs/{id}/approvals JSON: who approved the release-it
# environment.
release_it_approvers() {
  jq -c '[.[]? | select(.state == "approved" and any(.environments[]?; .name == "release-it")) | .user.login]'
}

# check_diff < `git diff --no-renames --name-status P T`: only modifications of allowed_files, with
# CHANGELOG.md and package.json among them.
check_diff() {
  local line status path seen_changelog=false seen_package=false ok f
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    status="${line%%$'\t'*}" path="${line#*$'\t'}"
    [ "$status" = M ] || fail "P..T: '$path' has status '$status', only modifications are expected"
    ok=false
    for f in "${allowed_files[@]}"; do [ "$path" = "$f" ] && ok=true; done
    [ "$ok" = true ] || fail "P..T changes '$path', which the release hooks never change"
    [ "$path" = CHANGELOG.md ] && seen_changelog=true
    [ "$path" = package.json ] && seen_package=true
  done
  [ "$seen_changelog" = true ] && [ "$seen_package" = true ] \
    || fail "P..T must change CHANGELOG.md and package.json (the notes moved, the version bumped)"
}

# higher_finals V < tag names, one per line: the final X.Y.Z tags above V.
higher_finals() {
  local v="$1" t
  while IFS= read -r t; do
    [[ "$t" =~ $FINAL_RE ]] || continue
    [ "$t" = "$v" ] && continue
    if [ "$(printf '%s\n%s\n' "$v" "$t" | sort -V | tail -n 1)" = "$t" ]; then echo "$t"; fi
  done
}

# published_count V < GET /releases JSON (one or more pages, concatenated): published releases of V.
published_count() { jq -s --arg v "$1" '[.[][]? | select(.tag_name == $v and .draft == false)] | length'; }

# in_window CT STARTED COMPLETED: CT (epoch seconds) within [STARTED - slack, COMPLETED + slack],
# STARTED and COMPLETED as the API gives them (ISO 8601).
in_window() {
  local ct="$1" s e
  [[ "$ct" =~ ^[0-9]+$ ]] || return 1
  s="$(date -u -d "$2" +%s 2>/dev/null)" || return 1
  e="$(date -u -d "$3" +%s 2>/dev/null)" || return 1
  [ "$ct" -ge $((s - WINDOW_SLACK_S)) ] && [ "$ct" -le $((e + WINDOW_SLACK_S)) ]
}

# SemVer 2.0.0 precedence (semver.org, item 11), for the pre-release channel. Build metadata (`+…`)
# is not accepted: no release tag carries it. Numbers are compared as strings of digits (length,
# then characters), so any size works.
SEMVER_ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER_RE="^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-($SEMVER_ID(\\.$SEMVER_ID)*))?\$"
# A tag that starts like a version (what the publish.yml trigger can match): it must parse.
VERSION_LIKE_RE='^[0-9]+\.[0-9]+\.[0-9]+(-|$)'

# num_cmp A B: digit strings without leading zeros; prints -1, 0 or 1.
num_cmp() {
  if [ "${#1}" -ne "${#2}" ]; then
    if [ "${#1}" -lt "${#2}" ]; then echo -1; else echo 1; fi
  elif [ "$1" = "$2" ]; then echo 0
  elif [[ "$1" < "$2" ]]; then echo -1
  else echo 1
  fi
}

# semver_cmp A B: prints -1, 0 or 1; returns 2 when A or B is not a SemVer version.
semver_cmp() {
  local a="$1" b="$2" an=() bn=() ap="" bp="" i c x y xa ya
  local LC_ALL=C
  [[ "$a" =~ $SEMVER_RE ]] || return 2
  an=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"); ap="${BASH_REMATCH[5]}"
  [[ "$b" =~ $SEMVER_RE ]] || return 2
  bn=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"); bp="${BASH_REMATCH[5]}"
  for i in 0 1 2; do
    c="$(num_cmp "${an[$i]}" "${bn[$i]}")"
    [ "$c" = 0 ] || { echo "$c"; return 0; }
  done
  # A version without pre-release is above any pre-release of the same X.Y.Z.
  if [ -z "$ap" ] && [ -z "$bp" ]; then echo 0; return 0; fi
  if [ -z "$ap" ]; then echo 1; return 0; fi
  if [ -z "$bp" ]; then echo -1; return 0; fi
  IFS=. read -r -a xa <<<"$ap"
  IFS=. read -r -a ya <<<"$bp"
  for ((i = 0; i < ${#xa[@]} && i < ${#ya[@]}; i++)); do
    x="${xa[$i]}" y="${ya[$i]}"
    if [[ "$x" =~ ^[0-9]+$ ]] && [[ "$y" =~ ^[0-9]+$ ]]; then c="$(num_cmp "$x" "$y")"
    elif [[ "$x" =~ ^[0-9]+$ ]]; then c=-1   # numeric identifiers are below alphanumeric ones
    elif [[ "$y" =~ ^[0-9]+$ ]]; then c=1
    elif [ "$x" = "$y" ]; then c=0
    elif [[ "$x" < "$y" ]]; then c=-1        # ASCII order (LC_ALL=C)
    else c=1
    fi
    [ "$c" = 0 ] || { echo "$c"; return 0; }
  done
  # Equal so far: the longer list of identifiers is above.
  if [ "${#xa[@]}" -eq "${#ya[@]}" ]; then echo 0
  elif [ "${#xa[@]}" -lt "${#ya[@]}" ]; then echo -1
  else echo 1
  fi
}

# versions_above V < tag names, one per line: the version tags above V in SemVer precedence. Fails
# (status 1, with an error) when V, or any tag that starts like a version, does not parse: an
# unparsable tag might be above V. Tags that do not start like a version (`latest`) are ignored.
versions_above() {
  local v="$1" t c
  [[ "$v" =~ $SEMVER_RE ]] || { echo "::error::'$v' is not a SemVer version" >&2; return 1; }
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    [[ "$t" =~ $VERSION_LIKE_RE ]] || continue
    c="$(semver_cmp "$t" "$v")" || { echo "::error::tag '$t' starts like a version but is not SemVer" >&2; return 1; }
    if [ "$c" = 1 ]; then echo "$t"; fi
  done
  return 0
}

# --- Checks ------------------------------------------------------------------------------------

need_version() {
  version="${VERSION:-}"
  [[ "$version" =~ $FINAL_RE ]] || fail "not a final version: '$version'"
}
need_tag_sha() {
  tag_sha="${TAG_SHA:-}"
  [[ "$tag_sha" =~ ^[0-9a-f]{40}$ ]] || fail "TAG_SHA is not a full commit id: '$tag_sha'"
}

parent_of() {
  local parents
  read -r -a parents <<<"$(git rev-list --parents -n 1 "$1")"
  [ "${#parents[@]}" -eq 2 ] || return 1
  echo "${parents[1]}"
}

# A re-run of an old publish run, or a hotfix on an older line, must not re-sign a published
# version or move `X.Y` / `latest` back (review H1 and L6): refuse when the release V is published
# or when a final tag above V exists. A draft that the token cannot see counts as absent, which is
# what is wanted: only a published release blocks.
check_not_superseded() {
  local repo="${GITHUB_REPOSITORY:?}" n higher releases tags
  releases="$(gh api --paginate "repos/$repo/releases?per_page=100")" || fail "releases not readable"
  n="$(published_count "$version" <<<"$releases")"
  [ "$n" -eq 0 ] || fail "release $version is already published: refusing to build or sign it again"
  tags="$(gh api --paginate "repos/$repo/git/matching-refs/tags" --jq '.[].ref | ltrimstr("refs/tags/")')" \
    || fail "tags not readable"
  higher="$(higher_finals "$version" <<<"$tags")"
  [ -z "$higher" ] || fail "final tags above $version exist ($(tr '\n' ' ' <<<"$higher")): refusing to publish an older version (publish.yml does not support a release on an older line)"
  echo "release $version: not published, no final tag above it"
}

# A re-run of an old pre-release run keeps the approval of its first attempt (Re-run failed jobs):
# it must not sign again or move `next` back. Refuse when any version tag, pre-release or final, is
# above V in SemVer precedence (re-review N1).
check_prerelease_not_superseded() {
  local repo="${GITHUB_REPOSITORY:?}" v="${VERSION:-}" tags above
  [[ "$v" == *-* ]] || fail "not a pre-release version: '$v'"
  tags="$(gh api --paginate "repos/$repo/git/matching-refs/tags" --jq '.[].ref | ltrimstr("refs/tags/")')" \
    || fail "tags not readable"
  above="$(versions_above "$v" <<<"$tags")" || fail "cannot order the tags against $v (see above)"
  [ -z "$above" ] || fail "version tags above $v exist ($(tr '\n' ' ' <<<"$above")): refusing to sign it or move next back"
  echo "pre-release $v: no version tag above it"
}

check_commit() {
  local repo="${GITHUB_REPOSITORY:?}" email="${RELEASE_EMAIL:?RELEASE_EMAIL}" ref obj tag_json msg
  # 1. An annotated tag (release-it: git.tagAnnotation "DataBastion ${version}") on T. Read from the
  #    API, not from the checkout, which may hold a lightweight copy of the tag.
  ref="$(gh api "repos/$repo/git/ref/tags/$version")" || fail "tag $version not found through the API"
  [ "$(jq -r .object.type <<<"$ref")" = tag ] || fail "tag $version is not an annotated tag"
  obj="$(jq -r .object.sha <<<"$ref")"
  tag_json="$(gh api "repos/$repo/git/tags/$obj")" || fail "tag object $obj not readable"
  msg="$(jq -r .message <<<"$tag_json")"   # $(…) drops the trailing newlines
  [ "$msg" = "DataBastion $version" ] || fail "tag $version: message is '$msg', expected 'DataBastion $version'"
  [ "$(jq -r .object.type <<<"$tag_json")" = commit ] && [ "$(jq -r .object.sha <<<"$tag_json")" = "$tag_sha" ] \
    || fail "tag $version does not point to the commit of this run ($tag_sha)"
  echo "tag $version: annotated, 'DataBastion $version', on $tag_sha"

  # 2. T is on main.
  git rev-parse --verify --quiet origin/main >/dev/null || fail "origin/main not fetched"
  git merge-base --is-ancestor "$tag_sha" origin/main \
    || fail "$tag_sha is not reachable from origin/main"
  echo "T reachable from origin/main ($(git rev-parse origin/main))"

  # 3. The release-it commit (git.commitMessage "chore(release): ${version}", commitArgs -s), under
  #    the release identity of release.yml.
  local subject author committer
  subject="$(git log -1 --format=%s "$tag_sha")"
  [ "$subject" = "chore(release): $version" ] || fail "T's subject is '$subject', expected 'chore(release): $version'"
  author="$(git log -1 --format=%ae "$tag_sha")"
  committer="$(git log -1 --format=%ce "$tag_sha")"
  [ "$author" = "$email" ] && [ "$committer" = "$email" ] \
    || fail "T's author / committer e-mail is '$author' / '$committer', expected the release identity '$email'"
  git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$tag_sha" | grep -q . \
    || fail "T has no Signed-off-by trailer"
  echo "T: 'chore(release): $version', author and committer $email, signed off"

  # 4. One parent P, itself a merge commit (the release pull request merged into main).
  local p pp
  p="$(parent_of "$tag_sha")" || fail "T must have exactly one parent"
  pp="$(git rev-list --parents -n 1 "$p" | wc -w)"
  [ "$pp" -eq 3 ] || fail "P ($p) is not a merge commit with two parents"
  echo "P: $p (merge commit)"

  # 5. Only the version and changelog files differ between P and T.
  git diff --no-renames --name-status "$p" "$tag_sha" | check_diff
  echo "P..T: $(git diff --no-renames --name-only "$p" "$tag_sha" | tr '\n' ' ')"
}

# The release.yml run that made T: on the push of P to main, its release-it job completed with
# `success`, approved in the release-it environment, and T committed while that job ran (review
# L2). release-it pushes the tag, then creates the draft release, so the run may still be running
# when this starts: it waits up to POLL_TIMEOUT_S (20 minutes, the timeout-minutes of that job in
# release.yml) for the job to complete, and fails if it has not (review L1).
check_release_run() {
  local repo="${GITHUB_REPOSITORY:?}" p deadline runs n run_id="" job="" approved status="" conclusion="" ct
  local timeout="${POLL_TIMEOUT_S:-1200}" interval="${POLL_INTERVAL_S:-20}"
  p="$(parent_of "$tag_sha")" || fail "T must have exactly one parent"
  deadline=$(( $(date +%s) + timeout ))
  while :; do
    runs="$(gh api "repos/$repo/actions/runs?head_sha=$p&event=push&branch=main&per_page=100" | runs_on "$p")" \
      || fail "workflow runs not readable"
    n="$(jq length <<<"$runs")"
    [ "$n" -le 1 ] || fail "$n release.yml push runs on $p, expected one: $runs"
    if [ "$n" -eq 1 ]; then
      run_id="$(jq -r '.[0]' <<<"$runs")"
      job="$(gh api "repos/$repo/actions/runs/$run_id/jobs?filter=latest&per_page=100" | release_it_jobs)" \
        || fail "jobs of run $run_id not readable"
      [ "$(jq length <<<"$job")" -eq 1 ] || fail "release.yml run $run_id: expected one job 'release-it', found $(jq length <<<"$job")"
      status="$(jq -r '.[0].status' <<<"$job")" conclusion="$(jq -r '.[0].conclusion // empty' <<<"$job")"
      if [ "$status" = completed ]; then break; fi
    fi
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "release.yml run on P ($p): ${run_id:+run $run_id, }job release-it ${status:-not found} after ${timeout}s"
    echo "waiting for the release.yml run on $p (${run_id:-not found yet}, release-it: ${status:-?})"
    sleep "$interval"
  done
  [ "$conclusion" = success ] || fail "release.yml run $run_id: job release-it concluded '$conclusion'"
  approved="$(gh api "repos/$repo/actions/runs/$run_id/approvals" | release_it_approvers)" \
    || fail "approvals of run $run_id not readable"
  [ "$(jq length <<<"$approved")" -ge 1 ] \
    || fail "release.yml run $run_id has no approval of the release-it environment (approve, do not bypass)"
  ct="$(git log -1 --format=%ct "$tag_sha")"
  in_window "$ct" "$(jq -r '.[0].started_at' <<<"$job")" "$(jq -r '.[0].completed_at' <<<"$job")" \
    || fail "T's committer time ($(date -u -d "@$ct" +%FT%TZ)) is outside the release-it job of run $run_id ($(jq -r '.[0].started_at + " to " + .[0].completed_at' <<<"$job"), ${WINDOW_SLACK_S}s slack)"
  echo "release.yml run $run_id on P ($p): release-it success, approved by $(jq -r 'join(", ")' <<<"$approved"), T committed during the job"
}

# T's tree recomputed: P checked out in a scratch worktree, the after:bump hooks of .release-it.json
# run on it in their order (changelog, then version), every tracked change staged as release-it
# does (`git add . --update`), and the resulting tree compared with T's. The changelog heading
# carries the date the hook ran (UTC), just before the commit: the dates of T's committer time and
# of 10 minutes earlier are tried. Needs node and cargo, with the agent dependencies fetched by
# this function (`cargo fetch --locked`), as in release.yml.
check_tree() {
  local p want got t d dates=() ok=false
  p="$(parent_of "$tag_sha")" || fail "T must have exactly one parent"
  want="$(git rev-parse "$tag_sha^{tree}")"
  t="$(git log -1 --format=%ct "$tag_sha")"
  for d in "$(date -u -d "@$t" +%F)" "$(date -u -d "@$((t - 600))" +%F)"; do
    [ "${#dates[@]}" -gt 0 ] && [ "${dates[0]}" = "$d" ] && continue
    dates+=("$d")
  done
  work="$(mktemp -d)"   # global: the EXIT trap reads it (EXIT, not RETURN: fail() exits)
  trap 'git worktree remove --force "$work" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
  git worktree add --quiet --detach "$work" "$p"
  if [ -f "$work/agent/Cargo.lock" ]; then
    cargo fetch --locked --quiet --manifest-path "$work/agent/Cargo.toml"
    if [ -f "$work/agent/fuzz/Cargo.lock" ]; then
      cargo fetch --locked --quiet --manifest-path "$work/agent/fuzz/Cargo.toml"
    fi
  fi
  for d in "${dates[@]}"; do
    git -C "$work" reset --quiet --hard "$p"
    (cd "$work" && CHANGELOG_RELEASE_DATE="$d" node scripts/changelog-release.mjs changelog "$version" \
      && node scripts/bump-version.mjs "$version") >&2 || fail "the release hooks failed on P"
    git -C "$work" add --update
    got="$(git -C "$work" write-tree)"
    if [ "$got" = "$want" ]; then ok=true; break; fi
    echo "tree with the date $d: $got (T: $want)"
  done
  [ "$ok" = true ] || { git -C "$work" diff --cached --stat "$tag_sha" >&2 || true
    fail "T's tree is not the release hooks applied to P (dates tried: ${dates[*]})"; }
  echo "T's tree recomputed from P: $want (changelog date $d)"
}

case "${1:-}" in
  not-superseded) need_version; check_not_superseded ;;
  commit) need_version; need_tag_sha; check_commit ;;
  release-run) need_version; need_tag_sha; check_release_run ;;
  tree) need_version; need_tag_sha; check_tree ;;
  prerelease-not-superseded) check_prerelease_not_superseded ;;
  test-above) versions_above "${2?V}" ;;
  test-cmp) semver_cmp "${2?A}" "${3?B}" ;;
  test-runs) runs_on "${2:?P}" ;;
  test-job) release_it_jobs ;;
  test-approvals) release_it_approvers ;;
  test-diff) check_diff; echo ok ;;
  test-higher) higher_finals "${2:?V}" ;;
  test-published) published_count "${2:?V}" ;;
  test-window) if in_window "${2:?CT}" "${3:?STARTED}" "${4:?COMPLETED}"; then echo in; else echo out; exit 1; fi ;;
  *) echo "usage: $0 not-superseded | commit | release-run | tree (test-* for the tests)" >&2; exit 64 ;;
esac
