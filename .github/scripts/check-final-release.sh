#!/usr/bin/env bash
# Checks, before publish.yml builds or signs anything, that a final-version tag (X.Y.Z) is the one
# release-it made in an approved release.yml run (ADR-0058 decision 3.2, as implemented without the
# release record of decision 2.10; implementation note of 2026-10-24). It replaces the approvals of
# the `release` environment for final versions. Pre-release tags are not checked here: they go
# through the `prerelease-approval` gate of publish.yml.
#
# A check of the honest path only: whoever can choose the publish.yml that a tag runs (an
# administrator, or the holder of RELEASE_TOKEN) can remove it (ADR-0058, decision 3.4).
#
#   check-final-release.sh commit       # the tag object, the release commit T, its parent P, the files
#   check-final-release.sh tree         # T's tree recomputed from P with the after:bump hooks
#   check-final-release.sh release-run  # the approved release.yml run on P (polls)
#
# Environment:
#   VERSION            the tag name (X.Y.Z)
#   TAG_SHA            the commit the tag points to (GITHUB_SHA of the tag-push run)
#   GITHUB_REPOSITORY  owner/repo
#   GH_TOKEN           read access to contents and actions (commit, release-run)
#   RELEASE_EMAIL      author and committer e-mail of the release commit (commit)
#   POLL_TIMEOUT_S     release-run: how long to wait for the release-it job (default 1200)
#   POLL_INTERVAL_S    release-run: delay between two reads (default 20)
# Run from a checkout with the whole history and origin/main (actions/checkout, fetch-depth: 0).
# Requires git and, depending on the subcommand, gh, jq, node and cargo.
set -euo pipefail

fail() { echo "::error::$*"; exit 1; }

version="${VERSION:?VERSION}"
tag_sha="${TAG_SHA:?TAG_SHA}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "not a final version: '$version'"
[[ "$tag_sha" =~ ^[0-9a-f]{40}$ ]] || fail "TAG_SHA is not a full commit id: '$tag_sha'"

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

parent_of() {
  local parents
  read -r -a parents <<<"$(git rev-list --parents -n 1 "$1")"
  [ "${#parents[@]}" -eq 2 ] || return 1
  echo "${parents[1]}"
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
  local line status path seen_changelog=false seen_package=false ok f
  while IFS= read -r line; do
    status="${line%%$'\t'*}" path="${line#*$'\t'}"
    [ "$status" = M ] || fail "P..T: '$path' has status '$status', only modifications are expected"
    ok=false
    for f in "${allowed_files[@]}"; do [ "$path" = "$f" ] && ok=true; done
    [ "$ok" = true ] || fail "P..T changes '$path', which the release hooks never change"
    [ "$path" = CHANGELOG.md ] && seen_changelog=true
    [ "$path" = package.json ] && seen_package=true
  done < <(git diff --no-renames --name-status "$p" "$tag_sha")
  [ "$seen_changelog" = true ] && [ "$seen_package" = true ] \
    || fail "P..T must change CHANGELOG.md and package.json (the notes moved, the version bumped)"
  echo "P..T: $(git diff --no-renames --name-only "$p" "$tag_sha" | tr '\n' ' ')"
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

# The release.yml run that made T: on the push of P to main, with its release-it job approved in
# the release-it environment. release-it pushes the tag, then creates the draft release: the run may
# still be running when this starts. It waits for the release-it job to complete, up to
# POLL_TIMEOUT_S, and requires `success`. If it is still running at the deadline, it is accepted
# with a warning: a job of the release-it environment runs only after its approval, which is
# checked too.
check_release_run() {
  local repo="${GITHUB_REPOSITORY:?}" p deadline runs n run_id job approved status conclusion
  local timeout="${POLL_TIMEOUT_S:-1200}" interval="${POLL_INTERVAL_S:-20}"
  p="$(parent_of "$tag_sha")" || fail "T must have exactly one parent"
  deadline=$(( $(date +%s) + timeout ))
  while :; do
    runs="$(gh api "repos/$repo/actions/runs?head_sha=$p&event=push&branch=main&per_page=100" \
      --jq '[.workflow_runs[] | select(.path == ".github/workflows/release.yml" and .event == "push"
              and .head_branch == "main" and .head_sha == "'"$p"'") | .id]')"
    n="$(jq length <<<"$runs")"
    [ "$n" -le 1 ] || fail "$n release.yml push runs on $p, expected one: $runs"
    if [ "$n" -eq 1 ]; then
      run_id="$(jq -r '.[0]' <<<"$runs")"
      job="$(gh api "repos/$repo/actions/runs/$run_id/jobs?filter=latest&per_page=100" \
        --jq '[.jobs[] | select(.name == "release-it")]')"
      [ "$(jq length <<<"$job")" -eq 1 ] || fail "release.yml run $run_id: expected one job 'release-it', found $(jq length <<<"$job")"
      status="$(jq -r '.[0].status' <<<"$job")" conclusion="$(jq -r '.[0].conclusion // empty' <<<"$job")"
      if [ "$status" = completed ]; then break; fi
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then break; fi
    echo "waiting for the release.yml run on $p (${run_id:-not found yet}, release-it: ${status:-?})"
    sleep "$interval"
  done
  [ -n "${run_id:-}" ] || fail "no release.yml push run on main for P ($p) after ${timeout}s"
  approved="$(gh api "repos/$repo/actions/runs/$run_id/approvals" \
    --jq '[.[] | select(.state == "approved" and any(.environments[]; .name == "release-it")) | .user.login]')"
  [ "$(jq length <<<"$approved")" -ge 1 ] \
    || fail "release.yml run $run_id has no approval of the release-it environment (approve, do not bypass)"
  case "$status" in
    completed)
      [ "$conclusion" = success ] || fail "release.yml run $run_id: job release-it concluded '$conclusion'" ;;
    in_progress)
      echo "::warning::release.yml run $run_id: job release-it still running after ${timeout}s; accepted, its approval is recorded" ;;
    *)
      fail "release.yml run $run_id: job release-it is '$status' after ${timeout}s" ;;
  esac
  echo "release.yml run $run_id on P ($p): release-it $status${conclusion:+ / $conclusion}, approved by $(jq -r 'join(", ")' <<<"$approved")"
}

case "${1:-}" in
  commit) check_commit ;;
  tree) check_tree ;;
  release-run) check_release_run ;;
  *) echo "usage: $0 commit | tree | release-run" >&2; exit 64 ;;
esac
