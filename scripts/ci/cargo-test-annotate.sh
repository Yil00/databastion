#!/usr/bin/env bash
# Runs a `cargo test` command line unchanged and, when it fails, turns the names of the failing
# tests and the first lines of their panic messages into GitHub Actions error annotations, so that
# an intermittent failure can be identified from the check run's annotations without the job log
# (which is the same text). Exit status is the command's.
#
# Usage: scripts/ci/cargo-test-annotate.sh cargo test -p <crate> --all-features --locked [-- …]
#
# Tests run on the dev fixtures only (fake data, dev/ground-truth.json); nothing is printed here
# that the job log does not already show.
set -uo pipefail

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
  # `test some::path ... FAILED` lines name the failing tests; `---- some::path stdout ----`
  # blocks hold their output, whose `panicked at` line and the next one carry the assertion.
  failed="$(grep -E '^test .+ \.\.\. FAILED$' "$log" | sed -E 's/^test (.+) \.\.\. FAILED$/\1/' | head -n 10)"
  if [ -z "$failed" ]; then
    echo "::error title=cargo test failed (exit ${status})::no failing test line found: build error, abort or timeout; see the job log"
  fi
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    detail="$(awk -v start="---- ${name} stdout ----" '
      $0 == start { inside = 1; next }
      inside && /^---- / { exit }
      inside && /panicked at/ { print; getline; print; exit }
    ' "$log" | tr '\n' ' ' | cut -c1-500 | sed 's/%/%25/g')"
    echo "::error title=Failing test: ${name//%/%25}::${detail:-see the job log}"
  done <<< "$failed"
fi

exit "$status"
