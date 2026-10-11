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
  # `test some::path ... FAILED` lines name the failing tests.
  failed="$(grep -E '^test .+ \.\.\. FAILED$' "$log" | sed -E 's/^test (.+) \.\.\. FAILED$/\1/' | head -n 10)"
  if [ -z "$failed" ]; then
    echo "::error title=cargo test failed (exit ${status})::no failing test line found: build error, abort or timeout; see the job log"
  fi
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    # Without --nocapture the panic is inside the test's stdout block; with it, the
    # `thread '<name>' … panicked at` line is printed in place. Either way, take that line and
    # the next three (the assertion message, `left` and `right`).
    detail="$(awk -v name="${name}" '
      index($0, "thread \x27" name "\x27") == 1 && /panicked at/ { print; for (i = 0; i < 3 && (getline line) > 0; i++) print line; exit }
    ' "$log" | tr '\n' ' ' | cut -c1-500)"
    # Workflow command escaping: `%`, CR and LF in the message; also `:` and `,` in properties.
    detail="${detail//%/%25}"
    title="${name//%/%25}"
    title="${title//:/%3A}"
    title="${title//,/%2C}"
    echo "::error title=Failing test ${title}::${detail:-see the job log}"
  done <<< "$failed"
fi

exit "$status"
