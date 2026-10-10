#!/usr/bin/env bash
# One AddressSanitizer fuzz run of an agent parser target (.github/workflows/fuzz-nightly.yml).
#
#   .github/scripts/fuzz-nightly.sh TARGET SECONDS
#
# Needs a nightly Rust toolchain as the default and cargo-fuzz on PATH. Builds TARGET with
# cargo-fuzz (release, debug assertions and overflow checks, AddressSanitizer), seeds its corpus
# from committed fixtures where a parser needs a fixed header to be reached (the same seeds as
# agent/fuzz/smoke.sh, plus the CAS audit log fixture one line per input), then fuzzes for SECONDS.
# Exits non-zero on a crash, panic, sanitizer report, timeout or out-of-memory; the input is kept in
# agent/fuzz/artifacts/TARGET/ (cargo-fuzz's default artifact prefix).
#
# Every seed is a committed fixture with fake values only (agent/crates/connector-cas/fixtures/
# README.md: fake dev user, ticket and token ids, ID tokens, Authorization header and cookies
# replaced by REDACTED / FAKE placeholders). Crash inputs are mutations of these seeds or of
# libFuzzer's own random bytes, so they cannot hold a secret: never seed this corpus with real
# log lines, server replies or service definitions (I2).
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 TARGET SECONDS" >&2
  exit 2
fi
TARGET="$1"
SECS="$2"
if ! [[ "$TARGET" =~ ^[a-z0-9_]+$ ]]; then
  echo "fuzz-nightly: invalid target name" >&2
  exit 2
fi
if ! [[ "$SECS" =~ ^[1-9][0-9]{0,4}$ ]]; then
  echo "fuzz-nightly: SECONDS must be a positive integer" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FUZZ="$ROOT/agent/fuzz"
if [ ! -f "$FUZZ/fuzz_targets/$TARGET.rs" ]; then
  echo "fuzz-nightly: no fuzz target $TARGET in agent/fuzz/fuzz_targets/" >&2
  exit 2
fi
CORPUS="$FUZZ/corpus/$TARGET"
mkdir -p "$CORPUS" "$FUZZ/artifacts/$TARGET"

FIXTURES="$ROOT/agent/crates/connector-cas/fixtures"
case "$TARGET" in
  cas_registry) cp "$FIXTURES"/registry/*.json "$CORPUS"/ ;;
  cas_registry_yaml | cas_registry_yaml_diff)
    cp "$FIXTURES"/registry/*.yml "$FIXTURES"/registry/*.yaml "$FIXTURES"/registry-hostile/*.yml "$CORPUS"/ ;;
  cas_audit_log) split -l 1 -a 3 -d "$FIXTURES/cas-8.0.2-oauth-oidc-audit.jsonl" "$CORPUS/fixture-" ;;
  *) ;; # the MongoDB and OpenLDAP targets start from an empty corpus, as in smoke.sh
esac
echo "fuzz-nightly: $TARGET for ${SECS}s, $(find "$CORPUS" -type f | wc -l) seed input(s)" >&2

cd "$ROOT/agent"
# The lockfile must be used as committed (cargo-fuzz has no --locked flag).
cargo fetch --locked --manifest-path fuzz/Cargo.toml
# Same libFuzzer bounds as smoke.sh, with more memory for the ASan shadow.
cargo fuzz run --fuzz-dir fuzz -O -a -s address "$TARGET" "$CORPUS" -- \
  -max_total_time="$SECS" -max_len=4096 -timeout=10 -rss_limit_mb=2560 -print_final_stats=1
