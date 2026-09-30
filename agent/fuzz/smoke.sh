#!/usr/bin/env bash
# Stable-toolchain smoke run of every fuzz target (CI and local).
#
#   agent/fuzz/smoke.sh [SECONDS]   # default 10 seconds per target
#
# Builds the targets with libFuzzer's coverage instrumentation (the flags cargo-fuzz passes, without
# a sanitizer: sanitizers need a nightly toolchain) plus debug assertions and overflow checks, then
# runs each target for SECONDS from an empty corpus in a temporary directory. Exits non-zero on the
# first crash, panic, timeout or out-of-memory; the crashing input is kept under
# $CARGO_TARGET_DIR/fuzz-artifacts/ (never commit it if it was built from real data).
# For longer campaigns, use cargo-fuzz on nightly (README.md).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SECS="${1:-10}"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HERE/target}"
# --target keeps these flags off the build scripts (as cargo-fuzz does).
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks" \
  cargo build --manifest-path "$HERE/Cargo.toml" --locked --release --target "$TRIPLE" --bins

BIN="$CARGO_TARGET_DIR/$TRIPLE/release"
ART="$CARGO_TARGET_DIR/fuzz-artifacts"
mkdir -p "$ART"
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
for src in "$HERE"/fuzz_targets/*.rs; do
  t="$(basename "$src" .rs)"
  mkdir -p "$CORPUS/$t"
  echo "fuzz smoke: $t (${SECS}s)" >&2
  rc=0
  "$BIN/$t" "$CORPUS/$t" -max_total_time="$SECS" -max_len=4096 -timeout=10 -rss_limit_mb=1024 \
    -artifact_prefix="$ART/$t-" > "$CORPUS/$t.log" 2>&1 || rc=$?
  grep -E '^Done' "$CORPUS/$t.log" >&2 || true
  if [ "$rc" -ne 0 ]; then
    tail -n 40 "$CORPUS/$t.log" >&2
    echo "fuzz smoke: $t failed (input in $ART)" >&2
    exit 1
  fi
done
