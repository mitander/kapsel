#!/usr/bin/env sh
set -eu

corpus_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-fuzz-corpus.XXXXXX")
trap 'rm -rf "$corpus_directory"' EXIT HUP INT TERM
cp fuzz/corpus/inspect_receipt/canonical-receipt-and-trust "$corpus_directory/"
cd fuzz
runs="${KAPSEL_FUZZ_RUNS:-10000}"
seed="${KAPSEL_FUZZ_SEED:-2118243591}"
max_time_arg=""
if [ -n "${KAPSEL_FUZZ_MAX_TIME:-}" ]; then
  max_time_arg="-max_total_time=${KAPSEL_FUZZ_MAX_TIME}"
fi

start_time=$(date +%s)
status=0
if ! rustup run nightly-2026-07-03 cargo fuzz run --dev inspect_receipt "$corpus_directory" -- \
  -runs="$runs" -seed="$seed" $max_time_arg; then
  status=1
fi

if [ -n "${KAPSEL_FUZZ_NOTIFY_URL:-}" ]; then
  end_time=$(date +%s)
  elapsed=$((end_time - start_time))
  if [ "$status" -eq 0 ]; then
    outcome="PASSED"
  else
    outcome="FAILED"
  fi
  message="Kapsel fuzz $outcome in ${elapsed}s (runs=$runs, seed=$seed)"
  if command -v curl >/dev/null 2>&1; then
    curl -s -S -m 10 -d "$message" "$KAPSEL_FUZZ_NOTIFY_URL" >/dev/null 2>&1 || true
  fi
fi

exit "$status"
