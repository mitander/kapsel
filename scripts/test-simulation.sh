#!/usr/bin/env sh
set -eu

log_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-simulation-logs.XXXXXX")
trap 'rm -rf "$log_directory"' EXIT HUP INT TERM
cargo test --release --locked -p kapsel --lib --no-run
shards="${KAPSEL_SIMULATION_SHARDS:-8}"
start_time=$(date +%s)
pids=""
shard=0
while [ "$shard" -lt "$shards" ]; do
  KAPSEL_SIMULATION_SHARDS="$shards" KAPSEL_SIMULATION_SHARD_INDEX="$shard" \
    cargo test --release --locked -p kapsel --lib \
      simulation_tests::seeded_lifecycle_crash_simulation_preserves_invariants -- \
      --ignored --exact --nocapture >"$log_directory/$shard.log" 2>&1 &
  pids="$pids $!"
  shard=$((shard + 1))
done
status=0
for pid in $pids; do
  if ! wait "$pid"; then
    status=1
  fi
done
shard=0
while [ "$shard" -lt "$shards" ]; do
  cat "$log_directory/$shard.log"
  shard=$((shard + 1))
done
if [ -n "${KAPSEL_SIMULATION_NOTIFY_URL:-}" ]; then
  end_time=$(date +%s)
  elapsed=$((end_time - start_time))
  cases="${KAPSEL_SIMULATION_CASES:-10000}"
  seed="${KAPSEL_SIMULATION_SEED:-21182435914953528}"
  if [ "$status" -eq 0 ]; then
    outcome="PASSED"
  else
    outcome="FAILED"
  fi
  message="Kapsel simulation $outcome in ${elapsed}s (cases=$cases, shards=$shards, seed=$seed)"
  if command -v curl >/dev/null 2>&1; then
    curl -s -S -m 10 -d "$message" "$KAPSEL_SIMULATION_NOTIFY_URL" >/dev/null 2>&1 || true
  fi
fi
exit "$status"
