#!/usr/bin/env sh
set -eu

# Nightly automated soak runner for Kapsel.
# Runs extended fuzzing and multi-seed simulations, automatically syncs latest
# master, deduplicates failures to avoid re-alerting on known bugs, and handles
# crash-recovery if aborted.

root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"

state_dir="${KAPSEL_SOAK_STATE_DIR:-${HOME}/.cache/kapsel/soak}"
notify_url="${KAPSEL_NOTIFY_URL:-}"
fuzz_seconds="${KAPSEL_SOAK_FUZZ_SECONDS:-1800}"
sim_seeds="${KAPSEL_SOAK_SIMULATION_SEEDS:-10}"
sim_cases="${KAPSEL_SOAK_SIMULATION_CASES:-5000}"
shards="${KAPSEL_SOAK_SHARDS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
auto_update="${KAPSEL_SOAK_AUTO_UPDATE:-1}"

mkdir -p "$state_dir"
lock_file="$state_dir/soak.pid"
seen_bugs_file="$state_dir/seen_bugs.txt"
touch "$seen_bugs_file"

# Crash recovery and mutual exclusion
if [ -f "$lock_file" ]; then
  prev_pid=$(cat "$lock_file" 2>/dev/null || echo "")
  if [ -n "$prev_pid" ] && kill -0 "$prev_pid" 2>/dev/null; then
    echo "Soak run already in progress (PID $prev_pid). Exiting."
    exit 0
  else
    echo "Stale lock file from aborted run (PID $prev_pid). Recovering."
    rm -f "$lock_file"
  fi
fi

echo "$$" > "$lock_file"
cleanup() {
  rm -f "$lock_file"
}
trap cleanup EXIT HUP INT TERM

send_notification() {
  msg="$1"
  echo "$msg"
  if [ -n "$notify_url" ] && command -v curl >/dev/null 2>&1; then
    curl -s -S -m 15 -d "$msg" "$notify_url" >/dev/null 2>&1 || true
  fi
}

# Auto-update to latest master if configured
if [ "$auto_update" = "1" ] && [ -d ".git" ]; then
  if git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "Syncing latest master..."
    git fetch -q origin master 2>/dev/null || true
    git checkout -q master 2>/dev/null || true
    git merge -q --ff-only origin/master 2>/dev/null || true
  else
    echo "Working tree dirty; skipping auto-update."
  fi
fi

commit_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
start_time=$(date +%s)
echo "Starting Kapsel nightly soak on commit $commit_sha (shards=$shards, fuzz=${fuzz_seconds}s, sim_seeds=$sim_seeds)..."

new_bugs=0
total_failures=0

fingerprint_and_record() {
  raw="$1"
  category="$2"
  # Compute sha256 fingerprint
  fp=$(printf '%s' "$raw" | (sha256sum 2>/dev/null || shasum -a 256 2>/dev/null || md5 2>/dev/null || echo "$raw") | awk '{print $1}')
  if grep -Fq "$fp" "$seen_bugs_file"; then
    echo "Known bug ($category fp=$fp) - suppressing notification."
  else
    echo "$fp" >> "$seen_bugs_file"
    new_bugs=$((new_bugs + 1))
    send_notification "ALERT: New Kapsel $category bug on $commit_sha (fp=$fp): $raw"
  fi
  total_failures=$((total_failures + 1))
}

# 1. Multi-seed simulation sweep
echo "==> Running simulation sweep ($sim_seeds seeds x $sim_cases cases)..."
seed_idx=1
while [ "$seed_idx" -le "$sim_seeds" ]; do
  seed=$(od -An -N8 -tu8 /dev/urandom 2>/dev/null | tr -d ' ' || echo "$((start_time + seed_idx))")
  sim_log=$(mktemp "${TMPDIR:-/tmp}/kapsel-soak-sim.XXXXXX")
  if ! KAPSEL_SIMULATION_SHARDS="$shards" \
       KAPSEL_SIMULATION_CASES="$sim_cases" \
       KAPSEL_SIMULATION_SEED="$seed" \
       ./scripts/test-simulation.sh >"$sim_log" 2>&1; then
    panic_line=$(grep -E 'panicked at|FAILED|assertion' "$sim_log" | head -n 1 || echo "Simulation failed for seed $seed")
    fingerprint_and_record "$panic_line" "simulation"
  fi
  rm -f "$sim_log"
  seed_idx=$((seed_idx + 1))
done

# 2. Time-bounded receipt fuzzing
if [ "$fuzz_seconds" -gt 0 ]; then
  echo "==> Running receipt fuzzing for ${fuzz_seconds}s..."
  fuzz_log=$(mktemp "${TMPDIR:-/tmp}/kapsel-soak-fuzz.XXXXXX")
  if ! KAPSEL_FUZZ_MAX_TIME="$fuzz_seconds" \
       ./scripts/test-fuzz.sh >"$fuzz_log" 2>&1; then
    crash_line=$(grep -E 'ERROR: libFuzzer:|panicked at|deadly signal' "$fuzz_log" | head -n 1 || echo "Fuzz crash")
    fingerprint_and_record "$crash_line" "fuzz"
  fi
  rm -f "$fuzz_log"
fi

end_time=$(date +%s)
duration=$((end_time - start_time))

if [ "$total_failures" -eq 0 ]; then
  send_notification "Kapsel nightly soak PASSED on $commit_sha in ${duration}s ($sim_seeds seeds, ${fuzz_seconds}s fuzz)."
else
  echo "Soak run completed with $total_failures failure(s) ($new_bugs new)."
fi
