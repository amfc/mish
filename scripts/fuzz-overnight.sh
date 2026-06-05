#!/usr/bin/env bash
# Long, parallel, unattended libFuzzer campaign across every cargo-fuzz target.
#
# The CI "fuzz smoke" job (40s/target) only gates regressions. This script is the
# out-of-band campaign the README points to: it runs ALL targets at once, each in
# libFuzzer **fork mode**, so the box's cores stay saturated for hours and a crash
# in one target doesn't stop the others (each unique crash is saved and fuzzing
# continues). Designed to be kicked off and left overnight.
#
#   ./scripts/fuzz-overnight.sh                # all targets, 8h each, all cores
#   DURATION=3600 ./scripts/fuzz-overnight.sh  # 1h
#   ./scripts/fuzz-overnight.sh diff_roundtrip differential_emulator   # a subset
#
# Env knobs: DURATION (s, default 28800=8h), CORES (default nproc),
#            RSS_LIMIT_MB (default 4096).
#
# Needs the nightly toolchain + cargo-fuzz (ASan is on by default).
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root (script lives in scripts/)

DURATION="${DURATION:-28800}"        # seconds, per target (all run concurrently)
CORES="${CORES:-$(nproc)}"
RSS_LIMIT_MB="${RSS_LIMIT_MB:-4096}"

# Default target set. Order = rough value (widest surface first). Override by
# passing names as args.
TARGETS=(
  diff_roundtrip          # emulator-driven diff round-trip — widest surface, found the most
  differential_emulator   # our emulator vs the independent vt100 (correctness oracle)
  screen_apply            # malformed screen-diff apply (found the zero-dimension panic)
  instruction_decode      # wire instruction decode
  frag_reassemble         # fragment reassembler
  userstream_decode       # keystroke / UserStream decode
)
[ "$#" -gt 0 ] && TARGETS=("$@")

n=${#TARGETS[@]}
# Forks per target, leaving the main merge processes (~1/target) some headroom.
per=$(( (CORES - n) / n ))
[ "$per" -lt 1 ] && per=1

ts=$(date +%Y%m%d-%H%M%S)
logdir="fuzz/logs/$ts"
mkdir -p "$logdir"

echo "mish overnight fuzz"
echo "  cores=$CORES  targets=$n  forks/target=$per  (~$((per * n)) fuzzing procs)"
echo "  duration=${DURATION}s (~$((DURATION / 3600))h)  rss_limit=${RSS_LIMIT_MB}MB"
echo "  logs=$logdir"
echo

# Build every target up front so the parallel launches don't stampede the build
# lock (and so a compile error fails fast, before we wait hours).
echo "building targets…"
for t in "${TARGETS[@]}"; do
  cargo +nightly fuzz build "$t"
done
echo

# Replay checked-in regression seeds first — deterministic gate. If a known bug
# came back, stop now instead of burning a night.
for t in "${TARGETS[@]}"; do
  reg="fuzz/regressions/$t"
  if [ -d "$reg" ] && [ -n "$(ls -A "$reg" 2>/dev/null)" ]; then
    echo "replaying regression seeds: $t"
    # -runs=0: execute each seed exactly once and exit (a deterministic gate);
    # without it, libFuzzer treats the dir as a live corpus and fuzzes forever.
    if ! cargo +nightly fuzz run "$t" "$reg"/ -- -runs=0 >"$logdir/$t.regress.log" 2>&1; then
      echo "!! regression re-triggered in $t — see $logdir/$t.regress.log" >&2
      exit 1
    fi
  fi
done
echo

# Launch each target in fork mode, in the background.
#  -fork=N         : N parallel fuzzing subprocesses, corpus merged centrally
#  -ignore_crashes=1 : keep going after a crash (save artifact, don't stop) — key for unattended runs
#  -max_total_time : wall-clock budget for this target
declare -a pids
for t in "${TARGETS[@]}"; do
  ( exec cargo +nightly fuzz run "$t" -- \
      -fork="$per" -ignore_crashes=1 \
      -max_total_time="$DURATION" -rss_limit_mb="$RSS_LIMIT_MB" \
      -print_final_stats=1 ) >"$logdir/$t.log" 2>&1 &
  pids+=("$!")
  echo "launched $t (pid $!) -> $logdir/$t.log"
done
echo
echo "running… (tail -f $logdir/<target>.log to watch)"

fail=0
for i in "${!TARGETS[@]}"; do
  wait "${pids[$i]}" || { echo "${TARGETS[$i]} campaign exited non-zero"; fail=1; }
done

echo
echo "=== new crash / oom / timeout artifacts ==="
found=0
for t in "${TARGETS[@]}"; do
  for f in fuzz/artifacts/"$t"/crash-* fuzz/artifacts/"$t"/oom-* fuzz/artifacts/"$t"/leak-* fuzz/artifacts/"$t"/timeout-*; do
    [ -e "$f" ] || continue
    echo "  $f"
    found=1
  done
done
if [ "$found" -eq 0 ]; then
  echo "  none — clean run 🎉"
else
  echo
  echo "Reproduce with: cargo +nightly fuzz run <target> <artifact-path>"
  echo "If real & fixed, copy the artifact into fuzz/regressions/<target>/ to guard it."
fi
echo "logs: $logdir"
exit "$fail"
