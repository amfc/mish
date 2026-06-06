#!/usr/bin/env bash
# Phase 2 of the overnight fuzzing plan — runs AFTER the libFuzzer campaign
# (scripts/fuzz-overnight.sh) so it has the whole box to itself.
#
# The in-process proptest harnesses and the deterministic sim / madsim engines
# converge fast, so they want VOLUME (many cases × several rounds with fresh
# entropy), not all-night duration. This cranks PROPTEST_CASES way past the
# default 256 and runs several rounds; each round draws fresh random inputs, so
# more rounds = wider structured coverage. The madsim/turmoil engines sweep their
# own seed space internally; we just run them under the soak too.
#
#   ./scripts/fuzz-proptest-soak.sh                 # 100k cases × 4 rounds
#   PROPTEST_CASES=250000 ROUNDS=6 ./scripts/fuzz-proptest-soak.sh
#
# A failing property prints its minimal counterexample and is persisted by
# proptest under <crate>/tests/<name>.proptest-regressions (committed = a guard).
set -uo pipefail

cd "$(dirname "$0")/.."   # repo root

CASES="${PROPTEST_CASES:-100000}"
ROUNDS="${ROUNDS:-4}"
ts="${TS:-manual}"
logdir="fuzz/logs/proptest-$ts"
mkdir -p "$logdir"

export PROPTEST_CASES="$CASES"
export RUST_BACKTRACE=1

# Structured / property "fuzz" harnesses, by crate (cargo runs the test fns
# inside each across all cores).
SSP_TESTS=(fuzz_clock fuzz_decode fuzz_driver_live fuzz_hostile proptest_ssp sim_convergence)
TERM_TESTS=(fuzz_apply fuzz_diff fuzz_predict differential_emulator state_sync)

ssp_args=(); for t in "${SSP_TESTS[@]}"; do ssp_args+=(--test "$t"); done
term_args=(); for t in "${TERM_TESTS[@]}"; do term_args+=(--test "$t"); done

echo "proptest + sim soak"
echo "  cases/property=$CASES  rounds=$ROUNDS  cores=$(nproc)"
echo "  ssp:  ${SSP_TESTS[*]}"
echo "  term: ${TERM_TESTS[*]}"
echo "  madsim: madsim_fullstack madsim_sim (--cfg madsim, seed sweep)"
echo "  logs=$logdir"
echo

fail=0

# Build once up front (release-ish test profile) so round timings are fuzzing,
# not compiling.
echo "building test binaries…"
cargo test --no-run -p mish-ssp "${ssp_args[@]}"   >"$logdir/build-ssp.log" 2>&1 || fail=1
cargo test --no-run -p mish-terminal "${term_args[@]}" >"$logdir/build-term.log" 2>&1 || fail=1
echo

for r in $(seq 1 "$ROUNDS"); do
  echo "== round $r/$ROUNDS =="
  if ! cargo test -p mish-ssp "${ssp_args[@]}" >"$logdir/ssp-r$r.log" 2>&1; then
    echo "  !! FAIL in mish-ssp round $r — see $logdir/ssp-r$r.log"; fail=1
  else echo "  mish-ssp ok"; fi
  if ! cargo test -p mish-terminal "${term_args[@]}" >"$logdir/term-r$r.log" 2>&1; then
    echo "  !! FAIL in mish-terminal round $r — see $logdir/term-r$r.log"; fail=1
  else echo "  mish-terminal ok"; fi
done

# madsim seed sweep (separate build flags → its own invocation, lower case count
# since each case is a full simulated session).
echo "== madsim seed sweep =="
if ! env RUSTFLAGS="--cfg madsim" PROPTEST_CASES="$(( CASES / 50 > 200 ? CASES / 50 : 200 ))" \
      cargo test -p mish-madsim --test madsim_fullstack --test madsim_sim \
      >"$logdir/madsim.log" 2>&1; then
  echo "  !! FAIL in madsim — see $logdir/madsim.log"; fail=1
else echo "  madsim ok"; fi

echo
if [ "$fail" -eq 0 ]; then
  echo "proptest + sim soak: PASS (all rounds clean) — logs $logdir"
else
  echo "proptest + sim soak: FAILURES — grep -l FAILED $logdir/*.log; new"
  echo "counterexamples persisted under */tests/*.proptest-regressions"
fi
exit "$fail"
