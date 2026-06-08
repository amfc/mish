#!/usr/bin/env bash
# Snapshot the live fuzzing corpus into a committed, *minimized* seed corpus, so
# future runs (and CI) start warm — replaying the saved inputs rebuilds the
# already-discovered edge coverage instead of re-finding it from scratch.
#
# Why the corpus and not a "coverage file": libFuzzer has no portable coverage
# map — SanitizerCoverage edge IDs are tied to the exact compiled binary, so they
# don't survive a recompile. The *inputs* (the corpus) are the durable record of
# what coverage was found. `cargo fuzz cmin` keeps the same edge coverage with far
# fewer / smaller inputs, which is what you check in.
#
#   ./scripts/fuzz-corpus-snapshot.sh                 # all targets
#   ./scripts/fuzz-corpus-snapshot.sh diff_roundtrip  # just one
#
# The live fuzz/corpus is **left untouched**: we minify a *copy* into
# fuzz/seed-corpus, so an ongoing/next campaign keeps its full working corpus.
#
# Run when **no campaign is active** (cmin runs the target on every input; a live
# fuzzer writing fuzz/corpus would race the copy). Afterwards:
#   git add fuzz/seed-corpus && git commit -m "fuzz: refresh minimized seed corpus"
set -uo pipefail

cd "$(dirname "$0")/.."

# cargo-fuzz needs nightly. On rustup boxes `cargo +nightly` works; where cargo is
# already the nightly toolchain (e.g. Nix) the `+nightly` shorthand isn't
# understood — fall back to a plain / rustup invocation.
if cargo +nightly fuzz --version >/dev/null 2>&1; then
  FUZZ=(cargo +nightly fuzz)
elif cargo fuzz --version >/dev/null 2>&1; then
  FUZZ=(cargo fuzz)
else
  FUZZ=(rustup run nightly cargo fuzz)
fi

# Targets default to every cargo-fuzz target; override by passing names.
mapfile -t TARGETS < <(ls fuzz/fuzz_targets/*.rs 2>/dev/null | xargs -n1 basename | sed 's/\.rs$//')
[ "$#" -gt 0 ] && TARGETS=("$@")

mkdir -p fuzz/seed-corpus
echo "minimizing ${#TARGETS[@]} corpora into fuzz/seed-corpus/ (live fuzz/corpus left untouched) …"
echo

for t in "${TARGETS[@]}"; do
  if [ ! -d "fuzz/corpus/$t" ] || [ -z "$(ls -A "fuzz/corpus/$t" 2>/dev/null)" ]; then
    echo "skip $t — no live corpus"
    continue
  fi
  before=$(ls "fuzz/corpus/$t" | wc -l)
  echo "cmin $t ($before inputs)…"
  # Seed the snapshot dir from a *copy* of the live corpus, then cmin minifies
  # that copy in place. fuzz/corpus/$t is never read-modify-written, so it stays
  # full for the next campaign.
  rm -rf "fuzz/seed-corpus/$t"
  mkdir -p "fuzz/seed-corpus/$t"
  cp "fuzz/corpus/$t"/* "fuzz/seed-corpus/$t"/ 2>/dev/null || true
  if ! "${FUZZ[@]}" cmin "$t" "fuzz/seed-corpus/$t" >/dev/null 2>&1; then
    echo "  !! cmin failed for $t — kept the unminimized copy"
    continue
  fi
  after=$(ls "fuzz/seed-corpus/$t" | wc -l)
  echo "  $before -> $after seeds ($(du -sh "fuzz/seed-corpus/$t" 2>/dev/null | cut -f1))"
done

echo
echo "seed corpus: $(du -sh fuzz/seed-corpus 2>/dev/null | cut -f1) total"
echo "live corpus: $(du -sh fuzz/corpus 2>/dev/null | cut -f1) total (preserved)"
echo "commit with: git add fuzz/seed-corpus && git commit -m 'fuzz: refresh minimized seed corpus'"
