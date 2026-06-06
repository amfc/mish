# Overnight fuzzing summary — 2026-06-05/06

A long, parallel fuzzing campaign on a 32-core box, run in two phases via
[`scripts/fuzz-overnight.sh`](scripts/fuzz-overnight.sh) (coverage-guided
libFuzzer) and [`scripts/fuzz-proptest-soak.sh`](scripts/fuzz-proptest-soak.sh)
(property + simulation soak). It found **3 distinct bug classes**, all now fixed,
guarded by regression seeds + tests, and re-verified.

## What ran

**Phase 1 — libFuzzer + ASan, fork mode, ~8 h** (19:56 → 03:58). All six
coverage-guided targets concurrently, 4 forks each, resuming from the checked-in
corpus.

| target | line cov | corpus (end) | unique crashes |
|---|---:|---:|---:|
| `diff_roundtrip` | 4448 | 5828 | **91** → bug #3 |
| `screen_apply` | 2268 | 1219 | **48** → bug #2 |
| `differential_emulator` | 1010 | 459 | 0 |
| `instruction_decode` | 864 | 798 | 0 |
| `frag_reassemble` | 241 | 245 | 0 |
| `userstream_decode` | 181 | 88 | 0 (bug #1 fix held) |

**Phase 2 — proptest + sim soak, ~2.7 h** (03:58 → 06:40). 100 000 cases ×
4 rounds, plus the madsim seed sweep.

| suite | result |
|---|---|
| `mish-ssp` (`fuzz_clock`, `fuzz_decode`, `fuzz_driver_live`, `fuzz_hostile`, `proptest_ssp`, `sim_convergence`) | clean, all 4 rounds |
| `mish-madsim` (`madsim_fullstack`, `madsim_sim`) | clean |
| `mish-terminal` (`fuzz_apply`, `fuzz_diff`, `fuzz_predict`, `differential_emulator`, `state_sync`) | **failed** — independently reproduced bug #2 |

## Bugs found & fixed

### #1 — `UserStream::apply_diff` integer overflow (hostile diff)
A diff with `start ≈ u64::MAX` overflowed `start + i` in the apply loop
(`crates/mish-terminal/src/user.rs`). Hostile-input no-panic violation.
**Fix:** `saturating_add`. *(Found & fixed during setup; stayed clean all night.)*

### #2 — `screen_apply` / `fuzz_apply`: alacritty grid out-of-bounds on a 1-column screen
All 48 crashes had `cols = 1`. A wide (CJK) glyph in a single-column grid makes
alacritty write the wide-char spacer to column 1 → `cursor_cell` index-out-of-bounds
panic. Reproduced independently by the proptest layer (`screen_apply_arbitrary_diff`).
**Fix:** reject `cols < 2` in `Screen::apply_diff`'s geometry guard — a 1-column
terminal can't render wide chars and never occurs in practice.

### #3 — `diff_roundtrip`: wide-char round-trip identity broken
The project's central invariant — `prev.apply_diff(cur.diff_from(prev)) == cur` —
failed (91 crashes). A **broken wide char** (a wide glyph whose spacer column was
overwritten by a real glyph after an insert-character/ICH shifted into it) is a
state the diff couldn't reproduce: the differ skipped the column after a wide
glyph as its implied spacer, so the change vanished and the wire diff came out
**empty**. The state also can't be rebuilt by replaying glyphs (writing onto a
spacer makes the terminal clear the wide char).
**Fix:** normalize at the source — `Emulator::snapshot` stores a blank for a wide
glyph whose partner isn't a real spacer, so the model never holds an
unreconstructible state (same spirit as the existing control-char normalization).

## Verification

- All 139 crash artifacts (48 + 91) and the persisted `fuzz_apply` proptest
  counterexample replay clean against the fixed code.
- Regression seeds added under `fuzz/regressions/{userstream_decode,screen_apply,diff_roundtrip}/`
  (replayed by CI and the overnight script).
- Fast deterministic regression tests added: `screen::tests::malformed_diff_geometry_does_not_panic`
  (cols=1 + wide glyph), `display_roundtrip::broken_wide_char_spacer_roundtrips`,
  `state_sync::userstream_apply_hostile_start_does_not_overflow`. `arb_screen`
  tightened to `cols >= 2` to match the guard.
- **Full workspace: 59 test binaries, 0 failures.**
- **Re-fuzz on the fixed tree (180 s × 3 affected targets): 0 new crashes**
  (`diff_roundtrip` 665 k execs, `differential_emulator` 910 k, `screen_apply`
  4.3 k).

## Reproduce / re-run

```sh
cargo +nightly fuzz run <target> fuzz/regressions/<target>/ -- -runs=0   # replay a guard
./scripts/fuzz-overnight.sh                                              # full 8h campaign
./scripts/fuzz-proptest-soak.sh                                          # property + sim soak
```
