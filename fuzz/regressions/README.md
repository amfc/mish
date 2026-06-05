# Fuzz regression seeds

Checked-in inputs that once crashed a fuzz target. Unlike `corpus/` and
`artifacts/` (gitignored, machine-generated), these are curated and **must never
crash again**. The CI fuzz job replays every file in `regressions/<target>/`
before starting a fresh fuzzing run, so a reintroduced bug fails deterministically
(no waiting for the fuzzer to rediscover it).

Replay locally:

```sh
cargo +nightly fuzz run <target> regressions/<target>/<seed>
# or the whole directory:
cargo +nightly fuzz run <target> regressions/<target>/
```

When a fuzzer finds a new crash (an `artifacts/<target>/crash-*` file), fix the
bug, add a focused unit regression test where it belongs, and move the minimized
input here with a descriptive name.

## Catalogued seeds

- `screen_apply/zero-dimension-grid-panic` — a diff header declaring a zero
  dimension (`cols=0, rows=0xe6e6`) slipped past the cell-count product guard
  (`0 * n == 0`) and panicked alacritty's grid building a zero-width row. Fixed in
  `screen.rs` (`cols == 0 || rows == 0` check); also covered by the
  `malformed_diff_geometry_does_not_panic` unit test.
