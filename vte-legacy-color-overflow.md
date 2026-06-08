# `parse_legacy_color` panics with "shift right with overflow" on a long `#`-color

**Crate:** `vte` 0.15.0
**Location:** `src/ansi.rs:219`, in `parse_legacy_color`
**Severity:** debug-build panic (DoS in any debug/overflow-checks build); silent wrong value in release.

## Summary

When an OSC color escape uses the legacy `#rgb` format and the color body is
long enough (≥ 51 hex bytes, i.e. each of the three components is ≥ 17 hex
digits), `parse_legacy_color` computes a bit-shift amount that meets or exceeds
the word width, so the right-shift overflows. In a build with overflow checks
(any debug build) this **panics**:

```
thread '...' panicked at vte-0.15.0/src/ansi.rs:219:14:
attempt to shift right with overflow
```

A remote peer can drive this through any terminal that forwards program output
to `vte` (e.g. an OSC `10;#…` / `4;n;#…` color query), turning a crafted escape
sequence into a remote panic of the host application.

## Root cause

```rust
// src/ansi.rs
fn parse_legacy_color(color: &[u8]) -> Option<Rgb> {
    let item_len = color.len() / 3;

    let color_from_slice = |slice: &[u8]| {
        let col = usize::from_str_radix(str::from_utf8(slice).ok()?, 16).ok()? << 4;
        Some((col >> (4 * slice.len().saturating_sub(1))) as u8)   // <-- line 219
    };
    ...
}
```

The shift amount is `4 * (slice.len() - 1)`. `slice` is one third of the color
body (`item_len = color.len() / 3`), and its length is unbounded. Once
`slice.len() >= 17`, the shift amount is `>= 64`, which is `>=` the bit width of
`usize` on a 64-bit target, so `col >> n` is an overflow.

Note the leading zeros make the *value* small enough that
`from_str_radix(..).ok()?` succeeds, so the early-return guards don't fire — it's
purely the **shift amount**, derived from the slice *length*, that overflows.

The sibling RGB-format parser a few lines up already guards exactly this with
`if input.len() > 4 { None }`; `parse_legacy_color`'s `color_from_slice` is
missing the equivalent bound.

## Reproduction

### Drop-in unit test (private fn — for maintainers)

```rust
#[test]
fn legacy_color_long_body_does_not_overflow() {
    // 60-byte body -> item_len 20 -> shift 4*19 = 76 >= 64 -> overflow.
    let body = vec![b'0'; 60];
    let _ = super::parse_legacy_color(&body); // panics today on a checked build
}
```

### Through the public API (byte level)

Feed an OSC set-foreground with a long `#`-color through a `Processor`:

```
ESC ] 10 ; # 000000000000000000000000000000000000000000000000000 BEL
```

i.e. `b"\x1b]10;#"` + `b"0" * 51` (or more) + `b"\x07"`. Any debug build panics
at `ansi.rs:219`.

## Expected vs. actual

- **Expected:** a malformed / over-long legacy color is rejected (`None`) like
  other malformed colors, never a panic.
- **Actual:** panic in checked builds; in release the masked shift yields an
  arbitrary color byte (wrong, though memory-safe).

## Suggested fix

Bound the component length the same way the RGB-format path does, e.g. reject
overly long slices before shifting:

```rust
let color_from_slice = |slice: &[u8]| {
    if slice.is_empty() || slice.len() > 4 {
        return None;
    }
    let col = usize::from_str_radix(str::from_utf8(slice).ok()?, 16).ok()? << 4;
    Some((col >> (4 * (slice.len() - 1))) as u8)
};
```

(Or compute with `checked_shr` / clamp the shift amount.) Capping at 4 hex
digits per component matches the documented `#r(rrr)g(ggg)b(bbb)` grammar.

## Environment

- `vte` 0.15.0, 64-bit target (`usize` = 64 bits).
- Found by a fuzz target feeding arbitrary bytes to the ANSI processor.
