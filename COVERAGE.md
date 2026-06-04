# Test coverage vs. mosh

This maps mosh's own test suite (`mosh/src/tests/`) to the equivalent tests in
mish, plus the simulation tests that go beyond it. "≈" means the scenario is
covered by an equivalent test rather than a byte-for-byte port (we render to a
`Screen` and assert on cells/cursor/attributes instead of tmux captures).

## Terminal emulation (`emulation-*.test`)

| mosh test | mish test | notes |
|-----------|--------------|-------|
| emulation-80th-column | `emulation_mish::eightieth_column_deferred_wrap` | VT100 deferred wrap |
| emulation-cursor-motion | `emulation_mish::cursor_motion_positions` | CUP placement |
| emulation-scroll | `emulation_mish::scroll_up` | SU/scroll |
| emulation-multiline-scroll | `emulation_mish::multiline_scroll_no_crash` | IL/DL no-crash regression |
| emulation-back-tab | `emulation_mish::back_tab_and_forward_tab` | CBT / CHT |
| emulation-wrap-across-frames | `emulation_mish::wrap_across_rows` | autowrap |
| emulation-ascii-iso-8859 | `emulation_mish::ascii_and_latin1` | UTF-8 text |
| emulation-attributes-vt100 | `emulator_test::sgr_attributes_and_color` | bold/underline/etc. |
| emulation-attributes-16color | `emulation_mish::sgr_16_colors_distinct` | SGR 30–37 |
| emulation-attributes-256color8/248 | `emulation_mish::indexed_256_background`, `emulator_test::sgr_attributes_and_color` | 256-color |
| emulation-attributes-truecolor | `emulator_test::rgb_truecolor` | 24-bit color |
| emulation-attributes-bce | `emulation_mish::background_color_erase` | BCE on erase |
| emulation-attributes-osc8 | `emulation_mish::osc8_hyperlink_captured_and_diffed` | OSC 8 hyperlinks modeled + round-tripped |

## Network / protocol behavior

| mosh test | mish test | notes |
|-----------|--------------|-------|
| network-no-diff | `emulation_mish::no_op_sequence_yields_empty_diff` | no-op ⇒ empty diff |
| repeat / repeat-with-input | `turmoil_sim::repeat_sessions_converge` | 50 sessions back-to-back |
| window-resize | `emulation_mish::resize_reflows`, `loopback::client_resize_propagates_to_server_pty` | resize/reflow + SIGWINCH path |
| server-network-timeout | `loopback::server_exits_after_network_timeout` | idle timeout (paused clock) |
| server-signal-timeout | `server_cli::exits_on_signal_timeout_without_client` | MOSH_SERVER_SIGNAL_TMOUT: exit if no client connects |
| pty-deadlock | `pty_real::flow_control_does_not_deadlock` | ^S/^Q (XOFF/XON) around I/O, session keeps flowing |
| local | `full_stack::quic_pty_full_stack` | real PTY + QUIC end-to-end |
| e2e-success / e2e-failure | `loopback::*`, `full_stack::*` | full client↔server round trip |

## Prediction (`prediction-unicode`, unicode combining)

| mosh test | mish test | notes |
|-----------|--------------|-------|
| prediction-unicode | `predict::tests::prediction_unicode_no_corruption`, `multibyte_utf8_not_split` | split-UTF-8 never corrupts a prediction |
| unicode-combine-fallback-assert | `emulation_mish::combining_after_erase_no_crash` | combining mark after erase, no panic |
| unicode-later-combining | `emulation_mish::later_combining_survives` | combining circumflex in stream |

## Crypto (`base64`, `encrypt-decrypt`, `ocb-aes`, `nonce-incr`)

Not applicable: QUIC (TLS 1.3) provides authenticated encryption, key exchange,
and nonce management, replacing mosh's hand-rolled OCB/AES and base64 framing.

## Diff fidelity (beyond mosh's shell tests)

mosh verifies its diff via a round-trip self-check in verbose mode; we make that
a first-class property test:

| property | test |
|----------|------|
| full repaint reproduces the screen | `display_roundtrip::full_repaint_roundtrips` |
| incremental `new_frame(old,new)` reproduces `new` | `display_roundtrip::incremental_diff_roundtrips` |
| identical screens ⇒ empty diff | `display_roundtrip::identical_screens_no_change` |
| `Screen` SyncState round-trip / from-initial / empty | `state_sync::screen_*` |

## Deterministic network simulation (turmoil) — beyond mosh

mosh has no in-process network simulator; mish runs the real async session
over simulated UDP with a controllable clock and fault injection:

| scenario | test |
|----------|------|
| convergence with latency | `turmoil_sim::converges_with_latency` |
| convergence under 30% packet loss | `turmoil_sim::converges_under_packet_loss` |
| large payload fragments + recovers under loss | `turmoil_sim::large_payload_fragments_and_converges_under_loss` |
| recovery after a network partition heals | `turmoil_sim::survives_network_partition` |
| many sessions back-to-back (soak) | `turmoil_sim::repeat_sessions_converge` |

Plus the deterministic sans-IO core simulator (`mish-ssp/src/sim.rs`) and its
convergence/property tests under loss + reordering across many seeds.
