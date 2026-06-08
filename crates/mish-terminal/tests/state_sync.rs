//! Property + simulation tests for the terminal `SyncState`s, reusing the
//! deterministic SSP simulator. Proves the row-granular screen diff and the
//! append-only user stream satisfy the `SyncState` contract and converge over a
//! lossy link.

use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{Cell, Color, Screen};
use mish_terminal::user::{UserEvent, UserStream};
use proptest::prelude::*;

// ---------- Screen proptest strategies ----------

// Colors as the emulator actually produces them: a slot's default sentinel
// never crosses (fg-default = 256, bg-default = 257); plus basic 0–15, indexed,
// and rgb. This keeps screens reproducible by mosh's escape-stream diff.
fn arb_color_with_default(default: u16) -> impl Strategy<Value = Color> {
    prop_oneof![
        Just(Color::Named(default)),
        (0u16..16).prop_map(Color::Named),
        any::<u8>().prop_map(Color::Indexed),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(r, g, b)| Color::Rgb(r, g, b)),
    ]
}

fn arb_cell() -> impl Strategy<Value = Cell> {
    (
        prop::char::range(' ', '~'),
        arb_color_with_default(mish_terminal::screen::NAMED_FOREGROUND),
        arb_color_with_default(mish_terminal::screen::NAMED_BACKGROUND),
        // Round-trippable attribute flags (no wide-char markers).
        prop_oneof![
            Just(0u16),
            Just(2u16),
            Just(4u16),
            Just(6u16),
            Just(8u16),
            Just(16u16)
        ],
    )
        .prop_map(|(c, fg, bg, flags)| Cell {
            c,
            fg,
            bg,
            flags,
            combining: Vec::new(),
            hyperlink: None,
        })
}

fn arb_screen() -> impl Strategy<Value = Screen> {
    // cols >= 2: a single-column screen is a degenerate geometry `apply_diff`
    // rejects (a wide glyph can't fit / makes alacritty's 1-wide grid panic), so
    // it isn't a reconstructible state — see Screen::apply_diff's geometry guard.
    (2u16..12, 1u16..6).prop_flat_map(|(cols, rows)| {
        let n = cols as usize * rows as usize;
        (
            Just(cols),
            Just(rows),
            prop::collection::vec(arb_cell(), n),
            0u16..rows,
            0u16..cols,
            any::<bool>(),
            // No trailing-space titles: the emulator strips them, so they can't
            // round-trip (an emulator quirk, not a diff concern).
            "[a-z]{0,8}",
            any::<u64>(),
            any::<bool>(), // focus_event
            any::<bool>(), // alternate_scroll
            any::<bool>(), // alt_screen
        )
            .prop_map(
                |(cols, rows, cells, cr, cc, cv, title, echo_ack, focus, alt_scroll, alt_screen)| {
                    Screen {
                        cols,
                        rows,
                        cells,
                        cursor_row: cr,
                        cursor_col: cc,
                        cursor_visible: cv,
                        title,
                        echo_ack,
                        bracketed_paste: false,
                        mouse_mode: 0,
                        cursor_shape: 0,
                        cursor_blink: false,
                        focus_event: focus,
                        alternate_scroll: alt_scroll,
                        alt_screen,
                        // Clipboard is monotonic (the emulator never reverts it
                        // to None), so an arbitrary Some→None pair would be an
                        // unreachable transition; covered by dedicated
                        // directional tests in display_roundtrip.rs instead.
                        clipboard: None,
                        app_cursor_keys: false,
                        bell_count: 0,
                    }
                },
            )
    })
}

proptest! {
    /// Applying a diff to the state it was computed from reconstructs the target.
    /// (SSP applies each diff to a fresh clone of the reference state and dedups
    /// duplicate instructions by num, so apply itself need not be idempotent.)
    #[test]
    fn screen_diff_roundtrip(a in arb_screen(), b in arb_screen()) {
        let diff = a.diff_from(&b);
        let mut x = b.clone();
        x.apply_diff(&diff);
        if !x.equals(&a) {
            let fd = (0..a.cells.len()).find(|&i| x.cells.get(i) != a.cells.get(i));
            prop_assert!(false, "roundtrip mismatch: dims x({},{}) a({},{}) cur x({},{},{}) a({},{},{}) title x={:?} a={:?}; firstcell {:?} x={:?} a={:?}; bdims({},{})",
                x.cols,x.rows,a.cols,a.rows, x.cursor_row,x.cursor_col,x.cursor_visible, a.cursor_row,a.cursor_col,a.cursor_visible,
                x.title,a.title, fd, fd.and_then(|i|x.cells.get(i)), fd.and_then(|i|a.cells.get(i)), b.cols,b.rows);
        }
    }

    #[test]
    fn screen_diff_from_initial(a in arb_screen()) {
        let mut x = Screen::new_initial();
        x.apply_diff(&a.diff_from(&x));
        if !x.equals(&a) {
            let fd = (0..a.cells.len()).find(|&i| x.cells.get(i) != a.cells.get(i));
            prop_assert!(false, "from_initial mismatch: dims x({},{}) a({},{}) cur x({},{},{}) a({},{},{}) title x={:?} a={:?} echo x={} a={}; firstcell {:?} x={:?} a={:?}",
                x.cols,x.rows,a.cols,a.rows, x.cursor_row,x.cursor_col,x.cursor_visible, a.cursor_row,a.cursor_col,a.cursor_visible,
                x.title,a.title,x.echo_ack,a.echo_ack, fd, fd.and_then(|i|x.cells.get(i)), fd.and_then(|i|a.cells.get(i)));
        }
    }

    #[test]
    fn screen_equal_states_empty_diff(a in arb_screen()) {
        prop_assert!(a.diff_from(&a).is_empty());
    }
}

// ---------- UserStream proptest ----------

fn arb_event() -> impl Strategy<Value = UserEvent> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..8).prop_map(UserEvent::Keystroke),
        (1u16..200, 1u16..60).prop_map(|(cols, rows)| UserEvent::Resize { cols, rows }),
    ]
}

proptest! {
    #[test]
    fn userstream_diff_roundtrip(events in prop::collection::vec(arb_event(), 0..20), k in 0usize..20) {
        let mut full = UserStream::new();
        for e in &events { full.push(e.clone()); }
        let k = k.min(events.len());
        let mut prev = UserStream::new();
        for e in events.iter().take(k) { prev.push(e.clone()); }

        let diff = full.diff_from(&prev);
        let mut x = prev.clone();
        x.apply_diff(&diff);
        prop_assert!(x.equals(&full), "round-trip failed");
        x.apply_diff(&diff);
        prop_assert!(x.equals(&full), "not idempotent");
    }
}

#[test]
fn userstream_subtract_preserves_logical_content() {
    let mut full = UserStream::new();
    for i in 0..5u8 {
        full.push_keystroke(vec![i]);
    }
    let mut prev = UserStream::new();
    prev.push_keystroke(vec![0]);
    prev.push_keystroke(vec![1]);
    assert_eq!(prev.total(), 2);

    full.subtract(&prev);
    // total() is unchanged; only the front is trimmed.
    assert_eq!(full.total(), 5);
    let tail: Vec<_> = full.events_since(2).cloned().collect();
    assert_eq!(
        tail,
        vec![
            UserEvent::Keystroke(vec![2]),
            UserEvent::Keystroke(vec![3]),
            UserEvent::Keystroke(vec![4]),
        ]
    );

    // Diffing after a trim still reconstructs the receiver correctly.
    let diff = full.diff_from(&prev);
    let mut x = prev.clone();
    x.apply_diff(&diff);
    assert_eq!(x.total(), 5);
}

// Regression (found by the `userstream_decode` fuzzer): a hostile diff whose
// `start` index is near u64::MAX must not overflow the per-event index. Before
// the `saturating_add` fix this panicked with "attempt to add with overflow" in
// the apply loop. Guarded as a seed under fuzz/regressions/userstream_decode/.
#[test]
fn userstream_apply_hostile_start_does_not_overflow() {
    // bincode of StreamDiff { start: u64::MAX, suffix: [<2 events>] }.
    let hostile: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // Against a fresh stream and a non-empty one (the fuzz harness's two cases).
    let mut s = UserStream::new();
    s.apply_diff(hostile); // must not panic
    let mut s2 = UserStream::new();
    s2.push_keystroke(b"hello".to_vec());
    s2.push_resize(80, 24);
    s2.apply_diff(hostile); // must not panic
}

// A hostile/relentless peer that streams input while pinning `throwaway_num`
// must not grow the receiver's reconstructed stream without bound. `apply_diff`
// caps retained event bodies (front-trim), keeping memory bounded while leaving
// `total()` — and therefore the diff chain and the most recent unread suffix —
// intact. Defends the post-auth memory-amplification DoS in core::recv.
#[test]
fn userstream_apply_bounds_retained_events() {
    use bincode::serialize;

    // Encode a StreamDiff the way `diff_from` does, but by hand so we can drive
    // far more events than any proptest would.
    fn diff_bytes(start: u64, n: usize) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Wire {
            start: u64,
            suffix: Vec<UserEvent>,
        }
        let suffix = (0..n)
            .map(|i| UserEvent::Keystroke(vec![(start + i as u64) as u8]))
            .collect();
        serialize(&Wire { start, suffix }).unwrap()
    }

    let mut s = UserStream::new();
    // Stream 300k events in chunks — well past the 64k retention cap.
    let chunk = 10_000;
    let total = 300_000u64;
    let mut sent = 0u64;
    while sent < total {
        s.apply_diff(&diff_bytes(sent, chunk));
        sent += chunk as u64;
        // Retention stays bounded throughout, never unbounded.
        assert!(
            s.retained_len() <= 1 << 16,
            "retained events must stay bounded (got {})",
            s.retained_len()
        );
    }
    // The logical cursor still reflects every event ever applied (so the diff
    // chain / acks keep working), even though old bodies were trimmed.
    assert_eq!(s.total(), total);
    // The most recent events — the only ones a live receiver hasn't processed —
    // are still present and correct.
    let last = s.events_since(total - 3).cloned().collect::<Vec<_>>();
    assert_eq!(
        last,
        vec![
            UserEvent::Keystroke(vec![(total - 3) as u8]),
            UserEvent::Keystroke(vec![(total - 2) as u8]),
            UserEvent::Keystroke(vec![(total - 1) as u8]),
        ]
    );
}

// ---------- End-to-end client/server convergence over the simulator ----------

// Node A = client: sends UserStream, receives Screen.
// Node B = server: sends Screen, receives UserStream.
type Sim = NetworkSim<UserStream, Screen>;

fn make_screen() -> Screen {
    let mut emu = Emulator::new(20, 4);
    emu.feed(b"\x1b[1mhello\x1b[0m\r\nworld");
    emu.snapshot()
}

fn make_input() -> UserStream {
    let mut us = UserStream::new();
    us.push_keystroke(b"ls -la\r".to_vec());
    us.push_resize(120, 40);
    us
}

#[test]
fn client_server_states_converge_lossless() {
    let mut sim = Sim::new(SimConfig::default());
    let screen = make_screen();
    let input = make_input();
    sim.set_a_local(input.clone());
    sim.set_b_local(screen.clone());

    let want_input: Vec<UserEvent> = input.events_since(0).cloned().collect();
    let ok = sim.run_until(
        |s| {
            *s.a_view_of_b() == screen
                && s.b_view_of_a().events_since(0).cloned().collect::<Vec<_>>() == want_input
        },
        300_000,
    );
    assert!(ok, "states should converge (t={})", sim.now());
    let lines = sim.a_view_of_b().to_lines();
    assert_eq!(&lines[0..2], &["hello".to_string(), "world".to_string()]);
}

#[test]
fn client_server_states_converge_lossy() {
    let cfg = SimConfig {
        loss: 0.4,
        min_delay: 1,
        max_delay: 50,
        seed: 0x5EED_1234,
        ..Default::default()
    };
    let mut sim = Sim::new(cfg);
    let screen = make_screen();
    let input = make_input();
    sim.set_a_local(input.clone());
    sim.set_b_local(screen.clone());

    let want_input: Vec<UserEvent> = input.events_since(0).cloned().collect();
    let ok = sim.run_until(
        |s| {
            *s.a_view_of_b() == screen
                && s.b_view_of_a().events_since(0).cloned().collect::<Vec<_>>() == want_input
        },
        300_000,
    );
    assert!(
        ok,
        "should converge despite 40% loss (t={}, dropped={})",
        sim.now(),
        sim.dropped
    );
    assert!(sim.dropped > 0);
}
